//! SQLite storage, ported from `src/slap/db.py`. Immutable, append-only runs.
//!
//! The DDL is byte-for-byte the Python app's DDL: every existing install's
//! history was written by that app into this exact schema, and this app
//! opens the same file. Cross-app compatibility was proven in both
//! directions before the Python app retired (see tests/python_compat.rs).
//! WAL mode made the coexistence-era sharing safe and still makes the UI
//! thread safe beside a batch writer.
//!
//! One deliberate translation: the Python module kept a thread-local
//! connection cache with an init-once memo, because Python front ends passed
//! `db.connect(path)` around freely and sqlite3 connections cannot cross
//! threads. Rust makes ownership explicit, so this module hands back a
//! [`rusqlite::Connection`] and the caller decides where it lives (the Tauri
//! shell keeps one behind a mutex in app state). The bug that cache grew,
//! where an emptied cache read as absent and every connection leaked until
//! `WinError 32`, cannot be ported because the design that housed it was not.
//!
//! Run status lives in the database, not in memory: a front end can close,
//! crash, or reattach mid-batch and still render the truth.

use std::collections::HashMap;
use std::path::Path;

use rusqlite::types::ValueRef;
use rusqlite::{params, Connection, OptionalExtension, Result};
use serde_json::{json, Map, Value as Json};

use crate::schema::{
    AuditDepth, DiscoveredVia, Finding, FormFactor, Observation, PageRole, RunStatus, Unit, Value,
};

pub const DDL: &str = r#"
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS site (
    id          INTEGER PRIMARY KEY,
    hostname    TEXT NOT NULL UNIQUE,
    label       TEXT,
    client      TEXT,
    created_at  TEXT NOT NULL,
    -- Endpoint probing is authorised per SITE, never globally. A global flag
    -- gets switched on once for a client who agreed and then silently applies
    -- to the next one, who did not. Recorded with who and when, so the report
    -- can print it and an audit trail survives the conversation.
    probe_authorised_at TEXT,
    probe_authorised_by TEXT,
    probe_note          TEXT
);

CREATE TABLE IF NOT EXISTS run (
    id                  INTEGER PRIMARY KEY,
    batch_id            TEXT NOT NULL,
    site_id             INTEGER NOT NULL REFERENCES site(id),
    started_at          TEXT NOT NULL,
    finished_at         TEXT,
    status              TEXT NOT NULL,
    error               TEXT,
    slap_version        TEXT NOT NULL,
    schema_version      INTEGER NOT NULL,
    lh_version          TEXT,
    chrome_version      TEXT,
    throttling_profile  TEXT,
    git_sha             TEXT
);
CREATE INDEX IF NOT EXISTS idx_run_batch ON run(batch_id);
CREATE INDEX IF NOT EXISTS idx_run_site_started ON run(site_id, started_at DESC);

CREATE TABLE IF NOT EXISTS page (
    id             INTEGER PRIMARY KEY,
    run_id         INTEGER NOT NULL REFERENCES run(id) ON DELETE CASCADE,
    url            TEXT NOT NULL,
    final_url      TEXT,
    form_factor    TEXT NOT NULL,
    role           TEXT NOT NULL DEFAULT 'home',
    discovered_via TEXT NOT NULL DEFAULT 'manual',
    audit_depth    TEXT NOT NULL DEFAULT 'light',
    template_class TEXT
);
CREATE INDEX IF NOT EXISTS idx_page_run ON page(run_id);
-- The home page of a run is looked up on every read path that needs a single
-- representative row: the trend line, the verdict, the origin-scoped
-- observations. Worth its own index once a run holds tens of pages.
CREATE INDEX IF NOT EXISTS idx_page_run_role ON page(run_id, role);

CREATE TABLE IF NOT EXISTS observation (
    id             INTEGER PRIMARY KEY,
    page_id        INTEGER NOT NULL REFERENCES page(id) ON DELETE CASCADE,
    source         TEXT NOT NULL,
    metric_key     TEXT NOT NULL,
    numeric_value  REAL,
    text_value     TEXT,
    unit           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_obs_page_key ON observation(page_id, metric_key);
CREATE INDEX IF NOT EXISTS idx_obs_key ON observation(metric_key);

CREATE TABLE IF NOT EXISTS finding (
    id            INTEGER PRIMARY KEY,
    page_id       INTEGER NOT NULL REFERENCES page(id) ON DELETE CASCADE,
    rule_id       TEXT NOT NULL,
    severity      TEXT NOT NULL,
    title         TEXT NOT NULL,
    detail        TEXT NOT NULL,
    evidence_json TEXT,
    impact_ms     REAL,
    effort        TEXT,
    remediation   TEXT,
    wp_rocket_setting TEXT
);
CREATE INDEX IF NOT EXISTS idx_finding_page ON finding(page_id);

-- Field-data history: 25 weekly periods per origin from the CrUX History API.
--
-- The first table in this schema that does NOT hang off a run, and that is
-- the point. The CrUX record for an origin in a given week is the same fact
-- whoever fetched it and whenever; two audits a week apart share 24 of their
-- 25 periods. Keying it to runs would duplicate ~96% of it, and every trend
-- query would need a dedup pass to avoid plotting the same week five times.
--
-- Immutability still holds. A run is immutable history of what SLAP did; this
-- is a cache of an external series keyed by its own identity, so re-fetching
-- a period overwrites it with the same values. `fetched_at` records when we
-- last saw it, which is the provenance that matters.
CREATE TABLE IF NOT EXISTS crux_history (
    origin       TEXT NOT NULL,
    form_factor  TEXT NOT NULL,
    period_end   TEXT NOT NULL,          -- ISO date; the natural period key
    period_start TEXT NOT NULL,
    metric_key   TEXT NOT NULL,
    p75          REAL,
    good         REAL,
    needs_improvement REAL,
    poor         REAL,
    fetched_at   TEXT NOT NULL,
    PRIMARY KEY (origin, form_factor, period_end, metric_key)
);
CREATE INDEX IF NOT EXISTS idx_crux_history_origin
    ON crux_history(origin, form_factor, metric_key, period_end);

CREATE TABLE IF NOT EXISTS artifact (
    id       INTEGER PRIMARY KEY,
    run_id   INTEGER NOT NULL REFERENCES run(id) ON DELETE CASCADE,
    page_id  INTEGER REFERENCES page(id) ON DELETE CASCADE,
    kind     TEXT NOT NULL,
    path     TEXT NOT NULL,
    sha256   TEXT,
    bytes    INTEGER
);
CREATE INDEX IF NOT EXISTS idx_artifact_run ON artifact(run_id);
"#;

/// The exact timestamp format the Python app writes:
/// `datetime.now(timezone.utc).isoformat(timespec="seconds")`. Rows from the
/// two apps sort against each other lexicographically, so the format is a
/// compatibility contract, not a style choice.
pub fn utcnow() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S+00:00")
        .to_string()
}

/// Open (creating if needed), apply pragmas, migrate, and ensure the DDL.
///
/// This is `connect` + `init_db` from the Python side folded into one,
/// because without a hidden connection cache there is no reason to offer a
/// connect that skips initialisation.
pub fn open_db(path: &Path) -> Result<Connection> {
    if path.to_str() != Some(":memory:") {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    let conn = Connection::open(path)?;
    // journal_mode returns a result row, so it goes through query_row;
    // pragma_update would report "Execute returned results".
    let _mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
    conn.execute_batch("PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;")?;
    conn.busy_timeout(std::time::Duration::from_secs(30))?;
    migrate(&conn)?;
    conn.execute_batch(DDL)?;
    Ok(conn)
}

/// Bring an existing database up to the current DDL. Returns what it did.
///
/// `CREATE TABLE IF NOT EXISTS` is a no-op on a table that already exists,
/// so a column ADDED to a table in the DDL does NOT reach a database
/// created before it. A run created before per-page analysis has a `page`
/// table without `role`/`audit_depth`, and without this it keeps working
/// right up until a query selects a column that isn't there.
///
/// Kept deliberately small: add columns in place, never copy, never drop. A
/// run row is immutable history and losing it to a schema bump would be a
/// bad trade.
pub fn migrate(conn: &Connection) -> Result<Vec<String>> {
    let mut applied: Vec<String> = Vec::new();
    let tables = table_names(conn)?;
    if !tables.contains("run") {
        return Ok(applied);
    }

    // Per-page analysis: a run gained the ability to hold more than one
    // page. These go here rather than only in the DDL body because
    // `CREATE TABLE IF NOT EXISTS` will not add them to an existing table.
    // Defaulting `role` to 'home' is what keeps old runs on the trend line:
    // a NULL role would silently drop all of history from the queries that
    // select the home page.
    if tables.contains("page") {
        let page_columns = column_names(conn, "page")?;
        for (column, ddl) in [
            ("role", "TEXT NOT NULL DEFAULT 'home'"),
            ("discovered_via", "TEXT NOT NULL DEFAULT 'manual'"),
            ("audit_depth", "TEXT NOT NULL DEFAULT 'light'"),
            ("template_class", "TEXT"),
        ] {
            if !page_columns.contains(column) {
                conn.execute(&format!("ALTER TABLE page ADD COLUMN {column} {ddl}"), [])?;
                applied.push(format!("page.{column} added"));
            }
        }
    }

    // Probe authorisation. On `site` rather than in config, so it survives
    // a config rewrite and travels with the history it belongs to.
    if tables.contains("site") {
        let site_columns = column_names(conn, "site")?;
        for column in ["probe_authorised_at", "probe_authorised_by", "probe_note"] {
            if !site_columns.contains(column) {
                conn.execute(&format!("ALTER TABLE site ADD COLUMN {column} TEXT"), [])?;
                applied.push(format!("site.{column} added"));
            }
        }

        // A pre-existing run whose page ran Lighthouse should say so, or
        // its report will claim the browser audit was never attempted. The
        // artifact table is the only record of that for historical rows.
        if applied
            .iter()
            .any(|entry| entry == "page.audit_depth added")
        {
            let changed = conn.execute(
                "UPDATE page SET audit_depth = 'full' WHERE id IN (\
                 SELECT DISTINCT page_id FROM artifact WHERE page_id IS NOT NULL)",
                [],
            )?;
            if changed > 0 {
                applied.push(format!(
                    "page.audit_depth = full for {changed} historical rows"
                ));
            }
        }
    }
    Ok(applied)
}

fn table_names(conn: &Connection) -> Result<std::collections::HashSet<String>> {
    let mut stmt = conn.prepare("SELECT name FROM sqlite_master WHERE type='table'")?;
    let names = stmt
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<_>>()?;
    Ok(names)
}

fn column_names(conn: &Connection, table: &str) -> Result<std::collections::HashSet<String>> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let names = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<_>>()?;
    Ok(names)
}

// ---------------------------------------------------------------------------
// Row-to-JSON plumbing. The Python reads returned dicts; the UI consumes
// them as JSON over IPC, so the Rust reads return serde_json objects.
// ---------------------------------------------------------------------------

fn rows_to_json(
    stmt: &mut rusqlite::Statement<'_>,
    params: &[rusqlite::types::Value],
) -> Result<Vec<Json>> {
    let names: Vec<String> = stmt
        .column_names()
        .into_iter()
        .map(|name| name.to_string())
        .collect();
    let mut rows = stmt.query(rusqlite::params_from_iter(params.iter()))?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let mut object = Map::new();
        for (index, name) in names.iter().enumerate() {
            let value = match row.get_ref(index)? {
                ValueRef::Null => Json::Null,
                ValueRef::Integer(int) => json!(int),
                ValueRef::Real(real) => json!(real),
                ValueRef::Text(text) => json!(String::from_utf8_lossy(text)),
                ValueRef::Blob(_) => Json::Null, // no blob columns in this schema
            };
            object.insert(name.clone(), value);
        }
        out.push(Json::Object(object));
    }
    Ok(out)
}

fn one_json(
    conn: &Connection,
    sql: &str,
    params: &[rusqlite::types::Value],
) -> Result<Option<Json>> {
    let mut stmt = conn.prepare(sql)?;
    Ok(rows_to_json(&mut stmt, params)?.into_iter().next())
}

fn sql_text(text: &str) -> rusqlite::types::Value {
    rusqlite::types::Value::Text(text.to_string())
}
fn sql_int(int: i64) -> rusqlite::types::Value {
    rusqlite::types::Value::Integer(int)
}

// ---------------------------------------------------------------------------
// Writes
// ---------------------------------------------------------------------------

pub fn upsert_site(
    conn: &Connection,
    hostname: &str,
    label: Option<&str>,
    client: Option<&str>,
) -> Result<i64> {
    let existing: Option<i64> = conn
        .query_row(
            "SELECT id FROM site WHERE hostname = ?",
            params![hostname],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(id) = existing {
        if label.is_some() || client.is_some() {
            conn.execute(
                "UPDATE site SET label = COALESCE(?, label), client = COALESCE(?, client) \
                 WHERE id = ?",
                params![label, client, id],
            )?;
        }
        return Ok(id);
    }
    conn.execute(
        "INSERT INTO site (hostname, label, client, created_at) VALUES (?, ?, ?, ?)",
        params![hostname, label, client, utcnow()],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Record permission to probe one host for exposed endpoints. Deliberately
/// per host and deliberately durable: asking on every run trains people to
/// click through it; a config flag applies to whoever comes next.
pub fn authorise_probe(
    conn: &Connection,
    hostname: &str,
    by: &str,
    note: Option<&str>,
) -> Result<i64> {
    let site_id = upsert_site(conn, hostname, None, None)?;
    conn.execute(
        "UPDATE site SET probe_authorised_at = ?, probe_authorised_by = ?, \
         probe_note = ? WHERE id = ?",
        params![utcnow(), by, note, site_id],
    )?;
    Ok(site_id)
}

/// Returns whether an authorisation was actually withdrawn.
///
/// Keyed on the authorisation, not on the site row: revoking a site that
/// was never authorised must not report "Revoked". Telling somebody you
/// withdrew permission that never existed is a small lie in the one part of
/// this feature that exists to keep an honest record.
pub fn revoke_probe(conn: &Connection, hostname: &str) -> Result<bool> {
    let row: Option<i64> = conn
        .query_row(
            "SELECT id FROM site WHERE hostname = ? AND probe_authorised_at IS NOT NULL",
            params![hostname],
            |row| row.get(0),
        )
        .optional()?;
    let Some(id) = row else {
        return Ok(false);
    };
    conn.execute(
        "UPDATE site SET probe_authorised_at = NULL, probe_authorised_by = NULL, \
         probe_note = NULL WHERE id = ?",
        params![id],
    )?;
    Ok(true)
}

/// Every host cleared for probing, with who cleared it and when.
pub fn authorised_probe_hosts(conn: &Connection) -> Result<HashMap<String, Json>> {
    let mut stmt = conn.prepare(
        "SELECT hostname, probe_authorised_at, probe_authorised_by, probe_note \
         FROM site WHERE probe_authorised_at IS NOT NULL",
    )?;
    let rows = rows_to_json(&mut stmt, &[])?;
    Ok(rows
        .into_iter()
        .map(|row| {
            let host = row["hostname"].as_str().unwrap_or_default().to_lowercase();
            (host, row)
        })
        .collect())
}

pub fn create_run(
    conn: &Connection,
    batch_id: &str,
    site_id: i64,
    slap_version: &str,
    schema_version: i64,
    git_sha: Option<&str>,
) -> Result<i64> {
    conn.execute(
        "INSERT INTO run (batch_id, site_id, started_at, status, slap_version, \
         schema_version, git_sha) VALUES (?, ?, ?, ?, ?, ?, ?)",
        params![
            batch_id,
            site_id,
            utcnow(),
            RunStatus::Running.as_str(),
            slap_version,
            schema_version,
            git_sha
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn finish_run(
    conn: &Connection,
    run_id: i64,
    status: RunStatus,
    error: Option<&str>,
) -> Result<()> {
    conn.execute(
        "UPDATE run SET status = ?, finished_at = ?, error = ? WHERE id = ?",
        params![status.as_str(), utcnow(), error, run_id],
    )?;
    Ok(())
}

/// Record which engine produced a run. Reports without this get argued with.
pub fn set_run_provenance(
    conn: &Connection,
    run_id: i64,
    lh_version: Option<&str>,
    chrome_version: Option<&str>,
    throttling_profile: Option<&str>,
) -> Result<()> {
    conn.execute(
        "UPDATE run SET lh_version = COALESCE(?, lh_version), \
         chrome_version = COALESCE(?, chrome_version), \
         throttling_profile = COALESCE(?, throttling_profile) WHERE id = ?",
        params![lh_version, chrome_version, throttling_profile, run_id],
    )?;
    Ok(())
}

pub struct NewPage<'a> {
    pub url: &'a str,
    pub final_url: Option<&'a str>,
    pub form_factor: FormFactor,
    pub role: PageRole,
    pub discovered_via: DiscoveredVia,
    pub audit_depth: AuditDepth,
    pub template_class: Option<&'a str>,
}

impl<'a> NewPage<'a> {
    /// The defaults describe a single manually supplied page, which is what
    /// a one-URL audit is, so callers that predate per-page keep meaning
    /// the same thing.
    pub fn new(url: &'a str) -> Self {
        Self {
            url,
            final_url: None,
            form_factor: FormFactor::None,
            role: PageRole::Home,
            discovered_via: DiscoveredVia::Manual,
            audit_depth: AuditDepth::Light,
            template_class: None,
        }
    }
}

pub fn create_page(conn: &Connection, run_id: i64, page: &NewPage<'_>) -> Result<i64> {
    conn.execute(
        "INSERT INTO page (run_id, url, final_url, form_factor, role, \
         discovered_via, audit_depth, template_class) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        params![
            run_id,
            page.url,
            page.final_url,
            page.form_factor.as_str(),
            page.role.as_str(),
            page.discovered_via.as_str(),
            page.audit_depth.as_str(),
            page.template_class
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn insert_observations(
    conn: &Connection,
    page_id: i64,
    observations: &[Observation],
) -> Result<usize> {
    if observations.is_empty() {
        return Ok(0);
    }
    let mut stmt = conn.prepare(
        "INSERT INTO observation (page_id, source, metric_key, numeric_value, \
         text_value, unit) VALUES (?, ?, ?, ?, ?, ?)",
    )?;
    for o in observations {
        stmt.execute(params![
            page_id,
            o.source.as_str(),
            o.metric_key,
            o.numeric_value,
            o.text_value,
            o.unit.as_str()
        ])?;
    }
    Ok(observations.len())
}

pub fn insert_findings(conn: &Connection, page_id: i64, findings: &[Finding]) -> Result<usize> {
    if findings.is_empty() {
        return Ok(0);
    }
    let mut stmt = conn.prepare(
        "INSERT INTO finding (page_id, rule_id, severity, title, detail, \
         evidence_json, impact_ms, effort, remediation, wp_rocket_setting) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )?;
    for f in findings {
        let evidence = if f.evidence.is_empty() {
            None
        } else {
            Some(Json::Object(f.evidence.clone()).to_string())
        };
        stmt.execute(params![
            page_id,
            f.rule_id,
            f.severity.as_str(),
            f.title,
            f.detail,
            evidence,
            f.impact_ms,
            f.effort,
            f.remediation,
            f.wp_rocket_setting
        ])?;
    }
    Ok(findings.len())
}

pub fn insert_artifact(
    conn: &Connection,
    run_id: i64,
    kind: &str,
    path: &str,
    page_id: Option<i64>,
    sha256: Option<&str>,
    size: Option<i64>,
) -> Result<i64> {
    conn.execute(
        "INSERT INTO artifact (run_id, page_id, kind, path, sha256, bytes) \
         VALUES (?, ?, ?, ?, ?, ?)",
        params![run_id, page_id, kind, path, sha256, size],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn get_artifacts(conn: &Connection, run_id: i64) -> Result<Vec<Json>> {
    let mut stmt = conn.prepare("SELECT * FROM artifact WHERE run_id = ? ORDER BY id")?;
    rows_to_json(&mut stmt, &[sql_int(run_id)])
}

#[derive(Debug, Clone)]
pub struct CruxPoint {
    pub period_end: String,
    pub period_start: String,
    pub metric_key: String,
    pub p75: Option<f64>,
    pub good: Option<f64>,
    pub needs_improvement: Option<f64>,
    pub poor: Option<f64>,
}

/// Upsert weekly periods for one origin.
///
/// ON CONFLICT UPDATE rather than IGNORE: Google can revise a recent period
/// as late data lands, and the newer answer is the better one.
pub fn insert_crux_history(
    conn: &Connection,
    origin: &str,
    form_factor: &str,
    points: &[CruxPoint],
) -> Result<usize> {
    if points.is_empty() {
        return Ok(0);
    }
    let mut stmt = conn.prepare(
        "INSERT INTO crux_history (origin, form_factor, period_end, period_start, \
         metric_key, p75, good, needs_improvement, poor, fetched_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
         ON CONFLICT(origin, form_factor, period_end, metric_key) DO UPDATE SET \
         p75=excluded.p75, good=excluded.good, \
         needs_improvement=excluded.needs_improvement, poor=excluded.poor, \
         period_start=excluded.period_start, fetched_at=excluded.fetched_at",
    )?;
    let now = utcnow();
    for point in points {
        stmt.execute(params![
            origin,
            form_factor,
            point.period_end,
            point.period_start,
            point.metric_key,
            point.p75,
            point.good,
            point.needs_improvement,
            point.poor,
            now
        ])?;
    }
    Ok(points.len())
}

/// One metric's weekly series for an origin, oldest first. Oldest first
/// because it is plotted left to right, and reversing a list in a template
/// is the kind of computation templates must not do.
pub fn crux_history(
    conn: &Connection,
    origin: &str,
    metric_key: &str,
    form_factor: &str,
    limit: i64,
) -> Result<Vec<Json>> {
    let mut stmt = conn.prepare(
        "SELECT period_start, period_end, p75, good, needs_improvement, poor \
         FROM crux_history WHERE origin = ? AND form_factor = ? AND metric_key = ? \
         ORDER BY period_end DESC LIMIT ?",
    )?;
    let mut rows = rows_to_json(
        &mut stmt,
        &[
            sql_text(origin),
            sql_text(form_factor),
            sql_text(metric_key),
            sql_int(limit),
        ],
    )?;
    rows.reverse();
    Ok(rows)
}

pub fn crux_history_origins(conn: &Connection) -> Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT DISTINCT origin FROM crux_history ORDER BY origin")?;
    let origins = stmt
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<_>>()?;
    Ok(origins)
}

// ---------------------------------------------------------------------------
// Reads. The UI calls these; they must stay cheap.
// ---------------------------------------------------------------------------

pub fn get_run(conn: &Connection, run_id: i64) -> Result<Option<Json>> {
    one_json(
        conn,
        "SELECT run.*, site.hostname, site.label, site.client \
         FROM run JOIN site ON site.id = run.site_id WHERE run.id = ?",
        &[sql_int(run_id)],
    )
}

pub fn list_runs(conn: &Connection, batch_id: Option<&str>, limit: i64) -> Result<Vec<Json>> {
    let mut sql = String::from(
        "SELECT run.*, site.hostname, site.label, site.client, \
         (SELECT COUNT(DISTINCT f.rule_id) FROM finding f JOIN page p ON p.id = f.page_id \
          WHERE p.run_id = run.id) AS finding_count, \
         (SELECT COUNT(*) FROM page p WHERE p.run_id = run.id) AS page_count \
         FROM run JOIN site ON site.id = run.site_id ",
    );
    let mut params_vec: Vec<rusqlite::types::Value> = Vec::new();
    if let Some(batch) = batch_id {
        sql.push_str("WHERE run.batch_id = ? ");
        params_vec.push(sql_text(batch));
    }
    sql.push_str("ORDER BY run.started_at DESC, run.id DESC LIMIT ?");
    params_vec.push(sql_int(limit));
    let mut stmt = conn.prepare(&sql)?;
    rows_to_json(&mut stmt, &params_vec)
}

pub fn list_batches(conn: &Connection, limit: i64) -> Result<Vec<Json>> {
    let mut stmt = conn.prepare(
        "SELECT batch_id, MIN(started_at) AS started_at, MAX(finished_at) AS finished_at, \
         COUNT(*) AS run_count, \
         SUM(status = 'completed') AS completed, \
         SUM(status = 'failed') AS failed, \
         SUM(status = 'cancelled') AS cancelled, \
         SUM(status = 'running') AS running \
         FROM run GROUP BY batch_id ORDER BY MIN(started_at) DESC LIMIT ?",
    )?;
    rows_to_json(&mut stmt, &[sql_int(limit)])
}

pub fn get_observations(conn: &Connection, run_id: i64) -> Result<Vec<Json>> {
    let mut stmt = conn.prepare(
        "SELECT o.*, p.url, p.final_url, p.form_factor FROM observation o \
         JOIN page p ON p.id = o.page_id WHERE p.run_id = ? ORDER BY o.id",
    )?;
    rows_to_json(&mut stmt, &[sql_int(run_id)])
}

pub fn get_findings(conn: &Connection, run_id: i64) -> Result<Vec<Json>> {
    let mut stmt = conn.prepare(
        "SELECT f.*, p.url FROM finding f JOIN page p ON p.id = f.page_id \
         WHERE p.run_id = ? ORDER BY \
         CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 \
         WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, f.id",
    )?;
    rows_to_json(&mut stmt, &[sql_int(run_id)])
}

/// Every page of a run, home first, with its finding counts. Home first
/// because it is the page the verdict speaks about and the one a reader
/// looks for; the rest follow in discovery order.
pub fn run_pages(conn: &Connection, run_id: i64) -> Result<Vec<Json>> {
    let mut stmt = conn.prepare(
        "SELECT p.*, \
         (SELECT COUNT(*) FROM finding f WHERE f.page_id = p.id) AS finding_count, \
         (SELECT COUNT(*) FROM finding f WHERE f.page_id = p.id \
           AND f.severity IN ('critical', 'high')) AS urgent_count, \
         (SELECT COUNT(*) FROM observation o WHERE o.page_id = p.id) AS observation_count \
         FROM page p WHERE p.run_id = ? \
         ORDER BY CASE p.role WHEN 'home' THEN 0 WHEN 'template' THEN 1 ELSE 2 END, p.id",
    )?;
    rows_to_json(&mut stmt, &[sql_int(run_id)])
}

/// The run's anchor page. Falls back to the lowest page id, because a
/// database migrated from before per-page has every row defaulted to 'home'
/// and a run written by a future bug might have none. Returning None here
/// would blank a report that has perfectly good data in it.
pub fn home_page_id(conn: &Connection, run_id: i64) -> Result<Option<i64>> {
    conn.query_row(
        "SELECT id FROM page WHERE run_id = ? \
         ORDER BY CASE role WHEN 'home' THEN 0 ELSE 1 END, id LIMIT 1",
        params![run_id],
        |row| row.get(0),
    )
    .optional()
}

/// Flatten one page's observations into `{metric_key: value}`. This is what
/// the findings engine and the report templates consume.
pub fn observations_as_dict(conn: &Connection, page_id: i64) -> Result<HashMap<String, Value>> {
    let mut stmt = conn.prepare(
        "SELECT metric_key, numeric_value, text_value, unit FROM observation \
         WHERE page_id = ?",
    )?;
    let mut rows = stmt.query(params![page_id])?;
    let mut out = HashMap::new();
    while let Some(row) = rows.next()? {
        let key: String = row.get(0)?;
        let numeric: Option<f64> = row.get(1)?;
        let text: Option<String> = row.get(2)?;
        let unit: String = row.get(3)?;
        let value = match (numeric, text) {
            (Some(n), _) if unit == Unit::Bool.as_str() => Value::Bool(n != 0.0),
            (Some(n), _) => Value::Num(n),
            (None, Some(t)) => Value::Text(t),
            (None, None) => continue,
        };
        out.insert(key, value);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Site-centric reads. The batch is a scheduling detail; the site is what
// anyone actually asks about.
// ---------------------------------------------------------------------------

/// A run whose observations are empty produced no findings by design, and
/// its metrics are meaningless. Trend lines and verdicts must skip these or
/// an unreachable host reads as a score of zero.
const COMPLETED: &str = "run.status = 'completed'";

/// Every site with its latest completed run summarised onto it.
///
/// `finding_count` counts DISTINCT rule ids, not finding rows: once a run
/// holds twenty pages, "no HSTS header" is twenty rows describing one
/// problem, and 240 open findings against a site with twelve real problems
/// is worse than useless. `finding_instances` keeps the raw total.
pub fn list_sites(conn: &Connection, limit: i64) -> Result<Vec<Json>> {
    let sql = format!(
        "WITH latest AS (\
            SELECT site_id, MAX(id) AS run_id FROM run WHERE {COMPLETED} GROUP BY site_id\
        )\
        SELECT \
            site.id, site.hostname, site.label, site.client, \
            r.id            AS latest_run_id, \
            r.started_at    AS last_audited, \
            r.lh_version, r.chrome_version, \
            (SELECT COUNT(*) FROM run WHERE run.site_id = site.id) AS run_count, \
            (SELECT COUNT(*) FROM page p WHERE p.run_id = r.id) AS page_count, \
            (SELECT COUNT(DISTINCT f.rule_id) FROM finding f JOIN page p ON p.id = f.page_id \
              WHERE p.run_id = r.id) AS finding_count, \
            (SELECT COUNT(DISTINCT f.rule_id) FROM finding f JOIN page p ON p.id = f.page_id \
              WHERE p.run_id = r.id AND f.severity IN ('critical', 'high')) AS urgent_count, \
            (SELECT COUNT(*) FROM finding f JOIN page p ON p.id = f.page_id \
              WHERE p.run_id = r.id) AS finding_instances \
        FROM site \
        LEFT JOIN latest ON latest.site_id = site.id \
        LEFT JOIN run r ON r.id = latest.run_id \
        ORDER BY site.hostname LIMIT ?"
    );
    let mut stmt = conn.prepare(&sql)?;
    rows_to_json(&mut stmt, &[sql_int(limit)])
}

/// One row per completed run, oldest first, with the named metrics on it.
///
/// **The trend follows the home page and only the home page.** Joining
/// every page of a run produces one row per page per metric and the chart
/// would plot an arbitrary page's LCP. A trend line has to track a stable
/// subject or it is noise rendered as a line.
pub fn site_metric_history(
    conn: &Connection,
    site_id: i64,
    metric_keys: &[&str],
    limit: usize,
) -> Result<Vec<Json>> {
    if metric_keys.is_empty() {
        return Ok(Vec::new());
    }
    let marks = vec!["?"; metric_keys.len()].join(",");
    let sql = format!(
        "WITH anchor AS (\
            SELECT run_id, MIN(CASE WHEN role = 'home' THEN id END) AS home_id, \
                   MIN(id) AS first_id \
            FROM page GROUP BY run_id\
        )\
        SELECT run.id AS run_id, run.started_at, run.status, \
               o.metric_key, o.numeric_value \
        FROM run \
        JOIN anchor a ON a.run_id = run.id \
        JOIN page p ON p.id = COALESCE(a.home_id, a.first_id) \
        LEFT JOIN observation o ON o.page_id = p.id AND o.metric_key IN ({marks}) \
        WHERE run.site_id = ? AND {COMPLETED} \
        ORDER BY run.started_at, run.id"
    );
    let mut params_vec: Vec<rusqlite::types::Value> =
        metric_keys.iter().map(|key| sql_text(key)).collect();
    params_vec.push(sql_int(site_id));

    let mut stmt = conn.prepare(&sql)?;
    let rows = rows_to_json(&mut stmt, &params_vec)?;

    // Group by run, preserving run order, mirroring the Python dict build.
    let mut order: Vec<i64> = Vec::new();
    let mut by_run: HashMap<i64, Json> = HashMap::new();
    for row in rows {
        let run_id = row["run_id"].as_i64().unwrap_or_default();
        let entry = by_run.entry(run_id).or_insert_with(|| {
            order.push(run_id);
            json!({"run_id": row["run_id"], "started_at": row["started_at"]})
        });
        if let Some(metric_key) = row["metric_key"].as_str() {
            entry[metric_key] = row["numeric_value"].clone();
        }
    }
    let start = order.len().saturating_sub(limit);
    Ok(order[start..]
        .iter()
        .map(|run_id| by_run.remove(run_id).expect("grouped above"))
        .collect())
}

pub fn get_site(conn: &Connection, site_id: i64) -> Result<Option<Json>> {
    one_json(conn, "SELECT * FROM site WHERE id = ?", &[sql_int(site_id)])
}

pub fn find_site_by_hostname(conn: &Connection, hostname: &str) -> Result<Option<Json>> {
    one_json(
        conn,
        "SELECT * FROM site WHERE hostname = ?",
        &[sql_text(hostname)],
    )
}

pub fn site_runs(conn: &Connection, site_id: i64, limit: i64) -> Result<Vec<Json>> {
    let mut stmt = conn.prepare(
        "SELECT run.*, \
         (SELECT COUNT(DISTINCT f.rule_id) FROM finding f JOIN page p ON p.id = f.page_id \
           WHERE p.run_id = run.id) AS finding_count, \
         (SELECT COUNT(*) FROM page p WHERE p.run_id = run.id) AS page_count \
         FROM run WHERE run.site_id = ? \
         ORDER BY run.started_at DESC, run.id DESC LIMIT ?",
    )?;
    rows_to_json(&mut stmt, &[sql_int(site_id), sql_int(limit)])
}

/// Open findings grouped by rule, with the sites they affect. "Open" means
/// present in each site's most recent completed run, the only definition
/// that does not double-count history.
pub fn findings_across_sites(conn: &Connection, limit: i64) -> Result<Vec<Json>> {
    let sql = format!(
        "WITH latest AS (\
            SELECT site_id, MAX(id) AS run_id FROM run WHERE {COMPLETED} GROUP BY site_id\
        )\
        SELECT \
            f.rule_id, \
            MIN(f.severity)             AS severity, \
            MIN(f.title)                AS title, \
            MIN(f.effort)               AS effort, \
            MIN(f.wp_rocket_setting)    AS wp_rocket_setting, \
            COUNT(DISTINCT site.id)     AS site_count, \
            COUNT(DISTINCT p.id)        AS page_count, \
            GROUP_CONCAT(DISTINCT site.hostname) AS hostnames \
        FROM latest \
        JOIN run   ON run.id = latest.run_id \
        JOIN site  ON site.id = latest.site_id \
        JOIN page p ON p.run_id = run.id \
        JOIN finding f ON f.page_id = p.id \
        GROUP BY f.rule_id \
        ORDER BY \
          CASE MIN(f.severity) WHEN 'critical' THEN 0 WHEN 'high' THEN 1 \
               WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, \
          COUNT(DISTINCT site.id) DESC \
        LIMIT ?"
    );
    let mut stmt = conn.prepare(&sql)?;
    rows_to_json(&mut stmt, &[sql_int(limit)])
}

pub fn count_sites_with_a_completed_run(conn: &Connection) -> Result<i64> {
    conn.query_row(
        &format!("SELECT COUNT(DISTINCT site_id) FROM run WHERE {COMPLETED}"),
        [],
        |row| row.get(0),
    )
}

// ---------------------------------------------------------------------------
// Clearing everything. The one deliberate exception to append-only.
// ---------------------------------------------------------------------------

/// What a wipe would remove. Shown BEFORE the confirmation, because "delete
/// everything" is only an informed decision when "everything" is a number.
pub fn history_totals(conn: &Connection) -> Result<HashMap<&'static str, i64>> {
    let mut totals = HashMap::new();
    for (name, table) in [
        ("sites", "site"),
        ("runs", "run"),
        ("pages", "page"),
        ("observations", "observation"),
        ("findings", "finding"),
        ("artifacts", "artifact"),
        ("crux_weeks", "crux_history"),
    ] {
        let count: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })?;
        totals.insert(name, count);
    }
    Ok(totals)
}

/// Delete every row of audit history. Returns counts and artifact paths.
///
/// Runs are immutable and append-only; that is a promise about what the APP
/// does to history, not a lock against the operator choosing a fresh start.
/// The rule this operation answers to instead is the confirmation seam
/// above it. Deletion leans on the schema's cascades; the artifact FILES
/// are returned for the caller to remove. VACUUM afterwards, outside the
/// transaction because SQLite requires that.
pub fn clear_history(conn: &mut Connection) -> Result<(HashMap<&'static str, i64>, Vec<String>)> {
    let totals = history_totals(conn)?;
    let artifact_paths: Vec<String> = {
        let mut stmt = conn.prepare("SELECT path FROM artifact")?;
        let paths = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<_>>()?;
        paths
    };
    let tx = conn.transaction()?;
    tx.execute("DELETE FROM run", [])?;
    tx.execute("DELETE FROM site", [])?;
    tx.execute("DELETE FROM crux_history", [])?;
    tx.commit()?;
    conn.execute("VACUUM", [])?;
    Ok((totals, artifact_paths))
}

/// Remove ONE site and all of its history: its runs (which cascade to pages,
/// observations, findings and artifacts), plus the origin's cached CrUX
/// history, which is decoupled from sites and so is matched by host. Returns
/// the number of runs removed and the artifact file paths, which live outside
/// the database for the caller to unlink.
///
/// Answers to the same confirmation seam as `clear_history`: append-only is a
/// promise about what the app does on its own, not a lock against the operator
/// removing a site they added.
pub fn delete_site(conn: &mut Connection, site_id: i64) -> Result<(i64, Vec<String>)> {
    let artifact_paths: Vec<String> = {
        let mut stmt = conn.prepare(
            "SELECT a.path FROM artifact a JOIN run r ON r.id = a.run_id \
             WHERE r.site_id = ?",
        )?;
        let paths = stmt
            .query_map([site_id], |row| row.get::<_, String>(0))?
            .collect::<Result<_>>()?;
        paths
    };
    let hostname: Option<String> = conn
        .query_row("SELECT hostname FROM site WHERE id = ?", [site_id], |row| {
            row.get(0)
        })
        .optional()?;

    let tx = conn.transaction()?;
    // `run` -> `site` is NOT ON DELETE CASCADE, so runs are removed explicitly;
    // pages, observations, findings and artifacts cascade from the run.
    let runs = tx.execute("DELETE FROM run WHERE site_id = ?", [site_id])? as i64;
    if let Some(host) = &hostname {
        // crux_history is origin-keyed (scheme://host[:port]); remove the rows
        // whose authority is this host, with or without a port.
        tx.execute(
            "DELETE FROM crux_history \
             WHERE origin LIKE '%//' || ?1 OR origin LIKE '%//' || ?1 || ':%'",
            [host],
        )?;
    }
    tx.execute("DELETE FROM site WHERE id = ?", [site_id])?;
    tx.commit()?;
    Ok((runs, artifact_paths))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{obs, Severity};

    fn scratch() -> (tempfile::TempDir, Connection) {
        let dir = tempfile::tempdir().unwrap();
        let conn = open_db(&dir.path().join("t.sqlite3")).unwrap();
        (dir, conn)
    }

    fn seed_run(conn: &Connection, host: &str, status: RunStatus) -> (i64, i64, i64) {
        let site = upsert_site(conn, host, None, None).unwrap();
        let run = create_run(conn, "batch-1", site, "0.1.0", 1, None).unwrap();
        let page = create_page(conn, run, &NewPage::new(&format!("https://{host}/"))).unwrap();
        finish_run(conn, run, status, None).unwrap();
        (site, run, page)
    }

    #[test]
    fn delete_site_removes_only_that_sites_history() {
        let (_dir, mut conn) = scratch();
        let (site_a, run_a, page_a) = seed_run(&conn, "keep.example", RunStatus::Completed);
        let (site_b, run_b, page_b) = seed_run(&conn, "drop.example", RunStatus::Completed);
        insert_observations(&conn, page_a, &[obs("http.version", crate::schema::Value::from("h2")).unwrap()]).unwrap();
        insert_observations(&conn, page_b, &[obs("http.version", crate::schema::Value::from("h2")).unwrap()]).unwrap();
        let now = utcnow();
        for origin in ["https://keep.example", "https://drop.example"] {
            conn.execute(
                "INSERT INTO crux_history (origin, form_factor, period_end, period_start, \
                 metric_key, p75, good, needs_improvement, poor, fetched_at) \
                 VALUES (?1, 'PHONE', '2026-01-01', '2025-12-04', 'crux.lcp.p75', \
                 1200.0, 0.9, 0.08, 0.02, ?2)",
                [origin, now.as_str()],
            )
            .unwrap();
        }

        let (runs, _artifacts) = delete_site(&mut conn, site_b).unwrap();
        assert_eq!(runs, 1, "one run removed");
        assert!(get_site(&conn, site_b).unwrap().is_none(), "dropped site is gone");
        assert!(get_site(&conn, site_a).unwrap().is_some(), "kept site is intact");
        assert!(
            run_pages(&conn, run_b).unwrap().is_empty(),
            "the dropped run's pages cascaded away"
        );

        let crux_count = |origin: &str| {
            conn.query_row(
                "SELECT COUNT(*) FROM crux_history WHERE origin = ?",
                [origin],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
        };
        assert_eq!(crux_count("https://drop.example"), 0, "dropped origin's crux history removed");
        assert_eq!(crux_count("https://keep.example"), 1, "kept origin's crux history intact");

        let kept_obs: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM observation o JOIN page p ON p.id = o.page_id \
                 WHERE p.run_id = ?",
                [run_a],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(kept_obs, 1, "the kept site's observations survive");
    }

    #[test]
    fn utcnow_matches_the_python_apps_format() {
        // datetime.now(timezone.utc).isoformat(timespec="seconds") gives
        // 2026-08-27T21:30:00+00:00. Both apps sort each other's rows, so
        // this is a compatibility contract.
        let now = utcnow();
        let re = regex::Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00$").unwrap();
        assert!(re.is_match(&now), "unexpected timestamp shape: {now}");
    }

    #[test]
    fn open_db_creates_the_schema_in_wal_mode() {
        let (_dir, conn) = scratch();
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert_eq!(mode.to_lowercase(), "wal");
        for table in [
            "site",
            "run",
            "page",
            "observation",
            "finding",
            "artifact",
            "crux_history",
        ] {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE name = ?",
                    params![table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "missing table {table}");
        }
    }

    #[test]
    fn a_full_write_and_read_roundtrip() {
        let (_dir, conn) = scratch();
        let site_id = upsert_site(&conn, "example.com", Some("Example"), None).unwrap();
        let run_id = create_run(&conn, "b1", site_id, "0.1.0", 1, None).unwrap();
        let page_id = create_page(&conn, run_id, &NewPage::new("https://example.com/")).unwrap();

        insert_observations(
            &conn,
            page_id,
            &[
                obs("http.ttfb", Value::Num(412.0)).unwrap(),
                obs("http.compressed", Value::Bool(true)).unwrap(),
                obs("http.server", Value::from("nginx")).unwrap(),
            ],
        )
        .unwrap();
        insert_findings(
            &conn,
            page_id,
            &[Finding {
                rule_id: "slow-ttfb".into(),
                severity: Severity::High,
                title: "TTFB is slow".into(),
                detail: "detail".into(),
                evidence: Map::new(),
                impact_ms: Some(412.0),
                effort: None,
                remediation: None,
                wp_rocket_setting: None,
            }],
        )
        .unwrap();
        finish_run(&conn, run_id, RunStatus::Completed, None).unwrap();

        // The flattened dict converts bool-unit rows back to booleans; the
        // findings engine depends on that.
        let values = observations_as_dict(&conn, page_id).unwrap();
        assert_eq!(values["http.ttfb"], Value::Num(412.0));
        assert_eq!(values["http.compressed"], Value::Bool(true));
        assert_eq!(values["http.server"], Value::Text("nginx".into()));

        let run = get_run(&conn, run_id).unwrap().unwrap();
        assert_eq!(run["hostname"], "example.com");
        assert_eq!(run["status"], "completed");

        let runs = list_runs(&conn, None, 10).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0]["finding_count"], 1);
        assert_eq!(runs[0]["page_count"], 1);
    }

    #[test]
    fn a_pre_per_page_database_is_migrated_not_recreated() {
        // A database from before per-page analysis: a four-column page with
        // no role/audit_depth, no probe columns, plus one run whose page has
        // a Lighthouse artifact.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old.sqlite3");
        {
            let old = Connection::open(&path).unwrap();
            old.execute_batch(
                "CREATE TABLE site (id INTEGER PRIMARY KEY, hostname TEXT NOT NULL UNIQUE, \
                     label TEXT, client TEXT, created_at TEXT NOT NULL);\
                 CREATE TABLE run (id INTEGER PRIMARY KEY, batch_id TEXT NOT NULL, \
                     site_id INTEGER NOT NULL, started_at TEXT NOT NULL, finished_at TEXT, \
                     status TEXT NOT NULL, error TEXT, slap_version TEXT NOT NULL, \
                     schema_version INTEGER NOT NULL, lh_version TEXT, chrome_version TEXT, \
                     throttling_profile TEXT, git_sha TEXT);\
                 CREATE TABLE page (id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL, \
                     url TEXT NOT NULL, final_url TEXT, form_factor TEXT NOT NULL);\
                 CREATE TABLE artifact (id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL, \
                     page_id INTEGER, kind TEXT NOT NULL, path TEXT NOT NULL, \
                     sha256 TEXT, bytes INTEGER);\
                 INSERT INTO site VALUES (1, 'old.example', NULL, NULL, '2026-01-01T00:00:00+00:00');\
                 INSERT INTO run VALUES (1, 'b', 1, '2026-01-01T00:00:00+00:00', NULL, \
                     'completed', NULL, '0.0.9', 1, NULL, NULL, NULL, NULL);\
                 INSERT INTO page VALUES (1, 1, 'https://old.example/', NULL, 'mobile');\
                 INSERT INTO page VALUES (2, 1, 'https://old.example/about', NULL, 'mobile');\
                 INSERT INTO artifact VALUES (1, 1, 1, 'lhr', '/tmp/x.json.gz', NULL, NULL);",
            )
            .unwrap();
        }

        let conn = open_db(&path).unwrap();

        // History is intact: the run row was migrated in place, not recreated.
        let version: String = conn
            .query_row("SELECT slap_version FROM run WHERE id = 1", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(version, "0.0.9");

        // Old rows defaulted onto the trend line, and the page that has a
        // Lighthouse artifact says the browser audit was attempted.
        let (role, depth): (String, String) = conn
            .query_row(
                "SELECT role, audit_depth FROM page WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(role, "home");
        assert_eq!(depth, "full");
        let depth2: String = conn
            .query_row("SELECT audit_depth FROM page WHERE id = 2", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(depth2, "light", "no artifact, no claimed browser audit");

        // And a second open applies nothing new.
        assert!(migrate(&conn).unwrap().is_empty());
    }

    #[test]
    fn trend_lines_skip_runs_that_did_not_complete() {
        let (_dir, conn) = scratch();
        let (site_id, run_a, page_a) = seed_run(&conn, "example.com", RunStatus::Completed);
        insert_observations(
            &conn,
            page_a,
            &[obs("lh.score.performance", Value::Num(80.0)).unwrap()],
        )
        .unwrap();
        // A failed run: an unreachable host must not read as a score of 0.
        let run_b = create_run(&conn, "b2", site_id, "0.1.0", 1, None).unwrap();
        let page_b = create_page(&conn, run_b, &NewPage::new("https://example.com/")).unwrap();
        insert_observations(
            &conn,
            page_b,
            &[obs("lh.score.performance", Value::Num(1.0)).unwrap()],
        )
        .unwrap();
        finish_run(&conn, run_b, RunStatus::Failed, Some("unreachable")).unwrap();

        let history = site_metric_history(&conn, site_id, &["lh.score.performance"], 60).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0]["run_id"].as_i64(), Some(run_a));
        assert_eq!(history[0]["lh.score.performance"], 80.0);
    }

    #[test]
    fn list_sites_summarises_the_latest_completed_run() {
        let (_dir, conn) = scratch();
        seed_run(&conn, "a.example", RunStatus::Completed);
        seed_run(&conn, "b.example", RunStatus::Failed);

        let sites = list_sites(&conn, 500).unwrap();
        assert_eq!(sites.len(), 2);
        let a = sites.iter().find(|s| s["hostname"] == "a.example").unwrap();
        let b = sites.iter().find(|s| s["hostname"] == "b.example").unwrap();
        assert!(a["latest_run_id"].is_i64());
        assert!(
            b["latest_run_id"].is_null(),
            "a failed run is not a latest run"
        );
    }

    #[test]
    fn revoking_a_probe_that_was_never_granted_says_so() {
        let (_dir, conn) = scratch();
        upsert_site(&conn, "example.com", None, None).unwrap();
        assert!(!revoke_probe(&conn, "example.com").unwrap());
        authorise_probe(&conn, "example.com", "austin", Some("client agreed")).unwrap();
        assert!(authorised_probe_hosts(&conn)
            .unwrap()
            .contains_key("example.com"));
        assert!(revoke_probe(&conn, "example.com").unwrap());
        assert!(authorised_probe_hosts(&conn).unwrap().is_empty());
    }

    #[test]
    fn crux_history_upserts_and_reads_oldest_first() {
        let (_dir, conn) = scratch();
        let point = |end: &str, p75: f64| CruxPoint {
            period_end: end.into(),
            period_start: "2026-01-01".into(),
            metric_key: "crux.lcp.p75".into(),
            p75: Some(p75),
            good: Some(0.5),
            needs_improvement: None,
            poor: None,
        };
        insert_crux_history(
            &conn,
            "https://example.com",
            "PHONE",
            &[point("2026-02-01", 2000.0), point("2026-01-25", 1900.0)],
        )
        .unwrap();
        // Google revised the newest period: the upsert takes the new value.
        insert_crux_history(
            &conn,
            "https://example.com",
            "PHONE",
            &[point("2026-02-01", 2100.0)],
        )
        .unwrap();

        let series =
            crux_history(&conn, "https://example.com", "crux.lcp.p75", "PHONE", 40).unwrap();
        assert_eq!(series.len(), 2);
        assert_eq!(series[0]["period_end"], "2026-01-25", "oldest first");
        assert_eq!(series[1]["p75"], 2100.0, "revised value won");
        assert_eq!(
            crux_history_origins(&conn).unwrap(),
            vec!["https://example.com"]
        );
    }

    #[test]
    fn home_page_id_falls_back_to_the_lowest_page() {
        let (_dir, conn) = scratch();
        let (_site, run_id, _page) = seed_run(&conn, "example.com", RunStatus::Completed);
        let mut discovered = NewPage::new("https://example.com/about");
        discovered.role = PageRole::Discovered;
        create_page(&conn, run_id, &discovered).unwrap();
        // Normal case: the home page wins.
        let home = home_page_id(&conn, run_id).unwrap().unwrap();
        let role: String = conn
            .query_row("SELECT role FROM page WHERE id = ?", params![home], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(role, "home");
    }

    #[test]
    fn clear_history_reports_what_it_removed_and_leaves_a_usable_database() {
        let (_dir, mut conn) = scratch();
        let (_s, run_id, page_id) = seed_run(&conn, "example.com", RunStatus::Completed);
        insert_artifact(
            &conn,
            run_id,
            "lhr",
            "/tmp/a.json.gz",
            Some(page_id),
            None,
            None,
        )
        .unwrap();

        let (totals, paths) = clear_history(&mut conn).unwrap();
        assert_eq!(totals["runs"], 1);
        assert_eq!(paths, vec!["/tmp/a.json.gz"]);
        // Cascades took the dependents with the run.
        for table in ["site", "run", "page", "observation", "finding", "artifact"] {
            let count: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0, "{table} not cleared");
        }
        // And the database still works.
        seed_run(&conn, "fresh.example", RunStatus::Completed);
        assert_eq!(count_sites_with_a_completed_run(&conn).unwrap(), 1);
    }
}
