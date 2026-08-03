"""SQLite storage. Immutable, append-only runs.

Qt-relevant design notes, decided here so the GUI phase is mechanical:

* **WAL is mandatory.** The GUI thread reads while the worker thread
  writes. Without ``journal_mode=WAL`` those block each other and the
  UI stutters, or worse, throws ``database is locked`` mid-batch.
* **One connection per thread.** ``sqlite3`` connections are not safe to
  share across threads. :func:`connect` keeps a thread-local handle, so
  the Qt main thread and the worker thread each get their own without
  any caller having to think about it.
* **Run status lives in the database, not in memory.** A front-end can
  close, crash, or reattach mid-batch and still render the truth.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .schema import (
    AuditDepth,
    DiscoveredVia,
    Finding,
    FormFactor,
    Observation,
    PageRole,
    RunStatus,
)

DDL = """
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
"""

_local = threading.local()


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect(path: str | Path) -> sqlite3.Connection:
    """Return this thread's connection to ``path``, creating it if needed.

    The cache lookup must be ``is None``, never truthiness.
    ``close_thread_connections`` leaves the cache as an EMPTY dict, and the
    first version's ``getattr(...) or {}`` treated empty as absent: it built
    a fresh dict, and the ``hasattr`` guard then declined to store it. From
    the first close onward, every connection this thread opened went into a
    dict nothing kept — uncached, unclosable, held until process exit.

    One command per process never notices; the leaked handles die with the
    process. A test suite is many commands in one process, and on Windows an
    open database cannot be deleted (SQLite opens without
    FILE_SHARE_DELETE), so the leak surfaced as ``WinError 32`` in
    `slap verify`'s scratch cleanup — two tests, deterministically, and only
    on Windows, pointing at everything except this line.
    """
    path = str(Path(path).expanduser())
    cache: dict[str, sqlite3.Connection] | None = getattr(_local, "conns", None)
    if cache is None:
        cache = _local.conns = {}
    conn = cache.get(path)
    if conn is not None:
        return conn

    if path != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    cache[path] = conn
    return conn


def close_thread_connections() -> None:
    """Close every connection this thread opened. Call on worker shutdown."""
    for conn in getattr(_local, "conns", {}).values():
        try:
            conn.close()
        except sqlite3.Error:
            pass
    _local.conns = {}
    # And forget which databases were initialised, so the next init_db on
    # this thread re-checks from scratch. A test that closes, deletes the
    # file, and reopens the same path must get tables again.
    _local.initialised = set()


def migrate(conn: sqlite3.Connection) -> list[str]:
    """Bring an existing database up to the current DDL. Returns what it did.

    ``CREATE TABLE IF NOT EXISTS`` is a no-op on a table that already
    exists, so a column rename in the DDL does NOT reach a database
    created before it. The SALP-to-SLAP rename turned ``run.salp_version``
    into ``run.slap_version``, and without this an existing database keeps
    working right up until the first insert, which fails with "table run
    has no column named slap_version" partway through a batch.

    Kept deliberately small: rename in place, never copy, never drop. A
    run row is immutable history and losing it to a cosmetic rename would
    be a bad trade.
    """
    applied: list[str] = []
    tables = {row[0] for row in
              conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if "run" not in tables:
        return applied

    columns = {row[1] for row in conn.execute("PRAGMA table_info(run)")}
    if "salp_version" in columns and "slap_version" not in columns:
        # RENAME COLUMN needs SQLite 3.25 (2018). Python 3.11 ships well
        # past that, but say so clearly rather than failing obscurely.
        if sqlite3.sqlite_version_info < (3, 25):
            raise RuntimeError(
                f"SQLite {sqlite3.sqlite_version} cannot rename a column. "
                "This database was created before the SALP-to-SLAP rename "
                "and needs SQLite 3.25 or newer to upgrade."
            )
        conn.execute("ALTER TABLE run RENAME COLUMN salp_version TO slap_version")
        applied.append("run.salp_version -> run.slap_version")

    # Per-page analysis: a run gained the ability to hold more than one page,
    # and each page needs to say what it is and how deeply it was audited.
    #
    # These go here rather than in the DDL body for the same reason the rename
    # does: `CREATE TABLE IF NOT EXISTS` is a no-op against a table that
    # already exists, so a database created before this release would keep a
    # four-column `page` and fail on the first insert partway through a batch.
    # The DDL above carries them too, for databases created fresh.
    if "page" in tables:
        page_columns = {row[1] for row in conn.execute("PRAGMA table_info(page)")}
        # Every existing row is a single manually supplied page that had
        # whatever depth the run used. Defaulting `role` to 'home' is what
        # keeps old runs on the trend line: the queries that follow select the
        # home page, and a NULL role would silently drop all of history.
        for column, ddl in (
            ("role", "TEXT NOT NULL DEFAULT 'home'"),
            ("discovered_via", "TEXT NOT NULL DEFAULT 'manual'"),
            ("audit_depth", "TEXT NOT NULL DEFAULT 'light'"),
            ("template_class", "TEXT"),
        ):
            if column not in page_columns:
                conn.execute(f"ALTER TABLE page ADD COLUMN {column} {ddl}")
                applied.append(f"page.{column} added")

    # Probe authorisation. Added to `site` rather than to config, so it
    # survives a config rewrite and travels with the history it belongs to.
    if "site" in tables:
        site_columns = {row[1] for row in conn.execute("PRAGMA table_info(site)")}
        for column in ("probe_authorised_at", "probe_authorised_by", "probe_note"):
            if column not in site_columns:
                conn.execute(f"ALTER TABLE site ADD COLUMN {column} TEXT")
                applied.append(f"site.{column} added")

        # A pre-existing run whose page ran Lighthouse should say so, or its
        # report will claim the browser audit was never attempted. The
        # artifact table is the only record of that for historical rows.
        if any(a.endswith("page.audit_depth added") or a == "page.audit_depth added"
               for a in applied):
            cur = conn.execute(
                "UPDATE page SET audit_depth = 'full' WHERE id IN ("
                "  SELECT DISTINCT page_id FROM artifact WHERE page_id IS NOT NULL)"
            )
            if cur.rowcount > 0:
                applied.append(f"page.audit_depth = full for {cur.rowcount} historical rows")
    return applied


def init_db(path: str | Path) -> sqlite3.Connection:
    """Connect, migrating and creating tables on first touch only.

    Every core read funnels through here, and the first version ran the
    migration probe plus the full DDL script on every call: a dozen
    ``CREATE TABLE IF NOT EXISTS`` statements and a ``PRAGMA table_info``
    per site-list render, paid again for every row the web UI shows. The
    schema cannot change between calls within one process, so it is applied
    once per thread per path and remembered beside the connection cache
    (and forgotten with it, so ``close_thread_connections`` keeps its
    "clean slate" meaning).
    """
    key = str(Path(path).expanduser())
    # `is None`, never truthiness: the connection-cache bug two functions up
    # was `or {}` reading an empty cache as an absent one, and an empty SET
    # here is the normal state after close_thread_connections.
    done: set[str] | None = getattr(_local, "initialised", None)
    if done is None:
        done = _local.initialised = set()
    conn = connect(path)
    if key in done:
        return conn
    # Migrate BEFORE the DDL. Order matters only for clarity here, since
    # CREATE TABLE IF NOT EXISTS would not touch the old table anyway, but
    # it keeps "fix what exists, then create what does not" readable.
    migrate(conn)
    conn.executescript(DDL)
    conn.commit()
    done.add(key)
    return conn


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


# --------------------------------------------------------------------------
# Writes
# --------------------------------------------------------------------------

def authorise_probe(conn: sqlite3.Connection, hostname: str, *,
                    by: str, note: str | None = None) -> int:
    """Record permission to probe one host for exposed endpoints.

    Deliberately per host and deliberately durable. Asking on every run would
    train people to click through it; a config flag would apply to whoever
    comes next.
    """
    site_id = upsert_site(conn, hostname)
    conn.execute(
        "UPDATE site SET probe_authorised_at = ?, probe_authorised_by = ?, "
        "probe_note = ? WHERE id = ?",
        (utcnow(), by, note, site_id),
    )
    return site_id


def revoke_probe(conn: sqlite3.Connection, hostname: str) -> bool:
    """Returns whether an authorisation was actually withdrawn.

    Keyed on the authorisation, not on the site row: the first version
    asked only whether the hostname was known, so revoking a site that had
    never been authorised reported "Revoked for example.com". Telling
    somebody you withdrew permission that never existed is a small lie in
    the one part of this feature that exists to keep an honest record.
    """
    row = conn.execute(
        "SELECT id FROM site WHERE hostname = ? "
        "AND probe_authorised_at IS NOT NULL", (hostname,)).fetchone()
    if row is None:
        return False
    conn.execute(
        "UPDATE site SET probe_authorised_at = NULL, probe_authorised_by = NULL, "
        "probe_note = NULL WHERE id = ?", (row["id"],))
    return True


def authorised_probe_hosts(conn: sqlite3.Connection) -> dict[str, dict[str, Any]]:
    """Every host cleared for probing, with who cleared it and when."""
    rows = conn.execute(
        "SELECT hostname, probe_authorised_at, probe_authorised_by, probe_note "
        "FROM site WHERE probe_authorised_at IS NOT NULL"
    ).fetchall()
    return {r["hostname"].lower(): dict(r) for r in rows}


def upsert_site(conn: sqlite3.Connection, hostname: str, *,
                label: str | None = None, client: str | None = None) -> int:
    row = conn.execute("SELECT id FROM site WHERE hostname = ?", (hostname,)).fetchone()
    if row:
        if label or client:
            conn.execute(
                "UPDATE site SET label = COALESCE(?, label), client = COALESCE(?, client) "
                "WHERE id = ?",
                (label, client, row["id"]),
            )
        return int(row["id"])
    cur = conn.execute(
        "INSERT INTO site (hostname, label, client, created_at) VALUES (?, ?, ?, ?)",
        (hostname, label, client, utcnow()),
    )
    return int(cur.lastrowid)


def create_run(conn: sqlite3.Connection, *, batch_id: str, site_id: int,
               slap_version: str, schema_version: int,
               git_sha: str | None = None) -> int:
    cur = conn.execute(
        "INSERT INTO run (batch_id, site_id, started_at, status, slap_version, "
        "schema_version, git_sha) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (batch_id, site_id, utcnow(), RunStatus.RUNNING.value,
         slap_version, schema_version, git_sha),
    )
    return int(cur.lastrowid)


def finish_run(conn: sqlite3.Connection, run_id: int, status: RunStatus,
               error: str | None = None) -> None:
    conn.execute(
        "UPDATE run SET status = ?, finished_at = ?, error = ? WHERE id = ?",
        (status.value, utcnow(), error, run_id),
    )


def set_run_provenance(conn: sqlite3.Connection, run_id: int, *,
                       lh_version: str | None = None,
                       chrome_version: str | None = None,
                       throttling_profile: str | None = None) -> None:
    """Record which engine produced a run. Reports without this get argued with."""
    conn.execute(
        "UPDATE run SET lh_version = COALESCE(?, lh_version), "
        "chrome_version = COALESCE(?, chrome_version), "
        "throttling_profile = COALESCE(?, throttling_profile) WHERE id = ?",
        (lh_version, chrome_version, throttling_profile, run_id),
    )


def insert_artifact(conn: sqlite3.Connection, run_id: int, *, kind: str,
                    path: str, page_id: int | None = None,
                    sha256: str | None = None, size: int | None = None) -> int:
    cur = conn.execute(
        "INSERT INTO artifact (run_id, page_id, kind, path, sha256, bytes) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (run_id, page_id, kind, path, sha256, size),
    )
    return int(cur.lastrowid)


def get_artifacts(conn: sqlite3.Connection, run_id: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM artifact WHERE run_id = ? ORDER BY id", (run_id,)
    ).fetchall()
    return [dict(r) for r in rows]


def insert_crux_history(conn: sqlite3.Connection, origin: str,
                        form_factor: str, points: Iterable[dict[str, Any]]) -> int:
    """Upsert weekly periods for one origin.

    ON CONFLICT REPLACE rather than IGNORE: Google can revise a recent period
    as late data lands, and the newer answer is the better one. Older periods
    are stable, so in practice this rewrites the same values.
    """
    rows = [
        (origin, form_factor, p["period_end"], p["period_start"], p["metric_key"],
         p.get("p75"), p.get("good"), p.get("needs_improvement"), p.get("poor"),
         utcnow())
        for p in points
    ]
    if not rows:
        return 0
    conn.executemany(
        "INSERT INTO crux_history (origin, form_factor, period_end, period_start, "
        "metric_key, p75, good, needs_improvement, poor, fetched_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(origin, form_factor, period_end, metric_key) DO UPDATE SET "
        "p75=excluded.p75, good=excluded.good, "
        "needs_improvement=excluded.needs_improvement, poor=excluded.poor, "
        "period_start=excluded.period_start, fetched_at=excluded.fetched_at",
        rows,
    )
    return len(rows)


def crux_history(conn: sqlite3.Connection, origin: str, metric_key: str, *,
                 form_factor: str = "PHONE",
                 limit: int = 40) -> list[dict[str, Any]]:
    """One metric's weekly series for an origin, oldest first.

    Oldest first because it is plotted left to right, and reversing a list in
    a template is the kind of computation templates must not do.
    """
    rows = conn.execute(
        "SELECT period_start, period_end, p75, good, needs_improvement, poor "
        "FROM crux_history WHERE origin = ? AND form_factor = ? AND metric_key = ? "
        "ORDER BY period_end DESC LIMIT ?",
        (origin, form_factor, metric_key, limit),
    ).fetchall()
    return [dict(r) for r in reversed(rows)]


def crux_history_origins(conn: sqlite3.Connection) -> list[str]:
    return [r[0] for r in conn.execute(
        "SELECT DISTINCT origin FROM crux_history ORDER BY origin")]


def create_page(conn: sqlite3.Connection, run_id: int, url: str,
                final_url: str | None, form_factor: FormFactor,
                *, role: PageRole = PageRole.HOME,
                discovered_via: DiscoveredVia = DiscoveredVia.MANUAL,
                audit_depth: AuditDepth = AuditDepth.LIGHT,
                template_class: str | None = None) -> int:
    """Insert one page of a run.

    The keyword defaults describe a single manually supplied page, which is
    what a one-URL audit is, so callers that predate per-page keep working
    and keep meaning the same thing.
    """
    cur = conn.execute(
        "INSERT INTO page (run_id, url, final_url, form_factor, role, "
        "discovered_via, audit_depth, template_class) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (run_id, url, final_url, form_factor.value, role.value,
         discovered_via.value, audit_depth.value, template_class),
    )
    return int(cur.lastrowid)


def insert_observations(conn: sqlite3.Connection, page_id: int,
                        observations: Iterable[Observation]) -> int:
    rows = [
        (page_id, o.source.value, o.metric_key, o.numeric_value, o.text_value, o.unit.value)
        for o in observations
    ]
    if not rows:
        return 0
    conn.executemany(
        "INSERT INTO observation (page_id, source, metric_key, numeric_value, "
        "text_value, unit) VALUES (?, ?, ?, ?, ?, ?)",
        rows,
    )
    return len(rows)


def insert_findings(conn: sqlite3.Connection, page_id: int,
                    findings: Iterable[Finding]) -> int:
    import json

    rows = [
        (page_id, f.rule_id, f.severity.value, f.title, f.detail,
         json.dumps(f.evidence) if f.evidence else None,
         f.impact_ms, f.effort, f.remediation, f.wp_rocket_setting)
        for f in findings
    ]
    if not rows:
        return 0
    conn.executemany(
        "INSERT INTO finding (page_id, rule_id, severity, title, detail, "
        "evidence_json, impact_ms, effort, remediation, wp_rocket_setting) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        rows,
    )
    return len(rows)


# --------------------------------------------------------------------------
# Reads. The GUI calls these from the main thread; they must stay cheap.
# --------------------------------------------------------------------------

def get_run(conn: sqlite3.Connection, run_id: int) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT run.*, site.hostname, site.label, site.client "
        "FROM run JOIN site ON site.id = run.site_id WHERE run.id = ?",
        (run_id,),
    ).fetchone()
    return dict(row) if row else None


def list_runs(conn: sqlite3.Connection, *, batch_id: str | None = None,
              limit: int = 200) -> list[dict[str, Any]]:
    sql = (
        "SELECT run.*, site.hostname, site.label, site.client, "
        "  (SELECT COUNT(DISTINCT f.rule_id) FROM finding f JOIN page p ON p.id = f.page_id "
        "   WHERE p.run_id = run.id) AS finding_count, "
        "  (SELECT COUNT(*) FROM page p WHERE p.run_id = run.id) AS page_count "
        "FROM run JOIN site ON site.id = run.site_id "
    )
    params: list[Any] = []
    if batch_id:
        sql += "WHERE run.batch_id = ? "
        params.append(batch_id)
    sql += "ORDER BY run.started_at DESC, run.id DESC LIMIT ?"
    params.append(limit)
    return [dict(r) for r in conn.execute(sql, params).fetchall()]


def list_batches(conn: sqlite3.Connection, limit: int = 50) -> list[dict[str, Any]]:
    sql = (
        "SELECT batch_id, MIN(started_at) AS started_at, MAX(finished_at) AS finished_at, "
        "COUNT(*) AS run_count, "
        "SUM(status = 'completed') AS completed, "
        "SUM(status = 'failed') AS failed, "
        "SUM(status = 'cancelled') AS cancelled, "
        "SUM(status = 'running') AS running "
        "FROM run GROUP BY batch_id ORDER BY MIN(started_at) DESC LIMIT ?"
    )
    return [dict(r) for r in conn.execute(sql, (limit,)).fetchall()]


def get_observations(conn: sqlite3.Connection, run_id: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT o.*, p.url, p.final_url, p.form_factor FROM observation o "
        "JOIN page p ON p.id = o.page_id WHERE p.run_id = ? ORDER BY o.id",
        (run_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_findings(conn: sqlite3.Connection, run_id: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT f.*, p.url FROM finding f JOIN page p ON p.id = f.page_id "
        "WHERE p.run_id = ? ORDER BY "
        "CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
        "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, f.id",
        (run_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def run_pages(conn: sqlite3.Connection, run_id: int) -> list[dict[str, Any]]:
    """Every page of a run, home first, with its finding counts.

    Home first because it is the page the verdict speaks about and the one a
    reader looks for; the rest follow in discovery order.
    """
    sql = """
    SELECT p.*,
           (SELECT COUNT(*) FROM finding f WHERE f.page_id = p.id) AS finding_count,
           (SELECT COUNT(*) FROM finding f WHERE f.page_id = p.id
             AND f.severity IN ('critical', 'high')) AS urgent_count,
           (SELECT COUNT(*) FROM observation o WHERE o.page_id = p.id) AS observation_count
    FROM page p WHERE p.run_id = ?
    ORDER BY CASE p.role WHEN 'home' THEN 0 WHEN 'template' THEN 1 ELSE 2 END, p.id
    """
    return [dict(r) for r in conn.execute(sql, (run_id,)).fetchall()]


def home_page_id(conn: sqlite3.Connection, run_id: int) -> int | None:
    """The run's anchor page.

    Falls back to the lowest page id, because a database migrated from before
    per-page has every row defaulted to 'home' and a run written by a future
    bug might have none. Returning None here would blank a report that has
    perfectly good data in it.
    """
    row = conn.execute(
        "SELECT id FROM page WHERE run_id = ? "
        "ORDER BY CASE role WHEN 'home' THEN 0 ELSE 1 END, id LIMIT 1",
        (run_id,),
    ).fetchone()
    return int(row["id"]) if row else None


def observations_as_dict(conn: sqlite3.Connection, page_id: int) -> dict[str, Any]:
    """Flatten one page's observations into ``{metric_key: value}``.

    This is what the findings engine and the report templates consume.
    """
    out: dict[str, Any] = {}
    for r in conn.execute(
        "SELECT metric_key, numeric_value, text_value, unit FROM observation "
        "WHERE page_id = ?", (page_id,)
    ):
        if r["numeric_value"] is not None:
            out[r["metric_key"]] = (
                bool(r["numeric_value"]) if r["unit"] == "bool" else r["numeric_value"]
            )
        else:
            out[r["metric_key"]] = r["text_value"]
    return out


# --------------------------------------------------------------------------
# Site-centric reads
#
# The batch is a scheduling detail; the site is what anyone actually asks
# about. These queries exist because the UI is organised around "how is this
# site doing" and "did the fix work", and answering that from run rows in the
# front end would mean the front end knowing the schema.
# --------------------------------------------------------------------------

#: A run whose observations are empty produced no findings by design, and its
#: metrics are meaningless. Trend lines and verdicts must skip these or an
#: unreachable host reads as a score of zero.
_COMPLETED = "run.status = 'completed'"


def list_sites(conn: sqlite3.Connection, limit: int = 500) -> list[dict[str, Any]]:
    """Every site with its latest completed run summarised onto it.

    One query rather than N+1: a correlated subquery picks each site's newest
    completed run id, and everything else joins against that.

    ``finding_count`` counts DISTINCT rule ids, not finding rows. Once a run
    holds twenty pages, "no HSTS header" is twenty rows describing one
    problem, and a site list reporting 240 open findings against a site with
    twelve real problems is worse than useless: it is plausible, it renders
    perfectly, and it is wrong. ``finding_instances`` keeps the raw total for
    anywhere that genuinely wants pages-affected volume.
    """
    sql = f"""
    WITH latest AS (
        SELECT site_id, MAX(id) AS run_id
        FROM run WHERE {_COMPLETED} GROUP BY site_id
    )
    SELECT
        site.id, site.hostname, site.label, site.client,
        r.id            AS latest_run_id,
        r.started_at    AS last_audited,
        r.lh_version, r.chrome_version,
        (SELECT COUNT(*) FROM run WHERE run.site_id = site.id) AS run_count,
        (SELECT COUNT(*) FROM page p WHERE p.run_id = r.id) AS page_count,
        (SELECT COUNT(DISTINCT f.rule_id) FROM finding f JOIN page p ON p.id = f.page_id
          WHERE p.run_id = r.id) AS finding_count,
        (SELECT COUNT(DISTINCT f.rule_id) FROM finding f JOIN page p ON p.id = f.page_id
          WHERE p.run_id = r.id AND f.severity IN ('critical', 'high'))
                        AS urgent_count,
        (SELECT COUNT(*) FROM finding f JOIN page p ON p.id = f.page_id
          WHERE p.run_id = r.id) AS finding_instances
    FROM site
    LEFT JOIN latest ON latest.site_id = site.id
    LEFT JOIN run r ON r.id = latest.run_id
    ORDER BY site.hostname LIMIT ?
    """
    return [dict(r) for r in conn.execute(sql, (limit,)).fetchall()]


def site_metric_history(conn: sqlite3.Connection, site_id: int,
                        metric_keys: Sequence[str],
                        limit: int = 60) -> list[dict[str, Any]]:
    """One row per completed run, oldest first, with the named metrics on it.

    Oldest first because it is plotted left to right, and reversing a list in
    a template is exactly the kind of computation templates must not do.

    **The trend follows the home page and only the home page.** Joining every
    page of a run produces one row per page per metric, and the dict below
    keeps whichever arrived last, so the chart would plot an arbitrary page's
    LCP and change which page that is between runs. A trend line has to track
    a stable subject or it is noise rendered as a line, and the home page is
    the one page every run of every site is guaranteed to have.
    """
    if not metric_keys:
        return []
    marks = ",".join("?" * len(metric_keys))
    sql = f"""
    WITH anchor AS (
        SELECT run_id, MIN(CASE WHEN role = 'home' THEN id END) AS home_id,
               MIN(id) AS first_id
        FROM page GROUP BY run_id
    )
    SELECT run.id AS run_id, run.started_at, run.status,
           o.metric_key, o.numeric_value
    FROM run
    JOIN anchor a ON a.run_id = run.id
    JOIN page p ON p.id = COALESCE(a.home_id, a.first_id)
    LEFT JOIN observation o ON o.page_id = p.id AND o.metric_key IN ({marks})
    WHERE run.site_id = ? AND {_COMPLETED}
    ORDER BY run.started_at, run.id
    """
    rows = conn.execute(sql, (*metric_keys, site_id)).fetchall()

    by_run: dict[int, dict[str, Any]] = {}
    for row in rows:
        entry = by_run.setdefault(row["run_id"], {
            "run_id": row["run_id"], "started_at": row["started_at"],
        })
        if row["metric_key"] is not None:
            entry[row["metric_key"]] = row["numeric_value"]
    return list(by_run.values())[-limit:]


def get_site(conn: sqlite3.Connection, site_id: int) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM site WHERE id = ?", (site_id,)).fetchone()
    return dict(row) if row else None


def find_site_by_hostname(conn: sqlite3.Connection,
                          hostname: str) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT * FROM site WHERE hostname = ?", (hostname,)
    ).fetchone()
    return dict(row) if row else None


def site_runs(conn: sqlite3.Connection, site_id: int,
              limit: int = 100) -> list[dict[str, Any]]:
    sql = """
    SELECT run.*,
           (SELECT COUNT(DISTINCT f.rule_id) FROM finding f JOIN page p ON p.id = f.page_id
             WHERE p.run_id = run.id) AS finding_count,
           (SELECT COUNT(*) FROM page p WHERE p.run_id = run.id) AS page_count
    FROM run WHERE run.site_id = ?
    ORDER BY run.started_at DESC, run.id DESC LIMIT ?
    """
    return [dict(r) for r in conn.execute(sql, (site_id, limit)).fetchall()]


def findings_across_sites(conn: sqlite3.Connection,
                          limit: int = 200) -> list[dict[str, Any]]:
    """Open findings grouped by rule, with the sites they affect.

    "Open" means present in each site's most recent completed run, which is
    the only definition that does not double-count history: a rule that
    fired six months ago and was fixed is not an open finding.

    Titles carry formatted numbers that differ per site ("Images could load
    3.9s faster" versus "1.2s faster"), so the rule id is the identity and
    one title is carried through as a representative label.
    """
    sql = f"""
    WITH latest AS (
        SELECT site_id, MAX(id) AS run_id
        FROM run WHERE {_COMPLETED} GROUP BY site_id
    )
    SELECT
        f.rule_id,
        MIN(f.severity)             AS severity,
        MIN(f.title)                AS title,
        MIN(f.effort)               AS effort,
        MIN(f.wp_rocket_setting)    AS wp_rocket_setting,
        COUNT(DISTINCT site.id)     AS site_count,
        -- Pages, not finding rows. Both aggregates are DISTINCT on purpose:
        -- the join fans out to one row per page per finding, so a plain
        -- COUNT(*) would report a rule affecting 3 sites of 20 pages each as
        -- affecting 60 of something, without saying 60 of what.
        COUNT(DISTINCT p.id)        AS page_count,
        GROUP_CONCAT(DISTINCT site.hostname) AS hostnames
    FROM latest
    JOIN run   ON run.id = latest.run_id
    JOIN site  ON site.id = latest.site_id
    JOIN page p ON p.run_id = run.id
    JOIN finding f ON f.page_id = p.id
    GROUP BY f.rule_id
    ORDER BY
      CASE MIN(f.severity) WHEN 'critical' THEN 0 WHEN 'high' THEN 1
           WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
      COUNT(DISTINCT site.id) DESC
    LIMIT ?
    """
    return [dict(r) for r in conn.execute(sql, (limit,)).fetchall()]


def count_sites_with_a_completed_run(conn: sqlite3.Connection) -> int:
    return int(conn.execute(
        f"SELECT COUNT(DISTINCT site_id) FROM run WHERE {_COMPLETED}"
    ).fetchone()[0])


# --------------------------------------------------------------------------
# Clearing everything. The one deliberate exception to append-only.
# --------------------------------------------------------------------------

def history_totals(conn: sqlite3.Connection) -> dict[str, int]:
    """What a wipe would remove. Shown BEFORE the confirmation, because
    "delete everything" is only an informed decision when "everything" is a
    number."""
    def count(table: str) -> int:
        return int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])

    return {
        "sites": count("site"),
        "runs": count("run"),
        "pages": count("page"),
        "observations": count("observation"),
        "findings": count("finding"),
        "artifacts": count("artifact"),
        "crux_weeks": count("crux_history"),
    }


def clear_history(conn: sqlite3.Connection) -> dict[str, Any]:
    """Delete every row of audit history. Returns counts and artifact paths.

    Runs are immutable and append-only; that is a promise about what the
    APP does to history, not a lock against the operator choosing a fresh
    start. The rule this operation answers to instead is the confirmation
    seam above it: the caller shows what exists, requires a typed word, and
    refuses while a batch is writing.

    Deletion order leans on the schema's own cascades: removing `run` takes
    pages, observations, findings and artifact rows with it, so a future
    table hung off `page` is cleared automatically rather than leaked by a
    hand-maintained list here. `site` and `crux_history` do not hang off
    runs and go explicitly. The artifact FILES are returned for the caller
    to remove -- this layer knows their recorded paths, not which directory
    the caller wants swept.

    VACUUM afterwards, outside the transaction because SQLite requires
    that: a history of hundreds of runs is most of the file, and a "cleared"
    database that still occupies half a gigabyte looks like a wipe that
    did not take.
    """
    totals = history_totals(conn)
    artifact_paths = [str(r[0]) for r in
                      conn.execute("SELECT path FROM artifact").fetchall()]
    with transaction(conn):
        conn.execute("DELETE FROM run")
        conn.execute("DELETE FROM site")
        conn.execute("DELETE FROM crux_history")
    conn.execute("VACUUM")
    return {**totals, "artifact_paths": artifact_paths}
