//! The core's slice of `--self-check`.
//!
//! The self-check inherits the rule that made the old verify step worth
//! having: check the thing the real code path does, not a proxy for it.
//! An earlier doctor once stat-ed a Chromium binary that was never launched
//! and reported a broken bundle healthy; the checks here open a real
//! database and write a real file rather than testing that paths look
//! plausible.
//!
//! Checks exist only for code that exists: today that is the data
//! directory, the full storage layer, and the findings rules. Every later
//! phase adds its own (worker handshake, Chromium fetch, report render)
//! the moment the code they exercise lands.

use std::fmt;

pub struct Check {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

impl fmt::Display for Check {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = if self.ok { "ok" } else { "FAIL" };
        write!(out, "[{status}] {}: {}", self.name, self.detail)
    }
}

pub fn run_core_checks() -> Vec<Check> {
    vec![
        check_data_dir_writable(),
        check_storage_roundtrip(),
        check_rules_load(),
    ]
}

/// The data directory can be created and written. Creating it is safe: it
/// is the same directory every app version creates on first run.
fn check_data_dir_writable() -> Check {
    let dir = crate::paths::default_data_dir();
    let attempt = (|| -> std::io::Result<()> {
        std::fs::create_dir_all(&dir)?;
        let probe = dir.join(".write-test");
        std::fs::write(&probe, b"")?;
        std::fs::remove_file(&probe)?;
        Ok(())
    })();
    match attempt {
        Ok(()) => Check {
            name: "data directory",
            ok: true,
            detail: format!("writable: {}", dir.display()),
        },
        Err(error) => Check {
            name: "data directory",
            ok: false,
            detail: format!("cannot write {}: {error}", dir.display()),
        },
    }
}

/// The real storage layer, end to end, against a throwaway file:
/// `open_db` (migrations and DDL included), a site, a run, a page, real
/// observations through the schema registry, and the flattened read the
/// findings engine consumes. Deliberately NOT the real database: proving
/// the engine works must never race the other app for the file that holds
/// history, and a self-check that can modify user data is not a check.
fn check_storage_roundtrip() -> Check {
    let attempt = (|| -> Result<String, Box<dyn std::error::Error>> {
        let scratch =
            std::env::temp_dir().join(format!("slap-selfcheck-{}.sqlite3", std::process::id()));
        let _ = std::fs::remove_file(&scratch);
        let conn = crate::storage::open_db(&scratch)?;
        let mode: String = conn.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
        let site = crate::storage::upsert_site(&conn, "selfcheck.invalid", None, None)?;
        let run = crate::storage::create_run(
            &conn,
            "selfcheck",
            site,
            crate::version(),
            crate::SCHEMA_VERSION,
            None,
        )?;
        let page = crate::storage::create_page(
            &conn,
            run,
            &crate::storage::NewPage::new("https://selfcheck.invalid/"),
        )?;
        crate::storage::insert_observations(
            &conn,
            page,
            &[crate::schema::obs(
                "http.ttfb",
                crate::schema::Value::Num(1.0),
            )?],
        )?;
        crate::storage::finish_run(&conn, run, crate::schema::RunStatus::Completed, None)?;
        let values = crate::storage::observations_as_dict(&conn, page)?;
        if values.get("http.ttfb") != Some(&crate::schema::Value::Num(1.0)) {
            return Err("the written observation did not read back".into());
        }
        drop(conn);
        let _ = std::fs::remove_file(&scratch);
        Ok(mode)
    })();
    match attempt {
        Ok(mode) if mode.eq_ignore_ascii_case("wal") => Check {
            name: "storage",
            ok: true,
            detail: format!(
                "bundled sqlite {} in WAL, full roundtrip",
                rusqlite::version()
            ),
        },
        Ok(mode) => Check {
            name: "storage",
            ok: false,
            detail: format!("journal mode came back {mode:?}, wanted WAL"),
        },
        Err(error) => Check {
            name: "storage",
            ok: false,
            detail: error.to_string(),
        },
    }
}

/// The shipped rules parse and the engine accepts them. Zero rules loading
/// "successfully" is the silent failure this check exists to catch: an
/// audit that finds nothing looks exactly like a healthy site.
fn check_rules_load() -> Check {
    match crate::findings::FindingsEngine::load(None) {
        Ok(engine) if !engine.rules.is_empty() => Check {
            name: "rules",
            ok: true,
            detail: format!("{} findings rules loaded", engine.rules.len()),
        },
        Ok(_) => Check {
            name: "rules",
            ok: false,
            detail: "the rules file parsed but holds no rules".to_string(),
        },
        Err(error) => Check {
            name: "rules",
            ok: false,
            detail: error.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_core_checks_pass_here() {
        for check in run_core_checks() {
            assert!(check.ok, "{check}");
        }
    }

    #[test]
    fn a_check_prints_its_name_status_and_detail() {
        let check = Check {
            name: "example",
            ok: false,
            detail: "broke".into(),
        };
        assert_eq!(check.to_string(), "[FAIL] example: broke");
    }
}
