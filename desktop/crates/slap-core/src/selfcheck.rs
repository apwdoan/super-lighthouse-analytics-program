//! The core's slice of `--self-check`.
//!
//! The self-check is the Rust port of `slap verify`, and it inherits the
//! rule that made verify worth having: check the thing the real code path
//! does, not a proxy for it. The Python `doctor` once stat-ed a Chromium
//! binary Playwright never launched and reported a broken bundle healthy;
//! the checks here open a real database and write a real file rather than
//! testing that paths look plausible.
//!
//! Phase 0 carries only the checks the phase-0 app can honestly make.
//! Every later phase adds its own (worker handshake, Chromium fetch,
//! report render) the moment the code they exercise exists.

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
    vec![check_data_dir_writable(), check_sqlite_works()]
}

/// The data directory can be created and written. Creating it is safe: it
/// is the same directory the Python app creates on first run, and the
/// legacy fallback in `paths` has already decided which directory that is.
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

/// The bundled SQLite links, opens, and honours WAL, exercised against a
/// throwaway file. Deliberately NOT the real database: proving the engine
/// works must never race the Python app for the file that holds history,
/// and a self-check that can modify user data is not a check.
fn check_sqlite_works() -> Check {
    let attempt = (|| -> rusqlite::Result<(String, String)> {
        let scratch =
            std::env::temp_dir().join(format!("slap-selfcheck-{}.sqlite3", std::process::id()));
        let _ = std::fs::remove_file(&scratch);
        let connection = rusqlite::Connection::open(&scratch)?;
        let mode: String = connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        connection.execute("CREATE TABLE probe (x TEXT)", [])?;
        connection.execute("INSERT INTO probe VALUES ('roundtrip')", [])?;
        let back: String = connection.query_row("SELECT x FROM probe", [], |row| row.get(0))?;
        drop(connection);
        let _ = std::fs::remove_file(&scratch);
        Ok((mode, back))
    })();
    match attempt {
        Ok((mode, back)) if mode.eq_ignore_ascii_case("wal") && back == "roundtrip" => Check {
            name: "sqlite",
            ok: true,
            detail: format!("bundled {} with WAL", rusqlite::version()),
        },
        Ok((mode, _)) => Check {
            name: "sqlite",
            ok: false,
            detail: format!("journal mode came back {mode:?}, wanted WAL"),
        },
        Err(error) => Check {
            name: "sqlite",
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
