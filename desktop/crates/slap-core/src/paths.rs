//! The data-directory contract, ported line for line from
//! `src/slap/config.py`.
//!
//! This is the one piece of the core that HAD to port first: every
//! existing install's history lives in the file the Python app resolved,
//! so this app must resolve the same one or it starts fine and simply
//! shows no history, which the rename postmortem identified as worse than
//! an error. The contract outlives the Python app itself, exactly as the
//! salp fallback outlived the rename.
//!
//! Deliberate quirk kept: macOS uses the XDG path (`~/.local/share/slap`),
//! not `~/Library/Application Support`. That is where the Python app has
//! kept every Mac user's history (its check is `os.name == "nt"`, nothing
//! else), and following platform convention here would strand it.

use std::env;
use std::path::PathBuf;

/// The directory the app used before it was renamed from SALP to SLAP.
/// Kept because the data under it is not disposable: the database holds
/// immutable run history, and `artifact` rows store absolute paths to
/// gzipped LHR blobs. Silently pointing at a fresh empty directory would
/// look exactly like "the app lost my audits".
pub const LEGACY_DIRNAME: &str = "salp";

pub const DIRNAME: &str = "slap";

fn home() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("."))
}

pub fn data_dir_base() -> PathBuf {
    if cfg!(windows) {
        env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| home().join("AppData").join("Local"))
    } else {
        env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home().join(".local").join("share"))
    }
}

pub fn legacy_db_path() -> PathBuf {
    data_dir_base()
        .join(LEGACY_DIRNAME)
        .join(format!("{LEGACY_DIRNAME}.sqlite3"))
}

/// Per-user data directory. Respects LOCALAPPDATA on Windows.
///
/// Falls back to the legacy `salp` directory when it holds a database and
/// the new directory does not exist, so an existing install keeps its
/// history across the rename with no migration step the user has to know
/// about. The whole directory falls back or none of it does: splitting the
/// database from the artifacts it references would leave dangling paths in
/// `artifact`.
///
/// The trigger is the legacy *database*, not merely the legacy directory.
/// A stray `salp/reports/` left behind by an export is not history worth
/// pinning every future run to.
///
/// Once the new directory exists it always wins, so nothing silently
/// reverts after a fresh install has been used.
pub fn default_data_dir() -> PathBuf {
    let base = data_dir_base();
    let current = base.join(DIRNAME);
    if !current.exists() && legacy_db_path().is_file() {
        return base.join(LEGACY_DIRNAME);
    }
    current
}

/// True when we fell back to the pre-rename directory. Surfaced in the UI
/// the way the Python app's `doctor` surfaces it.
pub fn using_legacy_data_dir() -> bool {
    default_data_dir()
        .file_name()
        .is_some_and(|name| name == LEGACY_DIRNAME)
}

/// The database file, named to match whichever directory we landed in.
///
/// The file was `salp.sqlite3` before the rename. Returning
/// `<legacy dir>/slap.sqlite3` would create an empty second database
/// beside the real one, which is a worse failure than an error: the app
/// starts fine and simply shows no history.
fn default_db_path() -> PathBuf {
    let directory = default_data_dir();
    if directory
        .file_name()
        .is_some_and(|name| name == LEGACY_DIRNAME)
    {
        return legacy_db_path();
    }
    directory.join(format!("{DIRNAME}.sqlite3"))
}

/// Where the database actually is, environment override included.
///
/// SALP_DB still works, exactly as it does in the Python app: anyone who
/// put it in a shell profile should not have their database quietly change
/// location because the project was renamed, and they should not lose it
/// again because the app changed frameworks.
pub fn db_path() -> PathBuf {
    if let Some(overridden) = env::var_os("SLAP_DB").or_else(|| env::var_os("SALP_DB")) {
        return expand_user(PathBuf::from(overridden));
    }
    default_db_path()
}

/// `Path.expanduser()` for the one shape people actually write in an env
/// var: a leading `~/`. Anything else passes through untouched.
fn expand_user(path: PathBuf) -> PathBuf {
    if let Ok(stripped) = path.strip_prefix("~") {
        return home().join(stripped);
    }
    path
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    /// Environment variables are process-wide and `cargo test` is
    /// multi-threaded, so every test that touches them serialises here.
    fn env_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    struct EnvGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &std::path::Path) -> Self {
            let previous = env::var_os(key);
            env::set_var(key, value);
            Self { key, previous }
        }
        fn unset(key: &'static str) -> Self {
            let previous = env::var_os(key);
            env::remove_var(key);
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => env::set_var(self.key, value),
                None => env::remove_var(self.key),
            }
        }
    }

    /// Point the platform base at a temp dir for the duration of a test.
    fn base_at(tmp: &std::path::Path) -> Vec<EnvGuard> {
        vec![
            EnvGuard::set(
                if cfg!(windows) {
                    "LOCALAPPDATA"
                } else {
                    "XDG_DATA_HOME"
                },
                tmp,
            ),
            EnvGuard::unset("SLAP_DB"),
            EnvGuard::unset("SALP_DB"),
        ]
    }

    #[test]
    fn a_fresh_machine_gets_the_slap_directory() {
        let _serial = env_lock();
        let tmp = tempfile::tempdir().unwrap();
        let _env = base_at(tmp.path());

        assert_eq!(default_data_dir(), tmp.path().join("slap"));
        assert_eq!(db_path(), tmp.path().join("slap").join("slap.sqlite3"));
        assert!(!using_legacy_data_dir());
    }

    #[test]
    fn the_legacy_fallback_triggers_on_the_database_not_the_directory() {
        let _serial = env_lock();
        let tmp = tempfile::tempdir().unwrap();
        let _env = base_at(tmp.path());

        // A stray legacy directory with no database is not history.
        std::fs::create_dir_all(tmp.path().join("salp").join("reports")).unwrap();
        assert_eq!(default_data_dir(), tmp.path().join("slap"));

        // The database is what makes it history worth following.
        std::fs::write(tmp.path().join("salp").join("salp.sqlite3"), b"x").unwrap();
        assert_eq!(default_data_dir(), tmp.path().join("salp"));
        assert!(using_legacy_data_dir());

        // And the filename follows the directory: asking for slap.sqlite3
        // inside salp/ would create an empty second database beside the
        // real one, the silent-worse-than-an-error failure.
        assert_eq!(db_path(), tmp.path().join("salp").join("salp.sqlite3"));
    }

    #[test]
    fn a_used_new_install_never_reverts_to_legacy() {
        let _serial = env_lock();
        let tmp = tempfile::tempdir().unwrap();
        let _env = base_at(tmp.path());

        std::fs::write(tmp.path().join("salp.sqlite3.placeholder"), b"").ok();
        std::fs::create_dir_all(tmp.path().join("salp")).unwrap();
        std::fs::write(tmp.path().join("salp").join("salp.sqlite3"), b"x").unwrap();
        std::fs::create_dir_all(tmp.path().join("slap")).unwrap();

        assert_eq!(default_data_dir(), tmp.path().join("slap"));
        assert!(!using_legacy_data_dir());
    }

    #[test]
    fn the_environment_override_wins_and_salp_db_still_works() {
        let _serial = env_lock();
        let tmp = tempfile::tempdir().unwrap();
        let _base = base_at(tmp.path());

        let named = tmp.path().join("elsewhere.sqlite3");
        {
            let _db = EnvGuard::set("SLAP_DB", &named);
            assert_eq!(db_path(), named);
        }
        {
            // The pre-rename spelling is still honoured, for the same
            // reason the legacy directory is: a shell profile outlives a
            // rename, and it will outlive a framework change too.
            let _db = EnvGuard::set("SALP_DB", &named);
            assert_eq!(db_path(), named);
        }
    }
}
