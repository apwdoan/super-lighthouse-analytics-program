//! The data-directory contract, ported line for line from
//! `src/slap/config.py`.
//!
//! This is the one piece of the core that HAD to port first: every
//! existing install's history lives in the file the Python app resolved,
//! so this app must resolve the same one or it starts fine and simply
//! shows no history, which the rename postmortem identified as worse than
//! an error.
//!
//! Deliberate quirk kept: macOS uses the XDG path (`~/.local/share/slap`),
//! not `~/Library/Application Support`. That is where the Python app has
//! kept every Mac user's history (its check is `os.name == "nt"`, nothing
//! else), and following platform convention here would strand it.

use std::env;
use std::path::PathBuf;

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

/// Per-user data directory. Respects LOCALAPPDATA on Windows and
/// XDG_DATA_HOME elsewhere.
pub fn default_data_dir() -> PathBuf {
    data_dir_base().join(DIRNAME)
}

/// The database file inside the data directory.
fn default_db_path() -> PathBuf {
    default_data_dir().join(format!("{DIRNAME}.sqlite3"))
}

/// Where the database actually is, environment override included.
///
/// SLAP_DB points the app at a specific database file; anyone who set it in
/// a shell profile should not have their database quietly change location
/// because the app changed frameworks.
pub fn db_path() -> PathBuf {
    if let Some(overridden) = env::var_os("SLAP_DB") {
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
        ]
    }

    #[test]
    fn a_fresh_machine_gets_the_slap_directory() {
        let _serial = env_lock();
        let tmp = tempfile::tempdir().unwrap();
        let _env = base_at(tmp.path());

        assert_eq!(default_data_dir(), tmp.path().join("slap"));
        assert_eq!(db_path(), tmp.path().join("slap").join("slap.sqlite3"));
    }

    #[test]
    fn the_environment_override_wins() {
        let _serial = env_lock();
        let tmp = tempfile::tempdir().unwrap();
        let _base = base_at(tmp.path());

        let named = tmp.path().join("elsewhere.sqlite3");
        let _db = EnvGuard::set("SLAP_DB", &named);
        assert_eq!(db_path(), named);
    }

    #[test]
    fn a_leading_tilde_in_the_override_expands_to_home() {
        let _serial = env_lock();
        let _base = base_at(tempfile::tempdir().unwrap().path());

        let _db = EnvGuard::set("SLAP_DB", std::path::Path::new("~/audits.sqlite3"));
        assert_eq!(db_path(), home().join("audits.sqlite3"));
    }
}
