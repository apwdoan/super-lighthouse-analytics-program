//! slap-core: the core, the part of SLAP that is not a window and not a
//! browser.
//!
//! The build order follows the project's own doctrine: the data contracts
//! freeze first. The *path* contract was nailed down earliest (which database
//! file, which data directory), because the app must read the SAME
//! SQLite database its predecessors wrote. Everything else arrives in later
//! phases.
//!
//! Two core rules, both load-bearing:
//!
//! - Nothing here depends on a UI framework. A test reads Cargo.toml and
//!   fails if `tauri` ever appears in it.
//! - Runs are immutable history. Nothing in this crate will ever mutate or
//!   delete a run row; the rename-era migration code renames columns in
//!   place and never copies or drops.

// Re-exported so front ends can hold the connection type and handle its
// errors through the core, rather than taking their own dependency on the
// storage engine. The shell manages a Connection in app state; this is how
// it names one without knowing it is SQLite.
pub use rusqlite;

pub mod events;
pub mod findings;
pub mod paths;
pub mod schema;
pub mod selfcheck;
pub mod settings;
pub mod storage;

/// The observation schema's version, recorded on every run row. Mirrors
/// `slap.SCHEMA_VERSION`; the two apps write the same value into the same
/// column while they coexist.
pub const SCHEMA_VERSION: i64 = 1;

/// The core's own version, distinct from the app shell's.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_core_never_depends_on_a_ui_framework() {
        // The rule that keeps the core reusable: it never imports a UI
        // framework, whatever shell drives it. That rule is what made each
        // front-end rewrite a one-package change, and it is what will keep
        // the core reusable if the shell ever changes again.
        let manifest = include_str!("../Cargo.toml");
        let deps = manifest
            .split("[dependencies]")
            .nth(1)
            .expect("a dependencies section");
        assert!(
            !deps.contains("tauri"),
            "slap-core must not depend on tauri; front ends are clients of \
             the core, never the other way around"
        );
    }

    #[test]
    fn the_version_is_reported() {
        assert!(!super::version().is_empty());
    }
}
