//! Regenerate the vulnerability database from the NVD via the same Rust path
//! the app's Settings button uses, from the command line. A convenience for CI
//! and a way to smoke-test the in-app generator without a GUI.
//!
//!   cargo run -p slap-engine --example vulndb_regen [-- <out.json>]
//!
//! Honours NVD_API_KEY. With no key it takes ~10 minutes (NVD's rate limit).

use std::collections::BTreeMap;

use slap_engine::vulndb_build::{build, Progress};

fn main() {
    let out = std::env::args().nth(1).unwrap_or_else(|| "/tmp/vulndb-rust.json".to_string());
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    // An empty baseline: this is a fresh build, not a guarded refresh.
    let baseline: BTreeMap<(String, String), usize> = BTreeMap::new();
    let result = rt.block_on(build(std::env::var("NVD_API_KEY").ok(), &baseline, |p: Progress| {
        eprintln!("[{}/{}] {}", p.done, p.total, p.label);
    }));
    match result {
        Ok(o) => {
            std::fs::write(&out, &o.json).expect("write output");
            eprintln!(
                "OK: {} CVEs, covered {:?}, severity {:?} -> {out}",
                o.cve_count, o.covered, o.by_severity
            );
        }
        Err(e) => {
            eprintln!("FAILED: {e}");
            std::process::exit(1);
        }
    }
}
