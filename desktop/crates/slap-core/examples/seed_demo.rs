//! Write a demo database so the UI can be exercised against real, non-empty
//! data during development. NOT part of the app: an example binary, run by
//! hand, e.g. `cargo run -p slap-core --example seed_demo -- /tmp/demo.sqlite3`.
//!
//! It writes through the real storage layer and produces findings by running
//! the real rules engine over seeded observations, so what the UI renders is
//! exactly what an audit would have written, not hand-authored fixtures.

use std::collections::HashMap;

use slap_core::findings::FindingsEngine;
use slap_core::schema::{obs, RunStatus, Value};
use slap_core::storage::{self, NewPage};

fn seed_site(
    conn: &rusqlite::Connection,
    engine: &FindingsEngine,
    host: &str,
    client: &str,
    runs: &[Vec<(&str, Value)>],
) {
    let site = storage::upsert_site(conn, host, Some(host), Some(client)).unwrap();
    for values in runs {
        let run = storage::create_run(conn, "demo-batch", site, "0.1.0", 1, None).unwrap();
        let page =
            storage::create_page(conn, run, &NewPage::new(&format!("https://{host}/"))).unwrap();
        let observations: Vec<_> = values
            .iter()
            .map(|(key, value)| obs(key, value.clone()).unwrap())
            .collect();
        storage::insert_observations(conn, page, &observations).unwrap();

        let flat: HashMap<String, Value> = values
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect();
        let findings = engine.run(&flat).unwrap();
        storage::insert_findings(conn, page, &findings).unwrap();
        storage::set_run_provenance(
            conn,
            run,
            Some("13.4.1"),
            Some("141.0.7390.37"),
            Some("mobileSlow4G"),
        )
        .unwrap();
        storage::finish_run(conn, run, RunStatus::Completed, None).unwrap();
    }
}

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/tmp/slap-demo.sqlite3".to_string());
    let _ = std::fs::remove_file(&path);
    let conn = storage::open_db(std::path::Path::new(&path)).unwrap();
    let engine = FindingsEngine::load(None).unwrap();

    // A WordPress site that improved over three runs: failing, then better.
    seed_site(
        &conn,
        &engine,
        "acme-store.com",
        "Acme Retail",
        &[
            vec![
                ("crux.available", Value::Bool(true)),
                ("crux.cwv_pass", Value::Bool(false)),
                ("crux.lcp.p75", Value::Num(4800.0)),
                ("crux.inp.p75", Value::Num(420.0)),
                ("crux.cls.p75", Value::Num(0.28)),
                ("crux.lcp.good", Value::Num(0.31)),
                ("lh.score.performance", Value::Num(38.0)),
                ("lh.lcp", Value::Num(6100.0)),
                ("lh.tbt", Value::Num(1800.0)),
                ("http.ttfb", Value::Num(1600.0)),
                ("http.version", Value::from("HTTP/1.1")),
                ("tech.cms", Value::from("WordPress")),
                ("wprocket.present", Value::Bool(true)),
                ("wprocket.page_cached", Value::Bool(false)),
                ("sec.missing_header_count", Value::Num(4.0)),
                ("tls.days_to_expiry", Value::Num(58.0)),
            ],
            vec![
                ("crux.available", Value::Bool(true)),
                ("crux.cwv_pass", Value::Bool(false)),
                ("crux.lcp.p75", Value::Num(3600.0)),
                ("crux.inp.p75", Value::Num(260.0)),
                ("crux.cls.p75", Value::Num(0.14)),
                ("crux.lcp.good", Value::Num(0.52)),
                ("lh.score.performance", Value::Num(61.0)),
                ("lh.lcp", Value::Num(4200.0)),
                ("http.ttfb", Value::Num(900.0)),
                ("tech.cms", Value::from("WordPress")),
                ("wprocket.present", Value::Bool(true)),
                ("wprocket.page_cached", Value::Bool(true)),
            ],
            vec![
                ("crux.available", Value::Bool(true)),
                ("crux.cwv_pass", Value::Bool(true)),
                ("crux.lcp.p75", Value::Num(2300.0)),
                ("crux.inp.p75", Value::Num(180.0)),
                ("crux.cls.p75", Value::Num(0.06)),
                ("crux.lcp.good", Value::Num(0.79)),
                ("lh.score.performance", Value::Num(86.0)),
                ("lh.lcp", Value::Num(2600.0)),
                ("http.ttfb", Value::Num(420.0)),
                ("tech.cms", Value::from("WordPress")),
                ("wprocket.present", Value::Bool(true)),
                ("wprocket.page_cached", Value::Bool(true)),
            ],
        ],
    );

    // A clean marketing site.
    seed_site(
        &conn,
        &engine,
        "northwind.io",
        "Northwind",
        &[vec![
            ("crux.available", Value::Bool(true)),
            ("crux.cwv_pass", Value::Bool(true)),
            ("crux.lcp.p75", Value::Num(1800.0)),
            ("crux.inp.p75", Value::Num(120.0)),
            ("crux.cls.p75", Value::Num(0.03)),
            ("lh.score.performance", Value::Num(94.0)),
            ("http.ttfb", Value::Num(210.0)),
            ("http.version", Value::from("HTTP/2")),
        ]],
    );

    // A site with a security problem and an expiring certificate.
    seed_site(
        &conn,
        &engine,
        "legacy-portal.net",
        "Legacy Portal",
        &[vec![
            ("crux.available", Value::Bool(false)),
            ("lh.score.performance", Value::Num(52.0)),
            ("lh.lcp", Value::Num(4800.0)),
            ("http.ttfb", Value::Num(2100.0)),
            ("http.version", Value::from("HTTP/1.1")),
            ("tls.protocol", Value::from("TLSv1.1")),
            ("tls.days_to_expiry", Value::Num(8.0)),
            ("sec.missing_header_count", Value::Num(6.0)),
            ("sec.csp", Value::from("")),
            ("mixed.insecure_count", Value::Num(3.0)),
        ]],
    );

    let sites = storage::count_sites_with_a_completed_run(&conn).unwrap();
    println!("seeded {sites} sites into {path}");
}
