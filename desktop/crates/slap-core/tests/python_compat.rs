//! Cross-app compatibility, from the coexistence era: the Rust port
//! against a database the PYTHON app wrote, and the Python app against one
//! this port wrote.
//!
//! Both harnesses PASSED on 2026-08-27, immediately before the Python app
//! was retired: a Python-seeded database read and extended through this
//! port, then read back by Python with zero migrations; and both findings
//! engines producing the identical 29 findings (order, rendered titles and
//! details, impacts) on the same busy synthetic page.
//!
//! The harnesses stay because existing teammates' databases WERE written
//! by the Python app, so the contract they proved is still load-bearing;
//! regenerating their inputs now needs a git checkout that predates the
//! retirement. Env-gated: without `SLAP_COMPAT_DB` / `SLAP_DIFF_JSON` each
//! test passes as a no-op and says so, which is what CI sees.

use slap_core::storage;

/// Differential check: the Python engine and this port, same observations,
/// identical findings. Activated by `SLAP_DIFF_JSON` pointing at a file the
/// Python side wrote: `{"values": {...}, "expected": [{rule_id, title,
/// detail, severity, impact_ms}, ...]}`. Rendered TEXT is compared, not
/// just rule ids, so formatter drift ("412ms" vs "412.0ms") fails loudly.
#[test]
fn the_two_engines_agree_on_the_same_observations() {
    let Ok(path) = std::env::var("SLAP_DIFF_JSON") else {
        eprintln!("SLAP_DIFF_JSON not set; engine differential skipped");
        return;
    };
    let text = std::fs::read_to_string(&path).expect("read the Python side's dump");
    let dump: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");

    let mut values = std::collections::HashMap::new();
    for (key, value) in dump["values"].as_object().expect("a values object") {
        let converted = match value {
            serde_json::Value::Bool(b) => slap_core::schema::Value::Bool(*b),
            serde_json::Value::Number(n) => {
                slap_core::schema::Value::Num(n.as_f64().expect("finite"))
            }
            serde_json::Value::String(s) => slap_core::schema::Value::Text(s.clone()),
            other => panic!("unexpected value shape for {key}: {other}"),
        };
        values.insert(key.clone(), converted);
    }

    let engine = slap_core::findings::FindingsEngine::load(None).expect("shipped rules");
    let ours = engine.run(&values).expect("engine run");
    let expected = dump["expected"].as_array().expect("an expected list");

    assert_eq!(
        ours.len(),
        expected.len(),
        "finding counts differ: rust={:?} python={:?}",
        ours.iter().map(|f| f.rule_id.as_str()).collect::<Vec<_>>(),
        expected
            .iter()
            .map(|f| f["rule_id"].as_str().unwrap_or("?"))
            .collect::<Vec<_>>(),
    );
    for (mine, theirs) in ours.iter().zip(expected) {
        assert_eq!(
            mine.rule_id, theirs["rule_id"],
            "order or membership drifted"
        );
        assert_eq!(mine.severity.as_str(), theirs["severity"]);
        assert_eq!(
            mine.title, theirs["title"],
            "title text drifted on {}",
            mine.rule_id
        );
        assert_eq!(
            mine.detail, theirs["detail"],
            "detail text drifted on {}",
            mine.rule_id
        );
        let their_impact = theirs["impact_ms"].as_f64();
        assert_eq!(
            mine.impact_ms, their_impact,
            "impact drifted on {}",
            mine.rule_id
        );
    }
    eprintln!("engines agree on {} findings", ours.len());
}

#[test]
fn a_python_written_database_reads_back_through_the_port() {
    let Ok(path) = std::env::var("SLAP_COMPAT_DB") else {
        eprintln!("SLAP_COMPAT_DB not set; cross-app check skipped");
        return;
    };
    let conn = storage::open_db(std::path::Path::new(&path)).expect("open the Python app's db");

    let sites = storage::list_sites(&conn, 500).expect("list sites");
    assert!(!sites.is_empty(), "the Python seed script wrote a site");
    let site = &sites[0];
    assert_eq!(site["hostname"], "compat.example");
    assert_eq!(site["finding_count"], 1, "distinct rule ids, not rows");

    let run_id = site["latest_run_id"].as_i64().expect("a completed run");
    let page_id = storage::home_page_id(&conn, run_id)
        .expect("query")
        .expect("a home page");
    let values = storage::observations_as_dict(&conn, page_id).expect("flatten");
    assert_eq!(values["http.ttfb"], slap_core::schema::Value::Num(412.0));
    assert_eq!(
        values["http.compressed"],
        slap_core::schema::Value::Bool(true)
    );

    // And write THROUGH the port into the same file, so the reverse
    // direction (Python reading a Rust-written run) has something to read.
    let site_id = storage::upsert_site(&conn, "rust.example", None, None).expect("upsert");
    let run = storage::create_run(
        &conn,
        "rust-batch",
        site_id,
        "0.1.0",
        slap_core::SCHEMA_VERSION,
        None,
    )
    .expect("run");
    let page = storage::create_page(&conn, run, &storage::NewPage::new("https://rust.example/"))
        .expect("page");
    storage::insert_observations(
        &conn,
        page,
        &[slap_core::schema::obs("http.ttfb", slap_core::schema::Value::Num(99.0)).unwrap()],
    )
    .expect("observations");
    storage::finish_run(&conn, run, slap_core::schema::RunStatus::Completed, None).expect("finish");
}
