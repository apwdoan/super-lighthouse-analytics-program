//! Cross-app compatibility: the Rust port against a database the PYTHON app
//! wrote, and the Python app against one this port wrote.
//!
//! This is the contract the whole side-by-side period rests on, so it gets
//! tested against the real other implementation, not against our own idea
//! of it. CI for the desktop lane cannot assume a Python checkout, so the
//! harness activates only when `SLAP_COMPAT_DB` points at a database (the
//! repo's `python3 -m` one-liners create one); without it the test passes
//! as a no-op and says so.
//!
//! Run from the repo root as:
//!
//!     python3 -c "import sys; sys.path.insert(0, 'src'); \
//!         from slap import db; conn = db.init_db('/tmp/compat.sqlite3'); ..."
//!     SLAP_COMPAT_DB=/tmp/compat.sqlite3 cargo test -p slap-core --test python_compat

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
