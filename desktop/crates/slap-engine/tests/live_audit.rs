//! End to end against a real socket: a local fixture server stands in for a
//! site, and the engine fetches it, runs the collectors, persists a run, and
//! produces findings, all through the real code path. This is the test that
//! proves the network half works, not just the pure parsers.
//!
//! The server is deliberately hostile: a WordPress page behind WP Rocket
//! that was NOT served from cache, missing every security header, gzip-
//! encoded on the wire. That exercises the compression decode, the
//! fingerprint, and the rule that fires on a cold WP Rocket cache.

use std::io::Write;

use slap_core::events::Event;
use slap_core::storage;

const PAGE: &str = r#"<!doctype html>
<html><head>
<meta name="generator" content="WordPress 6.5">
<meta name="generator" content="WP Rocket 3.15.2" data-wpr-features="lazyload,minify">
<link rel="stylesheet" href="/wp-content/plugins/elementor/frontend.css">
</head><body><h1>Hello</h1><script data-rocket-src="/app.js"></script></body></html>"#;

/// A one-request-per-connection HTTP/1.1 server that gzips the body and sets
/// no security headers. Returns its base URL; runs until the process exits.
fn start_server() -> String {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", server.server_addr());
    std::thread::spawn(move || {
        for request in server.incoming_requests() {
            let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            gz.write_all(PAGE.as_bytes()).unwrap();
            let body = gz.finish().unwrap();
            let headers = [
                tiny_http::Header::from_bytes(
                    &b"Content-Type"[..],
                    &b"text/html; charset=utf-8"[..],
                )
                .unwrap(),
                tiny_http::Header::from_bytes(&b"Content-Encoding"[..], &b"gzip"[..]).unwrap(),
                tiny_http::Header::from_bytes(&b"Server"[..], &b"nginx"[..]).unwrap(),
                tiny_http::Header::from_bytes(&b"Cache-Control"[..], &b"max-age=600"[..]).unwrap(),
            ];
            let response = tiny_http::Response::from_data(body).with_status_code(200);
            let response = headers.into_iter().fold(response, |r, h| r.with_header(h));
            let _ = request.respond(response);
        }
    });
    url
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_real_fetch_produces_a_run_the_ui_would_show() {
    let base = start_server();
    let dir = tempfile::tempdir().unwrap();
    let conn = storage::open_db(&dir.path().join("audit.sqlite3")).unwrap();

    let cfg = slap_engine::EngineConfig {
        user_agent: "SLAP-test".into(),
        max_redirects: 5,
        max_body_bytes: 4_000_000,
        concurrency: 4,
        timeout_secs: 10,
        // No CrUX key in the test: field data is skipped, exactly as it is
        // for a user who has not set one. The fixture is plain HTTP, so the
        // TLS collector records "not served over HTTPS" and moves on.
        crux_api_key: None,
        crux_rate_per_second: 2.0,
        lighthouse: None,
        // The fixture server answers every path with the same page, so
        // discovery finds no sitemap and no links: the run audits the home
        // page alone, which is what this test asserts on.
        discovery: slap_engine::discovery::DiscoveryConfig::default(),
        lighthouse_pages: 5,
        lighthouse_scope: slap_core::schema::LighthouseScope::Sampled,
        lighthouse_concurrency: 3,
        artifact_dir: None,
        keep_lhr: false,
        // Probing stays off in this test: no host is authorised.
        probe: slap_engine::run::ProbeSettings::default(),
    };

    let events = std::sync::Mutex::new(Vec::new());
    let summary = slap_engine::run_batch(&conn, &[base.clone()], &cfg, |event: Event| {
        events.lock().unwrap().push(event);
    })
    .await
    .expect("the batch runs");

    // The run itself.
    assert_eq!(summary.total, 1);
    assert_eq!(summary.succeeded, 1);
    let run = &summary.runs[0];
    assert!(run.ok);
    assert!(run.observations > 0);
    assert!(
        run.findings > 0,
        "a header-less WP Rocket page has findings"
    );

    // The gzip body decoded, so the fingerprint saw real HTML.
    let run_id = run.run_id.unwrap();
    let page_id = storage::home_page_id(&conn, run_id).unwrap().unwrap();
    let values = storage::observations_as_dict(&conn, page_id).unwrap();
    assert_eq!(
        values["tech.cms"],
        slap_core::schema::Value::Text("WordPress".into())
    );
    assert_eq!(
        values["wprocket.present"],
        slap_core::schema::Value::Bool(true)
    );
    assert_eq!(
        values["wprocket.page_cached"],
        slap_core::schema::Value::Bool(false),
        "installed but this response was not served from cache"
    );
    assert_eq!(
        values["http.compressed"],
        slap_core::schema::Value::Bool(true)
    );
    assert_eq!(
        values["http.compression"],
        slap_core::schema::Value::Text("gzip".into())
    );
    // Every expected security header is absent.
    assert_eq!(
        values["sec.missing_header_count"],
        slap_core::schema::Value::Num(6.0)
    );

    // The findings the UI would render include the cold-cache one.
    let findings = storage::get_findings(&conn, run_id).unwrap();
    let rule_ids: Vec<&str> = findings
        .iter()
        .filter_map(|f| f["rule_id"].as_str())
        .collect();
    assert!(
        rule_ids.contains(&"wprocket-cache-cold"),
        "cold WP Rocket cache flagged: {rule_ids:?}"
    );

    // And the event stream told the story a progress dock would show.
    let events = events.into_inner().unwrap();
    assert!(matches!(
        events.first(),
        Some(Event::BatchStarted { total: 1, .. })
    ));
    assert!(matches!(
        events.last(),
        Some(Event::BatchFinished { succeeded: 1, .. })
    ));
    assert!(events.iter().any(
        |e| matches!(e, Event::CollectorFinished { collector, ok: true, .. } if collector == "http")
    ));
    assert!(events.iter().any(
        |e| matches!(e, Event::CollectorStarted { collector, .. } if collector == "discovery")
    ));
    // Scanning progress: how many pages, then each page as it completes.
    assert!(events
        .iter()
        .any(|e| matches!(e, Event::PagesDiscovered { pages: 1, .. })));
    assert!(events.iter().any(
        |e| matches!(e, Event::PageScanned { index: 1, total: 1, ok: true, .. })
    ));

    // The Sites screen would now list exactly this one site.
    assert_eq!(storage::count_sites_with_a_completed_run(&conn).unwrap(), 1);
}
