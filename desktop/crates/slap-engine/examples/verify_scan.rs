//! Ad-hoc end-to-end check of vulnerability scanning against the embedded
//! database. Feeds a crafted page that references several of the newly-covered
//! WordPress plugins (and an observed-old jQuery) through the real
//! detection -> matching -> findings path, and prints what the report would
//! carry. Run: cargo run -p slap-engine --example verify_scan
//!
//! This is a demonstration, not a test; the assertions live in the unit tests.

use std::collections::HashMap;

use slap_core::findings::FindingsEngine;
use slap_core::schema::Value;
use slap_engine::components::observations_from_page;

fn main() {
    // A WordPress page: old jQuery in a versioned PATH (observed -> can confirm),
    // and several plugins carrying a ?ver= (inferred -> at most "possible").
    // The plugin versions are deliberately old so they hit known CVEs.
    let html = r#"<!doctype html><html><head>
      <meta name="generator" content="WordPress 6.2">
      <script src="/assets/vendor/jquery-1.6.2.min.js"></script>
      <link  href="/wp-content/plugins/ninja-forms/assets/css/display.css?ver=3.4.0">
      <script src="/wp-content/plugins/wordfence/js/admin.js?ver=7.4.5"></script>
      <script src="/wp-content/plugins/updraftplus/js/updraft.js?ver=1.16.0"></script>
      <link  href="/wp-content/plugins/elementor/assets/css/frontend.css?ver=3.5.0">
      <script src="/wp-content/plugins/some-obscure-plugin/x.js?ver=1.0.0"></script>
      <script src="/assets/swiper-bundle.min.js?ver=9.0.0"></script>
    </head><body>hi</body></html>"#;

    let obs = observations_from_page(html, &Default::default());
    let values: HashMap<String, Value> = obs
        .iter()
        .map(|o| (o.metric_key.to_string(), o.value()))
        .collect();

    let show = |k: &str| {
        if let Some(v) = values.get(k) {
            println!("  {k} = {}", render(v));
        }
    };

    println!("== component detection ==");
    show("component.count");
    show("component.detected");
    println!("== vulnerability observations ==");
    show("vuln.confirmed_count");
    show("vuln.confirmed_critical");
    show("vuln.confirmed_high");
    show("vuln.confirmed_detail");
    show("vuln.possible_count");
    show("vuln.possible_detail");
    show("vuln.unchecked_count");
    show("vuln.unchecked_detail");

    println!("== findings the rules engine fires ==");
    let engine = FindingsEngine::load(None).expect("embedded rules load");
    let findings = engine.run(&values).expect("rules run");
    for f in &findings {
        println!("  [{}] {}", f.rule_id, f.title);
    }
    if findings.iter().any(|f| f.rule_id.starts_with("vuln-")) {
        println!("\nOK: vulnerability scanning fired against the embedded database.");
    } else {
        println!("\nWARNING: no vuln-* findings fired.");
    }
}

fn render(v: &Value) -> String {
    match v {
        Value::Num(n) => format!("{n}"),
        other => format!("{other:?}"),
    }
}
