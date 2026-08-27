use slap_core::storage;
use slap_engine::{run_batch, EngineConfig};
fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("db path");
    let urls: Vec<String> = args.collect();
    let _ = std::fs::remove_file(&path);
    let conn = storage::open_db(std::path::Path::new(&path)).unwrap();
    let mut settings = slap_core::settings::Settings::default();
    settings.discovery.pages_per_site = 6;
    if let Ok(k) = std::env::var("CRUX_API_KEY") {
        settings.collector.crux_api_key = Some(k);
    }
    let cfg = EngineConfig::from_settings(&settings);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let summary = rt.block_on(run_batch(&conn, &urls, &cfg, |_e| {})).unwrap();
    for r in &summary.runs {
        println!(
            "{:<20} ok={} pages={} obs={} findings={}",
            r.hostname, r.ok, r.pages, r.observations, r.findings
        );
    }
    println!("{}/{} succeeded", summary.succeeded, summary.total);
}
