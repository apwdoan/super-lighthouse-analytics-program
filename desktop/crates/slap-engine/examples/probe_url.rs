//! Dev-only: run the endpoint probe against one origin and print the
//! observations. Point it at a LOCAL fixture server, not someone else's site.
use slap_engine::probe::{probe, ProbeConfig};
use std::time::Duration;

fn main() {
    let origin = std::env::args().nth(1).expect("usage: probe_url <origin>");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let cfg = ProbeConfig {
        rate_per_second: 50.0,
        timeout: Duration::from_secs(5),
        user_agent: "SLAP-probe-test".into(),
    };
    let obs = rt.block_on(probe(&client, &origin, &cfg));
    for o in &obs {
        println!("{:26} {:?}", o.metric_key, o.value());
    }
}
