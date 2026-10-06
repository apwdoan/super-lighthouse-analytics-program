//! Dev-only: render a stored run to a standalone HTML report on stdout, or,
//! given a third argument, print it to that PDF exactly as the app's export
//! does (Chromium from CHROME_PATH, the pinned copy, or a system install).
use slap_core::storage;
fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("usage: render_report <db> <run_id> [out.pdf]");
    let run_id: i64 = args.next().expect("run_id").parse().expect("run_id is a number");
    let conn = storage::open_db(std::path::Path::new(&path)).unwrap();
    let html = slap_engine::report::render_html(&conn, run_id).unwrap();
    match args.next() {
        Some(pdf) => {
            let chrome = slap_engine::lighthouse::resolve_chrome().expect("no Chromium found");
            let printed =
                slap_engine::pdf::print_pdf(&chrome, &html, std::path::Path::new(&pdf)).unwrap();
            eprintln!("{pdf}: {printed:?}");
        }
        None => print!("{html}"),
    }
}
