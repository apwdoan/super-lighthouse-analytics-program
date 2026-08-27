//! Dev-only: render a stored run to a standalone HTML report on stdout.
use slap_core::storage;
fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("usage: render_report <db> <run_id>");
    let run_id: i64 = args.next().expect("run_id").parse().expect("run_id is a number");
    let conn = storage::open_db(std::path::Path::new(&path)).unwrap();
    print!("{}", slap_engine::report::render_html(&conn, run_id).unwrap());
}
