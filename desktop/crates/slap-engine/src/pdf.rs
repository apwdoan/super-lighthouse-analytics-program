//! Printing a client report to PDF.
//!
//! The HTML report is the deliverable, and the PDF is a print of it by
//! headless Chromium (the pinned copy Lighthouse uses), with one adjustment:
//! the page fitting in `report_fit.js`. A report rarely ends at the foot of
//! its last sheet, and the space left there reads as wasted, so the print
//! grows the whole report (text, gauges and spacing alike) by the largest
//! zoom, up to `MAX_FIT_ZOOM`, that keeps the number of sheets it has at full
//! size. Nothing is added or taken away; only the scale changes.
//!
//! The fitting measures pagination inside the page, before Chromium prints
//! it, and reports what it measured on the console. The print is then
//! checked against that: if it came out longer than measured, or the
//! measurement cannot be read, the report is printed again unzoomed and the
//! shorter of the two is kept. A fitted PDF is never longer than an unfitted
//! one.
//!
//! The sheet is stated, not left to Chromium: US Letter, which is what a
//! headless print defaults to anyway, so the fitting measures the sheet that
//! is actually printed.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

/// The sheet, in inches: US Letter.
const SHEET_INCHES: (f64, f64) = (8.5, 11.0);

/// The `@page` margins in report.css, in millimetres: (top and bottom, left
/// and right). A test holds the two together.
const MARGINS_MM: (f64, f64) = (9.0, 10.0);

/// The most the fitting grows a report. Past this, a short report is better
/// left a little short of its last sheet than printed in a giant hand.
pub const MAX_FIT_ZOOM: f64 = 1.25;

const FIT_JS: &str = include_str!("report_fit.js");

/// What a print came to.
#[derive(Clone, Debug, PartialEq)]
pub struct Printed {
    /// Sheets in the PDF.
    pub pages: usize,
    /// The zoom it was printed at, 1.0 when the report was not grown, or
    /// `None` when the fitting's own report could not be read.
    pub zoom: Option<f64>,
}

/// One sheet's content box, in CSS pixels (96 to the inch).
fn sheet_content_px() -> (f64, f64) {
    let mm = |v: f64| v / 25.4 * 96.0;
    (
        SHEET_INCHES.0 * 96.0 - 2.0 * mm(MARGINS_MM.1),
        SHEET_INCHES.1 * 96.0 - 2.0 * mm(MARGINS_MM.0),
    )
}

/// The copy of a rendered report that is printed: the sheet stated, and the
/// fitting script added. The HTML export never goes through here.
pub fn print_html(html: &str) -> String {
    let sheet = format!(
        "<style>@page {{ size: {}in {}in; }}</style>",
        SHEET_INCHES.0, SHEET_INCHES.1
    );
    let script = format!("<script>{FIT_JS}</script>");
    let mut out = String::with_capacity(html.len() + sheet.len() + script.len());
    match html.find("</head>") {
        Some(i) => {
            out.push_str(&html[..i]);
            out.push_str(&sheet);
            out.push_str(&html[i..]);
        }
        None => {
            out.push_str(&sheet);
            out.push_str(html);
        }
    }
    match out.rfind("</body>") {
        Some(i) => out.insert_str(i, &script),
        None => out.push_str(&script),
    }
    out
}

/// Print a rendered report to `out`, grown to fill its last sheet where it
/// can be. Blocking: it runs Chromium once, or twice when the fitted print
/// has to be checked against an unzoomed one.
pub fn print_pdf(chrome: &Path, html: &str, out: &Path) -> Result<Printed, String> {
    let (bytes, printed) = print_pdf_bytes(chrome, html)?;
    std::fs::write(out, bytes).map_err(|e| format!("could not write {}: {e}", out.display()))?;
    Ok(printed)
}

/// [`print_pdf`], keeping the PDF in memory rather than writing it: what the
/// app's preview shows, byte for byte the file an export would write.
pub fn print_pdf_bytes(chrome: &Path, html: &str) -> Result<(Vec<u8>, Printed), String> {
    clear_stale_scratch();
    let dir = scratch_dir()?;
    let result = print_in(&dir, chrome, html);
    // Best effort: Chromium can hold a profile file for a moment after exit.
    // A folder left behind is cleared by a later export.
    let _ = std::fs::remove_dir_all(&dir);
    result
}

fn print_in(dir: &Path, chrome: &Path, html: &str) -> Result<(Vec<u8>, Printed), String> {
    let page = dir.join("report.html");
    std::fs::write(&page, print_html(html))
        .map_err(|e| format!("could not write the report to print: {e}"))?;
    let (width, height) = sheet_content_px();

    let fitted_path = dir.join("fitted.pdf");
    let log = chromium_print(
        chrome,
        dir,
        &page,
        &format!("w={width:.3}&h={height:.3}&cap={MAX_FIT_ZOOM}"),
        &fitted_path,
    )?;
    let fitted = read_pdf(&fitted_path)?;
    let fitted_pages = pdf_page_count(&fitted).ok_or("Chromium produced a PDF with no pages")?;
    let fit = fit_report(&log);

    Ok(match fit {
        Some(fit) if fitted_pages <= fit.pages => (
            fitted,
            Printed { pages: fitted_pages, zoom: Some(fit.zoom) },
        ),
        _ => {
            // The print does not match what the fitting measured, or the
            // measurement could not be read: print it as it is, and keep
            // whichever came out shorter.
            let plain_path = dir.join("plain.pdf");
            chromium_print(chrome, dir, &page, "fit=0", &plain_path)?;
            let plain = read_pdf(&plain_path)?;
            let plain_pages = pdf_page_count(&plain).ok_or("Chromium produced a PDF with no pages")?;
            if fitted_pages <= plain_pages {
                (fitted, Printed { pages: fitted_pages, zoom: fit.map(|f| f.zoom) })
            } else {
                (plain, Printed { pages: plain_pages, zoom: Some(1.0) })
            }
        }
    })
}

/// How long one print may take before it is abandoned. A print takes a second
/// or two; this is for a Chromium that never finishes.
const PRINT_TIMEOUT: Duration = Duration::from_secs(120);

/// One headless print, its console written to a log beside the PDF and
/// returned. The log is a file, not a pipe: a helper process Chromium leaves
/// running can hold an inherited pipe open long after the print is done, and
/// a pipe would wait for it. The profile lives in the scratch folder, so a
/// print never meets another Chromium's profile lock.
fn chromium_print(
    chrome: &Path,
    dir: &Path,
    page: &Path,
    fragment: &str,
    pdf: &Path,
) -> Result<String, String> {
    let mut url = url::Url::from_file_path(page)
        .map_err(|_| format!("{} is not a path Chromium can open", page.display()))?;
    url.set_fragment(Some(fragment));
    let log_path = pdf.with_extension("log");
    let log = std::fs::File::create(&log_path)
        .map_err(|e| format!("could not make the print log: {e}"))?;
    // No console window on Windows, whatever Chromium starts (see `spawn`).
    let mut child = crate::spawn::std_command(crate::spawn::plain(chrome))
        .args([
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            "--no-pdf-header-footer",
            // The fitting reports its measurement on the console.
            "--enable-logging=stderr",
            "--v=0",
        ])
        .arg(format!("--user-data-dir={}", dir.join("profile").display()))
        .arg(format!("--print-to-pdf={}", pdf.display()))
        .arg(url.as_str())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(log))
        .spawn()
        .map_err(|e| format!("could not run Chromium: {e}"))?;
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < PRINT_TIMEOUT => {
                std::thread::sleep(Duration::from_millis(50))
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("Chromium did not finish the PDF in time".to_string());
            }
            Err(e) => return Err(format!("lost track of Chromium: {e}")),
        }
    };
    if !status.success() || !pdf.exists() {
        return Err("Chromium did not produce the PDF".to_string());
    }
    // Lossy: a log line in the system's own code page must not cost the rest.
    let log = std::fs::read(&log_path).unwrap_or_default();
    Ok(String::from_utf8_lossy(&log).into_owned())
}

fn read_pdf(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("could not read the printed PDF: {e}"))
}

/// Every export's scratch folder in the temp directory starts with this.
const SCRATCH_PREFIX: &str = "slap-print-";

/// A scratch folder this old belongs to an export that has long finished
/// (a print gives up after `PRINT_TIMEOUT`, and an export prints twice at
/// most), never to one still running.
const STALE_SCRATCH: Duration = Duration::from_secs(15 * 60);

/// A fresh folder in the temp directory for one export.
fn scratch_dir() -> Result<PathBuf, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("{SCRATCH_PREFIX}{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| format!("could not make a scratch folder: {e}"))?;
    Ok(dir)
}

/// Remove scratch folders earlier exports could not, a few MB of Chromium
/// profile each. Best effort.
fn clear_stale_scratch() {
    let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
        return;
    };
    for entry in entries.flatten() {
        if !entry.file_name().to_string_lossy().starts_with(SCRATCH_PREFIX) {
            continue;
        }
        let stale = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|modified| modified.elapsed().ok())
            .is_some_and(|age| age > STALE_SCRATCH);
        if stale {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// The fitting's measurement: the sheets the report takes at full size, and
/// the zoom it was printed at.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Fit {
    pages: usize,
    zoom: f64,
}

/// The fitting's console line, out of Chromium's log:
/// `... CONSOLE(51)] "SLAP-FIT {"pages":7,"zoom":1.08}", source: ...`.
fn fit_report(log: &str) -> Option<Fit> {
    let at = log.find("SLAP-FIT ")?;
    let rest = &log[at..];
    let start = rest.find('{')?;
    let end = start + rest[start..].find('}')?;
    let json: serde_json::Value = serde_json::from_str(&rest[start..=end]).ok()?;
    let pages = json["pages"].as_u64()? as usize;
    let zoom = json["zoom"].as_f64()?;
    (pages > 0 && zoom >= 1.0).then_some(Fit { pages, zoom })
}

/// Pages in a PDF Chromium printed: its page objects, `/Type /Page` (and not
/// the `/Type /Pages` nodes of the page tree). Chromium writes them as plain
/// objects, never inside compressed object streams.
fn pdf_page_count(pdf: &[u8]) -> Option<usize> {
    let mut count = 0;
    let mut i = 0;
    while let Some(at) = find(&pdf[i..], b"/Type") {
        let mut j = i + at + b"/Type".len();
        while j < pdf.len() && pdf[j].is_ascii_whitespace() {
            j += 1;
        }
        if pdf[j..].starts_with(b"/Page") {
            let next = pdf.get(j + b"/Page".len()).copied().unwrap_or(b' ');
            if !next.is_ascii_alphanumeric() {
                count += 1;
            }
        }
        i = j;
    }
    (count > 0).then_some(count)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sheet_matches_the_reports_page_margins() {
        let css = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../templates/report/report.css"));
        assert!(
            css.contains(&format!("@page {{ margin: {}mm {}mm; }}", MARGINS_MM.0, MARGINS_MM.1)),
            "report.css's @page margins and MARGINS_MM must agree"
        );
        let (w, h) = sheet_content_px();
        assert!((w - 740.409).abs() < 0.01 && (h - 987.969).abs() < 0.01, "{w} x {h}");
    }

    #[test]
    fn the_printed_copy_states_the_sheet_and_carries_the_fitting() {
        let html = "<html><head><style>p{}</style></head><body><div class=\"page\">x</div></body></html>";
        let out = print_html(html);
        let sheet = out.find("@page { size: 8.5in 11in; }").unwrap();
        assert!(sheet < out.find("</head>").unwrap());
        let script = out.find("SLAP-FIT").unwrap();
        assert!(out.find("<div class=\"page\">").unwrap() < script && script < out.find("</body>").unwrap());
        assert!(print_html("<p>bare</p>").contains("SLAP-FIT"), "a fragment still gets the script");
    }

    #[test]
    fn page_objects_are_counted_and_page_tree_nodes_are_not() {
        let pdf = b"1 0 obj\n<< /Type /Pages\n/Count 2 /Kids [2 0 R 3 0 R] >>\nendobj\n\
                    2 0 obj\n<< /Type /Page\n/Parent 1 0 R >>\nendobj\n\
                    3 0 obj\n<</Type/Page/Parent 1 0 R>>\nendobj\n";
        assert_eq!(pdf_page_count(pdf), Some(2));
        assert_eq!(pdf_page_count(b"not a pdf"), None);
    }

    #[test]
    fn the_fittings_console_line_is_read_from_chromiums_log() {
        let log = "[1006/031512.345:INFO:CONSOLE(51)] \"SLAP-FIT {\"pages\":7,\"zoom\":1.08}\", source: file:///tmp/report.html (51)\n";
        assert_eq!(fit_report(log), Some(Fit { pages: 7, zoom: 1.08 }));
        assert_eq!(fit_report("[INFO] nothing here"), None);
        assert_eq!(fit_report("SLAP-FIT {\"pages\":0,\"zoom\":1}"), None);
    }

    /// A page in the shape the fitting expects: the report's sheet margins,
    /// and a `.page` that print widens to the sheet. Fixed heights in `style`
    /// keep any platform's font metrics from moving a test's answer.
    fn sheet_page(style: &str, body: &str) -> String {
        format!(
            "<!doctype html><html><head><style>@page {{ margin: 9mm 10mm; }} \
             body {{ margin: 0; }} .page {{ max-width: 190mm; margin: 0 auto; }} \
             @media print {{ .page {{ max-width: none; }} }} {style}\
             </style></head><body><div class=\"page\">{body}</div></body></html>"
        )
    }

    /// Print `html` fitted, and again as it is for comparison, with a real
    /// Chromium where one can be found (CHROME_PATH, the app's pinned copy, or
    /// a system install). `None`, and the test skipped, without one.
    fn print_fitted_and_plain(html: &str) -> Option<(Printed, usize)> {
        let Some(chrome) = crate::lighthouse::resolve_chrome() else {
            eprintln!("skipped: no Chromium found");
            return None;
        };
        let dir = scratch_dir().unwrap();
        let printed = print_pdf(&chrome, html, &dir.join("fitted-out.pdf")).unwrap();
        let page = dir.join("plain-check.html");
        std::fs::write(&page, print_html(html)).unwrap();
        let plain_path = dir.join("plain-check.pdf");
        chromium_print(&chrome, &dir, &page, "fit=0", &plain_path).unwrap();
        let plain_pages = pdf_page_count(&std::fs::read(&plain_path).unwrap()).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        Some((printed, plain_pages))
    }

    /// The zoom a report that fits its sheets even at the cap is printed at:
    /// the cap, less the fitting's step back from the edge.
    const CAPPED: f64 = MAX_FIT_ZOOM - 0.001;

    #[test]
    fn a_report_is_grown_to_fill_its_last_sheet_and_never_lengthened() {
        // Ten blocks that will not split, 120px each: eight fill the first
        // sheet (988px of content box), two sit at the top of the second. They
        // still fit two sheets at any zoom up to the cap.
        let html = sheet_page(
            ".b { height: 120px; break-inside: avoid; background: #eee; }",
            &"<div class=\"b\"></div>".repeat(10),
        );
        let Some((printed, plain_pages)) = print_fitted_and_plain(&html) else {
            return;
        };
        assert_eq!(plain_pages, 2);
        assert_eq!(printed.pages, plain_pages, "fitting never adds a sheet: {printed:?}");
        let zoom = printed.zoom.expect("the fitting's measurement was read");
        assert!(
            (zoom - CAPPED).abs() < 0.0015,
            "a mostly empty last sheet grows the report to the cap: {printed:?}"
        );
    }

    #[test]
    fn a_table_carried_onto_another_sheet_is_measured_with_its_repeated_header() {
        // Print repeats a table's header row on each sheet the table runs
        // onto, which the fitting's columns do not do by themselves. A header
        // and 47 rows, 40px each, where a sheet holds 24: the header and 23
        // rows, the header again and 23 rows, then the header and the last
        // row. Three sheets, which a count without the repeats puts at two,
        // and a fit made from that count would come out a sheet longer.
        let rows: String = (0..47).map(|i| format!("<tr><td>{i}</td></tr>")).collect();
        let html = sheet_page(
            "table { width: 100%; border-collapse: collapse; } \
             th, td { padding: 0; height: 40px; } tr { break-inside: avoid; }",
            &format!("<table><thead><tr><th>Header</th></tr></thead><tbody>{rows}</tbody></table>"),
        );
        let Some((printed, plain_pages)) = print_fitted_and_plain(&html) else {
            return;
        };
        assert_eq!(plain_pages, 3);
        assert_eq!(printed.pages, plain_pages, "{printed:?}");
        let zoom = printed.zoom.expect("the fitting's measurement was read");
        assert!(
            (zoom - CAPPED).abs() < 0.0015,
            "measured as printed, so grown to the cap: {printed:?}"
        );
    }
}
