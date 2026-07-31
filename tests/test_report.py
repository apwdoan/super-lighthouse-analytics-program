"""Report view model and rendering tests.

The view model is a pure function, so almost everything here runs without a
browser. Only the PDF tests need Playwright, and they skip cleanly when it
is not installed so the suite stays green on a fresh checkout.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from slap.report import check_backend, render_batch_html, render_report_html
from slap.report.model import (
    build_report_model,
    cwv_status,
    format_bytes,
    format_ms,
    meter_fraction,
    split_findings,
)
from slap.report.render import safe_filename
from slap.schema import format_value

STAMP = datetime(2026, 7, 31, tzinfo=timezone.utc)


def obs_row(key, numeric=None, text=None, unit="none", source="http"):
    return {
        "metric_key": key, "numeric_value": numeric, "text_value": text,
        "unit": unit, "source": source, "url": "https://x.test",
        "final_url": "https://x.test", "form_factor": "none",
    }


def finding_row(rule_id, severity, title, **kw):
    row = {
        "rule_id": rule_id, "severity": severity, "title": title,
        "detail": kw.get("detail", "Detail text."), "evidence_json": kw.get("evidence_json"),
        "impact_ms": kw.get("impact_ms"), "effort": kw.get("effort"),
        "remediation": kw.get("remediation"), "wp_rocket_setting": kw.get("wp_rocket_setting"),
        "url": "https://x.test",
    }
    return row


def make_detail(observations, findings=(), hostname="example.test"):
    return {
        "run": {
            "id": 7, "batch_id": "abc123", "hostname": hostname, "label": None,
            "client": None, "status": "completed", "error": None,
            "slap_version": "0.1.0", "schema_version": 1,
            "started_at": "2026-07-31T01:00:00+00:00",
            "finished_at": "2026-07-31T01:00:04+00:00",
            "lh_version": None, "chrome_version": None,
        },
        "observations": list(observations),
        "findings": list(findings),
    }


# --------------------------------------------------------------------------
# formatting
# --------------------------------------------------------------------------

@pytest.mark.parametrize("value,expected", [
    (412.0, "412ms"), (1340.0, "1.3s"), (999.0, "999ms"), (1000.0, "1.0s"),
    (None, "n/a"),
])
def test_format_ms(value, expected):
    assert format_ms(value) == expected


@pytest.mark.parametrize("value,expected", [
    (412_000, "402 KB"), (2_200_000, "2.1 MB"), (900, "900 B"), (None, "n/a"),
])
def test_format_bytes(value, expected):
    assert format_bytes(value) == expected


def test_schema_format_value_matches_the_registry_unit():
    assert format_value("http.ttfb", 1340) == "1.3s"
    assert format_value("http.content_bytes", 412_000) == "402 KB"
    assert format_value("tls.days_to_expiry", 12) == "12 days"
    assert format_value("http.compressed", True) == "Yes"
    assert format_value("sec.hsts_max_age", 31_536_000) == "365 days"
    assert format_value("http.status", 200) == "200"


def test_durations_are_pluralised_correctly():
    assert format_value("http.cache_max_age", 3600) == "1 hour"
    assert format_value("http.cache_max_age", 7200) == "2 hours"
    assert format_value("http.cache_max_age", 60) == "1 minute"
    assert format_value("tls.days_to_expiry", 1) == "1 day"


def test_cls_is_a_score_not_a_ratio():
    """0.06 must not render as '6%'."""
    assert format_value("crux.cls.p75", 0.06) == "0.06"
    assert format_value("crux.cls.good", 0.93) == "93%"


# --------------------------------------------------------------------------
# CWV banding
# --------------------------------------------------------------------------

@pytest.mark.parametrize("key,value,expected", [
    ("crux.lcp.p75", 2400, "good"),
    ("crux.lcp.p75", 2500, "good"),          # boundary is inclusive
    ("crux.lcp.p75", 3200, "needs-improvement"),
    ("crux.lcp.p75", 4900, "poor"),
    ("crux.inp.p75", 200, "good"),
    ("crux.inp.p75", 340, "needs-improvement"),
    ("crux.cls.p75", 0.06, "good"),
    ("crux.cls.p75", 0.3, "poor"),
    ("crux.lcp.p75", None, "unknown"),
])
def test_cwv_status(key, value, expected):
    assert cwv_status(key, value) == expected


def test_meter_thresholds_land_at_the_same_place_on_every_tile():
    """The two ticks are drawn at fixed 33%/66%, so the maths must agree."""
    for key, good_max, poor_min in [
        ("crux.lcp.p75", 2500, 4000),
        ("crux.inp.p75", 200, 500),
        ("crux.cls.p75", 0.1, 0.25),
    ]:
        assert meter_fraction(key, good_max) == pytest.approx(0.33, abs=0.01)
        assert meter_fraction(key, poor_min) == pytest.approx(0.66, abs=0.01)


def test_meter_never_overflows_the_track():
    assert meter_fraction("crux.lcp.p75", 60_000) <= 1.0
    assert meter_fraction("crux.lcp.p75", 0) >= 0.0


# --------------------------------------------------------------------------
# finding split: the regression that buried a HIGH finding
# --------------------------------------------------------------------------

def _views(*severities):
    from slap.report.model import build_finding_views

    return build_finding_views([
        finding_row(f"rule-{i}", sev, f"Title {i}")
        for i, sev in enumerate(severities)
    ])


def test_every_high_and_critical_finding_gets_the_detailed_treatment():
    """Six critical/high findings must all be detailed, none demoted.

    The earlier top-5 cap let an alphabetical rule-id tiebreak decide which
    HIGH finding was reduced to a one-liner.
    """
    top, other = split_findings(_views(
        "critical", "high", "high", "high", "high", "high", "medium", "low"
    ))
    assert len(top) == 6
    assert {f.severity for f in other} == {"medium", "low"}


def test_a_clean_site_still_shows_a_few_findings_in_detail():
    top, other = split_findings(_views("low", "low", "low", "info"))
    assert len(top) == 3
    assert len(other) == 1


def test_split_is_lossless():
    findings = _views("critical", "high", "medium", "low", "info")
    top, other = split_findings(findings)
    assert len(top) + len(other) == len(findings)
    assert not ({f.rule_id for f in top} & {f.rule_id for f in other})


# --------------------------------------------------------------------------
# view model
# --------------------------------------------------------------------------

FIELD_OBS = [
    obs_row("crux.available", 1.0, unit="bool", source="crux"),
    obs_row("crux.lcp.p75", 4900.0, unit="ms", source="crux"),
    obs_row("crux.inp.p75", 340.0, unit="ms", source="crux"),
    obs_row("crux.cls.p75", 0.06, unit="score", source="crux"),
    obs_row("crux.cwv_pass", 0.0, unit="bool", source="crux"),
    obs_row("http.ttfb", 1340.0, unit="ms"),
    obs_row("http.content_bytes", 412_000.0, unit="bytes"),
    obs_row("http.compressed", 1.0, unit="bool"),
    obs_row("http.compression", text="gzip"),
    obs_row("redirect.hops", 2.0, unit="count", source="redirect"),
]


def test_verdict_counts_failing_vitals_in_plain_language():
    model = build_report_model(make_detail(FIELD_OBS), generated_at=STAMP)
    assert model.verdict.has_field_data is True
    assert model.verdict.passes is False
    assert "2 of 3" in model.verdict.headline


def test_verdict_says_so_when_there_is_neither_field_nor_lab_data():
    model = build_report_model(
        make_detail([obs_row("crux.available", 0.0, unit="bool", source="crux")]),
        generated_at=STAMP,
    )
    assert model.verdict.has_field_data is False
    assert model.verdict.has_lab_data is False
    assert "No real-user data" in model.verdict.headline


def test_verdict_leads_with_the_lab_score_when_field_data_is_missing():
    """A verdict page whose headline is an absence tells the client nothing.

    If we ran Lighthouse ourselves we have a number; lead with it.
    """
    model = build_report_model(
        make_detail([
            obs_row("crux.available", 0.0, unit="bool", source="crux"),
            obs_row("lh.score.performance", 63.0, unit="score", source="lighthouse"),
            obs_row("lh.runs", 3.0, unit="count", source="lighthouse"),
        ]),
        generated_at=STAMP,
    )
    assert model.verdict.has_lab_data is True
    assert "63 out of 100" in model.verdict.headline
    assert "our own controlled tests" in model.verdict.explanation


def test_tiles_carry_a_status_word_not_just_a_colour():
    """Accessibility contract: status colour never travels alone."""
    model = build_report_model(make_detail(FIELD_OBS), generated_at=STAMP)
    for tile in model.verdict.tiles:
        assert tile.status_word
    words = {t.status_word for t in model.verdict.tiles}
    assert words == {"Poor", "Needs work", "Good"}


def test_security_section_marks_missing_headers():
    model = build_report_model(
        make_detail([obs_row("sec.hsts", text="max-age=31536000")]), generated_at=STAMP
    )
    assert model.security.headers_present == 1
    missing = [r for r in model.security.headers if r.status_word == "Missing"]
    assert len(missing) == 5
    assert all(r.status_word for r in model.security.headers)


def test_every_status_dot_has_sizing_css():
    """Regression: `.dot` sizing scoped under `.badge` made the security
    table's dots zero-sized, so those rows printed status as a bare word."""
    html = render_report_html(
        make_detail(FIELD_OBS + [obs_row("tls.valid", 1.0, unit="bool", source="tls")]),
        generated_at=STAMP,
    )
    import re

    assert 'class="status-cell"' in html
    css = html.split("<style>")[1].split("</style>")[0]
    # The rule must be unscoped, i.e. `.dot {` at the start of a line, not
    # `.badge .dot {` or `.verdict-flag .dot {`.
    match = re.search(r"^\.dot\s*\{([^}]*)\}", css, re.MULTILINE)
    assert match, "no unscoped `.dot` rule; status dots will collapse to 0x0"
    assert "width: 8px" in match.group(1)
    assert "height: 8px" in match.group(1)


def test_tls_1_2_is_acceptable_not_current():
    model = build_report_model(
        make_detail([
            obs_row("tls.valid", 1.0, unit="bool", source="tls"),
            obs_row("tls.protocol", text="TLSv1.2", source="tls"),
        ]),
        generated_at=STAMP,
    )
    row = next(r for r in model.security.tls if r.label == "TLS version")
    assert row.status_word == "Acceptable"


def test_obsolete_tls_is_flagged_critical():
    model = build_report_model(
        make_detail([
            obs_row("tls.valid", 1.0, unit="bool", source="tls"),
            obs_row("tls.protocol", text="TLSv1.1", source="tls"),
        ]),
        generated_at=STAMP,
    )
    row = next(r for r in model.security.tls if r.label == "TLS version")
    assert (row.status, row.status_word) == ("critical", "Obsolete")


def test_expired_certificate_does_not_read_as_negative_days():
    model = build_report_model(
        make_detail([
            obs_row("tls.valid", 0.0, unit="bool", source="tls"),
            obs_row("tls.days_to_expiry", -4.0, unit="days", source="tls"),
        ]),
        generated_at=STAMP,
    )
    row = next(r for r in model.security.tls if "expir" in r.label.lower())
    assert row.value_text == "Expired 4 days ago"
    assert row.status == "critical"


def test_numeric_columns_keep_a_right_gutter():
    """Regression: zeroing padding-right made '200' collide with 'http'."""
    import re

    html = render_report_html(make_detail(FIELD_OBS), generated_at=STAMP)
    css = html.split("<style>")[1].split("</style>")[0]
    rule = re.search(r"td\.num, th\.num \{([^}]*)\}", css).group(1)
    assert "padding-left" in rule
    assert "padding:" not in rule, "do not rewrite the padding shorthand here"


def test_appendix_includes_every_observation():
    model = build_report_model(make_detail(FIELD_OBS), generated_at=STAMP)
    assert len(model.appendix) == len(FIELD_OBS)


def test_evidence_is_formatted_not_raw():
    detail = make_detail(FIELD_OBS, [finding_row(
        "heavy-html", "low", "Large document",
        evidence_json='{"http.content_bytes": 412000}',
    )])
    model = build_report_model(detail, generated_at=STAMP)
    chip = model.top_findings[0].evidence[0]
    assert chip.value_text == "402 KB"


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------

def test_report_html_renders_and_contains_the_verdict():
    html = render_report_html(make_detail(FIELD_OBS), generated_at=STAMP)
    assert "<!doctype html>" in html
    assert "2 of 3" in html
    assert "Largest Contentful Paint" in html
    assert "4.9s" in html


def test_report_html_inlines_its_css_so_the_file_stands_alone():
    html = render_report_html(make_detail(FIELD_OBS), generated_at=STAMP)
    assert "--critical: #d03b3b" in html
    assert "print-color-adjust: exact" in html
    assert "<link" not in html


def test_report_html_escapes_hostile_content():
    detail = make_detail(FIELD_OBS, [finding_row(
        "x", "high", "<script>alert(1)</script>",
    )])
    html = render_report_html(detail, generated_at=STAMP)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_a_site_with_no_findings_reads_as_clean_not_info():
    from slap.report.model import build_batch_model

    runs = [{"id": 1, "hostname": "clean.test", "status": "completed"}]
    model = build_batch_model(
        "b", runs, {1: make_detail(FIELD_OBS, [], "clean.test")}, generated_at=STAMP
    )
    assert model.rows[0].worst_word == "Clean"
    assert model.rows[0].worst_status == "good"


def test_clean_sites_sort_below_sites_with_findings():
    from slap.report.model import build_batch_model

    runs = [
        {"id": 1, "hostname": "clean.test", "status": "completed"},
        {"id": 2, "hostname": "minor.test", "status": "completed"},
    ]
    details = {
        1: make_detail(FIELD_OBS, [], "clean.test"),
        2: make_detail(FIELD_OBS, [finding_row("a", "info", "FYI")], "minor.test"),
    }
    model = build_batch_model("b", runs, details, generated_at=STAMP)
    assert [r.hostname for r in model.rows] == ["minor.test", "clean.test"]


def test_batch_html_renders_and_ranks_worst_first():
    runs = [
        {"id": 1, "hostname": "clean.test", "status": "completed"},
        {"id": 2, "hostname": "broken.test", "status": "completed"},
    ]
    details = {
        1: make_detail(FIELD_OBS, [finding_row("a", "low", "Minor")], "clean.test"),
        2: make_detail(FIELD_OBS, [finding_row("b", "critical", "Bad")], "broken.test"),
    }
    html = render_batch_html("abc123", runs, details, generated_at=STAMP)
    assert html.index("broken.test") < html.index("clean.test")


def test_safe_filename_handles_windows_reserved_names():
    # Dots survive: "example.com-7.pdf" is more readable than "example-com-7.pdf".
    assert safe_filename("example.com") == "example.com"
    assert safe_filename("a b/c:d") == "a-b-c-d"
    # CON.pdf is unopenable on Windows even with the extension.
    assert safe_filename("con") != "con"
    assert safe_filename("COM1").startswith("site-")
    assert safe_filename("") == "report"


# --------------------------------------------------------------------------
# PDF (skipped without Playwright)
# --------------------------------------------------------------------------

pdf_backend = pytest.mark.skipif(
    not check_backend(), reason="Playwright Chromium not installed"
)


@pdf_backend
def test_pdf_renders_from_the_html_file(tmp_path):
    from slap.report import html_file_to_pdf, write_html

    html_path = write_html(
        render_report_html(make_detail(FIELD_OBS), generated_at=STAMP),
        tmp_path / "r.html",
    )
    pdf_path = html_file_to_pdf(html_path, tmp_path / "r.pdf", title="Test")
    assert pdf_path.exists()
    assert pdf_path.stat().st_size > 5000
    assert pdf_path.read_bytes()[:5] == b"%PDF-"


@pdf_backend
def test_merge_concatenates_page_counts(tmp_path):
    from pypdf import PdfReader

    from slap.report import html_file_to_pdf, merge_pdfs, write_html

    paths = []
    for i in range(2):
        html = write_html(
            render_report_html(make_detail(FIELD_OBS), generated_at=STAMP),
            tmp_path / f"r{i}.html",
        )
        paths.append(html_file_to_pdf(html, tmp_path / f"r{i}.pdf"))

    merged = merge_pdfs(paths, tmp_path / "all.pdf")
    expected = sum(len(PdfReader(str(p)).pages) for p in paths)
    assert len(PdfReader(str(merged)).pages) == expected


def test_html_survives_when_the_pdf_backend_is_missing(tmp_path, monkeypatch):
    """A teammate who skipped `playwright install` must still get the report."""
    from slap import core, db
    from slap.config import Settings
    from slap.report import PdfError
    from slap.schema import FormFactor, RunStatus, obs

    settings = Settings(db_path=tmp_path / "s.sqlite3", report_dir=tmp_path / "out")
    conn = db.init_db(settings.db_path)
    with db.transaction(conn):
        site_id = db.upsert_site(conn, "example.test")
        run_id = db.create_run(conn, batch_id="b1", site_id=site_id,
                               slap_version="0.1.0", schema_version=1)
        page_id = db.create_page(conn, run_id, "https://example.test", None,
                                 FormFactor.NONE)
        db.insert_observations(conn, page_id, [obs("http.status", 200)])
        db.finish_run(conn, run_id, RunStatus.COMPLETED)

    async def boom(*args, **kwargs):
        raise PdfError("Playwright is not installed.")

    monkeypatch.setattr("slap.report.html_file_to_pdf_async", boom)

    result = core.export_report(settings, run_id, pdf=True)
    assert result.html_path.exists()
    assert result.html_path.stat().st_size > 1000
    assert result.pdf_path is None
    assert "Playwright" in result.pdf_error
    db.close_thread_connections()


def test_sync_pdf_wrapper_refuses_to_run_inside_an_event_loop():
    """Guards the GUI case: calling the sync helper from the worker thread."""
    import asyncio

    from slap.report import PdfError, html_file_to_pdf

    async def attempt():
        with pytest.raises(PdfError, match="event loop"):
            html_file_to_pdf("x.html", "x.pdf")

    asyncio.run(attempt())
