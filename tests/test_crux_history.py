"""Field-data history: parsing, storage, and how it reaches the report.

No CrUX key exists in this environment, so the collector is proven against a
response built to the documented shape and its no-key path is proven to say
so rather than imply no history exists.
"""

from __future__ import annotations

import asyncio

import pytest

from slap import core, db
from slap.collectors.base import CollectorConfig, PageContext
from slap.collectors.crux_history import (
    DEFAULT_PERIODS,
    HISTORY_METRICS,
    CruxHistoryCollector,
    crossed_threshold,
    parse_history,
    series_for,
    summarise,
)
from slap.config import Settings
from slap.report.model import TREND_WORDS, build_report_model, field_sparkline
from tests.fixtures.crux_history import (
    CLS_P75,
    INP_P75,
    LCP_P75,
    PERIOD_COUNT,
    response,
)


# --------------------------------------------------------------------------
# Parsing. The response is transposed, which is where alignment goes wrong.
# --------------------------------------------------------------------------

def test_periods_and_metrics_are_transposed_into_flat_points():
    points = parse_history(response())
    assert {p["metric_key"] for p in points} == {
        "crux.lcp.p75", "crux.inp.p75", "crux.cls.p75"}
    assert len(series_for(points, "crux.cls.p75")) == PERIOD_COUNT


def test_a_null_period_is_skipped_not_stored_as_zero():
    """A zero LCP would plot as a perfect score."""
    points = series_for(parse_history(response()), "crux.lcp.p75")
    assert len(points) == PERIOD_COUNT - 1        # one null in the fixture
    assert all(p["p75"] for p in points)


def test_a_short_metric_array_truncates_rather_than_misaligns():
    """Real responses carry short arrays for thin metrics. Zipping past the
    end attributes one week's number to a different week."""
    points = series_for(parse_history(response()), "crux.inp.p75")
    assert len(points) == len(INP_P75)
    assert [p["p75"] for p in points] == [float(v) for v in INP_P75]
    # And they map to the EARLIEST periods, which is where the API puts them.
    ends = [p["period_end"] for p in points]
    assert ends == sorted(ends)
    assert ends[0] == "2026-01-03"


def test_dates_are_zero_padded():
    """These strings are ordered as text by the storage layer, and
    "2026-2-1" sorts after "2026-11-01"."""
    for point in parse_history(response()):
        assert len(point["period_end"]) == 10
        assert point["period_end"][4] == "-"


def test_density_bands_are_carried():
    point = series_for(parse_history(response()), "crux.cls.p75")[0]
    assert point["good"] is not None
    assert point["needs_improvement"] is not None
    assert point["poor"] is not None


def test_a_missing_metric_is_simply_absent():
    points = parse_history(response(include_inp=False))
    assert series_for(points, "crux.inp.p75") == []
    assert series_for(points, "crux.lcp.p75")


def test_an_empty_payload_parses_to_nothing():
    assert parse_history({}) == []
    assert parse_history({"record": {}}) == []


# --------------------------------------------------------------------------
# Crossings, not deltas
# --------------------------------------------------------------------------

def test_a_threshold_crossing_is_what_counts_not_the_delta():
    """1.2s -> 2.4s doubled and still passes; 2.4s -> 2.6s barely moved and
    now fails. Only the second is worth a client's attention."""
    points = parse_history(response())
    assert crossed_threshold(points, "crux.lcp.p75") == "regressed"


def test_a_large_improvement_that_never_crosses_is_not_reported():
    """CLS improves 0.16 -> 0.12 in the fixture and never reaches 0.1."""
    points = parse_history(response())
    assert crossed_threshold(points, "crux.cls.p75") is None


def test_an_improvement_across_the_threshold_is_reported():
    points = [
        {"metric_key": "crux.lcp.p75", "period_start": "2026-01-01",
         "period_end": "2026-01-07", "p75": 3200.0},
        {"metric_key": "crux.lcp.p75", "period_start": "2026-02-01",
         "period_end": "2026-02-07", "p75": 2100.0},
    ]
    assert crossed_threshold(points, "crux.lcp.p75") == "improved"


def test_one_period_cannot_establish_a_trend():
    points = [{"metric_key": "crux.lcp.p75", "period_start": "2026-01-01",
               "period_end": "2026-01-07", "p75": 3200.0}]
    assert crossed_threshold(points, "crux.lcp.p75") is None


def test_the_summary_reports_both_directions():
    values = {o.metric_key: o.value for o in summarise(parse_history(response()))}
    assert values["crux.history.available"] is True
    assert values["crux.history.weeks"] == PERIOD_COUNT
    assert values["crux.history.regressed"] is True
    assert values["crux.history.regressed_metrics"] == "LCP"
    assert values["crux.history.improved"] is False
    assert values["crux.history.lcp.delta"] == float(LCP_P75[-1] - LCP_P75[0])


def test_no_points_reports_unavailable_rather_than_silence():
    values = {o.metric_key: o.value for o in summarise([])}
    assert values["crux.history.available"] is False


# --------------------------------------------------------------------------
# Storage. The first table that does not hang off a run.
# --------------------------------------------------------------------------

@pytest.fixture
def conn(tmp_path):
    c = db.init_db(tmp_path / "slap.sqlite3")
    yield c
    db.close_thread_connections()


def test_periods_are_stored_once_across_repeated_audits(conn):
    """Two audits a week apart share 24 of 25 periods. Keying this to runs
    would duplicate ~96% of it and every trend query would need a dedup."""
    points = parse_history(response())
    db.insert_crux_history(conn, "https://x.test", "PHONE", points)
    db.insert_crux_history(conn, "https://x.test", "PHONE", points)
    db.insert_crux_history(conn, "https://x.test", "PHONE", points)
    conn.commit()
    total = conn.execute("SELECT COUNT(*) FROM crux_history").fetchone()[0]
    assert total == len(points)


def test_a_revised_period_overwrites_rather_than_duplicates(conn):
    """Google revises recent periods as late data lands, and the newer
    answer is the better one."""
    base = [{"period_start": "2026-01-01", "period_end": "2026-01-28",
             "metric_key": "crux.lcp.p75", "p75": 2000.0}]
    revised = [dict(base[0], p75=2400.0)]
    db.insert_crux_history(conn, "https://x.test", "PHONE", base)
    db.insert_crux_history(conn, "https://x.test", "PHONE", revised)
    conn.commit()
    series = db.crux_history(conn, "https://x.test", "crux.lcp.p75")
    assert len(series) == 1
    assert series[0]["p75"] == 2400.0


def test_the_series_comes_back_oldest_first(conn):
    """It is plotted left to right, and reversing in a template is the kind
    of computation templates must not do."""
    db.insert_crux_history(conn, "https://x.test", "PHONE",
                           parse_history(response()))
    conn.commit()
    series = db.crux_history(conn, "https://x.test", "crux.cls.p75")
    ends = [p["period_end"] for p in series]
    assert ends == sorted(ends)


def test_origins_are_kept_apart(conn):
    points = parse_history(response())
    db.insert_crux_history(conn, "https://a.test", "PHONE", points)
    db.insert_crux_history(conn, "https://b.test", "PHONE", points)
    conn.commit()
    assert db.crux_history_origins(conn) == ["https://a.test", "https://b.test"]
    assert len(db.crux_history(conn, "https://a.test", "crux.cls.p75")) == PERIOD_COUNT


def test_form_factors_are_kept_apart(conn):
    points = parse_history(response())
    db.insert_crux_history(conn, "https://x.test", "PHONE", points)
    db.insert_crux_history(conn, "https://x.test", "DESKTOP", points)
    conn.commit()
    assert db.crux_history(conn, "https://x.test", "crux.cls.p75",
                           form_factor="DESKTOP")
    total = conn.execute("SELECT COUNT(*) FROM crux_history").fetchone()[0]
    assert total == len(points) * 2


# --------------------------------------------------------------------------
# The collector
# --------------------------------------------------------------------------

def _context(api_key: str | None):
    config = CollectorConfig(crux_api_key=api_key)
    return PageContext(url="https://x.test/", client=None, config=config)


def test_without_a_key_it_says_so_rather_than_implying_no_history():
    """Otherwise the report cannot tell "no history exists for this origin"
    from "we never asked"."""
    values = {o.metric_key: o.value
              for o in asyncio.run(CruxHistoryCollector().collect(_context(None)))}
    assert values == {"crux.history.available": False}


def test_it_is_origin_scoped():
    """The History API has no url form at all."""
    from slap.schema import Scope

    assert CruxHistoryCollector.scope is Scope.ORIGIN


def test_the_period_count_is_clamped_to_the_api_range():
    assert CruxHistoryCollector(periods=999).periods == 40
    assert CruxHistoryCollector(periods=0).periods == 1
    assert CruxHistoryCollector().periods == DEFAULT_PERIODS


def test_only_the_three_assessed_metrics_are_requested():
    """Each extra metric is more quota and more response for a line nobody
    puts in front of a client."""
    assert set(HISTORY_METRICS) == {
        "largest_contentful_paint", "interaction_to_next_paint",
        "cumulative_layout_shift"}


def test_the_collector_shares_the_point_in_time_rate_limiter():
    """150 queries/minute is shared across both CrUX endpoints, so two
    independent limiters would let a wide batch burst through it."""
    from slap.collectors import default_pipeline
    from slap.collectors.crux import TokenBucket

    bucket = TokenBucket(2.0)
    pipeline = default_pipeline(bucket)
    collectors = {c.name: c for stage in pipeline for c in stage}
    assert collectors["crux"]._bucket is bucket
    assert collectors["crux-history"]._bucket is bucket


# --------------------------------------------------------------------------
# Reaching the report. Both of these were found by looking at the render.
# --------------------------------------------------------------------------

def test_history_alone_counts_as_field_data(tmp_path):
    """The page announced "No real-user data is available for this site"
    directly above a paragraph explaining how to read its eight-week
    real-user chart, with the tiles suppressed in between.

    `crux.available` answers "did the point-in-time endpoint return a
    record", which is a question about one API call, not about whether this
    report has real-user data to show.
    """
    from slap.report.model import build_verdict

    history = {"crux.lcp.p75": [
        {"period_end": "2026-01-03", "period_start": "2025-12-07", "p75": 2100.0},
        {"period_end": "2026-02-21", "period_start": "2026-01-25", "p75": 2790.0},
    ]}
    verdict = build_verdict({}, history)
    assert verdict.has_field_data is True
    assert "No real-user data" not in verdict.headline
    assert verdict.tiles


def test_a_tile_with_no_current_value_falls_back_to_the_latest_period():
    """A tile reading "No data" above its own trend line is a contradiction
    the reader resolves by trusting neither."""
    from slap.report.model import build_verdict

    history = {"crux.lcp.p75": [
        {"period_end": "2026-01-03", "period_start": "2025-12-07", "p75": 2100.0},
        {"period_end": "2026-02-21", "period_start": "2026-01-25", "p75": 2790.0},
    ]}
    tile = next(t for t in build_verdict({}, history).tiles
                if t.key == "crux.lcp.p75")
    assert tile.value_text == "2.8s"
    assert tile.status_word != "No data"


def test_trend_words_suit_the_metric():
    """"Faster" under a Cumulative Layout Shift heading is a category error,
    and the sort a client notices because it reads as though we do not know
    what the metric is.

    Asserted on the RENDERED tile, not on the constant: a test that reads the
    lookup table passes whether or not anything consults it, which is exactly
    how the first version of this test failed to catch the revert.
    """
    from slap.report.model import build_verdict

    def word(metric_key, first, last):
        history = {metric_key: [
            {"period_end": "2026-01-03", "period_start": "2025-12-07", "p75": first},
            {"period_end": "2026-02-21", "period_start": "2026-01-25", "p75": last},
        ]}
        tile = next(t for t in build_verdict({}, history).tiles
                    if t.key == metric_key)
        return tile.trend_word

    # Worsening, without crossing the threshold in either direction.
    assert word("crux.cls.p75", 0.30, 0.45) == "Less stable"
    assert word("crux.cls.p75", 0.45, 0.30) == "More stable"
    assert word("crux.lcp.p75", 3000.0, 3800.0) == "Slower"
    assert word("crux.lcp.p75", 3800.0, 3000.0) == "Faster"
    assert word("crux.inp.p75", 300.0, 420.0) == "Less responsive"
    # And a crossing still takes precedence over direction.
    assert word("crux.lcp.p75", 2100.0, 2900.0) == "Crossed into failing"
    assert TREND_WORDS["crux.cls.p75"] == ("Less stable", "More stable")


def test_the_sparkline_scale_always_includes_the_threshold():
    """Auto-scaling to the data alone puts a series that never approaches the
    limit next to one about to cross it, and they look identical."""
    comfortable = [{"p75": 900.0}, {"p75": 950.0}, {"p75": 1000.0}]
    path, threshold_y = field_sparkline(comfortable, 2500.0)
    assert path
    # The threshold sits below the drawn line, inside the 34px box.
    assert threshold_y is not None
    assert 0 <= threshold_y <= 34


def test_a_flat_series_does_not_divide_by_zero():
    path, _ = field_sparkline([{"p75": 2000.0}] * 5, 2500.0)
    assert path


def test_too_few_points_draw_nothing():
    assert field_sparkline([{"p75": 2000.0}], 2500.0) == ("", None)
    assert field_sparkline([], 2500.0) == ("", None)


def test_the_report_carries_the_series_end_to_end(tmp_path):
    from tests.multipage_server import start as start_multipage

    httpd, base = start_multipage()
    settings = Settings()
    settings.db_path = tmp_path / "x.sqlite3"
    settings.artifact_dir = tmp_path / "a"
    settings.report_dir = tmp_path / "r"
    settings.collector.crux_api_key = None
    settings.lighthouse.enabled = False
    settings.discovery.pages_per_site = 4
    try:
        result = asyncio.run(core.run_batch([base], settings))
        run_id = result.run_ids[0]
        connection = db.connect(settings.db_path)
        origin = core.get_run_detail(settings, run_id)["origin"]
        assert origin

        points = parse_history(response())
        db.insert_crux_history(connection, origin, "PHONE", points)
        db.insert_observations(connection, db.home_page_id(connection, run_id),
                               summarise(points))
        connection.commit()

        detail = core.get_run_detail(settings, run_id)
        assert set(detail["crux_history"]) == {
            "crux.lcp.p75", "crux.inp.p75", "crux.cls.p75"}

        model = build_report_model(detail)
        lcp = next(t for t in model.verdict.tiles if t.key == "crux.lcp.p75")
        assert lcp.spark_path
        assert lcp.spark_weeks == PERIOD_COUNT - 1
        assert lcp.trend_word == "Crossed into failing"

        from slap.report import render_report_html
        html = render_report_html(detail)
        assert "spark-line" in html
        assert "28-day average" in html
    finally:
        httpd.shutdown()
        db.close_thread_connections()


# --------------------------------------------------------------------------
# The web front-end
# --------------------------------------------------------------------------

def test_the_field_trend_is_separate_from_the_run_trend():
    """One is what we measured on our own machine, the other is what visitors
    experienced. A single line splicing them would be indefensible the first
    time the two disagreed."""
    from slap_web import viewmodel as vm

    points = parse_history(response())
    history = {"crux.lcp.p75": series_for(points, "crux.lcp.p75")}
    trend = vm.build_field_trend(history)
    assert trend["empty"] is False
    assert trend["weeks"] == PERIOD_COUNT - 1
    assert trend["threshold_text"] == "2.5s"
    assert trend["status_word"] == "Outside target"
    assert trend["path"]


def test_a_site_with_no_field_history_renders_nothing_rather_than_an_empty_axis():
    from slap_web import viewmodel as vm

    assert vm.build_field_trend({})["empty"] is True
    assert vm.build_field_trend({"crux.lcp.p75": [{"p75": None}]})["empty"] is True


def test_the_site_page_shows_the_field_trend(tmp_path):
    fastapi = pytest.importorskip("fastapi", reason="web extra not installed")
    from fastapi.testclient import TestClient

    from slap_web.app import create_app
    from tests.multipage_server import start as start_multipage

    httpd, base = start_multipage()
    settings = Settings()
    settings.db_path = tmp_path / "x.sqlite3"
    settings.artifact_dir = tmp_path / "a"
    settings.report_dir = tmp_path / "r"
    settings.collector.crux_api_key = None
    settings.lighthouse.enabled = False
    settings.discovery.pages_per_site = 3
    try:
        result = asyncio.run(core.run_batch([base], settings))
        connection = db.connect(settings.db_path)
        origin = core.get_run_detail(settings, result.run_ids[0])["origin"]
        db.insert_crux_history(connection, origin, "PHONE",
                               parse_history(response()))
        connection.commit()

        site_id = db.find_site_by_hostname(connection, "127.0.0.1")["id"]
        detail = core.get_site_detail(settings, site_id)
        assert detail["field_history"], "the site page must find the series"

        page = TestClient(create_app(settings)).get(f"/site/{site_id}")
        assert page.status_code == 200
        # Whitespace-normalised, because the template wraps this sentence
        # across lines and HTML collapses that to a single space. A raw
        # substring check tests the template's indentation, not the text the
        # reader sees.
        rendered = " ".join(page.text.split())
        assert "Real visitors" in rendered
        assert "28-day average" in rendered
        assert "Good is 2.5s or less" in rendered
    finally:
        httpd.shutdown()
        db.close_thread_connections()
