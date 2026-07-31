"""Phase 2 tests.

The extraction tests run against recorded LHR fixtures with no browser, so
they are fast and always run. The tests that actually drive Chrome are
marked ``lighthouse`` and skip when the worker is not installed.

The recorded fixtures matter more than usual here. Lighthouse 13 renamed
every opportunity audit and moved the savings API, so an extractor written
from memory returns nothing and looks fine. These fixtures are real output
from Lighthouse 13.4.1.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from slap.collectors.lighthouse import (
    LighthouseConfig,
    LighthouseRunner,
    _audit_savings,
    aggregate,
    extract_values,
)
from slap.findings import FindingsEngine
from slap.schema import LIGHTHOUSE_OPPORTUNITIES, METRIC_REGISTRY

FIXTURE_DIR = Path(__file__).parent / "fixtures"
# Stored gzipped: an LHR is ~850KB of JSON and this one lives in the repo.
SLOW_LHR = FIXTURE_DIR / "slow-lhr.json.gz"


@pytest.fixture(scope="module")
def slow_lhr() -> dict:
    if not SLOW_LHR.exists():
        pytest.skip("recorded LHR fixture missing")
    import gzip

    return json.loads(gzip.decompress(SLOW_LHR.read_bytes()))


def _runner_available() -> bool:
    return LighthouseRunner(LighthouseConfig()).check()[0]


lighthouse_backend = pytest.mark.skipif(
    not _runner_available(), reason="Lighthouse worker not installed"
)


# --------------------------------------------------------------------------
# The registry contract
# --------------------------------------------------------------------------

def test_every_opportunity_has_a_registered_metric():
    for suffix, _label in LIGHTHOUSE_OPPORTUNITIES.values():
        assert f"lh.opp.{suffix}" in METRIC_REGISTRY


def test_opportunity_ids_are_lighthouse_13_names():
    """Guards the exact trap Phase 2 walked into.

    Lighthouse 13 removed the classic opportunity audits. A rule written
    against `render-blocking-resources` never fires and the audit silently
    finds nothing, which is worse than an error.
    """
    removed = {
        "render-blocking-resources", "uses-long-cache-ttl",
        "modern-image-formats", "offscreen-images", "uses-optimized-images",
        "uses-responsive-images", "font-display", "legacy-javascript",
        "third-party-summary", "dom-size", "uses-text-compression",
    }
    assert not (removed & set(LIGHTHOUSE_OPPORTUNITIES)), (
        "these audit ids do not exist in Lighthouse 13"
    )


# --------------------------------------------------------------------------
# Savings extraction
# --------------------------------------------------------------------------

def test_savings_read_from_metric_savings_for_insights():
    audit = {"metricSavings": {"FCP": 300, "LCP": 2700}}
    assert _audit_savings(audit, "render-blocking-insight") == 2700


def test_insight_without_metric_savings_yields_none():
    """Must NOT fall back to numericValue.

    dom-size-insight's numericValue is an element count; reporting 3604 as
    "3.6 seconds of saving" would be nonsense in a client report.
    """
    audit = {"numericValue": 3604, "numericUnit": "element"}
    assert _audit_savings(audit, "dom-size-insight") is None


def test_classic_audit_falls_back_to_overall_savings():
    audit = {"details": {"overallSavingsMs": 1200}}
    assert _audit_savings(audit, "unminified-css") == 1200


def test_classic_audit_falls_back_to_millisecond_numeric_value():
    audit = {"numericValue": 450, "numericUnit": "millisecond"}
    assert _audit_savings(audit, "unused-javascript") == 450


def test_classic_audit_ignores_non_millisecond_numeric_value():
    audit = {"numericValue": 4379989, "numericUnit": "byte"}
    assert _audit_savings(audit, "total-byte-weight") is None


# --------------------------------------------------------------------------
# Against real recorded output
# --------------------------------------------------------------------------

def test_extracts_category_scores_as_0_to_100(slow_lhr):
    values = extract_values(slow_lhr)
    assert 0 <= values["lh.score.performance"] <= 100
    assert values["lh.score.performance"] == int(values["lh.score.performance"])
    for key in ("lh.score.accessibility", "lh.score.best_practices", "lh.score.seo"):
        assert key in values


def test_extracts_core_lab_metrics(slow_lhr):
    values = extract_values(slow_lhr)
    for key in ("lh.lcp", "lh.fcp", "lh.tbt", "lh.cls", "lh.speed_index",
                "lh.total_bytes", "lh.benchmark_index"):
        assert key in values, key


def test_a_bad_page_actually_fires_opportunities(slow_lhr):
    """The whole point of the slow fixture.

    A clean page yields zero savings everywhere, so it cannot tell a working
    extractor from a broken one.
    """
    values = extract_values(slow_lhr)
    opportunities = {k: v for k, v in values.items() if k.startswith("lh.opp.")}
    assert len(opportunities) >= 3, f"expected real savings, got {opportunities}"
    assert all(v > 0 for v in opportunities.values())
    assert "lh.opp.image_delivery" in opportunities


def test_every_extracted_key_is_registered(slow_lhr):
    for key in extract_values(slow_lhr):
        assert key in METRIC_REGISTRY, f"{key} is not in METRIC_REGISTRY"


def test_lab_rules_fire_against_real_output(slow_lhr):
    engine = FindingsEngine.load()
    findings = engine.run(extract_values(slow_lhr))
    ids = {f.rule_id for f in findings}
    assert "lh-image-delivery" in ids
    assert any(i.startswith("lh-") for i in ids)


def test_wp_rocket_settings_are_attached_to_lab_findings(slow_lhr):
    engine = FindingsEngine.load()
    findings = engine.run(extract_values(slow_lhr))
    lab = [f for f in findings if f.rule_id.startswith("lh-")]
    assert any(f.wp_rocket_setting for f in lab), (
        "lab findings should name the WP Rocket setting that fixes them"
    )


# --------------------------------------------------------------------------
# Median and spread
# --------------------------------------------------------------------------

def test_median_is_taken_not_the_mean():
    runs = [{"lh.lcp": 1000.0}, {"lh.lcp": 1100.0}, {"lh.lcp": 9000.0}]
    values = {o.metric_key: o.value for o in aggregate(runs)}
    assert values["lh.lcp"] == 1100.0  # mean would be 3700


def test_spread_is_recorded_so_a_noisy_run_is_visible():
    runs = [{"lh.lcp": 1000.0}, {"lh.lcp": 1100.0}, {"lh.lcp": 9000.0}]
    values = {o.metric_key: o.value for o in aggregate(runs)}
    assert values["lh.lcp.spread"] == 8000.0
    assert values["lh.runs"] == 3


def test_no_spread_emitted_for_a_single_run():
    values = {o.metric_key: o.value for o in aggregate([{"lh.lcp": 1000.0}])}
    assert "lh.lcp.spread" not in values
    assert values["lh.runs"] == 1


def test_scores_stay_integers_after_aggregation():
    runs = [{"lh.score.performance": 61}, {"lh.score.performance": 62},
            {"lh.score.performance": 64}]
    values = {o.metric_key: o.value for o in aggregate(runs)}
    assert values["lh.score.performance"] == 62


def test_a_metric_missing_from_one_run_is_not_treated_as_zero():
    runs = [{"lh.opp.cache": 400.0}, {}, {"lh.opp.cache": 600.0}]
    values = {o.metric_key: o.value for o in aggregate(runs)}
    assert values["lh.opp.cache"] == 500.0  # not 400


def test_aggregate_of_nothing_is_empty_not_a_crash():
    assert aggregate([]) == []


def test_meta_becomes_provenance_observations():
    values = {o.metric_key: o.value for o in aggregate(
        [{"lh.lcp": 1.0}],
        meta={"throttlingProfile": "mobile/simulate/lh13-default",
              "formFactor": "mobile"},
    )}
    assert values["lh.throttling_profile"] == "mobile/simulate/lh13-default"
    assert values["lh.form_factor"] == "mobile"


def test_unstable_measurement_rule_fires_on_a_wide_spread():
    engine = FindingsEngine.load()
    findings = engine.run({
        "lh.runs": 3, "lh.score.performance": 62,
        "lh.score.performance.spread": 18, "lh.lcp.spread": 2400,
    })
    assert "lh-unstable-measurement" in {f.rule_id for f in findings}


def test_contended_measurement_rule_fires_on_a_low_benchmark():
    engine = FindingsEngine.load()
    findings = engine.run({"lh.benchmark_index": 480, "lh.runs": 3})
    assert "lh-contended-measurement" in {f.rule_id for f in findings}


def test_stable_fast_machine_raises_neither_rule():
    engine = FindingsEngine.load()
    findings = engine.run({
        "lh.runs": 3, "lh.benchmark_index": 2100,
        "lh.benchmark_index.spread": 90,
        "lh.score.performance": 95, "lh.score.performance.spread": 2,
        "lh.lcp.spread": 200,
    })
    ids = {f.rule_id for f in findings}
    assert "lh-unstable-measurement" not in ids
    assert "lh-contended-measurement" not in ids


# --------------------------------------------------------------------------
# Configuration guards
# --------------------------------------------------------------------------

def test_lighthouse_is_off_by_default():
    """Enabling it takes a batch from seconds to ~90s per site."""
    assert LighthouseConfig().enabled is False


def test_lighthouse_concurrency_is_separate_from_http_concurrency():
    from slap.collectors.base import CollectorConfig

    assert LighthouseConfig().concurrency == 3
    assert CollectorConfig().http_concurrency == 20
    assert LighthouseConfig().concurrency < CollectorConfig().http_concurrency


def test_pipeline_omits_the_lighthouse_stage_when_no_runner_is_given():
    from slap.collectors import default_pipeline

    assert len(default_pipeline()) == 2
    assert len(default_pipeline(None, LighthouseRunner(LighthouseConfig()))) == 3


def test_runner_check_explains_what_is_missing():
    runner = LighthouseRunner(LighthouseConfig(node_path="definitely-not-node"))
    ok, detail = runner.check()
    assert ok is False
    assert "definitely-not-node" in detail


# --------------------------------------------------------------------------
# Live worker (skipped without Node + Lighthouse)
# --------------------------------------------------------------------------

@lighthouse_backend
def test_probe_reports_versions():
    import asyncio

    meta = asyncio.run(LighthouseRunner(LighthouseConfig()).probe())
    assert meta["lighthouseVersion"].startswith("13.")
    assert meta["chromeVersion"]


@lighthouse_backend
def test_worker_reports_a_bad_url_as_a_failed_run_not_a_crash():
    import asyncio

    runner = LighthouseRunner(LighthouseConfig(timeout=90))
    envelope = asyncio.run(runner.run_once("http://127.0.0.1:1/", "mobile"))
    assert envelope.ok is False
    assert envelope.error


# --------------------------------------------------------------------------
# Report integration
# --------------------------------------------------------------------------

def test_report_shows_category_scores_with_status_words(slow_lhr):
    """Same accessibility contract as everywhere else: never colour alone."""
    from datetime import datetime, timezone

    from slap.report.model import build_report_model

    values = extract_values(slow_lhr)
    observations = [
        {"metric_key": k, "numeric_value": v, "text_value": None,
         "unit": "score" if k.startswith("lh.score.") else "ms",
         "source": "lighthouse"}
        for k, v in values.items()
    ]
    detail = {
        "run": {"id": 1, "batch_id": "b", "hostname": "x.test", "status": "completed",
                "error": None, "slap_version": "0.1.0", "schema_version": 1,
                "started_at": "2026-07-31T01:00:00+00:00", "finished_at": None,
                "lh_version": "13.4.1", "chrome_version": "141.0.7390.37",
                "throttling_profile": "mobile/simulate/lh13-default"},
        "observations": observations,
        "findings": [],
    }
    model = build_report_model(
        detail, generated_at=datetime(2026, 7, 31, tzinfo=timezone.utc)
    )
    assert model.verdict.has_lab_data is True
    assert [c.label for c in model.verdict.categories] == [
        "Performance", "Accessibility", "Best Practices", "SEO"
    ]
    assert all(c.status_word for c in model.verdict.categories)
    assert model.provenance["lighthouse_version"] == "13.4.1"
    assert model.provenance["throttling_profile"] == "mobile/simulate/lh13-default"


def test_category_banding_matches_lighthouse_own_thresholds():
    """A client comparing against PageSpeed Insights must see the same colour."""
    from datetime import datetime, timezone

    from slap.report.model import build_report_model

    def score_status(value):
        detail = {
            "run": {"id": 1, "batch_id": "b", "hostname": "x.test",
                    "status": "completed", "error": None, "slap_version": "0.1.0",
                    "schema_version": 1, "started_at": "2026-07-31T01:00:00+00:00",
                    "finished_at": None, "lh_version": None, "chrome_version": None,
                    "throttling_profile": None},
            "observations": [{"metric_key": "lh.score.performance",
                              "numeric_value": value, "text_value": None,
                              "unit": "score", "source": "lighthouse"}],
            "findings": [],
        }
        model = build_report_model(
            detail, generated_at=datetime(2026, 7, 31, tzinfo=timezone.utc)
        )
        return model.verdict.categories[0].status

    assert score_status(90) == "good"
    assert score_status(89) == "needs-improvement"
    assert score_status(50) == "needs-improvement"
    assert score_status(49) == "poor"


# --------------------------------------------------------------------------
# Reading the worker's stdout
#
# A Windows CI build failed with the entire error message being
# "probe returned unparseable output:" and nothing after the colon. Every
# case below either produces a usable envelope or a message that names what
# actually happened.
# --------------------------------------------------------------------------

from slap.collectors.lighthouse import parse_envelope


def test_a_clean_envelope_parses():
    assert parse_envelope(b'{"ok": true, "meta": {"node": "v22"}}')["ok"] is True


def test_stray_output_before_the_envelope_does_not_lose_the_run():
    """The observed Windows failure: stdout non-empty and not JSON overall."""
    noisy = b'Some launcher banner\n{"ok": true, "meta": {"node": "v22"}}\n'
    assert parse_envelope(noisy) == {"ok": True, "meta": {"node": "v22"}}


def test_stray_output_after_the_envelope_also_works():
    noisy = b'{"ok": true, "meta": {}}\nWarning: something\n'
    assert parse_envelope(noisy) == {"ok": True, "meta": {}}


def test_the_last_envelope_wins():
    two = b'{"ok": false, "error": "first"}\n{"ok": true, "meta": {}}\n'
    assert parse_envelope(two)["ok"] is True


def test_empty_output_is_none_not_an_empty_envelope():
    """`json.loads(stdout or b"{}")` turned this into a valid {} and lost it."""
    assert parse_envelope(b"") is None
    assert parse_envelope(b"   \n") is None


def test_output_with_no_envelope_at_all_is_none():
    assert parse_envelope(b"MSVCP140.dll not found\n") is None


def test_a_json_array_is_not_an_envelope():
    assert parse_envelope(b"[1, 2, 3]") is None


def test_probe_failure_names_every_lookup(tmp_path):
    """The message has to say which node, worker and browser were used.

    On a frozen bundle those come from three separate lookups, any of which
    can miss, and the old message named none of them.
    """
    from slap.collectors.lighthouse import LighthouseConfig, LighthouseRunner

    worker = tmp_path / "worker.js"
    worker.write_text("//")
    runner = LighthouseRunner(LighthouseConfig(worker_path=worker,
                                               node_path="/usr/bin/node"))
    runner._chrome_path = "/somewhere/chrome"
    message = runner._probe_failure(3, b"", b"")

    assert "exit code 3" in message
    assert "stdout: (empty)" in message
    assert "stderr: (empty)" in message
    assert "/usr/bin/node" in message
    assert str(worker) in message
    assert "/somewhere/chrome" in message
