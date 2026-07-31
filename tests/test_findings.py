"""Tests for the rules-are-data engine, including the shipped rules.yaml."""

from __future__ import annotations

import pytest

from slap.findings.engine import (
    FindingsEngine,
    Rule,
    RuleError,
    evaluate,
    render_template,
)
from slap.schema import Severity


# --------------------------------------------------------------------------
# condition interpreter
# --------------------------------------------------------------------------

@pytest.mark.parametrize("condition,values,expected", [
    ({"metric": "http.ttfb", "gt": 800}, {"http.ttfb": 1200}, True),
    ({"metric": "http.ttfb", "gt": 800}, {"http.ttfb": 400}, False),
    ({"metric": "http.ttfb", "gt": 800}, {}, False),
    ({"metric": "sec.csp", "missing": True}, {}, True),
    ({"metric": "sec.csp", "missing": True}, {"sec.csp": "default-src"}, False),
    ({"metric": "sec.csp", "present": True}, {"sec.csp": "default-src"}, True),
    ({"metric": "http.compressed", "is": False}, {"http.compressed": False}, True),
    ({"metric": "http.compressed", "is": False}, {"http.compressed": True}, False),
    ({"metric": "tls.protocol", "in": ["TLSv1", "TLSv1.1"]}, {"tls.protocol": "TLSv1"}, True),
    ({"metric": "tls.protocol", "in": ["TLSv1"]}, {"tls.protocol": "TLSv1.3"}, False),
    ({"metric": "tech.cache_plugin", "contains": ","}, {"tech.cache_plugin": "A, B"}, True),
    ({"metric": "http.server", "matches": r"[0-9]+\.[0-9]+"}, {"http.server": "nginx/1.24.0"}, True),
    ({"metric": "http.server", "matches": r"[0-9]+\.[0-9]+"}, {"http.server": "nginx"}, False),
])
def test_leaf_conditions(condition, values, expected):
    assert evaluate(condition, values) is expected


def test_boolean_false_is_not_confused_with_missing():
    """The bug this guards: `is: false` must not fire on an absent metric."""
    assert evaluate({"metric": "http.compressed", "is": False}, {}) is False


def test_zero_is_not_treated_as_missing():
    assert evaluate({"metric": "http.cache_max_age", "lt": 300},
                    {"http.cache_max_age": 0}) is True


def test_nested_all_any_none():
    values = {"a": 1, "b": 5}
    assert evaluate({"all": [{"metric": "a", "eq": 1}, {"metric": "b", "gt": 3}]}, values)
    assert evaluate({"any": [{"metric": "a", "eq": 99}, {"metric": "b", "gt": 3}]}, values)
    assert evaluate({"none": [{"metric": "a", "eq": 99}]}, values)
    assert not evaluate({"none": [{"metric": "a", "eq": 1}]}, values)


def test_condition_without_operator_is_a_rule_error():
    with pytest.raises(RuleError):
        evaluate({"metric": "a"}, {"a": 1})


def test_condition_without_metric_is_a_rule_error():
    with pytest.raises(RuleError):
        evaluate({"gt": 5}, {})


# --------------------------------------------------------------------------
# templating
# --------------------------------------------------------------------------

def test_render_template_formats_by_the_registry_unit():
    """A rule writes {http.ttfb}; the formatter supplies 'ms' or 's' itself.

    Rule text must therefore not append its own unit, or you get '412msms'.
    """
    assert render_template("TTFB {http.ttfb}", {"http.ttfb": 412.0}) == "TTFB 412ms"
    assert render_template("TTFB {http.ttfb}", {"http.ttfb": 1340.0}) == "TTFB 1.3s"


def test_render_template_humanises_byte_counts():
    """A raw byte count in a client-facing title reads as a bug."""
    rendered = render_template("{http.content_bytes}", {"http.content_bytes": 412_000})
    assert rendered == "402 KB"


def test_render_template_does_not_percentage_cls():
    """CLS is a unitless score. Rendering 0.06 as '6%' is wrong."""
    assert render_template("{crux.cls.p75}", {"crux.cls.p75": 0.06}) == "0.06"
    # A genuine ratio still renders as a percentage.
    assert render_template("{crux.lcp.good}", {"crux.lcp.good": 0.38}) == "38%"


def test_no_shipped_rule_appends_a_unit_after_a_placeholder():
    """Guards the '412msms' regression across the whole rules file."""
    import re

    from slap.findings.engine import RULES_PATH

    text = RULES_PATH.read_text(encoding="utf-8")
    offenders = re.findall(r"\{[a-z][\w.]*\}\s*(?:ms|bytes|seconds|days)\b", text)
    assert offenders == [], f"rule text appends units the formatter supplies: {offenders}"


def test_render_template_marks_unknown_keys_rather_than_crashing():
    assert render_template("v={wprocket.version}", {}) == "v=n/a"


def test_render_template_leaves_non_placeholder_braces_alone():
    assert render_template("{not a key}", {}) == "{not a key}"


# --------------------------------------------------------------------------
# rules
# --------------------------------------------------------------------------

def test_rule_rejects_unknown_severity():
    with pytest.raises(RuleError):
        Rule.from_dict({"id": "x", "severity": "catastrophic", "title": "t", "when": {}})


def test_engine_rejects_duplicate_rule_ids():
    raw = {"id": "dup", "severity": "low", "title": "t", "when": {"metric": "a", "eq": 1}}
    with pytest.raises(RuleError):
        FindingsEngine([Rule.from_dict(raw), Rule.from_dict(raw)])


def test_default_evidence_is_the_metrics_the_condition_touched():
    rule = Rule.from_dict({
        "id": "r", "severity": "high", "title": "t", "detail": "d",
        "when": {"all": [{"metric": "http.ttfb", "gt": 100},
                         {"metric": "http.status", "eq": 200}]},
    })
    finding = rule.to_finding({"http.ttfb": 900, "http.status": 200, "other": 1})
    assert finding.evidence == {"http.ttfb": 900, "http.status": 200}


# --------------------------------------------------------------------------
# the shipped rules.yaml
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def engine() -> FindingsEngine:
    return FindingsEngine.load()


def test_shipped_rules_load_and_are_unique(engine):
    assert len(engine.rules) >= 20


def test_every_shipped_rule_has_a_detail(engine):
    missing = [r.id for r in engine.rules if not r.detail.strip()]
    assert missing == [], f"rules without detail: {missing}"


def test_clean_site_produces_no_high_severity_findings(engine):
    clean = {
        "http.status": 200, "http.compressed": True, "http.content_bytes": 40000,
        "http.ttfb": 180, "http.version": "HTTP/2", "http.cache_max_age": 3600,
        "http.has_etag": True, "http.server": "nginx",
        "http.cache_control": "public, max-age=3600",
        "sec.hsts": "max-age=31536000", "sec.hsts_max_age": 31536000,
        "sec.csp": "default-src 'self'; frame-ancestors 'none'",
        "sec.x_content_type_options": "nosniff", "sec.x_frame_options": "DENY",
        "sec.referrer_policy": "strict-origin-when-cross-origin",
        "sec.permissions_policy": "geolocation=()",
        "sec.cookies_total": 0,
        "redirect.hops": 0, "tls.valid": True, "tls.days_to_expiry": 75,
        "tls.protocol": "TLSv1.3",
        "crux.available": True, "crux.cwv_pass": True,
        "crux.lcp.p75": 1800, "crux.inp.p75": 120, "crux.cls.p75": 0.02,
    }
    findings = engine.run(clean)
    high = [f.rule_id for f in findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    assert high == [], f"clean site should not raise: {high}"


def test_wprocket_cold_cache_fires_and_names_the_setting(engine):
    findings = engine.run({
        "wprocket.present": True,
        "wprocket.page_cached": False,
        "wprocket.version": "3.15.9",
    })
    by_id = {f.rule_id: f for f in findings}
    assert "wprocket-cache-cold" in by_id
    finding = by_id["wprocket-cache-cold"]
    assert finding.severity is Severity.HIGH
    assert "3.15.9" in finding.detail
    assert finding.wp_rocket_setting


def test_wprocket_rule_does_not_fire_when_the_plugin_is_absent(engine):
    findings = engine.run({"wprocket.present": False})
    assert "wprocket-cache-cold" not in {f.rule_id for f in findings}


def test_findings_are_sorted_most_severe_first(engine):
    findings = engine.run({
        "tls.valid": False, "tls.error": "expired",
        "sec.referrer_policy": None,
        "http.compressed": False, "http.content_bytes": 90000,
    })
    severities = [f.severity for f in findings]
    assert severities[0] is Severity.CRITICAL
    assert severities == sorted(
        severities,
        key=lambda s: ["critical", "high", "medium", "low", "info"].index(s.value),
    )


def test_impact_ms_is_populated_from_the_named_metric(engine):
    findings = engine.run({"http.ttfb": 1500})
    ttfb = next(f for f in findings if f.rule_id == "slow-ttfb")
    assert ttfb.impact_ms == 1500.0
