"""Network-free tests for the parsing logic. These are the ones that matter:
every parser here is a pure function precisely so it can be tested with a
string instead of a live site.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from slap.collectors.fingerprint import (
    detect_cache_plugins,
    detect_cdn,
    detect_cms,
    detect_page_builder,
    detect_wp_rocket,
    find_generator_meta,
    parse_attrs,
)
from slap.collectors.http_probe import (
    analyze_cookies,
    missing_security_headers,
    normalize_url,
    parse_hsts_max_age,
    parse_max_age,
    upgrades_to_https,
)
from slap.collectors.crux import core_web_vitals_pass, parse_crux_record
from slap.collectors.tls_probe import days_to_expiry, flatten_name
from slap.schema import Observation, UnknownMetricError, obs


# --------------------------------------------------------------------------
# schema contract
# --------------------------------------------------------------------------

def test_unregistered_metric_is_rejected():
    with pytest.raises(UnknownMetricError):
        obs("http.definitely_not_a_real_key", 1)


def test_obs_routes_bool_to_numeric_with_bool_unit():
    o = obs("http.compressed", True)
    assert o.numeric_value == 1.0
    assert o.unit.value == "bool"
    assert o.value is True


def test_obs_inherits_unit_from_registry():
    assert obs("http.ttfb", 412.5).unit.value == "ms"
    assert obs("tls.days_to_expiry", 30).unit.value == "days"


def test_observation_requires_a_value():
    with pytest.raises(ValueError):
        Observation.__call__ if False else Observation(  # noqa: B018
            obs("http.status", 200).source, "http.status"
        )


# --------------------------------------------------------------------------
# http_probe
# --------------------------------------------------------------------------

@pytest.mark.parametrize("header,expected", [
    ("public, max-age=3600", 3600),
    ("max-age=0, no-cache", 0),
    ("MAX-AGE = 86400", 86400),
    ("no-store", None),
    (None, None),
    ("", None),
])
def test_parse_max_age(header, expected):
    assert parse_max_age(header) == expected


def test_parse_hsts_max_age():
    assert parse_hsts_max_age("max-age=31536000; includeSubDomains") == 31536000
    assert parse_hsts_max_age("includeSubDomains") is None


def test_missing_security_headers_is_case_insensitive():
    headers = {
        "Strict-Transport-Security": "max-age=1",
        "x-content-type-options": "nosniff",
    }
    missing = missing_security_headers(headers)
    assert "strict-transport-security" not in missing
    assert "x-content-type-options" not in missing
    assert "content-security-policy" in missing
    assert len(missing) == 4


def test_analyze_cookies_counts_each_missing_attribute():
    result = analyze_cookies([
        "sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax",
        "tracker=1; Path=/",
        "half=2; Secure",
    ])
    assert result == {
        "total": 3, "insecure": 1, "no_httponly": 2, "no_samesite": 2
    }


def test_analyze_cookies_ignores_malformed_headers():
    assert analyze_cookies(["", "novalue", "a=1"])["total"] == 1


def test_upgrades_to_https():
    assert upgrades_to_https([(301, "http://x.com"), (200, "https://x.com")]) is True
    assert upgrades_to_https([(200, "http://x.com")]) is False
    # Started on HTTPS: the question does not apply.
    assert upgrades_to_https([(200, "https://x.com")]) is None
    assert upgrades_to_https([]) is None


@pytest.mark.parametrize("raw,expected", [
    ("example.com", "https://example.com"),
    ("  example.com/path  ", "https://example.com/path"),
    ("http://example.com", "http://example.com"),
    ("HTTPS://Example.com", "HTTPS://Example.com"),
])
def test_normalize_url(raw, expected):
    assert normalize_url(raw) == expected


def test_normalize_url_rejects_empty():
    with pytest.raises(ValueError):
        normalize_url("   ")


# --------------------------------------------------------------------------
# fingerprint: WP Rocket is the differentiator, so it gets the most tests
# --------------------------------------------------------------------------

def test_parse_attrs_handles_all_quote_styles():
    attrs = parse_attrs("""<meta name="generator" content='WP Rocket 3.15' data-x=bare>""")
    assert attrs == {
        "name": "generator", "content": "WP Rocket 3.15", "data-x": "bare"
    }


def test_find_generator_meta_ignores_other_meta_tags():
    html = """
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width">
    <meta name="generator" content="WordPress 6.5">
    <meta name="generator" content="WP Rocket 3.15.9" data-wpr-features="1234">
    """
    tags = find_generator_meta(html)
    assert len(tags) == 2
    assert tags[1]["data-wpr-features"] == "1234"


def test_wp_rocket_detected_with_version_and_features():
    html = '<meta name="generator" content="WP Rocket 3.15.9" data-wpr-features="wpr_lazyload_images wpr_minify_css">'
    result = detect_wp_rocket(html)
    assert result["present"] is True
    assert result["version"] == "3.15.9"
    assert result["features"] == "wpr_lazyload_images wpr_minify_css"


def test_wp_rocket_cached_page_reads_the_debug_stamp():
    html = (
        '<meta name="generator" content="WP Rocket 3.15.9">'
        "<!-- This website is like a Rocket, isn't it? Performance optimized "
        "by WP Rocket. Learn more: https://wp-rocket.me - Debug: cached@1748000000 -->"
    )
    result = detect_wp_rocket(html)
    assert result["page_cached"] is True
    assert result["cached_at"] == "1748000000"


def test_wp_rocket_present_but_not_cached_is_the_headline_finding():
    """Installed, no cached@ stamp: the 'you're paying for it and it's off' case."""
    html = '<meta name="generator" content="WP Rocket 3.15.9">'
    result = detect_wp_rocket(html)
    assert result["present"] is True
    assert result["page_cached"] is False


def test_wp_rocket_detected_from_markup_when_generator_is_stripped():
    html = '<script data-rocket-src="/app.js"></script>'
    result = detect_wp_rocket(html)
    assert result["present"] is True
    assert result["version"] is None


def test_wp_rocket_absent_leaves_cache_state_unknown_not_false():
    result = detect_wp_rocket("<html><body>plain</body></html>")
    assert result["present"] is False
    assert result["page_cached"] is None


def test_wp_rocket_cache_hit_header_overrides_cold_markup():
    html = '<meta name="generator" content="WP Rocket 3.15">'
    result = detect_wp_rocket(html, {"x-cache": "HIT"})
    assert result["page_cached"] is True


def test_detect_cms_prefers_generator_over_markup():
    assert detect_cms('<meta name="generator" content="WordPress 6.5">', {}) == "WordPress"
    assert detect_cms('<link href="/wp-content/themes/x/s.css">', {}) == "WordPress"
    assert detect_cms("", {"x-shopid": "123"}) == "Shopify"
    assert detect_cms("<html></html>", {}) is None


def test_detect_cdn_from_headers_and_server_string():
    assert detect_cdn({"cf-ray": "abc"}) == "Cloudflare"
    assert detect_cdn({"x-amz-cf-id": "abc"}) == "Amazon CloudFront"
    assert detect_cdn({"server": "BunnyCDN-DE1"}) == "BunnyCDN"
    assert detect_cdn({"server": "nginx"}) is None


def test_detect_page_builder():
    assert detect_page_builder('<div class="elementor-widget">') == "Elementor"
    assert detect_page_builder('<div class="et_pb_section">') == "Divi"
    assert detect_page_builder("<div>nothing</div>") is None


def test_detect_multiple_cache_plugins():
    html = '<script data-rocket-src="/a.js"></script><link href="/wp-content/cache/minify/x.css">'
    plugins = detect_cache_plugins(html, {})
    assert "WP Rocket" in plugins
    assert "W3 Total Cache" in plugins
    assert len(plugins) >= 2


# --------------------------------------------------------------------------
# tls_probe
# --------------------------------------------------------------------------

def test_flatten_name_prefers_organization():
    issuer = ((("countryName", "US"),), (("organizationName", "Let's Encrypt"),),
              (("commonName", "R3"),))
    assert flatten_name(issuer) == "Let's Encrypt"


def test_flatten_name_falls_back_to_common_name():
    assert flatten_name(((("commonName", "example.com"),),)) == "example.com"
    assert flatten_name(None) == ""


def test_days_to_expiry():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert days_to_expiry("Jan 31 12:00:00 2026 GMT", now=now) == pytest.approx(30.5, abs=0.1)
    assert days_to_expiry("garbage", now=now) is None
    assert days_to_expiry("", now=now) is None


def test_days_to_expiry_goes_negative_when_expired():
    now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    assert days_to_expiry("Jan 1 12:00:00 2026 GMT", now=now) < 0


# --------------------------------------------------------------------------
# crux
# --------------------------------------------------------------------------

CRUX_RESPONSE = {
    "record": {
        "key": {"origin": "https://example.com"},
        "metrics": {
            "largest_contentful_paint": {
                "histogram": [{"density": 0.72}, {"density": 0.2}, {"density": 0.08}],
                "percentiles": {"p75": 3100},
            },
            "interaction_to_next_paint": {
                "histogram": [{"density": 0.9}, {"density": 0.08}, {"density": 0.02}],
                "percentiles": {"p75": 150},
            },
            "cumulative_layout_shift": {
                "histogram": [{"density": 0.95}, {"density": 0.03}, {"density": 0.02}],
                "percentiles": {"p75": "0.04"},
            },
        },
    }
}


def test_parse_crux_record_extracts_p75_and_good_share():
    values = {o.metric_key: o.value for o in parse_crux_record(CRUX_RESPONSE)}
    assert values["crux.available"] is True
    assert values["crux.lcp.p75"] == 3100
    assert values["crux.inp.p75"] == 150
    assert values["crux.cls.p75"] == 0.04  # string coerced to float
    assert values["crux.lcp.good"] == 0.72


def test_parse_crux_record_marks_cwv_fail_when_lcp_is_over_threshold():
    values = {o.metric_key: o.value for o in parse_crux_record(CRUX_RESPONSE)}
    assert values["crux.cwv_pass"] is False  # LCP 3100 > 2500


def test_cwv_pass_requires_lcp_and_cls():
    assert core_web_vitals_pass({"crux.lcp.p75": 2000}) is None
    assert core_web_vitals_pass({"crux.lcp.p75": 2000, "crux.cls.p75": 0.05}) is True
    assert core_web_vitals_pass({"crux.lcp.p75": 2000, "crux.cls.p75": 0.3}) is False


def test_cwv_pass_tolerates_missing_inp():
    """Thin INP coverage must not read as a failure."""
    assert core_web_vitals_pass({"crux.lcp.p75": 1000, "crux.cls.p75": 0.01}) is True


def test_parse_crux_record_handles_empty_payload():
    values = {o.metric_key: o.value for o in parse_crux_record({})}
    assert values == {"crux.available": True}
