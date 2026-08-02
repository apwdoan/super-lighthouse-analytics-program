"""CVE matching and endpoint probing.

Both features can damage a client relationship rather than merely annoy the
operator, so most of these tests are adversarial: they set up the conditions
under which a naive implementation reports something false, and assert
silence. The positive controls are here too, because a tool that never
reports anything also passes every negative test.
"""

from __future__ import annotations

import asyncio
import pathlib

import httpx
import pytest

from slap import core, db
from slap.collectors.base import CollectorConfig, FetchedDocument, PageContext
from slap.collectors.components import (
    INFERRED,
    OBSERVED,
    Component,
    ComponentCollector,
    Match,
    components_from_lighthouse,
    detect,
    effective_severity,
    match_all,
    wordpress_assets,
    wordpress_core_version,
)
from slap.collectors.exposure import (
    PROBES,
    Control,
    ExposureCollector,
    calibrate,
    looks_like_a_block_page,
    matches_signature,
)
from slap.config import Settings
from slap.vulndb import (
    AffectedRange,
    VulnDatabase,
    Vulnerability,
    compare,
    default_db_path,
    deduplicate,
    parse_version,
)
from tests.vulnerable_server import (
    EXPOSED,
    JQUERY_VERSION,
    WP_CORE_VERSION,
    start as start_vulnerable,
)


# --------------------------------------------------------------------------
# Version parsing: the single highest-risk function in the feature
# --------------------------------------------------------------------------

def test_real_versions_parse():
    assert parse_version("3.4.1") == (3, 4, 1)
    assert parse_version("v2.0") == (2, 0)
    assert parse_version("6.5.2") == (6, 5, 2)
    assert parse_version("1.11.3-rc1") == (1, 11, 3)
    assert parse_version("5.8.1.1") == (5, 8, 1, 1)


def test_cache_busters_do_not_parse_as_versions():
    """This is where false CVEs come from.

    A `?ver=` slot on a WordPress asset carries a version, a timestamp, a
    content hash or nothing, and only the first is safe to match. Anything
    that parses here becomes a version number the tool will confidently match
    against somebody's advisory list.
    """
    for junk in ("1699887600", "a3f9c2e1", "20231113", "latest", "", None,
                 "abc", "v", "-1"):
        assert parse_version(junk) is None, junk


def test_a_bare_large_integer_is_a_timestamp_not_a_version():
    assert parse_version("1699887600") is None
    assert parse_version("999") == (999,)      # plausible as a version


def test_version_comparison_pads():
    assert compare((1, 2), (1, 2, 0)) == 0
    assert compare((1, 2, 1), (1, 2)) == 1
    assert compare((1, 2), (1, 10)) == -1


# --------------------------------------------------------------------------
# Range semantics. `fixed` is exclusive, `last_affected` is inclusive.
# --------------------------------------------------------------------------

def test_fixed_is_exclusive():
    """Off by one here either clears a vulnerable version or condemns a
    patched one, and both are wrong in a client report."""
    r = AffectedRange(introduced=(1, 0, 0), fixed=(1, 2, 0))
    assert r.contains((1, 1, 9))
    assert not r.contains((1, 2, 0))
    assert not r.contains((1, 2, 1))
    assert not r.contains((0, 9, 0))


def test_last_affected_is_inclusive():
    r = AffectedRange(introduced=(1, 0, 0), last_affected=(1, 2, 0))
    assert r.contains((1, 2, 0))
    assert not r.contains((1, 2, 1))


# --------------------------------------------------------------------------
# The database, against real data
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def vulndb():
    database = VulnDatabase.load(default_db_path())
    if not database.available:
        pytest.skip("no vulnerability database; run `slap vulndb update`")
    return database


def test_known_vulnerable_jquery_matches(vulndb):
    """Positive control. jQuery 3.4.1 carries CVE-2020-11022 and -11023."""
    hits = vulndb.query("npm", "jquery", "3.4.1")
    ids = {h.cve for h in hits}
    assert "CVE-2020-11022" in ids
    assert "CVE-2020-11023" in ids


def test_a_patched_version_matches_nothing(vulndb):
    assert vulndb.query("npm", "jquery", "3.7.1") == []


def test_an_unparseable_version_matches_nothing(vulndb):
    """No version means no finding. Not "probably fine": silence."""
    assert vulndb.query("npm", "jquery", "a3f9c2e1") == []
    assert vulndb.query("npm", "jquery", "1699887600") == []


def test_an_unknown_package_matches_nothing(vulndb):
    assert vulndb.query("npm", "not-a-real-package-xyz", "1.0.0") == []


def test_severity_is_read_from_where_the_feed_puts_it(vulndb):
    """GHSA populates `database_specific.severity` at the top level and leaves
    `affected[].ecosystem_specific` null. Reading the latter rated a
    prototype-pollution CVE as `info`, which would have filed it under "also
    worth addressing" in a client report."""
    hits = vulndb.query("npm", "lodash", "4.17.15")
    assert hits, "expected lodash 4.17.15 to be vulnerable"
    assert any(h.severity in ("high", "critical") for h in hits)
    assert not all(h.severity == "info" for h in hits)


def test_aliased_advisories_are_reported_once():
    """GHSA re-issues advisories and aliases the old id to the new one.
    Counting both inflates every number a client reads."""
    a = Vulnerability(id="GHSA-aaaa", package="p", ecosystem="npm",
                      summary="x", severity="medium",
                      aliases=("CVE-2025-1", "GHSA-bbbb"))
    b = Vulnerability(id="GHSA-bbbb", package="p", ecosystem="npm",
                      summary="x", severity="high",
                      aliases=("CVE-2025-1", "GHSA-aaaa"))
    merged = deduplicate([a, b])
    assert len(merged) == 1
    assert merged[0].severity == "high"     # the more severe record survives


def test_covers_distinguishes_unchecked_from_clean(vulndb):
    """"No vulnerabilities found in your plugins" and "your plugins were not
    checked" are different sentences, and only one is true with no WordPress
    source configured."""
    assert vulndb.covers("npm")
    assert not vulndb.covers("wordpress-plugin")


def test_a_missing_database_degrades_rather_than_raises(tmp_path):
    empty = VulnDatabase.load(tmp_path / "nope.json")
    assert not empty.available
    assert empty.query("npm", "jquery", "3.4.1") == []
    assert not empty.covers("npm")


def test_a_corrupt_database_degrades_rather_than_raises(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json at all", encoding="utf-8")
    assert not VulnDatabase.load(path).available


def test_the_database_carries_its_date(vulndb):
    """A bundle built once and run for a year carries a year-old database."""
    assert vulndb.generated_at
    assert vulndb.age_days is not None


# --------------------------------------------------------------------------
# Detection and confidence
# --------------------------------------------------------------------------

LIBRARIES = [{"name": "jQuery", "version": "3.4.1", "npm": "jquery"}]

WP_HTML = f"""<meta name="generator" content="WordPress {WP_CORE_VERSION}">
<script src="/wp-content/plugins/contact-form-7/js/index.js?ver=5.8.1"></script>
<script src="/wp-content/plugins/akismet/_inc/a.js?ver={WP_CORE_VERSION}"></script>
<script src="/wp-content/plugins/wp-rocket/assets/x.js?ver=1699887600"></script>
<link rel="stylesheet" href="/wp-content/themes/astra/style.css?ver=a3f9c2e1">"""


def test_browser_read_versions_are_observed():
    got = components_from_lighthouse(LIBRARIES)
    assert got[0].confidence == OBSERVED
    assert got[0].package == "jquery"
    assert got[0].ecosystem == "npm"


def test_a_library_without_an_npm_coordinate_is_skipped():
    """Guessing that "Kendo UI" is npm's `kendo-ui-core` is how a version gets
    matched against another package's advisories."""
    assert components_from_lighthouse(
        [{"name": "Kendo UI", "version": "2019.1.115"}]) == []


def test_wordpress_core_version_is_observed():
    assert wordpress_core_version(WP_HTML) == WP_CORE_VERSION


def test_plugin_versions_from_ver_are_inferred_not_observed():
    components = wordpress_assets(WP_HTML)
    assert components
    assert all(c.confidence == INFERRED for c in components)
    assert all("?ver=" in c.evidence for c in components)


def test_the_core_version_substituted_into_ver_is_discarded():
    """WordPress puts the CORE version in `?ver=` for any asset that does not
    set its own. Reading that as the plugin's version matches every plugin on
    the site against core's number."""
    slugs = {c.package for c in wordpress_assets(WP_HTML)}
    assert "contact-form-7" in slugs     # a real, distinct version
    assert "akismet" not in slugs        # carried the core version


def test_cache_busters_and_hashes_yield_no_component():
    slugs = {c.package for c in wordpress_assets(WP_HTML)}
    assert "wp-rocket" not in slugs      # ?ver= was a unix timestamp
    assert "astra" not in slugs          # ?ver= was a content hash


def test_detect_orders_observed_before_inferred():
    components = detect(WP_HTML, LIBRARIES)
    confidences = [c.confidence for c in components]
    assert confidences == sorted(confidences, key=lambda c: c != OBSERVED)


def test_detection_is_stable_across_calls():
    """Two runs of a site must list components in the same order or a diff
    between two reports is unreadable."""
    assert detect(WP_HTML, LIBRARIES) == detect(WP_HTML, LIBRARIES)


# --------------------------------------------------------------------------
# The guardrail: an inferred version cannot print a critical
# --------------------------------------------------------------------------

def _match(confidence: str, severity: str) -> Match:
    return Match(
        component=Component(name="x", version="1.0.0", confidence=confidence,
                            ecosystem="npm", package="x"),
        vulnerability=Vulnerability(id="CVE-1", package="x", ecosystem="npm",
                                    summary="", severity=severity),
    )


def test_an_observed_version_reports_the_real_severity():
    assert effective_severity(_match(OBSERVED, "critical")) == "critical"


def test_an_inferred_version_can_never_print_a_critical():
    """A CVSS-critical advisory matched against a number scraped from a query
    string is still a guess. Printing CRITICAL next to a guess spends
    credibility that is hard to earn back."""
    assert effective_severity(_match(INFERRED, "critical")) == "medium"
    assert effective_severity(_match(INFERRED, "high")) == "medium"
    assert effective_severity(_match(INFERRED, "low")) == "low"


def test_components_in_an_uncovered_ecosystem_are_returned_as_unchecked(vulndb):
    components = detect(WP_HTML, LIBRARIES)
    matches, unchecked = match_all(components, vulndb)
    assert any(m.component.ecosystem == "npm" for m in matches)
    assert unchecked, "WordPress components must come back as unchecked"
    assert all(c.ecosystem.startswith("wordpress") for c in unchecked)


# --------------------------------------------------------------------------
# The collector, end to end
# --------------------------------------------------------------------------

def _run_component_collector(html: str, libraries, database) -> dict:
    async def go():
        ctx = PageContext(url="https://x.test/", client=None,
                          config=CollectorConfig())
        ctx.document = FetchedDocument(
            url="https://x.test/", final_url="https://x.test/", status=200,
            http_version="HTTP/2", headers={}, set_cookie=[], text=html,
            content_bytes=len(html), ttfb_ms=1.0)
        if libraries is not None:
            ctx.extras["lighthouse"] = type("R", (), {"libraries": libraries})()
        return {o.metric_key: o.value
                for o in await ComponentCollector(database).collect(ctx)}
    return asyncio.run(go())


def test_the_collector_separates_confirmed_from_possible(vulndb):
    values = _run_component_collector(WP_HTML, LIBRARIES, vulndb)
    assert values["vuln.confirmed_count"] >= 1     # jQuery 3.4.1
    assert values["component.observed_count"] >= 2
    assert values["vuln.unchecked_count"] >= 1     # the WordPress plugin
    assert "jQuery 3.4.1" in values["component.detected"]


def test_without_lighthouse_the_collector_still_works_from_markup(vulndb):
    """A page audited at `light` depth has no browser reading of its
    libraries. It must still inventory what the markup reveals."""
    values = _run_component_collector(WP_HTML, None, vulndb)
    assert values["component.count"] >= 1
    assert values["vuln.confirmed_count"] == 0     # nothing observed to match


def test_an_empty_database_reports_unchecked_not_clean(vulndb):
    values = _run_component_collector(WP_HTML, LIBRARIES, VulnDatabase())
    assert values["vuln.confirmed_count"] == 0
    # Every component is unchecked, and the metric says so rather than the
    # report implying a clean result.
    assert values["vuln.unchecked_count"] == values["component.count"]


# --------------------------------------------------------------------------
# Endpoint probing
# --------------------------------------------------------------------------

def test_probing_is_off_by_default():
    assert Settings().probe_enabled is False
    assert ExposureCollector().enabled is False


def test_an_unauthorised_host_is_never_probed():
    collector = ExposureCollector(enabled=True,
                                  authorised_hosts=frozenset({"other.test"}))
    assert not collector.authorised_for("client.test")


def test_authorisation_is_recorded_with_who_and_when(tmp_path):
    conn = db.init_db(tmp_path / "x.sqlite3")
    try:
        db.authorise_probe(conn, "client.test", by="Austin", note="SOW 2026-08")
        conn.commit()
        hosts = db.authorised_probe_hosts(conn)
        assert hosts["client.test"]["probe_authorised_by"] == "Austin"
        assert hosts["client.test"]["probe_authorised_at"]
        assert hosts["client.test"]["probe_note"] == "SOW 2026-08"
        assert db.revoke_probe(conn, "client.test")
        conn.commit()
        assert db.authorised_probe_hosts(conn) == {}
    finally:
        db.close_thread_connections()


def test_block_pages_are_recognised():
    assert looks_like_a_block_page(
        "<h1>Attention Required! | Cloudflare</h1> Ray ID: abc")
    assert looks_like_a_block_page("Sucuri WebSite Firewall - Access Denied")
    assert not looks_like_a_block_page("[core]\n repositoryformatversion = 0")


def test_signature_matching_requires_the_expected_content():
    """A site serving its homepage for /.env returns 200 with HTML. Without a
    content check that is a critical finding, and it is wrong."""
    assert matches_signature("[core]\n\trepositoryformatversion = 0", "git")
    assert not matches_signature("<html><body>Welcome</body></html>", "git")
    assert matches_signature("APP_KEY=base64:x\nDB_PASSWORD=y", "env")
    assert not matches_signature("<html><body>Welcome</body></html>", "env")


def test_a_block_page_never_matches_a_signature():
    """Even if a marker happens to appear in it."""
    assert not matches_signature(
        "Cloudflare Access denied. [core] repositoryformatversion", "git")


def test_control_resemblance_tolerates_a_templated_404():
    """A 404 page that echoes the requested path varies in length by a few
    bytes per request. Exact matching would call every one of them distinct."""
    control = Control(status=404, length=1000, digest="")
    assert control.resembles(404, 1040, "other")
    assert not control.resembles(404, 5000, "other")
    assert not control.resembles(200, 1000, "other")


# --- against the real fixtures -------------------------------------------

async def _probe(base: str, hostname: str = "127.0.0.1"):
    collector = ExposureCollector(enabled=True, rate_per_second=0,
                                  authorised_hosts=frozenset({hostname}))
    async with httpx.AsyncClient(follow_redirects=False) as client:
        ctx = PageContext(url=base + "/", client=client, config=CollectorConfig())
        return await collector.probe(ctx)


def test_real_exposed_files_are_found():
    """Positive control: a tool that finds nothing here is broken."""
    httpd, base = start_vulnerable("normal")
    try:
        result = asyncio.run(_probe(base))
        found = {f.probe.path for f in result.findings}
        assert set(EXPOSED) <= found, f"missed {set(EXPOSED) - found}"
        assert all(f.confirmed for f in result.findings
                   if f.probe.path in EXPOSED)
    finally:
        httpd.shutdown()


def test_a_soft_404_site_produces_no_findings():
    """200 and the homepage for every path. Status codes alone would report
    every probed path as critical."""
    httpd, base = start_vulnerable("soft404")
    try:
        result = asyncio.run(_probe(base))
        assert result.control.soft_404
        assert result.findings == [], [f.probe.path for f in result.findings]
    finally:
        httpd.shutdown()


def test_a_waf_stops_the_probe_rather_than_producing_fifteen_criticals():
    httpd, base = start_vulnerable("waf")
    try:
        result = asyncio.run(_probe(base))
        assert result.control.blocked
        assert result.findings == []
        assert result.checked == 0, "the probe should stop, not continue"
        assert result.errors
    finally:
        httpd.shutdown()


def test_calibration_uses_paths_that_cannot_exist():
    httpd, base = start_vulnerable("normal")
    try:
        async def go():
            async with httpx.AsyncClient() as client:
                return await calibrate(client, base, "SLAP-test", 10.0)
        control = asyncio.run(go())
        assert control.status == 404
        assert not control.soft_404
        assert not control.blocked
    finally:
        httpd.shutdown()


def test_nothing_from_a_probed_path_is_stored(tmp_path):
    """The body of a suspected secret is read for classification and dropped.

    Pulling a client's .env into a SQLite file that later gets zipped up and
    emailed creates a custody problem the audit did not start with.
    """
    httpd, base = start_vulnerable("normal")
    settings = Settings()
    settings.db_path = tmp_path / "x.sqlite3"
    settings.artifact_dir = tmp_path / "a"
    settings.report_dir = tmp_path / "r"
    settings.lighthouse.enabled = False
    settings.collector.crux_api_key = None
    settings.discovery.enabled = False
    settings.probe_enabled = True
    settings.probe_rate_per_second = 0
    try:
        conn = db.init_db(settings.db_path)
        db.authorise_probe(conn, "127.0.0.1", by="test")
        conn.commit()
        result = asyncio.run(core.run_batch([base], settings))
        run_id = result.run_ids[0]
        blob = "".join(
            str(r["text_value"] or "") for r in db.get_observations(conn, run_id))
        # The literal secrets from the fixture's .env and database dump.
        for secret in ("hunter2", "base64:abcd", "CREATE TABLE wp_users"):
            assert secret not in blob, f"{secret!r} reached the database"
        # But the path itself is recorded, because that is the finding.
        assert "/.env" in blob
    finally:
        httpd.shutdown()
        db.close_thread_connections()


def test_probing_does_not_run_without_authorisation(tmp_path):
    httpd, base = start_vulnerable("normal")
    settings = Settings()
    settings.db_path = tmp_path / "x.sqlite3"
    settings.artifact_dir = tmp_path / "a"
    settings.report_dir = tmp_path / "r"
    settings.lighthouse.enabled = False
    settings.collector.crux_api_key = None
    settings.discovery.enabled = False
    settings.probe_enabled = True          # enabled globally...
    try:                                   # ...but this host is not authorised
        result = asyncio.run(core.run_batch([base], settings))
        conn = db.connect(settings.db_path)
        values = db.observations_as_dict(
            conn, db.home_page_id(conn, result.run_ids[0]))
        assert values.get("exposure.authorised") is False
        assert "exposure.found_count" not in values
        rules = {f["rule_id"] for f in db.get_findings(conn, result.run_ids[0])}
        assert not any(r.startswith("exposed-") for r in rules)
    finally:
        httpd.shutdown()
        db.close_thread_connections()


def test_probes_are_a_short_list_not_a_wordlist():
    """A hygiene check, not a pentest. It should look unremarkable in the
    target's access log."""
    assert len(PROBES) <= 20
    assert len({p.path for p in PROBES}) == len(PROBES)


def test_each_false_positive_guard_actually_changes_the_outcome(monkeypatch):
    """A negative test that passes for the wrong reason is worse than none.

    Measured rather than assumed: with every guard disabled, the soft-404
    fixture produces a finding for all 16 probed paths, and so does the WAF
    fixture. The three guards are independent and each removes cases the
    others do not, so this asserts the whole ladder rather than any one rung.
    """
    from slap.collectors import exposure as ex

    def run(mode, *, resemblance=True, signature=True, block=True):
        with monkeypatch.context() as m:
            if not signature:
                m.setattr(ex, "matches_signature", lambda body, sig: True)
            if not block:
                m.setattr(ex, "looks_like_a_block_page", lambda body: False)
            if not resemblance:
                m.setattr(ex.Control, "resembles",
                          lambda self, s, length, digest: False)
            httpd, base = start_vulnerable(mode)
            try:
                return asyncio.run(_probe(base))
            finally:
                httpd.shutdown()

    # Ungoverned, a catch-all site reports every probed path as a finding.
    naked = run("soft404", resemblance=False, signature=False)
    assert len(naked.findings) == len(PROBES)
    # Either guard alone cuts it down; together they clear it.
    assert len(run("soft404", signature=False).findings) < len(PROBES)
    assert run("soft404", resemblance=False).findings == []
    assert run("soft404").findings == []

    # A WAF answers every path identically, including the control.
    assert len(run("waf", resemblance=False, signature=False,
                   block=False).findings) == len(PROBES)
    assert run("waf").findings == []

    # And the positive control still finds every genuinely exposed file.
    assert len(run("normal").findings) >= len(EXPOSED)


# --------------------------------------------------------------------------
# The whole chain, with a real browser. Skipped cleanly without one.
# --------------------------------------------------------------------------

def _lighthouse_available() -> bool:
    from slap.collectors.lighthouse import LighthouseConfig, LighthouseRunner
    return LighthouseRunner(LighthouseConfig(enabled=True)).check()[0]


@pytest.mark.lighthouse
@pytest.mark.skipif(not _lighthouse_available(),
                    reason="needs the Node Lighthouse worker")
def test_a_browser_observed_version_produces_a_confirmed_cve(tmp_path, vulndb):
    """The highest-confidence path, end to end.

    The fixture's jQuery is a live object rather than a version comment,
    because the detector reads `jQuery.fn.jquery` off the running window. A
    file that merely *says* 3.4.1 detects as nothing, which is precisely the
    difference between an observed version and an inferred one.
    """
    httpd, base = start_vulnerable("normal")
    settings = Settings()
    settings.db_path = tmp_path / "x.sqlite3"
    settings.artifact_dir = tmp_path / "a"
    settings.report_dir = tmp_path / "r"
    settings.collector.crux_api_key = None
    settings.lighthouse.enabled = True
    settings.lighthouse.runs = 1
    settings.discovery.enabled = False
    try:
        result = asyncio.run(core.run_batch([base], settings))
        conn = db.connect(settings.db_path)
        run_id = result.run_ids[0]
        values = db.observations_as_dict(conn, db.home_page_id(conn, run_id))

        assert f"jQuery {JQUERY_VERSION} [observed]" in values["component.detected"]
        assert values["vuln.confirmed_count"] >= 2
        detail = values["vuln.confirmed_detail"]
        assert "CVE-2020-11022" in detail and "CVE-2020-11023" in detail

        # The WordPress plugin is inventoried, not matched, and says so.
        assert values["vuln.unchecked_count"] >= 1
        rules = {f["rule_id"] for f in db.get_findings(conn, run_id)}
        assert "vuln-not-checked" in rules
        assert any(r.startswith("vuln-confirmed-") for r in rules)
    finally:
        httpd.shutdown()
        db.close_thread_connections()


@pytest.mark.lighthouse
@pytest.mark.skipif(not _lighthouse_available(),
                    reason="needs the Node Lighthouse worker")
def test_the_report_states_what_was_not_checked(tmp_path):
    """A report that omits this reads as "checked, all clear"."""
    from slap.report.model import build_report_model

    httpd, base = start_vulnerable("normal")
    settings = Settings()
    settings.db_path = tmp_path / "x.sqlite3"
    settings.artifact_dir = tmp_path / "a"
    settings.report_dir = tmp_path / "r"
    settings.collector.crux_api_key = None
    settings.lighthouse.enabled = True
    settings.lighthouse.runs = 1
    settings.discovery.enabled = False
    try:
        result = asyncio.run(core.run_batch([base], settings))
        model = build_report_model(core.get_run_detail(settings, result.run_ids[0]))
        note = model.coverage.vulnerability_note
        assert "OSV" in note
        assert "NOT checked" in note
        assert model.coverage.vuln_db_generated
        # Probing was never authorised here, so the report must say nothing
        # was concluded rather than implying the site is clean.
        assert "not run" in model.coverage.probe_note
    finally:
        httpd.shutdown()
        db.close_thread_connections()


def test_each_exposure_rule_describes_only_its_own_findings():
    """One shared `exposure.paths` made the version-control rule tell the
    client that /.env and /backup.sql are git metadata."""
    async def go():
        collector = ExposureCollector(
            enabled=True, rate_per_second=0,
            authorised_hosts=frozenset({"127.0.0.1"}))
        httpd, base = start_vulnerable("normal")
        try:
            async with httpx.AsyncClient(follow_redirects=False) as client:
                ctx = PageContext(url=base + "/", client=client,
                                  config=CollectorConfig())
                return {o.metric_key: o.value
                        for o in await collector.collect(ctx)}
        finally:
            httpd.shutdown()

    values = asyncio.run(go())
    assert values["exposure.vcs_paths"] == "/.git/config (200)"
    secrets_paths = values["exposure.secrets_paths"]
    assert "/.env" in secrets_paths and "/backup.sql" in secrets_paths
    assert "/.git/config" not in secrets_paths


# --------------------------------------------------------------------------
# Where the database lives. Found by running the real bundle, not by reading.
# --------------------------------------------------------------------------

def test_a_refresh_never_writes_inside_a_frozen_bundle(monkeypatch, tmp_path):
    """`vulndb update` from the bundle wrote to _internal/slap/data/.

    That path is inside the application. It may be read-only (Program Files,
    /Applications), writing to a signed .app breaks its signature, and even
    where it succeeds the next upgrade replaces the folder and silently
    discards the refresh. The teammate would have no way to tell why their
    data was aging.
    """
    from slap import config, vulndb

    monkeypatch.setattr(vulndb, "bundled_db_path", lambda: tmp_path / "app" / "vulndb.json")
    monkeypatch.setattr(config, "bundled_db_path", lambda: tmp_path / "app" / "vulndb.json")
    monkeypatch.setattr(config, "default_data_dir", lambda: tmp_path / "userdata")

    import sys
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    assert config.writable_vulndb_path() == tmp_path / "userdata" / "vulndb.json"

    monkeypatch.delattr(sys, "frozen", raising=False)
    # A source checkout writes to the package copy, which is what gets
    # committed.
    assert config.writable_vulndb_path() == tmp_path / "app" / "vulndb.json"


def test_the_newer_database_wins_whichever_copy_it_is(tmp_path):
    """Not "the user's copy always wins".

    A teammate who refreshed in January and installs a June bundle should get
    June's data; one who refreshed yesterday should keep theirs. Comparing the
    dates the files carry is the only rule that cannot regress either way.
    """
    from slap.vulndb import VulnDatabase, newer_of

    def write(path, stamp):
        database = VulnDatabase(generated_at=stamp, sources={"npm": "OSV.dev"})
        database.index[("npm", "x")] = [
            Vulnerability(id="X-1", package="x", ecosystem="npm",
                          summary="", severity="low",
                          ranges=(AffectedRange(introduced=(0,)),))]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(database.to_json(), encoding="utf-8")
        return path

    old = write(tmp_path / "user" / "vulndb.json", "2026-01-01T00:00:00+00:00")
    new = write(tmp_path / "app" / "vulndb.json", "2026-06-01T00:00:00+00:00")
    assert newer_of(old, new) == new
    assert newer_of(new, old) == new

    fresher_user = write(tmp_path / "user" / "vulndb.json",
                         "2026-07-01T00:00:00+00:00")
    assert newer_of(fresher_user, new) == fresher_user


def test_resolution_falls_back_when_neither_copy_exists(monkeypatch, tmp_path):
    from slap import config

    monkeypatch.setattr(config, "bundled_db_path", lambda: tmp_path / "app" / "vulndb.json")
    monkeypatch.setattr(config, "default_data_dir", lambda: tmp_path / "userdata")
    # No file anywhere: returns the bundled path rather than None, so callers
    # get a Path they can report on rather than a crash.
    assert config.default_vulndb_path() == tmp_path / "app" / "vulndb.json"


def test_an_empty_refresh_does_not_overwrite_good_data(monkeypatch, tmp_path, capsys):
    """OSV returning nothing must not blank the database: the next audit
    would report zero vulnerabilities and look clean doing it."""
    import argparse

    from slap import cli
    from slap.vulndb import VulnDatabase

    target = tmp_path / "vulndb.json"
    target.write_text(VulnDatabase.load(default_db_path()).to_json(), encoding="utf-8")
    before = target.read_text(encoding="utf-8")

    monkeypatch.setattr(cli, "config", cli.config)
    monkeypatch.setattr("slap.vulndb.build_from_osv", lambda **kw: VulnDatabase())
    monkeypatch.setattr(cli.config, "writable_vulndb_path", lambda: target)

    settings = Settings()
    settings.vulndb_path = target
    code = cli.cmd_vulndb(argparse.Namespace(action="update"), settings)
    assert code == 1
    assert target.read_text(encoding="utf-8") == before


def test_a_package_that_silently_returns_empty_is_treated_as_a_failure(monkeypatch):
    """A rebuild forty minutes after a good one came back with `angular` at
    zero advisories instead of fifteen, with no exception and nothing in the
    output to distinguish it from a package that genuinely has none.

    A quietly smaller database is the same failure as a stale one: every
    audit afterwards reports less and looks clean doing it.
    """
    from slap import vulndb

    previous = VulnDatabase()
    previous.index[("npm", "angular")] = [
        Vulnerability(id="X-1", package="angular", ecosystem="npm",
                      summary="", severity="high",
                      ranges=(AffectedRange(introduced=(0,)),))]

    monkeypatch.setattr(vulndb, "_query_osv", lambda package, timeout: [])
    built = vulndb.build_from_osv(["angular"], previous=previous, attempts=2,
                                  pause=0)
    assert built.failures == ["angular"]


def test_a_package_that_genuinely_has_no_advisories_is_not_a_failure(monkeypatch):
    """Retrying every genuine zero would triple the runtime for nothing."""
    from slap import vulndb

    monkeypatch.setattr(vulndb, "_query_osv", lambda package, timeout: [])
    built = vulndb.build_from_osv(["some-clean-package"], previous=VulnDatabase(),
                                  attempts=2, pause=0)
    assert built.failures == []


def test_a_transient_empty_is_retried_and_recovers(monkeypatch):
    from slap import vulndb

    previous = VulnDatabase()
    previous.index[("npm", "angular")] = [
        Vulnerability(id="X-1", package="angular", ecosystem="npm",
                      summary="", severity="high",
                      ranges=(AffectedRange(introduced=(0,)),))]

    calls = {"n": 0}
    real_record = {
        "id": "GHSA-real", "affected": [
            {"package": {"name": "angular", "ecosystem": "npm"},
             "ranges": [{"type": "SEMVER",
                         "events": [{"introduced": "1.0.0"}, {"fixed": "1.8.0"}]}]}],
        "database_specific": {"severity": "HIGH"},
    }

    def flaky(package, timeout):
        calls["n"] += 1
        return [] if calls["n"] == 1 else [real_record]

    monkeypatch.setattr(vulndb, "_query_osv", flaky)
    built = vulndb.build_from_osv(["angular"], previous=previous, attempts=3,
                                  pause=0)
    assert built.failures == []
    assert built.count == 1


def test_a_hard_failure_is_retried_then_recorded(monkeypatch):
    from slap import vulndb

    monkeypatch.setattr(vulndb, "_query_osv", lambda package, timeout: None)
    built = vulndb.build_from_osv(["jquery"], previous=VulnDatabase(),
                                  attempts=2, pause=0)
    assert built.failures == ["jquery"]


def test_reading_the_stamp_does_not_parse_the_whole_database(tmp_path):
    """Settings() resolves the database path on construction, so this runs on
    every CLI invocation and every test. Loading two 108KB files just to
    compare two dates cost 5ms a time."""
    from slap.vulndb import read_stamp

    real = default_db_path()
    assert read_stamp(real) == VulnDatabase.load(real).generated_at


def test_the_stamp_falls_back_to_a_real_parse_on_an_odd_layout(tmp_path):
    """A wrong answer here silently picks the older database."""
    from slap.vulndb import read_stamp

    path = tmp_path / "odd.json"
    # generated_at pushed past the bounded read by a wall of padding.
    padding = " " * 6000
    path.write_text(
        '{"schema": 1,' + padding + '"sources": {"npm": "OSV.dev"},'
        '"generated_at": "2026-05-05T00:00:00+00:00", "vulnerabilities": []}',
        encoding="utf-8")
    # The database has no advisories, so the fallback reports nothing usable
    # rather than a date it cannot stand behind.
    assert read_stamp(path) is None


def test_the_stamp_of_a_missing_file_is_none():
    from slap.vulndb import read_stamp

    assert read_stamp(None) is None
    assert read_stamp(pathlib.Path("/nonexistent/vulndb.json")) is None


# --------------------------------------------------------------------------
# The default configuration. Lighthouse is opt-in; this is what most runs do.
# --------------------------------------------------------------------------

def test_component_detection_runs_when_lighthouse_is_off(tmp_path):
    """The pass that reads components is independent of the pass that
    measures them.

    `collect_site` used to return early when the browser pipeline was empty,
    which skipped the final pass with it. Lighthouse is opt-in, so that is
    the DEFAULT: every audit without --lighthouse, including every audit the
    web UI starts, did no component detection and no CVE matching at all.
    Nothing raised, the run completed, and the report said "components were
    checked against OSV" having checked nothing.

    Every existing test missed it because the ones that exercised components
    through `run_batch` all enabled Lighthouse, and the ones that ran with it
    off called the collector directly.
    """
    httpd, base = start_vulnerable("normal")
    settings = Settings()
    settings.db_path = tmp_path / "x.sqlite3"
    settings.artifact_dir = tmp_path / "a"
    settings.report_dir = tmp_path / "r"
    settings.collector.crux_api_key = None
    settings.lighthouse.enabled = False          # the default
    try:
        result = asyncio.run(core.run_batch([base], settings))
        conn = db.connect(settings.db_path)
        values = db.observations_as_dict(
            conn, db.home_page_id(conn, result.run_ids[0]))
        assert "component.count" in values, "the component pass did not run"
        assert values["component.count"] >= 1
        assert "WordPress" in values["component.detected"]
        # And the honest-scope metric, which is what the report reads.
        assert values["vuln.unchecked_count"] >= 1
    finally:
        httpd.shutdown()
        db.close_thread_connections()


def test_the_report_does_not_claim_a_check_that_did_not_run(tmp_path):
    """The visible symptom of the bug above: the report named OSV as a source
    while no component had been looked at."""
    from slap.report.model import build_report_model

    httpd, base = start_vulnerable("normal")
    settings = Settings()
    settings.db_path = tmp_path / "x.sqlite3"
    settings.artifact_dir = tmp_path / "a"
    settings.report_dir = tmp_path / "r"
    settings.collector.crux_api_key = None
    settings.lighthouse.enabled = False
    try:
        result = asyncio.run(core.run_batch([base], settings))
        model = build_report_model(core.get_run_detail(settings, result.run_ids[0]))
        note = model.coverage.vulnerability_note
        assert "OSV" in note
        # The fixture runs WordPress, which has no source. If the components
        # were never detected this sentence goes missing and the report reads
        # as a clean check.
        assert "NOT checked" in note
        assert model.coverage.unchecked_ecosystems
    finally:
        httpd.shutdown()
        db.close_thread_connections()


def test_discovery_and_the_component_pass_are_independent(tmp_path):
    """Both orderings, because the early return was found with discovery on
    and Lighthouse off, and the CLI check that passed had it the other way."""
    for discover in (True, False):
        httpd, base = start_vulnerable("normal")
        settings = Settings()
        settings.db_path = tmp_path / f"x{discover}.sqlite3"
        settings.artifact_dir = tmp_path / "a"
        settings.report_dir = tmp_path / "r"
        settings.collector.crux_api_key = None
        settings.lighthouse.enabled = False
        settings.discovery.enabled = discover
        try:
            result = asyncio.run(core.run_batch([base], settings))
            conn = db.connect(settings.db_path)
            values = db.observations_as_dict(
                conn, db.home_page_id(conn, result.run_ids[0]))
            assert "component.count" in values, f"discovery={discover}"
        finally:
            httpd.shutdown()
            db.close_thread_connections()
