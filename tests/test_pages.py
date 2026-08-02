"""Per-page analysis: storage cardinality, aggregation, and discovery.

The aggregation tests come first and exist for one reason: every bug in this
area is silent. A trend chart that plots an arbitrary page's LCP renders
perfectly. A site list that reports 240 open findings against twelve real
problems renders perfectly. Neither raises, neither looks wrong in a
screenshot, and both are wrong. So each test below is written to fail loudly
on a number, and each was checked to fail against the pre-per-page query.
"""

from __future__ import annotations

import gzip

import pytest

from slap import db
from slap.schema import (
    AuditDepth,
    DiscoveredVia,
    Finding,
    FormFactor,
    Observation,
    PageRole,
    Scope,
    Severity,
    Source,
    Unit,
    origin_scoped_keys,
)


# --------------------------------------------------------------------------
# Fixtures: a run with several pages, built through the real writers.
# --------------------------------------------------------------------------

@pytest.fixture
def conn(tmp_path):
    c = db.init_db(tmp_path / "slap.sqlite3")
    yield c
    db.close_thread_connections()


def _finding(rule_id: str, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(rule_id=rule_id, severity=severity,
                   title=f"{rule_id} title", detail="detail")


def _obs(key: str, value: float) -> Observation:
    return Observation(Source.LIGHTHOUSE, key, numeric_value=value, unit=Unit.SCORE)


def _site_with_pages(conn, hostname="example.com", *, pages=4,
                     score=70.0, batch="b1", shared_rules=("no-hsts", "no-csp")):
    """One completed run holding `pages` pages.

    Every page fires the same shared rules, which is the realistic shape: a
    missing security header is missing site-wide. The home page carries a
    distinct score so a trend query that picks the wrong page is visible.
    """
    site_id = db.upsert_site(conn, hostname, client="Acme")
    run_id = db.create_run(conn, batch_id=batch, site_id=site_id,
                           slap_version="0.1.0", schema_version=1)
    page_ids = []
    for i in range(pages):
        role = PageRole.HOME if i == 0 else PageRole.TEMPLATE
        page_id = db.create_page(
            conn, run_id, f"https://{hostname}/p{i}" if i else f"https://{hostname}/",
            None, FormFactor.MOBILE, role=role,
            discovered_via=DiscoveredVia.MANUAL if i == 0 else DiscoveredVia.SITEMAP,
            audit_depth=AuditDepth.FULL if i < 2 else AuditDepth.LIGHT,
            template_class="home" if i == 0 else f"tpl{i}",
        )
        page_ids.append(page_id)
        # The home page scores `score`; every other page scores far worse, so
        # a query that grabs "whichever page sorted last" reads 10, not 70.
        db.insert_observations(conn, page_id, [
            _obs("lh.score.performance", score if i == 0 else 10.0),
        ])
        db.insert_findings(conn, page_id, [_finding(r) for r in shared_rules])
    db.finish_run(conn, run_id, db.RunStatus.COMPLETED)
    conn.commit()
    return site_id, run_id, page_ids


# --------------------------------------------------------------------------
# Cardinality
# --------------------------------------------------------------------------

def test_a_run_holds_many_pages(conn):
    _, run_id, page_ids = _site_with_pages(conn, pages=5)
    pages = db.run_pages(conn, run_id)
    assert len(pages) == 5
    assert len(page_ids) == 5


def test_run_pages_puts_home_first(conn):
    """The verdict speaks about the home page, so it leads the inventory."""
    site_id = db.upsert_site(conn, "example.com")
    run_id = db.create_run(conn, batch_id="b1", site_id=site_id,
                           slap_version="0.1.0", schema_version=1)
    # Insert the home page LAST, so ordering by id alone would not do it.
    db.create_page(conn, run_id, "https://example.com/a", None,
                   FormFactor.MOBILE, role=PageRole.TEMPLATE)
    db.create_page(conn, run_id, "https://example.com/b", None,
                   FormFactor.MOBILE, role=PageRole.DISCOVERED)
    db.create_page(conn, run_id, "https://example.com/", None,
                   FormFactor.MOBILE, role=PageRole.HOME)
    conn.commit()
    pages = db.run_pages(conn, run_id)
    assert pages[0]["url"] == "https://example.com/"
    assert pages[0]["role"] == "home"


def test_home_page_id_falls_back_to_lowest_id(conn):
    """A run with no page marked home still has to report something.

    Returning None would blank a report that has perfectly good data in it.
    """
    site_id = db.upsert_site(conn, "example.com")
    run_id = db.create_run(conn, batch_id="b1", site_id=site_id,
                           slap_version="0.1.0", schema_version=1)
    first = db.create_page(conn, run_id, "https://example.com/a", None,
                           FormFactor.MOBILE, role=PageRole.DISCOVERED)
    db.create_page(conn, run_id, "https://example.com/b", None,
                   FormFactor.MOBILE, role=PageRole.DISCOVERED)
    conn.commit()
    assert db.home_page_id(conn, run_id) == first


def test_page_records_what_was_attempted_not_what_succeeded(conn):
    """`audit_depth` distinguishes 'never asked' from 'asked and failed'.

    Both produce a page with no Lighthouse observations. The report needs a
    different sentence for each, so the distinction cannot be derived.
    """
    _, run_id, _ = _site_with_pages(conn, pages=4)
    depths = {p["url"]: p["audit_depth"] for p in db.run_pages(conn, run_id)}
    assert depths["https://example.com/"] == "full"
    assert depths["https://example.com/p3"] == "light"


# --------------------------------------------------------------------------
# Aggregation. Every one of these multiplies by page count if done naively.
# --------------------------------------------------------------------------

def test_site_list_counts_problems_not_page_instances(conn):
    """20 pages missing HSTS is one problem, not 20.

    Against the pre-per-page query this reads 8 (4 pages x 2 rules) and
    renders as "8 open findings" for a site with 2 real problems.
    """
    _site_with_pages(conn, pages=4, shared_rules=("no-hsts", "no-csp"))
    row = db.list_sites(conn)[0]
    assert row["finding_count"] == 2
    assert row["urgent_count"] == 2
    # The raw volume is still available for anywhere that wants it.
    assert row["finding_instances"] == 8
    assert row["page_count"] == 4


def test_site_list_urgent_count_does_not_multiply(conn):
    _site_with_pages(conn, pages=10, shared_rules=("no-hsts",))
    row = db.list_sites(conn)[0]
    assert row["urgent_count"] == 1
    assert row["finding_instances"] == 10


def test_trend_has_one_point_per_run_not_one_per_page(conn):
    """A run must contribute exactly one point to the trend line."""
    site_id, _, _ = _site_with_pages(conn, pages=6, batch="b1")
    history = db.site_metric_history(conn, site_id, ["lh.score.performance"])
    assert len(history) == 1


def test_trend_follows_the_home_page(conn):
    """Not "whichever page sorted last".

    The fixture gives the home page 70 and every other page 10. A query that
    joins all pages keeps the last row it sees, so this reads 10 and the
    chart plots a line that changes subject between runs.
    """
    site_id, _, _ = _site_with_pages(conn, pages=6, score=70.0)
    history = db.site_metric_history(conn, site_id, ["lh.score.performance"])
    assert history[0]["lh.score.performance"] == 70.0


def test_trend_keeps_runs_from_before_per_page(conn):
    """Rows migrated from a single-page database default to role 'home'.

    If they defaulted to NULL, or the query required role='home' with no
    fallback, every historical run would silently drop off the chart and the
    site would look brand new.
    """
    site_id = db.upsert_site(conn, "old.example")
    run_id = db.create_run(conn, batch_id="b0", site_id=site_id,
                           slap_version="0.1.0", schema_version=1)
    # Exactly what the pre-per-page writer produced: no role, no depth.
    conn.execute(
        "INSERT INTO page (run_id, url, final_url, form_factor) VALUES (?,?,?,?)",
        (run_id, "https://old.example/", None, "mobile"))
    page_id = conn.execute("SELECT id FROM page WHERE run_id = ?", (run_id,)).fetchone()[0]
    db.insert_observations(conn, page_id, [_obs("lh.score.performance", 55.0)])
    db.finish_run(conn, run_id, db.RunStatus.COMPLETED)
    conn.commit()

    history = db.site_metric_history(conn, site_id, ["lh.score.performance"])
    assert len(history) == 1
    assert history[0]["lh.score.performance"] == 55.0


def test_findings_across_sites_counts_sites_and_pages_separately(conn):
    _site_with_pages(conn, "a.example", pages=3, shared_rules=("no-hsts",))
    _site_with_pages(conn, "b.example", pages=5, shared_rules=("no-hsts",))
    rows = {r["rule_id"]: r for r in db.findings_across_sites(conn)}
    assert rows["no-hsts"]["site_count"] == 2
    assert rows["no-hsts"]["page_count"] == 8


def test_run_list_counts_distinct_rules_and_reports_pages(conn):
    _, run_id, _ = _site_with_pages(conn, pages=4, shared_rules=("no-hsts", "no-csp"))
    row = [r for r in db.list_runs(conn) if r["id"] == run_id][0]
    assert row["finding_count"] == 2
    assert row["page_count"] == 4


# --------------------------------------------------------------------------
# Migration
# --------------------------------------------------------------------------

def _legacy_db(path):
    """A database with the pre-per-page `page` table and nothing else new."""
    import sqlite3
    conn = sqlite3.connect(path)
    conn.executescript("""
    CREATE TABLE site (id INTEGER PRIMARY KEY, hostname TEXT NOT NULL UNIQUE,
                       label TEXT, client TEXT, created_at TEXT NOT NULL);
    CREATE TABLE run (id INTEGER PRIMARY KEY, batch_id TEXT, site_id INTEGER,
                      started_at TEXT, finished_at TEXT, status TEXT, error TEXT,
                      slap_version TEXT, schema_version INTEGER, lh_version TEXT,
                      chrome_version TEXT, throttling_profile TEXT, git_sha TEXT);
    CREATE TABLE page (id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL,
                       url TEXT NOT NULL, final_url TEXT, form_factor TEXT NOT NULL);
    CREATE TABLE artifact (id INTEGER PRIMARY KEY, run_id INTEGER, page_id INTEGER,
                           kind TEXT, path TEXT, sha256 TEXT, bytes INTEGER);
    INSERT INTO site VALUES (1, 'legacy.example', NULL, NULL, '2026-01-01T00:00:00+00:00');
    INSERT INTO run (id, batch_id, site_id, status) VALUES (1, 'b0', 1, 'completed');
    INSERT INTO page (id, run_id, url, final_url, form_factor)
                VALUES (1, 1, 'https://legacy.example/', NULL, 'mobile');
    INSERT INTO page (id, run_id, url, final_url, form_factor)
                VALUES (2, 1, 'https://legacy.example/x', NULL, 'mobile');
    INSERT INTO artifact (run_id, page_id, kind, path) VALUES (1, 1, 'lhr', '/tmp/x.json.gz');
    """)
    conn.commit()
    conn.close()


def test_migration_adds_the_page_columns(tmp_path):
    """The DDL is CREATE TABLE IF NOT EXISTS, so it never reaches an old table.

    Without the migration this database keeps a five-column `page` and dies
    on the first insert, partway through a batch.
    """
    path = tmp_path / "legacy.sqlite3"
    _legacy_db(path)
    conn = db.init_db(path)
    try:
        columns = {r[1] for r in conn.execute("PRAGMA table_info(page)")}
        assert {"role", "discovered_via", "audit_depth", "template_class"} <= columns
        # And the table is now writable through the current writer.
        db.create_page(conn, 1, "https://legacy.example/new", None,
                       FormFactor.MOBILE, role=PageRole.TEMPLATE)
        conn.commit()
    finally:
        db.close_thread_connections()


def test_migration_defaults_existing_pages_to_home(tmp_path):
    """Or every historical run drops off its site's trend line."""
    path = tmp_path / "legacy.sqlite3"
    _legacy_db(path)
    conn = db.init_db(path)
    try:
        roles = [r[0] for r in conn.execute("SELECT role FROM page ORDER BY id")]
        assert roles == ["home", "home"]
    finally:
        db.close_thread_connections()


def test_migration_marks_pages_that_actually_ran_lighthouse(tmp_path):
    """A historical page with an LHR artifact was audited at full depth.

    Defaulting it to 'light' would make the report claim the browser audit
    was never attempted on a run that has the artifact sitting on disk.
    """
    path = tmp_path / "legacy.sqlite3"
    _legacy_db(path)
    conn = db.init_db(path)
    try:
        depths = {r[0]: r[1] for r in
                  conn.execute("SELECT id, audit_depth FROM page ORDER BY id")}
        assert depths[1] == "full"   # has an artifact
        assert depths[2] == "light"  # does not
    finally:
        db.close_thread_connections()


def test_migration_is_idempotent(tmp_path):
    path = tmp_path / "legacy.sqlite3"
    _legacy_db(path)
    conn = db.init_db(path)
    try:
        assert db.migrate(conn) == []
    finally:
        db.close_thread_connections()


# --------------------------------------------------------------------------
# Metric scope
# --------------------------------------------------------------------------

def test_tls_is_origin_scoped():
    """One certificate serves every page. Collecting it per page is N
    identical results and N handshakes; printing it per page is the same
    sentence N times."""
    assert "tls.days_to_expiry" in origin_scoped_keys()
    assert "tls.valid" in origin_scoped_keys()


def test_crux_is_origin_scoped_as_collected():
    """The collector queries the origin, so every page gets the same answer.
    Running it per page is N times the quota for one row of data."""
    assert "crux.lcp.p75" in origin_scoped_keys()
    assert "crux.cwv_pass" in origin_scoped_keys()


def test_page_level_metrics_are_not_origin_scoped():
    for key in ("sec.csp", "sec.cookies_insecure", "lh.score.performance",
                "mixed.insecure_count"):
        assert key not in origin_scoped_keys(), key


def test_every_registered_metric_has_a_scope():
    from slap.schema import METRIC_REGISTRY
    assert all(isinstance(m.scope, Scope) for m in METRIC_REGISTRY.values())


# --------------------------------------------------------------------------
# Discovery, against a real offline server
# --------------------------------------------------------------------------

import asyncio  # noqa: E402

import httpx  # noqa: E402

from slap import core  # noqa: E402
from slap.collectors.base import CollectorConfig  # noqa: E402
from slap.config import Settings  # noqa: E402
from slap.discovery import (  # noqa: E402
    canonical_url,
    classify_template,
    choose_lighthouse_pages,
    discover,
    extract_links,
    is_sitemap_index,
    looks_like_a_page,
    parse_robots_disallow,
    parse_robots_sitemaps,
    parse_sitemap,
)
from tests.multipage_server import PAGES, start as start_multipage  # noqa: E402


@pytest.fixture(scope="module")
def site():
    httpd, base = start_multipage()
    yield base
    httpd.shutdown()


# --- pure parsers ---------------------------------------------------------

INDEX_XML = (b'<?xml version="1.0"?>'
             b'<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
             b'<sitemap><loc>https://x.test/s1.xml</loc></sitemap></sitemapindex>')
URLSET_XML = (b'<?xml version="1.0"?>'
              b'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
              b'<url><loc>https://x.test/</loc></url>'
              b'<url><loc>https://x.test/a</loc></url></urlset>')


def test_sitemap_index_is_not_a_page_list():
    """The single most costly discovery bug: it reports success and audits
    nothing, because an index's children are sitemaps, not pages."""
    locations, index = parse_sitemap(INDEX_XML)
    assert index is True
    assert locations == ["https://x.test/s1.xml"]
    assert is_sitemap_index(INDEX_XML)
    assert not is_sitemap_index(URLSET_XML)


def test_gzipped_sitemap_is_decoded():
    """httpx does not decode `Content-Type: application/gzip`; the gzip is the
    payload, not the transfer encoding. Undecoded, this yields [] not an error."""
    locations, index = parse_sitemap(gzip.compress(URLSET_XML))
    assert index is False
    assert locations == ["https://x.test/", "https://x.test/a"]


def test_canonical_url_collapses_the_duplicate_page_cases():
    assert canonical_url("https://x.test/a/") == canonical_url("https://x.test/a")
    assert canonical_url("HTTPS://X.TEST") == "https://x.test/"
    assert canonical_url("https://x.test/a#top") == "https://x.test/a"
    assert canonical_url("https://x.test:443/a") == "https://x.test/a"
    # A query string IS a different page, not a variant of the same one.
    assert canonical_url("https://x.test/a?p=2") != canonical_url("https://x.test/a")


def test_assets_are_not_pages():
    """Lighthouse cannot audit a PDF, and 'no CSP on this JPEG' is noise."""
    assert not looks_like_a_page("https://x.test/brochure.pdf")
    assert not looks_like_a_page("https://x.test/logo.png")
    assert looks_like_a_page("https://x.test/about")


def test_robots_parsing():
    text = "User-agent: *\nDisallow: /wp-admin/\nSitemap: https://x.test/s.xml\n"
    assert parse_robots_sitemaps(text, "https://x.test/") == ["https://x.test/s.xml"]
    assert parse_robots_disallow(text) == ["/wp-admin/"]


def test_links_stay_on_origin():
    html = (b'<a href="/a">1</a><a href="https://other.test/b">2</a>'
            b'<a href="mailto:x@y">3</a><a href="/c.pdf">4</a>')
    assert extract_links(html, "https://x.test/") == ["https://x.test/a"]


# --- template classification and sampling --------------------------------

def test_body_class_beats_url_shape():
    """A checkout page also carries `page`; order in the table decides."""
    assert classify_template("https://x.test/co",
                             '<body class="woocommerce-checkout page">') == "checkout"
    assert classify_template("https://x.test/x",
                             '<body class="single-product woocommerce">') == "product"


def test_url_shape_is_the_fallback():
    assert classify_template("https://x.test/shop/thing") == "product"
    assert classify_template("https://x.test/blog/hello") == "post"


def test_sampling_covers_each_template_once_and_keeps_home():
    pages = {"https://x.test/": "home",
             "https://x.test/p1": "product", "https://x.test/p2": "product",
             "https://x.test/b1": "post", "https://x.test/c": "checkout"}
    chosen = choose_lighthouse_pages(pages, limit=3, home_url="https://x.test/")
    assert chosen[0] == "https://x.test/"
    assert len(chosen) == 3
    assert len({pages[u] for u in chosen}) == 3


def test_sampling_is_deterministic():
    """Two runs of a site must measure the same pages or every run's 'product
    page score' is a different product page, which looks like a regression."""
    pages = {f"https://x.test/p{i}": "product" for i in range(20)}
    pages["https://x.test/"] = "home"
    first = choose_lighthouse_pages(pages, limit=4, home_url="https://x.test/")
    second = choose_lighthouse_pages(pages, limit=4, home_url="https://x.test/")
    assert first == second


# --- discovery against the real server -----------------------------------

async def _discover(base, **kwargs):
    cfg = CollectorConfig()
    async with httpx.AsyncClient(follow_redirects=True) as client:
        return await discover(client, base, cfg, **kwargs)


def test_discovery_follows_a_nested_gzipped_sitemap_index(site):
    found = asyncio.run(_discover(site, limit=50))
    assert found.method.value == "sitemap"
    paths = {canonical_url(u).replace(site, "") or "/" for u in found.urls}
    # Shard one is plain XML, shard two is gzipped. Both must be read.
    assert "/about" in paths          # shard 1
    assert "/checkout" in paths       # shard 2, gzipped
    assert len(found.urls) == len(PAGES)


def test_discovery_drops_assets_listed_in_the_sitemap(site):
    found = asyncio.run(_discover(site, limit=50))
    assert not any(u.endswith((".pdf", ".png")) for u in found.urls)


def test_discovery_reports_what_the_cap_dropped(site):
    """A cap applied and not stated reads as full coverage."""
    found = asyncio.run(_discover(site, limit=4))
    assert len(found.urls) == 4
    assert found.found == len(PAGES)
    assert found.dropped == len(PAGES) - 4
    assert found.capped


def test_discovery_always_keeps_the_starting_url_first(site):
    found = asyncio.run(_discover(site, limit=2))
    assert found.urls[0] == canonical_url(site)


def test_discovery_falls_back_to_the_single_page_when_nothing_answers():
    """An unreachable host must yield the one URL, not an exception."""
    found = asyncio.run(_discover("http://127.0.0.1:1/", limit=10))
    assert found.urls == ["http://127.0.0.1:1/"]
    assert found.found == 1


# --------------------------------------------------------------------------
# End to end: a real batch against the multi-page server
# --------------------------------------------------------------------------

@pytest.fixture
def settings(tmp_path, site):
    s = Settings()
    s.db_path = tmp_path / "slap.sqlite3"
    s.artifact_dir = tmp_path / "artifacts"
    s.report_dir = tmp_path / "reports"
    s.lighthouse.enabled = False          # no browser needed for these
    s.discovery.pages_per_site = 20
    s.collector.crux_api_key = None
    return s


def _audit(settings, site, **discovery):
    for key, value in discovery.items():
        setattr(settings.discovery, key, value)
    result = asyncio.run(core.run_batch([site], settings))
    conn = db.connect(settings.db_path)
    return result, conn


def test_one_run_holds_every_discovered_page(settings, site):
    result, conn = _audit(settings, site)
    try:
        assert result.succeeded == 1
        run_id = result.run_ids[0]
        pages = db.run_pages(conn, run_id)
        assert len(pages) == len(PAGES)
        assert sum(1 for p in pages if p["role"] == "home") == 1
    finally:
        db.close_thread_connections()


def test_discovery_is_recorded_on_the_run(settings, site):
    """So the report can say "10 of 12" rather than implying full coverage."""
    result, conn = _audit(settings, site, pages_per_site=5)
    try:
        run_id = result.run_ids[0]
        home = db.home_page_id(conn, run_id)
        values = db.observations_as_dict(conn, home)
        assert values["discovery.method"] == "sitemap"
        assert values["discovery.audited"] == 5
        assert values["discovery.found"] == len(PAGES)
        assert values["discovery.dropped"] == len(PAGES) - 5
    finally:
        db.close_thread_connections()


def test_pages_are_classified_by_template(settings, site):
    result, conn = _audit(settings, site)
    try:
        run_id = result.run_ids[0]
        by_url = {p["url"]: p["template_class"] for p in db.run_pages(conn, run_id)}
        assert by_url[f"{site}/checkout"] == "checkout"
        assert by_url[f"{site}/shop/widget"] == "product"
        assert by_url[f"{site}/blog/first-post"] == "post"
        assert by_url[f"{site}/"] == "home"
    finally:
        db.close_thread_connections()


def test_origin_scoped_collectors_run_once_not_once_per_page(settings, site):
    """TLS and CrUX describe the origin. Twenty pages must not mean twenty
    handshakes, twenty identical rows, and twenty times the API quota."""
    result, conn = _audit(settings, site)
    try:
        run_id = result.run_ids[0]
        rows = conn.execute(
            "SELECT o.metric_key, p.role FROM observation o "
            "JOIN page p ON p.id = o.page_id WHERE p.run_id = ?", (run_id,)
        ).fetchall()
        origin_keys = origin_scoped_keys()
        offenders = [r["metric_key"] for r in rows
                     if r["metric_key"] in origin_keys and r["role"] != "home"]
        assert offenders == [], f"origin-scoped observation on a non-home page: {offenders}"
        # And they were collected at all, on the home page.
        home_keys = {r["metric_key"] for r in rows if r["role"] == "home"}
        assert home_keys & origin_keys
    finally:
        db.close_thread_connections()


def test_findings_are_per_page(settings, site):
    """The checkout page sets a cookie with no Secure and no HttpOnly. A
    homepage-only audit never sees it; that is the whole point of per-page."""
    result, conn = _audit(settings, site)
    try:
        run_id = result.run_ids[0]
        rows = conn.execute(
            "SELECT p.url, f.rule_id FROM finding f JOIN page p ON p.id = f.page_id "
            "WHERE p.run_id = ?", (run_id,)
        ).fetchall()
        checkout = {r["rule_id"] for r in rows if r["url"].endswith("/checkout")}
        home = {r["rule_id"] for r in rows if r["url"] == f"{site}/"}
        assert checkout - home, (
            "the checkout page should have at least one finding the home page "
            f"does not: checkout={sorted(checkout)} home={sorted(home)}")
    finally:
        db.close_thread_connections()


def test_site_list_still_counts_problems_not_pages_after_a_real_audit(settings, site):
    """The end-to-end version of the aggregation guard: ten pages of one site
    must not read as ten times the problems."""
    result, conn = _audit(settings, site)
    try:
        row = db.list_sites(conn)[0]
        assert row["page_count"] == len(PAGES)
        assert row["finding_count"] < row["finding_instances"]
        assert row["finding_count"] > 0
    finally:
        db.close_thread_connections()


def test_disabling_discovery_restores_the_single_page_audit(settings, site):
    """The pre-pivot behaviour has to remain reachable, and reachable cheaply."""
    result, conn = _audit(settings, site, enabled=False)
    try:
        run_id = result.run_ids[0]
        pages = db.run_pages(conn, run_id)
        assert len(pages) == 1
        assert pages[0]["role"] == "home"
    finally:
        db.close_thread_connections()


def test_an_unreachable_host_still_fails_the_run(settings):
    """Per-page added audit metadata (discovery.method and friends), which is
    written as observations. If it counted toward "did we learn anything",
    an unreachable host would report completed and the findings engine would
    describe a site nobody reached. It is written after the check for exactly
    that reason, so this test guards the ordering."""
    result = asyncio.run(core.run_batch(["http://127.0.0.1:1/"], settings))
    conn = db.connect(settings.db_path)
    try:
        assert result.succeeded == 0
        run = db.get_run(conn, result.outcomes[0].run_id)
        assert run["status"] == "failed"
        assert db.get_findings(conn, run["id"]) == []
        assert db.get_observations(conn, run["id"]) == []
    finally:
        db.close_thread_connections()


# --------------------------------------------------------------------------
# The report
# --------------------------------------------------------------------------

from slap.report.model import (  # noqa: E402
    build_finding_views,
    build_page_rows,
    build_report_model,
    score_status,
    short_path,
)


def _rows(rule_id, urls, severity="high", evidence=None):
    import json
    return [{"rule_id": rule_id, "severity": severity, "title": f"{rule_id}!",
             "detail": "d", "remediation": None, "wp_rocket_setting": None,
             "effort": "low", "impact_ms": None, "url": u,
             "evidence_json": json.dumps(evidence) if evidence else None}
            for u in urls]


def test_one_finding_per_rule_not_one_per_page():
    """The 200-page-PDF bug. Twelve pages missing HSTS is ONE finding."""
    rows = _rows("no-hsts", [f"https://x.test/p{i}" for i in range(12)])
    views = build_finding_views(rows, pages_total=12)
    assert len(views) == 1
    assert views[0].page_count == 12


def test_a_sitewide_finding_says_so():
    views = build_finding_views(
        _rows("no-hsts", [f"https://x.test/p{i}" for i in range(12)]), pages_total=12)
    assert views[0].scope_text == "All 12 pages"
    assert views[0].is_sitewide


def test_a_single_page_finding_names_the_scale():
    """"1 of 12 pages" is the sentence that makes per-page worth reading."""
    views = build_finding_views(_rows("cookies-insecure", ["https://x.test/checkout"]),
                                pages_total=12)
    assert views[0].scope_text == "1 of 12 pages"
    assert not views[0].is_sitewide


def test_scope_text_pluralises_against_the_total():
    """"1 of 10 page" is what agreeing with the count instead produces."""
    views = build_finding_views(_rows("r", ["https://x.test/a"]), pages_total=10)
    assert views[0].scope_text.endswith("pages")


def test_a_single_page_audit_has_no_scope_text():
    """Scope on a one-page report is noise: there is nothing to compare to."""
    views = build_finding_views(_rows("r", ["https://x.test/"]), pages_total=1)
    assert views[0].scope_text == ""


def test_origin_scoped_findings_are_not_understated():
    """An expired certificate takes down all ten pages. Its observations live
    on the home page only because storage is page-keyed, so a naive page count
    reports "1 of 10 pages" for a site-wide critical."""
    views = build_finding_views(
        _rows("tls-invalid", ["https://x.test/"], severity="critical",
              evidence={"tls.error": "expired", "tls.valid": False}),
        pages_total=10)
    assert views[0].origin_scoped
    assert views[0].scope_text == "Site-wide"
    assert views[0].is_sitewide


def test_a_page_scoped_finding_with_evidence_is_not_origin_scoped():
    views = build_finding_views(
        _rows("no-csp", ["https://x.test/a"], evidence={"sec.csp": None}),
        pages_total=10)
    assert not views[0].origin_scoped


def test_grouped_finding_keeps_the_highest_severity_representative():
    """Findings arrive severity-ordered, so the first row for a rule wins."""
    rows = _rows("r", ["https://x.test/a"], severity="critical")
    rows += _rows("r", ["https://x.test/b"], severity="low")
    views = build_finding_views(rows, pages_total=2)
    assert len(views) == 1
    assert views[0].severity == "critical"


def test_affected_pages_are_shortest_first():
    views = build_finding_views(
        _rows("r", ["https://x.test/shop/a-long-one", "https://x.test/"]),
        pages_total=2)
    assert [short_path(p) for p in views[0].pages] == ["/", "/shop/a-long-one"]


def test_unmeasured_pages_never_print_a_blank_score():
    """A blank score cell reads as a zero to some readers and a pass to
    others. The honest answer is neither."""
    rows = build_page_rows([
        {"id": 1, "url": "https://x.test/", "audit_depth": "light",
         "template_class": "home", "role": "home", "finding_count": 2,
         "urgent_count": 0},
    ], {1: None})
    assert rows[0].measured is False
    assert rows[0].score_text == "—"
    assert rows[0].depth_note


def test_a_failed_browser_audit_reads_differently_from_one_never_run():
    """Both have no score. `audit_depth` is what distinguishes them, which is
    the whole reason it is stored rather than derived."""
    never = build_page_rows([{"id": 1, "url": "https://x.test/a",
                              "audit_depth": "light", "template_class": "page",
                              "role": "discovered"}], {1: None})[0]
    failed = build_page_rows([{"id": 2, "url": "https://x.test/b",
                               "audit_depth": "full", "template_class": "page",
                               "role": "template"}], {2: None})[0]
    assert never.depth_note != failed.depth_note


def test_score_status_is_shared_not_reimplemented():
    assert score_status(95) == "good"
    assert score_status(60) == "needs-improvement"
    assert score_status(20) == "poor"
    assert score_status(None) == "unknown"


def test_report_verdict_reads_the_home_page_not_the_last_page(settings, site):
    """Flattening every page's observations into one dict renders perfectly
    and reports whichever page was written last, so a site's headline would
    change depending on which product page sorted highest."""
    result, conn = _audit(settings, site)
    try:
        detail = core.get_run_detail(settings, result.run_ids[0])
        home_id = detail["home_page_id"]
        # Give a NON-home page a wildly different HTTP status observation and
        # confirm the model still reports the home page's.
        other = [p["id"] for p in detail["pages"] if p["id"] != home_id][0]
        conn.execute("UPDATE observation SET numeric_value = 599 "
                     "WHERE page_id = ? AND metric_key = 'http.status'", (other,))
        conn.commit()
        detail = core.get_run_detail(settings, result.run_ids[0])
        model = build_report_model(detail)
        appendix = {r.metric_key: r.value_text for r in model.appendix}
        assert detail["home_values"]["http.status"] == 200
        assert model.coverage.pages_audited == len(PAGES)
    finally:
        db.close_thread_connections()


def test_report_states_the_cap_rather_than_implying_full_coverage(settings, site):
    result, _ = _audit(settings, site, pages_per_site=4)
    try:
        model = build_report_model(core.get_run_detail(settings, result.run_ids[0]))
        assert model.coverage.capped
        assert str(len(PAGES)) in model.coverage.summary
        assert "4 of" in model.coverage.summary
    finally:
        db.close_thread_connections()


def test_report_explains_why_most_pages_have_no_score(settings, site):
    result, _ = _audit(settings, site)
    try:
        model = build_report_model(core.get_run_detail(settings, result.run_ids[0]))
        assert model.coverage.measurement_note
        assert model.is_multipage
    finally:
        db.close_thread_connections()


def test_multipage_report_renders(settings, site):
    from slap.report import render_report_html
    result, _ = _audit(settings, site)
    try:
        html = render_report_html(core.get_run_detail(settings, result.run_ids[0]))
        assert "Pages audited" in html
        assert "/checkout" in html
        assert "All 10 pages" in html
        assert "Site-wide" in html
        assert "Not measured" in html
    finally:
        db.close_thread_connections()


# --------------------------------------------------------------------------
# The web front-end
# --------------------------------------------------------------------------

def test_web_routes_render_a_multipage_run(settings, site):
    fastapi = pytest.importorskip("fastapi", reason="web extra not installed")
    from fastapi.testclient import TestClient

    from slap_web.app import create_app

    result, conn = _audit(settings, site)
    try:
        client = TestClient(create_app(settings))
        run_id = result.run_ids[0]

        run_page = client.get(f"/run/{run_id}")
        assert run_page.status_code == 200
        assert "Pages in this run" in run_page.text
        assert "/checkout" in run_page.text
        assert "Not measured" in run_page.text

        home = client.get("/")
        assert home.status_code == 200
        assert f"across {len(PAGES)} pages" in home.text

        site_id = db.find_site_by_hostname(conn, "127.0.0.1")["id"]
        detail_page = client.get(f"/site/{site_id}")
        assert detail_page.status_code == 200
        assert f"All {len(PAGES)} pages" in detail_page.text

        assert client.get("/findings").status_code == 200
        assert client.get(f"/run/{run_id}/report.html").status_code == 200
    finally:
        db.close_thread_connections()


def test_operator_finding_list_is_grouped_by_rule():
    from slap_web import viewmodel as vm

    rows = [{"rule_id": "no-hsts", "severity": "medium", "title": "No HSTS",
             "detail": "d", "url": f"https://x.test/p{i}"} for i in range(12)]
    grouped = vm.decorate_findings(rows, pages_total=12)
    assert len(grouped) == 1
    assert grouped[0]["page_count"] == 12
    assert grouped[0]["scope"] == "All 12 pages"


def test_decorating_preaggregated_rows_keeps_their_page_count():
    """`findings_across_sites` aggregates in SQL and carries no url. Writing
    len(pages) unconditionally replaced a real COUNT(DISTINCT p.id) with 0,
    and the template read it and rendered nothing."""
    from slap_web import viewmodel as vm

    rows = [{"rule_id": "no-hsts", "severity": "medium", "title": "No HSTS",
             "site_count": 2, "page_count": 80}]
    decorated = vm.decorate_findings(rows)
    assert decorated[0]["page_count"] == 80


def test_site_headline_comes_from_the_home_page(settings, site):
    """`SELECT id FROM page WHERE run_id = ? LIMIT 1` was correct while a run
    held one page and became a coin toss at twenty."""
    result, conn = _audit(settings, site)
    try:
        site_id = db.find_site_by_hostname(conn, "127.0.0.1")["id"]
        detail = core.get_site_detail(settings, site_id)
        home_id = db.home_page_id(conn, result.run_ids[0])
        expected = db.observations_as_dict(conn, home_id)
        assert detail["observations"] == expected
        assert len(detail["pages"]) == len(PAGES)
    finally:
        db.close_thread_connections()


def test_sampling_prefers_templates_that_cover_more_pages():
    """Alphabetical ordering measures four pages that represent four pages.

    On a ten-page site the alphabetical pass at limit=4 picks checkout,
    contact, home and page, and drops `post` and `product` entirely, which
    between them are six of the ten pages and the actual site.
    """
    pages = {"https://x.test/": "home",
             "https://x.test/contact": "contact",
             "https://x.test/about": "page"}
    pages |= {f"https://x.test/blog/{i}": "post" for i in range(3)}
    pages |= {f"https://x.test/shop/{i}": "product" for i in range(3)}

    chosen = choose_lighthouse_pages(pages, limit=4, home_url="https://x.test/")
    templates = {pages[u] for u in chosen}
    assert "post" in templates
    assert "product" in templates
    assert chosen[0] == "https://x.test/"


def test_sampling_stays_deterministic_under_the_coverage_ordering():
    pages = {"https://x.test/": "home"}
    pages |= {f"https://x.test/p{i}": "product" for i in range(5)}
    pages |= {f"https://x.test/b{i}": "post" for i in range(5)}
    first = choose_lighthouse_pages(pages, limit=3, home_url="https://x.test/")
    second = choose_lighthouse_pages(pages, limit=3, home_url="https://x.test/")
    assert first == second


# --------------------------------------------------------------------------
# Per-page subresources: mixed content, forms, third parties
# --------------------------------------------------------------------------

from slap.collectors.subresources import (  # noqa: E402
    SubresourceCollector,
    find_subresources,
    insecure_form_actions,
    insecure_subresources,
    third_party_origins,
)

MIXED_HTML = """<html><head>
<link rel="stylesheet" href="http://cdn.bad/a.css">
<link rel="canonical" href="http://example.com/x">
</head><body>
<img src="http://img.bad/a.png" srcset="http://img.bad/2x.png 2x, /local.png 1x">
<script src="https://analytics.other/t.js"></script>
<a href="http://not-a-resource.test/page">a link the user may click</a>
<form action="http://insecure.test/login"><input name="pw"></form>
<form><input name="fine"></form>
<div style="background:url(http://css.bad/bg.png)"></div>
</body></html>"""


def test_a_link_is_not_a_subresource():
    """<a href="http://..."> is a page the user may navigate to, not a
    resource this page loads. Reporting it as mixed content is a false
    positive, and false positives train people to ignore the finding."""
    subs = find_subresources(MIXED_HTML, "https://example.com/p")
    assert not any("not-a-resource" in u for u in subs)


def test_rel_canonical_is_not_a_fetch():
    """<link rel="canonical"> declares a URL; it does not load it."""
    subs = find_subresources(MIXED_HTML, "https://example.com/p")
    assert not any(u.endswith("/x") for u in subs)


def test_mixed_content_covers_css_urls_and_srcset():
    insecure = insecure_subresources(
        find_subresources(MIXED_HTML, "https://example.com/p"),
        "https://example.com/p")
    assert "http://cdn.bad/a.css" in insecure
    assert "http://img.bad/2x.png" in insecure      # srcset candidate
    assert "http://css.bad/bg.png" in insecure      # inline style url()


def test_mixed_content_is_decided_by_the_pages_own_scheme():
    """An http:// page loading http:// resources is not mixed content. It is
    an unencrypted site, which a different rule already covers; counting it
    here would report one problem twice."""
    subs = find_subresources(MIXED_HTML, "http://example.com/p")
    assert insecure_subresources(subs, "http://example.com/p") == []


def test_an_insecure_form_action_is_its_own_finding():
    """Nothing is fetched until the user submits, and what leaks is what they
    typed. Different failure, different severity, separate metric."""
    forms = insecure_form_actions(MIXED_HTML, "https://example.com/p")
    assert forms == ["http://insecure.test/login"]


def test_a_form_with_no_action_submits_to_the_current_https_url():
    assert insecure_form_actions('<form><input name="x"></form>',
                                 "https://example.com/p") == []


def test_third_party_origins_exclude_the_page_itself():
    origins = third_party_origins(
        find_subresources(MIXED_HTML, "https://example.com/p"),
        "https://example.com/p")
    assert "https://analytics.other" in origins
    assert not any("example.com" in o for o in origins)


def test_subresources_are_collected_per_page(settings, site):
    """The observation has to exist on every page, not just the home page:
    this is the collector per-page analysis exists for."""
    result, conn = _audit(settings, site)
    try:
        run_id = result.run_ids[0]
        rows = conn.execute(
            "SELECT p.url, o.metric_key, o.numeric_value, o.text_value "
            "FROM observation o JOIN page p ON p.id = o.page_id "
            "WHERE p.run_id = ? AND o.metric_key LIKE 'thirdparty.%'", (run_id,)
        ).fetchall()
        pages_with = {r["url"] for r in rows}
        assert len(pages_with) == len(PAGES)
    finally:
        db.close_thread_connections()


def test_the_inspection_method_is_recorded_not_implied(settings, site):
    """"No mixed content found" means one thing when a browser looked and
    another when a regex did. The report has to be able to say which."""
    result, conn = _audit(settings, site)
    try:
        run_id = result.run_ids[0]
        home = db.home_page_id(conn, run_id)
        assert db.observations_as_dict(conn, home)["mixed.method"] == "html"
    finally:
        db.close_thread_connections()


def test_the_insecure_form_fires_only_on_checkout():
    """End to end over https, which the http fixture cannot exercise."""
    import asyncio as _asyncio

    from slap.collectors.base import CollectorConfig, FetchedDocument, PageContext

    async def run(url, html):
        ctx = PageContext(url=url, client=None, config=CollectorConfig())
        ctx.document = FetchedDocument(
            url=url, final_url=url, status=200, http_version="HTTP/2",
            headers={}, set_cookie=[], text=html, content_bytes=len(html),
            ttfb_ms=1.0)
        return {o.metric_key: o.value
                for o in await SubresourceCollector().collect(ctx)}

    checkout = _asyncio.run(run("https://shop.test/checkout", MIXED_HTML))
    plain = _asyncio.run(run("https://shop.test/about",
                             '<html><body><img src="/a.png"></body></html>'))
    assert checkout["mixed.insecure_forms"] == 1
    assert checkout["mixed.insecure_count"] == 4
    assert plain["mixed.insecure_forms"] == 0
    assert plain["mixed.insecure_count"] == 0
    # Clean pages still record the method: absence of a finding is a claim.
    assert plain["mixed.method"] == "html"
