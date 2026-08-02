"""Finding the pages of a site.

Discovery is deliberately **not** a collector. A collector takes a
:class:`~slap.collectors.base.PageContext` and returns observations for one
URL; discovery runs before any context exists and produces the URL list
itself. Bending the collector protocol to fit would be the first crack in the
thing that has kept the pipeline honest, so this is a plain module that `core`
calls as a pre-stage.

The order is sitemap, then crawl:

1. ``robots.txt`` for ``Sitemap:`` directives, which is where a site says
   authoritatively what it wants indexed.
2. The conventional locations, because plenty of sites publish a sitemap and
   never mention it in robots.txt: ``/sitemap.xml``, ``/sitemap_index.xml``
   (Yoast), ``/wp-sitemap.xml`` (WordPress core since 5.5).
3. Failing both, a shallow same-origin crawl.

Every parser here is a module-level pure function that takes a string or
bytes, so the whole file is testable without a network.

Three failure modes shaped this code, and all three are silent:

* **A ``<sitemapindex>`` is not a list of pages.** It is a list of *sitemaps*.
  A parser that reads ``<loc>`` without checking the root element audits zero
  real pages and reports success.
* **``.xml.gz`` is common** and httpx does not transparently decode a body
  served as ``application/gzip``. The bytes arrive, the XML parse yields
  nothing, and the result is an empty list rather than an error.
* **A cap that is applied and not stated reads as full coverage.** Every
  result carries what was found and what was dropped so the report can say
  "12 of 3,400" instead of "12".
"""

from __future__ import annotations

import gzip
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from .collectors.base import CollectorConfig
from .schema import DiscoveredVia

#: Conventional sitemap locations, tried in order when robots.txt names none.
WELL_KNOWN_SITEMAPS = (
    "/sitemap.xml",
    "/sitemap_index.xml",   # Yoast
    "/wp-sitemap.xml",      # WordPress core, 5.5+
    "/sitemap-index.xml",
)

#: Extensions that are never HTML pages. A sitemap that lists PDFs and images
#: should not turn them into audited "pages": Lighthouse cannot audit a PDF
#: and the security checks would report a missing CSP on a JPEG.
_NON_PAGE_SUFFIXES = (
    ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".webp", ".avif", ".svg", ".ico",
    ".css", ".js", ".mjs", ".json", ".xml", ".txt", ".zip", ".gz", ".mp4",
    ".mp3", ".webm", ".woff", ".woff2", ".ttf", ".eot", ".doc", ".docx",
    ".xls", ".xlsx", ".ppt", ".pptx", ".rss", ".atom",
)

_HREF_RE = re.compile(rb"""<a\b[^>]*?\bhref\s*=\s*["']([^"'#]+)""", re.I)


@dataclass(slots=True)
class DiscoveryConfig:
    """How many pages of a site to find, and how many to measure.

    ``page_concurrency`` is a second dimension of the same setting
    ``http_concurrency`` already covers, and it is separate for the reason the
    Lighthouse cap is separate: multiplying two unbounded fan-outs together is
    how a batch ends up with hundreds of requests in flight.
    """

    enabled: bool = True
    #: Pages audited per site, including the home page. The cap that bites on
    #: a large site, and the one the report has to disclose when it does.
    pages_per_site: int = 20
    #: Pages given the browser audit. At ~90s per page against a hard
    #: concurrency cap of 3, this is the setting that decides whether a
    #: 24-site batch takes 48 minutes or two hours.
    lighthouse_pages_per_site: int = 5
    page_concurrency: int = 5
    crawl_depth: int = 2
    allow_crawl: bool = True


@dataclass(slots=True)
class DiscoveryResult:
    """What discovery found, and what it had to leave out."""

    urls: list[str] = field(default_factory=list)
    method: DiscoveredVia = DiscoveredVia.MANUAL
    #: Total distinct page URLs seen before the cap was applied.
    found: int = 0
    #: Found minus audited. Non-zero means the report must say so.
    dropped: int = 0
    #: Which sitemap documents were actually read, for the appendix.
    sitemaps: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def capped(self) -> bool:
        return self.dropped > 0


# --------------------------------------------------------------------------
# Pure parsing helpers
# --------------------------------------------------------------------------

def canonical_url(url: str) -> str:
    """A stable identity for a page URL.

    Discovery that does its own trailing-slash handling produces
    ``example.com/about`` and ``example.com/about/`` as two pages, and the
    report prints every finding twice with nothing to explain why. Fragments
    go, an empty path becomes ``/``, and the host is lowercased. Query strings
    are kept: ``?p=12`` is a different page, not a variant of the same one.
    """
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower() or "https"
    host = parts.hostname or ""
    if parts.port and not (
        (scheme == "https" and parts.port == 443)
        or (scheme == "http" and parts.port == 80)
    ):
        host = f"{host}:{parts.port}"
    path = parts.path or "/"
    # One trailing slash policy, applied everywhere: keep it only on the root.
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/") or "/"
    return urlunsplit((scheme, host, path, parts.query, ""))


def same_origin(a: str, b: str) -> bool:
    pa, pb = urlsplit(a), urlsplit(b)
    return (pa.scheme, pa.hostname, pa.port) == (pb.scheme, pb.hostname, pb.port)


def looks_like_a_page(url: str) -> bool:
    """False for assets and documents a page audit cannot say anything about."""
    path = urlsplit(url).path.lower()
    return not path.endswith(_NON_PAGE_SUFFIXES)


def decode_body(content: bytes, headers: dict[str, str] | None = None) -> bytes:
    """Gunzip when the body is gzipped, whatever the headers claim.

    httpx transparently decodes ``Content-Encoding: gzip``, but a
    ``sitemap.xml.gz`` is served as ``Content-Type: application/gzip`` with no
    content-encoding at all: the gzip is the *payload*, not the transfer
    encoding. Sniffing the magic bytes covers both the well-behaved server and
    the one that mislabels it, and costs nothing.
    """
    if content[:2] == b"\x1f\x8b":
        try:
            return gzip.decompress(content)
        except (OSError, EOFError, gzip.BadGzipFile):
            return content
    return content


def parse_robots_sitemaps(text: str, base_url: str) -> list[str]:
    """Every ``Sitemap:`` directive. Case-insensitive, group-independent.

    ``Sitemap`` is not scoped to a ``User-agent`` block, so this deliberately
    ignores grouping rather than trying to honour it.
    """
    out: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition(":")
        if key.strip().lower() != "sitemap":
            continue
        value = value.strip()
        if value:
            out.append(urljoin(base_url, value))
    return out


def parse_robots_disallow(text: str, user_agent: str = "*") -> list[str]:
    """Disallow path prefixes for our user-agent, falling back to ``*``.

    Only used by the crawl fallback. A sitemap URL is the site telling us to
    look at that page, so a Disallow rule does not override it.
    """
    groups: dict[str, list[str]] = {}
    current: list[str] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "user-agent":
            current = groups.setdefault(value.lower(), [])
        elif key == "disallow" and value:
            current.append(value)
    for name in (user_agent.lower(), "*"):
        if name in groups:
            return groups[name]
    return []


def is_sitemap_index(content: bytes) -> bool:
    """True when the root element is ``<sitemapindex>``.

    Checked on the root element rather than by looking for a ``<sitemap>``
    tag, because an index's children are themselves called ``<sitemap>`` and
    a substring test gets it right by accident and wrong under nesting.
    """
    try:
        root = ET.fromstring(decode_body(content))
    except ET.ParseError:
        return False
    return _localname(root.tag) == "sitemapindex"


def _localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def parse_sitemap(content: bytes, base_url: str = "") -> tuple[list[str], bool]:
    """Return ``(locations, is_index)`` from a sitemap document.

    One parser for both shapes, because the ``<loc>`` extraction is identical
    and only the meaning of the result differs. Getting that distinction wrong
    is the difference between auditing a site's pages and auditing its
    sitemaps.
    """
    body = decode_body(content)
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return [], False
    index = _localname(root.tag) == "sitemapindex"
    locations: list[str] = []
    for element in root.iter():
        if _localname(element.tag) != "loc":
            continue
        text = (element.text or "").strip()
        if text:
            locations.append(urljoin(base_url, text) if base_url else text)
    return locations, index


def extract_links(html: bytes, base_url: str) -> list[str]:
    """Same-origin ``href`` targets, absolute and canonical.

    A regex rather than a parser: this runs over the already-fetched bytes of
    every crawled page, the failure mode of missing a link is one fewer page
    rather than a wrong number, and the project has no HTML parser dependency.
    """
    out: list[str] = []
    seen: set[str] = set()
    for match in _HREF_RE.findall(html):
        try:
            href = match.decode("utf-8", "ignore").strip()
        except Exception:
            continue
        if not href or href.startswith(("mailto:", "tel:", "javascript:", "data:")):
            continue
        absolute = canonical_url(urljoin(base_url, href))
        if absolute in seen or not same_origin(absolute, base_url):
            continue
        if not looks_like_a_page(absolute):
            continue
        seen.add(absolute)
        out.append(absolute)
    return out


# --------------------------------------------------------------------------
# Template classification
# --------------------------------------------------------------------------

#: Body-class signals, most specific first. WordPress puts these on <body> and
#: they are a far better template signal than the URL, which is why
#: classification reads the already-fetched document rather than guessing from
#: the path. Order matters: a WooCommerce checkout page also carries `page`.
_BODY_CLASS_TEMPLATES = (
    ("checkout", ("woocommerce-checkout",)),
    ("cart", ("woocommerce-cart",)),
    ("account", ("woocommerce-account",)),
    ("product", ("single-product", "woocommerce-page single-product")),
    ("post", ("single-post", "single-format-standard")),
    ("archive", ("archive", "category", "tag", "blog")),
    ("search", ("search-results", "search-no-results")),
    ("contact", ("page-template-contact",)),
    ("page", ("page-template", "page-id-", " page ")),
)

#: URL-shape fallbacks for sites that are not WordPress or strip body classes.
_PATH_TEMPLATES = (
    ("checkout", ("/checkout", "/cart", "/basket")),
    ("account", ("/account", "/my-account", "/login", "/signin")),
    ("product", ("/product/", "/products/", "/shop/", "/item/")),
    ("post", ("/blog/", "/news/", "/post/", "/article/")),
    ("archive", ("/category/", "/tag/", "/archive/", "/topics/")),
    ("contact", ("/contact",)),
    ("about", ("/about",)),
    ("legal", ("/privacy", "/terms", "/legal", "/cookie")),
)

_BODY_CLASS_RE = re.compile(r"<body[^>]*\bclass\s*=\s*[\"']([^\"']*)[\"']", re.I)


def body_classes(html: str) -> list[str]:
    match = _BODY_CLASS_RE.search(html)
    return match.group(1).lower().split() if match else []


def classify_template(url: str, html: str | None = None, *,
                      is_home: bool = False) -> str:
    """Name the template a page is an instance of.

    Used to pick which pages get the browser audit: one representative per
    template is what makes per-page affordable, because a client acts on
    "product pages are slow", not on the 400th product page individually.
    """
    if is_home:
        return "home"
    classes = set(body_classes(html)) if html else set()
    if "home" in classes or "front-page" in classes:
        return "home"
    for name, needles in _BODY_CLASS_TEMPLATES:
        for needle in needles:
            needle = needle.strip()
            if needle.endswith("-"):  # prefix match, e.g. page-id-
                if any(c.startswith(needle) for c in classes):
                    return name
            elif needle in classes:
                return name
    path = urlsplit(url).path.lower()
    if path in ("", "/"):
        return "home"
    for name, needles in _PATH_TEMPLATES:
        if any(n in path for n in needles):
            return name
    # Depth is the last resort and a weak signal, so it says so in the name
    # rather than pretending to have recognised something.
    return f"depth-{max(1, len([p for p in path.split('/') if p]))}"


def choose_lighthouse_pages(pages: dict[str, str], *, limit: int,
                            home_url: str | None = None) -> list[str]:
    """One representative per template class, home first, capped at `limit`.

    ``pages`` maps URL to template class. Returns the URLs that should get the
    browser audit; everything else is audited at ``light`` depth.

    The home page is always included and always first: it is the page the
    verdict speaks about and the anchor every site trend follows, so dropping
    it to make room for a product page would break comparison across runs.
    """
    if limit <= 0:
        return []
    chosen: list[str] = []
    seen_classes: set[str] = set()

    if home_url and home_url in pages:
        chosen.append(home_url)
        seen_classes.add(pages[home_url])

    # Templates covering more pages are measured first.
    #
    # The obvious ordering is alphabetical by class name, and it is wrong in a
    # way that is easy to miss: on a ten-page site with home, page, contact,
    # checkout, post x3 and product x3, an alphabetical pass at limit=4 picks
    # checkout, contact, home and page, and drops `post` and `product`
    # entirely. That measures four pages representing four pages, and says
    # nothing about the six that are the actual site. Ordering by coverage
    # picks the templates that speak for the most pages.
    #
    # Ties break on the class name and then the URL, so the choice stays
    # deterministic: two runs of the same site must measure the same pages or
    # every run's "product page score" is a different product page, which
    # reads as a regression and is not one.
    coverage: dict[str, int] = {}
    for template in pages.values():
        coverage[template] = coverage.get(template, 0) + 1

    for url in sorted(pages, key=lambda u: (-coverage[pages[u]], pages[u], u)):
        if len(chosen) >= limit:
            break
        if url in chosen:
            continue
        template = pages[url]
        if template in seen_classes:
            continue
        seen_classes.add(template)
        chosen.append(url)
    return chosen[:limit]


# --------------------------------------------------------------------------
# The network side
# --------------------------------------------------------------------------

async def _get(client: httpx.AsyncClient, url: str, cfg: CollectorConfig,
               *, timeout: float | None = None) -> httpx.Response | None:
    try:
        return await client.get(
            url,
            headers={"User-Agent": cfg.user_agent},
            follow_redirects=True,
            timeout=timeout or cfg.timeout,
        )
    except (httpx.HTTPError, ValueError):
        return None


async def sitemap_urls(client: httpx.AsyncClient, origin: str,
                       cfg: CollectorConfig, *, max_sitemaps: int = 25,
                       max_urls: int = 5000) -> tuple[list[str], list[str]]:
    """Every page URL the site's sitemaps declare. Returns (urls, sitemaps read).

    Nested indexes are followed breadth-first with a hard cap on documents
    read, because a sitemap index can point at itself and a large site can
    publish hundreds of shards. ``max_urls`` bounds memory before the caller's
    much smaller audit cap is applied.
    """
    seen_docs: set[str] = set()
    read: list[str] = []
    queue: list[str] = []

    robots = await _get(client, urljoin(origin, "/robots.txt"), cfg)
    if robots is not None and robots.status_code == 200:
        queue.extend(parse_robots_sitemaps(robots.text, origin))
    if not queue:
        queue = [urljoin(origin, path) for path in WELL_KNOWN_SITEMAPS]

    urls: list[str] = []
    seen_urls: set[str] = set()
    while queue and len(read) < max_sitemaps and len(urls) < max_urls:
        doc_url = queue.pop(0)
        if doc_url in seen_docs:
            continue
        seen_docs.add(doc_url)
        response = await _get(client, doc_url, cfg)
        if response is None or response.status_code != 200:
            continue
        locations, index = parse_sitemap(response.content, doc_url)
        if not locations:
            continue
        read.append(doc_url)
        if index:
            # Children of an index are more sitemaps, not pages. Reading them
            # as pages is the bug this branch exists to prevent.
            queue.extend(locations)
            continue
        for loc in locations:
            canonical = canonical_url(loc)
            if canonical in seen_urls or not looks_like_a_page(canonical):
                continue
            if not same_origin(canonical, origin):
                continue
            seen_urls.add(canonical)
            urls.append(canonical)
            if len(urls) >= max_urls:
                break
    return urls, read


async def crawl_urls(client: httpx.AsyncClient, start_url: str,
                     cfg: CollectorConfig, *, depth: int = 2,
                     max_urls: int = 200,
                     disallow: list[str] | None = None) -> list[str]:
    """Breadth-first same-origin crawl. The fallback, not the default.

    Bounded three ways (depth, URL count, same-origin) because a crawler with
    one bound is a crawler that will eventually walk a calendar widget until
    the timeout.
    """
    disallow = disallow or []
    start = canonical_url(start_url)
    found = [start]
    seen = {start}
    frontier = [start]

    for _ in range(max(0, depth)):
        if len(found) >= max_urls or not frontier:
            break
        next_frontier: list[str] = []
        for url in frontier:
            if len(found) >= max_urls:
                break
            response = await _get(client, url, cfg)
            if response is None or response.status_code >= 400:
                continue
            content_type = response.headers.get("content-type", "")
            if "html" not in content_type.lower():
                continue
            for link in extract_links(response.content, url):
                if link in seen or len(found) >= max_urls:
                    continue
                path = urlsplit(link).path
                if any(path.startswith(rule) for rule in disallow):
                    continue
                seen.add(link)
                found.append(link)
                next_frontier.append(link)
        frontier = next_frontier
    return found


async def discover(client: httpx.AsyncClient, url: str, cfg: CollectorConfig,
                   *, limit: int = 20, crawl_depth: int = 2,
                   allow_crawl: bool = True) -> DiscoveryResult:
    """Find up to `limit` pages of the site `url` belongs to.

    The starting URL is always first in the result and always kept, whatever
    the cap: it is the home page, the trend anchor, and the page a one-URL
    audit would have covered on its own.
    """
    start = canonical_url(url)
    parts = urlsplit(start)
    origin = urlunsplit((parts.scheme, parts.netloc, "/", "", ""))
    result = DiscoveryResult(urls=[start], method=DiscoveredVia.MANUAL)

    if limit <= 1:
        result.found = 1
        return result

    candidates: list[str] = []
    try:
        candidates, sitemaps = await sitemap_urls(client, origin, cfg)
        result.sitemaps = sitemaps
        if candidates:
            result.method = DiscoveredVia.SITEMAP
    except Exception as exc:                     # noqa: BLE001 - reported, not fatal
        result.errors.append(f"sitemap: {type(exc).__name__}: {exc}")

    if not candidates and allow_crawl:
        try:
            robots = await _get(client, urljoin(origin, "/robots.txt"), cfg)
            disallow = (parse_robots_disallow(robots.text, cfg.user_agent)
                        if robots is not None and robots.status_code == 200 else [])
            candidates = await crawl_urls(client, start, cfg, depth=crawl_depth,
                                          max_urls=max(limit * 5, 50),
                                          disallow=disallow)
            if len(candidates) > 1:
                result.method = DiscoveredVia.CRAWL
        except Exception as exc:                 # noqa: BLE001
            result.errors.append(f"crawl: {type(exc).__name__}: {exc}")

    ordered: list[str] = [start]
    seen = {start}
    for candidate in candidates:
        if candidate not in seen:
            seen.add(candidate)
            ordered.append(candidate)

    result.found = len(ordered)
    result.urls = ordered[:limit]
    result.dropped = max(0, result.found - len(result.urls))
    return result
