"""Technology fingerprint, including the WP Rocket signals.

Per the roadmap, WP Rocket is not a data source; it is a *detectable
signal* and a *remediation target*. The high-value observation is the pair
"WP Rocket is installed" plus "this URL was not served from its cache",
which is the finding a client reads twice.

Everything here is a pure function over HTML text plus response headers,
so it is fully testable with a string and no network.
"""

from __future__ import annotations

import re
from typing import Any

from ..schema import Observation, obs
from .base import PageContext

# --------------------------------------------------------------------------
# Meta tag parsing
# --------------------------------------------------------------------------

_META_TAG_RE = re.compile(r"<meta\b[^>]*>", re.I)
_ATTR_RE = re.compile(r"""([\w:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))""")


def parse_attrs(tag: str) -> dict[str, str]:
    """Attribute dict for one HTML tag, lowercased keys."""
    out: dict[str, str] = {}
    for name, dq, sq, bare in _ATTR_RE.findall(tag):
        out[name.lower()] = dq or sq or bare
    return out


def find_generator_meta(html: str) -> list[dict[str, str]]:
    """Every ``<meta name="generator">`` tag's attributes, in document order."""
    found = []
    for tag in _META_TAG_RE.findall(html):
        attrs = parse_attrs(tag)
        if attrs.get("name", "").lower() == "generator":
            found.append(attrs)
    return found


# --------------------------------------------------------------------------
# WP Rocket
# --------------------------------------------------------------------------

_WPR_VERSION_RE = re.compile(r"WP\s*Rocket\s*([\d.]+)", re.I)
_WPR_CACHED_RE = re.compile(r"Debug:\s*cached@(\d+)", re.I)
_WPR_FOOTER_RE = re.compile(r"Performance optimized by WP Rocket", re.I)

_WPR_MARKUP_SIGNALS = (
    "data-rocket-src",
    "data-rocket-href",
    "data-rocket-defer",
    "data-rocket-type",
    "wp-content/cache/wp-rocket",
    "rocket-lazyload",
    "wpr-lazyload",
    "rocketlazyloadscript",
)


def detect_wp_rocket(html: str, headers: dict[str, str] | None = None) -> dict[str, Any]:
    """Detect WP Rocket, its version, enabled features, and cache state.

    Returns keys ``present``, ``version``, ``features``, ``page_cached``,
    ``cached_at``. ``page_cached`` is None when WP Rocket is not present,
    so the caller can tell "not installed" apart from "installed but cold".
    """
    headers = headers or {}
    result: dict[str, Any] = {
        "present": False,
        "version": None,
        "features": None,
        "page_cached": None,
        "cached_at": None,
    }

    # 1. The generator meta tag carries version and the feature bitfield.
    for attrs in find_generator_meta(html):
        content = attrs.get("content", "")
        if "wp rocket" in content.lower():
            result["present"] = True
            m = _WPR_VERSION_RE.search(content)
            if m:
                result["version"] = m.group(1)
            features = attrs.get("data-wpr-features")
            if features:
                result["features"] = features.strip()
            break

    # 2. Markup signals, for installs that strip the generator tag.
    if not result["present"]:
        haystack = html.lower()
        if any(sig in haystack for sig in _WPR_MARKUP_SIGNALS):
            result["present"] = True

    # 3. The footer comment proves the page was served from cache.
    cached_match = _WPR_CACHED_RE.search(html)
    if cached_match:
        result["present"] = True
        result["page_cached"] = True
        result["cached_at"] = cached_match.group(1)
    elif _WPR_FOOTER_RE.search(html):
        # Footer present without a cached@ stamp: WP Rocket ran but this
        # response was generated, not served from cache.
        result["present"] = True
        result["page_cached"] = False
    elif result["present"]:
        result["page_cached"] = False

    # Some hosts surface cache state in a header instead.
    cache_header = " ".join(
        headers.get(k, "") for k in ("x-rocket-cache", "x-cache", "cf-cache-status")
    ).lower()
    if result["present"] and result["page_cached"] is False and "hit" in cache_header:
        result["page_cached"] = True

    return result


# --------------------------------------------------------------------------
# CMS, CDN, page builder, competing cache plugins
# --------------------------------------------------------------------------

_CMS_MARKUP = (
    ("WordPress", ("/wp-content/", "/wp-includes/", "wp-json")),
    ("Shopify", ("cdn.shopify.com", "shopify-features", "/cdn/shop/")),
    ("Wix", ("static.wixstatic.com", "wix-code", "_wixCssStates")),
    ("Squarespace", ("static1.squarespace.com", "squarespace-headers")),
    ("Drupal", ("/sites/default/files/", "drupal-settings-json")),
    ("Joomla", ("/media/jui/", "joomla-script-options")),
    ("Webflow", ("assets.website-files.com", "w-webflow-badge", "webflow.js")),
    ("Ghost", ("/assets/built/", "ghost-sdk")),
)

_CDN_HEADERS = (
    ("Cloudflare", ("cf-ray", "cf-cache-status")),
    ("Amazon CloudFront", ("x-amz-cf-id", "x-amz-cf-pop")),
    ("Fastly", ("x-served-by", "x-fastly-request-id")),
    ("Akamai", ("x-akamai-transformed", "akamai-grn")),
    ("Sucuri", ("x-sucuri-id", "x-sucuri-cache")),
    ("Vercel", ("x-vercel-id",)),
    ("Netlify", ("x-nf-request-id",)),
)

_CDN_SERVER_STRINGS = (
    ("Cloudflare", "cloudflare"),
    ("BunnyCDN", "bunnycdn"),
    ("KeyCDN", "keycdn"),
    ("Netlify", "netlify"),
    ("Akamai", "akamaighost"),
    ("Amazon CloudFront", "cloudfront"),
)

_PAGE_BUILDERS = (
    ("Elementor", ("/plugins/elementor/", "elementor-page", "elementor-widget")),
    ("Divi", ("/themes/divi/", "et_pb_section", "et-db")),
    ("WPBakery", ("js_composer", "vc_row", "wpb_wrapper")),
    ("Beaver Builder", ("fl-builder", "/plugins/bb-plugin/")),
    ("Bricks", ("/themes/bricks/", "brxe-")),
    ("Oxygen", ("/plugins/oxygen/", "ct_section", "oxy-")),
    ("Gutenberg", ("wp-block-", "/wp-includes/css/dist/block-library/")),
)

_CACHE_PLUGINS = (
    ("WP Rocket", ("wp-content/cache/wp-rocket", "data-rocket-src")),
    ("W3 Total Cache", ("w3 total cache", "wp-content/cache/minify", "w3tc")),
    ("WP Super Cache", ("wp super cache", "wp-content/cache/supercache")),
    ("LiteSpeed Cache", ("litespeed", "x-litespeed-cache")),
    ("WP Fastest Cache", ("wp fastest cache", "wpfc-")),
    ("Autoptimize", ("autoptimize", "wp-content/cache/autoptimize")),
)


def _match_first(haystack: str, table: tuple) -> str | None:
    for name, needles in table:
        if any(n in haystack for n in needles):
            return name
    return None


def detect_cms(html: str, headers: dict[str, str]) -> str | None:
    generators = find_generator_meta(html)
    for attrs in generators:
        content = attrs.get("content", "").lower()
        for name in ("wordpress", "drupal", "joomla", "ghost", "typo3", "concrete"):
            if name in content:
                return name.capitalize() if name != "wordpress" else "WordPress"
    if "x-shopid" in headers or "x-shopify-stage" in headers:
        return "Shopify"
    if any(k.startswith("x-wix") for k in headers):
        return "Wix"
    if headers.get("x-generator", "").lower().startswith("drupal"):
        return "Drupal"
    return _match_first(html.lower(), _CMS_MARKUP)


def detect_cdn(headers: dict[str, str]) -> str | None:
    for name, keys in _CDN_HEADERS:
        if any(k in headers for k in keys):
            return name
    server = (headers.get("server", "") + " " + headers.get("via", "")).lower()
    for name, needle in _CDN_SERVER_STRINGS:
        if needle in server:
            return name
    return None


def detect_page_builder(html: str) -> str | None:
    return _match_first(html.lower(), _PAGE_BUILDERS)


def detect_cache_plugins(html: str, headers: dict[str, str]) -> list[str]:
    """All caching layers detected. More than one is itself a finding."""
    haystack = html.lower() + " " + " ".join(
        f"{k}:{v}" for k, v in headers.items()
    ).lower()
    return [name for name, needles in _CACHE_PLUGINS
            if any(n in haystack for n in needles)]


def observations_from_html(html: str, headers: dict[str, str]) -> list[Observation]:
    """Pure: HTML plus headers to fingerprint observations."""
    out: list[Observation] = []

    cms = detect_cms(html, headers)
    if cms:
        out.append(obs("tech.cms", cms))

    generators = find_generator_meta(html)
    if generators:
        joined = "; ".join(a.get("content", "") for a in generators if a.get("content"))
        if joined:
            out.append(obs("tech.generator", joined[:500]))

    cdn = detect_cdn(headers)
    if cdn:
        out.append(obs("tech.cdn", cdn))

    builder = detect_page_builder(html)
    if builder:
        out.append(obs("tech.page_builder", builder))

    plugins = detect_cache_plugins(html, headers)
    if plugins:
        out.append(obs("tech.cache_plugin", ", ".join(plugins)))

    rocket = detect_wp_rocket(html, headers)
    out.append(obs("wprocket.present", rocket["present"]))
    if rocket["present"]:
        if rocket["version"]:
            out.append(obs("wprocket.version", rocket["version"]))
        if rocket["features"]:
            out.append(obs("wprocket.features", rocket["features"]))
        if rocket["page_cached"] is not None:
            out.append(obs("wprocket.page_cached", rocket["page_cached"]))
        if rocket["cached_at"]:
            out.append(obs("wprocket.cached_at", rocket["cached_at"]))
    return out


class FingerprintCollector:
    """Reads the document the HTTP collector already fetched. No new request."""

    name = "fingerprint"

    async def collect(self, ctx: PageContext) -> list[Observation]:
        if ctx.document is None:
            return []
        return observations_from_html(ctx.document.text, ctx.document.headers)
