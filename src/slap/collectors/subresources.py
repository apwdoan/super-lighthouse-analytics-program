"""What each page loads: mixed content and third-party origins.

Page-scoped by nature, and the clearest argument for per-page analysis in the
whole project. A marketing landing page carries trackers the home page does
not; an old blog post still references an image over plain ``http://`` that
nobody has looked at since the site moved to TLS. A homepage-only audit sees
neither.

Reads the document :class:`~slap.collectors.http_probe.HttpCollector` already
fetched. No new request.

**The honest-reporting constraint.** Parsing HTML finds subresources declared
in the markup and cannot find anything a script injects at runtime. A browser
sees both. Those are different answers to the same question, so the method is
recorded as an observation alongside the count, and the report prints it:
"no mixed content found" means one thing when a browser looked and another
when a regex did, and a client is entitled to know which.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from ..schema import Observation, Scope, obs
from .base import PageContext

#: Attributes that fetch a subresource. `href` is deliberately restricted to
#: <link> below: an <a href="http://..."> is a link the user may click, not a
#: resource the page loads, and reporting it as mixed content is a false
#: positive that trains people to ignore the finding.
_RESOURCE_RE = re.compile(
    rb"""<(?P<tag>script|img|iframe|source|video|audio|embed|object|link|form)\b"""
    rb"""(?P<attrs>[^>]*)>""",
    re.I,
)
_ATTR_RE = re.compile(
    rb"""\b(?P<name>src|href|data|action|srcset)\s*=\s*["']?(?P<value>[^"'\s>]+)""",
    re.I,
)
#: Inline CSS url() references, which carry mixed content just as well.
_CSS_URL_RE = re.compile(rb"""url\(\s*["']?(http://[^"')\s]+)""", re.I)

#: <link rel> values that actually fetch something. A rel="canonical" or
#: rel="alternate" pointing at http:// is a URL declaration, not a load.
_FETCHING_LINK_RELS = {
    "stylesheet", "preload", "prefetch", "icon", "shortcut icon",
    "apple-touch-icon", "manifest", "preconnect", "modulepreload",
}


def _attrs(blob: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    for match in _ATTR_RE.finditer(blob):
        name = match.group("name").decode("ascii", "ignore").lower()
        out.setdefault(name, match.group("value").decode("utf-8", "ignore"))
    if b"rel" in blob.lower():
        rel = re.search(rb"""\brel\s*=\s*["']?([^"'>]+)""", blob, re.I)
        if rel:
            out["rel"] = rel.group(1).decode("utf-8", "ignore").strip().lower()
    return out


def find_subresources(html: str, base_url: str) -> list[str]:
    """Absolute URLs of everything the markup tells the browser to fetch."""
    body = html.encode("utf-8", "ignore")
    found: list[str] = []
    seen: set[str] = set()

    def keep(raw: str) -> None:
        raw = raw.strip()
        if not raw or raw.startswith(("data:", "about:", "javascript:", "#",
                                      "mailto:", "tel:", "blob:")):
            return
        absolute = urljoin(base_url, raw)
        if absolute not in seen and absolute.startswith(("http://", "https://")):
            seen.add(absolute)
            found.append(absolute)

    for match in _RESOURCE_RE.finditer(body):
        tag = match.group("tag").decode("ascii", "ignore").lower()
        attrs = _attrs(match.group("attrs"))
        if tag == "link":
            rel = attrs.get("rel", "")
            if not any(r in _FETCHING_LINK_RELS for r in rel.split()):
                continue
            if attrs.get("href"):
                keep(attrs["href"])
            continue
        if tag == "form":
            # Handled separately by `insecure_form_actions`. A form action is
            # not a subresource: nothing is fetched until the user submits,
            # and the severity is different in kind, because what leaks is
            # what they typed rather than what the page displayed.
            continue
        for key in ("src", "data"):
            if attrs.get(key):
                keep(attrs[key])
        # srcset is a comma-separated candidate list, each "url descriptor".
        for candidate in attrs.get("srcset", "").split(","):
            part = candidate.strip().split(" ")[0]
            if part:
                keep(part)

    for match in _CSS_URL_RE.finditer(body):
        keep(match.group(1).decode("utf-8", "ignore"))
    return found


def registrable_origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}" if parts.netloc else ""


def third_party_origins(subresources: list[str], page_url: str) -> list[str]:
    """Origins other than the page's own, sorted for a stable report."""
    own = urlsplit(page_url).netloc.lower()
    origins = {
        registrable_origin(u) for u in subresources
        if urlsplit(u).netloc.lower() not in ("", own)
    }
    return sorted(o for o in origins if o)


def insecure_subresources(subresources: list[str], page_url: str) -> list[str]:
    """http:// resources on an https:// page.

    Decided by the PAGE's scheme, not by a global setting. An http:// page
    loading http:// resources is insecure in a different way and is already
    covered by the no-HTTPS rule; reporting it here as well would double-count
    one problem and inflate the finding list.
    """
    if urlsplit(page_url).scheme != "https":
        return []
    return [u for u in subresources if u.startswith("http://")]


def insecure_form_actions(html: str, page_url: str) -> list[str]:
    """Forms on an HTTPS page whose action is an http:// URL.

    Separate from mixed content because the failure is different in kind:
    nothing is fetched until the user submits, and what leaks is what they
    typed rather than what the page displayed. A form with no action submits
    to the current URL, which is https, so absence is not a finding.
    """
    if urlsplit(page_url).scheme != "https":
        return []
    out: list[str] = []
    body = html.encode("utf-8", "ignore")
    for match in _RESOURCE_RE.finditer(body):
        if match.group("tag").decode("ascii", "ignore").lower() != "form":
            continue
        action = _attrs(match.group("attrs")).get("action", "").strip()
        if not action:
            continue
        absolute = urljoin(page_url, action)
        if absolute.startswith("http://") and absolute not in out:
            out.append(absolute)
    return out


class SubresourceCollector:
    """Mixed content, insecure form actions, and third-party origins."""

    name = "subresources"
    scope = Scope.PAGE

    async def collect(self, ctx: PageContext) -> list[Observation]:
        document = ctx.document
        if document is None:
            return []

        page_url = document.final_url or ctx.url
        subresources = find_subresources(document.text, page_url)
        insecure = insecure_subresources(subresources, page_url)
        third_party = third_party_origins(subresources, page_url)
        forms = insecure_form_actions(document.text, page_url)

        out = [
            obs("mixed.insecure_count", len(insecure)),
            # Recorded even when clean, because "checked by parsing the
            # markup" and "checked with a browser" are different claims and
            # the report has to be able to make the right one.
            obs("mixed.method", "html"),
            obs("mixed.insecure_forms", len(forms)),
            obs("thirdparty.origin_count", len(third_party)),
        ]
        if insecure:
            out.append(obs("mixed.insecure_urls", ", ".join(insecure[:10])))
        if forms:
            out.append(obs("mixed.insecure_form_urls", ", ".join(forms[:5])))
        if third_party:
            out.append(obs("thirdparty.origins", ", ".join(third_party[:20])))
        return out
