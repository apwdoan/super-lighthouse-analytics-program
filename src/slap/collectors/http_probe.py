"""HTTP collector: the one request every other Phase 1 collector shares.

Emits the response, caching, compression, cookie-hygiene, security-header,
and redirect-chain observations, and stashes the fetched document on the
context so the fingerprint collector does not re-request the page.

All parsing is done by module-level pure functions so the test suite can
exercise the interesting logic without touching the network.
"""

from __future__ import annotations

import functools
import re
import time
from typing import Any

import httpx

from ..schema import EXPECTED_SECURITY_HEADERS, Observation, Source, obs
from .base import CollectorConfig, FetchedDocument, PageContext

_MAX_AGE_RE = re.compile(r"\bmax-age\s*=\s*(\d+)", re.I)


def http2_available() -> bool:
    """Whether httpx can actually negotiate HTTP/2 in this environment.

    Matters because without the ``h2`` package httpx silently negotiates
    HTTP/1.1 for every site. Reporting "you are on HTTP/1.1" to a client
    who is in fact on HTTP/2 is the kind of confidently wrong finding that
    gets an entire report dismissed, so when h2 is missing we decline to
    report a protocol version at all.
    """
    try:
        import h2  # noqa: F401
    except ImportError:
        return False
    return True


def parse_max_age(cache_control: str | None) -> int | None:
    """Extract ``max-age`` seconds from a Cache-Control header."""
    if not cache_control:
        return None
    m = _MAX_AGE_RE.search(cache_control)
    return int(m.group(1)) if m else None


def parse_hsts_max_age(hsts: str | None) -> int | None:
    if not hsts:
        return None
    m = _MAX_AGE_RE.search(hsts)
    return int(m.group(1)) if m else None


def missing_security_headers(headers: dict[str, str]) -> list[str]:
    """Which of the expected security headers are absent, lowercased."""
    present = {k.lower() for k in headers}
    return [h for h in EXPECTED_SECURITY_HEADERS if h not in present]


def analyze_cookies(set_cookie_headers: list[str]) -> dict[str, int]:
    """Count cookies missing each hardening attribute.

    Only the response's own ``Set-Cookie`` headers are visible here, which
    is the honest scope for a no-browser collector: JavaScript-set cookies
    are Phase 2 territory.
    """
    total = insecure = no_httponly = no_samesite = 0
    for raw in set_cookie_headers:
        if not raw or "=" not in raw.split(";", 1)[0]:
            continue
        total += 1
        attrs = {p.strip().split("=", 1)[0].lower() for p in raw.split(";")[1:]}
        if "secure" not in attrs:
            insecure += 1
        if "httponly" not in attrs:
            no_httponly += 1
        if "samesite" not in attrs:
            no_samesite += 1
    return {
        "total": total,
        "insecure": insecure,
        "no_httponly": no_httponly,
        "no_samesite": no_samesite,
    }


def build_redirect_chain(response: httpx.Response) -> list[tuple[int, str]]:
    """``[(status, url), ...]`` for every hop, final response included."""
    chain = [(r.status_code, str(r.url)) for r in response.history]
    chain.append((response.status_code, str(response.url)))
    return chain


def upgrades_to_https(chain: list[tuple[int, str]]) -> bool | None:
    """True if the chain starts on http:// and ends on https://.

    Returns None when the request already started on HTTPS, because then
    the question does not apply and a False would read as a failure.
    """
    if not chain:
        return None
    if not chain[0][1].startswith("http://"):
        return None
    return chain[-1][1].startswith("https://")


def normalize_url(url: str) -> str:
    """Accept bare hostnames from a pasted list; default to https."""
    url = url.strip()
    if not url:
        raise ValueError("empty URL")
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    return url


@functools.lru_cache(maxsize=1)
def accept_encoding() -> str:
    """Only ever advertise encodings this process can actually decode.

    The header used to be the literal ``"gzip, deflate, br"``, and the first
    real-site audit showed what that costs: wordpress.org answered the ``br``
    with brotli, no brotli decoder was installed, and httpx quietly fell back
    to identity, handing every HTML-reading collector 28KB of raw compressed
    bytes. Zero components detected on a WordPress site, no error anywhere,
    and the fixtures never notice because they serve gzip, which the
    standard library always decodes.

    The decoders are declared as hard dependencies now (`httpx[brotli,zstd]`,
    same reasoning as the h2 extra), so normally everything below is
    importable. Probing anyway means a stripped-down install degrades to
    asking for gzip rather than to analysing bytes that only look like a
    page.
    """
    encodings = ["gzip", "deflate"]        # stdlib zlib; always decodable
    try:
        import brotli  # noqa: F401
        encodings.append("br")
    except ImportError:
        try:
            import brotlicffi  # noqa: F401
            encodings.append("br")
        except ImportError:
            pass
    try:
        import zstandard  # noqa: F401
        encodings.append("zstd")
    except ImportError:
        pass
    return ", ".join(encodings)


async def fetch(ctx: PageContext) -> FetchedDocument:
    """Fetch ``ctx.url``, following redirects, and record timing."""
    cfg: CollectorConfig = ctx.config
    request = ctx.client.build_request(
        "GET", ctx.url,
        headers={
            "User-Agent": cfg.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Encoding": accept_encoding(),
            "Accept-Language": "en-US,en;q=0.9",
        },
    )
    started = time.perf_counter()
    response = await ctx.client.send(request, stream=True, follow_redirects=True)
    ttfb_ms = (time.perf_counter() - started) * 1000.0
    try:
        body = b""
        async for chunk in response.aiter_bytes():
            body += chunk
            if len(body) >= cfg.max_body_bytes:
                break
    finally:
        await response.aclose()

    try:
        text = body.decode(response.encoding or "utf-8", errors="replace")
    except (LookupError, TypeError):
        text = body.decode("utf-8", errors="replace")

    return FetchedDocument(
        url=ctx.url,
        final_url=str(response.url),
        status=response.status_code,
        http_version=response.http_version,
        headers={k.lower(): v for k, v in response.headers.items()},
        set_cookie=list(response.headers.get_list("set-cookie")),
        text=text,
        content_bytes=len(body),
        ttfb_ms=ttfb_ms,
        redirect_chain=build_redirect_chain(response),
    )


def observations_from_document(doc: FetchedDocument) -> list[Observation]:
    """Pure: turn a fetched document into observations. Network-free."""
    out: list[Observation] = []
    h = doc.headers

    def add(key: str, value: Any) -> None:
        if value is not None and value != "":
            out.append(obs(key, value))

    # Response basics
    add("http.status", doc.status)
    if http2_available():
        add("http.version", doc.http_version)
    add("http.ttfb", round(doc.ttfb_ms, 1))
    add("http.content_bytes", doc.content_bytes)
    add("http.server", h.get("server"))

    encoding = h.get("content-encoding")
    add("http.compression", encoding or "none")
    add("http.compressed", bool(encoding))

    cache_control = h.get("cache-control")
    add("http.cache_control", cache_control)
    add("http.cache_max_age", parse_max_age(cache_control))
    add("http.has_etag", "etag" in h)

    # Security headers
    add("sec.hsts", h.get("strict-transport-security"))
    add("sec.hsts_max_age", parse_hsts_max_age(h.get("strict-transport-security")))
    add("sec.csp", h.get("content-security-policy"))
    add("sec.x_content_type_options", h.get("x-content-type-options"))
    add("sec.x_frame_options", h.get("x-frame-options"))
    add("sec.referrer_policy", h.get("referrer-policy"))
    add("sec.permissions_policy", h.get("permissions-policy"))
    add("sec.missing_header_count", len(missing_security_headers(h)))

    # Cookie hygiene
    cookies = analyze_cookies(doc.set_cookie)
    add("sec.cookies_total", cookies["total"])
    if cookies["total"]:
        add("sec.cookies_insecure", cookies["insecure"])
        add("sec.cookies_no_httponly", cookies["no_httponly"])
        add("sec.cookies_no_samesite", cookies["no_samesite"])

    # Redirects
    hops = max(0, len(doc.redirect_chain) - 1)
    out.append(Observation(Source.REDIRECT, "redirect.hops", numeric_value=float(hops)))
    if doc.redirect_chain:
        chain_text = " -> ".join(f"{status} {url}" for status, url in doc.redirect_chain)
        out.append(Observation(Source.REDIRECT, "redirect.chain", text_value=chain_text))
    out.append(Observation(Source.REDIRECT, "redirect.final_url", text_value=doc.final_url))
    upgraded = upgrades_to_https(doc.redirect_chain)
    if upgraded is not None:
        out.append(Observation(Source.REDIRECT, "redirect.upgrades_to_https",
                               numeric_value=float(upgraded)))
    return out


class HttpCollector:
    """Fetches the page and emits HTTP, security, and redirect observations."""

    name = "http"

    async def collect(self, ctx: PageContext) -> list[Observation]:
        doc = await fetch(ctx)
        ctx.document = doc  # shared with the fingerprint collector
        return observations_from_document(doc)
