"""A small multi-page site, served offline, with a nested sitemap index.

Built to exercise the three discovery failure modes that are all silent:

* the root element is ``<sitemapindex>``, so a parser that reads ``<loc>``
  without checking gets a list of sitemaps and audits none of the pages;
* one shard is served gzipped as ``application/gzip``, which httpx does not
  transparently decode, so a naive read yields an empty URL set rather than
  an error;
* more pages exist than any sane cap, so the cap has to be visible.

Page templates differ (home, product, post, checkout) so that template
sampling has something real to group, and the security headers differ per
page so that per-page hygiene has something real to find: ``/checkout``
sets a cookie with no Secure or HttpOnly flag, which is precisely the case
a homepage-only audit never sees.
"""

from __future__ import annotations

import gzip
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

#: url path -> (body class, extra headers)
PAGES: dict[str, tuple[str, dict[str, str]]] = {
    "/": ("home page", {}),
    "/about": ("page page-id-2", {}),
    "/contact": ("page page-template-contact", {}),
    "/blog/first-post": ("single-post single-format-standard", {}),
    "/blog/second-post": ("single-post single-format-standard", {}),
    "/blog/third-post": ("single-post single-format-standard", {}),
    "/shop/widget": ("single-product woocommerce", {}),
    "/shop/gadget": ("single-product woocommerce", {}),
    "/shop/gizmo": ("single-product woocommerce", {}),
    # The page a homepage-only audit never reaches, and the one that matters:
    # a session cookie with neither Secure nor HttpOnly, on the page that
    # takes payment details.
    "/checkout": ("woocommerce-checkout page", {
        "Set-Cookie": "checkout_session=abc123; Path=/",
    }),
}

#: Listed in the sitemap but not an auditable page. Discovery must drop these
#: rather than reporting a missing CSP on a PDF.
ASSETS = ("/brochure.pdf", "/logo.png")

_SHARD_ONE = ("/", "/about", "/contact")
_SHARD_TWO = tuple(p for p in PAGES if p not in _SHARD_ONE)


def _page_html(path: str, body_class: str) -> bytes:
    links = "".join(f'<a href="{p}">{p}</a>' for p in PAGES)
    return (
        f"<!doctype html><html><head><title>{path}</title>"
        f'<meta name="generator" content="WordPress 6.5">'
        "</head>"
        f'<body class="{body_class}">'
        f"<h1>{path}</h1><nav>{links}</nav>"
        # An http:// image on an https:// page is mixed content. Served over
        # http here, so the collector must decide by the page's own scheme.
        '<img src="http://cdn.example.com/a.png">'
        '<script src="https://analytics.example.net/t.js"></script>'
        # A payment form posting over plain http, on the checkout page only.
        # The single most valuable thing a per-page audit can find, and the
        # one a homepage-only audit structurally cannot.
        + ('<form action="http://pay.example.com/charge">'
           '<input name="card"></form>' if path == "/checkout" else "")
        + "</body></html>"
    ).encode()


def _urlset(base: str, paths) -> bytes:
    entries = "".join(f"<url><loc>{base}{p}</loc></url>" for p in paths)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        f"{entries}</urlset>"
    ).encode()


def _sitemap_index(base: str) -> bytes:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        f"<sitemap><loc>{base}/sitemap-1.xml</loc></sitemap>"
        f"<sitemap><loc>{base}/sitemap-2.xml.gz</loc></sitemap>"
        "</sitemapindex>"
    ).encode()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:
        pass

    def _send(self, body: bytes, content_type: str = "text/html",
              extra: dict[str, str] | None = None, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        base = f"http://{self.headers.get('Host', '127.0.0.1')}"
        path = self.path.split("?", 1)[0]

        if path == "/robots.txt":
            self._send(f"User-agent: *\nDisallow: /wp-admin/\n"
                       f"Sitemap: {base}/sitemap_index.xml\n".encode(), "text/plain")
        elif path == "/sitemap_index.xml":
            self._send(_sitemap_index(base), "application/xml")
        elif path == "/sitemap-1.xml":
            self._send(_urlset(base, _SHARD_ONE + ASSETS), "application/xml")
        elif path == "/sitemap-2.xml.gz":
            # Gzipped payload, NOT gzip transfer-encoding. httpx will not
            # decode this one for us, which is the whole point of shipping it.
            self._send(gzip.compress(_urlset(base, _SHARD_TWO)), "application/gzip")
        elif path in PAGES:
            body_class, extra = PAGES[path]
            self._send(_page_html(path, body_class), "text/html", extra)
        elif path in ASSETS:
            self._send(b"%PDF-1.4 not really", "application/pdf")
        else:
            self._send(b"<html><body>not found</body></html>", status=404)

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True


def start(port: int = 0) -> tuple[ThreadingHTTPServer, str]:
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}"
