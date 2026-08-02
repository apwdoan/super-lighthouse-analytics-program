"""Offline fixtures built to make CVE matching and probing produce FALSE
positives, so the tests can prove they do not.

Three modes, because the three ways this feature fails in the wild are
different and only one of them is "a real file is exposed".

``normal``
    A WordPress-shaped site that genuinely exposes ``/.git/config``, ``/.env``
    and a database dump, and runs a jQuery with real CVEs against it. The
    positive control: if the tool finds nothing here, it is broken.

``soft404``
    Returns **200 with the homepage** for every unknown path. Enormously
    common (any SPA with a catch-all route, plenty of misconfigured
    WordPress). Status codes alone would report every probed path as a
    critical finding. The tool must find nothing.

``waf``
    Returns **200 with a Cloudflare-style block page** for everything,
    including the control request. The tool must notice and stop rather than
    report fifteen identical criticals.

The `?ver=` traps in the markup are the other half. Three of the four asset
versions on the page are *not* the component's version, which is the normal
case on a real WordPress site, not an edge case.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

#: jQuery 3.4.1 has two real advisories in OSV (CVE-2020-11022, -11023) and
#: is old enough that nobody will quietly patch it out from under the test.
JQUERY_VERSION = "3.4.1"
WP_CORE_VERSION = "6.5.2"

#: Paths this fixture genuinely exposes, with content that matches the
#: signature the prober looks for. Anything not listed here must NOT be
#: reported, whatever status the mode returns.
EXPOSED: dict[str, tuple[str, str]] = {
    "/.git/config": ("text/plain",
                     "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"),
    "/.env": ("text/plain",
              "APP_ENV=production\nAPP_KEY=base64:abcd\nDB_PASSWORD=hunter2\n"),
    "/backup.sql": ("application/sql",
                    "-- MySQL dump 10.13\nCREATE TABLE wp_users (\n"),
}

_BLOCK_PAGE = (
    "<!doctype html><html><head><title>Attention Required! | Cloudflare</title>"
    "</head><body><h1>Access denied</h1><p>Ray ID: 8a1f2c3d4e5f</p>"
    "<p>The owner of this website has banned your access.</p></body></html>"
)


def _home_html() -> str:
    return f"""<!doctype html><html><head>
<meta name="generator" content="WordPress {WP_CORE_VERSION}">
<title>Vulnerable fixture</title>
<script src="/jquery.min.js?ver={WP_CORE_VERSION}"></script>

<!-- A real plugin version. This one SHOULD be inferred. -->
<script src="/wp-content/plugins/contact-form-7/includes/js/index.js?ver=5.8.1"></script>

<!-- The WordPress core version, substituted by WordPress for any asset that
     does not set its own. Treating this as the plugin's version means
     matching every plugin on the site against core's number. -->
<script src="/wp-content/plugins/akismet/_inc/akismet.js?ver={WP_CORE_VERSION}"></script>

<!-- A cache-buster timestamp. Extremely common; parses as an integer and
     must not be read as a version. -->
<script src="/wp-content/plugins/wp-rocket/assets/js/x.js?ver=1699887600"></script>

<!-- A content hash, which is what most build pipelines emit. -->
<link rel="stylesheet" href="/wp-content/themes/astra/style.css?ver=a3f9c2e1">
</head><body class="home page">
<h1>Fixture</h1>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    mode = "normal"

    def log_message(self, *args) -> None:
        pass

    def _send(self, body: bytes, content_type: str = "text/html",
              status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        mode = type(self).mode

        if mode == "waf":
            # Everything, including the control request, gets the block page.
            self._send(_BLOCK_PAGE.encode())
            return

        if path in ("/", "/index.html"):
            self._send(_home_html().encode())
            return
        if path == "/jquery.min.js":
            # The detector runs IN THE BROWSER and reads `jQuery.fn.jquery`
            # off the live object, so a file containing only a version comment
            # detects as nothing. This is the smallest thing that is actually
            # jQuery as far as the detector is concerned, which is the point:
            # the observed-version path has to be exercised by something the
            # browser really executes, not by markup that looks right.
            self._send(
                (f'window.jQuery = window.$ = '
                 f'{{ fn: {{ jquery: "{JQUERY_VERSION}" }} }};\n').encode(),
                "application/javascript")
            return
        if path.startswith("/wp-content/"):
            self._send(b"// asset", "application/javascript")
            return

        if mode == "normal" and path in EXPOSED:
            content_type, body = EXPOSED[path]
            self._send(body.encode(), content_type)
            return

        if mode == "soft404":
            # 200 and the homepage for everything, which is what makes status
            # codes useless and content checks mandatory.
            self._send(_home_html().encode())
            return

        self._send(b"<html><body><h1>Not found</h1></body></html>", status=404)

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True


def start(mode: str = "normal", port: int = 0) -> tuple[ThreadingHTTPServer, str]:
    handler = type(f"Handler_{mode}", (Handler,), {"mode": mode})
    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}"
