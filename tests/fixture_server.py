"""A deliberately slow local site, served with deliberately bad headers.

Phase 2's whole risk is that Lighthouse 13 renamed the opportunity audits
and moved the savings API, so an extractor written from memory silently
finds nothing. A clean page cannot catch that: every saving is zero and the
extractor looks fine. This fixture is a page bad enough that the insights
actually fire, served offline so the test suite stays deterministic.

Used by ``tests/test_lighthouse.py`` and importable as a script:

    python -m tests.fixture_server 8899
"""

from __future__ import annotations

import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "slowsite"


class BadHeaderHandler(SimpleHTTPRequestHandler):
    """Serves the fixture with no compression and no caching.

    Both are deliberate: they are what make ``cache-insight`` and the
    document-latency insight fire.
    """

    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Server", "FixtureServer/1.0")
        self.send_header("Set-Cookie", "fixture_session=abc123; Path=/")
        super().end_headers()

    def log_message(self, *args) -> None:  # keep test output readable
        pass

    def handle_one_request(self):
        # Lighthouse aborts in-flight requests when it finishes a page load,
        # which raises BrokenPipeError here and floods the test output with
        # tracebacks for something entirely expected.
        try:
            super().handle_one_request()
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True


def start(port: int = 0) -> tuple[ThreadingHTTPServer, str]:
    """Start the fixture server on ``port`` (0 picks a free one)."""
    handler = partial(BadHeaderHandler, directory=str(FIXTURE_DIR))
    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}"


if __name__ == "__main__":
    import sys
    import time

    httpd, base = start(int(sys.argv[1]) if len(sys.argv) > 1 else 8899)
    print(f"serving {FIXTURE_DIR} at {base}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        httpd.shutdown()
