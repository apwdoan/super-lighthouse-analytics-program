"""Generate a database with REAL audit history, for looking at the web UI.

Not fixtures and not fabricated rows: this runs the actual pipeline, actual
Lighthouse, against pages served locally. The point of Site detail is a trend
and an open-versus-fixed split, and neither is worth judging on invented
numbers.

Three loopback addresses give three distinct hostnames (`core._persist` keys a
site on `httpx.URL(url).host`, so 127.0.0.1 on three ports would collapse into
one site). Each is served a page that gets progressively less awful across
runs, which is what produces a rising line and findings that genuinely stop
firing.

    python design/seed_demo.py --db /tmp/demo.sqlite3
"""

from __future__ import annotations

import argparse
import http.server
import shutil
import socketserver
import threading
from pathlib import Path

from slap import core
from slap.config import Settings

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "slowsite"

# Each stage removes one real problem, so the improvement Lighthouse measures
# is caused by the change rather than by run-to-run noise.
STAGES = [
    {"name": "as-shipped", "compress": False, "defer": False, "cache": False},
    {"name": "caching on", "compress": False, "defer": False, "cache": True},
    {"name": "compression on", "compress": True, "defer": False, "cache": True},
    {"name": "css deferred", "compress": True, "defer": True, "cache": True},
    # The last stage must retire RULES, not just improve a number, or the
    # open-versus-fixed split has nothing to show between the final two runs.
    {"name": "security headers", "compress": True, "defer": True, "cache": True,
     "secure": True},
]

SITES = [
    {"host": "127.0.0.1", "port": 8901, "stages": [0, 1, 2, 3, 4]},
    {"host": "127.0.0.2", "port": 8902, "stages": [0, 1]},
    {"host": "127.0.0.3", "port": 8903, "stages": [0]},
]


class Handler(http.server.SimpleHTTPRequestHandler):
    stage = STAGES[0]
    root = str(FIXTURE)

    def __init__(self, *a, **kw):
        super().__init__(*a, directory=type(self).root, **kw)

    def end_headers(self):
        stage = type(self).stage
        if stage["cache"]:
            self.send_header("Cache-Control", "public, max-age=31536000")
        else:
            self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if stage.get("secure"):
            self.send_header("Strict-Transport-Security", "max-age=63072000")
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
        super().end_headers()

    def log_message(self, *a):  # silence
        pass


def serve(port: int) -> socketserver.TCPServer:
    socketserver.TCPServer.allow_reuse_address = True
    server = socketserver.TCPServer(("", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def variant(stage: dict) -> Path:
    """A copy of the fixture with the stage's fixes actually applied."""
    out = Path("/tmp/slap-demo") / stage["name"].replace(" ", "-")
    if out.exists():
        shutil.rmtree(out)
    shutil.copytree(FIXTURE, out)
    if stage["defer"]:
        html = (out / "index.html").read_text(encoding="utf-8")
        html = html.replace('rel="stylesheet"', 'rel="stylesheet" media="print" '
                                                'onload="this.media=\'all\'"')
        (out / "index.html").write_text(html, encoding="utf-8")
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="/tmp/demo.sqlite3")
    parser.add_argument("--lighthouse", action="store_true", default=True)
    parser.add_argument("--no-lighthouse", dest="lighthouse", action="store_false")
    args = parser.parse_args()

    settings = Settings()
    settings.db_path = Path(args.db)
    settings.artifact_dir = Path("/tmp/slap-demo/artifacts")
    settings.report_dir = Path("/tmp/slap-demo/reports")
    settings.lighthouse.enabled = args.lighthouse
    settings.lighthouse.runs = 1          # 1, not 3: this is a demo, not a measurement
    settings.ensure_dirs()

    servers = {s["port"]: serve(s["port"]) for s in SITES}
    try:
        for step in range(len(STAGES)):
            for site in SITES:
                if step not in site["stages"]:
                    continue
                stage = STAGES[step]
                Handler.stage = stage
                Handler.root = str(variant(stage))
                url = f"http://{site['host']}:{site['port']}/index.html"
                print(f"  {site['host']}  stage {step} ({stage['name']}) ...", flush=True)
                worker = core.BatchWorker([url], settings).start()
                worker.wait(300)
    finally:
        for server in servers.values():
            server.shutdown()

    sites = core.list_sites(settings)
    print(f"\n{len(sites)} sites:")
    for s in sites:
        detail = core.get_site_detail(settings, s["id"])
        scores = [h.get("lh.score.performance") for h in detail["history"]]
        print(f"  {s['hostname']:<12} runs={s['run_count']} "
              f"open={s['finding_count']} fixed={len(detail['fixed'])} "
              f"scores={[round(x) if x else None for x in scores]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
