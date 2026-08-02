"""Phase 2: the Lighthouse runner.

Python owns everything except the browser. This module launches the Node
worker in :mod:`slap.node_worker` as a subprocess, takes the median of N
runs, extracts observations from the raw LHR, and writes the LHR to disk
gzipped for forensics.

Three things here are load-bearing rather than incidental:

* **Lighthouse concurrency is a separate setting from HTTP concurrency.**
  ``LighthouseConfig.concurrency`` defaults to 3 and is gated by its own
  semaphore. Running Lighthouse as wide as the network collectors is the
  single biggest batch-auditing mistake: contended CPU inflates TBT and TTI
  and produces plausible, irreproducible scores.
* **Median of N, and the spread is recorded.** A single Lighthouse run is
  noise. The median goes in the report and the spread goes in beside it, so
  a wide spread is visible rather than hidden.
* **``benchmarkIndex`` is captured on every run.** It is Lighthouse's own
  measure of how fast the measuring machine was. If it sags across a batch,
  that is direct evidence of the contention above.

``asyncio.create_subprocess_exec``, not Qt's ``QProcess``: the subprocess
belongs to the core and the core does not import Qt.
"""

from __future__ import annotations

import asyncio
import gzip
import hashlib
import json
import shutil
import statistics
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

from .. import bundle
from ..schema import (
    LIGHTHOUSE_OPPORTUNITIES,
    Observation,
    Source,
    obs,
)
from .base import PageContext

WORKER_DIR = Path(__file__).resolve().parent.parent / "node_worker"
WORKER_SCRIPT = WORKER_DIR / "worker.js"

DEFAULT_CATEGORIES = ("performance", "accessibility", "best-practices", "seo")

#: Lighthouse category id -> our metric key.
CATEGORY_KEYS = {
    "performance": "lh.score.performance",
    "accessibility": "lh.score.accessibility",
    "best-practices": "lh.score.best_practices",
    "seo": "lh.score.seo",
}

#: Lighthouse audit id -> our metric key, for straight numeric measurements.
METRIC_AUDITS = {
    "largest-contentful-paint": "lh.lcp",
    "first-contentful-paint": "lh.fcp",
    "total-blocking-time": "lh.tbt",
    "cumulative-layout-shift": "lh.cls",
    "speed-index": "lh.speed_index",
    "interactive": "lh.tti",
    "server-response-time": "lh.server_response",
    "total-byte-weight": "lh.total_bytes",
    "bootup-time": "lh.bootup_time",
    "mainthread-work-breakdown": "lh.mainthread_work",
    "dom-size-insight": "lh.dom_elements",
}

#: Metrics whose run-to-run spread is worth recording.
SPREAD_KEYS = {
    "lh.lcp": "lh.lcp.spread",
    "lh.tbt": "lh.tbt.spread",
    "lh.score.performance": "lh.score.performance.spread",
    "lh.benchmark_index": "lh.benchmark_index.spread",
}


class LighthouseError(RuntimeError):
    """The Lighthouse worker could not run, or the run failed."""


@dataclass(slots=True)
class LighthouseConfig:
    #: Off by default. Phase 1 batches take seconds per site; enabling this
    #: takes them to roughly 90 seconds per site, so it is an explicit choice.
    enabled: bool = False
    runs: int = 3
    form_factors: tuple[str, ...] = ("mobile",)
    categories: tuple[str, ...] = DEFAULT_CATEGORIES
    #: NOT http_concurrency. See the module docstring.
    concurrency: int = 3
    timeout: float = 150.0
    node_path: str = "node"
    worker_path: Path | None = None
    chrome_path: str | None = None
    keep_artifacts: bool = True


@dataclass(slots=True)
class RunEnvelope:
    """One Lighthouse run's result, as returned by the Node worker."""

    ok: bool
    lhr: dict[str, Any] | None = None
    meta: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    code: str | None = None


@dataclass(slots=True)
class ArtifactRecord:
    kind: str
    path: Path
    sha256: str
    bytes: int


@dataclass(slots=True)
class LighthouseResult:
    observations: list[Observation] = field(default_factory=list)
    artifacts: list[ArtifactRecord] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    runs_attempted: int = 0
    runs_succeeded: int = 0
    #: Libraries the browser identified in the running page, as
    #: ``[{"name", "version", "npm"}]``. Extracted here rather than kept as a
    #: reference to the whole LHR: the report only needs a handful of names,
    #: and holding a ~4MB blob per page across a batch with twenty pages of
    #: twenty sites in flight is real memory for no reason. The full LHR is
    #: on disk if anyone needs to re-derive more.
    libraries: list[dict[str, Any]] = field(default_factory=list)


# --------------------------------------------------------------------------
# Pure extraction. Tested against recorded LHR fixtures, no browser needed.
# --------------------------------------------------------------------------

def _audit_savings(audit: dict[str, Any], audit_id: str) -> float | None:
    """Estimated milliseconds saved by fixing this audit.

    Lighthouse 13's insight audits report savings as
    ``metricSavings: {FCP: n, LCP: n, INP: n}``; the classic diagnostic
    audits still use ``details.overallSavingsMs`` or a millisecond
    ``numericValue``. Reading the wrong one yields None everywhere and rules
    that never fire.
    """
    savings = audit.get("metricSavings") or {}
    values = [v for v in savings.values() if isinstance(v, (int, float))]
    if values:
        return float(max(values))

    if audit_id.endswith("-insight"):
        # An insight with no metricSavings has nothing to offer. Do NOT fall
        # back to numericValue: for dom-size-insight that is an element
        # count, and reporting "9000ms saving" would be nonsense.
        return None

    details = audit.get("details") or {}
    overall = details.get("overallSavingsMs")
    if isinstance(overall, (int, float)):
        return float(overall)
    if audit.get("numericUnit") == "millisecond":
        value = audit.get("numericValue")
        if isinstance(value, (int, float)):
            return float(value)
    return None


def extract_values(lhr: dict[str, Any]) -> dict[str, float]:
    """Pure: one LHR to ``{metric_key: numeric_value}``.

    Opportunities are emitted only when the saving is positive, so a rule
    firing on ``gt: 0`` means a genuine, quantified saving rather than an
    audit that merely ran.
    """
    values: dict[str, float] = {}
    audits = lhr.get("audits") or {}

    for category_id, key in CATEGORY_KEYS.items():
        category = (lhr.get("categories") or {}).get(category_id)
        if category and isinstance(category.get("score"), (int, float)):
            values[key] = round(category["score"] * 100)

    for audit_id, key in METRIC_AUDITS.items():
        audit = audits.get(audit_id)
        if not audit:
            continue
        value = audit.get("numericValue")
        if isinstance(value, (int, float)):
            values[key] = float(value)

    for audit_id, (suffix, _label) in LIGHTHOUSE_OPPORTUNITIES.items():
        audit = audits.get(audit_id)
        if not audit:
            continue
        saving = _audit_savings(audit, audit_id)
        if saving is not None and saving > 0:
            values[f"lh.opp.{suffix}"] = round(saving, 1)

    benchmark = (lhr.get("environment") or {}).get("benchmarkIndex")
    if isinstance(benchmark, (int, float)):
        values["lh.benchmark_index"] = round(float(benchmark), 1)

    return values


def aggregate(runs: Sequence[dict[str, float]], *,
              meta: dict[str, Any] | None = None) -> list[Observation]:
    """Median across runs, plus the spread for the metrics that matter.

    The median is what goes in the report; the spread is what stops the
    report from being quietly wrong. A metric present in only some runs is
    aggregated over the runs that have it rather than treated as zero.
    """
    if not runs:
        return []

    keys: set[str] = set()
    for run in runs:
        keys.update(run)

    out: list[Observation] = []
    for key in sorted(keys):
        present = [run[key] for run in runs if key in run]
        if not present:
            continue
        median = statistics.median(present)
        # Scores and element counts are integers; don't render 91.5.
        if key.startswith("lh.score.") or key == "lh.dom_elements":
            median = round(median)
        else:
            median = round(median, 1)
        out.append(obs(key, median))

        spread_key = SPREAD_KEYS.get(key)
        if spread_key and len(present) > 1:
            out.append(obs(spread_key, round(max(present) - min(present), 1)))

    out.append(obs("lh.runs", len(runs)))
    meta = meta or {}
    if meta.get("throttlingProfile"):
        out.append(obs("lh.throttling_profile", meta["throttlingProfile"]))
    if meta.get("formFactor"):
        out.append(obs("lh.form_factor", meta["formFactor"]))
    return out


# --------------------------------------------------------------------------
# Running the worker
# --------------------------------------------------------------------------

def _playwright_browsers_dir() -> Path | None:
    import os

    if env := os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
        path = Path(env)
        return path if path.is_dir() else None
    for candidate in (
        Path.home() / ".cache" / "ms-playwright",                      # Linux
        Path.home() / "Library" / "Caches" / "ms-playwright",          # macOS
        Path(os.environ.get("LOCALAPPDATA", "")) / "ms-playwright",    # Windows
    ):
        if candidate.is_dir():
            return candidate
    return None


def _scan_for_chromium() -> str | None:
    """Find Playwright's Chromium on disk, without starting its driver.

    Delegates the layout knowledge to :mod:`slap.bundle` rather than keeping
    a second copy. The two lists were duplicated and drifted out of date
    together when Playwright renamed the directories, which is the usual
    fate of a table written down twice.
    """
    root = _playwright_browsers_dir()
    if root is None:
        return None
    found = bundle.find_chromium_under(root)
    return str(found) if found is not None else None


def parse_envelope(stdout: bytes) -> dict[str, Any] | None:
    """The worker's JSON envelope from its stdout, or None if there isn't one.

    Tolerant of stray output on the same stream. The worker's contract is
    "one JSON object on stdout", and it holds when the only thing writing
    there is the worker. It is not guaranteed: a Windows CI build produced
    stdout that was non-empty and not JSON, with nothing at all on stderr,
    which under the old whole-buffer parse surfaced as

        probe returned unparseable output:

    and no way to tell whether the worker had run. Scanning for the
    envelope line means a Node warning or a launcher banner degrades to a
    working audit instead of a dead one. Anything unparseable still returns
    None, and the caller prints the raw streams.
    """
    if not stdout.strip():
        return None
    text = stdout.decode("utf-8", errors="replace")

    # FIRST envelope wins, and objects are decoded one at a time rather than
    # by lines. The worker emitted two, concatenated with no separator:
    #
    #   {"ok":true,"meta":{...}}{"ok":false,"code":"worker_crashed",...}
    #
    # A completed probe followed by a temp-directory cleanup failure. Line
    # splitting cannot separate those, and taking the last one would prefer
    # the cleanup crash over the result it came after. The worker no longer
    # emits a second envelope, but a client that trusts the worker to be
    # well-behaved is how this went unnoticed the first time.
    decoder = json.JSONDecoder()
    index = 0
    while True:
        start = text.find("{", index)
        if start == -1:
            return None
        try:
            loaded, index = decoder.raw_decode(text, start)
        except ValueError:
            index = start + 1
            continue
        if isinstance(loaded, dict) and "ok" in loaded:
            return loaded


def default_chrome_path() -> str | None:
    """Playwright's pinned Chromium, so every teammate measures identically.

    Reuses the browser already installed for PDF export.

    **Do not call this from inside a running event loop**: it may reach for
    Playwright's *sync* API, which raises there. :meth:`LighthouseRunner`
    resolves it through ``asyncio.to_thread`` for exactly that reason. This
    is the same trap as the sync PDF wrapper, and it fails at probe time
    with a message about CHROME_PATH that does not obviously point back
    here, which is why it is called out.
    """
    import os

    if env := os.environ.get("CHROME_PATH"):
        if Path(env).exists():
            return env

    # A frozen bundle ships its own; never reach for the user's Chrome.
    if bundled := bundle.bundled_chromium():
        return str(bundled)

    # Filesystem scan first: it is cheap, has no loop constraint, and is
    # what makes this safe to call from either context.
    if scanned := _scan_for_chromium():
        return scanned

    try:
        import asyncio as _asyncio

        _asyncio.get_running_loop()
    except RuntimeError:
        pass  # no loop, the sync API is safe
    else:
        return None

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None
    try:
        with sync_playwright() as p:
            path = p.chromium.executable_path
    except Exception:  # noqa: BLE001 - best effort
        return None
    return path if path and Path(path).exists() else None


class LighthouseRunner:
    """Owns the Node subprocess and the Lighthouse concurrency cap."""

    def __init__(self, config: LighthouseConfig, *,
                 artifact_dir: Path | None = None) -> None:
        self.config = config
        self.artifact_dir = Path(artifact_dir) if artifact_dir else None
        self._semaphore = asyncio.Semaphore(max(1, config.concurrency))
        self._chrome_path = config.chrome_path
        self._probed: dict[str, Any] | None = None

    # -- setup / diagnostics ------------------------------------------------

    @property
    def worker_script(self) -> Path:
        if self.config.worker_path:
            return Path(self.config.worker_path)
        # A frozen bundle ships the worker beside the executable, not inside
        # the Python package, because node_modules is ~12,000 files.
        bundled = bundle.bundled_worker()
        return bundled if bundled is not None else WORKER_SCRIPT

    @property
    def node_executable(self) -> str:
        """Bundled Node if present, otherwise whatever config says."""
        if self.config.node_path != "node":
            return self.config.node_path      # explicit override wins
        bundled = bundle.bundled_node()
        return str(bundled) if bundled is not None else self.config.node_path

    def check(self) -> tuple[bool, str]:
        """Is the worker runnable? Returns (ok, human-readable detail)."""
        if not self.worker_script.exists():
            return False, f"worker script missing at {self.worker_script}"
        node = self.node_executable
        if not (Path(node).exists() or shutil.which(node)):
            if not bundle.is_frozen():
                return False, f"'{node}' not found. Lighthouse 13 needs Node >= 22.19."
            # Frozen and still falling back to a bare name means
            # bundle.bundled_node() found nothing, which is a different
            # fault from "the path it found is gone". Saying "bundled Node
            # missing at node" described neither.
            if bundle.bundled_node() is None:
                return False, (
                    "no Node in the bundle. Expected Playwright's driver "
                    f"node under {bundle.bundle_root()}, or runtime/node/. "
                    "The distributable is incomplete."
                )
            return False, (
                f"bundled Node missing at {node}. The distributable is incomplete."
            )
        modules = self.worker_script.parent / "node_modules" / "lighthouse"
        if not modules.exists():
            # NOT `npm install --prefix <dir>`: on Windows npm ignores the
            # prefix and reads the current directory's package.json
            # (npm/cli#7722). Telling someone to run a command that fails on
            # their platform is worse than saying nothing.
            return False, (
                "Lighthouse is not installed. Run:\n"
                f"    cd {self.worker_script.parent}\n"
                "    npm install"
            )
        return True, f"worker at {self.worker_script}"

    async def _env(self) -> dict[str, str]:
        import os

        env = dict(os.environ)
        if self._chrome_path is None:
            # Off-thread because default_chrome_path may touch Playwright's
            # sync API, which raises inside a running loop.
            self._chrome_path = await asyncio.to_thread(default_chrome_path)
        if self._chrome_path:
            env["CHROME_PATH"] = self._chrome_path
        return env

    async def _spawn(self, argv: list[str], payload: bytes | None,
                     timeout: float) -> tuple[int, bytes, bytes]:
        process = await asyncio.create_subprocess_exec(
            self.node_executable, str(self.worker_script), *argv,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(self.worker_script.parent),
            env=await self._env(),
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(payload), timeout=timeout
            )
        except asyncio.TimeoutError:
            # Lighthouse can wedge on a page that never settles. Kill the
            # process group rather than leaking a Chrome for the rest of the
            # batch; a leaked Chrome is itself a source of CPU contention.
            process.kill()
            await process.wait()
            raise LighthouseError(f"timed out after {timeout:.0f}s") from None
        return process.returncode or 0, stdout, stderr

    def _probe_failure(self, code: int, stdout: bytes, stderr: bytes) -> str:
        """Everything needed to diagnose a dead worker, in one message.

        The previous version printed only stderr. When the worker died
        producing NO output on either stream, which is what a Windows CI
        build did, the entire error read:

            probe returned unparseable output:

        That is worse than useless: it says something failed and withholds
        every fact about it. An empty stream is itself a finding, so say so
        rather than interpolating nothing, and name the exact node, script
        and browser that were used, because on a frozen bundle those are
        resolved by three different lookups any of which can miss.
        """
        def stream(name: str, raw: bytes) -> str:
            text = raw.decode(errors="replace").strip()
            return f"  {name}: {text[:600]}" if text else f"  {name}: (empty)"

        return "\n".join([
            f"probe failed with exit code {code}.",
            stream("stdout", stdout),
            stream("stderr", stderr),
            f"  node: {self.node_executable}",
            f"  worker: {self.worker_script}",
            f"  CHROME_PATH: {self._chrome_path or '(unresolved)'}",
            f"  frozen: {bundle.is_frozen()}",
        ])

    async def probe(self) -> dict[str, Any]:
        """Lighthouse, Chrome, and Node versions. Cached per runner."""
        if self._probed is not None:
            return self._probed
        ok, detail = self.check()
        if not ok:
            raise LighthouseError(detail)
        code, stdout, stderr = await self._spawn(["--probe"], None, 60.0)
        envelope = parse_envelope(stdout)
        if envelope is None:
            # `json.loads(stdout or b"{}")` used to turn EMPTY output into a
            # valid empty envelope, which then failed the `ok` check below
            # and reported the bare string "probe failed". A worker that
            # died without printing anything is the single most useful
            # thing to describe in detail, and it was the one case that
            # described nothing.
            raise LighthouseError(self._probe_failure(code, stdout, stderr))
        if not envelope.get("ok"):
            detail = envelope.get("error")
            raise LighthouseError(
                f"{envelope.get('code', 'probe failed')}: {detail}" if detail
                else self._probe_failure(code, stdout, stderr)
            )
        self._probed = envelope.get("meta", {})
        return self._probed

    # -- running ------------------------------------------------------------

    async def run_once(self, url: str, form_factor: str = "mobile") -> RunEnvelope:
        job = json.dumps({
            "url": url,
            "formFactor": form_factor,
            "categories": list(self.config.categories),
        }).encode()

        async with self._semaphore:
            try:
                code, stdout, stderr = await self._spawn([], job, self.config.timeout)
            except LighthouseError as exc:
                return RunEnvelope(ok=False, error=str(exc), code="timeout")

        if not stdout:
            tail = stderr.decode(errors="replace").strip()[-400:]
            return RunEnvelope(
                ok=False, code="no_output",
                error=f"worker exited {code} with no output. {tail}",
            )
        # Same tolerant parse as the probe. An audit is 90 seconds of work;
        # throwing it away because something else wrote a line to stdout is
        # an expensive way to be strict.
        payload = parse_envelope(stdout)
        if payload is None:
            return RunEnvelope(
                ok=False, code="bad_output",
                error=(f"worker output was not JSON: {stdout[:300]!r} "
                       f"(exit {code}, stderr: "
                       f"{stderr.decode(errors='replace').strip()[-300:] or 'empty'})"),
            )
        return RunEnvelope(
            ok=bool(payload.get("ok")),
            lhr=payload.get("lhr"),
            meta=payload.get("meta") or {},
            error=payload.get("error"),
            code=payload.get("code"),
        )

    def _write_artifact(self, lhr: dict[str, Any], *, hostname: str,
                        form_factor: str, index: int) -> ArtifactRecord | None:
        """Gzip the raw LHR to disk. Never parse it twice; keep it for forensics."""
        if not self.config.keep_artifacts or self.artifact_dir is None:
            return None
        from ..report.render import safe_filename

        directory = Path(self.artifact_dir)
        directory.mkdir(parents=True, exist_ok=True)
        name = f"{safe_filename(hostname)}-{form_factor}-{index}.lhr.json.gz"
        path = directory / name
        blob = json.dumps(lhr, separators=(",", ":")).encode()
        path.write_bytes(gzip.compress(blob, compresslevel=6))
        return ArtifactRecord(
            kind="lhr",
            path=path,
            sha256=hashlib.sha256(blob).hexdigest(),
            bytes=path.stat().st_size,
        )

    async def audit(self, url: str, *, hostname: str,
                    form_factor: str = "mobile",
                    on_run: Any = None) -> LighthouseResult:
        """Run Lighthouse ``config.runs`` times and aggregate the median."""
        result = LighthouseResult()
        extracts: list[dict[str, float]] = []
        last_meta: dict[str, Any] = {}

        for index in range(1, self.config.runs + 1):
            result.runs_attempted += 1
            envelope = await self.run_once(url, form_factor)
            if callable(on_run):
                on_run(index, envelope)

            if not envelope.ok or not envelope.lhr:
                result.errors.append(
                    f"lighthouse run {index}: {envelope.error or 'failed'}"
                )
                continue

            result.runs_succeeded += 1
            last_meta = envelope.meta or {}
            extracts.append(extract_values(envelope.lhr))
            # Library detection is deterministic for a given page, so the
            # last run's list is as good as any; taking it here means the
            # LHR can be released with the loop iteration.
            result.libraries = extract_libraries(envelope.lhr)
            artifact = self._write_artifact(
                envelope.lhr, hostname=hostname,
                form_factor=form_factor, index=index,
            )
            if artifact:
                result.artifacts.append(artifact)

        if extracts:
            result.observations = aggregate(extracts, meta=last_meta)

        # Chrome's user-agent reports a reduced version (141.0.0.0), so the
        # LHR-derived value loses the build number. The probe asks Chrome
        # directly and gets 141.0.7390.37. Provenance is the whole point of
        # recording it, so prefer the precise one.
        if self._probed and self._probed.get("chromeVersion"):
            last_meta = {**last_meta, "chromeVersion": self._probed["chromeVersion"]}
        result.meta = last_meta
        return result


class LighthouseCollector:
    """Pipeline adapter.

    Sits in its own pipeline stage. Because the runner holds its own
    semaphore, site-level concurrency can stay wide (network collectors want
    that) while only ``config.concurrency`` sites are inside Lighthouse at
    any moment.
    """

    name = "lighthouse"
    #: Marks this collector as the expensive pass. `core.split_pipeline`
    #: reads it to run every page cheaply first and only then measure the
    #: sampled representatives, because the sampling decision is made from
    #: template classes that only the cheap pass can produce.
    needs_browser = True

    def __init__(self, runner: LighthouseRunner) -> None:
        self.runner = runner

    async def collect(self, ctx: PageContext) -> list[Observation]:
        target = ctx.url
        if ctx.document is not None and ctx.document.final_url:
            # Audit where the redirects actually landed, so Lighthouse is not
            # scoring a 301 hop.
            target = ctx.document.final_url

        observations: list[Observation] = []
        results: list[LighthouseResult] = []
        for form_factor in self.runner.config.form_factors:
            result = await self.runner.audit(
                target, hostname=ctx.hostname, form_factor=form_factor
            )
            results.append(result)
            observations.extend(result.observations)
            ctx.errors.extend(result.errors)

        merged = LighthouseResult(
            observations=observations,
            libraries=next((r.libraries for r in results if r.libraries), []),
            artifacts=[a for r in results for a in r.artifacts],
            meta=next((r.meta for r in reversed(results) if r.meta), {}),
            errors=[e for r in results for e in r.errors],
            runs_attempted=sum(r.runs_attempted for r in results),
            runs_succeeded=sum(r.runs_succeeded for r in results),
        )
        # On the CONTEXT, not on self: one collector instance serves every
        # page in the batch and many pages are in flight at once, so
        # instance state would be clobbered by whichever site finished last.
        ctx.extras["lighthouse"] = merged
        return observations


def extract_libraries(lhr: dict[str, Any]) -> list[dict[str, Any]]:
    """The `js-libraries` audit rows: name, version, and npm coordinate.

    The npm coordinate is why this is worth extracting rather than
    fingerprinting from markup: it maps onto OSV's npm ecosystem with no name
    guessing, so the version the browser actually observed can be matched
    against advisories without an intermediate lookup table that could be
    wrong.

    Rows without all three fields are dropped. Guessing that "Kendo UI" is
    npm's `kendo-ui-core` is how a version gets matched against another
    package's advisories.
    """
    audit = (lhr.get("audits") or {}).get("js-libraries") or {}
    details = audit.get("details") or {}
    out: list[dict[str, Any]] = []
    for item in details.get("items") or []:
        name, version, npm = (item.get("name"), item.get("version"),
                              item.get("npm"))
        if name and version and npm:
            out.append({"name": str(name), "version": str(version),
                        "npm": str(npm)})
    return out


def lighthouse_observations(lhr: dict[str, Any]) -> list[Observation]:
    """Convenience for tests and one-off scripts: one LHR to observations."""
    return [
        Observation(Source.LIGHTHOUSE, key, numeric_value=value)
        for key, value in extract_values(lhr).items()
    ]
