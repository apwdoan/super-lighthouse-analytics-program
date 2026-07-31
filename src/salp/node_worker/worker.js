/**
 * SALP Lighthouse worker.
 *
 * The entire Node surface of this project. It reads one JSON job on stdin,
 * runs Lighthouse, writes one JSON envelope on stdout, and exits.
 *
 *   in:   {"url": "...", "formFactor": "mobile", "categories": [...]}
 *   out:  {"ok": true, "lhr": {...}, "meta": {...}}
 *         {"ok": false, "error": "...", "code": "..."}
 *
 * Deliberately dumb, per the roadmap's language boundary:
 *   - no business logic, no thresholds, no severity
 *   - no storage: it never touches the database or the filesystem
 *   - no formatting: the raw LHR goes out untouched
 *
 * Everything downstream of "what did Chrome measure" is Python's job. If you
 * find yourself wanting to add a condition here, it belongs in
 * salp/collectors/lighthouse.py or in findings/rules.yaml instead.
 *
 * Exit codes: 0 success, 1 job failed (envelope on stdout explains), 2 bad
 * invocation. Diagnostics go to stderr so stdout stays parseable.
 */

import { launch } from "chrome-launcher";
import lighthouse from "lighthouse";

const DEFAULT_CATEGORIES = [
  "performance",
  "accessibility",
  "best-practices",
  "seo",
];

// Chrome flags for a measurement run. --no-sandbox is required in containers
// and CI; it is not a security posture for browsing, and this Chrome only
// ever loads the URL under audit.
const CHROME_FLAGS = [
  "--headless=new",
  "--no-sandbox",
  "--disable-dev-shm-usage",
  "--disable-gpu",
  "--no-first-run",
  "--no-default-browser-check",
  "--disable-extensions",
  "--disable-background-networking",
  "--disable-sync",
  "--disable-features=TranslateUI,MediaRouter",
  "--mute-audio",
];

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => {
      data += chunk;
    });
    process.stdin.on("end", () => resolve(data));
    process.stdin.on("error", reject);
  });
}

function emit(payload) {
  process.stdout.write(JSON.stringify(payload));
}

function fail(code, error, extra = {}) {
  emit({ ok: false, code, error: String(error), ...extra });
  process.exit(1);
}

/**
 * Lighthouse's own throttling presets, named so Python can record which one
 * produced a run. Comparing a simulated-3G number against an unthrottled one
 * is meaningless, so the profile name is stored on every run.
 */
function settingsFor(job) {
  const formFactor = job.formFactor === "desktop" ? "desktop" : "mobile";
  const base = {
    output: "json",
    logLevel: "error",
    onlyCategories: job.categories?.length ? job.categories : DEFAULT_CATEGORIES,
    formFactor,
    throttlingMethod: job.throttlingMethod || "simulate",
    disableStorageReset: false,
  };

  if (formFactor === "desktop") {
    return {
      ...base,
      screenEmulation: {
        mobile: false,
        width: 1350,
        height: 940,
        deviceScaleFactor: 1,
        disabled: false,
      },
      throttling: {
        rttMs: 40,
        throughputKbps: 10 * 1024,
        cpuSlowdownMultiplier: 1,
        requestLatencyMs: 0,
        downloadThroughputKbps: 0,
        uploadThroughputKbps: 0,
      },
      emulatedUserAgent:
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 " +
        "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    };
  }

  // Lighthouse's mobile defaults: Moto G Power, simulated slow 4G, 4x CPU
  // slowdown. Left as defaults on purpose so numbers stay comparable with
  // PageSpeed Insights and web.dev, which a client will inevitably re-test on.
  return base;
}

/**
 * Pull a clean "141.0.7390.37" out of a user-agent string.
 *
 * The raw UA is useless in a report's provenance block, and headless Chrome
 * reports itself as HeadlessChrome/… so a naive match on "Chrome/" misses it.
 */
function chromeVersionFrom(userAgent) {
  if (!userAgent) return null;
  const match = /(?:Headless)?Chrome\/([\d.]+)/.exec(userAgent);
  return match ? match[1] : null;
}

function throttlingProfileName(job) {
  const formFactor = job.formFactor === "desktop" ? "desktop" : "mobile";
  const method = job.throttlingMethod || "simulate";
  return `${formFactor}/${method}/lh13-default`;
}

async function probe() {
  // Used by Python to record provenance and to fail early with a useful
  // message rather than mid-batch.
  let chrome;
  try {
    chrome = await launch({ chromeFlags: CHROME_FLAGS, chromePath: process.env.CHROME_PATH });
  } catch (err) {
    fail("chrome_launch_failed", err);
    return;
  }
  try {
    const response = await fetch(`http://127.0.0.1:${chrome.port}/json/version`);
    const version = await response.json();
    const { default: pkg } = await import("lighthouse/package.json", {
      with: { type: "json" },
    });
    emit({
      ok: true,
      meta: {
        lighthouseVersion: pkg.version,
        chromeVersion: chromeVersionFrom(version.Browser) ?? version.Browser,
        chromePath: chrome.path ?? process.env.CHROME_PATH ?? null,
        node: process.version,
      },
    });
  } catch (err) {
    fail("probe_failed", err);
  } finally {
    await chrome.kill();
  }
}

async function runJob(job) {
  if (!job.url) {
    emit({ ok: false, code: "bad_job", error: "job has no url" });
    process.exit(2);
  }

  let chrome;
  try {
    chrome = await launch({
      chromeFlags: CHROME_FLAGS,
      chromePath: process.env.CHROME_PATH,
    });
  } catch (err) {
    fail("chrome_launch_failed", err);
    return;
  }

  try {
    const result = await lighthouse(
      job.url,
      { ...settingsFor(job), port: chrome.port },
    );

    if (!result?.lhr) {
      fail("no_result", "Lighthouse returned no result object");
      return;
    }
    // runtimeError is how Lighthouse reports "the page did not load" rather
    // than throwing. Surfacing it as a failure keeps Python from storing a
    // run full of zeroes that look like real measurements.
    if (result.lhr.runtimeError) {
      fail("runtime_error", result.lhr.runtimeError.message, {
        runtimeErrorCode: result.lhr.runtimeError.code,
      });
      return;
    }

    emit({
      ok: true,
      lhr: result.lhr,
      meta: {
        lighthouseVersion: result.lhr.lighthouseVersion,
        chromeVersion: chromeVersionFrom(result.lhr.environment?.hostUserAgent),
        userAgent: result.lhr.environment?.hostUserAgent ?? null,
        // Lighthouse's own CPU benchmark for the machine that took this
        // measurement. Python compares it across a batch: a benchmarkIndex
        // that sags mid-run is direct evidence of the CPU contention that
        // silently inflates TBT and TTI.
        benchmarkIndex: result.lhr.environment?.benchmarkIndex ?? null,
        throttlingProfile: throttlingProfileName(job),
        formFactor: job.formFactor === "desktop" ? "desktop" : "mobile",
        requestedUrl: result.lhr.requestedUrl,
        finalUrl: result.lhr.finalDisplayedUrl ?? result.lhr.finalUrl,
        fetchTime: result.lhr.fetchTime,
      },
    });
  } catch (err) {
    fail("lighthouse_failed", err?.stack || err);
  } finally {
    await chrome.kill();
  }
}

async function main() {
  if (process.argv.includes("--probe")) {
    await probe();
    return;
  }

  const raw = await readStdin();
  if (!raw.trim()) {
    emit({ ok: false, code: "bad_job", error: "empty stdin" });
    process.exit(2);
  }

  let job;
  try {
    job = JSON.parse(raw);
  } catch (err) {
    emit({ ok: false, code: "bad_job", error: `stdin is not JSON: ${err}` });
    process.exit(2);
    return;
  }

  await runJob(job);
}

main().catch((err) => {
  fail("worker_crashed", err?.stack || err);
});
