// Build desktop/data/vulndb.json from the NIST NVD.
//
// Vulnerability scanning matches detected components (see crates/slap-engine/
// src/components.rs) against a local, dated, curated CVE database. This script
// is that database's generator: it queries the NVD API by product (CPE) for
// exactly the components the detector recognises, extracts the affected version
// ranges and CVSS severity, and writes the file `vulndb.rs` embeds at build
// time.
//
// Design (from claude/vulnerabilities.md):
//   - Local + dated: the app never calls a CVE API during an audit; the file
//     carries `generated_at`, and the report prints its age.
//   - Curated: a database wider than the detector is dead weight; narrower is a
//     silent gap. So the covered set is precisely the detected products that
//     actually have CVEs.
//   - No silent shrinkage: the previous database is a baseline. A covered
//     package that comes back with FEWER CVEs than before (NVD rate-limits by
//     answering, not refusing) fails the build rather than shipping less.
//
// Every target - JS library, WordPress core, WordPress plugin - is one or more
// NVD CPE `vendor:product` pairs. NVD's vendor and product naming is wildly
// inconsistent (the "Elementor" plugin is `elementor:website_builder`, Yoast is
// `yoast:yoast_seo`), and a plugin's product name almost never equals its URL
// slug, so the pairs below were each discovered from real CVEs rather than
// derived. A package with more than one pair (a renamed vendor, a fork) has its
// CVEs unioned. A wrong pair simply returns nothing - extraction only keeps
// cpeMatch rows whose vendor:product equals a listed pair - so it can widen a
// gap, never invent a false match.
//
// Usage:  node scripts/build-vulndb.mjs [--out <path>] [--api-key <key>]
// NVD without a key allows 5 requests / 30s; the script paces itself to that.

import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const DEFAULT_OUT = resolve(HERE, "../data/vulndb.json");

const args = process.argv.slice(2);
const OUT = argOf("--out") || DEFAULT_OUT;
const API_KEY = argOf("--api-key") || process.env.NVD_API_KEY || null;
// NVD: 5 req/30s without a key, 50 with. Pace conservatively either way.
const DELAY_MS = API_KEY ? 900 : 6500;

function argOf(flag) {
  const i = args.indexOf(flag);
  return i >= 0 && args[i + 1] ? args[i + 1] : null;
}

// --- What the detector recognises, mapped to NVD CPEs ---------------------
//
// npm: the JS libraries components.rs covers (its JS_LIBS, minus the handful it
// detects only to report "not checked"). Each is one or more `vendor:product`
// candidates; a library NVD files under more than one vendor lists them all.
const NPM = {
  jquery: ["jquery:jquery"],
  "jquery-ui": ["jqueryui:jquery_ui"],
  bootstrap: ["getbootstrap:bootstrap"],
  angular: ["angular:angular", "google:angularjs", "angularjs:angular.js"],
  react: ["facebook:react"],
  lodash: ["lodash:lodash"],
  underscore: ["underscorejs:underscore", "jashkenas:underscore.js"],
  moment: ["momentjs:moment"],
  handlebars: ["handlebarsjs:handlebars"],
  knockout: ["knockoutjs:knockout"],
  highcharts: ["highcharts:highcharts", "highsoft:highcharts"],
  "socket.io": ["socket:socket.io", "socketio:socket.io"],
  dojo: ["dojotoolkit:dojo", "dojofoundation:dojo"],
  yui: ["yahoo:yui"],
  next: ["vercel:next.js", "zeit:next.js"],
};

// WordPress core.
const WORDPRESS = { wordpress: ["wordpress:wordpress"] };

// WordPress plugins. The KEY is the slug the detector reads from the asset URL
// (`/wp-content/plugins/<slug>/`); the value is the NVD `vendor:product`
// pair(s) that slug's plugin actually appears under. These were discovered by
// inspecting real CVEs, because the product name is unpredictable (`elementor`
// -> `website_builder`, `wordpress-seo` -> `yoast_seo`, `wp-google-maps` ->
// `wp_go_maps`). Plugins whose NVD product could not be pinned to a single
// unambiguous pair are deliberately absent: the detector still reports them,
// honestly, as "not checked" rather than risk a misattributed finding. Plugin
// versions are only ever Inferred (from `?ver=`), so every plugin match is
// reported as "possible", never a confirmed critical - which is the safety
// margin that makes this curation tolerable.
const WP_PLUGINS = {
  // The originally-covered twelve.
  akismet: ["automattic:akismet"],
  "contact-form-7": ["rocklobster:contact_form_7"],
  elementor: ["elementor:website_builder"],
  gutenberg: ["wordpress:gutenberg"],
  jetpack: ["automattic:jetpack"],
  "litespeed-cache": ["litespeedtech:litespeed_cache"],
  "w3-total-cache": ["boldgrid:w3_total_cache"],
  woocommerce: ["woocommerce:woocommerce"],
  "wordpress-seo": ["yoast:yoast_seo"],
  "wp-super-cache": ["automattic:wp_super_cache"],
  wpforms: ["wpforms:wpforms"],
  "wpforms-lite": ["wpforms:wpforms"],
  // Expanded coverage: common plugins with a known CVE history and a product
  // pinned from real NVD CVEs.
  "advanced-custom-fields": ["advancedcustomfields:advanced_custom_fields"],
  "all-in-one-seo-pack": [
    "semperfiwebdesign:all_in_one_seo_pack",
    "semperplugins:all_in_one_seo_pack",
  ],
  "all-in-one-wp-migration": ["servmask:all-in-one_wp_migration"],
  autoptimize: ["autoptimize:autoptimize"],
  backwpup: ["inpsyde:backwpup"],
  "better-wp-security": ["ithemes:ithemes_security", "ithemes:security"],
  "broken-link-checker": [
    "broken_link_checker_project:broken_link_checker",
    "managewp:broken_link_checker",
  ],
  cloudflare: ["cloudflare:cloudflare"],
  "code-snippets": ["codesnippets:code_snippets", "code_snippets:code_snippets"],
  "duplicate-post": [
    "duplicate_post_project:duplicate_post",
    "copy-delete-posts:duplicate_post",
  ],
  "essential-addons-for-elementor-lite": [
    "wpdeveloper:essential_addons_for_elementor",
  ],
  forminator: ["incsub:forminator"],
  "google-analytics-for-wordpress": ["monsterinsights:monsterinsights"],
  "limit-login-attempts-reloaded": [
    "limitloginattempts:limit_login_attempts_reloaded",
  ],
  loginizer: ["loginizer:loginizer"],
  "mailchimp-for-wp": ["ibericode:mailchimp_for_wordpress"],
  "ninja-forms": ["ninjaforms:ninja_forms"],
  "popup-maker": ["code-atlantic:popup_maker"],
  redirection: ["redirection_project:redirection", "redirection:redirection"],
  revslider: ["themepunch:slider_revolution"],
  "seo-by-rank-math": ["rankmath:seo", "rankmath:seo_pro"],
  "shortpixel-image-optimiser": ["shortpixel:image_optimizer"],
  "sucuri-scanner": ["sucuri:security"],
  tablepress: ["tablepress:tablepress"],
  updraftplus: ["updraftplus:updraftplus"],
  wordfence: ["wordfence:wordfence"],
  "wp-fastest-cache": ["wpfastestcache:wp_fastest_cache"],
  "wp-google-maps": ["codecabin:wp_go_maps", "wpgmaps:wp_go_maps"],
  "wp-mail-smtp": ["wpforms:wp_mail_smtp"],
  "wp-optimize": ["updraftplus:wp-optimize"],
  "wp-smushit": ["wpmudev:smush_image_compression_and_optimization"],
  "wp-statistics": [
    "wp-statistics:wp_statistics",
    "wp_statistics:wp_statistics",
    "veronalabs:wp_statistics",
  ],
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function nvd(virtualMatchString, startIndex = 0) {
  const url =
    `https://services.nvd.nist.gov/rest/json/cves/2.0` +
    `?virtualMatchString=${encodeURIComponent(virtualMatchString)}` +
    `&resultsPerPage=2000&startIndex=${startIndex}`;
  const headers = API_KEY ? { apiKey: API_KEY } : {};
  for (let attempt = 0; ; attempt++) {
    let res;
    try {
      res = await fetch(url, { headers });
    } catch (e) {
      // A dropped connection is as transient as a 5xx; retry it the same way.
      if (attempt < 5) {
        const backoff = 20000 * (attempt + 1);
        process.stderr.write(`  NVD fetch error (${e.message}), backing off ${backoff / 1000}s\n`);
        await sleep(backoff);
        continue;
      }
      throw e;
    }
    if (res.ok) return res.json();
    // Retry NVD's rate-limit (403/429) and any gateway/server 5xx (500/502/503/
    // 504 all seen in practice); a partial answer to one candidate silently
    // undercounts that package.
    if ((res.status === 403 || res.status === 429 || res.status >= 500) && attempt < 5) {
      const backoff = 20000 * (attempt + 1);
      process.stderr.write(`  NVD ${res.status}, backing off ${backoff / 1000}s\n`);
      await sleep(backoff);
      continue;
    }
    throw new Error(`NVD ${res.status} for ${virtualMatchString}`);
  }
}

// Every CVE affecting the CPE match string, across pages.
async function fetchAll(vms) {
  let index = 0;
  const out = [];
  for (;;) {
    const page = await nvd(vms, index);
    out.push(...(page.vulnerabilities || []).map((v) => v.cve));
    const total = page.totalResults || 0;
    index += page.resultsPerPage || 2000;
    if (index >= total) return out;
    await sleep(DELAY_MS);
  }
}

function severityOf(metrics) {
  const word = (arr) => arr && arr[0] && (arr[0].cvssData?.baseSeverity || arr[0].baseSeverity);
  const s =
    word(metrics?.cvssMetricV31) ||
    word(metrics?.cvssMetricV30) ||
    word(metrics?.cvssMetricV2);
  return s ? s.toLowerCase() : "unknown";
}

// Pull the versions and ranges a CVE names for one `vendor:product`. Only rows
// whose vendor AND product match are kept, so a CVE that also touches other
// software contributes only its rows for this product.
function extract(cve, vendor, product) {
  const versions = new Set();
  const ranges = [];
  for (const conf of cve.configurations || []) {
    for (const node of conf.nodes || []) {
      for (const m of node.cpeMatch || []) {
        if (!m.vulnerable) continue;
        const p = m.criteria.split(":");
        const cVendor = p[3], cProduct = p[4], cVersion = p[5];
        if (cVendor !== vendor || cProduct !== product) continue;
        const hasRange =
          m.versionStartIncluding || m.versionStartExcluding ||
          m.versionEndIncluding || m.versionEndExcluding;
        if (hasRange) {
          ranges.push({
            introduced: m.versionStartIncluding || m.versionStartExcluding || null,
            fixed: m.versionEndExcluding || null,
            last_affected: m.versionEndIncluding || null,
          });
        } else if (cVersion && cVersion !== "*" && cVersion !== "-") {
          versions.add(cVersion.replace(/\\/g, ""));
        }
        // A row with neither a concrete version nor a range means "all/unknown
        // version"; matching every detected version off that is how a vague CVE
        // becomes a page of false positives, so it is dropped.
      }
    }
  }
  return { versions: [...versions], ranges };
}

// Collect all CVEs for one package across its candidate CPEs, merging a CVE
// seen under more than one candidate into a single entry.
async function collectPackage(ecosystem, pkg, candidates) {
  const byId = new Map();
  for (const cpe of candidates) {
    const [vendor, product] = cpe.split(":");
    const vms = `cpe:2.3:a:${vendor}:${product}:*:*:*:*:*:*:*:*`;
    let cves;
    try {
      cves = await fetchAll(vms);
    } catch (e) {
      process.stderr.write(`  ${pkg} <${cpe}>: ${e.message}\n`);
      await sleep(DELAY_MS);
      continue;
    }
    for (const cve of cves) {
      const { versions, ranges } = extract(cve, vendor, product);
      if (versions.length === 0 && ranges.length === 0) continue;
      const prev = byId.get(cve.id) || {
        id: cve.id,
        ecosystem,
        package: pkg,
        severity: severityOf(cve.metrics),
        versions: new Set(),
        ranges: [],
      };
      versions.forEach((v) => prev.versions.add(v));
      prev.ranges.push(...ranges);
      byId.set(cve.id, prev);
    }
    await sleep(DELAY_MS);
  }
  // Finalise: dedupe ranges, sort versions.
  return [...byId.values()].map((v) => ({
    id: v.id,
    ecosystem: v.ecosystem,
    package: v.package,
    severity: v.severity,
    versions: [...v.versions].sort(),
    ranges: dedupeRanges(v.ranges),
  }));
}

function dedupeRanges(ranges) {
  const seen = new Set();
  const out = [];
  for (const r of ranges) {
    const key = `${r.introduced}|${r.fixed}|${r.last_affected}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(r);
  }
  return out;
}

function baselineCounts() {
  try {
    const db = JSON.parse(readFileSync(OUT, "utf8"));
    const counts = new Map();
    for (const v of db.vulnerabilities || []) {
      const k = `${v.ecosystem}/${v.package}`;
      counts.set(k, (counts.get(k) || 0) + 1);
    }
    return counts;
  } catch {
    return new Map();
  }
}

async function main() {
  process.stderr.write(
    `Building vulndb from NVD${API_KEY ? " (with API key)" : " (no key, ~10 min)"}...\n`,
  );
  const baseline = baselineCounts();
  const targets = [
    ...Object.entries(NPM).map(([pkg, c]) => ["npm", pkg, c]),
    ...Object.entries(WORDPRESS).map(([pkg, c]) => ["wordpress", pkg, c]),
    ...Object.entries(WP_PLUGINS).map(([slug, c]) => ["wordpress-plugin", slug, c]),
  ];

  const vulnerabilities = [];
  const covered = { npm: [], wordpress: [], "wordpress-plugin": [] };
  const degraded = [];

  for (const [eco, pkg, candidates] of targets) {
    const entries = await collectPackage(eco, pkg, candidates);
    const key = `${eco}/${pkg}`;
    const before = baseline.get(key) || 0;
    process.stderr.write(
      `  ${key}: ${entries.length} CVEs` +
        (before ? ` (was ${before})` : "") +
        (entries.length < before ? "  << SHRANK" : "") +
        "\n",
    );
    if (entries.length < before) degraded.push(`${key}: ${entries.length} < ${before}`);
    if (entries.length > 0) {
      covered[eco].push(pkg);
      vulnerabilities.push(...entries);
    }
  }

  if (degraded.length) {
    process.stderr.write(
      `\nREFUSING to write a degraded database. These covered packages shrank:\n  ` +
        degraded.join("\n  ") +
        `\nThis is usually NVD rate-limiting or a changed CPE. Re-run.\n`,
    );
    process.exit(1);
  }

  for (const eco of Object.keys(covered)) covered[eco].sort();
  vulnerabilities.sort((a, b) =>
    a.ecosystem.localeCompare(b.ecosystem) ||
    a.package.localeCompare(b.package) ||
    a.id.localeCompare(b.id),
  );

  const db = {
    schema: 1,
    generated_at: new Date().toISOString().replace(/\.\d+Z$/, "+00:00"),
    sources: {
      npm: "NIST NVD",
      wordpress: "NIST NVD",
      "wordpress-plugin": "NIST NVD",
    },
    covered_packages: covered,
    vulnerabilities,
  };
  writeFileSync(OUT, JSON.stringify(db, null, 2) + "\n");
  const bySev = vulnerabilities.reduce((m, v) => ((m[v.severity] = (m[v.severity] || 0) + 1), m), {});
  process.stderr.write(
    `\nWrote ${vulnerabilities.length} CVEs to ${OUT}\n` +
      `  covered: npm ${covered.npm.length}, wordpress ${covered.wordpress.length}, ` +
      `wordpress-plugin ${covered["wordpress-plugin"].length}\n` +
      `  by severity: ${JSON.stringify(bySev)}\n`,
  );
}

main().catch((e) => {
  process.stderr.write(`FAILED: ${e.stack || e}\n`);
  process.exit(1);
});
