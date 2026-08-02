"""The vulnerability database: a local, dated, offline file.

Three properties, each of which is a decision rather than a convenience.

**Local.** Matching happens against a file on disk, never a live API call
during an audit. Two reasons. A per-audit lookup sends a client's component
inventory to a third party, which is not a thing to do quietly on a client's
behalf; and a rate-limited external dependency in the middle of a 24-site
batch turns a network hiccup into a report that silently finds nothing.

**Dated.** Every database carries ``generated_at`` and it is printed in the
report appendix beside the Lighthouse and Chrome versions. A bundle built once
and run for a year carries a year-old database, and a report that does not say
so is wrong in a way nobody can detect.

**Curated, not complete.** OSV's full npm export is ~213MB, and SLAP can only
name the ~83 packages Lighthouse's library detector recognises. The database
holds exactly those, which is small enough to ship and exactly as broad as the
detection is. A database wider than the detector is dead weight; narrower
would be a silent coverage gap.

Sources
-------

``NIST NVD`` — the primary source, for every ecosystem at once. The CVE API
(https://nvd.nist.gov/developers/vulnerabilities) is keyless (5 requests per
30s) or keyed (free, 50 per 30s via ``NVD_API_KEY``), carries CVSS severity
from NIST's own analysis, and its permanent CVE storage is explicitly
permitted. It is queried by CPE, which is the catch: a wrong CPE returns
zero results, and zero is indistinguishable from a clean product. So the
map in ``NVD_PRODUCTS`` holds only CPEs verified live against the API, each
annotated with the CVE count seen at verification, and a package without a
verified CPE is **not covered** rather than silently unmatched — the
``covered_packages`` field is how the database says so and how the report
keeps "not checked" distinct from "clean". Using NVD also unlocks what no
free WordPress-specific source could: WordPress core (583 CVEs at
verification) and the most common plugins.

NVD's fair-use terms require the notice in ``NVD_NOTICE``; the report
appendix prints it whenever NVD data is in use.

``OSV.dev`` — retained as an alternative (``slap vulndb update --source
osv``): no key, no CPE mapping to maintain, npm only. Useful when NVD is
having a bad day, which is not hypothetical for that API.

``WPScan`` — deliberately **not** used. Its terms forbid exactly this
("permanent storage of our vulnerability data is not permitted", "API
vulnerability data caching is not permitted"). Wordfence's feed was free
when this was designed; as of 2026-08-02 its v2 endpoints return 410 Gone
and v3 returns 401. NVD made both moot.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SCHEMA = 1

#: Packages worth carrying. Derived from js-library-detector's npm
#: coordinates, which is precisely the set Lighthouse can name a version for.
#: Two entries in that list are URLs rather than package names; they are
#: filtered rather than corrected upstream.
DEFAULT_NPM_PACKAGES: tuple[str, ...] = (
    "@angular/core", "@polymer/polymer", "amplifyjs", "angular", "backbone",
    "backbone.marionette", "boomerangjs", "bootstrap", "brewser", "caman",
    "can", "core-js", "createjs", "d3", "dc", "dojo", "ember-source", "fabric",
    "fastclick", "flexslider", "flot", "foundation-sites", "framerjs",
    "fuse.js", "gatsby", "google-closure-library", "gsap", "hammerjs",
    "handlebars", "handsontable", "headjs", "highcharts", "ifvisible.js",
    "isotope-layout", "jquery", "jquery-mobile", "jquery-ui", "kendo-ui-core",
    "knockout", "leaflet", "lit-element", "lodash", "mapbox-gl", "marko",
    "material-design-lite", "matter-js", "modernizr", "moment",
    "moment-timezone", "move", "mustache", "next", "numeraljs", "nuxt",
    "paper", "philogl", "pixi.js", "preact", "processing-js", "pusher-js",
    "qooxdoo", "react", "react-scripts", "remix", "requirejs", "riot",
    "scrollmagic", "seajs", "socket.io", "spf", "sugar", "three", "tween.js",
    "two.js", "underscore", "velocity-animate", "visibilityjs", "vue",
    "webfontloader", "workbox-sw", "yui", "zepto",
)

#: OSV severity vocabulary mapped onto this project's. Deliberately
#: conservative at the boundary: a CVSS "MODERATE" becomes MEDIUM, not HIGH.
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2,
                 "LOW": 1, "UNKNOWN": 0}
RANK_SEVERITY = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}


# --------------------------------------------------------------------------
# Version comparison
# --------------------------------------------------------------------------

_NUM = re.compile(r"\d+")


def parse_version(text: str | None) -> tuple[int, ...] | None:
    """A comparable tuple, or None when the string is not a version.

    Deliberately lenient about what it accepts and strict about what it
    rejects. Real version strings in the wild are "3.4.1", "1.11.3-rc1",
    "v2.0", "6.5.2" and "5.8.1.1"; the things that must NOT parse are the
    cache-busters and content hashes that appear in the same `?ver=` slot,
    because a hash that parses as a version produces a confident, wrong CVE.
    """
    if not text:
        return None
    text = str(text).strip().lstrip("vV")
    if not text or not text[0].isdigit():
        return None
    # A pre-release or build suffix is dropped rather than ordered. Ordering
    # pre-releases correctly needs full semver, and getting it subtly wrong
    # here means mismatching a fix boundary.
    head = re.split(r"[-+_ ]", text, 1)[0]
    parts = head.split(".")
    if not all(_NUM.fullmatch(p) for p in parts if p):
        return None
    numbers = tuple(int(p) for p in parts if p)
    if not numbers:
        return None
    # A single huge number is a timestamp or a hash, not a version. WordPress
    # asset URLs carry `?ver=1699887600` constantly.
    if len(numbers) == 1 and numbers[0] > 1000:
        return None
    return numbers


def compare(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    """Standard tuple comparison, zero-padded so 1.2 == 1.2.0."""
    width = max(len(a), len(b))
    pa = a + (0,) * (width - len(a))
    pb = b + (0,) * (width - len(b))
    return (pa > pb) - (pa < pb)


# --------------------------------------------------------------------------
# Records
# --------------------------------------------------------------------------

@dataclass(slots=True, frozen=True)
class AffectedRange:
    """One OSV range: affected from ``introduced`` until ``fixed``.

    ``fixed`` is exclusive and ``last_affected`` is inclusive; conflating them
    is an off-by-one that either clears a vulnerable version or condemns a
    patched one, and both are bad in a client report.
    """

    introduced: tuple[int, ...] | None = None
    fixed: tuple[int, ...] | None = None
    last_affected: tuple[int, ...] | None = None

    def contains(self, version: tuple[int, ...]) -> bool:
        if self.introduced and compare(version, self.introduced) < 0:
            return False
        if self.fixed and compare(version, self.fixed) >= 0:
            return False
        if self.last_affected and compare(version, self.last_affected) > 0:
            return False
        return True


@dataclass(slots=True, frozen=True)
class Vulnerability:
    id: str
    package: str
    ecosystem: str
    summary: str
    severity: str                       # this project's vocabulary
    ranges: tuple[AffectedRange, ...] = ()
    versions: tuple[str, ...] = ()      # explicit affected versions, if listed
    aliases: tuple[str, ...] = ()
    reference: str | None = None

    @property
    def cve(self) -> str | None:
        for alias in (self.id, *self.aliases):
            if alias.upper().startswith("CVE-"):
                return alias
        return None

    @property
    def label(self) -> str:
        """What a client sees. The CVE if there is one, else the advisory id."""
        return self.cve or self.id

    def affects(self, version: tuple[int, ...], raw: str) -> bool:
        if raw in self.versions:
            return True
        return any(r.contains(version) for r in self.ranges)


# --------------------------------------------------------------------------
# The database
# --------------------------------------------------------------------------

@dataclass(slots=True)
class VulnDatabase:
    generated_at: str | None = None
    sources: dict[str, str] = field(default_factory=dict)
    #: (ecosystem, lowercased package) -> vulnerabilities
    index: dict[tuple[str, str], list[Vulnerability]] = field(default_factory=dict)
    #: Which packages within an ecosystem were actually queried. An
    #: ecosystem absent from this dict is covered in full (the OSV npm
    #: behaviour); one present is covered ONLY for the listed packages.
    #: Exists because NVD is queried by hand-verified CPE, so "wordpress
    #: plugins" is never covered as a class -- and a plugin outside the map
    #: must report as NOT CHECKED, not as clean.
    covered: dict[str, tuple[str, ...]] = field(default_factory=dict)
    #: Packages whose query failed outright during the last build. Not
    #: serialised: it describes a build, not the data.
    failures: list[str] = field(default_factory=list)

    @property
    def available(self) -> bool:
        return bool(self.index)

    @property
    def count(self) -> int:
        return sum(len(v) for v in self.index.values())

    @property
    def age_days(self) -> int | None:
        """How stale the data is. The number the appendix prints."""
        if not self.generated_at:
            return None
        try:
            when = datetime.fromisoformat(self.generated_at)
        except ValueError:
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return max(0, (datetime.now(timezone.utc) - when).days)

    def covers(self, ecosystem: str, package: str | None = None) -> bool:
        """Whether this database can speak to an ecosystem, or one package.

        The distinction that keeps the report honest: "no vulnerabilities
        found in your WordPress plugins" and "WordPress plugins were not
        checked" are different sentences, and only one of them is true when
        no WordPress source is configured. With a package given, the same
        distinction one level down: an NVD database covers exactly the
        CPE-mapped packages, so a plugin outside the map is *not checked*
        even though its ecosystem has a source.
        """
        if ecosystem not in self.sources:
            return False
        restriction = self.covered.get(ecosystem)
        if restriction is None or package is None:
            return True
        return package.lower() in restriction

    def query(self, ecosystem: str, package: str,
              version: str) -> list[Vulnerability]:
        parsed = parse_version(version)
        if parsed is None:
            # No usable version means no finding. Not "probably fine": the
            # report must not imply a check happened that did not.
            return []
        candidates = self.index.get((ecosystem, package.lower()), [])
        # Deduplicated on the way out rather than at build time, so a database
        # built before the alias problem was understood still reports honest
        # counts without needing a rebuild.
        return deduplicate([v for v in candidates if v.affects(parsed, version)])

    # -- serialisation -----------------------------------------------------

    def to_json(self) -> str:
        payload = {
            "schema": SCHEMA,
            "generated_at": self.generated_at,
            "sources": self.sources,
            "covered_packages": {k: sorted(v) for k, v in self.covered.items()},
            "vulnerabilities": [
                {
                    "id": v.id, "package": v.package, "ecosystem": v.ecosystem,
                    "summary": v.summary, "severity": v.severity,
                    "aliases": list(v.aliases),
                    "reference": v.reference,
                    "versions": list(v.versions),
                    "ranges": [
                        {"introduced": ".".join(map(str, r.introduced)) if r.introduced else None,
                         "fixed": ".".join(map(str, r.fixed)) if r.fixed else None,
                         "last_affected": ".".join(map(str, r.last_affected)) if r.last_affected else None}
                        for r in v.ranges
                    ],
                }
                for group in self.index.values() for v in group
            ],
        }
        return json.dumps(payload, indent=1, sort_keys=True)

    @classmethod
    def from_json(cls, text: str) -> "VulnDatabase":
        raw = json.loads(text)
        db = cls(generated_at=raw.get("generated_at"),
                 sources=dict(raw.get("sources") or {}),
                 covered={k: tuple(v) for k, v in
                          (raw.get("covered_packages") or {}).items()})
        for entry in raw.get("vulnerabilities", []):
            ranges = tuple(
                AffectedRange(
                    introduced=parse_version(r.get("introduced")),
                    fixed=parse_version(r.get("fixed")),
                    last_affected=parse_version(r.get("last_affected")),
                )
                for r in entry.get("ranges", [])
            )
            vuln = Vulnerability(
                id=entry["id"], package=entry["package"],
                ecosystem=entry["ecosystem"], summary=entry.get("summary", ""),
                severity=entry.get("severity", "info"), ranges=ranges,
                versions=tuple(entry.get("versions") or ()),
                aliases=tuple(entry.get("aliases") or ()),
                reference=entry.get("reference"),
            )
            db.index.setdefault(
                (vuln.ecosystem, vuln.package.lower()), []).append(vuln)
        return db

    @classmethod
    def load(cls, path: str | Path | None) -> "VulnDatabase":
        """Load, or return an empty database. Never raise.

        A missing or corrupt database must degrade to "not checked", never to
        a failed audit: the rest of the report is still worth having, and the
        `covers()` distinction means the absence is stated rather than read as
        a clean result.
        """
        if not path:
            return cls()
        p = Path(path)
        if not p.is_file():
            return cls()
        try:
            return cls.from_json(p.read_text(encoding="utf-8"))
        except (ValueError, KeyError, OSError):
            return cls()


def bundled_db_path() -> Path:
    """Beside the package, so a PyInstaller bundle carries it as data.

    Read-only in practice. A frozen bundle may sit in Program Files or
    /Applications, and even where it is writable, an update written here is
    silently discarded the next time the bundle is replaced. See
    `config.default_vulndb_path` for the copy that is actually used.
    """
    return Path(__file__).parent / "data" / "vulndb.json"


#: Retained under the old name: `default_db_path` is what the first version
#: exported and what the packaging spec and a few scripts still import.
default_db_path = bundled_db_path


def read_stamp(path: Path | None) -> str | None:
    """`generated_at` alone, without parsing the whole database.

    `Settings()` resolves the database path on construction, and the first
    version did it by loading and parsing up to two 108KB JSON files just to
    compare two dates: 5ms per Settings(), paid by every CLI invocation and
    every test. The field sits in the first few hundred bytes because the
    file is written with sorted keys, so a bounded read finds it.
    """
    if not path:
        return None
    path = Path(path)
    try:
        with path.open("r", encoding="utf-8") as handle:
            head = handle.read(4096)
    except OSError:
        return None
    match = re.search(r'"generated_at"\s*:\s*"([^"]*)"', head)
    if match:
        return match.group(1)
    # Not in the first chunk, or an unexpected layout. Fall back to a real
    # parse rather than guessing: a wrong answer here silently picks the
    # older database.
    database = VulnDatabase.load(path)
    return database.generated_at if database.available else None


def newer_of(*paths: Path | None) -> Path | None:
    """Whichever database was generated most recently.

    Not "the user's copy wins": a teammate who refreshed in January and
    installs a new bundle in June should get June's data, and one who
    refreshed yesterday should keep it. Comparing the dates the databases
    carry is the only rule that cannot regress in either direction.
    """
    best: Path | None = None
    best_stamp = ""
    for path in paths:
        if not path or not Path(path).is_file():
            continue
        stamp = read_stamp(path)
        if stamp is None:
            continue
        if best is None or stamp > best_stamp:
            best, best_stamp = Path(path), stamp
    return best


# --------------------------------------------------------------------------
# Building. Network, and only ever run explicitly by `slap vulndb update`.
# --------------------------------------------------------------------------

OSV_QUERY_URL = "https://api.osv.dev/v1/query"


def _osv_severity(record: dict[str, Any]) -> str:
    """Highest severity the record claims, mapped conservatively.

    **`database_specific.severity` at the TOP level is where GHSA puts the
    word.** The first version of this read
    `affected[].ecosystem_specific.severity`, which is `null` on every GitHub
    advisory, so a prototype-pollution CVE came out rated `info` and would
    have been filed under "also worth addressing" in a client report. The
    lesson generalises past this function: when a feed has three plausible
    places for a field, check which one it actually populates against a real
    record rather than taking the first one the schema allows.
    """
    best = 0
    database_specific = record.get("database_specific") or {}
    best = max(best, SEVERITY_RANK.get(
        str(database_specific.get("severity", "")).upper(), 0))

    for affected in record.get("affected", []):
        ecosystem_specific = affected.get("ecosystem_specific") or {}
        best = max(best, SEVERITY_RANK.get(
            str(ecosystem_specific.get("severity", "")).upper(), 0))

    if best == 0:
        # Last resort: band the CVSS v3 vector by its impact metrics. Coarse
        # on purpose. A real CVSS score needs the full base equation, and a
        # number that is subtly wrong is worse here than an honest band.
        for severity in record.get("severity", []) or []:
            score = str(severity.get("score", ""))
            if not score.startswith("CVSS:3"):
                continue
            high_impacts = sum(f"/{m}:H" in score for m in ("C", "I", "A"))
            if high_impacts >= 2:
                best = max(best, 3)
            elif high_impacts == 1:
                best = max(best, 2)
            else:
                best = max(best, 1)
    return RANK_SEVERITY.get(best, "info")


def _identity(vuln: "Vulnerability") -> str:
    """What makes two advisory records the same problem.

    GHSA re-issues advisories, and the old and new records are aliases of one
    another: lodash carries GHSA-f23m-r3pf-42rh and GHSA-xxjr-mmjv-4gpg, both
    aliased to CVE-2025-13465, describing one prototype pollution bug. Keying
    on the record id reports it twice, which inflates every count a client
    reads and makes the tool look like it is padding.

    The CVE is the identity where there is one. Where there is not, the
    lexicographically smallest id in the alias group is stable across
    rebuilds, which matters because an unstable key would make the same
    database dedupe differently on each build.
    """
    cve = vuln.cve
    if cve:
        return cve.upper()
    return min([vuln.id, *vuln.aliases], key=str.upper).upper()


def deduplicate(vulns: list["Vulnerability"]) -> list["Vulnerability"]:
    """One entry per distinct problem, keeping the most severe record."""
    order = ["info", "low", "medium", "high", "critical"]
    best: dict[str, Vulnerability] = {}
    for vuln in vulns:
        key = _identity(vuln)
        current = best.get(key)
        if current is None or order.index(vuln.severity) > order.index(current.severity):
            best[key] = vuln
    return sorted(best.values(),
                  key=lambda v: (-order.index(v.severity), v.label))


def parse_osv_record(record: dict[str, Any], package: str,
                     ecosystem: str) -> Vulnerability | None:
    ranges: list[AffectedRange] = []
    versions: list[str] = []
    for affected in record.get("affected", []):
        pkg = affected.get("package") or {}
        if str(pkg.get("name", "")).lower() != package.lower():
            continue
        versions.extend(affected.get("versions") or [])
        for rng in affected.get("ranges", []):
            if rng.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue
            introduced = fixed = last = None
            for event in rng.get("events", []):
                if "introduced" in event:
                    introduced = parse_version(event["introduced"])
                elif "fixed" in event:
                    fixed = parse_version(event["fixed"])
                elif "last_affected" in event:
                    last = parse_version(event["last_affected"])
            if introduced or fixed or last:
                ranges.append(AffectedRange(introduced, fixed, last))
    if not ranges and not versions:
        return None
    references = record.get("references") or []
    advisory = next((r.get("url") for r in references
                     if r.get("type") in ("ADVISORY", "WEB") and r.get("url")), None)
    return Vulnerability(
        id=record["id"], package=package, ecosystem=ecosystem,
        summary=" ".join((record.get("summary") or "").split()),
        severity=_osv_severity(record), ranges=tuple(ranges),
        versions=tuple(versions), aliases=tuple(record.get("aliases") or ()),
        reference=advisory,
    )


def _query_osv(package: str, timeout: float) -> list[dict[str, Any]] | None:
    """One OSV query. None means the request failed, [] means no advisories."""
    import urllib.error
    import urllib.request

    body = json.dumps({"package": {"name": package, "ecosystem": "npm"}}).encode()
    request = urllib.request.Request(
        OSV_QUERY_URL, data=body,
        headers={"Content-Type": "application/json", "User-Agent": "SLAP"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read())
    except (urllib.error.URLError, ValueError, OSError):
        return None
    return payload.get("vulns") or []


def build_from_osv(packages: Iterable[str] = DEFAULT_NPM_PACKAGES, *,
                   timeout: float = 30.0,
                   previous: "VulnDatabase | None" = None,
                   attempts: int = 3,
                   pause: float = 0.4,
                   progress=None) -> VulnDatabase:
    """Query OSV for each package and assemble a database. Network required.

    Queried per package rather than by downloading the 213MB npm export,
    because the export is 99.9% packages this tool can never detect.

    **Retried, and checked against the previous database.** A rebuild forty
    minutes after a good one silently came back with `angular` at zero
    advisories instead of fifteen, with no exception raised and nothing in
    the output to distinguish it from a package that genuinely has none. A
    quietly smaller database is the same failure as a stale one: every audit
    afterwards reports less and looks clean doing it.

    So a package that returns empty when the previous database had entries is
    retried, and a package that fails outright is recorded in
    ``failures`` for the caller to refuse on.
    """
    import time

    db = VulnDatabase(
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        sources={"npm": "OSV.dev"},
    )
    for i, package in enumerate(packages, 1):
        if package.startswith("http"):      # the two junk entries upstream
            continue
        had_before = len(previous.index.get(("npm", package.lower()), [])) if previous else 0

        records: list[dict[str, Any]] | None = None
        for attempt in range(1, max(1, attempts) + 1):
            records = _query_osv(package, timeout)
            # Retry a hard failure, and retry an empty answer only when we
            # have reason to expect content. Retrying every genuine zero
            # would triple the runtime for no information.
            if records is None or (not records and had_before):
                if attempt < attempts:
                    time.sleep(pause * attempt)
                    continue
            break

        if records is None:
            db.failures.append(package)
            if progress:
                progress(i, package, "FAILED after retries")
            continue
        if not records and had_before:
            db.failures.append(package)
            if progress:
                progress(i, package,
                         f"EMPTY but previously had {had_before}; treating as a failure")
            continue

        found = 0
        for record in records:
            vuln = parse_osv_record(record, package, "npm")
            if vuln is not None:
                db.index.setdefault(("npm", package.lower()), []).append(vuln)
                found += 1
        if progress:
            progress(i, package, f"{found} advisories")
    return db


# --------------------------------------------------------------------------
# NIST NVD: the primary source.
# --------------------------------------------------------------------------

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

#: Required by NVD's fair-use terms wherever their data is presented.
NVD_NOTICE = ("This product uses data from the NVD API but is not endorsed "
              "or certified by the NVD.")

#: (ecosystem, package as this tool detects it, CPE 2.3 prefix).
#:
#: Every prefix was verified LIVE against the API on 2026-08-02, with the
#: CVE count seen at verification in the comment. Verification is the whole
#: game: NVD answers a wrong CPE with zero results, and zero results is
#: exactly what a clean product returns, so an unverified guess ships a
#: coverage gap disguised as good news. Candidates that returned zero
#: (vuejs:vue, backbone.js_project:backbone.js, wp_media:wp_rocket) were
#: DROPPED, not kept on faith.
#:
#: Some products appear under two of our package names because detection
#: sees different slugs for the same software (wpforms vs wpforms-lite).
NVD_PRODUCTS: tuple[tuple[str, str, str], ...] = (
    # npm -- the libraries Lighthouse names by coordinate
    ("npm", "jquery",          "cpe:2.3:a:jquery:jquery"),                    # 11
    ("npm", "jquery-ui",       "cpe:2.3:a:jqueryui:jquery_ui"),               # 7
    ("npm", "bootstrap",       "cpe:2.3:a:getbootstrap:bootstrap"),           # 7
    ("npm", "lodash",          "cpe:2.3:a:lodash:lodash"),                    # 10
    ("npm", "moment",          "cpe:2.3:a:momentjs:moment"),                  # 4
    ("npm", "angular",         "cpe:2.3:a:angularjs:angular.js"),             # 1
    ("npm", "handlebars",      "cpe:2.3:a:handlebars.js_project:handlebars.js"),  # 2
    ("npm", "react",           "cpe:2.3:a:facebook:react"),                   # 6
    ("npm", "next",            "cpe:2.3:a:vercel:next.js"),                   # 56
    ("npm", "socket.io",       "cpe:2.3:a:socket:socket.io"),                 # 2
    ("npm", "underscore",      "cpe:2.3:a:underscorejs:underscore"),          # 2
    ("npm", "highcharts",      "cpe:2.3:a:highcharts:highcharts"),            # 2
    ("npm", "dojo",            "cpe:2.3:a:linuxfoundation:dojo"),             # 2
    ("npm", "yui",             "cpe:2.3:a:yahoo:yui"),                        # 12
    ("npm", "knockout",        "cpe:2.3:a:knockoutjs:knockout"),              # 1
    # WordPress core -- the coverage no free WP-specific source could offer
    ("wordpress", "wordpress", "cpe:2.3:a:wordpress:wordpress"),              # 583
    # WordPress plugins, keyed by the asset-path slug detection produces
    ("wordpress-plugin", "gutenberg",        "cpe:2.3:a:wordpress:gutenberg"),         # 1
    ("wordpress-plugin", "elementor",        "cpe:2.3:a:elementor:website_builder"),   # 37
    ("wordpress-plugin", "contact-form-7",   "cpe:2.3:a:rocklobster:contact_form_7"),  # 9
    ("wordpress-plugin", "woocommerce",      "cpe:2.3:a:woocommerce:woocommerce"),     # 16
    ("wordpress-plugin", "wordpress-seo",    "cpe:2.3:a:yoast:yoast_seo"),             # 10
    ("wordpress-plugin", "jetpack",          "cpe:2.3:a:automattic:jetpack"),          # 16
    ("wordpress-plugin", "akismet",          "cpe:2.3:a:automattic:akismet"),          # 1
    ("wordpress-plugin", "wpforms",          "cpe:2.3:a:wpforms:wpforms"),             # 9
    ("wordpress-plugin", "wpforms-lite",     "cpe:2.3:a:wpforms:wpforms"),             # 9
    ("wordpress-plugin", "wp-super-cache",   "cpe:2.3:a:automattic:wp_super_cache"),   # 6
    ("wordpress-plugin", "w3-total-cache",   "cpe:2.3:a:boldgrid:w3_total_cache"),     # 14
    ("wordpress-plugin", "litespeed-cache",  "cpe:2.3:a:litespeedtech:litespeed_cache"),  # 15
)


def _nvd_severity(item: dict[str, Any]) -> str:
    """NIST's own severity, newest CVSS version first, Primary source first.

    NVD publishes several CVSS generations side by side and old CVEs only
    have v2. The mapping is direct because NVD already speaks this
    project's vocabulary (LOW/MEDIUM/HIGH/CRITICAL); v2 has no CRITICAL, so
    a v2-only record tops out at HIGH, which is the honest reading of a
    scale that never defined anything higher.
    """
    metrics = item.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = entry.get("cvssData") or {}
        word = str(data.get("baseSeverity") or entry.get("baseSeverity") or "").upper()
        rank = SEVERITY_RANK.get(word, 0)
        if rank:
            return RANK_SEVERITY[rank]
    return "info"


def parse_nvd_record(item: dict[str, Any], package: str, ecosystem: str,
                     cpe_prefix: str) -> Vulnerability | None:
    """One CVE from the API into this project's record, or None.

    Version bounds come from the ``cpeMatch`` entries under our prefix:
    an exact version in the criteria's version field, or the
    versionStart/End bounds when the field is a wildcard. A criteria of
    ``-`` (NVD for "version unknown") with no bounds is skipped: it would
    match every version of the product forever, and jQuery's CVE-2007-2379
    would then be reported against jQuery 3.7. Dropping it trades a
    2007-era false negative for not crying wolf on every modern site,
    which is the trade a client-facing report has to make.
    """
    ranges: list[AffectedRange] = []
    versions: list[str] = []
    prefix = cpe_prefix.rstrip(":") + ":"
    for config in item.get("configurations") or []:
        for node in config.get("nodes") or []:
            for cm in node.get("cpeMatch") or []:
                if not cm.get("vulnerable"):
                    continue
                criteria = str(cm.get("criteria", ""))
                if not criteria.startswith(prefix):
                    continue
                exact = criteria[len(prefix):].split(":", 1)[0]
                start_inc = parse_version(cm.get("versionStartIncluding"))
                start_exc = parse_version(cm.get("versionStartExcluding"))
                end_exc = parse_version(cm.get("versionEndExcluding"))
                end_inc = parse_version(cm.get("versionEndIncluding"))
                if exact not in ("*", "-"):
                    if parse_version(exact) is not None:
                        versions.append(exact)
                    continue
                if start_inc or start_exc or end_exc or end_inc:
                    # startExcluding is rare enough that treating it as
                    # inclusive is the least-wrong option: the alternative
                    # (no lower bound) widens the range to every release
                    # since the beginning.
                    ranges.append(AffectedRange(
                        introduced=start_inc or start_exc,
                        fixed=end_exc, last_affected=end_inc))
                # exact == "-" with no bounds: skipped, see docstring.
    if not ranges and not versions:
        return None

    descriptions = item.get("descriptions") or []
    summary = next((d.get("value", "") for d in descriptions
                    if d.get("lang") == "en"), "")
    return Vulnerability(
        id=item["id"], package=package, ecosystem=ecosystem,
        summary=" ".join(summary.split())[:400],
        severity=_nvd_severity(item),
        ranges=tuple(ranges), versions=tuple(versions),
        reference=f"https://nvd.nist.gov/vuln/detail/{item['id']}",
    )


def _nvd_get(params: dict[str, str], timeout: float,
             api_key: str | None) -> dict[str, Any] | None:
    """One API request. None means it failed; a dict is the parsed page."""
    import urllib.error
    import urllib.parse
    import urllib.request

    url = f"{NVD_API_URL}?{urllib.parse.urlencode(params)}&noRejected"
    headers = {"User-Agent": "SLAP"}
    if api_key:
        headers["apiKey"] = api_key
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read())
    except (urllib.error.URLError, ValueError, OSError):
        return None


def build_from_nvd(products: Iterable[tuple[str, str, str]] = NVD_PRODUCTS, *,
                   timeout: float = 60.0,
                   previous: "VulnDatabase | None" = None,
                   attempts: int = 3,
                   api_key: str | None = None,
                   progress=None,
                   fetch=_nvd_get) -> VulnDatabase:
    """Query NVD per verified CPE and assemble a database. Network required.

    Efficiency is rate-limit shaped: NVD allows 5 requests per rolling 30
    seconds without a key and 50 with one (free, instant, via the
    ``NVD_API_KEY`` environment variable or ``api_key``). The pause between
    requests is derived from that; ``resultsPerPage=2000`` keeps almost
    every product to a single request, and ``noRejected`` stops rejected
    CVEs from being fetched only to be thrown away.

    Carries the guards the OSV builder learned the hard way: a product that
    fails after retries lands in ``failures`` for the caller to refuse on,
    and one that suddenly returns nothing where the previous database had
    entries is treated as a failed query wearing a success, because NVD's
    rate limiter answers over-eager clients with errors that an incautious
    loop records as "no vulnerabilities".
    """
    import os
    import time

    if api_key is None:
        api_key = os.environ.get("NVD_API_KEY") or None
    pause = 0.8 if api_key else 6.2

    db = VulnDatabase(
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )
    ecosystems: dict[str, set[str]] = {}
    first_request = True

    for i, (ecosystem, package, cpe) in enumerate(products, 1):
        ecosystems.setdefault(ecosystem, set()).add(package.lower())
        had_before = len(previous.index.get((ecosystem, package.lower()), [])) \
            if previous else 0

        collected: list[dict[str, Any]] | None = None
        for attempt in range(1, max(1, attempts) + 1):
            if not first_request:
                time.sleep(pause * attempt if attempt > 1 else pause)
            first_request = False

            items: list[dict[str, Any]] = []
            start, total = 0, None
            while total is None or start < total:
                page = fetch({"virtualMatchString": cpe,
                              "resultsPerPage": "2000",
                              "startIndex": str(start)}, timeout, api_key)
                if page is None:
                    items = None
                    break
                total = int(page.get("totalResults") or 0)
                got = [w.get("cve") or {} for w in page.get("vulnerabilities") or []]
                items.extend(got)
                start += max(1, len(got)) if got else 2000
            collected = items
            if collected is None or (not collected and had_before):
                continue                      # retry with a longer pause
            break

        if collected is None:
            db.failures.append(f"{ecosystem}:{package}")
            if progress:
                progress(i, package, "FAILED after retries")
            continue
        if not collected and had_before:
            db.failures.append(f"{ecosystem}:{package}")
            if progress:
                progress(i, package,
                         f"EMPTY but previously had {had_before}; treating as a failure")
            continue

        parsed = [v for v in (parse_nvd_record(item, package, ecosystem, cpe)
                              for item in collected) if v is not None]
        # NVD keys by CVE already, but two of OUR package names can share a
        # CPE, and one CVE can carry several cpeMatch blocks; dedupe per
        # package so counts stay honest.
        for vuln in deduplicate(parsed):
            db.index.setdefault((ecosystem, package.lower()), []).append(vuln)
        if progress:
            progress(i, package, f"{len(parsed)} CVE(s)")

    for ecosystem, packages in ecosystems.items():
        db.sources[ecosystem] = "NIST NVD"
        db.covered[ecosystem] = tuple(sorted(packages))
    return db
