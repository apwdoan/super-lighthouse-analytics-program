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

``npm`` — OSV.dev. No key, no auth, no licence obstacle, and it covers every
JavaScript library Lighthouse can identify by npm coordinate.

``wordpress`` — deliberately **not bundled**. WPScan's terms forbid exactly
this ("permanent storage of our vulnerability data is not permitted", "API
vulnerability data caching is not permitted", commercial integration requires
an Enterprise account). Wordfence's feed was free and unauthenticated when
this was designed; as of 2026-08-02 its v2 endpoints return 410 Gone and v3
returns 401, so it needs credentials this project does not ship. The adapter
is here and takes a key from config. Until one is configured, WordPress
components are inventoried and **not** matched, and the report says that
rather than implying a clean bill of health.
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

    def covers(self, ecosystem: str) -> bool:
        """Whether this database can speak to an ecosystem at all.

        The distinction that keeps the report honest: "no vulnerabilities
        found in your WordPress plugins" and "WordPress plugins were not
        checked" are different sentences, and only one of them is true when
        no WordPress source is configured.
        """
        return ecosystem in self.sources

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
                 sources=dict(raw.get("sources") or {}))
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


def default_db_path() -> Path:
    """Beside the package, so a PyInstaller bundle carries it as data."""
    return Path(__file__).parent / "data" / "vulndb.json"


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


def build_from_osv(packages: Iterable[str] = DEFAULT_NPM_PACKAGES, *,
                   timeout: float = 30.0,
                   progress=None) -> VulnDatabase:
    """Query OSV for each package and assemble a database. Network required.

    Queried per package rather than by downloading the 213MB npm export,
    because the export is 99.9% packages this tool can never detect.
    """
    import urllib.error
    import urllib.request

    db = VulnDatabase(
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        sources={"npm": "OSV.dev"},
    )
    for i, package in enumerate(packages, 1):
        if package.startswith("http"):      # the two junk entries upstream
            continue
        body = json.dumps({"package": {"name": package, "ecosystem": "npm"}}).encode()
        request = urllib.request.Request(
            OSV_QUERY_URL, data=body,
            headers={"Content-Type": "application/json", "User-Agent": "SLAP"})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = json.loads(response.read())
        except (urllib.error.URLError, ValueError, OSError) as exc:
            if progress:
                progress(i, package, f"failed: {type(exc).__name__}")
            continue
        found = 0
        for record in payload.get("vulns", []) or []:
            vuln = parse_osv_record(record, package, "npm")
            if vuln is not None:
                db.index.setdefault(("npm", package.lower()), []).append(vuln)
                found += 1
        if progress:
            progress(i, package, f"{found} advisories")
    return db
