"""What software a page runs, and which known vulnerabilities affect it.

**The binding constraint is version detection, not the vulnerability
database.** The database is a solved problem. Knowing from the outside that a
site runs Contact Form 7 *5.8.1* rather than *5.9.x* is not, and a wrong
version produces a confident, specific, wrong CVE in a client-facing PDF,
which is the worst thing this project can print.

So every component carries **how its version was determined**, and that
travels with it all the way to the report:

``observed``
    A browser executed the page and read the version out of the running
    library (Lighthouse's ``js-libraries`` audit), or the software announced
    itself in a generator tag. Trustworthy enough to name a CVE.

``inferred``
    Read from a ``?ver=`` query string on an asset URL. This is the standard
    technique for WordPress plugins and it is wrong often enough to matter:
    the value is frequently the WordPress *core* version rather than the
    plugin's, a cache-buster timestamp, or a content hash, and optimisers
    (including WP Rocket, which SLAP specifically targets) strip or rewrite
    it. An inferred match is reported as *possible*, at a lower severity, and
    says how it was determined.

No version means no component. Not "probably fine" — silence. The report must
never imply a check happened that did not.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qs, urlsplit

from ..schema import Observation, Scope, obs
from ..vulndb import VulnDatabase, Vulnerability, parse_version
from .base import PageContext

OBSERVED = "observed"
INFERRED = "inferred"

#: WordPress serves plugin and theme assets from fixed paths. The slug is the
#: directory name, which is also the identifier every WordPress vulnerability
#: database keys on.
_WP_ASSET_RE = re.compile(
    r"/wp-content/(?P<kind>plugins|themes)/(?P<slug>[a-z0-9][a-z0-9._-]*)/", re.I)
_SRC_RE = re.compile(
    r"""\b(?:src|href)\s*=\s*["']([^"'>]+)""", re.I)
_WP_CORE_RE = re.compile(r"WordPress\s+([\d.]+)", re.I)


@dataclass(slots=True, frozen=True)
class Component:
    name: str
    version: str
    confidence: str                 # observed | inferred
    ecosystem: str                  # npm | wordpress | wordpress-plugin | ...
    package: str                    # the coordinate the database is keyed on
    evidence: str = ""              # how the version was determined, in words

    @property
    def label(self) -> str:
        return f"{self.name} {self.version}"


# --------------------------------------------------------------------------
# Detection. Pure functions over strings; no network, no browser.
# --------------------------------------------------------------------------

def components_from_lighthouse(libraries: list[dict]) -> list[Component]:
    """From the `js-libraries` rows: a real browser reading a running library.

    Lighthouse 13 emits ``{"name": "jQuery", "version": "3.4.1", "npm":
    "jquery"}``. The npm coordinate is the part that makes this worth
    building on: it maps straight onto OSV's npm ecosystem with no name
    guessing, so the highest-confidence source is also the one with the
    cleanest database behind it.
    """
    out: list[Component] = []
    for item in libraries or []:
        name = str(item.get("name") or "").strip()
        version = str(item.get("version") or "").strip()
        package = str(item.get("npm") or "").strip()
        if not name or not version or not package:
            continue
        if parse_version(version) is None:
            continue
        out.append(Component(
            name=name, version=version, confidence=OBSERVED,
            ecosystem="npm", package=package,
            evidence="read from the running library by the browser",
        ))
    return out


def wordpress_core_version(html: str) -> str | None:
    """From the generator meta tag. Announced by the software, so observed.

    Frequently stripped by security plugins, in which case there is no
    version and therefore no finding.
    """
    for match in re.finditer(
            r"""<meta[^>]+name=["']generator["'][^>]*>""", html, re.I):
        content = re.search(r"""content=["']([^"']+)""", match.group(0), re.I)
        if not content:
            continue
        version = _WP_CORE_RE.search(content.group(1))
        if version and parse_version(version.group(1)):
            return version.group(1)
    return None


def wordpress_assets(html: str) -> list[Component]:
    """Plugins and themes, with versions inferred from `?ver=`.

    This is the dangerous one, and the checks below are what make it
    publishable rather than reckless:

    * a `?ver=` that does not parse as a version (timestamp, hash, "latest")
      yields a component with no version, which yields no finding;
    * a `?ver=` equal to the WordPress core version found on the same page is
      discarded, because WordPress defaults `?ver=` to the core version for
      any asset that does not set its own, and treating that as the plugin's
      version means matching every plugin on the site against core's number;
    * the highest version seen for a slug wins, since a plugin can enqueue
      several assets and the stale one is the misleading one.
    """
    core = wordpress_core_version(html)
    best: dict[tuple[str, str], str] = {}
    for match in _SRC_RE.finditer(html):
        url = match.group(1)
        asset = _WP_ASSET_RE.search(url)
        if not asset:
            continue
        kind = asset.group("kind").lower()
        slug = asset.group("slug").lower()
        query = parse_qs(urlsplit(url).query)
        raw = (query.get("ver") or [""])[0]
        parsed = parse_version(raw)
        if parsed is None:
            continue
        if core and raw == core:
            # WordPress's own default, not this plugin's version.
            continue
        key = (kind, slug)
        current = parse_version(best.get(key, ""))
        if current is None or parsed > current:
            best[key] = raw

    out: list[Component] = []
    for (kind, slug), version in sorted(best.items()):
        singular = "plugin" if kind == "plugins" else "theme"
        out.append(Component(
            name=f"{slug} ({singular})", version=version, confidence=INFERRED,
            ecosystem=f"wordpress-{singular}", package=slug,
            evidence=f"inferred from a ?ver= query string on a {singular} asset",
        ))
    return out


def detect(html: str,
           libraries: list[dict] | None = None) -> list[Component]:
    """Every component this page reveals, most trustworthy first."""
    found: list[Component] = []
    if libraries:
        found.extend(components_from_lighthouse(libraries))

    core = wordpress_core_version(html)
    if core:
        found.append(Component(
            name="WordPress", version=core, confidence=OBSERVED,
            ecosystem="wordpress", package="wordpress",
            evidence="announced in the generator meta tag",
        ))
    found.extend(wordpress_assets(html))

    # Stable order: observed before inferred, then by name. Two runs of the
    # same site must list components in the same order or a diff between
    # reports is unreadable.
    return sorted(found, key=lambda c: (c.confidence != OBSERVED, c.name.lower()))


# --------------------------------------------------------------------------
# Matching
# --------------------------------------------------------------------------

@dataclass(slots=True)
class Match:
    component: Component
    vulnerability: Vulnerability

    @property
    def text(self) -> str:
        return (f"{self.component.label}: {self.vulnerability.label} "
                f"({self.vulnerability.severity})")


def match_all(components: list[Component],
              db: VulnDatabase) -> tuple[list[Match], list[Component]]:
    """Returns (matches, components in ecosystems this database cannot check).

    The second half of that tuple is the point. "No vulnerabilities found in
    your plugins" and "your plugins were not checked" are different sentences,
    and a tool with no WordPress source configured can only honestly say the
    second. Returning the unchecked list forces the caller to decide which one
    to print rather than defaulting to silence, which always reads as the
    first.
    """
    matches: list[Match] = []
    unchecked: list[Component] = []
    for component in components:
        # Package-level, not just ecosystem-level: an NVD database covers
        # exactly its verified CPE map, so "wordpress-plugin" being a
        # source does not mean THIS plugin was checked.
        if not db.covers(component.ecosystem, component.package):
            unchecked.append(component)
            continue
        for vulnerability in db.query(component.ecosystem, component.package,
                                      component.version):
            matches.append(Match(component, vulnerability))
    return matches, unchecked


#: An inferred version can never produce more than this, whatever the
#: advisory says. A CVSS-critical advisory matched against a number scraped
#: from a query string is still a guess, and printing "CRITICAL" next to a
#: guess in a client report spends credibility that is hard to earn back.
INFERRED_SEVERITY_CEILING = "medium"

_ORDER = ["info", "low", "medium", "high", "critical"]


def effective_severity(match: Match) -> str:
    if match.component.confidence == OBSERVED:
        return match.vulnerability.severity
    ceiling = _ORDER.index(INFERRED_SEVERITY_CEILING)
    return _ORDER[min(_ORDER.index(match.vulnerability.severity), ceiling)]


def _identifiers(matches: list[Match], limit: int = 4) -> str:
    """A short, de-duplicated identifier list for a finding title."""
    seen: list[str] = []
    for match in matches:
        label = match.vulnerability.label
        if label not in seen:
            seen.append(label)
    head = ", ".join(seen[:limit])
    return head + (f" and {len(seen) - limit} more" if len(seen) > limit else "")


class ComponentCollector:
    """Detects components, then matches them against the local database.

    Runs **last**, after the browser pass, because the highest-confidence
    source of versions is the Lighthouse audit and it does not exist until
    Lighthouse has run. On a page audited at ``light`` depth it still works,
    from the markup alone, with correspondingly lower confidence.
    """

    name = "components"
    scope = Scope.PAGE
    #: Read by `core.split_pipeline`: this collector consumes what the others
    #: produce, so it cannot run beside them.
    runs_last = True

    def __init__(self, db: VulnDatabase | None = None) -> None:
        self.db = db or VulnDatabase()

    async def collect(self, ctx: PageContext) -> list[Observation]:
        document = ctx.document
        if document is None:
            return []

        lighthouse = ctx.extras.get("lighthouse")
        libraries = getattr(lighthouse, "libraries", None) if lighthouse else None
        components = detect(document.text, libraries)
        matches, unchecked = match_all(components, self.db)

        out: list[Observation] = [
            obs("component.count", len(components)),
            obs("component.observed_count",
                sum(1 for c in components if c.confidence == OBSERVED)),
            obs("component.inferred_count",
                sum(1 for c in components if c.confidence == INFERRED)),
        ]
        if components:
            out.append(obs("component.detected", "; ".join(
                f"{c.label} [{c.confidence}]" for c in components[:20])))

        confirmed = [m for m in matches if m.component.confidence == OBSERVED]
        possible = [m for m in matches if m.component.confidence == INFERRED]

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for match in confirmed:
            severity = effective_severity(match)
            if severity in counts:
                counts[severity] += 1

        out.extend([
            obs("vuln.confirmed_count", len(confirmed)),
            obs("vuln.confirmed_critical", counts["critical"]),
            obs("vuln.confirmed_high", counts["high"]),
            obs("vuln.confirmed_medium", counts["medium"] + counts["low"]),
            obs("vuln.possible_count", len(possible)),
            # Components in an ecosystem with no configured source. Emitted
            # even when zero, because the report needs to distinguish "nothing
            # to check" from "could not check".
            obs("vuln.unchecked_count", len(unchecked)),
        ])
        if confirmed:
            out.append(obs("vuln.confirmed_detail",
                           "; ".join(m.text for m in confirmed[:12])))
            out.append(obs("vuln.confirmed_ids", _identifiers(confirmed)))
        if possible:
            out.append(obs("vuln.possible_detail",
                           "; ".join(m.text for m in possible[:12])))
            out.append(obs("vuln.possible_ids", _identifiers(possible)))
        if unchecked:
            # Named per component, not per ecosystem: with package-level
            # coverage, "wordpress-plugin" can be a configured source while
            # THIS plugin is outside the verified CPE map, and the report
            # has to name what was skipped, not indict the whole ecosystem.
            out.append(obs("vuln.unchecked_detail", ", ".join(
                sorted({f"{c.name}" for c in unchecked}))))
        return out
