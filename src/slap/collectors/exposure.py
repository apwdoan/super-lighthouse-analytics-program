"""Probing for endpoints that should not be reachable.

Different in kind from everything else in this pipeline. Every other collector
requests pages the site publishes; this one requests things it hopes are not
there. That difference drives every decision in this file.

**Off by default, and authorised per site, not globally.** A global "enable
probing" flag gets switched on once and then silently applies to the next
client, who never agreed to it. Authorisation is recorded against the site row
with a timestamp and a name, and the report prints it.

**A dozen paths, not a wordlist.** This is a hygiene check for things that
should never be served, not a penetration test. It should look unremarkable in
the target's access log.

**The body is never stored.** A response prefix is read to tell a real file
from a soft 404 and then discarded; nothing from these paths reaches the
database, the gzipped artifacts, or the log. Pulling a client's `.env` into a
SQLite file that later gets zipped up and emailed around creates a custody
problem that did not exist before the audit.

**A WAF returns 200 with a block page, and plenty of sites return 200 for
everything.** Status codes alone would hand the first client behind Cloudflare
a page of false criticals, so every probe is judged against a control request
for a path that certainly does not exist.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import secrets
from dataclasses import dataclass, field

import httpx

from ..schema import Observation, Scope, obs
from .base import PageContext

#: How much of a response to read for classification. Enough to tell a git
#: config from an HTML error page, small enough that a large file is not
#: pulled across the wire. Never stored, never logged.
_SNIFF_BYTES = 512

#: Fingerprints that identify a path as genuinely present rather than as a
#: prettified 404 or a WAF page. Checked against the sniffed prefix only.
_SIGNATURES: dict[str, tuple[str, ...]] = {
    "git": ("[core]", "repositoryformatversion"),
    "env": ("APP_KEY=", "DB_PASSWORD=", "SECRET", "APP_ENV=", "DB_HOST="),
    "sql": ("CREATE TABLE", "INSERT INTO", "-- MySQL dump", "DROP TABLE"),
    "phpconfig": ("<?php", "DB_NAME", "DB_PASSWORD"),
    "svn": ("dir", "svn:"),
    "dsstore": ("Bud1",),
    "status": ("Apache Server Status", "Total Accesses"),
    "phpinfo": ("phpinfo()", "PHP Version"),
    "json": ("[{", '{"'),
    "xmlrpc": ("XML-RPC server accepts POST requests only",),
    "log": ("PHP Notice", "PHP Warning", "PHP Fatal", "Stack trace"),
}

#: Anything a WAF or bot-wall says instead of serving the file. Present in the
#: body of a 200 response, which is why status alone cannot be trusted.
_BLOCKPAGE_MARKERS = (
    "cloudflare", "attention required", "access denied", "request blocked",
    "sucuri website firewall", "wordfence", "security check",
    "are you a robot", "captcha", "incapsula", "mod_security",
    "your request has been blocked", "ray id",
)


@dataclass(slots=True, frozen=True)
class Probe:
    path: str
    category: str          # secrets | vcs | info | wp_surface
    signature: str         # key into _SIGNATURES
    label: str


#: Fifteen paths. Every one of them is a file that is never meant to be served
#: by a web server, or an endpoint whose exposure has a well-understood cost.
PROBES: tuple[Probe, ...] = (
    Probe("/.git/config", "vcs", "git", "Git repository metadata"),
    Probe("/.svn/entries", "vcs", "svn", "Subversion metadata"),
    Probe("/.env", "secrets", "env", "Environment file"),
    Probe("/.env.local", "secrets", "env", "Local environment file"),
    Probe("/wp-config.php.bak", "secrets", "phpconfig", "WordPress config backup"),
    Probe("/wp-config.php.save", "secrets", "phpconfig", "WordPress config backup"),
    Probe("/wp-config.php~", "secrets", "phpconfig", "WordPress config backup"),
    Probe("/backup.sql", "secrets", "sql", "Database dump"),
    Probe("/database.sql", "secrets", "sql", "Database dump"),
    Probe("/dump.sql", "secrets", "sql", "Database dump"),
    Probe("/server-status", "info", "status", "Apache server status page"),
    Probe("/phpinfo.php", "info", "phpinfo", "phpinfo() output"),
    Probe("/.DS_Store", "info", "dsstore", "macOS directory index"),
    Probe("/wp-content/debug.log", "info", "log", "WordPress debug log"),
    Probe("/xmlrpc.php", "wp_surface", "xmlrpc", "WordPress XML-RPC endpoint"),
    Probe("/wp-json/wp/v2/users", "wp_surface", "json", "WordPress user enumeration"),
)


@dataclass(slots=True)
class Control:
    """How this origin answers a request for something that is not there."""

    status: int = 404
    length: int = 0
    digest: str = ""
    soft_404: bool = False          # returns 2xx for nonsense paths
    blocked: bool = False           # a WAF answered

    def resembles(self, status: int, length: int, digest: str) -> bool:
        """True when a response is indistinguishable from 'not found' here.

        Length within 10% is the useful part: a templated 404 page varies by
        the path echoed back into it, so identical digests are the exception
        and near-identical sizes are the rule.
        """
        if digest and digest == self.digest:
            return True
        if status != self.status:
            return False
        if self.length and length:
            return abs(length - self.length) <= max(64, self.length * 0.1)
        return True


@dataclass(slots=True)
class Finding:
    probe: Probe
    status: int
    length: int
    confirmed: bool                 # content matched the expected signature
    note: str = ""


@dataclass(slots=True)
class ExposureResult:
    control: Control = field(default_factory=Control)
    findings: list[Finding] = field(default_factory=list)
    checked: int = 0
    errors: list[str] = field(default_factory=list)


def looks_like_a_block_page(body: str) -> bool:
    lowered = body.lower()
    return any(marker in lowered for marker in _BLOCKPAGE_MARKERS)


def matches_signature(body: str, signature: str) -> bool:
    """Whether the body really is the thing the path implies.

    A site that serves its homepage for every unknown path returns 200 with
    HTML for `/.env`. Without this check that is a critical finding, and it is
    wrong, and it is the first thing a client would disprove.
    """
    needles = _SIGNATURES.get(signature, ())
    if not needles:
        return False
    if looks_like_a_block_page(body):
        return False
    return any(needle.lower() in body.lower() for needle in needles)


async def _fetch(client: httpx.AsyncClient, url: str, user_agent: str,
                 timeout: float) -> tuple[int, int, str, str] | None:
    """Returns (status, length, digest, sniffed prefix), or None on error.

    The prefix is returned for classification and is the caller's
    responsibility to drop. It is never persisted.
    """
    try:
        async with client.stream("GET", url, timeout=timeout,
                                 follow_redirects=False,
                                 headers={"User-Agent": user_agent}) as response:
            chunk = b""
            async for part in response.aiter_bytes():
                chunk += part
                if len(chunk) >= _SNIFF_BYTES:
                    break
            declared = response.headers.get("content-length")
            length = int(declared) if declared and declared.isdigit() else len(chunk)
            prefix = chunk[:_SNIFF_BYTES]
            digest = hashlib.sha256(prefix).hexdigest()[:16]
            return response.status_code, length, digest, prefix.decode(
                "utf-8", "ignore")
    except (httpx.HTTPError, ValueError, OSError):
        return None


async def calibrate(client: httpx.AsyncClient, origin: str, user_agent: str,
                    timeout: float) -> Control:
    """Learn how this origin says "not found", using paths that cannot exist.

    Two random paths rather than one: a site that echoes the path into its 404
    page produces two different bodies, and comparing them is how you tell a
    templated 404 from a static one. Without this the digest check would only
    ever fire on static error pages.
    """
    control = Control()
    samples = []
    for _ in range(2):
        nonce = secrets.token_hex(8)
        result = await _fetch(client, f"{origin}/slap-probe-{nonce}",
                              user_agent, timeout)
        if result:
            samples.append(result)
    if not samples:
        return control

    status, length, digest, body = samples[0]
    control.status = status
    control.length = length
    control.blocked = looks_like_a_block_page(body)
    # Only keep the digest when the error page is byte-identical across two
    # different nonsense paths. A templated page would make it useless and,
    # worse, would make every probe look distinct from the control.
    if len(samples) == 2 and samples[0][2] == samples[1][2]:
        control.digest = digest
    control.soft_404 = 200 <= status < 300
    return control


class ExposureCollector:
    """Probes a fixed list of paths that should never be served.

    Origin-scoped: the paths are properties of the server, not of a page, so
    this runs once per site however many pages are audited. Probing them
    twenty times would be twenty times the traffic in the client's log for
    exactly the same answer, which is both rude and slower.
    """

    name = "exposure"
    scope = Scope.ORIGIN

    def __init__(self, *, enabled: bool = False, rate_per_second: float = 2.0,
                 authorised_hosts: frozenset[str] | None = None) -> None:
        self.enabled = enabled
        self.delay = 1.0 / rate_per_second if rate_per_second > 0 else 0.0
        self.authorised_hosts = authorised_hosts or frozenset()

    def authorised_for(self, hostname: str) -> bool:
        return hostname.lower() in self.authorised_hosts

    async def collect(self, ctx: PageContext) -> list[Observation]:
        if not self.enabled:
            return []
        if not self.authorised_for(ctx.hostname):
            # Emitted rather than silent. A report that simply omits the
            # section looks identical to one where everything passed.
            return [obs("exposure.authorised", False)]

        result = await self.probe(ctx)
        counts = {"secrets": 0, "vcs": 0, "info": 0, "wp_surface": 0}
        for finding in result.findings:
            counts[finding.probe.category] += 1

        out = [
            obs("exposure.authorised", True),
            obs("exposure.checked", result.checked),
            obs("exposure.found_count", len(result.findings)),
            obs("exposure.secrets_count", counts["secrets"]),
            obs("exposure.vcs_count", counts["vcs"]),
            obs("exposure.info_count", counts["info"]),
            obs("exposure.wp_surface_count", counts["wp_surface"]),
            # Recorded so the appendix can explain how "not found" was
            # decided. A probe run against a soft-404 site is much weaker
            # evidence and the report should be able to say so.
            obs("exposure.control_status", result.control.status),
            obs("exposure.soft_404", result.control.soft_404),
            obs("exposure.waf_detected", result.control.blocked),
        ]
        if result.findings:
            out.append(obs("exposure.paths", ", ".join(
                f"{f.probe.path} ({f.status})" for f in result.findings)))
            # And per category, so each rule describes only its own findings.
            for category, key in (("secrets", "exposure.secrets_paths"),
                                  ("vcs", "exposure.vcs_paths"),
                                  ("info", "exposure.info_paths"),
                                  ("wp_surface", "exposure.wp_surface_paths")):
                paths = [f"{f.probe.path} ({f.status})" for f in result.findings
                         if f.probe.category == category]
                if paths:
                    out.append(obs(key, ", ".join(paths)))
        return out

    async def probe(self, ctx: PageContext) -> ExposureResult:
        client: httpx.AsyncClient = ctx.client
        cfg = ctx.config
        origin = ctx.origin
        result = ExposureResult()
        result.control = await calibrate(client, origin, cfg.user_agent,
                                         cfg.timeout)

        if result.control.blocked:
            # A WAF is answering. Continuing would produce a list of
            # "findings" that are all the same block page.
            result.errors.append("a firewall answered the control request")
            return result

        for probe in PROBES:
            if self.delay:
                await asyncio.sleep(self.delay)
            fetched = await _fetch(client, f"{origin}{probe.path}",
                                   cfg.user_agent, cfg.timeout)
            result.checked += 1
            if fetched is None:
                continue
            status, length, digest, body = fetched

            if not (200 <= status < 300):
                # 403 is interesting: on a server that 404s missing files, a
                # 403 usually means the file exists and something in front of
                # it is refusing. Recorded, but never as confirmed, because
                # the content that would confirm it is exactly what is being
                # withheld.
                if status == 403 and result.control.status == 404:
                    result.findings.append(Finding(
                        probe, status, length, confirmed=False,
                        note="forbidden rather than missing, which usually "
                             "means the file is there"))
                continue

            if result.control.resembles(status, length, digest):
                continue                      # this origin's way of saying 404
            if looks_like_a_block_page(body):
                continue
            if not matches_signature(body, probe.signature):
                # 200, not the control, and not the expected content. Almost
                # always a soft 404 serving the homepage. Not a finding.
                continue

            result.findings.append(Finding(probe, status, length, confirmed=True))
        # `body` goes out of scope here and is never written anywhere.
        return result
