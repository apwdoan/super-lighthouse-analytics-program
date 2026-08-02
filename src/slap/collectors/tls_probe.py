"""TLS collector: certificate validity, expiry, protocol, cipher.

Runs a real handshake rather than trusting what the HTTP client happened
to negotiate, because the two questions a client report has to answer are
"does it validate" and "when does it expire", and a failed validation is
itself the finding. So we handshake twice when needed: once verifying, and
if that fails, once unverified purely to read the certificate we could not
trust.
"""

from __future__ import annotations

import asyncio
import ssl
from datetime import datetime, timezone
from typing import Any

import httpx

from ..schema import Observation, Scope, Source, obs
from .base import PageContext


def flatten_name(rdn_sequence: Any) -> str:
    """Flatten ``getpeercert()`` issuer/subject tuples into a readable string.

    Prefers organizationName, falls back to commonName, then anything.
    """
    if not rdn_sequence:
        return ""
    fields: dict[str, str] = {}
    for rdn in rdn_sequence:
        for item in rdn:
            if isinstance(item, (tuple, list)) and len(item) == 2:
                fields.setdefault(str(item[0]), str(item[1]))
    for key in ("organizationName", "commonName", "organizationalUnitName"):
        if key in fields:
            return fields[key]
    return ", ".join(f"{k}={v}" for k, v in fields.items())


def days_to_expiry(not_after: str, *, now: datetime | None = None) -> float | None:
    """Days from ``now`` until an OpenSSL ``notAfter`` timestamp."""
    if not not_after:
        return None
    try:
        expires_at = datetime.fromtimestamp(
            ssl.cert_time_to_seconds(not_after), tz=timezone.utc
        )
    except (ValueError, TypeError):
        return None
    reference = now or datetime.now(timezone.utc)
    return round((expires_at - reference).total_seconds() / 86400.0, 1)


def observations_from_cert(cert: dict[str, Any] | None, protocol: str | None,
                           cipher: str | None, *, valid: bool,
                           now: datetime | None = None) -> list[Observation]:
    """Pure: certificate dict to observations. Network-free."""
    out: list[Observation] = [obs("tls.valid", valid)]
    if protocol:
        out.append(obs("tls.protocol", protocol))
    if cipher:
        out.append(obs("tls.cipher", cipher))
    if not cert:
        return out
    issuer = flatten_name(cert.get("issuer"))
    subject = flatten_name(cert.get("subject"))
    if issuer:
        out.append(obs("tls.issuer", issuer))
    if subject:
        out.append(obs("tls.subject", subject))
    days = days_to_expiry(cert.get("notAfter", ""), now=now)
    if days is not None:
        out.append(obs("tls.days_to_expiry", days))
    return out


async def _handshake(host: str, port: int, context: ssl.SSLContext,
                     timeout: float) -> tuple[dict[str, Any] | None, str | None, str | None]:
    reader = writer = None
    try:
        coro = asyncio.open_connection(host, port, ssl=context, server_hostname=host)
        reader, writer = await asyncio.wait_for(coro, timeout=timeout)
        sslobj = writer.get_extra_info("ssl_object")
        if sslobj is None:
            return None, None, None
        cert = sslobj.getpeercert()
        cipher_info = sslobj.cipher()
        return cert, sslobj.version(), (cipher_info[0] if cipher_info else None)
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ssl.SSLError):
                pass


class TlsCollector:
    name = "tls"
    #: One certificate serves every page of a host, so this runs once per
    #: site rather than once per page: N pages would be N identical results
    #: and N handshakes, and the report would print the same expiry N times.
    scope = Scope.ORIGIN

    async def collect(self, ctx: PageContext) -> list[Observation]:
        url = httpx.URL(ctx.url)
        if url.scheme != "https":
            return [obs("tls.error", "site not served over HTTPS"),
                    obs("tls.valid", False)]

        host = url.host
        port = url.port or 443
        timeout = ctx.config.timeout

        verified = ssl.create_default_context()
        try:
            cert, protocol, cipher = await _handshake(host, port, verified, timeout)
            return observations_from_cert(cert, protocol, cipher, valid=True)
        except (ssl.SSLCertVerificationError, ssl.SSLError) as exc:
            reason = getattr(exc, "verify_message", None) or str(exc)
        except (OSError, asyncio.TimeoutError) as exc:
            return [obs("tls.valid", False),
                    obs("tls.error", f"connection failed: {exc}")]

        # Validation failed. Reconnect unverified so the report can still say
        # *why*: an expired cert and a hostname mismatch are different findings.
        permissive = ssl.create_default_context()
        permissive.check_hostname = False
        permissive.verify_mode = ssl.CERT_NONE
        try:
            cert, protocol, cipher = await _handshake(host, port, permissive, timeout)
        except (OSError, ssl.SSLError, asyncio.TimeoutError) as exc:
            return [obs("tls.valid", False),
                    obs("tls.error", f"{reason}; retry failed: {exc}")]

        results = observations_from_cert(cert, protocol, cipher, valid=False)
        results.append(obs("tls.error", reason))
        return results
