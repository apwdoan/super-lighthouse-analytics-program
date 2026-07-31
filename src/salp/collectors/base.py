"""Collector protocol and shared fetch context.

Collectors never format and never write to the database. They take a
:class:`PageContext` and return a list of :class:`~salp.schema.Observation`.
That is the entire contract.

The context also carries the *already fetched* document, so the HTTP,
fingerprint, and (later) content collectors share one request instead of
hammering the target site once per collector.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

import httpx

from ..schema import Observation


@dataclass(slots=True)
class FetchedDocument:
    """One HTTP response, retained so collectors can share it."""

    url: str
    final_url: str
    status: int
    http_version: str
    headers: dict[str, str]
    set_cookie: list[str]
    text: str
    content_bytes: int
    ttfb_ms: float
    redirect_chain: list[tuple[int, str]] = field(default_factory=list)


@dataclass(slots=True)
class PageContext:
    """Everything a collector may need for one URL.

    One context per page. A collector that needs to hand back something
    richer than observations (artifacts, run provenance) must put it in
    :attr:`extras` and NOT on the collector instance: collector objects are
    shared across every page in a batch and several pages are in flight at
    once, so instance state is a race.
    """

    url: str
    client: httpx.AsyncClient
    config: "CollectorConfig"
    document: FetchedDocument | None = None
    errors: list[str] = field(default_factory=list)
    extras: dict[str, Any] = field(default_factory=dict)

    @property
    def hostname(self) -> str:
        return httpx.URL(self.url).host

    @property
    def origin(self) -> str:
        u = httpx.URL(self.url)
        return f"{u.scheme}://{u.host}" + (f":{u.port}" if u.port else "")


@dataclass(slots=True)
class CollectorConfig:
    timeout: float = 20.0
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 SALP/0.1"
    )
    max_redirects: int = 10
    max_body_bytes: int = 4_000_000
    crux_api_key: str | None = None
    crux_rate_per_second: float = 2.0
    verify_tls: bool = True
    http_concurrency: int = 20


@runtime_checkable
class Collector(Protocol):
    """A unit of collection. Stateless, async, returns observations."""

    name: str

    async def collect(self, ctx: PageContext) -> list[Observation]:
        ...


class CollectorError(Exception):
    """A collector failed in a way that should be recorded, not fatal."""
