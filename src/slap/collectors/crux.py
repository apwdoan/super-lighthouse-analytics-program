"""CrUX field data: the report's verdict layer.

The roadmap is explicit that field data comes from the dedicated CrUX API,
not from PageSpeed Insights, whose embedded CrUX data Google is retiring.

Two behaviours worth knowing:

* **404 is not an error.** It means the origin has too little traffic for a
  CrUX record. That is a normal outcome for most small-business sites and
  the report has to say "no field data" rather than "collection failed".
* **Quota is 150 queries/minute.** :class:`TokenBucket` paces requests at a
  configurable rate (default 2/s) and is shared across the whole batch, so
  fanning out 100 sites cannot burst through the limit.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx

from ..schema import CWV_GOOD_THRESHOLDS, Observation, Scope, obs
from .base import PageContext

CRUX_ENDPOINT = "https://chromeuxreport.googleapis.com/v1/records:queryRecord"

#: CrUX metric name -> (our metric key for p75, our metric key for good share)
METRIC_MAP: dict[str, tuple[str, str | None]] = {
    "largest_contentful_paint": ("crux.lcp.p75", "crux.lcp.good"),
    "interaction_to_next_paint": ("crux.inp.p75", "crux.inp.good"),
    "cumulative_layout_shift": ("crux.cls.p75", "crux.cls.good"),
    "experimental_time_to_first_byte": ("crux.ttfb.p75", None),
    "round_trip_time": ("crux.ttfb.p75", None),
}


class TokenBucket:
    """Async rate limiter. One instance is shared by every CrUX call in a batch."""

    def __init__(self, rate_per_second: float, capacity: float | None = None) -> None:
        self.rate = max(rate_per_second, 0.01)
        self.capacity = capacity if capacity is not None else max(self.rate, 1.0)
        self._tokens = self.capacity
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                self._tokens = min(
                    self.capacity, self._tokens + (now - self._updated) * self.rate
                )
                self._updated = now
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                await asyncio.sleep((tokens - self._tokens) / self.rate)


def _as_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def parse_crux_record(payload: dict[str, Any]) -> list[Observation]:
    """Pure: a CrUX ``queryRecord`` response body to observations."""
    out: list[Observation] = [obs("crux.available", True)]
    metrics = (payload.get("record") or {}).get("metrics") or {}

    p75_values: dict[str, float] = {}
    for crux_name, (p75_key, good_key) in METRIC_MAP.items():
        metric = metrics.get(crux_name)
        if not metric:
            continue
        p75 = _as_float((metric.get("percentiles") or {}).get("p75"))
        if p75 is not None and p75_key not in p75_values:
            p75_values[p75_key] = p75
            out.append(obs(p75_key, p75))
        if good_key:
            histogram = metric.get("histogram") or []
            if histogram:
                good = _as_float(histogram[0].get("density"))
                if good is not None:
                    out.append(obs(good_key, round(good, 4)))

    verdict = core_web_vitals_pass(p75_values)
    if verdict is not None:
        out.append(obs("crux.cwv_pass", verdict))
    return out


def core_web_vitals_pass(p75_values: dict[str, float]) -> bool | None:
    """Pass/fail against the CWV thresholds, or None if LCP and CLS are absent.

    Google's assessment requires LCP, INP, and CLS to all be good. INP is
    treated as optional here because origins with thin INP coverage still
    report LCP and CLS, and a missing metric should not read as a failure.
    """
    if "crux.lcp.p75" not in p75_values or "crux.cls.p75" not in p75_values:
        return None
    for key, threshold in CWV_GOOD_THRESHOLDS.items():
        value = p75_values.get(key)
        if value is None:
            continue
        if value > threshold:
            return False
    return True


class CruxCollector:
    """Queries the CrUX API for origin-level field data."""

    name = "crux"
    #: The API is queried by origin, so every page of a site receives an
    #: identical answer. Running it per page is N times the quota for one
    #: row of data. (The API does accept a url parameter, but most
    #: individual pages lack the traffic to have a record at all.)
    scope = Scope.ORIGIN

    def __init__(self, bucket: TokenBucket | None = None) -> None:
        self._bucket = bucket

    async def collect(self, ctx: PageContext) -> list[Observation]:
        api_key = ctx.config.crux_api_key
        if not api_key:
            return [obs("crux.available", False)]

        bucket = self._bucket or TokenBucket(ctx.config.crux_rate_per_second)
        await bucket.acquire()

        try:
            response = await ctx.client.post(
                CRUX_ENDPOINT,
                params={"key": api_key},
                json={"origin": ctx.origin, "formFactor": "PHONE"},
                timeout=ctx.config.timeout,
            )
        except httpx.HTTPError as exc:
            ctx.errors.append(f"crux: {exc}")
            return [obs("crux.available", False)]

        if response.status_code == 404:
            # Expected: origin has insufficient real-user traffic.
            return [obs("crux.available", False)]
        if response.status_code == 429:
            ctx.errors.append("crux: rate limited (429); lower crux_rate_per_second")
            return [obs("crux.available", False)]
        if response.status_code >= 400:
            ctx.errors.append(f"crux: HTTP {response.status_code}")
            return [obs("crux.available", False)]

        try:
            return parse_crux_record(response.json())
        except ValueError as exc:
            ctx.errors.append(f"crux: bad JSON ({exc})")
            return [obs("crux.available", False)]


async def check_key(api_key: str | None, *, timeout: float = 15.0) -> tuple[bool, str]:
    """Does this key actually return field data? Returns (ok, detail).

    `doctor` used to report CrUX healthy whenever a key was merely *set*.
    That is the same class of lie as the PDF check that stat-ed a file
    instead of launching the browser: a key can be well-formed, present in
    the environment, and rejected on every request. This one was, with the
    API disabled on its Google Cloud project, and every audit would have
    quietly recorded `crux.available: false` while `doctor` said ok.

    Uses a high-traffic origin so "no data for this origin" cannot be
    mistaken for "the key does not work".
    """
    if not api_key:
        return False, (
            "No CRUX_API_KEY set. Reports will say 'no field data' and rely on\n"
            "lab measurements only. Key is free: "
            "https://developer.chrome.com/docs/crux/api"
        )
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(
                CRUX_ENDPOINT, params={"key": api_key},
                json={"origin": "https://www.wikipedia.org", "formFactor": "PHONE"},
            )
    except httpx.HTTPError as exc:
        return False, f"could not reach the CrUX API: {exc}"

    if response.status_code == 200:
        return True, "Real-user Core Web Vitals available."
    if response.status_code == 403:
        detail = response.json().get("error", {}).get("message", "")
        if "has not been used in project" in detail or "is disabled" in detail:
            return False, (
                "The key is valid but the Chrome UX Report API is not enabled on\n"
                "its Google Cloud project. Enable it here, then retry:\n"
                "https://console.cloud.google.com/apis/library/chromeuxreport.googleapis.com"
            )
        return False, f"CrUX rejected the key (403): {detail[:200]}"
    if response.status_code == 429:
        return False, "rate limited (429). The key works; try again shortly."
    return False, f"CrUX returned HTTP {response.status_code}"
