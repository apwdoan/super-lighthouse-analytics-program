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

from ..schema import CWV_GOOD_THRESHOLDS, Observation, obs
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
