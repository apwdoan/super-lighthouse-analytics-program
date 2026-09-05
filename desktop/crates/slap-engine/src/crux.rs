//! CrUX field data and 25-week history: the report's verdict layer.
//!
//! Field data comes from the dedicated CrUX API, not PageSpeed Insights
//! (whose embedded CrUX data Google is retiring). Two behaviours matter:
//! a 404 is NOT an error (the origin has too little traffic for a record,
//! the common case for a small site, and the report says "no field data"),
//! and the quota is 150 queries/minute, paced by a shared token bucket.
//!
//! The API key is read from settings/environment and never stored by this
//! crate. Origin-scoped: the API is queried per origin, so every page of a
//! site would get an identical answer; running it per page is N times the
//! quota for one row of data.

use std::sync::Arc;

use serde_json::Value as Json;
use slap_core::schema::{obs, Observation, Value, CWV_GOOD_THRESHOLDS};
use slap_core::storage::CruxPoint;
use tokio::sync::Mutex;

pub const FIELD_ENDPOINT: &str = "https://chromeuxreport.googleapis.com/v1/records:queryRecord";
pub const HISTORY_ENDPOINT: &str =
    "https://chromeuxreport.googleapis.com/v1/records:queryHistoryRecord";

pub const DEFAULT_PERIODS: u32 = 25;

/// CrUX metric name -> (our p75 key, our "good share" key). The two TTFB
/// spellings both map to the same key; whichever the API returns wins.
const METRIC_MAP: &[(&str, &str, Option<&str>)] = &[
    (
        "largest_contentful_paint",
        "crux.lcp.p75",
        Some("crux.lcp.good"),
    ),
    (
        "interaction_to_next_paint",
        "crux.inp.p75",
        Some("crux.inp.good"),
    ),
    (
        "cumulative_layout_shift",
        "crux.cls.p75",
        Some("crux.cls.good"),
    ),
    ("experimental_time_to_first_byte", "crux.ttfb.p75", None),
    ("round_trip_time", "crux.ttfb.p75", None),
];

/// Metrics worth the history quota. TTFB is deliberately absent: diagnostic,
/// not something a client is assessed on.
const HISTORY_METRICS: &[&str] = &[
    "largest_contentful_paint",
    "interaction_to_next_paint",
    "cumulative_layout_shift",
];

fn as_f64(v: &Json) -> Option<f64> {
    match v {
        Json::Number(n) => n.as_f64(),
        Json::String(s) => s.parse().ok(),
        _ => None,
    }
}

fn threshold_for(key: &str) -> Option<f64> {
    CWV_GOOD_THRESHOLDS
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, t)| *t)
}

// ---------------------------------------------------------------------------
// Point-in-time field data
// ---------------------------------------------------------------------------

/// Pass/fail against the CWV thresholds, or None if LCP and CLS are absent.
/// INP is optional: origins with thin INP coverage still report LCP and CLS,
/// and a missing metric must not read as a failure.
pub fn core_web_vitals_pass(p75: &std::collections::HashMap<String, f64>) -> Option<bool> {
    if !p75.contains_key("crux.lcp.p75") || !p75.contains_key("crux.cls.p75") {
        return None;
    }
    for (key, threshold) in CWV_GOOD_THRESHOLDS {
        if let Some(value) = p75.get(*key) {
            if value > threshold {
                return Some(false);
            }
        }
    }
    Some(true)
}

/// Pure: a `queryRecord` response body to observations.
pub fn parse_field_record(payload: &Json) -> Vec<Observation> {
    let mut out = vec![obs("crux.available", Value::Bool(true)).unwrap()];
    let metrics = &payload["record"]["metrics"];
    let mut p75_values: std::collections::HashMap<String, f64> = std::collections::HashMap::new();

    for (crux_name, p75_key, good_key) in METRIC_MAP {
        let metric = &metrics[*crux_name];
        if metric.is_null() {
            continue;
        }
        if let Some(p75) = as_f64(&metric["percentiles"]["p75"]) {
            if !p75_values.contains_key(*p75_key) {
                p75_values.insert(p75_key.to_string(), p75);
                if let Ok(o) = obs(p75_key, Value::Num(p75)) {
                    out.push(o);
                }
            }
        }
        if let Some(good_key) = good_key {
            if let Some(good) = metric["histogram"][0]["density"]
                .as_f64()
                .or_else(|| as_f64(&metric["histogram"][0]["density"]))
            {
                let rounded = (good * 10000.0).round() / 10000.0;
                if let Ok(o) = obs(good_key, Value::Num(rounded)) {
                    out.push(o);
                }
            }
        }
    }

    if let Some(verdict) = core_web_vitals_pass(&p75_values) {
        out.push(obs("crux.cwv_pass", Value::Bool(verdict)).unwrap());
    }
    out
}

// ---------------------------------------------------------------------------
// History
// ---------------------------------------------------------------------------

fn iso(date: &Json) -> Option<String> {
    let year = date["year"].as_i64()?;
    let month = date["month"].as_i64()?;
    let day = date["day"].as_i64()?;
    // Zero-padded: these strings are compared and ordered as TEXT by storage,
    // and "2026-2-1" sorts after "2026-11-01".
    Some(format!("{year:04}-{month:02}-{day:02}"))
}

/// A `queryHistoryRecord` response to flat weekly points. The response is
/// transposed: the collection periods are one list, and every metric carries
/// parallel arrays indexed against it. A metric whose arrays are shorter than
/// the period list is truncated rather than misaligned.
pub fn parse_history(payload: &Json) -> Vec<CruxPoint> {
    let record = &payload["record"];
    let periods = record["collectionPeriods"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let metrics = &record["metrics"];

    let bounds: Vec<(String, String)> = periods
        .iter()
        .filter_map(|p| Some((iso(&p["firstDate"])?, iso(&p["lastDate"])?)))
        .collect();

    let mut points = Vec::new();
    let mut seen: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();

    for (crux_name, metric_key, _good) in METRIC_MAP {
        if !HISTORY_METRICS.contains(crux_name) {
            continue;
        }
        let metric = &metrics[*crux_name];
        if metric.is_null() {
            continue;
        }
        let p75s = metric["percentilesTimeseries"]["p75s"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let histogram = metric["histogramTimeseries"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        // densities[bin][period]. Bin 0 good, 1 needs improvement, 2 poor.
        let densities: Vec<Vec<Json>> = histogram
            .iter()
            .take(3)
            .map(|b| b["densities"].as_array().cloned().unwrap_or_default())
            .collect();

        for (index, (start, end)) in bounds.iter().enumerate() {
            let key = (metric_key.to_string(), end.clone());
            if seen.contains(&key) {
                continue;
            }
            let p75 = p75s.get(index).and_then(as_f64);
            let share = |bin: usize| {
                densities
                    .get(bin)
                    .and_then(|b| b.get(index))
                    .and_then(as_f64)
            };
            let (good, ni, poor) = (share(0), share(1), share(2));
            if p75.is_none() && good.is_none() && ni.is_none() && poor.is_none() {
                // No data for this metric this period. Skipped, not stored as
                // zero: a zero LCP would plot as a perfect score.
                continue;
            }
            seen.insert(key);
            points.push(CruxPoint {
                period_start: start.clone(),
                period_end: end.clone(),
                metric_key: metric_key.to_string(),
                p75,
                good,
                needs_improvement: ni,
                poor,
            });
        }
    }
    points
}

fn series_for<'a>(points: &'a [CruxPoint], metric_key: &str) -> Vec<&'a CruxPoint> {
    let mut s: Vec<&CruxPoint> = points
        .iter()
        .filter(|p| p.metric_key == metric_key && p.p75.is_some())
        .collect();
    s.sort_by(|a, b| a.period_end.cmp(&b.period_end));
    s
}

/// "regressed", "improved", or None. Compares the FIRST and LAST period
/// against the CWV threshold, not the raw delta: 1.2s -> 2.4s doubled and
/// still passes; 2.4s -> 2.6s barely moved and now fails, and only the
/// second is worth telling a client about.
pub fn crossed_threshold(points: &[CruxPoint], metric_key: &str) -> Option<&'static str> {
    let threshold = threshold_for(metric_key)?;
    let series = series_for(points, metric_key);
    if series.len() < 2 {
        return None;
    }
    let was_good = series[0].p75.unwrap() <= threshold;
    let is_good = series[series.len() - 1].p75.unwrap() <= threshold;
    match (was_good, is_good) {
        (true, false) => Some("regressed"),
        (false, true) => Some("improved"),
        _ => None,
    }
}

/// Run-level observations. The series itself goes to its own table.
pub fn summarise(points: &[CruxPoint]) -> Vec<Observation> {
    if points.is_empty() {
        return vec![obs("crux.history.available", Value::Bool(false)).unwrap()];
    }
    let weeks = points
        .iter()
        .map(|p| &p.period_end)
        .collect::<std::collections::HashSet<_>>()
        .len();
    let mut out = vec![
        obs("crux.history.available", Value::Bool(true)).unwrap(),
        obs("crux.history.weeks", Value::Num(weeks as f64)).unwrap(),
    ];

    let mut regressed = Vec::new();
    let mut improved = Vec::new();
    for (metric_key, short) in [
        ("crux.lcp.p75", "lcp"),
        ("crux.inp.p75", "inp"),
        ("crux.cls.p75", "cls"),
    ] {
        let series = series_for(points, metric_key);
        if series.len() < 2 {
            continue;
        }
        let (first, last) = (
            series[0].p75.unwrap(),
            series[series.len() - 1].p75.unwrap(),
        );
        let round4 = |x: f64| (x * 10000.0).round() / 10000.0;
        out.push(
            obs(
                &format!("crux.history.{short}.delta"),
                Value::Num(round4(last - first)),
            )
            .unwrap(),
        );
        out.push(obs(&format!("crux.history.{short}.first"), Value::Num(first)).unwrap());
        match crossed_threshold(points, metric_key) {
            Some("regressed") => regressed.push(short.to_uppercase()),
            Some("improved") => improved.push(short.to_uppercase()),
            _ => {}
        }
    }

    out.push(obs("crux.history.regressed", Value::Bool(!regressed.is_empty())).unwrap());
    if !regressed.is_empty() {
        out.push(
            obs(
                "crux.history.regressed_metrics",
                Value::from(regressed.join(", ")),
            )
            .unwrap(),
        );
    }
    out.push(obs("crux.history.improved", Value::Bool(!improved.is_empty())).unwrap());
    if !improved.is_empty() {
        out.push(
            obs(
                "crux.history.improved_metrics",
                Value::from(improved.join(", ")),
            )
            .unwrap(),
        );
    }
    let mut span: Vec<&String> = points
        .iter()
        .map(|p| &p.period_end)
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    span.sort();
    out.push(obs("crux.history.first_period", Value::from(span[0].as_str())).unwrap());
    out.push(
        obs(
            "crux.history.last_period",
            Value::from(span[span.len() - 1].as_str()),
        )
        .unwrap(),
    );
    out
}

// ---------------------------------------------------------------------------
// Rate limiter + network
// ---------------------------------------------------------------------------

/// Async token bucket. One instance is shared by every CrUX call in a batch,
/// so fanning out cannot burst through the 150/min quota. Uses tokio time,
/// so it is testable without a wall clock via `tokio::time::pause`.
pub struct TokenBucket {
    rate: f64,
    capacity: f64,
    state: Mutex<(f64, tokio::time::Instant)>,
}

impl TokenBucket {
    pub fn new(rate_per_second: f64) -> Arc<Self> {
        let rate = rate_per_second.max(0.01);
        let capacity = rate.max(1.0);
        Arc::new(Self {
            rate,
            capacity,
            state: Mutex::new((capacity, tokio::time::Instant::now())),
        })
    }

    pub async fn acquire(&self) {
        loop {
            let wait = {
                let mut guard = self.state.lock().await;
                let (tokens, updated) = &mut *guard;
                let now = tokio::time::Instant::now();
                *tokens = (*tokens + now.duration_since(*updated).as_secs_f64() * self.rate)
                    .min(self.capacity);
                *updated = now;
                if *tokens >= 1.0 {
                    *tokens -= 1.0;
                    return;
                }
                (1.0 - *tokens) / self.rate
            };
            tokio::time::sleep(std::time::Duration::from_secs_f64(wait)).await;
        }
    }
}

/// The result of a CrUX history fetch: the summary observations, plus the
/// series to persist (None when there is nothing to store).
pub struct HistoryResult {
    pub observations: Vec<Observation>,
    pub series: Option<(String, String, Vec<CruxPoint>)>, // (origin, form_factor, points)
}

/// Query point-in-time field data for an origin. A 404/429/4xx is not fatal:
/// it becomes `crux.available=false` and an optional note in `errors`.
pub async fn fetch_field(
    client: &reqwest::Client,
    origin: &str,
    api_key: &str,
    timeout: std::time::Duration,
    errors: &mut Vec<String>,
) -> Vec<Observation> {
    let unavailable = || vec![obs("crux.available", Value::Bool(false)).unwrap()];
    let response = client
        .post(FIELD_ENDPOINT)
        .query(&[("key", api_key)])
        .json(&serde_json::json!({ "origin": origin, "formFactor": "PHONE" }))
        .timeout(timeout)
        .send()
        .await;
    let response = match response {
        Ok(r) => r,
        Err(e) => {
            errors.push(format!("crux: {e}"));
            return unavailable();
        }
    };
    match response.status().as_u16() {
        200 => match response.json::<Json>().await {
            Ok(body) => parse_field_record(&body),
            Err(e) => {
                errors.push(format!("crux: bad JSON ({e})"));
                unavailable()
            }
        },
        404 => unavailable(), // insufficient real-user traffic; expected
        429 => {
            errors.push("crux: rate limited (429); lower crux_rate_per_second".into());
            unavailable()
        }
        code => {
            errors.push(format!("crux: HTTP {code}"));
            unavailable()
        }
    }
}

/// Query the 25-week history for an origin.
pub async fn fetch_history(
    client: &reqwest::Client,
    origin: &str,
    api_key: &str,
    periods: u32,
    form_factor: &str,
    timeout: std::time::Duration,
    errors: &mut Vec<String>,
) -> HistoryResult {
    let unavailable = || HistoryResult {
        observations: vec![obs("crux.history.available", Value::Bool(false)).unwrap()],
        series: None,
    };
    let body = serde_json::json!({
        "origin": origin,
        "formFactor": form_factor,
        "metrics": HISTORY_METRICS,
        "collectionPeriodCount": periods.clamp(1, 40),
    });
    let response = client
        .post(HISTORY_ENDPOINT)
        .query(&[("key", api_key)])
        .json(&body)
        .timeout(timeout)
        .send()
        .await;
    let response = match response {
        Ok(r) => r,
        Err(e) => {
            errors.push(format!("crux-history: {e}"));
            return unavailable();
        }
    };
    match response.status().as_u16() {
        200 => match response.json::<Json>().await {
            Ok(body) => {
                let points = parse_history(&body);
                let observations = summarise(&points);
                let series = (!points.is_empty())
                    .then(|| (origin.to_string(), form_factor.to_string(), points));
                HistoryResult {
                    observations,
                    series,
                }
            }
            Err(e) => {
                errors.push(format!("crux-history: bad JSON ({e})"));
                unavailable()
            }
        },
        404 => unavailable(),
        code => {
            errors.push(format!("crux-history: HTTP {code}"));
            unavailable()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(obs: Vec<Observation>) -> std::collections::HashMap<String, Value> {
        obs.into_iter()
            .map(|o| (o.metric_key.to_string(), o.value()))
            .collect()
    }

    #[test]
    fn a_passing_origin_record_parses_and_verdicts() {
        let payload = serde_json::json!({"record": {"metrics": {
            "largest_contentful_paint": {"percentiles": {"p75": 2100}, "histogram": [{"density": 0.82}]},
            "interaction_to_next_paint": {"percentiles": {"p75": 150}, "histogram": [{"density": 0.9}]},
            "cumulative_layout_shift": {"percentiles": {"p75": "0.05"}, "histogram": [{"density": 0.95}]}
        }}});
        let v = values(parse_field_record(&payload));
        assert_eq!(v["crux.available"], Value::Bool(true));
        assert_eq!(v["crux.lcp.p75"], Value::Num(2100.0));
        assert_eq!(v["crux.cls.p75"], Value::Num(0.05));
        assert_eq!(v["crux.lcp.good"], Value::Num(0.82));
        assert_eq!(v["crux.cwv_pass"], Value::Bool(true));
    }

    #[test]
    fn a_failing_lcp_fails_the_verdict() {
        let payload = serde_json::json!({"record": {"metrics": {
            "largest_contentful_paint": {"percentiles": {"p75": 4200}},
            "cumulative_layout_shift": {"percentiles": {"p75": 0.05}}
        }}});
        let v = values(parse_field_record(&payload));
        assert_eq!(v["crux.cwv_pass"], Value::Bool(false));
    }

    #[test]
    fn a_verdict_needs_lcp_and_cls() {
        // Only INP present: no verdict, because a missing metric is not a fail.
        let mut p75 = std::collections::HashMap::new();
        p75.insert("crux.inp.p75".to_string(), 150.0);
        assert_eq!(core_web_vitals_pass(&p75), None);
    }

    #[test]
    fn history_transpose_aligns_periods_and_detects_a_regression() {
        // Two periods; LCP good then poor -> regressed.
        let payload = serde_json::json!({"record": {
            "collectionPeriods": [
                {"firstDate": {"year": 2026, "month": 1, "day": 1}, "lastDate": {"year": 2026, "month": 1, "day": 28}},
                {"firstDate": {"year": 2026, "month": 2, "day": 1}, "lastDate": {"year": 2026, "month": 2, "day": 28}}
            ],
            "metrics": {"largest_contentful_paint": {
                "percentilesTimeseries": {"p75s": [2000, 3200]},
                "histogramTimeseries": [{"densities": [0.8, 0.5]}, {"densities": [0.15, 0.3]}, {"densities": [0.05, 0.2]}]
            }}
        }});
        let points = parse_history(&payload);
        assert_eq!(points.len(), 2);
        assert_eq!(points[0].period_end, "2026-01-28");
        assert_eq!(points[0].p75, Some(2000.0));
        assert_eq!(points[1].p75, Some(3200.0));
        assert_eq!(
            crossed_threshold(&points, "crux.lcp.p75"),
            Some("regressed")
        );
        let v = values(summarise(&points));
        assert_eq!(v["crux.history.available"], Value::Bool(true));
        assert_eq!(v["crux.history.weeks"], Value::Num(2.0));
        assert_eq!(v["crux.history.regressed"], Value::Bool(true));
        assert_eq!(v["crux.history.lcp.delta"], Value::Num(1200.0));
    }

    #[test]
    fn a_period_with_no_data_is_skipped_not_zeroed() {
        let payload = serde_json::json!({"record": {
            "collectionPeriods": [
                {"firstDate": {"year": 2026, "month": 1, "day": 1}, "lastDate": {"year": 2026, "month": 1, "day": 28}}
            ],
            "metrics": {"largest_contentful_paint": {
                "percentilesTimeseries": {"p75s": [null]},
                "histogramTimeseries": []
            }}
        }});
        assert!(
            parse_history(&payload).is_empty(),
            "a null period must not become a zero point"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_token_bucket_paces_after_the_burst() {
        // capacity == rate == 2: two immediate, the third waits ~0.5s.
        let bucket = TokenBucket::new(2.0);
        bucket.acquire().await;
        bucket.acquire().await;
        let start = tokio::time::Instant::now();
        bucket.acquire().await;
        assert!(start.elapsed() >= std::time::Duration::from_millis(400));
    }
}
