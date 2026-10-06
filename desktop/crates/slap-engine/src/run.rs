//! Batch orchestration: for each site, discover its pages, run every
//! collector, persist one run holding all the pages, emit progress.
//!
//! Collectors by scope:
//! - **Page**: HTTP (the one shared fetch) and the technology fingerprint,
//!   run for every discovered page.
//! - **Origin**: TLS (one certificate serves the whole host) and CrUX field
//!   data + 25-week history (the API is queried by origin). These run once
//!   per site and their observations attach to the home page, which is the
//!   page the verdict speaks about and the anchor every trend follows.
//!
//! Discovery is a pre-stage, not a collector: it produces the URL list before
//! any page context exists. A run holds the home page plus every other page
//! discovered up to the cap; a cap that bites is disclosed as
//! `discovery.dropped`, never hidden.
//!
//! ## Two passes, and a run that survives the night
//!
//! 1. **Light pass**: the no-browser collectors on every discovered page, and
//!    the origin collectors once. Seconds per site.
//! 2. **Heavy pass**: Lighthouse, median of N, on the pages the run's
//!    coverage mode selects: one per template (`sampled`, the default) or
//!    every discovered page (`every_page`), always in coverage order, so a
//!    batch stopped at hour six has measured the pages that matter most
//!    rather than an alphabetical prefix.
//!
//! An every-page batch can run for many hours, so nothing is held in memory
//! until the end. Every run of a batch is written as `pending` before any work
//! starts; the light pass is written as one transaction when it completes;
//! each Lighthouse page is written, with its artifacts, the moment its median
//! is known. Findings are a pure function of the stored observations and are
//! evaluated once, when the run is finalised. A crash, a closed laptop or the
//! Stop button therefore costs at most the pages that were inside Chrome at
//! the time, and [`resume_runs`] picks up exactly where the run left off, as
//! long as the engine that measured it is still the one installed.
//!
//! Concurrency: sites run concurrently (`http_concurrency`), pages within a
//! site's light pass run concurrently too, and Lighthouse has its OWN global
//! cap (`[lighthouse] concurrency`, 3 by default, never above 4) shared by
//! every site in the batch. Contended CPU inflates TBT and produces plausible,
//! irreproducible scores, so that cap is the one that must hold.
//!
//! All of it runs on one task: the futures are polled together by
//! `buffer_unordered`, so the one connection never crosses a thread, and no
//! transaction is ever held across an `.await`.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures::stream::{self, StreamExt};
use serde_json::Value as Json;
use slap_core::events::{CancelToken, Event};
use slap_core::findings::FindingsEngine;
use slap_core::rusqlite::{params, Connection};
use slap_core::schema::{
    obs, AuditDepth, DiscoveredVia, FormFactor, LighthouseScope, Observation, PageRole, RunStatus,
    Value,
};
use slap_core::storage::{self, CruxPoint, NewPage};

use crate::crux::{self, TokenBucket};
use crate::discovery::{self, DiscoveryConfig};
use crate::fingerprint::observations_from_html;
use crate::http::{fetch, normalize_url, observations_from_document, FetchedDocument};
use crate::tls;

/// Wall-clock seconds one Lighthouse run takes on a typical machine (Chrome
/// launch, a throttled mobile load, teardown). The estimate, not a timeout.
pub const SECONDS_PER_LIGHTHOUSE_RUN: f64 = 30.0;
/// Bytes kept per measured page: the compact summary the report renders
/// from, and (when raw LHRs are kept) the gzipped median-run LHR.
pub const SUMMARY_BYTES_PER_PAGE: u64 = 6_000;
pub const LHR_BYTES_PER_PAGE: u64 = 600_000;

/// Everything the engine needs to run, most of it from the user's settings.
#[derive(Clone, Debug)]
pub struct EngineConfig {
    pub user_agent: String,
    pub max_redirects: u32,
    pub max_body_bytes: usize,
    pub concurrency: usize,
    pub timeout_secs: u64,
    pub crux_api_key: Option<String>,
    pub crux_rate_per_second: f64,
    /// The Lighthouse runner config, or None to skip the browser audit. Left
    /// None by `from_settings` because it needs paths the engine cannot know
    /// (the bundled worker directory, the pinned Chromium): the shell resolves
    /// those and sets this when the user asks for Lighthouse.
    pub lighthouse: Option<crate::lighthouse::LighthouseConfig>,
    pub discovery: DiscoveryConfig,
    /// How many pages per site get the browser audit in `sampled` mode.
    pub lighthouse_pages: usize,
    /// Which pages get the browser audit: one per template, or every page.
    pub lighthouse_scope: LighthouseScope,
    /// How many Lighthouse instances may run at once across the whole batch.
    pub lighthouse_concurrency: usize,
    /// The runs each Lighthouse page is planned for (`[lighthouse] runs`).
    /// The shell copies it into `lighthouse` when it builds the runner; the
    /// estimate reads it here, before there is a runner to ask.
    pub lighthouse_runs: usize,
    /// Where per-page Lighthouse summaries (and, if kept, raw LHRs) are
    /// written. None keeps nothing on disk; the observations still land.
    pub artifact_dir: Option<PathBuf>,
    /// Keep the median run's raw LHR beside its summary.
    pub keep_lhr: bool,
    /// Active endpoint probing. Off unless the shell both enables it and lists
    /// the host as authorised, because it actively requests sensitive paths.
    pub probe: ProbeSettings,
}

/// Whether to run the opt-in endpoint probe, and for which hosts. A host is
/// probed only when `enabled` AND it appears in `authorised_hosts`: the two
/// together are the recorded authorization the probe requires.
#[derive(Clone, Debug, Default)]
pub struct ProbeSettings {
    pub enabled: bool,
    pub rate_per_second: f64,
    pub authorised_hosts: std::collections::HashSet<String>,
}

impl EngineConfig {
    pub fn from_settings(settings: &slap_core::settings::Settings) -> Self {
        let c = &settings.collector;
        let d = &settings.discovery;
        Self {
            user_agent: c.user_agent.clone(),
            max_redirects: c.max_redirects,
            max_body_bytes: c.max_body_bytes as usize,
            concurrency: c.http_concurrency.max(1) as usize,
            timeout_secs: c.timeout.max(1.0) as u64,
            crux_api_key: c.crux_api_key.clone().filter(|k| !k.is_empty()),
            crux_rate_per_second: c.crux_rate_per_second.max(0.1),
            lighthouse: None,
            discovery: DiscoveryConfig {
                enabled: d.enabled,
                pages_per_site: d.pages_per_site.max(1) as usize,
                crawl_depth: d.crawl_depth as usize,
                allow_crawl: d.allow_crawl,
            },
            lighthouse_pages: d.lighthouse_pages_per_site.max(1) as usize,
            lighthouse_scope: settings.lighthouse.scope(),
            lighthouse_concurrency: settings.lighthouse.effective_concurrency(),
            lighthouse_runs: settings.lighthouse.effective_runs(),
            artifact_dir: Some(settings.artifact_dir.clone()),
            keep_lhr: settings.lighthouse.keep_artifacts,
            probe: ProbeSettings {
                // `from_settings` records the user's default and rate; the shell
                // supplies the authorised host set, because authorization is a
                // per-run, per-host decision the engine cannot make itself.
                enabled: settings.probe_enabled,
                rate_per_second: settings.probe_rate_per_second.max(0.1),
                authorised_hosts: std::collections::HashSet::new(),
            },
        }
    }
}

#[derive(Debug, serde::Serialize)]
pub struct RunSummary {
    pub url: String,
    pub hostname: String,
    pub run_id: Option<i64>,
    pub ok: bool,
    pub pages: usize,
    pub observations: usize,
    pub findings: usize,
    pub error: Option<String>,
    /// Stopped before it finished; the run is still resumable.
    #[serde(default)]
    pub interrupted: bool,
    /// Pages queued for Lighthouse, and how many have a result.
    #[serde(default)]
    pub lighthouse_planned: usize,
    #[serde(default)]
    pub lighthouse_done: usize,
}

#[derive(Debug, serde::Serialize)]
pub struct AuditSummary {
    pub batch_id: String,
    pub total: usize,
    pub succeeded: usize,
    pub failed: usize,
    /// Runs left unfinished by a Stop: resumable, not failed.
    #[serde(default)]
    pub interrupted: usize,
    pub runs: Vec<RunSummary>,
}

/// One page of a site, with its page-scoped observations. Nothing here has
/// touched the database yet.
struct PageData {
    url: String,
    final_url: Option<String>,
    role: PageRole,
    discovered_via: DiscoveredVia,
    template: Option<String>,
    observations: Vec<Observation>,
}

/// What the light pass learned about one site.
struct SiteData {
    /// The URL this site's progress events carry, so a progress view can
    /// follow one site from its first event to its last.
    event_url: String,
    /// Home first, then the other discovered pages.
    pages: Vec<PageData>,
    /// TLS + CrUX + discovery metadata: origin-scoped, so they attach to the
    /// home page rather than repeating on every page.
    origin_observations: Vec<Observation>,
    crux_history: Option<(String, String, Vec<CruxPoint>)>,
    /// Set when the HOME page could not be fetched: the run is then failed.
    error: Option<String>,
}

fn host_of(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(String::from))
        .unwrap_or_else(|| url.to_string())
}

fn origin_of(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(u) => {
            let mut o = format!("{}://{}", u.scheme(), u.host_str().unwrap_or(""));
            if let Some(port) = u.port() {
                o.push_str(&format!(":{port}"));
            }
            o
        }
        Err(_) => url.to_string(),
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The hostname a requested URL will be filed under, before any network.
fn planned_hostname(raw: &str) -> String {
    match normalize_url(raw) {
        Ok(n) => host_of(&n),
        Err(_) => host_of(raw),
    }
}

/// Fetch and run the page-scoped collectors on one URL, returning its
/// observations and the raw HTML (for template classification).
async fn fetch_page(
    client: &reqwest::Client,
    url: &str,
    cfg: &EngineConfig,
) -> Result<(FetchedDocument, Vec<Observation>), String> {
    let doc = fetch(
        client,
        url,
        &cfg.user_agent,
        cfg.max_redirects,
        cfg.max_body_bytes,
    )
    .await?;
    let mut observations = observations_from_document(&doc);
    observations.extend(observations_from_html(&doc.text, &doc.headers));
    observations.extend(crate::components::observations_from_page(&doc.text, &doc.headers));
    Ok((doc, observations))
}

/// Does a URL's transport (TCP, and the TLS handshake for https) accept a
/// connection at all? A HEAD that returns any HTTP status, even a 4xx or 5xx,
/// proves the transport works; only a connection, TLS, or timeout error is
/// `Err`. HEAD is used so the probe transfers no body and does not warm the
/// server's cache before the real measurement is taken.
async fn head_reachable(
    client: &reqwest::Client,
    url: &str,
    user_agent: &str,
    timeout: Duration,
) -> Result<(), String> {
    client
        .head(url)
        .header(reqwest::header::USER_AGENT, user_agent)
        .timeout(timeout)
        .send()
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Lighthouse queue order
// ---------------------------------------------------------------------------

/// The order pages go into Chrome. Every page sorted by how many pages its
/// template speaks for (most first), then template, then URL, with home
/// first and one representative of each template ahead of any second page
/// of a template. In `sampled` mode the queue is the first `limit` of these
/// (exactly [`discovery::choose_lighthouse_pages`]); in `every_page` mode it
/// is all of them. Deterministic, so a resumed run rebuilds the same order
/// from its stored pages, and two runs of a site measure in the same order.
pub fn lighthouse_order(
    pages: &HashMap<String, String>,
    home_url: Option<&str>,
    scope: LighthouseScope,
    sampled_limit: usize,
) -> Vec<String> {
    let first = discovery::choose_lighthouse_pages(
        pages,
        match scope {
            LighthouseScope::Sampled => sampled_limit,
            LighthouseScope::EveryPage => usize::MAX,
        },
        home_url,
    );
    if scope == LighthouseScope::Sampled {
        return first;
    }
    let mut coverage: HashMap<&str, usize> = HashMap::new();
    for template in pages.values() {
        *coverage.entry(template.as_str()).or_insert(0) += 1;
    }
    let chosen: HashSet<&String> = first.iter().collect();
    let mut rest: Vec<&String> = pages.keys().filter(|u| !chosen.contains(u)).collect();
    rest.sort_by(|a, b| {
        let (ca, cb) = (&pages[*a], &pages[*b]);
        (std::cmp::Reverse(coverage[ca.as_str()]), ca, *a).cmp(&(
            std::cmp::Reverse(coverage[cb.as_str()]),
            cb,
            *b,
        ))
    });
    let mut order = first.clone();
    order.extend(rest.into_iter().cloned());
    order
}

// ---------------------------------------------------------------------------
// Estimates
// ---------------------------------------------------------------------------

/// What one site would cost, from discovery alone (robots.txt and sitemaps,
/// or a shallow crawl): no page is fetched for measurement and nothing is
/// written.
#[derive(Debug, serde::Serialize)]
pub struct SiteEstimate {
    pub url: String,
    pub pages: usize,
    pub found: usize,
    pub dropped: usize,
    pub lighthouse_pages: usize,
    pub error: Option<String>,
}

#[derive(Debug, serde::Serialize)]
pub struct BatchEstimate {
    pub sites: Vec<SiteEstimate>,
    pub pages: usize,
    pub lighthouse_pages: usize,
    pub scope: String,
    pub runs_per_page: usize,
    pub concurrency: usize,
    pub seconds: f64,
    pub disk_bytes: u64,
}

/// Wall-clock seconds for `pages` Lighthouse pages at `runs` runs each,
/// `concurrency` at a time.
pub fn lighthouse_seconds(pages: usize, runs: usize, concurrency: usize) -> f64 {
    pages as f64 * runs.max(1) as f64 * SECONDS_PER_LIGHTHOUSE_RUN / concurrency.max(1) as f64
}

/// Count what a batch would measure before the operator commits to it. The
/// number that decides "48 minutes or overnight" is the page count, and only
/// discovery knows it.
pub async fn estimate_batch(urls: &[String], cfg: &EngineConfig) -> BatchEstimate {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(cfg.max_redirects as usize))
        .timeout(Duration::from_secs(cfg.timeout_secs))
        .build()
        .unwrap_or_default();
    let timeout = Duration::from_secs(cfg.timeout_secs);
    let sites: Vec<SiteEstimate> = stream::iter(urls.iter().cloned())
        .map(|raw| {
            let client = &client;
            async move {
                let normalized = match normalize_url(&raw) {
                    Ok(n) => n,
                    Err(e) => {
                        return SiteEstimate {
                            url: raw,
                            pages: 0,
                            found: 0,
                            dropped: 0,
                            lighthouse_pages: 0,
                            error: Some(e),
                        }
                    }
                };
                let found =
                    discovery::discover(client, &normalized, &cfg.user_agent, &cfg.discovery, timeout)
                        .await;
                let pages = found.urls.len();
                let lighthouse_pages = match cfg.lighthouse_scope {
                    LighthouseScope::EveryPage => pages,
                    LighthouseScope::Sampled => pages.min(cfg.lighthouse_pages),
                };
                SiteEstimate {
                    url: raw,
                    pages,
                    found: found.found,
                    dropped: found.dropped,
                    lighthouse_pages,
                    error: None,
                }
            }
        })
        .buffered(cfg.concurrency.max(1))
        .collect()
        .await;
    let runs = cfg.lighthouse.as_ref().map(|l| l.runs).unwrap_or(cfg.lighthouse_runs).max(1);
    let pages = sites.iter().map(|s| s.pages).sum();
    let lighthouse_pages: usize = sites.iter().map(|s| s.lighthouse_pages).sum();
    let per_page = SUMMARY_BYTES_PER_PAGE + if cfg.keep_lhr { LHR_BYTES_PER_PAGE } else { 0 };
    BatchEstimate {
        pages,
        lighthouse_pages,
        scope: cfg.lighthouse_scope.as_str().to_string(),
        runs_per_page: runs,
        concurrency: cfg.lighthouse_concurrency.max(1),
        seconds: lighthouse_seconds(lighthouse_pages, runs, cfg.lighthouse_concurrency),
        disk_bytes: lighthouse_pages as u64 * per_page,
        sites,
    }
}

// ---------------------------------------------------------------------------
// The light pass
// ---------------------------------------------------------------------------

/// One page's scan: its discovery index, its URL, and the fetched document
/// with its page-scoped observations, or why it would not load.
type ScanResult = (usize, String, Result<(FetchedDocument, Vec<Observation>), String>);

/// Discover a site's pages, run the page collectors on each, and the origin
/// collectors once. Emits collector progress as it goes. Writes nothing.
#[allow(clippy::too_many_arguments)]
async fn light_pass(
    client: &reqwest::Client,
    bucket: &Arc<TokenBucket>,
    cfg: &EngineConfig,
    batch_id: &str,
    raw: &str,
    index: usize,
    total: usize,
    emit: &(impl Fn(Event) + Sync),
) -> SiteData {
    let mut normalized = match normalize_url(raw) {
        Ok(n) => n,
        Err(e) => {
            return SiteData {
                event_url: raw.to_string(),
                pages: Vec::new(),
                origin_observations: Vec::new(),
                crux_history: None,
                error: Some(e),
            }
        }
    };
    let timeout = Duration::from_secs(cfg.timeout_secs);

    // Reachability: a site whose HTTPS endpoint refuses the connection (an
    // absent or broken certificate, a misconfigured TLS terminator) can still
    // be audited over plain HTTP, which is far more useful than failing the
    // whole run. When the HTTPS handshake fails but HTTP answers, fall back to
    // http:// for every page collector, remember the original HTTPS origin so
    // the TLS collector still reports why HTTPS did not work, and record the
    // fallback so a finding can flag it. A HEAD is enough: any HTTP status,
    // even a 4xx, proves the transport works, so only a connection/TLS error
    // triggers the fallback, and HEAD does not warm the server's cache.
    let mut https_unreachable: Option<String> = None;
    let mut https_origin: Option<String> = None;
    if normalized.starts_with("https://") {
        if let Err(err) = head_reachable(client, &normalized, &cfg.user_agent, timeout).await {
            let http_url = format!("http://{}", &normalized["https://".len()..]);
            if head_reachable(client, &http_url, &cfg.user_agent, timeout)
                .await
                .is_ok()
            {
                https_origin = Some(origin_of(&normalized));
                https_unreachable = Some(err);
                normalized = http_url;
            }
            // If HTTP is also unreachable, leave normalized on https:// so the
            // home fetch fails and the run is marked failed, exactly as before.
        }
    }

    let origin = origin_of(&normalized);
    emit(Event::SiteStarted {
        batch_id: batch_id.into(),
        url: normalized.clone(),
        index,
        total,
    });
    let started = |name: &str| {
        emit(Event::CollectorStarted {
            batch_id: batch_id.into(),
            url: normalized.clone(),
            collector: name.into(),
        })
    };
    let finished = |name: &str, n: usize, ok: bool| {
        emit(Event::CollectorFinished {
            batch_id: batch_id.into(),
            url: normalized.clone(),
            collector: name.into(),
            observations: n,
            ok,
            error: None,
        })
    };

    // --- discovery (pre-stage) ---
    started("discovery");
    let discovered = discovery::discover(
        client,
        &normalized,
        &cfg.user_agent,
        &cfg.discovery,
        timeout,
    )
    .await;
    finished("discovery", discovered.urls.len(), true);
    let scan_total = discovered.urls.len();
    emit(Event::PagesDiscovered {
        batch_id: batch_id.into(),
        url: normalized.clone(),
        pages: scan_total,
        found: discovered.found,
        dropped: discovered.dropped,
    });

    // --- page-scoped collectors, one home + each discovered page ---
    // Each page reports when its scan starts and finishes, so the composer's
    // progress bar can say which page it is on.
    started("http");
    let page_concurrency = cfg.discovery.pages_per_site.clamp(1, 5);
    let scanned = std::sync::atomic::AtomicUsize::new(0);
    let fetched: Vec<ScanResult> = stream::iter(discovered.urls.iter().cloned().enumerate())
        .map(|(i, url)| {
            let (scanned, normalized) = (&scanned, &normalized);
            async move {
                emit(Event::PageScanStarted {
                    batch_id: batch_id.into(),
                    url: normalized.clone(),
                    page_url: url.clone(),
                    total: scan_total,
                });
                let result = fetch_page(client, &url, cfg).await;
                let index = scanned.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                emit(Event::PageScanned {
                    batch_id: batch_id.into(),
                    url: normalized.clone(),
                    page_url: url.clone(),
                    index,
                    total: scan_total,
                    ok: result.is_ok(),
                    error: result.as_ref().err().cloned(),
                });
                (i, url, result)
            }
        })
        .buffer_unordered(page_concurrency)
        .collect()
        .await;

    let mut pages: Vec<(usize, PageData)> = Vec::new();
    let mut home_error = None;
    let mut page_obs_count = 0;
    for (i, url, result) in fetched {
        let is_home = i == 0;
        match result {
            Ok((doc, observations)) => {
                page_obs_count += observations.len();
                let template = discovery::classify_template(&url, Some(&doc.text), is_home);
                pages.push((
                    i,
                    PageData {
                        url,
                        final_url: Some(doc.final_url),
                        role: if is_home {
                            PageRole::Home
                        } else {
                            PageRole::Discovered
                        },
                        discovered_via: if is_home {
                            DiscoveredVia::Manual
                        } else {
                            discovered.method
                        },
                        template: Some(template),
                        observations,
                    },
                ));
            }
            Err(e) => {
                if is_home {
                    home_error = Some(e);
                    // Keep a home page row so origin observations have a home.
                    pages.push((
                        i,
                        PageData {
                            url,
                            final_url: None,
                            role: PageRole::Home,
                            discovered_via: DiscoveredVia::Manual,
                            template: Some("home".into()),
                            observations: Vec::new(),
                        },
                    ));
                }
                // A non-home page that would not load is simply dropped.
            }
        }
    }
    finished("http", page_obs_count, home_error.is_none());
    // Home first, then discovery order, regardless of completion order: the
    // page rows (and so the report's inventory) follow the order the site
    // itself lists its pages in.
    pages.sort_by_key(|(i, _)| *i);
    let pages: Vec<PageData> = pages.into_iter().map(|(_, p)| p).collect();

    // --- origin-scoped collectors, once ---
    started("tls");
    // Probe TLS against the real HTTPS origin even when the page audit fell
    // back to http://, so a certificate or handshake failure is still reported.
    let tls_target = https_origin.as_deref().unwrap_or(&normalized);
    let tls_obs = tls::probe(tls_target, timeout, now_unix()).await;
    finished("tls", tls_obs.len(), true);

    let mut origin_observations = tls_obs;

    // Record the HTTPS-unreachable fallback so a finding can flag it and the
    // report can explain that the measurements below were taken over http://.
    if let Some(err) = &https_unreachable {
        if let Ok(o) = obs("https.unreachable", Value::Bool(true)) {
            origin_observations.push(o);
        }
        if let Ok(o) = obs("https.error", Value::from(err.clone())) {
            origin_observations.push(o);
        }
    }

    let mut crux_history = None;
    if let Some(key) = &cfg.crux_api_key {
        started("crux");
        bucket.acquire().await;
        let mut errs = Vec::new();
        let field = crux::fetch_field(client, &origin, key, timeout, &mut errs).await;
        origin_observations.extend(field);
        bucket.acquire().await;
        let history = crux::fetch_history(
            client,
            &origin,
            key,
            crux::DEFAULT_PERIODS,
            "PHONE",
            timeout,
            &mut errs,
        )
        .await;
        origin_observations.extend(history.observations);
        crux_history = history.series;
        finished("crux", origin_observations.len(), errs.is_empty());
    }

    // --- endpoint probing (origin-scoped, opt-in and authorised only) ---
    let host = host_of(&normalized);
    if cfg.probe.enabled && cfg.probe.authorised_hosts.contains(&host) {
        started("probe");
        let probe_cfg = crate::probe::ProbeConfig {
            rate_per_second: cfg.probe.rate_per_second,
            timeout,
            user_agent: cfg.user_agent.clone(),
        };
        let probe_obs = crate::probe::probe(client, &origin, &probe_cfg).await;
        let n = probe_obs.len();
        finished("probe", n, true);
        origin_observations.extend(probe_obs);
    }

    // --- discovery metadata (origin-scoped) ---
    let audited = pages
        .iter()
        .filter(|p| p.role != PageRole::Home || p.final_url.is_some())
        .count();
    let method = match discovered.method {
        DiscoveredVia::Manual => "manual",
        DiscoveredVia::Sitemap => "sitemap",
        DiscoveredVia::Crawl => "crawl",
    };
    for (key, value) in [
        ("discovery.method", Value::from(method)),
        ("discovery.found", Value::Num(discovered.found as f64)),
        ("discovery.audited", Value::Num(audited as f64)),
        ("discovery.dropped", Value::Num(discovered.dropped as f64)),
    ] {
        if let Ok(o) = obs(key, value) {
            origin_observations.push(o);
        }
    }
    if !discovered.sitemaps.is_empty() {
        if let Ok(o) = obs(
            "discovery.sitemap_urls",
            Value::from(discovered.sitemaps.join(", ")),
        ) {
            origin_observations.push(o);
        }
    }

    // --- vulnerability database provenance (origin-scoped) ---
    // The per-page component collectors emit the vuln.* findings; this records
    // which database version judged them, once for the run.
    origin_observations.extend(crate::vulndb::db_metadata(now_unix()));

    SiteData {
        event_url: normalized,
        pages,
        origin_observations,
        crux_history,
        error: home_error,
    }
}

// ---------------------------------------------------------------------------
// Persistence: the light pass, one page, the finalised run
// ---------------------------------------------------------------------------

/// Write the light pass as one transaction: every page with its observations,
/// the origin observations on the home page, the CrUX series, and which pages
/// are queued for Lighthouse (audit_depth = full). All or nothing, so a run
/// that has any page rows has a complete light pass.
fn persist_light_pass(
    conn: &Connection,
    run_id: i64,
    site: &SiteData,
    scope: Option<LighthouseScope>,
    sampled_limit: usize,
) -> slap_core::rusqlite::Result<usize> {
    let tx = conn.unchecked_transaction()?;
    if let Some((origin, form_factor, points)) = &site.crux_history {
        storage::insert_crux_history(&tx, origin, form_factor, points)?;
    }
    let mut ids: HashMap<String, i64> = HashMap::new();
    for (i, page) in site.pages.iter().enumerate() {
        let mut new_page = NewPage::new(&page.url);
        new_page.final_url = page.final_url.as_deref();
        new_page.form_factor = FormFactor::None;
        new_page.role = page.role;
        new_page.discovered_via = page.discovered_via;
        new_page.audit_depth = AuditDepth::Light;
        new_page.template_class = page.template.as_deref();
        let page_id = storage::create_page(&tx, run_id, &new_page)?;
        storage::insert_observations(&tx, page_id, &page.observations)?;
        // The origin observations (TLS, CrUX, discovery) land on the home
        // page, which is pages[0] after the sort in light_pass.
        if i == 0 {
            storage::insert_observations(&tx, page_id, &site.origin_observations)?;
        }
        ids.insert(page.url.clone(), page_id);
    }

    let mut queued = 0;
    if let (Some(scope), None) = (scope, &site.error) {
        let class_of: HashMap<String, String> = site
            .pages
            .iter()
            .filter(|p| p.final_url.is_some())
            .map(|p| {
                (
                    p.url.clone(),
                    p.template.clone().unwrap_or_else(|| "page".into()),
                )
            })
            .collect();
        let home = site.pages.first().map(|p| p.url.as_str());
        for url in lighthouse_order(&class_of, home, scope, sampled_limit) {
            if let Some(id) = ids.get(&url) {
                storage::set_page_audit_depth(&tx, *id, AuditDepth::Full)?;
                queued += 1;
            }
        }
    }
    tx.commit()?;
    Ok(queued)
}

/// The run's Lighthouse queue as it stands: pages queued and not yet
/// measured, in the same coverage order the run was planned with. Rebuilt
/// from the stored pages, so a resumed run continues in the original order.
fn pending_lighthouse_queue(
    conn: &Connection,
    run_id: i64,
) -> slap_core::rusqlite::Result<(Vec<(i64, String)>, usize)> {
    let pages = storage::run_pages(conn, run_id)?;
    let awaiting: HashSet<i64> = storage::pages_awaiting_lighthouse(conn, run_id)?
        .iter()
        .filter_map(|p| p["id"].as_i64())
        .collect();
    let planned: Vec<&Json> = pages
        .iter()
        .filter(|p| p["audit_depth"].as_str() == Some("full"))
        .collect();
    let class_of: HashMap<String, String> = pages
        .iter()
        .filter(|p| !p["final_url"].is_null())
        .map(|p| {
            (
                p["url"].as_str().unwrap_or("").to_string(),
                p["template_class"].as_str().unwrap_or("page").to_string(),
            )
        })
        .collect();
    let home = pages
        .iter()
        .find(|p| p["role"] == "home")
        .and_then(|p| p["url"].as_str());
    let by_url: HashMap<&str, i64> = planned
        .iter()
        .filter_map(|p| Some((p["url"].as_str()?, p["id"].as_i64()?)))
        .collect();
    let mut queue = Vec::new();
    for url in lighthouse_order(&class_of, home, LighthouseScope::EveryPage, usize::MAX) {
        if let Some(id) = by_url.get(url.as_str()) {
            if awaiting.contains(id) {
                queue.push((*id, url));
            }
        }
    }
    // A queued page missing from the order (no final_url, which only a home
    // that failed to load has) still gets its turn rather than vanishing.
    for p in &planned {
        if let Some(id) = p["id"].as_i64() {
            if awaiting.contains(&id) && !queue.iter().any(|(q, _)| *q == id) {
                queue.push((id, p["url"].as_str().unwrap_or("").to_string()));
            }
        }
    }
    Ok((queue, planned.len()))
}

/// A path-safe name for a host, for the artifact directory.
fn safe_name(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
        .collect()
}

/// Write one gzipped JSON artifact, returning its size on disk.
fn write_gz_json(path: &Path, value: &Json) -> std::io::Result<i64> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let file = std::fs::File::create(&tmp)?;
        let mut gz = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        serde_json::to_writer(&mut gz, value)?;
        gz.finish()?.flush()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(std::fs::metadata(path).map(|m| m.len() as i64).unwrap_or(0))
}

/// What the run already says about the engine that measured it.
struct Provenance {
    lighthouse_version: Option<String>,
    chrome_version: Option<String>,
}

/// Write one measured page: its Lighthouse observations, its artifacts, and
/// (on the run's first success) the run's provenance. One transaction, so a
/// page is either fully recorded or still queued.
#[allow(clippy::too_many_arguments)]
fn persist_page_measurement(
    conn: &Connection,
    run_id: i64,
    page_id: i64,
    batch_dir: Option<&Path>,
    keep_lhr: bool,
    m: &crate::lighthouse::PageMeasurement,
    probed: Option<&Provenance>,
) -> slap_core::rusqlite::Result<()> {
    // Files first, outside the transaction: a crash between the two leaves an
    // orphan file that the resumed page overwrites, never a row pointing at
    // nothing.
    let mut files: Vec<(&str, String, i64)> = Vec::new();
    if let Some(dir) = batch_dir {
        if let Some(summary) = &m.summary {
            let path = dir.join(format!("page-{page_id}.lh-summary.json.gz"));
            if let Ok(size) = write_gz_json(&path, summary) {
                files.push(("lh-summary", path.display().to_string(), size));
            }
        }
        if keep_lhr {
            if let Some(lhr) = &m.lhr {
                let path = dir.join(format!("page-{page_id}.lhr.json.gz"));
                if let Ok(size) = write_gz_json(&path, lhr) {
                    files.push(("lhr", path.display().to_string(), size));
                }
            }
        }
    }

    let tx = conn.unchecked_transaction()?;
    storage::insert_observations(&tx, page_id, &m.observations)?;
    storage::set_page_audit_depth(&tx, page_id, AuditDepth::Full)?;
    for (kind, path, size) in &files {
        tx.execute(
            "DELETE FROM artifact WHERE page_id = ? AND kind = ?",
            params![page_id, kind],
        )?;
        storage::insert_artifact(&tx, run_id, kind, path, Some(page_id), None, Some(*size))?;
    }
    if let Some(meta) = &m.meta {
        // Existing values win: the first measured page decides a run's
        // provenance, and the probe's precise Chrome build beats the reduced
        // version an LHR's user agent carries.
        let lh = probed
            .and_then(|p| p.lighthouse_version.clone())
            .or_else(|| meta["lighthouseVersion"].as_str().map(String::from));
        let chrome = probed
            .and_then(|p| p.chrome_version.clone())
            .or_else(|| meta["chromeVersion"].as_str().map(String::from));
        tx.execute(
            "UPDATE run SET lh_version = COALESCE(lh_version, ?), \
             chrome_version = COALESCE(chrome_version, ?), \
             throttling_profile = COALESCE(throttling_profile, ?) WHERE id = ?",
            params![lh, chrome, meta["throttlingProfile"].as_str(), run_id],
        )?;
    }
    tx.commit()
}

/// Close a run: the run-level Lighthouse observations on the home page,
/// every page's findings evaluated from its stored observations, and the
/// terminal status. One transaction, so a run is either finished or still
/// resumable, never half-finished.
fn finalize_run(
    conn: &Connection,
    engine: &FindingsEngine,
    run_id: i64,
    error: Option<&str>,
) -> slap_core::rusqlite::Result<(usize, usize, usize)> {
    let run = storage::get_run(conn, run_id)?.unwrap_or(Json::Null);
    let pages = storage::run_pages(conn, run_id)?;
    let home_id = storage::home_page_id(conn, run_id)?;

    let tx = conn.unchecked_transaction()?;
    storage::clear_run_findings(&tx, run_id)?;

    // Run-level Lighthouse coverage and machine stability. Only for a run
    // that asked for Lighthouse; a light-only run has nothing to say here.
    if let (Some(scope), Some(home_id)) = (
        run["lh_scope"].as_str().and_then(LighthouseScope::parse),
        home_id,
    ) {
        tx.execute(
            "DELETE FROM observation WHERE page_id = ? AND metric_key LIKE 'lh.run.%'",
            params![home_id],
        )?;
        let mut planned = 0usize;
        let mut measured = 0usize;
        let mut failed = 0usize;
        let mut benchmarks: Vec<f64> = Vec::new();
        for p in &pages {
            if p["audit_depth"].as_str() != Some("full") {
                continue;
            }
            planned += 1;
            let values = storage::observations_as_dict(&tx, p["id"].as_i64().unwrap_or(0))?;
            match values.get("lh.runs").and_then(Value::as_f64) {
                Some(n) if n > 0.0 => {
                    measured += 1;
                    if let Some(b) = values.get("lh.benchmark_index").and_then(Value::as_f64) {
                        benchmarks.push(b);
                    }
                }
                Some(_) => failed += 1,
                None => {}
            }
        }
        let mut run_obs = vec![
            obs("lh.run.scope", Value::from(scope.label())),
            obs("lh.run.pages_planned", Value::Num(planned as f64)),
            obs("lh.run.pages_measured", Value::Num(measured as f64)),
            obs("lh.run.pages_failed", Value::Num(failed as f64)),
        ];
        if !benchmarks.is_empty() {
            let min = benchmarks.iter().cloned().fold(f64::MAX, f64::min);
            let max = benchmarks.iter().cloned().fold(f64::MIN, f64::max);
            run_obs.push(obs("lh.run.benchmark_min", Value::Num(min)));
            run_obs.push(obs("lh.run.benchmark_max", Value::Num(max)));
            if benchmarks.len() > 1 && max > 0.0 {
                let drift = ((max - min) / max * 1000.0).round() / 1000.0;
                run_obs.push(obs("lh.run.benchmark_drift", Value::Num(drift)));
            }
        }
        let run_obs: Vec<Observation> = run_obs.into_iter().filter_map(Result::ok).collect();
        storage::insert_observations(&tx, home_id, &run_obs)?;
    }

    let mut total_obs = 0usize;
    let mut total_findings = 0usize;
    for p in &pages {
        let page_id = p["id"].as_i64().unwrap_or(0);
        let values = storage::observations_as_dict(&tx, page_id)?;
        total_obs += tx.query_row(
            "SELECT COUNT(*) FROM observation WHERE page_id = ?",
            params![page_id],
            |row| row.get::<_, i64>(0),
        )? as usize;
        if values.is_empty() {
            continue;
        }
        if let Ok(findings) = engine.run(&values) {
            total_findings += storage::insert_findings(&tx, page_id, &findings)?;
        }
    }
    let status = if error.is_none() {
        RunStatus::Completed
    } else {
        RunStatus::Failed
    };
    storage::finish_run(&tx, run_id, status, error)?;
    tx.commit()?;
    Ok((pages.len(), total_obs, total_findings))
}

// ---------------------------------------------------------------------------
// The batch
// ---------------------------------------------------------------------------

/// One run to bring to completion.
struct Job {
    run_id: i64,
    requested_url: String,
    hostname: String,
    scope: Option<LighthouseScope>,
    index: usize,
}

/// Shared, read-only state for every job in a session.
struct Session<'a, E: Fn(Event) + Sync> {
    conn: &'a Connection,
    engine: FindingsEngine,
    client: reqwest::Client,
    bucket: Arc<TokenBucket>,
    cfg: &'a EngineConfig,
    session_id: String,
    total: usize,
    emit: &'a E,
    cancel: &'a CancelToken,
    lighthouse_gate: tokio::sync::Semaphore,
    probed: Option<Provenance>,
}

impl<'a, E: Fn(Event) + Sync> Session<'a, E> {
    fn new(
        conn: &'a Connection,
        cfg: &'a EngineConfig,
        session_id: String,
        total: usize,
        emit: &'a E,
        cancel: &'a CancelToken,
        probed: Option<Provenance>,
    ) -> Result<Self, String> {
        Ok(Self {
            conn,
            engine: FindingsEngine::load(None).map_err(|e| e.to_string())?,
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(cfg.timeout_secs))
                .build()
                .map_err(|e| e.to_string())?,
            bucket: TokenBucket::new(cfg.crux_rate_per_second),
            cfg,
            session_id,
            total,
            emit,
            cancel,
            lighthouse_gate: tokio::sync::Semaphore::new(cfg.lighthouse_concurrency.max(1)),
            probed,
        })
    }

    fn summary(&self, job: &Job, ok: bool, error: Option<String>) -> RunSummary {
        RunSummary {
            url: job.requested_url.clone(),
            hostname: job.hostname.clone(),
            run_id: Some(job.run_id),
            ok,
            pages: 0,
            observations: 0,
            findings: 0,
            error,
            interrupted: false,
            lighthouse_planned: 0,
            lighthouse_done: 0,
        }
    }

    /// Bring one run from wherever it is to finished, or leave it resumable
    /// if the batch is stopped first.
    async fn process(&self, job: Job) -> Result<RunSummary, String> {
        let conn = self.conn;
        let db = |e: slap_core::rusqlite::Error| e.to_string();
        if self.cancel.cancelled() {
            let mut s = self.summary(&job, false, None);
            s.interrupted = true;
            return Ok(s);
        }
        let has_pages = !storage::run_pages(conn, job.run_id).map_err(db)?.is_empty();
        let mut site_url = job.requested_url.clone();
        let mut site_error: Option<String> = None;

        if !has_pages {
            storage::start_run(conn, job.run_id).map_err(db)?;
            let site = light_pass(
                &self.client,
                &self.bucket,
                self.cfg,
                &self.session_id,
                &job.requested_url,
                job.index,
                self.total,
                self.emit,
            )
            .await;
            persist_light_pass(conn, job.run_id, &site, job.scope, self.cfg.lighthouse_pages)
                .map_err(db)?;
            site_url = site.event_url.clone();
            site_error = site.error;
        } else {
            storage::start_run(conn, job.run_id).map_err(db)?;
            site_url = normalize_url(&job.requested_url).unwrap_or_else(|_| site_url.clone());
            // The light pass was written, so it is known whether the home
            // page loaded: a home with no final URL is the failed-run case.
            let pages = storage::run_pages(conn, job.run_id).map_err(db)?;
            if pages
                .iter()
                .find(|p| p["role"] == "home")
                .is_some_and(|home| home["final_url"].is_null())
            {
                site_error = Some("The home page could not be fetched.".into());
            }
            (self.emit)(Event::SiteStarted {
                batch_id: self.session_id.clone(),
                url: site_url.clone(),
                index: job.index,
                total: self.total,
            });
        }

        // --- heavy pass ---
        let (queue, planned) = pending_lighthouse_queue(conn, job.run_id).map_err(db)?;
        let already = planned - queue.len();
        let page_count = storage::run_pages(conn, job.run_id).map_err(db)?.len();
        (self.emit)(Event::PagesPlanned {
            batch_id: self.session_id.clone(),
            url: site_url.clone(),
            run_id: job.run_id,
            pages: page_count,
            lighthouse_pages: planned,
            lighthouse_done: already,
        });

        let mut interrupted = false;
        if !queue.is_empty() && site_error.is_none() {
            match &self.cfg.lighthouse {
                None => {
                    // Asked for, but this session cannot drive a browser. Leave
                    // the run resumable rather than finishing it without the
                    // measurements it was queued for.
                    interrupted = true;
                    (self.emit)(Event::LogMessage {
                        batch_id: self.session_id.clone(),
                        text: format!(
                            "{site_url}: {} page(s) still need Lighthouse, which is not available in this session",
                            queue.len()
                        ),
                        level: "warning".into(),
                    });
                }
                Some(lh_cfg) => {
                    let batch_dir = self.cfg.artifact_dir.as_ref().map(|dir| {
                        let run = storage::get_run(conn, job.run_id).ok().flatten();
                        let batch = run
                            .as_ref()
                            .and_then(|r| r["batch_id"].as_str().map(String::from))
                            .unwrap_or_else(|| self.session_id.clone());
                        dir.join(safe_name(&batch)).join(safe_name(&job.hostname))
                    });
                    (self.emit)(Event::CollectorStarted {
                        batch_id: self.session_id.clone(),
                        url: site_url.clone(),
                        collector: "lighthouse".into(),
                    });
                    let run_id = job.run_id;
                    let outcomes: Vec<bool> = stream::iter(queue.into_iter().enumerate())
                        .map(|(i, (page_id, page_url))| {
                            let site_url = &site_url;
                            let batch_dir = batch_dir.as_deref();
                            async move {
                                if self.cancel.cancelled() {
                                    return false;
                                }
                                let Ok(_permit) = self.lighthouse_gate.acquire().await else {
                                    return false;
                                };
                                if self.cancel.cancelled() {
                                    return false;
                                }
                                let index = already + i + 1;
                                (self.emit)(Event::PageStarted {
                                    batch_id: self.session_id.clone(),
                                    url: site_url.clone(),
                                    page_url: page_url.clone(),
                                    index,
                                    total: planned,
                                });
                                let t0 = Instant::now();
                                let m = crate::lighthouse::measure_page(&page_url, lh_cfg).await;
                                let persisted = persist_page_measurement(
                                    conn,
                                    run_id,
                                    page_id,
                                    batch_dir,
                                    self.cfg.keep_lhr,
                                    &m,
                                    self.probed.as_ref(),
                                );
                                // A page whose write failed (a full disk, a
                                // database busy past its timeout) is NOT done:
                                // reporting it done would finalise the run
                                // without it. It stays queued, and the run
                                // stays resumable.
                                let written = persisted.is_ok();
                                (self.emit)(Event::PageFinished {
                                    batch_id: self.session_id.clone(),
                                    url: site_url.clone(),
                                    page_url,
                                    index,
                                    total: planned,
                                    ok: m.runs_ok > 0 && written,
                                    performance: m.performance(),
                                    seconds: t0.elapsed().as_secs_f64(),
                                    error: persisted
                                        .err()
                                        .map(|e| format!("could not save the result: {e}"))
                                        .or(m.error),
                                });
                                written
                            }
                        })
                        .buffer_unordered(self.cfg.lighthouse_concurrency.max(1))
                        .collect()
                        .await;
                    interrupted = outcomes.iter().any(|done| !done);
                    let measured = outcomes.iter().filter(|done| **done).count();
                    (self.emit)(Event::CollectorFinished {
                        batch_id: self.session_id.clone(),
                        url: site_url.clone(),
                        collector: "lighthouse".into(),
                        observations: measured,
                        ok: !interrupted,
                        error: None,
                    });
                }
            }
        }

        let (planned_now, done_now) = {
            let (queue, planned) = pending_lighthouse_queue(conn, job.run_id).map_err(db)?;
            (planned, planned - queue.len())
        };
        if interrupted {
            let mut s = self.summary(&job, false, None);
            s.interrupted = true;
            s.pages = page_count;
            s.lighthouse_planned = planned_now;
            s.lighthouse_done = done_now;
            return Ok(s);
        }

        let (pages, observations, findings) =
            finalize_run(conn, &self.engine, job.run_id, site_error.as_deref()).map_err(db)?;
        let ok = site_error.is_none();
        (self.emit)(Event::SiteFinished {
            batch_id: self.session_id.clone(),
            url: site_url,
            run_id: job.run_id,
            index: job.index,
            total: self.total,
            observations,
            findings,
            ok,
            error: site_error.clone(),
        });
        Ok(RunSummary {
            url: job.requested_url,
            hostname: job.hostname,
            run_id: Some(job.run_id),
            ok,
            pages,
            observations,
            findings,
            error: site_error,
            interrupted: false,
            lighthouse_planned: planned_now,
            lighthouse_done: done_now,
        })
    }

    async fn run_jobs(&self, jobs: Vec<Job>) -> Result<AuditSummary, String> {
        (self.emit)(Event::BatchStarted {
            batch_id: self.session_id.clone(),
            total: self.total,
        });
        let results: Vec<Result<RunSummary, String>> = stream::iter(jobs)
            .map(|job| self.process(job))
            .buffer_unordered(self.cfg.concurrency.max(1))
            .collect()
            .await;
        let mut runs = Vec::new();
        for r in results {
            runs.push(r?);
        }
        runs.sort_by_key(|r| r.run_id);
        let succeeded = runs.iter().filter(|r| r.ok).count();
        let interrupted = runs.iter().filter(|r| r.interrupted).count();
        let failed = runs.len() - succeeded - interrupted;
        (self.emit)(Event::BatchFinished {
            batch_id: self.session_id.clone(),
            total: self.total,
            succeeded,
            failed,
            cancelled: interrupted > 0,
        });
        Ok(AuditSummary {
            batch_id: self.session_id.clone(),
            total: self.total,
            succeeded,
            failed,
            interrupted,
            runs,
        })
    }
}

/// Ask the worker which engine will measure, once per session. A failure is
/// not fatal here: each page then records its own failure, which is what the
/// report needs to say "attempted and failed" rather than "never run".
async fn probe_provenance(cfg: &EngineConfig) -> Option<Provenance> {
    let lh = cfg.lighthouse.as_ref()?;
    let meta = crate::lighthouse::probe(lh).await.ok()?;
    Some(Provenance {
        lighthouse_version: meta["lighthouseVersion"].as_str().map(String::from),
        chrome_version: meta["chromeVersion"].as_str().map(String::from),
    })
}

/// Run an audit of every URL, persisting one run each, and return a summary.
pub async fn run_batch(
    conn: &Connection,
    urls: &[String],
    cfg: &EngineConfig,
    emit: impl Fn(Event) + Sync,
) -> Result<AuditSummary, String> {
    run_batch_controlled(conn, urls, cfg, &CancelToken::new(), emit).await
}

/// [`run_batch`] with a Stop button. Cancelling stops new work from starting;
/// pages already inside Chrome finish and are written, and every unfinished
/// run stays `pending`/`running` for [`resume_runs`].
pub async fn run_batch_controlled(
    conn: &Connection,
    urls: &[String],
    cfg: &EngineConfig,
    cancel: &CancelToken,
    emit: impl Fn(Event) + Sync,
) -> Result<AuditSummary, String> {
    let batch_id = format!("batch-{}", storage::utcnow());
    let scope = cfg.lighthouse.as_ref().map(|_| cfg.lighthouse_scope);

    // Every run is queued before any work starts, so an interrupted batch
    // can be resumed in full, including the sites it never reached.
    let mut jobs = Vec::new();
    for (i, raw) in urls.iter().enumerate() {
        let hostname = planned_hostname(raw);
        let site_id = storage::upsert_site(conn, &hostname, None, None).map_err(|e| e.to_string())?;
        let run_id = storage::create_pending_run(
            conn,
            &batch_id,
            site_id,
            slap_core::version(),
            slap_core::SCHEMA_VERSION,
            raw,
            scope.map(LighthouseScope::as_str),
        )
        .map_err(|e| e.to_string())?;
        jobs.push(Job {
            run_id,
            requested_url: raw.clone(),
            hostname,
            scope,
            index: i + 1,
        });
    }

    let probed = probe_provenance(cfg).await;
    let session = Session::new(conn, cfg, batch_id, urls.len(), &emit, cancel, probed)?;
    session.run_jobs(jobs).await
}

/// Why an unfinished run cannot simply carry on, if it cannot. Mixing two
/// engines inside one run would make its pages incomparable while the report
/// printed one provenance line over all of them, so a changed engine means a
/// fresh run, not a resumed one.
pub fn resume_blocker(
    run: &Json,
    current_slap: &str,
    lighthouse_version: Option<&str>,
    chrome_version: Option<&str>,
) -> Option<String> {
    let recorded = |key: &str| run[key].as_str().filter(|s| !s.is_empty());
    if !matches!(run["requested_url"].as_str(), Some(url) if !url.is_empty()) {
        return Some("it predates resumable audits".into());
    }
    if let Some(v) = recorded("slap_version") {
        if v != current_slap {
            return Some(format!("SLAP changed from {v} to {current_slap}"));
        }
    }
    if let (Some(was), Some(now)) = (recorded("lh_version"), lighthouse_version) {
        if was != now {
            return Some(format!("Lighthouse changed from {was} to {now}"));
        }
    }
    if let (Some(was), Some(now)) = (recorded("chrome_version"), chrome_version) {
        if !same_chrome(was, now) {
            return Some(format!("Chrome changed from {was} to {now}"));
        }
    }
    None
}

/// Whether two Chrome versions name the same browser. A run whose start-up
/// probe failed recorded the version from an LHR's user agent, which Chrome
/// REDUCES to `141.0.0.0`; that proves the major version and nothing more, so
/// it is compared on the major alone rather than read as a different Chrome
/// (which would throw away every measured page of a run that never changed
/// engine).
fn same_chrome(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    let reduced = |v: &str| v.ends_with(".0.0.0");
    if reduced(a) || reduced(b) {
        return a.split('.').next() == b.split('.').next();
    }
    false
}

/// Carry unfinished runs on to completion. A run whose engine is unchanged
/// continues in place: its finished pages are kept, and only the pages still
/// queued for Lighthouse are measured. A run measured by a different engine
/// is closed as cancelled, with the reason, and its site is audited afresh as
/// a new run in the same batch.
pub async fn resume_runs(
    conn: &Connection,
    run_ids: &[i64],
    cfg: &EngineConfig,
    cancel: &CancelToken,
    emit: impl Fn(Event) + Sync,
) -> Result<AuditSummary, String> {
    let wanted: HashSet<i64> = run_ids.iter().copied().collect();
    let rows: Vec<Json> = storage::unfinished_runs(conn)
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|r| r["id"].as_i64().is_some_and(|id| wanted.contains(&id)))
        .collect();

    let needs_lighthouse = rows.iter().any(|r| !r["lh_scope"].is_null());
    let probed = if needs_lighthouse {
        if cfg.lighthouse.is_none() {
            return Err("These runs were queued for Lighthouse, which is not available in this session."
                .into());
        }
        Some(probe_provenance(cfg).await.ok_or_else(|| {
            "Lighthouse could not start, so the runs were left as they are. Check Diagnostics."
                .to_string()
        })?)
    } else {
        None
    };

    let mut jobs = Vec::new();
    for (i, row) in rows.iter().enumerate() {
        let run_id = row["id"].as_i64().unwrap_or(0);
        let hostname = row["hostname"].as_str().unwrap_or("").to_string();
        let scope = row["lh_scope"].as_str().and_then(LighthouseScope::parse);
        let requested = row["requested_url"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(String::from)
            .unwrap_or_else(|| format!("https://{hostname}"));
        let blocker = resume_blocker(
            row,
            slap_core::version(),
            probed.as_ref().and_then(|p| p.lighthouse_version.as_deref()),
            probed.as_ref().and_then(|p| p.chrome_version.as_deref()),
        );
        match blocker {
            None => jobs.push(Job {
                run_id,
                requested_url: requested,
                hostname,
                scope,
                index: i + 1,
            }),
            Some(reason) => {
                let note = format!("Interrupted, and not resumed because {reason}; re-audited as a new run.");
                storage::finish_run(conn, run_id, RunStatus::Cancelled, Some(&note))
                    .map_err(|e| e.to_string())?;
                let site_id = row["site_id"].as_i64().unwrap_or(0);
                let new_id = storage::create_pending_run(
                    conn,
                    row["batch_id"].as_str().unwrap_or("batch-resumed"),
                    site_id,
                    slap_core::version(),
                    slap_core::SCHEMA_VERSION,
                    &requested,
                    scope.map(LighthouseScope::as_str),
                )
                .map_err(|e| e.to_string())?;
                emit(Event::LogMessage {
                    batch_id: "resume".into(),
                    text: format!("{hostname}: {note}"),
                    level: "warning".into(),
                });
                jobs.push(Job {
                    run_id: new_id,
                    requested_url: requested,
                    hostname,
                    scope,
                    index: i + 1,
                });
            }
        }
    }
    let session_id = format!("resume-{}", storage::utcnow());
    let total = jobs.len();
    let session = Session::new(conn, cfg, session_id, total, &emit, cancel, probed)?;
    session.run_jobs(jobs).await
}

/// Close unfinished runs the operator chose not to resume. Their partial
/// pages stay in the database as a cancelled run, which every completed-run
/// query already skips.
pub fn discard_runs(conn: &Connection, run_ids: &[i64]) -> Result<usize, String> {
    let unfinished: HashSet<i64> = storage::unfinished_runs(conn)
        .map_err(|e| e.to_string())?
        .iter()
        .filter_map(|r| r["id"].as_i64())
        .collect();
    let mut n = 0;
    for id in run_ids.iter().filter(|id| unfinished.contains(id)) {
        storage::finish_run(
            conn,
            *id,
            RunStatus::Cancelled,
            Some("Interrupted and discarded."),
        )
        .map_err(|e| e.to_string())?;
        n += 1;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> HashMap<String, String> {
        // home, page, contact, checkout, post x3, product x3.
        let mut pages = HashMap::new();
        pages.insert("https://x.com/".to_string(), "home".to_string());
        pages.insert("https://x.com/page".to_string(), "page".to_string());
        pages.insert("https://x.com/contact".to_string(), "contact".to_string());
        pages.insert("https://x.com/checkout".to_string(), "checkout".to_string());
        for i in 0..3 {
            pages.insert(format!("https://x.com/post/{i}"), "post".to_string());
            pages.insert(format!("https://x.com/product/{i}"), "product".to_string());
        }
        pages
    }

    #[test]
    fn every_page_order_measures_the_representatives_first() {
        let pages = fixture();
        let home = Some("https://x.com/");
        let sampled = lighthouse_order(&pages, home, LighthouseScope::Sampled, 4);
        let every = lighthouse_order(&pages, home, LighthouseScope::EveryPage, 4);

        assert_eq!(sampled.len(), 4);
        assert_eq!(every.len(), pages.len(), "every page, once");
        let unique: HashSet<&String> = every.iter().collect();
        assert_eq!(unique.len(), pages.len());

        // A batch stopped early has already measured one page of every
        // template, biggest templates first, before any template's second page.
        assert_eq!(every[0], "https://x.com/");
        let templates = pages.values().collect::<HashSet<_>>().len();
        let first_round: HashSet<&str> =
            every[..templates].iter().map(|u| pages[u].as_str()).collect();
        assert_eq!(first_round.len(), templates, "one per template first: {every:?}");
        assert_eq!(&every[..4], &sampled[..], "sampled is a prefix of every-page");

        // Deterministic: a resume rebuilds the same order.
        assert_eq!(every, lighthouse_order(&pages, home, LighthouseScope::EveryPage, 4));
    }

    #[test]
    fn the_estimate_is_pages_times_runs_over_concurrency() {
        // 1,840 pages, median of 3, 3 at a time: 1,840 x 30s = ~15.3 hours.
        let hours = lighthouse_seconds(1840, 3, 3) / 3600.0;
        assert!((hours - 15.33).abs() < 0.05, "{hours}");
        // The sampled default for 24 sites x 5 pages is under an hour.
        assert!(lighthouse_seconds(24 * 5, 3, 3) / 60.0 < 61.0);
    }

    #[test]
    fn a_changed_engine_blocks_a_resume_and_says_which() {
        let run = serde_json::json!({
            "requested_url": "example.com",
            "slap_version": "0.1.0",
            "lh_version": "13.4.1",
            "chrome_version": "141.0.7390.37",
        });
        assert_eq!(resume_blocker(&run, "0.1.0", Some("13.4.1"), Some("141.0.7390.37")), None);
        assert_eq!(
            resume_blocker(&run, "0.1.0", Some("13.4.1"), Some("142.0.7444.59")).as_deref(),
            Some("Chrome changed from 141.0.7390.37 to 142.0.7444.59")
        );
        assert!(resume_blocker(&run, "0.2.0", Some("13.4.1"), Some("141.0.7390.37"))
            .unwrap()
            .starts_with("SLAP changed"));
        // A reduced version (from an LHR user agent) is compared on its major.
        let reduced = serde_json::json!({
            "requested_url": "example.com", "slap_version": "0.1.0",
            "lh_version": "13.4.1", "chrome_version": "141.0.0.0",
        });
        assert_eq!(resume_blocker(&reduced, "0.1.0", Some("13.4.1"), Some("141.0.7390.37")), None);
        assert!(resume_blocker(&reduced, "0.1.0", Some("13.4.1"), Some("142.0.7444.59")).is_some());
        // Nothing measured yet: any engine may take it on.
        let fresh = serde_json::json!({ "requested_url": "example.com", "slap_version": "0.1.0" });
        assert_eq!(resume_blocker(&fresh, "0.1.0", Some("14.0.0"), Some("150.0")), None);
        // A run from before resumable audits cannot say what it was asked to do.
        let old = serde_json::json!({ "slap_version": "0.1.0" });
        assert!(resume_blocker(&old, "0.1.0", None, None).is_some());
    }
}
