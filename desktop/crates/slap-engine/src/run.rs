//! Batch orchestration: for each site, discover its pages, run every
//! collector, persist one run holding all the pages, emit progress. The Rust
//! face of `core.py`'s per-site pipeline.
//!
//! Collectors by scope, matching the Python design:
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
//! Concurrency: sites run concurrently, and within a site the page fetches run
//! concurrently too, both bounded. Persistence is a separate sequential phase
//! over the one connection, so the connection never crosses a task boundary.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures::stream::{self, StreamExt};
use slap_core::events::Event;
use slap_core::findings::FindingsEngine;
use slap_core::rusqlite::Connection;
use slap_core::schema::{obs, AuditDepth, DiscoveredVia, FormFactor, Observation, PageRole, Value};
use slap_core::storage::{self, CruxPoint, NewPage};

use crate::crux::{self, TokenBucket};
use crate::discovery::{self, DiscoveryConfig};
use crate::fingerprint::observations_from_html;
use crate::http::{fetch, normalize_url, observations_from_document, FetchedDocument};
use crate::tls;

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
    /// How many pages per site get the browser audit.
    pub lighthouse_pages: usize,
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
}

#[derive(Debug, serde::Serialize)]
pub struct AuditSummary {
    pub batch_id: String,
    pub total: usize,
    pub succeeded: usize,
    pub failed: usize,
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
    audit_depth: AuditDepth,
    observations: Vec<Observation>,
}

struct SiteData {
    url: String,
    hostname: String,
    /// Home first, then the other discovered pages.
    pages: Vec<PageData>,
    /// TLS + CrUX + discovery metadata: origin-scoped, so they attach to the
    /// home page rather than repeating on every page.
    origin_observations: Vec<Observation>,
    crux_history: Option<(String, String, Vec<CruxPoint>)>,
    /// The first Lighthouse run's meta (version, chrome, throttling), for the
    /// run's provenance row.
    lighthouse_meta: Option<serde_json::Value>,
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

/// Discover a site's pages, audit each one, run the origin collectors once,
/// and gather it all into a SiteData. Emits collector progress as it goes.
async fn audit_one_site(
    client: &reqwest::Client,
    bucket: &Arc<TokenBucket>,
    cfg: &EngineConfig,
    batch_id: &str,
    raw: &str,
    index: usize,
    total: usize,
    emit: &(impl Fn(Event) + Sync),
) -> SiteData {
    let normalized = match normalize_url(raw) {
        Ok(n) => n,
        Err(e) => {
            return SiteData {
                url: raw.to_string(),
                hostname: host_of(raw),
                pages: Vec::new(),
                origin_observations: Vec::new(),
                crux_history: None,
                lighthouse_meta: None,
                error: Some(e),
            }
        }
    };
    let origin = origin_of(&normalized);
    let timeout = Duration::from_secs(cfg.timeout_secs);
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

    // --- page-scoped collectors, one home + each discovered page ---
    started("http");
    let page_concurrency = cfg.discovery.pages_per_site.min(5).max(1);
    let fetched: Vec<(
        usize,
        String,
        Result<(FetchedDocument, Vec<Observation>), String>,
    )> = stream::iter(discovered.urls.iter().cloned().enumerate())
        .map(|(i, url)| async move { (i, url.clone(), fetch_page(client, &url, cfg).await) })
        .buffer_unordered(page_concurrency)
        .collect()
        .await;

    let mut pages: Vec<PageData> = Vec::new();
    let mut home_error = None;
    let mut page_obs_count = 0;
    for (i, url, result) in fetched {
        let is_home = i == 0;
        match result {
            Ok((doc, observations)) => {
                page_obs_count += observations.len();
                let template = discovery::classify_template(&url, Some(&doc.text), is_home);
                pages.push(PageData {
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
                    audit_depth: AuditDepth::Light,
                    observations,
                });
            }
            Err(e) => {
                if is_home {
                    home_error = Some(e);
                    // Keep a home page row so origin observations have a home.
                    pages.push(PageData {
                        url,
                        final_url: None,
                        role: PageRole::Home,
                        discovered_via: DiscoveredVia::Manual,
                        template: Some("home".into()),
                        audit_depth: AuditDepth::Light,
                        observations: Vec::new(),
                    });
                }
                // A non-home page that would not load is simply dropped.
            }
        }
    }
    finished("http", page_obs_count, home_error.is_none());
    // Home must be pages[0] regardless of completion order.
    pages.sort_by_key(|p| if p.role == PageRole::Home { 0 } else { 1 });

    // --- origin-scoped collectors, once ---
    started("tls");
    let tls_obs = tls::probe(&normalized, timeout, now_unix()).await;
    finished("tls", tls_obs.len(), true);

    let mut origin_observations = tls_obs;

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

    // --- Lighthouse (page-scoped, on a sample of representative pages) ---
    let mut lighthouse_meta = None;
    if let Some(lh_cfg) = &cfg.lighthouse {
        // One representative per template class, home first, coverage-ordered.
        let class_of: std::collections::HashMap<String, String> = pages
            .iter()
            .filter(|p| p.final_url.is_some())
            .map(|p| {
                (
                    p.url.clone(),
                    p.template.clone().unwrap_or_else(|| "page".into()),
                )
            })
            .collect();
        let home = pages.first().map(|p| p.url.clone());
        let chosen =
            discovery::choose_lighthouse_pages(&class_of, cfg.lighthouse_pages, home.as_deref());
        started("lighthouse");
        let mut lh_obs_count = 0;
        // Lighthouse is heavy (a whole browser per run); the roadmap caps it
        // hard. Run the chosen pages one at a time to keep CPU contention (and
        // therefore the numbers) honest.
        for url in &chosen {
            let (observations, meta) = crate::lighthouse::run_median(url, lh_cfg).await;
            if meta.is_some() && lighthouse_meta.is_none() {
                lighthouse_meta = meta;
            }
            if let Some(page) = pages.iter_mut().find(|p| &p.url == url) {
                lh_obs_count += observations.len();
                page.observations.extend(observations);
                page.audit_depth = AuditDepth::Full;
            }
        }
        finished("lighthouse", lh_obs_count, true);
    }

    SiteData {
        url: raw.to_string(),
        hostname: host_of(&normalized),
        pages,
        origin_observations,
        crux_history,
        lighthouse_meta,
        error: home_error,
    }
}

/// Run an audit of every URL, persisting one run each, and return a summary.
pub async fn run_batch(
    conn: &Connection,
    urls: &[String],
    cfg: &EngineConfig,
    emit: impl Fn(Event) + Sync,
) -> Result<AuditSummary, String> {
    let engine = FindingsEngine::load(None).map_err(|e| e.to_string())?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(cfg.timeout_secs))
        .build()
        .map_err(|e| e.to_string())?;
    let bucket = TokenBucket::new(cfg.crux_rate_per_second);

    let batch_id = format!("batch-{}", storage::utcnow());
    let total = urls.len();
    emit(Event::BatchStarted {
        batch_id: batch_id.clone(),
        total,
    });

    let gathered: Vec<SiteData> = stream::iter(urls.iter().enumerate())
        .map(|(index, raw)| {
            let (client, cfg, emit, batch_id, bucket) = (&client, &cfg, &emit, &batch_id, &bucket);
            async move {
                audit_one_site(client, bucket, cfg, batch_id, raw, index + 1, total, emit).await
            }
        })
        .buffer_unordered(cfg.concurrency)
        .collect()
        .await;

    let mut summaries = Vec::new();
    let (mut succeeded, mut failed) = (0usize, 0usize);
    for (index, site) in gathered.into_iter().enumerate() {
        let summary = persist_site(conn, &engine, &batch_id, site).map_err(|e| e.to_string())?;
        if summary.ok {
            succeeded += 1
        } else {
            failed += 1
        }
        emit(Event::SiteFinished {
            batch_id: batch_id.clone(),
            url: summary.url.clone(),
            run_id: summary.run_id.unwrap_or(0),
            index: index + 1,
            total,
            observations: summary.observations,
            findings: summary.findings,
            ok: summary.ok,
            error: summary.error.clone(),
        });
        summaries.push(summary);
    }

    emit(Event::BatchFinished {
        batch_id: batch_id.clone(),
        total,
        succeeded,
        failed,
        cancelled: false,
    });
    Ok(AuditSummary {
        batch_id,
        total,
        succeeded,
        failed,
        runs: summaries,
    })
}

fn persist_site(
    conn: &Connection,
    engine: &FindingsEngine,
    batch_id: &str,
    site: SiteData,
) -> slap_core::rusqlite::Result<RunSummary> {
    let site_id = storage::upsert_site(conn, &site.hostname, None, None)?;
    let run_id = storage::create_run(
        conn,
        batch_id,
        site_id,
        slap_core::version(),
        slap_core::SCHEMA_VERSION,
        None,
    )?;

    if let Some((origin, form_factor, points)) = &site.crux_history {
        storage::insert_crux_history(conn, origin, form_factor, points)?;
    }

    // Record which engine produced the run, from Lighthouse's meta. A report
    // without provenance gets argued with.
    if let Some(meta) = &site.lighthouse_meta {
        storage::set_run_provenance(
            conn,
            run_id,
            meta["lighthouseVersion"].as_str(),
            meta["chromeVersion"].as_str(),
            meta["throttlingProfile"].as_str(),
        )?;
    }

    let mut total_obs = 0;
    let mut total_findings = 0;
    let page_count = site.pages.len();
    for (i, page) in site.pages.into_iter().enumerate() {
        let mut new_page = NewPage::new(&page.url);
        new_page.final_url = page.final_url.as_deref();
        new_page.form_factor = FormFactor::None;
        new_page.role = page.role;
        new_page.discovered_via = page.discovered_via;
        new_page.audit_depth = page.audit_depth;
        new_page.template_class = page.template.as_deref();
        let page_id = storage::create_page(conn, run_id, &new_page)?;

        // The origin observations (TLS, CrUX, discovery) land on the home
        // page, which is pages[0] after the sort in audit_one_site.
        let mut observations = page.observations;
        if i == 0 {
            observations.extend(site.origin_observations.iter().cloned());
        }
        total_obs += observations.len();
        if !observations.is_empty() {
            storage::insert_observations(conn, page_id, &observations)?;
            let values: std::collections::HashMap<String, Value> = observations
                .iter()
                .map(|o| (o.metric_key.to_string(), o.value()))
                .collect();
            if let Ok(findings) = engine.run(&values) {
                total_findings += storage::insert_findings(conn, page_id, &findings)?;
            }
        }
    }

    let ok = site.error.is_none();
    let status = if ok {
        slap_core::schema::RunStatus::Completed
    } else {
        slap_core::schema::RunStatus::Failed
    };
    storage::finish_run(conn, run_id, status, site.error.as_deref())?;

    Ok(RunSummary {
        url: site.url,
        hostname: site.hostname,
        run_id: Some(run_id),
        ok,
        pages: page_count,
        observations: total_obs,
        findings: total_findings,
        error: site.error,
    })
}
