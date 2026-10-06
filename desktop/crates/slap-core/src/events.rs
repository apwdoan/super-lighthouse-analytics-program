//! Progress events: the seam between the core and any front-end.
//!
//! The core deliberately imports nothing from Tauri. It emits plain typed
//! events; front ends decide what to do with them. In the desktop shell
//! that is one subscriber forwarding each event to `app.emit(...)`, which
//! is the whole replacement for the web UI's SSE channel.
//!
//! What did NOT carry over: a queue-based sink. Older front ends needed one
//! because their main loop drained events off a background queue, and a
//! slow sink could clog every other producer. Tauri's event system does
//! its own cross-thread delivery, so that whole problem class (the one
//! that produced a sink drained mid-emit and dropped in the race) has no
//! Rust counterpart to house it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde::Serialize;

/// Every event carries the batch it belongs to; the shell adds transport
/// concerns (timestamps arrive with Tauri's own event envelope).
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    BatchStarted {
        batch_id: String,
        total: usize,
    },
    SiteStarted {
        batch_id: String,
        url: String,
        index: usize,
        total: usize,
    },
    /// A collector began work on a page. Exists so a progress UI can show
    /// what a site is *doing* rather than what it last finished: without
    /// it, a site sitting in a 90-second Lighthouse run displays the name
    /// of whichever collector completed before it.
    CollectorStarted {
        batch_id: String,
        url: String,
        collector: String,
    },
    CollectorFinished {
        batch_id: String,
        url: String,
        collector: String,
        observations: usize,
        ok: bool,
        error: Option<String>,
    },
    /// A site's light pass is written and its Lighthouse queue is known.
    /// This is the first moment a batch knows how many browser audits it
    /// holds, so it is what a progress view's ETA is built from: discovery
    /// decides the page count, and until it has run the count is a guess.
    PagesPlanned {
        batch_id: String,
        url: String,
        run_id: i64,
        pages: usize,
        lighthouse_pages: usize,
        /// Pages already measured in an earlier session (a resumed run).
        lighthouse_done: usize,
    },
    /// One page went into Chrome. `index` is 1-based within the site's
    /// Lighthouse queue, which runs in coverage order.
    PageStarted {
        batch_id: String,
        url: String,
        page_url: String,
        index: usize,
        total: usize,
    },
    /// One page's Lighthouse result (median of N runs) is on disk. Written
    /// before this is emitted, so whatever the UI saw finish survives a crash.
    PageFinished {
        batch_id: String,
        url: String,
        page_url: String,
        index: usize,
        total: usize,
        ok: bool,
        performance: Option<f64>,
        seconds: f64,
        error: Option<String>,
    },
    SiteFinished {
        batch_id: String,
        url: String,
        run_id: i64,
        index: usize,
        total: usize,
        observations: usize,
        findings: usize,
        ok: bool,
        error: Option<String>,
    },
    BatchFinished {
        batch_id: String,
        total: usize,
        succeeded: usize,
        failed: usize,
        cancelled: bool,
    },
    LogMessage {
        batch_id: String,
        text: String,
        level: String,
    },
}

impl Event {
    pub fn batch_id(&self) -> &str {
        match self {
            Event::BatchStarted { batch_id, .. }
            | Event::SiteStarted { batch_id, .. }
            | Event::CollectorStarted { batch_id, .. }
            | Event::CollectorFinished { batch_id, .. }
            | Event::PagesPlanned { batch_id, .. }
            | Event::PageStarted { batch_id, .. }
            | Event::PageFinished { batch_id, .. }
            | Event::SiteFinished { batch_id, .. }
            | Event::BatchFinished { batch_id, .. }
            | Event::LogMessage { batch_id, .. } => batch_id,
        }
    }

    /// Human-readable one-liner, matching the log-line format every
    /// front-end has rendered, so the log pane reads identically.
    pub fn message(&self) -> String {
        match self {
            Event::BatchStarted { total, .. } => format!("Batch started: {total} site(s)"),
            Event::SiteStarted {
                url, index, total, ..
            } => format!("[{index}/{total}] {url}"),
            Event::CollectorStarted { collector, .. } => format!("    {collector}: started"),
            Event::CollectorFinished {
                collector,
                observations,
                ok,
                error,
                ..
            } => {
                if *ok {
                    format!("    {collector}: {observations} observation(s)")
                } else {
                    format!(
                        "    {collector}: failed ({})",
                        error.as_deref().unwrap_or("unknown")
                    )
                }
            }
            Event::PagesPlanned {
                url,
                pages,
                lighthouse_pages,
                lighthouse_done,
                ..
            } => {
                if *lighthouse_done > 0 {
                    format!(
                        "    {url}: {pages} page(s), Lighthouse {lighthouse_done}/{lighthouse_pages} already done"
                    )
                } else {
                    format!("    {url}: {pages} page(s), {lighthouse_pages} queued for Lighthouse")
                }
            }
            Event::PageStarted {
                page_url,
                index,
                total,
                ..
            } => format!("    lighthouse [{index}/{total}] {page_url}"),
            Event::PageFinished {
                page_url,
                index,
                total,
                ok,
                performance,
                seconds,
                error,
                ..
            } => {
                if *ok {
                    let score = performance
                        .map(|p| format!("performance {}", p.round() as i64))
                        .unwrap_or_else(|| "measured".to_string());
                    format!("    lighthouse [{index}/{total}] {page_url}: {score} ({seconds:.0}s)")
                } else {
                    format!(
                        "    lighthouse [{index}/{total}] {page_url}: failed ({})",
                        error.as_deref().unwrap_or("unknown")
                    )
                }
            }
            Event::SiteFinished {
                url,
                index,
                total,
                observations,
                findings,
                ok,
                error,
                ..
            } => {
                if *ok {
                    format!(
                        "[{index}/{total}] {url} done ({observations} obs, {findings} findings)"
                    )
                } else {
                    format!(
                        "[{index}/{total}] {url} FAILED: {}",
                        error.as_deref().unwrap_or("unknown")
                    )
                }
            }
            Event::BatchFinished {
                succeeded,
                failed,
                cancelled,
                ..
            } => {
                let verb = if *cancelled { "cancelled" } else { "finished" };
                format!("Batch {verb}: {succeeded} ok, {failed} failed")
            }
            Event::LogMessage { text, .. } => text.clone(),
        }
    }
}

type Sink = Arc<dyn Fn(&Event) + Send + Sync>;

/// Fan-out for progress events. Safe to emit from any thread. A broken
/// front end must not kill a batch, which in Rust is enforced by the type
/// system rather than a try/except: sinks return nothing and cannot
/// propagate an error into the emitter.
#[derive(Default)]
pub struct EventBus {
    sinks: Mutex<Vec<(usize, Sink)>>,
    next_id: std::sync::atomic::AtomicUsize,
}

impl EventBus {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a subscription id for `unsubscribe`.
    pub fn subscribe(&self, sink: impl Fn(&Event) + Send + Sync + 'static) -> usize {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.sinks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push((id, Arc::new(sink)));
        id
    }

    pub fn unsubscribe(&self, id: usize) {
        self.sinks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retain(|(sink_id, _)| *sink_id != id);
    }

    pub fn emit(&self, event: &Event) {
        // Snapshot under the lock, call outside it: a slow sink must not
        // serialise every other producer.
        let sinks: Vec<Sink> = self
            .sinks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .map(|(_, sink)| Arc::clone(sink))
            .collect();
        for sink in sinks {
            sink(event);
        }
    }

    pub fn log(&self, batch_id: &str, text: &str, level: &str) {
        self.emit(&Event::LogMessage {
            batch_id: batch_id.to_string(),
            text: text.to_string(),
            level: level.to_string(),
        });
    }
}

/// Cooperative cancellation the UI's Stop button sets. Checked between
/// sites and between collectors, so a cancelled batch leaves every run row
/// in a coherent terminal state instead of a half-written one.
#[derive(Clone, Default)]
pub struct CancelToken {
    flag: Arc<AtomicBool>,
}

#[derive(Debug)]
pub struct BatchCancelled;

impl std::fmt::Display for BatchCancelled {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str("the batch was cancelled")
    }
}
impl std::error::Error for BatchCancelled {}

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    pub fn cancelled(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    pub fn check(&self) -> Result<(), BatchCancelled> {
        if self.cancelled() {
            Err(BatchCancelled)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_match_the_log_lines() {
        let started = Event::SiteStarted {
            batch_id: "b".into(),
            url: "https://example.com".into(),
            index: 2,
            total: 5,
        };
        assert_eq!(started.message(), "[2/5] https://example.com");

        let finished = Event::SiteFinished {
            batch_id: "b".into(),
            url: "https://example.com".into(),
            run_id: 1,
            index: 2,
            total: 5,
            observations: 30,
            findings: 4,
            ok: true,
            error: None,
        };
        assert_eq!(
            finished.message(),
            "[2/5] https://example.com done (30 obs, 4 findings)"
        );

        let batch = Event::BatchFinished {
            batch_id: "b".into(),
            total: 5,
            succeeded: 4,
            failed: 1,
            cancelled: false,
        };
        assert_eq!(batch.message(), "Batch finished: 4 ok, 1 failed");
    }

    #[test]
    fn page_events_read_as_log_lines_and_serialise_for_the_dock() {
        let finished = Event::PageFinished {
            batch_id: "b".into(),
            url: "https://example.com".into(),
            page_url: "https://example.com/shop".into(),
            index: 3,
            total: 20,
            ok: true,
            performance: Some(71.0),
            seconds: 88.4,
            error: None,
        };
        assert_eq!(
            finished.message(),
            "    lighthouse [3/20] https://example.com/shop: performance 71 (88s)"
        );
        let json = serde_json::to_value(&finished).unwrap();
        assert_eq!(json["type"], "page_finished");
        assert_eq!(json["total"], 20);

        let planned = Event::PagesPlanned {
            batch_id: "b".into(),
            url: "https://example.com".into(),
            run_id: 7,
            pages: 20,
            lighthouse_pages: 20,
            lighthouse_done: 0,
        };
        assert_eq!(
            planned.message(),
            "    https://example.com: 20 page(s), 20 queued for Lighthouse"
        );
    }

    #[test]
    fn the_bus_fans_out_and_unsubscribes() {
        use std::sync::atomic::AtomicUsize;

        let bus = EventBus::new();
        let seen = Arc::new(AtomicUsize::new(0));
        let seen_a = Arc::clone(&seen);
        let seen_b = Arc::clone(&seen);
        let a = bus.subscribe(move |_| {
            seen_a.fetch_add(1, Ordering::SeqCst);
        });
        let _b = bus.subscribe(move |_| {
            seen_b.fetch_add(1, Ordering::SeqCst);
        });

        bus.log("batch", "hello", "info");
        assert_eq!(seen.load(Ordering::SeqCst), 2);

        bus.unsubscribe(a);
        bus.log("batch", "again", "info");
        assert_eq!(seen.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn events_serialise_with_a_type_tag_for_the_ui() {
        let event = Event::CollectorStarted {
            batch_id: "b".into(),
            url: "https://example.com".into(),
            collector: "crux".into(),
        };
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["type"], "collector_started");
        assert_eq!(json["collector"], "crux");
    }

    #[test]
    fn cancellation_is_shared_across_clones() {
        let token = CancelToken::new();
        let clone = token.clone();
        assert!(token.check().is_ok());
        clone.cancel();
        assert!(token.cancelled());
        assert!(token.check().is_err());
    }
}
