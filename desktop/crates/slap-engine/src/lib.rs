//! slap-engine: the audit engine. The collectors that measure a site and
//! the orchestration that runs them, persists a run, and reports progress.
//!
//! Kept out of slap-core so the core stays a light, HTTP-free layer that
//! anything reading and rendering a stored audit can depend on without
//! pulling in a full HTTP and browser-driving stack: the core is schema,
//! storage, and rules; this crate is everything that reaches the network.
//!
//! What is here today: the page collectors (HTTP, security headers,
//! cookies, redirects, the technology fingerprint, and software component
//! detection with its vulnerability match against the offline database),
//! the origin collectors (TLS introspection, CrUX field + history, and the
//! opt-in endpoint probe), multi-page discovery, the Lighthouse runner (a
//! Node sidecar), the batch runner that ties them together, and the client
//! report render and its print to PDF. The auditing engine is
//! feature-complete; the mobile viewer and release hardening are what
//! remain, tracked in the project doc.

pub mod components;
pub mod crux;
pub mod discovery;
pub mod fingerprint;
pub mod http;
pub mod lighthouse;
pub mod pdf;
pub mod probe;
pub mod report;
pub mod run;
pub mod spawn;
pub mod tls;
pub mod vulndb;
pub mod vulndb_build;

pub use run::{
    discard_runs, estimate_batch, resume_runs, run_batch, run_batch_controlled, AuditSummary,
    BatchEstimate, EngineConfig, RunSummary,
};
