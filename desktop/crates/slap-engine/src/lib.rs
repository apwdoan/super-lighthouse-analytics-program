//! slap-engine: the audit engine. The collectors that measure a site and
//! the orchestration that runs them, persists a run, and reports progress.
//!
//! Kept out of slap-core so the mobile viewer never compiles an HTTP stack
//! it cannot use: a phone cannot audit (Lighthouse needs Node and a full
//! Chrome), so the phone wants the core's schema, storage, and rules, and
//! none of this.
//!
//! What is here today: the page collectors (HTTP, security headers,
//! cookies, redirects, the technology fingerprint, and software component
//! detection with its vulnerability match against the offline database),
//! the origin collectors (TLS introspection, CrUX field + history, and the
//! opt-in endpoint probe), multi-page discovery, the Lighthouse runner (a
//! Node sidecar), the batch runner that ties them together, and the client
//! report render. The auditing engine is feature-complete; the mobile
//! viewer and release hardening are what remain, tracked in the project doc.

pub mod components;
pub mod crux;
pub mod discovery;
pub mod fingerprint;
pub mod http;
pub mod lighthouse;
pub mod probe;
pub mod report;
pub mod run;
pub mod tls;
pub mod vulndb;
pub mod vulndb_build;

pub use run::{run_batch, AuditSummary, EngineConfig, RunSummary};
