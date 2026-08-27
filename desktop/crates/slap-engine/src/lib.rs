//! slap-engine: the audit engine. The collectors that measure a site and
//! the orchestration that runs them, persists a run, and reports progress.
//!
//! Kept out of slap-core so the mobile viewer never compiles an HTTP stack
//! it cannot use: a phone cannot audit (Lighthouse needs Node and a full
//! Chrome), so the phone wants the core's schema, storage, and rules, and
//! none of this.
//!
//! What is here today: the no-browser collectors (HTTP, security headers,
//! cookies, redirects, technology fingerprint) and the batch runner. Still
//! to come, tracked in the project doc: TLS introspection, CrUX field data,
//! and the Lighthouse runner (a Node sidecar).

pub mod crux;
pub mod discovery;
pub mod fingerprint;
pub mod http;
pub mod lighthouse;
pub mod run;
pub mod tls;

pub use run::{run_batch, AuditSummary, EngineConfig, RunSummary};
