//! # Mooting
//!
//! Backend-neutral p2panda storage primitives for signed multi-writer spaces.
//!
//! The gerund form (*mooting* = the act of holding a moot) names the protocol
//! plumbing; the singular noun (*moot* = a single community) is the user-facing
//! object. [`MunimentStore`] is intentionally generic enough for non-Moot
//! domains: consumers provide their operation extension, log id, backend,
//! validation, and materializer.
//!
//! ## Status
//!
//! Pre-1.0. The p2panda `OperationStore`, `LogStore`, and `TopicStore` adapter
//! over Muniment is implemented and exercised by multiple domains. Network
//! pumps and domain folds stay outside this crate.

#![doc(html_root_url = "https://docs.rs/mooting/0.0.1")]

pub mod store;

pub use store::MunimentStore;

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Lifecycle stage marker.
pub const STAGE: &str = "pre-alpha";
