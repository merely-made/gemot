//! # Mooting
//!
//! Recognition policy for governed Moot spaces.
//!
//! [`RecognitionContext`] evaluates a recognition policy against a membership
//! set frozen at one signed revision. The generic [`MunimentStore`] moved to
//! `murm-replication`; this crate temporarily re-exports it for compatibility.
//!
//! ## Status
//!
//! Pre-1.0. Recognition policy is implemented. Generic replicated storage now
//! lives in `murm-replication`; domain folds stay in Moot.

#![doc(html_root_url = "https://docs.rs/mooting/0.0.1")]

pub mod recognition;
pub mod store;

pub use recognition::{
    ElectorateSnapshot, MemberKey, RecognitionContext, RecognitionDecision, RecognitionPolicy,
    RecognitionPolicyError,
};
pub use store::MunimentStore;

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Lifecycle stage marker.
pub const STAGE: &str = "pre-alpha";
