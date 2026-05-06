//! # Mooting
//!
//! Protocol core for community social-primitives selection — the modular
//! layer within [`moothold`](https://crates.io/crates/moothold) that lets
//! each moot select which social protocols and primitives to use (Matrix,
//! Nostr, IRC, ATproto, ActivityPub, and Mere-native moot infrastructure)
//! for the [`mere`](https://crates.io/crates/mere) browser.
//!
//! The gerund form (*mooting* = the act of holding a moot) names the
//! protocol plumbing; the singular noun (*moot* = a single community)
//! is the user-facing object. Each enabled protocol provides its own
//! mooting adapter; consumers of `moothold` see a unified social-primitive
//! API regardless of which protocol backs any given moot.
//!
//! ## Status
//!
//! Pre-1.0. This 0.0.x release reserves the crate name and documents intent;
//! implementation is in progress within the
//! [Mere workspace](https://crates.io/crates/mere).

#![doc(html_root_url = "https://docs.rs/mooting/0.0.1")]

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Lifecycle stage marker.
pub const STAGE: &str = "pre-alpha";
