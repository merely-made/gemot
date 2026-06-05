//! # Moothold
//!
//! Community and federation supercrate for the
//! [`mere`](https://crates.io/crates/mere) browser. A *moot* is a single
//! persistent themed federatable graph-view community; a *coalition* is a
//! federation of moots (a sovereign cluster). `moothold` is the system that
//! holds them — manages moot lifecycle, coalition federation, replication, and
//! tessera (trust-token) validation across communities.
//!
//! Inside `moothold`, the [`mooting`](https://crates.io/crates/mooting)
//! crate is the protocol-core layer that handles selection between social
//! protocols (Matrix, Nostr, IRC, ATproto, ActivityPub, and Mere-native
//! moot infrastructure), with each protocol pluggable.
//!
//! ## Naming note
//!
//! The crate is called `moothold` (a *holding* of moots, in the Anglo-Saxon
//! sense — like *household*, *stronghold*, *freehold*). If the bare crate
//! name `moot` becomes available later, this crate will move there; for now,
//! `moothold` carries the supercrate role.
//!
//! ## Status
//!
//! Pre-1.0. This 0.0.x release reserves the crate name and documents intent;
//! implementation is in progress within the
//! [Mere workspace](https://crates.io/crates/mere).

#![doc(html_root_url = "https://docs.rs/moothold/0.0.1")]

pub mod tessera;

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Lifecycle stage marker.
pub const STAGE: &str = "pre-alpha";
