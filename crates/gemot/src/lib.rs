//! # Gemot
//!
//! Community and federation supercrate for the
//! [`mere`](https://crates.io/crates/mere) browser. A *moot* is a single
//! persistent themed federatable graph-view community. `gemot` is the assembly
//! layer that manages Moot lifecycle, governance, replication, and Tessera
//! validation. Tier 3 federation lives in the sibling `moothold` crate.
//!
//! Inside `gemot`, the [`mooting`](https://crates.io/crates/mooting)
//! crate supplies backend-neutral p2panda storage and recognition-policy
//! plumbing. [`moot`] owns the community namespace: constitutional law, public
//! records, and Tessera trust facts sit beneath one aggregate boundary.
//!
//! ## Naming note
//!
//! *Gemot* is the Old English assembly from which *moot* descends. The crate
//! convenes the shared machinery across social tiers; *moothold* retains its
//! narrower meaning, a Tier 3 holding of moots.
//!
//! ## Status
//!
//! Pre-1.0. Signed Moot declarations, membership, fauna, deterministic roster
//! folds, trust records, and host-composed sync tests are implemented. Signed
//! constitutional governance has a durable fold and high-level command/snapshot
//! service. The aggregate `Moot` service now composes that governance with the
//! muniment-backed object lane, plain declare/join/share commands, durable
//! snapshots, constitution-bound retention checkpoints, rotation-safe
//! checkpoint ancestry, prefix pruning, and public/local native-drop
//! export/import with refreshed snapshots. Aggregate drops carry critical
//! constitution evidence before object records, so a fresh recipient can
//! verify a rotated checkpoint chain. Protected drops take an injected group
//! protector, and Tessera commands return an explicit host-publication seam.
//! Quorum rules and capability grants remain.

#![doc(html_root_url = "https://docs.rs/gemot/0.1.0")]

pub mod moot;

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Lifecycle stage marker.
pub const STAGE: &str = "pre-alpha";
