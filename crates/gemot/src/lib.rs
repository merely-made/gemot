// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! # Gemot
//!
//! Community and federation supercrate for the
//! [`mere`](https://crates.io/crates/mere) browser. A *moot* is a single
//! persistent themed federatable graph-view community. `gemot` is the assembly
//! layer that manages Moot lifecycle, governance, replication, and Standing
//! validation. Tier 3 federation lives in the sibling `moothold` crate.
//!
//! Inside `gemot`, the [`mooting`](https://crates.io/crates/mooting)
//! crate supplies backend-neutral p2panda storage and recognition-policy
//! plumbing. [`moot`] owns the community namespace: constitutional law,
//! delegation, membership, public records, Standing trust facts, Tulpa
//! adoption, and FLORA receipts sit beneath one aggregate boundary.
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
//! service. The aggregate `Moot` service now composes that governance with
//! signed membership, delegation, object, Standing, Tulpa, and FLORA stores,
//! plain commands, durable snapshots, constitution-bound retention checkpoints, rotation-safe
//! checkpoint ancestry, prefix pruning, and public/local native-drop
//! export/import. Aggregate drops reconstruct all seven retained domains on a
//! fresh recipient. Protected drops take an injected group protector, and
//! membership, object, Standing, Tulpa, and FLORA commands return explicit
//! host-publication seams. Tulpa uses frozen recognition contexts and retains
//! revocation history; FLORA carries references and receipts only, never raw
//! tensors or training corpus bytes.
//! The signed admission policy now evaluates an injected membership/capability
//! provider. Founder-governed signed grants narrow that provider's live
//! decision; quorum amendments and the p2panda-auth group adapter are
//! implemented. Membership has a Gemot-owned signed wire grammar and durable
//! store; a verified derived-key attestation binds its signer to a stable
//! Personae root. The adapter binds membership changes to a host-owned
//! p2panda-encryption group-secret epoch. Independent Personae-signed
//! certificates now attenuate constitutional grant roots through a Gemot fold,
//! including cascading certificate and root revocation. Their signed p2panda
//! lane survives durable reopen, out-of-order arrival, and live late-peer
//! catch-up. Aggregate drops carry it as critical capability-chain evidence.
//! Deterministic read-only participant projections and revocation-derived
//! scope-key epochs preserve the signed-ledger and host-encryption boundaries.

#![doc(html_root_url = "https://docs.rs/gemot/0.1.0")]

pub mod moot;

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Lifecycle stage marker.
pub const STAGE: &str = "pre-alpha";
