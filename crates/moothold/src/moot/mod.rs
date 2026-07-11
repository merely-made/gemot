/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! The moot object — declare it, join it, share into its flora.
//!
//! The tessera lane ([`crate::tessera`]) carries a moot's trust receipts;
//! this lane carries the moot *itself*: the founding declaration (name +
//! charter), visible membership, and the **flora** — engram references
//! shared into the community (the hand-off eidetic's deferred consume half
//! picks up from). Same proven recipe, third lap: signed operations on the
//! event-DAG ([`wire`]), a deterministic order-independent fold
//! ([`roster`]), one transactional store write path ([`store`]) with a
//! sign-and-store [`author`](store::MootStore::author) helper. The LogSync
//! catch-up + live session is **host-composed** over [`transport::SyncedSpace`]:
//! after the sibling-posture purity split moot owns no p2panda-net, so the host
//! builds the pump (endpoint injected) and publishes authored ops.
//!
//! M1 trust is the ring rule: holding the moot id is membership
//! eligibility (the kith ring's definition). Invitations, capability
//! gating, and flora blob transfer are later milestones — the plan names
//! them rather than half-building them.

pub mod roster;
pub mod store;
#[cfg(test)]
mod sync;
pub mod wire;

pub use roster::{Declaration, FloraEntry, Member, MootRoster};
pub use store::{MootStore, MootStoreError};
pub use wire::{
    MootEvent, MootExt, WireError, from_operation, to_operation, to_operation_seed, verify,
};
