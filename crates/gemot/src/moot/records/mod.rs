// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The Moot's replicated public record: declaration, roster, fauna, and
//! retention checkpoints. This is one lane within a Moot, not the Moot's
//! application boundary.

pub mod retention;
pub mod roster;
pub mod store;
pub mod wire;

#[cfg(test)]
mod sync;

pub use retention::{
    AvailabilityPolicy, CheckpointError, ErasurePolicy, GovernedCheckpointAuthority, KeepBound,
    LogFrontier, MootRetentionPolicy, MootRosterSnapshot, PolicyRevision, RetentionCheckpoint,
};
pub use roster::{Declaration, FaunaEntry, Member, MootRoster, fauna_cap};
pub use store::{MootStore, MootStoreError, MootStoreFile, StoredCheckpoint};
pub use wire::{
    MootEvent, MootExt, MootLogId, WireError, from_operation, to_operation, to_operation_seed,
    to_prune_operation, to_prune_operation_seed, verify,
};
