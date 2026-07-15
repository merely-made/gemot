/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! A Moot community and its bounded record lanes.
//!
//! [`Moot`] is the command and snapshot boundary. Its three lanes are
//! [`constitution`], [`records`], and [`tessera`]. Hosts may adapt the signed
//! wire/store types for LogSync, but Gemot owns neither a network session nor a
//! UI runtime.
//!
//! M1 trust is the ring rule: holding the moot id is membership
//! eligibility (the kith ring's definition). Invitations, capability
//! gating, and fauna blob transfer are later milestones — the plan names
//! them rather than half-building them.
//!
//! External identity providers author through raw protocol-scoped Ed25519
//! seeds. The folded roster exposes a membership revision committed only to the
//! winning signed join operations, so unrelated fauna does not invalidate
//! recognition contexts.

pub mod constitution;
mod id;
pub mod records;
mod service;
pub mod tessera;

pub use constitution::{
    MootGovernance, MootGovernanceError, MootGovernanceFile, MootGovernanceSnapshot,
};
pub use id::MootId;
pub use records::{
    AvailabilityPolicy, CheckpointError, Declaration, ErasurePolicy, FaunaEntry,
    GovernedCheckpointAuthority, KeepBound, LogFrontier, Member, MootEvent, MootExt, MootLogId,
    MootRetentionPolicy, MootRoster, MootRosterSnapshot, MootStore, MootStoreError, MootStoreFile,
    PolicyRevision, RetentionCheckpoint, StoredCheckpoint, WireError, from_operation, to_operation,
    to_operation_seed, to_prune_operation, to_prune_operation_seed, verify,
};
pub use service::{
    Moot, MootAuthorizationInputs, MootAuthorizationProvider, MootAuthorizationRequest,
    MootCheckpointSnapshot, MootCommandReceipt, MootDropImportReceipt, MootDropSelector, MootError,
    MootFile, MootLane, MootOutboundOperation, MootRetentionSettings, MootSnapshot,
};
