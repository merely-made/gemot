// Copyright 2026 Mark AB (markik)
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A Moot community and its bounded record lanes.
//!
//! [`Moot`] is the command and snapshot boundary. Its five retained domains are
//! [`constitution`], [`delegation`], [`group`], [`records`], and [`tessera`].
//! Hosts may adapt the signed wire/store types for LogSync, but Gemot owns
//! neither a network session nor a UI runtime.
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
pub mod delegation;
pub mod group;
mod id;
/// Cross-lane proof: every lane shares the Moot id as its topic, so the
/// combination needs its own receipt rather than one-lane-at-a-time ones.
#[cfg(test)]
mod lane_coexistence;
pub mod records;
mod service;
pub mod tessera;
pub mod typed_authorization;

pub use constitution::{
    MootGovernance, MootGovernanceError, MootGovernanceFile, MootGovernanceSnapshot,
};
pub use delegation::{
    MOOT_ACT_ACTION, MOOT_DELEGATION_DOMAIN, MootDelegationError, MootDelegationProjection,
    MootDelegations, MootScopeKeyEpoch,
};
pub use group::store::{MootGroupFileStore, MootGroupStore, MootGroupStoreError};
pub use group::wire::{MootGroupExt, MootGroupWireError, membership_identity_salt};
pub use group::{
    MootAccessLevel, MootGroup, MootGroupError, MootGroupHandle, MootGroupOperation,
    MootGroupOperationId, MootGroupSnapshot, MootGroupTransition, MootMember, MootMembershipAction,
    MootMembershipRecord, P2pandaGroupKeyEpoch, P2pandaScopeKeyEpoch,
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
pub use typed_authorization::{MootAuthority, TypedMootAuthorization};
