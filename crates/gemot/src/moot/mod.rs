// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! A Moot community and its bounded record lanes.
//!
//! [`Moot`] is the command and snapshot boundary. Its retained domains are
//! [`constitution`], [`delegation`], [`group`], [`records`], [`standing`],
//! [`tulpa`], and [`flora`].
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

pub mod artifact;
pub mod constitution;
pub mod delegation;
pub mod flora;
pub mod group;
mod id;
/// Cross-lane proof: every lane shares the Moot id as its topic, so the
/// combination needs its own receipt rather than one-lane-at-a-time ones.
#[cfg(test)]
mod lane_coexistence;
mod lanes;
pub mod records;
mod service;
pub mod standing;
pub mod tulpa;
pub mod typed_authorization;

/// Read-only source-compatibility bridge for callers moving from the former
/// Tessera spelling. The signed event and extension layouts are unchanged, so
/// an existing `tessera.redb` corpus can be read as Standing facts. New
/// publication must use [`standing`] and `gemot/standing/v1`.
#[deprecated(note = "use gemot::moot::standing; the public lane is gemot/standing/v1")]
pub mod tessera {
    pub use super::standing::*;

    pub mod event {
        pub use super::super::standing::event::*;
        pub type TesseraEvent = super::super::standing::event::StandingEvent;
    }

    pub mod gate {
        pub use super::super::standing::gate::*;
        pub type TesseraFacts = super::super::standing::gate::StandingFacts;
    }

    pub mod ledger {
        pub use super::super::standing::ledger::*;
        pub type TesseraConfig = super::super::standing::ledger::StandingConfig;
    }

    pub mod persona_chain {
        pub use super::super::standing::persona_chain::*;
    }

    pub mod persona_vault {
        pub use super::super::standing::persona_vault::*;
    }

    pub mod store {
        pub use super::super::standing::store::*;
        pub type TesseraFileStore = super::super::standing::store::StandingFileStore;
        pub type TesseraStore<B> = super::super::standing::store::StandingStore<B>;
        pub type TesseraStoreError = super::super::standing::store::StandingStoreError;
    }

    pub mod wire {
        pub use super::super::standing::wire::*;
        pub type TesseraExt = super::super::standing::wire::StandingExt;
    }

    pub type TesseraEvent = super::standing::StandingEvent;
    pub type TesseraFacts = super::standing::StandingFacts;
    pub type TesseraConfig = super::standing::StandingConfig;
    pub type TesseraFileStore = super::standing::StandingFileStore;
    pub type TesseraStore<B> = super::standing::StandingStore<B>;
    pub type TesseraStoreError = super::standing::StandingStoreError;
    pub type TesseraExt = super::standing::StandingExt;
}

pub use artifact::ArtifactRef;
pub use constitution::{
    MootGovernance, MootGovernanceError, MootGovernanceFile, MootGovernanceSnapshot,
};
pub use delegation::{
    MOOT_ACT_ACTION, MOOT_DELEGATION_DOMAIN, MootDelegationError, MootDelegationProjection,
    MootDelegations, MootScopeKeyEpoch,
};
pub use flora::{
    FloraCandidateArtifact, FloraContributionReceipt, FloraEvent, FloraExt, FloraFileStore,
    FloraParticipant, FloraProjection, FloraRoundId, FloraRoundProjection, FloraRoundSpec,
    FloraStacking, FloraStore, FloraStoreError, FloraValidationError, FloraWeight,
};
pub use group::store::{MootGroupFileStore, MootGroupStore, MootGroupStoreError};
pub use group::wire::{MootGroupExt, MootGroupWireError, membership_identity_salt};
pub use group::{
    MootAccessLevel, MootGroup, MootGroupError, MootGroupHandle, MootGroupOperation,
    MootGroupOperationId, MootGroupSnapshot, MootGroupTransition, MootMember, MootMembershipAction,
    MootMembershipRecord, P2pandaGroupKeyEpoch, P2pandaScopeKeyEpoch,
};
pub use id::MootId;
pub use lanes::{
    GEMOT_CONSTITUTION_LANE, GEMOT_DELEGATION_LANE, GEMOT_FLORA_LANE, GEMOT_MEMBERSHIP_LANE,
    GEMOT_RECORDS_LANE, GEMOT_STANDING_LANE, GEMOT_TULPA_LANE, MootLanes,
};
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
pub use tulpa::{
    AdoptedTulpaVersion, TulpaEvent, TulpaExt, TulpaFact, TulpaFileStore, TulpaId, TulpaProjection,
    TulpaProposal, TulpaProposalId, TulpaStore, TulpaStoreError, TulpaVersion,
};
pub use typed_authorization::{MootAuthority, TypedMootAuthorization};
