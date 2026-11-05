// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Aggregate domain service for one Moot.
//!
//! This is the application boundary above constitutional governance and the
//! replicated Moot object store. Commands take seeds and domain values, persist
//! through the shared processor, and return plain receipts and snapshots.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use muniment::{Backend, MemoryBackend, RedbBackend};
use p2panda_core::cbor::{decode_cbor_strict, encode_cbor};
use proofs::Digest;
use serde::{Deserialize, Serialize};
use servitor::{AuthorityProvider, Cap, Mode, Subject, cap_path};
use stickleback::{
    DropExportBudget, DropExportDecision, DropExportProfile, DropExportSelector, DropId,
    DropImportReport, DropLimits, DropProtector, DropRecord, DropWriteReceipt, EvidenceKind,
    MunimentStore, NativeDropError, decode_operation_record, export_topic_operations,
    read_plain_drop, read_protected_drop, write_plain_drop, write_protected_drop,
};

use super::constitution::{
    ConstitutionExt, ConstitutionRules, MootGovernance, MootGovernanceError, MootGovernanceSnapshot,
};
use super::delegation::{
    MootDelegationProjection, MootDelegationStore, MootDelegationStoreError, MootDelegations,
    MootScopeKeyEpoch,
};
use super::flora::{
    FloraEvent, FloraExt, FloraFileStore, FloraProjection, FloraStore, FloraStoreError,
};
use super::group::store::{MootGroupStore, MootGroupStoreError};
use super::group::wire::MootGroupExt;
use super::group::{MootGroup, MootGroupSnapshot, MootMembershipAction};

use super::MootId;
use super::records::{
    AvailabilityPolicy, CollectionChange, CollectionEvent, CollectionFork, CollectionId,
    CollectionRef, CollectionView, ErasurePolicy, FaunaEntry, MootEvent, MootRetentionPolicy,
    MootRoster, MootStore, MootStoreError, PolicyRevision, collection_cap, fauna_cap,
};
use super::tulpa::{
    TulpaEvent, TulpaExt, TulpaFileStore, TulpaProjection, TulpaStore, TulpaStoreError,
};
use super::typed_authorization::MootAuthority;
use mien::{
    DenyReason, GateDecision, StandingEvent, StandingExt, StandingFacts, StandingFileStore,
    StandingStore, StandingStoreError, authorize,
};

const CONSTITUTION_EVIDENCE_VERSION: u16 = 1;
const DELEGATION_EVIDENCE_VERSION: u16 = 1;
const DOMAIN_EVIDENCE_VERSION: u16 = 1;

/// Prefer the Standing file for new state, but keep the renamed domain able to
/// read an existing Tessera corpus. The wire structs retain their exact serde
/// layout, so no lossy rewrite or offline compaction is needed for this bridge.
fn standing_store_path(directory: &Path) -> PathBuf {
    let standing = directory.join("standing.redb");
    if standing.exists() {
        standing
    } else {
        let legacy = directory.join("tessera.redb");
        if legacy.exists() { legacy } else { standing }
    }
}

/// Stable privacy and radio-budget priorities for an importable Moot drop.
/// Every selected record remains full-bodied because a signed log with a
/// missing body cannot safely reconstruct governance or roster state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MootDropSelector {
    pub checkpoint_priority: u32,
    pub roster_priority: u32,
    pub fauna_priority: u32,
}

impl Default for MootDropSelector {
    fn default() -> Self {
        Self {
            checkpoint_priority: 100,
            roster_priority: 80,
            fauna_priority: 40,
        }
    }
}

impl DropExportSelector<super::MootExt> for MootDropSelector {
    fn select(&self, operation: &p2panda_core::Operation<super::MootExt>) -> DropExportDecision {
        let priority = match super::from_operation(operation) {
            Ok((_, MootEvent::RetentionCheckpoint { .. })) => self.checkpoint_priority,
            Ok((_, MootEvent::Declared { .. } | MootEvent::Joined { .. })) => self.roster_priority,
            Ok((
                _,
                MootEvent::Shared { .. }
                | MootEvent::Withdrawn { .. }
                | MootEvent::Collection { .. }
                | MootEvent::Workflow { .. }
                | MootEvent::HistoryPruned { .. },
            )) => self.fauna_priority,
            Err(_) => return DropExportDecision::Omit,
        };
        DropExportDecision::Full { priority }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ConstitutionEvidence {
    version: u16,
    operations: Vec<DropRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct DelegationEvidence {
    version: u16,
    operations: Vec<DropRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct DomainEvidence {
    version: u16,
    membership_operations: Vec<DropRecord>,
    #[serde(alias = "tessera_operations")]
    standing_operations: Vec<DropRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    tulpa_operations: Vec<DropRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    flora_operations: Vec<DropRecord>,
}

/// Retention settings supplied by the Moot's governed configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MootRetentionSettings {
    pub revision: PolicyRevision,
    pub availability: AvailabilityPolicy,
    pub erasure: ErasurePolicy,
}

impl MootRetentionSettings {
    fn resolve(
        &self,
        checkpoint_authority: super::GovernedCheckpointAuthority,
        checkpoint_authority_history: Vec<super::GovernedCheckpointAuthority>,
    ) -> MootRetentionPolicy {
        MootRetentionPolicy {
            revision: self.revision.clone(),
            checkpoint_authority,
            checkpoint_authority_history,
            availability: self.availability,
            erasure: self.erasure,
        }
    }
}

/// Latest accepted checkpoint, presented without wire-operation types.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MootCheckpointSnapshot {
    pub operation: [u8; 32],
    pub policy_revision: PolicyRevision,
    pub authority_revision: Digest,
    pub previous_checkpoint: Option<[u8; 32]>,
    pub frontier_count: usize,
    pub at_ms: u64,
}

/// Readable current state of one Moot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MootSnapshot {
    pub moot_id: MootId,
    pub governance: MootGovernanceSnapshot,
    /// Signed, converged membership and its retained-operation health.
    pub membership: MootGroupSnapshot,
    pub roster: MootRoster,
    pub checkpoint: Option<MootCheckpointSnapshot>,
    /// Signed delegated certificates retained in the current authority fold.
    pub delegated_certificates: usize,
    /// Signed Standing operations retained for the Moot's trust projection.
    pub standing_operations: usize,
    /// Retained Tulpa facts and their effective adopted versions.
    pub tulpa: TulpaProjection,
    /// Retained federated-LoRA facts and compatibility-checked candidates.
    pub flora: FloraProjection,
}

/// A request to evaluate one capability-scoped community action.
///
/// `subject` is the stable persona-chain root, not the signing key of a single
/// device or session. The capability path remains opaque to Gemot: Meadowcap,
/// a p2panda group-state adapter, or a local policy provider may each give it
/// its own structural meaning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MootAuthorizationRequest {
    pub subject: [u8; 32],
    pub capability_path: String,
    pub at_ms: u64,
}

/// Inputs supplied by the Moot's membership and capability authority.
///
/// The provider answers structural access and supplies the current Standing
/// facts. Its `facts.is_member` field is the single membership input for a
/// members-only constitution; `capability_covers` is the corresponding scoped
/// live decision. [`Moot::authorize_constitution_grant`] intersects it with the
/// signed constitutional grant state. Key material never crosses this API: a
/// group-key engine may back the provider later without putting decryption
/// authority in Gemot.
#[derive(Clone, Debug, Default)]
pub struct MootAuthorizationInputs {
    pub capability_covers: bool,
    pub facts: StandingFacts,
}

/// Supplies membership, scoped-capability, and reputation facts at the Moot
/// authorization seam.
///
/// This is deliberately an injected read boundary. The signed constitution
/// chooses the admission policy; the provider is the replaceable source of
/// current group membership and grants. A future p2panda group-state/key
/// adapter belongs here, rather than in the constitution fold or Standing log.
pub trait MootAuthorizationProvider {
    fn inputs(&self, request: &MootAuthorizationRequest) -> MootAuthorizationInputs;
}

/// Result of an object command. The operation id is enough for citations and
/// outbox tracking while the p2panda operation remains inside the store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MootCommandReceipt {
    pub operation: [u8; 32],
    pub lane: MootLane,
    pub snapshot: MootSnapshot,
}

/// The replicated lane an authored command must be published on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MootLane {
    Membership,
    Objects,
    Standing,
    Tulpa,
    Flora,
}

/// A signed operation recovered from a command receipt for host-side live
/// publication. Gemot stays transport-neutral; the host owns the typed handle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MootOutboundOperation {
    Membership(p2panda_core::Operation<MootGroupExt>),
    Object(p2panda_core::Operation<super::MootExt>),
    Standing(p2panda_core::Operation<StandingExt>),
    Tulpa(p2panda_core::Operation<TulpaExt>),
    Flora(p2panda_core::Operation<FloraExt>),
}

/// Native-drop import result plus the refreshed materialized view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MootDropImportReceipt {
    pub import: DropImportReport,
    pub constitution_operations: u64,
    pub delegation_operations: u64,
    pub membership_operations: u64,
    pub standing_operations: u64,
    pub tulpa_operations: u64,
    pub flora_operations: u64,
    pub snapshot: MootSnapshot,
}

/// Aggregate Moot service failure.
#[derive(Debug, thiserror::Error)]
pub enum MootError {
    #[error(transparent)]
    Governance(#[from] MootGovernanceError),
    #[error(transparent)]
    Store(#[from] MootStoreError),
    #[error(transparent)]
    Standing(#[from] StandingStoreError),
    #[error(transparent)]
    Tulpa(#[from] TulpaStoreError),
    #[error(transparent)]
    Flora(#[from] FloraStoreError),
    #[error(transparent)]
    Delegation(#[from] MootDelegationStoreError),
    #[error(transparent)]
    Membership(#[from] MootGroupStoreError),
    #[error("moot has no accepted retention checkpoint")]
    CheckpointMissing,
    #[error("moot storage directory: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Drop(#[from] NativeDropError),
    #[error("Moot drop needs full operation bodies")]
    HeaderOnlyDrop,
    #[error("Moot drop selection omitted {0} retained records; increase its byte budget")]
    IncompleteDropBudget(u64),
    #[error("Moot drop is missing critical constitution authority evidence")]
    ConstitutionEvidenceMissing,
    #[error("Moot drop carries malformed constitution authority evidence")]
    ConstitutionEvidenceMalformed,
    #[error("Moot drop carries malformed delegation authority evidence")]
    DelegationEvidenceMalformed,
    #[error("Moot drop carries malformed auxiliary domain evidence")]
    DomainEvidenceMalformed,
    #[error("authored operation is absent from its retained lane")]
    OutboundMissing,
    #[error("Moot authority denied the local command: {0:?}")]
    Unauthorized(DenyReason),
    #[error("withdrawal targets an unknown shared operation")]
    WithdrawalUnknownTarget,
    #[error("withdrawal identity did not author the target shared operation")]
    WithdrawalWrongIdentity,
    #[error("workflow command refused: {0}")]
    Workflow(String),
    #[error("collection event references another Moot")]
    ForeignCollection,
    #[error("collection fork does not reproduce its named parent membership")]
    InvalidCollectionFork,
    #[error("collection does not have an effective current view")]
    CollectionUnknown,
    #[error("collection change does not name the exact current heads")]
    StaleCollectionHeads,
    #[error("collection membership names a contribution outside current effective fauna")]
    IneffectiveCollectionContribution,
}

struct CurrentCollectionAuthority<'a> {
    typed: MootAuthority<'a>,
    group: &'a MootGroup,
    rules: &'a ConstitutionRules,
    at_ms: u64,
}

impl AuthorityProvider for CurrentCollectionAuthority<'_> {
    fn covers(&self, subject: Subject, needed: &Cap, mode: Mode) -> bool {
        if !self.typed.covers(subject, needed, mode) {
            return false;
        }
        let request = MootAuthorizationRequest {
            subject: subject.0,
            capability_path: cap_path(needed),
            at_ms: self.at_ms,
        };
        let inputs = self.group.inputs(&request);
        matches!(
            authorize(
                &self.rules.admission,
                inputs.capability_covers,
                &inputs.facts,
                self.at_ms,
            ),
            GateDecision::Allow
        )
    }
}

/// One Moot's constitutional and replicated object services.
#[derive(Clone)]
pub struct Moot<B> {
    moot_id: MootId,
    governance: MootGovernance<B>,
    objects: MootStore<B>,
    standing: StandingStore<B>,
    tulpa: TulpaStore<B>,
    flora: FloraStore<B>,
    delegations: MootDelegationStore<B>,
    membership: MootGroupStore<B>,
    retention: MootRetentionSettings,
}

/// Durable redb-backed aggregate Moot service.
pub type MootFile = Moot<RedbBackend>;

impl Moot<MemoryBackend> {
    pub fn in_memory(moot_id: MootId, founder: [u8; 32], retention: MootRetentionSettings) -> Self {
        Self {
            moot_id,
            governance: MootGovernance::in_memory(moot_id.0, founder),
            objects: MootStore::in_memory(),
            standing: StandingStore::in_memory(),
            tulpa: TulpaStore::in_memory(),
            flora: FloraStore::in_memory(),
            delegations: MootDelegationStore::in_memory(moot_id.0),
            membership: MootGroupStore::in_memory(moot_id.0),
            retention,
        }
    }
}

impl Moot<RedbBackend> {
    /// Open one Moot beneath `directory`. Governance and object data use
    /// separate redb files while presenting one domain service.
    pub async fn open(
        directory: impl AsRef<Path>,
        moot_id: MootId,
        founder: [u8; 32],
        retention: MootRetentionSettings,
    ) -> Result<Self, MootError> {
        std::fs::create_dir_all(directory.as_ref())?;
        let service = Self {
            moot_id,
            governance: MootGovernance::open(
                directory.as_ref().join("constitution.redb"),
                moot_id.0,
                founder,
            )?,
            objects: MootStore::at_path(directory.as_ref().join("objects.redb"))?,
            standing: StandingFileStore::open(standing_store_path(directory.as_ref()))?,
            tulpa: TulpaFileStore::open(directory.as_ref().join("tulpa.redb"))?,
            flora: FloraFileStore::open(directory.as_ref().join("flora.redb"))?,
            delegations: super::delegation::MootDelegationFileStore::open(
                directory.as_ref().join("delegations.redb"),
                moot_id.0,
            )?,
            membership: super::group::store::MootGroupFileStore::open(
                directory.as_ref().join("membership.redb"),
                moot_id.0,
            )?,
            retention,
        };
        match service.governance.snapshot().await {
            Ok(_) => service.refresh_retention_authority().await?,
            Err(MootGovernanceError::NotFounded) => {}
            Err(error) => return Err(error.into()),
        }
        Ok(service)
    }

    /// Reopen one already-founded Moot beneath `directory`.
    ///
    /// The governance founder is recovered from the retained signed genesis,
    /// keeping product bindings free of an independently asserted root key.
    pub async fn open_existing(
        directory: impl AsRef<Path>,
        moot_id: MootId,
        retention: MootRetentionSettings,
    ) -> Result<Self, MootError> {
        let service = Self {
            moot_id,
            governance: MootGovernance::open_existing(
                directory.as_ref().join("constitution.redb"),
                moot_id.0,
            )
            .await?,
            objects: MootStore::at_path(directory.as_ref().join("objects.redb"))?,
            standing: StandingFileStore::open(standing_store_path(directory.as_ref()))?,
            tulpa: TulpaFileStore::open(directory.as_ref().join("tulpa.redb"))?,
            flora: FloraFileStore::open(directory.as_ref().join("flora.redb"))?,
            delegations: super::delegation::MootDelegationFileStore::open(
                directory.as_ref().join("delegations.redb"),
                moot_id.0,
            )?,
            membership: super::group::store::MootGroupFileStore::open(
                directory.as_ref().join("membership.redb"),
                moot_id.0,
            )?,
            retention,
        };
        service.refresh_retention_authority().await?;
        Ok(service)
    }
}

impl<B: Backend + Clone> Moot<B> {
    pub fn moot_id(&self) -> MootId {
        self.moot_id
    }

    /// Constitution lane for host-composed LogSync publication.
    pub fn constitution_store(&self) -> MunimentStore<B, ConstitutionExt> {
        self.governance.sync_store()
    }

    /// Lower store boundary for host-composed LogSync and native-drop adapters.
    pub fn object_store(&self) -> &MootStore<B> {
        &self.objects
    }

    /// Lower store boundary for a host-composed Standing LogSync session.
    pub fn standing_store(&self) -> &StandingStore<B> {
        &self.standing
    }

    /// Lower store boundary for the social Tulpa lane.
    pub fn tulpa_store(&self) -> &TulpaStore<B> {
        &self.tulpa
    }

    /// Lower store boundary for the FLORA receipt lane.
    pub fn flora_store(&self) -> &FloraStore<B> {
        &self.flora
    }

    /// Independent delegation lane for host-composed LogSync publication.
    pub fn delegation_store(&self) -> &MootDelegationStore<B> {
        &self.delegations
    }

    /// The governance service, for the constitution lane's accept path.
    pub fn governance(&self) -> &MootGovernance<B> {
        &self.governance
    }

    /// Independent membership lane for host-composed LogSync publication.
    pub fn membership_store(&self) -> &MootGroupStore<B> {
        &self.membership
    }

    /// Current effective p2panda-auth membership.
    pub async fn membership(&self) -> Result<MootGroup, MootError> {
        Ok(self.membership.group().await?)
    }
}

#[cfg(test)]
#[path = "service/tests.rs"]
mod tests;

#[path = "service/governance.rs"]
mod governance;

#[path = "service/records.rs"]
mod records;

#[path = "service/workflow.rs"]
mod workflow;

#[path = "service/drop.rs"]
mod drop;
