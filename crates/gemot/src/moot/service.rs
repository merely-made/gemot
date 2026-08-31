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
use p2panda_core::cbor::{decode_cbor, encode_cbor};
use proofs::Digest;
use serde::{Deserialize, Serialize};
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
    AvailabilityPolicy, ErasurePolicy, FaunaEntry, MootEvent, MootRetentionPolicy, MootRoster,
    MootStore, MootStoreError, PolicyRevision,
};
use super::standing::{
    GateDecision, StandingEvent, StandingExt, StandingFacts, StandingFileStore, StandingStore,
    StandingStoreError, authorize,
};
use super::tulpa::{
    TulpaEvent, TulpaExt, TulpaFileStore, TulpaProjection, TulpaStore, TulpaStoreError,
};
use super::typed_authorization::MootAuthority;

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
            Ok((_, MootEvent::Shared { .. } | MootEvent::HistoryPruned { .. })) => {
                self.fauna_priority
            }
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

    async fn refresh_retention_authority(&self) -> Result<(), MootError> {
        let authority = self.governance.checkpoint_authority().await?;
        let history = self.governance.checkpoint_authority_history().await?;
        self.objects
            .set_retention_policy(Some(self.retention.resolve(authority, history)));
        Ok(())
    }

    /// Establish this Moot's first constitution and activate its checkpoint
    /// authority for subsequent object commands.
    pub async fn found(
        &self,
        founder_seed: [u8; 32],
        parent_constitution: Option<Digest>,
        divergence_point: Option<Digest>,
        rules: ConstitutionRules,
        at_ms: u64,
    ) -> Result<MootSnapshot, MootError> {
        self.governance
            .found(
                founder_seed,
                parent_constitution,
                divergence_point,
                rules,
                at_ms,
            )
            .await?;
        self.refresh_retention_authority().await?;
        self.snapshot().await
    }

    /// Amend the constitution and atomically switch future checkpoint
    /// admission to the accepted authority revision.
    pub async fn amend(
        &self,
        actor_seed: [u8; 32],
        rules: ConstitutionRules,
        at_ms: u64,
    ) -> Result<MootSnapshot, MootError> {
        self.governance.amend(actor_seed, rules, at_ms).await?;
        self.refresh_retention_authority().await?;
        self.snapshot().await
    }

    /// Evaluate a capability-scoped action under the currently accepted,
    /// signed admission rule.
    ///
    /// The provider supplies mutable membership/capability facts; the rule it
    /// is evaluated against comes only from the accepted constitution. This
    /// prevents a host from quietly changing a Moot from open to members-only
    /// or weakening its standing floor outside the replicated law.
    pub async fn authorize<P: MootAuthorizationProvider>(
        &self,
        provider: &P,
        request: &MootAuthorizationRequest,
    ) -> Result<GateDecision, MootError> {
        let policy = self.governance.snapshot().await?.rules.admission;
        let inputs = provider.inputs(request);
        Ok(authorize(
            &policy,
            inputs.capability_covers,
            &inputs.facts,
            request.at_ms,
        ))
    }

    /// Evaluate a current signed constitutional grant and a provider's live
    /// structural decision together.
    ///
    /// Both checks must pass. The constitutional grant is portable, signed
    /// authority; the provider supplies the present group/session condition
    /// that can narrow it immediately. This permits future group-key rotation
    /// or local device policy to deny access without rewriting constitutional
    /// history.
    pub async fn authorize_constitution_grant<P: MootAuthorizationProvider>(
        &self,
        provider: &P,
        request: &MootAuthorizationRequest,
    ) -> Result<GateDecision, MootError> {
        let governance = self.governance.snapshot().await?;
        let inputs = provider.inputs(request);
        let grant_covers =
            governance
                .rules
                .grant_covers(request.subject, &request.capability_path, request.at_ms);
        Ok(authorize(
            &governance.rules.admission,
            grant_covers && inputs.capability_covers,
            &inputs.facts,
            request.at_ms,
        ))
    }

    /// Evaluate independently delegated authority and the provider's current
    /// structural decision under the accepted constitutional admission rule.
    pub async fn delegations(&self) -> Result<MootDelegations, MootError> {
        let rules = self.governance.snapshot().await?.rules;
        Ok(self.delegations.delegations(&rules).await?)
    }

    /// Deterministic authority projections for a participant graph. Callers
    /// may replace their projection nodes from this value, never petition the
    /// graph to mutate the underlying authority ledger.
    pub async fn delegation_projections(
        &self,
        at_ms: u64,
    ) -> Result<Vec<MootDelegationProjection>, MootError> {
        let rules = self.governance.snapshot().await?.rules;
        Ok(self
            .delegations
            .delegations(&rules)
            .await?
            .projections(self.moot_id.0, &rules, at_ms))
    }

    /// Scope-key epochs the host encryption engine must bind and distribute.
    pub async fn delegation_scope_key_epochs(&self) -> Result<Vec<MootScopeKeyEpoch>, MootError> {
        Ok(self.delegations().await?.scope_key_epochs())
    }

    /// Evaluate the aggregate's retained independent delegation lane.
    pub async fn authorize_current_delegated<P: MootAuthorizationProvider>(
        &self,
        provider: &P,
        request: &MootAuthorizationRequest,
    ) -> Result<GateDecision, MootError> {
        let governance = self.governance.snapshot().await?;
        let delegations = self.delegations.delegations(&governance.rules).await?;
        self.authorize_delegated(&delegations, provider, request)
            .await
    }

    /// Evaluate caller-supplied delegated authority. Prefer
    /// [`Self::authorize_current_delegated`] for the aggregate-owned lane.
    pub async fn authorize_delegated<P: MootAuthorizationProvider>(
        &self,
        delegations: &super::MootDelegations,
        provider: &P,
        request: &MootAuthorizationRequest,
    ) -> Result<GateDecision, MootError> {
        let governance = self.governance.snapshot().await?;
        let inputs = provider.inputs(request);
        let grant_covers = delegations.covers(
            self.moot_id.0,
            &governance.rules,
            request.subject,
            &request.capability_path,
            request.at_ms,
        );
        Ok(authorize(
            &governance.rules.admission,
            grant_covers && inputs.capability_covers,
            &inputs.facts,
            request.at_ms,
        ))
    }

    pub async fn declare(
        &self,
        actor_seed: [u8; 32],
        name: String,
        charter: String,
        at_ms: u64,
    ) -> Result<MootCommandReceipt, MootError> {
        self.governance.snapshot().await?;
        self.author_object(
            actor_seed,
            MootEvent::Declared {
                name,
                charter,
                at_ms,
            },
        )
        .await
    }

    pub async fn join(
        &self,
        actor_seed: [u8; 32],
        name: String,
        at_ms: u64,
    ) -> Result<MootCommandReceipt, MootError> {
        self.governance.snapshot().await?;
        self.author_object(actor_seed, MootEvent::Joined { name, at_ms })
            .await
    }

    pub async fn share(
        &self,
        actor_seed: [u8; 32],
        manifest_id: [u8; 32],
        schema_id: String,
        title: String,
        at_ms: u64,
    ) -> Result<MootCommandReceipt, MootError> {
        self.governance.snapshot().await?;
        self.author_object(
            actor_seed,
            MootEvent::Shared {
                manifest_id,
                schema_id,
                title,
                at_ms,
            },
        )
        .await
    }

    async fn author_object(
        &self,
        actor_seed: [u8; 32],
        event: MootEvent,
    ) -> Result<MootCommandReceipt, MootError> {
        let operation = self
            .objects
            .author_seed(actor_seed, self.moot_id.0, &event)
            .await?;
        Ok(MootCommandReceipt {
            operation: *operation.hash.as_bytes(),
            lane: MootLane::Objects,
            snapshot: self.snapshot().await?,
        })
    }

    /// Author a membership change directly under a stable identity key.
    pub async fn update_membership(
        &self,
        actor_seed: [u8; 32],
        action: MootMembershipAction,
    ) -> Result<MootCommandReceipt, MootError> {
        self.governance.snapshot().await?;
        let operation = self.membership.author_seed(actor_seed, action).await?;
        Ok(MootCommandReceipt {
            operation: *operation.hash.as_bytes(),
            lane: MootLane::Membership,
            snapshot: self.snapshot().await?,
        })
    }

    /// Author a membership change under a Moot-derived key certified by the
    /// stable Personae root.
    pub async fn update_membership_for_identity<P: identity::IdentityProvider + ?Sized>(
        &self,
        identity: &P,
        action: MootMembershipAction,
    ) -> Result<MootCommandReceipt, MootError> {
        self.governance.snapshot().await?;
        let operation = self
            .membership
            .author_for_identity(identity, action)
            .await?;
        Ok(MootCommandReceipt {
            operation: *operation.hash.as_bytes(),
            lane: MootLane::Membership,
            snapshot: self.snapshot().await?,
        })
    }

    /// Record one Standing fact through the same aggregate command surface.
    /// The receipt can be resolved with [`outbound`](Self::outbound) and
    /// published by the host on its Standing LogSync handle.
    pub async fn record_standing(
        &self,
        actor_seed: [u8; 32],
        event: StandingEvent,
    ) -> Result<MootCommandReceipt, MootError> {
        self.governance.snapshot().await?;
        let operation = self
            .standing
            .author_seed(actor_seed, self.moot_id.0, &event)
            .await?;
        Ok(MootCommandReceipt {
            operation: *operation.hash.as_bytes(),
            lane: MootLane::Standing,
            snapshot: self.snapshot().await?,
        })
    }

    /// Retain one Tulpa proposal or endorsement. Recognition remains a
    /// projection over the proposal's frozen electorate, so recording this fact
    /// never grants its author a separate governance power.
    pub async fn record_tulpa(
        &self,
        actor_seed: [u8; 32],
        event: TulpaEvent,
    ) -> Result<MootCommandReceipt, MootError> {
        self.governance.snapshot().await?;
        let operation = self
            .tulpa
            .author_seed(actor_seed, self.moot_id.0, &event)
            .await?;
        Ok(MootCommandReceipt {
            operation: *operation.hash.as_bytes(),
            lane: MootLane::Tulpa,
            snapshot: self.snapshot().await?,
        })
    }

    /// Retain a FLORA round specification, contribution receipt, or candidate
    /// artifact reference. The operation contains no training or tensor bytes.
    pub async fn record_flora(
        &self,
        actor_seed: [u8; 32],
        event: FloraEvent,
    ) -> Result<MootCommandReceipt, MootError> {
        self.governance.snapshot().await?;
        let operation = self
            .flora
            .author_seed(actor_seed, self.moot_id.0, &event)
            .await?;
        Ok(MootCommandReceipt {
            operation: *operation.hash.as_bytes(),
            lane: MootLane::Flora,
            snapshot: self.snapshot().await?,
        })
    }

    /// Recover an authored operation for host-side publication. This is the
    /// only operation-typed aggregate API: transport ownership stays outside
    /// Gemot while commands and receipts stay plain.
    pub async fn outbound(
        &self,
        receipt: &MootCommandReceipt,
    ) -> Result<MootOutboundOperation, MootError> {
        let hash = p2panda_core::Hash::from_bytes(receipt.operation);
        match receipt.lane {
            MootLane::Membership => self
                .membership
                .get(&hash)
                .await?
                .map(MootOutboundOperation::Membership)
                .ok_or(MootError::OutboundMissing),
            MootLane::Objects => self
                .objects
                .operation(&hash)
                .await?
                .map(MootOutboundOperation::Object)
                .ok_or(MootError::OutboundMissing),
            MootLane::Standing => self
                .standing
                .get(&hash)
                .await?
                .map(MootOutboundOperation::Standing)
                .ok_or(MootError::OutboundMissing),
            MootLane::Tulpa => self
                .tulpa
                .get(&hash)
                .await?
                .map(MootOutboundOperation::Tulpa)
                .ok_or(MootError::OutboundMissing),
            MootLane::Flora => self
                .flora
                .get(&hash)
                .await?
                .map(MootOutboundOperation::Flora)
                .ok_or(MootError::OutboundMissing),
        }
    }

    /// Author the next checkpoint under the currently accepted constitution.
    pub async fn checkpoint(
        &self,
        actor_seed: [u8; 32],
        at_ms: u64,
    ) -> Result<MootCommandReceipt, MootError> {
        self.refresh_retention_authority().await?;
        let checkpoint = self.objects.build_checkpoint(self.moot_id.0, at_ms).await?;
        self.author_object(
            actor_seed,
            MootEvent::RetentionCheckpoint {
                checkpoint: Box::new(checkpoint),
            },
        )
        .await
    }

    /// Retire this actor's event prefix at the latest accepted checkpoint.
    pub async fn prune_current(
        &self,
        actor_seed: [u8; 32],
        at_ms: u64,
    ) -> Result<MootCommandReceipt, MootError> {
        let checkpoint = self
            .objects
            .latest_checkpoint(self.moot_id.0)
            .await?
            .ok_or(MootError::CheckpointMissing)?;
        let operation = self
            .objects
            .author_prune_seed(actor_seed, self.moot_id.0, checkpoint.operation, at_ms)
            .await?;
        Ok(MootCommandReceipt {
            operation: *operation.hash.as_bytes(),
            lane: MootLane::Objects,
            snapshot: self.snapshot().await?,
        })
    }

    async fn aggregate_drop_records(
        &self,
        selector: &MootDropSelector,
        budget: DropExportBudget,
    ) -> Result<Vec<DropRecord>, MootError> {
        let evidence = ConstitutionEvidence {
            version: CONSTITUTION_EVIDENCE_VERSION,
            operations: self.governance.drop_records().await?,
        };
        let evidence_bytes =
            encode_cbor(&evidence).map_err(|_| MootError::ConstitutionEvidenceMalformed)?;
        let mut records = vec![DropRecord::Evidence {
            kind: EvidenceKind::CheckpointAuthorization,
            subject: self.moot_id.0,
            bytes: evidence_bytes,
            critical: true,
        }];
        let delegation = DelegationEvidence {
            version: DELEGATION_EVIDENCE_VERSION,
            operations: self.delegations.drop_records().await?,
        };
        let delegation_bytes =
            encode_cbor(&delegation).map_err(|_| MootError::DelegationEvidenceMalformed)?;
        records.push(DropRecord::Evidence {
            kind: EvidenceKind::CapabilityChain,
            subject: self.moot_id.0,
            bytes: delegation_bytes,
            critical: true,
        });
        let domains = DomainEvidence {
            version: DOMAIN_EVIDENCE_VERSION,
            membership_operations: self.membership.drop_records().await?,
            standing_operations: export_topic_operations::<B, StandingExt, u64>(
                &self.standing.sync_store(),
                &p2panda_core::Topic::from(self.moot_id.0),
                DropExportProfile::default(),
            )
            .await
            .map_err(|_| MootError::DomainEvidenceMalformed)?,
            tulpa_operations: export_topic_operations::<B, TulpaExt, u64>(
                &self.tulpa.sync_store(),
                &p2panda_core::Topic::from(self.moot_id.0),
                DropExportProfile::default(),
            )
            .await
            .map_err(|_| MootError::DomainEvidenceMalformed)?,
            flora_operations: export_topic_operations::<B, FloraExt, u64>(
                &self.flora.sync_store(),
                &p2panda_core::Topic::from(self.moot_id.0),
                DropExportProfile::default(),
            )
            .await
            .map_err(|_| MootError::DomainEvidenceMalformed)?,
        };
        let domain_bytes = encode_cbor(&domains).map_err(|_| MootError::DomainEvidenceMalformed)?;
        records.push(DropRecord::Evidence {
            kind: EvidenceKind::DomainOperations,
            subject: self.moot_id.0,
            bytes: domain_bytes,
            critical: true,
        });
        let (objects, selection) = self
            .objects
            .export_selected_drop_records(self.moot_id.0, selector, budget)
            .await?;
        if selection.budget_omitted != 0 || selection.policy_omitted != 0 {
            return Err(MootError::IncompleteDropBudget(
                selection.budget_omitted + selection.policy_omitted,
            ));
        }
        records.extend(objects);
        Ok(records)
    }

    /// Extract at most one critical evidence section of `kind` addressed to
    /// this Moot.
    ///
    /// Every section obeys the same three rules -- one occurrence, our subject,
    /// and a body that round-trips to exactly the bytes it arrived as, so an
    /// importer cannot be handed a re-encoding that means something else. The
    /// three callers differ only in the wire type, its version and the error
    /// they report, so the rules live here once rather than in three copies
    /// that could drift apart.
    fn evidence_section<T: Serialize + for<'a> Deserialize<'a>>(
        &self,
        records: &[DropRecord],
        kind: EvidenceKind,
        version: u16,
        version_of: impl Fn(&T) -> u16,
        malformed: impl Fn() -> MootError,
    ) -> Result<Option<T>, MootError> {
        let mut found = None;
        for record in records {
            let DropRecord::Evidence {
                kind: record_kind,
                subject,
                bytes,
                critical: true,
            } = record
            else {
                continue;
            };
            if *record_kind != kind {
                continue;
            }
            if *subject != self.moot_id.0 || found.is_some() {
                return Err(malformed());
            }
            let evidence: T = decode_cbor(&bytes[..]).map_err(|_| malformed())?;
            if version_of(&evidence) != version
                || encode_cbor(&evidence).ok().as_deref() != Some(bytes.as_slice())
            {
                return Err(malformed());
            }
            found = Some(evidence);
        }
        Ok(found)
    }

    fn constitution_evidence(&self, records: &[DropRecord]) -> Result<Vec<DropRecord>, MootError> {
        self.evidence_section::<ConstitutionEvidence>(
            records,
            EvidenceKind::CheckpointAuthorization,
            CONSTITUTION_EVIDENCE_VERSION,
            |evidence| evidence.version,
            || MootError::ConstitutionEvidenceMalformed,
        )?
        .map(|evidence| evidence.operations)
        .ok_or(MootError::ConstitutionEvidenceMissing)
    }

    fn delegation_evidence(&self, records: &[DropRecord]) -> Result<Vec<DropRecord>, MootError> {
        Ok(self
            .evidence_section::<DelegationEvidence>(
                records,
                EvidenceKind::CapabilityChain,
                DELEGATION_EVIDENCE_VERSION,
                |evidence| evidence.version,
                || MootError::DelegationEvidenceMalformed,
            )?
            .map(|evidence| evidence.operations)
            .unwrap_or_default())
    }

    fn domain_evidence(&self, records: &[DropRecord]) -> Result<DomainEvidence, MootError> {
        Ok(self
            .evidence_section::<DomainEvidence>(
                records,
                EvidenceKind::DomainOperations,
                DOMAIN_EVIDENCE_VERSION,
                |evidence| evidence.version,
                || MootError::DomainEvidenceMalformed,
            )?
            .unwrap_or(DomainEvidence {
                version: DOMAIN_EVIDENCE_VERSION,
                membership_operations: Vec::new(),
                standing_operations: Vec::new(),
                tulpa_operations: Vec::new(),
                flora_operations: Vec::new(),
            }))
    }

    async fn accept_standing_drop_records(&self, records: &[DropRecord]) -> Result<u64, MootError> {
        let mut accepted = 0;
        for record in records {
            let Some(operation) = decode_operation_record::<StandingExt>(record)
                .map_err(|_| MootError::DomainEvidenceMalformed)?
            else {
                continue;
            };
            if operation.body.is_none() {
                return Err(MootError::DomainEvidenceMalformed);
            }
            accepted += u64::from(self.standing.accept(self.moot_id.0, &operation).await?);
        }
        Ok(accepted)
    }

    async fn accept_tulpa_drop_records(&self, records: &[DropRecord]) -> Result<u64, MootError> {
        let mut accepted = 0;
        for record in records {
            let Some(operation) = decode_operation_record::<TulpaExt>(record)
                .map_err(|_| MootError::DomainEvidenceMalformed)?
            else {
                continue;
            };
            if operation.body.is_none() {
                return Err(MootError::DomainEvidenceMalformed);
            }
            accepted += u64::from(self.tulpa.accept(self.moot_id.0, &operation).await?);
        }
        Ok(accepted)
    }

    async fn accept_flora_drop_records(&self, records: &[DropRecord]) -> Result<u64, MootError> {
        let mut accepted = 0;
        for record in records {
            let Some(operation) = decode_operation_record::<FloraExt>(record)
                .map_err(|_| MootError::DomainEvidenceMalformed)?
            else {
                continue;
            };
            if operation.body.is_none() {
                return Err(MootError::DomainEvidenceMalformed);
            }
            accepted += u64::from(self.flora.accept(self.moot_id.0, &operation).await?);
        }
        Ok(accepted)
    }

    async fn import_aggregate_records(
        &self,
        drop_id: DropId,
        records: Vec<DropRecord>,
    ) -> Result<MootDropImportReceipt, MootError> {
        let evidence = self.constitution_evidence(&records)?;
        let constitution_operations = self.governance.accept_drop_records(&evidence).await?;
        let delegation_evidence = self.delegation_evidence(&records)?;
        let delegation_operations = self
            .delegations
            .accept_drop_records(&delegation_evidence)
            .await?;
        let domains = self.domain_evidence(&records)?;
        let membership_operations = self
            .membership
            .accept_drop_records(&domains.membership_operations)
            .await?;
        let standing_operations = self
            .accept_standing_drop_records(&domains.standing_operations)
            .await?;
        let tulpa_operations = self
            .accept_tulpa_drop_records(&domains.tulpa_operations)
            .await?;
        let flora_operations = self
            .accept_flora_drop_records(&domains.flora_operations)
            .await?;
        // The evidence becomes active before the object lane examines its
        // checkpoint chain. This is the dependency order a fresh device needs
        // after a signer rotation.
        self.refresh_retention_authority().await?;
        let import = self
            .objects
            .import_drop_records(self.moot_id.0, drop_id, records)
            .await?;
        Ok(MootDropImportReceipt {
            import,
            constitution_operations,
            delegation_operations,
            membership_operations,
            standing_operations,
            tulpa_operations,
            flora_operations,
            snapshot: self.snapshot().await?,
        })
    }

    /// Export public or explicitly local Moot state as a self-contained native
    /// drop. The carrier includes critical constitution authority evidence.
    pub async fn export_plain_drop<W: Write>(
        &self,
        writer: &mut W,
        profile: DropExportProfile,
        limits: DropLimits,
    ) -> Result<DropWriteReceipt, MootError> {
        if !profile.include_operation_bodies {
            return Err(MootError::HeaderOnlyDrop);
        }
        let records = self
            .aggregate_drop_records(&MootDropSelector::default(), DropExportBudget::default())
            .await?;
        Ok(write_plain_drop(writer, &records, limits)?)
    }

    /// Export a protected, importable Moot drop. A caller supplies its group
    /// protection suite; Gemot never picks keys or silently falls back to
    /// plaintext.
    pub async fn export_protected_drop<W: Write, D: DropProtector>(
        &self,
        writer: &mut W,
        selector: &MootDropSelector,
        budget: DropExportBudget,
        limits: DropLimits,
        protector: &D,
    ) -> Result<DropWriteReceipt, MootError> {
        let records = self.aggregate_drop_records(selector, budget).await?;
        Ok(write_protected_drop(writer, &records, limits, protector)?)
    }

    /// Import a self-contained plaintext/public Moot drop. Critical
    /// constitution evidence is admitted before the checkpoint chain.
    pub async fn import_plain_drop<R: Read>(
        &self,
        reader: R,
        limits: DropLimits,
    ) -> Result<MootDropImportReceipt, MootError> {
        let (read, records) = read_plain_drop(reader, limits)?;
        self.import_aggregate_records(read.id, records).await
    }

    /// Import a protected Moot drop through the caller's group-key suite.
    pub async fn import_protected_drop<R: Read, D: DropProtector>(
        &self,
        reader: R,
        limits: DropLimits,
        protector: &D,
    ) -> Result<MootDropImportReceipt, MootError> {
        let (read, records) = read_protected_drop(reader, limits, protector)?;
        self.import_aggregate_records(read.id, records).await
    }

    /// The moot's commons **as converged authority sees it**: fauna entries
    /// whose sharer holds the typed `moot/fauna` capability at `at_ms`.
    ///
    /// Today `MootPolicy::admit` accepts a `Shared` event on wire grammar and
    /// moot address alone, so the raw
    /// [`roster.fauna`](super::MootRoster::fauna) is *everything anyone put
    /// there*. This is the authorized view over it, evaluated at read for the
    /// reason recorded on
    /// [`MootRoster::authorized_fauna`](super::MootRoster::authorized_fauna):
    /// authority converges separately from the operations it authorizes, so
    /// refusing at admission would discard operations that become authorized
    /// a moment later.
    ///
    /// Both views are deliberately available. Which one a surface shows is a
    /// product call — the unfiltered record lets a UI show an unauthorized
    /// contribution as *pending* rather than making it vanish.
    pub async fn authorized_fauna(&self, at_ms: u64) -> Result<Vec<FaunaEntry>, MootError> {
        let rules = self.governance.snapshot().await?.rules;
        let delegations = self.delegations.delegations(&rules).await?;
        let roster = self.objects.roster(self.moot_id.0).await?;
        let authority = MootAuthority {
            delegations: &delegations,
            rules: &rules,
            moot_id: self.moot_id.0,
            now_ms: at_ms,
        };
        Ok(roster
            .authorized_fauna(&authority)
            .into_iter()
            .cloned()
            .collect())
    }

    pub async fn snapshot(&self) -> Result<MootSnapshot, MootError> {
        let governance = self.governance.snapshot().await?;
        let membership = self.membership.snapshot().await?;
        let roster = self.objects.roster(self.moot_id.0).await?;
        let checkpoint = self
            .objects
            .latest_checkpoint(self.moot_id.0)
            .await?
            .map(|stored| MootCheckpointSnapshot {
                operation: stored.operation,
                policy_revision: stored.checkpoint.policy_revision,
                authority_revision: stored.checkpoint.authority_revision,
                previous_checkpoint: stored.checkpoint.previous_checkpoint,
                frontier_count: stored.checkpoint.frontier.len(),
                at_ms: stored.checkpoint.at_ms,
            });
        let delegated_certificates = self
            .delegations
            .delegations(&governance.rules)
            .await?
            .certificate_count();
        let standing_operations = self.standing.len().await?;
        let tulpa = self.tulpa.fold_moot(self.moot_id.0).await?;
        let flora = self.flora.fold_moot(self.moot_id.0).await?;
        Ok(MootSnapshot {
            moot_id: self.moot_id,
            governance,
            membership,
            roster,
            checkpoint,
            delegated_certificates,
            standing_operations,
            tulpa,
            flora,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::moot::constitution::CapabilityGrant;
    use crate::moot::delegation::{MOOT_ACT_ACTION, MOOT_DELEGATION_DOMAIN};
    use crate::moot::standing::{
        ChainRoot, DenyReason, GateConfig, GateDecision, Policy, StandingEvent, StandingFacts,
    };
    use crate::moot::tulpa::{TulpaEvent, TulpaId, TulpaProposal, TulpaProposalId, TulpaVersion};
    use crate::moot::{
        ArtifactRef, FloraEvent, FloraParticipant, FloraRoundId, FloraRoundSpec, FloraScale,
        KeepBound, MootAccessLevel, MootMember, MootMembershipAction, MootStoreError,
    };
    use identity::delegation::{
        CapabilityScope, DelegationCertificate, DelegationParent, DelegationRevocation,
        SignedDelegationCertificate, SignedDelegationRevocation, delegation_signing_salt,
    };
    use identity::{IdentityProvider, InMemoryProvider};
    use mooting::{ElectorateSnapshot, RecognitionContext, RecognitionPolicy};
    use std::collections::BTreeMap;
    use std::io::Cursor;
    use stickleback::NativeDropError;

    const ID: MootId = MootId([0x6d; 32]);

    fn keypair(seed: u8) -> identity::Ed25519Keypair {
        InMemoryProvider::from_seed([seed; 32])
            .derive_keypair(b"moot-service")
            .unwrap()
    }

    fn retention() -> MootRetentionSettings {
        MootRetentionSettings {
            revision: PolicyRevision(Digest::blake3(b"moot retention settings")),
            availability: AvailabilityPolicy {
                promised_floor: KeepBound::Forever,
            },
            erasure: ErasurePolicy {
                history_ceiling: KeepBound::UntilCheckpoint,
            },
        }
    }

    struct Access {
        capability_covers: bool,
        facts: StandingFacts,
    }

    impl MootAuthorizationProvider for Access {
        fn inputs(&self, _: &MootAuthorizationRequest) -> MootAuthorizationInputs {
            MootAuthorizationInputs {
                capability_covers: self.capability_covers,
                facts: self.facts.clone(),
            }
        }
    }

    struct TestProtector;

    impl DropProtector for TestProtector {
        fn suite_id(&self) -> u16 {
            77
        }

        fn protect(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, NativeDropError> {
            Ok(plaintext
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ aad[index % aad.len()])
                .collect())
        }

        fn unprotect(
            &self,
            protected: &[u8],
            aad: &[u8],
            max_plaintext_bytes: u64,
        ) -> Result<Vec<u8>, NativeDropError> {
            if protected.len() as u64 > max_plaintext_bytes {
                return Err(NativeDropError::Limit {
                    limit: "test plaintext bytes",
                    actual: protected.len() as u64,
                    maximum: max_plaintext_bytes,
                });
            }
            self.protect(protected, aad)
        }
    }

    #[tokio::test]
    async fn one_service_runs_governance_roster_checkpoint_and_rotation() {
        let founder = keypair(1);
        let successor = keypair(2);
        let service = Moot::in_memory(ID, founder.public_key().to_bytes(), retention());
        service
            .found(
                founder.to_seed(),
                None,
                None,
                ConstitutionRules::founder_only(founder.public_key().to_bytes()),
                1,
            )
            .await
            .unwrap();
        service
            .declare(
                founder.to_seed(),
                "printing circle".into(),
                "shared type".into(),
                2,
            )
            .await
            .unwrap();
        service
            .join(founder.to_seed(), "mark".into(), 3)
            .await
            .unwrap();
        let first = service.checkpoint(founder.to_seed(), 10).await.unwrap();

        let mut rotated = ConstitutionRules::founder_only(founder.public_key().to_bytes());
        rotated.checkpoint_signers.clear();
        rotated
            .checkpoint_signers
            .insert(successor.public_key().to_bytes());
        service.amend(founder.to_seed(), rotated, 11).await.unwrap();
        assert!(matches!(
            service.checkpoint(founder.to_seed(), 12).await,
            Err(MootError::Store(MootStoreError::Process(_)))
        ));
        let second = service.checkpoint(successor.to_seed(), 13).await.unwrap();
        assert_eq!(
            second
                .snapshot
                .checkpoint
                .as_ref()
                .unwrap()
                .previous_checkpoint,
            Some(first.operation)
        );

        service.prune_current(founder.to_seed(), 14).await.unwrap();
        let snapshot = service.snapshot().await.unwrap();
        assert_eq!(snapshot.roster.declaration.unwrap().name, "printing circle");
        assert_eq!(snapshot.roster.members.len(), 1);
        assert_eq!(snapshot.checkpoint.unwrap().operation, second.operation);
    }

    #[tokio::test]
    async fn signed_admission_rule_uses_the_injected_membership_and_capability_inputs() {
        let founder = keypair(8);
        let founder_id = founder.public_key().to_bytes();
        let service = Moot::in_memory(ID, founder_id, retention());
        let mut rules = ConstitutionRules::founder_only(founder_id);
        rules.admission = Policy::MembersOnly {
            rate_limit: 20,
            rate_window_ms: 60_000,
        };
        service
            .found(founder.to_seed(), None, None, rules, 1)
            .await
            .unwrap();
        let request = MootAuthorizationRequest {
            subject: [9; 32],
            capability_path: "moot/fauna/write".into(),
            at_ms: 10,
        };

        assert_eq!(
            service
                .authorize(
                    &Access {
                        capability_covers: false,
                        facts: StandingFacts {
                            is_member: true,
                            ..Default::default()
                        },
                    },
                    &request,
                )
                .await
                .unwrap(),
            GateDecision::Deny(DenyReason::NoCapability)
        );
        assert_eq!(
            service
                .authorize(
                    &Access {
                        capability_covers: true,
                        facts: StandingFacts {
                            score: 1,
                            ..Default::default()
                        },
                    },
                    &request,
                )
                .await
                .unwrap(),
            GateDecision::Deny(DenyReason::NotAMember)
        );
        assert_eq!(
            service
                .authorize(
                    &Access {
                        capability_covers: true,
                        facts: StandingFacts {
                            is_member: true,
                            ..Default::default()
                        },
                    },
                    &request,
                )
                .await
                .unwrap(),
            GateDecision::Allow
        );

        let mut amended = ConstitutionRules::founder_only(founder_id);
        amended.admission = Policy::OpenWithFloor(GateConfig {
            posting_threshold: 2,
            rate_limit: 20,
            rate_window_ms: 60_000,
        });
        service.amend(founder.to_seed(), amended, 11).await.unwrap();
        assert_eq!(
            service
                .authorize(
                    &Access {
                        capability_covers: true,
                        facts: StandingFacts {
                            score: 1,
                            is_member: true,
                            ..Default::default()
                        },
                    },
                    &request,
                )
                .await
                .unwrap(),
            GateDecision::Deny(DenyReason::BelowThreshold)
        );
    }

    #[tokio::test]
    async fn constitutional_grants_narrow_live_capability_inputs_and_revoke_by_amendment() {
        let founder = keypair(9);
        let founder_id = founder.public_key().to_bytes();
        let service = Moot::in_memory(ID, founder_id, retention());
        let grant_id = [0xa9; 32];
        let mut rules = ConstitutionRules::founder_only(founder_id);
        rules.admission = Policy::MembersOnly {
            rate_limit: 20,
            rate_window_ms: 60_000,
        };
        rules.grant(CapabilityGrant {
            id: grant_id,
            subject: [9; 32],
            path_prefix: "moot/fauna".into(),
            not_before_ms: 5,
            expires_at_ms: Some(20),
            delegation_depth: 0,
        });
        service
            .found(founder.to_seed(), None, None, rules.clone(), 1)
            .await
            .unwrap();
        let member = Access {
            capability_covers: true,
            facts: StandingFacts {
                is_member: true,
                ..Default::default()
            },
        };
        let request = MootAuthorizationRequest {
            subject: [9; 32],
            capability_path: "moot/fauna/write".into(),
            at_ms: 10,
        };
        assert_eq!(
            service
                .authorize_constitution_grant(&member, &request)
                .await
                .unwrap(),
            GateDecision::Allow
        );

        let sibling = MootAuthorizationRequest {
            capability_path: "moot/faunarium/write".into(),
            ..request.clone()
        };
        assert_eq!(
            service
                .authorize_constitution_grant(&member, &sibling)
                .await
                .unwrap(),
            GateDecision::Deny(DenyReason::NoCapability)
        );
        let expired = MootAuthorizationRequest {
            at_ms: 21,
            ..request.clone()
        };
        assert_eq!(
            service
                .authorize_constitution_grant(&member, &expired)
                .await
                .unwrap(),
            GateDecision::Deny(DenyReason::NoCapability)
        );

        rules.revoke_grant(&grant_id);
        service.amend(founder.to_seed(), rules, 22).await.unwrap();
        assert_eq!(
            service
                .authorize_constitution_grant(&member, &request)
                .await
                .unwrap(),
            GateDecision::Deny(DenyReason::NoCapability)
        );
    }

    #[tokio::test]
    async fn delegated_grants_intersect_constitution_group_and_admission() {
        let founder = keypair(10);
        let founder_id = founder.public_key().to_bytes();
        let root_holder = InMemoryProvider::from_seed([0x31; 32]);
        let delegate = InMemoryProvider::from_seed([0x32; 32]);
        let root_id = [0xb1; 32];
        let service = Moot::in_memory(ID, founder_id, retention());
        let mut rules = ConstitutionRules::founder_only(founder_id);
        rules.admission = Policy::MembersOnly {
            rate_limit: 20,
            rate_window_ms: 60_000,
        };
        rules.grant(CapabilityGrant {
            id: root_id,
            subject: root_holder.master_public_key().to_bytes(),
            path_prefix: "moot/fauna".into(),
            not_before_ms: 5,
            expires_at_ms: Some(100),
            delegation_depth: 2,
        });
        service
            .found(founder.to_seed(), None, None, rules.clone(), 1)
            .await
            .unwrap();

        let scope = CapabilityScope {
            domain: MOOT_DELEGATION_DOMAIN.into(),
            resource: ID.0.to_vec(),
            path_prefix: "moot/fauna/research".into(),
            actions: [MOOT_ACT_ACTION.to_string()].into_iter().collect(),
        };
        let certificate = DelegationCertificate::new(
            DelegationParent::Root(root_id),
            root_holder.master_public_key().to_bytes(),
            delegate.master_public_key().to_bytes(),
            scope.clone(),
            5,
            10,
            Some(90),
            1,
            [0x41; 32],
        );
        let delegation_key = root_holder
            .derive_keypair(&delegation_signing_salt(&scope))
            .unwrap();
        service
            .delegation_store()
            .author_issue(
                &delegation_key,
                &rules,
                SignedDelegationCertificate::issue(&root_holder, certificate).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(service.snapshot().await.unwrap().delegated_certificates, 1);
        let request = MootAuthorizationRequest {
            subject: delegate.master_public_key().to_bytes(),
            capability_path: "moot/fauna/research/write".into(),
            at_ms: 50,
        };
        let member = Access {
            capability_covers: true,
            facts: StandingFacts {
                is_member: true,
                ..Default::default()
            },
        };
        assert_eq!(
            service
                .authorize_current_delegated(&member, &request)
                .await
                .unwrap(),
            GateDecision::Allow
        );
        assert_eq!(
            service
                .authorize_current_delegated(
                    &Access {
                        capability_covers: false,
                        facts: member.facts.clone(),
                    },
                    &request,
                )
                .await
                .unwrap(),
            GateDecision::Deny(DenyReason::NoCapability)
        );

        rules.revoke_grant(&root_id);
        service.amend(founder.to_seed(), rules, 101).await.unwrap();
        assert_eq!(
            service
                .authorize_current_delegated(&member, &request)
                .await
                .unwrap(),
            GateDecision::Deny(DenyReason::NoCapability)
        );
    }

    #[tokio::test]
    async fn native_drop_bootstraps_independent_delegation_authority() {
        let founder = keypair(11);
        let founder_id = founder.public_key().to_bytes();
        let root_holder = InMemoryProvider::from_seed([0x51; 32]);
        let delegate = InMemoryProvider::from_seed([0x52; 32]);
        let root_id = [0xc1; 32];
        let mut rules = ConstitutionRules::founder_only(founder_id);
        rules.grant(CapabilityGrant {
            id: root_id,
            subject: root_holder.master_public_key().to_bytes(),
            path_prefix: "moot/fauna".into(),
            not_before_ms: 1,
            expires_at_ms: Some(100),
            delegation_depth: 1,
        });
        let source = Moot::in_memory(ID, founder_id, retention());
        source
            .found(founder.to_seed(), None, None, rules.clone(), 1)
            .await
            .unwrap();
        let scope = CapabilityScope {
            domain: MOOT_DELEGATION_DOMAIN.into(),
            resource: ID.0.to_vec(),
            path_prefix: "moot/fauna/notes".into(),
            actions: [MOOT_ACT_ACTION.to_string()].into_iter().collect(),
        };
        let signed = SignedDelegationCertificate::issue(
            &root_holder,
            DelegationCertificate::new(
                DelegationParent::Root(root_id),
                root_holder.master_public_key().to_bytes(),
                delegate.master_public_key().to_bytes(),
                scope.clone(),
                2,
                3,
                Some(90),
                0,
                [0x53; 32],
            ),
        )
        .unwrap();
        let certificate_id = signed.certificate.id();
        let delegation_key = root_holder
            .derive_keypair(&delegation_signing_salt(&scope))
            .unwrap();
        source
            .delegation_store()
            .author_issue(&delegation_key, &rules, signed)
            .await
            .unwrap();

        let mut bytes = Vec::new();
        source
            .export_plain_drop(
                &mut bytes,
                DropExportProfile::default(),
                DropLimits::default(),
            )
            .await
            .unwrap();
        let target = Moot::in_memory(ID, founder_id, retention());
        let receipt = target
            .import_plain_drop(Cursor::new(bytes), DropLimits::default())
            .await
            .unwrap();
        assert_eq!(receipt.delegation_operations, 1);
        assert_eq!(receipt.snapshot.delegated_certificates, 1);
        assert_eq!(
            target
                .authorize_current_delegated(
                    &Access {
                        capability_covers: true,
                        facts: StandingFacts {
                            score: 1,
                            ..Default::default()
                        },
                    },
                    &MootAuthorizationRequest {
                        subject: delegate.master_public_key().to_bytes(),
                        capability_path: "moot/fauna/notes/write".into(),
                        at_ms: 50,
                    },
                )
                .await
                .unwrap(),
            GateDecision::Allow
        );

        let revocation = SignedDelegationRevocation::issue(
            &root_holder,
            DelegationRevocation::new(
                certificate_id,
                root_holder.master_public_key().to_bytes(),
                scope.clone(),
                60,
                [0x54; 32],
            ),
        )
        .unwrap();
        source
            .delegation_store()
            .author_revoke(&delegation_key, &rules, revocation)
            .await
            .unwrap();
        let mut revoked_bytes = Vec::new();
        source
            .export_plain_drop(
                &mut revoked_bytes,
                DropExportProfile::default(),
                DropLimits::default(),
            )
            .await
            .unwrap();
        let revoked_receipt = target
            .import_plain_drop(Cursor::new(revoked_bytes), DropLimits::default())
            .await
            .unwrap();
        assert_eq!(revoked_receipt.delegation_operations, 1);
        assert_eq!(
            target.delegation_scope_key_epochs().await.unwrap()[0].epoch,
            1
        );
        assert!(
            target
                .delegation_projections(60)
                .await
                .unwrap()
                .iter()
                .all(|projection| !projection.active)
        );
        assert_eq!(
            target
                .authorize_current_delegated(
                    &Access {
                        capability_covers: true,
                        facts: StandingFacts {
                            score: 1,
                            ..Default::default()
                        },
                    },
                    &MootAuthorizationRequest {
                        subject: delegate.master_public_key().to_bytes(),
                        capability_path: "moot/fauna/notes/write".into(),
                        at_ms: 60,
                    },
                )
                .await
                .unwrap(),
            GateDecision::Deny(DenyReason::NoCapability)
        );
    }

    #[tokio::test]
    async fn aggregate_drop_reconstructs_all_seven_retained_domains_for_late_peer() {
        let founder = keypair(12);
        let founder_id = founder.public_key().to_bytes();
        let member_identity = InMemoryProvider::from_seed([0x61; 32]);
        let member_root = member_identity.master_public_key().to_bytes();
        let root_holder = InMemoryProvider::from_seed([0x62; 32]);
        let delegate = InMemoryProvider::from_seed([0x63; 32]);
        let root_id = [0xd1; 32];
        let mut rules = ConstitutionRules::founder_only(founder_id);
        rules.grant(CapabilityGrant {
            id: root_id,
            subject: root_holder.master_public_key().to_bytes(),
            path_prefix: "moot/fauna".into(),
            not_before_ms: 1,
            expires_at_ms: Some(100),
            delegation_depth: 1,
        });

        let source = Moot::in_memory(ID, founder_id, retention());
        source
            .found(founder.to_seed(), None, None, rules.clone(), 1)
            .await
            .unwrap();
        let membership_receipt = source
            .update_membership_for_identity(
                &member_identity,
                MootMembershipAction::Create {
                    initial_members: vec![MootMember {
                        member: member_root,
                        access: MootAccessLevel::Manage,
                    }],
                },
            )
            .await
            .unwrap();
        assert!(matches!(
            source.outbound(&membership_receipt).await.unwrap(),
            MootOutboundOperation::Membership(_)
        ));

        let scope = CapabilityScope {
            domain: MOOT_DELEGATION_DOMAIN.into(),
            resource: ID.0.to_vec(),
            path_prefix: "moot/fauna/notes".into(),
            actions: [MOOT_ACT_ACTION.to_string()].into_iter().collect(),
        };
        let signed = SignedDelegationCertificate::issue(
            &root_holder,
            DelegationCertificate::new(
                DelegationParent::Root(root_id),
                root_holder.master_public_key().to_bytes(),
                delegate.master_public_key().to_bytes(),
                scope.clone(),
                2,
                3,
                Some(90),
                0,
                [0x64; 32],
            ),
        )
        .unwrap();
        let delegation_key = root_holder
            .derive_keypair(&delegation_signing_salt(&scope))
            .unwrap();
        source
            .delegation_store()
            .author_issue(&delegation_key, &rules, signed)
            .await
            .unwrap();

        source
            .declare(
                founder.to_seed(),
                "peer press".into(),
                "shared place".into(),
                4,
            )
            .await
            .unwrap();
        source
            .join(founder.to_seed(), "founder".into(), 5)
            .await
            .unwrap();
        source
            .share(
                founder.to_seed(),
                [0x65; 32],
                "text/plain".into(),
                "field note".into(),
                6,
            )
            .await
            .unwrap();
        source
            .record_standing(
                founder.to_seed(),
                StandingEvent::GovernanceParticipation {
                    by: ChainRoot(member_root),
                    at_ms: 7,
                },
            )
            .await
            .unwrap();
        source
            .record_tulpa(
                founder.to_seed(),
                TulpaEvent::Proposed {
                    proposal: TulpaProposalId([0x66; 32]),
                    action: TulpaProposal::Adopt {
                        tulpa: TulpaId([0x67; 32]),
                        version: TulpaVersion([0x68; 32]),
                        artifact: ArtifactRef::blake3(b"drop Tulpa"),
                    },
                    recognition: RecognitionContext::new(
                        RecognitionPolicy::AnyEligible,
                        ElectorateSnapshot::new(ID.0, [0x69; 32], [founder_id]),
                    ),
                    at_ms: 8,
                },
            )
            .await
            .unwrap();
        source
            .record_flora(
                founder.to_seed(),
                FloraEvent::RoundProposed {
                    spec: FloraRoundSpec {
                        round: FloraRoundId([0x6a; 32]),
                        base_model: ArtifactRef::blake3(b"drop base"),
                        rank_budget: 1,
                        participants: BTreeMap::from([(
                            founder_id,
                            FloraParticipant {
                                rank: 1,
                                scale: FloraScale {
                                    numerator: 1,
                                    denominator: 1,
                                },
                            },
                        )]),
                    },
                    at_ms: 9,
                },
            )
            .await
            .unwrap();
        let expected = source.snapshot().await.unwrap();

        let mut bytes = Vec::new();
        source
            .export_plain_drop(
                &mut bytes,
                DropExportProfile::default(),
                DropLimits::default(),
            )
            .await
            .unwrap();
        let late_peer = Moot::in_memory(ID, founder_id, retention());
        let receipt = late_peer
            .import_plain_drop(Cursor::new(bytes), DropLimits::default())
            .await
            .unwrap();

        assert_eq!(receipt.constitution_operations, 1);
        assert_eq!(receipt.delegation_operations, 1);
        assert_eq!(receipt.membership_operations, 1);
        assert_eq!(receipt.standing_operations, 1);
        assert_eq!(receipt.tulpa_operations, 1);
        assert_eq!(receipt.flora_operations, 1);
        assert_eq!(receipt.snapshot, expected);
        assert_eq!(receipt.snapshot.membership.members[0].member, member_root);
        assert_eq!(receipt.snapshot.roster.members.len(), 1);
        assert_eq!(receipt.snapshot.roster.fauna.len(), 1);
        assert_eq!(receipt.snapshot.delegated_certificates, 1);
        assert_eq!(receipt.snapshot.standing_operations, 1);
        assert_eq!(receipt.snapshot.tulpa.facts.len(), 1);
        assert_eq!(receipt.snapshot.flora.rounds.len(), 1);
    }

    #[tokio::test]
    async fn durable_service_reopens_both_governance_and_roster() {
        let directory = tempfile::tempdir().unwrap();
        let founder = keypair(3);
        let founder_id = founder.public_key().to_bytes();
        let service = MootFile::open(directory.path(), ID, founder_id, retention())
            .await
            .unwrap();
        service
            .found(
                founder.to_seed(),
                None,
                None,
                ConstitutionRules::founder_only(founder_id),
                1,
            )
            .await
            .unwrap();
        service
            .join(founder.to_seed(), "mark".into(), 2)
            .await
            .unwrap();
        drop(service);

        let reopened = MootFile::open(directory.path(), ID, founder_id, retention())
            .await
            .unwrap();
        assert_eq!(reopened.snapshot().await.unwrap().roster.members.len(), 1);
    }

    #[test]
    fn legacy_tessera_file_is_opened_until_standing_file_exists() {
        let directory = tempfile::tempdir().unwrap();
        let legacy = directory.path().join("tessera.redb");
        StandingFileStore::open(&legacy).unwrap();
        assert_eq!(standing_store_path(directory.path()), legacy);

        let standing = directory.path().join("standing.redb");
        StandingFileStore::open(&standing).unwrap();
        assert_eq!(standing_store_path(directory.path()), standing);
    }

    #[test]
    fn legacy_domain_drop_decodes_tessera_operations_as_standing() {
        #[derive(Serialize)]
        struct LegacyDomainEvidence {
            version: u16,
            membership_operations: Vec<DropRecord>,
            tessera_operations: Vec<DropRecord>,
        }

        let legacy = LegacyDomainEvidence {
            version: DOMAIN_EVIDENCE_VERSION,
            membership_operations: Vec::new(),
            tessera_operations: Vec::new(),
        };
        let bytes = encode_cbor(&legacy).unwrap();
        let decoded: DomainEvidence = decode_cbor(&bytes).unwrap();
        assert_eq!(decoded.version, DOMAIN_EVIDENCE_VERSION);
        assert!(decoded.membership_operations.is_empty());
        assert!(decoded.standing_operations.is_empty());
        assert!(decoded.tulpa_operations.is_empty());
        assert!(decoded.flora_operations.is_empty());
    }

    #[tokio::test]
    async fn native_drop_bootstraps_checkpoint_and_roster_then_is_idempotent() {
        let founder = keypair(4);
        let founder_id = founder.public_key().to_bytes();
        let source = Moot::in_memory(ID, founder_id, retention());
        let destination = Moot::in_memory(ID, founder_id, retention());
        for service in [&source, &destination] {
            service
                .found(
                    founder.to_seed(),
                    None,
                    None,
                    ConstitutionRules::founder_only(founder_id),
                    1,
                )
                .await
                .unwrap();
        }
        source
            .declare(
                founder.to_seed(),
                "drop circle".into(),
                "travels by file".into(),
                2,
            )
            .await
            .unwrap();
        source
            .join(founder.to_seed(), "mark".into(), 3)
            .await
            .unwrap();
        source.checkpoint(founder.to_seed(), 4).await.unwrap();

        let mut bytes = Vec::new();
        source
            .export_plain_drop(
                &mut bytes,
                DropExportProfile::default(),
                DropLimits::default(),
            )
            .await
            .unwrap();
        let first = destination
            .import_plain_drop(Cursor::new(bytes.clone()), DropLimits::default())
            .await
            .unwrap();
        assert_eq!(first.snapshot.roster.members.len(), 1);
        assert_eq!(
            first.snapshot.roster.declaration.unwrap().name,
            "drop circle"
        );
        assert!(first.snapshot.checkpoint.is_some());

        let repeated = destination
            .import_plain_drop(Cursor::new(bytes), DropLimits::default())
            .await
            .unwrap();
        assert!(repeated.import.receipt_hit);
    }

    #[tokio::test]
    async fn aggregate_drop_bootstraps_rotated_checkpoint_authority() {
        let founder = keypair(5);
        let successor = keypair(6);
        let founder_id = founder.public_key().to_bytes();
        let source = Moot::in_memory(ID, founder_id, retention());
        let destination = Moot::in_memory(ID, founder_id, retention());
        source
            .found(
                founder.to_seed(),
                None,
                None,
                ConstitutionRules::founder_only(founder_id),
                1,
            )
            .await
            .unwrap();
        source
            .join(founder.to_seed(), "mark".into(), 2)
            .await
            .unwrap();
        source.checkpoint(founder.to_seed(), 3).await.unwrap();
        let mut rules = ConstitutionRules::founder_only(founder_id);
        rules.checkpoint_signers.clear();
        rules
            .checkpoint_signers
            .insert(successor.public_key().to_bytes());
        source.amend(founder.to_seed(), rules, 4).await.unwrap();
        let rotated = source.checkpoint(successor.to_seed(), 5).await.unwrap();

        let mut bytes = Vec::new();
        source
            .export_plain_drop(
                &mut bytes,
                DropExportProfile::default(),
                DropLimits::default(),
            )
            .await
            .unwrap();
        let imported = destination
            .import_plain_drop(Cursor::new(bytes), DropLimits::default())
            .await
            .unwrap();
        assert_eq!(imported.constitution_operations, 2);
        assert_eq!(
            imported.snapshot.checkpoint.unwrap().operation,
            rotated.operation
        );
        assert_eq!(imported.snapshot.roster.members.len(), 1);
    }

    #[tokio::test]
    async fn protected_drop_and_standing_command_expose_publishable_operations() {
        let founder = keypair(7);
        let founder_id = founder.public_key().to_bytes();
        let source = Moot::in_memory(ID, founder_id, retention());
        let destination = Moot::in_memory(ID, founder_id, retention());
        source
            .found(
                founder.to_seed(),
                None,
                None,
                ConstitutionRules::founder_only(founder_id),
                1,
            )
            .await
            .unwrap();
        destination
            .found(
                founder.to_seed(),
                None,
                None,
                ConstitutionRules::founder_only(founder_id),
                1,
            )
            .await
            .unwrap();
        source
            .declare(
                founder.to_seed(),
                "private circle".into(),
                "sealed".into(),
                2,
            )
            .await
            .unwrap();
        let mut bytes = Vec::new();
        source
            .export_protected_drop(
                &mut bytes,
                &MootDropSelector::default(),
                DropExportBudget::default(),
                DropLimits::default(),
                &TestProtector,
            )
            .await
            .unwrap();
        let imported = destination
            .import_protected_drop(Cursor::new(bytes), DropLimits::default(), &TestProtector)
            .await
            .unwrap();
        assert_eq!(
            imported.snapshot.roster.declaration.unwrap().name,
            "private circle"
        );

        let receipt = source
            .record_standing(
                founder.to_seed(),
                StandingEvent::GovernanceParticipation {
                    by: ChainRoot(founder_id),
                    at_ms: 3,
                },
            )
            .await
            .unwrap();
        assert_eq!(receipt.lane, MootLane::Standing);
        assert!(matches!(
            source.outbound(&receipt).await.unwrap(),
            MootOutboundOperation::Standing(_)
        ));
    }

    #[tokio::test]
    async fn tulpa_and_flora_commands_surface_distinct_lanes_and_snapshots() {
        let founder = keypair(71);
        let founder_id = founder.public_key().to_bytes();
        let service = Moot::in_memory(ID, founder_id, retention());
        service
            .found(
                founder.to_seed(),
                None,
                None,
                ConstitutionRules::founder_only(founder_id),
                1,
            )
            .await
            .unwrap();

        let tulpa = service
            .record_tulpa(
                founder.to_seed(),
                TulpaEvent::Proposed {
                    proposal: TulpaProposalId([1; 32]),
                    action: TulpaProposal::Adopt {
                        tulpa: TulpaId([2; 32]),
                        version: TulpaVersion([3; 32]),
                        artifact: ArtifactRef::blake3(b"tulpa-v1"),
                    },
                    recognition: RecognitionContext::new(
                        RecognitionPolicy::AnyEligible,
                        ElectorateSnapshot::new(ID.0, [4; 32], [founder_id]),
                    ),
                    at_ms: 2,
                },
            )
            .await
            .unwrap();
        assert_eq!(tulpa.lane, MootLane::Tulpa);
        assert!(matches!(
            service.outbound(&tulpa).await.unwrap(),
            MootOutboundOperation::Tulpa(_)
        ));
        assert_eq!(tulpa.snapshot.tulpa.facts.len(), 1);

        let flora = service
            .record_flora(
                founder.to_seed(),
                FloraEvent::RoundProposed {
                    spec: FloraRoundSpec {
                        round: FloraRoundId([5; 32]),
                        base_model: ArtifactRef::blake3(b"base-model"),
                        rank_budget: 1,
                        participants: BTreeMap::from([(
                            founder_id,
                            FloraParticipant {
                                rank: 1,
                                scale: FloraScale {
                                    numerator: 1,
                                    denominator: 1,
                                },
                            },
                        )]),
                    },
                    at_ms: 3,
                },
            )
            .await
            .unwrap();
        assert_eq!(flora.lane, MootLane::Flora);
        assert!(matches!(
            service.outbound(&flora).await.unwrap(),
            MootOutboundOperation::Flora(_)
        ));
        assert_eq!(flora.snapshot.flora.rounds.len(), 1);
    }
}
