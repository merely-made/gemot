// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Minimal encrypted Commons chat profile.
//!
//! This is intentionally distinct from Murm's bilateral `Post` grammar. It is
//! the second consumer of Stickleback's causal projection seam after Knot.

use insigne::CheckFault;
use personae::AttestationKeys;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::parking::{
    ParkedHeader, Parking, ParkingLimits, ParkingStatus, ReadmitReport, Readmitted,
};
use crate::pruning::{EpochNeed, EpochNeedReason, LaneEpochReport};
use crate::{AllowAllAuthority, AuthorityOperation, AuthorityState, CommonsAuthority, GroupKeys};
use insigne::DerivedKeyAttestation;
use muniment::{Backend, MemoryBackend, StoreError, WriteOp};
use murm_sync::JoinedSpace;
use murm_sync::{Endpoint, Gossip};
use p2panda_core::cbor::{decode_cbor_strict, encode_cbor};
use p2panda_core::{Body, Hash, Header, Operation, SigningKey, Topic, VerifyingKey};
use p2panda_encryption::data_scheme::GroupSecretId;
use p2panda_store::topics::TopicStore;
use personae::{IdentityError, IdentityProvider};
use proofs::Digest;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use servitor::{Cap, Mode, Subject};
use stickleback::{
    Admission, CausalEntry, CausalError, CausalLimits, CheckpointAuthority, DataKeyring,
    EpochCheckpointBasis, EpochHold, EpochHoldReason, EpochPruningProposal, EpochRetentionFacts,
    EpochRetentionReason, GroupCiphertext, GroupCryptoError, GroupEncryptionMode,
    GroupEncryptionProfile, JoinError, MunimentStore, OperationPolicy, OperationProcessor,
    PendingCausalOperation, ProcessError, Reject, StoreTarget, author_head, causal_projection,
    observed_frontier, propose_epoch_pruning, validate_causal_metadata,
};

/// This chat profile's sync-lane kind, combined with the space id through
/// `stickleback::lane_id`. Both peers derive the same protocol id from it, and
/// it must differ from every other lane kind sharing an endpoint.
pub const COMMONS_CHAT_LANE: &str = "commons/chat/v1";

const CHAT_LOG: u64 = 0;
const CHAT_CHECKPOINT_LOG: u64 = 1;
const CHAT_AUTHORED_VERSION: u16 = 1;
/// Version 2 adds the signed header link and the covered-author index.
/// Version 1 checkpoints are refused.
pub const CHAT_CHECKPOINT_VERSION: u16 = 2;
const CHAT_LIMITS: CausalLimits = CausalLimits {
    max_parents: 64,
    max_payload_bytes: 1024 * 1024,
};

/// The first chat fixture deliberately chooses durable data encryption. A
/// forward-secure profile is a different wire/runtime contract.
pub const COMMONS_CHAT_PROFILE: GroupEncryptionProfile = GroupEncryptionProfile::durable_data(8);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChatClass {
    #[default]
    Channel,
    Message,
    Checkpoint,
    MessageEdit,
    MessageDelete,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatExt {
    pub space_id: [u8; 32],
    pub class: ChatClass,
    #[serde(default)]
    pub parents: Vec<[u8; 32]>,
    /// Present only on checkpoints, so the chain is walked without decrypting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<ChatCheckpointLink>,
}

/// Signed checkpoint chain link, mirrored by the encrypted body.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatCheckpointLink {
    pub version: u16,
    pub previous: Option<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Channel {
    pub id: String,
    pub title: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    pub channel: String,
    pub body: String,
    pub sent_at_ms: u64,
    pub reply_to: Option<[u8; 32]>,
}

/// Immutable fact replacing only the projected body of an earlier message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageEdit {
    pub original: [u8; 32],
    pub body: String,
    pub edited_at_ms: u64,
}

/// Immutable fact retracting an earlier message from the current projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageDelete {
    pub original: [u8; 32],
    pub deleted_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChatEvent {
    Channel(Channel),
    Message(Message),
    MessageEdit(MessageEdit),
    MessageDelete(MessageDelete),
}

/// Encrypted inner wire record carrying one chat fact and its stable-root
/// binding. Legacy chat payloads decode as unattested direct-root records.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ChatAuthored<T> {
    version: u16,
    payload: T,
    #[serde(default)]
    author_attestation: Option<DerivedKeyAttestation>,
}

/// Invalid binding between a signed chat operation and a stable Personae root.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ChatAuthorBindingError {
    #[error("unsupported authored-chat payload version {0}")]
    UnsupportedVersion(u16),
    #[error("derived chat-author attestation does not check for this space: {0}")]
    InvalidAttestation(CheckFault),
    #[error("derived chat-author attestation contains an invalid key")]
    InvalidDerivedKey,
    #[error("derived chat-author attestation does not bind the operation signer")]
    SignerMismatch,
    #[error("derived chat-author attestation contains an invalid root key")]
    InvalidRoot,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthoredMessage {
    pub operation: [u8; 32],
    /// Stable Personae root verified from the encrypted authored record.
    pub author: [u8; 32],
    pub message: Message,
    #[serde(default)]
    pub latest_edit: Option<[u8; 32]>,
    #[serde(default)]
    pub edited_at_ms: Option<u64>,
}

/// A message retracted from the current projection. Its original and deletion
/// facts remain in the encrypted operation store.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeletedMessage {
    pub original: [u8; 32],
    pub author: [u8; 32],
    pub deletion: [u8; 32],
    pub deleted_at_ms: u64,
}

/// Current chat state plus the two retained subsets a member cannot see.
///
/// `pending_authority` and `revoked` mirror [`crate::CommonsProjection`]: the
/// operation stays retained and inspectable, its content stays out of the
/// projection. A surface may report their counts; it must not render them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChatProjection {
    pub channels: Vec<Channel>,
    pub messages: Vec<AuthoredMessage>,
    pub deleted_messages: Vec<DeletedMessage>,
    pub pending: Vec<PendingCausalOperation>,
    /// Retained facts whose author holds no converged capability yet.
    pub pending_authority: Vec<AuthorityOperation>,
    /// Retained facts whose author's capability was withdrawn.
    pub revoked: Vec<AuthorityOperation>,
}

/// Current materialized chat state committed by a retention checkpoint, plus
/// what re-evaluating authority over covered records needs without their keys.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatCheckpointSnapshot {
    pub channels: Vec<Channel>,
    pub messages: Vec<AuthoredMessage>,
    #[serde(default)]
    pub deleted_messages: Vec<DeletedMessage>,
    /// Every covered data operation, grouped by stable author root.
    #[serde(default)]
    pub covered: Vec<ChatCoveredAuthor>,
    /// Each author's last covered write per channel id.
    #[serde(default)]
    pub channel_writes: Vec<ChatChannelWrite>,
}

/// Covered operations of one stable author root, in causal order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatCoveredAuthor {
    pub author: [u8; 32],
    pub operations: Vec<[u8; 32]>,
}

/// One covered channel write, kept so a withdrawn author's write can be undone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatChannelWrite {
    pub operation: [u8; 32],
    pub author: [u8; 32],
    pub channel: Channel,
}

/// Highest complete chat operation represented for one author.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatAuthorFrontier {
    pub author: [u8; 32],
    pub seq_num: u32,
    pub operation: [u8; 32],
}

/// Why a checkpoint requires one epoch to remain decryptable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ChatEpochHoldReason {
    PendingCausality,
    AuthorityReevaluation,
}

/// Exact retained operations that keep one epoch reachable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatEpochHold {
    pub epoch: GroupSecretId,
    pub reason: ChatEpochHoldReason,
    pub operations: Vec<[u8; 32]>,
}

/// Commons-owned encrypted checkpoint grammar.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatCheckpoint {
    pub version: u16,
    pub space_id: [u8; 32],
    pub authority_revision: Digest,
    #[serde(default)]
    pub previous_checkpoint: Option<[u8; 32]>,
    /// Exact complete-data frontier represented by `snapshot`.
    pub causal_frontier: Vec<[u8; 32]>,
    /// Continuation point for every represented author log.
    pub author_frontiers: Vec<ChatAuthorFrontier>,
    pub epoch_inventory: Vec<GroupSecretId>,
    pub current_epoch: GroupSecretId,
    pub holds: Vec<ChatEpochHold>,
    pub snapshot: ChatCheckpointSnapshot,
    pub snapshot_commitment: Digest,
}

/// Authority resolved by Commons from its current governed membership state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatCheckpointAuthority {
    authority_revision: Digest,
    signers: BTreeSet<[u8; 32]>,
}

/// Latest accepted checkpoint and its signed operation identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredChatCheckpoint {
    pub operation: [u8; 32],
    pub checkpoint: ChatCheckpoint,
}

/// Recovery promise supplied by the Commons offline-member policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OfflineMemberEpochHold {
    pub member: [u8; 32],
    pub epoch: GroupSecretId,
}

/// Explicit recovery result after a member misses one or more rotations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OfflineMemberRecovery {
    Resume,
    BootstrapRequired { checkpoint: Option<Digest> },
}

#[derive(Debug, thiserror::Error)]
pub enum ChatError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Process(#[from] ProcessError),
    #[error(transparent)]
    Causal(#[from] CausalError),
    #[error(transparent)]
    Crypto(#[from] GroupCryptoError),
    #[error("chat checkpoint: {0}")]
    Checkpoint(String),
    #[error("unsupported chat checkpoint version {0}")]
    UnsupportedCheckpointVersion(u16),
    #[error("message mutation: {0}")]
    MessageMutation(String),
    #[error("chat wire: {0}")]
    Wire(String),
    #[error(transparent)]
    AuthorBinding(#[from] ChatAuthorBindingError),
}

/// Failure to construct a chat replica under a Personae-derived writer.
#[derive(Debug, thiserror::Error)]
pub enum ChatReplicaIdentityError {
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error("identity provider returned an invalid chat-writer attestation: {0}")]
    InvalidAttestation(CheckFault),
    #[error("identity provider attested a different chat writer")]
    WriterMismatch,
    #[error("identity provider attested a different stable Personae root")]
    RootMismatch,
}

#[derive(Clone)]
struct ChatPolicy {
    space_id: [u8; 32],
    /// One snapshot of the key handle for this admission.
    keys: Arc<DataKeyring>,
    projected_message_authors: BTreeMap<[u8; 32], [u8; 32]>,
    checkpoint_authority: Option<ChatCheckpointAuthority>,
    current_checkpoint: Option<StoredChatCheckpoint>,
    /// Retained data records, against which a new checkpoint is rebuilt.
    data: Vec<StoredChatOperation>,
}

/// A chat record's log, read before decrypting.
enum ChatLog<'a> {
    Data,
    Checkpoint {
        authority: &'a ChatCheckpointAuthority,
        link: ChatCheckpointLink,
    },
}

impl ChatLog<'_> {
    fn id(&self) -> u64 {
        match self {
            Self::Data => CHAT_LOG,
            Self::Checkpoint { .. } => CHAT_CHECKPOINT_LOG,
        }
    }
}

#[derive(Clone)]
struct StoredChatOperation {
    operation: Operation<ChatExt>,
    log_id: u64,
}

/// One member's encrypted Commons chat replica.
pub struct ChatReplica<B: Backend + Clone> {
    store: MunimentStore<B, ChatExt>,
    space_id: [u8; 32],
    signing_seed: [u8; 32],
    stable_author: [u8; 32],
    author_attestation: Option<DerivedKeyAttestation>,
    keys: GroupKeys,
    checkpoint_authority: Option<ChatCheckpointAuthority>,
    parking: Parking,
}

impl ChatReplica<MemoryBackend> {
    pub fn in_memory(
        space_id: [u8; 32],
        signing_seed: [u8; 32],
        keys: impl Into<GroupKeys>,
    ) -> Self {
        Self::new(MemoryBackend::new(), space_id, signing_seed, keys)
    }

    /// In-memory replica under this chat space's Personae-derived writer.
    pub fn in_memory_for_identity<P: IdentityProvider + ?Sized>(
        space_id: [u8; 32],
        identity: &P,
        keys: impl Into<GroupKeys>,
    ) -> Result<Self, ChatReplicaIdentityError> {
        Self::for_identity(MemoryBackend::new(), space_id, identity, keys)
    }
}

impl<B: Backend + Clone + Send + Sync + 'static> ChatReplica<B> {
    pub async fn join(
        &self,
        endpoint: Endpoint,
        gossip: Gossip,
    ) -> Result<JoinedSpace<ChatExt>, JoinError> {
        let store = self.sync_store();
        let accept_store = self.store.clone();
        let space_id = self.space_id;
        // The handle, not a copy of the keys: a keyring replaced after a
        // rotation reaches this lane's next admission.
        let keys = self.keys.clone();
        let checkpoint_authority = self.checkpoint_authority.clone();
        let parking = self.parking.clone();
        JoinedSpace::join::<_, u64, _, _>(
            stickleback::lane_id(COMMONS_CHAT_LANE, space_id),
            store,
            endpoint,
            gossip,
            space_id,
            move |operation: Operation<ChatExt>| {
                let accept_store = accept_store.clone();
                let keys = keys.current();
                let checkpoint_authority = checkpoint_authority.clone();
                let parking = parking.clone();
                async move {
                    matches!(
                        accept_or_park(
                            &accept_store,
                            space_id,
                            keys,
                            checkpoint_authority,
                            &parking,
                            &operation,
                        )
                        .await,
                        Ok(true)
                    )
                }
            },
        )
        .await
    }
}

/// The retained history split by log, loaded once.
///
/// Admitting one operation needs the data log (for the projected message
/// authors) and the checkpoint log (for the current checkpoint). Both used to
/// be fetched by their own full store read.
struct RetainedChatRecords {
    data: Vec<StoredChatOperation>,
    checkpoints: Vec<StoredChatOperation>,
}

impl RetainedChatRecords {
    /// Project from the latest checkpoint plus the records it does not cover.
    fn fold<A: CommonsAuthority>(
        &self,
        keys: &DataKeyring,
        space_id: [u8; 32],
        authority: &A,
    ) -> Result<ChatProjection, ChatError> {
        let checkpoint = latest_checkpoint_from_records(space_id, keys, &self.checkpoints)?;
        let checkpoint = checkpoint.as_ref().map(|stored| &stored.checkpoint);
        Ok(fold_chat(keys, space_id, &self.data, checkpoint, authority)?.projection)
    }
}

/// One checkpoint's covered records, by operation.
#[derive(Default)]
struct CheckpointIndex<'a> {
    authors: BTreeMap<[u8; 32], [u8; 32]>,
    messages: BTreeMap<[u8; 32], &'a AuthoredMessage>,
    deleted: BTreeMap<[u8; 32], &'a DeletedMessage>,
    channels: BTreeMap<[u8; 32], &'a ChatChannelWrite>,
}

impl<'a> CheckpointIndex<'a> {
    fn new(checkpoint: Option<&'a ChatCheckpoint>) -> Self {
        let Some(checkpoint) = checkpoint else {
            return Self::default();
        };
        let snapshot = &checkpoint.snapshot;
        Self {
            authors: snapshot
                .covered
                .iter()
                .flat_map(|covered| {
                    covered
                        .operations
                        .iter()
                        .map(|operation| (*operation, covered.author))
                })
                .collect(),
            messages: snapshot
                .messages
                .iter()
                .map(|message| (message.operation, message))
                .collect(),
            deleted: snapshot
                .deleted_messages
                .iter()
                .map(|deleted| (deleted.deletion, deleted))
                .collect(),
            channels: snapshot
                .channel_writes
                .iter()
                .map(|write| (write.operation, write))
                .collect(),
        }
    }
}

/// A chat fold plus what a checkpoint over the same records commits.
struct ChatFold {
    projection: ChatProjection,
    /// Causal order, as indices into the folded records.
    order: Vec<usize>,
    /// Stable author of each ordered record.
    authors: Vec<[u8; 32]>,
    /// Last write per channel id and author.
    channel_writes: BTreeMap<(String, [u8; 32]), ChatChannelWrite>,
}

/// What a checkpoint over `records` commits, folded onto `previous`.
struct CheckpointContent {
    causal_frontier: Vec<[u8; 32]>,
    author_frontiers: Vec<ChatAuthorFrontier>,
    snapshot: ChatCheckpointSnapshot,
    pending: Vec<PendingCausalOperation>,
}

#[cfg(test)]
#[path = "chat/tests.rs"]
mod tests;

#[path = "chat/writing.rs"]
mod writing;

#[path = "chat/checkpoint_ops.rs"]
mod checkpoint_ops;

#[path = "chat/checkpoint_validation.rs"]
mod checkpoint_validation;

use checkpoint_validation::{
    checkpoint_content, checkpoint_link, covered_operations, latest_checkpoint_from_records,
    validate_checkpoint_body, validate_checkpoint_epoch_inventory, validate_checkpoint_succession,
    validate_current_checkpoint_authority, verify_checkpoint_content,
};

#[path = "chat/fold.rs"]
mod fold;

use fold::{
    causal_entries, encrypted_body, fold_chat, load_operations_from_store, split_chat_records,
};

#[path = "chat/admission.rs"]
mod admission;

pub use admission::{chat_identity_salt, chat_write_capability};

use admission::{accept_or_park, admit_onto, chat_header, decode_authored, stable_chat_author};

#[path = "chat/replica.rs"]
mod replica;

#[cfg(test)]
use checkpoint_validation::decode_checkpoint_operation;
#[cfg(test)]
use fold::decode_event;
