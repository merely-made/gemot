//! Minimal encrypted Commons chat profile.
//!
//! This is intentionally distinct from Murm's bilateral `Post` grammar. It is
//! the second consumer of Stickleback's causal projection seam after Knot.

use std::collections::{BTreeMap, BTreeSet};

use muniment::{Backend, MemoryBackend, StoreError, WriteOp};
use p2panda_core::cbor::{decode_cbor, encode_cbor};
use p2panda_core::{Body, Hash, Header, Operation, SigningKey, Topic, VerifyingKey};
use p2panda_encryption::data_scheme::GroupSecretId;
use p2panda_net::{Endpoint, Gossip};
use p2panda_store::logs::LogStore;
use p2panda_store::topics::TopicStore;
use personae::{DerivedKeyAttestation, IdentityError, IdentityProvider};
use proofs::Digest;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use servitor::Cap;
use stickleback::{
    Admission, CausalEntry, CausalError, CausalLimits, CheckpointAuthority, DataKeyring,
    EpochCheckpointBasis, EpochHold, EpochHoldReason, EpochPruningProposal, EpochRetentionFacts,
    GroupCiphertext, GroupCryptoError, GroupEncryptionMode, GroupEncryptionProfile, JoinError,
    JoinedSpace, MunimentStore, OperationPolicy, OperationProcessor, PendingCausalOperation,
    ProcessError, Reject, StoreTarget, author_head, causal_projection, observed_frontier,
    propose_epoch_pruning, validate_causal_metadata,
};

const CHAT_LOG: u64 = 0;
const CHAT_CHECKPOINT_LOG: u64 = 1;
const CHAT_AUTHORED_VERSION: u16 = 1;
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

impl ChatClass {
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Channel => "commons.channel",
            Self::Message => "commons.message",
            Self::Checkpoint => "commons.checkpoint",
            Self::MessageEdit => "commons.message.edit",
            Self::MessageDelete => "commons.message.delete",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatExt {
    pub space_id: [u8; 32],
    pub class: ChatClass,
    #[serde(default)]
    pub parents: Vec<[u8; 32]>,
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

impl ChatEvent {
    fn class(&self) -> ChatClass {
        match self {
            Self::Channel(_) => ChatClass::Channel,
            Self::Message(_) => ChatClass::Message,
            Self::MessageEdit(_) => ChatClass::MessageEdit,
            Self::MessageDelete(_) => ChatClass::MessageDelete,
        }
    }
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

impl<T> ChatAuthored<T> {
    fn new(payload: T, author_attestation: Option<DerivedKeyAttestation>) -> Self {
        Self {
            version: CHAT_AUTHORED_VERSION,
            payload,
            author_attestation,
        }
    }
}

/// Domain-separated salt for one chat space's Personae-derived signing key.
pub fn chat_identity_salt(space_id: [u8; 32]) -> Vec<u8> {
    let mut salt = Vec::with_capacity(61);
    salt.extend_from_slice(b"mere.commons.chat.writer.v1/");
    salt.extend_from_slice(&space_id);
    salt
}

/// Typed write capability carried by every retained fact in one chat space.
pub fn chat_write_capability(space_id: [u8; 32]) -> Cap {
    let hex: String = space_id.iter().map(|byte| format!("{byte:02x}")).collect();
    Cap::scope(&format!("commons/chat/{hex}"))
        .expect("a fixed prefix plus lowercase hex is a valid scope")
}

/// Invalid binding between a signed chat operation and a stable Personae root.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ChatAuthorBindingError {
    #[error("unsupported authored-chat payload version {0}")]
    UnsupportedVersion(u16),
    #[error("derived chat-author attestation does not verify for this space")]
    InvalidAttestation,
    #[error("derived chat-author attestation contains an invalid key")]
    InvalidDerivedKey,
    #[error("derived chat-author attestation does not bind the operation signer")]
    SignerMismatch,
    #[error("derived chat-author attestation contains an invalid root key")]
    InvalidRoot,
}

fn decode_authored<T: DeserializeOwned>(bytes: &[u8]) -> Result<ChatAuthored<T>, ChatError> {
    match decode_cbor::<ChatAuthored<T>, _>(bytes) {
        Ok(record) => {
            if record.version != CHAT_AUTHORED_VERSION {
                return Err(ChatAuthorBindingError::UnsupportedVersion(record.version).into());
            }
            Ok(record)
        }
        Err(_) => {
            let payload = decode_cbor(bytes).map_err(|error| ChatError::Wire(error.to_string()))?;
            Ok(ChatAuthored {
                version: 0,
                payload,
                author_attestation: None,
            })
        }
    }
}

fn stable_chat_author<T>(
    operation: &Operation<ChatExt>,
    record: &ChatAuthored<T>,
) -> Result<[u8; 32], ChatAuthorBindingError> {
    let signer = *operation.header.verifying_key.as_bytes();
    let Some(attestation) = &record.author_attestation else {
        return Ok(signer);
    };
    if !attestation.verify(&chat_identity_salt(operation.header.extensions.space_id)) {
        return Err(ChatAuthorBindingError::InvalidAttestation);
    }
    let derived = attestation
        .derived_public_key()
        .map_err(|_| ChatAuthorBindingError::InvalidDerivedKey)?
        .to_bytes();
    if derived != signer {
        return Err(ChatAuthorBindingError::SignerMismatch);
    }
    attestation
        .master_public_key()
        .map(|key| key.to_bytes())
        .map_err(|_| ChatAuthorBindingError::InvalidRoot)
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

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChatProjection {
    pub channels: Vec<Channel>,
    pub messages: Vec<AuthoredMessage>,
    pub deleted_messages: Vec<DeletedMessage>,
    pub pending: Vec<PendingCausalOperation>,
}

/// Current materialized chat state committed by a retention checkpoint.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatCheckpointSnapshot {
    pub channels: Vec<Channel>,
    pub messages: Vec<AuthoredMessage>,
    #[serde(default)]
    pub deleted_messages: Vec<DeletedMessage>,
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

impl ChatCheckpoint {
    fn snapshot_commitment(snapshot: &ChatCheckpointSnapshot) -> Result<Digest, ChatError> {
        let bytes = encode_cbor(snapshot).map_err(|error| ChatError::Wire(error.to_string()))?;
        Ok(Digest::blake3(&bytes))
    }
}

/// Authority resolved by Commons from its current governed membership state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatCheckpointAuthority {
    authority_revision: Digest,
    signers: BTreeSet<[u8; 32]>,
}

impl ChatCheckpointAuthority {
    pub fn new(authority_revision: Digest, signers: impl IntoIterator<Item = [u8; 32]>) -> Self {
        Self {
            authority_revision,
            signers: signers.into_iter().collect(),
        }
    }
}

impl CheckpointAuthority for ChatCheckpointAuthority {
    fn authority_revision(&self) -> Digest {
        self.authority_revision.clone()
    }

    fn permits_checkpoint(&self, author: [u8; 32], named_revision: &Digest) -> bool {
        *named_revision == self.authority_revision && self.signers.contains(&author)
    }
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

/// Atomic host receipt for one explicit, revalidated epoch erasure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatEpochExecutionReceipt {
    pub version: u16,
    pub space_id: [u8; 32],
    pub checkpoint: Digest,
    pub authority_revision: Digest,
    pub forgotten: Vec<GroupSecretId>,
    pub retained: Vec<GroupSecretId>,
    pub previous_keyring: Digest,
    pub persisted_keyring: Digest,
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
    #[error("reviewed epoch proposal is stale")]
    StaleRetentionProposal,
    #[error("epoch proposal is blocked")]
    BlockedRetentionProposal,
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
    #[error("identity provider returned an invalid chat-writer attestation")]
    InvalidAttestation,
    #[error("identity provider attested a different chat writer")]
    WriterMismatch,
    #[error("identity provider attested a different stable Personae root")]
    RootMismatch,
}

#[derive(Clone)]
struct ChatPolicy {
    space_id: [u8; 32],
    key_state: Vec<u8>,
    projected_message_authors: BTreeMap<[u8; 32], [u8; 32]>,
    checkpoint_authority: Option<ChatCheckpointAuthority>,
    current_checkpoint: Option<StoredChatCheckpoint>,
}

impl OperationPolicy<ChatExt> for ChatPolicy {
    type LogId = u64;

    fn admit(&self, operation: &Operation<ChatExt>) -> Result<Admission<u64>, Reject> {
        if operation.header.extensions.space_id != self.space_id {
            return Err(Reject::new(
                "wrong-chat-space",
                "operation addresses another Commons chat space",
            ));
        }
        validate_causal_metadata(operation, &operation.header.extensions.parents, CHAT_LIMITS)
            .map_err(|error| Reject::new("invalid-chat-causality", error.to_string()))?;
        let body = operation.body.as_ref().ok_or_else(|| {
            Reject::new(
                "missing-chat-ciphertext",
                "chat operation requires an encrypted body",
            )
        })?;
        let envelope = decode_cbor::<GroupCiphertext, _>(body.to_bytes().as_slice())
            .map_err(|error| Reject::new("invalid-chat-ciphertext", error.to_string()))?;
        let keys = DataKeyring::from_bytes(&self.key_state)
            .map_err(|error| Reject::new("invalid-chat-key-state", error.to_string()))?;
        let log_id = match operation.header.extensions.class {
            ChatClass::Channel
            | ChatClass::Message
            | ChatClass::MessageEdit
            | ChatClass::MessageDelete => {
                let plaintext = keys
                    .open(&envelope)
                    .map_err(|error| Reject::new("unreadable-chat-event", error.to_string()))?;
                let record: ChatAuthored<ChatEvent> = decode_authored(plaintext.as_slice())
                    .map_err(|error| Reject::new("invalid-chat-event", error.to_string()))?;
                let stable_author = stable_chat_author(operation, &record).map_err(|error| {
                    Reject::new("invalid-chat-author-binding", error.to_string())
                })?;
                let event = record.payload;
                if event.class() != operation.header.extensions.class {
                    return Err(Reject::new(
                        "mismatched-chat-class",
                        "signed content class does not match encrypted event",
                    ));
                }
                let original = match &event {
                    ChatEvent::MessageEdit(edit) => Some(edit.original),
                    ChatEvent::MessageDelete(delete) => Some(delete.original),
                    ChatEvent::Channel(_) | ChatEvent::Message(_) => None,
                };
                if let Some(original) = original {
                    let Some(author) = self.projected_message_authors.get(&original) else {
                        return Err(Reject::new(
                            "unprojected-message-mutation",
                            "edit or deletion must reference a current projected message",
                        ));
                    };
                    if author != &stable_author {
                        return Err(Reject::new(
                            "foreign-message-mutation",
                            "only the original author can edit or delete a message",
                        ));
                    }
                }
                CHAT_LOG
            }
            ChatClass::Checkpoint => {
                let authority = self.checkpoint_authority.as_ref().ok_or_else(|| {
                    Reject::new(
                        "checkpoint-authority-unconfigured",
                        "this Commons has no configured checkpoint authority",
                    )
                })?;
                if authority.signers.len() != 1 {
                    return Err(Reject::new(
                        "ambiguous-checkpoint-authority",
                        format!(
                            "checkpoint v1 requires one active signer, found {}",
                            authority.signers.len()
                        ),
                    ));
                }
                let plaintext = keys.open(&envelope).map_err(|error| {
                    Reject::new("unreadable-chat-checkpoint", error.to_string())
                })?;
                let record: ChatAuthored<ChatCheckpoint> = decode_authored(plaintext.as_slice())
                    .map_err(|error| Reject::new("invalid-chat-checkpoint", error.to_string()))?;
                let stable_author = stable_chat_author(operation, &record).map_err(|error| {
                    Reject::new("invalid-chat-author-binding", error.to_string())
                })?;
                let checkpoint = record.payload;
                validate_retained_checkpoint(
                    self.space_id,
                    self.current_checkpoint.as_ref(),
                    &envelope,
                    &operation.header.extensions.parents,
                    &checkpoint,
                )
                .map_err(|error| Reject::new("invalid-chat-checkpoint", error))?;
                validate_current_checkpoint_authority(stable_author, authority, &checkpoint)
                    .map_err(|error| Reject::new("invalid-chat-checkpoint", error))?;
                validate_checkpoint_epoch_inventory(&keys, &checkpoint)
                    .map_err(|error| Reject::new("invalid-chat-checkpoint", error))?;
                CHAT_CHECKPOINT_LOG
            }
        };
        Ok(Admission::keep(StoreTarget::new(
            Topic::from(self.space_id),
            log_id,
        )))
    }
}

fn validate_current_checkpoint_authority(
    author: [u8; 32],
    authority: &ChatCheckpointAuthority,
    candidate: &ChatCheckpoint,
) -> Result<(), String> {
    if !authority.permits_checkpoint(author, &candidate.authority_revision) {
        return Err("checkpoint author or authority revision is not current".into());
    }
    Ok(())
}

fn validate_checkpoint_epoch_inventory(
    keys: &DataKeyring,
    candidate: &ChatCheckpoint,
) -> Result<(), String> {
    let Some(local_order) = keys.epochs_oldest_first() else {
        return Err("checkpoint admission requires proven local epoch chronology".into());
    };
    if candidate.epoch_inventory.len() > local_order.len()
        || local_order[..candidate.epoch_inventory.len()] != candidate.epoch_inventory
    {
        return Err("checkpoint epoch inventory is not a prefix of local chronology".into());
    }
    Ok(())
}

fn validate_retained_checkpoint(
    expected_space: [u8; 32],
    current: Option<&StoredChatCheckpoint>,
    envelope: &GroupCiphertext,
    signed_parents: &[[u8; 32]],
    candidate: &ChatCheckpoint,
) -> Result<(), String> {
    if candidate.version != 1 {
        return Err(format!(
            "unsupported checkpoint version {}",
            candidate.version
        ));
    }
    if candidate.space_id != expected_space {
        return Err("checkpoint addresses another Commons".into());
    }
    if candidate.previous_checkpoint != current.map(|stored| stored.operation) {
        return Err("checkpoint does not extend the latest accepted checkpoint".into());
    }
    if candidate.snapshot_commitment
        != ChatCheckpoint::snapshot_commitment(&candidate.snapshot)
            .map_err(|error| error.to_string())?
    {
        return Err("checkpoint snapshot commitment is false".into());
    }
    if signed_parents != candidate.causal_frontier {
        return Err("signed checkpoint frontier does not match its encrypted body".into());
    }
    let unique_causal: BTreeSet<_> = candidate.causal_frontier.iter().copied().collect();
    if unique_causal.len() != candidate.causal_frontier.len() {
        return Err("checkpoint causal frontier contains duplicates".into());
    }
    if candidate.epoch_inventory.last().copied() != Some(candidate.current_epoch)
        || envelope.epoch != candidate.current_epoch
    {
        return Err("checkpoint is not protected under its named current epoch".into());
    }

    let mut candidate_authors = BTreeMap::new();
    for frontier in &candidate.author_frontiers {
        if candidate_authors
            .insert(frontier.author, frontier)
            .is_some()
        {
            return Err("checkpoint author frontier contains duplicates".into());
        }
    }
    if let Some(current) = current {
        for previous in &current.checkpoint.author_frontiers {
            let Some(next) = candidate_authors.get(&previous.author) else {
                return Err("checkpoint drops an existing author frontier".into());
            };
            if next.seq_num < previous.seq_num
                || (next.seq_num == previous.seq_num && next.operation != previous.operation)
            {
                return Err("checkpoint author frontier rewinds".into());
            }
        }
    }

    let mut held_operations = BTreeSet::new();
    for hold in &candidate.holds {
        if !candidate.epoch_inventory.contains(&hold.epoch) {
            return Err("checkpoint hold names an epoch outside its inventory".into());
        }
        if hold.operations.is_empty() {
            return Err("checkpoint hold contains no retained operation".into());
        }
        for operation in &hold.operations {
            if !held_operations.insert(*operation) {
                return Err("checkpoint hold repeats a retained operation".into());
            }
        }
    }
    Ok(())
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
    keys: DataKeyring,
    checkpoint_authority: Option<ChatCheckpointAuthority>,
}

impl ChatReplica<MemoryBackend> {
    pub fn in_memory(space_id: [u8; 32], signing_seed: [u8; 32], keys: DataKeyring) -> Self {
        Self::new(MemoryBackend::new(), space_id, signing_seed, keys)
    }

    /// In-memory replica under this chat space's Personae-derived writer.
    pub fn in_memory_for_identity<P: IdentityProvider + ?Sized>(
        space_id: [u8; 32],
        identity: &P,
        keys: DataKeyring,
    ) -> Result<Self, ChatReplicaIdentityError> {
        Self::for_identity(MemoryBackend::new(), space_id, identity, keys)
    }
}

impl<B: Backend + Clone> ChatReplica<B> {
    /// Direct-root compatibility constructor.
    ///
    /// Product hosts with a Personae identity should use
    /// [`Self::for_identity`].
    pub fn new(backend: B, space_id: [u8; 32], signing_seed: [u8; 32], keys: DataKeyring) -> Self {
        debug_assert_eq!(COMMONS_CHAT_PROFILE.mode, GroupEncryptionMode::Data);
        let stable_author = *SigningKey::from_bytes(&signing_seed)
            .verifying_key()
            .as_bytes();
        Self {
            store: MunimentStore::new(backend),
            space_id,
            signing_seed,
            stable_author,
            author_attestation: None,
            keys,
            checkpoint_authority: None,
        }
    }

    /// Replica writing under this chat space's derived Personae key.
    ///
    /// Every authored encrypted record carries the root attestation. Admission
    /// verifies it against the operation signer and projection exposes the
    /// stable root as the message author.
    pub fn for_identity<P: IdentityProvider + ?Sized>(
        backend: B,
        space_id: [u8; 32],
        identity: &P,
        keys: DataKeyring,
    ) -> Result<Self, ChatReplicaIdentityError> {
        debug_assert_eq!(COMMONS_CHAT_PROFILE.mode, GroupEncryptionMode::Data);
        let salt = chat_identity_salt(space_id);
        let keypair = identity.derive_keypair(&salt)?;
        let author_attestation = identity.attest_derived_key(&salt)?;
        if !author_attestation.verify(&salt) {
            return Err(ChatReplicaIdentityError::InvalidAttestation);
        }
        let derived = author_attestation
            .derived_public_key()
            .map_err(|_| ChatReplicaIdentityError::InvalidAttestation)?
            .to_bytes();
        if derived != keypair.public_key().to_bytes() {
            return Err(ChatReplicaIdentityError::WriterMismatch);
        }
        let stable_author = author_attestation
            .master_public_key()
            .map_err(|_| ChatReplicaIdentityError::InvalidAttestation)?
            .to_bytes();
        if stable_author != identity.master_public_key().to_bytes() {
            return Err(ChatReplicaIdentityError::RootMismatch);
        }
        Ok(Self {
            store: MunimentStore::new(backend),
            space_id,
            signing_seed: keypair.to_seed(),
            stable_author,
            author_attestation: Some(author_attestation),
            keys,
            checkpoint_authority: None,
        })
    }

    /// Stable Personae root used for author and authority projection.
    pub fn stable_author(&self) -> [u8; 32] {
        self.stable_author
    }

    /// Install the current Commons-governed checkpoint authority.
    pub fn set_checkpoint_authority(&mut self, authority: ChatCheckpointAuthority) {
        self.checkpoint_authority = Some(authority);
    }

    pub fn sync_store(&self) -> MunimentStore<B, ChatExt> {
        self.store.clone()
    }

    pub fn key_state(&self) -> Result<Vec<u8>, GroupCryptoError> {
        self.keys.to_bytes()
    }

    pub async fn author(&mut self, event: ChatEvent) -> Result<Operation<ChatExt>, ChatError> {
        let records = self.load_data_operations().await?;
        let entries = causal_entries(&records);
        let parents = observed_frontier(&entries)?;
        let signing_key = SigningKey::from_bytes(&self.signing_seed);
        let author = signing_key.verifying_key();
        let (seq_num, backlink) = author_head(&entries, *author.as_bytes(), &CHAT_LOG)?;
        let class = event.class();
        let record = ChatAuthored::new(event, self.author_attestation.clone());
        let plaintext = encode_cbor(&record).map_err(|error| ChatError::Wire(error.to_string()))?;
        let envelope = self
            .keys
            .seal(&plaintext, &p2panda_encryption::Rng::default())?;
        let body_bytes =
            encode_cbor(&envelope).map_err(|error| ChatError::Wire(error.to_string()))?;
        let body = Body::new(&body_bytes);
        let mut header = Header {
            version: 1,
            verifying_key: author,
            signature: None,
            payload_size: body.size(),
            payload_hash: Some(body.hash()),
            seq_num,
            backlink: backlink.map(Hash::from),
            extensions: ChatExt {
                space_id: self.space_id,
                class,
                parents,
            },
        };
        header.sign(&signing_key);
        let operation = Operation {
            hash: header.hash(),
            header,
            body: Some(body),
        };
        self.accept(&operation).await?;
        Ok(operation)
    }

    /// Author an immutable edit of this member's projected message.
    pub async fn edit_message(
        &mut self,
        original: [u8; 32],
        body: String,
        edited_at_ms: u64,
    ) -> Result<Operation<ChatExt>, ChatError> {
        self.ensure_owned_projected_message(original).await?;
        self.author(ChatEvent::MessageEdit(MessageEdit {
            original,
            body,
            edited_at_ms,
        }))
        .await
    }

    /// Author an immutable deletion of this member's projected message.
    pub async fn delete_message(
        &mut self,
        original: [u8; 32],
        deleted_at_ms: u64,
    ) -> Result<Operation<ChatExt>, ChatError> {
        self.ensure_owned_projected_message(original).await?;
        self.author(ChatEvent::MessageDelete(MessageDelete {
            original,
            deleted_at_ms,
        }))
        .await
    }

    async fn ensure_owned_projected_message(&self, original: [u8; 32]) -> Result<(), ChatError> {
        let projection = self.projection().await?;
        let message = projection
            .messages
            .iter()
            .find(|message| message.operation == original)
            .ok_or_else(|| {
                ChatError::MessageMutation(
                    "the original message is absent from the current projection".into(),
                )
            })?;
        if message.author != self.stable_author {
            return Err(ChatError::MessageMutation(
                "only the original author can edit or delete a message".into(),
            ));
        }
        Ok(())
    }

    pub async fn accept(&self, operation: &Operation<ChatExt>) -> Result<bool, ChatError> {
        let current_checkpoint = self.latest_checkpoint().await?;
        let projected_message_authors = self
            .projection()
            .await?
            .messages
            .into_iter()
            .map(|message| (message.operation, message.author))
            .collect();
        let processor = OperationProcessor::new(
            self.store.clone(),
            ChatPolicy {
                space_id: self.space_id,
                key_state: self.keys.to_bytes()?,
                projected_message_authors,
                checkpoint_authority: self.checkpoint_authority.clone(),
                current_checkpoint,
            },
        );
        Ok(processor.process(operation).await?.inserted())
    }

    pub async fn projection(&self) -> Result<ChatProjection, ChatError> {
        let records = self.load_data_operations().await?;
        project_records(&self.keys, &records)
    }

    async fn load_data_operations(&self) -> Result<Vec<StoredChatOperation>, ChatError> {
        Ok(self
            .load_operations()
            .await?
            .into_iter()
            .filter(|record| record.log_id == CHAT_LOG)
            .collect())
    }

    async fn load_checkpoint_operations(&self) -> Result<Vec<StoredChatOperation>, ChatError> {
        Ok(self
            .load_operations()
            .await?
            .into_iter()
            .filter(|record| record.log_id == CHAT_CHECKPOINT_LOG)
            .collect())
    }

    /// Latest structurally valid checkpoint in the signed predecessor chain.
    pub async fn latest_checkpoint(&self) -> Result<Option<StoredChatCheckpoint>, ChatError> {
        latest_checkpoint_from_records(
            self.space_id,
            &self.keys,
            self.load_checkpoint_operations().await?,
        )
    }

    /// Build, encrypt, sign, authorize, and retain a checkpoint.
    pub async fn author_checkpoint(&mut self) -> Result<Operation<ChatExt>, ChatError> {
        let checkpoint = self.build_checkpoint().await?;
        let checkpoint_records = self.load_checkpoint_operations().await?;
        let entries = causal_entries(&checkpoint_records);
        let signing_key = SigningKey::from_bytes(&self.signing_seed);
        let author = signing_key.verifying_key();
        let (seq_num, backlink) = author_head(&entries, *author.as_bytes(), &CHAT_CHECKPOINT_LOG)?;
        let record = ChatAuthored::new(checkpoint.clone(), self.author_attestation.clone());
        let plaintext = encode_cbor(&record).map_err(|error| ChatError::Wire(error.to_string()))?;
        let envelope = self
            .keys
            .seal(&plaintext, &p2panda_encryption::Rng::default())?;
        debug_assert_eq!(envelope.epoch, checkpoint.current_epoch);
        let body_bytes =
            encode_cbor(&envelope).map_err(|error| ChatError::Wire(error.to_string()))?;
        let body = Body::new(&body_bytes);
        let mut header = Header {
            version: 1,
            verifying_key: author,
            signature: None,
            payload_size: body.size(),
            payload_hash: Some(body.hash()),
            seq_num,
            backlink: backlink.map(Hash::from),
            extensions: ChatExt {
                space_id: self.space_id,
                class: ChatClass::Checkpoint,
                parents: checkpoint.causal_frontier.clone(),
            },
        };
        header.sign(&signing_key);
        let operation = Operation {
            hash: header.hash(),
            header,
            body: Some(body),
        };
        self.accept(&operation).await?;
        Ok(operation)
    }

    /// Construct the checkpoint candidate without mutating the store.
    pub async fn build_checkpoint(&self) -> Result<ChatCheckpoint, ChatError> {
        let authority = self.checkpoint_authority.as_ref().ok_or_else(|| {
            ChatError::Checkpoint("checkpoint authority is not configured".into())
        })?;
        if !authority.permits_checkpoint(self.stable_author, &authority.authority_revision()) {
            return Err(ChatError::Checkpoint(
                "local signer is not the current checkpoint authority".into(),
            ));
        }
        let records = self.load_data_operations().await?;
        let entries = causal_entries(&records);
        let causal = causal_projection(&entries)?;
        let effective_entries: Vec<_> = causal
            .order
            .iter()
            .map(|index| entries[*index].clone())
            .collect();
        let mut causal_frontier = observed_frontier(&effective_entries)?;
        causal_frontier.sort_unstable();
        let projection = project_records(&self.keys, &records)?;

        let mut author_frontiers = BTreeMap::<[u8; 32], ChatAuthorFrontier>::new();
        for entry in &effective_entries {
            let frontier = ChatAuthorFrontier {
                author: entry.author,
                seq_num: entry.seq_num,
                operation: entry.operation,
            };
            match author_frontiers.get(&entry.author) {
                Some(current) if current.seq_num >= entry.seq_num => {}
                _ => {
                    author_frontiers.insert(entry.author, frontier);
                }
            }
        }

        let by_operation: BTreeMap<_, _> = records
            .iter()
            .map(|record| (*record.operation.hash.as_bytes(), record))
            .collect();
        let mut pending_by_epoch = BTreeMap::<GroupSecretId, Vec<[u8; 32]>>::new();
        for pending in &causal.pending {
            let record = by_operation.get(&pending.operation).ok_or_else(|| {
                ChatError::Checkpoint("pending operation is absent from the retained store".into())
            })?;
            let envelope = encrypted_body(&record.operation)?;
            pending_by_epoch
                .entry(envelope.epoch)
                .or_default()
                .push(pending.operation);
        }
        let holds = pending_by_epoch
            .into_iter()
            .map(|(epoch, mut operations)| {
                operations.sort_unstable();
                ChatEpochHold {
                    epoch,
                    reason: ChatEpochHoldReason::PendingCausality,
                    operations,
                }
            })
            .collect();

        let epoch_inventory = self
            .keys
            .epochs_oldest_first()
            .ok_or_else(|| {
                ChatError::Checkpoint(
                    "checkpoint construction requires proven epoch chronology".into(),
                )
            })?
            .to_vec();
        let current_epoch = self
            .keys
            .current_epoch()
            .ok_or(GroupCryptoError::MissingCurrentEpoch)?;
        let snapshot = ChatCheckpointSnapshot {
            channels: projection.channels,
            messages: projection.messages,
            deleted_messages: projection.deleted_messages,
        };
        let snapshot_commitment = ChatCheckpoint::snapshot_commitment(&snapshot)?;
        Ok(ChatCheckpoint {
            version: 1,
            space_id: self.space_id,
            authority_revision: authority.authority_revision(),
            previous_checkpoint: self
                .latest_checkpoint()
                .await?
                .map(|stored| stored.operation),
            causal_frontier,
            author_frontiers: author_frontiers.into_values().collect(),
            epoch_inventory,
            current_epoch,
            holds,
            snapshot,
            snapshot_commitment,
        })
    }

    /// Rebuild current state from the latest checkpoint plus retained tail.
    pub async fn projection_from_checkpoint(&self) -> Result<ChatProjection, ChatError> {
        let Some(stored) = self.latest_checkpoint().await? else {
            return self.projection().await;
        };
        let records = self.load_data_operations().await?;
        project_checkpoint_tail(&self.keys, &stored.checkpoint, &records)
    }

    /// Compute the dry-run epoch proposal from Commons-owned retention facts.
    pub async fn epoch_pruning_proposal(
        &self,
        offline_members: &[OfflineMemberEpochHold],
    ) -> Result<EpochPruningProposal, ChatError> {
        let stored = self.latest_checkpoint().await?;
        let mut holds = Vec::new();
        let checkpoint = if let Some(stored) = stored {
            let authority = self.checkpoint_authority.as_ref().ok_or_else(|| {
                ChatError::Checkpoint(
                    "checkpoint authority must be configured before proposing retention".into(),
                )
            })?;
            let records = self.load_data_operations().await?;
            for record in records_after_checkpoint(&stored.checkpoint, &records) {
                holds.push(EpochHold {
                    epoch: encrypted_body(&record.operation)?.epoch,
                    reason: EpochHoldReason::DecryptionReachability,
                });
            }
            holds.push(EpochHold {
                epoch: stored.checkpoint.current_epoch,
                reason: EpochHoldReason::DecryptionReachability,
            });
            for hold in &stored.checkpoint.holds {
                let reason = match hold.reason {
                    ChatEpochHoldReason::PendingCausality => EpochHoldReason::PendingCausality,
                    ChatEpochHoldReason::AuthorityReevaluation => {
                        EpochHoldReason::AuthorityReevaluation
                    }
                };
                holds.push(EpochHold {
                    epoch: hold.epoch,
                    reason,
                });
            }
            let author_continuation_ready =
                self.projection_from_checkpoint().await? == self.projection().await?;
            Some(EpochCheckpointBasis {
                checkpoint: Digest::p2panda_operation(stored.operation),
                authority_revision: stored.checkpoint.authority_revision,
                current_authority_revision: authority.authority_revision(),
                author_continuation_ready,
            })
        } else {
            None
        };
        holds.extend(offline_members.iter().map(|hold| EpochHold {
            epoch: hold.epoch,
            reason: EpochHoldReason::OfflineMember(hold.member),
        }));
        Ok(propose_epoch_pruning(
            COMMONS_CHAT_PROFILE,
            &self.keys,
            &EpochRetentionFacts { checkpoint, holds },
        ))
    }

    /// Revalidate and explicitly execute a reviewed proposal. Key state and
    /// receipt land in one backend `apply`; only then does the live keyring
    /// switch to the reduced state.
    pub async fn execute_epoch_pruning(
        &mut self,
        reviewed: &EpochPruningProposal,
        offline_members: &[OfflineMemberEpochHold],
    ) -> Result<ChatEpochExecutionReceipt, ChatError> {
        let current = self.epoch_pruning_proposal(offline_members).await?;
        if &current != reviewed {
            return Err(ChatError::StaleRetentionProposal);
        }
        if !current.is_executable() {
            return Err(ChatError::BlockedRetentionProposal);
        }
        let checkpoint = current
            .checkpoint
            .clone()
            .ok_or(ChatError::BlockedRetentionProposal)?;
        let stored = self
            .latest_checkpoint()
            .await?
            .ok_or(ChatError::BlockedRetentionProposal)?;
        let before = self.keys.to_bytes()?;
        let mut reduced = DataKeyring::from_bytes(&before)?;
        for epoch in &current.forget {
            if !reduced.forget_authorized(epoch) {
                return Err(ChatError::StaleRetentionProposal);
            }
        }
        let after = reduced.to_bytes()?;
        let receipt = ChatEpochExecutionReceipt {
            version: 1,
            space_id: self.space_id,
            checkpoint,
            authority_revision: stored.checkpoint.authority_revision,
            forgotten: current.forget,
            retained: reduced
                .epochs_oldest_first()
                .ok_or_else(|| {
                    ChatError::Checkpoint(
                        "executed keyring lost its proven epoch chronology".into(),
                    )
                })?
                .to_vec(),
            previous_keyring: Digest::blake3(&before),
            persisted_keyring: Digest::blake3(&after),
        };
        let receipt_bytes =
            encode_cbor(&receipt).map_err(|error| ChatError::Wire(error.to_string()))?;
        self.store
            .backend()
            .apply(&[
                WriteOp::Put {
                    key: chat_keyring_key(self.space_id),
                    value: after,
                },
                WriteOp::Put {
                    key: chat_epoch_receipt_key(self.space_id),
                    value: receipt_bytes,
                },
            ])
            .await?;
        self.keys = reduced;
        Ok(receipt)
    }

    /// Restore the atomically persisted reduced keyring, if one exists.
    pub async fn restore_persisted_keyring(&mut self) -> Result<bool, ChatError> {
        let Some(bytes) = self
            .store
            .backend()
            .get(&chat_keyring_key(self.space_id))
            .await?
        else {
            return Ok(false);
        };
        self.keys = DataKeyring::from_bytes(&bytes)?;
        Ok(true)
    }

    pub async fn epoch_execution_receipt(
        &self,
    ) -> Result<Option<ChatEpochExecutionReceipt>, ChatError> {
        let Some(bytes) = self
            .store
            .backend()
            .get(&chat_epoch_receipt_key(self.space_id))
            .await?
        else {
            return Ok(None);
        };
        decode_cbor(bytes.as_slice())
            .map(Some)
            .map_err(|error| ChatError::Wire(error.to_string()))
    }

    pub async fn offline_member_recovery(
        &self,
        required_epoch: GroupSecretId,
    ) -> Result<OfflineMemberRecovery, ChatError> {
        if self.keys.contains(&required_epoch) {
            return Ok(OfflineMemberRecovery::Resume);
        }
        Ok(OfflineMemberRecovery::BootstrapRequired {
            checkpoint: self
                .latest_checkpoint()
                .await?
                .map(|stored| Digest::p2panda_operation(stored.operation)),
        })
    }

    async fn load_operations(&self) -> Result<Vec<StoredChatOperation>, ChatError> {
        load_operations_from_store(&self.store, self.space_id).await
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
        let key_state = self
            .keys
            .to_bytes()
            .map_err(|error| JoinError::Spawn(format!("chat key state: {error}")))?;
        let checkpoint_authority = self.checkpoint_authority.clone();
        JoinedSpace::join::<_, u64, _, _>(
            store,
            endpoint,
            gossip,
            space_id,
            move |operation: Operation<ChatExt>| {
                let accept_store = accept_store.clone();
                let key_state = key_state.clone();
                let checkpoint_authority = checkpoint_authority.clone();
                async move {
                    let Ok(keys) = DataKeyring::from_bytes(&key_state) else {
                        return false;
                    };
                    let Ok(records) = load_operations_from_store(&accept_store, space_id).await
                    else {
                        return false;
                    };
                    let data_records: Vec<_> = records
                        .iter()
                        .filter(|record| record.log_id == CHAT_LOG)
                        .cloned()
                        .collect();
                    let Ok(projection) = project_records(&keys, &data_records) else {
                        return false;
                    };
                    let projected_message_authors = projection
                        .messages
                        .into_iter()
                        .map(|message| (message.operation, message.author))
                        .collect();
                    let checkpoints = records
                        .into_iter()
                        .filter(|record| record.log_id == CHAT_CHECKPOINT_LOG)
                        .collect();
                    let Ok(current_checkpoint) =
                        latest_checkpoint_from_records(space_id, &keys, checkpoints)
                    else {
                        return false;
                    };
                    let processor = OperationProcessor::new(
                        accept_store,
                        ChatPolicy {
                            space_id,
                            key_state,
                            projected_message_authors,
                            checkpoint_authority,
                            current_checkpoint,
                        },
                    );
                    matches!(processor.process(&operation).await, Ok(out) if out.inserted())
                }
            },
        )
        .await
    }
}

fn causal_entries(records: &[StoredChatOperation]) -> Vec<CausalEntry<u64>> {
    records
        .iter()
        .map(|record| {
            CausalEntry::from_operation(
                &record.operation,
                record.log_id,
                record.operation.header.extensions.parents.clone(),
            )
        })
        .collect()
}

fn chat_keyring_key(space_id: [u8; 32]) -> String {
    let hex: String = space_id.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("commons/chat/{hex}/data-keyring")
}

fn chat_epoch_receipt_key(space_id: [u8; 32]) -> String {
    let hex: String = space_id.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("commons/chat/{hex}/epoch-pruning-receipt")
}

async fn load_operations_from_store<B: Backend + Clone>(
    store: &MunimentStore<B, ChatExt>,
    space_id: [u8; 32],
) -> Result<Vec<StoredChatOperation>, ChatError> {
    let logs: BTreeMap<VerifyingKey, Vec<u64>> = store.resolve(&Topic::from(space_id)).await?;
    let mut records = Vec::new();
    for (author, mut log_ids) in logs {
        log_ids.sort_unstable();
        log_ids.dedup();
        for log_id in log_ids {
            for (operation, _) in store
                .get_log_entries(&author, &log_id, None, None)
                .await?
                .unwrap_or_default()
            {
                records.push(StoredChatOperation { operation, log_id });
            }
        }
    }
    Ok(records)
}

fn latest_checkpoint_from_records(
    space_id: [u8; 32],
    keys: &DataKeyring,
    records: Vec<StoredChatOperation>,
) -> Result<Option<StoredChatCheckpoint>, ChatError> {
    let mut decoded = records
        .into_iter()
        .map(|record| {
            let operation = *record.operation.hash.as_bytes();
            let signed_parents = record.operation.header.extensions.parents.clone();
            let (checkpoint, envelope) = decode_checkpoint_operation(keys, &record.operation)?;
            Ok((operation, signed_parents, checkpoint, envelope))
        })
        .collect::<Result<Vec<_>, ChatError>>()?;
    let mut current: Option<StoredChatCheckpoint> = None;
    while !decoded.is_empty() {
        let expected_previous = current.as_ref().map(|stored| stored.operation);
        let matches: Vec<_> = decoded
            .iter()
            .enumerate()
            .filter_map(|(index, (_, _, checkpoint, _))| {
                (checkpoint.previous_checkpoint == expected_previous).then_some(index)
            })
            .collect();
        if matches.len() != 1 {
            return Err(ChatError::Checkpoint(
                "checkpoint history is forked or missing a predecessor".into(),
            ));
        }
        let (operation, signed_parents, checkpoint, envelope) = decoded.remove(matches[0]);
        validate_retained_checkpoint(
            space_id,
            current.as_ref(),
            &envelope,
            &signed_parents,
            &checkpoint,
        )
        .map_err(ChatError::Checkpoint)?;
        current = Some(StoredChatCheckpoint {
            operation,
            checkpoint,
        });
    }
    Ok(current)
}

fn project_records(
    keys: &DataKeyring,
    records: &[StoredChatOperation],
) -> Result<ChatProjection, ChatError> {
    let causal = causal_projection(&causal_entries(records))?;
    let mut channels = BTreeMap::new();
    let mut messages = Vec::new();
    let mut deleted_messages = Vec::new();
    for index in causal.order {
        let (event, author) = decode_event_record(keys, &records[index].operation)?;
        apply_event(
            &mut channels,
            &mut messages,
            &mut deleted_messages,
            &records[index].operation,
            author,
            event,
        )?;
    }
    Ok(ChatProjection {
        channels: channels.into_values().collect(),
        messages,
        deleted_messages,
        pending: causal.pending,
    })
}

fn project_checkpoint_tail(
    keys: &DataKeyring,
    checkpoint: &ChatCheckpoint,
    records: &[StoredChatOperation],
) -> Result<ChatProjection, ChatError> {
    let tail_records = records_after_checkpoint(checkpoint, records);
    let checkpoint_dependencies: BTreeSet<_> = checkpoint
        .causal_frontier
        .iter()
        .copied()
        .chain(
            checkpoint
                .author_frontiers
                .iter()
                .map(|frontier| frontier.operation),
        )
        .collect();
    let tail_entries: Vec<_> = tail_records
        .iter()
        .map(|record| {
            let mut entry = CausalEntry::from_operation(
                &record.operation,
                record.log_id,
                record
                    .operation
                    .header
                    .extensions
                    .parents
                    .iter()
                    .copied()
                    .filter(|parent| !checkpoint_dependencies.contains(parent))
                    .collect(),
            );
            if entry
                .backlink
                .is_some_and(|backlink| checkpoint_dependencies.contains(&backlink))
            {
                entry.backlink = None;
            }
            entry
        })
        .collect();
    let causal = causal_projection(&tail_entries)?;
    let mut channels: BTreeMap<_, _> = checkpoint
        .snapshot
        .channels
        .iter()
        .cloned()
        .map(|channel| (channel.id.clone(), channel))
        .collect();
    let mut messages = checkpoint.snapshot.messages.clone();
    let mut deleted_messages = checkpoint.snapshot.deleted_messages.clone();
    for index in causal.order {
        let (event, author) = decode_event_record(keys, &tail_records[index].operation)?;
        apply_event(
            &mut channels,
            &mut messages,
            &mut deleted_messages,
            &tail_records[index].operation,
            author,
            event,
        )?;
    }
    Ok(ChatProjection {
        channels: channels.into_values().collect(),
        messages,
        deleted_messages,
        pending: causal.pending,
    })
}

fn records_after_checkpoint<'a>(
    checkpoint: &ChatCheckpoint,
    records: &'a [StoredChatOperation],
) -> Vec<&'a StoredChatOperation> {
    let author_frontiers: BTreeMap<_, _> = checkpoint
        .author_frontiers
        .iter()
        .map(|frontier| (frontier.author, frontier))
        .collect();
    let mut tail_records = Vec::new();
    for record in records {
        let author = *record.operation.header.verifying_key.as_bytes();
        if author_frontiers
            .get(&author)
            .is_some_and(|frontier| record.operation.header.seq_num <= frontier.seq_num)
        {
            continue;
        }
        tail_records.push(record);
    }
    tail_records
}

fn apply_event(
    channels: &mut BTreeMap<String, Channel>,
    messages: &mut Vec<AuthoredMessage>,
    deleted_messages: &mut Vec<DeletedMessage>,
    operation: &Operation<ChatExt>,
    stable_author: [u8; 32],
    event: ChatEvent,
) -> Result<(), ChatError> {
    if event.class() != operation.header.extensions.class {
        return Err(ChatError::Wire(
            "signed content class does not match encrypted event".into(),
        ));
    }
    match event {
        ChatEvent::Channel(channel) => {
            channels.insert(channel.id.clone(), channel);
        }
        ChatEvent::Message(message) => messages.push(AuthoredMessage {
            operation: *operation.hash.as_bytes(),
            author: stable_author,
            message,
            latest_edit: None,
            edited_at_ms: None,
        }),
        ChatEvent::MessageEdit(edit) => {
            let message = messages
                .iter_mut()
                .find(|message| message.operation == edit.original)
                .ok_or_else(|| {
                    ChatError::MessageMutation(
                        "edit does not reference a projected original message".into(),
                    )
                })?;
            require_original_author(message, stable_author)?;
            message.message.body = edit.body;
            message.latest_edit = Some(*operation.hash.as_bytes());
            message.edited_at_ms = Some(edit.edited_at_ms);
        }
        ChatEvent::MessageDelete(delete) => {
            let index = messages
                .iter()
                .position(|message| message.operation == delete.original)
                .ok_or_else(|| {
                    ChatError::MessageMutation(
                        "deletion does not reference a projected original message".into(),
                    )
                })?;
            require_original_author(&messages[index], stable_author)?;
            let message = messages.remove(index);
            deleted_messages.push(DeletedMessage {
                original: message.operation,
                author: message.author,
                deletion: *operation.hash.as_bytes(),
                deleted_at_ms: delete.deleted_at_ms,
            });
        }
    }
    Ok(())
}

fn require_original_author(
    original: &AuthoredMessage,
    mutation_author: [u8; 32],
) -> Result<(), ChatError> {
    if original.author != mutation_author {
        return Err(ChatError::MessageMutation(
            "only the original author can edit or delete a message".into(),
        ));
    }
    Ok(())
}

fn encrypted_body(operation: &Operation<ChatExt>) -> Result<GroupCiphertext, ChatError> {
    let body = operation
        .body
        .as_ref()
        .ok_or_else(|| ChatError::Wire("operation body is absent".into()))?;
    decode_cbor(body.to_bytes().as_slice()).map_err(|error| ChatError::Wire(error.to_string()))
}

fn decode_checkpoint_operation(
    keys: &DataKeyring,
    operation: &Operation<ChatExt>,
) -> Result<(ChatCheckpoint, GroupCiphertext), ChatError> {
    if operation.header.extensions.class != ChatClass::Checkpoint {
        return Err(ChatError::Checkpoint(
            "checkpoint log contains a non-checkpoint operation".into(),
        ));
    }
    let envelope = encrypted_body(operation)?;
    let plaintext = keys.open(&envelope)?;
    let record: ChatAuthored<ChatCheckpoint> = decode_authored(plaintext.as_slice())?;
    stable_chat_author(operation, &record)?;
    Ok((record.payload, envelope))
}

#[cfg(test)]
fn decode_event(
    keys: &DataKeyring,
    operation: &Operation<ChatExt>,
) -> Result<ChatEvent, ChatError> {
    decode_event_record(keys, operation).map(|(event, _)| event)
}

fn decode_event_record(
    keys: &DataKeyring,
    operation: &Operation<ChatExt>,
) -> Result<(ChatEvent, [u8; 32]), ChatError> {
    let envelope = encrypted_body(operation)?;
    let plaintext = keys.open(&envelope)?;
    let record: ChatAuthored<ChatEvent> = decode_authored(plaintext.as_slice())?;
    let stable_author = stable_chat_author(operation, &record)?;
    Ok((record.payload, stable_author))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::net::{SocketAddr, TcpListener};
    use std::sync::Arc;
    use std::time::Duration;

    use crate::{AuthorityState, CommonsAuthority, GemotAuthorityView};
    use gemot::moot::constitution::{CapabilityGrant, ConstitutionRules};
    use gemot::moot::{MOOT_ACT_ACTION, MOOT_DELEGATION_DOMAIN, MootAuthority, MootDelegations};
    use muniment::RedbBackend;
    use murm::{CabalId, CabalKey, CabalKeyring};
    use personae::delegation::{
        CapabilityScope, DelegationCertificate, DelegationParent, DelegationRevocation,
        SignedDelegationCertificate, SignedDelegationRevocation,
    };
    use personae::{IdentityProvider, InMemoryProvider};
    use servitor::{Mode, Subject, cap_path};
    use stickleback::{
        DropLimits, DropRecord, decode_operation_record, operation_record, read_protected_drop,
        write_protected_drop,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use transport::{
        Alpn, P2pandaTransport, PeerID, ReticulumInterface, ReticulumTransport, Transport,
        sync_overlay_topic,
    };

    use super::*;

    const SPACE: [u8; 32] = [0x51; 32];
    const MOOT: [u8; 32] = [0x6d; 32];
    const ROOT_GRANT: [u8; 32] = [0x67; 32];

    fn paired_keys() -> (DataKeyring, DataKeyring) {
        let rng = p2panda_encryption::Rng::default();
        let mut alice = DataKeyring::new();
        let secret = alice.rotate(&rng).unwrap();
        let mut bob = DataKeyring::new();
        bob.install(secret);
        (alice, bob)
    }

    fn free_addr() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        addr
    }

    fn checkpoint_authority(seed: [u8; 32], revision: &[u8]) -> ChatCheckpointAuthority {
        let author = SigningKey::from_bytes(&seed).verifying_key();
        ChatCheckpointAuthority::new(Digest::blake3(revision), [*author.as_bytes()])
    }

    fn checkpoint_operation(
        replica: &ChatReplica<MemoryBackend>,
        checkpoint: &ChatCheckpoint,
        signing_seed: [u8; 32],
        seq_num: u32,
        backlink: Option<[u8; 32]>,
    ) -> Operation<ChatExt> {
        let plaintext = encode_cbor(checkpoint).unwrap();
        let envelope = replica
            .keys
            .seal(&plaintext, &p2panda_encryption::Rng::default())
            .unwrap();
        let body = Body::new(&encode_cbor(&envelope).unwrap());
        let signing_key = SigningKey::from_bytes(&signing_seed);
        let mut header = Header {
            version: 1,
            verifying_key: signing_key.verifying_key(),
            signature: None,
            payload_size: body.size(),
            payload_hash: Some(body.hash()),
            seq_num,
            backlink: backlink.map(Hash::from),
            extensions: ChatExt {
                space_id: replica.space_id,
                class: ChatClass::Checkpoint,
                parents: checkpoint.causal_frontier.clone(),
            },
        };
        header.sign(&signing_key);
        Operation {
            hash: header.hash(),
            header,
            body: Some(body),
        }
    }

    fn event_operation(
        replica: &ChatReplica<MemoryBackend>,
        event: &ChatEvent,
        signing_seed: [u8; 32],
        parents: Vec<[u8; 32]>,
        seq_num: u32,
        backlink: Option<[u8; 32]>,
    ) -> Operation<ChatExt> {
        let plaintext = encode_cbor(event).unwrap();
        let envelope = replica
            .keys
            .seal(&plaintext, &p2panda_encryption::Rng::default())
            .unwrap();
        let body = Body::new(&encode_cbor(&envelope).unwrap());
        let signing_key = SigningKey::from_bytes(&signing_seed);
        let mut header = Header {
            version: 1,
            verifying_key: signing_key.verifying_key(),
            signature: None,
            payload_size: body.size(),
            payload_hash: Some(body.hash()),
            seq_num,
            backlink: backlink.map(Hash::from),
            extensions: ChatExt {
                space_id: replica.space_id,
                class: event.class(),
                parents,
            },
        };
        header.sign(&signing_key);
        Operation {
            hash: header.hash(),
            header,
            body: Some(body),
        }
    }

    fn bound_event_operation(
        replica: &ChatReplica<MemoryBackend>,
        event: ChatEvent,
        signing_seed: [u8; 32],
        author_attestation: DerivedKeyAttestation,
    ) -> Operation<ChatExt> {
        let record = ChatAuthored::new(event, Some(author_attestation));
        let plaintext = encode_cbor(&record).unwrap();
        let envelope = replica
            .keys
            .seal(&plaintext, &p2panda_encryption::Rng::default())
            .unwrap();
        let body = Body::new(&encode_cbor(&envelope).unwrap());
        let signing_key = SigningKey::from_bytes(&signing_seed);
        let mut header = Header {
            version: 1,
            verifying_key: signing_key.verifying_key(),
            signature: None,
            payload_size: body.size(),
            payload_hash: Some(body.hash()),
            seq_num: 0,
            backlink: None,
            extensions: ChatExt {
                space_id: replica.space_id,
                class: record.payload.class(),
                parents: Vec::new(),
            },
        };
        header.sign(&signing_key);
        Operation {
            hash: header.hash(),
            header,
            body: Some(body),
        }
    }

    #[tokio::test]
    async fn personae_chat_author_binds_to_gemot_subject_and_revocation() {
        let founder = InMemoryProvider::from_seed([0x71; 32]);
        let writer = InMemoryProvider::from_seed([0x72; 32]);
        let stranger = InMemoryProvider::from_seed([0x73; 32]);
        let (author_keys, relay_keys) = paired_keys();
        let mut author = ChatReplica::in_memory_for_identity(SPACE, &writer, author_keys).unwrap();
        assert_eq!(
            author.stable_author(),
            writer.master_public_key().to_bytes()
        );
        assert_ne!(
            *SigningKey::from_bytes(&author.signing_seed)
                .verifying_key()
                .as_bytes(),
            author.stable_author()
        );

        let message = Message {
            channel: "general".into(),
            body: "bound author".into(),
            sent_at_ms: 1,
            reply_to: None,
        };
        let operation = author
            .author(ChatEvent::Message(message.clone()))
            .await
            .unwrap();
        let edit = author
            .edit_message(*operation.hash.as_bytes(), "root-bound edit".into(), 2)
            .await
            .unwrap();
        author.set_checkpoint_authority(ChatCheckpointAuthority::new(
            Digest::blake3(b"root-bound checkpoint"),
            [writer.master_public_key().to_bytes()],
        ));
        let checkpoint = author.author_checkpoint().await.unwrap();
        assert!(decode_checkpoint_operation(&author.keys, &checkpoint).is_ok());

        let relay = ChatReplica::in_memory(SPACE, [0x74; 32], relay_keys);
        let forged = bound_event_operation(
            &author,
            ChatEvent::Message(message.clone()),
            author.signing_seed,
            stranger
                .attest_derived_key(&chat_identity_salt(SPACE))
                .unwrap(),
        );
        let error = relay
            .accept(&forged)
            .await
            .expect_err("a foreign root cannot claim the derived chat signer");
        assert!(error.to_string().contains("invalid-chat-author-binding"));
        assert_eq!(relay.sync_store().operation_count().await.unwrap(), 0);

        let cross_space = bound_event_operation(
            &author,
            ChatEvent::Message(message),
            author.signing_seed,
            writer
                .attest_derived_key(&chat_identity_salt([0x52; 32]))
                .unwrap(),
        );
        let error = relay
            .accept(&cross_space)
            .await
            .expect_err("a derived-key attestation cannot be replayed into another chat space");
        assert!(error.to_string().contains("invalid-chat-author-binding"));
        assert_eq!(relay.sync_store().operation_count().await.unwrap(), 0);

        relay.accept(&operation).await.unwrap();
        relay.accept(&edit).await.unwrap();
        let projection = relay.projection().await.unwrap();
        assert_eq!(projection.messages.len(), 1);
        assert_eq!(projection.messages[0].message.body, "root-bound edit");
        assert_eq!(
            projection.messages[0].author,
            writer.master_public_key().to_bytes()
        );

        let capability = chat_write_capability(SPACE);
        let needed = cap_path(&capability);
        let mut rules = ConstitutionRules::founder_only(founder.master_public_key().to_bytes());
        rules.grant(CapabilityGrant {
            id: ROOT_GRANT,
            subject: founder.master_public_key().to_bytes(),
            path_prefix: needed.clone(),
            not_before_ms: 10,
            expires_at_ms: Some(1_000),
            delegation_depth: 2,
        });
        let delegation = SignedDelegationCertificate::issue(
            &founder,
            DelegationCertificate::new(
                DelegationParent::Root(ROOT_GRANT),
                founder.master_public_key().to_bytes(),
                writer.master_public_key().to_bytes(),
                CapabilityScope {
                    domain: MOOT_DELEGATION_DOMAIN.into(),
                    resource: MOOT.to_vec(),
                    path_prefix: needed,
                    actions: [MOOT_ACT_ACTION.to_string()].into_iter().collect(),
                },
                15,
                20,
                Some(900),
                0,
                [1; 32],
            ),
        )
        .unwrap();
        let delegation_id = delegation.certificate.id();
        let delegation_scope = delegation.certificate.scope.clone();
        let mut delegations = MootDelegations::new();
        assert!(
            delegations
                .accept_certificate(MOOT, &rules, delegation)
                .unwrap()
        );
        let view = GemotAuthorityView {
            authority: MootAuthority {
                delegations: &delegations,
                rules: &rules,
                moot_id: MOOT,
                now_ms: 50,
            },
        };
        assert_eq!(
            view.classify(
                Subject(projection.messages[0].author),
                &capability,
                Mode::Write
            ),
            AuthorityState::Effective
        );

        let revocation = SignedDelegationRevocation::issue(
            &founder,
            DelegationRevocation::new(
                delegation_id,
                founder.master_public_key().to_bytes(),
                delegation_scope,
                60,
                [2; 32],
            ),
        )
        .unwrap();
        assert!(delegations.accept_revocation(revocation).unwrap());
        let withdrawn = GemotAuthorityView {
            authority: MootAuthority {
                delegations: &delegations,
                rules: &rules,
                moot_id: MOOT,
                now_ms: 50,
            },
        };
        assert_eq!(
            withdrawn.classify(
                Subject(projection.messages[0].author),
                &capability,
                Mode::Write
            ),
            AuthorityState::Revoked
        );
        assert_eq!(relay.sync_store().operation_count().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn immutable_edit_changes_only_the_projected_message_body() {
        let seed = [0x91; 32];
        let (keys, _) = paired_keys();
        let mut replica = ChatReplica::in_memory(SPACE, seed, keys);
        let original = replica
            .author(ChatEvent::Message(Message {
                channel: "general".into(),
                body: "first draft".into(),
                sent_at_ms: 10,
                reply_to: None,
            }))
            .await
            .unwrap();
        replica
            .author(ChatEvent::Channel(Channel {
                id: "general".into(),
                title: "General".into(),
            }))
            .await
            .unwrap();

        let edit = replica
            .edit_message(*original.hash.as_bytes(), "second draft".into(), 12)
            .await
            .unwrap();
        let projection = replica.projection().await.unwrap();
        assert_eq!(projection.messages.len(), 1);
        assert_eq!(projection.messages[0].operation, *original.hash.as_bytes());
        assert_eq!(projection.messages[0].message.body, "second draft");
        assert_eq!(
            projection.messages[0].latest_edit,
            Some(*edit.hash.as_bytes())
        );
        assert_eq!(projection.messages[0].edited_at_ms, Some(12));

        let records = replica.load_data_operations().await.unwrap();
        assert_eq!(records.len(), 3);
        assert!(records.iter().any(|record| {
            matches!(
                decode_event(&replica.keys, &record.operation),
                Ok(event)
                    if event == ChatEvent::Message(Message {
                        channel: "general".into(),
                        body: "first draft".into(),
                        sent_at_ms: 10,
                        reply_to: None,
                    })
            )
        }));
        assert!(records.iter().any(|record| {
            matches!(
                decode_event(&replica.keys, &record.operation),
                Ok(event)
                    if event == ChatEvent::MessageEdit(MessageEdit {
                        original: *original.hash.as_bytes(),
                        body: "second draft".into(),
                        edited_at_ms: 12,
                    })
            )
        }));
    }

    #[tokio::test]
    async fn deletion_retracts_projection_but_survives_checkpoint_and_storage() {
        let seed = [0x92; 32];
        let (keys, _) = paired_keys();
        let mut replica = ChatReplica::in_memory(SPACE, seed, keys);
        replica.set_checkpoint_authority(checkpoint_authority(seed, b"mutation checkpoint"));
        let original = replica
            .author(ChatEvent::Message(Message {
                channel: "general".into(),
                body: "remove me".into(),
                sent_at_ms: 20,
                reply_to: None,
            }))
            .await
            .unwrap();
        let deletion = replica
            .delete_message(*original.hash.as_bytes(), 21)
            .await
            .unwrap();

        let projection = replica.projection().await.unwrap();
        assert!(projection.messages.is_empty());
        assert_eq!(
            projection.deleted_messages,
            vec![DeletedMessage {
                original: *original.hash.as_bytes(),
                author: *SigningKey::from_bytes(&seed).verifying_key().as_bytes(),
                deletion: *deletion.hash.as_bytes(),
                deleted_at_ms: 21,
            }]
        );
        assert!(matches!(
            replica
                .edit_message(*original.hash.as_bytes(), "resurrect".into(), 22)
                .await,
            Err(ChatError::MessageMutation(_))
        ));

        replica.author_checkpoint().await.unwrap();
        assert_eq!(
            replica.projection_from_checkpoint().await.unwrap(),
            projection
        );
        let records = replica.load_data_operations().await.unwrap();
        assert_eq!(records.len(), 2);
        assert!(records.iter().any(|record| {
            matches!(
                decode_event(&replica.keys, &record.operation),
                Ok(ChatEvent::Message(_))
            )
        }));
        assert!(records.iter().any(|record| {
            matches!(
                decode_event(&replica.keys, &record.operation),
                Ok(ChatEvent::MessageDelete(_))
            )
        }));
    }

    #[tokio::test]
    async fn another_author_cannot_mutate_a_message() {
        let seed = [0x93; 32];
        let (keys, _) = paired_keys();
        let mut replica = ChatReplica::in_memory(SPACE, seed, keys);
        let original = replica
            .author(ChatEvent::Message(Message {
                channel: "general".into(),
                body: "mine".into(),
                sent_at_ms: 30,
                reply_to: None,
            }))
            .await
            .unwrap();
        let foreign = event_operation(
            &replica,
            &ChatEvent::MessageDelete(MessageDelete {
                original: *original.hash.as_bytes(),
                deleted_at_ms: 31,
            }),
            [0x94; 32],
            vec![*original.hash.as_bytes()],
            0,
            None,
        );
        assert!(matches!(
            replica.accept(&foreign).await,
            Err(ChatError::Process(ProcessError::Rejected(reject)))
                if reject.code == "foreign-message-mutation"
        ));
        let projection = replica.projection().await.unwrap();
        assert_eq!(projection.messages.len(), 1);
        assert!(projection.deleted_messages.is_empty());
    }

    #[tokio::test]
    async fn authorized_checkpoint_plus_tail_reproduces_full_replay() {
        let seed = [0xa1; 32];
        let (keys, _) = paired_keys();
        let mut replica = ChatReplica::in_memory(SPACE, seed, keys);
        replica.set_checkpoint_authority(checkpoint_authority(seed, b"commons authority 1"));
        replica
            .author(ChatEvent::Channel(Channel {
                id: "general".into(),
                title: "General".into(),
            }))
            .await
            .unwrap();
        replica
            .author(ChatEvent::Message(Message {
                channel: "general".into(),
                body: "represented by the checkpoint".into(),
                sent_at_ms: 1,
                reply_to: None,
            }))
            .await
            .unwrap();

        let first = replica.author_checkpoint().await.unwrap();
        let stored = replica.latest_checkpoint().await.unwrap().unwrap();
        assert_eq!(stored.operation, *first.hash.as_bytes());
        assert_eq!(stored.checkpoint.previous_checkpoint, None);
        assert_eq!(
            stored.checkpoint.snapshot_commitment,
            ChatCheckpoint::snapshot_commitment(&stored.checkpoint.snapshot).unwrap()
        );
        assert_eq!(
            encrypted_body(&first).unwrap().epoch,
            stored.checkpoint.current_epoch
        );

        replica
            .author(ChatEvent::Message(Message {
                channel: "general".into(),
                body: "retained tail".into(),
                sent_at_ms: 2,
                reply_to: None,
            }))
            .await
            .unwrap();
        assert_eq!(
            replica.projection_from_checkpoint().await.unwrap(),
            replica.projection().await.unwrap()
        );

        let second = replica.author_checkpoint().await.unwrap();
        assert_eq!(
            replica
                .latest_checkpoint()
                .await
                .unwrap()
                .unwrap()
                .checkpoint
                .previous_checkpoint,
            Some(*first.hash.as_bytes())
        );
        assert_ne!(first.hash, second.hash);
    }

    #[tokio::test]
    async fn pending_fact_keeps_its_ciphertext_epoch_reachable() {
        let seed = [0xa1; 32];
        let (keys, _) = paired_keys();
        let mut replica = ChatReplica::in_memory(SPACE, seed, keys);
        replica.set_checkpoint_authority(checkpoint_authority(seed, b"commons authority 1"));
        let pending = event_operation(
            &replica,
            &ChatEvent::Message(Message {
                channel: "general".into(),
                body: "waiting for a missing parent".into(),
                sent_at_ms: 3,
                reply_to: None,
            }),
            seed,
            vec![[0xfe; 32]],
            0,
            None,
        );
        let pending_epoch = encrypted_body(&pending).unwrap().epoch;
        replica.accept(&pending).await.unwrap();
        for _ in 0..9 {
            replica
                .keys
                .rotate(&p2panda_encryption::Rng::default())
                .unwrap();
        }

        let checkpoint = replica.build_checkpoint().await.unwrap();
        assert_eq!(
            checkpoint.holds,
            vec![ChatEpochHold {
                epoch: pending_epoch,
                reason: ChatEpochHoldReason::PendingCausality,
                operations: vec![*pending.hash.as_bytes()],
            }]
        );
        replica.author_checkpoint().await.unwrap();
        assert_eq!(
            replica.projection_from_checkpoint().await.unwrap(),
            replica.projection().await.unwrap()
        );
        let proposal = replica.epoch_pruning_proposal(&[]).await.unwrap();
        assert!(proposal.is_executable());
        assert!(!proposal.forget.contains(&pending_epoch));
        assert!(proposal.retain.iter().any(|retained| {
            retained.epoch == pending_epoch
                && retained
                    .reasons
                    .contains(&stickleback::EpochRetentionReason::Domain(
                        EpochHoldReason::PendingCausality,
                    ))
        }));
    }

    #[tokio::test]
    async fn commons_proposal_combines_profile_tail_and_offline_member_holds() {
        let seed = [0xa1; 32];
        let mut keys = DataKeyring::new();
        let mut epochs = Vec::new();
        for _ in 0..10 {
            epochs.push(
                keys.rotate(&p2panda_encryption::Rng::default())
                    .unwrap()
                    .id(),
            );
        }
        let mut replica = ChatReplica::in_memory(SPACE, seed, keys);
        replica.set_checkpoint_authority(checkpoint_authority(seed, b"commons authority 1"));
        replica.author_checkpoint().await.unwrap();

        let ordinary = replica.epoch_pruning_proposal(&[]).await.unwrap();
        assert!(ordinary.is_executable());
        assert_eq!(ordinary.forget, epochs[..2]);

        let offline = replica
            .epoch_pruning_proposal(&[OfflineMemberEpochHold {
                member: [0xb2; 32],
                epoch: epochs[0],
            }])
            .await
            .unwrap();
        assert!(offline.is_executable());
        assert_eq!(offline.forget, vec![epochs[1]]);
        assert!(offline.retain.iter().any(|retained| {
            retained.epoch == epochs[0]
                && retained
                    .reasons
                    .contains(&stickleback::EpochRetentionReason::Domain(
                        EpochHoldReason::OfflineMember([0xb2; 32]),
                    ))
        }));
    }

    #[tokio::test]
    async fn authorized_execution_is_atomic_revalidated_and_reopens() {
        let seed = [0xa1; 32];
        let directory = tempfile::tempdir().unwrap();
        let backend = RedbBackend::open(directory.path().join("commons.redb")).unwrap();
        let mut keys = DataKeyring::new();
        let mut epochs = Vec::new();
        for _ in 0..10 {
            epochs.push(
                keys.rotate(&p2panda_encryption::Rng::default())
                    .unwrap()
                    .id(),
            );
        }
        let authority = checkpoint_authority(seed, b"commons authority 1");
        let mut replica = ChatReplica::new(backend.clone(), SPACE, seed, keys);
        replica.set_checkpoint_authority(authority.clone());
        replica.author_checkpoint().await.unwrap();

        let stale = replica.epoch_pruning_proposal(&[]).await.unwrap();
        replica.author_checkpoint().await.unwrap();
        assert!(matches!(
            replica.execute_epoch_pruning(&stale, &[]).await,
            Err(ChatError::StaleRetentionProposal)
        ));
        assert!(replica.epoch_execution_receipt().await.unwrap().is_none());
        assert_eq!(replica.keys.epoch_count(), 10);

        let reviewed = replica.epoch_pruning_proposal(&[]).await.unwrap();
        let receipt = replica.execute_epoch_pruning(&reviewed, &[]).await.unwrap();
        assert_eq!(receipt.forgotten, epochs[..2]);
        assert_eq!(receipt.retained, epochs[2..]);
        assert_eq!(replica.keys.epoch_count(), 8);
        assert_eq!(
            replica.epoch_execution_receipt().await.unwrap(),
            Some(receipt.clone())
        );

        let mut reopened = ChatReplica::new(backend, SPACE, seed, DataKeyring::new());
        reopened.set_checkpoint_authority(authority);
        assert!(reopened.restore_persisted_keyring().await.unwrap());
        assert_eq!(reopened.keys.epochs_oldest_first().unwrap(), &epochs[2..]);
        assert_eq!(
            reopened.offline_member_recovery(epochs[2]).await.unwrap(),
            OfflineMemberRecovery::Resume
        );
        assert!(matches!(
            reopened.offline_member_recovery(epochs[0]).await.unwrap(),
            OfflineMemberRecovery::BootstrapRequired {
                checkpoint: Some(_)
            }
        ));
        assert_eq!(
            reopened.projection_from_checkpoint().await.unwrap(),
            reopened.projection().await.unwrap()
        );
    }

    #[tokio::test]
    async fn stale_foreign_forged_and_rewinding_checkpoints_do_not_mutate() {
        let seed = [0xa1; 32];
        let (keys, _) = paired_keys();
        let mut replica = ChatReplica::in_memory(SPACE, seed, keys);
        replica.set_checkpoint_authority(checkpoint_authority(seed, b"commons authority 1"));
        replica
            .author(ChatEvent::Message(Message {
                channel: "general".into(),
                body: "checkpoint base".into(),
                sent_at_ms: 4,
                reply_to: None,
            }))
            .await
            .unwrap();
        let first = replica.author_checkpoint().await.unwrap();
        let current = replica.latest_checkpoint().await.unwrap().unwrap();
        let candidate = replica.build_checkpoint().await.unwrap();

        let mut stale = candidate.clone();
        stale.previous_checkpoint = None;
        assert!(
            replica
                .accept(&checkpoint_operation(
                    &replica,
                    &stale,
                    seed,
                    1,
                    Some(*first.hash.as_bytes()),
                ))
                .await
                .is_err()
        );

        let mut foreign = candidate.clone();
        foreign.space_id = [0xf0; 32];
        assert!(
            replica
                .accept(&checkpoint_operation(
                    &replica,
                    &foreign,
                    seed,
                    1,
                    Some(*first.hash.as_bytes()),
                ))
                .await
                .is_err()
        );

        let mut old_authority = candidate.clone();
        old_authority.authority_revision = Digest::blake3(b"superseded authority");
        assert!(
            replica
                .accept(&checkpoint_operation(
                    &replica,
                    &old_authority,
                    seed,
                    1,
                    Some(*first.hash.as_bytes()),
                ))
                .await
                .is_err()
        );

        let mut rewinding = candidate.clone();
        rewinding.author_frontiers[0].operation = [0x99; 32];
        assert!(
            replica
                .accept(&checkpoint_operation(
                    &replica,
                    &rewinding,
                    seed,
                    1,
                    Some(*first.hash.as_bytes()),
                ))
                .await
                .is_err()
        );

        let mut forged =
            checkpoint_operation(&replica, &candidate, seed, 1, Some(*first.hash.as_bytes()));
        forged.header.seq_num = 2;
        assert!(replica.accept(&forged).await.is_err());

        assert_eq!(replica.latest_checkpoint().await.unwrap(), Some(current));
    }

    #[tokio::test]
    async fn two_partitioned_members_converge_through_memory_accept() {
        let (alice_keys, bob_keys) = paired_keys();
        let mut alice = ChatReplica::in_memory(SPACE, [0xa1; 32], alice_keys);
        let mut bob = ChatReplica::in_memory(SPACE, [0xb2; 32], bob_keys);

        let channel = alice
            .author(ChatEvent::Channel(Channel {
                id: "general".into(),
                title: "General".into(),
            }))
            .await
            .unwrap();
        bob.accept(&channel).await.unwrap();
        let a_message = alice
            .author(ChatEvent::Message(Message {
                channel: "general".into(),
                body: "amber".into(),
                sent_at_ms: 1,
                reply_to: None,
            }))
            .await
            .unwrap();
        let b_message = bob
            .author(ChatEvent::Message(Message {
                channel: "general".into(),
                body: "blue".into(),
                sent_at_ms: 2,
                reply_to: Some(*a_message.hash.as_bytes()),
            }))
            .await
            .unwrap();
        alice.accept(&b_message).await.unwrap();
        bob.accept(&a_message).await.unwrap();

        let a = alice.projection().await.unwrap();
        let b = bob.projection().await.unwrap();
        assert_eq!(a, b);
        assert_eq!(a.channels.len(), 1);
        assert_eq!(a.messages.len(), 2);
        assert!(a.pending.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_members_converge_over_real_logsync() {
        let alice_identity = Arc::new(InMemoryProvider::from_seed([0xa1; 32]));
        let bob_identity = Arc::new(InMemoryProvider::from_seed([0xb2; 32]));
        let alice_transport = P2pandaTransport::builder(alice_identity.master_keypair())
            .gossip()
            .bind()
            .await
            .unwrap();
        let bob_transport = P2pandaTransport::builder(bob_identity.master_keypair())
            .gossip()
            .bind()
            .await
            .unwrap();
        let overlay = sync_overlay_topic(SPACE);
        alice_transport
            .add_peer(bob_transport.endpoint_addr().await.unwrap())
            .await
            .unwrap();
        alice_transport
            .set_topics(
                PeerID::from_public_key(bob_identity.master_public_key()),
                &[overlay],
            )
            .await
            .unwrap();
        bob_transport
            .add_peer(alice_transport.endpoint_addr().await.unwrap())
            .await
            .unwrap();
        bob_transport
            .set_topics(
                PeerID::from_public_key(alice_identity.master_public_key()),
                &[overlay],
            )
            .await
            .unwrap();

        let (alice_keys, bob_keys) = paired_keys();
        let mut alice =
            ChatReplica::in_memory(SPACE, alice_identity.master_keypair().to_seed(), alice_keys);
        let mut bob =
            ChatReplica::in_memory(SPACE, bob_identity.master_keypair().to_seed(), bob_keys);
        alice
            .author(ChatEvent::Message(Message {
                channel: "general".into(),
                body: "over the lane".into(),
                sent_at_ms: 3,
                reply_to: None,
            }))
            .await
            .unwrap();
        bob.author(ChatEvent::Message(Message {
            channel: "general".into(),
            body: "from the other side".into(),
            sent_at_ms: 4,
            reply_to: None,
        }))
        .await
        .unwrap();

        let (a_endpoint, a_gossip) = alice_transport.sync_parts().unwrap();
        let (b_endpoint, b_gossip) = bob_transport.sync_parts().unwrap();
        let alice_joined = alice.join(a_endpoint, a_gossip).await.unwrap();
        let bob_joined = bob.join(b_endpoint, b_gossip).await.unwrap();
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if alice.projection().await.unwrap().messages.len() == 2
                    && bob.projection().await.unwrap().messages.len() == 2
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("Commons chat peers did not converge");
        assert_eq!(
            alice.projection().await.unwrap(),
            bob.projection().await.unwrap()
        );
        assert!(alice_joined.ops_received() >= 1);
        assert!(bob_joined.ops_received() >= 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn identical_signed_ciphertext_survives_native_drop_and_reticulum_tcp() {
        let (alice_keys, _) = paired_keys();
        let mut alice = ChatReplica::in_memory(SPACE, [0xa1; 32], alice_keys);
        let operation = alice
            .author(ChatEvent::Message(Message {
                channel: "general".into(),
                body: "same bytes on every carrier".into(),
                sent_at_ms: 5,
                reply_to: None,
            }))
            .await
            .unwrap();
        let canonical_record = operation_record(&operation, true);
        let canonical = encode_cbor(&canonical_record).unwrap();

        let protector =
            CabalKeyring::from_cabal_key(CabalId::new([0xd1; 32]), &CabalKey::new([0xd2; 32]));
        let mut drop_bytes = Vec::new();
        write_protected_drop(
            &mut drop_bytes,
            &[operation_record(&operation, true)],
            DropLimits::default(),
            &protector,
        )
        .unwrap();
        let (_, records) =
            read_protected_drop(Cursor::new(drop_bytes), DropLimits::default(), &protector)
                .unwrap();
        assert_eq!(records[0], canonical_record);
        let recovered = decode_operation_record::<ChatExt>(&records[0])
            .unwrap()
            .unwrap();
        assert_eq!(operation_record(&recovered, true), canonical_record);

        let server_identity = InMemoryProvider::from_seed([0xe1; 32]);
        let client_identity = InMemoryProvider::from_seed([0xe2; 32]);
        let server_peer = PeerID::from_public_key(server_identity.master_public_key());
        let server_keypair = server_identity.master_keypair();
        let client_keypair = client_identity.master_keypair();
        let addr = free_addr();
        let alpn = Alpn::new("mere/commons-operation/v1");
        let server = ReticulumTransport::builder(server_keypair)
            .alpns(vec![alpn.clone()])
            .interfaces(vec![ReticulumInterface::TcpServer { bind: addr }])
            .announce_interval(Duration::from_millis(100))
            .bind()
            .await
            .unwrap();
        let client = ReticulumTransport::builder(client_keypair)
            .alpns(vec![alpn.clone()])
            .interfaces(vec![ReticulumInterface::TcpClient { addr }])
            .announce_interval(Duration::from_millis(100))
            .connect_timeout(Duration::from_secs(10))
            .bind()
            .await
            .unwrap();
        let expected = canonical.clone();
        let accept = tokio::spawn(async move {
            let accepted = server.accept(alpn).await.unwrap();
            let mut stream = accepted.into_stream();
            let len = stream.read_u32_le().await.unwrap();
            let mut received = vec![0; len as usize];
            stream.read_exact(&mut received).await.unwrap();
            received
        });
        let mut stream = client
            .connect(server_peer, Alpn::new("mere/commons-operation/v1"))
            .await
            .unwrap();
        stream.write_u32_le(canonical.len() as u32).await.unwrap();
        stream.write_all(&canonical).await.unwrap();
        stream.flush().await.unwrap();
        let received = tokio::time::timeout(Duration::from_secs(15), accept)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, expected);
        let decoded_record: DropRecord = decode_cbor(received.as_slice()).unwrap();
        assert_eq!(decoded_record, canonical_record);
        let decoded = decode_operation_record::<ChatExt>(&decoded_record)
            .unwrap()
            .unwrap();
        assert!(decoded.header.verify());
    }
}
