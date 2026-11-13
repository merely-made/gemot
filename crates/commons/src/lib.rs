// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The commons spine: a chartulary container graph as a replicated domain.
//!
//! M3 of the Commons multi-writer convergence plan, promoted when Turnstone
//! became its first intended place consumer. A chartulary `Batch` is not a
//! p2panda `Operation`, so a graph edit needs this profile to ride a lane.
//!
//! ## The shape
//!
//! One journal batch is one signed operation. The container id is the signed
//! addressing extension, so a batch for one container cannot replay into
//! another. Each replica writes its own per-author log, which is what p2panda
//! reconciles.
//!
//! ## Why receipt does not apply edits
//!
//! The obvious `accept` closure applies each received batch to a live
//! `GraphLog` as it arrives. That does not converge. The merge rules settled
//! in M1/M2 require one deterministic fold, and a live drain delivers in
//! *arrival* order, which differs per peer.
//!
//! So receipt only **stores**, and the graph is a fold over the store in
//! causal order ([`Replica::materialize`]). Per-author backlinks plus the
//! signed observed frontier preserve happens-before across writers; the
//! canonical `(verifying_key, log_id, seq_num)` order breaks ties only between
//! concurrent records. This is the same "recorded fact versus derived state"
//! split the statement kernel brief draws: the log accumulates, the graph is
//! recomputed.

use insigne::CheckFault;
pub mod call;
pub mod chat;
pub mod encrypted;
mod keys;
pub mod parking;
pub mod pruning;

pub use keys::GroupKeys;

use portolan::{Batch, Container, GraphEdit, GraphLog, Identified, Relation, WriterId};
use insigne::DerivedKeyAttestation;
use muniment::Backend;
use muniment::Journal;
use p2panda_core::cbor::{decode_cbor_strict, encode_cbor};
use p2panda_core::operation::validate_operation;
use p2panda_core::{Body, Extensions, Hash, Header, Operation, SigningKey, Topic, VerifyingKey};
use p2panda_store::topics::TopicStore;
use personae::{IdentityError, IdentityProvider};
use serde::{Deserialize, Serialize};
use servitor::{AuthorityProvider, Cap, Mode, Subject, cap_path};
use std::collections::{BTreeMap, BTreeSet};
use stickleback::{
    Admission, CausalEntry, CausalError, CausalIndex, CausalLimits, GroupCryptoError,
    MunimentStore, OperationPolicy, OperationProcessor, PendingCausalOperation, ProcessError,
    Reject, StoreTarget, author_head, causal_projection, observed_frontier, stable_writer_subject,
    validate_causal_metadata,
};

/// One log per author. The commons has no second log class (no separate
/// checkpoint lane yet), so the log id is a constant.
pub const COMMONS_LOG: u64 = 0;

/// Desktop Commons admission bounds. Smaller carrier profiles may tighten
/// these without changing the retained operation format.
pub const COMMONS_CAUSAL_LIMITS: CausalLimits = CausalLimits {
    max_parents: 64,
    max_payload_bytes: 1024 * 1024,
};

/// One operation remains a reviewable journal turn rather than an unbounded
/// transaction.
pub const MAX_EDITS_PER_BATCH: usize = 1024;

/// The signed addressing extension: which container this batch edits.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommonsExt {
    /// The container's stable id, and the LogSync topic.
    pub container: [u8; 32],
}

/// What the shared fold reads from a graph profile's signed header.
trait GraphHeader: Extensions {
    fn container(&self) -> [u8; 32];
}

impl GraphHeader for CommonsExt {
    fn container(&self) -> [u8; 32] {
        self.container
    }
}

/// A chartulary journal batch, the unit that rides the lane.
pub type CommonsBatch = Batch<Container, Relation>;

/// One recorded commons fact.
///
/// `parents` is the exact operation frontier the writer had observed before
/// authoring this batch. Per-author backlinks still order a writer's own log;
/// these cross-author parents preserve happens-before across writers. A
/// deterministic key order is used only between records that are truly
/// concurrent.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommonsRecord {
    /// The graph edit batch.
    pub batch: CommonsBatch,
    /// Operation ids at the observed per-author frontier.
    #[serde(default)]
    pub parents: Vec<[u8; 32]>,
    /// When present, binds the per-container signing key to its stable
    /// Personae root. An absent attestation means the signer is itself the
    /// stable root.
    #[serde(default)]
    pub writer_attestation: Option<DerivedKeyAttestation>,
}

/// A malformed commons operation.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    #[error("commons operation has no body")]
    MissingBody,
    #[error("commons operation body is not a record")]
    Malformed,
}

/// Sign one journal batch into an operation on `container`'s log, at the
/// author's per-author position.
pub fn to_operation(
    signing_seed: [u8; 32],
    container: [u8; 32],
    batch: &CommonsBatch,
    parents: Vec<[u8; 32]>,
    seq_num: u32,
    backlink: Option<[u8; 32]>,
) -> Operation<CommonsExt> {
    to_operation_with_attestation(
        signing_seed,
        container,
        batch,
        parents,
        seq_num,
        backlink,
        None,
    )
}

/// Sign a batch under a derived key certified by its stable Personae root.
pub fn to_operation_with_attestation(
    signing_seed: [u8; 32],
    container: [u8; 32],
    batch: &CommonsBatch,
    parents: Vec<[u8; 32]>,
    seq_num: u32,
    backlink: Option<[u8; 32]>,
    writer_attestation: Option<DerivedKeyAttestation>,
) -> Operation<CommonsExt> {
    let signing_key = SigningKey::from_bytes(&signing_seed);
    let record = CommonsRecord {
        batch: batch.clone(),
        parents,
        writer_attestation,
    };
    let body_bytes = encode_cbor(&record).expect("a commons record always CBOR-encodes");
    let body = Body::from_bytes(&body_bytes);
    // p2panda 0.7.1 made the header's CBOR cache, size and digest private
    // and folded signing into the builder: `build` encodes, signs and
    // caches the digest in one step, so the struct-literal + `sign` pair
    // has no equivalent. `body` sets payload_size and payload_hash.
    let header = Header::builder()
        .body(&body_bytes)
        .seq_num(seq_num)
        .backlink(backlink.map(Hash::from))
        .build(&signing_key, CommonsExt { container });
    let hash = header.hash();
    Operation {
        hash,
        header,
        body: Some(body),
    }
}

/// Domain-separated salt used for one container's derived signing key.
pub fn commons_identity_salt(container: [u8; 32]) -> Vec<u8> {
    let mut salt = Vec::with_capacity(65);
    salt.extend_from_slice(b"mere.commons.writer.v1/");
    salt.extend_from_slice(&container);
    salt
}

fn stable_subject<E: GraphHeader>(
    operation: &Operation<E>,
    record: &CommonsRecord,
) -> Result<[u8; 32], Reject> {
    stable_writer_subject(
        *operation.header.verifying_key.as_bytes(),
        record.writer_attestation.as_ref(),
        &commons_identity_salt(operation.header.extensions.container()),
    )
    .map_err(|error| Reject::new(error.code(), error.to_string()))
}

/// The shared-graph sync-lane kind, combined with the container id through
/// `stickleback::lane_id`. Distinct from [`chat::COMMONS_CHAT_LANE`] because
/// the two replicas are separate LogSync sessions on one endpoint, and the
/// endpoint routes inbound sync by exactly this identifier.
pub const COMMONS_GRAPH_LANE: &str = "commons/graph/v1";

/// Typed write capability implied by every batch for one container.
pub fn commons_write_capability(container: [u8; 32]) -> Cap {
    let hex: String = container.iter().map(|byte| format!("{byte:02x}")).collect();
    Cap::scope(&format!("commons/container/{hex}"))
        .expect("a fixed prefix plus lowercase hex is a valid scope")
}

/// Decode the record carried by an operation. Does not check the signature.
pub fn from_operation(op: &Operation<CommonsExt>) -> Result<CommonsRecord, WireError> {
    let body = op.body.as_ref().ok_or(WireError::MissingBody)?;
    decode_cbor_strict(body.to_bytes().as_slice()).map_err(|_| WireError::Malformed)
}

/// Admission for the commons lane: the operation must address this container,
/// carry a decodable record, be validly signed, and mint edges only under the
/// signer identity.
///
/// Deliberately thin. Membership and capability are the moot's and personae's
/// jobs; this probe proves convergence, not authority.
struct CommonsPolicy {
    container: [u8; 32],
}

impl OperationPolicy<CommonsExt> for CommonsPolicy {
    type LogId = u64;

    fn admit(&self, operation: &Operation<CommonsExt>) -> Result<Admission<Self::LogId>, Reject> {
        if operation.header.extensions.container != self.container {
            return Err(Reject::new(
                "wrong-container",
                "operation addresses a different container",
            ));
        }
        // The signature itself is already guaranteed: p2panda 0.7.1 verifies it
        // inside `Header::decode` and made `Header::verify` test-only, so an
        // `Operation` reaching here was decoded (verified) or locally signed.
        // The body commitment and log rules still need checking.
        if validate_operation(operation).is_err() || operation.hash != operation.header.hash() {
            return Err(Reject::new(
                "bad-operation",
                "operation header or body commitment is invalid",
            ));
        }
        let record = from_operation(operation)
            .map_err(|err| Reject::new("invalid-commons-batch", err.to_string()))?;
        validate_causal_metadata(operation, &record.parents, COMMONS_CAUSAL_LIMITS)
            .map_err(|err| Reject::new("invalid-commons-causality", err.to_string()))?;
        check_batch(operation, &record)?;
        Ok(Admission::keep(StoreTarget::new(
            Topic::from(self.container),
            COMMONS_LOG,
        )))
    }
}

/// A failure while folding the store back into a graph.
#[derive(Debug, thiserror::Error)]
pub enum MaterializeError {
    #[error(transparent)]
    Store(#[from] muniment::StoreError),
    #[error(transparent)]
    Wire(#[from] WireError),
    #[error(transparent)]
    Causal(#[from] CausalError),
    #[error("stored commons operation has an invalid writer binding: {0}")]
    WriterBinding(String),
    #[error("stored encrypted commons operation: {0}")]
    Encrypted(Reject),
}

#[derive(Clone)]
struct StoredRecord<E = CommonsExt> {
    operation: Operation<E>,
    record: CommonsRecord,
    log_id: u64,
}

/// Which effective records remove each node identity.
///
/// Built once per fold and shared by every batch. Rediscovering it per insert
/// edit meant rescanning every record for every edit, which is where the fold's
/// quadratic term came from.
type RemovalIndex<'a> = BTreeMap<&'a <Container as Identified>::Id, Vec<usize>>;

/// Validate and store one operation against `container`'s policy.
///
/// Free-standing so a joined space's `accept` closure can capture a cloned
/// store rather than the whole replica.
pub async fn accept_into<B: Backend + Clone + Send + Sync + 'static>(
    store: &MunimentStore<B, CommonsExt>,
    container: [u8; 32],
    op: &Operation<CommonsExt>,
) -> Result<bool, stickleback::ProcessError> {
    let processor = OperationProcessor::new(store.clone(), CommonsPolicy { container });
    processor.preflight(op)?;
    let record =
        from_operation(op).map_err(|err| Reject::new("invalid-commons-batch", err.to_string()))?;
    validate_counter_frontier(store, op, &record, |stored| {
        from_operation(stored)
            .map_err(|err| Reject::new("invalid-stored-commons-batch", err.to_string()))
    })
    .await?;
    Ok(processor.process(op).await?.inserted())
}

/// Fold every stored batch for `container` into a graph in causal order.
///
/// Two replicas holding the same operations produce the same graph, which is
/// the convergence claim. Per-author backlinks and signed cross-author
/// parents preserve happens-before; the canonical author/log/sequence tuple
/// orders only concurrent ready records.
/// One current graph plus retained operations whose causal history is
/// incomplete.
pub struct CommonsProjection {
    pub graph: GraphLog<Container, Relation>,
    pub pending: Vec<PendingCausalOperation>,
    pub pending_authority: Vec<AuthorityOperation>,
    pub revoked: Vec<AuthorityOperation>,
}

/// One retained operation classified by converged authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityOperation {
    pub operation: [u8; 32],
    pub subject: [u8; 32],
    pub capability: Cap,
}

/// Effective-state classification over retained authority facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityState {
    Effective,
    Pending,
    Revoked,
}

/// Read boundary supplied by Gemot/Personae authority materialization.
pub trait CommonsAuthority {
    fn classify(&self, subject: Subject, capability: &Cap, mode: Mode) -> AuthorityState;
}

/// Adapter for the existing typed Servitor authority seam plus Gemot's
/// converged directly-revoked subject set.
pub struct ServitorAuthorityView<'a, A> {
    pub provider: &'a A,
    pub revoked_subjects: &'a BTreeSet<[u8; 32]>,
}

/// Adapter from Gemot's converged delegation fold to the Commons capability
/// query. The adapter receives only retained authority facts and a host-set
/// evaluation time: session, relay, and transport identity never enter this
/// decision.
pub struct GemotAuthorityView<'a> {
    pub authority: gemot::moot::MootAuthority<'a>,
}

impl CommonsAuthority for GemotAuthorityView<'_> {
    fn classify(&self, subject: Subject, capability: &Cap, mode: Mode) -> AuthorityState {
        if self.authority.covers(subject, capability, mode) {
            return AuthorityState::Effective;
        }

        let needed = cap_path(capability);
        let withdrawn_current_grant = self
            .authority
            .delegations
            .projections(
                self.authority.moot_id,
                self.authority.rules,
                self.authority.now_ms,
            )
            .into_iter()
            .any(|grant| {
                grant.subject == subject.0
                    && grant.not_before_ms <= self.authority.now_ms
                    && grant
                        .expires_at_ms
                        .is_none_or(|expires| self.authority.now_ms <= expires)
                    && !grant.active
                    && path_covers(&grant.path_prefix, &needed)
            });

        if withdrawn_current_grant {
            AuthorityState::Revoked
        } else {
            AuthorityState::Pending
        }
    }
}

/// Match a capability path at a segment boundary. A narrower delegation does
/// not authorize its parent and an unrelated prefix cannot collide by text.
fn path_covers(prefix: &str, path: &str) -> bool {
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

impl<A: AuthorityProvider> CommonsAuthority for ServitorAuthorityView<'_, A> {
    fn classify(&self, subject: Subject, capability: &Cap, mode: Mode) -> AuthorityState {
        if self.revoked_subjects.contains(&subject.0) {
            AuthorityState::Revoked
        } else if self.provider.covers(subject, capability, mode) {
            AuthorityState::Effective
        } else {
            AuthorityState::Pending
        }
    }
}

struct AllowAllAuthority;

impl CommonsAuthority for AllowAllAuthority {
    fn classify(&self, _subject: Subject, _capability: &Cap, _mode: Mode) -> AuthorityState {
        AuthorityState::Effective
    }
}

/// A local authoring failure.
#[derive(Debug, thiserror::Error)]
pub enum ReplicaError {
    #[error(transparent)]
    Materialize(#[from] MaterializeError),
    #[error(transparent)]
    Process(#[from] ProcessError),
    #[error("local authoring is blocked by {0} operations with missing causal history")]
    PendingHistory(usize),
    #[error("one authoring turn must append exactly one batch, appended {0}")]
    BatchCount(usize),
    #[error(transparent)]
    Crypto(#[from] GroupCryptoError),
}

/// One authoring turn's batch and its place in the causal history.
struct AuthoredBatch {
    batch: CommonsBatch,
    parents: Vec<[u8; 32]>,
    seq_num: u32,
    backlink: Option<[u8; 32]>,
}

/// Replay the stored history for `writer`, apply `edit`, and take the single
/// batch it appended, positioned after `author`'s log head.
fn author_batch<E: GraphHeader>(
    records: &[StoredRecord<E>],
    writer: WriterId,
    author: [u8; 32],
    edit: impl FnOnce(&mut GraphLog<Container, Relation>),
) -> Result<AuthoredBatch, ReplicaError> {
    let entries = causal_entries(records);
    let parents = observed_frontier(&entries).map_err(MaterializeError::from)?;
    let (journal, pending) = causal_journal(records)?;
    if !pending.is_empty() {
        return Err(ReplicaError::PendingHistory(pending.len()));
    }
    let mut shared = GraphLog::replay_for_writer(journal, writer);
    let before = shared.log().entries().len();
    edit(&mut shared);
    let appended = shared.log().entries().len().saturating_sub(before);
    if appended != 1 {
        return Err(ReplicaError::BatchCount(appended));
    }
    let batch = shared
        .log()
        .entries()
        .get(before)
        .expect("an edit appends exactly one batch")
        .clone();
    let (seq_num, backlink) =
        author_head(&entries, author, &COMMONS_LOG).map_err(MaterializeError::from)?;
    Ok(AuthoredBatch {
        batch,
        parents,
        seq_num,
        backlink,
    })
}

/// The container's derived writer key, its seed, and the root attestation.
fn derived_writer<P: IdentityProvider + ?Sized>(
    identity: &P,
    container: [u8; 32],
) -> Result<(WriterId, [u8; 32], DerivedKeyAttestation), ReplicaIdentityError> {
    let salt = commons_identity_salt(container);
    let keypair = identity.derive_keypair(&salt)?;
    let writer_attestation = identity.attest_derived_key(&salt)?;
    let checked = writer_attestation
        .check(&salt)
        .map_err(ReplicaIdentityError::InvalidAttestation)?;
    let writer = WriterId(keypair.public_key().to_bytes());
    if *checked.derived() != writer.0 {
        return Err(ReplicaIdentityError::WriterMismatch);
    }
    Ok((writer, keypair.to_seed(), writer_attestation))
}

/// Failure to bind a Commons replica to its stable Personae identity.
#[derive(Debug, thiserror::Error)]
pub enum ReplicaIdentityError {
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error("identity provider returned an invalid Commons writer attestation: {0}")]
    InvalidAttestation(CheckFault),
    #[error("identity provider attested a different Commons writer")]
    WriterMismatch,
}

/// One member's replica of one shared container.
pub struct Replica<B: Backend + Clone + Send + Sync + 'static> {
    store: MunimentStore<B, CommonsExt>,
    container: [u8; 32],
    writer: WriterId,
    signing_seed: [u8; 32],
    writer_attestation: Option<DerivedKeyAttestation>,
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

#[path = "replica.rs"]
mod replica;

#[path = "projection.rs"]
mod projection;

pub use projection::{materialize, materialize_projection, materialize_with_authority};

use projection::{
    causal_entries, causal_journal, check_batch, fold_with_authority, load_operations,
    load_plaintext_records, load_records, validate_counter_frontier,
};
