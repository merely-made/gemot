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

pub mod call;
pub mod chat;

use chartulary::{Batch, Container, GraphEdit, GraphLog, Relation, WriterId};
use codicil::Codicil;
use muniment::Backend;
use p2panda_core::cbor::{decode_cbor, encode_cbor};
use p2panda_core::{Body, Hash, Header, Operation, SigningKey, Topic, VerifyingKey};
use p2panda_store::logs::LogStore;
use p2panda_store::topics::TopicStore;
use personae::{DerivedKeyAttestation, IdentityError, IdentityProvider};
use serde::{Deserialize, Serialize};
use servitor::{AuthorityProvider, Cap, Mode, Subject, cap_path};
use std::collections::{BTreeMap, BTreeSet};
use stickleback::{
    Admission, CausalEntry, CausalError, CausalLimits, MunimentStore, OperationPolicy,
    OperationProcessor, PendingCausalOperation, ProcessError, Reject, StoreTarget, author_head,
    causal_projection, happens_before, observed_frontier, stable_writer_subject,
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
    let body = Body::new(&body_bytes);
    let mut header = Header {
        version: 1,
        verifying_key: signing_key.verifying_key(),
        signature: None,
        payload_size: body.size(),
        payload_hash: Some(body.hash()),
        seq_num,
        backlink: backlink.map(Hash::from),
        extensions: CommonsExt { container },
    };
    header.sign(&signing_key);
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

fn stable_subject(
    operation: &Operation<CommonsExt>,
    record: &CommonsRecord,
) -> Result<[u8; 32], Reject> {
    stable_writer_subject(
        *operation.header.verifying_key.as_bytes(),
        record.writer_attestation.as_ref(),
        &commons_identity_salt(operation.header.extensions.container),
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
    decode_cbor(body.to_bytes().as_slice()).map_err(|_| WireError::Malformed)
}

fn record_connect_counters(record: &CommonsRecord, writer: WriterId) -> Result<Vec<u64>, Reject> {
    let mut counters = Vec::new();
    for edit in &record.batch.edits {
        if let GraphEdit::Connect { id, .. } = edit {
            if id.writer != writer {
                return Err(Reject::new(
                    "edge-writer-mismatch",
                    "a connect id is not scoped to the operation signer",
                ));
            }
            counters.push(id.counter);
        }
    }
    if counters
        .windows(2)
        .any(|pair| pair[0].checked_add(1) != Some(pair[1]))
    {
        return Err(Reject::new(
            "edge-counter-sequence",
            "connect counters inside one batch are not contiguous",
        ));
    }
    Ok(counters)
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
        if !operation.header.verify() {
            return Err(Reject::new(
                "bad-signature",
                "operation signature is invalid",
            ));
        }
        let record = from_operation(operation)
            .map_err(|err| Reject::new("invalid-commons-batch", err.to_string()))?;
        validate_causal_metadata(operation, &record.parents, COMMONS_CAUSAL_LIMITS)
            .map_err(|err| Reject::new("invalid-commons-causality", err.to_string()))?;
        if record.batch.edits.len() > MAX_EDITS_PER_BATCH {
            return Err(Reject::new(
                "commons-edit-limit",
                format!(
                    "batch contains {} edits; maximum is {MAX_EDITS_PER_BATCH}",
                    record.batch.edits.len()
                ),
            ));
        }
        stable_subject(operation, &record)?;
        let writer = WriterId(*operation.header.verifying_key.as_bytes());
        record_connect_counters(&record, writer)?;
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
}

#[derive(Clone)]
struct StoredRecord {
    operation: Operation<CommonsExt>,
    record: CommonsRecord,
    log_id: u64,
}

async fn load_records<B: Backend + Clone + Send + Sync + 'static>(
    store: &MunimentStore<B, CommonsExt>,
    container: [u8; 32],
) -> Result<Vec<StoredRecord>, MaterializeError> {
    let by_author: BTreeMap<VerifyingKey, Vec<u64>> =
        TopicStore::<Topic, VerifyingKey, u64>::resolve(store, &Topic::from(container)).await?;
    let mut records = Vec::new();
    for (author, mut logs) in by_author {
        logs.sort_unstable();
        logs.dedup();
        for log_id in logs {
            let entries =
                LogStore::<Operation<CommonsExt>, VerifyingKey, u64, u32, Hash>::get_log_entries(
                    store, &author, &log_id, None, None,
                )
                .await?
                .unwrap_or_default();
            // The tuple's second element is encoded header bytes, not the
            // payload. The signed record is reconstructed from `operation.body`.
            for (operation, _header_bytes) in entries {
                let record = from_operation(&operation)?;
                records.push(StoredRecord {
                    operation,
                    record,
                    log_id,
                });
            }
        }
    }
    Ok(records)
}

fn causal_entries(records: &[StoredRecord]) -> Vec<CausalEntry<u64>> {
    records
        .iter()
        .map(|record| {
            CausalEntry::from_operation(
                &record.operation,
                record.log_id,
                record.record.parents.clone(),
            )
        })
        .collect()
}

fn causal_journal(
    records: &[StoredRecord],
) -> Result<(Codicil<CommonsBatch>, Vec<PendingCausalOperation>), MaterializeError> {
    let entries = causal_entries(records);
    let projection = causal_projection(&entries)?;
    let effective: BTreeSet<_> = projection.order.iter().copied().collect();
    let mut journal = Codicil::new();
    for index in projection.order {
        journal.append(remove_wins_batch(records, &entries, &effective, index));
    }
    Ok((journal, projection.pending))
}

/// Suppress only inserts concurrent with a removal of the same identity.
/// Causally later inserts remain deliberate recreation.
fn remove_wins_batch(
    records: &[StoredRecord],
    entries: &[CausalEntry<u64>],
    effective: &BTreeSet<usize>,
    index: usize,
) -> CommonsBatch {
    let operation = entries[index].operation;
    let mut batch = records[index].record.batch.clone();
    batch.edits.retain(|edit| {
        let GraphEdit::InsertNode(node) = edit else {
            return true;
        };
        !records.iter().enumerate().any(|(other_index, other)| {
            if other_index == index || !effective.contains(&other_index) {
                return false;
            }
            let removes_same_node =
                other.record.batch.edits.iter().any(
                    |candidate| matches!(candidate, GraphEdit::RemoveNode(id) if id == &node.id),
                );
            if !removes_same_node {
                return false;
            }
            let removal = entries[other_index].operation;
            !happens_before(entries, removal, operation)
                && !happens_before(entries, operation, removal)
        })
    });
    batch
}

async fn validate_counter_frontier<B: Backend + Clone + Send + Sync + 'static>(
    store: &MunimentStore<B, CommonsExt>,
    operation: &Operation<CommonsExt>,
    record: &CommonsRecord,
) -> Result<(), ProcessError> {
    if store.has_operation(&operation.hash).await? {
        return Ok(());
    }
    let writer = WriterId(*operation.header.verifying_key.as_bytes());
    let counters = record_connect_counters(record, writer)?;
    if counters.is_empty() {
        return Ok(());
    }

    let entries = LogStore::<Operation<CommonsExt>, VerifyingKey, u64, u32, Hash>::get_log_entries(
        store,
        &operation.header.verifying_key,
        &COMMONS_LOG,
        None,
        None,
    )
    .await?
    .unwrap_or_default();
    let mut next = 0u64;
    for (stored, _header_bytes) in entries {
        let stored_record = from_operation(&stored)
            .map_err(|err| Reject::new("invalid-stored-commons-batch", err.to_string()))?;
        for counter in record_connect_counters(&stored_record, writer)? {
            next = next.max(counter.saturating_add(1));
        }
    }
    for counter in counters {
        if counter != next {
            return Err(Reject::new(
                "edge-counter-frontier",
                format!("connect counter {counter} does not continue frontier {next}"),
            )
            .into());
        }
        next = next
            .checked_add(1)
            .ok_or_else(|| Reject::new("edge-counter-exhausted", "edge counter exhausted"))?;
    }
    Ok(())
}

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
    validate_counter_frontier(store, op, &record).await?;
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

/// Fold the causally and authoritatively effective subset.
pub async fn materialize_with_authority<
    B: Backend + Clone + Send + Sync + 'static,
    A: CommonsAuthority,
>(
    store: &MunimentStore<B, CommonsExt>,
    container: [u8; 32],
    authority: &A,
) -> Result<CommonsProjection, MaterializeError> {
    let records = load_records(store, container).await?;
    let entries = causal_entries(&records);
    let causal = causal_projection(&entries)?;
    let capability = commons_write_capability(container);
    let mut journal = Codicil::new();
    let mut effective = Vec::new();
    let mut pending_authority = Vec::new();
    let mut revoked = Vec::new();
    for index in causal.order {
        let record = &records[index];
        let subject = stable_subject(&record.operation, &record.record)
            .map_err(|error| MaterializeError::WriterBinding(error.to_string()))?;
        let classified = AuthorityOperation {
            operation: *record.operation.hash.as_bytes(),
            subject,
            capability: capability.clone(),
        };
        match authority.classify(Subject(subject), &capability, Mode::Write) {
            AuthorityState::Effective => effective.push(index),
            AuthorityState::Pending => pending_authority.push(classified),
            AuthorityState::Revoked => revoked.push(classified),
        }
    }
    let effective_set: BTreeSet<_> = effective.iter().copied().collect();
    for index in effective {
        journal.append(remove_wins_batch(&records, &entries, &effective_set, index));
    }
    Ok(CommonsProjection {
        graph: GraphLog::replay(journal),
        pending: causal.pending,
        pending_authority,
        revoked,
    })
}

/// Fold the causally closed subset with structural admission as the authority
/// floor. Communal callers should prefer [`materialize_with_authority`].
pub async fn materialize_projection<B: Backend + Clone + Send + Sync + 'static>(
    store: &MunimentStore<B, CommonsExt>,
    container: [u8; 32],
) -> Result<CommonsProjection, MaterializeError> {
    materialize_with_authority(store, container, &AllowAllAuthority).await
}

/// Compatibility view for callers that only need the current graph.
pub async fn materialize<B: Backend + Clone + Send + Sync + 'static>(
    store: &MunimentStore<B, CommonsExt>,
    container: [u8; 32],
) -> Result<GraphLog<Container, Relation>, MaterializeError> {
    Ok(materialize_projection(store, container).await?.graph)
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
}

/// Failure to bind a Commons replica to its stable Personae identity.
#[derive(Debug, thiserror::Error)]
pub enum ReplicaIdentityError {
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error("identity provider returned an invalid Commons writer attestation")]
    InvalidAttestation,
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

impl<B: Backend + Clone + Send + Sync + 'static> Replica<B> {
    /// A replica writing directly under `signing_seed`, whose verifying key is
    /// both the stable authority subject and the chartulary `WriterId` that
    /// scopes minted edge ids.
    ///
    /// Product hosts with a Personae identity should use [`Self::for_identity`]
    /// so the wire record carries the root binding.
    pub fn new(backend: B, container: [u8; 32], signing_seed: [u8; 32]) -> Self {
        let writer = WriterId(
            *SigningKey::from_bytes(&signing_seed)
                .verifying_key()
                .as_bytes(),
        );
        Self {
            store: MunimentStore::new(backend),
            container,
            writer,
            signing_seed,
            writer_attestation: None,
        }
    }

    /// A replica writing under this container's derived Personae key.
    ///
    /// The master secret remains behind `identity`. Each authored operation
    /// carries the master-signed attestation, so authority is evaluated against
    /// the stable Personae root while edge ids remain scoped to the derived
    /// writer key.
    pub fn for_identity<P: IdentityProvider + ?Sized>(
        backend: B,
        container: [u8; 32],
        identity: &P,
    ) -> Result<Self, ReplicaIdentityError> {
        let salt = commons_identity_salt(container);
        let keypair = identity.derive_keypair(&salt)?;
        let writer_attestation = identity.attest_derived_key(&salt)?;
        if !writer_attestation.verify(&salt) {
            return Err(ReplicaIdentityError::InvalidAttestation);
        }
        let writer = WriterId(keypair.public_key().to_bytes());
        if writer_attestation
            .derived_public_key()
            .map_err(|_| ReplicaIdentityError::InvalidAttestation)?
            .to_bytes()
            != writer.0
        {
            return Err(ReplicaIdentityError::WriterMismatch);
        }
        Ok(Self {
            store: MunimentStore::new(backend),
            container,
            writer,
            signing_seed: keypair.to_seed(),
            writer_attestation: Some(writer_attestation),
        })
    }

    /// The store, for `JoinedSpace::join`.
    pub fn sync_store(&self) -> MunimentStore<B, CommonsExt> {
        self.store.clone()
    }

    /// Join this container's live lane, draining received operations through
    /// the same structural admission local authoring uses. The counterpart to
    /// [`chat::ChatReplica::join`], so a host holds handles instead of
    /// assembling p2panda sessions.
    pub async fn join(
        &self,
        endpoint: p2panda_net::Endpoint,
        gossip: p2panda_net::Gossip,
    ) -> Result<stickleback::JoinedSpace<CommonsExt>, stickleback::JoinError> {
        let accept_store = self.store.clone();
        let container = self.container;
        stickleback::JoinedSpace::join::<_, u64, _, _>(
            stickleback::lane_id(COMMONS_GRAPH_LANE, container),
            self.sync_store(),
            endpoint,
            gossip,
            container,
            move |operation: Operation<CommonsExt>| {
                let store = accept_store.clone();
                async move {
                    accept_into(&store, container, &operation)
                        .await
                        .unwrap_or(false)
                }
            },
        )
        .await
    }

    /// This replica's writer identity.
    pub fn writer(&self) -> WriterId {
        self.writer
    }

    /// Edit the current shared projection, sign the resulting batch, and store
    /// it. Returns the operation so a caller can publish it on a live lane.
    ///
    /// The graph and both authoring frontiers are reconstructed from the store
    /// on every turn. That makes a peer's synced nodes and edges editable and
    /// makes restart resume both the p2panda log and the writer-scoped edge
    /// counter instead of returning either to zero.
    pub async fn edit(
        &mut self,
        edit: impl FnOnce(&mut GraphLog<Container, Relation>),
    ) -> Result<Operation<CommonsExt>, ReplicaError> {
        let records = load_records(&self.store, self.container).await?;
        let entries = causal_entries(&records);
        let parents = observed_frontier(&entries).map_err(MaterializeError::from)?;
        let (journal, pending) = causal_journal(&records)?;
        if !pending.is_empty() {
            return Err(ReplicaError::PendingHistory(pending.len()));
        }
        let mut shared = GraphLog::replay_for_writer(journal, self.writer);
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

        let signing_key = SigningKey::from_bytes(&self.signing_seed);
        let (seq, backlink) = author_head(
            &entries,
            *signing_key.verifying_key().as_bytes(),
            &COMMONS_LOG,
        )
        .map_err(MaterializeError::from)?;
        let op = to_operation_with_attestation(
            self.signing_seed,
            self.container,
            &batch,
            parents,
            seq,
            backlink,
            self.writer_attestation.clone(),
        );
        self.accept(&op).await?;
        Ok(op)
    }

    /// Validate and store one operation. The `accept` closure a joined space
    /// drains into. Storing only: the graph is a fold, see the module docs.
    pub async fn accept(
        &self,
        op: &Operation<CommonsExt>,
    ) -> Result<bool, stickleback::ProcessError> {
        accept_into(&self.store, self.container, op).await
    }

    /// This replica's view of the container: see [`materialize`].
    pub async fn materialize(&self) -> Result<GraphLog<Container, Relation>, MaterializeError> {
        materialize(&self.store, self.container).await
    }

    /// Current graph plus operations waiting on unavailable causal parents.
    pub async fn projection(&self) -> Result<CommonsProjection, MaterializeError> {
        materialize_projection(&self.store, self.container).await
    }

    /// Current graph classified by the caller's converged authority view.
    /// Product ports must use this for communal projection; the authority view
    /// receives retained Personae/Gemot facts, never relay or session identity.
    pub async fn projection_with_authority<A: CommonsAuthority>(
        &self,
        authority: &A,
    ) -> Result<CommonsProjection, MaterializeError> {
        materialize_with_authority(&self.store, self.container, authority).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chartulary::taxonomy::{Recognized, RelationClass};
    use chartulary::{Author, EdgeId, FacetId};
    use gemot::moot::constitution::{CapabilityGrant, ConstitutionRules};
    use gemot::moot::{MOOT_ACT_ACTION, MOOT_DELEGATION_DOMAIN, MootAuthority, MootDelegations};
    use muniment::{MemoryBackend, RedbBackend};
    use personae::delegation::{
        CapabilityScope, DelegationCertificate, DelegationParent, DelegationRevocation,
        SignedDelegationCertificate, SignedDelegationRevocation,
    };
    use personae::{IdentityProvider, InMemoryProvider};
    use proptest::prelude::*;
    use serde_json::json;
    use std::sync::Arc;
    use std::time::Duration;
    use stickleback::JoinedSpace;
    use transport::{P2pandaTransport, PeerID, sync_overlay_topic};

    const CONTAINER: [u8; 32] = [0xc0; 32];
    const MOOT: [u8; 32] = [0x6d; 32];
    const ROOT_GRANT: [u8; 32] = [0x67; 32];
    const AUTHORITY_NOW_MS: u64 = 50;

    fn cites() -> Relation {
        Relation::new(RelationClass::recognized(Recognized::Cites))
    }

    fn gemot_rules(root: &InMemoryProvider, path_prefix: String) -> ConstitutionRules {
        let mut rules = ConstitutionRules::founder_only(root.master_public_key().to_bytes());
        rules.grant(CapabilityGrant {
            id: ROOT_GRANT,
            subject: root.master_public_key().to_bytes(),
            path_prefix,
            not_before_ms: 10,
            expires_at_ms: Some(1_000),
            delegation_depth: 2,
        });
        rules
    }

    fn issue_gemot_delegation(
        root: &InMemoryProvider,
        writer: &InMemoryProvider,
        path_prefix: String,
        expires_at_ms: Option<u64>,
        nonce: u8,
    ) -> SignedDelegationCertificate {
        SignedDelegationCertificate::issue(
            root,
            DelegationCertificate::new(
                DelegationParent::Root(ROOT_GRANT),
                root.master_public_key().to_bytes(),
                writer.master_public_key().to_bytes(),
                CapabilityScope {
                    domain: MOOT_DELEGATION_DOMAIN.into(),
                    resource: MOOT.to_vec(),
                    path_prefix,
                    actions: [MOOT_ACT_ACTION.to_string()].into_iter().collect(),
                },
                15,
                20,
                expires_at_ms,
                0,
                [nonce; 32],
            ),
        )
        .expect("test delegation signs")
    }

    fn gemot_authority<'a>(
        delegations: &'a MootDelegations,
        rules: &'a ConstitutionRules,
    ) -> GemotAuthorityView<'a> {
        GemotAuthorityView {
            authority: MootAuthority {
                delegations,
                rules,
                moot_id: MOOT,
                now_ms: AUTHORITY_NOW_MS,
            },
        }
    }

    type Fingerprint = (
        Vec<(String, String, Vec<String>)>,
        Vec<(String, String, String)>,
    );

    fn fingerprint(log: &GraphLog<Container, Relation>) -> Fingerprint {
        let graph = log.graph();
        let mut nodes = Vec::new();
        let mut edges = Vec::new();
        for (key, node) in graph.nodes() {
            let mut tags: Vec<_> = node.tags.iter().cloned().collect();
            tags.sort();
            nodes.push((node.id.clone(), node.title.clone(), tags));
            for (_, target, edge) in graph.out_edges(key) {
                edges.push((
                    node.id.clone(),
                    graph.node(target).expect("target present").id.clone(),
                    format!("{:?}", edge.class),
                ));
            }
        }
        nodes.sort();
        edges.sort();
        (nodes, edges)
    }

    fn connect_id(operation: &Operation<CommonsExt>) -> Option<EdgeId> {
        from_operation(operation)
            .ok()?
            .batch
            .edits
            .iter()
            .find_map(|edit| match edit {
                GraphEdit::Connect { id, .. } => Some(*id),
                _ => None,
            })
    }

    struct FixedAuthority {
        subject: [u8; 32],
        state: AuthorityState,
    }

    impl CommonsAuthority for FixedAuthority {
        fn classify(&self, subject: Subject, capability: &Cap, mode: Mode) -> AuthorityState {
            assert_eq!(subject.0, self.subject);
            assert_eq!(capability, &commons_write_capability(CONTAINER));
            assert_eq!(mode, Mode::Write);
            self.state
        }
    }

    /// Two bound transports tagged with each other on the container's overlay
    /// topic (the two-peer bootstrap mesh and gemot already use).
    async fn two_peers() -> (P2pandaTransport, P2pandaTransport) {
        let alice_provider = Arc::new(InMemoryProvider::from_seed([90; 32]));
        let bob_provider = Arc::new(InMemoryProvider::from_seed([91; 32]));
        let alice_id = PeerID::from_public_key(alice_provider.master_public_key());
        let bob_id = PeerID::from_public_key(bob_provider.master_public_key());

        let alice = P2pandaTransport::builder(alice_provider.master_keypair())
            .gossip()
            .bind()
            .await
            .expect("bind alice");
        let bob = P2pandaTransport::builder(bob_provider.master_keypair())
            .gossip()
            .bind()
            .await
            .expect("bind bob");

        let overlay = sync_overlay_topic(CONTAINER);
        alice
            .add_peer(bob.endpoint_addr().await.unwrap())
            .await
            .unwrap();
        alice.set_topics(bob_id, &[overlay]).await.unwrap();
        bob.add_peer(alice.endpoint_addr().await.unwrap())
            .await
            .unwrap();
        bob.set_topics(alice_id, &[overlay]).await.unwrap();
        (alice, bob)
    }

    /// M3: two members edit one container **while partitioned**, then
    /// reconverge over real LogSync reconciliation.
    ///
    /// This is the first time the M1/M2 merge rules are exercised over a lane
    /// rather than a hand-built journal. Both members mint an edge before they
    /// can see each other, which is exactly the case that collided before
    /// `EdgeId` became `(writer, counter)`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_partitioned_members_converge_on_one_container() {
        let (alice_t, bob_t) = two_peers().await;

        let mut alice = Replica::new(MemoryBackend::new(), CONTAINER, [90; 32]);
        let mut bob = Replica::new(MemoryBackend::new(), CONTAINER, [91; 32]);
        assert_ne!(
            alice.writer(),
            bob.writer(),
            "each replica writes under its own identity"
        );

        // ── Partitioned: neither has joined a space yet, so neither can see
        // the other's edits. Both insert a pair and connect it. ──
        let author = Author::new("ui");
        let a_edge = {
            let a = author.clone();
            let mut minted = None;
            alice
                .edit(|g| {
                    g.insert_node(&a, Container::new("alice-1"));
                })
                .await
                .expect("alice inserts");
            alice
                .edit(|g| {
                    g.insert_node(&a, Container::new("alice-2"));
                })
                .await
                .expect("alice inserts");
            alice
                .edit(|g| {
                    minted = g.connect(&a, &"alice-1".to_string(), &"alice-2".to_string(), cites());
                })
                .await
                .expect("alice connects");
            minted.expect("alice minted an edge")
        };

        let b_edge = {
            let a = author.clone();
            let mut minted = None;
            bob.edit(|g| {
                g.insert_node(&a, Container::new("bob-1"));
            })
            .await
            .expect("bob inserts");
            bob.edit(|g| {
                g.insert_node(&a, Container::new("bob-2"));
            })
            .await
            .expect("bob inserts");
            bob.edit(|g| {
                minted = g.connect(&a, &"bob-1".to_string(), &"bob-2".to_string(), cites());
            })
            .await
            .expect("bob connects");
            minted.expect("bob minted an edge")
        };

        assert_eq!(a_edge.counter, 0, "alice minted counter 0");
        assert_eq!(b_edge.counter, 0, "bob minted counter 0");
        assert_ne!(
            a_edge, b_edge,
            "and the ids still differ, because the writer half separates them"
        );

        // ── Reconnect: join the space on both sides and let LogSync reconcile. ──
        let (a_ep, a_gossip) = alice_t.sync_parts().expect("alice sync parts");
        let a_store = alice.sync_store();
        let alice_space = JoinedSpace::join::<_, u64, _, _>(
            stickleback::lane_id(COMMONS_GRAPH_LANE, CONTAINER),
            alice.sync_store(),
            a_ep,
            a_gossip,
            CONTAINER,
            move |op| {
                let store = a_store.clone();
                async move { accept_into(&store, CONTAINER, &op).await.unwrap_or(false) }
            },
        )
        .await
        .expect("alice joins");

        let (b_ep, b_gossip) = bob_t.sync_parts().expect("bob sync parts");
        let b_store = bob.sync_store();
        let bob_space = JoinedSpace::join::<_, u64, _, _>(
            stickleback::lane_id(COMMONS_GRAPH_LANE, CONTAINER),
            bob.sync_store(),
            b_ep,
            b_gossip,
            CONTAINER,
            move |op| {
                let store = b_store.clone();
                async move { accept_into(&store, CONTAINER, &op).await.unwrap_or(false) }
            },
        )
        .await
        .expect("bob joins");

        // ── Converge: both graphs hold all four nodes and both edges. ──
        let converged = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let a = alice.materialize().await.unwrap();
                let b = bob.materialize().await.unwrap();
                if a.graph().node_count() == 4
                    && b.graph().node_count() == 4
                    && a.graph().edge_count() == 2
                    && b.graph().edge_count() == 2
                {
                    return (a, b);
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await;
        let (a_graph, b_graph) = converged.expect("the two replicas converged");
        assert_eq!(
            fingerprint(&a_graph),
            fingerprint(&b_graph),
            "same operation set means the same exact graph projection"
        );

        for (who, g) in [("alice", &a_graph), ("bob", &b_graph)] {
            assert_eq!(g.graph().node_count(), 4, "{who} sees every node");
            assert_eq!(g.graph().edge_count(), 2, "{who} sees both edges");
            for id in ["alice-1", "alice-2", "bob-1", "bob-2"] {
                assert!(
                    g.graph().key_of(&id.to_string()).is_some(),
                    "{who} is missing {id}"
                );
            }
            // The M1 payoff, over a real lane: two concurrently-minted edges
            // stay separately addressable, so either can be retracted by name.
            let a_key = g.edge_key(a_edge).expect("alice's edge addressable");
            let b_key = g.edge_key(b_edge).expect("bob's edge addressable");
            assert_ne!(a_key, b_key, "{who}: each id names a different edge");
        }

        // Bob now edits Alice's synced state, not a private Bob-only graph,
        // and publishes that causally-later edit over the live lane.
        let retract = bob
            .edit(|g| {
                assert!(
                    g.disconnect(&author, a_edge),
                    "bob can address alice's synced edge"
                );
            })
            .await
            .expect("bob retracts alice's edge");
        bob_space.publish(retract).expect("publish retraction");

        let reconverged = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let a = alice.materialize().await.unwrap();
                let b = bob.materialize().await.unwrap();
                if a.graph().edge_count() == 1 && b.graph().edge_count() == 1 {
                    return (a, b);
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await;
        let (a_graph, b_graph) = reconverged.expect("the shared retraction converged");
        assert_eq!(fingerprint(&a_graph), fingerprint(&b_graph));
        for graph in [&a_graph, &b_graph] {
            assert!(
                graph.edge_key(a_edge).is_none(),
                "alice's retracted edge is gone"
            );
            assert!(
                graph.edge_key(b_edge).is_some(),
                "bob's unrelated edge survives"
            );
        }

        drop(alice_space);
        drop(bob_space);
    }

    #[tokio::test]
    async fn partitioned_edits_to_different_facets_merge_without_node_translation() {
        let mut alice = Replica::new(MemoryBackend::new(), CONTAINER, [0x71; 32]);
        let mut bob = Replica::new(MemoryBackend::new(), CONTAINER, [0x72; 32]);
        let author = Author::new("ui");
        let node = "shared-note".to_string();
        let created = alice
            .edit(|graph| {
                graph.insert_node(&author, Container::new(node.clone()));
            })
            .await
            .unwrap();
        bob.accept(&created).await.unwrap();

        let title = FacetId::new("content.title");
        let pin = FacetId::new("arrangement.pin");
        let alice_edit = alice
            .edit(|graph| {
                assert!(graph.set_facet(&author, &node, title.clone(), json!("Field note")));
            })
            .await
            .unwrap();
        let bob_edit = bob
            .edit(|graph| {
                assert!(graph.set_facet(&author, &node, pin.clone(), json!(true)));
            })
            .await
            .unwrap();

        alice.accept(&bob_edit).await.unwrap();
        bob.accept(&alice_edit).await.unwrap();
        for graph in [
            alice.materialize().await.unwrap(),
            bob.materialize().await.unwrap(),
        ] {
            assert_eq!(
                graph.facets().get(&node, &title),
                Some(&json!("Field note"))
            );
            assert_eq!(graph.facets().get(&node, &pin), Some(&json!(true)));
        }
    }

    /// Before blaming a lane: a replica must be able to fold back its own
    /// stored edits. If this fails, `materialize` is wrong, not sync.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_replica_folds_back_its_own_edits() {
        let author = Author::new("ui");
        let mut alice = Replica::new(MemoryBackend::new(), CONTAINER, [90; 32]);
        alice
            .edit(|g| {
                g.insert_node(&author, Container::new("n1"));
            })
            .await
            .expect("insert");
        alice
            .edit(|g| {
                g.insert_node(&author, Container::new("n2"));
            })
            .await
            .expect("insert");

        let store = alice.sync_store();
        let count = store.operation_count().await.expect("count");
        let resolved: std::collections::BTreeMap<VerifyingKey, Vec<u64>> =
            TopicStore::<Topic, VerifyingKey, u64>::resolve(&store, &Topic::from(CONTAINER))
                .await
                .expect("resolve");
        assert_eq!(count, 2, "both operations are stored");
        assert_eq!(resolved.len(), 1, "one author is associated with the topic");

        let folded = alice.materialize().await.expect("materialize");
        assert_eq!(
            folded.graph().node_count(),
            2,
            "the fold reads back what the replica stored"
        );
    }

    /// A container id is the signed address: a batch for one container cannot
    /// be replayed into another.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_operation_for_another_container_is_refused() {
        let mut alice = Replica::new(MemoryBackend::new(), CONTAINER, [90; 32]);
        let op = alice
            .edit(|g| {
                g.insert_node(&Author::new("ui"), Container::new("n"));
            })
            .await
            .expect("alice inserts");

        let other = Replica::new(MemoryBackend::new(), [0xd1; 32], [91; 32]);
        assert!(
            other.accept(&op).await.is_err(),
            "a foreign container's batch is refused before mutation"
        );
        assert_eq!(
            other.materialize().await.unwrap().graph().node_count(),
            0,
            "and nothing was stored"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_signed_batch_cannot_mint_under_another_writer() {
        let signing_seed = [90; 32];
        let signer = WriterId(
            *SigningKey::from_bytes(&signing_seed)
                .verifying_key()
                .as_bytes(),
        );
        let foreign_writer = WriterId([0xff; 32]);
        assert_ne!(signer, foreign_writer);

        let author = Author::new("ui");
        let mut forged = GraphLog::<Container, Relation>::new().for_writer(foreign_writer);
        forged.insert_node(&author, Container::new("x"));
        forged.insert_node(&author, Container::new("y"));
        forged
            .connect(&author, &"x".to_string(), &"y".to_string(), cites())
            .unwrap();
        let batch = forged.log().entries().last().unwrap().clone();
        let operation = to_operation(signing_seed, CONTAINER, &batch, Vec::new(), 0, None);

        let replica = Replica::new(MemoryBackend::new(), CONTAINER, signing_seed);
        let error = replica
            .accept(&operation)
            .await
            .expect_err("writer forgery must be rejected");
        assert!(error.to_string().contains("edge-writer-mismatch"));
        assert_eq!(replica.sync_store().operation_count().await.unwrap(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_signed_writer_cannot_reuse_an_edge_counter() {
        let signing_seed = [90; 32];
        let author = Author::new("ui");
        let mut replica = Replica::new(MemoryBackend::new(), CONTAINER, signing_seed);
        replica
            .edit(|g| {
                g.insert_node(&author, Container::new("x"));
            })
            .await
            .unwrap();
        replica
            .edit(|g| {
                g.insert_node(&author, Container::new("y"));
            })
            .await
            .unwrap();
        let first_edge = replica
            .edit(|g| {
                g.connect(&author, &"x".to_string(), &"y".to_string(), cites());
            })
            .await
            .unwrap();
        let repeated_batch = from_operation(&first_edge).unwrap().batch;
        let repeated = to_operation(
            signing_seed,
            CONTAINER,
            &repeated_batch,
            vec![*first_edge.hash.as_bytes()],
            first_edge.header.seq_num + 1,
            Some(*first_edge.hash.as_bytes()),
        );

        let error = replica
            .accept(&repeated)
            .await
            .expect_err("counter reuse must be rejected");
        assert!(error.to_string().contains("edge-counter-frontier"));
        assert_eq!(replica.sync_store().operation_count().await.unwrap(), 3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn retained_authority_reprojects_pending_effective_and_revoked() {
        let author = Author::new("ui");
        let mut origin = Replica::new(MemoryBackend::new(), CONTAINER, [90; 32]);
        let operation = origin
            .edit(|graph| {
                graph.insert_node(&author, Container::new("authority-fact"));
            })
            .await
            .unwrap();
        let subject = *operation.header.verifying_key.as_bytes();

        // A different replica is merely the relay/holder. Its own writer key
        // does not participate in the authority decision.
        let relay = Replica::new(MemoryBackend::new(), CONTAINER, [91; 32]);
        relay.accept(&operation).await.unwrap();
        let retained = relay.sync_store();
        for (state, nodes, pending, revoked) in [
            (AuthorityState::Pending, 0, 1, 0),
            (AuthorityState::Effective, 1, 0, 0),
            (AuthorityState::Revoked, 0, 0, 1),
        ] {
            let projection = materialize_with_authority(
                &retained,
                CONTAINER,
                &FixedAuthority { subject, state },
            )
            .await
            .unwrap();
            assert_eq!(projection.graph.graph().node_count(), nodes);
            assert_eq!(projection.pending_authority.len(), pending);
            assert_eq!(projection.revoked.len(), revoked);
            assert_eq!(retained.operation_count().await.unwrap(), 1);
        }
    }

    /// A retained fact is governed by its stable writer subject and the
    /// converged Gemot delegation state. The holder that relays the operation
    /// has no input to the decision, and neither does a session or carrier.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn gemot_delegation_reprojects_retained_write_and_revocation() {
        let root = InMemoryProvider::from_seed([0x71; 32]);
        let writer = InMemoryProvider::from_seed([0x72; 32]);
        let capability = commons_write_capability(CONTAINER);
        let rules = gemot_rules(&root, cap_path(&capability));
        let delegation =
            issue_gemot_delegation(&root, &writer, cap_path(&capability), Some(900), 1);
        let delegation_id = delegation.certificate.id();
        let delegation_scope = delegation.certificate.scope.clone();
        let mut delegations = MootDelegations::new();
        assert!(
            delegations
                .accept_certificate(MOOT, &rules, delegation)
                .expect("live delegation is admitted")
        );

        let mut author = Replica::for_identity(MemoryBackend::new(), CONTAINER, &writer).unwrap();
        let operation = author
            .edit(|graph| {
                graph.insert_node(&Author::new("turnstone"), Container::new("retained"));
            })
            .await
            .expect("author writes a retained fact");
        let relay = Replica::new(MemoryBackend::new(), CONTAINER, [0x73; 32]);
        relay
            .accept(&operation)
            .await
            .expect("relay retains the fact");
        let retained = relay.sync_store();

        let effective = relay
            .projection_with_authority(&gemot_authority(&delegations, &rules))
            .await
            .expect("Gemot grants the writer capability");
        assert_eq!(effective.graph.graph().node_count(), 1);
        assert!(effective.pending_authority.is_empty());
        assert!(effective.revoked.is_empty());

        let revocation = SignedDelegationRevocation::issue(
            &root,
            DelegationRevocation::new(
                delegation_id,
                root.master_public_key().to_bytes(),
                delegation_scope,
                60,
                [2; 32],
            ),
        )
        .expect("test revocation signs");
        assert!(
            delegations
                .accept_revocation(revocation)
                .expect("Gemot accepts the issuer revocation")
        );

        let withdrawn = relay
            .projection_with_authority(&gemot_authority(&delegations, &rules))
            .await
            .expect("authority reprojects without reinserting the fact");
        assert_eq!(withdrawn.graph.graph().node_count(), 0);
        assert!(withdrawn.pending_authority.is_empty());
        assert_eq!(withdrawn.revoked.len(), 1);
        assert_eq!(
            retained
                .operation_count()
                .await
                .expect("retained fact count"),
            1,
            "revocation changes projection, never retained history"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn gemot_expired_unrelated_and_insufficient_delegations_stay_pending() {
        let root = InMemoryProvider::from_seed([0x81; 32]);
        let writer = InMemoryProvider::from_seed([0x82; 32]);
        let capability = commons_write_capability(CONTAINER);
        let needed = cap_path(&capability);
        let mut author = Replica::new(MemoryBackend::new(), CONTAINER, [0x82; 32]);
        let operation = author
            .edit(|graph| {
                graph.insert_node(&Author::new("turnstone"), Container::new("pending"));
            })
            .await
            .expect("author writes one retained fact");
        let relay = Replica::new(MemoryBackend::new(), CONTAINER, [0x83; 32]);
        relay
            .accept(&operation)
            .await
            .expect("relay retains the fact");
        let retained = relay.sync_store();

        let cases = [
            ("expired", needed.clone(), needed.clone(), Some(40)),
            (
                "unrelated",
                "scope/commons".to_string(),
                "scope/commons/other".to_string(),
                Some(900),
            ),
            (
                "insufficient",
                "scope/commons".to_string(),
                format!("{needed}/child"),
                Some(900),
            ),
        ];

        for (index, (name, root_path, delegation_path, expires_at_ms)) in
            cases.into_iter().enumerate()
        {
            let rules = gemot_rules(&root, root_path);
            let delegation = issue_gemot_delegation(
                &root,
                &writer,
                delegation_path,
                expires_at_ms,
                index as u8 + 3,
            );
            let mut delegations = MootDelegations::new();
            assert!(
                delegations
                    .accept_certificate(MOOT, &rules, delegation)
                    .expect("structurally valid delegation is retained")
            );

            let projection = relay
                .projection_with_authority(&gemot_authority(&delegations, &rules))
                .await
                .expect("authority fold succeeds");
            assert_eq!(projection.graph.graph().node_count(), 0, "{name}");
            assert_eq!(projection.pending_authority.len(), 1, "{name}");
            assert!(projection.revoked.is_empty(), "{name} is not revocation");
        }
        assert_eq!(
            retained
                .operation_count()
                .await
                .expect("retained fact count"),
            1,
            "ineffective authority never deletes the retained fact"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_derived_writer_is_bound_to_its_personae_root() {
        let root = InMemoryProvider::from_seed([0xa7; 32]);
        let author = Author::new("ui");
        let mut origin =
            Replica::for_identity(MemoryBackend::new(), CONTAINER, &root).expect("bind identity");
        let operation = origin
            .edit(|graph| {
                graph.insert_node(&author, Container::new("derived"));
            })
            .await
            .expect("identity-backed replica authors");
        let record = from_operation(&operation).unwrap();
        let attestation = record
            .writer_attestation
            .expect("the authoring path carries its stable-root binding");
        assert_eq!(
            attestation.master_public_key().unwrap(),
            root.master_public_key()
        );
        assert_eq!(
            attestation.derived_public_key().unwrap().to_bytes(),
            origin.writer().0
        );

        let receiver = Replica::new(MemoryBackend::new(), CONTAINER, [91; 32]);
        receiver.accept(&operation).await.unwrap();
        let projection = materialize_with_authority(
            &receiver.sync_store(),
            CONTAINER,
            &FixedAuthority {
                subject: root.master_public_key().to_bytes(),
                state: AuthorityState::Effective,
            },
        )
        .await
        .unwrap();
        assert_eq!(projection.graph.graph().node_count(), 1);

        let forged = to_operation_with_attestation(
            [0xb8; 32],
            CONTAINER,
            &record.batch,
            Vec::new(),
            0,
            None,
            Some(attestation),
        );
        let empty = Replica::new(MemoryBackend::new(), CONTAINER, [92; 32]);
        let error = empty
            .accept(&forged)
            .await
            .expect_err("another signer cannot claim the certified derived key");
        assert!(error.to_string().contains("writer-attestation-mismatch"));
        assert_eq!(empty.sync_store().operation_count().await.unwrap(), 0);
    }

    struct CrossWiredIdentity {
        writer: InMemoryProvider,
        attester: InMemoryProvider,
    }

    impl IdentityProvider for CrossWiredIdentity {
        fn master_public_key(&self) -> personae::Ed25519PublicKey {
            self.attester.master_public_key()
        }

        fn derive_keypair(&self, salt: &[u8]) -> Result<personae::Ed25519Keypair, IdentityError> {
            self.writer.derive_keypair(salt)
        }

        fn attest_derived_key(&self, salt: &[u8]) -> Result<DerivedKeyAttestation, IdentityError> {
            self.attester.attest_derived_key(salt)
        }
    }

    #[test]
    fn a_replica_rejects_an_attestation_for_another_derived_writer() {
        let identity = CrossWiredIdentity {
            writer: InMemoryProvider::from_seed([0xc1; 32]),
            attester: InMemoryProvider::from_seed([0xc2; 32]),
        };
        let error = Replica::for_identity(MemoryBackend::new(), CONTAINER, &identity)
            .err()
            .expect("cross-wired identity must fail closed");
        assert!(matches!(error, ReplicaIdentityError::WriterMismatch));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reconstruction_from_an_existing_store_resumes_both_counters() {
        let backend = MemoryBackend::new();
        let author = Author::new("ui");
        let mut replica = Replica::new(backend.clone(), CONTAINER, [90; 32]);
        replica
            .edit(|g| {
                g.insert_node(&author, Container::new("x"));
            })
            .await
            .unwrap();
        replica
            .edit(|g| {
                g.insert_node(&author, Container::new("y"));
            })
            .await
            .unwrap();
        let first = replica
            .edit(|g| {
                g.connect(&author, &"x".to_string(), &"y".to_string(), cites());
            })
            .await
            .unwrap();
        let first_id = connect_id(&first).unwrap();
        drop(replica);

        let mut restarted = Replica::new(backend, CONTAINER, [90; 32]);
        let second = restarted
            .edit(|g| {
                g.connect(&author, &"x".to_string(), &"y".to_string(), cites());
            })
            .await
            .expect("authoring resumes after restart");
        let second_id = connect_id(&second).unwrap();

        assert_eq!(second.header.seq_num, first.header.seq_num + 1);
        assert_eq!(
            second.header.backlink.as_ref().map(|hash| *hash.as_bytes()),
            Some(*first.hash.as_bytes())
        );
        assert_eq!(first_id.counter, 0);
        assert_eq!(second_id.counter, 1);
        assert_eq!(
            restarted.materialize().await.unwrap().graph().edge_count(),
            2
        );
    }

    /// Durable counterpart to the in-memory reconstruction receipt above.
    /// Every database handle is dropped before the same file is reopened.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn redb_reopen_resumes_the_operation_head_and_edge_counter() {
        let dir = tempfile::tempdir().expect("scratch directory");
        let path = dir.path().join("commons.redb");
        let author = Author::new("ui");

        let (first, first_id) = {
            let backend = RedbBackend::open(&path).expect("open initial database");
            let mut replica = Replica::new(backend, CONTAINER, [90; 32]);
            replica
                .edit(|g| {
                    g.insert_node(&author, Container::new("x"));
                })
                .await
                .expect("insert x");
            replica
                .edit(|g| {
                    g.insert_node(&author, Container::new("y"));
                })
                .await
                .expect("insert y");
            let first = replica
                .edit(|g| {
                    g.connect(&author, &"x".to_string(), &"y".to_string(), cites());
                })
                .await
                .expect("mint first edge");
            let first_id = connect_id(&first).expect("first edge id");
            (first, first_id)
        };

        let backend = RedbBackend::open(&path).expect("reopen database");
        let mut reopened = Replica::new(backend, CONTAINER, [90; 32]);
        let second = reopened
            .edit(|g| {
                g.connect(&author, &"x".to_string(), &"y".to_string(), cites());
            })
            .await
            .expect("authoring resumes after durable reopen");
        let second_id = connect_id(&second).expect("second edge id");

        assert_eq!(second.header.seq_num, first.header.seq_num + 1);
        assert_eq!(
            second.header.backlink.as_ref().map(|hash| *hash.as_bytes()),
            Some(*first.hash.as_bytes())
        );
        assert_eq!(first_id.counter, 0);
        assert_eq!(second_id.counter, 1);
        assert_eq!(
            reopened.materialize().await.unwrap().graph().edge_count(),
            2
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_causally_later_lower_key_writer_wins() {
        let seed_a = [90; 32];
        let seed_b = [91; 32];
        let key_a = SigningKey::from_bytes(&seed_a).verifying_key();
        let key_b = SigningKey::from_bytes(&seed_b).verifying_key();
        let (higher_seed, lower_seed) = if key_a > key_b {
            (seed_a, seed_b)
        } else {
            (seed_b, seed_a)
        };
        let higher_key = SigningKey::from_bytes(&higher_seed).verifying_key();
        let lower_key = SigningKey::from_bytes(&lower_seed).verifying_key();
        assert!(lower_key < higher_key);

        let author = Author::new("ui");
        let mut higher = Replica::new(MemoryBackend::new(), CONTAINER, higher_seed);
        let old = higher
            .edit(|g| {
                g.insert_node(&author, Container::new("n").with_title("old"));
            })
            .await
            .unwrap();

        let mut lower = Replica::new(MemoryBackend::new(), CONTAINER, lower_seed);
        lower.accept(&old).await.unwrap();
        let new = lower
            .edit(|g| {
                g.insert_node(&author, Container::new("n").with_title("new"));
            })
            .await
            .unwrap();
        assert!(
            from_operation(&new)
                .unwrap()
                .parents
                .contains(old.hash.as_bytes()),
            "the later edit records the operation it observed"
        );
        higher.accept(&new).await.unwrap();

        for replica in [&higher, &lower] {
            let graph = replica.materialize().await.unwrap();
            let key = graph.graph().key_of(&"n".to_string()).unwrap();
            assert_eq!(
                graph.graph().node(key).unwrap().title,
                "new",
                "causality outranks permanent verifying-key priority"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_causal_child_waits_for_its_missing_parent() {
        let author = Author::new("ui");
        let mut parent_writer = Replica::new(MemoryBackend::new(), CONTAINER, [90; 32]);
        let parent = parent_writer
            .edit(|g| {
                g.insert_node(&author, Container::new("n").with_title("parent"));
            })
            .await
            .unwrap();

        let mut child_writer = Replica::new(MemoryBackend::new(), CONTAINER, [91; 32]);
        child_writer.accept(&parent).await.unwrap();
        let child = child_writer
            .edit(|g| {
                g.insert_node(&author, Container::new("n").with_title("child"));
            })
            .await
            .unwrap();

        let receiver = Replica::new(MemoryBackend::new(), CONTAINER, [92; 32]);
        receiver.accept(&child).await.unwrap();
        let projection = receiver.projection().await.unwrap();
        assert_eq!(projection.graph.graph().node_count(), 0);
        assert_eq!(projection.pending.len(), 1);
        assert_eq!(projection.pending[0].operation, *child.hash.as_bytes());
        assert_eq!(projection.pending[0].missing, vec![*parent.hash.as_bytes()]);

        receiver.accept(&parent).await.unwrap();
        let projection = receiver.projection().await.unwrap();
        assert!(projection.pending.is_empty());
        let key = projection.graph.graph().key_of(&"n".to_string()).unwrap();
        assert_eq!(projection.graph.graph().node(key).unwrap().title, "child");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_remove_wins_but_an_observing_insert_recreates() {
        let author = Author::new("ui");
        let mut base_writer = Replica::new(MemoryBackend::new(), CONTAINER, [90; 32]);
        let base = base_writer
            .edit(|graph| {
                graph.insert_node(&author, Container::new("n").with_title("base"));
            })
            .await
            .unwrap();

        let mut remover = Replica::new(MemoryBackend::new(), CONTAINER, [91; 32]);
        remover.accept(&base).await.unwrap();
        let removal = remover
            .edit(|graph| {
                graph.remove_node(&author, &"n".to_string());
            })
            .await
            .unwrap();

        let mut editor = Replica::new(MemoryBackend::new(), CONTAINER, [92; 32]);
        editor.accept(&base).await.unwrap();
        let concurrent_insert = editor
            .edit(|graph| {
                graph.insert_node(
                    &author,
                    Container::new("n").with_title("unseen concurrent edit"),
                );
            })
            .await
            .unwrap();

        let receiver = Replica::new(MemoryBackend::new(), CONTAINER, [93; 32]);
        for operation in [&base, &concurrent_insert, &removal] {
            receiver.accept(operation).await.unwrap();
        }
        assert!(
            receiver
                .materialize()
                .await
                .unwrap()
                .graph()
                .key_of(&"n".to_string())
                .is_none(),
            "a concurrent insert cannot resurrect a removed node"
        );

        let mut recreator = Replica::new(MemoryBackend::new(), CONTAINER, [94; 32]);
        for operation in [&base, &concurrent_insert, &removal] {
            recreator.accept(operation).await.unwrap();
        }
        let recreation = recreator
            .edit(|graph| {
                graph.insert_node(&author, Container::new("n").with_title("deliberate"));
            })
            .await
            .unwrap();
        receiver.accept(&recreation).await.unwrap();
        let graph = receiver.materialize().await.unwrap();
        let key = graph.graph().key_of(&"n".to_string()).unwrap();
        assert_eq!(graph.graph().node(key).unwrap().title, "deliberate");
    }

    /// The edge ids the wire carries survive a CBOR round trip, including the
    /// writer half. A silent loss there would collapse two writers' edges.
    #[test]
    fn a_batch_round_trips_through_the_wire_with_writer_scoped_ids() {
        let signing_seed = [0xa1; 32];
        let writer = WriterId(
            *SigningKey::from_bytes(&signing_seed)
                .verifying_key()
                .as_bytes(),
        );
        let author = Author::new("ui");
        let mut g = GraphLog::<Container, Relation>::new().for_writer(writer);
        g.insert_node(&author, Container::new("x"));
        g.insert_node(&author, Container::new("y"));
        let minted = g
            .connect(&author, &"x".to_string(), &"y".to_string(), cites())
            .expect("connect");

        let batch = g.log().entries().last().expect("a batch").clone();
        let op = to_operation(signing_seed, CONTAINER, &batch, Vec::new(), 0, None);
        let decoded = from_operation(&op).expect("round trip");

        let carried = decoded.batch.edits.iter().find_map(|e| match e {
            chartulary::GraphEdit::Connect { id, .. } => Some(*id),
            _ => None,
        });
        assert_eq!(carried, Some(minted));
        assert_eq!(
            carried.map(|id| id.writer),
            Some(WriterId(*op.header.verifying_key.as_bytes())),
            "the writer half survives the wire and is bound to the signer"
        );
        assert!(decoded.parents.is_empty());
        assert_ne!(
            carried,
            Some(EdgeId::local(0)),
            "and it is not a bare counter"
        );
    }

    fn authored_inserts(seed: [u8; 32], label: &str, count: usize) -> Vec<StoredRecord> {
        let signing_key = SigningKey::from_bytes(&seed);
        let writer = WriterId(*signing_key.verifying_key().as_bytes());
        let author = Author::new(label);
        let mut graph = GraphLog::<Container, Relation>::new().for_writer(writer);
        let mut backlink = None;
        let mut records = Vec::new();
        for seq in 0..count {
            graph.insert_node(
                &author,
                Container::new(format!("shared-{}", seq % 3)).with_title(format!("{label}-{seq}")),
            );
            let batch = graph.log().entries().last().unwrap().clone();
            let operation = to_operation(seed, CONTAINER, &batch, Vec::new(), seq as u32, backlink);
            backlink = Some(*operation.hash.as_bytes());
            let record = from_operation(&operation).unwrap();
            records.push(StoredRecord {
                operation,
                record,
                log_id: COMMONS_LOG,
            });
        }
        records
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        #[test]
        fn the_same_operation_set_has_one_projection_under_arbitrary_arrival_order(
            alice_count in 1usize..6,
            bob_count in 1usize..6,
            arrival_keys in prop::collection::vec(any::<u8>(), 0..16),
        ) {
            let mut records = authored_inserts([90; 32], "alice", alice_count);
            records.extend(authored_inserts([91; 32], "bob", bob_count));
            let expected = GraphLog::replay(causal_journal(&records).unwrap().0);
            let expected = fingerprint(&expected);

            let mut shuffled = records;
            shuffled.sort_by_key(|record| {
                let hash = record.operation.hash.as_bytes();
                let arrival = if arrival_keys.is_empty() {
                    hash[0]
                } else {
                    arrival_keys[usize::from(hash[0]) % arrival_keys.len()]
                };
                (arrival, hash[1], hash[2])
            });
            if arrival_keys.first().is_some_and(|value| value % 2 == 1) {
                shuffled.reverse();
            }
            let actual = GraphLog::replay(causal_journal(&shuffled).unwrap().0);

            prop_assert_eq!(fingerprint(&actual), expected);
        }
    }
}
