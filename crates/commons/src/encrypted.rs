// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Encrypted graph profile: the commons graph over group-sealed records.
//!
//! Beside the plaintext profile at the crate root, never mixed with it: its
//! own header type, lane kind and replica type. The signed header keeps what
//! admission and causal ordering read before decrypting: an explicit
//! encryption marker, the container (address and topic) and the observed
//! parents. The body is a `GroupCiphertext` sealing the batch and the writer
//! attestation to the current epoch of a shared [`GroupKeys`].
//!
//! Receipt decrypts to admit and stores the ciphertext. A record this member
//! cannot open is refused as `unreadable-commons-record` and not stored, so a
//! later sync can offer it again. The projection decrypts with every retained
//! epoch and runs the plaintext profile's fold, so the same edits project the
//! same graph.

use std::collections::BTreeMap;
use std::sync::Arc;

use chartulary::{Container, GraphLog, Relation, WriterId};
use muniment::Backend;
use p2panda_core::cbor::{decode_cbor, encode_cbor};
use p2panda_core::operation::validate_operation;
use p2panda_core::{Body, Hash, Header, Operation, SigningKey, Topic};
use p2panda_net::{Endpoint, Gossip};
use personae::{DerivedKeyAttestation, IdentityProvider};
use serde::{Deserialize, Serialize};
use stickleback::{
    Admission, DataKeyring, GroupCiphertext, GroupCryptoError, GroupSecretId, JoinError,
    JoinedSpace, MunimentStore, OperationPolicy, OperationProcessor, ProcessError, Reject,
    StoreTarget, lane_id, validate_causal_metadata,
};

use crate::pruning::{EpochNeed, EpochNeedReason, LaneEpochReport};
use crate::{
    AllowAllAuthority, AuthoredBatch, COMMONS_CAUSAL_LIMITS, COMMONS_LOG, CommonsAuthority,
    CommonsBatch, CommonsProjection, CommonsRecord, GraphHeader, GroupKeys, MaterializeError,
    ReplicaError, ReplicaIdentityError, StoredRecord, author_batch, check_batch, derived_writer,
    fold_with_authority, load_operations, load_records, validate_counter_frontier,
};

/// The encrypted graph's sync-lane kind, distinct from
/// [`crate::COMMONS_GRAPH_LANE`] so the two profiles never share a session.
pub const COMMONS_ENCRYPTED_GRAPH_LANE: &str = "commons/graph/encrypted/v1";

/// The signed marker that separates encrypted graph records from plaintext.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GraphEncryption {
    /// Sealed to a stickleback group data epoch.
    GroupData,
}

/// The signed header extension of an encrypted graph record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedCommonsExt {
    /// Required, so a plaintext header never decodes as an encrypted one.
    pub encryption: GraphEncryption,
    /// The container's stable id, and the LogSync topic.
    pub container: [u8; 32],
    /// Operation ids at the observed per-author frontier, readable before
    /// decryption so causal checks and ordering need no keys.
    pub parents: Vec<[u8; 32]>,
}

impl GraphHeader for EncryptedCommonsExt {
    fn container(&self) -> [u8; 32] {
        self.container
    }
}

/// The sealed part of a record; the parents stay in the signed header.
#[derive(Serialize, Deserialize)]
struct SealedRecord {
    batch: CommonsBatch,
    writer_attestation: Option<DerivedKeyAttestation>,
}

/// The body's ciphertext envelope, which names its epoch in the clear.
fn envelope(operation: &Operation<EncryptedCommonsExt>) -> Result<GroupCiphertext, Reject> {
    let body = operation.body.as_ref().ok_or_else(|| {
        Reject::new(
            "invalid-commons-ciphertext",
            "encrypted commons operation has no body",
        )
    })?;
    decode_cbor(body.to_bytes().as_slice())
        .map_err(|error| Reject::new("invalid-commons-ciphertext", error.to_string()))
}

/// Decrypt one operation back into the record the plaintext fold reads.
fn open_record(
    keys: &DataKeyring,
    operation: &Operation<EncryptedCommonsExt>,
) -> Result<CommonsRecord, Reject> {
    let plaintext = keys
        .open(&envelope(operation)?)
        .map_err(|error| Reject::new("unreadable-commons-record", error.to_string()))?;
    let sealed: SealedRecord = decode_cbor(plaintext.as_slice())
        .map_err(|error| Reject::new("invalid-commons-batch", error.to_string()))?;
    Ok(CommonsRecord {
        batch: sealed.batch,
        parents: operation.header.extensions.parents.clone(),
        writer_attestation: sealed.writer_attestation,
    })
}

/// The plaintext policy's checks, with causality read from the header before
/// decrypting and the batch checks run on the decrypted record.
struct EncryptedCommonsPolicy {
    container: [u8; 32],
    keys: Arc<DataKeyring>,
}

impl OperationPolicy<EncryptedCommonsExt> for EncryptedCommonsPolicy {
    type LogId = u64;

    fn admit(
        &self,
        operation: &Operation<EncryptedCommonsExt>,
    ) -> Result<Admission<Self::LogId>, Reject> {
        let extensions = &operation.header.extensions;
        if extensions.container != self.container {
            return Err(Reject::new(
                "wrong-container",
                "operation addresses a different container",
            ));
        }
        if validate_operation(operation).is_err() || operation.hash != operation.header.hash() {
            return Err(Reject::new(
                "bad-operation",
                "operation header or body commitment is invalid",
            ));
        }
        validate_causal_metadata(operation, &extensions.parents, COMMONS_CAUSAL_LIMITS)
            .map_err(|err| Reject::new("invalid-commons-causality", err.to_string()))?;
        check_batch(operation, &open_record(&self.keys, operation)?)?;
        Ok(Admission::keep(StoreTarget::new(
            Topic::from(self.container),
            COMMONS_LOG,
        )))
    }
}

/// Admit one operation with one snapshot of the handle's keys.
async fn accept_into<B: Backend + Clone + Send + Sync + 'static>(
    store: &MunimentStore<B, EncryptedCommonsExt>,
    container: [u8; 32],
    keys: &GroupKeys,
    operation: &Operation<EncryptedCommonsExt>,
) -> Result<bool, ProcessError> {
    let keys = keys.current();
    let processor = OperationProcessor::new(
        store.clone(),
        EncryptedCommonsPolicy {
            container,
            keys: keys.clone(),
        },
    );
    processor.preflight(operation)?;
    let record = open_record(&keys, operation)?;
    validate_counter_frontier(store, operation, &record, |stored| {
        open_record(&keys, stored)
    })
    .await?;
    Ok(processor.process(operation).await?.inserted())
}

fn to_encrypted_operation(
    keys: &DataKeyring,
    signing_seed: [u8; 32],
    container: [u8; 32],
    authored: AuthoredBatch,
    writer_attestation: Option<DerivedKeyAttestation>,
) -> Result<Operation<EncryptedCommonsExt>, GroupCryptoError> {
    let sealed = encode_cbor(&SealedRecord {
        batch: authored.batch,
        writer_attestation,
    })
    .expect("a sealed commons record always CBOR-encodes");
    let envelope = keys.seal_random(&sealed)?;
    let body_bytes = encode_cbor(&envelope).expect("a group ciphertext always CBOR-encodes");
    let header = Header::builder()
        .body(&body_bytes)
        .seq_num(authored.seq_num)
        .backlink(authored.backlink.map(Hash::from))
        .build(
            &SigningKey::from_bytes(&signing_seed),
            EncryptedCommonsExt {
                encryption: GraphEncryption::GroupData,
                container,
                parents: authored.parents,
            },
        );
    Ok(Operation {
        hash: header.hash(),
        header,
        body: Some(Body::from_bytes(&body_bytes)),
    })
}

/// One member's replica of one encrypted shared container.
pub struct EncryptedReplica<B: Backend + Clone + Send + Sync + 'static> {
    store: MunimentStore<B, EncryptedCommonsExt>,
    container: [u8; 32],
    writer: WriterId,
    signing_seed: [u8; 32],
    writer_attestation: Option<DerivedKeyAttestation>,
    keys: GroupKeys,
}

impl<B: Backend + Clone + Send + Sync + 'static> EncryptedReplica<B> {
    /// Direct-root writer, as [`crate::Replica::new`]. Pass a [`GroupKeys`]
    /// clone to share a refreshable handle, or a `DataKeyring` for a fresh one.
    pub fn new(
        backend: B,
        container: [u8; 32],
        signing_seed: [u8; 32],
        keys: impl Into<GroupKeys>,
    ) -> Self {
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
            keys: keys.into(),
        }
    }

    /// Derived Personae writer, as [`crate::Replica::for_identity`]. Same
    /// salt, so the same write capability governs both profiles.
    pub fn for_identity<P: IdentityProvider + ?Sized>(
        backend: B,
        container: [u8; 32],
        identity: &P,
        keys: impl Into<GroupKeys>,
    ) -> Result<Self, ReplicaIdentityError> {
        let (writer, signing_seed, writer_attestation) = derived_writer(identity, container)?;
        Ok(Self {
            store: MunimentStore::new(backend),
            container,
            writer,
            signing_seed,
            writer_attestation: Some(writer_attestation),
            keys: keys.into(),
        })
    }

    /// The key handle this replica and its joined lane read.
    pub fn keys(&self) -> &GroupKeys {
        &self.keys
    }

    pub fn sync_store(&self) -> MunimentStore<B, EncryptedCommonsExt> {
        self.store.clone()
    }

    pub fn writer(&self) -> WriterId {
        self.writer
    }

    /// Join this container's encrypted lane. The accept closure holds a clone
    /// of the key handle, not a copy of the keys, so a replaced keyring reaches
    /// the live lane.
    pub async fn join(
        &self,
        endpoint: Endpoint,
        gossip: Gossip,
    ) -> Result<JoinedSpace<EncryptedCommonsExt>, JoinError> {
        let accept_store = self.store.clone();
        let container = self.container;
        let keys = self.keys.clone();
        JoinedSpace::join::<_, u64, _, _>(
            lane_id(COMMONS_ENCRYPTED_GRAPH_LANE, container),
            self.sync_store(),
            endpoint,
            gossip,
            container,
            move |operation: Operation<EncryptedCommonsExt>| {
                let store = accept_store.clone();
                let keys = keys.clone();
                async move {
                    accept_into(&store, container, &keys, &operation)
                        .await
                        .unwrap_or(false)
                }
            },
        )
        .await
    }

    /// Edit the shared projection, seal the batch to the current epoch, sign
    /// and store it. Returns the operation for publishing.
    pub async fn edit(
        &mut self,
        edit: impl FnOnce(&mut GraphLog<Container, Relation>),
    ) -> Result<Operation<EncryptedCommonsExt>, ReplicaError> {
        let keys = self.keys.current();
        let records = self.load(&keys).await?;
        let author = *SigningKey::from_bytes(&self.signing_seed)
            .verifying_key()
            .as_bytes();
        let authored = author_batch(&records, self.writer, author, edit)?;
        let operation = to_encrypted_operation(
            &keys,
            self.signing_seed,
            self.container,
            authored,
            self.writer_attestation.clone(),
        )?;
        self.accept(&operation).await?;
        Ok(operation)
    }

    /// Decrypt, validate and store one operation.
    pub async fn accept(
        &self,
        operation: &Operation<EncryptedCommonsExt>,
    ) -> Result<bool, ProcessError> {
        accept_into(&self.store, self.container, &self.keys, operation).await
    }

    /// Current graph plus operations waiting on unavailable causal parents.
    pub async fn projection(&self) -> Result<CommonsProjection, MaterializeError> {
        self.projection_with_authority(&AllowAllAuthority).await
    }

    /// As [`crate::Replica::projection_with_authority`], over decrypted records.
    pub async fn projection_with_authority<A: CommonsAuthority>(
        &self,
        authority: &A,
    ) -> Result<CommonsProjection, MaterializeError> {
        let records = self.load(&self.keys.current()).await?;
        fold_with_authority(records, self.container, authority)
    }

    /// The epochs retained records are sealed under, read from their envelopes
    /// without decrypting, plus the current epoch. Changes nothing.
    pub async fn epoch_report(&self) -> Result<LaneEpochReport, MaterializeError> {
        let mut sealed = BTreeMap::<GroupSecretId, usize>::new();
        for (operation, _) in load_operations(&self.store, self.container).await? {
            let epoch = envelope(&operation)
                .map_err(MaterializeError::Encrypted)?
                .epoch;
            *sealed.entry(epoch).or_default() += 1;
        }
        let keys = self.keys.current();
        let current = keys.current_epoch();
        let needed = current
            .map(|epoch| EpochNeed {
                epoch,
                reason: EpochNeedReason::Current,
            })
            .into_iter()
            .chain(sealed.iter().map(|(epoch, records)| EpochNeed {
                epoch: *epoch,
                reason: EpochNeedReason::EncryptedGraph { records: *records },
            }))
            .collect();
        let releasable = keys
            .epoch_ids()
            .into_iter()
            .filter(|epoch| Some(*epoch) != current && !sealed.contains_key(epoch))
            .collect();
        Ok(LaneEpochReport {
            lane: COMMONS_ENCRYPTED_GRAPH_LANE,
            needed,
            releasable,
        })
    }

    async fn load(
        &self,
        keys: &DataKeyring,
    ) -> Result<Vec<StoredRecord<EncryptedCommonsExt>>, MaterializeError> {
        load_records(&self.store, self.container, |operation| {
            open_record(keys, operation).map_err(MaterializeError::Encrypted)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use chartulary::Author;
    use muniment::MemoryBackend;
    use servitor::{Cap, Mode, Subject};
    use stickleback::{GroupSecretId, decode_operation_record, operation_record};

    use super::*;
    use crate::keys::test_group::{Group, keyring};
    use crate::tests::{cites, fingerprint};
    use crate::{AuthorityState, COMMONS_GRAPH_LANE, CommonsExt, Replica, from_operation};

    const CONTAINER: [u8; 32] = [0xc0; 32];

    fn founding_keyring() -> DataKeyring {
        let mut keys = DataKeyring::new();
        keys.rotate_random().unwrap();
        keys
    }

    fn epoch_of(operation: &Operation<EncryptedCommonsExt>) -> GroupSecretId {
        let body = operation.body.as_ref().unwrap().to_bytes();
        decode_cbor::<GroupCiphertext, _>(body.as_slice())
            .unwrap()
            .epoch
    }

    fn node_ids(projection: &CommonsProjection) -> Vec<String> {
        let (nodes, _) = fingerprint(&projection.graph);
        nodes.into_iter().map(|(id, _, _)| id).collect()
    }

    /// Withdraws one writer, keeps everyone else effective.
    struct RevokeWriter([u8; 32]);

    impl CommonsAuthority for RevokeWriter {
        fn classify(&self, subject: Subject, _: &Cap, _: Mode) -> AuthorityState {
            if subject.0 == self.0 {
                AuthorityState::Revoked
            } else {
                AuthorityState::Effective
            }
        }
    }

    /// The same edits, in the same order, against either profile's pair.
    macro_rules! shared_script {
        ($alice:ident, $bob:ident) => {{
            let author = Author::new("ui");
            let x = $alice
                .edit(|g| {
                    g.insert_node(&author, Container::new("x").with_title("sealed title"));
                })
                .await
                .unwrap();
            $bob.accept(&x).await.unwrap();
            let y = $bob
                .edit(|g| {
                    g.insert_node(&author, Container::new("y"));
                })
                .await
                .unwrap();
            $alice.accept(&y).await.unwrap();
            // Concurrent: neither has seen the other's next batch.
            let edge = $alice
                .edit(|g| {
                    g.connect(&author, &"x".to_string(), &"y".to_string(), cites())
                        .unwrap();
                })
                .await
                .unwrap();
            let z = $bob
                .edit(|g| {
                    g.insert_node(&author, Container::new("z"));
                })
                .await
                .unwrap();
            $alice.accept(&z).await.unwrap();
            $bob.accept(&edge).await.unwrap();
            x
        }};
    }

    #[tokio::test]
    async fn encrypted_members_converge_on_the_plaintext_projection() {
        let keys = founding_keyring().to_bytes().unwrap();
        let (alice_seed, bob_seed) = ([0x61; 32], [0x62; 32]);
        let mut alice = EncryptedReplica::new(
            MemoryBackend::new(),
            CONTAINER,
            alice_seed,
            GroupKeys::from_bytes(&keys).unwrap(),
        );
        let mut bob = EncryptedReplica::new(
            MemoryBackend::new(),
            CONTAINER,
            bob_seed,
            GroupKeys::from_bytes(&keys).unwrap(),
        );
        let mut plain_alice = Replica::new(MemoryBackend::new(), CONTAINER, alice_seed);
        let mut plain_bob = Replica::new(MemoryBackend::new(), CONTAINER, bob_seed);

        let sealed = shared_script!(alice, bob);
        shared_script!(plain_alice, plain_bob);

        let expected = fingerprint(&plain_alice.projection().await.unwrap().graph);
        assert_eq!(expected.0.len(), 3, "x, y and z");
        assert_eq!(expected.1.len(), 1, "one edge");
        assert_eq!(
            fingerprint(&plain_bob.projection().await.unwrap().graph),
            expected
        );
        for (who, replica) in [("alice", &alice), ("bob", &bob)] {
            let projection = replica.projection().await.unwrap();
            assert!(projection.pending.is_empty(), "{who}");
            assert_eq!(fingerprint(&projection.graph), expected, "{who}");
        }

        // Authority classification folds the same way over decrypted records.
        let bob_subject = *SigningKey::from_bytes(&bob_seed).verifying_key().as_bytes();
        let sealed_view = alice
            .projection_with_authority(&RevokeWriter(bob_subject))
            .await
            .unwrap();
        let plain_view = plain_alice
            .projection_with_authority(&RevokeWriter(bob_subject))
            .await
            .unwrap();
        assert_eq!(
            fingerprint(&sealed_view.graph),
            fingerprint(&plain_view.graph)
        );
        assert_eq!(sealed_view.revoked.len(), 2);
        assert_eq!(plain_view.revoked.len(), 2);

        // The title rides only as ciphertext; the header still names the container.
        let body = sealed.body.as_ref().unwrap().to_bytes();
        assert!(!body.windows(12).any(|window| window == b"sealed title"));
        assert_eq!(sealed.header.extensions.container, CONTAINER);
    }

    /// A, B and removed C share the founding epoch. Replicas are built once,
    /// before the rotation, and only their key handles are replaced.
    #[tokio::test]
    async fn a_rotation_through_the_handle_reaches_live_members_and_not_the_removed_one() {
        let mut group = Group::found();
        let a_keys = GroupKeys::new(keyring(&group.a));
        let b_keys = GroupKeys::new(keyring(&group.b));
        let c_keys = GroupKeys::new(keyring(&group.c));
        let founding = a_keys.current().current_epoch();
        assert!(founding.is_some());
        assert_eq!(b_keys.current().current_epoch(), founding);
        assert_eq!(c_keys.current().current_epoch(), founding);

        let mut a =
            EncryptedReplica::new(MemoryBackend::new(), CONTAINER, [0xa1; 32], a_keys.clone());
        let b = EncryptedReplica::new(MemoryBackend::new(), CONTAINER, [0xb2; 32], b_keys.clone());
        let c = EncryptedReplica::new(MemoryBackend::new(), CONTAINER, [0xc3; 32], c_keys.clone());
        let author = Author::new("ui");

        let before = a
            .edit(|g| {
                g.insert_node(&author, Container::new("before"));
            })
            .await
            .unwrap();
        assert!(b.accept(&before).await.unwrap());
        assert!(
            c.accept(&before).await.unwrap(),
            "positive control: C admits the pre-rotation edit"
        );
        assert_eq!(node_ids(&c.projection().await.unwrap()), ["before"]);

        group.remove_c_and_rotate();
        a_keys.replace(keyring(&group.a));
        b_keys.replace(keyring(&group.b));
        // C's host drains the same frames and refreshes too; it installs nothing.
        c_keys.replace(keyring(&group.c));
        let rotated = a_keys.current().current_epoch().unwrap();
        assert_ne!(Some(rotated), founding);
        assert_eq!(b_keys.current().current_epoch(), Some(rotated));
        assert_eq!(c_keys.current().current_epoch(), founding);

        let after = a
            .edit(|g| {
                g.insert_node(&author, Container::new("after"));
            })
            .await
            .unwrap();
        assert_eq!(epoch_of(&after), rotated, "A seals to the new epoch");
        assert!(
            b.accept(&after).await.unwrap(),
            "B admits without a rebuild"
        );

        let refused = c.accept(&after).await.expect_err("C cannot open it");
        assert!(
            matches!(&refused, ProcessError::Rejected(reject) if reject.code == "unreadable-commons-record"),
            "{refused}"
        );
        assert_eq!(c.sync_store().operation_count().await.unwrap(), 1);
        assert_eq!(node_ids(&c.projection().await.unwrap()), ["before"]);
        for (who, replica) in [("a", &a), ("b", &b)] {
            assert_eq!(
                node_ids(&replica.projection().await.unwrap()),
                ["after", "before"],
                "{who}"
            );
        }

        // Refused records are not stored, so a later offer is judged afresh:
        // given the epoch (a stand-in for being re-added), C admits it.
        c_keys.replace(keyring(&group.b));
        assert!(c.accept(&after).await.unwrap());
        assert_eq!(
            node_ids(&c.projection().await.unwrap()),
            ["after", "before"]
        );
    }

    #[tokio::test]
    async fn the_epoch_report_reads_envelopes_without_decrypting() {
        let backend = MemoryBackend::new();
        let mut writer =
            EncryptedReplica::new(backend.clone(), CONTAINER, [0x61; 32], founding_keyring());
        let sealed = writer
            .edit(|g| {
                g.insert_node(&Author::new("ui"), Container::new("sealed"));
            })
            .await
            .unwrap();
        let epoch = epoch_of(&sealed);
        let sealed_need = EpochNeed {
            epoch,
            reason: EpochNeedReason::EncryptedGraph { records: 1 },
        };
        let current_need = EpochNeed {
            epoch,
            reason: EpochNeedReason::Current,
        };
        assert_eq!(
            writer.epoch_report().await.unwrap().needed,
            [current_need, sealed_need.clone()]
        );

        // Same store, no keys: it cannot project, yet reports the same need.
        let keyless = EncryptedReplica::new(backend, CONTAINER, [0x62; 32], DataKeyring::new());
        assert!(keyless.projection().await.is_err(), "positive control");
        let report = keyless.epoch_report().await.unwrap();
        assert_eq!(report.needed, [sealed_need]);
        assert!(report.releasable.is_empty());
    }

    #[tokio::test]
    async fn plaintext_and_encrypted_records_refuse_each_other() {
        let author = Author::new("ui");
        let mut encrypted = EncryptedReplica::new(
            MemoryBackend::new(),
            CONTAINER,
            [0x61; 32],
            founding_keyring(),
        );
        let mut plain = Replica::new(MemoryBackend::new(), CONTAINER, [0x62; 32]);
        let sealed_op = encrypted
            .edit(|g| {
                g.insert_node(&author, Container::new("sealed"));
            })
            .await
            .unwrap();
        let plain_op = plain
            .edit(|g| {
                g.insert_node(&author, Container::new("plain"));
            })
            .await
            .unwrap();
        let encrypted_receiver = EncryptedReplica::new(
            MemoryBackend::new(),
            CONTAINER,
            [0x63; 32],
            encrypted.keys().clone(),
        );
        let plain_receiver = Replica::new(MemoryBackend::new(), CONTAINER, [0x64; 32]);
        assert_ne!(COMMONS_ENCRYPTED_GRAPH_LANE, COMMONS_GRAPH_LANE);

        // A plaintext header lacks the signed marker: it never decodes as encrypted.
        let error =
            decode_operation_record::<EncryptedCommonsExt>(&operation_record(&plain_op, true))
                .expect_err("a plaintext header is not an encrypted one");
        assert!(error.to_string().contains("encryption"), "{error}");

        // An encrypted header carried to a plaintext replica: its body is refused.
        let crossed = decode_operation_record::<CommonsExt>(&operation_record(&sealed_op, true))
            .unwrap()
            .unwrap();
        let error = plain_receiver.accept(&crossed).await.unwrap_err();
        assert!(
            error.to_string().contains("invalid-commons-batch"),
            "{error}"
        );
        assert_eq!(
            plain_receiver.sync_store().operation_count().await.unwrap(),
            0
        );

        // A plaintext record signed under the encrypted header is refused too.
        let body = encode_cbor(&CommonsRecord {
            batch: from_operation(&plain_op).unwrap().batch,
            parents: Vec::new(),
            writer_attestation: None,
        })
        .unwrap();
        let header = Header::builder()
            .body(&body)
            .seq_num(0)
            .backlink(None)
            .build(
                &SigningKey::from_bytes(&[0x62; 32]),
                EncryptedCommonsExt {
                    encryption: GraphEncryption::GroupData,
                    container: CONTAINER,
                    parents: Vec::new(),
                },
            );
        let downgraded = Operation {
            hash: header.hash(),
            header,
            body: Some(Body::from_bytes(&body)),
        };
        let error = encrypted_receiver.accept(&downgraded).await.unwrap_err();
        assert!(
            matches!(&error, ProcessError::Rejected(reject) if reject.code == "invalid-commons-ciphertext"),
            "{error}"
        );
        assert_eq!(
            encrypted_receiver
                .sync_store()
                .operation_count()
                .await
                .unwrap(),
            0
        );

        // Positive controls: each receiver admits its own profile's record.
        assert!(encrypted_receiver.accept(&sealed_op).await.unwrap());
        assert!(plain_receiver.accept(&plain_op).await.unwrap());
    }
}
