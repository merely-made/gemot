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
//! Receipt decrypts to admit and stores the ciphertext. A record sealed to an
//! epoch the key handle lacks, or following such a record, parks until the
//! host refreshes the handle and calls [`EncryptedReplica::readmit_parked`]
//! (see [`crate::parking`]); any other record this member cannot open is
//! refused as `unreadable-commons-record` and not stored. The projection
//! decrypts with every retained epoch and runs the plaintext profile's fold,
//! so the same edits project the same graph.

use std::collections::BTreeMap;
use std::sync::Arc;

use chartulary::{Container, GraphLog, Relation, WriterId};
use insigne::DerivedKeyAttestation;
use muniment::{Backend, WriteOp};
use murm_sync::JoinedSpace;
use murm_sync::{Endpoint, Gossip};
use p2panda_core::cbor::{decode_cbor_strict, encode_cbor};
use p2panda_core::operation::validate_operation;
use p2panda_core::{Body, Hash, Header, Operation, SigningKey, Topic};
use personae::IdentityProvider;
use serde::{Deserialize, Serialize};
use stickleback::{
    Admission, DataKeyring, GroupCiphertext, GroupCryptoError, GroupSecretId, JoinError,
    MunimentStore, OperationPolicy, OperationProcessor, ProcessError, Reject, StoreTarget, lane_id,
    validate_causal_metadata,
};

use crate::parking::{
    ParkedHeader, Parking, ParkingLimits, ParkingStatus, ReadmitReport, Readmitted,
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
    decode_cbor_strict(body.to_bytes().as_slice())
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
    let sealed: SealedRecord = decode_cbor_strict(plaintext.as_slice())
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

/// The checks made before decrypting, which parking repeats; returns the
/// envelope.
fn sealed_header(
    container: [u8; 32],
    operation: &Operation<EncryptedCommonsExt>,
) -> Result<GroupCiphertext, Reject> {
    let extensions = &operation.header.extensions;
    if extensions.container != container {
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
    envelope(operation)
}

impl OperationPolicy<EncryptedCommonsExt> for EncryptedCommonsPolicy {
    type LogId = u64;

    fn admit(
        &self,
        operation: &Operation<EncryptedCommonsExt>,
    ) -> Result<Admission<Self::LogId>, Reject> {
        sealed_header(self.container, operation)?;
        check_batch(operation, &open_record(&self.keys, operation)?)?;
        Ok(Admission::keep(StoreTarget::new(
            Topic::from(self.container),
            COMMONS_LOG,
        )))
    }
}

/// Admit one operation with one snapshot of the handle's keys, or park it.
async fn accept_into<B: Backend + Clone + Send + Sync + 'static>(
    store: &MunimentStore<B, EncryptedCommonsExt>,
    container: [u8; 32],
    keys: &GroupKeys,
    parking: &Parking,
    operation: &Operation<EncryptedCommonsExt>,
) -> Result<bool, ProcessError> {
    let keys = keys.current();
    if let Ok(envelope) = sealed_header(container, operation)
        && parking
            .should_park(
                store,
                operation,
                COMMONS_LOG,
                keys.contains(&envelope.epoch),
            )
            .await?
        && parking
            .park(store.backend(), operation, COMMONS_LOG)
            .await?
    {
        return Ok(false);
    }
    admit_with(store, container, keys, operation, &[]).await
}

/// Ordinary admission, never parking. `carried` writes commit in the insert's
/// own batch: a re-admission unparks the record there, and every other caller
/// passes none.
async fn admit_with<B: Backend + Clone + Send + Sync + 'static>(
    store: &MunimentStore<B, EncryptedCommonsExt>,
    container: [u8; 32],
    keys: Arc<DataKeyring>,
    operation: &Operation<EncryptedCommonsExt>,
    carried: &[WriteOp],
) -> Result<bool, ProcessError> {
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
    if carried.is_empty() {
        return Ok(processor.process(operation).await?.inserted());
    }
    processor.process_with_writes(operation, carried).await
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
    parking: Parking,
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
            parking: Parking::new(COMMONS_ENCRYPTED_GRAPH_LANE, container),
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
            parking: Parking::new(COMMONS_ENCRYPTED_GRAPH_LANE, container),
        })
    }

    /// Bound this replica's parked records; see [`crate::parking`].
    pub fn with_parking_limits(mut self, limits: ParkingLimits) -> Self {
        self.parking.limits = limits;
        self
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
        let parking = self.parking.clone();
        JoinedSpace::join::<_, u64, _, _>(
            lane_id(COMMONS_ENCRYPTED_GRAPH_LANE, container),
            self.sync_store(),
            endpoint,
            gossip,
            container,
            move |operation: Operation<EncryptedCommonsExt>| {
                let store = accept_store.clone();
                let keys = keys.clone();
                let parking = parking.clone();
                async move {
                    accept_into(&store, container, &keys, &parking, &operation)
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

    /// Decrypt, validate and store one operation. A record sealed to an
    /// epoch the handle lacks, or backlinking a parked one, parks and returns
    /// `false`.
    pub async fn accept(
        &self,
        operation: &Operation<EncryptedCommonsExt>,
    ) -> Result<bool, ProcessError> {
        accept_into(
            &self.store,
            self.container,
            &self.keys,
            &self.parking,
            operation,
        )
        .await
    }

    /// Re-admit parked records with the handle's current keys, in causal
    /// order. A host calls this after it replaces the key handle.
    pub async fn readmit_parked(&self) -> Result<ReadmitReport, MaterializeError> {
        let keys = self.keys.current();
        self.parking
            .readmit(
                &self.store,
                |operation| {
                    let envelope = sealed_header(self.container, operation).ok()?;
                    Some(ParkedHeader {
                        parents: operation.header.extensions.parents.clone(),
                        epoch_held: keys.contains(&envelope.epoch),
                    })
                },
                async |operation, unpark| match admit_with(
                    &self.store,
                    self.container,
                    keys.clone(),
                    operation,
                    unpark,
                )
                .await
                {
                    Ok(true) => Ok(Readmitted::Inserted),
                    Ok(false) => Ok(Readmitted::Duplicate),
                    Err(ProcessError::Store(error)) => Err(error.into()),
                    Err(_) => Ok(Readmitted::Refused),
                },
            )
            .await
    }

    pub async fn parking_status(&self) -> Result<ParkingStatus, MaterializeError> {
        Ok(self.parking.status(self.store.backend()).await?)
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
#[path = "encrypted/tests.rs"]
mod tests;
