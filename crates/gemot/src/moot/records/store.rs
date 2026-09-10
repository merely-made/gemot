// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The Moot object store over the shared muniment replication processor.
//!
//! Ordinary events and retention checkpoints use separate per-author logs.
//! An authorized prune operation can therefore remove an event prefix while
//! leaving the signed checkpoint and compact roster snapshot available.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::{Arc, RwLock};

use identity::{Ed25519Keypair, IdentityError, IdentityProvider};
use muniment::{Backend, MemoryBackend, RedbBackend, StoreError};
use p2panda_core::{Hash, Operation, SigningKey, Topic, VerifyingKey};
use p2panda_store::topics::TopicStore;
use stickleback::{
    Admission, CheckpointAuthority, DropExportBudget, DropExportProfile, DropExportSelector,
    DropImportReport, DropIoError, DropLimits, DropWriteReceipt, MunimentStore, OperationPolicy,
    OperationProcessor, ProcessError, ProcessOutcome, Reject, StoreTarget, decode_operation_record,
    export_topic_operations, export_topic_operations_selected, import_drop_records,
    import_plain_drop, write_plain_drop,
};

use super::retention::{
    CheckpointError, LogFrontier, MootRetentionPolicy, MootRosterSnapshot, RetentionCheckpoint,
};
use super::roster::MootRoster;
use super::wire::{
    MootEvent, MootExt, MootLogId, from_operation, object_identity_salt, stable_author,
    to_operation_seed, to_operation_seed_with_attestation, to_prune_operation_seed,
};

/// A Moot store failure.
#[derive(Debug, thiserror::Error)]
pub enum MootStoreError {
    #[error("moot store: {0}")]
    Backend(#[from] StoreError),
    #[error(transparent)]
    Process(#[from] ProcessError),
    #[error("moot retention: {0}")]
    Retention(String),
    #[error(transparent)]
    Drop(#[from] DropIoError),
    #[error(transparent)]
    Identity(#[from] IdentityError),
}

/// Latest accepted checkpoint and its signed operation identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredCheckpoint {
    pub operation: [u8; 32],
    pub checkpoint: RetentionCheckpoint,
}

#[derive(Clone, Copy)]
struct MootPolicy<'a> {
    moot_id: [u8; 32],
    retention: Option<&'a MootRetentionPolicy>,
    checkpoints: &'a BTreeMap<[u8; 32], RetentionCheckpoint>,
    current_operation: Option<[u8; 32]>,
    allow_historical_checkpoint_authority: bool,
    allow_historical_prune: bool,
}

impl OperationPolicy<MootExt> for MootPolicy<'_> {
    type LogId = MootLogId;

    fn admit(&self, operation: &Operation<MootExt>) -> Result<Admission<Self::LogId>, Reject> {
        if operation.header.extensions.moot_id != self.moot_id {
            return Err(Reject::new(
                "wrong-moot",
                "operation addresses a different moot",
            ));
        }
        let (_, event) = from_operation(operation)
            .map_err(|error| Reject::new("invalid-moot-event", error.to_string()))?;
        stable_author(operation)
            .map_err(|error| Reject::new("invalid-moot-author", error.to_string()))?;
        let target = StoreTarget::new(Topic::from(self.moot_id), event.log_id());
        match event {
            MootEvent::RetentionCheckpoint { checkpoint } => {
                if operation.header.extensions.prune_flag.is_set() {
                    return Err(Reject::new(
                        "checkpoint-cannot-prune",
                        "checkpoint operations remain in their dedicated log",
                    ));
                }
                let policy = self.retention.ok_or_else(|| {
                    Reject::new(
                        "retention-unconfigured",
                        "this moot has no configured retention policy",
                    )
                })?;
                let current = checkpoint.previous_checkpoint.and_then(|operation| {
                    self.checkpoints
                        .get(&operation)
                        .map(|checkpoint| (operation, checkpoint))
                });
                let result = if self.allow_historical_checkpoint_authority {
                    policy.validate_checkpoint_from_history(
                        self.moot_id,
                        *operation.header.verifying_key.as_bytes(),
                        current,
                        &checkpoint,
                    )
                } else {
                    policy.validate_checkpoint(
                        self.moot_id,
                        *operation.header.verifying_key.as_bytes(),
                        current,
                        &checkpoint,
                    )
                };
                result.map_err(checkpoint_reject)?;
                Ok(Admission::keep(target))
            },
            MootEvent::HistoryPruned { checkpoint, .. } => {
                if !operation.header.extensions.prune_flag.is_set() {
                    return Err(Reject::new(
                        "missing-prune-flag",
                        "history-pruned event requires the p2panda prune flag",
                    ));
                }
                let current = self.current_operation.ok_or_else(|| {
                    Reject::new(
                        "checkpoint-missing",
                        "no accepted checkpoint authorizes pruning",
                    )
                })?;
                if !self.allow_historical_prune && checkpoint != current {
                    return Err(Reject::new(
                        "checkpoint-stale",
                        "history-pruned event does not name the latest accepted checkpoint",
                    ));
                }
                if self.allow_historical_prune && !self.checkpoints.contains_key(&checkpoint) {
                    return Err(Reject::new(
                        "checkpoint-missing",
                        "history-pruned event names no checkpoint carried by this drop",
                    ));
                }
                Ok(Admission::prune_before_current(target))
            },
            _ => {
                if operation.header.extensions.prune_flag.is_set() {
                    return Err(Reject::new(
                        "unexpected-prune-flag",
                        "only a history-pruned event may carry the prune flag",
                    ));
                }
                Ok(Admission::keep(target))
            },
        }
    }
}

fn checkpoint_reject(error: CheckpointError) -> Reject {
    let code = match error {
        CheckpointError::UnsupportedAuthoritySet(_) => "checkpoint-authority-set",
        CheckpointError::UnsupportedVersion(_) => "checkpoint-version",
        CheckpointError::ForeignMoot => "checkpoint-foreign-moot",
        CheckpointError::UnauthorizedAuthority => "checkpoint-unauthorized",
        CheckpointError::StalePolicy => "checkpoint-stale-policy",
        CheckpointError::StaleCheckpoint => "checkpoint-stale-checkpoint",
        CheckpointError::FalseSnapshotReference => "checkpoint-false-snapshot-ref",
        CheckpointError::FalseSnapshotCommitment => "checkpoint-false-commitment",
        CheckpointError::DuplicateFrontier => "checkpoint-duplicate-frontier",
        CheckpointError::FrontierRewind => "checkpoint-frontier-rewind",
    };
    Reject::new(code, error.to_string())
}

/// Moot operation store, generic over memory or durable redb backends.
#[derive(Clone)]
pub struct MootStore<B = MemoryBackend> {
    store: MunimentStore<B, MootExt>,
    retention: Arc<RwLock<Option<MootRetentionPolicy>>>,
}

/// Durable redb-backed Moot object store.
pub type MootStoreFile = MootStore<RedbBackend>;

impl MootStore<MemoryBackend> {
    pub fn in_memory() -> Self {
        Self {
            store: MunimentStore::new(MemoryBackend::new()),
            retention: Arc::new(RwLock::new(None)),
        }
    }

    pub fn in_memory_with_retention(retention: MootRetentionPolicy) -> Self {
        Self {
            store: MunimentStore::new(MemoryBackend::new()),
            retention: Arc::new(RwLock::new(Some(retention))),
        }
    }
}

impl MootStore<RedbBackend> {
    pub fn at_path(path: impl AsRef<Path>) -> Result<Self, MootStoreError> {
        Ok(Self {
            store: MunimentStore::new(RedbBackend::open(path)?),
            retention: Arc::new(RwLock::new(None)),
        })
    }

    pub fn at_path_with_retention(
        path: impl AsRef<Path>,
        retention: MootRetentionPolicy,
    ) -> Result<Self, MootStoreError> {
        Ok(Self {
            store: MunimentStore::new(RedbBackend::open(path)?),
            retention: Arc::new(RwLock::new(Some(retention))),
        })
    }
}

impl<B: Backend + Clone> MootStore<B> {
    /// Current retention settings and constitution-derived authority.
    pub fn retention_policy(&self) -> Option<MootRetentionPolicy> {
        self.retention
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Replace the active retention policy after a governed settings or
    /// constitution revision. Clones handed to sync share this policy cell.
    pub fn set_retention_policy(&self, policy: Option<MootRetentionPolicy>) {
        *self
            .retention
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = policy;
    }

    pub fn sync_store(&self) -> MunimentStore<B, MootExt> {
        self.store.clone()
    }

    pub async fn insert(&self, op: &Operation<MootExt>) -> Result<bool, MootStoreError> {
        self.accept(op.header.extensions.moot_id, op).await
    }

    pub async fn accept(
        &self,
        moot_id: [u8; 32],
        op: &Operation<MootExt>,
    ) -> Result<bool, MootStoreError> {
        Ok(self.accept_outcome(moot_id, op).await?.inserted())
    }

    pub async fn accept_outcome(
        &self,
        moot_id: [u8; 32],
        op: &Operation<MootExt>,
    ) -> Result<ProcessOutcome, MootStoreError> {
        let retention = self.retention_policy();
        let operations = self.ops(moot_id).await?;
        let current = self.latest_checkpoint_from_ops(moot_id, &operations)?;
        if matches!(
            from_operation(op).ok().map(|(_, event)| event),
            Some(MootEvent::RetentionCheckpoint { .. })
        ) {
            let mut prospective = operations.clone();
            if !prospective.iter().any(|existing| existing.hash == op.hash) {
                prospective.push(op.clone());
            }
            self.latest_checkpoint_from_ops(moot_id, &prospective)?;
        }
        let checkpoints = Self::checkpoint_index(&operations);
        let processor = OperationProcessor::new(
            self.store.clone(),
            MootPolicy {
                moot_id,
                retention: retention.as_ref(),
                checkpoints: &checkpoints,
                current_operation: current.as_ref().map(|stored| stored.operation),
                allow_historical_checkpoint_authority: false,
                allow_historical_prune: false,
            },
        );
        Ok(processor.process(op).await?)
    }

    pub async fn operation(&self, id: &Hash) -> Result<Option<Operation<MootExt>>, MootStoreError> {
        Ok(self.store.get_operation(id).await?)
    }

    pub async fn latest(
        &self,
        author: &VerifyingKey,
        _moot_id: [u8; 32],
    ) -> Result<Option<Operation<MootExt>>, MootStoreError> {
        self.latest_in(author, MootLogId::Events).await
    }

    pub async fn latest_in(
        &self,
        author: &VerifyingKey,
        log_id: MootLogId,
    ) -> Result<Option<Operation<MootExt>>, MootStoreError> {
        Ok(self.store.get_latest_entry(author, &log_id).await?)
    }

    pub async fn author(
        &self,
        keypair: &Ed25519Keypair,
        moot_id: [u8; 32],
        event: &MootEvent,
    ) -> Result<Operation<MootExt>, MootStoreError> {
        self.author_seed(keypair.to_seed(), moot_id, event).await
    }

    pub async fn author_seed(
        &self,
        signing_seed: [u8; 32],
        moot_id: [u8; 32],
        event: &MootEvent,
    ) -> Result<Operation<MootExt>, MootStoreError> {
        let author = SigningKey::from_bytes(&signing_seed).verifying_key();
        let (seq_num, backlink) = match self.latest_in(&author, event.log_id()).await? {
            Some(previous) => (previous.header.seq_num + 1, Some(*previous.hash.as_bytes())),
            None => (0, None),
        };
        let operation = to_operation_seed(signing_seed, moot_id, event, seq_num, backlink);
        self.accept(moot_id, &operation).await?;
        Ok(operation)
    }

    /// Author under this Moot's derived object key, certified by the stable
    /// Personae root carried in the signed operation extension.
    pub async fn author_for_identity<P: IdentityProvider + ?Sized>(
        &self,
        identity: &P,
        moot_id: [u8; 32],
        event: &MootEvent,
    ) -> Result<Operation<MootExt>, MootStoreError> {
        let salt = object_identity_salt(moot_id);
        let keypair = identity.derive_keypair(&salt)?;
        let attestation = identity.attest_derived_key(&salt)?;
        let author = SigningKey::from_bytes(&keypair.to_seed()).verifying_key();
        let (seq_num, backlink) = match self.latest_in(&author, event.log_id()).await? {
            Some(previous) => (previous.header.seq_num + 1, Some(*previous.hash.as_bytes())),
            None => (0, None),
        };
        let operation = to_operation_seed_with_attestation(
            keypair.to_seed(),
            moot_id,
            event,
            seq_num,
            backlink,
            Some(attestation),
        );
        self.accept(moot_id, &operation).await?;
        Ok(operation)
    }

    pub async fn author_prune(
        &self,
        keypair: &Ed25519Keypair,
        moot_id: [u8; 32],
        checkpoint: [u8; 32],
        at_ms: u64,
    ) -> Result<Operation<MootExt>, MootStoreError> {
        self.author_prune_seed(keypair.to_seed(), moot_id, checkpoint, at_ms)
            .await
    }

    pub async fn author_prune_seed(
        &self,
        signing_seed: [u8; 32],
        moot_id: [u8; 32],
        checkpoint: [u8; 32],
        at_ms: u64,
    ) -> Result<Operation<MootExt>, MootStoreError> {
        let author = SigningKey::from_bytes(&signing_seed).verifying_key();
        let (seq_num, backlink) = match self.latest_in(&author, MootLogId::Events).await? {
            Some(previous) => (previous.header.seq_num + 1, Some(*previous.hash.as_bytes())),
            None => (0, None),
        };
        let operation =
            to_prune_operation_seed(signing_seed, moot_id, checkpoint, at_ms, seq_num, backlink);
        self.accept(moot_id, &operation).await?;
        Ok(operation)
    }

    pub async fn ops(&self, moot_id: [u8; 32]) -> Result<Vec<Operation<MootExt>>, MootStoreError> {
        let logs: BTreeMap<VerifyingKey, Vec<MootLogId>> =
            self.store.resolve(&Topic::from(moot_id)).await?;
        let mut operations = Vec::new();
        for (author, log_ids) in logs {
            for log_id in log_ids {
                if let Some(entries) = self
                    .store
                    .get_log_entries(&author, &log_id, None, None)
                    .await?
                {
                    operations.extend(entries.into_iter().map(|(operation, _)| operation));
                }
            }
        }
        Ok(operations)
    }

    /// Export retained Moot operations as a plaintext native drop. This is for
    /// public data or an explicit local transfer; private Moot export waits for
    /// a domain privacy selector and injected protector.
    pub async fn export_plain_drop<W: Write>(
        &self,
        moot_id: [u8; 32],
        writer: &mut W,
        profile: DropExportProfile,
        limits: DropLimits,
    ) -> Result<DropWriteReceipt, MootStoreError> {
        let records = export_topic_operations::<B, MootExt, MootLogId>(
            &self.store,
            &Topic::from(moot_id),
            profile,
        )
        .await?;
        Ok(write_plain_drop(writer, &records, limits).map_err(DropIoError::from)?)
    }

    /// Select retained Moot operation records for an aggregate carrier. The
    /// caller owns the privacy decision and can then protect the complete
    /// carrier with its group-key suite.
    pub async fn export_selected_drop_records<S: DropExportSelector<MootExt>>(
        &self,
        moot_id: [u8; 32],
        selector: &S,
        budget: DropExportBudget,
    ) -> Result<(Vec<stickleback::DropRecord>, stickleback::DropExportStats), MootStoreError> {
        Ok(
            export_topic_operations_selected::<B, MootExt, MootLogId, S>(
                &self.store,
                &Topic::from(moot_id),
                selector,
                budget,
            )
            .await?,
        )
    }

    /// Import a verified plaintext/public Moot drop through the same admission
    /// policy and atomic processor used by authoring and LogSync.
    pub async fn import_plain_drop<R: Read>(
        &self,
        moot_id: [u8; 32],
        reader: R,
        limits: DropLimits,
    ) -> Result<DropImportReport, MootStoreError> {
        let retention = self.retention_policy();
        let operations = self.ops(moot_id).await?;
        let current = self.latest_checkpoint_from_ops(moot_id, &operations)?;
        let checkpoints = Self::checkpoint_index(&operations);
        let processor = OperationProcessor::new(
            self.store.clone(),
            MootPolicy {
                moot_id,
                retention: retention.as_ref(),
                checkpoints: &checkpoints,
                current_operation: current.as_ref().map(|stored| stored.operation),
                allow_historical_checkpoint_authority: false,
                allow_historical_prune: false,
            },
        );
        Ok(import_plain_drop(reader, limits, &processor).await?)
    }

    /// Import records already verified by an aggregate carrier. The caller may
    /// include checkpoint-authority evidence among non-operation records; this
    /// store advances the checkpoint chain in the same atomic operation batch.
    pub async fn import_drop_records(
        &self,
        moot_id: [u8; 32],
        drop_id: stickleback::DropId,
        records: Vec<stickleback::DropRecord>,
    ) -> Result<DropImportReport, MootStoreError> {
        let retention = self.retention_policy();
        let mut operations = self.ops(moot_id).await?;
        let mut seen: BTreeSet<_> = operations
            .iter()
            .map(|operation| *operation.hash.as_bytes())
            .collect();
        for record in &records {
            if let Some(operation) = decode_operation_record::<MootExt>(record)?
                && seen.insert(*operation.hash.as_bytes())
            {
                operations.push(operation);
            }
        }
        let current = self.latest_checkpoint_from_ops(moot_id, &operations)?;
        let checkpoints = Self::checkpoint_index(&operations);
        let processor = OperationProcessor::new(
            self.store.clone(),
            MootPolicy {
                moot_id,
                retention: retention.as_ref(),
                checkpoints: &checkpoints,
                current_operation: current.as_ref().map(|stored| stored.operation),
                allow_historical_checkpoint_authority: true,
                allow_historical_prune: true,
            },
        );
        Ok(import_drop_records(drop_id, records, &processor).await?)
    }

    pub async fn roster(&self, moot_id: [u8; 32]) -> Result<MootRoster, MootStoreError> {
        let operations = self.ops(moot_id).await?;
        let Some(stored) = self.latest_checkpoint_from_ops(moot_id, &operations)? else {
            return Ok(MootRoster::fold(moot_id, operations.iter()));
        };
        let frontier: BTreeMap<_, _> = stored
            .checkpoint
            .frontier
            .iter()
            .map(|entry| ((entry.author, entry.log_id), entry.seq_num))
            .collect();
        let tail: Vec<_> = operations
            .iter()
            .filter(|operation| {
                let Ok((_, event)) = from_operation(operation) else {
                    return false;
                };
                frontier
                    .get(&(*operation.header.verifying_key.as_bytes(), event.log_id()))
                    .is_none_or(|seq_num| u64::from(operation.header.seq_num) > *seq_num)
            })
            .collect();
        Ok(MootRoster::fold_from_snapshot(
            moot_id,
            &stored.checkpoint.snapshot,
            tail,
        ))
    }

    pub async fn latest_checkpoint(
        &self,
        moot_id: [u8; 32],
    ) -> Result<Option<StoredCheckpoint>, MootStoreError> {
        let operations = self.ops(moot_id).await?;
        self.latest_checkpoint_from_ops(moot_id, &operations)
    }

    fn latest_checkpoint_from_ops(
        &self,
        moot_id: [u8; 32],
        operations: &[Operation<MootExt>],
    ) -> Result<Option<StoredCheckpoint>, MootStoreError> {
        let mut checkpoints: Vec<_> = operations
            .iter()
            .filter_map(|operation| match from_operation(operation).ok()?.1 {
                MootEvent::RetentionCheckpoint { checkpoint } => Some((operation, *checkpoint)),
                _ => None,
            })
            .collect();
        let mut current: Option<StoredCheckpoint> = None;
        while !checkpoints.is_empty() {
            let expected_previous = current.as_ref().map(|stored| stored.operation);
            let matches: Vec<_> = checkpoints
                .iter()
                .enumerate()
                .filter_map(|(index, (_, checkpoint))| {
                    (checkpoint.previous_checkpoint == expected_previous).then_some(index)
                })
                .collect();
            if matches.len() != 1 {
                return Err(MootStoreError::Retention(
                    "checkpoint history is forked or missing a predecessor".into(),
                ));
            }
            let (operation, checkpoint) = checkpoints.remove(matches[0]);
            checkpoint
                .validate_retained(
                    moot_id,
                    current
                        .as_ref()
                        .map(|stored| (stored.operation, &stored.checkpoint)),
                )
                .map_err(|error| MootStoreError::Retention(error.to_string()))?;
            current = Some(StoredCheckpoint {
                operation: *operation.hash.as_bytes(),
                checkpoint,
            });
        }
        Ok(current)
    }

    fn checkpoint_index(
        operations: &[Operation<MootExt>],
    ) -> BTreeMap<[u8; 32], RetentionCheckpoint> {
        operations
            .iter()
            .filter_map(|operation| match from_operation(operation).ok()?.1 {
                MootEvent::RetentionCheckpoint { checkpoint } => {
                    Some((*operation.hash.as_bytes(), *checkpoint))
                },
                _ => None,
            })
            .collect()
    }

    pub async fn build_checkpoint(
        &self,
        moot_id: [u8; 32],
        at_ms: u64,
    ) -> Result<RetentionCheckpoint, MootStoreError> {
        let retention = self.retention_policy();
        let policy = retention.as_ref().ok_or_else(|| {
            MootStoreError::Retention("this moot has no configured retention policy".into())
        })?;
        let operations = self.ops(moot_id).await?;
        let current = self.latest_checkpoint_from_ops(moot_id, &operations)?;
        let snapshot = MootRosterSnapshot::from_roster(&self.roster(moot_id).await?);
        let mut frontier: BTreeMap<_, _> = current
            .iter()
            .flat_map(|stored| stored.checkpoint.frontier.iter().cloned())
            .map(|entry| ((entry.author, entry.log_id), entry))
            .collect();
        for operation in &operations {
            let Ok((_, event)) = from_operation(operation) else {
                continue;
            };
            let log_id = event.log_id();
            if log_id != MootLogId::Events {
                continue;
            }
            let key = (*operation.header.verifying_key.as_bytes(), log_id);
            frontier.insert(
                key,
                LogFrontier {
                    author: key.0,
                    log_id,
                    seq_num: u64::from(operation.header.seq_num),
                    operation: *operation.hash.as_bytes(),
                },
            );
        }
        Ok(RetentionCheckpoint::new(
            moot_id,
            policy.revision.clone(),
            policy.checkpoint_authority.authority_revision(),
            current.as_ref().map(|stored| stored.operation),
            frontier.into_values().collect(),
            snapshot,
            at_ms,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::moot::records::retention::{
        AvailabilityPolicy, ErasurePolicy, GovernedCheckpointAuthority, KeepBound, PolicyRevision,
    };
    use identity::{IdentityProvider, InMemoryProvider};
    use proofs::Digest;
    use servitor::{AuthorityProvider, Cap, Mode, Subject};

    const MOOT: [u8; 32] = [0x6d; 32];

    fn keypair(seed: u8) -> Ed25519Keypair {
        InMemoryProvider::from_seed([seed; 32])
            .derive_keypair(b"moot-store")
            .unwrap()
    }

    fn retention(authority: &Ed25519Keypair) -> MootRetentionPolicy {
        MootRetentionPolicy {
            revision: PolicyRevision(Digest::blake3(b"moot retention policy")),
            checkpoint_authority: GovernedCheckpointAuthority::from_constitution(
                Digest::blake3(b"moot constitution"),
                [authority.public_key().to_bytes()],
            ),
            checkpoint_authority_history: Vec::new(),
            availability: AvailabilityPolicy {
                promised_floor: KeepBound::Forever,
            },
            erasure: ErasurePolicy {
                history_ceiling: KeepBound::UntilCheckpoint,
            },
        }
    }

    struct RootAuthority([u8; 32]);

    impl AuthorityProvider for RootAuthority {
        fn covers(&self, subject: Subject, _: &Cap, mode: Mode) -> bool {
            subject.0 == self.0 && mode == Mode::Write
        }
    }

    #[tokio::test]
    async fn insert_is_idempotent_and_feeds_the_roster() {
        let store = MootStore::in_memory();
        let keypair = keypair(1);
        let operation = super::super::wire::to_operation(
            &keypair,
            MOOT,
            &MootEvent::Declared {
                name: "circle".into(),
                charter: "c".into(),
                at_ms: 1,
            },
            0,
            None,
        );
        assert!(store.insert(&operation).await.unwrap());
        assert!(!store.insert(&operation).await.unwrap());
        assert_eq!(
            store.roster(MOOT).await.unwrap().declaration.unwrap().name,
            "circle"
        );
    }

    #[tokio::test]
    async fn derived_share_projects_and_authorizes_as_the_stable_persona() {
        let store = MootStore::in_memory();
        let identity = InMemoryProvider::from_seed([0x21; 32]);
        let operation = store
            .author_for_identity(
                &identity,
                MOOT,
                &MootEvent::Shared {
                    manifest_id: [0xaa; 32],
                    schema_id: "fleece.snapshot/v1".into(),
                    title: "the remembered page".into(),
                    at_ms: 5,
                },
            )
            .await
            .unwrap();

        let root = identity.master_public_key().to_bytes();
        assert_ne!(*operation.header.verifying_key.as_bytes(), root);
        let roster = store.roster(MOOT).await.unwrap();
        assert_eq!(roster.fauna[0].shared_by, root);
        assert_eq!(
            roster.authorized_fauna(&RootAuthority(root)),
            vec![&roster.fauna[0]]
        );
    }

    #[tokio::test]
    async fn false_derived_writer_binding_is_rejected_before_storage() {
        let claimed = InMemoryProvider::from_seed([0x31; 32]);
        let signer = InMemoryProvider::from_seed([0x32; 32]);
        let salt = object_identity_salt(MOOT);
        let signer_key = signer.derive_keypair(&salt).unwrap();
        let operation = to_operation_seed_with_attestation(
            signer_key.to_seed(),
            MOOT,
            &MootEvent::Shared {
                manifest_id: [0xbb; 32],
                schema_id: "fleece.snapshot/v1".into(),
                title: "forged attribution".into(),
                at_ms: 6,
            },
            0,
            None,
            Some(claimed.attest_derived_key(&salt).unwrap()),
        );

        let error = store_error(&MootStore::in_memory(), &operation).await;
        assert!(
            error.contains("invalid-moot-author") && error.contains("does not bind"),
            "unexpected refusal: {error}"
        );
    }

    async fn store_error(store: &MootStore, operation: &Operation<MootExt>) -> String {
        store
            .accept(MOOT, operation)
            .await
            .expect_err("false attribution must fail")
            .to_string()
    }

    #[tokio::test]
    async fn checkpoint_survives_event_prefix_prune_and_replays_roster() {
        let authority = keypair(1);
        let store = MootStore::in_memory_with_retention(retention(&authority));
        let declared = store
            .author(
                &authority,
                MOOT,
                &MootEvent::Declared {
                    name: "printing circle".into(),
                    charter: "shared type".into(),
                    at_ms: 1,
                },
            )
            .await
            .unwrap();
        let joined = store
            .author(
                &authority,
                MOOT,
                &MootEvent::Joined {
                    name: "mark".into(),
                    at_ms: 2,
                },
            )
            .await
            .unwrap();

        let checkpoint = store.build_checkpoint(MOOT, 10).await.unwrap();
        let checkpoint_operation = store
            .author(
                &authority,
                MOOT,
                &MootEvent::RetentionCheckpoint {
                    checkpoint: Box::new(checkpoint),
                },
            )
            .await
            .unwrap();
        let prune = store
            .author_prune(&authority, MOOT, *checkpoint_operation.hash.as_bytes(), 11)
            .await
            .unwrap();
        let shared = store
            .author(
                &authority,
                MOOT,
                &MootEvent::Shared {
                    manifest_id: [0xaa; 32],
                    schema_id: "codicil/v1".into(),
                    title: "retained tail".into(),
                    at_ms: 12,
                },
            )
            .await
            .unwrap();

        let operations = store.ops(MOOT).await.unwrap();
        assert!(
            !operations
                .iter()
                .any(|operation| operation.hash == declared.hash)
        );
        assert!(
            !operations
                .iter()
                .any(|operation| operation.hash == joined.hash)
        );
        assert!(
            operations
                .iter()
                .any(|operation| operation.hash == checkpoint_operation.hash)
        );
        assert!(
            operations
                .iter()
                .any(|operation| operation.hash == prune.hash)
        );
        assert!(
            operations
                .iter()
                .any(|operation| operation.hash == shared.hash)
        );
        let roster = store.roster(MOOT).await.unwrap();
        assert_eq!(roster.declaration.unwrap().name, "printing circle");
        assert_eq!(roster.members.len(), 1);
        assert_eq!(roster.fauna[0].title, "retained tail");
    }

    #[tokio::test]
    async fn checkpoint_snapshot_keeps_withdrawal_after_pruning_the_source_log() {
        let authority = keypair(1);
        let identity = InMemoryProvider::from_seed([0x22; 32]);
        let store = MootStore::in_memory_with_retention(retention(&authority));
        let share = store
            .author_for_identity(
                &identity,
                MOOT,
                &MootEvent::Shared {
                    manifest_id: [0xaa; 32],
                    schema_id: "fleece/v1".into(),
                    title: "withdrawn page".into(),
                    at_ms: 1,
                },
            )
            .await
            .unwrap();
        let withdrawal = store
            .author_for_identity(
                &identity,
                MOOT,
                &MootEvent::Withdrawn {
                    target_share: *share.hash.as_bytes(),
                    at_ms: 2,
                },
            )
            .await
            .unwrap();
        let checkpoint = store.build_checkpoint(MOOT, 3).await.unwrap();
        let checkpoint_operation = store
            .author(
                &authority,
                MOOT,
                &MootEvent::RetentionCheckpoint {
                    checkpoint: Box::new(checkpoint),
                },
            )
            .await
            .unwrap();
        store
            .author_prune_seed(
                identity
                    .derive_keypair(&object_identity_salt(MOOT))
                    .unwrap()
                    .to_seed(),
                MOOT,
                *checkpoint_operation.hash.as_bytes(),
                4,
            )
            .await
            .unwrap();

        let operations = store.ops(MOOT).await.unwrap();
        assert!(
            !operations
                .iter()
                .any(|operation| operation.hash == share.hash)
        );
        assert!(
            !operations
                .iter()
                .any(|operation| operation.hash == withdrawal.hash)
        );
        let roster = store.roster(MOOT).await.unwrap();
        assert_eq!(roster.fauna.len(), 1);
        assert_eq!(roster.withdrawals.len(), 1);
        assert_eq!(roster.withdrawals[0].target_share, *share.hash.as_bytes());
        assert!(
            roster
                .authorized_fauna(&RootAuthority(identity.master_public_key().to_bytes()))
                .is_empty()
        );
    }

    #[tokio::test]
    async fn checkpoint_keeps_collection_lineage_and_accepts_a_child_after_pruning() {
        use super::super::collection::{
            CollectionChange, CollectionEvent, CollectionFork, CollectionId, CollectionRef,
            ContributionRef,
        };

        let checkpoint_authority = keypair(1);
        let identity = InMemoryProvider::from_seed([0x23; 32]);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("collection-lineage.redb");
        let store = MootStoreFile::at_path_with_retention(
            &path,
            retention(&checkpoint_authority),
        )
        .unwrap();
        let share = store
            .author_for_identity(
                &identity,
                MOOT,
                &MootEvent::Shared {
                    manifest_id: [0xaa; 32],
                    schema_id: "fleece/v1".into(),
                    title: "lineage page".into(),
                    at_ms: 1,
                },
            )
            .await
            .unwrap();
        let collection_id = CollectionId([0xc1; 32]);
        let collection = CollectionRef { moot_id: MOOT, collection_id };
        let declaration = store
            .author_for_identity(
                &identity,
                MOOT,
                &MootEvent::Collection {
                    event: CollectionEvent::Declared {
                        collection_id,
                        name: "field notes".into(),
                        fork: None,
                        at_ms: 2,
                    },
                },
            )
            .await
            .unwrap();
        let first_change = store
            .author_for_identity(
                &identity,
                MOOT,
                &MootEvent::Collection {
                    event: CollectionEvent::Changed {
                        collection,
                        parents: vec![*declaration.hash.as_bytes()],
                        change: CollectionChange::SetMembership {
                            contribution: ContributionRef {
                                moot_id: MOOT,
                                share: *share.hash.as_bytes(),
                            },
                            included: true,
                        },
                        at_ms: 3,
                    },
                },
            )
            .await
            .unwrap();
        let checkpoint = store.build_checkpoint(MOOT, 4).await.unwrap();
        let checkpoint_operation = store
            .author(
                &checkpoint_authority,
                MOOT,
                &MootEvent::RetentionCheckpoint { checkpoint: Box::new(checkpoint) },
            )
            .await
            .unwrap();
        store
            .author_prune_seed(
                identity.derive_keypair(&object_identity_salt(MOOT)).unwrap().to_seed(),
                MOOT,
                *checkpoint_operation.hash.as_bytes(),
                5,
            )
            .await
            .unwrap();

        let operations = store.ops(MOOT).await.unwrap();
        assert!(!operations.iter().any(|operation| operation.hash == declaration.hash));
        assert!(!operations.iter().any(|operation| operation.hash == first_change.hash));
        let retained = store.roster(MOOT).await.unwrap();
        let before = retained
            .authorized_collection(
                MOOT,
                collection_id,
                &RootAuthority(identity.master_public_key().to_bytes()),
            )
            .unwrap();
        assert_eq!(before.heads, vec![*first_change.hash.as_bytes()]);

        drop(store);
        let store = MootStoreFile::at_path_with_retention(
            &path,
            retention(&checkpoint_authority),
        )
        .unwrap();

        let fork_id = CollectionId([0xc2; 32]);
        store
            .author_for_identity(
                &identity,
                MOOT,
                &MootEvent::Collection {
                    event: CollectionEvent::Declared {
                        collection_id: fork_id,
                        name: "forked notes".into(),
                        fork: Some(CollectionFork::new(
                            before.version.clone(),
                            before.selected.clone(),
                        )),
                        at_ms: 6,
                    },
                },
            )
            .await
            .unwrap();
        let forked = store
            .roster(MOOT)
            .await
            .unwrap()
            .authorized_collection(
                MOOT,
                fork_id,
                &RootAuthority(identity.master_public_key().to_bytes()),
            )
            .unwrap();
        assert_eq!(forked.selected, before.selected);
        assert_eq!(forked.fork.unwrap().parent, before.version);

        let child = store
            .author_for_identity(
                &identity,
                MOOT,
                &MootEvent::Collection {
                    event: CollectionEvent::Changed {
                        collection,
                        parents: before.heads,
                        change: CollectionChange::SetMembership {
                            contribution: ContributionRef {
                                moot_id: MOOT,
                                share: *share.hash.as_bytes(),
                            },
                            included: false,
                        },
                        at_ms: 7,
                    },
                },
            )
            .await
            .unwrap();
        let after = store
            .roster(MOOT)
            .await
            .unwrap()
            .authorized_collection(
                MOOT,
                collection_id,
                &RootAuthority(identity.master_public_key().to_bytes()),
            )
            .unwrap();
        assert_eq!(after.heads, vec![*child.hash.as_bytes()]);
        assert!(after.selected.is_empty());
    }

    #[tokio::test]
    async fn reopened_checkpoint_does_not_resurrect_a_late_withdrawn_share() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("withdrawal.redb");
        let authority = keypair(3);
        let identity = InMemoryProvider::from_seed([0x32; 32]);
        let (share, withdrawal) = {
            let store =
                MootStoreFile::at_path_with_retention(&path, retention(&authority)).unwrap();
            let share = store
                .author_for_identity(
                    &identity,
                    MOOT,
                    &MootEvent::Shared {
                        manifest_id: [0xbb; 32],
                        schema_id: "fleece/v1".into(),
                        title: "late page".into(),
                        at_ms: 1,
                    },
                )
                .await
                .unwrap();
            let withdrawal = store
                .author_for_identity(
                    &identity,
                    MOOT,
                    &MootEvent::Withdrawn {
                        target_share: *share.hash.as_bytes(),
                        at_ms: 2,
                    },
                )
                .await
                .unwrap();
            let checkpoint = store.build_checkpoint(MOOT, 3).await.unwrap();
            let checkpoint_operation = store
                .author(
                    &authority,
                    MOOT,
                    &MootEvent::RetentionCheckpoint {
                        checkpoint: Box::new(checkpoint),
                    },
                )
                .await
                .unwrap();
            store
                .author_prune_seed(
                    identity
                        .derive_keypair(&object_identity_salt(MOOT))
                        .unwrap()
                        .to_seed(),
                    MOOT,
                    *checkpoint_operation.hash.as_bytes(),
                    4,
                )
                .await
                .unwrap();
            (share, withdrawal)
        };

        let reopened = MootStoreFile::at_path_with_retention(&path, retention(&authority)).unwrap();
        let roster = reopened.roster(MOOT).await.unwrap();
        assert_eq!(roster.fauna.len(), 1);
        assert_eq!(roster.withdrawals.len(), 1);
        assert!(
            reopened.accept(MOOT, &share).await.is_err(),
            "a late prefix replay cannot pass the retained prune point"
        );
        assert!(
            reopened
                .roster(MOOT)
                .await
                .unwrap()
                .authorized_fauna(&RootAuthority(identity.master_public_key().to_bytes()))
                .is_empty()
        );
        assert_eq!(withdrawal.header.seq_num, 1);
    }

    /// The intake paths do NOT all return the same decision, and that is
    /// deliberate — this pins the one place they diverge so it cannot be
    /// "cleaned up" into agreement.
    ///
    /// `MootPolicy` carries `allow_historical_checkpoint_authority` and
    /// `allow_historical_prune`: `false` for live processing and plain-drop
    /// import, `true` for the aggregate carrier. An aggregate drop bootstraps
    /// a fresh peer *through a rotated checkpoint chain*, so it must accept a
    /// prune naming a checkpoint that has since been superseded — exactly what
    /// live intake must reject as stale, because on a live peer that prune
    /// would destroy history against outdated authority.
    ///
    /// One store, one operation, two paths, two answers. Phase B's "same
    /// decision for one operation corpus" holds for everything else.
    #[tokio::test]
    async fn aggregate_import_admits_the_historical_prune_that_live_intake_rejects() {
        let authority = keypair(1);
        let store = MootStore::in_memory_with_retention(retention(&authority));
        store
            .author(
                &authority,
                MOOT,
                &MootEvent::Declared {
                    name: "printing circle".into(),
                    charter: "shared type".into(),
                    at_ms: 1,
                },
            )
            .await
            .unwrap();
        let joined = store
            .author(
                &authority,
                MOOT,
                &MootEvent::Joined {
                    name: "mark".into(),
                    at_ms: 2,
                },
            )
            .await
            .unwrap();

        // Two checkpoints: the second supersedes the first, so a prune naming
        // the first is historical.
        let first = store.build_checkpoint(MOOT, 10).await.unwrap();
        let superseded = store
            .author(
                &authority,
                MOOT,
                &MootEvent::RetentionCheckpoint {
                    checkpoint: Box::new(first),
                },
            )
            .await
            .unwrap();
        let second = store.build_checkpoint(MOOT, 20).await.unwrap();
        store
            .author(
                &authority,
                MOOT,
                &MootEvent::RetentionCheckpoint {
                    checkpoint: Box::new(second),
                },
            )
            .await
            .unwrap();

        // Build the prune WITHOUT accepting it: checkpoints ride their own
        // log, so the events log still ends at `joined`.
        let prune = to_prune_operation_seed(
            authority.to_seed(),
            MOOT,
            *superseded.hash.as_bytes(),
            30,
            joined.header.seq_num + 1,
            Some(*joined.hash.as_bytes()),
        );

        // Live intake: refused, and nothing moved.
        let before = store.ops(MOOT).await.unwrap().len();
        let error = store
            .accept(MOOT, &prune)
            .await
            .expect_err("live intake rejects a prune against superseded authority");
        assert!(
            format!("{error}").contains("checkpoint-stale")
                || format!("{error:?}").contains("checkpoint-stale"),
            "rejected for staleness, not something incidental: {error:?}"
        );
        assert_eq!(
            store.ops(MOOT).await.unwrap().len(),
            before,
            "a refused prune leaves the live store unchanged"
        );

        // The aggregate carrier: the same operation, admitted, because a
        // bootstrapping peer has to walk the whole rotated chain.
        let report = store
            .import_drop_records(
                MOOT,
                stickleback::DropId([0x0d; 32]),
                vec![stickleback::operation_record(&prune, true)],
            )
            .await
            .expect("the aggregate carrier admits historical prune ancestry");
        assert_eq!(report.accepted, 1, "the divergence is real: {report:?}");
    }

    #[tokio::test]
    async fn unauthorized_checkpoint_is_rejected_before_mutation() {
        let authority = keypair(1);
        let intruder = keypair(2);
        let store = MootStore::in_memory_with_retention(retention(&authority));
        let checkpoint = store.build_checkpoint(MOOT, 10).await.unwrap();
        let operation = super::super::wire::to_operation(
            &intruder,
            MOOT,
            &MootEvent::RetentionCheckpoint {
                checkpoint: Box::new(checkpoint),
            },
            0,
            None,
        );
        assert!(store.accept(MOOT, &operation).await.is_err());
        assert!(store.ops(MOOT).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn file_store_survives_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("moot.redb");
        let authority = keypair(1);
        {
            let store = MootStoreFile::at_path(&path).unwrap();
            store
                .author(
                    &authority,
                    MOOT,
                    &MootEvent::Joined {
                        name: "mark".into(),
                        at_ms: 1,
                    },
                )
                .await
                .unwrap();
        }
        let reopened = MootStoreFile::at_path(path).unwrap();
        assert_eq!(reopened.roster(MOOT).await.unwrap().members.len(), 1);
    }
}
