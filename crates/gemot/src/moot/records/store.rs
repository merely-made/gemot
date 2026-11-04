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
            }
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
            }
            _ => {
                if operation.header.extensions.prune_flag.is_set() {
                    return Err(Reject::new(
                        "unexpected-prune-flag",
                        "only a history-pruned event may carry the prune flag",
                    ));
                }
                Ok(Admission::keep(target))
            }
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

#[cfg(test)]
#[path = "store/tests.rs"]
mod tests;

#[path = "store/operations.rs"]
mod operations;
