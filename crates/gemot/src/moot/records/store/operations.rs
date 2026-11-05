// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

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
        let operation = self.prepare_for_identity(identity, moot_id, event).await?;
        self.accept(moot_id, &operation).await?;
        Ok(operation)
    }

    /// Prepare a signed command for domain validation before it is persisted.
    pub async fn prepare_for_identity<P: IdentityProvider + ?Sized>(
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

    pub(super) fn latest_checkpoint_from_ops(
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

    pub(super) fn checkpoint_index(
        operations: &[Operation<MootExt>],
    ) -> BTreeMap<[u8; 32], RetentionCheckpoint> {
        operations
            .iter()
            .filter_map(|operation| match from_operation(operation).ok()?.1 {
                MootEvent::RetentionCheckpoint { checkpoint } => {
                    Some((*operation.hash.as_bytes(), *checkpoint))
                }
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
