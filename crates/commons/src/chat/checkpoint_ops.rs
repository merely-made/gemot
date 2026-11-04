// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

impl<B: Backend + Clone> ChatReplica<B> {
    /// Latest checkpoint in the signed header chain; only it is decrypted.
    pub async fn latest_checkpoint(&self) -> Result<Option<StoredChatCheckpoint>, ChatError> {
        latest_checkpoint_from_records(
            self.space_id,
            &self.keys.current(),
            &self.load_retained().await?.checkpoints,
        )
    }

    /// Build, encrypt, sign, authorize, and retain a checkpoint.
    pub async fn author_checkpoint(&mut self) -> Result<Operation<ChatExt>, ChatError> {
        // One snapshot builds and seals, so the named epoch is the sealing one.
        let keys = self.keys.current();
        let retained = self.load_retained().await?;
        let checkpoint = self.build_checkpoint_onto(&keys, &retained)?;
        let entries = causal_entries(&retained.checkpoints);
        let signing_key = SigningKey::from_bytes(&self.signing_seed);
        let author = signing_key.verifying_key();
        let (seq_num, backlink) = author_head(&entries, *author.as_bytes(), &CHAT_CHECKPOINT_LOG)?;
        let record = ChatAuthored::new(checkpoint.clone(), self.author_attestation.clone());
        let plaintext = encode_cbor(&record).map_err(|error| ChatError::Wire(error.to_string()))?;
        let envelope = keys.seal(&plaintext, &p2panda_encryption::Rng::default())?;
        debug_assert_eq!(envelope.epoch, checkpoint.current_epoch);
        let body_bytes =
            encode_cbor(&envelope).map_err(|error| ChatError::Wire(error.to_string()))?;
        let body = Body::from_bytes(&body_bytes);
        // p2panda 0.7.1 made the header's CBOR cache, size and digest private
        // and folded signing into the builder: `build` encodes, signs and
        // caches the digest in one step, so the struct-literal + `sign` pair
        // has no equivalent. The builder derives verifying_key from the
        // signing key -- the same value `author` already held.
        let header = Header::builder()
            .body(&body_bytes)
            .seq_num(seq_num)
            .backlink(backlink.map(Hash::from))
            .build(
                &signing_key,
                ChatExt {
                    space_id: self.space_id,
                    class: ChatClass::Checkpoint,
                    parents: checkpoint.causal_frontier.clone(),
                    checkpoint: Some(ChatCheckpointLink {
                        version: CHAT_CHECKPOINT_VERSION,
                        previous: checkpoint.previous_checkpoint,
                    }),
                },
            );
        let operation = Operation {
            hash: header.hash(),
            header,
            body: Some(body),
        };
        self.accept_onto(&operation, retained).await?;
        Ok(operation)
    }

    /// Construct the checkpoint candidate without mutating the store.
    pub async fn build_checkpoint(&self) -> Result<ChatCheckpoint, ChatError> {
        let retained = self.load_retained().await?;
        self.build_checkpoint_onto(&self.keys.current(), &retained)
    }

    pub(super) fn build_checkpoint_onto(
        &self,
        keys: &DataKeyring,
        retained: &RetainedChatRecords,
    ) -> Result<ChatCheckpoint, ChatError> {
        let authority = self.checkpoint_authority.as_ref().ok_or_else(|| {
            ChatError::Checkpoint("checkpoint authority is not configured".into())
        })?;
        if !authority.permits_checkpoint(self.stable_author, &authority.authority_revision()) {
            return Err(ChatError::Checkpoint(
                "local signer is not the current checkpoint authority".into(),
            ));
        }
        let previous = latest_checkpoint_from_records(self.space_id, keys, &retained.checkpoints)?;
        // Retention commits retained facts, not the current authority verdict:
        // the covered-author index lets a later capability change reach them.
        let content = checkpoint_content(
            keys,
            self.space_id,
            &retained.data,
            previous.as_ref().map(|stored| &stored.checkpoint),
        )?;

        let by_operation: BTreeMap<_, _> = retained
            .data
            .iter()
            .map(|record| (*record.operation.hash.as_bytes(), record))
            .collect();
        let mut pending_by_epoch = BTreeMap::<GroupSecretId, Vec<[u8; 32]>>::new();
        for pending in &content.pending {
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

        let epoch_inventory = keys
            .epochs_oldest_first()
            .ok_or_else(|| {
                ChatError::Checkpoint(
                    "checkpoint construction requires proven epoch chronology".into(),
                )
            })?
            .to_vec();
        let current_epoch = keys
            .current_epoch()
            .ok_or(GroupCryptoError::MissingCurrentEpoch)?;
        let snapshot_commitment = ChatCheckpoint::snapshot_commitment(&content.snapshot)?;
        Ok(ChatCheckpoint {
            version: CHAT_CHECKPOINT_VERSION,
            space_id: self.space_id,
            authority_revision: authority.authority_revision(),
            previous_checkpoint: previous.map(|stored| stored.operation),
            causal_frontier: content.causal_frontier,
            author_frontiers: content.author_frontiers,
            epoch_inventory,
            current_epoch,
            holds,
            snapshot: content.snapshot,
            snapshot_commitment,
        })
    }

    /// Compute the dry-run epoch proposal from Commons-owned retention facts.
    pub async fn epoch_pruning_proposal(
        &self,
        offline_members: &[OfflineMemberEpochHold],
    ) -> Result<EpochPruningProposal, ChatError> {
        let keys = self.keys.current();
        let retained = self.load_retained().await?;
        let stored = latest_checkpoint_from_records(self.space_id, &keys, &retained.checkpoints)?;
        let mut holds = Vec::new();
        let checkpoint = if let Some(stored) = stored {
            let authority = self.checkpoint_authority.as_ref().ok_or_else(|| {
                ChatError::Checkpoint(
                    "checkpoint authority must be configured before proposing retention".into(),
                )
            })?;
            let covered: BTreeSet<_> = covered_operations(&stored.checkpoint).collect();
            let mut retained_operations = BTreeSet::new();
            for record in &retained.data {
                let operation = *record.operation.hash.as_bytes();
                retained_operations.insert(operation);
                // Replay decrypts only what the checkpoint does not cover.
                if !covered.contains(&operation) {
                    holds.push(EpochHold {
                        epoch: encrypted_body(&record.operation)?.epoch,
                        reason: EpochHoldReason::DecryptionReachability,
                    });
                }
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
            // Replay orders the tail around every covered record's header.
            let author_continuation_ready = covered.is_subset(&retained_operations);
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
            &keys,
            &EpochRetentionFacts { checkpoint, holds },
        ))
    }

    /// What chat's retained records still need and what chat alone could
    /// release, for the host's [`crate::pruning::release_epochs`]. The host,
    /// not chat, forgets epochs in its group session and refreshes the handle.
    pub async fn epoch_report(
        &self,
        offline_members: &[OfflineMemberEpochHold],
    ) -> Result<LaneEpochReport, ChatError> {
        let proposal = self.epoch_pruning_proposal(offline_members).await?;
        let needed = proposal
            .retain
            .iter()
            .flat_map(|retained| {
                retained.reasons.iter().map(|reason| EpochNeed {
                    epoch: retained.epoch,
                    reason: match reason {
                        EpochRetentionReason::Current => EpochNeedReason::Current,
                        other => EpochNeedReason::Chat(other.clone()),
                    },
                })
            })
            .collect();
        Ok(LaneEpochReport {
            lane: COMMONS_CHAT_LANE,
            needed,
            releasable: proposal.forget,
        })
    }

    pub async fn offline_member_recovery(
        &self,
        required_epoch: GroupSecretId,
    ) -> Result<OfflineMemberRecovery, ChatError> {
        if self.keys.current().contains(&required_epoch) {
            return Ok(OfflineMemberRecovery::Resume);
        }
        Ok(OfflineMemberRecovery::BootstrapRequired {
            checkpoint: self
                .latest_checkpoint()
                .await?
                .map(|stored| Digest::p2panda_operation(stored.operation)),
        })
    }

    pub(super) async fn load_operations(&self) -> Result<Vec<StoredChatOperation>, ChatError> {
        load_operations_from_store(&self.store, self.space_id).await
    }

    pub(super) async fn load_retained(&self) -> Result<RetainedChatRecords, ChatError> {
        Ok(split_chat_records(self.load_operations().await?))
    }
}
