// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The standing operation store, over the muniment substrate.
//!
//! [`StandingStore`] persists a moot's standing operations through
//! [`stickleback::MunimentStore`], the shared p2panda-store adapter murm and mesh
//! also ride: one operation store that doubles as the `LogStore` + `TopicStore`
//! LogSync reconciles, keyed and folded the same way across all three. One store
//! of record, one write path ([`insert`](StandingStore::insert)), serving both the
//! projection ([`fold_moot`](StandingStore::fold_moot)) and sync.
//!
//! Backed by muniment: an in-memory floor for tests, redb on a device (the
//! [`StandingFileStore`] alias). When the browser backends land (OPFS + IndexedDB),
//! a moot's reputation log rides them with no change here.
//!
//! ## Projection
//!
//! A moot's reputation is the fold of *every* member's standing log, not one
//! author's. [`fold_moot`](StandingStore::fold_moot) resolves the moot's
//! `(author, log)` pairs, reads each log's operations, decodes them to
//! [`StandingEvent`]s, orders them deterministically (by asserted time, then
//! author, then log position — so every peer folds the same events the same way),
//! and runs the [`Ledger`]. The clock stays the caller's: it returns a `Ledger`,
//! and the host asks it for `scores(now_ms)`.

use std::collections::BTreeMap;
use std::path::Path;

use muniment::{Backend, MemoryBackend, RedbBackend, StoreError};
use p2panda_core::{Hash, Operation, Topic, VerifyingKey};
use p2panda_store::logs::LogStore;
use p2panda_store::topics::TopicStore;
use stickleback::{
    Admission, MunimentStore, OperationPolicy, OperationProcessor, ProcessError, Reject,
    StoreTarget,
};

use crate::moot::standing::event::StandingEvent;
use crate::moot::standing::ledger::{Ledger, StandingConfig};
use crate::moot::standing::wire::{StandingExt, from_operation, to_operation_seed};

/// The single per-moot standing log id: each author keeps one standing log per moot,
/// so the log id is a constant and the moot id is the topic.
const LOG_ID: u64 = 0;

/// A standing store failure.
#[derive(Debug, thiserror::Error)]
pub enum StandingStoreError {
    /// The muniment backend or the store adapter failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The shared policy-before-insert processor rejected or could not store
    /// the operation.
    #[error(transparent)]
    Process(#[from] ProcessError),
    /// A stored operation did not decode to a valid standing event.
    #[error("malformed standing operation")]
    Malformed,
}

/// Standing's current wire-level admission policy.
///
/// It binds every operation to the expected Moot, requires a decodable
/// [`StandingEvent`], and selects the one per-author Standing log. The shared
/// processor performs signature, payload, continuity, idempotence, and atomic
/// indexed-write checks before this policy runs. Moot membership, constitution,
/// and moderation authorization deliberately remain a later Moot-domain policy
/// rather than being inferred from reputation events.
#[derive(Clone, Copy)]
struct StandingPolicy {
    moot_id: [u8; 32],
}

impl OperationPolicy<StandingExt> for StandingPolicy {
    type LogId = u64;

    fn admit(&self, operation: &Operation<StandingExt>) -> Result<Admission<Self::LogId>, Reject> {
        if operation.header.extensions.moot_id != self.moot_id {
            return Err(Reject::new(
                "wrong-moot",
                "operation addresses a different moot",
            ));
        }
        from_operation(operation).map_err(|_| {
            Reject::new(
                "invalid-standing-event",
                "operation body is not a Standing event",
            )
        })?;
        Ok(Admission::keep(StoreTarget::new(
            Topic::from(self.moot_id),
            LOG_ID,
        )))
    }
}

/// A standing operation store over a muniment backend `B`.
///
/// `Clone` shares the same backend handle, so a clone handed to `LogSync::builder`
/// reads and writes the same store.
#[derive(Clone)]
pub struct StandingStore<B> {
    store: MunimentStore<B, StandingExt>,
}

/// The durable, redb-backed standing store — one moot's reputation log on disk.
pub type StandingFileStore = StandingStore<RedbBackend>;

impl StandingStore<MemoryBackend> {
    /// An in-memory standing store (tests, rehearsals). Nothing persisted.
    pub fn in_memory() -> Self {
        Self {
            store: MunimentStore::new(MemoryBackend::new()),
        }
    }
}

impl StandingStore<RedbBackend> {
    /// Open or create a redb-backed standing store at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StandingStoreError> {
        Ok(Self {
            store: MunimentStore::new(RedbBackend::open(path)?),
        })
    }
}

impl<B: Backend + Clone> StandingStore<B> {
    /// Sign and store the next event in this author's per-Moot Standing log.
    /// The returned operation is the explicit host-publication seam.
    pub async fn author_seed(
        &self,
        signing_seed: [u8; 32],
        moot_id: [u8; 32],
        event: &StandingEvent,
    ) -> Result<Operation<StandingExt>, StandingStoreError> {
        let author = p2panda_core::SigningKey::from_bytes(&signing_seed).verifying_key();
        let previous = self.store.get_latest_entry(&author, &LOG_ID).await?;
        let (seq_num, backlink) = match previous {
            Some(operation) => (
                operation.header.seq_num + 1,
                Some(*operation.hash.as_bytes()),
            ),
            None => (0, None),
        };
        let operation = to_operation_seed(signing_seed, moot_id, event, seq_num, backlink);
        self.accept(moot_id, &operation).await?;
        Ok(operation)
    }

    /// A clone of the underlying store, for `LogSync::builder` (which takes the
    /// store by value and reconciles through its trait surface).
    pub fn sync_store(&self) -> MunimentStore<B, StandingExt> {
        self.store.clone()
    }
}

impl<B: Backend + Clone> StandingStore<B> {
    /// Validate and store a standing operation under its signed Moot address.
    ///
    /// Prefer [`accept`](Self::accept) at a session boundary, where an expected
    /// Moot prevents cross-space replay before mutation. This convenience keeps
    /// direct authoring on the same processor path by taking the Moot from the
    /// signed extension.
    pub async fn insert(&self, op: &Operation<StandingExt>) -> Result<bool, StandingStoreError> {
        self.accept(op.header.extensions.moot_id, op).await
    }

    /// Run the shared policy-before-insert path for `moot_id`.
    ///
    /// Returns `true` for a newly admitted operation and `false` for an accepted
    /// duplicate. A wrong-Moot, malformed, invalid, or discontinuous operation
    /// is rejected before the shared store changes.
    pub async fn accept(
        &self,
        moot_id: [u8; 32],
        op: &Operation<StandingExt>,
    ) -> Result<bool, StandingStoreError> {
        let processor = OperationProcessor::new(self.store.clone(), StandingPolicy { moot_id });
        Ok(processor.process(op).await?.inserted())
    }

    /// Look up an operation by hash.
    pub async fn get(
        &self,
        hash: &Hash,
    ) -> Result<Option<Operation<StandingExt>>, StandingStoreError> {
        Ok(self.store.get_operation(hash).await?)
    }

    /// Whether the store holds an operation with this hash.
    pub async fn has(&self, hash: &Hash) -> Result<bool, StandingStoreError> {
        Ok(self.store.has_operation(hash).await?)
    }

    /// Total operation count.
    pub async fn len(&self) -> Result<usize, StandingStoreError> {
        Ok(self.store.operation_count().await?)
    }

    /// Whether the store holds no operations.
    pub async fn is_empty(&self) -> Result<bool, StandingStoreError> {
        Ok(self.store.is_empty().await?)
    }

    /// Fold every member's standing log in `moot_id` into the moot's [`Ledger`].
    ///
    /// Reputation is the projection over the whole moot, not one author: this
    /// resolves the moot's `(author, log)` pairs, reads each log, decodes the
    /// operations to events, orders them deterministically (asserted time, then
    /// author, then log position — so every peer folds identically), and runs the
    /// ledger. Ask the returned ledger for `scores(now_ms)`.
    pub async fn fold_moot(
        &self,
        moot_id: [u8; 32],
        config: StandingConfig,
    ) -> Result<Ledger, StandingStoreError> {
        let logs: BTreeMap<VerifyingKey, Vec<u64>> =
            self.store.resolve(&Topic::from(moot_id)).await?;

        // Collect (asserted time, author, log position, event) across every log.
        let mut tagged: Vec<(u64, [u8; 32], u64, StandingEvent)> = Vec::new();
        for (author, log_ids) in logs {
            let author_bytes = *author.as_bytes();
            for log_id in log_ids {
                let Some(entries) = self
                    .store
                    .get_log_entries(&author, &log_id, None, None)
                    .await?
                else {
                    continue;
                };
                for (op, _header) in entries {
                    let seq = op.header.seq_num;
                    let (_moot, event) =
                        from_operation(&op).map_err(|_| StandingStoreError::Malformed)?;
                    tagged.push((event.at_ms(), author_bytes, u64::from(seq), event));
                }
            }
        }

        // Deterministic order, then fold.
        tagged.sort_by_key(|entry| (entry.0, entry.1, entry.2));
        let mut ledger = Ledger::new(config);
        for (_, _, _, event) in &tagged {
            ledger.apply(event);
        }
        Ok(ledger)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::moot::standing::event::{ChainRoot, CommitmentId, Scope};
    use crate::moot::standing::wire::to_operation;
    use identity::{Ed25519Keypair, IdentityProvider, InMemoryProvider};
    use tempfile::tempdir;

    const MOOT: [u8; 32] = [0x30; 32];

    fn keypair(seed: u8) -> Ed25519Keypair {
        InMemoryProvider::from_seed([seed; 32])
            .derive_keypair(b"standing-store-test")
            .unwrap()
    }

    fn root_of(kp: &Ed25519Keypair) -> ChainRoot {
        ChainRoot(kp.public_key().to_bytes())
    }

    /// Author a `commit -> fulfil -> govern` log for `kp`, returning the three
    /// signed operations (a chained per-author log).
    fn commit_fulfil_govern(kp: &Ed25519Keypair) -> [Operation<StandingExt>; 3] {
        let by = root_of(kp);
        let cid = CommitmentId([0xc1; 32]);
        let e0 = StandingEvent::CommitmentMade {
            by,
            commitment: cid,
            scope: Scope("host/cluster".into()),
            cadence_ms: 1_000,
            duration_ms: None,
            at_ms: 1_000,
        };
        let e1 = StandingEvent::CommitmentFulfilled {
            by,
            commitment: cid,
            at_ms: 1_050,
        };
        let e2 = StandingEvent::GovernanceParticipation { by, at_ms: 1_100 };
        let op0 = to_operation(kp, MOOT, &e0, 0, None);
        let op1 = to_operation(kp, MOOT, &e1, 1, Some(*op0.hash.as_bytes()));
        let op2 = to_operation(kp, MOOT, &e2, 2, Some(*op1.hash.as_bytes()));
        [op0, op1, op2]
    }

    #[tokio::test]
    async fn insert_then_get_round_trips_and_is_idempotent() {
        let store = StandingStore::in_memory();
        let [op0, op1, op2] = commit_fulfil_govern(&keypair(1));
        assert!(store.insert(&op0).await.unwrap());
        assert!(store.insert(&op1).await.unwrap());
        assert!(store.insert(&op2).await.unwrap());
        assert!(
            !store.insert(&op2).await.unwrap(),
            "re-insert is idempotent on the hash"
        );
        assert_eq!(store.len().await.unwrap(), 3);

        let got = store.get(&op1.hash).await.unwrap().expect("op stored");
        assert_eq!(got.hash, op1.hash);
        assert!(store.has(&op0.hash).await.unwrap());
    }

    #[tokio::test]
    async fn expected_moot_rejects_cross_space_replay_before_mutation() {
        let store = StandingStore::in_memory();
        let kp = keypair(1);
        let foreign = to_operation(
            &kp,
            [0xee; 32],
            &StandingEvent::GovernanceParticipation {
                by: root_of(&kp),
                at_ms: 1_000,
            },
            0,
            None,
        );

        assert!(matches!(
            store.accept(MOOT, &foreign).await,
            Err(StandingStoreError::Process(ProcessError::Rejected(
                Reject {
                    code: "wrong-moot",
                    ..
                }
            )))
        ));
        assert!(store.is_empty().await.unwrap());
    }

    #[tokio::test]
    async fn fold_moot_projects_a_single_authors_score() {
        let store = StandingStore::in_memory();
        let kp = keypair(1);
        for op in commit_fulfil_govern(&kp) {
            store.insert(&op).await.unwrap();
        }
        let ledger = store
            .fold_moot(MOOT, StandingConfig::default())
            .await
            .unwrap();
        // +10 fulfil, +1 govern = 11; the commitment is closed, so no lapse.
        assert_eq!(ledger.score(&root_of(&kp), 5_000), 11);
    }

    #[tokio::test]
    async fn fold_moot_merges_every_members_log() {
        let store = StandingStore::in_memory();
        let alice = keypair(1);
        let bob = keypair(2);
        // Alice: commit -> fulfil -> govern = 11. Bob: one governance = 1.
        for op in commit_fulfil_govern(&alice) {
            store.insert(&op).await.unwrap();
        }
        let bob_govern = StandingEvent::GovernanceParticipation {
            by: root_of(&bob),
            at_ms: 1_200,
        };
        store
            .insert(&to_operation(&bob, MOOT, &bob_govern, 0, None))
            .await
            .unwrap();

        let ledger = store
            .fold_moot(MOOT, StandingConfig::default())
            .await
            .unwrap();
        assert_eq!(ledger.score(&root_of(&alice), 5_000), 11);
        assert_eq!(ledger.score(&root_of(&bob), 5_000), 1);
    }

    #[tokio::test]
    async fn fold_moot_ignores_a_foreign_moot() {
        let store = StandingStore::in_memory();
        let kp = keypair(1);
        for op in commit_fulfil_govern(&kp) {
            store.insert(&op).await.unwrap();
        }
        // A different moot id resolves to no logs, so the fold is empty.
        let ledger = store
            .fold_moot([0xee; 32], StandingConfig::default())
            .await
            .unwrap();
        assert_eq!(ledger.score(&root_of(&kp), 5_000), 0);
    }

    #[tokio::test]
    async fn operations_persist_across_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("moot.redb");
        let kp = keypair(1);
        let ops = commit_fulfil_govern(&kp);
        {
            let store = StandingStore::open(&path).unwrap();
            for op in &ops {
                store.insert(op).await.unwrap();
            }
            assert_eq!(store.len().await.unwrap(), 3);
        }
        // Reopen: the log and its projection survive.
        let store = StandingStore::open(&path).unwrap();
        assert_eq!(store.len().await.unwrap(), 3);
        let ledger = store
            .fold_moot(MOOT, StandingConfig::default())
            .await
            .unwrap();
        assert_eq!(ledger.score(&root_of(&kp), 5_000), 11);
    }
}
