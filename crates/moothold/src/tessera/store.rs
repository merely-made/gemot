//! The tessera operation store, over the muniment substrate.
//!
//! [`TesseraStore`] persists a moot's tessera operations through
//! [`mooting::MunimentStore`], the shared p2panda-store adapter murm and mesh
//! also ride: one operation store that doubles as the `LogStore` + `TopicStore`
//! LogSync reconciles, keyed and folded the same way across all three. One store
//! of record, one write path ([`insert`](TesseraStore::insert)), serving both the
//! projection ([`fold_moot`](TesseraStore::fold_moot)) and sync.
//!
//! Backed by muniment: an in-memory floor for tests, redb on a device (the
//! [`TesseraFileStore`] alias). When the browser backends land (OPFS + IndexedDB),
//! a moot's reputation log rides them with no change here.
//!
//! ## Projection
//!
//! A moot's reputation is the fold of *every* member's tessera log, not one
//! author's. [`fold_moot`](TesseraStore::fold_moot) resolves the moot's
//! `(author, log)` pairs, reads each log's operations, decodes them to
//! [`TesseraEvent`]s, orders them deterministically (by asserted time, then
//! author, then log position — so every peer folds the same events the same way),
//! and runs the [`Ledger`]. The clock stays the caller's: it returns a `Ledger`,
//! and the host asks it for `scores(now_ms)`.

use std::collections::BTreeMap;
use std::path::Path;

use mooting::MunimentStore;
use muniment::{Backend, MemoryBackend, RedbBackend, StoreError};
use p2panda_core::{Hash, Operation, Topic, VerifyingKey};
use p2panda_store::logs::LogStore;
use p2panda_store::operations::OperationStore;
use p2panda_store::topics::TopicStore;

use crate::tessera::event::TesseraEvent;
use crate::tessera::ledger::{Ledger, TesseraConfig};
use crate::tessera::wire::{TesseraExt, from_operation};

/// The single per-moot tessera log id: each author keeps one tessera log per moot,
/// so the log id is a constant and the moot id is the topic.
const LOG_ID: u64 = 0;

/// A tessera store failure.
#[derive(Debug, thiserror::Error)]
pub enum TesseraStoreError {
    /// The muniment backend or the store adapter failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// A stored operation did not decode to a valid tessera event.
    #[error("malformed tessera operation")]
    Malformed,
}

/// A tessera operation store over a muniment backend `B`.
///
/// `Clone` shares the same backend handle, so a clone handed to `LogSync::builder`
/// reads and writes the same store.
#[derive(Clone)]
pub struct TesseraStore<B> {
    store: MunimentStore<B, TesseraExt>,
}

/// The durable, redb-backed tessera store — one moot's reputation log on disk.
pub type TesseraFileStore = TesseraStore<RedbBackend>;

impl TesseraStore<MemoryBackend> {
    /// An in-memory tessera store (tests, rehearsals). Nothing persisted.
    pub fn in_memory() -> Self {
        Self {
            store: MunimentStore::new(MemoryBackend::new()),
        }
    }
}

impl TesseraStore<RedbBackend> {
    /// Open or create a redb-backed tessera store at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, TesseraStoreError> {
        Ok(Self {
            store: MunimentStore::new(RedbBackend::open(path)?),
        })
    }
}

impl<B: Backend + Clone> TesseraStore<B> {
    /// A clone of the underlying store, for `LogSync::builder` (which takes the
    /// store by value and reconciles through its trait surface).
    pub fn sync_store(&self) -> MunimentStore<B, TesseraExt> {
        self.store.clone()
    }
}

impl<B: Backend> TesseraStore<B> {
    /// Insert a tessera operation: associate the moot topic with the author's log,
    /// then store the op with its log entry. The moot id is the op's *signed*
    /// extension, so authoring and receiving (over sync) share this one write path.
    ///
    /// Returns `Ok(true)` on first insert of a hash, `Ok(false)` if already present
    /// (content addressing: same hash implies same bytes, no overwrite).
    pub async fn insert(&self, op: &Operation<TesseraExt>) -> Result<bool, TesseraStoreError> {
        let moot_id = op.header.extensions.moot_id;
        self.store
            .associate(&Topic::from(moot_id), &op.header.verifying_key, &LOG_ID)
            .await?;
        Ok(self.store.insert_operation(&op.hash, op, &LOG_ID).await?)
    }

    /// Look up an operation by hash.
    pub async fn get(
        &self,
        hash: &Hash,
    ) -> Result<Option<Operation<TesseraExt>>, TesseraStoreError> {
        Ok(self.store.get_operation(hash).await?)
    }

    /// Whether the store holds an operation with this hash.
    pub async fn has(&self, hash: &Hash) -> Result<bool, TesseraStoreError> {
        Ok(self.store.has_operation(hash).await?)
    }

    /// Total operation count.
    pub async fn len(&self) -> Result<usize, TesseraStoreError> {
        Ok(self.store.operation_count().await?)
    }

    /// Whether the store holds no operations.
    pub async fn is_empty(&self) -> Result<bool, TesseraStoreError> {
        Ok(self.store.is_empty().await?)
    }

    /// Fold every member's tessera log in `moot_id` into the moot's [`Ledger`].
    ///
    /// Reputation is the projection over the whole moot, not one author: this
    /// resolves the moot's `(author, log)` pairs, reads each log, decodes the
    /// operations to events, orders them deterministically (asserted time, then
    /// author, then log position — so every peer folds identically), and runs the
    /// ledger. Ask the returned ledger for `scores(now_ms)`.
    pub async fn fold_moot(
        &self,
        moot_id: [u8; 32],
        config: TesseraConfig,
    ) -> Result<Ledger, TesseraStoreError> {
        let logs: BTreeMap<VerifyingKey, Vec<u64>> =
            self.store.resolve(&Topic::from(moot_id)).await?;

        // Collect (asserted time, author, log position, event) across every log.
        let mut tagged: Vec<(u64, [u8; 32], u64, TesseraEvent)> = Vec::new();
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
                        from_operation(&op).map_err(|_| TesseraStoreError::Malformed)?;
                    tagged.push((event.at_ms(), author_bytes, seq, event));
                }
            }
        }

        // Deterministic order, then fold.
        tagged.sort_by(|a, b| (a.0, a.1, a.2).cmp(&(b.0, b.1, b.2)));
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
    use crate::tessera::event::{ChainRoot, CommitmentId, Scope};
    use crate::tessera::wire::to_operation;
    use identity::{Ed25519Keypair, IdentityProvider, InMemoryProvider};
    use tempfile::tempdir;

    const MOOT: [u8; 32] = [0x30; 32];

    fn keypair(seed: u8) -> Ed25519Keypair {
        InMemoryProvider::from_seed([seed; 32])
            .derive_keypair(b"tessera-store-test")
            .unwrap()
    }

    fn root_of(kp: &Ed25519Keypair) -> ChainRoot {
        ChainRoot(kp.public_key().to_bytes())
    }

    /// Author a `commit -> fulfil -> govern` log for `kp`, returning the three
    /// signed operations (a chained per-author log).
    fn commit_fulfil_govern(kp: &Ed25519Keypair) -> [Operation<TesseraExt>; 3] {
        let by = root_of(kp);
        let cid = CommitmentId([0xc1; 32]);
        let e0 = TesseraEvent::CommitmentMade {
            by,
            commitment: cid,
            scope: Scope("host/cluster".into()),
            cadence_ms: 1_000,
            duration_ms: None,
            at_ms: 1_000,
        };
        let e1 = TesseraEvent::CommitmentFulfilled {
            by,
            commitment: cid,
            at_ms: 1_050,
        };
        let e2 = TesseraEvent::GovernanceParticipation { by, at_ms: 1_100 };
        let op0 = to_operation(kp, MOOT, &e0, 0, None);
        let op1 = to_operation(kp, MOOT, &e1, 1, Some(*op0.hash.as_bytes()));
        let op2 = to_operation(kp, MOOT, &e2, 2, Some(*op1.hash.as_bytes()));
        [op0, op1, op2]
    }

    #[tokio::test]
    async fn insert_then_get_round_trips_and_is_idempotent() {
        let store = TesseraStore::in_memory();
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
    async fn fold_moot_projects_a_single_authors_score() {
        let store = TesseraStore::in_memory();
        let kp = keypair(1);
        for op in commit_fulfil_govern(&kp) {
            store.insert(&op).await.unwrap();
        }
        let ledger = store
            .fold_moot(MOOT, TesseraConfig::default())
            .await
            .unwrap();
        // +10 fulfil, +1 govern = 11; the commitment is closed, so no lapse.
        assert_eq!(ledger.score(&root_of(&kp), 5_000), 11);
    }

    #[tokio::test]
    async fn fold_moot_merges_every_members_log() {
        let store = TesseraStore::in_memory();
        let alice = keypair(1);
        let bob = keypair(2);
        // Alice: commit -> fulfil -> govern = 11. Bob: one governance = 1.
        for op in commit_fulfil_govern(&alice) {
            store.insert(&op).await.unwrap();
        }
        let bob_govern = TesseraEvent::GovernanceParticipation {
            by: root_of(&bob),
            at_ms: 1_200,
        };
        store
            .insert(&to_operation(&bob, MOOT, &bob_govern, 0, None))
            .await
            .unwrap();

        let ledger = store
            .fold_moot(MOOT, TesseraConfig::default())
            .await
            .unwrap();
        assert_eq!(ledger.score(&root_of(&alice), 5_000), 11);
        assert_eq!(ledger.score(&root_of(&bob), 5_000), 1);
    }

    #[tokio::test]
    async fn fold_moot_ignores_a_foreign_moot() {
        let store = TesseraStore::in_memory();
        let kp = keypair(1);
        for op in commit_fulfil_govern(&kp) {
            store.insert(&op).await.unwrap();
        }
        // A different moot id resolves to no logs, so the fold is empty.
        let ledger = store
            .fold_moot([0xee; 32], TesseraConfig::default())
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
            let store = TesseraStore::open(&path).unwrap();
            for op in &ops {
                store.insert(op).await.unwrap();
            }
            assert_eq!(store.len().await.unwrap(), 3);
        }
        // Reopen: the log and its projection survive.
        let store = TesseraStore::open(&path).unwrap();
        assert_eq!(store.len().await.unwrap(), 3);
        let ledger = store
            .fold_moot(MOOT, TesseraConfig::default())
            .await
            .unwrap();
        assert_eq!(ledger.score(&root_of(&kp), 5_000), 11);
    }
}
