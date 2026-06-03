//! The tessera operation store, redb-backed.
//!
//! [`TesseraStore`] persists a moot's tessera operations in a single redb file
//! (or in memory). An operation is stored as its canonical form — the signed
//! [`Header`] plus the CBOR body — keyed by hash; alongside it the store
//! maintains the per-author-log and topic indexes (see
//! [`log_store`](super::log_store)) so it doubles as the p2panda-net `LogStore` +
//! `TopicStore` that LogSync reconciles. One store of record, one write path
//! ([`insert`](TesseraStore::insert)), serving both the [projection]
//! ([`fold_moot`](TesseraStore::fold_moot)) and sync. This is the shape
//! murmuring's `PersistentCabalStore` gives the cabal post store.
//!
//! [projection]: super::ledger
//!
//! ## Projection
//!
//! A moot's reputation is the fold of *every* member's tessera log, not one
//! author's. [`fold_moot`](TesseraStore::fold_moot) resolves the moot's
//! `(author, log)` pairs, reads each log's operations, decodes them to
//! [`TesseraEvent`]s, orders them deterministically (by asserted time, then
//! author, then log position — so every peer folds the same events the same
//! way), and runs the [`Ledger`]. The clock stays the caller's: it returns a
//! `Ledger`, and the host asks it for `scores(now_ms)`.

use std::path::Path;
use std::sync::Arc;

use p2panda_core::cbor::{decode_cbor, encode_cbor};
use p2panda_core::{Body, Hash, Header, Operation};
use redb::{Database, ReadTransaction, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};

use crate::tessera::event::TesseraEvent;
use crate::tessera::ledger::{Ledger, TesseraConfig};
use crate::tessera::log_store::{
    create_index_tables, index_op_in_txn, log_prefix, seq_from_key, with_seq, LOG_TOPICS,
    OPS_BY_LOG,
};
use crate::tessera::wire::{from_operation, TesseraExt};

/// `hash(32)` → stored operation (CBOR header + body). `pub(crate)` so the sync
/// layer ([`log_store`](super::log_store)) can read operations back.
pub(crate) const OPS: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("tessera_ops");

/// A tessera store failure.
#[derive(Debug, thiserror::Error)]
pub enum TesseraStoreError {
    /// The redb backend failed.
    #[error("tessera store backend: {0}")]
    Backend(String),
    /// CBOR encode / decode of a stored operation failed.
    #[error("tessera store cbor: {0}")]
    Cbor(String),
    /// A stored key was malformed (wrong length / not a valid key).
    #[error("tessera store key: {0}")]
    Key(String),
    /// A stored operation did not decode to a valid tessera event.
    #[error("malformed tessera operation")]
    Malformed,
}

/// Map a redb (or other backend) error into [`TesseraStoreError::Backend`].
pub(crate) fn be(e: impl std::fmt::Display) -> TesseraStoreError {
    TesseraStoreError::Backend(e.to_string())
}
fn ce(e: impl std::fmt::Display) -> TesseraStoreError {
    TesseraStoreError::Cbor(e.to_string())
}

/// The stored form of an operation: the signed header and the optional CBOR
/// body. The hash is recomputed from the header on read (it is the header's
/// hash), so it is not stored twice.
#[derive(Serialize, Deserialize)]
struct StoredOp {
    header: Header<TesseraExt>,
    body: Option<Vec<u8>>,
}

fn encode_op(op: &Operation<TesseraExt>) -> Result<Vec<u8>, TesseraStoreError> {
    let stored = StoredOp {
        header: op.header.clone(),
        body: op.body.as_ref().map(|b| b.to_bytes()),
    };
    encode_cbor(&stored).map_err(ce)
}

fn decode_op(bytes: &[u8]) -> Result<Operation<TesseraExt>, TesseraStoreError> {
    let stored: StoredOp = decode_cbor(bytes).map_err(ce)?;
    let hash = stored.header.hash();
    Ok(Operation {
        hash,
        header: stored.header,
        body: stored.body.map(Body::from),
    })
}

/// A redb-backed store for one moot's tessera operations.
///
/// `Clone` shares the same underlying redb database (cheap `Arc` clone), so a
/// clone handed to `LogSync::builder` reads and writes the same store.
#[derive(Clone)]
pub struct TesseraStore {
    pub(crate) db: Arc<Database>,
}

/// Touch the op + sync-index tables so they exist before the first read, even if
/// nothing is inserted. Shared by [`open`](TesseraStore::open) and
/// [`in_memory`](TesseraStore::in_memory).
fn init_tables(db: &Database) -> Result<(), TesseraStoreError> {
    let txn = db.begin_write().map_err(be)?;
    {
        txn.open_table(OPS).map_err(be)?;
        create_index_tables(&txn)?;
    }
    txn.commit().map_err(be)?;
    Ok(())
}

impl TesseraStore {
    /// Open or create a redb file at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, TesseraStoreError> {
        let db = Database::create(path).map_err(be)?;
        init_tables(&db)?;
        Ok(Self { db: Arc::new(db) })
    }

    /// Open an **in-memory** tessera store (redb's in-memory backend). Same
    /// schema and trait impls as [`open`](Self::open), nothing persisted.
    pub fn in_memory() -> Result<Self, TesseraStoreError> {
        let db = Database::builder()
            .create_with_backend(redb::backends::InMemoryBackend::new())
            .map_err(be)?;
        init_tables(&db)?;
        Ok(Self { db: Arc::new(db) })
    }

    /// Insert a tessera operation: the op row plus its per-author-log and topic
    /// index rows, atomically. The moot id is the op's *signed* extension, so
    /// authoring and receiving (over sync) share this one write path.
    ///
    /// Returns `Ok(true)` on first insert of a hash, `Ok(false)` if already
    /// present (content addressing: same hash implies same bytes, no overwrite).
    pub fn insert(&self, op: &Operation<TesseraExt>) -> Result<bool, TesseraStoreError> {
        let id_bytes: [u8; 32] = *op.hash.as_bytes();
        let wire = encode_op(op)?;
        let txn = self.db.begin_write().map_err(be)?;
        let inserted;
        {
            let mut ops = txn.open_table(OPS).map_err(be)?;
            if ops.get(&id_bytes).map_err(be)?.is_some() {
                inserted = false;
            } else {
                ops.insert(&id_bytes, wire.as_slice()).map_err(be)?;
                inserted = true;
            }
        }
        if inserted {
            // Same txn, so op bytes and sync indexes commit together. This is
            // what makes the store double as a p2panda LogStore / TopicStore.
            index_op_in_txn(&txn, op)?;
        }
        txn.commit().map_err(be)?;
        Ok(inserted)
    }

    /// Look up an operation by hash.
    pub fn get(&self, hash: &Hash) -> Result<Option<Operation<TesseraExt>>, TesseraStoreError> {
        let read = self.db.begin_read().map_err(be)?;
        self.operation_by_hash(&read, hash.as_bytes())
    }

    /// Whether the store holds an operation with this hash.
    pub fn has(&self, hash: &Hash) -> Result<bool, TesseraStoreError> {
        Ok(self.get(hash)?.is_some())
    }

    /// Total operation count.
    pub fn len(&self) -> Result<usize, TesseraStoreError> {
        let read = self.db.begin_read().map_err(be)?;
        let ops = read.open_table(OPS).map_err(be)?;
        Ok(ops.len().map_err(be)? as usize)
    }

    /// Whether the store holds no operations.
    pub fn is_empty(&self) -> Result<bool, TesseraStoreError> {
        Ok(self.len()? == 0)
    }

    /// Load the [`Operation`] for a stored hash (via the [`OPS`] table). Shared
    /// by the `LogStore` read methods and the projection.
    pub(crate) fn operation_by_hash(
        &self,
        read: &ReadTransaction,
        hash: &[u8; 32],
    ) -> Result<Option<Operation<TesseraExt>>, TesseraStoreError> {
        let ops = read.open_table(OPS).map_err(be)?;
        match ops.get(hash).map_err(be)? {
            None => Ok(None),
            Some(v) => Ok(Some(decode_op(v.value())?)),
        }
    }

    /// Fold every member's tessera log in `moot_id` into the moot's [`Ledger`].
    ///
    /// Reputation is the projection over the whole moot, not one author: this
    /// resolves the moot's `(author, log)` pairs, reads each log, decodes the
    /// operations to events, orders them deterministically (asserted time, then
    /// author, then log position — so every peer folds identically), and runs
    /// the ledger. Ask the returned ledger for `scores(now_ms)`.
    pub fn fold_moot(
        &self,
        moot_id: [u8; 32],
        config: TesseraConfig,
    ) -> Result<Ledger, TesseraStoreError> {
        let read = self.db.begin_read().map_err(be)?;

        // 1. The (author, log) pairs the moot holds.
        let mut logs: Vec<([u8; 32], u64)> = Vec::new();
        {
            let topics = read.open_table(LOG_TOPICS).map_err(be)?;
            for entry in topics.range(moot_id.as_slice()..).map_err(be)? {
                let (k, _v) = entry.map_err(be)?;
                let key = k.value();
                if !key.starts_with(moot_id.as_slice()) {
                    break;
                }
                let author: [u8; 32] = key[32..64]
                    .try_into()
                    .map_err(|_| TesseraStoreError::Key("topic author".into()))?;
                let log_id = u64::from_be_bytes(
                    key[64..72]
                        .try_into()
                        .map_err(|_| TesseraStoreError::Key("topic log_id".into()))?,
                );
                logs.push((author, log_id));
            }
        }

        // 2a. Collect (author, seq, hash) across those logs (hashes first, so the
        // OPS lookups don't overlap the range scan).
        let mut refs: Vec<([u8; 32], u64, [u8; 32])> = Vec::new();
        {
            let by_log = read.open_table(OPS_BY_LOG).map_err(be)?;
            for (author, log_id) in &logs {
                let prefix = log_prefix(author, *log_id);
                let lo = with_seq(&prefix, 0);
                let hi = with_seq(&prefix, u64::MAX);
                for entry in by_log.range(lo.as_slice()..=hi.as_slice()).map_err(be)? {
                    let (k, v) = entry.map_err(be)?;
                    let seq = seq_from_key(k.value());
                    let hash: [u8; 32] = v
                        .value()
                        .try_into()
                        .map_err(|_| TesseraStoreError::Key("log entry hash".into()))?;
                    refs.push((*author, seq, hash));
                }
            }
        }

        // 2b. Resolve each to its tessera event.
        let ops = read.open_table(OPS).map_err(be)?;
        let mut tagged: Vec<(u64, [u8; 32], u64, TesseraEvent)> = Vec::new();
        for (author, seq, hash) in refs {
            if let Some(stored) = ops.get(&hash).map_err(be)? {
                let op = decode_op(stored.value())?;
                let (_moot, event) =
                    from_operation(&op).map_err(|_| TesseraStoreError::Malformed)?;
                tagged.push((event.at_ms(), author, seq, event));
            }
        }

        // 3. Deterministic order, then fold.
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
        let e1 = TesseraEvent::CommitmentFulfilled { by, commitment: cid, at_ms: 1_050 };
        let e2 = TesseraEvent::GovernanceParticipation { by, at_ms: 1_100 };
        let op0 = to_operation(kp, MOOT, &e0, 0, None);
        let op1 = to_operation(kp, MOOT, &e1, 1, Some(*op0.hash.as_bytes()));
        let op2 = to_operation(kp, MOOT, &e2, 2, Some(*op1.hash.as_bytes()));
        [op0, op1, op2]
    }

    #[test]
    fn insert_then_get_round_trips_and_is_idempotent() {
        let store = TesseraStore::in_memory().unwrap();
        let [op0, op1, op2] = commit_fulfil_govern(&keypair(1));
        assert!(store.insert(&op0).unwrap());
        assert!(store.insert(&op1).unwrap());
        assert!(store.insert(&op2).unwrap());
        assert!(!store.insert(&op2).unwrap(), "re-insert is idempotent on the hash");
        assert_eq!(store.len().unwrap(), 3);

        let got = store.get(&op1.hash).unwrap().expect("op stored");
        assert_eq!(got.hash, op1.hash);
        assert!(store.has(&op0.hash).unwrap());
    }

    #[test]
    fn fold_moot_projects_a_single_authors_score() {
        let store = TesseraStore::in_memory().unwrap();
        let kp = keypair(1);
        for op in commit_fulfil_govern(&kp) {
            store.insert(&op).unwrap();
        }
        let ledger = store.fold_moot(MOOT, TesseraConfig::default()).unwrap();
        // +10 fulfil, +1 govern = 11; the commitment is closed, so no lapse.
        assert_eq!(ledger.score(&root_of(&kp), 5_000), 11);
    }

    #[test]
    fn fold_moot_merges_every_members_log() {
        let store = TesseraStore::in_memory().unwrap();
        let alice = keypair(1);
        let bob = keypair(2);
        // Alice: commit -> fulfil -> govern = 11. Bob: one governance = 1.
        for op in commit_fulfil_govern(&alice) {
            store.insert(&op).unwrap();
        }
        let bob_govern = TesseraEvent::GovernanceParticipation {
            by: root_of(&bob),
            at_ms: 1_200,
        };
        store.insert(&to_operation(&bob, MOOT, &bob_govern, 0, None)).unwrap();

        let ledger = store.fold_moot(MOOT, TesseraConfig::default()).unwrap();
        assert_eq!(ledger.score(&root_of(&alice), 5_000), 11);
        assert_eq!(ledger.score(&root_of(&bob), 5_000), 1);
    }

    #[test]
    fn fold_moot_ignores_a_foreign_moot() {
        let store = TesseraStore::in_memory().unwrap();
        let kp = keypair(1);
        for op in commit_fulfil_govern(&kp) {
            store.insert(&op).unwrap();
        }
        // A different moot id resolves to no logs, so the fold is empty.
        let ledger = store.fold_moot([0xee; 32], TesseraConfig::default()).unwrap();
        assert_eq!(ledger.score(&root_of(&kp), 5_000), 0);
    }

    #[test]
    fn operations_persist_across_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("moot.redb");
        let kp = keypair(1);
        let ops = commit_fulfil_govern(&kp);
        {
            let store = TesseraStore::open(&path).unwrap();
            for op in &ops {
                store.insert(op).unwrap();
            }
            assert_eq!(store.len().unwrap(), 3);
        }
        // Reopen: the log and its projection survive.
        let store = TesseraStore::open(&path).unwrap();
        assert_eq!(store.len().unwrap(), 3);
        let ledger = store.fold_moot(MOOT, TesseraConfig::default()).unwrap();
        assert_eq!(ledger.score(&root_of(&kp), 5_000), 11);
    }
}
