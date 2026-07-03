//! p2panda-net sync traits over the tessera operation store.
//!
//! [`TesseraStore`] persists a moot's tessera operations; p2panda-net's LogSync
//! needs that data exposed as *logs* it can reconcile. This module implements the
//! two traits LogSync requires — [`LogStore`] (per-author append-only logs, for
//! offering and serving entries) and [`TopicStore`] (which logs a moot holds) —
//! over that store, so there is **one store of record and one write path**: a
//! tessera operation is the canonical record, served either to the [projection]
//! (folded into scores) or to a peer (over sync). No second operation store, no
//! double-write. It is the same shape murmuring's `cable::log_store` gives the
//! cabal post store.
//!
//! ## Index
//!
//! The store keys operations by hash (see [`store`](super::store)). Sync also
//! needs ordered per-author-log access and topic resolution, so
//! [`index_op_in_txn`] (called inside [`TesseraStore::insert`]'s transaction)
//! maintains two sibling tables:
//!
//! - [`OPS_BY_LOG`]: `author(32) ++ log_id_be(8) ++ seq_be(8)` → `hash(32)`.
//!   Fixed-length key, so a log is a native redb range scan in `seq` order.
//! - [`LOG_TOPICS`]: `moot_id(32) ++ author(32) ++ log_id_be(8)` → `()`. Resolves
//!   a moot (the topic) to the `(author, log)` pairs it holds.
//!
//! ## Log model
//!
//! Each author keeps a single per-moot tessera log, so the log id is always
//! [`LOG_ID`] (`0`) — the per-space granularity murm's store settled on. The
//! topic is the moot id (the operation's signed addressing extension).

use std::collections::BTreeMap;

use p2panda_core::cbor::encode_cbor;
use p2panda_core::{Hash, Operation, Topic, VerifyingKey};
use p2panda_store::logs::LogStore;
use p2panda_store::topics::TopicStore;
use redb::{ReadableTable, TableDefinition, WriteTransaction};

use crate::tessera::store::{OPS, TesseraStore, TesseraStoreError, be};
use crate::tessera::wire::TesseraExt;

/// `author(32) ++ log_id_be(8) ++ seq_be(8)` → `hash(32)` — per-author log
/// entries in `seq` order (native redb range scan).
pub(crate) const OPS_BY_LOG: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("tessera_ops_by_log");
/// `moot_id(32) ++ author(32) ++ log_id_be(8)` → `()` — a moot → its `(author, log)` pairs.
pub(crate) const LOG_TOPICS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("tessera_log_topics");

/// The single per-moot log id (each author keeps one tessera log per moot).
pub(crate) const LOG_ID: u64 = 0;

// ── key helpers ──────────────────────────────────────────────────────────────

/// `author(32) ++ log_id_be(8)` — the prefix shared by all entries of one log.
pub(crate) fn log_prefix(author: &[u8; 32], log_id: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(40);
    k.extend_from_slice(author);
    k.extend_from_slice(&log_id.to_be_bytes());
    k
}

pub(crate) fn with_seq(prefix: &[u8], seq: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(prefix.len() + 8);
    k.extend_from_slice(prefix);
    k.extend_from_slice(&seq.to_be_bytes());
    k
}

pub(crate) fn seq_from_key(key: &[u8]) -> u64 {
    u64::from_be_bytes(key[40..48].try_into().unwrap())
}

fn topics_key(moot_id: &[u8; 32], author: &[u8; 32], log_id: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(72);
    k.extend_from_slice(moot_id);
    k.extend_from_slice(author);
    k.extend_from_slice(&log_id.to_be_bytes());
    k
}

// ── write path (called from TesseraStore::insert) ────────────────────────────

/// Create the sync index tables. Called once from the store constructors so they
/// exist on disk before the first insert.
pub(crate) fn create_index_tables(txn: &WriteTransaction) -> Result<(), TesseraStoreError> {
    txn.open_table(OPS_BY_LOG).map_err(be)?;
    txn.open_table(LOG_TOPICS).map_err(be)?;
    Ok(())
}

/// Index a newly-inserted operation into the per-author log and topic tables,
/// inside the caller's write transaction (so op bytes + indexes commit
/// atomically). The moot id is the operation's *signed* addressing extension, so
/// authoring and receiving share one write path.
///
/// Idempotent at the row level: re-indexing the same `(author, seq)` overwrites
/// with the same hash (content addressing means same hash ⇒ same bytes), and the
/// topic row is a set membership. `insert` only calls this on first insert.
pub(crate) fn index_op_in_txn(
    txn: &WriteTransaction,
    op: &Operation<TesseraExt>,
) -> Result<(), TesseraStoreError> {
    let author = op.header.verifying_key.as_bytes();
    let moot_id = op.header.extensions.moot_id;
    let log_key = with_seq(&log_prefix(author, LOG_ID), op.header.seq_num);
    let topic_key = topics_key(&moot_id, author, LOG_ID);
    let hash = op.hash.as_bytes();
    {
        let mut by_log = txn.open_table(OPS_BY_LOG).map_err(be)?;
        by_log
            .insert(log_key.as_slice(), hash.as_slice())
            .map_err(be)?;
    }
    {
        let mut topics = txn.open_table(LOG_TOPICS).map_err(be)?;
        topics
            .insert(topic_key.as_slice(), [].as_slice())
            .map_err(be)?;
    }
    Ok(())
}

// ── LogStore ─────────────────────────────────────────────────────────────────

impl LogStore<Operation<TesseraExt>, VerifyingKey, u64, u64, Hash> for TesseraStore {
    type Error = TesseraStoreError;

    async fn get_latest_entry(
        &self,
        author: &VerifyingKey,
        log_id: &u64,
    ) -> Result<Option<Operation<TesseraExt>>, Self::Error> {
        let prefix = log_prefix(author.as_bytes(), *log_id);
        let read = self.db.begin_read().map_err(be)?;
        let by_log = read.open_table(OPS_BY_LOG).map_err(be)?;
        let lo = with_seq(&prefix, 0);
        let hi = with_seq(&prefix, u64::MAX);
        let mut range = by_log.range(lo.as_slice()..=hi.as_slice()).map_err(be)?;
        match range.next_back() {
            None => Ok(None),
            Some(entry) => {
                let (_k, v) = entry.map_err(be)?;
                let hash: [u8; 32] = v
                    .value()
                    .try_into()
                    .map_err(|_| TesseraStoreError::Key("log entry hash".into()))?;
                self.operation_by_hash(&read, &hash)
            }
        }
    }

    async fn get_latest_entry_tx(
        &self,
        author: &VerifyingKey,
        log_id: &u64,
    ) -> Result<Option<Operation<TesseraExt>>, Self::Error> {
        // redb opens its own read transaction per call; the `_tx` contract
        // (caller holds the transaction) is a SqliteStore concern.
        self.get_latest_entry(author, log_id).await
    }

    async fn get_log_heights(
        &self,
        author: &VerifyingKey,
        logs: &[u64],
    ) -> Result<Option<BTreeMap<u64, u64>>, Self::Error> {
        let read = self.db.begin_read().map_err(be)?;
        let by_log = read.open_table(OPS_BY_LOG).map_err(be)?;
        let mut map = BTreeMap::new();
        for log_id in logs {
            let prefix = log_prefix(author.as_bytes(), *log_id);
            let lo = with_seq(&prefix, 0);
            let hi = with_seq(&prefix, u64::MAX);
            if let Some(entry) = by_log
                .range(lo.as_slice()..=hi.as_slice())
                .map_err(be)?
                .next_back()
            {
                let (k, _v) = entry.map_err(be)?;
                map.insert(*log_id, seq_from_key(k.value()));
            }
        }
        Ok(if map.is_empty() { None } else { Some(map) })
    }

    async fn get_log_size(
        &self,
        author: &VerifyingKey,
        log_id: &u64,
        after: Option<u64>,
        until: Option<u64>,
    ) -> Result<Option<(u64, u64)>, Self::Error> {
        let prefix = log_prefix(author.as_bytes(), *log_id);
        let lo = with_seq(&prefix, after.map(|a| a + 1).unwrap_or(0));
        let hi = with_seq(&prefix, until.unwrap_or(u64::MAX));
        let read = self.db.begin_read().map_err(be)?;
        let by_log = read.open_table(OPS_BY_LOG).map_err(be)?;
        let ops = read.open_table(OPS).map_err(be)?;
        let mut count = 0u64;
        let mut bytes = 0u64;
        for entry in by_log.range(lo.as_slice()..=hi.as_slice()).map_err(be)? {
            let (_k, v) = entry.map_err(be)?;
            let hash: [u8; 32] = v
                .value()
                .try_into()
                .map_err(|_| TesseraStoreError::Key("log entry hash".into()))?;
            if let Some(stored) = ops.get(&hash).map_err(be)? {
                count += 1;
                // Approximate stored size with the stored op-byte length; the
                // exact header/payload split is not load-bearing for sync.
                bytes += stored.value().len() as u64;
            }
        }
        Ok(if count == 0 {
            None
        } else {
            Some((count, bytes))
        })
    }

    async fn get_log_entries(
        &self,
        author: &VerifyingKey,
        log_id: &u64,
        after: Option<u64>,
        until: Option<u64>,
    ) -> Result<Option<Vec<(Operation<TesseraExt>, Vec<u8>)>>, Self::Error> {
        let prefix = log_prefix(author.as_bytes(), *log_id);
        let lo = with_seq(&prefix, after.map(|a| a + 1).unwrap_or(0));
        let hi = with_seq(&prefix, until.unwrap_or(u64::MAX));
        let read = self.db.begin_read().map_err(be)?;
        let by_log = read.open_table(OPS_BY_LOG).map_err(be)?;
        // Collect hashes first so the OPS lookups don't borrow the range iterator.
        let mut hashes: Vec<[u8; 32]> = Vec::new();
        for entry in by_log.range(lo.as_slice()..=hi.as_slice()).map_err(be)? {
            let (_k, v) = entry.map_err(be)?;
            let hash: [u8; 32] = v
                .value()
                .try_into()
                .map_err(|_| TesseraStoreError::Key("log entry hash".into()))?;
            hashes.push(hash);
        }
        let mut entries = Vec::new();
        for hash in hashes {
            if let Some(operation) = self.operation_by_hash(&read, &hash)? {
                let header_cbor = encode_cbor(&operation.header)
                    .map_err(|e| TesseraStoreError::Cbor(e.to_string()))?;
                entries.push((operation, header_cbor));
            }
        }
        Ok(if entries.is_empty() {
            None
        } else {
            Some(entries)
        })
    }

    async fn prune_entries(
        &self,
        _author: &VerifyingKey,
        _log_id: &u64,
        _until: &u64,
    ) -> Result<u64, Self::Error> {
        // Pruning a tessera log is an open question (the score depends on the
        // whole history, and lapse-and-revive wants durability), and the op
        // bundles header + body in one stored blob, so p2panda's payload-only
        // prune does not map cleanly. No-op for v1: nothing is dropped.
        Ok(0)
    }
}

// ── TopicStore ───────────────────────────────────────────────────────────────

impl TopicStore<Topic, VerifyingKey, u64> for TesseraStore {
    type Error = TesseraStoreError;

    async fn associate(
        &self,
        topic: &Topic,
        author: &VerifyingKey,
        data_id: &u64,
    ) -> Result<bool, Self::Error> {
        let key = topics_key(topic.as_bytes(), author.as_bytes(), *data_id);
        let txn = self.db.begin_write().map_err(be)?;
        let inserted;
        {
            let mut t = txn.open_table(LOG_TOPICS).map_err(be)?;
            if t.get(key.as_slice()).map_err(be)?.is_some() {
                inserted = false;
            } else {
                t.insert(key.as_slice(), [].as_slice()).map_err(be)?;
                inserted = true;
            }
        }
        txn.commit().map_err(be)?;
        Ok(inserted)
    }

    async fn remove(
        &self,
        topic: &Topic,
        author: &VerifyingKey,
        data_id: &u64,
    ) -> Result<bool, Self::Error> {
        let key = topics_key(topic.as_bytes(), author.as_bytes(), *data_id);
        let txn = self.db.begin_write().map_err(be)?;
        let removed;
        {
            let mut t = txn.open_table(LOG_TOPICS).map_err(be)?;
            removed = t.remove(key.as_slice()).map_err(be)?.is_some();
        }
        txn.commit().map_err(be)?;
        Ok(removed)
    }

    async fn resolve(
        &self,
        topic: &Topic,
    ) -> Result<BTreeMap<VerifyingKey, Vec<u64>>, Self::Error> {
        let prefix = topic.as_bytes();
        let read = self.db.begin_read().map_err(be)?;
        let t = read.open_table(LOG_TOPICS).map_err(be)?;
        let mut map: BTreeMap<VerifyingKey, Vec<u64>> = BTreeMap::new();
        for entry in t.range(prefix.as_slice()..).map_err(be)? {
            let (k, _v) = entry.map_err(be)?;
            let key = k.value();
            if !key.starts_with(prefix.as_slice()) {
                break;
            }
            let author_bytes: [u8; 32] = key[32..64]
                .try_into()
                .map_err(|_| TesseraStoreError::Key("topic key author".into()))?;
            let author = VerifyingKey::from_bytes(&author_bytes)
                .map_err(|e| TesseraStoreError::Key(e.to_string()))?;
            let log_id = u64::from_be_bytes(
                key[64..72]
                    .try_into()
                    .map_err(|_| TesseraStoreError::Key("topic key log_id".into()))?,
            );
            map.entry(author).or_default().push(log_id);
        }
        Ok(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tessera::event::{ChainRoot, TesseraEvent};
    use crate::tessera::store::TesseraStore;
    use crate::tessera::wire::to_operation;
    use identity::{Ed25519Keypair, IdentityProvider, InMemoryProvider};

    const MOOT: [u8; 32] = [0x30; 32];

    fn keypair(seed: u8) -> Ed25519Keypair {
        InMemoryProvider::from_seed([seed; 32])
            .derive_keypair(b"tessera-log-store-test")
            .unwrap()
    }

    fn govern(
        kp: &Ed25519Keypair,
        seq: u64,
        backlink: Option<Hash>,
        at_ms: u64,
    ) -> Operation<TesseraExt> {
        let event = TesseraEvent::GovernanceParticipation {
            by: ChainRoot(kp.public_key().to_bytes()),
            at_ms,
        };
        to_operation(kp, MOOT, &event, seq, backlink.map(|h| *h.as_bytes()))
    }

    /// Insert a 3-op chained tessera log, then read it back through the LogStore API.
    #[tokio::test]
    async fn log_entries_round_trip_as_operations() {
        let store = TesseraStore::in_memory().unwrap();
        let kp = keypair(1);
        let author = VerifyingKey::from_bytes(&kp.public_key().to_bytes()).unwrap();

        let op0 = govern(&kp, 0, None, 1);
        let op1 = govern(&kp, 1, Some(op0.hash), 2);
        let op2 = govern(&kp, 2, Some(op1.hash), 3);
        store.insert(&op0).unwrap();
        store.insert(&op1).unwrap();
        store.insert(&op2).unwrap();

        let latest = store
            .get_latest_entry(&author, &LOG_ID)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(latest.hash, op2.hash);

        let heights = store
            .get_log_heights(&author, &[LOG_ID])
            .await
            .unwrap()
            .unwrap();
        assert_eq!(heights.get(&LOG_ID), Some(&2));

        let all = store
            .get_log_entries(&author, &LOG_ID, None, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].0.hash, op0.hash);
        assert_eq!(all[2].0.hash, op2.hash);

        let ranged = store
            .get_log_entries(&author, &LOG_ID, Some(0), None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ranged.len(), 2);
        assert_eq!(ranged[0].0.hash, op1.hash);

        let (count, bytes) = store
            .get_log_size(&author, &LOG_ID, None, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(count, 3);
        assert!(bytes > 0);
    }

    /// The served operations satisfy p2panda's own log validators, so LogSync
    /// will accept what this store serves.
    #[tokio::test]
    async fn served_operations_pass_p2panda_validation() {
        use p2panda_core::operation::{validate_backlink, validate_header};

        let store = TesseraStore::in_memory().unwrap();
        let kp = keypair(2);
        let author = VerifyingKey::from_bytes(&kp.public_key().to_bytes()).unwrap();
        let op0 = govern(&kp, 0, None, 1);
        let op1 = govern(&kp, 1, Some(op0.hash), 2);
        store.insert(&op0).unwrap();
        store.insert(&op1).unwrap();

        let entries = store
            .get_log_entries(&author, &LOG_ID, None, None)
            .await
            .unwrap()
            .unwrap();
        let h0 = &entries[0].0.header;
        let h1 = &entries[1].0.header;
        assert!(validate_header(h0).is_ok());
        assert!(validate_header(h1).is_ok());
        assert!(validate_backlink(h0, h1).is_ok(), "served chain validates");
    }

    /// The moot topic resolves to the authors whose ops the store holds (insert
    /// associated them from each op's signed extension).
    #[tokio::test]
    async fn topic_resolves_to_authors_logs() {
        let store = TesseraStore::in_memory().unwrap();
        let topic = Topic::from(MOOT);

        let alice = keypair(3);
        let bob = keypair(4);
        let alice_vk = VerifyingKey::from_bytes(&alice.public_key().to_bytes()).unwrap();
        let bob_vk = VerifyingKey::from_bytes(&bob.public_key().to_bytes()).unwrap();
        store.insert(&govern(&alice, 0, None, 1)).unwrap();
        store.insert(&govern(&bob, 0, None, 1)).unwrap();

        let resolved = store.resolve(&topic).await.unwrap();
        assert_eq!(resolved.get(&alice_vk), Some(&vec![LOG_ID]));
        assert_eq!(resolved.get(&bob_vk), Some(&vec![LOG_ID]));

        let empty = store.resolve(&Topic::from([0x00; 32])).await.unwrap();
        assert!(empty.is_empty());
    }

    /// Explicit `associate` / `remove` round-trip (idempotent associate).
    #[tokio::test]
    async fn associate_and_remove_topic() {
        let store = TesseraStore::in_memory().unwrap();
        let topic = Topic::from([0x42; 32]);
        let kp = keypair(5);
        let vk = VerifyingKey::from_bytes(&kp.public_key().to_bytes()).unwrap();

        assert!(store.associate(&topic, &vk, &LOG_ID).await.unwrap());
        assert!(!store.associate(&topic, &vk, &LOG_ID).await.unwrap());
        assert_eq!(
            store.resolve(&topic).await.unwrap().get(&vk),
            Some(&vec![LOG_ID])
        );

        assert!(store.remove(&topic, &vk, &LOG_ID).await.unwrap());
        assert!(store.resolve(&topic).await.unwrap().is_empty());
    }
}
