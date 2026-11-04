// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0
#![cfg(feature = "history")]

use async_trait::async_trait;
use gemot_site::{
    PublishedSnapshotV1,
    history::{Checkpoint, HistoryError, HistoryLimits, SiteHistory, SiteId},
};
use muniment::{Backend, DirectoryBackend, MemoryBackend, StoreError, TransactFn, WriteOp};
use std::sync::{
    Arc, Barrier,
    atomic::{AtomicBool, Ordering},
};

fn checkpoint() -> Checkpoint {
    Checkpoint {
        recorded_at_unix_ms: 42,
        label: "Saved by hand / Zoë".into(),
    }
}
fn first() -> PublishedSnapshotV1 {
    PublishedSnapshotV1::decode(include_bytes!("fixtures/scroll-v1.json")).unwrap()
}
const SITE: SiteId = SiteId([7; 32]);

#[test]
fn two_revisions_survive_reopen_with_original_v1_bytes_and_digests() {
    pollster::block_on(async {
        let folder = tempfile::tempdir().unwrap();
        let first = first();
        let mut second = first.clone();
        second
            .pages
            .get_mut("/index.scroll")
            .unwrap()
            .source
            .extend_from_slice(b"\r\nhand edit\r\n");
        let originals = [first.encode().unwrap(), second.encode().unwrap()];
        {
            let store = SiteHistory::new(
                DirectoryBackend::open(folder.path()).unwrap(),
                HistoryLimits::default(),
            );
            for snapshot in [&first, &second] {
                store.record(SITE, snapshot, checkpoint()).await.unwrap();
            }
        }
        let reopened = SiteHistory::new(
            DirectoryBackend::open(folder.path()).unwrap(),
            HistoryLimits::default(),
        );
        let revisions = reopened.list(SITE).await.unwrap();
        assert_eq!(revisions.len(), 2);
        for (index, original) in originals.iter().enumerate() {
            assert_eq!(revisions[index].sequence, index as u64);
            assert_eq!(
                revisions[index].snapshot_digest,
                *blake3::hash(original).as_bytes()
            );
            assert_eq!(
                reopened
                    .load(SITE, index as u64)
                    .await
                    .unwrap()
                    .unwrap()
                    .encode()
                    .unwrap(),
                *original
            );
        }
        assert!(reopened.list(SiteId([8; 32])).await.unwrap().is_empty());
        assert!(reopened.load(SITE, 2).await.unwrap().is_none());
    });
}

#[derive(Clone)]
struct Controlled {
    inner: MemoryBackend,
    fail_blob: Arc<AtomicBool>,
    fail_commit: Arc<AtomicBool>,
    barrier: Option<Arc<Barrier>>,
    no_transactions: bool,
}
impl Default for Controlled {
    fn default() -> Self {
        Self {
            inner: MemoryBackend::new(),
            fail_blob: Arc::new(AtomicBool::new(false)),
            fail_commit: Arc::new(AtomicBool::new(false)),
            barrier: None,
            no_transactions: false,
        }
    }
}
#[async_trait]
impl Backend for Controlled {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        self.inner.get(key).await
    }
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<(), StoreError> {
        if self.fail_blob.load(Ordering::SeqCst) {
            return Err(StoreError::Backend("injected blob failure".into()));
        }
        self.inner.put(key, bytes).await
    }
    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        self.inner.delete(key).await
    }
    async fn list(&self, prefix: &str) -> Result<Vec<String>, StoreError> {
        self.inner.list(prefix).await
    }
    async fn scan(&self, start: &str, end: &str) -> Result<Vec<String>, StoreError> {
        self.inner.scan(start, end).await
    }
    async fn apply(&self, ops: &[WriteOp]) -> Result<(), StoreError> {
        self.inner.apply(ops).await
    }
    async fn transact(&self, f: TransactFn) -> Result<(), StoreError> {
        if self.no_transactions {
            return Err(StoreError::NotTransactional);
        }
        if self.fail_commit.load(Ordering::SeqCst) {
            return Err(StoreError::Backend("injected journal failure".into()));
        }
        if let Some(barrier) = &self.barrier {
            barrier.wait();
        }
        self.inner.transact(f).await
    }
}

#[test]
fn unsupported_transactions_refuse_and_corrupt_journals_do_not_reset_history() {
    pollster::block_on(async {
        let backend = Controlled {
            no_transactions: true,
            ..Controlled::default()
        };
        let store = SiteHistory::new(backend.clone(), HistoryLimits::default());
        assert!(matches!(
            store.record(SITE, &first(), checkpoint()).await,
            Err(HistoryError::Storage(StoreError::NotTransactional))
        ));
        assert!(store.list(SITE).await.unwrap().is_empty());
        let store = SiteHistory::new(backend.inner.clone(), HistoryLimits::default());
        store.record(SITE, &first(), checkpoint()).await.unwrap();
        let keys = backend.inner.list("site-history/").await.unwrap();
        assert_eq!(keys.len(), 1);
        backend
            .inner
            .put(&keys[0], b"damaged journal")
            .await
            .unwrap();
        assert!(matches!(
            store.list(SITE).await,
            Err(HistoryError::Invalid(_))
        ));
        assert!(matches!(
            store.record(SITE, &first(), checkpoint()).await,
            Err(HistoryError::Invalid(_))
        ));
        assert_eq!(
            backend.inner.get(&keys[0]).await.unwrap().unwrap(),
            b"damaged journal"
        );
    });
}

#[test]
fn failed_blob_or_journal_commit_never_exposes_a_revision() {
    pollster::block_on(async {
        let backend = Controlled::default();
        let store = SiteHistory::new(backend.clone(), HistoryLimits::default());
        store.record(SITE, &first(), checkpoint()).await.unwrap();
        backend.fail_blob.store(true, Ordering::SeqCst);
        assert!(store.record(SITE, &first(), checkpoint()).await.is_err());
        backend.fail_blob.store(false, Ordering::SeqCst);
        backend.fail_commit.store(true, Ordering::SeqCst);
        assert!(store.record(SITE, &first(), checkpoint()).await.is_err());
        assert_eq!(store.list(SITE).await.unwrap().len(), 1);
        assert!(store.load(SITE, 1).await.unwrap().is_none());
        assert_eq!(store.load(SITE, 0).await.unwrap().unwrap(), first());
        backend.fail_commit.store(false, Ordering::SeqCst);
        assert_eq!(
            store
                .record(SITE, &first(), checkpoint())
                .await
                .unwrap()
                .sequence,
            1
        );
    });
}

#[test]
fn competing_checkpoints_cannot_overwrite_each_other() {
    let backend = Controlled {
        barrier: Some(Arc::new(Barrier::new(2))),
        ..Controlled::default()
    };
    let threads: Vec<_> = (0..2)
        .map(|_| {
            let backend = backend.clone();
            std::thread::spawn(move || {
                pollster::block_on(SiteHistory::new(backend, HistoryLimits::default()).record(
                    SITE,
                    &first(),
                    checkpoint(),
                ))
            })
        })
        .collect();
    let results: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(HistoryError::ConcurrentChange)))
            .count(),
        1
    );
    let store = SiteHistory::new(backend.inner, HistoryLimits::default());
    assert_eq!(pollster::block_on(store.list(SITE)).unwrap().len(), 1);
}

#[test]
fn corrupted_or_missing_snapshot_is_refused() {
    pollster::block_on(async {
        let backend = MemoryBackend::new();
        let store = SiteHistory::new(backend.clone(), HistoryLimits::default());
        let revision = store.record(SITE, &first(), checkpoint()).await.unwrap();
        let key = format!(
            "blob/{}",
            blake3::Hash::from_bytes(revision.snapshot_digest).to_hex()
        );
        backend.put(&key, b"damaged").await.unwrap();
        assert!(matches!(
            store.load(SITE, 0).await,
            Err(HistoryError::Invalid(_))
        ));
        backend.delete(&key).await.unwrap();
        assert!(matches!(
            store.load(SITE, 0).await,
            Err(HistoryError::MissingSnapshot)
        ));
    });
}

#[test]
fn capacity_refuses_without_pruning_and_identical_checkpoints_share_one_blob() {
    pollster::block_on(async {
        let backend = MemoryBackend::new();
        let store = SiteHistory::new(
            backend.clone(),
            HistoryLimits {
                max_revisions: 2,
                ..HistoryLimits::default()
            },
        );
        store.record(SITE, &first(), checkpoint()).await.unwrap();
        store.record(SITE, &first(), checkpoint()).await.unwrap();
        assert!(matches!(
            store.record(SITE, &first(), checkpoint()).await,
            Err(HistoryError::Capacity)
        ));
        assert_eq!(store.list(SITE).await.unwrap().len(), 2);
        assert_eq!(backend.list("blob/").await.unwrap().len(), 1);
        let refused = SiteHistory::new(
            backend.clone(),
            HistoryLimits {
                max_journal_bytes: 1,
                ..HistoryLimits::default()
            },
        );
        assert!(matches!(
            refused
                .record(SiteId([9; 32]), &first(), checkpoint())
                .await,
            Err(HistoryError::Capacity)
        ));
        assert!(refused.list(SiteId([9; 32])).await.unwrap().is_empty());
    });
}
