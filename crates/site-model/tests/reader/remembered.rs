// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;
use async_trait::async_trait;
use gemot_site::publication::reader::history::{ReaderHistory, ReaderHistoryError};
use muniment::{Backend, RedbBackend, StoreError, TransactFn, WriteOp};
use std::sync::{
    Arc, Barrier,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

fn reader<B: Backend + Sync>(backend: B, trust: &ReaderTrust) -> ReaderHistory<B> {
    ReaderHistory::new(backend, trust.clone(), retention(), ReaderLimits::default())
}

#[test]
#[ignore = "subprocess entry point; invoked against persisted reader authority"]
fn reopen_reader_child() {
    let root = std::path::PathBuf::from(std::env::var_os("MERE_SITE_REMEMBERED_INPUT").unwrap());
    let trust: ReaderTrust =
        serde_json::from_slice(&std::fs::read(root.join("trust.json")).unwrap()).unwrap();
    let history = std::fs::read(root.join("history.drop")).unwrap();
    let snapshot = std::fs::read(root.join("snapshot.json")).unwrap();
    let expected = std::env::var("MERE_SITE_REMEMBERED_EXPECT").unwrap() == "ok";
    let at_ms: u64 = std::env::var("MERE_SITE_REMEMBERED_TIME")
        .unwrap()
        .parse()
        .unwrap();
    let backend = RedbBackend::open(root.join("reader.redb")).unwrap();
    let result = pollster::block_on(reader(backend, &trust).verify(&history, &snapshot, at_ms));
    assert_eq!(result.is_ok(), expected, "{result:?}");
    match result {
        Ok(verified) => assert_eq!(verified.scope, EvidenceScope::SuppliedAndRememberedHistory),
        Err(error) => assert!(
            matches!(error, ReaderHistoryError::Verification(_)),
            "{error}"
        ),
    }
}

fn child(root: &std::path::Path, history: &[u8], snapshot: &[u8], at_ms: u64, expected: bool) {
    std::fs::write(root.join("history.drop"), history).unwrap();
    std::fs::write(root.join("snapshot.json"), snapshot).unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "remembered::reopen_reader_child",
            "--ignored",
            "--nocapture",
        ])
        .env("MERE_SITE_REMEMBERED_INPUT", root)
        .env("MERE_SITE_REMEMBERED_TIME", at_ms.to_string())
        .env(
            "MERE_SITE_REMEMBERED_EXPECT",
            if expected { "ok" } else { "refused" },
        )
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn replacement_and_withdrawal_survive_independent_reader_processes() {
    pollster::block_on(async {
        let mut a = Author::new().await;
        let first = a.publish(FIXTURES[0], None, 10).await;
        let old = a.export().await;
        let second = a.publish(FIXTURES[1], Some(first.contribution), 11).await;
        let new = a.export().await;
        a.moot
            .withdraw_share_for_identity(&a.identity, second.contribution.share, 12)
            .await
            .unwrap();
        let withdrawn = a.export().await;
        let trust = a.trust.clone();
        drop(a);
        let folder = tempfile::tempdir().unwrap();
        let root = folder.path();
        std::fs::write(root.join("trust.json"), serde_json::to_vec(&trust).unwrap()).unwrap();
        child(root, &old, FIXTURES[0], 20, true);
        child(root, &new, FIXTURES[1], 21, true);
        child(root, &old, FIXTURES[0], 22, false);
        child(root, &old, FIXTURES[1], 23, true);
        // The refused read must still commit valid withdrawal authority.
        child(root, &withdrawn, FIXTURES[1], 24, false);
        child(root, &new, FIXTURES[1], 25, false);
    });
}

#[test]
fn revocation_and_conflict_are_remembered_even_when_page_verification_refuses() {
    pollster::block_on(async {
        let mut a = Author::new().await;
        a.publish(FIXTURES[0], None, 10).await;
        let old = a.export().await;
        let backend = MemoryBackend::new();
        let r = reader(backend.clone(), &a.trust);
        r.verify(&old, FIXTURES[0], 20).await.unwrap();
        a.publish(FIXTURES[1], None, 11).await;
        assert!(r.verify(&a.export().await, FIXTURES[0], 21).await.is_err());
        drop(r);
        assert!(
            reader(backend, &a.trust)
                .verify(&old, FIXTURES[0], 22)
                .await
                .is_err()
        );

        let mut a = Author::new().await;
        a.publish(FIXTURES[0], None, 10).await;
        let old = a.export().await;
        a.moot
            .update_membership_for_identity(
                &a.identity,
                MootMembershipAction::Remove {
                    member: a.trust.founder,
                },
            )
            .await
            .unwrap();
        let backend = MemoryBackend::new();
        let r = reader(backend.clone(), &a.trust);
        assert!(r.verify(&a.export().await, FIXTURES[0], 20).await.is_err());
        drop(r);
        assert!(
            reader(backend, &a.trust)
                .verify(&old, FIXTURES[0], 21)
                .await
                .is_err()
        );
    });
}

async fn stored(backend: &MemoryBackend) -> Vec<(String, Vec<u8>)> {
    let mut keys = backend.list("site-reader/").await.unwrap();
    keys.sort();
    let mut records = Vec::new();
    for key in keys {
        records.push((key.clone(), backend.get(&key).await.unwrap().unwrap()));
    }
    records
}

#[test]
fn invalid_evidence_and_backwards_clock_do_not_change_observations() {
    pollster::block_on(async {
        let mut a = Author::new().await;
        a.publish(FIXTURES[0], None, 10).await;
        let history = a.export().await;
        let backend = MemoryBackend::new();
        let r = reader(backend.clone(), &a.trust);
        r.observe(&history, 20).await.unwrap();
        let before = stored(&backend).await;
        assert!(r.observe(&history[..history.len() - 1], 21).await.is_err());
        assert!(matches!(
            r.observe(&history, 19).await,
            Err(ReaderHistoryError::ClockRollback)
        ));
        assert_eq!(stored(&backend).await, before);
        // A failed content decode still preserves an otherwise valid observation.
        a.publish(FIXTURES[1], None, 11).await;
        assert!(
            r.verify(&a.export().await, b"invalid snapshot", 21)
                .await
                .is_err()
        );
        assert!(r.verify(&history, FIXTURES[0], 22).await.is_err());
    });
}

#[test]
fn corrupted_or_incomplete_storage_refuses_instead_of_resetting() {
    pollster::block_on(async {
        let mut a = Author::new().await;
        a.publish(FIXTURES[0], None, 10).await;
        let history = a.export().await;
        for target in ["history.drop", "state.json"] {
            let backend = MemoryBackend::new();
            let r = reader(backend.clone(), &a.trust);
            r.observe(&history, 20).await.unwrap();
            let key = backend
                .list("site-reader/")
                .await
                .unwrap()
                .into_iter()
                .find(|k| k.ends_with(target))
                .unwrap();
            backend.put(&key, b"corrupt").await.unwrap();
            let before = stored(&backend).await;
            assert!(matches!(
                r.observe(&history, 21).await,
                Err(ReaderHistoryError::InvalidState(_))
            ));
            assert_eq!(stored(&backend).await, before);
            backend.delete(&key).await.unwrap();
            assert!(matches!(
                r.observe(&history, 21).await,
                Err(ReaderHistoryError::InvalidState(_))
            ));
        }
    });
}

#[derive(Clone)]
struct Controlled {
    inner: MemoryBackend,
    fail_writes: Arc<AtomicBool>,
    no_transactions: bool,
    gate: Option<Arc<Barrier>>,
    calls: Arc<AtomicUsize>,
    replace_on_final_read: Option<Vec<(String, Vec<u8>)>>,
}
impl Controlled {
    fn new(inner: MemoryBackend) -> Self {
        Self {
            inner,
            fail_writes: Arc::new(AtomicBool::new(false)),
            no_transactions: false,
            gate: None,
            calls: Arc::new(AtomicUsize::new(0)),
            replace_on_final_read: None,
        }
    }
}
#[async_trait]
impl Backend for Controlled {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        self.inner.get(key).await
    }
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<(), StoreError> {
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
        if self.calls.load(Ordering::SeqCst) == 2
            && let Some(records) = &self.replace_on_final_read
        {
            let writes = records
                .iter()
                .map(|(key, value)| WriteOp::Put {
                    key: key.clone(),
                    value: value.clone(),
                })
                .collect::<Vec<_>>();
            self.inner.apply(&writes).await?;
        }
        let failed = Arc::new(AtomicBool::new(false));
        let mark_failed = failed.clone();
        let fail = self.fail_writes.load(Ordering::SeqCst);
        self.inner
            .transact(Box::new(move |view| {
                let ops = f(view);
                if fail && !ops.is_empty() {
                    mark_failed.store(true, Ordering::SeqCst);
                    vec![]
                } else {
                    ops
                }
            }))
            .await?;
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0
            && let Some(gate) = &self.gate
        {
            gate.wait();
        }
        if failed.load(Ordering::SeqCst) {
            return Err(StoreError::Backend("injected atomic commit failure".into()));
        }
        Ok(())
    }
}

#[test]
fn failed_and_unsupported_transactions_never_return_verified_content() {
    pollster::block_on(async {
        let mut a = Author::new().await;
        let first = a.publish(FIXTURES[0], None, 10).await;
        let old = a.export().await;
        let control = Controlled::new(MemoryBackend::new());
        let r = reader(control.clone(), &a.trust);
        r.verify(&old, FIXTURES[0], 20).await.unwrap();
        let before = stored(&control.inner).await;
        a.publish(FIXTURES[1], Some(first.contribution), 11).await;
        control.fail_writes.store(true, Ordering::SeqCst);
        assert!(matches!(
            r.verify(&a.export().await, FIXTURES[1], 21).await,
            Err(ReaderHistoryError::Storage(_))
        ));
        assert_eq!(stored(&control.inner).await, before);
        let mut unsupported = Controlled::new(MemoryBackend::new());
        unsupported.no_transactions = true;
        assert!(matches!(
            reader(unsupported.clone(), &a.trust)
                .verify(&old, FIXTURES[0], 20)
                .await,
            Err(ReaderHistoryError::Storage(StoreError::NotTransactional))
        ));
        assert!(stored(&unsupported.inner).await.is_empty());
    });
}

#[test]
fn capacity_refusal_preserves_existing_authority() {
    pollster::block_on(async {
        let mut a = Author::new().await;
        let first = a.publish(FIXTURES[0], None, 10).await;
        let old = a.export().await;
        let backend = MemoryBackend::new();
        let r = ReaderHistory::new(
            backend.clone(),
            a.trust.clone(),
            retention(),
            ReaderLimits {
                max_history_bytes: old.len(),
                ..ReaderLimits::default()
            },
        );
        r.observe(&old, 20).await.unwrap();
        let before = stored(&backend).await;
        a.publish(FIXTURES[1], Some(first.contribution), 11).await;
        assert!(matches!(
            r.observe(&a.export().await, 21).await,
            Err(ReaderHistoryError::Capacity)
        ));
        assert_eq!(stored(&backend).await, before);
    });
}

#[test]
fn competing_observers_cannot_erase_each_others_history() {
    pollster::block_on(async {
        let mut a = Author::new().await;
        let first = a.publish(FIXTURES[0], None, 10).await;
        let old = a.export().await;
        a.publish(FIXTURES[1], Some(first.contribution), 11).await;
        let new = a.export().await;
        let backend = MemoryBackend::new();
        let gate = Arc::new(Barrier::new(2));
        let workers = [old.clone(), new.clone()]
            .into_iter()
            .map(|history| {
                let mut control = Controlled::new(backend.clone());
                control.gate = Some(gate.clone());
                let trust = a.trust.clone();
                std::thread::spawn(move || {
                    pollster::block_on(reader(control, &trust).observe(&history, 20))
                })
            })
            .collect::<Vec<_>>();
        let outcomes = workers
            .into_iter()
            .map(|w| w.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(outcomes.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|r| matches!(r, Err(ReaderHistoryError::ConcurrentChange)))
                .count(),
            1
        );
        // The refused observer retries against committed state and converges.
        let r = reader(backend, &a.trust);
        r.observe(&new, 21).await.unwrap();
        assert!(r.verify(&old, FIXTURES[0], 22).await.is_err());
        r.verify(&old, FIXTURES[1], 23).await.unwrap();
    });
}

#[test]
fn authority_change_during_content_verification_requires_retry() {
    pollster::block_on(async {
        let mut a = Author::new().await;
        let first = a.publish(FIXTURES[0], None, 10).await;
        let old = a.export().await;
        a.publish(FIXTURES[1], Some(first.contribution), 11).await;
        let new = a.export().await;
        let concurrent = MemoryBackend::new();
        reader(concurrent.clone(), &a.trust)
            .observe(&new, 21)
            .await
            .unwrap();
        let mut control = Controlled::new(MemoryBackend::new());
        control.replace_on_final_read = Some(stored(&concurrent).await);
        let backend = control.inner.clone();
        assert!(matches!(
            reader(control, &a.trust)
                .verify(&old, FIXTURES[0], 20)
                .await,
            Err(ReaderHistoryError::ConcurrentChange)
        ));
        assert!(
            reader(backend, &a.trust)
                .verify(&old, FIXTURES[0], 22)
                .await
                .is_err()
        );
    });
}
