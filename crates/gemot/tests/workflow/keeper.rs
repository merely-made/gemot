// SPDX-License-Identifier: MPL-2.0
use super::common::*;
use eidetic::{
    BlobManifest, BlobSource, Hash, ManifestId, PrivacyClass, ProvenanceRecord, SchemaRef,
    Timestamp, TrustEnvelope,
};
use gemot::moot::workflow::keeper::{catalogue::*, *};
use gemot::moot::workflow::work::*;
use gemot::moot::*;
use muniment::{Backend, MemoryBackend, RedbBackend};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use stickleback::{DropExportProfile, DropLimits};

fn keeper() -> Keeper {
    Keeper {
        owner: root(&person(8)),
        policy_revision: [3; 32],
        limits: eidetic::retention::Limits {
            max_payload_bytes: 65536,
            max_stored_bytes: 65536,
        },
        max_jobs: 8,
        max_inputs_per_job: 64,
    }
}
fn document() -> CatalogueDocument {
    CatalogueDocument {
        version: 1,
        address: "scroll://garden.test/index.scroll".into(),
        title: "The garden catalogue".into(),
        abstract_text: "A garden of painting and music".into(),
        scroll_subject: Some(7),
        language: Some("en".into()),
        body: include_str!("../../../site-model/tests/fixtures/writers/index.html").into(),
    }
}
fn manifest(bytes: &[u8]) -> BlobManifest {
    BlobManifest {
        id: ManifestId::of_blob(bytes),
        schema: SchemaRef::from_id(ManifestId::of_blob(SCHEMA.as_bytes())),
        content_hash: Hash::of(bytes),
        byte_size: bytes.len() as u64,
        created_at: Timestamp(1),
        last_accessed: None,
        sources: vec![BlobSource::Embedded {
            bytes: bytes.to_vec(),
            media_type: "application/json".into(),
        }],
        privacy: PrivacyClass::PublicPortable,
        provenance: ProvenanceRecord::self_imported("workflow process fixture"),
        trust: TrustEnvelope::self_asserted(),
        schema_metadata: serde_json::Value::Null,
        manifest_version: BlobManifest::CURRENT_VERSION,
    }
}
struct Source {
    items: BTreeMap<[u8; 32], (BlobManifest, Vec<u8>)>,
    calls: usize,
}
impl WorkFetcher for Source {
    async fn fetch(&mut self, id: [u8; 32], max: u64) -> Result<(BlobManifest, Vec<u8>)> {
        self.calls += 1;
        let data = self
            .items
            .get(&id)
            .cloned()
            .ok_or_else(|| KeeperError::Refused("contributor stopped".into()))?;
        if data.1.len() as u64 > max {
            return Err(KeeperError::Refused("fetch ceiling".into()));
        }
        Ok(data)
    }
}
#[tokio::test]
async fn restart_checks_copies_and_live_withdrawal_expiry_and_reader_rights() {
    let bytes = document().encode().unwrap();
    let meta = manifest(&bytes);
    let id = *meta.id.0.as_bytes();
    let moot = Moot::in_memory(ID, root(&person(7)), retention());
    initialize(&moot).await;
    let share = populate(&moot, id).await;
    let agreement = agree(&moot).await;
    let mut store = MemoryBackend::default();
    let mut source = Source {
        items: [(id, (meta.clone(), bytes.clone()))].into(),
        calls: 0,
    };
    let k = keeper();
    let job = k
        .reconcile(&moot, &mut store, WORK, 20, &mut source, None)
        .await
        .unwrap();
    assert_eq!(source.calls, 1);
    source.items.clear();
    // Reconciliation after host reconstruction discovers verified owner copies.
    let k = keeper();
    let jobs = k.jobs(&store).await.unwrap();
    assert_eq!(jobs, vec![job.clone()]);
    k.reconcile(&moot, &mut store, WORK, 21, &mut source, None)
        .await
        .unwrap();
    assert_eq!(source.calls, 1);
    assert_eq!(
        k.retrieve(&moot, &mut store, &job, root(&person(10)), share, 22, None)
            .await
            .unwrap()
            .1,
        bytes
    );
    assert!(
        k.retrieve(&moot, &mut store, &job, root(&person(11)), share, 22, None)
            .await
            .is_err()
    );
    assert_eq!(
        k.search(
            &moot,
            &mut store,
            &jobs,
            root(&person(10)),
            "painting",
            Some(7),
            10,
            22,
            None
        )
        .await
        .unwrap()
        .len(),
        1
    );
    assert!(
        k.search(
            &moot,
            &mut store,
            &jobs,
            root(&person(10)),
            "painting",
            Some(5),
            10,
            22,
            None
        )
        .await
        .unwrap()
        .is_empty()
    );
    assert!(
        k.retrieve(
            &moot,
            &mut store,
            &job,
            root(&person(10)),
            share,
            1010,
            None
        )
        .await
        .is_err()
    );
    moot.update_membership_for_identity(
        &person(7),
        MootMembershipAction::Remove {
            member: root(&person(10)),
        },
    )
    .await
    .unwrap();
    assert!(
        k.retrieve(&moot, &mut store, &job, root(&person(10)), share, 23, None)
            .await
            .is_err()
    );
    moot.withdraw_share_for_identity(&person(7), share.share, 24)
        .await
        .unwrap();
    assert!(
        k.retrieve(&moot, &mut store, &job, root(&person(9)), share, 25, None)
            .await
            .is_err()
    );
    assert!(
        k.search(
            &moot,
            &mut store,
            &jobs,
            root(&person(9)),
            "painting",
            None,
            10,
            25,
            None
        )
        .await
        .unwrap()
        .is_empty()
    );
    // Cancellation never destroys accepted history or selects a garbage-collection policy.
    moot.work_for_identity(
        &person(8),
        event(
            WorkAction::Cancel {
                agreement,
                reason: "ended".into(),
            },
            26,
        ),
    )
    .await
    .unwrap();
    assert!(
        k.reconcile(&moot, &mut store, WORK, 27, &mut source, None)
            .await
            .is_err()
    );
    assert_eq!(k.jobs(&store).await.unwrap()[0].state, JobState::Suspended);
    assert!(
        eidetic::retention::read(&mut store, k.owner, meta.id, None)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn failed_acquisition_retries_and_private_or_corrupt_bytes_refuse() {
    let bytes = document().encode().unwrap();
    let mut meta = manifest(&bytes);
    let id = *meta.id.0.as_bytes();
    let moot = Moot::in_memory(ID, root(&person(7)), retention());
    initialize(&moot).await;
    populate(&moot, id).await;
    agree(&moot).await;
    let mut store = MemoryBackend::default();
    let k = keeper();
    let mut source = Source {
        items: BTreeMap::new(),
        calls: 0,
    };
    assert!(
        k.reconcile(&moot, &mut store, WORK, 20, &mut source, None)
            .await
            .is_err()
    );
    assert_eq!(k.jobs(&store).await.unwrap()[0].state, JobState::Acquiring);
    source
        .items
        .insert(id, (meta.clone(), b"wrong bytes".to_vec()));
    assert!(
        k.reconcile(&moot, &mut store, WORK, 21, &mut source, None)
            .await
            .is_err()
    );
    meta.privacy = PrivacyClass::LocalOnly;
    source.items.insert(id, (meta.clone(), bytes.clone()));
    assert!(
        k.reconcile(&moot, &mut store, WORK, 22, &mut source, None)
            .await
            .is_err()
    );
    meta.privacy = PrivacyClass::PublicPortable;
    source.items.insert(id, (meta, bytes));
    k.reconcile(&moot, &mut store, WORK, 23, &mut source, None)
        .await
        .unwrap();
    // Actual stored corruption is detected on restart, even with a Retained flag.
    let body = store
        .list(&format!("retained/{}/body/", hex(k.owner)))
        .await
        .unwrap()
        .pop()
        .unwrap();
    store.put(&body, b"corrupt").await.unwrap();
    assert!(
        k.reconcile(&moot, &mut store, WORK, 24, &mut source, None)
            .await
            .is_err()
    );
}
fn hex(id: [u8; 32]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::test]
async fn renewed_job_reuses_owner_bytes_and_retiring_old_claim_keeps_new_service() {
    let bytes = document().encode().unwrap();
    let metadata = manifest(&bytes);
    let id = *metadata.id.0.as_bytes();
    let moot = Moot::in_memory(ID, root(&person(7)), retention());
    initialize(&moot).await;
    let share = populate(&moot, id).await;
    let first = agree(&moot).await;
    let mut store = MemoryBackend::default();
    let k = keeper();
    let mut source = Source {
        items: [(id, (metadata, bytes.clone()))].into(),
        calls: 0,
    };
    let old = k
        .reconcile(&moot, &mut store, WORK, 20, &mut source, None)
        .await
        .unwrap();
    source.items.clear();
    moot.work_for_identity(
        &person(8),
        event(
            WorkAction::Cancel {
                agreement: first,
                reason: "renew under new exact terms".into(),
            },
            21,
        ),
    )
    .await
    .unwrap();
    let next = moot
        .work_for_identity(
            &person(7),
            event(
                WorkAction::Offer {
                    terms: terms(),
                    replaces: Some(first),
                },
                22,
            ),
        )
        .await
        .unwrap()
        .operation;
    moot.work_for_identity(&person(8), event(WorkAction::Accept { offer: next }, 23))
        .await
        .unwrap();
    let new = k
        .reconcile(&moot, &mut store, WORK, 24, &mut source, None)
        .await
        .unwrap();
    assert_eq!(source.calls, 1);
    assert_eq!(k.jobs(&store).await.unwrap().len(), 2);
    assert_eq!(
        store
            .list(&format!("retained/{}/copy/", hex(k.owner)))
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        k.retrieve(&moot, &mut store, &old, root(&person(10)), share, 25, None)
            .await
            .is_err()
    );
    assert_eq!(
        k.retrieve(&moot, &mut store, &new, root(&person(10)), share, 25, None)
            .await
            .unwrap()
            .1,
        bytes
    );
}

#[path = "processes.rs"]
mod processes;

#[test]
fn keeper_restart_after_contributor_exit_and_fresh_reader_process() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();
    processes::run(dir, "author");
    let mut source = processes::spawn(dir, "source");
    wait_file(dir, "source.addr");
    processes::run(dir, "acquire");
    assert!(source.wait().unwrap().success());
    let mut keeper = processes::spawn(dir, "restart");
    wait_file(dir, "keeper.addr");
    processes::run(dir, "reader");
    assert!(keeper.wait().unwrap().success());
    let receipt = std::fs::read_to_string(dir.join("reader-receipt.json")).unwrap();
    assert!(receipt.contains("\"search_hits\": 1"));
    if let Some(output) = std::env::var_os("GEMOT_WORKFLOW_RECEIPT_DIR") {
        let output = std::path::PathBuf::from(output);
        std::fs::create_dir_all(&output).unwrap();
        for name in ["reader-receipt.json", "keeper-receipt.json"] {
            let target = output.join(name);
            assert!(!target.exists());
            std::fs::copy(dir.join(name), target).unwrap();
        }
    }
}
fn wait_file(dir: &Path, name: &str) {
    let start = Instant::now();
    while !dir.join(name).exists() {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "process readiness: {name}"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[tokio::test]
#[ignore = "subprocess entry; exercised by keeper_restart_after_contributor_exit_and_fresh_reader_process"]
async fn process_role() {
    let Some(role) = std::env::var_os("GEMOT_WORKFLOW_ROLE") else {
        return;
    };
    let dir = std::path::PathBuf::from(std::env::var_os("GEMOT_WORKFLOW_DIR").unwrap());
    processes::role(&dir, &role.to_string_lossy()).await;
}
