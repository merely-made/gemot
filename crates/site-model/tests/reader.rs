// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0
#![cfg(feature = "publication")]

use gemot::moot::constitution::{CapabilityGrant, ConstitutionRules};
use gemot::moot::{
    AvailabilityPolicy, CollectionId, CollectionRef, ContributionRef, ErasurePolicy, KeepBound,
    Moot, MootAccessLevel, MootId, MootMember, MootMembershipAction, MootRetentionSettings,
    PolicyRevision,
};
use gemot_site::publication::reader::{
    EvidenceScope, ReaderLimits, ReaderTrust, verify_reader_evidence,
};
use gemot_site::{PublishedSnapshotV1, publication};
use muniment::MemoryBackend;
use personae::{IdentityProvider, InMemoryProvider};
use proofs::Digest;
use servitor::{Cap, cap_path};
use stickleback::{
    DropExportProfile, DropLimits, DropRecord, EvidenceKind, read_plain_drop, write_plain_drop,
};

const MOOT: [u8; 32] = [71; 32];
const COLLECTION: CollectionId = CollectionId([72; 32]);
const FIXTURES: [&[u8]; 3] = [
    include_bytes!("fixtures/gemini-v1.json"),
    include_bytes!("fixtures/scroll-v1.json"),
    include_bytes!("fixtures/micron-v1.json"),
];

fn retention() -> MootRetentionSettings {
    MootRetentionSettings {
        revision: PolicyRevision(Digest::blake3(b"portable-reader-proof")),
        availability: AvailabilityPolicy {
            promised_floor: KeepBound::Forever,
        },
        erasure: ErasurePolicy {
            history_ceiling: KeepBound::UntilCheckpoint,
        },
    }
}

struct Author {
    identity: InMemoryProvider,
    moot: Moot<MemoryBackend>,
    content: MemoryBackend,
    trust: ReaderTrust,
}

impl Author {
    async fn new() -> Self {
        let identity = InMemoryProvider::from_seed([11; 32]);
        let founder = identity.master_public_key().to_bytes();
        let mut rules = ConstitutionRules::founder_only(founder);
        rules.admission = mien::Policy::MembersOnly {
            rate_limit: 100,
            rate_window_ms: 1000,
        };
        rules.grant(CapabilityGrant {
            id: [43; 32],
            subject: founder,
            path_prefix: cap_path(&Cap::scope("moot").unwrap()),
            not_before_ms: 1,
            expires_at_ms: Some(100),
            delegation_depth: 0,
        });
        let moot = Moot::in_memory(MootId(MOOT), founder, retention());
        moot.found(identity.master_keypair().to_seed(), None, None, rules, 1)
            .await
            .unwrap();
        moot.update_membership_for_identity(
            &identity,
            MootMembershipAction::Create {
                initial_members: vec![MootMember {
                    member: founder,
                    access: MootAccessLevel::Manage,
                }],
            },
        )
        .await
        .unwrap();
        moot.declare_collection_for_identity(&identity, COLLECTION, "Garden".into(), None, 2)
            .await
            .unwrap();
        Self {
            identity,
            moot,
            content: MemoryBackend::new(),
            trust: ReaderTrust {
                founder,
                collection: CollectionRef {
                    moot_id: MOOT,
                    collection_id: COLLECTION,
                },
            },
        }
    }

    async fn publish(
        &mut self,
        bytes: &[u8],
        replace: Option<ContributionRef>,
        at: u64,
    ) -> publication::SiteSelection {
        let version = self
            .moot
            .authorized_collection(COLLECTION, at)
            .await
            .unwrap()
            .unwrap()
            .version;
        publication::publish_public_snapshot(
            &self.moot,
            &self.identity,
            &mut self.content,
            &PublishedSnapshotV1::decode(bytes).unwrap(),
            &version,
            replace,
            "Garden".into(),
            at,
        )
        .await
        .unwrap()
        .selection
    }

    async fn export(&self) -> Vec<u8> {
        export(&self.moot).await
    }
}

async fn export(moot: &Moot<MemoryBackend>) -> Vec<u8> {
    let mut bytes = Vec::new();
    moot.export_plain_drop(
        &mut bytes,
        DropExportProfile::default(),
        DropLimits::default(),
    )
    .await
    .unwrap();
    bytes
}

async fn verify(
    trust: &ReaderTrust,
    history: &[u8],
    bytes: &[u8],
) -> Result<publication::reader::VerifiedPublication, publication::PublicationError> {
    verify_reader_evidence(
        trust,
        history,
        bytes,
        retention(),
        20,
        ReaderLimits::default(),
    )
    .await
}

// The child receives only the public trust anchor and B's evidence files. It
// constructs no author identity, has no membership, and uses no provider store.
#[test]
#[ignore = "subprocess entry point; invoked with isolated public evidence"]
fn cold_reader_child() {
    let root = std::env::var_os("MERE_SITE_COLD_READER_INPUT").expect("public evidence input");
    let root = std::path::PathBuf::from(root);
    let trust: ReaderTrust =
        serde_json::from_slice(&std::fs::read(root.join("trust.json")).unwrap()).unwrap();
    let history = std::fs::read(root.join("history.drop")).unwrap();
    let bytes = std::fs::read(root.join("snapshot.json")).unwrap();
    let verified = pollster::block_on(verify(&trust, &history, &bytes)).unwrap();
    assert_eq!(verified.scope, EvidenceScope::SuppliedHistoryOnly);
    assert_eq!(verified.site.snapshot().encode().unwrap(), bytes);
    assert_eq!(verified.site.manifest, eidetic::ManifestId::of_blob(&bytes));
    std::fs::write(
        root.join("verified.json"),
        serde_json::to_vec(&serde_json::json!({
            "selection": verified.site.selection,
            "snapshot_digest": verified.site.snapshot().digest().unwrap(),
            "evaluated_at_ms": verified.evaluated_at_ms,
            "scope": "supplied_history_only"
        }))
        .unwrap(),
    )
    .unwrap();
}

#[test]
fn cold_process_verifies_all_native_profiles_reexported_by_b_after_a_is_gone() {
    pollster::block_on(async {
        for bytes in FIXTURES {
            let mut a = Author::new().await;
            let selection = a.publish(bytes, None, 10).await;
            let trust = a.trust.clone();
            let history = a.export().await;
            let b = Moot::in_memory(MootId(MOOT), trust.founder, retention());
            b.import_plain_drop(history.as_slice(), DropLimits::default())
                .await
                .unwrap();
            // B needs neither the author key nor its content store to re-serve
            // public history and the complete canonical snapshot it received.
            let b_snapshot = bytes.to_vec();
            drop(a);
            let b_history = export(&b).await;
            drop(b);
            let input = tempfile::tempdir().unwrap();
            std::fs::write(
                input.path().join("trust.json"),
                serde_json::to_vec(&trust).unwrap(),
            )
            .unwrap();
            std::fs::write(input.path().join("history.drop"), b_history).unwrap();
            std::fs::write(input.path().join("snapshot.json"), b_snapshot).unwrap();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "cold_reader_child", "--ignored", "--nocapture"])
                .env("MERE_SITE_COLD_READER_INPUT", input.path())
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let report: serde_json::Value =
                serde_json::from_slice(&std::fs::read(input.path().join("verified.json")).unwrap())
                    .unwrap();
            assert_eq!(
                report["selection"],
                serde_json::to_value(selection).unwrap()
            );
            assert_eq!(report["scope"], "supplied_history_only");
        }
    });
}

#[test]
fn wrong_roots_collections_and_snapshot_bytes_refuse() {
    pollster::block_on(async {
        let mut a = Author::new().await;
        a.publish(FIXTURES[0], None, 10).await;
        let history = a.export().await;
        let mut trust = a.trust.clone();
        trust.founder = InMemoryProvider::from_seed([99; 32])
            .master_public_key()
            .to_bytes();
        assert!(verify(&trust, &history, FIXTURES[0]).await.is_err());
        trust = a.trust.clone();
        trust.collection.moot_id = [99; 32];
        assert!(verify(&trust, &history, FIXTURES[0]).await.is_err());
        trust = a.trust.clone();
        trust.collection.collection_id = CollectionId([99; 32]);
        assert!(verify(&trust, &history, FIXTURES[0]).await.is_err());
        assert!(verify(&a.trust, &history, FIXTURES[1]).await.is_err());
        let mut changed = PublishedSnapshotV1::decode(FIXTURES[0]).unwrap();
        changed
            .pages
            .get_mut("/index.gmi")
            .unwrap()
            .source
            .push(b'!');
        assert!(
            verify(&a.trust, &history, &changed.encode().unwrap())
                .await
                .is_err()
        );
        let mut noncanonical = FIXTURES[0].to_vec();
        noncanonical.push(b'\n');
        assert!(
            verify(&a.trust, &history, &noncanonical)
                .await
                .unwrap_err()
                .to_string()
                .contains("canonical")
        );
    });
}

fn rewrite_drop(history: &[u8], change: impl FnOnce(&mut Vec<DropRecord>)) -> Vec<u8> {
    let (_, mut records) = read_plain_drop(history, DropLimits::default()).unwrap();
    change(&mut records);
    let mut rewritten = Vec::new();
    // Recompute carrier integrity so rejection exercises authority admission.
    write_plain_drop(&mut rewritten, &records, DropLimits::default()).unwrap();
    rewritten
}

#[test]
fn missing_authority_and_forged_records_refuse_even_with_valid_carrier_integrity() {
    pollster::block_on(async {
        let mut a = Author::new().await;
        a.publish(FIXTURES[0], None, 10).await;
        let history = a.export().await;
        for missing in [
            EvidenceKind::CheckpointAuthorization,
            EvidenceKind::DomainOperations,
        ] {
            let incomplete = rewrite_drop(&history, |records| {
                records
                    .retain(|r| !matches!(r, DropRecord::Evidence { kind, .. } if *kind == missing))
            });
            assert!(verify(&a.trust, &incomplete, FIXTURES[0]).await.is_err());
        }
        let forged = rewrite_drop(&history, |records| {
            let header = records
                .iter_mut()
                .find_map(|r| match r {
                    DropRecord::Operation { header, .. } => Some(header),
                    _ => None,
                })
                .unwrap();
            // Last byte belongs to signed header data; a valid carrier cannot
            // make a modified signed operation authoritative.
            let last = header.len() - 1;
            header[last] ^= 1;
        });
        assert!(verify(&a.trust, &forged, FIXTURES[0]).await.is_err());
        assert!(
            verify(&a.trust, &history[..history.len() - 1], FIXTURES[0])
                .await
                .is_err()
        );
        assert!(
            verify_reader_evidence(
                &a.trust,
                &history,
                FIXTURES[0],
                retention(),
                101,
                ReaderLimits::default()
            )
            .await
            .is_err()
        );
    });
}

#[test]
fn ambiguity_withdrawal_and_older_valid_history_have_distinct_results() {
    pollster::block_on(async {
        let mut a = Author::new().await;
        let first = a.publish(FIXTURES[0], None, 10).await;
        let old_history = a.export().await;
        a.publish(FIXTURES[1], None, 11).await;
        assert!(
            verify(&a.trust, &a.export().await, FIXTURES[0])
                .await
                .unwrap_err()
                .to_string()
                .contains("more than one")
        );
        a.moot
            .withdraw_share_for_identity(&a.identity, first.contribution.share, 12)
            .await
            .unwrap();
        assert!(
            verify(&a.trust, &a.export().await, FIXTURES[0])
                .await
                .is_err()
        );
        // An isolated older valid set cannot prove the absence of later state.
        let old = verify(&a.trust, &old_history, FIXTURES[0]).await.unwrap();
        assert_eq!(old.scope, EvidenceScope::SuppliedHistoryOnly);
        assert_eq!(old.site.selection, first);
        let current = verify(&a.trust, &a.export().await, FIXTURES[1])
            .await
            .unwrap();
        assert_ne!(old.site.selection, current.site.selection);
    });
}

#[test]
fn caller_byte_and_record_limits_refuse_without_poisoning_the_next_read() {
    pollster::block_on(async {
        let mut a = Author::new().await;
        a.publish(FIXTURES[0], None, 10).await;
        let history = a.export().await;
        let limits = ReaderLimits {
            max_history_bytes: history.len() - 1,
            ..ReaderLimits::default()
        };
        assert!(
            verify_reader_evidence(&a.trust, &history, FIXTURES[0], retention(), 20, limits)
                .await
                .is_err()
        );
        let limits = ReaderLimits {
            drop: DropLimits {
                max_records: 0,
                ..DropLimits::default()
            },
            ..ReaderLimits::default()
        };
        assert!(
            verify_reader_evidence(&a.trust, &history, FIXTURES[0], retention(), 20, limits)
                .await
                .is_err()
        );
        let oversized = vec![b' '; gemot_site::MAX_ENCODED_SNAPSHOT_BYTES + 1];
        assert!(
            verify(&a.trust, &history, &oversized)
                .await
                .unwrap_err()
                .to_string()
                .contains("byte limit")
        );
        assert!(verify(&a.trust, &history, FIXTURES[0]).await.is_ok());
    });
}

#[test]
fn sole_withdrawal_and_membership_revocation_refuse() {
    pollster::block_on(async {
        let mut a = Author::new().await;
        let release = a.publish(FIXTURES[0], None, 10).await;
        a.moot
            .withdraw_share_for_identity(&a.identity, release.contribution.share, 11)
            .await
            .unwrap();
        assert!(
            verify(&a.trust, &a.export().await, FIXTURES[0])
                .await
                .is_err()
        );

        let mut a = Author::new().await;
        a.publish(FIXTURES[0], None, 10).await;
        a.moot
            .update_membership_for_identity(
                &a.identity,
                MootMembershipAction::Remove {
                    member: a.trust.founder,
                },
            )
            .await
            .unwrap();
        assert!(
            verify(&a.trust, &a.export().await, FIXTURES[0])
                .await
                .is_err()
        );
    });
}

#[test]
fn replacement_resolves_from_history_and_refuses_the_previous_snapshot() {
    pollster::block_on(async {
        let mut a = Author::new().await;
        let first = a.publish(FIXTURES[0], None, 10).await;
        let second = a.publish(FIXTURES[1], Some(first.contribution), 11).await;
        let history = a.export().await;
        assert!(verify(&a.trust, &history, FIXTURES[0]).await.is_err());
        assert_eq!(
            verify(&a.trust, &history, FIXTURES[1])
                .await
                .unwrap()
                .site
                .selection,
            second
        );
    });
}

#[path = "reader/remembered.rs"]
mod remembered;
