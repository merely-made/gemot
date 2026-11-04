// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0
#![cfg(feature = "publication")]

use eidetic::manifest::{load_manifest, save_manifest};
use eidetic::schema_def::{bootstrap_meta_schema, save_schema};
use eidetic::typed::{TypedPayload, save_typed};
use eidetic::{ManifestId, PrivacyClass, ProvenanceRecord, Store, Timestamp, TrustEnvelope};
use gemot::moot::constitution::{CapabilityGrant, ConstitutionRules};
use gemot::moot::{
    AvailabilityPolicy, CollectionChange, CollectionFork, CollectionId, CollectionRef,
    ContributionRef, ErasurePolicy, KeepBound, Moot, MootAccessLevel, MootCommandReceipt, MootId,
    MootMember, MootMembershipAction, MootOutboundOperation, MootRetentionSettings, PolicyRevision,
};
use gemot_site::{
    PublishedSnapshotV1,
    publication::{self, SiteSelection},
};
use muniment::{MemoryBackend, RedbBackend};
use personae::{IdentityProvider, InMemoryProvider};
use proofs::Digest;
use servitor::{Cap, cap_path};

const MOOT: [u8; 32] = [71; 32];
const COLLECTION: CollectionId = CollectionId([72; 32]);
const FIXTURES: [&[u8]; 3] = [
    include_bytes!("fixtures/gemini-v1.json"),
    include_bytes!("fixtures/scroll-v1.json"),
    include_bytes!("fixtures/micron-v1.json"),
];

#[test]
fn schema_identity_is_independent_of_json_map_order_features() {
    let bytes = include_bytes!("../src/snapshot-schema.json").trim_ascii();
    let schema = publication::snapshot_schema();
    assert_eq!(schema.schema_id, publication::SNAPSHOT_SCHEMA_ID);
    assert_eq!(serde_json::to_vec(&schema).unwrap(), bytes);
    assert_eq!(
        PublishedSnapshotV1::schema_ref().0,
        ManifestId::of_blob(bytes)
    );
}

#[test]
fn a_later_collection_refusal_reports_the_already_signed_contribution() {
    pollster::block_on(async {
        let f = Fixture::with_contributor(true).await;
        let mut store = MemoryBackend::new();
        let observed = f
            .moot
            .authorized_collection(COLLECTION, 10)
            .await
            .unwrap()
            .unwrap()
            .version;
        let snapshot = PublishedSnapshotV1::decode(FIXTURES[0]).unwrap();
        let error = publication::publish_public_snapshot(
            &f.moot,
            &f.reader,
            &mut store,
            &snapshot,
            &observed,
            None,
            "Contributor".into(),
            10,
        )
        .await
        .unwrap_err();
        let contribution = error
            .contribution
            .expect("the authorized share was authored");
        assert!(error.collection_operations.is_empty());
        assert!(
            f.moot
                .authorized_fauna(10)
                .await
                .unwrap()
                .iter()
                .any(|share| share.op_hash == contribution.share)
        );
        assert!(
            f.moot
                .authorized_collection(COLLECTION, 10)
                .await
                .unwrap()
                .unwrap()
                .effective_selected
                .is_empty()
        );
    });
}

#[test]
fn binding_follows_explicit_replacement_and_refuses_ambiguity_and_withdrawal() {
    use publication::{SiteBindingV1, SiteRevisionPolicy};
    pollster::block_on(async {
        let f = Fixture::new().await;
        let mut store = MemoryBackend::new();
        let snapshot = PublishedSnapshotV1::decode(FIXTURES[0]).unwrap();
        let version = f
            .moot
            .authorized_collection(COLLECTION, 10)
            .await
            .unwrap()
            .unwrap()
            .version;
        let first = publication::publish_public_snapshot(
            &f.moot,
            &f.author,
            &mut store,
            &snapshot,
            &version,
            None,
            "Garden".into(),
            10,
        )
        .await
        .unwrap();
        let follow = SiteBindingV1 {
            version: 1,
            collection: version.collection,
            revision: SiteRevisionPolicy::FollowCollection,
        };
        let pinned = SiteBindingV1 {
            revision: SiteRevisionPolicy::Pinned {
                contribution: first.selection.contribution,
            },
            ..follow.clone()
        };
        let mut edited = snapshot.clone();
        edited
            .pages
            .get_mut("/index.gmi")
            .unwrap()
            .source
            .extend_from_slice(b"\nSaved replacement\n");
        let second = publication::publish_public_snapshot(
            &f.moot,
            &f.author,
            &mut store,
            &edited,
            &first.selection.collection,
            None,
            "Second".into(),
            11,
        )
        .await
        .unwrap();
        assert!(
            publication::open_binding(&f.moot, &mut store, &follow, 12)
                .await
                .is_err()
        );
        assert_eq!(
            publication::open_binding(&f.moot, &mut store, &pinned, 12)
                .await
                .unwrap()
                .snapshot(),
            &snapshot
        );
        let before = store.len();
        let stale = publication::publish_public_snapshot(
            &f.moot,
            &f.author,
            &mut store,
            &edited,
            &first.selection.collection,
            None,
            "Stale".into(),
            12,
        )
        .await
        .unwrap_err();
        assert!(stale.contribution.is_none());
        assert_eq!(store.len(), before);
        let receipt = f
            .moot
            .set_collection_membership_for_identity(
                &f.author,
                version.collection,
                second.selection.collection.frontier,
                CollectionChange::SetMembership {
                    contribution: first.selection.contribution,
                    included: false,
                },
                13,
            )
            .await
            .unwrap();
        assert!(
            publication::open_binding(&f.moot, &mut store, &pinned, 13)
                .await
                .is_err()
        );
        assert_eq!(
            publication::open_binding(&f.moot, &mut store, &follow, 13)
                .await
                .unwrap()
                .snapshot(),
            &edited
        );
        let _ = receipt;
        let third = publication::publish_public_snapshot(
            &f.moot,
            &f.author,
            &mut store,
            &snapshot,
            &f.moot
                .authorized_collection(COLLECTION, 14)
                .await
                .unwrap()
                .unwrap()
                .version,
            Some(second.selection.contribution),
            "Replace".into(),
            14,
        )
        .await
        .unwrap();
        assert_eq!(third.collection_operations.len(), 2);
        assert_eq!(
            publication::open_binding(&f.moot, &mut store, &follow, 14)
                .await
                .unwrap()
                .snapshot(),
            &snapshot
        );
        f.moot
            .withdraw_share_for_identity(&f.author, third.selection.contribution.share, 15)
            .await
            .unwrap();
        assert!(
            publication::open_binding(&f.moot, &mut store, &follow, 15)
                .await
                .is_err()
        );
    });
}

struct Fixture {
    author: InMemoryProvider,
    reader: InMemoryProvider,
    moot: Moot<MemoryBackend>,
    peer: Moot<MemoryBackend>,
}

impl Fixture {
    async fn new() -> Self {
        Self::with_contributor(false).await
    }

    async fn with_contributor(writer: bool) -> Self {
        let author = InMemoryProvider::from_seed([11; 32]);
        let reader = InMemoryProvider::from_seed([12; 32]);
        let root = author.master_public_key().to_bytes();
        let mut rules = ConstitutionRules::founder_only(root);
        rules.admission = mien::Policy::MembersOnly {
            rate_limit: 100,
            rate_window_ms: 1_000,
        };
        rules.grant(CapabilityGrant {
            id: [41; 32],
            subject: root,
            path_prefix: cap_path(&Cap::scope("moot").unwrap()),
            not_before_ms: 1,
            expires_at_ms: Some(100),
            delegation_depth: 0,
        });
        if writer {
            rules.grant(CapabilityGrant {
                id: [42; 32],
                subject: reader.master_public_key().to_bytes(),
                path_prefix: cap_path(&Cap::scope("moot/fauna").unwrap()),
                not_before_ms: 1,
                expires_at_ms: Some(100),
                delegation_depth: 0,
            });
        }
        let retention = MootRetentionSettings {
            revision: PolicyRevision(Digest::blake3(b"site-publication-test")),
            availability: AvailabilityPolicy {
                promised_floor: KeepBound::Forever,
            },
            erasure: ErasurePolicy {
                history_ceiling: KeepBound::UntilCheckpoint,
            },
        };
        let moot = Moot::in_memory(MootId(MOOT), root, retention.clone());
        let peer = Moot::in_memory(MootId(MOOT), root, retention);
        for instance in [&moot, &peer] {
            instance
                .found(
                    author.master_keypair().to_seed(),
                    None,
                    None,
                    rules.clone(),
                    1,
                )
                .await
                .unwrap();
        }
        let fixture = Self {
            author,
            reader,
            moot,
            peer,
        };
        let receipt = fixture
            .moot
            .update_membership_for_identity(
                &fixture.author,
                MootMembershipAction::Create {
                    initial_members: vec![
                        MootMember {
                            member: root,
                            access: MootAccessLevel::Manage,
                        },
                        MootMember {
                            member: fixture.reader.master_public_key().to_bytes(),
                            access: if writer {
                                MootAccessLevel::Write
                            } else {
                                MootAccessLevel::Read
                            },
                        },
                    ],
                },
            )
            .await
            .unwrap();
        fixture.replicate(&receipt).await;
        let receipt = fixture
            .moot
            .declare_collection_for_identity(
                &fixture.author,
                COLLECTION,
                "Published garden".into(),
                None,
                2,
            )
            .await
            .unwrap();
        fixture.replicate(&receipt).await;
        fixture
    }

    async fn replicate(&self, receipt: &MootCommandReceipt) {
        match self.moot.outbound(receipt).await.unwrap() {
            MootOutboundOperation::Membership(operation) => {
                self.peer
                    .membership_store()
                    .accept(&operation)
                    .await
                    .unwrap();
            },
            MootOutboundOperation::Object(operation) => {
                self.peer
                    .object_store()
                    .accept(MOOT, &operation)
                    .await
                    .unwrap();
            },
            _ => panic!("unexpected publication fixture lane"),
        }
    }

    async fn select(&self, id: ManifestId, store: &mut dyn Store) -> SiteSelection {
        let receipt =
            publication::contribute(&self.moot, &self.author, store, id, "Garden".into(), 10)
                .await
                .unwrap();
        self.replicate(&receipt).await;
        let contribution = ContributionRef {
            moot_id: MOOT,
            share: receipt.operation,
        };
        let view = self
            .moot
            .authorized_collection(COLLECTION, 11)
            .await
            .unwrap()
            .unwrap();
        let receipt = self
            .moot
            .set_collection_membership_for_identity(
                &self.author,
                view.collection,
                view.heads,
                CollectionChange::SetMembership {
                    contribution,
                    included: true,
                },
                11,
            )
            .await
            .unwrap();
        self.replicate(&receipt).await;
        let view = self
            .moot
            .authorized_collection(COLLECTION, 12)
            .await
            .unwrap()
            .unwrap();
        SiteSelection {
            collection: view.version,
            contribution,
        }
    }
}

async fn retain(store: &mut dyn Store, bytes: &[u8], privacy: PrivacyClass) -> ManifestId {
    let snapshot = PublishedSnapshotV1::decode(bytes).unwrap();
    bootstrap_meta_schema(store).await.unwrap();
    let schema = save_schema(
        store,
        &publication::snapshot_schema(),
        PrivacyClass::PublicPortable,
        ProvenanceRecord::self_imported("site schema"),
        TrustEnvelope::self_asserted(),
        Timestamp(3),
    )
    .await
    .unwrap();
    assert_eq!(schema, PublishedSnapshotV1::schema_ref().0);
    let id = save_typed(
        store,
        &snapshot,
        vec![],
        privacy,
        ProvenanceRecord::self_imported("saved site fixture"),
        TrustEnvelope::self_asserted(),
        Timestamp(4),
    )
    .await
    .unwrap();
    assert_eq!(id, ManifestId::of_blob(bytes));
    id
}

#[test]
fn native_profiles_reopen_on_a_replica_with_the_author_dropped() {
    pollster::block_on(async {
        for bytes in FIXTURES {
            let f = Fixture::new().await;
            let folder = tempfile::tempdir().unwrap();
            let selection;
            {
                let mut disk = RedbBackend::open(folder.path().join("site.redb")).unwrap();
                let id = retain(&mut disk, bytes, PrivacyClass::PublicPortable).await;
                selection = f.select(id, &mut disk).await;
            }
            let Fixture {
                peer,
                author,
                moot,
                reader,
            } = f;
            drop((author, moot, reader));
            let mut reopened = RedbBackend::open(folder.path().join("site.redb")).unwrap();
            let before = reopened.list("").await.unwrap();
            let site = publication::open(&peer, &mut reopened, &selection, 20)
                .await
                .unwrap();
            assert_eq!(site.snapshot().encode().unwrap(), bytes);
            let original = PublishedSnapshotV1::decode(bytes).unwrap();
            assert_eq!(site.page("/"), original.pages.values().next());
            assert_eq!(
                site.page(&format!("/{}", original.format.index_file())),
                site.page("/")
            );
            for path in ["/missing", "/../index.gmi", "/index.gmi?query", "index.gmi"] {
                assert!(site.page(path).is_none());
            }
            assert_eq!(reopened.list("").await.unwrap(), before);
        }
    });
}

#[test]
fn membership_alone_cannot_publish_or_select() {
    pollster::block_on(async {
        let f = Fixture::new().await;
        let mut store = MemoryBackend::new();
        let id = retain(&mut store, FIXTURES[0], PrivacyClass::PublicPortable).await;
        let before = f.moot.snapshot().await.unwrap().roster.fauna.len();
        assert!(
            publication::contribute(&f.moot, &f.reader, &mut store, id, "No grant".into(), 10)
                .await
                .is_err()
        );
        assert_eq!(f.moot.snapshot().await.unwrap().roster.fauna.len(), before);
        let selection = f.select(id, &mut store).await;
        assert!(
            f.moot
                .set_collection_membership_for_identity(
                    &f.reader,
                    selection.collection.collection,
                    selection.collection.frontier.clone(),
                    CollectionChange::SetMembership {
                        contribution: selection.contribution,
                        included: false
                    },
                    12,
                )
                .await
                .is_err()
        );
        // Public reading does not request a reader identity at all.
        publication::open(&f.peer, &mut store, &selection, 20)
            .await
            .unwrap();
        assert!(
            publication::open(&f.peer, &mut store, &selection, 101)
                .await
                .is_err()
        );
    });
}

#[test]
fn selection_changes_withdrawal_and_forks_use_existing_collection_history() {
    pollster::block_on(async {
        let f = Fixture::new().await;
        let mut store = MemoryBackend::new();
        let id = retain(&mut store, FIXTURES[1], PrivacyClass::PublicPortable).await;
        let old = f.select(id, &mut store).await;
        let current = f.select(id, &mut store).await;
        assert_ne!(old.contribution, current.contribution);
        assert!(
            publication::open(&f.moot, &mut store, &old, 20)
                .await
                .is_err()
        );
        let source = f
            .moot
            .authorized_collection(COLLECTION, 20)
            .await
            .unwrap()
            .unwrap();
        let fork = CollectionFork::new(source.version, source.effective_selected);
        let child = CollectionId([73; 32]);
        f.moot
            .declare_collection_for_identity(&f.author, child, "Garden fork".into(), Some(fork), 21)
            .await
            .unwrap();
        let child_view = f
            .moot
            .authorized_collection(child, 22)
            .await
            .unwrap()
            .unwrap();
        let child_selection = SiteSelection {
            collection: child_view.version,
            contribution: old.contribution,
        };
        publication::open(&f.moot, &mut store, &child_selection, 22)
            .await
            .unwrap();
        f.moot
            .withdraw_share_for_identity(&f.author, old.contribution.share, 23)
            .await
            .unwrap();
        assert!(
            publication::open(&f.moot, &mut store, &child_selection, 24)
                .await
                .is_err()
        );
        publication::open(&f.moot, &mut store, &current, 24)
            .await
            .unwrap();
        assert!(
            store
                .get(&format!("blob:{}", id.0.to_hex()))
                .await
                .unwrap()
                .is_some()
        );
    });
}

#[test]
fn private_corrupt_missing_foreign_and_unsupported_content_refuse() {
    pollster::block_on(async {
        let f = Fixture::new().await;
        let mut store = MemoryBackend::new();
        let private = retain(&mut store, FIXTURES[0], PrivacyClass::MootScoped).await;
        assert!(
            publication::contribute(
                &f.moot,
                &f.author,
                &mut store,
                private,
                "Private".into(),
                10
            )
            .await
            .is_err()
        );
        let spartan = retain(
            &mut store,
            include_bytes!("fixtures/spartan-v1.json"),
            PrivacyClass::PublicPortable,
        )
        .await;
        assert!(
            publication::contribute(
                &f.moot,
                &f.author,
                &mut store,
                spartan,
                "Spartan".into(),
                10
            )
            .await
            .is_err()
        );
        let id = retain(&mut store, FIXTURES[1], PrivacyClass::PublicPortable).await;
        let selection = f.select(id, &mut store).await;
        let mut foreign = selection.clone();
        foreign.collection.collection = CollectionRef {
            moot_id: [99; 32],
            collection_id: COLLECTION,
        };
        assert!(
            publication::open(&f.moot, &mut store, &foreign, 20)
                .await
                .is_err()
        );
        let key = format!("blob:{}", id.0.to_hex());
        store.put(&key, b"corrupt").await.unwrap();
        assert!(
            publication::open(&f.moot, &mut store, &selection, 20)
                .await
                .is_err()
        );
        store.delete(&key).await.unwrap();
        assert!(
            publication::open(&f.moot, &mut store, &selection, 20)
                .await
                .is_err()
        );
        store.put(&key, FIXTURES[1]).await.unwrap();
        let mut manifest = load_manifest(&mut store, id).await.unwrap().unwrap();
        manifest.byte_size += 1;
        save_manifest(&mut store, &manifest).await.unwrap();
        assert!(
            publication::open(&f.moot, &mut store, &selection, 20)
                .await
                .is_err()
        );
        manifest.byte_size -= 1;
        manifest.privacy = PrivacyClass::LocalOnly;
        save_manifest(&mut store, &manifest).await.unwrap();
        assert!(
            publication::open(&f.moot, &mut store, &selection, 20)
                .await
                .is_err()
        );
    });
}
