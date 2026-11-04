// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

#[tokio::test]
async fn checkpoint_survives_event_prefix_prune_and_replays_roster() {
    let authority = keypair(1);
    let store = MootStore::in_memory_with_retention(retention(&authority));
    let declared = store
        .author(
            &authority,
            MOOT,
            &MootEvent::Declared {
                name: "printing circle".into(),
                charter: "shared type".into(),
                at_ms: 1,
            },
        )
        .await
        .unwrap();
    let joined = store
        .author(
            &authority,
            MOOT,
            &MootEvent::Joined {
                name: "mark".into(),
                at_ms: 2,
            },
        )
        .await
        .unwrap();

    let checkpoint = store.build_checkpoint(MOOT, 10).await.unwrap();
    let checkpoint_operation = store
        .author(
            &authority,
            MOOT,
            &MootEvent::RetentionCheckpoint {
                checkpoint: Box::new(checkpoint),
            },
        )
        .await
        .unwrap();
    let prune = store
        .author_prune(&authority, MOOT, *checkpoint_operation.hash.as_bytes(), 11)
        .await
        .unwrap();
    let shared = store
        .author(
            &authority,
            MOOT,
            &MootEvent::Shared {
                manifest_id: [0xaa; 32],
                schema_id: "codicil/v1".into(),
                title: "retained tail".into(),
                at_ms: 12,
            },
        )
        .await
        .unwrap();

    let operations = store.ops(MOOT).await.unwrap();
    assert!(
        !operations
            .iter()
            .any(|operation| operation.hash == declared.hash)
    );
    assert!(
        !operations
            .iter()
            .any(|operation| operation.hash == joined.hash)
    );
    assert!(
        operations
            .iter()
            .any(|operation| operation.hash == checkpoint_operation.hash)
    );
    assert!(
        operations
            .iter()
            .any(|operation| operation.hash == prune.hash)
    );
    assert!(
        operations
            .iter()
            .any(|operation| operation.hash == shared.hash)
    );
    let roster = store.roster(MOOT).await.unwrap();
    assert_eq!(roster.declaration.unwrap().name, "printing circle");
    assert_eq!(roster.members.len(), 1);
    assert_eq!(roster.fauna[0].title, "retained tail");
}

#[tokio::test]
async fn checkpoint_snapshot_keeps_withdrawal_after_pruning_the_source_log() {
    let authority = keypair(1);
    let identity = InMemoryProvider::from_seed([0x22; 32]);
    let store = MootStore::in_memory_with_retention(retention(&authority));
    let share = store
        .author_for_identity(
            &identity,
            MOOT,
            &MootEvent::Shared {
                manifest_id: [0xaa; 32],
                schema_id: "fleece/v1".into(),
                title: "withdrawn page".into(),
                at_ms: 1,
            },
        )
        .await
        .unwrap();
    let withdrawal = store
        .author_for_identity(
            &identity,
            MOOT,
            &MootEvent::Withdrawn {
                target_share: *share.hash.as_bytes(),
                at_ms: 2,
            },
        )
        .await
        .unwrap();
    let checkpoint = store.build_checkpoint(MOOT, 3).await.unwrap();
    let checkpoint_operation = store
        .author(
            &authority,
            MOOT,
            &MootEvent::RetentionCheckpoint {
                checkpoint: Box::new(checkpoint),
            },
        )
        .await
        .unwrap();
    store
        .author_prune_seed(
            identity
                .derive_keypair(&object_identity_salt(MOOT))
                .unwrap()
                .to_seed(),
            MOOT,
            *checkpoint_operation.hash.as_bytes(),
            4,
        )
        .await
        .unwrap();

    let operations = store.ops(MOOT).await.unwrap();
    assert!(
        !operations
            .iter()
            .any(|operation| operation.hash == share.hash)
    );
    assert!(
        !operations
            .iter()
            .any(|operation| operation.hash == withdrawal.hash)
    );
    let roster = store.roster(MOOT).await.unwrap();
    assert_eq!(roster.fauna.len(), 1);
    assert_eq!(roster.withdrawals.len(), 1);
    assert_eq!(roster.withdrawals[0].target_share, *share.hash.as_bytes());
    assert!(
        roster
            .authorized_fauna(&RootAuthority(identity.master_public_key().to_bytes()))
            .is_empty()
    );
}

#[tokio::test]
async fn checkpoint_keeps_collection_lineage_and_accepts_a_child_after_pruning() {
    use super::super::super::collection::{
        CollectionChange, CollectionEvent, CollectionFork, CollectionId, CollectionRef,
        ContributionRef,
    };

    let checkpoint_authority = keypair(1);
    let identity = InMemoryProvider::from_seed([0x23; 32]);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("collection-lineage.redb");
    let store =
        MootStoreFile::at_path_with_retention(&path, retention(&checkpoint_authority)).unwrap();
    let share = store
        .author_for_identity(
            &identity,
            MOOT,
            &MootEvent::Shared {
                manifest_id: [0xaa; 32],
                schema_id: "fleece/v1".into(),
                title: "lineage page".into(),
                at_ms: 1,
            },
        )
        .await
        .unwrap();
    let collection_id = CollectionId([0xc1; 32]);
    let collection = CollectionRef {
        moot_id: MOOT,
        collection_id,
    };
    let declaration = store
        .author_for_identity(
            &identity,
            MOOT,
            &MootEvent::Collection {
                event: CollectionEvent::Declared {
                    collection_id,
                    name: "field notes".into(),
                    fork: None,
                    at_ms: 2,
                },
            },
        )
        .await
        .unwrap();
    let first_change = store
        .author_for_identity(
            &identity,
            MOOT,
            &MootEvent::Collection {
                event: CollectionEvent::Changed {
                    collection,
                    parents: vec![*declaration.hash.as_bytes()],
                    change: CollectionChange::SetMembership {
                        contribution: ContributionRef {
                            moot_id: MOOT,
                            share: *share.hash.as_bytes(),
                        },
                        included: true,
                    },
                    at_ms: 3,
                },
            },
        )
        .await
        .unwrap();
    let checkpoint = store.build_checkpoint(MOOT, 4).await.unwrap();
    let checkpoint_operation = store
        .author(
            &checkpoint_authority,
            MOOT,
            &MootEvent::RetentionCheckpoint {
                checkpoint: Box::new(checkpoint),
            },
        )
        .await
        .unwrap();
    store
        .author_prune_seed(
            identity
                .derive_keypair(&object_identity_salt(MOOT))
                .unwrap()
                .to_seed(),
            MOOT,
            *checkpoint_operation.hash.as_bytes(),
            5,
        )
        .await
        .unwrap();

    let operations = store.ops(MOOT).await.unwrap();
    assert!(
        !operations
            .iter()
            .any(|operation| operation.hash == declaration.hash)
    );
    assert!(
        !operations
            .iter()
            .any(|operation| operation.hash == first_change.hash)
    );
    let retained = store.roster(MOOT).await.unwrap();
    let before = retained
        .authorized_collection(
            MOOT,
            collection_id,
            &RootAuthority(identity.master_public_key().to_bytes()),
        )
        .unwrap();
    assert_eq!(before.heads, vec![*first_change.hash.as_bytes()]);

    drop(store);
    let store =
        MootStoreFile::at_path_with_retention(&path, retention(&checkpoint_authority)).unwrap();

    let fork_id = CollectionId([0xc2; 32]);
    store
        .author_for_identity(
            &identity,
            MOOT,
            &MootEvent::Collection {
                event: CollectionEvent::Declared {
                    collection_id: fork_id,
                    name: "forked notes".into(),
                    fork: Some(CollectionFork::new(
                        before.version.clone(),
                        before.selected.clone(),
                    )),
                    at_ms: 6,
                },
            },
        )
        .await
        .unwrap();
    let forked = store
        .roster(MOOT)
        .await
        .unwrap()
        .authorized_collection(
            MOOT,
            fork_id,
            &RootAuthority(identity.master_public_key().to_bytes()),
        )
        .unwrap();
    assert_eq!(forked.selected, before.selected);
    assert_eq!(forked.fork.unwrap().parent, before.version);

    let child = store
        .author_for_identity(
            &identity,
            MOOT,
            &MootEvent::Collection {
                event: CollectionEvent::Changed {
                    collection,
                    parents: before.heads,
                    change: CollectionChange::SetMembership {
                        contribution: ContributionRef {
                            moot_id: MOOT,
                            share: *share.hash.as_bytes(),
                        },
                        included: false,
                    },
                    at_ms: 7,
                },
            },
        )
        .await
        .unwrap();
    let after = store
        .roster(MOOT)
        .await
        .unwrap()
        .authorized_collection(
            MOOT,
            collection_id,
            &RootAuthority(identity.master_public_key().to_bytes()),
        )
        .unwrap();
    assert_eq!(after.heads, vec![*child.hash.as_bytes()]);
    assert!(after.selected.is_empty());
}

#[tokio::test]
async fn reopened_checkpoint_does_not_resurrect_a_late_withdrawn_share() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("withdrawal.redb");
    let authority = keypair(3);
    let identity = InMemoryProvider::from_seed([0x32; 32]);
    let (share, withdrawal) = {
        let store = MootStoreFile::at_path_with_retention(&path, retention(&authority)).unwrap();
        let share = store
            .author_for_identity(
                &identity,
                MOOT,
                &MootEvent::Shared {
                    manifest_id: [0xbb; 32],
                    schema_id: "fleece/v1".into(),
                    title: "late page".into(),
                    at_ms: 1,
                },
            )
            .await
            .unwrap();
        let withdrawal = store
            .author_for_identity(
                &identity,
                MOOT,
                &MootEvent::Withdrawn {
                    target_share: *share.hash.as_bytes(),
                    at_ms: 2,
                },
            )
            .await
            .unwrap();
        let checkpoint = store.build_checkpoint(MOOT, 3).await.unwrap();
        let checkpoint_operation = store
            .author(
                &authority,
                MOOT,
                &MootEvent::RetentionCheckpoint {
                    checkpoint: Box::new(checkpoint),
                },
            )
            .await
            .unwrap();
        store
            .author_prune_seed(
                identity
                    .derive_keypair(&object_identity_salt(MOOT))
                    .unwrap()
                    .to_seed(),
                MOOT,
                *checkpoint_operation.hash.as_bytes(),
                4,
            )
            .await
            .unwrap();
        (share, withdrawal)
    };

    let reopened = MootStoreFile::at_path_with_retention(&path, retention(&authority)).unwrap();
    let roster = reopened.roster(MOOT).await.unwrap();
    assert_eq!(roster.fauna.len(), 1);
    assert_eq!(roster.withdrawals.len(), 1);
    assert!(
        reopened.accept(MOOT, &share).await.is_err(),
        "a late prefix replay cannot pass the retained prune point"
    );
    assert!(
        reopened
            .roster(MOOT)
            .await
            .unwrap()
            .authorized_fauna(&RootAuthority(identity.master_public_key().to_bytes()))
            .is_empty()
    );
    assert_eq!(withdrawal.header.seq_num, 1);
}

/// The intake paths do NOT all return the same decision, and that is
/// deliberate — this pins the one place they diverge so it cannot be
/// "cleaned up" into agreement.
///
/// `MootPolicy` carries `allow_historical_checkpoint_authority` and
/// `allow_historical_prune`: `false` for live processing and plain-drop
/// import, `true` for the aggregate carrier. An aggregate drop bootstraps
/// a fresh peer *through a rotated checkpoint chain*, so it must accept a
/// prune naming a checkpoint that has since been superseded — exactly what
/// live intake must reject as stale, because on a live peer that prune
/// would destroy history against outdated authority.
///
/// One store, one operation, two paths, two answers. Phase B's "same
/// decision for one operation corpus" holds for everything else.
#[tokio::test]
async fn aggregate_import_admits_the_historical_prune_that_live_intake_rejects() {
    let authority = keypair(1);
    let store = MootStore::in_memory_with_retention(retention(&authority));
    store
        .author(
            &authority,
            MOOT,
            &MootEvent::Declared {
                name: "printing circle".into(),
                charter: "shared type".into(),
                at_ms: 1,
            },
        )
        .await
        .unwrap();
    let joined = store
        .author(
            &authority,
            MOOT,
            &MootEvent::Joined {
                name: "mark".into(),
                at_ms: 2,
            },
        )
        .await
        .unwrap();

    // Two checkpoints: the second supersedes the first, so a prune naming
    // the first is historical.
    let first = store.build_checkpoint(MOOT, 10).await.unwrap();
    let superseded = store
        .author(
            &authority,
            MOOT,
            &MootEvent::RetentionCheckpoint {
                checkpoint: Box::new(first),
            },
        )
        .await
        .unwrap();
    let second = store.build_checkpoint(MOOT, 20).await.unwrap();
    store
        .author(
            &authority,
            MOOT,
            &MootEvent::RetentionCheckpoint {
                checkpoint: Box::new(second),
            },
        )
        .await
        .unwrap();

    // Build the prune WITHOUT accepting it: checkpoints ride their own
    // log, so the events log still ends at `joined`.
    let prune = to_prune_operation_seed(
        authority.to_seed(),
        MOOT,
        *superseded.hash.as_bytes(),
        30,
        joined.header.seq_num + 1,
        Some(*joined.hash.as_bytes()),
    );

    // Live intake: refused, and nothing moved.
    let before = store.ops(MOOT).await.unwrap().len();
    let error = store
        .accept(MOOT, &prune)
        .await
        .expect_err("live intake rejects a prune against superseded authority");
    assert!(
        format!("{error}").contains("checkpoint-stale")
            || format!("{error:?}").contains("checkpoint-stale"),
        "rejected for staleness, not something incidental: {error:?}"
    );
    assert_eq!(
        store.ops(MOOT).await.unwrap().len(),
        before,
        "a refused prune leaves the live store unchanged"
    );

    // The aggregate carrier: the same operation, admitted, because a
    // bootstrapping peer has to walk the whole rotated chain.
    let report = store
        .import_drop_records(
            MOOT,
            stickleback::DropId([0x0d; 32]),
            vec![stickleback::operation_record(&prune, true)],
        )
        .await
        .expect("the aggregate carrier admits historical prune ancestry");
    assert_eq!(report.accepted, 1, "the divergence is real: {report:?}");
}

#[tokio::test]
async fn unauthorized_checkpoint_is_rejected_before_mutation() {
    let authority = keypair(1);
    let intruder = keypair(2);
    let store = MootStore::in_memory_with_retention(retention(&authority));
    let checkpoint = store.build_checkpoint(MOOT, 10).await.unwrap();
    let operation = super::super::super::wire::to_operation(
        &intruder,
        MOOT,
        &MootEvent::RetentionCheckpoint {
            checkpoint: Box::new(checkpoint),
        },
        0,
        None,
    );
    assert!(store.accept(MOOT, &operation).await.is_err());
    assert!(store.ops(MOOT).await.unwrap().is_empty());
}
