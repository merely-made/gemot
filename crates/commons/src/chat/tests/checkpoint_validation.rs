// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

#[tokio::test]
async fn stale_foreign_forged_and_rewinding_checkpoints_do_not_mutate() {
    let seed = [0xa1; 32];
    let (keys, _) = paired_keys();
    let mut replica = ChatReplica::in_memory(SPACE, seed, keys);
    replica.set_checkpoint_authority(checkpoint_authority(seed, b"commons authority 1"));
    replica
        .author(ChatEvent::Message(Message {
            channel: "general".into(),
            body: "checkpoint base".into(),
            sent_at_ms: 4,
            reply_to: None,
        }))
        .await
        .unwrap();
    let first = replica.author_checkpoint().await.unwrap();
    let current = replica.latest_checkpoint().await.unwrap().unwrap();
    let candidate = replica.build_checkpoint().await.unwrap();

    let mut stale = candidate.clone();
    stale.previous_checkpoint = None;
    assert!(
        replica
            .accept(&checkpoint_operation(
                &replica,
                &stale,
                seed,
                1,
                Some(*first.hash.as_bytes()),
            ))
            .await
            .is_err()
    );

    let mut foreign = candidate.clone();
    foreign.space_id = [0xf0; 32];
    assert!(
        replica
            .accept(&checkpoint_operation(
                &replica,
                &foreign,
                seed,
                1,
                Some(*first.hash.as_bytes()),
            ))
            .await
            .is_err()
    );

    let mut old_authority = candidate.clone();
    old_authority.authority_revision = Digest::blake3(b"superseded authority");
    assert!(
        replica
            .accept(&checkpoint_operation(
                &replica,
                &old_authority,
                seed,
                1,
                Some(*first.hash.as_bytes()),
            ))
            .await
            .is_err()
    );

    let mut rewinding = candidate.clone();
    rewinding.author_frontiers[0].operation = [0x99; 32];
    assert!(
        replica
            .accept(&checkpoint_operation(
                &replica,
                &rewinding,
                seed,
                1,
                Some(*first.hash.as_bytes()),
            ))
            .await
            .is_err()
    );

    let mut forged =
        checkpoint_operation(&replica, &candidate, seed, 1, Some(*first.hash.as_bytes()));
    forged.header.seq_num = 2;
    assert!(replica.accept(&forged).await.is_err());

    assert_eq!(replica.latest_checkpoint().await.unwrap(), Some(current));
}

#[tokio::test]
async fn a_writer_revoked_after_a_checkpoint_loses_covered_records_before_and_after_pruning() {
    use crate::keys::test_group::{Group, keyring};

    let founder = InMemoryProvider::from_seed([0x71; 32]);
    let writer = InMemoryProvider::from_seed([0x72; 32]);
    let subject = writer.master_public_key().to_bytes();
    let mut group = Group::found();
    let keys = GroupKeys::new(keyring(&group.a));
    let mut f = ChatReplica::in_memory_for_identity(SPACE, &founder, keys.clone()).unwrap();
    f.set_checkpoint_authority(ChatCheckpointAuthority::new(
        Digest::blake3(b"revocation checkpoint"),
        [founder.master_public_key().to_bytes()],
    ));
    let mut w = ChatReplica::in_memory_for_identity(SPACE, &writer, keyring(&group.b)).unwrap();
    let hall = |title: &str| {
        ChatEvent::Channel(Channel {
            id: "hall".into(),
            title: title.into(),
        })
    };
    let founded = f.author(hall("Hall")).await.unwrap();
    assert!(w.accept(&founded).await.unwrap());
    let renamed = w.author(hall("Writer's hall")).await.unwrap();
    let written = w.author(message("covered", 1)).await.unwrap();
    for operation in [&renamed, &written] {
        assert!(f.accept(operation).await.unwrap());
    }
    for _ in 0..9 {
        group.rotate();
    }
    keys.replace(keyring(&group.a));
    f.author_checkpoint().await.unwrap();

    let (granted, granted_rules) = chat_authority_fixture(&founder, subject, false);
    let (withdrawn, withdrawn_rules) = chat_authority_fixture(&founder, subject, true);
    let granted = gemot_view(&granted, &granted_rules);
    let withdrawn = gemot_view(&withdrawn, &withdrawn_rules);
    let check = |effective: &ChatProjection, filtered: &ChatProjection| {
        assert_eq!(bodies(effective), ["covered"]);
        assert_eq!(effective.channels[0].title, "Writer's hall");
        assert!(
            filtered.messages.is_empty(),
            "revoked content must not project"
        );
        assert_eq!(
            filtered.channels[0].title, "Hall",
            "the founder's write returns"
        );
        let revoked: BTreeSet<_> = filtered.revoked.iter().map(|op| op.operation).collect();
        assert_eq!(
            revoked,
            BTreeSet::from([*renamed.hash.as_bytes(), *written.hash.as_bytes()])
        );
        assert!(filtered.revoked.iter().all(|op| op.subject == subject));
    };

    let effective = f.projection_with_authority(&granted).await.unwrap();
    let filtered = f.projection_with_authority(&withdrawn).await.unwrap();
    check(&effective, &filtered);
    assert_eq!(effective, full_replay(&f, &granted).await.unwrap());
    assert_eq!(filtered, full_replay(&f, &withdrawn).await.unwrap());

    host_prune(&mut group.a, &keys, &f).await;
    assert!(
        matches!(
            full_replay(&f, &withdrawn).await,
            Err(ChatError::Crypto(GroupCryptoError::UnknownEpoch(_)))
        ),
        "positive control: the covered records are no longer readable"
    );
    assert_eq!(
        f.projection_with_authority(&granted).await.unwrap(),
        effective
    );
    assert_eq!(
        f.projection_with_authority(&withdrawn).await.unwrap(),
        filtered
    );
}

#[tokio::test]
async fn a_concurrent_record_after_a_checkpoint_folds_in_full_replay_order() {
    let key = |seed: [u8; 32]| *SigningKey::from_bytes(&seed).verifying_key().as_bytes();
    let (low, high) = if key([0x11; 32]) < key([0x22; 32]) {
        ([0x11; 32], [0x22; 32])
    } else {
        ([0x22; 32], [0x11; 32])
    };
    let (high_keys, low_keys) = paired_keys();
    let mut committed = ChatReplica::in_memory(SPACE, high, high_keys);
    committed.set_checkpoint_authority(checkpoint_authority(high, b"order authority"));
    let mut concurrent = ChatReplica::in_memory(SPACE, low, low_keys);
    committed.author(message("committed", 1)).await.unwrap();
    committed.author_checkpoint().await.unwrap();
    let late = concurrent.author(message("late", 2)).await.unwrap();
    assert!(committed.accept(&late).await.unwrap());

    // The lower key orders first between concurrent records, checkpoint or not.
    let projection = committed.projection().await.unwrap();
    assert_eq!(bodies(&projection), ["late", "committed"]);
    assert_eq!(
        projection,
        full_replay(&committed, &AllowAllAuthority).await.unwrap()
    );
}

#[tokio::test]
async fn a_version_one_checkpoint_is_refused_by_name() {
    let seed = [0xa1; 32];
    let (keys, _) = paired_keys();
    let mut replica = ChatReplica::in_memory(SPACE, seed, keys);
    replica.set_checkpoint_authority(checkpoint_authority(seed, b"commons authority 1"));
    replica.author(message("before", 1)).await.unwrap();
    let mut legacy = replica.build_checkpoint().await.unwrap();
    legacy.version = 1;
    let unlinked = linked_checkpoint_operation(&replica, &legacy, seed, 0, None, None);
    assert!(matches!(
        replica.accept(&unlinked).await,
        Err(ChatError::Process(ProcessError::Rejected(reject)))
            if reject.code == "unsupported-chat-checkpoint-version"
    ));
    assert!(replica.latest_checkpoint().await.unwrap().is_none());

    // One already retained is refused by name on read.
    OperationProcessor::new(replica.sync_store(), UncheckedChat)
        .process(&unlinked)
        .await
        .unwrap();
    assert!(matches!(
        replica.projection().await,
        Err(ChatError::UnsupportedCheckpointVersion(1))
    ));
}
