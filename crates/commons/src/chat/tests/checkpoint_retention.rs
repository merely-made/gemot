// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

#[tokio::test]
async fn authorized_checkpoint_plus_tail_reproduces_full_replay() {
    let seed = [0xa1; 32];
    let (keys, _) = paired_keys();
    let mut replica = ChatReplica::in_memory(SPACE, seed, keys);
    replica.set_checkpoint_authority(checkpoint_authority(seed, b"commons authority 1"));
    replica
        .author(ChatEvent::Channel(Channel {
            id: "general".into(),
            title: "General".into(),
        }))
        .await
        .unwrap();
    replica
        .author(ChatEvent::Message(Message {
            channel: "general".into(),
            body: "represented by the checkpoint".into(),
            sent_at_ms: 1,
            reply_to: None,
        }))
        .await
        .unwrap();

    let first = replica.author_checkpoint().await.unwrap();
    let stored = replica.latest_checkpoint().await.unwrap().unwrap();
    assert_eq!(stored.operation, *first.hash.as_bytes());
    assert_eq!(stored.checkpoint.previous_checkpoint, None);
    assert_eq!(
        stored.checkpoint.snapshot_commitment,
        ChatCheckpoint::snapshot_commitment(&stored.checkpoint.snapshot).unwrap()
    );
    assert_eq!(
        encrypted_body(&first).unwrap().epoch,
        stored.checkpoint.current_epoch
    );

    replica
        .author(ChatEvent::Message(Message {
            channel: "general".into(),
            body: "retained tail".into(),
            sent_at_ms: 2,
            reply_to: None,
        }))
        .await
        .unwrap();
    assert_eq!(
        replica.projection().await.unwrap(),
        full_replay(&replica, &AllowAllAuthority).await.unwrap()
    );

    let second = replica.author_checkpoint().await.unwrap();
    assert_eq!(
        replica
            .latest_checkpoint()
            .await
            .unwrap()
            .unwrap()
            .checkpoint
            .previous_checkpoint,
        Some(*first.hash.as_bytes())
    );
    assert_ne!(first.hash, second.hash);
}

#[tokio::test]
async fn pending_fact_keeps_its_ciphertext_epoch_reachable() {
    let seed = [0xa1; 32];
    let (keys, _) = paired_keys();
    let mut replica = ChatReplica::in_memory(SPACE, seed, keys);
    replica.set_checkpoint_authority(checkpoint_authority(seed, b"commons authority 1"));
    let pending = event_operation(
        &replica,
        &ChatEvent::Message(Message {
            channel: "general".into(),
            body: "waiting for a missing parent".into(),
            sent_at_ms: 3,
            reply_to: None,
        }),
        seed,
        vec![[0xfe; 32]],
        0,
        None,
    );
    let pending_epoch = encrypted_body(&pending).unwrap().epoch;
    replica.accept(&pending).await.unwrap();
    let mut rotated = DataKeyring::from_bytes(&replica.key_state().unwrap()).unwrap();
    for _ in 0..9 {
        rotated.rotate(&p2panda_encryption::Rng::default()).unwrap();
    }
    replica.keys().replace(rotated);

    let checkpoint = replica.build_checkpoint().await.unwrap();
    assert_eq!(
        checkpoint.holds,
        vec![ChatEpochHold {
            epoch: pending_epoch,
            reason: ChatEpochHoldReason::PendingCausality,
            operations: vec![*pending.hash.as_bytes()],
        }]
    );
    replica.author_checkpoint().await.unwrap();
    assert_eq!(
        replica.projection().await.unwrap(),
        full_replay(&replica, &AllowAllAuthority).await.unwrap()
    );
    let proposal = replica.epoch_pruning_proposal(&[]).await.unwrap();
    assert!(proposal.is_executable());
    assert!(!proposal.forget.contains(&pending_epoch));
    assert!(proposal.retain.iter().any(|retained| {
        retained.epoch == pending_epoch
            && retained
                .reasons
                .contains(&stickleback::EpochRetentionReason::Domain(
                    EpochHoldReason::PendingCausality,
                ))
    }));
}

#[tokio::test]
async fn commons_proposal_combines_profile_tail_and_offline_member_holds() {
    let seed = [0xa1; 32];
    let mut keys = DataKeyring::new();
    let mut epochs = Vec::new();
    for _ in 0..10 {
        epochs.push(
            keys.rotate(&p2panda_encryption::Rng::default())
                .unwrap()
                .id(),
        );
    }
    let mut replica = ChatReplica::in_memory(SPACE, seed, keys);
    replica.set_checkpoint_authority(checkpoint_authority(seed, b"commons authority 1"));
    replica.author_checkpoint().await.unwrap();

    let ordinary = replica.epoch_pruning_proposal(&[]).await.unwrap();
    assert!(ordinary.is_executable());
    assert_eq!(ordinary.forget, epochs[..2]);

    let offline = replica
        .epoch_pruning_proposal(&[OfflineMemberEpochHold {
            member: [0xb2; 32],
            epoch: epochs[0],
        }])
        .await
        .unwrap();
    assert!(offline.is_executable());
    assert_eq!(offline.forget, vec![epochs[1]]);
    assert!(offline.retain.iter().any(|retained| {
        retained.epoch == epochs[0]
            && retained
                .reasons
                .contains(&stickleback::EpochRetentionReason::Domain(
                    EpochHoldReason::OfflineMember([0xb2; 32]),
                ))
    }));
}

#[tokio::test]
async fn host_pruning_reopens_from_the_persisted_session() {
    use crate::keys::test_group::{Group, keyring};

    let seed = [0xa1; 32];
    let directory = tempfile::tempdir().unwrap();
    let backend = RedbBackend::open(directory.path().join("commons.redb")).unwrap();
    let mut group = Group::found();
    let keys = GroupKeys::new(keyring(&group.a));
    let authority = checkpoint_authority(seed, b"commons authority 1");
    let mut replica = ChatReplica::new(backend.clone(), SPACE, seed, keys.clone());
    replica.set_checkpoint_authority(authority.clone());
    replica
        .author(message("sealed before rotation", 1))
        .await
        .unwrap();
    for _ in 0..9 {
        group.rotate();
    }
    keys.replace(keyring(&group.a));
    let epochs = keys.current().epochs_oldest_first().unwrap().to_vec();
    replica.author_checkpoint().await.unwrap();
    replica.author_checkpoint().await.unwrap();
    let before = replica.projection().await.unwrap();

    let release = crate::pruning::host::apply(
        &mut group.a,
        &keys,
        &[replica.epoch_report(&[]).await.unwrap()],
    );
    assert_eq!(release.release, epochs[..2]);
    assert_eq!(group.a.epoch_count(), 8);
    assert_eq!(keys.current().epochs_oldest_first().unwrap(), &epochs[2..]);

    // Reopen from the persisted session, not from anything chat stored.
    let session = stickleback::GroupSession::from_bytes(&group.a.to_bytes().unwrap()).unwrap();
    let reopened_keys = GroupKeys::from_bytes(&session.data_keyring_state().unwrap()).unwrap();
    let mut reopened = ChatReplica::new(backend, SPACE, seed, reopened_keys);
    reopened.set_checkpoint_authority(authority);
    assert_eq!(
        reopened.keys.current().epochs_oldest_first().unwrap(),
        &epochs[2..]
    );
    assert_eq!(
        reopened.offline_member_recovery(epochs[2]).await.unwrap(),
        OfflineMemberRecovery::Resume
    );
    assert!(matches!(
        reopened.offline_member_recovery(epochs[0]).await.unwrap(),
        OfflineMemberRecovery::BootstrapRequired {
            checkpoint: Some(_)
        }
    ));
    assert!(
        matches!(
            full_replay(&reopened, &AllowAllAuthority).await,
            Err(ChatError::Crypto(GroupCryptoError::UnknownEpoch(_)))
        ),
        "positive control: the message's epoch is gone"
    );
    assert_eq!(reopened.projection().await.unwrap(), before);
}

#[tokio::test]
async fn host_pruning_a_checkpoint_covered_epoch_keeps_chat_working() {
    use crate::keys::test_group::{Group, keyring};

    let mut group = Group::found();
    let a_keys = GroupKeys::new(keyring(&group.a));
    let b_keys = GroupKeys::new(keyring(&group.b));
    let a_seed = [0xa1; 32];
    let mut a = ChatReplica::in_memory(SPACE, a_seed, a_keys.clone());
    a.set_checkpoint_authority(checkpoint_authority(a_seed, b"pruning authority"));
    let mut b = ChatReplica::in_memory(SPACE, [0xb2; 32], b_keys.clone());

    let early = a.author(message("founding epoch", 1)).await.unwrap();
    let founding = encrypted_body(&early).unwrap().epoch;
    assert!(b.accept(&early).await.unwrap());
    for _ in 0..9 {
        group.rotate();
    }
    a_keys.replace(keyring(&group.a));
    b_keys.replace(keyring(&group.b));
    a.author_checkpoint().await.unwrap();
    let before = a.projection().await.unwrap();

    let released = host_prune(&mut group.a, &a_keys, &a).await;
    assert!(released.contains(&founding), "{released:?}");
    assert!(!a_keys.current().contains(&founding));

    assert_eq!(a.projection().await.unwrap(), before);
    let peer = b.author(message("from the peer", 2)).await.unwrap();
    assert!(a.accept(&peer).await.unwrap());
    a.author(message("after pruning", 3)).await.unwrap();
    assert_eq!(
        bodies(&a.projection().await.unwrap()),
        ["founding epoch", "from the peer", "after pruning"]
    );
}

#[tokio::test]
async fn the_latest_checkpoint_is_found_after_an_older_checkpoint_epoch_is_released() {
    use crate::keys::test_group::{Group, keyring};

    let mut group = Group::found();
    let keys = GroupKeys::new(keyring(&group.a));
    let seed = [0xa1; 32];
    let mut a = ChatReplica::in_memory(SPACE, seed, keys.clone());
    a.set_checkpoint_authority(checkpoint_authority(seed, b"pruning authority"));
    a.author(message("founding epoch", 1)).await.unwrap();
    let first = a.author_checkpoint().await.unwrap();
    let first_epoch = encrypted_body(&first).unwrap().epoch;
    for _ in 0..9 {
        group.rotate();
    }
    keys.replace(keyring(&group.a));
    let second = a.author_checkpoint().await.unwrap();

    let released = host_prune(&mut group.a, &keys, &a).await;
    assert!(released.contains(&first_epoch), "{released:?}");
    assert!(
        matches!(
            decode_checkpoint_operation(&keys.current(), &first),
            Err(ChatError::Crypto(GroupCryptoError::UnknownEpoch(_)))
        ),
        "positive control: the older checkpoint is unreadable"
    );
    let latest = a.latest_checkpoint().await.unwrap().unwrap();
    assert_eq!(latest.operation, *second.hash.as_bytes());
    assert_eq!(
        latest.checkpoint.previous_checkpoint,
        Some(*first.hash.as_bytes())
    );
    let third = a.author_checkpoint().await.unwrap();
    assert_eq!(
        a.latest_checkpoint().await.unwrap().unwrap().operation,
        *third.hash.as_bytes()
    );
}
