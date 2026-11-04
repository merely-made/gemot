// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

/// Replicas built before a rotation follow it through their key handles.
/// `stale` is B's twin whose handle is never replaced; C is removed.
#[tokio::test]
async fn chat_replicas_follow_a_rotation_through_their_key_handles() {
    use crate::keys::test_group::{Group, keyring};

    let mut group = Group::found();
    let a_keys = GroupKeys::new(keyring(&group.a));
    let b_keys = GroupKeys::new(keyring(&group.b));
    let stale_keys = GroupKeys::new(keyring(&group.b));
    let c_keys = GroupKeys::new(keyring(&group.c));
    let mut a = ChatReplica::in_memory(SPACE, [0xa1; 32], a_keys.clone());
    let b = ChatReplica::in_memory(SPACE, [0xb2; 32], b_keys.clone());
    let stale = ChatReplica::in_memory(SPACE, [0xb3; 32], stale_keys.clone());
    let c = ChatReplica::in_memory(SPACE, [0xc3; 32], c_keys.clone());
    let message = |body: &str, sent_at_ms| {
        ChatEvent::Message(Message {
            channel: "general".into(),
            body: body.into(),
            sent_at_ms,
            reply_to: None,
        })
    };

    let before = a.author(message("before rotation", 1)).await.unwrap();
    for replica in [&b, &stale, &c] {
        assert!(replica.accept(&before).await.unwrap(), "positive control");
    }

    group.remove_c_and_rotate();
    a_keys.replace(keyring(&group.a));
    b_keys.replace(keyring(&group.b));
    c_keys.replace(keyring(&group.c));

    let after = a.author(message("after rotation", 2)).await.unwrap();
    let rotated = a_keys.current().current_epoch().unwrap();
    assert_eq!(
        encrypted_body(&before).unwrap().epoch,
        group.c.current_epoch().unwrap()
    );
    assert_eq!(encrypted_body(&after).unwrap().epoch, rotated);
    assert!(b.accept(&after).await.unwrap());
    assert_eq!(
        bodies(&b.projection().await.unwrap()),
        ["before rotation", "after rotation"]
    );
    for (who, replica) in [("stale handle", &stale), ("removed member", &c)] {
        assert!(!replica.accept(&after).await.unwrap(), "{who} parks it");
        assert_eq!(replica.parking_status().await.unwrap().parked, 1, "{who}");
        assert_eq!(
            bodies(&replica.projection().await.unwrap()),
            ["before rotation"],
            "{who}"
        );
    }

    // Once its handle is replaced the stale replica re-admits the record.
    stale_keys.replace(keyring(&group.b));
    assert_eq!(stale.readmit_parked().await.unwrap().admitted, 1);
    assert_eq!(
        stale.projection().await.unwrap(),
        b.projection().await.unwrap()
    );
}

#[tokio::test]
async fn a_member_behind_a_rotation_parks_then_readmits_in_order() {
    use crate::keys::test_group::keyring;

    let (group, a, b, [first, second]) = behind_a_rotation(MemoryBackend::new()).await;
    for operation in [&first, &second] {
        assert!(!b.accept(operation).await.unwrap(), "parked, not accepted");
    }
    let status = b.parking_status().await.unwrap();
    assert_eq!((status.parked, status.evicted_total), (2, 0));
    assert_eq!(b.sync_store().operation_count().await.unwrap(), 1);
    assert_eq!(bodies(&b.projection().await.unwrap()), ["before rotation"]);
    let unrefreshed = b.readmit_parked().await.unwrap();
    assert_eq!(
        unrefreshed,
        ReadmitReport {
            still_parked: 2,
            ..ReadmitReport::default()
        }
    );

    b.keys().replace(keyring(&group.b));
    let report = b.readmit_parked().await.unwrap();
    assert_eq!(
        report,
        ReadmitReport {
            admitted: 2,
            ..ReadmitReport::default()
        }
    );
    assert_eq!(b.parking_status().await.unwrap(), ParkingStatus::default());
    let projection = b.projection().await.unwrap();
    assert_eq!(
        bodies(&projection),
        [
            "before rotation",
            "first after rotation",
            "second after rotation"
        ]
    );
    assert_eq!(projection, a.projection().await.unwrap());
}

/// The re-admission's insert carries its own unparking write, so the
/// record becomes stored and stops being parked in one commit: no crash
/// can strand a stored record in the parking area. Stickleback's
/// `process_with_writes` tests show that batch applies both or neither.
#[tokio::test]
async fn a_readmitted_record_is_stored_and_unparked_in_one_commit() {
    use crate::keys::test_group::keyring;

    let backend = MemoryBackend::new();
    let (group, _, b, [first, second]) = behind_a_rotation(backend.clone()).await;
    let parked = format!(
        "{}/parking/records/",
        stickleback::lane_id(COMMONS_CHAT_LANE, SPACE)
    );
    for operation in [&first, &second] {
        assert!(!b.accept(operation).await.unwrap(), "parked, not accepted");
    }
    assert_eq!(backend.list(&parked).await.unwrap().len(), 2);
    let store = b.sync_store();
    for operation in [&first, &second] {
        assert!(
            store
                .get_operation(&operation.hash)
                .await
                .unwrap()
                .is_none()
        );
    }

    b.keys().replace(keyring(&group.b));
    assert_eq!(b.readmit_parked().await.unwrap().admitted, 2);
    for operation in [&first, &second] {
        assert!(
            store
                .get_operation(&operation.hash)
                .await
                .unwrap()
                .is_some()
        );
    }
    assert!(
        backend.list(&parked).await.unwrap().is_empty(),
        "stored and still parked is never observable"
    );
    assert_eq!(b.parking_status().await.unwrap(), ParkingStatus::default());
}

#[tokio::test]
async fn a_successor_under_a_held_epoch_parks_behind_its_parked_predecessor() {
    use crate::keys::test_group::keyring;

    let (group, a, b, [first, second]) = behind_a_rotation(MemoryBackend::new()).await;
    assert!(!b.accept(&first).await.unwrap());
    b.keys().replace(keyring(&group.b));
    assert!(
        !b.accept(&second).await.unwrap(),
        "readable, but its predecessor is parked"
    );
    assert_eq!(b.parking_status().await.unwrap().parked, 2);

    // Positive control: with nothing parked the same record is refused.
    let fresh = ChatReplica::in_memory(SPACE, [0xb3; 32], keyring(&group.b));
    assert!(matches!(
        fresh.accept(&second).await,
        Err(ChatError::Process(ProcessError::MissingPredecessor { .. }))
    ));
    assert_eq!(fresh.parking_status().await.unwrap().parked, 0);

    assert_eq!(b.readmit_parked().await.unwrap().admitted, 2);
    assert_eq!(b.projection().await.unwrap(), a.projection().await.unwrap());
}

#[tokio::test]
async fn a_removed_member_keeps_parked_records_within_its_bound() {
    use crate::keys::test_group::{Group, keyring};

    let mut group = Group::found();
    let a_keys = GroupKeys::new(keyring(&group.a));
    let mut a = ChatReplica::in_memory(SPACE, [0xa1; 32], a_keys.clone());
    let c = ChatReplica::in_memory(SPACE, [0xc3; 32], keyring(&group.c)).with_parking_limits(
        ParkingLimits {
            max_records: 2,
            ..ParkingLimits::default()
        },
    );
    let before = a.author(message("before removal", 1)).await.unwrap();
    assert!(c.accept(&before).await.unwrap(), "positive control");
    group.remove_c_and_rotate();
    a_keys.replace(keyring(&group.a));
    // C's host drains the same frames and refreshes; it installs nothing.
    c.keys().replace(keyring(&group.c));

    let mut after = Vec::new();
    for turn in 0..3u64 {
        let body = format!("after removal {turn}");
        after.push(a.author(message(&body, 2 + turn)).await.unwrap());
    }
    for operation in &after {
        assert!(!c.accept(operation).await.unwrap());
    }
    let evicted_oldest = ReadmitReport {
        still_parked: 2,
        evicted_total: 1,
        ..ReadmitReport::default()
    };
    for _ in 0..2 {
        assert_eq!(c.readmit_parked().await.unwrap(), evicted_oldest);
    }
    let status = c.parking_status().await.unwrap();
    assert_eq!((status.parked, status.evicted_total), (2, 1));
    assert_eq!(bodies(&c.projection().await.unwrap()), ["before removal"]);
    assert_eq!(c.sync_store().operation_count().await.unwrap(), 1);

    // The oldest was the one evicted: given the epoch (a stand-in for being
    // re-added), the survivors wait on it until it is offered again.
    c.keys().replace(keyring(&group.b));
    assert_eq!(c.readmit_parked().await.unwrap(), evicted_oldest);
    assert!(c.accept(&after[0]).await.unwrap());
    assert_eq!(
        c.readmit_parked().await.unwrap(),
        ReadmitReport {
            admitted: 2,
            evicted_total: 1,
            ..ReadmitReport::default()
        }
    );
    assert_eq!(c.projection().await.unwrap(), a.projection().await.unwrap());
}

#[tokio::test]
async fn the_byte_bound_evicts_the_oldest_parked_record() {
    let (_, _, b, [first, second]) = behind_a_rotation(MemoryBackend::new()).await;
    assert!(!b.accept(&first).await.unwrap());
    let one = b.parking_status().await.unwrap().parked_bytes;
    let bounded = ChatReplica::new(MemoryBackend::new(), SPACE, [0xb3; 32], b.keys().clone())
        .with_parking_limits(ParkingLimits {
            max_bytes: one * 3 / 2,
            ..ParkingLimits::default()
        });
    for operation in [&first, &second] {
        assert!(!bounded.accept(operation).await.unwrap());
    }
    let status = bounded.parking_status().await.unwrap();
    assert_eq!((status.parked, status.evicted_total), (1, 1));
    assert!(status.parked_bytes <= one * 3 / 2);
}

#[tokio::test]
async fn parked_records_survive_reopening_the_replica() {
    use crate::keys::test_group::keyring;

    let backend = MemoryBackend::new();
    let (group, a, b, [first, second]) = behind_a_rotation(backend.clone()).await;
    for operation in [&first, &second] {
        assert!(!b.accept(operation).await.unwrap());
    }
    drop(b);

    let reopened = ChatReplica::new(backend, SPACE, [0xb2; 32], keyring(&group.b));
    assert_eq!(reopened.parking_status().await.unwrap().parked, 2);
    assert_eq!(reopened.readmit_parked().await.unwrap().admitted, 2);
    assert_eq!(
        reopened.projection().await.unwrap(),
        a.projection().await.unwrap()
    );
}

#[tokio::test]
async fn a_tampered_ciphertext_or_another_space_is_refused_not_parked() {
    use crate::keys::test_group::keyring;

    let (group, _, b, [first, _]) = behind_a_rotation(MemoryBackend::new()).await;
    b.keys().replace(keyring(&group.b));
    let plaintext = encode_cbor(&ChatAuthored::new(message("sealed", 9), None)).unwrap();
    let mut tampered = b.keys().current().seal_random(&plaintext).unwrap();
    tampered.ciphertext[0] ^= 1;
    let refusal = b
        .accept(&signed_envelope(SPACE, [0xd4; 32], &tampered))
        .await
        .unwrap_err();
    assert!(
        matches!(&refusal, ChatError::Process(ProcessError::Rejected(reject)) if reject.code == "unreadable-chat-event"),
        "{refusal}"
    );

    let mut other_group = DataKeyring::new();
    other_group.rotate_random().unwrap();
    let foreign = other_group.seal_random(&plaintext).unwrap();
    let refusal = b
        .accept(&signed_envelope([0x99; 32], [0xd4; 32], &foreign))
        .await
        .unwrap_err();
    assert!(
        matches!(&refusal, ChatError::Process(ProcessError::Rejected(reject)) if reject.code == "wrong-chat-space"),
        "{refusal}"
    );
    assert_eq!(b.parking_status().await.unwrap(), ParkingStatus::default());
    assert_eq!(b.sync_store().operation_count().await.unwrap(), 1);

    // Positive controls: epoch ids name no group, so the same foreign
    // ciphertext addressed here parks; the untampered record is admitted.
    assert!(
        !b.accept(&signed_envelope(SPACE, [0xd4; 32], &foreign))
            .await
            .unwrap()
    );
    assert_eq!(b.parking_status().await.unwrap().parked, 1);
    assert!(b.accept(&first).await.unwrap());
}

#[tokio::test]
async fn repeated_and_reordered_delivery_parks_each_record_once() {
    use crate::keys::test_group::keyring;

    let (group, a, b, [first, second]) = behind_a_rotation(MemoryBackend::new()).await;
    for operation in [&second, &first, &second, &first] {
        assert!(!b.accept(operation).await.unwrap());
    }
    assert_eq!(b.parking_status().await.unwrap().parked, 2);

    // `second` arrived first; causal order re-admits `first` before it.
    b.keys().replace(keyring(&group.b));
    assert_eq!(
        b.readmit_parked().await.unwrap(),
        ReadmitReport {
            admitted: 2,
            ..ReadmitReport::default()
        }
    );
    assert!(!b.accept(&first).await.unwrap(), "now a stored duplicate");
    assert_eq!(b.parking_status().await.unwrap().parked, 0);
    assert_eq!(b.projection().await.unwrap(), a.projection().await.unwrap());
}
