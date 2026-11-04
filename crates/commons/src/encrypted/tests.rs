// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use chartulary::Author;
use muniment::MemoryBackend;
use servitor::{Cap, Mode, Subject};
use stickleback::{GroupSecretId, decode_operation_record, operation_record};

use super::*;
use crate::keys::test_group::{Group, keyring};
use crate::tests::{cites, fingerprint};
use crate::{AuthorityState, COMMONS_GRAPH_LANE, CommonsExt, Replica, from_operation};
use p2panda_core::cbor::decode_cbor;

const CONTAINER: [u8; 32] = [0xc0; 32];

fn founding_keyring() -> DataKeyring {
    let mut keys = DataKeyring::new();
    keys.rotate_random().unwrap();
    keys
}

fn epoch_of(operation: &Operation<EncryptedCommonsExt>) -> GroupSecretId {
    let body = operation.body.as_ref().unwrap().to_bytes();
    decode_cbor::<GroupCiphertext, _>(body.as_slice())
        .unwrap()
        .epoch
}

fn node_ids(projection: &CommonsProjection) -> Vec<String> {
    let (nodes, _) = fingerprint(&projection.graph);
    nodes.into_iter().map(|(id, _, _)| id).collect()
}

/// Withdraws one writer, keeps everyone else effective.
struct RevokeWriter([u8; 32]);

impl CommonsAuthority for RevokeWriter {
    fn classify(&self, subject: Subject, _: &Cap, _: Mode) -> AuthorityState {
        if subject.0 == self.0 {
            AuthorityState::Revoked
        } else {
            AuthorityState::Effective
        }
    }
}

/// The same edits, in the same order, against either profile's pair.
macro_rules! shared_script {
    ($alice:ident, $bob:ident) => {{
        let author = Author::new("ui");
        let x = $alice
            .edit(|g| {
                g.insert_node(&author, Container::new("x").with_title("sealed title"));
            })
            .await
            .unwrap();
        $bob.accept(&x).await.unwrap();
        let y = $bob
            .edit(|g| {
                g.insert_node(&author, Container::new("y"));
            })
            .await
            .unwrap();
        $alice.accept(&y).await.unwrap();
        // Concurrent: neither has seen the other's next batch.
        let edge = $alice
            .edit(|g| {
                g.connect(&author, &"x".to_string(), &"y".to_string(), cites())
                    .unwrap();
            })
            .await
            .unwrap();
        let z = $bob
            .edit(|g| {
                g.insert_node(&author, Container::new("z"));
            })
            .await
            .unwrap();
        $alice.accept(&z).await.unwrap();
        $bob.accept(&edge).await.unwrap();
        x
    }};
}

#[tokio::test]
async fn encrypted_members_converge_on_the_plaintext_projection() {
    let keys = founding_keyring().to_bytes().unwrap();
    let (alice_seed, bob_seed) = ([0x61; 32], [0x62; 32]);
    let mut alice = EncryptedReplica::new(
        MemoryBackend::new(),
        CONTAINER,
        alice_seed,
        GroupKeys::from_bytes(&keys).unwrap(),
    );
    let mut bob = EncryptedReplica::new(
        MemoryBackend::new(),
        CONTAINER,
        bob_seed,
        GroupKeys::from_bytes(&keys).unwrap(),
    );
    let mut plain_alice = Replica::new(MemoryBackend::new(), CONTAINER, alice_seed);
    let mut plain_bob = Replica::new(MemoryBackend::new(), CONTAINER, bob_seed);

    let sealed = shared_script!(alice, bob);
    shared_script!(plain_alice, plain_bob);

    let expected = fingerprint(&plain_alice.projection().await.unwrap().graph);
    assert_eq!(expected.0.len(), 3, "x, y and z");
    assert_eq!(expected.1.len(), 1, "one edge");
    assert_eq!(
        fingerprint(&plain_bob.projection().await.unwrap().graph),
        expected
    );
    for (who, replica) in [("alice", &alice), ("bob", &bob)] {
        let projection = replica.projection().await.unwrap();
        assert!(projection.pending.is_empty(), "{who}");
        assert_eq!(fingerprint(&projection.graph), expected, "{who}");
    }

    // Authority classification folds the same way over decrypted records.
    let bob_subject = *SigningKey::from_bytes(&bob_seed).verifying_key().as_bytes();
    let sealed_view = alice
        .projection_with_authority(&RevokeWriter(bob_subject))
        .await
        .unwrap();
    let plain_view = plain_alice
        .projection_with_authority(&RevokeWriter(bob_subject))
        .await
        .unwrap();
    assert_eq!(
        fingerprint(&sealed_view.graph),
        fingerprint(&plain_view.graph)
    );
    assert_eq!(sealed_view.revoked.len(), 2);
    assert_eq!(plain_view.revoked.len(), 2);

    // The title rides only as ciphertext; the header still names the container.
    let body = sealed.body.as_ref().unwrap().to_bytes();
    assert!(!body.windows(12).any(|window| window == b"sealed title"));
    assert_eq!(sealed.header.extensions.container, CONTAINER);
}

/// A, B and removed C share the founding epoch. Replicas are built once,
/// before the rotation, and only their key handles are replaced.
#[tokio::test]
async fn a_rotation_through_the_handle_reaches_live_members_and_not_the_removed_one() {
    let mut group = Group::found();
    let a_keys = GroupKeys::new(keyring(&group.a));
    let b_keys = GroupKeys::new(keyring(&group.b));
    let c_keys = GroupKeys::new(keyring(&group.c));
    let founding = a_keys.current().current_epoch();
    assert!(founding.is_some());
    assert_eq!(b_keys.current().current_epoch(), founding);
    assert_eq!(c_keys.current().current_epoch(), founding);

    let mut a = EncryptedReplica::new(MemoryBackend::new(), CONTAINER, [0xa1; 32], a_keys.clone());
    let b = EncryptedReplica::new(MemoryBackend::new(), CONTAINER, [0xb2; 32], b_keys.clone());
    let c = EncryptedReplica::new(MemoryBackend::new(), CONTAINER, [0xc3; 32], c_keys.clone());
    let author = Author::new("ui");

    let before = a
        .edit(|g| {
            g.insert_node(&author, Container::new("before"));
        })
        .await
        .unwrap();
    assert!(b.accept(&before).await.unwrap());
    assert!(
        c.accept(&before).await.unwrap(),
        "positive control: C admits the pre-rotation edit"
    );
    assert_eq!(node_ids(&c.projection().await.unwrap()), ["before"]);

    group.remove_c_and_rotate();
    a_keys.replace(keyring(&group.a));
    b_keys.replace(keyring(&group.b));
    // C's host drains the same frames and refreshes too; it installs nothing.
    c_keys.replace(keyring(&group.c));
    let rotated = a_keys.current().current_epoch().unwrap();
    assert_ne!(Some(rotated), founding);
    assert_eq!(b_keys.current().current_epoch(), Some(rotated));
    assert_eq!(c_keys.current().current_epoch(), founding);

    let after = a
        .edit(|g| {
            g.insert_node(&author, Container::new("after"));
        })
        .await
        .unwrap();
    assert_eq!(epoch_of(&after), rotated, "A seals to the new epoch");
    assert!(
        b.accept(&after).await.unwrap(),
        "B admits without a rebuild"
    );

    assert!(!c.accept(&after).await.unwrap(), "C cannot open it: parked");
    assert_eq!(c.parking_status().await.unwrap().parked, 1);
    assert_eq!(c.sync_store().operation_count().await.unwrap(), 1);
    assert_eq!(node_ids(&c.projection().await.unwrap()), ["before"]);
    for (who, replica) in [("a", &a), ("b", &b)] {
        assert_eq!(
            node_ids(&replica.projection().await.unwrap()),
            ["after", "before"],
            "{who}"
        );
    }

    // Parked records are not stored; given the epoch (a stand-in for
    // being re-added), C re-admits it.
    c_keys.replace(keyring(&group.b));
    assert_eq!(c.readmit_parked().await.unwrap().admitted, 1);
    assert_eq!(
        node_ids(&c.projection().await.unwrap()),
        ["after", "before"]
    );
}

/// A and B share the nodes in `shared`; then A removes C, rotates and
/// authors `after`, which B's handle cannot open yet.
async fn graph_behind_a_rotation(
    shared: &[&str],
    after: Vec<Box<dyn FnOnce(&mut GraphLog<Container, Relation>)>>,
) -> (
    Group,
    EncryptedReplica<MemoryBackend>,
    EncryptedReplica<MemoryBackend>,
    Vec<Operation<EncryptedCommonsExt>>,
) {
    let mut group = Group::found();
    let a_keys = GroupKeys::new(keyring(&group.a));
    let mut a = EncryptedReplica::new(MemoryBackend::new(), CONTAINER, [0xa1; 32], a_keys.clone());
    let b = EncryptedReplica::new(
        MemoryBackend::new(),
        CONTAINER,
        [0xb2; 32],
        keyring(&group.b),
    );
    for id in shared {
        let operation = a.edit(insert(id)).await.unwrap();
        assert!(b.accept(&operation).await.unwrap(), "positive control");
    }
    group.remove_c_and_rotate();
    a_keys.replace(keyring(&group.a));
    let mut authored = Vec::new();
    for edit in after {
        authored.push(a.edit(edit).await.unwrap());
    }
    (group, a, b, authored)
}

fn insert(id: &str) -> Box<dyn FnOnce(&mut GraphLog<Container, Relation>)> {
    let id = id.to_owned();
    Box::new(move |g| {
        g.insert_node(&Author::new("ui"), Container::new(id));
    })
}

fn connect(from: &str, to: &str) -> Box<dyn FnOnce(&mut GraphLog<Container, Relation>)> {
    let (from, to) = (from.to_owned(), to.to_owned());
    Box::new(move |g| {
        g.connect(&Author::new("ui"), &from, &to, cites()).unwrap();
    })
}

fn signed_graph_envelope(
    container: [u8; 32],
    envelope: &GroupCiphertext,
) -> Operation<EncryptedCommonsExt> {
    let body = encode_cbor(envelope).unwrap();
    let header = Header::builder()
        .body(&body)
        .seq_num(0)
        .backlink(None)
        .build(
            &SigningKey::from_bytes(&[0xd4; 32]),
            EncryptedCommonsExt {
                encryption: GraphEncryption::GroupData,
                container,
                parents: Vec::new(),
            },
        );
    Operation {
        hash: header.hash(),
        header,
        body: Some(Body::from_bytes(&body)),
    }
}

#[tokio::test]
async fn a_member_behind_a_rotation_parks_graph_records_then_readmits_in_order() {
    let (group, a, b, after) =
        graph_behind_a_rotation(&["before"], vec![insert("first"), insert("second")]).await;
    for operation in &after {
        assert!(!b.accept(operation).await.unwrap(), "parked, not accepted");
    }
    assert_eq!(b.parking_status().await.unwrap().parked, 2);
    assert_eq!(b.sync_store().operation_count().await.unwrap(), 1);
    assert_eq!(node_ids(&b.projection().await.unwrap()), ["before"]);
    assert_eq!(
        b.readmit_parked().await.unwrap(),
        ReadmitReport {
            still_parked: 2,
            ..ReadmitReport::default()
        }
    );

    b.keys().replace(keyring(&group.b));
    assert_eq!(
        b.readmit_parked().await.unwrap(),
        ReadmitReport {
            admitted: 2,
            ..ReadmitReport::default()
        }
    );
    assert_eq!(b.parking_status().await.unwrap(), ParkingStatus::default());
    let projection = b.projection().await.unwrap();
    assert_eq!(node_ids(&projection), ["before", "first", "second"]);
    assert_eq!(
        fingerprint(&projection.graph),
        fingerprint(&a.projection().await.unwrap().graph)
    );
}

/// The successor's edge counter continues its parked predecessor's, so
/// without parking it would be refused before its predecessor is checked.
#[tokio::test]
async fn a_graph_successor_under_a_held_epoch_parks_behind_its_parked_predecessor() {
    let (group, a, b, after) = graph_behind_a_rotation(
        &["before", "x"],
        vec![connect("before", "x"), connect("x", "before")],
    )
    .await;
    let [first, second] = <[_; 2]>::try_from(after).unwrap();
    assert!(!b.accept(&first).await.unwrap());
    b.keys().replace(keyring(&group.b));
    assert!(
        !b.accept(&second).await.unwrap(),
        "readable, but its predecessor is parked"
    );
    assert_eq!(b.parking_status().await.unwrap().parked, 2);

    // Positive control: with nothing parked the same record is refused.
    let fresh = EncryptedReplica::new(
        MemoryBackend::new(),
        CONTAINER,
        [0xb3; 32],
        keyring(&group.b),
    );
    for stored in load_operations(&b.store, CONTAINER).await.unwrap() {
        assert!(fresh.accept(&stored.0).await.unwrap());
    }
    let refusal = fresh.accept(&second).await.unwrap_err();
    assert!(
        matches!(&refusal, ProcessError::Rejected(reject) if reject.code == "edge-counter-frontier"),
        "{refusal}"
    );

    assert_eq!(b.readmit_parked().await.unwrap().admitted, 2);
    assert_eq!(
        fingerprint(&b.projection().await.unwrap().graph),
        fingerprint(&a.projection().await.unwrap().graph)
    );
}

#[tokio::test]
async fn a_tampered_graph_ciphertext_or_another_container_is_refused_not_parked() {
    let (group, _, b, after) = graph_behind_a_rotation(&["before"], vec![insert("first")]).await;
    let first = &after[0];
    b.keys().replace(keyring(&group.b));
    let mut tampered = b.keys().current().seal_random(b"sealed batch").unwrap();
    tampered.ciphertext[0] ^= 1;
    let refusal = b
        .accept(&signed_graph_envelope(CONTAINER, &tampered))
        .await
        .unwrap_err();
    assert!(
        matches!(&refusal, ProcessError::Rejected(reject) if reject.code == "unreadable-commons-record"),
        "{refusal}"
    );

    let mut other_group = DataKeyring::new();
    other_group.rotate_random().unwrap();
    let foreign = other_group.seal_random(b"sealed batch").unwrap();
    let refusal = b
        .accept(&signed_graph_envelope([0x99; 32], &foreign))
        .await
        .unwrap_err();
    assert!(
        matches!(&refusal, ProcessError::Rejected(reject) if reject.code == "wrong-container"),
        "{refusal}"
    );
    assert_eq!(b.parking_status().await.unwrap(), ParkingStatus::default());
    assert_eq!(b.sync_store().operation_count().await.unwrap(), 1);

    // Positive controls: the same foreign ciphertext addressed here parks;
    // the untampered record is admitted.
    assert!(
        !b.accept(&signed_graph_envelope(CONTAINER, &foreign))
            .await
            .unwrap()
    );
    assert_eq!(b.parking_status().await.unwrap().parked, 1);
    assert!(b.accept(first).await.unwrap());
}

#[tokio::test]
async fn the_epoch_report_reads_envelopes_without_decrypting() {
    let backend = MemoryBackend::new();
    let mut writer =
        EncryptedReplica::new(backend.clone(), CONTAINER, [0x61; 32], founding_keyring());
    let sealed = writer
        .edit(|g| {
            g.insert_node(&Author::new("ui"), Container::new("sealed"));
        })
        .await
        .unwrap();
    let epoch = epoch_of(&sealed);
    let sealed_need = EpochNeed {
        epoch,
        reason: EpochNeedReason::EncryptedGraph { records: 1 },
    };
    let current_need = EpochNeed {
        epoch,
        reason: EpochNeedReason::Current,
    };
    assert_eq!(
        writer.epoch_report().await.unwrap().needed,
        [current_need, sealed_need.clone()]
    );

    // Same store, no keys: it cannot project, yet reports the same need.
    let keyless = EncryptedReplica::new(backend, CONTAINER, [0x62; 32], DataKeyring::new());
    assert!(keyless.projection().await.is_err(), "positive control");
    let report = keyless.epoch_report().await.unwrap();
    assert_eq!(report.needed, [sealed_need]);
    assert!(report.releasable.is_empty());
}

#[tokio::test]
async fn plaintext_and_encrypted_records_refuse_each_other() {
    let author = Author::new("ui");
    let mut encrypted = EncryptedReplica::new(
        MemoryBackend::new(),
        CONTAINER,
        [0x61; 32],
        founding_keyring(),
    );
    let mut plain = Replica::new(MemoryBackend::new(), CONTAINER, [0x62; 32]);
    let sealed_op = encrypted
        .edit(|g| {
            g.insert_node(&author, Container::new("sealed"));
        })
        .await
        .unwrap();
    let plain_op = plain
        .edit(|g| {
            g.insert_node(&author, Container::new("plain"));
        })
        .await
        .unwrap();
    let encrypted_receiver = EncryptedReplica::new(
        MemoryBackend::new(),
        CONTAINER,
        [0x63; 32],
        encrypted.keys().clone(),
    );
    let plain_receiver = Replica::new(MemoryBackend::new(), CONTAINER, [0x64; 32]);
    assert_ne!(COMMONS_ENCRYPTED_GRAPH_LANE, COMMONS_GRAPH_LANE);

    // A plaintext header lacks the signed marker: it never decodes as encrypted.
    let error = decode_operation_record::<EncryptedCommonsExt>(&operation_record(&plain_op, true))
        .expect_err("a plaintext header is not an encrypted one");
    assert!(error.to_string().contains("encryption"), "{error}");

    // An encrypted header carried to a plaintext replica: its body is refused.
    let crossed = decode_operation_record::<CommonsExt>(&operation_record(&sealed_op, true))
        .unwrap()
        .unwrap();
    let error = plain_receiver.accept(&crossed).await.unwrap_err();
    assert!(
        error.to_string().contains("invalid-commons-batch"),
        "{error}"
    );
    assert_eq!(
        plain_receiver.sync_store().operation_count().await.unwrap(),
        0
    );

    // A plaintext record signed under the encrypted header is refused too.
    let body = encode_cbor(&CommonsRecord {
        batch: from_operation(&plain_op).unwrap().batch,
        parents: Vec::new(),
        writer_attestation: None,
    })
    .unwrap();
    let header = Header::builder()
        .body(&body)
        .seq_num(0)
        .backlink(None)
        .build(
            &SigningKey::from_bytes(&[0x62; 32]),
            EncryptedCommonsExt {
                encryption: GraphEncryption::GroupData,
                container: CONTAINER,
                parents: Vec::new(),
            },
        );
    let downgraded = Operation {
        hash: header.hash(),
        header,
        body: Some(Body::from_bytes(&body)),
    };
    let error = encrypted_receiver.accept(&downgraded).await.unwrap_err();
    assert!(
        matches!(&error, ProcessError::Rejected(reject) if reject.code == "invalid-commons-ciphertext"),
        "{error}"
    );
    assert_eq!(
        encrypted_receiver
            .sync_store()
            .operation_count()
            .await
            .unwrap(),
        0
    );

    // Positive controls: each receiver admits its own profile's record.
    assert!(encrypted_receiver.accept(&sealed_op).await.unwrap());
    assert!(plain_receiver.accept(&plain_op).await.unwrap());
}
