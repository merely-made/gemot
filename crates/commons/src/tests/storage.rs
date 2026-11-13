// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

/// A container id is the signed address: a batch for one container cannot
/// be replayed into another.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_operation_for_another_container_is_refused() {
    let mut alice = Replica::new(MemoryBackend::new(), CONTAINER, [90; 32]);
    let op = alice
        .edit(|g| {
            g.insert_node(&Author::new("ui"), Container::new("n"));
        })
        .await
        .expect("alice inserts");

    let other = Replica::new(MemoryBackend::new(), [0xd1; 32], [91; 32]);
    assert!(
        other.accept(&op).await.is_err(),
        "a foreign container's batch is refused before mutation"
    );
    assert_eq!(
        other.materialize().await.unwrap().graph().node_count(),
        0,
        "and nothing was stored"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_signed_batch_cannot_mint_under_another_writer() {
    let signing_seed = [90; 32];
    let signer = WriterId(
        *SigningKey::from_bytes(&signing_seed)
            .verifying_key()
            .as_bytes(),
    );
    let foreign_writer = WriterId([0xff; 32]);
    assert_ne!(signer, foreign_writer);

    let author = Author::new("ui");
    let mut forged = GraphLog::<Container, Relation>::new().for_writer(foreign_writer);
    forged.insert_node(&author, Container::new("x"));
    forged.insert_node(&author, Container::new("y"));
    forged
        .connect(&author, &"x".to_string(), &"y".to_string(), cites())
        .unwrap();
    let batch = forged.log().entries().last().unwrap().clone();
    let operation = to_operation(signing_seed, CONTAINER, &batch, Vec::new(), 0, None);

    let replica = Replica::new(MemoryBackend::new(), CONTAINER, signing_seed);
    let error = replica
        .accept(&operation)
        .await
        .expect_err("writer forgery must be rejected");
    assert!(error.to_string().contains("edge-writer-mismatch"));
    assert_eq!(replica.sync_store().operation_count().await.unwrap(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_signed_writer_cannot_reuse_an_edge_counter() {
    let signing_seed = [90; 32];
    let author = Author::new("ui");
    let mut replica = Replica::new(MemoryBackend::new(), CONTAINER, signing_seed);
    replica
        .edit(|g| {
            g.insert_node(&author, Container::new("x"));
        })
        .await
        .unwrap();
    replica
        .edit(|g| {
            g.insert_node(&author, Container::new("y"));
        })
        .await
        .unwrap();
    let first_edge = replica
        .edit(|g| {
            g.connect(&author, &"x".to_string(), &"y".to_string(), cites());
        })
        .await
        .unwrap();
    let repeated_batch = from_operation(&first_edge).unwrap().batch;
    let repeated = to_operation(
        signing_seed,
        CONTAINER,
        &repeated_batch,
        vec![*first_edge.hash.as_bytes()],
        first_edge.header.seq_num + 1,
        Some(*first_edge.hash.as_bytes()),
    );

    let error = replica
        .accept(&repeated)
        .await
        .expect_err("counter reuse must be rejected");
    assert!(error.to_string().contains("edge-counter-frontier"));
    assert_eq!(replica.sync_store().operation_count().await.unwrap(), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconstruction_from_an_existing_store_resumes_both_counters() {
    let backend = MemoryBackend::new();
    let author = Author::new("ui");
    let mut replica = Replica::new(backend.clone(), CONTAINER, [90; 32]);
    replica
        .edit(|g| {
            g.insert_node(&author, Container::new("x"));
        })
        .await
        .unwrap();
    replica
        .edit(|g| {
            g.insert_node(&author, Container::new("y"));
        })
        .await
        .unwrap();
    let first = replica
        .edit(|g| {
            g.connect(&author, &"x".to_string(), &"y".to_string(), cites());
        })
        .await
        .unwrap();
    let first_id = connect_id(&first).unwrap();
    drop(replica);

    let mut restarted = Replica::new(backend, CONTAINER, [90; 32]);
    let second = restarted
        .edit(|g| {
            g.connect(&author, &"x".to_string(), &"y".to_string(), cites());
        })
        .await
        .expect("authoring resumes after restart");
    let second_id = connect_id(&second).unwrap();

    assert_eq!(second.header.seq_num, first.header.seq_num + 1);
    assert_eq!(
        second.header.backlink.as_ref().map(|hash| *hash.as_bytes()),
        Some(*first.hash.as_bytes())
    );
    assert_eq!(first_id.counter, 0);
    assert_eq!(second_id.counter, 1);
    assert_eq!(
        restarted.materialize().await.unwrap().graph().edge_count(),
        2
    );
}

/// Durable counterpart to the in-memory reconstruction receipt above.
/// Every database handle is dropped before the same file is reopened.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redb_reopen_resumes_the_operation_head_and_edge_counter() {
    let dir = tempfile::tempdir().expect("scratch directory");
    let path = dir.path().join("commons.redb");
    let author = Author::new("ui");

    let (first, first_id) = {
        let backend = RedbBackend::open(&path).expect("open initial database");
        let mut replica = Replica::new(backend, CONTAINER, [90; 32]);
        replica
            .edit(|g| {
                g.insert_node(&author, Container::new("x"));
            })
            .await
            .expect("insert x");
        replica
            .edit(|g| {
                g.insert_node(&author, Container::new("y"));
            })
            .await
            .expect("insert y");
        let first = replica
            .edit(|g| {
                g.connect(&author, &"x".to_string(), &"y".to_string(), cites());
            })
            .await
            .expect("mint first edge");
        let first_id = connect_id(&first).expect("first edge id");
        (first, first_id)
    };

    let backend = RedbBackend::open(&path).expect("reopen database");
    let mut reopened = Replica::new(backend, CONTAINER, [90; 32]);
    let second = reopened
        .edit(|g| {
            g.connect(&author, &"x".to_string(), &"y".to_string(), cites());
        })
        .await
        .expect("authoring resumes after durable reopen");
    let second_id = connect_id(&second).expect("second edge id");

    assert_eq!(second.header.seq_num, first.header.seq_num + 1);
    assert_eq!(
        second.header.backlink.as_ref().map(|hash| *hash.as_bytes()),
        Some(*first.hash.as_bytes())
    );
    assert_eq!(first_id.counter, 0);
    assert_eq!(second_id.counter, 1);
    assert_eq!(
        reopened.materialize().await.unwrap().graph().edge_count(),
        2
    );
}

/// The edge ids the wire carries survive a CBOR round trip, including the
/// writer half. A silent loss there would collapse two writers' edges.
#[test]
fn a_batch_round_trips_through_the_wire_with_writer_scoped_ids() {
    let signing_seed = [0xa1; 32];
    let writer = WriterId(
        *SigningKey::from_bytes(&signing_seed)
            .verifying_key()
            .as_bytes(),
    );
    let author = Author::new("ui");
    let mut g = GraphLog::<Container, Relation>::new().for_writer(writer);
    g.insert_node(&author, Container::new("x"));
    g.insert_node(&author, Container::new("y"));
    let minted = g
        .connect(&author, &"x".to_string(), &"y".to_string(), cites())
        .expect("connect");

    let batch = g.log().entries().last().expect("a batch").clone();
    let op = to_operation(signing_seed, CONTAINER, &batch, Vec::new(), 0, None);
    let decoded = from_operation(&op).expect("round trip");

    let carried = decoded.batch.edits.iter().find_map(|e| match e {
        portolan::GraphEdit::Connect { id, .. } => Some(*id),
        _ => None,
    });
    assert_eq!(carried, Some(minted));
    assert_eq!(
        carried.map(|id| id.writer),
        Some(WriterId(*op.header.verifying_key.as_bytes())),
        "the writer half survives the wire and is bound to the signer"
    );
    assert!(decoded.parents.is_empty());
    assert_ne!(
        carried,
        Some(EdgeId::local(0)),
        "and it is not a bare counter"
    );
}
