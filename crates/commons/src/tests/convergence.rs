// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

/// M3: two members edit one container **while partitioned**, then
/// reconverge over real LogSync reconciliation.
///
/// This is the first time the M1/M2 merge rules are exercised over a lane
/// rather than a hand-built journal. Both members mint an edge before they
/// can see each other, which is exactly the case that collided before
/// `EdgeId` became `(writer, counter)`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_partitioned_members_converge_on_one_container() {
    let (alice_t, bob_t) = two_peers().await;

    let mut alice = Replica::new(MemoryBackend::new(), CONTAINER, [90; 32]);
    let mut bob = Replica::new(MemoryBackend::new(), CONTAINER, [91; 32]);
    assert_ne!(
        alice.writer(),
        bob.writer(),
        "each replica writes under its own identity"
    );

    // ── Partitioned: neither has joined a space yet, so neither can see
    // the other's edits. Both insert a pair and connect it. ──
    let author = Author::new("ui");
    let a_edge = {
        let a = author.clone();
        let mut minted = None;
        alice
            .edit(|g| {
                g.insert_node(&a, Container::new("alice-1"));
            })
            .await
            .expect("alice inserts");
        alice
            .edit(|g| {
                g.insert_node(&a, Container::new("alice-2"));
            })
            .await
            .expect("alice inserts");
        alice
            .edit(|g| {
                minted = g.connect(&a, &"alice-1".to_string(), &"alice-2".to_string(), cites());
            })
            .await
            .expect("alice connects");
        minted.expect("alice minted an edge")
    };

    let b_edge = {
        let a = author.clone();
        let mut minted = None;
        bob.edit(|g| {
            g.insert_node(&a, Container::new("bob-1"));
        })
        .await
        .expect("bob inserts");
        bob.edit(|g| {
            g.insert_node(&a, Container::new("bob-2"));
        })
        .await
        .expect("bob inserts");
        bob.edit(|g| {
            minted = g.connect(&a, &"bob-1".to_string(), &"bob-2".to_string(), cites());
        })
        .await
        .expect("bob connects");
        minted.expect("bob minted an edge")
    };

    assert_eq!(a_edge.counter, 0, "alice minted counter 0");
    assert_eq!(b_edge.counter, 0, "bob minted counter 0");
    assert_ne!(
        a_edge, b_edge,
        "and the ids still differ, because the writer half separates them"
    );

    // ── Reconnect: join the space on both sides and let LogSync reconcile. ──
    let (a_ep, a_gossip) = alice_t.sync_parts().expect("alice sync parts");
    let a_store = alice.sync_store();
    let alice_space = JoinedSpace::join::<_, u64, _, _>(
        stickleback::lane_id(COMMONS_GRAPH_LANE, CONTAINER),
        alice.sync_store(),
        a_ep,
        a_gossip,
        CONTAINER,
        move |op| {
            let store = a_store.clone();
            async move { accept_into(&store, CONTAINER, &op).await.unwrap_or(false) }
        },
    )
    .await
    .expect("alice joins");

    let (b_ep, b_gossip) = bob_t.sync_parts().expect("bob sync parts");
    let b_store = bob.sync_store();
    let bob_space = JoinedSpace::join::<_, u64, _, _>(
        stickleback::lane_id(COMMONS_GRAPH_LANE, CONTAINER),
        bob.sync_store(),
        b_ep,
        b_gossip,
        CONTAINER,
        move |op| {
            let store = b_store.clone();
            async move { accept_into(&store, CONTAINER, &op).await.unwrap_or(false) }
        },
    )
    .await
    .expect("bob joins");

    // ── Converge: both graphs hold all four nodes and both edges. ──
    let converged = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let a = alice.materialize().await.unwrap();
            let b = bob.materialize().await.unwrap();
            if a.graph().node_count() == 4
                && b.graph().node_count() == 4
                && a.graph().edge_count() == 2
                && b.graph().edge_count() == 2
            {
                return (a, b);
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await;
    let (a_graph, b_graph) = converged.expect("the two replicas converged");
    assert_eq!(
        fingerprint(&a_graph),
        fingerprint(&b_graph),
        "same operation set means the same exact graph projection"
    );

    for (who, g) in [("alice", &a_graph), ("bob", &b_graph)] {
        assert_eq!(g.graph().node_count(), 4, "{who} sees every node");
        assert_eq!(g.graph().edge_count(), 2, "{who} sees both edges");
        for id in ["alice-1", "alice-2", "bob-1", "bob-2"] {
            assert!(
                g.graph().key_of(&id.to_string()).is_some(),
                "{who} is missing {id}"
            );
        }
        // The M1 payoff, over a real lane: two concurrently-minted edges
        // stay separately addressable, so either can be retracted by name.
        let a_key = g.edge_key(a_edge).expect("alice's edge addressable");
        let b_key = g.edge_key(b_edge).expect("bob's edge addressable");
        assert_ne!(a_key, b_key, "{who}: each id names a different edge");
    }

    // Bob now edits Alice's synced state, not a private Bob-only graph,
    // and publishes that causally-later edit over the live lane.
    let retract = bob
        .edit(|g| {
            assert!(
                g.disconnect(&author, a_edge),
                "bob can address alice's synced edge"
            );
        })
        .await
        .expect("bob retracts alice's edge");
    bob_space.publish(retract).expect("publish retraction");

    let reconverged = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let a = alice.materialize().await.unwrap();
            let b = bob.materialize().await.unwrap();
            if a.graph().edge_count() == 1 && b.graph().edge_count() == 1 {
                return (a, b);
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await;
    let (a_graph, b_graph) = reconverged.expect("the shared retraction converged");
    assert_eq!(fingerprint(&a_graph), fingerprint(&b_graph));
    for graph in [&a_graph, &b_graph] {
        assert!(
            graph.edge_key(a_edge).is_none(),
            "alice's retracted edge is gone"
        );
        assert!(
            graph.edge_key(b_edge).is_some(),
            "bob's unrelated edge survives"
        );
    }

    drop(alice_space);
    drop(bob_space);
}

#[tokio::test]
async fn partitioned_edits_to_different_facets_merge_without_node_translation() {
    let mut alice = Replica::new(MemoryBackend::new(), CONTAINER, [0x71; 32]);
    let mut bob = Replica::new(MemoryBackend::new(), CONTAINER, [0x72; 32]);
    let author = Author::new("ui");
    let node = "shared-note".to_string();
    let created = alice
        .edit(|graph| {
            graph.insert_node(&author, Container::new(node.clone()));
        })
        .await
        .unwrap();
    bob.accept(&created).await.unwrap();

    let title = FacetId::new("content.title");
    let pin = FacetId::new("arrangement.pin");
    let alice_edit = alice
        .edit(|graph| {
            assert!(graph.set_facet(&author, &node, title.clone(), json!("Field note")));
        })
        .await
        .unwrap();
    let bob_edit = bob
        .edit(|graph| {
            assert!(graph.set_facet(&author, &node, pin.clone(), json!(true)));
        })
        .await
        .unwrap();

    alice.accept(&bob_edit).await.unwrap();
    bob.accept(&alice_edit).await.unwrap();
    for graph in [
        alice.materialize().await.unwrap(),
        bob.materialize().await.unwrap(),
    ] {
        assert_eq!(
            graph.facets().get(&node, &title),
            Some(&json!("Field note"))
        );
        assert_eq!(graph.facets().get(&node, &pin), Some(&json!(true)));
    }
}

/// Before blaming a lane: a replica must be able to fold back its own
/// stored edits. If this fails, `materialize` is wrong, not sync.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replica_folds_back_its_own_edits() {
    let author = Author::new("ui");
    let mut alice = Replica::new(MemoryBackend::new(), CONTAINER, [90; 32]);
    alice
        .edit(|g| {
            g.insert_node(&author, Container::new("n1"));
        })
        .await
        .expect("insert");
    alice
        .edit(|g| {
            g.insert_node(&author, Container::new("n2"));
        })
        .await
        .expect("insert");

    let store = alice.sync_store();
    let count = store.operation_count().await.expect("count");
    let resolved: std::collections::BTreeMap<VerifyingKey, Vec<u64>> =
        TopicStore::<Topic, VerifyingKey, u64>::resolve(&store, &Topic::from(CONTAINER))
            .await
            .expect("resolve");
    assert_eq!(count, 2, "both operations are stored");
    assert_eq!(resolved.len(), 1, "one author is associated with the topic");

    let folded = alice.materialize().await.expect("materialize");
    assert_eq!(
        folded.graph().node_count(),
        2,
        "the fold reads back what the replica stored"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_causally_later_lower_key_writer_wins() {
    let seed_a = [90; 32];
    let seed_b = [91; 32];
    let key_a = SigningKey::from_bytes(&seed_a).verifying_key();
    let key_b = SigningKey::from_bytes(&seed_b).verifying_key();
    let (higher_seed, lower_seed) = if key_a > key_b {
        (seed_a, seed_b)
    } else {
        (seed_b, seed_a)
    };
    let higher_key = SigningKey::from_bytes(&higher_seed).verifying_key();
    let lower_key = SigningKey::from_bytes(&lower_seed).verifying_key();
    assert!(lower_key < higher_key);

    let author = Author::new("ui");
    let mut higher = Replica::new(MemoryBackend::new(), CONTAINER, higher_seed);
    let old = higher
        .edit(|g| {
            g.insert_node(&author, Container::new("n").with_title("old"));
        })
        .await
        .unwrap();

    let mut lower = Replica::new(MemoryBackend::new(), CONTAINER, lower_seed);
    lower.accept(&old).await.unwrap();
    let new = lower
        .edit(|g| {
            g.insert_node(&author, Container::new("n").with_title("new"));
        })
        .await
        .unwrap();
    assert!(
        from_operation(&new)
            .unwrap()
            .parents
            .contains(old.hash.as_bytes()),
        "the later edit records the operation it observed"
    );
    higher.accept(&new).await.unwrap();

    for replica in [&higher, &lower] {
        let graph = replica.materialize().await.unwrap();
        let key = graph.graph().key_of(&"n".to_string()).unwrap();
        assert_eq!(
            graph.graph().node(key).unwrap().title,
            "new",
            "causality outranks permanent verifying-key priority"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_causal_child_waits_for_its_missing_parent() {
    let author = Author::new("ui");
    let mut parent_writer = Replica::new(MemoryBackend::new(), CONTAINER, [90; 32]);
    let parent = parent_writer
        .edit(|g| {
            g.insert_node(&author, Container::new("n").with_title("parent"));
        })
        .await
        .unwrap();

    let mut child_writer = Replica::new(MemoryBackend::new(), CONTAINER, [91; 32]);
    child_writer.accept(&parent).await.unwrap();
    let child = child_writer
        .edit(|g| {
            g.insert_node(&author, Container::new("n").with_title("child"));
        })
        .await
        .unwrap();

    let receiver = Replica::new(MemoryBackend::new(), CONTAINER, [92; 32]);
    receiver.accept(&child).await.unwrap();
    let projection = receiver.projection().await.unwrap();
    assert_eq!(projection.graph.graph().node_count(), 0);
    assert_eq!(projection.pending.len(), 1);
    assert_eq!(projection.pending[0].operation, *child.hash.as_bytes());
    assert_eq!(projection.pending[0].missing, vec![*parent.hash.as_bytes()]);

    receiver.accept(&parent).await.unwrap();
    let projection = receiver.projection().await.unwrap();
    assert!(projection.pending.is_empty());
    let key = projection.graph.graph().key_of(&"n".to_string()).unwrap();
    assert_eq!(projection.graph.graph().node(key).unwrap().title, "child");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_remove_wins_but_an_observing_insert_recreates() {
    let author = Author::new("ui");
    let mut base_writer = Replica::new(MemoryBackend::new(), CONTAINER, [90; 32]);
    let base = base_writer
        .edit(|graph| {
            graph.insert_node(&author, Container::new("n").with_title("base"));
        })
        .await
        .unwrap();

    let mut remover = Replica::new(MemoryBackend::new(), CONTAINER, [91; 32]);
    remover.accept(&base).await.unwrap();
    let removal = remover
        .edit(|graph| {
            graph.remove_node(&author, &"n".to_string());
        })
        .await
        .unwrap();

    let mut editor = Replica::new(MemoryBackend::new(), CONTAINER, [92; 32]);
    editor.accept(&base).await.unwrap();
    let concurrent_insert = editor
        .edit(|graph| {
            graph.insert_node(
                &author,
                Container::new("n").with_title("unseen concurrent edit"),
            );
        })
        .await
        .unwrap();

    let receiver = Replica::new(MemoryBackend::new(), CONTAINER, [93; 32]);
    for operation in [&base, &concurrent_insert, &removal] {
        receiver.accept(operation).await.unwrap();
    }
    assert!(
        receiver
            .materialize()
            .await
            .unwrap()
            .graph()
            .key_of(&"n".to_string())
            .is_none(),
        "a concurrent insert cannot resurrect a removed node"
    );

    let mut recreator = Replica::new(MemoryBackend::new(), CONTAINER, [94; 32]);
    for operation in [&base, &concurrent_insert, &removal] {
        recreator.accept(operation).await.unwrap();
    }
    let recreation = recreator
        .edit(|graph| {
            graph.insert_node(&author, Container::new("n").with_title("deliberate"));
        })
        .await
        .unwrap();
    receiver.accept(&recreation).await.unwrap();
    let graph = receiver.materialize().await.unwrap();
    let key = graph.graph().key_of(&"n".to_string()).unwrap();
    assert_eq!(graph.graph().node(key).unwrap().title, "deliberate");
}
