// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use std::net::TcpListener;

use murm_sync::StreamSyncLimits;
use portolan::EditSpec;
use stickleback::DataKeyring;
use transport::security::SetupLimits;
use transport::sync_lane::{SyncLane, SyncLaneError};
use transport::{Alpn, ReticulumInterface, ReticulumTransport, Transport};

use super::*;
use crate::encrypted::EncryptedReplica;

async fn reticulum_pair(protocol: &Alpn) -> (ReticulumTransport, ReticulumTransport) {
    let addr = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let server_identity = InMemoryProvider::from_seed([0xe1; 32]);
    let client_identity = InMemoryProvider::from_seed([0xe2; 32]);
    let server = ReticulumTransport::builder(server_identity.master_keypair())
        .alpns(vec![protocol.clone()])
        .interfaces(vec![ReticulumInterface::TcpServer { bind: addr }])
        .announce_interval(Duration::from_millis(250))
        .bind()
        .await
        .expect("bind Reticulum TCP server");
    let client = ReticulumTransport::builder(client_identity.master_keypair())
        .alpns(vec![protocol.clone()])
        .interfaces(vec![ReticulumInterface::TcpClient { addr }])
        .announce_interval(Duration::from_millis(250))
        .bind()
        .await
        .expect("bind Reticulum TCP client");
    (server, client)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn offline_commons_writers_converge_over_reticulum_tcp_without_iroh() {
    let alice_identity = InMemoryProvider::from_seed([0x61; 32]);
    let bob_identity = InMemoryProvider::from_seed([0x62; 32]);
    let outsider_identity = InMemoryProvider::from_seed([0x63; 32]);
    let scope = cap_path(&commons_write_capability(CONTAINER));
    let rules = gemot_rules(&alice_identity, scope.clone());
    let mut delegations = MootDelegations::new();
    let grant = issue_gemot_delegation(&alice_identity, &bob_identity, scope, Some(900), 1);
    assert!(delegations.accept_certificate(MOOT, &rules, grant).unwrap());
    let authority = gemot_authority(&delegations, &rules);

    let directory = tempfile::tempdir().unwrap();
    let alice_path = directory.path().join("alice.redb");
    let bob_path = directory.path().join("bob.redb");
    let mut keys = DataKeyring::new();
    keys.rotate_random().unwrap();
    let keys = keys.to_bytes().unwrap();
    let open = |path: &std::path::Path, identity: &InMemoryProvider| {
        EncryptedReplica::for_identity(
            RedbBackend::open(path).unwrap(),
            CONTAINER,
            identity,
            GroupKeys::from_bytes(&keys).unwrap(),
        )
        .unwrap()
    };
    let mut alice = open(&alice_path, &alice_identity);
    let mut bob = open(&bob_path, &bob_identity);

    let author = Author::new("catalogue");
    let base = alice
        .edit(|graph| {
            graph.insert_node(&author, Container::new("release"));
        })
        .await
        .unwrap();
    assert!(bob.accept(&base).await.unwrap());
    // Both enrolled replicas start from the same release. They then edit it
    // independently before the test opens any transport.
    for (replica, id) in [(&mut alice, "alice-source"), (&mut bob, "bob-source")] {
        replica
            .edit(|graph| {
                graph
                    .commit_batch(
                        author.clone(),
                        graph.revision(),
                        vec![
                            EditSpec::InsertNode(Container::new(id)),
                            EditSpec::Connect {
                                from: "release".into(),
                                to: id.into(),
                                edge: cites(),
                            },
                        ],
                    )
                    .unwrap();
            })
            .await
            .unwrap();
    }
    let alice_offline = fingerprint(
        &alice
            .projection_with_authority(&authority)
            .await
            .unwrap()
            .graph,
    );
    let bob_offline = fingerprint(
        &bob.projection_with_authority(&authority)
            .await
            .unwrap()
            .graph,
    );
    assert_eq!((alice_offline.1.len(), bob_offline.1.len()), (1, 1));
    assert_ne!(alice_offline, bob_offline);

    sync_over_reticulum(
        &alice,
        &bob,
        &alice_identity,
        &bob_identity,
        &outsider_identity,
    )
    .await;
    drop((alice, bob));

    let expected_edges = [alice_offline.1[0].clone(), bob_offline.1[0].clone()];
    for replica in [
        open(&alice_path, &alice_identity),
        open(&bob_path, &bob_identity),
    ] {
        let projection = replica.projection_with_authority(&authority).await.unwrap();
        let (nodes, edges) = fingerprint(&projection.graph);
        assert_eq!(
            nodes.iter().map(|node| node.0.as_str()).collect::<Vec<_>>(),
            ["alice-source", "bob-source", "release"]
        );
        assert_eq!(edges, expected_edges);
        assert!(projection.pending.is_empty());
        assert!(projection.pending_authority.is_empty());
        assert!(projection.revoked.is_empty());
        assert_eq!(replica.sync_store().operation_count().await.unwrap(), 3);
    }
}

async fn sync_over_reticulum(
    alice: &EncryptedReplica<RedbBackend>,
    bob: &EncryptedReplica<RedbBackend>,
    alice_identity: &InMemoryProvider,
    bob_identity: &InMemoryProvider,
    outsider_identity: &InMemoryProvider,
) {
    // The fixture creates only Reticulum carriers. Its admission rule maps the
    // enrolled dialer's Noise key to read access for this one container.
    let protocol = Alpn::new("mere/commons-test/v1");
    let (server, client) = reticulum_pair(&protocol).await;
    let server_lane = SyncLane::new(protocol.clone(), 1, SetupLimits::default());
    let client_lane = SyncLane::new(protocol.clone(), 1, SetupLimits::default());
    let alice_peer = PeerID::from_public_key(alice_identity.master_public_key());
    let bob_peer = PeerID::from_public_key(bob_identity.master_public_key());
    let limits = StreamSyncLimits::default();
    for (identity, expected) in [
        (outsider_identity, None),
        (bob_identity, Some(1)),
        (bob_identity, Some(0)),
    ] {
        let serve = async {
            let inbound = server.accept(protocol.clone()).await.unwrap();
            server_lane
                .serve_noise(
                    alice_identity.master_keypair(),
                    inbound.into_stream(),
                    |peer| peer == bob_peer,
                    alice.stream_sync(limits),
                )
                .await
        };
        let dial = client_lane.dial_noise(
            &client,
            server.local_peer_id(),
            identity.master_keypair(),
            alice_peer,
            bob.stream_sync(limits),
        );
        let (served, dialed) =
            tokio::time::timeout(Duration::from_secs(30), async { tokio::join!(serve, dial) })
                .await
                .expect("Commons sync round timed out");

        match expected {
            None => {
                assert!(matches!(served, Err(SyncLaneError::Refused)));
                assert!(dialed.is_err());
                assert_eq!(alice.sync_store().operation_count().await.unwrap(), 2);
                assert_eq!(bob.sync_store().operation_count().await.unwrap(), 2);
            }
            Some(count) => {
                for outcome in [served.unwrap(), dialed.unwrap()] {
                    assert_eq!((outcome.received, outcome.accepted), (count, count));
                    assert_eq!((outcome.declined, outcome.lagged), (0, 0));
                }
            }
        }
    }
}
