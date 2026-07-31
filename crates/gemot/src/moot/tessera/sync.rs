// Copyright 2026 Mark AB (markik)
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Two-peer convergence for the tessera lane.
//!
//! After the sibling-posture purity split, gemot no longer owns p2panda-net:
//! the pump (the LogSync session + the [`stickleback::SyncedSpace`] drain) is
//! **host-composed**, and tessera keeps only the store, wire-level admission,
//! and ledger fold. The tessera lane is receive-only (authoring is a direct
//! `store.insert`, no live publish), so the host just builds the session, drives
//! it, and folds. These tests play the host so the lane's convergence stays
//! covered without a production `SyncedMoot` type.

#![cfg(test)]

use std::sync::Arc;

use identity::{Ed25519Keypair, IdentityProvider, InMemoryProvider};
use muniment::MemoryBackend;
use p2panda_core::Operation;
use p2panda_net::{Endpoint, Gossip};
use stickleback::JoinedSpace;
use transport::{P2pandaTransport, PeerID};

use crate::moot::tessera::event::{ChainRoot, CommitmentId, Scope, TesseraEvent};
use crate::moot::tessera::ledger::{Ledger, TesseraConfig};
use crate::moot::tessera::store::{TesseraStore, TesseraStoreError};
use crate::moot::tessera::wire::{TesseraExt, to_operation};

const MOOT: [u8; 32] = [0x33; 32];

/// A host-composed tessera session: the store to fold and the joined LogSync
/// session. The tessera lane is receive-only, so nothing publishes on the
/// live lane.
struct TesseraSession {
    store: TesseraStore<MemoryBackend>,
    moot_id: [u8; 32],
    joined: JoinedSpace<TesseraExt>,
}

impl TesseraSession {
    async fn join(
        endpoint: Endpoint,
        gossip: Gossip,
        store: TesseraStore<MemoryBackend>,
        moot_id: [u8; 32],
    ) -> Self {
        let accept_store = store.clone();
        let joined = JoinedSpace::join::<_, u64, _, _>(
            stickleback::lane_id("gemot/tessera/v1", moot_id),
            store.sync_store(),
            endpoint,
            gossip,
            moot_id,
            move |op: Operation<TesseraExt>| {
                let store = accept_store.clone();
                async move { matches!(store.accept(moot_id, &op).await, Ok(true)) }
            },
        )
        .await
        .expect("tessera join");
        Self {
            store,
            moot_id,
            joined,
        }
    }

    async fn ledger(&self, config: TesseraConfig) -> Result<Ledger, TesseraStoreError> {
        self.store.fold_moot(self.moot_id, config).await
    }
}

/// A `commit -> fulfil -> govern` chained log for `kp` (scores 11).
fn commit_fulfil_govern(kp: &Ed25519Keypair) -> Vec<Operation<TesseraExt>> {
    let by = ChainRoot(kp.public_key().to_bytes());
    let cid = CommitmentId([0xc1; 32]);
    let e0 = TesseraEvent::CommitmentMade {
        by,
        commitment: cid,
        scope: Scope("host/cluster".into()),
        cadence_ms: 1_000,
        duration_ms: None,
        at_ms: 1_000,
    };
    let e1 = TesseraEvent::CommitmentFulfilled {
        by,
        commitment: cid,
        at_ms: 1_050,
    };
    let e2 = TesseraEvent::GovernanceParticipation { by, at_ms: 1_100 };
    let op0 = to_operation(kp, MOOT, &e0, 0, None);
    let op1 = to_operation(kp, MOOT, &e1, 1, Some(*op0.hash.as_bytes()));
    let op2 = to_operation(kp, MOOT, &e2, 2, Some(*op1.hash.as_bytes()));
    vec![op0, op1, op2]
}

/// Two real p2panda-net peers: A holds a tessera log before B connects, B
/// catches up over LogSync, and both fold their stores to the same score.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_moots_converge_on_the_same_scores() {
    let alice_provider = Arc::new(InMemoryProvider::from_seed([40; 32]));
    let bob_provider = Arc::new(InMemoryProvider::from_seed([41; 32]));
    let alice_id = PeerID::from_public_key(alice_provider.master_public_key());
    let bob_id = PeerID::from_public_key(bob_provider.master_public_key());
    let alice_kp = alice_provider.master_keypair().clone();
    let bob_kp = bob_provider.master_keypair().clone();

    let alice_t = P2pandaTransport::builder(&alice_kp)
        .gossip()
        .bind()
        .await
        .expect("bind alice");
    let bob_t = P2pandaTransport::builder(&bob_kp)
        .gossip()
        .bind()
        .await
        .expect("bind bob");

    // The tessera author is a derived persona key; the transport runs on the
    // master key. Peer A authors, peer B only receives.
    let author = alice_provider.derive_keypair(b"tessera-author").unwrap();
    let author_root = ChainRoot(author.public_key().to_bytes());

    // LogSync joins gossip on the derived overlay topic — tag peers with it.
    let overlay = transport::sync_overlay_topic(MOOT);
    alice_t
        .add_peer(bob_t.endpoint_addr().await.unwrap())
        .await
        .unwrap();
    alice_t.set_topics(bob_id, &[overlay]).await.unwrap();
    bob_t
        .add_peer(alice_t.endpoint_addr().await.unwrap())
        .await
        .unwrap();
    bob_t.set_topics(alice_id, &[overlay]).await.unwrap();

    // Alice holds a 3-event tessera log before bob connects (offline catch-up).
    let alice_store = TesseraStore::in_memory();
    for op in commit_fulfil_govern(&author) {
        alice_store.insert(&op).await.unwrap();
    }
    let bob_store = TesseraStore::in_memory();

    let (a_ep, a_gossip) = alice_t.sync_parts().expect("alice sync parts");
    let (b_ep, b_gossip) = bob_t.sync_parts().expect("bob sync parts");
    let alice_moot = TesseraSession::join(a_ep, a_gossip, alice_store, MOOT).await;
    let bob_moot = TesseraSession::join(b_ep, b_gossip, bob_store, MOOT).await;

    // Bob catches up over LogSync and folds the synced log to score 11.
    let converged = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            let ledger = bob_moot.ledger(TesseraConfig::default()).await.unwrap();
            if ledger.score(&author_root, 5_000) == 11 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    })
    .await;
    assert!(
        converged.is_ok(),
        "bob converged on alice's tessera score over LogSync within the timeout"
    );

    // Both peers compute the identical score from their own stores.
    let alice_score = alice_moot
        .ledger(TesseraConfig::default())
        .await
        .unwrap()
        .score(&author_root, 5_000);
    let bob_score = bob_moot
        .ledger(TesseraConfig::default())
        .await
        .unwrap()
        .score(&author_root, 5_000);
    assert_eq!(bob_score, alice_score, "both peers project the same score");
    assert_eq!(bob_score, 11, "+10 fulfil, +1 govern");

    // Real (non-placebo) sync feedback recorded the catch-up.
    let status = bob_moot.joined.sync_status();
    assert!(
        status.ops_received >= 3,
        "sync status recorded the caught-up ops (got {})",
        status.ops_received
    );
    assert!(status.last_activity_ms.is_some());

    // The manual checkpoint returns quickly (already synced).
    let round = bob_moot.joined.resync().await;
    println!(
        "tessera resync checkpoint: items_received={}",
        round.items_received
    );
}

/// The same convergence, bootstrapped by **ticket** — the host's "connect to
/// peer" path. Each side parses the other's ticket string (not its raw
/// `EndpointAddr`), proving `transport::ticket` / `add_peer_ticket` drive a real
/// LogSync convergence end to end.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_moots_converge_bootstrapped_by_ticket() {
    let alice_provider = Arc::new(InMemoryProvider::from_seed([50; 32]));
    let bob_provider = Arc::new(InMemoryProvider::from_seed([51; 32]));
    let alice_kp = alice_provider.master_keypair().clone();
    let bob_kp = bob_provider.master_keypair().clone();

    let alice_t = P2pandaTransport::builder(&alice_kp)
        .gossip()
        .bind()
        .await
        .expect("bind alice");
    let bob_t = P2pandaTransport::builder(&bob_kp)
        .gossip()
        .bind()
        .await
        .expect("bind bob");

    let author = alice_provider.derive_keypair(b"tessera-author").unwrap();
    let author_root = ChainRoot(author.public_key().to_bytes());

    // Bootstrap by ticket: each side parses the other's ticket (learning its
    // PeerID + transport info) and tags it on the derived overlay topic.
    let overlay = transport::sync_overlay_topic(MOOT);
    let bob_learns_alice = bob_t
        .add_peer_ticket(&alice_t.ticket().await.unwrap())
        .await
        .unwrap();
    bob_t
        .set_topics(bob_learns_alice, &[overlay])
        .await
        .unwrap();
    let alice_learns_bob = alice_t
        .add_peer_ticket(&bob_t.ticket().await.unwrap())
        .await
        .unwrap();
    alice_t
        .set_topics(alice_learns_bob, &[overlay])
        .await
        .unwrap();

    let alice_store = TesseraStore::in_memory();
    for op in commit_fulfil_govern(&author) {
        alice_store.insert(&op).await.unwrap();
    }
    let bob_store = TesseraStore::in_memory();

    let (a_ep, a_gossip) = alice_t.sync_parts().expect("alice sync parts");
    let (b_ep, b_gossip) = bob_t.sync_parts().expect("bob sync parts");
    let alice_moot = TesseraSession::join(a_ep, a_gossip, alice_store, MOOT).await;
    let bob_moot = TesseraSession::join(b_ep, b_gossip, bob_store, MOOT).await;

    let converged = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            let score = bob_moot
                .ledger(TesseraConfig::default())
                .await
                .unwrap()
                .score(&author_root, 5_000);
            if score == 11 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    })
    .await;
    assert!(
        converged.is_ok(),
        "bob converged on alice's score via a ticket-bootstrapped connection"
    );
    let alice_score = alice_moot
        .ledger(TesseraConfig::default())
        .await
        .unwrap()
        .score(&author_root, 5_000);
    let bob_score = bob_moot
        .ledger(TesseraConfig::default())
        .await
        .unwrap()
        .score(&author_root, 5_000);
    assert_eq!(
        bob_score, alice_score,
        "both peers agree after a ticket bootstrap"
    );
    assert_eq!(bob_score, 11);
}
