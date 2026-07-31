// Copyright 2026 Mark AB (markik)
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Two-peer convergence for the moot-object lane.
//!
//! After the sibling-posture purity split, gemot no longer owns p2panda-net:
//! the pump (the LogSync session + the [`stickleback::SyncedSpace`] drain) is
//! **host-composed**, and moot keeps only the store + fold + [`author`]
//! (sign-and-store; the host publishes). These tests play the host — build the
//! session over a [`MootStore`], drive it via `SyncedSpace`, and author via
//! [`MootStore::author`] + [`SyncHandle::publish`] — so the moot-object lane's
//! convergence stays covered without a production `SyncedMootSpace` type.
//!
//! [`author`]: MootStore::author

#![cfg(test)]

use std::sync::Arc as StdArc;
use std::time::Duration;

use identity::{Ed25519Keypair, IdentityProvider, InMemoryProvider};
use p2panda_core::Operation;
use p2panda_net::{Endpoint, Gossip};
use stickleback::JoinedSpace;
use transport::P2pandaTransport;

use super::roster::MootRoster;
use super::store::MootStore;
use super::wire::{MootEvent, MootExt, MootLogId, verify};

const MOOT: [u8; 32] = [0x6e; 32];

/// A host-composed moot-object session: the joined LogSync session (session +
/// live-publish lane + drain) and the store to fold. This is the boilerplate a
/// real host writes now that the pump lives host-side.
struct MootSession {
    store: MootStore,
    joined: JoinedSpace<MootExt>,
}

impl MootSession {
    async fn join(endpoint: Endpoint, gossip: Gossip, store: MootStore) -> Self {
        let accept_store = store.clone();
        let joined = JoinedSpace::join::<_, MootLogId, _, _>(
            stickleback::lane_id("gemot/records/v1", MOOT),
            store.sync_store(),
            endpoint,
            gossip,
            MOOT,
            move |op: Operation<MootExt>| {
                let store = accept_store.clone();
                async move {
                    verify(&op)
                        && op.header.extensions.moot_id == MOOT
                        && matches!(store.insert(&op).await, Ok(true))
                }
            },
        )
        .await
        .expect("moot join");
        Self { store, joined }
    }

    /// Sign + store an event (moot-side), then publish it live (host-side).
    async fn author(&self, keypair: &Ed25519Keypair, event: &MootEvent) {
        let op = self
            .store
            .author(keypair, MOOT, event)
            .await
            .expect("author");
        self.joined.publish(op).expect("publish");
    }

    async fn roster(&self) -> MootRoster {
        self.store.roster(MOOT).await.expect("roster")
    }

    fn ops_received(&self) -> u64 {
        self.joined.sync_status().ops_received
    }
}

/// Two bound transports tagged with each other on the moot's overlay topic
/// (the proven two-peer bootstrap).
async fn two_peers() -> (P2pandaTransport, P2pandaTransport) {
    let founder_provider = StdArc::new(InMemoryProvider::from_seed([70; 32]));
    let friend_provider = StdArc::new(InMemoryProvider::from_seed([71; 32]));
    let founder_id = transport::PeerID::from_public_key(founder_provider.master_public_key());
    let friend_id = transport::PeerID::from_public_key(friend_provider.master_public_key());

    let founder_t = P2pandaTransport::builder(founder_provider.master_keypair())
        .gossip()
        .bind()
        .await
        .expect("bind founder");
    let friend_t = P2pandaTransport::builder(friend_provider.master_keypair())
        .gossip()
        .bind()
        .await
        .expect("bind friend");

    let overlay = transport::sync_overlay_topic(MOOT);
    founder_t
        .add_peer(friend_t.endpoint_addr().await.unwrap())
        .await
        .unwrap();
    founder_t.set_topics(friend_id, &[overlay]).await.unwrap();
    friend_t
        .add_peer(founder_t.endpoint_addr().await.unwrap())
        .await
        .unwrap();
    friend_t.set_topics(founder_id, &[overlay]).await.unwrap();
    (founder_t, friend_t)
}

async fn join(t: &P2pandaTransport) -> MootSession {
    let (ep, gossip) = t.sync_parts().expect("sync parts");
    let store = MootStore::in_memory();
    MootSession::join(ep, gossip, store).await
}

async fn wait_for_roster(space: &MootSession, pred: impl Fn(&MootRoster) -> bool, what: &str) {
    let outcome = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if pred(&space.roster().await) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await;
    assert!(outcome.is_ok(), "timed out waiting for: {what}");
}

/// The M1 shape, in process: founder declares + joins + shares; a friend joins
/// live; both rosters agree on founding, members, fauna.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn declare_join_share_converges_on_both_peers() {
    let (founder_t, friend_t) = two_peers().await;
    let founder_space = join(&founder_t).await;
    let friend_space = join(&friend_t).await;

    let founder_kp = InMemoryProvider::from_seed([70; 32])
        .derive_keypair(b"moot-author")
        .unwrap();
    let friend_kp = InMemoryProvider::from_seed([71; 32])
        .derive_keypair(b"moot-author")
        .unwrap();

    founder_space
        .author(
            &founder_kp,
            &MootEvent::Declared {
                name: "printing circle".into(),
                charter: "we share what we set in type".into(),
                at_ms: 10,
            },
        )
        .await;
    founder_space
        .author(
            &founder_kp,
            &MootEvent::Joined {
                name: "mark".into(),
                at_ms: 11,
            },
        )
        .await;

    // The friend sees the founding, then joins and shares.
    wait_for_roster(
        &friend_space,
        |r| r.declaration.is_some(),
        "friend sees the declaration",
    )
    .await;
    friend_space
        .author(
            &friend_kp,
            &MootEvent::Joined {
                name: "alex".into(),
                at_ms: 20,
            },
        )
        .await;
    friend_space
        .author(
            &friend_kp,
            &MootEvent::Shared {
                manifest_id: [0xaa; 32],
                schema_id: "eidetic.SearchIndexSpec/v1".into(),
                title: "my trail index".into(),
                at_ms: 21,
            },
        )
        .await;

    // Both rosters converge to the same picture.
    for (space, who) in [(&founder_space, "founder"), (&friend_space, "friend")] {
        wait_for_roster(
            space,
            |r| {
                r.declaration.as_ref().map(|d| d.name.as_str()) == Some("printing circle")
                    && r.members.len() == 2
                    && r.fauna.len() == 1
                    && r.fauna[0].title == "my trail index"
            },
            &format!("{who} converges on the full roster"),
        )
        .await;
    }

    // Real (non-placebo) sync feedback on both sides.
    assert!(founder_space.ops_received() >= 2);
    assert!(friend_space.ops_received() >= 2);
    assert!(
        founder_space
            .joined
            .sync_status()
            .last_activity_ms
            .is_some()
    );
}

/// The catch-up lane: a roster authored before the friend connects converges
/// over RBSR.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_late_joiner_catches_up_on_an_existing_moot() {
    let (founder_t, friend_t) = two_peers().await;

    let founder_kp = InMemoryProvider::from_seed([70; 32])
        .derive_keypair(b"moot-author")
        .unwrap();
    let store = MootStore::in_memory();
    // Author into the store before joining (no live peer yet); the friend
    // catches up over RBSR.
    store
        .author(
            &founder_kp,
            MOOT,
            &MootEvent::Declared {
                name: "early circle".into(),
                charter: "founded before you arrived".into(),
                at_ms: 5,
            },
        )
        .await
        .unwrap();

    let (ep, gossip) = founder_t.sync_parts().expect("founder sync parts");
    let _founder_space = MootSession::join(ep, gossip, store).await;
    let friend_space = join(&friend_t).await;

    wait_for_roster(
        &friend_space,
        |r| r.declaration.as_ref().map(|d| d.name.as_str()) == Some("early circle"),
        "friend catches up on the founding",
    )
    .await;
    assert!(friend_space.ops_received() >= 1);
}
