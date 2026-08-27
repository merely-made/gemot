// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Two-peer convergence proof for the constitution lane.

use std::sync::Arc;
use std::time::Duration;

use identity::{IdentityProvider, InMemoryProvider};
use muniment::MemoryBackend;
use stickleback::{CheckpointAuthority, JoinedSpace};
use transport::{P2pandaTransport, PeerID, sync_overlay_topic};

use super::{Constitution, ConstitutionExt, ConstitutionRules, ConstitutionStore};
use crate::moot::GovernedCheckpointAuthority;

const MOOT: [u8; 32] = [0x64; 32];

struct ConstitutionSession {
    store: ConstitutionStore<MemoryBackend>,
    joined: JoinedSpace<ConstitutionExt>,
}

impl ConstitutionSession {
    async fn join(transport: &P2pandaTransport, store: ConstitutionStore<MemoryBackend>) -> Self {
        let (endpoint, gossip) = transport.sync_parts().expect("constitution sync parts");
        let receiving_store = store.clone();
        let joined = JoinedSpace::join::<_, u64, _, _>(
            stickleback::lane_id("gemot/constitution/v1", MOOT),
            store.sync_store(),
            endpoint,
            gossip,
            MOOT,
            move |operation| {
                let store = receiving_store.clone();
                async move { matches!(store.accept(&operation).await, Ok(true)) }
            },
        )
        .await
        .expect("constitution join");
        Self { store, joined }
    }

    async fn constitution(&self) -> Option<Constitution> {
        self.store.constitution().await.unwrap()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn late_peer_catches_up_on_accepted_constitution() {
    let alice_provider = Arc::new(InMemoryProvider::from_seed([80; 32]));
    let bob_provider = Arc::new(InMemoryProvider::from_seed([81; 32]));
    let alice_id = PeerID::from_public_key(alice_provider.master_public_key());
    let bob_id = PeerID::from_public_key(bob_provider.master_public_key());
    let alice_transport = P2pandaTransport::builder(alice_provider.master_keypair())
        .gossip()
        .bind()
        .await
        .expect("bind alice");
    let bob_transport = P2pandaTransport::builder(bob_provider.master_keypair())
        .gossip()
        .bind()
        .await
        .expect("bind bob");

    let overlay = sync_overlay_topic(MOOT);
    alice_transport
        .add_peer(bob_transport.endpoint_addr().await.unwrap())
        .await
        .unwrap();
    alice_transport
        .set_topics(bob_id, &[overlay])
        .await
        .unwrap();
    bob_transport
        .add_peer(alice_transport.endpoint_addr().await.unwrap())
        .await
        .unwrap();
    bob_transport
        .set_topics(alice_id, &[overlay])
        .await
        .unwrap();

    let founder = alice_provider
        .derive_keypair(b"constitution-author")
        .unwrap();
    let founder_id = founder.public_key().to_bytes();
    let alice_store = ConstitutionStore::in_memory(MOOT, founder_id);
    alice_store
        .author_genesis(
            founder.to_seed(),
            None,
            None,
            ConstitutionRules::founder_only(founder_id),
            1,
        )
        .await
        .unwrap();
    let mut amended_rules = ConstitutionRules::founder_only(founder_id);
    amended_rules.checkpoint_signers.insert([9; 32]);
    alice_store
        .author_amendment(founder.to_seed(), amended_rules.clone(), 2)
        .await
        .unwrap();

    let alice = ConstitutionSession::join(&alice_transport, alice_store).await;
    let bob = ConstitutionSession::join(
        &bob_transport,
        ConstitutionStore::in_memory(MOOT, founder_id),
    )
    .await;

    let converged = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if bob
                .constitution()
                .await
                .is_some_and(|state| state.rules == amended_rules)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await;
    assert!(
        converged.is_ok(),
        "late peer did not receive the constitution"
    );

    let alice_state = alice.constitution().await.unwrap();
    let bob_state = bob.constitution().await.unwrap();
    assert_eq!(bob_state, alice_state);
    let authority = GovernedCheckpointAuthority::from_state(&bob_state);
    assert!(authority.permits_checkpoint([9; 32], &bob_state.revision));
    assert!(bob.joined.sync_status().ops_received >= 2);
}
