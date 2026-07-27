//! Live two-peer convergence proof for independent Moot delegation.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use identity::delegation::{
    CapabilityScope, DelegationCertificate, DelegationParent, SignedDelegationCertificate,
    delegation_signing_salt,
};
use identity::{IdentityProvider, InMemoryProvider};
use muniment::MemoryBackend;
use stickleback::JoinedSpace;
use transport::{P2pandaTransport, PeerID, sync_overlay_topic};

use super::{MOOT_ACT_ACTION, MOOT_DELEGATION_DOMAIN, MootDelegationExt, MootDelegationStore};
use crate::moot::constitution::{CapabilityGrant, ConstitutionRules};

const MOOT: [u8; 32] = [0x67; 32];
const ROOT_GRANT: [u8; 32] = [0x68; 32];

struct DelegationSession {
    store: MootDelegationStore<MemoryBackend>,
    joined: JoinedSpace<MootDelegationExt>,
}

impl DelegationSession {
    async fn join(transport: &P2pandaTransport, store: MootDelegationStore<MemoryBackend>) -> Self {
        let (endpoint, gossip) = transport.sync_parts().expect("delegation sync parts");
        let receiving_store = store.clone();
        let joined = JoinedSpace::join::<_, u64, _, _>(
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
        .expect("delegation join");
        Self { store, joined }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn late_peer_catches_up_on_independent_delegation() {
    let alice_transport_identity = Arc::new(InMemoryProvider::from_seed([40; 32]));
    let bob_transport_identity = Arc::new(InMemoryProvider::from_seed([41; 32]));
    let alice_id = PeerID::from_public_key(alice_transport_identity.master_public_key());
    let bob_id = PeerID::from_public_key(bob_transport_identity.master_public_key());
    let alice_transport = P2pandaTransport::builder(alice_transport_identity.master_keypair())
        .gossip()
        .bind()
        .await
        .expect("bind alice");
    let bob_transport = P2pandaTransport::builder(bob_transport_identity.master_keypair())
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

    let root = InMemoryProvider::from_seed([1; 32]);
    let delegate = InMemoryProvider::from_seed([2; 32]);
    let root_id = root.master_public_key().to_bytes();
    let delegate_id = delegate.master_public_key().to_bytes();
    let mut rules = ConstitutionRules::founder_only(root_id);
    rules.grant(CapabilityGrant {
        id: ROOT_GRANT,
        subject: root_id,
        path_prefix: "moot/fauna".into(),
        not_before_ms: 1,
        expires_at_ms: Some(100),
        delegation_depth: 2,
    });
    let scope = CapabilityScope {
        domain: MOOT_DELEGATION_DOMAIN.into(),
        resource: MOOT.to_vec(),
        path_prefix: "moot/fauna/notes".into(),
        actions: BTreeSet::from([MOOT_ACT_ACTION.into()]),
    };
    let signed = SignedDelegationCertificate::issue(
        &root,
        DelegationCertificate::new(
            DelegationParent::Root(ROOT_GRANT),
            root_id,
            delegate_id,
            scope.clone(),
            2,
            3,
            Some(90),
            1,
            [3; 32],
        ),
    )
    .unwrap();
    let signing_key = root
        .derive_keypair(&delegation_signing_salt(&scope))
        .unwrap();
    let alice_store = MootDelegationStore::in_memory(MOOT);
    alice_store
        .author_issue(&signing_key, &rules, signed)
        .await
        .unwrap();

    let _alice = DelegationSession::join(&alice_transport, alice_store).await;
    let bob = DelegationSession::join(&bob_transport, MootDelegationStore::in_memory(MOOT)).await;

    let converged = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if bob
                .store
                .delegations(&rules)
                .await
                .is_ok_and(|delegations| {
                    delegations.covers(MOOT, &rules, delegate_id, "moot/fauna/notes/write", 50)
                })
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await;
    assert!(converged.is_ok(), "late peer did not receive delegation");
    assert!(bob.joined.sync_status().ops_received >= 1);
}
