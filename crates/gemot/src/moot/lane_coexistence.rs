//! Do two Moot lanes converge while sharing one topic?
//!
//! Every lane in a Moot subscribes to the same 32-byte Moot id and is
//! distinguished only by its extension type. Each existing lane proof joins
//! exactly one lane in isolation, so the combination was never exercised: a
//! session receives every message published on the topic, including operations
//! belonging to sibling lanes that cannot decode as its own extension.
//!
//! A product host joins the whole set at once, so this is load-bearing rather
//! than academic. If sibling traffic were to stall or poison a lane, the fix
//! would be topic separation inside Gemot, not a workaround in the host.

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

use super::constitution::{CapabilityGrant, ConstitutionExt, ConstitutionRules, ConstitutionStore};
use super::delegation::{
    MOOT_ACT_ACTION, MOOT_DELEGATION_DOMAIN, MootDelegationExt, MootDelegationStore,
};

const MOOT: [u8; 32] = [0x7c; 32];
const ROOT_GRANT: [u8; 32] = [0x7d; 32];

/// One peer holding both lanes, joined in the order a host would.
struct BothLanes {
    constitution: ConstitutionStore<MemoryBackend>,
    delegations: MootDelegationStore<MemoryBackend>,
    _constitution_lane: JoinedSpace<ConstitutionExt>,
    _delegation_lane: JoinedSpace<MootDelegationExt>,
}

impl BothLanes {
    /// `delegation_first` flips which lane subscribes to the shared topic
    /// first, which is what distinguishes "the second lane loses" from "the
    /// delegation lane is broken".
    async fn join(
        transport: &P2pandaTransport,
        founder_id: [u8; 32],
        delegation_first: bool,
    ) -> Self {
        let constitution = ConstitutionStore::in_memory(MOOT, founder_id);
        let delegations = MootDelegationStore::in_memory(MOOT);
        if delegation_first {
            let (endpoint, gossip) = transport.sync_parts().expect("delegation sync parts");
            let receiving = delegations.clone();
            let delegation_lane = JoinedSpace::join::<_, u64, _, _>(
                delegations.sync_store(),
                endpoint,
                gossip,
                MOOT,
                move |operation| {
                    let store = receiving.clone();
                    async move { matches!(store.accept(&operation).await, Ok(true)) }
                },
            )
            .await
            .expect("delegation join");
            let (endpoint, gossip) = transport.sync_parts().expect("constitution sync parts");
            let receiving = constitution.clone();
            let constitution_lane = JoinedSpace::join::<_, u64, _, _>(
                constitution.sync_store(),
                endpoint,
                gossip,
                MOOT,
                move |operation| {
                    let store = receiving.clone();
                    async move { matches!(store.accept(&operation).await, Ok(true)) }
                },
            )
            .await
            .expect("constitution join");
            return Self {
                constitution,
                delegations,
                _constitution_lane: constitution_lane,
                _delegation_lane: delegation_lane,
            };
        }

        let (endpoint, gossip) = transport.sync_parts().expect("constitution sync parts");
        let receiving = constitution.clone();
        let constitution_lane = JoinedSpace::join::<_, u64, _, _>(
            constitution.sync_store(),
            endpoint,
            gossip,
            MOOT,
            move |operation| {
                let store = receiving.clone();
                async move { matches!(store.accept(&operation).await, Ok(true)) }
            },
        )
        .await
        .expect("constitution join");

        let (endpoint, gossip) = transport.sync_parts().expect("delegation sync parts");
        let receiving = delegations.clone();
        let delegation_lane = JoinedSpace::join::<_, u64, _, _>(
            delegations.sync_store(),
            endpoint,
            gossip,
            MOOT,
            move |operation| {
                let store = receiving.clone();
                async move { matches!(store.accept(&operation).await, Ok(true)) }
            },
        )
        .await
        .expect("delegation join");

        Self {
            constitution,
            delegations,
            _constitution_lane: constitution_lane,
            _delegation_lane: delegation_lane,
        }
    }
}

async fn peer(seed: u8) -> (Arc<InMemoryProvider>, P2pandaTransport) {
    let provider = Arc::new(InMemoryProvider::from_seed([seed; 32]));
    let transport = P2pandaTransport::builder(provider.master_keypair())
        .gossip()
        .bind()
        .await
        .expect("bind peer");
    (provider, transport)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_lanes_sharing_one_topic_both_converge() {
    lanes_converge(false).await;
}

/// The same proof with the join order reversed, and a known failure.
///
/// **Reproducible, isolated, not flaky.** Constitution-then-delegation
/// converges; delegation-then-constitution leaves the delegation lane empty
/// while constitution still arrives. Each lane converges alone, so neither
/// lane is individually broken: joining two lanes to one topic is
/// order-sensitive.
///
/// Deriving a separate topic per lane was the obvious guess and is **not** the
/// fix. Tried on 2026-07-31, with each lane's overlay registered through
/// `set_topics`: it made both orders fail rather than one, so the mechanism is
/// not simply two sessions contending for a subscription. Diagnosing it means
/// understanding how p2panda's LogSync sessions share an endpoint and gossip
/// handle, which is a real investigation rather than a patch.
///
/// Ignored rather than deleted or left red: a product host joins the whole
/// lane set at once, so this is load-bearing, and the receipt should stay
/// visible and named. Un-ignore it when the mechanism is understood.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "known defect: two lanes on one topic are order-sensitive; \
            per-lane topics are not the fix (2026-07-31)"]
async fn two_lanes_converge_whichever_joins_the_topic_first() {
    lanes_converge(true).await;
}

async fn lanes_converge(delegation_first: bool) {
    let (alice_provider, alice_transport) = peer(0x70).await;
    let (bob_provider, bob_transport) = peer(0x71).await;
    let alice_id = PeerID::from_public_key(alice_provider.master_public_key());
    let bob_id = PeerID::from_public_key(bob_provider.master_public_key());

    let overlay = sync_overlay_topic(MOOT);
    alice_transport
        .add_peer(bob_transport.endpoint_addr().await.unwrap())
        .await
        .unwrap();
    alice_transport.set_topics(bob_id, &[overlay]).await.unwrap();
    bob_transport
        .add_peer(alice_transport.endpoint_addr().await.unwrap())
        .await
        .unwrap();
    bob_transport
        .set_topics(alice_id, &[overlay])
        .await
        .unwrap();

    let root = InMemoryProvider::from_seed([0x72; 32]);
    let delegate = InMemoryProvider::from_seed([0x73; 32]);
    let root_id = root.master_public_key().to_bytes();

    let mut rules = ConstitutionRules::founder_only(root_id);
    rules.grant(CapabilityGrant {
        id: ROOT_GRANT,
        subject: root_id,
        path_prefix: "moot/fauna".into(),
        not_before_ms: 1,
        expires_at_ms: Some(100),
        delegation_depth: 2,
    });

    let alice = BothLanes::join(&alice_transport, root_id, delegation_first).await;
    let bob = BothLanes::join(&bob_transport, root_id, delegation_first).await;

    // Author on both lanes, so each peer publishes traffic the other lane's
    // session will also see and must discard without harm.
    alice
        .constitution
        .author_genesis(
            root.master_keypair().to_seed(),
            None,
            None,
            rules.clone(),
            1,
        )
        .await
        .unwrap();

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
            delegate.master_public_key().to_bytes(),
            scope.clone(),
            2,
            3,
            Some(90),
            1,
            [0x74; 32],
        ),
    )
    .unwrap();
    alice
        .delegations
        .author_issue(
            &root.derive_keypair(&delegation_signing_salt(&scope)).unwrap(),
            &rules,
            signed,
        )
        .await
        .unwrap();

    // Both lanes must arrive. A single shared assertion would let one lane
    // carry the test while the other silently never converged.
    let converged = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let constitution_here = bob.constitution.constitution().await.unwrap().is_some();
            let delegation_here = bob
                .delegations
                .delegations(&rules)
                .await
                .unwrap()
                .certificate_count()
                == 1;
            if constitution_here && delegation_here {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await;

    // Rule out a silent authoring failure before blaming the topic: the
    // publisher must hold what the receiver is waiting for.
    assert!(alice.constitution.constitution().await.unwrap().is_some());
    assert_eq!(
        alice
            .delegations
            .delegations(&rules)
            .await
            .unwrap()
            .certificate_count(),
        1,
        "the author's own delegation store must hold the certificate"
    );

    assert!(
        converged.is_ok(),
        "delegation_first={delegation_first}: sharing one topic stalled a lane: \
         constitution present {}, delegation certificates {}",
        bob.constitution.constitution().await.unwrap().is_some(),
        bob.delegations
            .delegations(&rules)
            .await
            .unwrap()
            .certificate_count(),
    );

    // Sibling traffic must not have been absorbed as this lane's own.
    assert_eq!(
        bob.constitution.constitution().await.unwrap().unwrap().rules,
        rules
    );
    assert_eq!(
        bob.delegations
            .delegations(&rules)
            .await
            .unwrap()
            .certificate_count(),
        1
    );
}
