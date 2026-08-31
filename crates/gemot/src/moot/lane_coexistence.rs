// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Two Moot lanes converge over one transport pair, on distinct lane ids.
//!
//! ## The defect this file found, diagnosed 2026-07-31
//!
//! Every `LogSync` instance used to register the same hardcoded protocol id
//! (`p2panda/log_sync/v1`) on the shared endpoint, and the endpoint keeps
//! exactly one handler per id (`BTreeMap::insert`, last writer wins,
//! silently). So the last-joined lane received ALL inbound sync sessions and
//! every other lane stopped converging. Symptoms measured before diagnosis:
//! each lane fine alone, any two lanes broken in both join orders, and
//! per-lane *topics* useless, because topics live inside the sync protocol
//! while routing happens at the ALPN, before any topic is read.
//!
//! The fix is in the p2panda fork: `LogSync::builder().protocol_id(...)`,
//! surfaced through `JoinedSpace::join`'s required `lane` argument. Every
//! lane kind sharing an endpoint names itself, scoped to its space id, and
//! the tests below are the receipt that the combination now converges. The
//! join-order variant is kept because order was the original symptom: it must
//! stay green in both orders, not merely in the one that happened to work.
//!
//! Upstream p2panda has the same hardcoded id as of 2026-07-31, so this stays
//! a fork divergence until it is offered upstream.

use std::collections::{BTreeMap, BTreeSet};
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
use super::{
    ArtifactRef, FloraEvent, FloraParticipant, FloraRoundId, FloraRoundSpec, FloraWeight,
    TulpaEvent, TulpaId, TulpaProposal, TulpaProposalId, TulpaVersion,
};
use mooting::{ElectorateSnapshot, RecognitionContext, RecognitionPolicy};

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
    /// `delegation_first` flips which lane joins first. Under the original
    /// defect the last-joined lane stole all inbound sync, so both orders
    /// staying green is the proof that order no longer matters.
    async fn join(
        transport: &P2pandaTransport,
        constitution: ConstitutionStore<MemoryBackend>,
        delegations: MootDelegationStore<MemoryBackend>,
        delegation_first: bool,
    ) -> Self {
        if delegation_first {
            let (endpoint, gossip) = transport.sync_parts().expect("delegation sync parts");
            let receiving = delegations.clone();
            let delegation_lane = JoinedSpace::join::<_, u64, _, _>(
                stickleback::lane_id("gemot/delegation/v1", MOOT),
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
                stickleback::lane_id("gemot/constitution/v1", MOOT),
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
            stickleback::lane_id("gemot/constitution/v1", MOOT),
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
            stickleback::lane_id("gemot/delegation/v1", MOOT),
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

/// The same proof with the join order reversed.
///
/// Join order was the defect's original symptom: before the per-lane protocol
/// id, whichever lane registered last on the endpoint received all inbound
/// sync and the other stalled. Keeping both orders green is what proves the
/// fix removed the order sensitivity rather than moving it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_lanes_converge_whichever_joins_the_topic_first() {
    lanes_converge(true).await;
}

/// The product-shaped join: one call, all seven lanes, a late peer catching up
/// on retained governance. This is `Moot::join_lanes`' receipt, and the shape
/// Turnstone's place worker holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_late_peer_catches_up_on_the_whole_lane_set() {
    use super::MootRetentionSettings;
    use super::records::{AvailabilityPolicy, ErasurePolicy, KeepBound, PolicyRevision};
    use super::service::Moot;

    let (alice_provider, alice_transport) = peer(0x76).await;
    let (bob_provider, bob_transport) = peer(0x77).await;
    let alice_id = PeerID::from_public_key(alice_provider.master_public_key());
    let bob_id = PeerID::from_public_key(bob_provider.master_public_key());

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

    let retention = MootRetentionSettings {
        revision: PolicyRevision(proofs::Digest::blake3(b"lane-set-receipt")),
        availability: AvailabilityPolicy {
            promised_floor: KeepBound::Forever,
        },
        erasure: ErasurePolicy {
            history_ceiling: KeepBound::Forever,
        },
    };
    let root = InMemoryProvider::from_seed([0x78; 32]);
    let root_id = root.master_public_key().to_bytes();

    // Alice's Moot holds retained governance before any lane joins.
    let alice_moot = Moot::in_memory(super::MootId(MOOT), root_id, retention.clone());
    alice_moot
        .found(
            root.master_keypair().to_seed(),
            None,
            None,
            ConstitutionRules::founder_only(root_id),
            1,
        )
        .await
        .unwrap();
    alice_moot
        .membership_store()
        .author_for_identity(
            &root,
            super::MootMembershipAction::Create {
                initial_members: vec![super::MootMember {
                    member: root_id,
                    access: super::MootAccessLevel::Manage,
                }],
            },
        )
        .await
        .unwrap();
    alice_moot
        .record_tulpa(
            root.master_keypair().to_seed(),
            TulpaEvent::Proposed {
                proposal: TulpaProposalId([0x79; 32]),
                action: TulpaProposal::Adopt {
                    tulpa: TulpaId([0x7a; 32]),
                    version: TulpaVersion([0x7b; 32]),
                    artifact: ArtifactRef::blake3(b"two-peer Tulpa receipt"),
                },
                recognition: RecognitionContext::new(
                    RecognitionPolicy::AnyEligible,
                    ElectorateSnapshot::new(MOOT, [0x7c; 32], [root_id]),
                ),
                at_ms: 2,
            },
        )
        .await
        .unwrap();
    alice_moot
        .record_flora(
            root.master_keypair().to_seed(),
            FloraEvent::RoundProposed {
                spec: FloraRoundSpec {
                    round: FloraRoundId([0x7d; 32]),
                    base_model: ArtifactRef::blake3(b"two-peer base model"),
                    rank_budget: 3,
                    participants: BTreeMap::from([(
                        root_id,
                        FloraParticipant {
                            rank: 3,
                            weight: FloraWeight {
                                numerator: 1,
                                denominator: 1,
                            },
                        },
                    )]),
                },
                at_ms: 3,
            },
        )
        .await
        .unwrap();

    let (a_endpoint, a_gossip) = alice_transport.sync_parts().unwrap();
    let _alice_lanes = alice_moot.join_lanes(a_endpoint, a_gossip).await.unwrap();

    let bob_moot = Moot::in_memory(super::MootId(MOOT), root_id, retention);
    let (b_endpoint, b_gossip) = bob_transport.sync_parts().unwrap();
    let bob_lanes = bob_moot.join_lanes(b_endpoint, b_gossip).await.unwrap();

    let converged = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let governed = bob_moot.snapshot().await;
            if let Ok(snapshot) = governed
                && snapshot.membership.members.len() == 1
                && snapshot.tulpa.facts.len() == 1
                && snapshot.flora.rounds.len() == 1
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await;
    assert!(
        converged.is_ok(),
        "the late peer did not converge on retained governance"
    );
    let snapshot = bob_moot.snapshot().await.unwrap();
    assert_eq!(snapshot.governance.founder, root_id);
    assert_eq!(snapshot.membership.members.len(), 1);
    assert_eq!(snapshot.tulpa.facts.len(), 1);
    assert_eq!(snapshot.flora.rounds.len(), 1);
    // Every lane reports its own sync activity: a host status surface must be
    // able to say WHICH lane is behind, not that "some lane" is.
    let status = bob_lanes.sync_status();
    assert!(
        status[0].ops_received >= 1,
        "constitution lane received genesis"
    );
    assert!(
        status[2].ops_received >= 1,
        "membership lane received the create"
    );
    assert!(
        status[5].ops_received >= 1,
        "Tulpa lane received the proposal"
    );
    assert!(status[6].ops_received >= 1, "FLORA lane received the round");
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

    // Author on both lanes BEFORE joining, matching the single-lane proofs and
    // the product scenario: retained state exists, a late joiner catches up
    // through initial sync. Post-join authoring reaching live peers is the
    // publish path's job and a separate proof.
    let alice_constitution = ConstitutionStore::in_memory(MOOT, root_id);
    let alice_delegations = MootDelegationStore::in_memory(MOOT);
    alice_constitution
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
    alice_delegations
        .author_issue(
            &root
                .derive_keypair(&delegation_signing_salt(&scope))
                .unwrap(),
            &rules,
            signed,
        )
        .await
        .unwrap();

    let alice = BothLanes::join(
        &alice_transport,
        alice_constitution,
        alice_delegations,
        delegation_first,
    )
    .await;
    let bob = BothLanes::join(
        &bob_transport,
        ConstitutionStore::in_memory(MOOT, root_id),
        MootDelegationStore::in_memory(MOOT),
        delegation_first,
    )
    .await;

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
        bob.constitution
            .constitution()
            .await
            .unwrap()
            .unwrap()
            .rules,
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
