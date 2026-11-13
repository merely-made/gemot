// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;
use portolan::taxonomy::{Recognized, RelationClass};
use portolan::{Author, EdgeId, FacetId};
use gemot::moot::constitution::{CapabilityGrant, ConstitutionRules};
use gemot::moot::{MOOT_ACT_ACTION, MOOT_DELEGATION_DOMAIN, MootAuthority, MootDelegations};
use insigne::delegation::{
    CapabilityScope, DelegationCertificate, DelegationParent, DelegationRevocation,
    SignedDelegationCertificate, SignedDelegationRevocation,
};
use muniment::{MemoryBackend, RedbBackend};
use murm_sync::JoinedSpace;
use personae::AttestationKeys;
use personae::delegation::Issue;
use personae::{IdentityProvider, InMemoryProvider};
use proptest::prelude::*;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use transport::{P2pandaTransport, PeerID, sync_overlay_topic};

const CONTAINER: [u8; 32] = [0xc0; 32];
const MOOT: [u8; 32] = [0x6d; 32];
const ROOT_GRANT: [u8; 32] = [0x67; 32];
const AUTHORITY_NOW_MS: u64 = 50;

pub(super) fn cites() -> Relation {
    Relation::new(RelationClass::recognized(Recognized::Cites))
}

fn gemot_rules(root: &InMemoryProvider, path_prefix: String) -> ConstitutionRules {
    let mut rules = ConstitutionRules::founder_only(root.master_public_key().to_bytes());
    rules.grant(CapabilityGrant {
        id: ROOT_GRANT,
        subject: root.master_public_key().to_bytes(),
        path_prefix,
        not_before_ms: 10,
        expires_at_ms: Some(1_000),
        delegation_depth: 2,
    });
    rules
}

fn issue_gemot_delegation(
    root: &InMemoryProvider,
    writer: &InMemoryProvider,
    path_prefix: String,
    expires_at_ms: Option<u64>,
    nonce: u8,
) -> SignedDelegationCertificate {
    SignedDelegationCertificate::issue(
        root,
        DelegationCertificate::new(
            DelegationParent::Root(ROOT_GRANT),
            root.master_public_key().to_bytes(),
            writer.master_public_key().to_bytes(),
            CapabilityScope {
                domain: MOOT_DELEGATION_DOMAIN.into(),
                resource: MOOT.to_vec(),
                path_prefix,
                actions: [MOOT_ACT_ACTION.to_string()].into_iter().collect(),
            },
            15,
            20,
            expires_at_ms,
            0,
            [nonce; 32],
        ),
    )
    .expect("test delegation signs")
}

fn gemot_authority<'a>(
    delegations: &'a MootDelegations,
    rules: &'a ConstitutionRules,
) -> GemotAuthorityView<'a> {
    GemotAuthorityView {
        authority: MootAuthority {
            delegations,
            rules,
            moot_id: MOOT,
            now_ms: AUTHORITY_NOW_MS,
        },
    }
}

pub(super) type Fingerprint = (
    Vec<(String, String, Vec<String>)>,
    Vec<(String, String, String)>,
);

pub(super) fn fingerprint(log: &GraphLog<Container, Relation>) -> Fingerprint {
    let graph = log.graph();
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    for (key, node) in graph.nodes() {
        let mut tags: Vec<_> = node.tags.iter().cloned().collect();
        tags.sort();
        nodes.push((node.id.clone(), node.title.clone(), tags));
        for (_, target, edge) in graph.out_edges(key) {
            edges.push((
                node.id.clone(),
                graph.node(target).expect("target present").id.clone(),
                format!("{:?}", edge.class),
            ));
        }
    }
    nodes.sort();
    edges.sort();
    (nodes, edges)
}

fn connect_id(operation: &Operation<CommonsExt>) -> Option<EdgeId> {
    from_operation(operation)
        .ok()?
        .batch
        .edits
        .iter()
        .find_map(|edit| match edit {
            GraphEdit::Connect { id, .. } => Some(*id),
            _ => None,
        })
}

struct FixedAuthority {
    subject: [u8; 32],
    state: AuthorityState,
}

impl CommonsAuthority for FixedAuthority {
    fn classify(&self, subject: Subject, capability: &Cap, mode: Mode) -> AuthorityState {
        assert_eq!(subject.0, self.subject);
        assert_eq!(capability, &commons_write_capability(CONTAINER));
        assert_eq!(mode, Mode::Write);
        self.state
    }
}

/// Two bound transports tagged with each other on the container's overlay
/// topic (the two-peer bootstrap mesh and gemot already use).
async fn two_peers() -> (P2pandaTransport, P2pandaTransport) {
    let alice_provider = Arc::new(InMemoryProvider::from_seed([90; 32]));
    let bob_provider = Arc::new(InMemoryProvider::from_seed([91; 32]));
    let alice_id = PeerID::from_public_key(alice_provider.master_public_key());
    let bob_id = PeerID::from_public_key(bob_provider.master_public_key());

    let alice = P2pandaTransport::builder(alice_provider.master_keypair())
        .gossip()
        .bind()
        .await
        .expect("bind alice");
    let bob = P2pandaTransport::builder(bob_provider.master_keypair())
        .gossip()
        .bind()
        .await
        .expect("bind bob");

    let overlay = sync_overlay_topic(CONTAINER);
    alice
        .add_peer(bob.endpoint_addr().await.unwrap())
        .await
        .unwrap();
    alice.set_topics(bob_id, &[overlay]).await.unwrap();
    bob.add_peer(alice.endpoint_addr().await.unwrap())
        .await
        .unwrap();
    bob.set_topics(alice_id, &[overlay]).await.unwrap();
    (alice, bob)
}

struct CrossWiredIdentity {
    writer: InMemoryProvider,
    attester: InMemoryProvider,
}

impl IdentityProvider for CrossWiredIdentity {
    fn master_public_key(&self) -> personae::Ed25519PublicKey {
        self.attester.master_public_key()
    }

    fn derive_keypair(&self, salt: &[u8]) -> Result<personae::Ed25519Keypair, IdentityError> {
        self.writer.derive_keypair(salt)
    }

    fn attest_derived_key(&self, salt: &[u8]) -> Result<DerivedKeyAttestation, IdentityError> {
        self.attester.attest_derived_key(salt)
    }
}

fn authored_inserts(seed: [u8; 32], label: &str, count: usize) -> Vec<StoredRecord> {
    let signing_key = SigningKey::from_bytes(&seed);
    let writer = WriterId(*signing_key.verifying_key().as_bytes());
    let author = Author::new(label);
    let mut graph = GraphLog::<Container, Relation>::new().for_writer(writer);
    let mut backlink = None;
    let mut records = Vec::new();
    for seq in 0..count {
        graph.insert_node(
            &author,
            Container::new(format!("shared-{}", seq % 3)).with_title(format!("{label}-{seq}")),
        );
        let batch = graph.log().entries().last().unwrap().clone();
        let operation = to_operation(seed, CONTAINER, &batch, Vec::new(), seq as u32, backlink);
        backlink = Some(*operation.hash.as_bytes());
        let record = from_operation(&operation).unwrap();
        records.push(StoredRecord {
            operation,
            record,
            log_id: COMMONS_LOG,
        });
    }
    records
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn the_same_operation_set_has_one_projection_under_arbitrary_arrival_order(
        alice_count in 1usize..6,
        bob_count in 1usize..6,
        arrival_keys in prop::collection::vec(any::<u8>(), 0..16),
    ) {
        let mut records = authored_inserts([90; 32], "alice", alice_count);
        records.extend(authored_inserts([91; 32], "bob", bob_count));
        let expected = GraphLog::replay(causal_journal(&records).unwrap().0);
        let expected = fingerprint(&expected);

        let mut shuffled = records;
        shuffled.sort_by_key(|record| {
            let hash = record.operation.hash.as_bytes();
            let arrival = if arrival_keys.is_empty() {
                hash[0]
            } else {
                arrival_keys[usize::from(hash[0]) % arrival_keys.len()]
            };
            (arrival, hash[1], hash[2])
        });
        if arrival_keys.first().is_some_and(|value| value % 2 == 1) {
            shuffled.reverse();
        }
        let actual = GraphLog::replay(causal_journal(&shuffled).unwrap().0);

        prop_assert_eq!(fingerprint(&actual), expected);
    }
}

#[path = "tests/authority.rs"]
mod authority;

#[path = "tests/convergence.rs"]
mod convergence;

#[path = "tests/storage.rs"]
mod storage;

#[path = "tests/stream_sync.rs"]
mod stream_sync;
