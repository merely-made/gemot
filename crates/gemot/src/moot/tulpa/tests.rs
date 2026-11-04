// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;
use identity::{IdentityProvider, InMemoryProvider};
use mooting::{ElectorateSnapshot, RecognitionPolicy};

const MOOT: [u8; 32] = [0x71; 32];

fn key(seed: u8) -> Ed25519Keypair {
    InMemoryProvider::from_seed([seed; 32])
        .derive_keypair(b"tulpa-test")
        .unwrap()
}

fn context(members: impl IntoIterator<Item = [u8; 32]>) -> RecognitionContext {
    RecognitionContext::new(
        RecognitionPolicy::Unanimous,
        ElectorateSnapshot::new(MOOT, [0x22; 32], members),
    )
}

fn proposed(id: u8, members: impl IntoIterator<Item = [u8; 32]>) -> TulpaEvent {
    TulpaEvent::Proposed {
        proposal: TulpaProposalId([id; 32]),
        action: TulpaProposal::Adopt {
            tulpa: TulpaId([3; 32]),
            version: TulpaVersion([4; 32]),
            artifact: ArtifactRef::blake3(b"candidate"),
        },
        recognition: context(members),
        at_ms: 10,
    }
}

#[test]
fn fold_is_order_independent_and_uses_the_frozen_electorate() {
    let alice = key(1);
    let bob = key(2);
    let proposal = to_operation(
        &key(9),
        MOOT,
        &proposed(
            1,
            [alice.public_key().to_bytes(), bob.public_key().to_bytes()],
        ),
        0,
        None,
    );
    let a = to_operation(
        &alice,
        MOOT,
        &TulpaEvent::Endorsed {
            proposal: TulpaProposalId([1; 32]),
            at_ms: 11,
        },
        0,
        None,
    );
    let b = to_operation(
        &bob,
        MOOT,
        &TulpaEvent::Endorsed {
            proposal: TulpaProposalId([1; 32]),
            at_ms: 12,
        },
        0,
        None,
    );
    let facts = |operations: Vec<&Operation<TulpaExt>>| {
        operations
            .into_iter()
            .map(|operation| TulpaFact {
                operation: *operation.hash.as_bytes(),
                author: *operation.header.verifying_key.as_bytes(),
                event: from_operation(operation).unwrap(),
            })
            .collect()
    };
    let forward = TulpaProjection::fold(facts(vec![&proposal, &a, &b]));
    let backward = TulpaProjection::fold(facts(vec![&b, &proposal, &a]));
    assert_eq!(forward, backward);
    assert_eq!(forward.adopted.len(), 1);

    let later_context = context([
        alice.public_key().to_bytes(),
        bob.public_key().to_bytes(),
        key(3).public_key().to_bytes(),
    ]);
    assert!(
        !later_context
            .evaluate(&BTreeSet::from([
                alice.public_key().to_bytes(),
                bob.public_key().to_bytes()
            ]))
            .unwrap()
            .accepted
    );
}

#[test]
fn outsiders_and_duplicate_endorsements_never_add_weight() {
    let alice = key(1);
    let bob = key(2);
    let outsider = key(3);
    let owner = key(9);
    let proposal = to_operation(
        &owner,
        MOOT,
        &proposed(
            1,
            [alice.public_key().to_bytes(), bob.public_key().to_bytes()],
        ),
        0,
        None,
    );
    let a0 = to_operation(
        &alice,
        MOOT,
        &TulpaEvent::Endorsed {
            proposal: TulpaProposalId([1; 32]),
            at_ms: 11,
        },
        0,
        None,
    );
    let a1 = to_operation(
        &alice,
        MOOT,
        &TulpaEvent::Endorsed {
            proposal: TulpaProposalId([1; 32]),
            at_ms: 12,
        },
        1,
        Some(*a0.hash.as_bytes()),
    );
    let foreign = to_operation(
        &outsider,
        MOOT,
        &TulpaEvent::Endorsed {
            proposal: TulpaProposalId([1; 32]),
            at_ms: 13,
        },
        0,
        None,
    );
    let projection = TulpaProjection::fold(
        [&proposal, &a0, &a1, &foreign]
            .into_iter()
            .map(|operation| TulpaFact {
                operation: *operation.hash.as_bytes(),
                author: *operation.header.verifying_key.as_bytes(),
                event: from_operation(operation).unwrap(),
            })
            .collect(),
    );
    let decision = projection.decisions.get(&TulpaProposalId([1; 32])).unwrap();
    assert!(!decision.accepted);
    assert_eq!(decision.eligible_endorsements.len(), 1);
    assert_eq!(decision.ineligible_endorsements.len(), 1);
}

#[test]
fn revoke_removes_the_effect_without_deleting_source_facts() {
    let signer = key(1);
    let member = signer.public_key().to_bytes();
    let recognition = RecognitionContext::new(
        RecognitionPolicy::AnyEligible,
        ElectorateSnapshot::new(MOOT, [1; 32], [member]),
    );
    let adopt = TulpaEvent::Proposed {
        proposal: TulpaProposalId([1; 32]),
        action: TulpaProposal::Adopt {
            tulpa: TulpaId([2; 32]),
            version: TulpaVersion([3; 32]),
            artifact: ArtifactRef::blake3(b"v1"),
        },
        recognition: recognition.clone(),
        at_ms: 1,
    };
    let revoke = TulpaEvent::Proposed {
        proposal: TulpaProposalId([4; 32]),
        action: TulpaProposal::Revoke {
            tulpa: TulpaId([2; 32]),
            version: TulpaVersion([3; 32]),
        },
        recognition,
        at_ms: 3,
    };
    let proposed = to_operation(&signer, MOOT, &adopt, 0, None);
    let adopted = to_operation(
        &signer,
        MOOT,
        &TulpaEvent::Endorsed {
            proposal: TulpaProposalId([1; 32]),
            at_ms: 2,
        },
        1,
        Some(*proposed.hash.as_bytes()),
    );
    let proposed_revoke = to_operation(&signer, MOOT, &revoke, 2, Some(*adopted.hash.as_bytes()));
    let revoked = to_operation(
        &signer,
        MOOT,
        &TulpaEvent::Endorsed {
            proposal: TulpaProposalId([4; 32]),
            at_ms: 4,
        },
        3,
        Some(*proposed_revoke.hash.as_bytes()),
    );
    let operations = [proposed, adopted, proposed_revoke, revoked];
    let projection = TulpaProjection::fold(
        operations
            .iter()
            .map(|operation| TulpaFact {
                operation: *operation.hash.as_bytes(),
                author: *operation.header.verifying_key.as_bytes(),
                event: from_operation(operation).unwrap(),
            })
            .collect(),
    );
    assert!(projection.adopted.is_empty());
    assert_eq!(projection.facts.len(), 4);
    assert!(
        projection
            .revoked
            .contains(&(TulpaId([2; 32]), TulpaVersion([3; 32])))
    );
}

#[test]
fn rollback_reselects_an_adopted_version_without_removing_facts() {
    let signer = key(5);
    let member = signer.public_key().to_bytes();
    let recognition = RecognitionContext::new(
        RecognitionPolicy::AnyEligible,
        ElectorateSnapshot::new(MOOT, [5; 32], [member]),
    );
    let tulpa = TulpaId([6; 32]);
    let v1 = TulpaVersion([7; 32]);
    let v2 = TulpaVersion([8; 32]);
    let events = [
        TulpaEvent::Proposed {
            proposal: TulpaProposalId([1; 32]),
            action: TulpaProposal::Adopt {
                tulpa,
                version: v1,
                artifact: ArtifactRef::blake3(b"v1"),
            },
            recognition: recognition.clone(),
            at_ms: 1,
        },
        TulpaEvent::Endorsed {
            proposal: TulpaProposalId([1; 32]),
            at_ms: 2,
        },
        TulpaEvent::Proposed {
            proposal: TulpaProposalId([2; 32]),
            action: TulpaProposal::Adopt {
                tulpa,
                version: v2,
                artifact: ArtifactRef::blake3(b"v2"),
            },
            recognition: recognition.clone(),
            at_ms: 3,
        },
        TulpaEvent::Endorsed {
            proposal: TulpaProposalId([2; 32]),
            at_ms: 4,
        },
        TulpaEvent::Proposed {
            proposal: TulpaProposalId([3; 32]),
            action: TulpaProposal::Rollback {
                tulpa,
                to_version: v1,
            },
            recognition,
            at_ms: 5,
        },
        TulpaEvent::Endorsed {
            proposal: TulpaProposalId([3; 32]),
            at_ms: 6,
        },
    ];
    let mut operations = Vec::new();
    let mut backlink = None;
    for (sequence, event) in events.iter().enumerate() {
        let operation = to_operation(&signer, MOOT, event, sequence as u32, backlink);
        backlink = Some(*operation.hash.as_bytes());
        operations.push(operation);
    }
    let projection = TulpaProjection::fold(
        operations
            .iter()
            .map(|operation| TulpaFact {
                operation: *operation.hash.as_bytes(),
                author: *operation.header.verifying_key.as_bytes(),
                event: from_operation(operation).unwrap(),
            })
            .collect(),
    );
    assert_eq!(projection.facts.len(), 6);
    assert_eq!(projection.adopted.get(&tulpa).unwrap().version, v1);
}
