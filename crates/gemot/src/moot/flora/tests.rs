// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

fn artifact(label: &'static [u8]) -> ArtifactRef {
    ArtifactRef::blake3(label)
}

fn spec() -> FloraRoundSpec {
    FloraRoundSpec {
        round: FloraRoundId([1; 32]),
        base_model: artifact(b"base"),
        rank_budget: 5,
        participants: BTreeMap::from([
            (
                [2; 32],
                FloraParticipant {
                    rank: 2,
                    weight: FloraWeight {
                        numerator: 8,
                        denominator: 2,
                    },
                },
            ),
            (
                [3; 32],
                FloraParticipant {
                    rank: 3,
                    weight: FloraWeight {
                        numerator: 1,
                        denominator: 1,
                    },
                },
            ),
        ]),
    }
}

#[test]
fn heterogeneous_ranks_sum_exactly_and_budget_is_never_compressed() {
    let round = spec();
    assert_eq!(round.validate(), Ok(5));
    let mut over = round.clone();
    over.rank_budget = 4;
    assert_eq!(
        over.validate(),
        Err(FloraValidationError::RankBudgetExceeded {
            global_rank: 5,
            budget: 4,
        })
    );
    const {
        assert!(FloraStacking::A_VERTICALLY_STACKED);
        assert!(FloraStacking::B_HORIZONTALLY_STACKED);
        assert!(FloraStacking::SCALE_B_ONLY);
    }
}

#[test]
fn compatibility_requires_every_receipt_and_the_exact_global_rank() {
    let round = spec();
    let contribution = |participant| FloraContributionReceipt {
        round: round.round,
        participant,
        a_factor: artifact(b"a"),
        b_factor: artifact(b"b"),
        receipt: artifact(b"receipt"),
    };
    let events = vec![
        FloraFact {
            operation: [1; 32],
            author: [9; 32],
            event: FloraEvent::RoundProposed {
                spec: round.clone(),
                at_ms: 1,
            },
        },
        FloraFact {
            operation: [2; 32],
            author: [2; 32],
            event: FloraEvent::ContributionReceived {
                contribution: contribution([2; 32]),
                at_ms: 2,
            },
        },
        FloraFact {
            operation: [3; 32],
            author: [3; 32],
            event: FloraEvent::ContributionReceived {
                contribution: contribution([3; 32]),
                at_ms: 3,
            },
        },
        FloraFact {
            operation: [4; 32],
            author: [9; 32],
            event: FloraEvent::CandidatePublished {
                candidate: FloraCandidateArtifact {
                    round: round.round,
                    adapter: artifact(b"adapter"),
                    global_rank: 4,
                    contributors: BTreeSet::from([[2; 32], [3; 32]]),
                },
                at_ms: 4,
            },
        },
        FloraFact {
            operation: [5; 32],
            author: [9; 32],
            event: FloraEvent::CandidatePublished {
                candidate: FloraCandidateArtifact {
                    round: round.round,
                    adapter: artifact(b"adapter"),
                    global_rank: 5,
                    contributors: BTreeSet::from([[2; 32], [3; 32]]),
                },
                at_ms: 5,
            },
        },
    ];
    let projection = FloraProjection::fold(events.clone());
    let backwards = FloraProjection::fold(events.into_iter().rev().collect());
    assert_eq!(projection, backwards);
    let projected = projection.rounds.get(&round.round).unwrap();
    assert_eq!(projected.global_rank, 5);
    assert_eq!(projected.viable_candidates.len(), 1);
}
