// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;
use crate::event::Scope;

fn root(n: u8) -> ChainRoot {
    ChainRoot([n; 32])
}
fn cid(n: u8) -> CommitmentId {
    CommitmentId([n; 32])
}
fn made(by: ChainRoot, commitment: CommitmentId, cadence_ms: u64, at_ms: u64) -> StandingEvent {
    StandingEvent::CommitmentMade {
        by,
        commitment,
        scope: Scope("session".into()),
        cadence_ms,
        duration_ms: None,
        at_ms,
    }
}

#[test]
fn fulfilment_raises_score() {
    let a = root(1);
    let c = cid(1);
    let ledger = Ledger::from_events(
        StandingConfig::default(),
        &[
            made(a, c, 100, 0),
            StandingEvent::CommitmentFulfilled {
                by: a,
                commitment: c,
                at_ms: 50,
            },
        ],
    );
    // Fulfilled before lapse: +reward, and no lapse penalty ever after.
    assert_eq!(ledger.score(&a, 10_000), 10);
    assert!(
        ledger.lapsed(10_000).is_empty(),
        "a fulfilled commitment can't lapse"
    );
}

#[test]
fn silent_commitment_lapses_after_cadence() {
    let a = root(1);
    let c = cid(1);
    let ledger = Ledger::from_events(StandingConfig::default(), &[made(a, c, 100, 0)]);
    // Within cadence: not yet lapsed.
    assert_eq!(ledger.score(&a, 100), 0);
    // Past cadence with no heartbeat: the stick.
    assert_eq!(ledger.score(&a, 101), -20);
    assert_eq!(ledger.lapsed(101), vec![(c, a)]);
}

#[test]
fn heartbeats_keep_it_alive_then_lapse_and_revive() {
    let a = root(1);
    let c = cid(1);
    let mut ledger = Ledger::new(StandingConfig::default());
    ledger.apply(&made(a, c, 100, 0));
    ledger.apply(&StandingEvent::Heartbeat {
        by: a,
        commitment: c,
        at_ms: 80,
    });
    ledger.apply(&StandingEvent::Heartbeat {
        by: a,
        commitment: c,
        at_ms: 160,
    });
    // Alive shortly after the last heartbeat.
    assert_eq!(ledger.score(&a, 200), 0);
    // Goes silent: lapsed well past the last heartbeat + cadence.
    assert_eq!(ledger.score(&a, 400), -20);
    // Revive: a fresh heartbeat un-lapses it as of a later-but-close clock.
    ledger.apply(&StandingEvent::Heartbeat {
        by: a,
        commitment: c,
        at_ms: 410,
    });
    assert_eq!(
        ledger.score(&a, 450),
        0,
        "lapse-and-revive: resuming clears the lapse"
    );
}

#[test]
fn clean_handoff_moves_the_liability_not_a_penalty() {
    let a = root(1);
    let b = root(2);
    let c = cid(1);
    // A pledges, hands off to B cleanly, then B ghosts it.
    let ledger = Ledger::from_events(
        StandingConfig::default(),
        &[
            made(a, c, 100, 0),
            StandingEvent::CleanHandoff {
                from: a,
                to: b,
                commitment: c,
                at_ms: 50,
            },
        ],
    );
    // After the handoff window, the lapse falls on B (current owner), not A.
    assert_eq!(ledger.score(&a, 1_000), 0, "A walked away clean");
    assert_eq!(ledger.score(&b, 1_000), -20, "B owns the commitment now");
    assert_eq!(ledger.lapsed(1_000), vec![(c, b)]);
}

#[test]
fn fulfilment_after_handoff_rewards_the_successor() {
    let a = root(1);
    let b = root(2);
    let c = cid(1);
    let ledger = Ledger::from_events(
        StandingConfig::default(),
        &[
            made(a, c, 100, 0),
            StandingEvent::CleanHandoff {
                from: a,
                to: b,
                commitment: c,
                at_ms: 50,
            },
            StandingEvent::CommitmentFulfilled {
                by: b,
                commitment: c,
                at_ms: 80,
            },
        ],
    );
    assert_eq!(ledger.score(&a, 10_000), 0);
    assert_eq!(
        ledger.score(&b, 10_000),
        10,
        "the successor who finished it earns the reward"
    );
}

#[test]
fn only_the_owner_can_heartbeat_or_fulfil() {
    let a = root(1);
    let stranger = root(9);
    let c = cid(1);
    let ledger = Ledger::from_events(
        StandingConfig::default(),
        &[
            made(a, c, 100, 0),
            // A stranger's heartbeat + fulfilment must not count.
            StandingEvent::Heartbeat {
                by: stranger,
                commitment: c,
                at_ms: 90,
            },
            StandingEvent::CommitmentFulfilled {
                by: stranger,
                commitment: c,
                at_ms: 95,
            },
        ],
    );
    // Still lapses (the stranger's heartbeat didn't keep it alive), and the
    // stranger earned nothing.
    assert_eq!(ledger.score(&a, 1_000), -20);
    assert_eq!(ledger.score(&stranger, 1_000), 0);
}

#[test]
fn governance_participation_rewards() {
    let a = root(1);
    let ledger = Ledger::from_events(
        StandingConfig::default(),
        &[
            StandingEvent::GovernanceParticipation { by: a, at_ms: 1 },
            StandingEvent::GovernanceParticipation { by: a, at_ms: 2 },
        ],
    );
    assert_eq!(ledger.score(&a, 10), 2);
}

#[test]
fn vouch_lends_a_fraction_of_the_vouchers_standing() {
    let a = root(1);
    let b = root(2);
    let c = cid(1);
    let ledger = Ledger::from_events(
        StandingConfig::default(),
        &[
            // A earns 10 by fulfilling, then vouches half of it to newcomer B.
            made(a, c, 100, 0),
            StandingEvent::CommitmentFulfilled {
                by: a,
                commitment: c,
                at_ms: 10,
            },
            StandingEvent::Vouch {
                voucher: a,
                newcomer: b,
                fraction_bp: 5_000,
                at_ms: 20,
            },
        ],
    );
    assert_eq!(
        ledger.score(&a, 1_000),
        10,
        "vouching lends, it does not spend the voucher's own score"
    );
    assert_eq!(
        ledger.score(&b, 1_000),
        5,
        "the newcomer gets half of A's standing as a boost"
    );
}

#[test]
fn a_mixed_sequence_yields_the_expected_scores() {
    let a = root(1);
    let b = root(2);
    let (c1, c2) = (cid(1), cid(2));
    let ledger = Ledger::from_events(
        StandingConfig::default(),
        &[
            // A keeps one commitment, ghosts another; B participates in governance.
            made(a, c1, 100, 0),
            StandingEvent::CommitmentFulfilled {
                by: a,
                commitment: c1,
                at_ms: 40,
            },
            made(a, c2, 100, 0), // never heartbeated -> will lapse
            StandingEvent::GovernanceParticipation { by: b, at_ms: 5 },
        ],
    );
    // A: +10 fulfilled, -20 lapsed = -10. B: +1 governance.
    assert_eq!(ledger.score(&a, 1_000), -10);
    assert_eq!(ledger.score(&b, 1_000), 1);
}

#[test]
fn censure_lowers_and_pardon_restores() {
    let a = root(1);
    let gov = root(50); // a moot's governance identity
    let censured = Ledger::from_events(
        StandingConfig::default(),
        &[StandingEvent::Censure {
            by: gov,
            target: a,
            weight: 30,
            at_ms: 1,
        }],
    );
    assert_eq!(censured.score(&a, 10), -30);

    // A later pardon of the same weight restores the standing.
    let pardoned = Ledger::from_events(
        StandingConfig::default(),
        &[
            StandingEvent::Censure {
                by: gov,
                target: a,
                weight: 30,
                at_ms: 1,
            },
            StandingEvent::Pardon {
                by: gov,
                target: a,
                weight: 30,
                at_ms: 2,
            },
        ],
    );
    assert_eq!(pardoned.score(&a, 10), 0);
}

#[test]
fn a_pardon_can_forgive_a_lapse() {
    let a = root(1);
    let gov = root(50);
    let ledger = Ledger::from_events(
        StandingConfig::default(),
        &[
            made(a, cid(1), 100, 0), // ghosted -> lapses (-20)
            StandingEvent::Pardon {
                by: gov,
                target: a,
                weight: 20,
                at_ms: 1,
            },
        ],
    );
    // The -20 lapse is offset by +20 of community forgiveness.
    assert_eq!(ledger.score(&a, 1_000), 0);
}

#[test]
fn you_cannot_judge_yourself() {
    let a = root(1);
    // A self-pardon and a self-censure are both ignored (by == target).
    let ledger = Ledger::from_events(
        StandingConfig::default(),
        &[
            StandingEvent::Pardon {
                by: a,
                target: a,
                weight: 100,
                at_ms: 1,
            },
            StandingEvent::Censure {
                by: a,
                target: a,
                weight: 100,
                at_ms: 2,
            },
        ],
    );
    assert_eq!(ledger.score(&a, 10), 0);
}

#[test]
fn censure_of_a_vouchee_loops_back_to_the_voucher() {
    let a = root(1); // voucher
    let b = root(2); // newcomer
    let gov = root(50);
    let ledger = Ledger::from_events(
        StandingConfig::default(),
        &[
            // A earns standing, vouches for B, then B is censured.
            made(a, cid(1), 100, 0),
            StandingEvent::CommitmentFulfilled {
                by: a,
                commitment: cid(1),
                at_ms: 10,
            },
            StandingEvent::Vouch {
                voucher: a,
                newcomer: b,
                fraction_bp: 5_000,
                at_ms: 20,
            },
            StandingEvent::Censure {
                by: gov,
                target: b,
                weight: 30,
                at_ms: 30,
            },
        ],
    );
    // B: +5 vouch boost (half of A's 10) - 30 censure = -25.
    assert_eq!(ledger.score(&b, 1_000), -25);
    // A: +10 fulfilled - 15 loop-back (half of B's 30 censure) = -5.
    assert_eq!(ledger.score(&a, 1_000), -5);
}

#[test]
fn an_unvouched_censure_does_not_loop_back() {
    let b = root(2);
    let gov = root(50);
    let ledger = Ledger::from_events(
        StandingConfig::default(),
        &[StandingEvent::Censure {
            by: gov,
            target: b,
            weight: 30,
            at_ms: 1,
        }],
    );
    assert_eq!(ledger.score(&b, 10), -30);
    assert_eq!(
        ledger.score(&root(1), 10),
        0,
        "no voucher exists, nobody else is touched"
    );
}
