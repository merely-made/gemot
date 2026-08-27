// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The tessera projection — folds events into a per-chain-root score.
//!
//! Standing is event-sourced: the signed events are authoritative, the score is
//! a projection (the same content-authoritative / experience-derived rule the
//! rest of the substrate follows). The fold is **deterministic** — integer math
//! only, no floats — so every peer computing it over the same events and the
//! same clock agrees.
//!
//! Lapse is derived here, not emitted: a commitment with no heartbeat for longer
//! than its cadence is lapsed *as of a given clock*, so [`Ledger::scores`] takes
//! `now_ms` and the stick falls out of the projection. A commitment can recover
//! (lapse-and-revive): heartbeating again advances its liveness, so it is no
//! longer lapsed as of a later clock.

use std::collections::HashMap;

use crate::moot::tessera::event::{BASIS_POINTS, ChainRoot, CommitmentId, TesseraEvent};

/// Tunable weights and curves for the score. Per-moot configurable — the plan
/// keeps no global hardcoded reputation economy — these are the defaults.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TesseraConfig {
    /// Reward for keeping a commitment (`CommitmentFulfilled`).
    pub fulfil_reward: i64,
    /// Penalty applied while a commitment is lapsed (silent past its cadence).
    pub lapse_penalty: i64,
    /// Reward for governance participation.
    pub governance_reward: i64,
    /// Fraction (basis points) of a chain root's *positive* standing a forked
    /// persona presents, applied once per generation from the root — the Sybil
    /// cost of a fresh face. See [`crate::moot::tessera::persona_chain`].
    pub depreciation_bp: u16,
    /// Fraction (basis points) of a censure that loops back onto each persona who
    /// vouched for the censured one — the accountability cost of vouching. Phase 3.
    pub vouch_loopback_bp: u16,
}

impl Default for TesseraConfig {
    fn default() -> Self {
        Self {
            fulfil_reward: 10,
            // The stick bites harder than the honey rewards: ghosting a
            // commitment costs more than fulfilling one earns.
            lapse_penalty: 20,
            governance_reward: 1,
            // A fork presents half the root's positive standing per generation.
            depreciation_bp: 5_000,
            // A voucher feels half of what their vouchee is censured.
            vouch_loopback_bp: 5_000,
        }
    }
}

/// A commitment's live state as the ledger folds events.
#[derive(Clone, Debug)]
struct Commitment {
    /// Current owner — reassigned on `CleanHandoff`; whoever holds it lapses.
    owner: ChainRoot,
    cadence_ms: u64,
    /// Last time the current owner proved liveness (made / heartbeat / handoff).
    last_alive_ms: u64,
    /// Closed cleanly (fulfilled or handed off away) — no longer lapse-eligible.
    closed: bool,
}

impl Commitment {
    /// Lapsed as of `now_ms`: still open, and the owner has been silent for
    /// longer than the cadence. Recoverable — a later heartbeat advances liveness
    /// and clears it (lapse-and-revive).
    fn is_lapsed(&self, now_ms: u64) -> bool {
        !self.closed && now_ms.saturating_sub(self.last_alive_ms) > self.cadence_ms
    }
}

/// The folded tessera ledger: open commitments plus non-lapse accruals.
///
/// Lapse penalties are *not* folded in; they are applied at score time because
/// they depend on the clock. Build one with [`Ledger::from_events`] (or
/// [`Ledger::apply`] incrementally), then read [`Ledger::scores`] for a moment.
#[derive(Clone, Debug)]
pub struct Ledger {
    config: TesseraConfig,
    commitments: HashMap<CommitmentId, Commitment>,
    /// Fulfilment + governance + vouch accruals (everything except lapse).
    accruals: HashMap<ChainRoot, i64>,
    /// Vouch edges: a persona -> the personas who vouched for it (one hop), so a
    /// censure of the vouchee can loop back onto its vouchers (Phase 3).
    vouchers_of: HashMap<ChainRoot, Vec<ChainRoot>>,
}

impl Ledger {
    /// An empty ledger with the given weights.
    pub fn new(config: TesseraConfig) -> Self {
        Self {
            config,
            commitments: HashMap::new(),
            accruals: HashMap::new(),
            vouchers_of: HashMap::new(),
        }
    }

    /// This ledger's weights (read by the persona-chain depreciation curve).
    pub fn config(&self) -> &TesseraConfig {
        &self.config
    }

    /// Fold a whole event sequence (in causal / DAG order).
    pub fn from_events(config: TesseraConfig, events: &[TesseraEvent]) -> Self {
        let mut ledger = Self::new(config);
        for event in events {
            ledger.apply(event);
        }
        ledger
    }

    /// The commitment iff it is still open and currently owned by `who` — the
    /// precondition every owner-driven transition (heartbeat / fulfil / handoff)
    /// shares.
    fn open_owned_by(
        &mut self,
        commitment: &CommitmentId,
        who: &ChainRoot,
    ) -> Option<&mut Commitment> {
        self.commitments
            .get_mut(commitment)
            .filter(|c| !c.closed && c.owner == *who)
    }

    /// Fold one event into the ledger.
    pub fn apply(&mut self, event: &TesseraEvent) {
        match event {
            TesseraEvent::CommitmentMade {
                by,
                commitment,
                cadence_ms,
                at_ms,
                ..
            } => {
                // First write wins (the commitment id is its making); a replayed
                // CommitmentMade is idempotent.
                self.commitments.entry(*commitment).or_insert(Commitment {
                    owner: *by,
                    cadence_ms: *cadence_ms,
                    last_alive_ms: *at_ms,
                    closed: false,
                });
            }
            TesseraEvent::Heartbeat {
                by,
                commitment,
                at_ms,
            } => {
                if let Some(c) = self.open_owned_by(commitment, by) {
                    // Only liveness moving forward counts.
                    if *at_ms > c.last_alive_ms {
                        c.last_alive_ms = *at_ms;
                    }
                }
            }
            TesseraEvent::CommitmentFulfilled { by, commitment, .. } => {
                // Scope the &mut borrow (closing the commitment) before the
                // accrual, which is a fresh borrow of `self`.
                let fulfilled = match self.open_owned_by(commitment, by) {
                    Some(c) => {
                        c.closed = true;
                        true
                    }
                    None => false,
                };
                if fulfilled {
                    *self.accruals.entry(*by).or_default() += self.config.fulfil_reward;
                }
            }
            TesseraEvent::CleanHandoff {
                from,
                to,
                commitment,
                at_ms,
            } => {
                if let Some(c) = self.open_owned_by(commitment, from) {
                    // Successor takes ownership and a fresh liveness clock; the
                    // original walks away with no penalty.
                    c.owner = *to;
                    c.last_alive_ms = *at_ms;
                }
            }
            TesseraEvent::Vouch {
                voucher,
                newcomer,
                fraction_bp,
                ..
            } => {
                // Record the vouch edge (deduped) so a later censure of the
                // newcomer can loop back onto the voucher (Phase 3).
                let vouchers = self.vouchers_of.entry(*newcomer).or_default();
                if !vouchers.contains(voucher) {
                    vouchers.push(*voucher);
                }
                // Lend a fraction of the voucher's *current positive* accrual as
                // an entry boost (the voucher's own score is not spent).
                let lent = self.accruals.get(voucher).copied().unwrap_or(0).max(0)
                    * (*fraction_bp as i64)
                    / (BASIS_POINTS as i64);
                if lent != 0 {
                    *self.accruals.entry(*newcomer).or_default() += lent;
                }
            }
            TesseraEvent::GovernanceParticipation { by, .. } => {
                *self.accruals.entry(*by).or_default() += self.config.governance_reward;
            }
            TesseraEvent::Pardon {
                by, target, weight, ..
            } => {
                // Community forgiveness. You cannot pardon yourself, so a
                // self-judgement is ignored (defence-in-depth behind the
                // ingestion-time governance check).
                if by != target {
                    *self.accruals.entry(*target).or_default() += *weight as i64;
                }
            }
            TesseraEvent::Censure {
                by, target, weight, ..
            } => {
                if by != target {
                    *self.accruals.entry(*target).or_default() -= *weight as i64;
                    // Loop a fraction of the censure back onto everyone who
                    // vouched for the censured persona — vouching for a bad actor
                    // costs you (one hop: direct vouchers only).
                    let loopback = *weight as i64 * (self.config.vouch_loopback_bp as i64)
                        / (BASIS_POINTS as i64);
                    if loopback != 0 {
                        let vouchers = self.vouchers_of.get(target).cloned().unwrap_or_default();
                        for voucher in vouchers {
                            *self.accruals.entry(voucher).or_default() -= loopback;
                        }
                    }
                }
            }
        }
    }

    /// Commitments lapsed as of `now_ms`: open, and the owner has been silent for
    /// longer than the commitment's cadence.
    pub fn lapsed(&self, now_ms: u64) -> Vec<(CommitmentId, ChainRoot)> {
        self.commitments
            .iter()
            .filter(|(_, c)| c.is_lapsed(now_ms))
            .map(|(id, c)| (*id, c.owner))
            .collect()
    }

    /// Per-chain-root scores as of `now_ms`: accruals minus a lapse penalty for
    /// each commitment that has gone silent by now. Roots with a zero result are
    /// omitted unless an event ever touched them.
    pub fn scores(&self, now_ms: u64) -> HashMap<ChainRoot, i64> {
        let mut scores = self.accruals.clone();
        for (_, owner) in self.lapsed(now_ms) {
            *scores.entry(owner).or_default() -= self.config.lapse_penalty;
        }
        scores
    }

    /// One chain root's score as of `now_ms` (`0` if untouched). Computed
    /// directly — accruals minus a lapse penalty per silent commitment it owns —
    /// without materializing the whole score map.
    pub fn score(&self, chain_root: &ChainRoot, now_ms: u64) -> i64 {
        let accrued = self.accruals.get(chain_root).copied().unwrap_or(0);
        let lapses = self
            .commitments
            .values()
            .filter(|c| c.owner == *chain_root && c.is_lapsed(now_ms))
            .count() as i64;
        accrued - lapses * self.config.lapse_penalty
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::moot::tessera::event::Scope;

    fn root(n: u8) -> ChainRoot {
        ChainRoot([n; 32])
    }
    fn cid(n: u8) -> CommitmentId {
        CommitmentId([n; 32])
    }
    fn made(by: ChainRoot, commitment: CommitmentId, cadence_ms: u64, at_ms: u64) -> TesseraEvent {
        TesseraEvent::CommitmentMade {
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
            TesseraConfig::default(),
            &[
                made(a, c, 100, 0),
                TesseraEvent::CommitmentFulfilled {
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
        let ledger = Ledger::from_events(TesseraConfig::default(), &[made(a, c, 100, 0)]);
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
        let mut ledger = Ledger::new(TesseraConfig::default());
        ledger.apply(&made(a, c, 100, 0));
        ledger.apply(&TesseraEvent::Heartbeat {
            by: a,
            commitment: c,
            at_ms: 80,
        });
        ledger.apply(&TesseraEvent::Heartbeat {
            by: a,
            commitment: c,
            at_ms: 160,
        });
        // Alive shortly after the last heartbeat.
        assert_eq!(ledger.score(&a, 200), 0);
        // Goes silent: lapsed well past the last heartbeat + cadence.
        assert_eq!(ledger.score(&a, 400), -20);
        // Revive: a fresh heartbeat un-lapses it as of a later-but-close clock.
        ledger.apply(&TesseraEvent::Heartbeat {
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
            TesseraConfig::default(),
            &[
                made(a, c, 100, 0),
                TesseraEvent::CleanHandoff {
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
            TesseraConfig::default(),
            &[
                made(a, c, 100, 0),
                TesseraEvent::CleanHandoff {
                    from: a,
                    to: b,
                    commitment: c,
                    at_ms: 50,
                },
                TesseraEvent::CommitmentFulfilled {
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
            TesseraConfig::default(),
            &[
                made(a, c, 100, 0),
                // A stranger's heartbeat + fulfilment must not count.
                TesseraEvent::Heartbeat {
                    by: stranger,
                    commitment: c,
                    at_ms: 90,
                },
                TesseraEvent::CommitmentFulfilled {
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
            TesseraConfig::default(),
            &[
                TesseraEvent::GovernanceParticipation { by: a, at_ms: 1 },
                TesseraEvent::GovernanceParticipation { by: a, at_ms: 2 },
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
            TesseraConfig::default(),
            &[
                // A earns 10 by fulfilling, then vouches half of it to newcomer B.
                made(a, c, 100, 0),
                TesseraEvent::CommitmentFulfilled {
                    by: a,
                    commitment: c,
                    at_ms: 10,
                },
                TesseraEvent::Vouch {
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
            TesseraConfig::default(),
            &[
                // A keeps one commitment, ghosts another; B participates in governance.
                made(a, c1, 100, 0),
                TesseraEvent::CommitmentFulfilled {
                    by: a,
                    commitment: c1,
                    at_ms: 40,
                },
                made(a, c2, 100, 0), // never heartbeated -> will lapse
                TesseraEvent::GovernanceParticipation { by: b, at_ms: 5 },
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
            TesseraConfig::default(),
            &[TesseraEvent::Censure {
                by: gov,
                target: a,
                weight: 30,
                at_ms: 1,
            }],
        );
        assert_eq!(censured.score(&a, 10), -30);

        // A later pardon of the same weight restores the standing.
        let pardoned = Ledger::from_events(
            TesseraConfig::default(),
            &[
                TesseraEvent::Censure {
                    by: gov,
                    target: a,
                    weight: 30,
                    at_ms: 1,
                },
                TesseraEvent::Pardon {
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
            TesseraConfig::default(),
            &[
                made(a, cid(1), 100, 0), // ghosted -> lapses (-20)
                TesseraEvent::Pardon {
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
            TesseraConfig::default(),
            &[
                TesseraEvent::Pardon {
                    by: a,
                    target: a,
                    weight: 100,
                    at_ms: 1,
                },
                TesseraEvent::Censure {
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
            TesseraConfig::default(),
            &[
                // A earns standing, vouches for B, then B is censured.
                made(a, cid(1), 100, 0),
                TesseraEvent::CommitmentFulfilled {
                    by: a,
                    commitment: cid(1),
                    at_ms: 10,
                },
                TesseraEvent::Vouch {
                    voucher: a,
                    newcomer: b,
                    fraction_bp: 5_000,
                    at_ms: 20,
                },
                TesseraEvent::Censure {
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
            TesseraConfig::default(),
            &[TesseraEvent::Censure {
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
}
