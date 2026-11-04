// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The standing projection — folds events into a per-chain-root score.
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

use crate::event::{BASIS_POINTS, ChainRoot, CommitmentId, StandingEvent};

/// Tunable weights and curves for the score. Per-moot configurable — the plan
/// keeps no global hardcoded reputation economy — these are the defaults.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StandingConfig {
    /// Reward for keeping a commitment (`CommitmentFulfilled`).
    pub fulfil_reward: i64,
    /// Penalty applied while a commitment is lapsed (silent past its cadence).
    pub lapse_penalty: i64,
    /// Reward for governance participation.
    pub governance_reward: i64,
    /// Fraction (basis points) of a chain root's *positive* standing a forked
    /// persona presents, applied once per generation from the root — the Sybil
    /// cost of a fresh face. See [`crate::persona_chain`].
    pub depreciation_bp: u16,
    /// Fraction (basis points) of a censure that loops back onto each persona who
    /// vouched for the censured one — the accountability cost of vouching. Phase 3.
    pub vouch_loopback_bp: u16,
}

impl Default for StandingConfig {
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

/// The folded standing ledger: open commitments plus non-lapse accruals.
///
/// Lapse penalties are *not* folded in; they are applied at score time because
/// they depend on the clock. Build one with [`Ledger::from_events`] (or
/// [`Ledger::apply`] incrementally), then read [`Ledger::scores`] for a moment.
#[derive(Clone, Debug)]
pub struct Ledger {
    config: StandingConfig,
    commitments: HashMap<CommitmentId, Commitment>,
    /// Fulfilment + governance + vouch accruals (everything except lapse).
    accruals: HashMap<ChainRoot, i64>,
    /// Vouch edges: a persona -> the personas who vouched for it (one hop), so a
    /// censure of the vouchee can loop back onto its vouchers (Phase 3).
    vouchers_of: HashMap<ChainRoot, Vec<ChainRoot>>,
}

impl Ledger {
    /// An empty ledger with the given weights.
    pub fn new(config: StandingConfig) -> Self {
        Self {
            config,
            commitments: HashMap::new(),
            accruals: HashMap::new(),
            vouchers_of: HashMap::new(),
        }
    }

    /// This ledger's weights (read by the persona-chain depreciation curve).
    pub fn config(&self) -> &StandingConfig {
        &self.config
    }

    /// Fold a whole event sequence (in causal / DAG order).
    pub fn from_events(config: StandingConfig, events: &[StandingEvent]) -> Self {
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
    pub fn apply(&mut self, event: &StandingEvent) {
        match event {
            StandingEvent::CommitmentMade {
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
            StandingEvent::Heartbeat {
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
            StandingEvent::CommitmentFulfilled { by, commitment, .. } => {
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
            StandingEvent::CleanHandoff {
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
            StandingEvent::Vouch {
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
            StandingEvent::GovernanceParticipation { by, .. } => {
                *self.accruals.entry(*by).or_default() += self.config.governance_reward;
            }
            StandingEvent::Pardon {
                by, target, weight, ..
            } => {
                // Community forgiveness. You cannot pardon yourself, so a
                // self-judgement is ignored (defence-in-depth behind the
                // ingestion-time governance check).
                if by != target {
                    *self.accruals.entry(*target).or_default() += *weight as i64;
                }
            }
            StandingEvent::Censure {
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
#[path = "ledger/tests.rs"]
mod tests;
