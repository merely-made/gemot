// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Standing event grammar — the authoritative layer.
//!
//! Standing-affecting events are signed operations on the event-DAG (the same
//! wire as murm posts, addressed by space). This module is the *logical* event
//! form — the decoded shape the [ledger](super::ledger) folds — decoupled from
//! the operation wire, which a later phase bridges exactly as Murm's
//! `Post` ↔ `Operation`.
//!
//! **No negative is ever self-issued.** A lapse (silent disappearance past a
//! commitment's cadence) is *derived* by the ledger from missing heartbeats,
//! never self-reported. A [`Censure`](StandingEvent::Censure) and its forgiveness
//! [`Pardon`](StandingEvent::Pardon) are issued by a moot's *governance*, never by
//! the subject. So a persona can neither make themselves look bad nor clear their
//! own bad standing; both directions come from outside them. (Governance
//! authorisation is an ingestion concern, like signature validation; the fold
//! trusts the events it is handed, but defensively ignores a self-judgement where
//! `by == target`.)
//!
//! Fractions are basis points (`u16`, `0..=10_000`), not floats: the score is
//! computed by every peer independently, so the math must be deterministic
//! across platforms.

use serde::{Deserialize, Serialize};

/// A persona-chain **root** — the stable identity standing accrues against (not
/// the leaf persona). Phase 1 treats it as an opaque key; Phase 2 wires it to
/// the persona chain (`master + persona_id`, root-linked), so a user's standing
/// follows them across persona forks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ChainRoot(pub [u8; 32]);

/// Identifies a commitment across its whole lifecycle (made -> heartbeats ->
/// fulfilled / handed off, or lapsed). In the wire form this is the
/// `CommitmentMade` operation's id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CommitmentId(pub [u8; 32]);

/// The structural scope of a commitment — the cluster-path the pledge covers
/// (host this cluster, pin this path). Phase 1 carries it as metadata; the
/// structural cluster-path *capability* it pairs with is the §8.8 caps work
/// (the cap says *where*, standing says *whether, right now*).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Scope(pub String);

/// One basis point = 1/10_000. A `Vouch` fraction of `5_000` lends half.
pub const BASIS_POINTS: u32 = 10_000;

/// A signed standing event. Most are positive assertions a subject makes about
/// their own commitment or participation; the community-issued [`Pardon`](Self::Pardon)
/// and [`Censure`](Self::Censure) are the exception (a moot's governance restoring
/// or removing standing). The self-inflicted stick, lapse, is *derived* by the
/// [ledger](super::ledger), not emitted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StandingEvent {
    /// A pledge: host a service, pin a cluster, take a role. Opens a commitment
    /// the owner must keep alive with heartbeats and close cleanly.
    CommitmentMade {
        by: ChainRoot,
        commitment: CommitmentId,
        scope: Scope,
        /// Max gap between heartbeats before the commitment counts as lapsed.
        cadence_ms: u64,
        /// Intended lifetime. Advisory in Phase 1 — a commitment is closed by an
        /// explicit `CommitmentFulfilled` or `CleanHandoff`, not by elapsing.
        duration_ms: Option<u64>,
        at_ms: u64,
    },
    /// "Still hosting" — renews a live commitment. Only the current owner's
    /// heartbeats count.
    Heartbeat {
        by: ChainRoot,
        commitment: CommitmentId,
        at_ms: u64,
    },
    /// The commitment was kept — closes it and raises the owner's standing.
    CommitmentFulfilled {
        by: ChainRoot,
        commitment: CommitmentId,
        at_ms: u64,
    },
    /// Hand a live commitment to a willing successor with no penalty — walk away
    /// cleanly. The successor becomes the owner (and the one who lapses if they
    /// later ghost it).
    CleanHandoff {
        from: ChainRoot,
        to: ChainRoot,
        commitment: CommitmentId,
        at_ms: u64,
    },
    /// Delegate a fraction (basis points) of the voucher's standing to a
    /// newcomer as an entry boost. Phase 1 grants the boost; the abuse loop-back
    /// (the newcomer's misbehaviour costing the voucher) is Phase 3.
    Vouch {
        voucher: ChainRoot,
        newcomer: ChainRoot,
        /// Fraction of the voucher's current standing to lend, in basis points
        /// (`0..=10_000`).
        fraction_bp: u16,
        at_ms: u64,
    },
    /// Participation the moot rewards (voting and other governance).
    GovernanceParticipation { by: ChainRoot, at_ms: u64 },
    /// A moot's governance restores standing to `target` — community forgiveness.
    /// The counterpart to a lapse or censure: because you cannot pardon yourself,
    /// it is redemption, not laundering. Its cross-moot reach is the concord graph
    /// (a pardon in one moot only carries to moots that concord it).
    Pardon {
        /// The authorising governance identity (a moot's governance key).
        by: ChainRoot,
        /// The persona-chain root whose standing is restored.
        target: ChainRoot,
        /// Standing restored.
        weight: u64,
        at_ms: u64,
    },
    /// A moot's governance marks `target` down for in-house behaviour beyond
    /// ghosting a pledge (the negative a lapse can't express). Governance-issued,
    /// never self-issued; forgiven by a [`Pardon`](Self::Pardon).
    Censure {
        /// The authorising governance identity.
        by: ChainRoot,
        /// The persona-chain root being marked down.
        target: ChainRoot,
        /// Standing removed.
        weight: u64,
        at_ms: u64,
    },
}

impl StandingEvent {
    /// The event's author-asserted timestamp (ms).
    pub fn at_ms(&self) -> u64 {
        match self {
            StandingEvent::CommitmentMade { at_ms, .. }
            | StandingEvent::Heartbeat { at_ms, .. }
            | StandingEvent::CommitmentFulfilled { at_ms, .. }
            | StandingEvent::CleanHandoff { at_ms, .. }
            | StandingEvent::Vouch { at_ms, .. }
            | StandingEvent::GovernanceParticipation { at_ms, .. }
            | StandingEvent::Pardon { at_ms, .. }
            | StandingEvent::Censure { at_ms, .. } => *at_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn at_ms_reads_every_variant() {
        let root = ChainRoot([1; 32]);
        let cid = CommitmentId([2; 32]);
        let events = [
            StandingEvent::CommitmentMade {
                by: root,
                commitment: cid,
                scope: Scope("a/b".into()),
                cadence_ms: 100,
                duration_ms: None,
                at_ms: 1,
            },
            StandingEvent::Heartbeat {
                by: root,
                commitment: cid,
                at_ms: 2,
            },
            StandingEvent::CommitmentFulfilled {
                by: root,
                commitment: cid,
                at_ms: 3,
            },
            StandingEvent::CleanHandoff {
                from: root,
                to: ChainRoot([9; 32]),
                commitment: cid,
                at_ms: 4,
            },
            StandingEvent::Vouch {
                voucher: root,
                newcomer: ChainRoot([9; 32]),
                fraction_bp: 5_000,
                at_ms: 5,
            },
            StandingEvent::GovernanceParticipation { by: root, at_ms: 6 },
            StandingEvent::Pardon {
                by: ChainRoot([50; 32]),
                target: root,
                weight: 10,
                at_ms: 7,
            },
            StandingEvent::Censure {
                by: ChainRoot([50; 32]),
                target: root,
                weight: 10,
                at_ms: 8,
            },
        ];
        let stamps: Vec<u64> = events.iter().map(StandingEvent::at_ms).collect();
        assert_eq!(stamps, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    }
}
