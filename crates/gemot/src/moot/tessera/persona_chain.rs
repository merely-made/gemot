// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Persona chains + fork depreciation — Phase 2.
//!
//! Tessera accrues at a chain *root* (the [`Ledger`] keys by [`ChainRoot`]). A
//! persona is a leaf that links to a parent; walking the links reaches the root.
//! A user's standing therefore follows them across persona forks (it lives at the
//! root), while a freshly forked persona *presents* only a depreciated fraction
//! of that standing — the Sybil cost of a clean face — and a brand-new unlinked
//! chain presents nothing.
//!
//! **Anti-laundering.** Only *positive* standing depreciates. A chain in debt (or
//! at zero) carries that debt fully to every fork, so forking cannot wash a bad
//! reputation. The only way out is a brand-new chain, which starts at zero and so
//! sits below any posting threshold anyway. This is the plan's "anonymity is the
//! cost of starting over" made concrete.
//!
//! Phase 2 models the chain abstractly (an opaque [`PersonaId`] forest), like
//! Phase 1's [`ChainRoot`]; wiring it to the identity vault's persona chain
//! (`master + persona_id`) is a thin adapter for the host layer.

use std::collections::{HashMap, HashSet};

use crate::moot::tessera::event::{BASIS_POINTS, ChainRoot};
use crate::moot::tessera::ledger::Ledger;

/// A persona's leaf identity (its public key). Derives in production from
/// `master + persona_id`; Phase 2 treats it as an opaque key, like Phase 1's
/// [`ChainRoot`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PersonaId(pub [u8; 32]);

/// The persona forest: each persona may link to a parent; a persona with no
/// parent is a chain root.
#[derive(Clone, Debug, Default)]
pub struct PersonaChains {
    /// child -> parent. Absent means the persona is a root.
    parent: HashMap<PersonaId, PersonaId>,
}

impl PersonaChains {
    /// An empty forest (every persona is its own root until linked).
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `child` is a fork of `parent` (same chain). Re-linking a child
    /// overwrites its parent (the latest fork link wins).
    pub fn fork(&mut self, child: PersonaId, parent: PersonaId) {
        self.parent.insert(child, parent);
    }

    /// Resolve a persona to its chain root and its depth (hops to the root; a
    /// root is depth 0). Cycle-safe: a malformed cyclic chain stops at the first
    /// repeat rather than looping forever.
    pub fn root_and_depth(&self, persona: PersonaId) -> (ChainRoot, u32) {
        let mut current = persona;
        let mut depth = 0u32;
        let mut visited = HashSet::new();
        visited.insert(current);
        while let Some(&parent) = self.parent.get(&current) {
            if !visited.insert(parent) {
                break; // cycle — treat `current` as the root
            }
            current = parent;
            depth += 1;
        }
        (ChainRoot(current.0), depth)
    }

    /// The chain root a persona accrues to.
    pub fn root_of(&self, persona: PersonaId) -> ChainRoot {
        self.root_and_depth(persona).0
    }

    /// A persona's **effective** tessera — what a moot or gate sees — as of
    /// `now_ms`: the chain root's score, with *positive* standing depreciated once
    /// per generation from the root (the `depreciation_bp` curve). Debt and zero
    /// pass through undepreciated, so forking cannot launder a bad reputation.
    pub fn effective_score(&self, persona: PersonaId, ledger: &Ledger, now_ms: u64) -> i64 {
        let (root, depth) = self.root_and_depth(persona);
        let base = ledger.score(&root, now_ms);
        if base <= 0 {
            return base; // no laundering: debt / zero carries fully to forks
        }
        let factor = ledger.config().depreciation_bp as i64;
        let mut score = base;
        for _ in 0..depth {
            score = score * factor / (BASIS_POINTS as i64);
        }
        score
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::moot::tessera::event::{CommitmentId, Scope, TesseraEvent};
    use crate::moot::tessera::ledger::TesseraConfig;

    fn persona(n: u8) -> PersonaId {
        PersonaId([n; 32])
    }

    /// A ledger where chain root `root` has accrued `fulfilments * fulfil_reward`
    /// (default reward 10) by keeping that many commitments.
    fn ledger_with_root_fulfilments(root: PersonaId, fulfilments: u8) -> Ledger {
        let root = ChainRoot(root.0);
        let mut events = Vec::new();
        for i in 0..fulfilments {
            let c = CommitmentId([100 + i; 32]);
            events.push(TesseraEvent::CommitmentMade {
                by: root,
                commitment: c,
                scope: Scope("s".into()),
                cadence_ms: 100,
                duration_ms: None,
                at_ms: 0,
            });
            events.push(TesseraEvent::CommitmentFulfilled {
                by: root,
                commitment: c,
                at_ms: 1,
            });
        }
        Ledger::from_events(TesseraConfig::default(), &events)
    }

    #[test]
    fn a_root_is_its_own_root_at_depth_zero() {
        let chains = PersonaChains::new();
        assert_eq!(chains.root_and_depth(persona(1)), (ChainRoot([1; 32]), 0));
    }

    #[test]
    fn forks_resolve_to_the_root_at_increasing_depth() {
        let mut chains = PersonaChains::new();
        let (r, p1, p2) = (persona(1), persona(2), persona(3));
        chains.fork(p1, r);
        chains.fork(p2, p1);
        assert_eq!(chains.root_and_depth(p1), (ChainRoot([1; 32]), 1));
        assert_eq!(chains.root_and_depth(p2), (ChainRoot([1; 32]), 2));
        assert_eq!(chains.root_of(p2), ChainRoot([1; 32]));
    }

    #[test]
    fn the_root_presents_full_standing() {
        let r = persona(1);
        let ledger = ledger_with_root_fulfilments(r, 10); // 10 * 10 = 100
        let chains = PersonaChains::new();
        assert_eq!(chains.effective_score(r, &ledger, 10), 100);
    }

    #[test]
    fn a_fork_inherits_the_depreciated_fraction() {
        // The done-condition: a forked persona inherits f * root tessera.
        let r = persona(1);
        let ledger = ledger_with_root_fulfilments(r, 10); // root = 100
        let mut chains = PersonaChains::new();
        let p1 = persona(2);
        chains.fork(p1, r);
        assert_eq!(chains.effective_score(p1, &ledger, 10), 50); // default 0.5 * 100
    }

    #[test]
    fn deeper_forks_depreciate_further() {
        let r = persona(1);
        let ledger = ledger_with_root_fulfilments(r, 10); // 100
        let mut chains = PersonaChains::new();
        let (p1, p2) = (persona(2), persona(3));
        chains.fork(p1, r);
        chains.fork(p2, p1);
        assert_eq!(chains.effective_score(p2, &ledger, 10), 25); // 0.5^2 * 100
    }

    #[test]
    fn a_fresh_chain_presents_zero() {
        // The Sybil floor: a brand-new chain (no accrual) presents nothing.
        let ledger = Ledger::new(TesseraConfig::default());
        let chains = PersonaChains::new();
        assert_eq!(chains.effective_score(persona(9), &ledger, 10), 0);
    }

    #[test]
    fn debt_carries_fully_to_forks_no_laundering() {
        // A chain in debt cannot fork to a less-penalized face.
        let r = persona(1);
        let ledger = Ledger::from_events(
            TesseraConfig::default(),
            &[TesseraEvent::CommitmentMade {
                by: ChainRoot([1; 32]),
                commitment: CommitmentId([7; 32]),
                scope: Scope("s".into()),
                cadence_ms: 100,
                duration_ms: None,
                at_ms: 0,
            }],
        );
        // The root lapsed the commitment: -lapse_penalty (default 20).
        assert_eq!(ledger.score(&ChainRoot([1; 32]), 1_000), -20);
        let mut chains = PersonaChains::new();
        chains.fork(persona(2), r);
        // The fork carries the FULL -20, not a depreciated -10.
        assert_eq!(chains.effective_score(persona(2), &ledger, 1_000), -20);
    }

    #[test]
    fn a_cyclic_chain_terminates() {
        let mut chains = PersonaChains::new();
        let (a, b) = (persona(1), persona(2));
        chains.fork(a, b);
        chains.fork(b, a); // cycle
        let (_root, depth) = chains.root_and_depth(a);
        assert!(depth <= 2, "cycle resolution stays finite");
    }
}
