//! Moot concords + composite reputation — Phase 5 (federation, t3).
//!
//! Reputation is per-moot primary: a persona's standing lives in each moot's own
//! [`Ledger`] (Phase 1 accrual + the Phase 2 depreciation). There is no single
//! global score. A *concord* is a one-directional agreement in which a viewer
//! moot honours another moot's reputations at a weight; a viewer's **composite**
//! reputation for a persona folds its own standing together with its concorded
//! moots' standings, under a composition policy the viewer chooses.
//!
//! Two invariants keep it safe:
//!
//! - **One hop, no transitive trust.** A moot honours its direct concords, never
//!   its concords' concords — otherwise reputation launders down a chain of
//!   agreements (the classic web-of-trust failure). So a junk moot's inflation
//!   reaches only the moots that *directly* chose to concord it, and a moot that
//!   concords junk pollutes its own view, which makes the guard self-policing.
//! - **The composition rule is the moot operator's choice**, not a project
//!   default ([`CompositionPolicy`]). Mere ships the set; the community picks how
//!   trusting or cautious it is.
//!
//! Schema note: composing standings across moots assumes they share (or have
//! normalised) their `TesseraConfig` — a score computed under different weights
//! is not comparable, so a real rep concord carries a schema concord. Phase 5
//! composes the numbers and leaves that gating to the federation layer.

use std::collections::HashMap;

pub use gemot::moot::MootId;
use gemot::moot::tessera::event::BASIS_POINTS;
use gemot::moot::tessera::ledger::Ledger;
use gemot::moot::tessera::persona_chain::{PersonaChains, PersonaId};
use serde::{Deserialize, Serialize};

/// How a viewer moot folds concorded moots' reputations into its own view.
///
/// The choice belongs to the people running the moot — how trusting or cautious
/// the community is — not to a project default. The set is extensible.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompositionPolicy {
    /// Local only; concords are ignored. "I judge behaviour in my house."
    Insular,
    /// Local plus each concorded moot's standing scaled by the concord weight.
    /// "I trust my allies' read in proportion to the concord."
    WeightedSum,
    /// Like [`WeightedSum`](Self::WeightedSum), but a concorded moot's *negative*
    /// read counts at full weight while a positive read is discounted by the
    /// concord. "A red flag is a red flag; praise from elsewhere I discount."
    /// The anti-laundering posture.
    CautiousImport,
}

/// A viewer moot's reputation lens: its own id, its composition policy, and the
/// moots it concords (each at a weight in basis points). One hop — only these
/// direct concords contribute to a composite score.
#[derive(Clone, Debug)]
pub struct RepLens {
    moot: MootId,
    composition: CompositionPolicy,
    concords: HashMap<MootId, u16>,
}

impl RepLens {
    /// A lens for `moot` under `composition`, with no concords yet.
    pub fn new(moot: MootId, composition: CompositionPolicy) -> Self {
        Self {
            moot,
            composition,
            concords: HashMap::new(),
        }
    }

    /// Honour `other`'s reputations at `weight_bp` basis points. Builder-style;
    /// re-concording the same moot overwrites the weight.
    pub fn concord(&mut self, other: MootId, weight_bp: u16) -> &mut Self {
        self.concords.insert(other, weight_bp);
        self
    }

    /// The weight this lens gives a moot (`0` if not concorded).
    pub fn weight(&self, other: &MootId) -> u16 {
        self.concords.get(other).copied().unwrap_or(0)
    }

    /// `persona`'s composite reputation through this lens as of `now_ms`: the
    /// viewer's own effective score plus its concorded moots' effective scores,
    /// combined under the lens's composition policy.
    ///
    /// `ledgers` maps each moot to its tessera ledger; `chains` is the global
    /// persona forest (Phase 2), so each moot's contribution is the persona's
    /// *depreciated* standing there. A moot absent from `ledgers` contributes 0.
    pub fn composite_score(
        &self,
        persona: PersonaId,
        ledgers: &HashMap<MootId, Ledger>,
        chains: &PersonaChains,
        now_ms: u64,
    ) -> i64 {
        let effective = |moot: &MootId| -> i64 {
            ledgers
                .get(moot)
                .map(|l| chains.effective_score(persona, l, now_ms))
                .unwrap_or(0)
        };
        let local = effective(&self.moot);
        if self.composition == CompositionPolicy::Insular {
            return local;
        }
        // Schema gate: drop a concord whose moot scores under a *different* config
        // — standings measured on different scales cannot be added (a schema
        // concord is config agreement). When the viewer's own config is unknown
        // here we do not gate; in production a moot always carries one.
        let viewer_config = ledgers.get(&self.moot).map(|l| l.config());
        let mut total = local;
        for (other, &weight_bp) in &self.concords {
            let schema_mismatch = matches!(
                (viewer_config, ledgers.get(other).map(|l| l.config())),
                (Some(a), Some(b)) if a != b
            );
            if schema_mismatch {
                continue;
            }
            let remote = effective(other);
            let weighted = remote * weight_bp as i64 / (BASIS_POINTS as i64);
            total += match self.composition {
                CompositionPolicy::Insular => 0, // handled above
                CompositionPolicy::WeightedSum => weighted,
                // A red flag counts at full weight; praise is discounted.
                CompositionPolicy::CautiousImport if remote < 0 => remote,
                CompositionPolicy::CautiousImport => weighted,
            };
        }
        total
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gemot::moot::tessera::event::{ChainRoot, CommitmentId, Scope, TesseraEvent};
    use gemot::moot::tessera::ledger::TesseraConfig;

    fn moot(n: u8) -> MootId {
        MootId([n; 32])
    }
    fn persona(n: u8) -> PersonaId {
        PersonaId([n; 32])
    }

    /// A ledger where chain root `root` has score `+10 * fulfilments` from kept
    /// commitments (default reward 10).
    fn ledger_scoring(root: PersonaId, fulfilments: u8) -> Ledger {
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

    /// A ledger where `root` ghosted one commitment (score -20).
    fn ledger_in_debt(root: PersonaId) -> Ledger {
        Ledger::from_events(
            TesseraConfig::default(),
            &[TesseraEvent::CommitmentMade {
                by: ChainRoot(root.0),
                commitment: CommitmentId([7; 32]),
                scope: Scope("s".into()),
                cadence_ms: 100,
                duration_ms: None,
                at_ms: 0,
            }],
        )
    }

    #[test]
    fn insular_ignores_concords() {
        let (v, x, p) = (moot(1), moot(2), persona(3));
        let ledgers = HashMap::from([(v, ledger_scoring(p, 10)), (x, ledger_scoring(p, 10))]);
        let chains = PersonaChains::new();
        let mut lens = RepLens::new(v, CompositionPolicy::Insular);
        lens.concord(x, 10_000);
        assert_eq!(lens.composite_score(p, &ledgers, &chains, 10), 100); // local only
    }

    #[test]
    fn weighted_sum_imports_at_the_concord_weight() {
        let (v, x, p) = (moot(1), moot(2), persona(3));
        // P is unknown in V (0) but well-regarded in X (100).
        let ledgers = HashMap::from([(x, ledger_scoring(p, 10))]);
        let chains = PersonaChains::new();
        let mut lens = RepLens::new(v, CompositionPolicy::WeightedSum);
        lens.concord(x, 5_000); // honour X at 50%
        assert_eq!(lens.composite_score(p, &ledgers, &chains, 10), 50);
    }

    #[test]
    fn local_dominates_under_a_weak_concord() {
        let (v, x, p) = (moot(1), moot(2), persona(3));
        let ledgers = HashMap::from([(v, ledger_scoring(p, 10)), (x, ledger_scoring(p, 10))]);
        let chains = PersonaChains::new();
        let mut lens = RepLens::new(v, CompositionPolicy::WeightedSum);
        lens.concord(x, 1_000); // 10%
        assert_eq!(lens.composite_score(p, &ledgers, &chains, 10), 110); // 100 local + 10
    }

    #[test]
    fn unconcorded_moots_do_not_count() {
        let (v, z, p) = (moot(1), moot(9), persona(3));
        // P has standing in Z, but V does not concord Z.
        let ledgers = HashMap::from([(z, ledger_scoring(p, 10))]);
        let chains = PersonaChains::new();
        let lens = RepLens::new(v, CompositionPolicy::WeightedSum);
        assert_eq!(lens.composite_score(p, &ledgers, &chains, 10), 0);
    }

    #[test]
    fn composition_is_one_hop_only() {
        // V concords X; P is regarded only in Z. Even if X concorded Z, V does not
        // reach Z — composite_score never traverses another moot's concords.
        let (v, x, z, p) = (moot(1), moot(2), moot(9), persona(3));
        let ledgers = HashMap::from([(z, ledger_scoring(p, 10))]); // P known only in Z
        let chains = PersonaChains::new();
        let mut lens = RepLens::new(v, CompositionPolicy::WeightedSum);
        lens.concord(x, 10_000); // V honours X fully, but P has nothing in X
        assert_eq!(lens.composite_score(p, &ledgers, &chains, 10), 0);
    }

    #[test]
    fn cautious_import_heeds_warnings_fully_discounts_praise() {
        let (v, x, p) = (moot(1), moot(2), persona(3));
        let chains = PersonaChains::new();
        let mut lens = RepLens::new(v, CompositionPolicy::CautiousImport);
        lens.concord(x, 5_000); // 50%

        // Praise from X is discounted: +100 -> +50.
        let praised = HashMap::from([(x, ledger_scoring(p, 10))]);
        assert_eq!(lens.composite_score(p, &praised, &chains, 10), 50);

        // A warning from X counts at full weight: -20 -> -20.
        let flagged = HashMap::from([(x, ledger_in_debt(p))]);
        assert_eq!(lens.composite_score(p, &flagged, &chains, 1_000), -20);
    }

    #[test]
    fn a_concorded_moots_contribution_is_the_depreciated_effective() {
        // P1 is a fork of root R; in moot X, R earned 100, so P1 *presents* 50
        // there (Phase 2). A concord imports that depreciated 50, not the raw 100.
        let (v, x) = (moot(1), moot(2));
        let r = persona(3);
        let p1 = persona(4);
        let ledgers = HashMap::from([(x, ledger_scoring(r, 10))]); // R = 100 in X
        let mut chains = PersonaChains::new();
        chains.fork(p1, r); // P1 forks R, depth 1, default f = 0.5
        let mut lens = RepLens::new(v, CompositionPolicy::WeightedSum);
        lens.concord(x, 10_000); // honour X fully
        // P1's effective in X is 50; imported at 100% -> 50.
        assert_eq!(lens.composite_score(p1, &ledgers, &chains, 10), 50);
    }

    #[test]
    fn a_pardon_in_one_moot_reaches_its_concorders() {
        // The payoff for the whole thread: P is in debt in moot X; X's governance
        // pardons P; a viewer V that concords X sees the restored standing, and the
        // absolution carries exactly as far as the concord with X.
        let (v, x) = (moot(1), moot(2));
        let p = persona(3);
        let gov = persona(50);
        let chains = PersonaChains::new();
        let mut lens = RepLens::new(v, CompositionPolicy::WeightedSum);
        lens.concord(x, 5_000); // V honours X at 50%

        // Before any pardon, P's -20 in X imports as -10.
        let unpardoned = HashMap::from([(x, ledger_in_debt(p))]);
        assert_eq!(lens.composite_score(p, &unpardoned, &chains, 1_000), -10);

        // X's governance pardons P (+20), clearing the debt in X. The concord now
        // imports 0, not -10 — the absolution reached V because V concords X.
        let pardoned = HashMap::from([(
            x,
            Ledger::from_events(
                TesseraConfig::default(),
                &[
                    TesseraEvent::CommitmentMade {
                        by: ChainRoot(p.0),
                        commitment: CommitmentId([7; 32]),
                        scope: Scope("s".into()),
                        cadence_ms: 100,
                        duration_ms: None,
                        at_ms: 0,
                    },
                    TesseraEvent::Pardon {
                        by: ChainRoot(gov.0),
                        target: ChainRoot(p.0),
                        weight: 20,
                        at_ms: 1,
                    },
                ],
            ),
        )]);
        assert_eq!(lens.composite_score(p, &pardoned, &chains, 1_000), 0);
    }

    #[test]
    fn a_concord_across_mismatched_schemas_imports_nothing() {
        // V (default config) concords X fully, and P is well-regarded in X — but X
        // scores under a different config, so the standings are not comparable and
        // the concord is dropped.
        let (v, x, p) = (moot(1), moot(2), persona(3));
        let chains = PersonaChains::new();
        let mut x_ledger = Ledger::new(TesseraConfig {
            fulfil_reward: 99,
            ..TesseraConfig::default()
        });
        x_ledger.apply(&TesseraEvent::CommitmentMade {
            by: ChainRoot(p.0),
            commitment: CommitmentId([1; 32]),
            scope: Scope("s".into()),
            cadence_ms: 100,
            duration_ms: None,
            at_ms: 0,
        });
        x_ledger.apply(&TesseraEvent::CommitmentFulfilled {
            by: ChainRoot(p.0),
            commitment: CommitmentId([1; 32]),
            at_ms: 1,
        });
        // V carries the default config via its own (empty) ledger.
        let ledgers = HashMap::from([(v, Ledger::new(TesseraConfig::default())), (x, x_ledger)]);
        let mut lens = RepLens::new(v, CompositionPolicy::WeightedSum);
        lens.concord(x, 10_000);
        // P scored +99 in X, but the schema mismatch drops the concord -> 0.
        assert_eq!(lens.composite_score(p, &ledgers, &chains, 10), 0);
    }
}
