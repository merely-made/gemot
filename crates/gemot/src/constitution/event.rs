//! Logical constitution events and the minimal native rule vocabulary.

use std::collections::BTreeSet;

use p2panda_core::cbor::encode_cbor;
use proofs::Digest;
use serde::{Deserialize, Serialize};

/// The rule controlling amendments to the shared constitution.
///
/// The first rung is intentionally small. Tessera thresholds and quorum rules
/// can extend this enum without changing the signed event or fold shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AmendmentRule {
    /// Only the founder bound by genesis may amend the constitution.
    FounderSigned,
}

/// Constitutional clauses needed by the first governed-retention slice.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstitutionRules {
    /// How this ruleset may be replaced.
    pub amendment: AmendmentRule,
    /// Keys allowed to author governed retention checkpoints.
    pub checkpoint_signers: BTreeSet<[u8; 32]>,
}

impl ConstitutionRules {
    /// Bootstrap rules for a founder-governed Moot.
    pub fn founder_only(founder: [u8; 32]) -> Self {
        Self {
            amendment: AmendmentRule::FounderSigned,
            checkpoint_signers: [founder].into_iter().collect(),
        }
    }

    /// Canonical digest committed by a constitution event.
    pub fn digest(&self) -> Digest {
        let bytes = encode_cbor(self).expect("constitution rules always CBOR-encode");
        Digest::blake3(&bytes)
    }
}

/// One signed entry in a Moot's constitution log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConstitutionEvent {
    /// Establish the governance identity and initial rules of a Moot or fork.
    Genesis {
        /// Moot whose law this event establishes.
        moot_id: [u8; 32],
        /// Initial governance key, also required to sign this event.
        founder: [u8; 32],
        /// Constitution from which this Moot forked, when applicable.
        parent_constitution: Option<Digest>,
        /// Parent revision at which the fork diverged.
        divergence_point: Option<Digest>,
        /// Readable initial clauses.
        rules: ConstitutionRules,
        /// Commitment to the canonical rule bytes.
        rules_hash: Digest,
        /// Author-asserted timestamp.
        at_ms: u64,
    },
    /// Replace the rules under the authority of the immediately prior revision.
    Amended {
        /// Accepted constitution revision this amendment advances.
        previous: Digest,
        /// Replacement clauses.
        rules: ConstitutionRules,
        /// Commitment to the canonical rule bytes.
        rules_hash: Digest,
        /// Author-asserted timestamp.
        at_ms: u64,
    },
}

impl ConstitutionEvent {
    /// Construct a self-consistent genesis event.
    pub fn genesis(
        moot_id: [u8; 32],
        founder: [u8; 32],
        parent_constitution: Option<Digest>,
        divergence_point: Option<Digest>,
        rules: ConstitutionRules,
        at_ms: u64,
    ) -> Self {
        let rules_hash = rules.digest();
        Self::Genesis {
            moot_id,
            founder,
            parent_constitution,
            divergence_point,
            rules,
            rules_hash,
            at_ms,
        }
    }

    /// Construct a self-consistent amendment event.
    pub fn amended(previous: Digest, rules: ConstitutionRules, at_ms: u64) -> Self {
        let rules_hash = rules.digest();
        Self::Amended {
            previous,
            rules,
            rules_hash,
            at_ms,
        }
    }

    /// Author-asserted event time.
    pub fn at_ms(&self) -> u64 {
        match self {
            Self::Genesis { at_ms, .. } | Self::Amended { at_ms, .. } => *at_ms,
        }
    }

    /// Whether the readable rules match the signed commitment.
    pub fn rules_are_bound(&self) -> bool {
        match self {
            Self::Genesis {
                rules, rules_hash, ..
            }
            | Self::Amended {
                rules, rules_hash, ..
            } => rules.digest() == *rules_hash,
        }
    }
}
