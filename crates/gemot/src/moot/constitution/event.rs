//! Logical constitution events and the minimal native rule vocabulary.

use std::collections::{BTreeMap, BTreeSet};

use p2panda_core::cbor::encode_cbor;
use proofs::Digest;
use serde::{Deserialize, Serialize};

use crate::moot::tessera::Policy;

/// The rule controlling amendments to the shared constitution.
///
/// The first rung is intentionally small. Tessera thresholds and quorum rules
/// can extend this enum without changing the signed event or fold shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AmendmentRule {
    /// Only the founder bound by genesis may amend the constitution.
    FounderSigned,
}

/// A founder-governed capability grant carried by the signed constitution.
///
/// This is deliberately a current-state grant, not an independently delegated
/// token. The accepted constitutional revision supplies its authority and an
/// amendment revokes it by removing it. A later quorum/delegation rule can move
/// grants to their own signed log without changing the Moot authorization seam.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityGrant {
    /// Stable identifier chosen by the constitutional author.
    pub id: [u8; 32],
    /// Persona-chain root this grant belongs to.
    pub subject: [u8; 32],
    /// Inclusive structural path prefix, such as `moot/fauna`.
    pub path_prefix: String,
    /// The first millisecond at which the grant is usable.
    pub not_before_ms: u64,
    /// Optional expiry. Expiry preserves the historical constitution evidence.
    pub expires_at_ms: Option<u64>,
}

impl CapabilityGrant {
    /// Whether this grant covers `path` at `at_ms`.
    ///
    /// Path matching stops on a segment boundary, so `moot/fauna` does not
    /// cover `moot/faunarium`. Empty prefixes and invalid time intervals are
    /// denied defensively even if malformed historical rules are encountered.
    pub fn covers(&self, subject: [u8; 32], path: &str, at_ms: u64) -> bool {
        self.subject == subject
            && !self.path_prefix.is_empty()
            && at_ms >= self.not_before_ms
            && match self.expires_at_ms {
                None => true,
                Some(expires) => expires >= self.not_before_ms && at_ms <= expires,
            }
            && (path == self.path_prefix
                || path
                    .strip_prefix(&self.path_prefix)
                    .is_some_and(|suffix| suffix.starts_with('/')))
    }
}

/// Constitutional clauses needed by the first governed-retention slice.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstitutionRules {
    /// How this ruleset may be replaced.
    pub amendment: AmendmentRule,
    /// Keys allowed to author governed retention checkpoints.
    pub checkpoint_signers: BTreeSet<[u8; 32]>,
    /// The signed admission rule evaluated from Tessera facts plus a host- or
    /// group-state supplied membership/capability provider.
    pub admission: Policy,
    /// Current founder-governed capability grants. Removing an entry in an
    /// accepted amendment revokes it for future authorization decisions.
    pub capability_grants: BTreeMap<[u8; 32], CapabilityGrant>,
}

impl ConstitutionRules {
    /// Bootstrap rules for a founder-governed Moot.
    pub fn founder_only(founder: [u8; 32]) -> Self {
        Self {
            amendment: AmendmentRule::FounderSigned,
            checkpoint_signers: [founder].into_iter().collect(),
            admission: Policy::OpenWithFloor(Default::default()),
            capability_grants: BTreeMap::new(),
        }
    }

    /// Insert or replace one grant by its stable id.
    pub fn grant(&mut self, grant: CapabilityGrant) {
        self.capability_grants.insert(grant.id, grant);
    }

    /// Revoke one grant in the next signed constitutional revision.
    pub fn revoke_grant(&mut self, grant_id: &[u8; 32]) -> Option<CapabilityGrant> {
        self.capability_grants.remove(grant_id)
    }

    /// Whether any current grant covers this subject/path/time tuple.
    pub fn grant_covers(&self, subject: [u8; 32], path: &str, at_ms: u64) -> bool {
        self.capability_grants
            .values()
            .any(|grant| grant.covers(subject, path, at_ms))
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
