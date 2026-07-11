//! Deterministic group-policy evaluation over a frozen electorate.

use std::collections::BTreeSet;

use p2panda_core::Hash;
use p2panda_core::cbor::encode_cbor;
use serde::{Deserialize, Serialize};

/// Canonical bytes of a member's signing key.
pub type MemberKey = [u8; 32];

/// A group membership set at one signed revision.
///
/// Freezing membership is essential: later joins or departures must not alter
/// whether an earlier proposal met its recognition policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElectorateSnapshot {
    pub group_id: [u8; 32],
    pub revision: [u8; 32],
    pub members: BTreeSet<MemberKey>,
}

impl ElectorateSnapshot {
    pub fn new(
        group_id: [u8; 32],
        revision: [u8; 32],
        members: impl IntoIterator<Item = MemberKey>,
    ) -> Self {
        Self {
            group_id,
            revision,
            members: members.into_iter().collect(),
        }
    }
}

/// How eligible endorsements become group recognition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RecognitionPolicy {
    /// One eligible member is enough.
    AnyEligible,
    /// A fixed number of eligible members must endorse.
    Threshold { required: u32 },
    /// A fraction of the frozen electorate, rounded up, with an absolute floor.
    Fraction {
        numerator: u32,
        denominator: u32,
        minimum: u32,
    },
    /// Every member in the frozen electorate must endorse.
    Unanimous,
}

impl RecognitionPolicy {
    pub fn validate(&self) -> Result<(), RecognitionPolicyError> {
        match self {
            Self::Threshold { required: 0 } => Err(RecognitionPolicyError::ZeroThreshold),
            Self::Fraction {
                numerator,
                denominator,
                ..
            } if *numerator == 0 || *denominator == 0 || numerator > denominator => {
                Err(RecognitionPolicyError::InvalidFraction)
            }
            Self::Fraction { minimum: 0, .. } => Err(RecognitionPolicyError::ZeroMinimum),
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RecognitionPolicyError {
    #[error("recognition threshold must be at least one")]
    ZeroThreshold,
    #[error("recognition fraction must satisfy 0 < numerator <= denominator")]
    InvalidFraction,
    #[error("recognition fraction minimum must be at least one")]
    ZeroMinimum,
    #[error("recognition context could not be encoded")]
    Encoding,
}

/// Policy plus the membership revision against which it is evaluated.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecognitionContext {
    pub policy: RecognitionPolicy,
    pub electorate: ElectorateSnapshot,
}

impl RecognitionContext {
    pub fn new(policy: RecognitionPolicy, electorate: ElectorateSnapshot) -> Self {
        Self { policy, electorate }
    }

    /// Content identity of the policy and frozen electorate.
    pub fn fingerprint(&self) -> Result<[u8; 32], RecognitionPolicyError> {
        let encoded = encode_cbor(self).map_err(|_| RecognitionPolicyError::Encoding)?;
        let mut bytes = b"mooting/recognition-context/v1\0".to_vec();
        bytes.extend_from_slice(&encoded);
        Ok(*Hash::digest(bytes).as_bytes())
    }

    pub fn evaluate(
        &self,
        endorsements: &BTreeSet<MemberKey>,
    ) -> Result<RecognitionDecision, RecognitionPolicyError> {
        self.policy.validate()?;
        let eligible: BTreeSet<_> = endorsements
            .intersection(&self.electorate.members)
            .copied()
            .collect();
        let ineligible: BTreeSet<_> = endorsements
            .difference(&self.electorate.members)
            .copied()
            .collect();
        let electorate_size = self.electorate.members.len() as u64;
        let required = match self.policy {
            RecognitionPolicy::AnyEligible => 1,
            RecognitionPolicy::Threshold { required } => required as u64,
            RecognitionPolicy::Fraction {
                numerator,
                denominator,
                minimum,
            } => {
                let fraction = electorate_size
                    .saturating_mul(numerator as u64)
                    .div_ceil(denominator as u64);
                fraction.max(minimum as u64)
            }
            RecognitionPolicy::Unanimous => electorate_size.max(1),
        };

        Ok(RecognitionDecision {
            group_id: self.electorate.group_id,
            electorate_revision: self.electorate.revision,
            electorate_size,
            required,
            eligible_endorsements: eligible,
            ineligible_endorsements: ineligible,
            accepted: electorate_size > 0
                && endorsements_count(endorsements, &self.electorate.members) >= required,
        })
    }
}

fn endorsements_count(endorsements: &BTreeSet<MemberKey>, electorate: &BTreeSet<MemberKey>) -> u64 {
    endorsements.intersection(electorate).count() as u64
}

/// Inspectable result of one recognition evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecognitionDecision {
    pub group_id: [u8; 32],
    pub electorate_revision: [u8; 32],
    pub electorate_size: u64,
    pub required: u64,
    pub eligible_endorsements: BTreeSet<MemberKey>,
    pub ineligible_endorsements: BTreeSet<MemberKey>,
    pub accepted: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn electorate(size: u8) -> ElectorateSnapshot {
        ElectorateSnapshot::new([8; 32], [9; 32], (1..=size).map(|member| [member; 32]))
    }

    #[test]
    fn fraction_rounds_up_and_ignores_outsiders() {
        let context = RecognitionContext::new(
            RecognitionPolicy::Fraction {
                numerator: 2,
                denominator: 3,
                minimum: 1,
            },
            electorate(4),
        );
        let endorsements = BTreeSet::from([[1; 32], [2; 32], [99; 32]]);
        let decision = context.evaluate(&endorsements).unwrap();
        assert_eq!(decision.required, 3);
        assert_eq!(decision.eligible_endorsements.len(), 2);
        assert_eq!(decision.ineligible_endorsements, BTreeSet::from([[99; 32]]));
        assert!(!decision.accepted);
    }

    #[test]
    fn frozen_electorate_prevents_later_membership_from_rewriting_history() {
        let policy = RecognitionPolicy::Unanimous;
        let original = RecognitionContext::new(policy.clone(), electorate(2));
        let later = RecognitionContext::new(policy, electorate(3));
        let endorsements = BTreeSet::from([[1; 32], [2; 32]]);
        assert!(original.evaluate(&endorsements).unwrap().accepted);
        assert!(!later.evaluate(&endorsements).unwrap().accepted);
        assert_ne!(
            original.fingerprint().unwrap(),
            later.fingerprint().unwrap()
        );
    }

    #[test]
    fn empty_electorate_never_recognizes() {
        let context = RecognitionContext::new(
            RecognitionPolicy::AnyEligible,
            ElectorateSnapshot::new([8; 32], [1; 32], []),
        );
        assert!(!context.evaluate(&BTreeSet::new()).unwrap().accepted);
    }

    #[test]
    fn invalid_policy_is_reported_not_silently_rewritten() {
        let context =
            RecognitionContext::new(RecognitionPolicy::Threshold { required: 0 }, electorate(2));
        assert_eq!(
            context.evaluate(&BTreeSet::new()),
            Err(RecognitionPolicyError::ZeroThreshold)
        );
    }

    #[test]
    fn identical_rosters_in_different_groups_have_distinct_contexts() {
        let members = [[1; 32], [2; 32]];
        let first = RecognitionContext::new(
            RecognitionPolicy::Unanimous,
            ElectorateSnapshot::new([1; 32], [9; 32], members),
        );
        let second = RecognitionContext::new(
            RecognitionPolicy::Unanimous,
            ElectorateSnapshot::new([2; 32], [9; 32], members),
        );
        assert_ne!(first.fingerprint().unwrap(), second.fingerprint().unwrap());
    }
}
