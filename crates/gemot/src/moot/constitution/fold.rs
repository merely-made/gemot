//! Deterministic constitution fold and the shared governance chokepoint.

use p2panda_core::Operation;
use proofs::Digest;

use super::wire::{ConstitutionExt, from_operation, verify};
use super::{AmendmentRule, ConstitutionEvent, ConstitutionRules};

/// A community action evaluated under the accepted constitution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GovernedAction {
    /// Replace the constitution's current rules.
    AmendConstitution,
}

/// Accepted current constitution of one Moot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Constitution {
    /// Governed Moot.
    pub moot_id: [u8; 32],
    /// Governance root fixed by genesis.
    pub founder: [u8; 32],
    /// Parent constitution for a fork.
    pub parent_constitution: Option<Digest>,
    /// Parent revision where a fork diverged.
    pub divergence_point: Option<Digest>,
    /// Current readable rules.
    pub rules: ConstitutionRules,
    /// Accepted operation identity of the current revision.
    pub revision: Digest,
}

/// Rejection while applying a constitution operation to live state.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConstitutionError {
    /// Operation signature or body commitment failed.
    #[error("constitution operation signature is invalid")]
    InvalidSignature,
    /// Operation addresses another Moot.
    #[error("constitution operation addresses another moot")]
    WrongMoot,
    /// Operation body did not decode.
    #[error("constitution operation is malformed")]
    Malformed,
    /// Readable rules did not match their committed digest.
    #[error("constitution rules do not match their digest")]
    RulesDigest,
    /// A second genesis cannot advance an established constitution.
    #[error("constitution is already founded")]
    AlreadyFounded,
    /// Amendment does not advance the accepted revision.
    #[error("amendment does not name the accepted prior revision")]
    StaleRevision,
    /// Actor is not permitted by the prior constitution.
    #[error("actor is not authorized to amend this constitution")]
    Unauthorized,
}

/// Evaluate one governed action against the current shared law.
pub fn authorize_governed(
    action: GovernedAction,
    actor: [u8; 32],
    constitution: &Constitution,
) -> bool {
    match (action, &constitution.rules.amendment) {
        (GovernedAction::AmendConstitution, AmendmentRule::FounderSigned) => {
            actor == constitution.founder
        }
    }
}

impl Constitution {
    /// Deterministically fold a retained operation corpus.
    ///
    /// The configured founder is the external root of governance supplied by
    /// the Moot declaration. Invalid candidates are ignored. A founder's
    /// concurrent amendments of one revision resolve by operation hash.
    pub fn fold<'a, I>(moot_id: [u8; 32], expected_founder: [u8; 32], operations: I) -> Option<Self>
    where
        I: IntoIterator<Item = &'a Operation<ConstitutionExt>>,
    {
        let mut candidates: Vec<([u8; 32], [u8; 32], ConstitutionEvent)> = operations
            .into_iter()
            .filter_map(|operation| {
                if operation.header.extensions.moot_id != moot_id || !verify(operation) {
                    return None;
                }
                let event = from_operation(operation).ok()?;
                if !event.rules_are_bound() {
                    return None;
                }
                Some((
                    *operation.hash.as_bytes(),
                    *operation.header.verifying_key.as_bytes(),
                    event,
                ))
            })
            .collect();
        candidates.sort_by_key(|candidate| candidate.0);

        let (genesis_hash, _, genesis) = candidates.iter().find(|(_, author, event)| {
            matches!(
                event,
                ConstitutionEvent::Genesis {
                    moot_id: event_moot,
                    founder,
                    ..
                } if *event_moot == moot_id
                    && *founder == expected_founder
                    && *author == expected_founder
            )
        })?;
        let ConstitutionEvent::Genesis {
            founder,
            parent_constitution,
            divergence_point,
            rules,
            ..
        } = genesis
        else {
            unreachable!()
        };
        let mut state = Self {
            moot_id,
            founder: *founder,
            parent_constitution: parent_constitution.clone(),
            divergence_point: divergence_point.clone(),
            rules: rules.clone(),
            revision: Digest::p2panda_operation(*genesis_hash),
        };

        loop {
            let next = candidates.iter().find(|(_, author, event)| {
                let ConstitutionEvent::Amended { previous, .. } = event else {
                    return false;
                };
                *previous == state.revision
                    && authorize_governed(GovernedAction::AmendConstitution, *author, &state)
            });
            let Some((hash, _, ConstitutionEvent::Amended { rules, .. })) = next else {
                break;
            };
            state.rules = rules.clone();
            state.revision = Digest::p2panda_operation(*hash);
        }
        Some(state)
    }

    /// Apply one next operation to a live fold.
    pub fn apply(
        &mut self,
        operation: &Operation<ConstitutionExt>,
    ) -> Result<(), ConstitutionError> {
        if operation.header.extensions.moot_id != self.moot_id {
            return Err(ConstitutionError::WrongMoot);
        }
        if !verify(operation) {
            return Err(ConstitutionError::InvalidSignature);
        }
        let event = from_operation(operation).map_err(|_| ConstitutionError::Malformed)?;
        if !event.rules_are_bound() {
            return Err(ConstitutionError::RulesDigest);
        }
        let ConstitutionEvent::Amended {
            previous, rules, ..
        } = event
        else {
            return Err(ConstitutionError::AlreadyFounded);
        };
        if previous != self.revision {
            return Err(ConstitutionError::StaleRevision);
        }
        let actor = *operation.header.verifying_key.as_bytes();
        if !authorize_governed(GovernedAction::AmendConstitution, actor, self) {
            return Err(ConstitutionError::Unauthorized);
        }
        self.rules = rules;
        self.revision = Digest::p2panda_operation(*operation.hash.as_bytes());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::moot::constitution::{ConstitutionEvent, ConstitutionRules, to_operation};
    use identity::{Ed25519Keypair, IdentityProvider, InMemoryProvider};

    const MOOT: [u8; 32] = [0x63; 32];

    fn keypair(seed: u8) -> Ed25519Keypair {
        InMemoryProvider::from_seed([seed; 32])
            .derive_keypair(b"constitution-fold")
            .unwrap()
    }

    #[test]
    fn fold_is_order_independent_and_uses_the_prior_rule() {
        let founder = keypair(1);
        let intruder = keypair(2);
        let founder_id = founder.public_key().to_bytes();
        let genesis_event = ConstitutionEvent::genesis(
            MOOT,
            founder_id,
            None,
            None,
            ConstitutionRules::founder_only(founder_id),
            1,
        );
        let genesis = to_operation(&founder, MOOT, &genesis_event, 0, None);
        let genesis_revision = Digest::p2panda_operation(*genesis.hash.as_bytes());

        let mut accepted_rules = ConstitutionRules::founder_only(founder_id);
        accepted_rules.checkpoint_signers.insert([9; 32]);
        let accepted_event =
            ConstitutionEvent::amended(genesis_revision.clone(), accepted_rules.clone(), 2);
        let accepted = to_operation(
            &founder,
            MOOT,
            &accepted_event,
            1,
            Some(*genesis.hash.as_bytes()),
        );
        let rejected_event = ConstitutionEvent::amended(
            genesis_revision,
            ConstitutionRules::founder_only(founder_id),
            2,
        );
        let rejected = to_operation(&intruder, MOOT, &rejected_event, 0, None);

        let forward = Constitution::fold(MOOT, founder_id, [&genesis, &accepted, &rejected]);
        let reverse = Constitution::fold(MOOT, founder_id, [&rejected, &accepted, &genesis]);
        assert_eq!(forward, reverse);
        assert_eq!(forward.unwrap().rules, accepted_rules);
    }

    #[test]
    fn live_apply_rejects_a_non_founder_without_changing_state() {
        let founder = keypair(1);
        let intruder = keypair(2);
        let founder_id = founder.public_key().to_bytes();
        let genesis_event = ConstitutionEvent::genesis(
            MOOT,
            founder_id,
            None,
            None,
            ConstitutionRules::founder_only(founder_id),
            1,
        );
        let genesis = to_operation(&founder, MOOT, &genesis_event, 0, None);
        let mut state = Constitution::fold(MOOT, founder_id, [&genesis]).unwrap();
        let before = state.clone();
        let event = ConstitutionEvent::amended(
            state.revision.clone(),
            ConstitutionRules::founder_only(founder_id),
            2,
        );
        let operation = to_operation(&intruder, MOOT, &event, 0, None);
        assert_eq!(
            state.apply(&operation),
            Err(ConstitutionError::Unauthorized)
        );
        assert_eq!(state, before);
    }
}
