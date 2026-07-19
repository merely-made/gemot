// Copyright 2026 Mark AB (markik)
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeMap;

use p2panda_core::Operation;

use crate::{
    CompositionPolicy, MemberTerms, MootId, MootholdEvent, MootholdExt, MootholdId, from_operation,
    verify,
};

/// Accepted state of one holding of moots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Moothold {
    pub id: MootholdId,
    pub name: String,
    pub founder: [u8; 32],
    pub revision: [u8; 32],
    pub composition: CompositionPolicy,
    pub members: BTreeMap<MootId, MemberTerms>,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MootholdError {
    #[error("Moothold operation signature is invalid")]
    InvalidSignature,
    #[error("Moothold operation addresses another holding")]
    WrongMoothold,
    #[error("Moothold operation is malformed")]
    Malformed,
    #[error("Moothold event is not well formed")]
    InvalidEvent,
    #[error("Moothold is already founded")]
    AlreadyFounded,
    #[error("Moothold event does not name the accepted prior revision")]
    StaleRevision,
    #[error("actor is not the Moothold founder")]
    Unauthorized,
}

impl Moothold {
    /// Deterministically fold a retained operation corpus.
    pub fn fold<'a, I>(id: MootholdId, expected_founder: [u8; 32], operations: I) -> Option<Self>
    where
        I: IntoIterator<Item = &'a Operation<MootholdExt>>,
    {
        let mut candidates: Vec<([u8; 32], [u8; 32], MootholdEvent)> = operations
            .into_iter()
            .filter_map(|operation| {
                if operation.header.extensions.moothold_id != id.0 || !verify(operation) {
                    return None;
                }
                let event = from_operation(operation).ok()?;
                if !event.is_well_formed() {
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
                MootholdEvent::Founded {
                    moothold_id,
                    founder,
                    ..
                } if *moothold_id == id
                    && *founder == expected_founder
                    && *author == expected_founder
            )
        })?;
        let MootholdEvent::Founded {
            name,
            founder,
            initial_moot,
            initial_terms,
            composition,
            ..
        } = genesis
        else {
            unreachable!()
        };
        let mut state = Self {
            id,
            name: name.clone(),
            founder: *founder,
            revision: *genesis_hash,
            composition: *composition,
            members: BTreeMap::from([(*initial_moot, *initial_terms)]),
        };

        loop {
            let next = candidates.iter().find(|(_, author, event)| {
                *author == state.founder && event.previous() == Some(state.revision)
            });
            let Some((hash, _, event)) = next else {
                break;
            };
            state.apply_event(event);
            state.revision = *hash;
        }
        Some(state)
    }

    pub fn apply(&mut self, operation: &Operation<MootholdExt>) -> Result<(), MootholdError> {
        if operation.header.extensions.moothold_id != self.id.0 {
            return Err(MootholdError::WrongMoothold);
        }
        if !verify(operation) {
            return Err(MootholdError::InvalidSignature);
        }
        let event = from_operation(operation).map_err(|_| MootholdError::Malformed)?;
        if !event.is_well_formed() {
            return Err(MootholdError::InvalidEvent);
        }
        if matches!(event, MootholdEvent::Founded { .. }) {
            return Err(MootholdError::AlreadyFounded);
        }
        if event.previous() != Some(self.revision) {
            return Err(MootholdError::StaleRevision);
        }
        if *operation.header.verifying_key.as_bytes() != self.founder {
            return Err(MootholdError::Unauthorized);
        }
        self.apply_event(&event);
        self.revision = *operation.hash.as_bytes();
        Ok(())
    }

    fn apply_event(&mut self, event: &MootholdEvent) {
        match event {
            MootholdEvent::Founded { .. } => {}
            MootholdEvent::MootAdmitted { moot, terms, .. } => {
                self.members.insert(*moot, *terms);
            }
            MootholdEvent::MootRemoved { moot, .. } => {
                self.members.remove(moot);
            }
            MootholdEvent::CompositionChanged { composition, .. } => {
                self.composition = *composition;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use p2panda_core::SigningKey;

    use super::*;
    use crate::to_operation_seed;

    fn founder(seed: u8) -> ([u8; 32], [u8; 32]) {
        let seed = [seed; 32];
        let author = *SigningKey::from_bytes(&seed).verifying_key().as_bytes();
        (seed, author)
    }

    fn founded(seed: [u8; 32], author: [u8; 32], id: MootholdId) -> Operation<MootholdExt> {
        to_operation_seed(
            seed,
            id,
            &MootholdEvent::Founded {
                moothold_id: id,
                name: "river towns".into(),
                founder: author,
                initial_moot: MootId([1; 32]),
                initial_terms: MemberTerms::new(10_000, 10).unwrap(),
                composition: CompositionPolicy::CautiousImport,
                at_ms: 1,
            },
            0,
            None,
        )
    }

    #[test]
    fn fold_is_order_independent_and_selects_one_concurrent_child() {
        let id = MootholdId([8; 32]);
        let (seed, author) = founder(1);
        let genesis = founded(seed, author, id);
        let admit = |moot: u8| {
            to_operation_seed(
                seed,
                id,
                &MootholdEvent::MootAdmitted {
                    previous: *genesis.hash.as_bytes(),
                    moot: MootId([moot; 32]),
                    terms: MemberTerms::new(5_000, 20).unwrap(),
                    at_ms: 2,
                },
                1,
                Some(*genesis.hash.as_bytes()),
            )
        };
        let a = admit(2);
        let b = admit(3);
        let forward = Moothold::fold(id, author, [&genesis, &a, &b]).unwrap();
        let reverse = Moothold::fold(id, author, [&b, &a, &genesis]).unwrap();
        assert_eq!(forward, reverse);
        assert_eq!(forward.members.len(), 2);
    }

    #[test]
    fn live_apply_rejects_a_non_founder_without_mutation() {
        let id = MootholdId([8; 32]);
        let (seed, author) = founder(1);
        let genesis = founded(seed, author, id);
        let mut state = Moothold::fold(id, author, [&genesis]).unwrap();
        let before = state.clone();
        let event = MootholdEvent::MootRemoved {
            previous: state.revision,
            moot: MootId([1; 32]),
            at_ms: 2,
        };
        let intruder = to_operation_seed([2; 32], id, &event, 0, None);
        assert_eq!(state.apply(&intruder), Err(MootholdError::Unauthorized));
        assert_eq!(state, before);
    }
}
