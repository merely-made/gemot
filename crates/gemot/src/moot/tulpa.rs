// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Tulpa: a community-adopted, revisioned shared artifact.
//!
//! Tulpa retains signed proposals and endorsements as facts. Its projection
//! uses `mooting::RecognitionContext`, whose electorate is frozen in every
//! proposal, so later membership churn cannot change an earlier decision.
//! Revocation and rollback change only the effective adopted version; they do
//! not erase a proposal or its endorsements.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use identity::Ed25519Keypair;
use mooting::{RecognitionContext, RecognitionDecision};
use muniment::{Backend, MemoryBackend, RedbBackend, StoreError};
use p2panda_core::cbor::{decode_cbor, encode_cbor};
use p2panda_core::operation::validate_operation;
use p2panda_core::{Body, Hash, Header, Operation, SigningKey, Topic, VerifyingKey};
use p2panda_store::logs::LogStore;
use p2panda_store::topics::TopicStore;
use serde::{Deserialize, Serialize};
use stickleback::{
    Admission, MunimentStore, OperationPolicy, OperationProcessor, ProcessError, Reject,
    StoreTarget,
};

use super::artifact::ArtifactRef;

const LOG_ID: u64 = 0;

/// Stable community identity of a Tulpa.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TulpaId(pub [u8; 32]);

/// Stable identifier of one offered Tulpa revision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TulpaVersion(pub [u8; 32]);

/// Stable identifier shared by a proposal and its endorsements.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TulpaProposalId(pub [u8; 32]);

/// One change a proposal asks the community to recognize.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TulpaProposal {
    /// Adopt `artifact` as a named version of a Tulpa.
    Adopt {
        tulpa: TulpaId,
        version: TulpaVersion,
        artifact: ArtifactRef,
    },
    /// Withdraw an adopted version from the effective projection.
    Revoke {
        tulpa: TulpaId,
        version: TulpaVersion,
    },
    /// Make a prior, still available version effective again.
    Rollback {
        tulpa: TulpaId,
        to_version: TulpaVersion,
    },
}

/// One signed Tulpa source fact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[allow(
    clippy::large_enum_variant,
    reason = "the frozen recognition context stays inline so one signed event is self-contained"
)]
pub enum TulpaEvent {
    /// An offer with a frozen recognition context. A matching proposal id is
    /// intentionally de-duplicated in the projection, while all conflicting
    /// source facts remain inspectable.
    Proposed {
        proposal: TulpaProposalId,
        action: TulpaProposal,
        recognition: RecognitionContext,
        at_ms: u64,
    },
    /// The operation author endorses exactly one proposal.
    Endorsed {
        proposal: TulpaProposalId,
        at_ms: u64,
    },
}

impl TulpaEvent {
    pub fn at_ms(&self) -> u64 {
        match self {
            Self::Proposed { at_ms, .. } | Self::Endorsed { at_ms, .. } => *at_ms,
        }
    }
}

/// A retained source fact, including its p2panda operation identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TulpaFact {
    pub operation: [u8; 32],
    pub author: [u8; 32],
    pub event: TulpaEvent,
}

/// One effective adoption. `proposal` is the signed source fact that caused it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdoptedTulpaVersion {
    pub version: TulpaVersion,
    pub artifact: ArtifactRef,
    pub proposal: TulpaProposalId,
    pub operation: [u8; 32],
}

/// The full deterministic projection: raw facts, recognition decisions, and
/// current versions. Ineligible endorsements are retained in the decision.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TulpaProjection {
    pub facts: Vec<TulpaFact>,
    pub decisions: BTreeMap<TulpaProposalId, RecognitionDecision>,
    pub adopted: BTreeMap<TulpaId, AdoptedTulpaVersion>,
    pub revoked: BTreeSet<(TulpaId, TulpaVersion)>,
}

#[derive(Clone)]
struct ProposedFact {
    operation: [u8; 32],
    action: TulpaProposal,
    recognition: RecognitionContext,
    at_ms: u64,
}

impl TulpaProjection {
    /// Fold already-verified operation facts. A duplicate proposal id uses the
    /// lexicographically first operation as canonical; every conflicting fact
    /// still appears in [`facts`](Self::facts).
    pub fn fold(mut facts: Vec<TulpaFact>) -> Self {
        facts.sort_by_key(|fact| fact.operation);
        let mut proposals = BTreeMap::<TulpaProposalId, ProposedFact>::new();
        let mut endorsements = BTreeMap::<TulpaProposalId, BTreeSet<[u8; 32]>>::new();
        for fact in &facts {
            match &fact.event {
                TulpaEvent::Proposed {
                    proposal,
                    action,
                    recognition,
                    at_ms,
                } if recognition.policy.validate().is_ok() => {
                    proposals.entry(*proposal).or_insert_with(|| ProposedFact {
                        operation: fact.operation,
                        action: action.clone(),
                        recognition: recognition.clone(),
                        at_ms: *at_ms,
                    });
                }
                TulpaEvent::Endorsed { proposal, .. } => {
                    endorsements
                        .entry(*proposal)
                        .or_default()
                        .insert(fact.author);
                }
                _ => {}
            }
        }

        let mut decisions = BTreeMap::new();
        let mut accepted = Vec::new();
        for (proposal, proposed) in &proposals {
            let endorsers = endorsements.get(proposal).cloned().unwrap_or_default();
            let decision = proposed.recognition.evaluate(&endorsers);
            if let Ok(decision) = decision {
                if decision.accepted {
                    accepted.push((*proposal, proposed.clone()));
                }
                decisions.insert(*proposal, decision);
            }
        }

        let mut revoked = BTreeSet::new();
        for (_, proposed) in &accepted {
            if let TulpaProposal::Revoke { tulpa, version } = &proposed.action {
                revoked.insert((*tulpa, *version));
            }
        }

        let mut versions =
            BTreeMap::<(TulpaId, TulpaVersion), (ArtifactRef, TulpaProposalId)>::new();
        for (proposal, proposed) in &accepted {
            if let TulpaProposal::Adopt {
                tulpa,
                version,
                artifact,
            } = &proposed.action
            {
                versions
                    .entry((*tulpa, *version))
                    .or_insert((artifact.clone(), *proposal));
            }
        }

        let mut candidates =
            BTreeMap::<TulpaId, Vec<(u64, [u8; 32], TulpaVersion, TulpaProposalId)>>::new();
        for (proposal, proposed) in accepted {
            match proposed.action {
                TulpaProposal::Adopt { tulpa, version, .. }
                    if !revoked.contains(&(tulpa, version)) =>
                {
                    candidates.entry(tulpa).or_default().push((
                        proposed.at_ms,
                        proposed.operation,
                        version,
                        proposal,
                    ));
                }
                TulpaProposal::Rollback { tulpa, to_version }
                    if !revoked.contains(&(tulpa, to_version))
                        && versions.contains_key(&(tulpa, to_version)) =>
                {
                    candidates.entry(tulpa).or_default().push((
                        proposed.at_ms,
                        proposed.operation,
                        to_version,
                        proposal,
                    ));
                }
                _ => {}
            }
        }

        let adopted = candidates
            .into_iter()
            .filter_map(|(tulpa, mut options)| {
                options.sort_by_key(|option| (option.0, option.1));
                let (_, operation, version, proposal) = options.pop()?;
                let (artifact, _) = versions.get(&(tulpa, version))?.clone();
                Some((
                    tulpa,
                    AdoptedTulpaVersion {
                        version,
                        artifact,
                        proposal,
                        operation,
                    },
                ))
            })
            .collect();
        Self {
            facts,
            decisions,
            adopted,
            revoked,
        }
    }
}

/// Signed Moot addressing extension for the Tulpa lane.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TulpaExt {
    pub moot_id: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TulpaWireError {
    #[error("tulpa operation has no body")]
    MissingBody,
    #[error("tulpa operation body is malformed")]
    Malformed,
}

pub fn to_operation(
    keypair: &Ed25519Keypair,
    moot_id: [u8; 32],
    event: &TulpaEvent,
    seq_num: u32,
    backlink: Option<[u8; 32]>,
) -> Operation<TulpaExt> {
    to_operation_seed(keypair.to_seed(), moot_id, event, seq_num, backlink)
}

pub fn to_operation_seed(
    signing_seed: [u8; 32],
    moot_id: [u8; 32],
    event: &TulpaEvent,
    seq_num: u32,
    backlink: Option<[u8; 32]>,
) -> Operation<TulpaExt> {
    let signing_key = SigningKey::from_bytes(&signing_seed);
    let bytes = encode_cbor(event).expect("Tulpa events always CBOR-encode");
    let body = Body::from_bytes(&bytes);
    let header = Header::builder()
        .body(&bytes)
        .seq_num(seq_num)
        .backlink(backlink.map(Hash::from))
        .build(&signing_key, TulpaExt { moot_id });
    Operation {
        hash: header.hash(),
        header,
        body: Some(body),
    }
}

pub fn from_operation(operation: &Operation<TulpaExt>) -> Result<TulpaEvent, TulpaWireError> {
    let body = operation.body.as_ref().ok_or(TulpaWireError::MissingBody)?;
    decode_cbor(body.to_bytes().as_slice()).map_err(|_| TulpaWireError::Malformed)
}

pub fn verify(operation: &Operation<TulpaExt>) -> bool {
    validate_operation(operation).is_ok() && operation.hash == operation.header.hash()
}

#[derive(Debug, thiserror::Error)]
pub enum TulpaStoreError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Process(#[from] ProcessError),
    #[error("malformed Tulpa operation")]
    Malformed,
}

#[derive(Clone, Copy)]
struct TulpaPolicy {
    moot_id: [u8; 32],
}

impl OperationPolicy<TulpaExt> for TulpaPolicy {
    type LogId = u64;

    fn admit(&self, operation: &Operation<TulpaExt>) -> Result<Admission<Self::LogId>, Reject> {
        if operation.header.extensions.moot_id != self.moot_id {
            return Err(Reject::new(
                "wrong-moot",
                "operation addresses a different moot",
            ));
        }
        from_operation(operation).map_err(|_| {
            Reject::new("invalid-tulpa-event", "operation body is not a Tulpa event")
        })?;
        Ok(Admission::keep(StoreTarget::new(
            Topic::from(self.moot_id),
            LOG_ID,
        )))
    }
}

/// A retained signed Tulpa fact store. Governance is evaluated in the fold;
/// wire admission deliberately retains pending or later-revoked source facts.
#[derive(Clone)]
pub struct TulpaStore<B> {
    store: MunimentStore<B, TulpaExt>,
}

pub type TulpaFileStore = TulpaStore<RedbBackend>;

impl TulpaStore<MemoryBackend> {
    pub fn in_memory() -> Self {
        Self {
            store: MunimentStore::new(MemoryBackend::new()),
        }
    }
}

impl TulpaStore<RedbBackend> {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, TulpaStoreError> {
        Ok(Self {
            store: MunimentStore::new(RedbBackend::open(path)?),
        })
    }
}

impl<B: Backend + Clone> TulpaStore<B> {
    pub fn sync_store(&self) -> MunimentStore<B, TulpaExt> {
        self.store.clone()
    }

    pub async fn author_seed(
        &self,
        signing_seed: [u8; 32],
        moot_id: [u8; 32],
        event: &TulpaEvent,
    ) -> Result<Operation<TulpaExt>, TulpaStoreError> {
        let author = SigningKey::from_bytes(&signing_seed).verifying_key();
        let previous = self.store.get_latest_entry(&author, &LOG_ID).await?;
        let (seq_num, backlink) = match previous {
            Some(operation) => (
                operation.header.seq_num + 1,
                Some(*operation.hash.as_bytes()),
            ),
            None => (0, None),
        };
        let operation = to_operation_seed(signing_seed, moot_id, event, seq_num, backlink);
        self.accept(moot_id, &operation).await?;
        Ok(operation)
    }

    pub async fn accept(
        &self,
        moot_id: [u8; 32],
        operation: &Operation<TulpaExt>,
    ) -> Result<bool, TulpaStoreError> {
        let processor = OperationProcessor::new(self.store.clone(), TulpaPolicy { moot_id });
        Ok(processor.process(operation).await?.inserted())
    }

    pub async fn get(&self, hash: &Hash) -> Result<Option<Operation<TulpaExt>>, TulpaStoreError> {
        Ok(self.store.get_operation(hash).await?)
    }

    pub async fn len(&self) -> Result<usize, TulpaStoreError> {
        Ok(self.store.operation_count().await?)
    }

    /// Whether this store currently contains no Tulpa operations.
    pub async fn is_empty(&self) -> Result<bool, TulpaStoreError> {
        Ok(self.store.operation_count().await? == 0)
    }

    pub async fn fold_moot(&self, moot_id: [u8; 32]) -> Result<TulpaProjection, TulpaStoreError> {
        let logs: BTreeMap<VerifyingKey, Vec<u64>> =
            self.store.resolve(&Topic::from(moot_id)).await?;
        let mut facts = Vec::new();
        for (author, log_ids) in logs {
            for log_id in log_ids {
                let Some(entries) = self
                    .store
                    .get_log_entries(&author, &log_id, None, None)
                    .await?
                else {
                    continue;
                };
                for (operation, _) in entries {
                    if !verify(&operation) {
                        continue;
                    }
                    let event =
                        from_operation(&operation).map_err(|_| TulpaStoreError::Malformed)?;
                    facts.push(TulpaFact {
                        operation: *operation.hash.as_bytes(),
                        author: *operation.header.verifying_key.as_bytes(),
                        event,
                    });
                }
            }
        }
        Ok(TulpaProjection::fold(facts))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use identity::{IdentityProvider, InMemoryProvider};
    use mooting::{ElectorateSnapshot, RecognitionPolicy};

    const MOOT: [u8; 32] = [0x71; 32];

    fn key(seed: u8) -> Ed25519Keypair {
        InMemoryProvider::from_seed([seed; 32])
            .derive_keypair(b"tulpa-test")
            .unwrap()
    }

    fn context(members: impl IntoIterator<Item = [u8; 32]>) -> RecognitionContext {
        RecognitionContext::new(
            RecognitionPolicy::Unanimous,
            ElectorateSnapshot::new(MOOT, [0x22; 32], members),
        )
    }

    fn proposed(id: u8, members: impl IntoIterator<Item = [u8; 32]>) -> TulpaEvent {
        TulpaEvent::Proposed {
            proposal: TulpaProposalId([id; 32]),
            action: TulpaProposal::Adopt {
                tulpa: TulpaId([3; 32]),
                version: TulpaVersion([4; 32]),
                artifact: ArtifactRef::blake3(b"candidate"),
            },
            recognition: context(members),
            at_ms: 10,
        }
    }

    #[test]
    fn fold_is_order_independent_and_uses_the_frozen_electorate() {
        let alice = key(1);
        let bob = key(2);
        let proposal = to_operation(
            &key(9),
            MOOT,
            &proposed(
                1,
                [alice.public_key().to_bytes(), bob.public_key().to_bytes()],
            ),
            0,
            None,
        );
        let a = to_operation(
            &alice,
            MOOT,
            &TulpaEvent::Endorsed {
                proposal: TulpaProposalId([1; 32]),
                at_ms: 11,
            },
            0,
            None,
        );
        let b = to_operation(
            &bob,
            MOOT,
            &TulpaEvent::Endorsed {
                proposal: TulpaProposalId([1; 32]),
                at_ms: 12,
            },
            0,
            None,
        );
        let facts = |operations: Vec<&Operation<TulpaExt>>| {
            operations
                .into_iter()
                .map(|operation| TulpaFact {
                    operation: *operation.hash.as_bytes(),
                    author: *operation.header.verifying_key.as_bytes(),
                    event: from_operation(operation).unwrap(),
                })
                .collect()
        };
        let forward = TulpaProjection::fold(facts(vec![&proposal, &a, &b]));
        let backward = TulpaProjection::fold(facts(vec![&b, &proposal, &a]));
        assert_eq!(forward, backward);
        assert_eq!(forward.adopted.len(), 1);

        let later_context = context([
            alice.public_key().to_bytes(),
            bob.public_key().to_bytes(),
            key(3).public_key().to_bytes(),
        ]);
        assert!(
            !later_context
                .evaluate(&BTreeSet::from([
                    alice.public_key().to_bytes(),
                    bob.public_key().to_bytes()
                ]))
                .unwrap()
                .accepted
        );
    }

    #[test]
    fn outsiders_and_duplicate_endorsements_never_add_weight() {
        let alice = key(1);
        let bob = key(2);
        let outsider = key(3);
        let owner = key(9);
        let proposal = to_operation(
            &owner,
            MOOT,
            &proposed(
                1,
                [alice.public_key().to_bytes(), bob.public_key().to_bytes()],
            ),
            0,
            None,
        );
        let a0 = to_operation(
            &alice,
            MOOT,
            &TulpaEvent::Endorsed {
                proposal: TulpaProposalId([1; 32]),
                at_ms: 11,
            },
            0,
            None,
        );
        let a1 = to_operation(
            &alice,
            MOOT,
            &TulpaEvent::Endorsed {
                proposal: TulpaProposalId([1; 32]),
                at_ms: 12,
            },
            1,
            Some(*a0.hash.as_bytes()),
        );
        let foreign = to_operation(
            &outsider,
            MOOT,
            &TulpaEvent::Endorsed {
                proposal: TulpaProposalId([1; 32]),
                at_ms: 13,
            },
            0,
            None,
        );
        let projection = TulpaProjection::fold(
            [&proposal, &a0, &a1, &foreign]
                .into_iter()
                .map(|operation| TulpaFact {
                    operation: *operation.hash.as_bytes(),
                    author: *operation.header.verifying_key.as_bytes(),
                    event: from_operation(operation).unwrap(),
                })
                .collect(),
        );
        let decision = projection.decisions.get(&TulpaProposalId([1; 32])).unwrap();
        assert!(!decision.accepted);
        assert_eq!(decision.eligible_endorsements.len(), 1);
        assert_eq!(decision.ineligible_endorsements.len(), 1);
    }

    #[test]
    fn revoke_removes_the_effect_without_deleting_source_facts() {
        let signer = key(1);
        let member = signer.public_key().to_bytes();
        let recognition = RecognitionContext::new(
            RecognitionPolicy::AnyEligible,
            ElectorateSnapshot::new(MOOT, [1; 32], [member]),
        );
        let adopt = TulpaEvent::Proposed {
            proposal: TulpaProposalId([1; 32]),
            action: TulpaProposal::Adopt {
                tulpa: TulpaId([2; 32]),
                version: TulpaVersion([3; 32]),
                artifact: ArtifactRef::blake3(b"v1"),
            },
            recognition: recognition.clone(),
            at_ms: 1,
        };
        let revoke = TulpaEvent::Proposed {
            proposal: TulpaProposalId([4; 32]),
            action: TulpaProposal::Revoke {
                tulpa: TulpaId([2; 32]),
                version: TulpaVersion([3; 32]),
            },
            recognition,
            at_ms: 3,
        };
        let proposed = to_operation(&signer, MOOT, &adopt, 0, None);
        let adopted = to_operation(
            &signer,
            MOOT,
            &TulpaEvent::Endorsed {
                proposal: TulpaProposalId([1; 32]),
                at_ms: 2,
            },
            1,
            Some(*proposed.hash.as_bytes()),
        );
        let proposed_revoke =
            to_operation(&signer, MOOT, &revoke, 2, Some(*adopted.hash.as_bytes()));
        let revoked = to_operation(
            &signer,
            MOOT,
            &TulpaEvent::Endorsed {
                proposal: TulpaProposalId([4; 32]),
                at_ms: 4,
            },
            3,
            Some(*proposed_revoke.hash.as_bytes()),
        );
        let operations = [proposed, adopted, proposed_revoke, revoked];
        let projection = TulpaProjection::fold(
            operations
                .iter()
                .map(|operation| TulpaFact {
                    operation: *operation.hash.as_bytes(),
                    author: *operation.header.verifying_key.as_bytes(),
                    event: from_operation(operation).unwrap(),
                })
                .collect(),
        );
        assert!(projection.adopted.is_empty());
        assert_eq!(projection.facts.len(), 4);
        assert!(
            projection
                .revoked
                .contains(&(TulpaId([2; 32]), TulpaVersion([3; 32])))
        );
    }

    #[test]
    fn rollback_reselects_an_adopted_version_without_removing_facts() {
        let signer = key(5);
        let member = signer.public_key().to_bytes();
        let recognition = RecognitionContext::new(
            RecognitionPolicy::AnyEligible,
            ElectorateSnapshot::new(MOOT, [5; 32], [member]),
        );
        let tulpa = TulpaId([6; 32]);
        let v1 = TulpaVersion([7; 32]);
        let v2 = TulpaVersion([8; 32]);
        let events = [
            TulpaEvent::Proposed {
                proposal: TulpaProposalId([1; 32]),
                action: TulpaProposal::Adopt {
                    tulpa,
                    version: v1,
                    artifact: ArtifactRef::blake3(b"v1"),
                },
                recognition: recognition.clone(),
                at_ms: 1,
            },
            TulpaEvent::Endorsed {
                proposal: TulpaProposalId([1; 32]),
                at_ms: 2,
            },
            TulpaEvent::Proposed {
                proposal: TulpaProposalId([2; 32]),
                action: TulpaProposal::Adopt {
                    tulpa,
                    version: v2,
                    artifact: ArtifactRef::blake3(b"v2"),
                },
                recognition: recognition.clone(),
                at_ms: 3,
            },
            TulpaEvent::Endorsed {
                proposal: TulpaProposalId([2; 32]),
                at_ms: 4,
            },
            TulpaEvent::Proposed {
                proposal: TulpaProposalId([3; 32]),
                action: TulpaProposal::Rollback {
                    tulpa,
                    to_version: v1,
                },
                recognition,
                at_ms: 5,
            },
            TulpaEvent::Endorsed {
                proposal: TulpaProposalId([3; 32]),
                at_ms: 6,
            },
        ];
        let mut operations = Vec::new();
        let mut backlink = None;
        for (sequence, event) in events.iter().enumerate() {
            let operation = to_operation(&signer, MOOT, event, sequence as u32, backlink);
            backlink = Some(*operation.hash.as_bytes());
            operations.push(operation);
        }
        let projection = TulpaProjection::fold(
            operations
                .iter()
                .map(|operation| TulpaFact {
                    operation: *operation.hash.as_bytes(),
                    author: *operation.header.verifying_key.as_bytes(),
                    event: from_operation(operation).unwrap(),
                })
                .collect(),
        );
        assert_eq!(projection.facts.len(), 6);
        assert_eq!(projection.adopted.get(&tulpa).unwrap().version, v1);
    }
}
