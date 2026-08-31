// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! FLORA: social receipts for federated LoRA rounds.
//!
//! This is specifically the FLoRA stacking contract: each participant's `A`
//! factor is stacked vertically, `B` horizontally, and each participant's
//! round weight is combined with that adapter's `alpha / rank` and applied to
//! `B` only. That supports heterogeneous ranks; the global rank
//! is the exact sum and must fit the signed round budget. Gemot carries only
//! artifact references and social receipts. Distillery/ESP executes tensors,
//! Mesh owns jobs and leases, and Eidetic/Muniment stores bytes. Training corpus
//! data and raw tensor payloads never enter this public lane.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use identity::Ed25519Keypair;
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

/// Stable id of a social FLORA training round.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FloraRoundId(pub [u8; 32]);

/// One participating contributor, keyed by a public persona or device id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FloraParticipant {
    /// FLoRA rank allocated to this contribution.
    pub rank: u16,
    /// Round contribution weight. The tensor executor computes
    /// `weight * source_alpha / source_rank` and applies that value to `B`
    /// exactly once; it is deliberately not duplicated onto `A`.
    pub weight: FloraWeight,
}

/// Exact rational round weight. Tensor execution owns its numeric dtype.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FloraWeight {
    /// Positive numerator of the participant's round weight.
    pub numerator: u32,
    /// Positive denominator of the participant's round weight.
    pub denominator: u32,
}

/// The only aggregate layout supported by this protocol version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FloraStacking;

impl FloraStacking {
    /// Participants' A factors are vertically concatenated.
    pub const A_VERTICALLY_STACKED: bool = true;
    /// Participants' B factors are horizontally concatenated.
    pub const B_HORIZONTALLY_STACKED: bool = true;
    /// Participant scaling is applied exactly once, to B.
    pub const SCALE_B_ONLY: bool = true;
}

/// Signed social contract for one FLoRA round.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FloraRoundSpec {
    pub round: FloraRoundId,
    /// Exact base-model artifact this adapter targets.
    pub base_model: ArtifactRef,
    /// Explicit ceiling for the sum of all participant ranks.
    pub rank_budget: u16,
    /// Keyed by participant identity; each contribution keeps its own rank and
    /// weight, permitting heterogeneous ranks without compression.
    pub participants: BTreeMap<[u8; 32], FloraParticipant>,
}

impl FloraRoundSpec {
    pub fn global_rank(&self) -> Result<u16, FloraValidationError> {
        let mut total = 0_u16;
        for participant in self.participants.values() {
            if participant.rank == 0 {
                return Err(FloraValidationError::ZeroParticipantRank);
            }
            if participant.weight.numerator == 0 {
                return Err(FloraValidationError::ZeroWeightNumerator);
            }
            if participant.weight.denominator == 0 {
                return Err(FloraValidationError::ZeroWeightDenominator);
            }
            total = total
                .checked_add(participant.rank)
                .ok_or(FloraValidationError::RankOverflow)?;
        }
        Ok(total)
    }

    /// Reject invalid rank declarations rather than silently truncating,
    /// rebalancing, or compressing an adapter.
    pub fn validate(&self) -> Result<u16, FloraValidationError> {
        if self.rank_budget == 0 {
            return Err(FloraValidationError::ZeroRankBudget);
        }
        if self.participants.is_empty() {
            return Err(FloraValidationError::NoParticipants);
        }
        let global_rank = self.global_rank()?;
        if global_rank > self.rank_budget {
            return Err(FloraValidationError::RankBudgetExceeded {
                global_rank,
                budget: self.rank_budget,
            });
        }
        Ok(global_rank)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FloraValidationError {
    #[error("FLORA rank budget must be explicit and non-zero")]
    ZeroRankBudget,
    #[error("FLORA rounds need at least one participant")]
    NoParticipants,
    #[error("a FLORA participant rank must be non-zero")]
    ZeroParticipantRank,
    #[error("a FLORA participant weight numerator must be non-zero")]
    ZeroWeightNumerator,
    #[error("a FLORA participant weight denominator must be non-zero")]
    ZeroWeightDenominator,
    #[error("FLORA global rank overflowed the current u16 adapter contract")]
    RankOverflow,
    #[error("FLORA global rank {global_rank} exceeds explicit budget {budget}")]
    RankBudgetExceeded { global_rank: u16, budget: u16 },
}

/// Exact out-of-band references to one participant's LoRA factors and its
/// optional training receipt. No tensor/corpus bytes appear in this value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FloraContributionReceipt {
    pub round: FloraRoundId,
    pub participant: [u8; 32],
    pub a_factor: ArtifactRef,
    pub b_factor: ArtifactRef,
    pub receipt: ArtifactRef,
}

/// Candidate adapter published for community inspection or later Tulpa adoption.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FloraCandidateArtifact {
    pub round: FloraRoundId,
    pub adapter: ArtifactRef,
    pub global_rank: u16,
    /// This must name the complete signed participant set. A partial set would
    /// change the FLoRA rank, so it is not silently accepted.
    pub contributors: BTreeSet<[u8; 32]>,
}

/// One signed FLORA source fact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FloraEvent {
    RoundProposed {
        spec: FloraRoundSpec,
        at_ms: u64,
    },
    ContributionReceived {
        contribution: FloraContributionReceipt,
        at_ms: u64,
    },
    CandidatePublished {
        candidate: FloraCandidateArtifact,
        at_ms: u64,
    },
    /// A social withdrawal of this round. Facts remain available for audit.
    RoundRevoked {
        round: FloraRoundId,
        at_ms: u64,
    },
}

impl FloraEvent {
    pub fn at_ms(&self) -> u64 {
        match self {
            Self::RoundProposed { at_ms, .. }
            | Self::ContributionReceived { at_ms, .. }
            | Self::CandidatePublished { at_ms, .. }
            | Self::RoundRevoked { at_ms, .. } => *at_ms,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FloraFact {
    pub operation: [u8; 32],
    pub author: [u8; 32],
    pub event: FloraEvent,
}

/// Projection for one round. Invalid or incompatible facts stay in `facts` but
/// are excluded from `viable_candidates`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FloraRoundProjection {
    pub spec: FloraRoundSpec,
    pub global_rank: u16,
    pub contributions: BTreeMap<[u8; 32], FloraContributionReceipt>,
    pub viable_candidates: Vec<FloraCandidateArtifact>,
    pub revoked: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FloraProjection {
    pub facts: Vec<FloraFact>,
    pub rounds: BTreeMap<FloraRoundId, FloraRoundProjection>,
}

impl FloraProjection {
    pub fn fold(mut facts: Vec<FloraFact>) -> Self {
        facts.sort_by_key(|fact| fact.operation);
        let mut specs = BTreeMap::<FloraRoundId, FloraRoundSpec>::new();
        let mut contributions =
            BTreeMap::<FloraRoundId, BTreeMap<[u8; 32], FloraContributionReceipt>>::new();
        let mut candidates = BTreeMap::<FloraRoundId, Vec<FloraCandidateArtifact>>::new();
        let mut revoked = BTreeSet::new();

        for fact in &facts {
            match &fact.event {
                FloraEvent::RoundProposed { spec, .. } if spec.validate().is_ok() => {
                    specs.entry(spec.round).or_insert_with(|| spec.clone());
                }
                FloraEvent::ContributionReceived { contribution, .. }
                    if contribution.participant == fact.author =>
                {
                    contributions
                        .entry(contribution.round)
                        .or_default()
                        .entry(contribution.participant)
                        .or_insert_with(|| contribution.clone());
                }
                FloraEvent::CandidatePublished { candidate, .. } => {
                    candidates
                        .entry(candidate.round)
                        .or_default()
                        .push(candidate.clone());
                }
                FloraEvent::RoundRevoked { round, .. } => {
                    revoked.insert(*round);
                }
                _ => {}
            }
        }

        let rounds = specs
            .into_iter()
            .filter_map(|(round, spec)| {
                let global_rank = spec.validate().ok()?;
                let expected: BTreeSet<_> = spec.participants.keys().copied().collect();
                let received = contributions.remove(&round).unwrap_or_default();
                let compatible: BTreeMap<_, _> = received
                    .into_iter()
                    .filter(|(participant, receipt)| {
                        receipt.round == round
                            && receipt.participant == *participant
                            && spec.participants.contains_key(participant)
                    })
                    .collect();
                let viable_candidates =
                    if revoked.contains(&round) || compatible.len() != expected.len() {
                        Vec::new()
                    } else {
                        candidates
                            .remove(&round)
                            .unwrap_or_default()
                            .into_iter()
                            .filter(|candidate| {
                                candidate.global_rank == global_rank
                                    && candidate.contributors == expected
                                    && candidate.round == round
                            })
                            .collect()
                    };
                Some((
                    round,
                    FloraRoundProjection {
                        spec,
                        global_rank,
                        contributions: compatible,
                        viable_candidates,
                        revoked: revoked.contains(&round),
                    },
                ))
            })
            .collect();
        Self { facts, rounds }
    }
}

/// Signed Moot address on FLORA operations.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FloraExt {
    pub moot_id: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FloraWireError {
    #[error("FLORA operation has no body")]
    MissingBody,
    #[error("FLORA operation body is malformed")]
    Malformed,
}

pub fn to_operation(
    keypair: &Ed25519Keypair,
    moot_id: [u8; 32],
    event: &FloraEvent,
    seq_num: u32,
    backlink: Option<[u8; 32]>,
) -> Operation<FloraExt> {
    to_operation_seed(keypair.to_seed(), moot_id, event, seq_num, backlink)
}

pub fn to_operation_seed(
    signing_seed: [u8; 32],
    moot_id: [u8; 32],
    event: &FloraEvent,
    seq_num: u32,
    backlink: Option<[u8; 32]>,
) -> Operation<FloraExt> {
    let signing_key = SigningKey::from_bytes(&signing_seed);
    let bytes = encode_cbor(event).expect("FLORA events always CBOR-encode");
    let body = Body::from_bytes(&bytes);
    let header = Header::builder()
        .body(&bytes)
        .seq_num(seq_num)
        .backlink(backlink.map(Hash::from))
        .build(&signing_key, FloraExt { moot_id });
    Operation {
        hash: header.hash(),
        header,
        body: Some(body),
    }
}

pub fn from_operation(operation: &Operation<FloraExt>) -> Result<FloraEvent, FloraWireError> {
    let body = operation.body.as_ref().ok_or(FloraWireError::MissingBody)?;
    decode_cbor(body.to_bytes().as_slice()).map_err(|_| FloraWireError::Malformed)
}

pub fn verify(operation: &Operation<FloraExt>) -> bool {
    validate_operation(operation).is_ok() && operation.hash == operation.header.hash()
}

#[derive(Debug, thiserror::Error)]
pub enum FloraStoreError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Process(#[from] ProcessError),
    #[error("malformed FLORA operation")]
    Malformed,
}

#[derive(Clone, Copy)]
struct FloraPolicy {
    moot_id: [u8; 32],
}

impl OperationPolicy<FloraExt> for FloraPolicy {
    type LogId = u64;

    fn admit(&self, operation: &Operation<FloraExt>) -> Result<Admission<Self::LogId>, Reject> {
        if operation.header.extensions.moot_id != self.moot_id {
            return Err(Reject::new(
                "wrong-moot",
                "operation addresses a different moot",
            ));
        }
        from_operation(operation).map_err(|_| {
            Reject::new("invalid-flora-event", "operation body is not a FLORA event")
        })?;
        Ok(Admission::keep(StoreTarget::new(
            Topic::from(self.moot_id),
            LOG_ID,
        )))
    }
}

#[derive(Clone)]
pub struct FloraStore<B> {
    store: MunimentStore<B, FloraExt>,
}

pub type FloraFileStore = FloraStore<RedbBackend>;

impl FloraStore<MemoryBackend> {
    pub fn in_memory() -> Self {
        Self {
            store: MunimentStore::new(MemoryBackend::new()),
        }
    }
}

impl FloraStore<RedbBackend> {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, FloraStoreError> {
        Ok(Self {
            store: MunimentStore::new(RedbBackend::open(path)?),
        })
    }
}

impl<B: Backend + Clone> FloraStore<B> {
    pub fn sync_store(&self) -> MunimentStore<B, FloraExt> {
        self.store.clone()
    }

    pub async fn author_seed(
        &self,
        signing_seed: [u8; 32],
        moot_id: [u8; 32],
        event: &FloraEvent,
    ) -> Result<Operation<FloraExt>, FloraStoreError> {
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
        operation: &Operation<FloraExt>,
    ) -> Result<bool, FloraStoreError> {
        let processor = OperationProcessor::new(self.store.clone(), FloraPolicy { moot_id });
        Ok(processor.process(operation).await?.inserted())
    }

    pub async fn get(&self, hash: &Hash) -> Result<Option<Operation<FloraExt>>, FloraStoreError> {
        Ok(self.store.get_operation(hash).await?)
    }

    pub async fn len(&self) -> Result<usize, FloraStoreError> {
        Ok(self.store.operation_count().await?)
    }

    pub async fn fold_moot(&self, moot_id: [u8; 32]) -> Result<FloraProjection, FloraStoreError> {
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
                        from_operation(&operation).map_err(|_| FloraStoreError::Malformed)?;
                    facts.push(FloraFact {
                        operation: *operation.hash.as_bytes(),
                        author: *operation.header.verifying_key.as_bytes(),
                        event,
                    });
                }
            }
        }
        Ok(FloraProjection::fold(facts))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact(label: &'static [u8]) -> ArtifactRef {
        ArtifactRef::blake3(label)
    }

    fn spec() -> FloraRoundSpec {
        FloraRoundSpec {
            round: FloraRoundId([1; 32]),
            base_model: artifact(b"base"),
            rank_budget: 5,
            participants: BTreeMap::from([
                (
                    [2; 32],
                    FloraParticipant {
                        rank: 2,
                        weight: FloraWeight {
                            numerator: 8,
                            denominator: 2,
                        },
                    },
                ),
                (
                    [3; 32],
                    FloraParticipant {
                        rank: 3,
                        weight: FloraWeight {
                            numerator: 1,
                            denominator: 1,
                        },
                    },
                ),
            ]),
        }
    }

    #[test]
    fn heterogeneous_ranks_sum_exactly_and_budget_is_never_compressed() {
        let round = spec();
        assert_eq!(round.validate(), Ok(5));
        let mut over = round.clone();
        over.rank_budget = 4;
        assert_eq!(
            over.validate(),
            Err(FloraValidationError::RankBudgetExceeded {
                global_rank: 5,
                budget: 4,
            })
        );
        assert!(FloraStacking::A_VERTICALLY_STACKED);
        assert!(FloraStacking::B_HORIZONTALLY_STACKED);
        assert!(FloraStacking::SCALE_B_ONLY);
    }

    #[test]
    fn compatibility_requires_every_receipt_and_the_exact_global_rank() {
        let round = spec();
        let contribution = |participant| FloraContributionReceipt {
            round: round.round,
            participant,
            a_factor: artifact(b"a"),
            b_factor: artifact(b"b"),
            receipt: artifact(b"receipt"),
        };
        let events = vec![
            FloraFact {
                operation: [1; 32],
                author: [9; 32],
                event: FloraEvent::RoundProposed {
                    spec: round.clone(),
                    at_ms: 1,
                },
            },
            FloraFact {
                operation: [2; 32],
                author: [2; 32],
                event: FloraEvent::ContributionReceived {
                    contribution: contribution([2; 32]),
                    at_ms: 2,
                },
            },
            FloraFact {
                operation: [3; 32],
                author: [3; 32],
                event: FloraEvent::ContributionReceived {
                    contribution: contribution([3; 32]),
                    at_ms: 3,
                },
            },
            FloraFact {
                operation: [4; 32],
                author: [9; 32],
                event: FloraEvent::CandidatePublished {
                    candidate: FloraCandidateArtifact {
                        round: round.round,
                        adapter: artifact(b"adapter"),
                        global_rank: 4,
                        contributors: BTreeSet::from([[2; 32], [3; 32]]),
                    },
                    at_ms: 4,
                },
            },
            FloraFact {
                operation: [5; 32],
                author: [9; 32],
                event: FloraEvent::CandidatePublished {
                    candidate: FloraCandidateArtifact {
                        round: round.round,
                        adapter: artifact(b"adapter"),
                        global_rank: 5,
                        contributors: BTreeSet::from([[2; 32], [3; 32]]),
                    },
                    at_ms: 5,
                },
            },
        ];
        let projection = FloraProjection::fold(events.clone());
        let backwards = FloraProjection::fold(events.into_iter().rev().collect());
        assert_eq!(projection, backwards);
        let projected = projection.rounds.get(&round.round).unwrap();
        assert_eq!(projected.global_rank, 5);
        assert_eq!(projected.viable_candidates.len(), 1);
    }
}
