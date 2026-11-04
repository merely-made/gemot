// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Causal, contribution-preserving collection history inside one Moot.

use std::collections::{BTreeMap, BTreeSet};

use p2panda_core::Hash;
use serde::{Deserialize, Serialize};
use servitor::{AuthorityProvider, Cap, Mode, Subject};

use super::{FaunaEntry, MootRoster};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CollectionId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CollectionRef {
    pub moot_id: [u8; 32],
    pub collection_id: CollectionId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ContributionRef {
    pub moot_id: [u8; 32],
    /// The original signed `Shared` operation, not its payload manifest.
    pub share: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionVersion {
    pub collection: CollectionRef,
    /// Sorted causal heads represented by this version.
    pub frontier: Vec<[u8; 32]>,
    pub membership_commitment: [u8; 32],
}

impl CollectionVersion {
    pub fn new(
        collection: CollectionRef,
        mut frontier: Vec<[u8; 32]>,
        selected: &[ContributionRef],
    ) -> Self {
        frontier.sort();
        frontier.dedup();
        Self {
            collection,
            frontier,
            membership_commitment: membership_commitment(selected),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionFork {
    pub parent: CollectionVersion,
    /// Materialized references allow the child root to survive source-log pruning.
    pub selected: Vec<ContributionRef>,
    pub seed_commitment: [u8; 32],
}

impl CollectionFork {
    pub fn new(parent: CollectionVersion, selected: Vec<ContributionRef>) -> Self {
        let selected = canonical_members(selected);
        let seed_commitment = membership_commitment(&selected);
        Self {
            parent,
            selected,
            seed_commitment,
        }
    }

    pub fn verifies(&self) -> bool {
        self.selected == canonical_members(self.selected.clone())
            && self.seed_commitment == membership_commitment(&self.selected)
            && self.parent.membership_commitment == self.seed_commitment
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CollectionChange {
    SetMembership {
        contribution: ContributionRef,
        included: bool,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CollectionEvent {
    Declared {
        collection_id: CollectionId,
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fork: Option<CollectionFork>,
        at_ms: u64,
    },
    Changed {
        collection: CollectionRef,
        /// Exact heads observed by the author.
        parents: Vec<[u8; 32]>,
        change: CollectionChange,
        at_ms: u64,
    },
}

impl CollectionEvent {
    pub fn at_ms(&self) -> u64 {
        match self {
            Self::Declared { at_ms, .. } | Self::Changed { at_ms, .. } => *at_ms,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionFact {
    pub event: CollectionEvent,
    pub by: [u8; 32],
    pub op_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectionCitation {
    pub contribution: ContributionRef,
    pub collection_operation: [u8; 32],
    pub effective: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PendingCollectionReason {
    ForeignReference,
    MissingParent([u8; 32]),
    InvalidForkCommitment,
    IneffectiveContribution(ContributionRef),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingCollectionFact {
    pub op_hash: [u8; 32],
    pub reason: PendingCollectionReason,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectionView {
    pub collection: CollectionRef,
    pub name: String,
    pub selected: Vec<ContributionRef>,
    pub effective_selected: Vec<ContributionRef>,
    pub citations: Vec<SelectionCitation>,
    pub heads: Vec<[u8; 32]>,
    pub version: CollectionVersion,
    pub fork: Option<CollectionFork>,
    pub pending: Vec<PendingCollectionFact>,
}

pub fn collection_cap(collection: CollectionRef) -> Cap {
    let mut suffix = String::with_capacity(64);
    for byte in collection.collection_id.0 {
        suffix.push_str(&format!("{byte:02x}"));
    }
    Cap::scope(&format!("moot/collection/{suffix}")).expect("a valid collection scope")
}

pub fn membership_commitment(selected: &[ContributionRef]) -> [u8; 32] {
    let selected = canonical_members(selected.to_vec());
    let mut bytes = b"gemot/collection-membership/v1\0".to_vec();
    for member in selected {
        bytes.extend_from_slice(&member.moot_id);
        bytes.extend_from_slice(&member.share);
    }
    *Hash::digest(bytes).as_bytes()
}

pub(crate) fn canonical_members(mut selected: Vec<ContributionRef>) -> Vec<ContributionRef> {
    selected.sort();
    selected.dedup();
    selected
}

impl MootRoster {
    /// Resolve an effective same-Moot collection while retaining every raw fact.
    pub fn authorized_collection(
        &self,
        moot_id: [u8; 32],
        collection_id: CollectionId,
        authority: &impl AuthorityProvider,
    ) -> Option<CollectionView> {
        let collection = CollectionRef {
            moot_id,
            collection_id,
        };
        let cap = collection_cap(collection);
        let effective_fauna: BTreeMap<_, &FaunaEntry> = self
            .authorized_fauna(authority)
            .into_iter()
            .map(|entry| (entry.op_hash, entry))
            .collect();
        let mut facts: Vec<_> = self
            .collections
            .iter()
            .filter(|fact| {
                let addressed = match &fact.event {
                    CollectionEvent::Declared {
                        collection_id: id, ..
                    } => *id == collection_id,
                    CollectionEvent::Changed {
                        collection: addressed,
                        ..
                    } => addressed.collection_id == collection_id,
                };
                addressed && authority.covers(Subject::new(fact.by), &cap, Mode::Write)
            })
            .cloned()
            .collect();
        facts.sort_by_key(|fact| fact.op_hash);
        let mut pending = Vec::new();
        let fact = facts
            .iter()
            .find(|fact| matches!(fact.event, CollectionEvent::Declared { .. }))?;
        let CollectionEvent::Declared { name, fork, .. } = &fact.event else {
            unreachable!()
        };
        if let Some(seed) = fork {
            if !seed.verifies() {
                pending.push(PendingCollectionFact {
                    op_hash: fact.op_hash,
                    reason: PendingCollectionReason::InvalidForkCommitment,
                });
            }
            if seed.parent.collection.moot_id != moot_id
                || seed.selected.iter().any(|member| member.moot_id != moot_id)
            {
                pending.push(PendingCollectionFact {
                    op_hash: fact.op_hash,
                    reason: PendingCollectionReason::ForeignReference,
                });
            }
        }
        let (declaration, name, fork) = (fact.clone(), name.clone(), fork.clone());
        type MemberState = BTreeMap<ContributionRef, (bool, [u8; 32])>;
        let root: MemberState = fork
            .as_ref()
            .filter(|seed| {
                seed.verifies()
                    && seed.parent.collection.moot_id == moot_id
                    && seed.selected.iter().all(|member| member.moot_id == moot_id)
            })
            .map_or_else(Vec::new, |seed| seed.selected.clone())
            .into_iter()
            .map(|member| (member, (true, declaration.op_hash)))
            .collect();
        let mut accepted: BTreeMap<[u8; 32], MemberState> = BTreeMap::new();
        accepted.insert(declaration.op_hash, root);
        let mut causal_parents: BTreeMap<[u8; 32], Vec<[u8; 32]>> = BTreeMap::new();
        causal_parents.insert(declaration.op_hash, Vec::new());
        let mut remaining: Vec<_> = facts
            .into_iter()
            .filter(|f| f.op_hash != declaration.op_hash)
            .collect();
        loop {
            let mut progressed = false;
            let mut next = Vec::new();
            for fact in remaining {
                let CollectionEvent::Changed {
                    collection: addressed,
                    parents,
                    change,
                    ..
                } = &fact.event
                else {
                    continue;
                };
                if addressed.moot_id != moot_id {
                    pending.push(PendingCollectionFact {
                        op_hash: fact.op_hash,
                        reason: PendingCollectionReason::ForeignReference,
                    });
                    continue;
                }
                let mut parents = parents.clone();
                parents.sort();
                parents.dedup();
                if parents.is_empty() || parents.iter().any(|parent| !accepted.contains_key(parent))
                {
                    next.push(fact);
                    continue;
                }
                let CollectionChange::SetMembership {
                    contribution,
                    included,
                } = change;
                if contribution.moot_id != moot_id {
                    pending.push(PendingCollectionFact {
                        op_hash: fact.op_hash,
                        reason: PendingCollectionReason::ForeignReference,
                    });
                    continue;
                }
                let mut state = MemberState::new();
                for parent in &parents {
                    for (member, candidate) in accepted.get(parent).expect("checked parent") {
                        state
                            .entry(*member)
                            .and_modify(|current| {
                                if prefer_candidate(candidate.1, current.1, &causal_parents) {
                                    *current = *candidate;
                                }
                            })
                            .or_insert(*candidate);
                    }
                }
                state.insert(*contribution, (*included, fact.op_hash));
                causal_parents.insert(fact.op_hash, parents);
                accepted.insert(fact.op_hash, state);
                progressed = true;
            }
            if !progressed {
                for fact in next {
                    if let CollectionEvent::Changed { parents, .. } = fact.event {
                        let missing = parents
                            .into_iter()
                            .find(|p| !accepted.contains_key(p))
                            .unwrap_or([0; 32]);
                        pending.push(PendingCollectionFact {
                            op_hash: fact.op_hash,
                            reason: PendingCollectionReason::MissingParent(missing),
                        });
                    }
                }
                break;
            }
            remaining = next;
        }
        let parented: BTreeSet<_> = self
            .collections
            .iter()
            .filter_map(|fact| match &fact.event {
                CollectionEvent::Changed {
                    collection: addressed,
                    parents,
                    ..
                } if *addressed == collection && accepted.contains_key(&fact.op_hash) => {
                    Some(parents.clone())
                }
                _ => None,
            })
            .flatten()
            .collect();
        let mut heads: Vec<_> = accepted
            .keys()
            .filter(|hash| !parented.contains(*hash))
            .copied()
            .collect();
        heads.sort();
        let mut state = MemberState::new();
        for head in &heads {
            for (member, candidate) in accepted.get(head)? {
                state
                    .entry(*member)
                    .and_modify(|current| {
                        if prefer_candidate(candidate.1, current.1, &causal_parents) {
                            *current = *candidate;
                        }
                    })
                    .or_insert(*candidate);
            }
        }
        let selected: Vec<_> = state
            .iter()
            .filter_map(|(member, (included, _))| included.then_some(*member))
            .collect();
        let mut effective_selected = Vec::new();
        let mut citations = Vec::new();
        for reference in &selected {
            let (_, citation) = state.get(reference).expect("selected state");
            let effective = effective_fauna.contains_key(&reference.share);
            citations.push(SelectionCitation {
                contribution: *reference,
                collection_operation: *citation,
                effective,
            });
            if effective {
                effective_selected.push(*reference);
            } else {
                pending.push(PendingCollectionFact {
                    op_hash: *citation,
                    reason: PendingCollectionReason::IneffectiveContribution(*reference),
                });
            }
        }
        let version = CollectionVersion::new(collection, heads.clone(), &selected);
        pending.sort_by_key(|item| item.op_hash);
        Some(CollectionView {
            collection,
            name,
            selected,
            effective_selected,
            citations,
            heads,
            version,
            fork,
            pending,
        })
    }
}

fn prefer_candidate(
    candidate: [u8; 32],
    current: [u8; 32],
    parents: &BTreeMap<[u8; 32], Vec<[u8; 32]>>,
) -> bool {
    if observes(candidate, current, parents) {
        true
    } else if observes(current, candidate, parents) {
        false
    } else {
        candidate < current
    }
}

fn observes(
    descendant: [u8; 32],
    ancestor: [u8; 32],
    parents: &BTreeMap<[u8; 32], Vec<[u8; 32]>>,
) -> bool {
    let mut stack = parents.get(&descendant).cloned().unwrap_or_default();
    let mut seen = BTreeSet::new();
    while let Some(next) = stack.pop() {
        if next == ancestor {
            return true;
        }
        if seen.insert(next) {
            stack.extend(parents.get(&next).into_iter().flatten().copied());
        }
    }
    false
}

#[cfg(test)]
#[path = "collection/tests.rs"]
mod tests;
