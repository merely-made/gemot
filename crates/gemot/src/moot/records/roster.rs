// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The moot roster — a deterministic, order-independent fold of moot events.
//!
//! Every member folds the same op set into the same roster regardless of
//! arrival order (the rule the mesh board proved): gather first, then
//! resolve.
//!
//! - **Competing declarations resolve by lowest declaring-op hash** — one
//!   founding, the same on every member, a pure function of the op set.
//! - **First join per author wins** — re-joins and label changes don't
//!   churn membership (a rename event is a later milestone).
//! - **Fauna order is `(at_ms, op_hash)`** — stable everywhere, ties broken
//!   content-addressably.

use std::collections::BTreeMap;

use mooting::{ElectorateSnapshot, RecognitionContext, RecognitionPolicy};
use p2panda_core::{Hash, Operation};
use serde::{Deserialize, Serialize};

use servitor::{AuthorityProvider, Cap, Mode, Subject};

use super::collection::CollectionFact;
use super::retention::MootRosterSnapshot;
use super::wire::{MootEvent, MootExt, from_operation, stable_author, verify};

/// The founding statement, as resolved by the fold.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Declaration {
    pub name: String,
    pub charter: String,
    /// The declaring author's verifying-key bytes.
    pub by: [u8; 32],
    pub at_ms: u64,
    /// Winning declaration operation, retained as checkpoint fold evidence.
    pub op_hash: [u8; 32],
}

/// One visible member.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    /// Display label from the member's first `Joined`.
    pub name: String,
    pub joined_at_ms: u64,
    /// Winning join operation, retained as checkpoint fold evidence.
    pub join_op_hash: [u8; 32],
}

/// One codicil reference in the fauna.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaunaEntry {
    pub manifest_id: [u8; 32],
    pub schema_id: String,
    pub title: String,
    /// The sharing author's verifying-key bytes.
    pub shared_by: [u8; 32],
    pub at_ms: u64,
    /// The sharing operation's hash (the stable tiebreak + a citation).
    pub op_hash: [u8; 32],
}

/// One signed withdrawal fact for a single `Shared` operation.
///
/// The withdrawing root is resolved from the operation's stable identity
/// binding during the fold. Withdrawal facts stay in the roster after they
/// affect the authorized projection, which lets callers inspect consent and
/// audit history without retaining a live contribution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaunaWithdrawal {
    /// The original `Shared` operation being withdrawn.
    pub target_share: [u8; 32],
    /// Stable Personae root of the withdrawing contributor.
    pub withdrawn_by: [u8; 32],
    pub at_ms: u64,
    /// The signed withdrawal operation's hash.
    pub op_hash: [u8; 32],
}

/// The capability a sharer must hold for their contribution to count as part
/// of the moot's commons: the typed scope `moot/fauna`
/// (`scope/moot/fauna` on the wire, per the capability-model encoding).
pub fn fauna_cap() -> Cap {
    Cap::scope("moot/fauna").expect("a valid scope")
}

/// The folded moot: founding, membership, fauna.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MootRoster {
    pub declaration: Option<Declaration>,
    /// Members keyed by author (verifying-key bytes), iteration-stable.
    pub members: BTreeMap<[u8; 32], Member>,
    /// Commitment over the winning signed membership operations only.
    pub membership_revision: [u8; 32],
    /// Fauna entries in `(at_ms, op_hash)` order.
    pub fauna: Vec<FaunaEntry>,
    /// Withdrawal facts in `(target_share, at_ms, op_hash)` order.
    #[serde(default)]
    pub withdrawals: Vec<FaunaWithdrawal>,
    /// Raw signed collection facts, retained independently of current authority.
    #[serde(default)]
    pub collections: Vec<CollectionFact>,
    /// Raw signed workflow facts survive snapshots and authority changes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub workflow: Vec<super::super::workflow::WorkflowFact>,
}

impl MootRoster {
    /// Freeze this roster's members for a recognition decision.
    pub fn electorate_snapshot(&self, moot_id: [u8; 32]) -> ElectorateSnapshot {
        ElectorateSnapshot::new(
            moot_id,
            self.membership_revision,
            self.members.keys().copied(),
        )
    }

    /// Bind a configured policy to this roster at one signed revision.
    pub fn recognition_context(
        &self,
        moot_id: [u8; 32],
        policy: RecognitionPolicy,
    ) -> RecognitionContext {
        RecognitionContext::new(policy, self.electorate_snapshot(moot_id))
    }

    /// The commons **as converged authority sees it**: fauna entries whose
    /// sharer holds [`fauna_cap`] under `authority`, in the roster's order.
    ///
    /// Authority is applied here, at read, rather than at admission — and that
    /// is a correctness requirement, not a preference. Authority state
    /// (delegation certificates, constitution amendments) converges
    /// *separately* from the operations it authorizes, so an operation can
    /// legitimately arrive before the certificate that authorizes it:
    /// out-of-order sync, a late-joining peer, a drop import. Refusing at
    /// admission would permanently discard operations that become authorized
    /// moments later, with no retry, because the operation is gone. Evaluating
    /// here cannot fail that way: the same entry becomes visible the moment
    /// its certificate lands, and stops being visible the moment it is
    /// revoked — the identical read-time discipline
    /// [`MootDelegations`](crate::moot::MootDelegations) already applies to
    /// chain validity.
    ///
    /// The division of labour: **admission validates what one operation can
    /// prove about itself** (signature, moot address, wire grammar, prune
    /// flag — all self-contained); **the fold and this projection decide what
    /// converged authority makes effective.**
    ///
    /// [`fauna`](Self::fauna) remains the unfiltered convergent record, so
    /// nothing is lost and an entry can be shown as pending rather than
    /// silently dropped.
    pub fn authorized_fauna(&self, authority: &impl AuthorityProvider) -> Vec<&FaunaEntry> {
        let cap = fauna_cap();
        self.fauna
            .iter()
            .filter(|entry| {
                authority.covers(Subject::new(entry.shared_by), &cap, Mode::Write)
                    && !self.withdrawals.iter().any(|withdrawal| {
                        withdrawal.target_share == entry.op_hash
                            && withdrawal.withdrawn_by == entry.shared_by
                    })
            })
            .collect()
    }

    /// Fold a set of operations into a roster. Order-independent; ops that
    /// fail signature verification, decode, or address a different moot are
    /// skipped (defence in depth behind the sync drain's checks).
    pub fn fold<'a, I>(moot_id: [u8; 32], ops: I) -> Self
    where
        I: IntoIterator<Item = &'a Operation<MootExt>>,
    {
        Self::fold_from_snapshot(moot_id, &MootRosterSnapshot::default(), ops)
    }

    /// Replay a retained checkpoint plus operations after its frontier.
    pub fn fold_from_snapshot<'a, I>(
        moot_id: [u8; 32],
        snapshot: &MootRosterSnapshot,
        ops: I,
    ) -> Self
    where
        I: IntoIterator<Item = &'a Operation<MootExt>>,
    {
        // Gather.
        // declaring-op hash → declaration; BTreeMap gives the lowest-hash
        // winner for free.
        let mut declarations: BTreeMap<[u8; 32], Declaration> = BTreeMap::new();
        // author → (joined_at_ms, op hash, name); earliest join wins, hash
        // breaks at_ms ties deterministically.
        let mut joins: BTreeMap<[u8; 32], (u64, [u8; 32], String)> = BTreeMap::new();
        let mut fauna: Vec<FaunaEntry> = Vec::new();
        let mut withdrawals: BTreeMap<[u8; 32], FaunaWithdrawal> = BTreeMap::new();
        let mut collections: BTreeMap<[u8; 32], CollectionFact> = BTreeMap::new();
        let mut workflow = BTreeMap::new();
        for fact in &snapshot.roster.workflow {
            if fact.verified_for(moot_id) {
                workflow.insert(fact.op_hash, fact.clone());
            }
        }

        if let Some(declaration) = &snapshot.roster.declaration {
            declarations.insert(declaration.op_hash, declaration.clone());
        }
        for (author, member) in &snapshot.roster.members {
            joins.insert(
                *author,
                (
                    member.joined_at_ms,
                    member.join_op_hash,
                    member.name.clone(),
                ),
            );
        }
        fauna.extend(snapshot.roster.fauna.iter().cloned());
        for withdrawal in &snapshot.roster.withdrawals {
            withdrawals.insert(withdrawal.op_hash, withdrawal.clone());
        }
        for fact in &snapshot.roster.collections {
            collections.insert(fact.op_hash, fact.clone());
        }

        for op in ops {
            if !verify(op) {
                continue;
            }
            let Ok((id, event)) = from_operation(op) else {
                continue;
            };
            if id != moot_id {
                continue;
            }
            let Ok(author) = stable_author(op) else {
                continue;
            };
            let op_hash = *op.hash.as_bytes();
            match event {
                MootEvent::Declared {
                    name,
                    charter,
                    at_ms,
                } => {
                    declarations.insert(
                        op_hash,
                        Declaration {
                            name,
                            charter,
                            by: author,
                            at_ms,
                            op_hash,
                        },
                    );
                }
                MootEvent::Joined { name, at_ms } => {
                    let candidate = (at_ms, op_hash, name);
                    joins
                        .entry(author)
                        .and_modify(|existing| {
                            if (candidate.0, candidate.1) < (existing.0, existing.1) {
                                *existing = candidate.clone();
                            }
                        })
                        .or_insert(candidate);
                }
                MootEvent::Shared {
                    manifest_id,
                    schema_id,
                    title,
                    at_ms,
                } => {
                    fauna.push(FaunaEntry {
                        manifest_id,
                        schema_id,
                        title,
                        shared_by: author,
                        at_ms,
                        op_hash,
                    });
                }
                MootEvent::Withdrawn {
                    target_share,
                    at_ms,
                } => {
                    withdrawals.entry(op_hash).or_insert(FaunaWithdrawal {
                        target_share,
                        withdrawn_by: author,
                        at_ms,
                        op_hash,
                    });
                }
                MootEvent::Collection { event } => {
                    collections.entry(op_hash).or_insert(CollectionFact {
                        event,
                        by: author,
                        op_hash,
                    });
                }
                MootEvent::Workflow { .. } => {
                    if let Some(fact) = super::super::workflow::WorkflowFact::from_operation(op) {
                        workflow.insert(op_hash, fact);
                    }
                }
                MootEvent::RetentionCheckpoint { .. } | MootEvent::HistoryPruned { .. } => {}
            }
        }

        // Resolve.
        let declaration = declarations.into_iter().next().map(|(_, d)| d);
        let membership_revision = membership_revision(&joins);
        let members = joins
            .into_iter()
            .map(|(author, (joined_at_ms, join_op_hash, name))| {
                (
                    author,
                    Member {
                        name,
                        joined_at_ms,
                        join_op_hash,
                    },
                )
            })
            .collect();
        fauna.sort_by_key(|entry| (entry.at_ms, entry.op_hash));
        let mut withdrawals: Vec<_> = withdrawals.into_values().collect();
        withdrawals.sort_by_key(|withdrawal| {
            (
                withdrawal.target_share,
                withdrawal.at_ms,
                withdrawal.op_hash,
            )
        });
        let collections = collections.into_values().collect();

        Self {
            declaration,
            members,
            membership_revision,
            fauna,
            withdrawals,
            collections,
            workflow: workflow.into_values().collect(),
        }
    }
}

impl Default for MootRoster {
    fn default() -> Self {
        Self {
            declaration: None,
            members: BTreeMap::new(),
            membership_revision: membership_revision(&BTreeMap::new()),
            fauna: Vec::new(),
            withdrawals: Vec::new(),
            collections: Vec::new(),
            workflow: Vec::new(),
        }
    }
}

fn membership_revision(joins: &BTreeMap<[u8; 32], (u64, [u8; 32], String)>) -> [u8; 32] {
    let mut bytes = b"gemot/moot-membership/v1\0".to_vec();
    for (author, (_, operation, _)) in joins {
        bytes.extend_from_slice(author);
        bytes.extend_from_slice(operation);
    }
    *Hash::digest(bytes).as_bytes()
}

#[cfg(test)]
#[path = "roster/tests.rs"]
mod tests;
