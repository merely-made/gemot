// Copyright 2026 Mark AB (markik)
// SPDX-License-Identifier: MIT OR Apache-2.0

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
//! - **Flora order is `(at_ms, op_hash)`** — stable everywhere, ties broken
//!   content-addressably.

use std::collections::BTreeMap;

use mooting::{ElectorateSnapshot, RecognitionContext, RecognitionPolicy};
use p2panda_core::{Hash, Operation};
use serde::{Deserialize, Serialize};

use servitor::{AuthorityProvider, Cap, Mode, Subject};

use super::retention::MootRosterSnapshot;
use super::wire::{MootEvent, MootExt, from_operation, verify};

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

/// One engram reference in the fauna.
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
            let author = *op.header.verifying_key.as_bytes();
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
        fauna.sort_by(|a, b| (a.at_ms, a.op_hash).cmp(&(b.at_ms, b.op_hash)));

        Self {
            declaration,
            members,
            membership_revision,
            fauna,
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
mod tests {
    use super::*;
    use crate::moot::records::wire::to_operation;
    use identity::{Ed25519Keypair, IdentityProvider, InMemoryProvider};

    const MOOT: [u8; 32] = [0x6d; 32];

    fn keypair(seed: u8) -> Ed25519Keypair {
        InMemoryProvider::from_seed([seed; 32])
            .derive_keypair(b"moot-roster")
            .unwrap()
    }

    fn author(kp: &Ed25519Keypair) -> [u8; 32] {
        kp.public_key().to_bytes()
    }

    #[test]
    fn declare_join_share_folds_into_the_roster() {
        let founder = keypair(1);
        let friend = keypair(2);

        let declared = to_operation(
            &founder,
            MOOT,
            &MootEvent::Declared {
                name: "printing circle".into(),
                charter: "we share what we set in type".into(),
                at_ms: 10,
            },
            0,
            None,
        );
        let founder_join = to_operation(
            &founder,
            MOOT,
            &MootEvent::Joined {
                name: "mark".into(),
                at_ms: 11,
            },
            1,
            Some(*declared.hash.as_bytes()),
        );
        let friend_join = to_operation(
            &friend,
            MOOT,
            &MootEvent::Joined {
                name: "alex".into(),
                at_ms: 12,
            },
            0,
            None,
        );
        let shared = to_operation(
            &friend,
            MOOT,
            &MootEvent::Shared {
                manifest_id: [0xaa; 32],
                schema_id: "eidetic.SearchIndexSpec/v1".into(),
                title: "my trail index".into(),
                at_ms: 13,
            },
            1,
            Some(*friend_join.hash.as_bytes()),
        );

        let roster = MootRoster::fold(MOOT, [&declared, &founder_join, &friend_join, &shared]);
        let declaration = roster.declaration.as_ref().expect("founded");
        assert_eq!(declaration.name, "printing circle");
        assert_eq!(declaration.by, author(&founder));
        assert_eq!(roster.members.len(), 2);
        assert_eq!(roster.members[&author(&friend)].name, "alex");
        assert_eq!(roster.fauna.len(), 1);
        assert_eq!(roster.fauna[0].schema_id, "eidetic.SearchIndexSpec/v1");
        assert_eq!(roster.fauna[0].shared_by, author(&friend));
        // The pack hand-off (participant gate B5's curation half): a shared
        // engram whose schema is mere.pack/v1 lists in the fauna like any
        // other — the moot's flora IS where a distributed pack becomes
        // discoverable, no pack-specific wire needed.
        let pack_shared = to_operation(
            &friend,
            MOOT,
            &MootEvent::Shared {
                manifest_id: [0xbb; 32],
                schema_id: "mere.pack/v1".into(),
                title: "trail-keeper 0.1.0".into(),
                at_ms: 14,
            },
            2,
            Some(*shared.hash.as_bytes()),
        );
        let with_pack =
            MootRoster::fold(MOOT, [&declared, &founder_join, &friend_join, &shared, &pack_shared]);
        assert_eq!(with_pack.fauna.len(), 2);
        assert!(
            with_pack
                .fauna
                .iter()
                .any(|f| f.schema_id == "mere.pack/v1" && f.title == "trail-keeper 0.1.0"),
            "the pack is visible in the moot's flora under its schema"
        );

        let without_fauna = MootRoster::fold(MOOT, [&declared, &founder_join, &friend_join]);
        assert_eq!(
            roster.membership_revision, without_fauna.membership_revision,
            "non-membership events do not invalidate policy contexts"
        );
    }

    #[test]
    fn a_declaration_race_resolves_identically_in_both_fold_orders() {
        let a = keypair(1);
        let b = keypair(2);
        let decl_a = to_operation(
            &a,
            MOOT,
            &MootEvent::Declared {
                name: "a's founding".into(),
                charter: "a".into(),
                at_ms: 10,
            },
            0,
            None,
        );
        let decl_b = to_operation(
            &b,
            MOOT,
            &MootEvent::Declared {
                name: "b's founding".into(),
                charter: "b".into(),
                at_ms: 10,
            },
            0,
            None,
        );

        let one = MootRoster::fold(MOOT, [&decl_a, &decl_b]);
        let two = MootRoster::fold(MOOT, [&decl_b, &decl_a]);
        assert_eq!(one, two, "fold is order-independent");

        let expected = if decl_a.hash.as_bytes() < decl_b.hash.as_bytes() {
            "a's founding"
        } else {
            "b's founding"
        };
        assert_eq!(one.declaration.unwrap().name, expected);
    }

    #[test]
    fn roster_freezes_members_into_a_recognition_context() {
        let founder = keypair(1);
        let friend = keypair(2);
        let founder_join = to_operation(
            &founder,
            MOOT,
            &MootEvent::Joined {
                name: "mark".into(),
                at_ms: 1,
            },
            0,
            None,
        );
        let friend_join = to_operation(
            &friend,
            MOOT,
            &MootEvent::Joined {
                name: "alex".into(),
                at_ms: 2,
            },
            0,
            None,
        );
        let roster = MootRoster::fold(MOOT, [&founder_join, &friend_join]);
        let context =
            roster.recognition_context(MOOT, RecognitionPolicy::Threshold { required: 2 });
        assert_eq!(context.electorate.group_id, MOOT);
        assert_eq!(context.electorate.revision, roster.membership_revision);
        assert_eq!(context.electorate.members.len(), 2);
    }

    #[test]
    fn duplicate_joins_collapse_to_the_first() {
        let member = keypair(3);
        let first = to_operation(
            &member,
            MOOT,
            &MootEvent::Joined {
                name: "early".into(),
                at_ms: 5,
            },
            0,
            None,
        );
        let again = to_operation(
            &member,
            MOOT,
            &MootEvent::Joined {
                name: "later".into(),
                at_ms: 9,
            },
            1,
            Some(*first.hash.as_bytes()),
        );
        let roster = MootRoster::fold(MOOT, [&again, &first]);
        assert_eq!(roster.members.len(), 1);
        let member_info = roster.members.values().next().unwrap();
        assert_eq!(member_info.name, "early");
        assert_eq!(member_info.joined_at_ms, 5);
    }

    #[test]
    fn fauna_order_is_stable_and_foreign_moot_ops_are_skipped() {
        let kp = keypair(4);
        let here_late = to_operation(
            &kp,
            MOOT,
            &MootEvent::Shared {
                manifest_id: [1; 32],
                schema_id: "s".into(),
                title: "late".into(),
                at_ms: 20,
            },
            0,
            None,
        );
        let here_early = to_operation(
            &kp,
            MOOT,
            &MootEvent::Shared {
                manifest_id: [2; 32],
                schema_id: "s".into(),
                title: "early".into(),
                at_ms: 10,
            },
            1,
            Some(*here_late.hash.as_bytes()),
        );
        let elsewhere = to_operation(
            &kp,
            [0xee; 32],
            &MootEvent::Shared {
                manifest_id: [3; 32],
                schema_id: "s".into(),
                title: "other moot".into(),
                at_ms: 1,
            },
            2,
            Some(*here_early.hash.as_bytes()),
        );

        let roster = MootRoster::fold(MOOT, [&here_late, &here_early, &elsewhere]);
        assert_eq!(roster.fauna.len(), 2, "foreign-moot share skipped");
        assert_eq!(roster.fauna[0].title, "early");
        assert_eq!(roster.fauna[1].title, "late");
    }
}
