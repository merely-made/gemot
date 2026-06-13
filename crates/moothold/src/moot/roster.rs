/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

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

use p2panda_core::Operation;

use super::wire::{from_operation, verify, MootEvent, MootExt};

/// The founding statement, as resolved by the fold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Declaration {
    pub name: String,
    pub charter: String,
    /// The declaring author's verifying-key bytes.
    pub by: [u8; 32],
    pub at_ms: u64,
}

/// One visible member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    /// Display label from the member's first `Joined`.
    pub name: String,
    pub joined_at_ms: u64,
}

/// One engram reference in the flora.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FloraEntry {
    pub manifest_id: [u8; 32],
    pub schema_id: String,
    pub title: String,
    /// The sharing author's verifying-key bytes.
    pub shared_by: [u8; 32],
    pub at_ms: u64,
    /// The sharing operation's hash (the stable tiebreak + a citation).
    pub op_hash: [u8; 32],
}

/// The folded moot: founding, membership, flora.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MootRoster {
    pub declaration: Option<Declaration>,
    /// Members keyed by author (verifying-key bytes), iteration-stable.
    pub members: BTreeMap<[u8; 32], Member>,
    /// Flora entries in `(at_ms, op_hash)` order.
    pub flora: Vec<FloraEntry>,
}

impl MootRoster {
    /// Fold a set of operations into a roster. Order-independent; ops that
    /// fail signature verification, decode, or address a different moot are
    /// skipped (defence in depth behind the sync drain's checks).
    pub fn fold<'a, I>(moot_id: [u8; 32], ops: I) -> Self
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
        let mut flora: Vec<FloraEntry> = Vec::new();

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
                MootEvent::Declared { name, charter, at_ms } => {
                    declarations.insert(
                        op_hash,
                        Declaration {
                            name,
                            charter,
                            by: author,
                            at_ms,
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
                    flora.push(FloraEntry {
                        manifest_id,
                        schema_id,
                        title,
                        shared_by: author,
                        at_ms,
                        op_hash,
                    });
                }
            }
        }

        // Resolve.
        let declaration = declarations.into_iter().next().map(|(_, d)| d);
        let members = joins
            .into_iter()
            .map(|(author, (joined_at_ms, _, name))| (author, Member { name, joined_at_ms }))
            .collect();
        flora.sort_by(|a, b| (a.at_ms, a.op_hash).cmp(&(b.at_ms, b.op_hash)));

        Self {
            declaration,
            members,
            flora,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::moot::wire::to_operation;
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
        assert_eq!(roster.flora.len(), 1);
        assert_eq!(roster.flora[0].schema_id, "eidetic.SearchIndexSpec/v1");
        assert_eq!(roster.flora[0].shared_by, author(&friend));
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
    fn flora_order_is_stable_and_foreign_moot_ops_are_skipped() {
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
        assert_eq!(roster.flora.len(), 2, "foreign-moot share skipped");
        assert_eq!(roster.flora[0].title, "early");
        assert_eq!(roster.flora[1].title, "late");
    }
}
