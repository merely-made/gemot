// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

struct Allowed(BTreeSet<[u8; 32]>);
impl AuthorityProvider for Allowed {
    fn covers(&self, subject: Subject, _: &Cap, mode: Mode) -> bool {
        mode == Mode::Write && self.0.contains(&subject.0)
    }
}

const MOOT: [u8; 32] = [0x6d; 32];
const CURATOR: [u8; 32] = [0xc0; 32];
const SHARER: [u8; 32] = [0x51; 32];

fn reference(tag: u8) -> ContributionRef {
    ContributionRef {
        moot_id: MOOT,
        share: [tag; 32],
    }
}

fn fact(hash: u8, event: CollectionEvent) -> CollectionFact {
    CollectionFact {
        event,
        by: CURATOR,
        op_hash: [hash; 32],
    }
}

fn roster_with_fauna() -> MootRoster {
    let mut roster = MootRoster::default();
    for tag in 1..=4 {
        roster.fauna.push(FaunaEntry {
            manifest_id: [tag; 32],
            schema_id: "test".into(),
            title: format!("share {tag}"),
            shared_by: SHARER,
            at_ms: u64::from(tag),
            op_hash: [tag; 32],
        });
    }
    roster
}

#[test]
fn causal_descendant_beats_ancestor_while_concurrent_edits_commute() {
    let id = CollectionId([7; 32]);
    let collection = CollectionRef {
        moot_id: MOOT,
        collection_id: id,
    };
    let root = fact(
        10,
        CollectionEvent::Declared {
            collection_id: id,
            name: "songs".into(),
            fork: None,
            at_ms: 1,
        },
    );
    let add_x = fact(
        50,
        CollectionEvent::Changed {
            collection,
            parents: vec![root.op_hash],
            change: CollectionChange::SetMembership {
                contribution: reference(1),
                included: true,
            },
            at_ms: 2,
        },
    );
    let remove_x = fact(
        90,
        CollectionEvent::Changed {
            collection,
            parents: vec![add_x.op_hash],
            change: CollectionChange::SetMembership {
                contribution: reference(1),
                included: false,
            },
            at_ms: 3,
        },
    );
    let concurrent_y = fact(
        20,
        CollectionEvent::Changed {
            collection,
            parents: vec![root.op_hash],
            change: CollectionChange::SetMembership {
                contribution: reference(2),
                included: true,
            },
            at_ms: 3,
        },
    );
    let merge = fact(
        80,
        CollectionEvent::Changed {
            collection,
            parents: vec![remove_x.op_hash, concurrent_y.op_hash],
            change: CollectionChange::SetMembership {
                contribution: reference(3),
                included: true,
            },
            at_ms: 4,
        },
    );
    let mut roster = roster_with_fauna();
    roster.collections = vec![merge.clone(), concurrent_y, remove_x, root, add_x];
    let allowed = Allowed([CURATOR, SHARER].into_iter().collect());
    let view = roster.authorized_collection(MOOT, id, &allowed).unwrap();
    let mut shuffled = roster.clone();
    shuffled.collections.reverse();
    let shuffled_view = shuffled.authorized_collection(MOOT, id, &allowed).unwrap();
    assert_eq!(view.heads, vec![merge.op_hash]);
    assert_eq!(view.selected, vec![reference(2), reference(3)]);
    assert_eq!(view, shuffled_view);
    assert_eq!(
        view.version.membership_commitment,
        membership_commitment(&view.selected)
    );
}

#[test]
fn authority_changes_effective_selection_without_rewriting_version() {
    let id = CollectionId([8; 32]);
    let collection = CollectionRef {
        moot_id: MOOT,
        collection_id: id,
    };
    let root = fact(
        10,
        CollectionEvent::Declared {
            collection_id: id,
            name: "pages".into(),
            fork: None,
            at_ms: 1,
        },
    );
    let add = fact(
        11,
        CollectionEvent::Changed {
            collection,
            parents: vec![root.op_hash],
            change: CollectionChange::SetMembership {
                contribution: reference(1),
                included: true,
            },
            at_ms: 2,
        },
    );
    let mut roster = roster_with_fauna();
    roster.collections = vec![add, root];
    let live = roster
        .authorized_collection(MOOT, id, &Allowed([CURATOR, SHARER].into_iter().collect()))
        .unwrap();
    let revoked = roster
        .authorized_collection(MOOT, id, &Allowed([CURATOR].into_iter().collect()))
        .unwrap();
    assert_eq!(live.version, revoked.version);
    assert_eq!(revoked.selected, vec![reference(1)]);
    assert!(revoked.effective_selected.is_empty());
    assert!(!revoked.citations[0].effective);
    assert!(matches!(
        revoked.pending[0].reason,
        PendingCollectionReason::IneffectiveContribution(_)
    ));
    assert!(
        roster
            .authorized_collection(MOOT, id, &Allowed([SHARER].into_iter().collect()))
            .is_none()
    );
    assert_eq!(
        roster.collections.len(),
        2,
        "curation history stays retained"
    );
}

#[test]
fn missing_and_foreign_changes_remain_pending() {
    let id = CollectionId([9; 32]);
    let collection = CollectionRef {
        moot_id: MOOT,
        collection_id: id,
    };
    let root = fact(
        10,
        CollectionEvent::Declared {
            collection_id: id,
            name: "pages".into(),
            fork: None,
            at_ms: 1,
        },
    );
    let missing = fact(
        11,
        CollectionEvent::Changed {
            collection,
            parents: vec![[99; 32]],
            change: CollectionChange::SetMembership {
                contribution: reference(1),
                included: true,
            },
            at_ms: 2,
        },
    );
    let foreign = fact(
        12,
        CollectionEvent::Changed {
            collection: CollectionRef {
                moot_id: [3; 32],
                collection_id: id,
            },
            parents: vec![root.op_hash],
            change: CollectionChange::SetMembership {
                contribution: ContributionRef {
                    moot_id: [3; 32],
                    share: [1; 32],
                },
                included: true,
            },
            at_ms: 2,
        },
    );
    let mut roster = roster_with_fauna();
    roster.collections = vec![foreign, missing, root];
    let view = roster
        .authorized_collection(MOOT, id, &Allowed([CURATOR, SHARER].into_iter().collect()))
        .unwrap();
    assert!(
        view.pending
            .iter()
            .any(|item| matches!(item.reason, PendingCollectionReason::MissingParent(_)))
    );
    assert!(
        view.pending
            .iter()
            .any(|item| item.reason == PendingCollectionReason::ForeignReference)
    );
}

#[test]
fn fork_commitment_materializes_exact_parent_membership() {
    let parent_ref = CollectionRef {
        moot_id: MOOT,
        collection_id: CollectionId([1; 32]),
    };
    let selected = vec![reference(1), reference(2)];
    let parent = CollectionVersion::new(parent_ref, vec![[5; 32]], &selected);
    let fork = CollectionFork::new(parent, selected.clone());
    assert!(fork.verifies());
    let mut false_fork = fork.clone();
    false_fork.selected.pop();
    assert!(!false_fork.verifies());
}
