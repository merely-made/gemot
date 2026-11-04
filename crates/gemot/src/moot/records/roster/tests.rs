// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;
use crate::moot::records::wire::to_operation;
use identity::{Ed25519Keypair, IdentityProvider, InMemoryProvider};
use servitor::{Cap, Mode, Subject};
use std::collections::BTreeSet;

const MOOT: [u8; 32] = [0x6d; 32];

fn keypair(seed: u8) -> Ed25519Keypair {
    InMemoryProvider::from_seed([seed; 32])
        .derive_keypair(b"moot-roster")
        .unwrap()
}

fn author(kp: &Ed25519Keypair) -> [u8; 32] {
    kp.public_key().to_bytes()
}

struct Allowed(BTreeSet<[u8; 32]>);

impl AuthorityProvider for Allowed {
    fn covers(&self, subject: Subject, _: &Cap, mode: Mode) -> bool {
        mode == Mode::Write && self.0.contains(&subject.0)
    }
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
    // codicil whose schema is mere.pack/v1 lists in the fauna like any
    // other: the Moot's fauna catalog is where a distributed pack becomes
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
    let with_pack = MootRoster::fold(
        MOOT,
        [
            &declared,
            &founder_join,
            &friend_join,
            &shared,
            &pack_shared,
        ],
    );
    assert_eq!(with_pack.fauna.len(), 2);
    assert!(
        with_pack
            .fauna
            .iter()
            .any(|f| f.schema_id == "mere.pack/v1" && f.title == "trail-keeper 0.1.0"),
        "the pack is visible in the Moot's fauna under its schema"
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
    let context = roster.recognition_context(MOOT, RecognitionPolicy::Threshold { required: 2 });
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

#[test]
fn withdrawal_is_order_independent_and_only_hides_the_matching_share() {
    let identity = keypair(0x44);
    let other = keypair(0x45);
    let share = to_operation(
        &identity,
        MOOT,
        &MootEvent::Shared {
            manifest_id: [0xaa; 32],
            schema_id: "fleece/v1".into(),
            title: "one".into(),
            at_ms: 1,
        },
        0,
        None,
    );
    let other_share = to_operation(
        &other,
        MOOT,
        &MootEvent::Shared {
            manifest_id: [0xaa; 32],
            schema_id: "fleece/v1".into(),
            title: "copy".into(),
            at_ms: 2,
        },
        0,
        None,
    );
    let withdrawal = to_operation(
        &identity,
        MOOT,
        &MootEvent::Withdrawn {
            target_share: *share.hash.as_bytes(),
            at_ms: 3,
        },
        1,
        Some(*share.hash.as_bytes()),
    );
    let one = MootRoster::fold(MOOT, [&withdrawal, &other_share, &share]);
    let two = MootRoster::fold(MOOT, [&share, &other_share, &withdrawal]);
    assert_eq!(one, two);
    assert_eq!(one.withdrawals.len(), 1);
    assert_eq!(one.fauna.len(), 2);
    let authority = Allowed([author(&identity), author(&other)].into_iter().collect());
    let visible = one.authorized_fauna(&authority);
    assert_eq!(visible.len(), 1);
    assert_eq!(visible[0].title, "copy");

    // A withdrawal signed by another stable root is retained as a fact,
    // but cannot hide the contribution it did not author.
    let forged = to_operation(
        &other,
        MOOT,
        &MootEvent::Withdrawn {
            target_share: *share.hash.as_bytes(),
            at_ms: 4,
        },
        1,
        Some(*other_share.hash.as_bytes()),
    );
    let with_forged = MootRoster::fold(MOOT, [&share, &other_share, &withdrawal, &forged]);
    assert_eq!(with_forged.withdrawals.len(), 2);
    let visible = with_forged.authorized_fauna(&authority);
    assert_eq!(
        visible.len(),
        1,
        "the valid withdrawal still hides the target"
    );
    assert_eq!(visible[0].title, "copy");
}

#[test]
fn repeated_withdrawal_operation_is_retained_once() {
    let identity = keypair(0x46);
    let withdrawal = to_operation(
        &identity,
        MOOT,
        &MootEvent::Withdrawn {
            target_share: [0xaa; 32],
            at_ms: 3,
        },
        0,
        None,
    );
    let roster = MootRoster::fold(MOOT, [&withdrawal, &withdrawal]);
    assert_eq!(roster.withdrawals.len(), 1);
}
