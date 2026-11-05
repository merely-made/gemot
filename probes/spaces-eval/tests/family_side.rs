// SPDX-License-Identifier: MPL-2.0

//! R25 criteria exercised on the family's current code: Gemot's `MootGroup`
//! (p2panda-auth `GroupCrdt` with `StrongRemove`) and Stickleback's
//! `GroupSession`, `GroupKeyLane` and `DataKeyring` (p2panda-encryption data
//! scheme). The same scenarios run on p2panda-spaces in `spaces_side.rs`.

use std::collections::BTreeSet;

use auth_old::Access;
use auth_old::group::{GroupAction, GroupMember};
use gemot::moot::group::{
    MootGroup, MootGroupError, MootGroupHandle, MootGroupOperation, MootGroupOperationId,
};
use identity::InMemoryProvider;
use muniment::MemoryBackend;
use pollster::block_on;
use stickleback::{
    GroupCryptoError, GroupEncryptionMode, GroupEncryptionProfile, GroupKeyLane, GroupPrekeyBundle,
    GroupSession, GroupSessionDispatch, GroupSessionError, GroupSessionId,
};

fn id(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn op(
    op_id: u8,
    author: u8,
    deps: &[u8],
    group: u8,
    action: GroupAction<MootGroupHandle>,
) -> MootGroupOperation {
    MootGroupOperation {
        id: MootGroupOperationId(id(op_id)),
        author: MootGroupHandle(id(author)),
        dependencies: deps.iter().map(|d| MootGroupOperationId(id(*d))).collect(),
        group: MootGroupHandle(id(group)),
        action,
    }
}

fn member(byte: u8) -> GroupMember<MootGroupHandle> {
    GroupMember::Individual(MootGroupHandle(id(byte)))
}

fn roots(group: &MootGroup) -> Vec<u8> {
    group
        .members()
        .iter()
        .map(|(member, _)| member[0])
        .collect()
}

// ~~~ 1. concurrent add and remove ~~~

/// The same scenario as spaces' `c1`: 1 removes 2 while 2 concurrently adds 3.
/// MootGroup runs the same CRDT and resolver, so membership and auth heads converge
/// in both delivery orders. Its `epoch` does not: it counts membership changes seen
/// locally, so the two replicas hold the same members under different epoch numbers.
#[test]
fn c1_gemot_concurrent_remove_converges_but_epoch_numbers_do_not() {
    let create = op(
        10,
        1,
        &[],
        9,
        GroupAction::Create {
            initial_members: vec![(member(1), Access::manage()), (member(2), Access::manage())],
        },
    );
    let remove = op(11, 1, &[10], 9, GroupAction::Remove { member: member(2) });
    let add = op(
        12,
        2,
        &[10],
        9,
        GroupAction::Add {
            member: member(3),
            access: Access::read(),
        },
    );
    let replay = |order: [&MootGroupOperation; 3]| {
        let mut group = MootGroup::new(id(9));
        for operation in order {
            group.apply_verified(operation).unwrap();
        }
        group
    };
    let removed_first = replay([&create, &remove, &add]);
    let added_first = replay([&create, &add, &remove]);

    assert_eq!(roots(&removed_first), vec![1]);
    assert_eq!(roots(&added_first), vec![1]);
    assert_eq!(removed_first.auth_heads(), added_first.auth_heads());
    assert_eq!(removed_first.epoch(), 2);
    assert_eq!(
        added_first.epoch(),
        3,
        "epoch is a local count, not a convergent value"
    );
    // The binding Gemot hands the host therefore has to carry the auth heads.
    let a = removed_first.bind_group_secret(id(77)).unwrap();
    let b = added_first.bind_group_secret(id(77)).unwrap();
    assert_eq!((a.members, a.auth_heads), (b.members, b.auth_heads));
}

// ~~~ 2. nested devices ~~~

/// MootGroup is one group of Personae roots. A sub-group's operations are refused as
/// another group; a group can be a member by id, but its own membership is not held
/// in this state. Devices are resolved one level down, in Stickleback's session: a
/// root may own several recipients (device prekeys), and the member among them is
/// the live one.
#[test]
fn c2_gemot_holds_no_nested_group_state_devices_live_in_the_session() {
    let create = op(
        10,
        1,
        &[],
        9,
        GroupAction::Create {
            initial_members: vec![(member(1), Access::manage())],
        },
    );
    let mut group = MootGroup::new(id(9));
    group.apply_verified(&create).unwrap();
    let device_group_create = op(
        20,
        1,
        &[],
        8,
        GroupAction::Create {
            initial_members: vec![(member(5), Access::manage())],
        },
    );
    assert!(matches!(
        group.apply_verified(&device_group_create),
        Err(MootGroupError::WrongGroup)
    ));
    let nested = op(
        21,
        1,
        &[10],
        9,
        GroupAction::Add {
            member: GroupMember::Group(MootGroupHandle(id(8))),
            access: Access::read(),
        },
    );
    group.apply_verified(&nested).unwrap();
    assert!(
        !roots(&group).contains(&5),
        "the sub-group's members are not materialised"
    );

    // Stickleback side: one root, two device recipients; the member one resolves.
    let session_group = GroupSessionId([0x49; 32]);
    let alice_identity = InMemoryProvider::from_seed([0xa1; 32]);
    let bob_identity = InMemoryProvider::from_seed([0xb2; 32]);
    let (mut alice, _) = GroupSession::new(session_group, &alice_identity).unwrap();
    let (phone, phone_prekey) = GroupSession::new(session_group, &bob_identity).unwrap();
    let (laptop, laptop_prekey) = GroupSession::new(session_group, &bob_identity).unwrap();
    assert_ne!(phone.member(), laptop.member());
    assert_eq!(phone.personae_root(), laptop.personae_root());
    alice.register_prekey(&phone_prekey).unwrap();
    alice.register_prekey(&laptop_prekey).unwrap();
    alice.create(&[]).unwrap();
    alice.add(laptop.member()).unwrap();
    assert_eq!(
        alice.recipient_for_root(phone.personae_root()),
        Some(laptop.member())
    );
    alice.add(phone.member()).unwrap();
    assert_eq!(
        alice.recipient_for_root(phone.personae_root()),
        None,
        "two live devices for one root is ambiguous to the session; the caller decides"
    );
}

// ~~~ 3 to 5. rotation, offline revoked peers, cold reopen (session level) ~~~

struct Trio {
    prekeys: Vec<GroupPrekeyBundle>,
    alice: GroupSession,
    bob: GroupSession,
    carol: GroupSession,
}

const GROUP: GroupSessionId = GroupSessionId([0x47; 32]);

fn trio() -> Trio {
    let ids = [0xa1, 0xb2, 0xc3].map(|seed| InMemoryProvider::from_seed([seed; 32]));
    let mut sessions = Vec::new();
    let mut prekeys = Vec::new();
    for identity in &ids {
        let (session, prekey) = GroupSession::new(GROUP, identity).unwrap();
        sessions.push(session);
        prekeys.push(prekey);
    }
    for session in &mut sessions {
        for prekey in &prekeys {
            session.register_prekey(prekey).unwrap();
        }
    }
    let mut carol = sessions.pop().unwrap();
    let mut bob = sessions.pop().unwrap();
    let mut alice = sessions.pop().unwrap();
    let create = alice.create(&[bob.member(), carol.member()]).unwrap();
    for session in [&mut bob, &mut carol] {
        session
            .process(
                alice.personae_root(),
                &create.control,
                create.direct_for(session.member()),
            )
            .unwrap();
    }
    Trio {
        prekeys,
        alice,
        bob,
        carol,
    }
}

fn apply(session: &mut GroupSession, from: &GroupSession, dispatch: &GroupSessionDispatch) {
    session
        .process(
            from.personae_root(),
            &dispatch.control,
            dispatch.direct_for(session.member()),
        )
        .unwrap();
}

/// Removing bob and rotating reaches carol and not bob; carol still reads what
/// predates the removal, bob does not read what follows. (Spaces' `c3`.)
#[test]
fn c3_session_rotation_after_removal_excludes_the_removed_member() {
    let Trio {
        mut alice,
        mut bob,
        mut carol,
        ..
    } = trio();
    let before = alice.seal_random(b"before removal").unwrap();

    let removal = alice.remove(bob.member()).unwrap();
    assert!(removal.direct_for(bob.member()).is_none());
    assert!(removal.direct_for(carol.member()).is_some());
    let rotation = alice.update().unwrap();
    assert_eq!(
        rotation
            .direct
            .iter()
            .map(|frame| frame.recipient)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([carol.member()]),
        "the rotation is addressed to the remaining member only"
    );
    for dispatch in [&removal, &rotation] {
        apply(&mut carol, &alice, dispatch);
        apply(&mut bob, &alice, dispatch);
    }

    let after = alice.seal_random(b"after rotation").unwrap();
    assert_eq!(carol.open(&after).unwrap(), b"after rotation");
    assert!(matches!(
        bob.open(&after),
        Err(GroupSessionError::Crypto(GroupCryptoError::UnknownEpoch(_)))
    ));
    assert_eq!(bob.open(&before).unwrap(), b"before removal");
}

/// Bob is offline for the removal and the rotation, then catches up in order: he
/// learns he is out and installs no new epoch. (Spaces' `c4`.)
#[test]
fn c4_session_offline_revoked_peer_catches_up_without_new_epochs() {
    let Trio {
        mut alice, mut bob, ..
    } = trio();
    let epoch_before = bob.current_epoch();
    let removal = alice.remove(bob.member()).unwrap();
    let rotation = alice.update().unwrap();
    let after = alice.seal_random(b"while bob was offline").unwrap();

    let first = bob
        .process(
            alice.personae_root(),
            &removal.control,
            removal.direct_for(bob.member()),
        )
        .unwrap();
    let second = bob
        .process(
            alice.personae_root(),
            &rotation.control,
            rotation.direct_for(bob.member()),
        )
        .unwrap();
    assert!(first.installed_epochs.is_empty() && second.installed_epochs.is_empty());
    assert_eq!(bob.current_epoch(), epoch_before);
    assert!(!bob.members().unwrap().contains(&bob.member()));
    assert!(bob.open(&after).is_err());
}

/// The session persists to bytes and reopens with its epochs, membership and keys;
/// the reopened member opens what was sealed before and after. (Spaces' `c5`.)
#[test]
fn c5_session_cold_reopen_keeps_epochs_and_membership() {
    let Trio {
        mut alice,
        bob,
        carol,
        ..
    } = trio();
    let update = alice.update().unwrap();
    let mut carol = carol;
    apply(&mut carol, &alice, &update);
    let sealed = alice.seal_random(b"sealed before restart").unwrap();

    let bytes = carol.to_bytes().unwrap();
    drop(carol);
    let reopened = GroupSession::from_bytes(&bytes).unwrap();
    assert_eq!(reopened.current_epoch(), alice.current_epoch());
    assert_eq!(reopened.members().unwrap(), alice.members().unwrap());
    assert_eq!(reopened.open(&sealed).unwrap(), b"sealed before restart");
    drop(bob);
}

// ~~~ 6. Muniment storage without SQLite ~~~

/// The durable half runs on Muniment: a group-key lane over a Muniment backend
/// authors a welcome and a removal that another member's lane accepts and applies.
/// Nothing here links SQLite (see `storage_graph.rs`).
#[test]
fn c6_group_key_lane_runs_on_muniment() {
    let a_identity = InMemoryProvider::from_seed([0xa1; 32]);
    let b_identity = InMemoryProvider::from_seed([0xb2; 32]);
    let a_lane = GroupKeyLane::for_identity(MemoryBackend::new(), GROUP, &a_identity).unwrap();
    let b_lane = GroupKeyLane::for_identity(MemoryBackend::new(), GROUP, &b_identity).unwrap();
    let (mut a, a_prekey) = GroupSession::new(GROUP, &a_identity).unwrap();
    let (mut b, b_prekey) = GroupSession::new(GROUP, &b_identity).unwrap();
    a.register_prekey(&b_prekey).unwrap();
    b.register_prekey(&a_prekey).unwrap();
    a.create(&[]).unwrap();

    let welcome = a.add(b.member()).unwrap();
    b.process(
        a_lane.stable_author(),
        &welcome.control,
        welcome.direct_for(b.member()),
    )
    .unwrap();
    let rotation = a.update().unwrap();
    let authored = block_on(a_lane.author_dispatch(&rotation)).unwrap();

    block_on(b_lane.accept(&authored)).unwrap();
    let drain = block_on(b_lane.drain_ready(&mut b, |_| Ok::<_, GroupSessionError>(()))).unwrap();
    assert_eq!(drain.applied.len(), 1);
    assert!(drain.refused.is_empty());
    assert_eq!(b.current_epoch(), a.current_epoch());
}

// ~~~ 7. durable data versus forward secrecy ~~~

/// Stickleback's session is the data scheme: a member added later is welcomed with
/// every retained epoch and reads earlier data. A forward-secure message profile
/// exists as a label (`GroupEncryptionProfile::forward_secure_messages`) but no
/// session operation is driven by it.
#[test]
fn c7_session_late_member_reads_earlier_data_and_the_forward_profile_is_a_label() {
    let Trio {
        prekeys,
        mut alice,
        mut bob,
        mut carol,
    } = trio();
    alice.update().unwrap();
    let early = alice.seal_random(b"written before dave joined").unwrap();

    let dave_identity = InMemoryProvider::from_seed([0xd4; 32]);
    let (mut dave, dave_prekey) = GroupSession::new(GROUP, &dave_identity).unwrap();
    for session in [&mut alice, &mut bob, &mut carol] {
        session.register_prekey(&dave_prekey).unwrap();
    }
    for prekey in &prekeys {
        dave.register_prekey(prekey).unwrap();
    }
    let welcome = alice.add(dave.member()).unwrap();
    let welcomed = dave
        .process(
            alice.personae_root(),
            &welcome.control,
            welcome.direct_for(dave.member()),
        )
        .unwrap();
    assert_eq!(welcomed.installed_epochs.len(), alice.epoch_count());
    assert_eq!(dave.open(&early).unwrap(), b"written before dave joined");

    let profile = GroupEncryptionProfile::forward_secure_messages();
    assert_eq!(profile.mode, GroupEncryptionMode::Message);
    assert_eq!(profile.retained_data_epochs, 0);
}
