// SPDX-License-Identifier: MPL-2.0

//! R25 criteria exercised on p2panda-spaces (the intake branch of p2mere), with the
//! `Manager` running over a map store: no SQLite at runtime. The family's current
//! code is exercised on the same scenarios in `family_side.rs`.

use std::borrow::Borrow;
use std::collections::BTreeSet;

use p2auth::Access;
use p2core::VerifyingKey;
use p2enc::Rng;
use p2spaces::space::SpaceOutput;
use p2spaces::test_utils::{TestConditions, TestOperation};
use p2spaces::{Event, SpaceEvent, SpaceId, SpacesArgs};
use spaces_eval::{MapPeer, exchange_bundles};

type Op = TestOperation;

fn space_id() -> SpaceId {
    SpaceId::digest(b"r25-space")
}

fn ops(output: SpaceOutput<TestConditions, Op>) -> Vec<Op> {
    output
        .messages
        .into_iter()
        .map(|(message, _)| message)
        .collect()
}

async fn deliver(peer: &MapPeer, messages: &[Op]) -> Vec<Event<TestConditions>> {
    let mut events = Vec::new();
    for message in messages {
        events.extend(peer.receive(message).await.unwrap());
    }
    events
}

fn applications(events: &[Event<TestConditions>]) -> Vec<Vec<u8>> {
    events
        .iter()
        .filter_map(|event| match event {
            Event::Application { data, .. } => Some(data.clone()),
            _ => None,
        })
        .collect()
}

fn ejected(events: &[Event<TestConditions>]) -> bool {
    events
        .iter()
        .any(|event| matches!(event, Event::Spaces(SpaceEvent::Ejected { .. })))
}

fn ids(members: &[(VerifyingKey, Access<TestConditions>)]) -> BTreeSet<VerifyingKey> {
    members.iter().map(|(id, _)| *id).collect()
}

/// Recipients of the direct (welcome or rotation) messages inside one forged message.
fn direct_recipients(message: &Op) -> BTreeSet<VerifyingKey> {
    let args: &SpacesArgs<TestConditions> = message.borrow();
    match args {
        SpacesArgs::SpaceMembership {
            direct_messages, ..
        } => direct_messages
            .iter()
            .map(|direct| direct.recipient)
            .collect(),
        _ => BTreeSet::new(),
    }
}

struct Founded {
    alice: MapPeer,
    bob: MapPeer,
    claire: MapPeer,
    dave: MapPeer,
    /// Everything forged so far, in the order alice produced or accepted it.
    log: Vec<Op>,
}

/// Alice founds a space with bob (manager) and claire (reader); all have processed it.
async fn founded() -> Founded {
    let alice = MapPeer::new(1);
    let bob = MapPeer::new(2);
    let claire = MapPeer::new(3);
    let dave = MapPeer::new(4);
    exchange_bundles(&[&alice, &bob, &claire, &dave]).await;
    let (space, output) = alice
        .manager
        .create_space(
            space_id(),
            &[
                (bob.manager.id(), Access::manage()),
                (claire.manager.id(), Access::read()),
            ],
        )
        .await
        .unwrap();
    drop(space);
    let log = ops(output);
    deliver(&bob, &log).await;
    deliver(&claire, &log).await;
    Founded {
        alice,
        bob,
        claire,
        dave,
        log,
    }
}

// ~~~ 1. concurrent add and remove ~~~

/// Alice removes bob while bob concurrently adds dave. The same group CRDT and
/// StrongRemove resolver as Gemot's `MootGroup` decide it: the removed manager's
/// concurrent add does not take effect, alice and bob converge, and a later add by
/// alice still welcomes the new member, who reads what is published after.
#[tokio::test]
async fn c1_concurrent_remove_beats_the_removed_managers_add() {
    let mut f = founded().await;
    let alice_space = f.alice.manager.space(space_id()).joined().await.unwrap();
    let bob_space = f.bob.manager.space(space_id()).joined().await.unwrap();

    let removal = ops(alice_space.remove(f.bob.manager.id()).await.unwrap());
    let addition = ops(bob_space
        .add(f.dave.manager.id(), Access::read())
        .await
        .unwrap());

    deliver(&f.alice, &addition).await;
    let bob_events = deliver(&f.bob, &removal).await;
    f.log.extend(removal);
    f.log.extend(addition);

    let alice_members = ids(&alice_space.members().await.unwrap());
    assert_eq!(
        alice_members,
        BTreeSet::from([f.alice.manager.id(), f.claire.manager.id()]),
        "bob's concurrent add of dave did not take effect"
    );
    assert!(ejected(&bob_events), "bob learns he was ejected");
    assert_eq!(
        ids(&bob_space.members().await.unwrap()),
        alice_members,
        "alice and bob converge"
    );

    // Alice adds dave herself afterwards; dave is welcomed and reads what follows.
    let welcome = ops(alice_space
        .add(f.dave.manager.id(), Access::read())
        .await
        .unwrap());
    f.log.extend(welcome);
    let (after, _) = alice_space.publish(b"after the conflict").await.unwrap();
    f.log.push(after);
    let dave_events = deliver(&f.dave, &f.log).await;
    assert_eq!(
        applications(&dave_events),
        vec![b"after the conflict".to_vec()]
    );
}

// ~~~ 2. nested devices ~~~

/// A person is a group of devices; the space holds the group. Removing a device from
/// the group changes the space's flattened members.
#[tokio::test]
async fn c2_nested_device_group_is_a_space_member() {
    // Alice is the founding space author and also one of a person's two devices (the
    // "phone"); the group is created by a device that belongs to it.
    let phone = MapPeer::new(1);
    let laptop = MapPeer::new(2);
    let watch = MapPeer::new(3);
    exchange_bundles(&[&phone, &laptop, &watch]).await;

    let (devices, created) = phone
        .manager
        .create_group(&[
            (phone.manager.id(), Access::manage()),
            (laptop.manager.id(), Access::manage()),
        ])
        .await
        .unwrap();
    let device_group = devices.id();
    let mut log = vec![created.message];

    // The space is authored by the phone; the person (device group) is a writer.
    let (space, output) = phone
        .manager
        .create_space(space_id(), &[(device_group, Access::write())])
        .await
        .unwrap();
    log.extend(ops(output));

    let actors = ids(&space.actors().await.unwrap());
    assert!(
        actors.contains(&device_group),
        "the group itself is an actor"
    );
    let members = ids(&space.members().await.unwrap());
    assert!(members.contains(&phone.manager.id()) && members.contains(&laptop.manager.id()));
    assert!(
        !members.contains(&device_group),
        "members are flattened to individuals"
    );

    // The laptop processes the founding and sees the same flattened members.
    deliver(&laptop, &log).await;
    let delivered = log.len();
    let laptop_space = laptop.manager.space(space_id()).joined().await.unwrap();
    assert_eq!(ids(&laptop_space.members().await.unwrap()), members);

    // Adding the watch to the device group, then repairing the space, brings the
    // watch into the space's flattened members.
    let addition = devices
        .add(watch.manager.id(), Access::write())
        .await
        .unwrap();
    log.push(addition.message);
    let repair = space.repair(&[device_group]).await.unwrap();
    log.extend(repair.messages.into_iter().map(|(message, _)| message));
    let members = ids(&space.members().await.unwrap());
    assert!(members.contains(&watch.manager.id()), "{members:?}");

    // Removing the laptop from the device group removes it from the space.
    let removal = devices.remove(laptop.manager.id()).await.unwrap();
    log.push(removal.message);
    let repair = space.repair(&[device_group]).await.unwrap();
    log.extend(repair.messages.into_iter().map(|(message, _)| message));
    let members = ids(&space.members().await.unwrap());
    assert!(members.contains(&phone.manager.id()) && members.contains(&watch.manager.id()));
    assert!(!members.contains(&laptop.manager.id()), "{members:?}");

    // The removed device cannot read what the space publishes afterwards.
    let (after, _) = space.publish(b"after the device left").await.unwrap();
    deliver(&laptop, &log[delivered..]).await;
    let refused = laptop.receive(&after).await.unwrap_err();
    assert!(
        format!("{refused:?}").contains("UnknownGroupSecret"),
        "{refused:?}"
    );
}

// ~~~ 3. key rotation ~~~

/// Removal carries a fresh group secret to the remaining members and to nobody
/// else; the removed member cannot read what follows, remaining members can.
#[tokio::test]
async fn c3_removal_rotates_the_secret_towards_remaining_members_only() {
    let mut f = founded().await;
    let space = f.alice.manager.space(space_id()).joined().await.unwrap();

    let (before, _) = space.publish(b"before removal").await.unwrap();
    let removal = ops(space.remove(f.bob.manager.id()).await.unwrap());
    let membership = removal.last().unwrap();
    assert_eq!(
        direct_recipients(membership),
        BTreeSet::from([f.claire.manager.id()]),
        "the new secret is addressed to claire, not to bob"
    );
    let (after, _) = space.publish(b"after removal").await.unwrap();

    // Positive control: both read what predates the removal.
    let bob_before = deliver(&f.bob, std::slice::from_ref(&before)).await;
    let claire_before = deliver(&f.claire, std::slice::from_ref(&before)).await;
    assert_eq!(applications(&bob_before), vec![b"before removal".to_vec()]);
    assert_eq!(
        applications(&claire_before),
        vec![b"before removal".to_vec()]
    );

    deliver(&f.claire, &removal).await;
    let claire_after = deliver(&f.claire, std::slice::from_ref(&after)).await;
    assert_eq!(applications(&claire_after), vec![b"after removal".to_vec()]);

    deliver(&f.bob, &removal).await;
    let refused = f.bob.receive(&after).await.unwrap_err();
    assert!(
        format!("{refused:?}").contains("UnknownGroupSecret"),
        "{refused:?}"
    );
    f.log.push(before);
}

// ~~~ 4. offline revoked peers ~~~

/// Bob is offline across his removal. A message he authored before he learned of it
/// is dropped by alice rather than delivered as application data; when he returns he
/// is ejected and cannot read anything published after the removal.
#[tokio::test]
async fn c4_an_offline_revoked_peer_is_ejected_and_filtered() {
    let f = founded().await;
    let alice_space = f.alice.manager.space(space_id()).joined().await.unwrap();
    let bob_space = f.bob.manager.space(space_id()).joined().await.unwrap();

    let removal = ops(alice_space.remove(f.bob.manager.id()).await.unwrap());
    let (after, _) = alice_space.publish(b"secret after removal").await.unwrap();
    // Bob, still offline, writes into the space.
    let (from_bob, _) = bob_space.publish(b"from a revoked peer").await.unwrap();

    let alice_events = f.alice.receive(&from_bob).await.unwrap();
    assert!(
        applications(&alice_events).is_empty(),
        "a concurrent write by the removed member is filtered"
    );

    let bob_events = deliver(&f.bob, &removal).await;
    assert!(ejected(&bob_events));
    let refused = f.bob.receive(&after).await.unwrap_err();
    assert!(
        format!("{refused:?}").contains("UnknownGroupSecret"),
        "{refused:?}"
    );
    assert!(
        f.alice
            .manager
            .removed_space_members(space_id())
            .await
            .unwrap()
            .contains(&f.bob.manager.id())
    );
}

// ~~~ 5. cold reopen ~~~

/// A new manager over the same store resumes the space: membership is restored, it
/// can publish, and peers decrypt what it publishes.
#[tokio::test]
async fn c5_cold_reopen_resumes_the_space() {
    let f = founded().await;
    let Founded { alice, claire, .. } = f;
    let members_before = {
        let space = alice.manager.space(space_id()).joined().await.unwrap();
        ids(&space.members().await.unwrap())
    };
    let MapPeer {
        store, credentials, ..
    } = alice;

    let reopened = MapPeer::reopen(store, credentials, Rng::from_seed([9; 32]));
    assert!(reopened.manager.has_joined_space(space_id()).await.unwrap());
    let space = reopened.manager.space(space_id()).joined().await.unwrap();
    assert_eq!(ids(&space.members().await.unwrap()), members_before);

    let (message, _) = space.publish(b"after reopen").await.unwrap();
    let events = deliver(&claire, std::slice::from_ref(&message)).await;
    assert_eq!(applications(&events), vec![b"after reopen".to_vec()]);
}

// ~~~ 6. storage without SQLite ~~~

/// The whole `Manager` surface ran above over `MapStore`, which implements the six
/// store traits and nothing else. This test is the minimal statement of that.
#[tokio::test]
async fn c6_manager_runs_over_a_store_that_is_not_sqlite() {
    let alice = MapPeer::new(1);
    let bob = MapPeer::new(2);
    exchange_bundles(&[&alice, &bob]).await;
    let (_space, output) = alice
        .manager
        .create_space(space_id(), &[(bob.manager.id(), Access::read())])
        .await
        .unwrap();
    let log = ops(output);
    deliver(&bob, &log).await;
    let space = alice.manager.space(space_id()).joined().await.unwrap();
    let (message, _) = space.publish(b"no sqlite").await.unwrap();
    let events = deliver(&bob, std::slice::from_ref(&message)).await;
    assert_eq!(applications(&events), vec![b"no sqlite".to_vec()]);
}

// ~~~ 7. durable data versus forward secrecy ~~~

/// Spaces runs the p2panda-encryption data scheme only: a member added later is
/// given the retained secrets and reads earlier data (durable-data behaviour, the
/// same as Commons' `COMMONS_CHAT_PROFILE`). There is no per-message forward-secure
/// profile to select.
#[tokio::test]
async fn c7_a_late_member_reads_earlier_data() {
    let mut f = founded().await;
    let space = f.alice.manager.space(space_id()).joined().await.unwrap();
    let (early, _) = space.publish(b"written before dave joined").await.unwrap();
    f.log.push(early);
    let welcome = ops(space
        .add(f.dave.manager.id(), Access::read())
        .await
        .unwrap());
    f.log.extend(welcome);

    let events = deliver(&f.dave, &f.log).await;
    assert_eq!(
        applications(&events),
        vec![b"written before dave joined".to_vec()]
    );
}
