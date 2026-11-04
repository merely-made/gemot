// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

use super::*;
use crate::moot::constitution::{CapabilityGrant, ConstitutionRules};
use crate::moot::{
    AvailabilityPolicy, ErasurePolicy, KeepBound, Moot, MootAccessLevel, MootId, MootMember,
    MootMembershipAction, MootRetentionSettings, PolicyRevision,
};
use identity::{IdentityProvider, InMemoryProvider};
use muniment::MemoryBackend;
use std::sync::{Arc, RwLock};
use stickleback::{DataKeyring, GroupSession, GroupSessionId};
mod authority;
#[cfg(feature = "relay-pool-i2p")]
mod i2p;
#[cfg(feature = "relay-pool-native")]
mod native;

const POOL: [u8; 32] = [41; 32];
const DEVICE_A: [u8; 32] = [51; 32];
const DEVICE_B: [u8; 32] = [52; 32];
const TARGET: [u8; 32] = [61; 32];

fn identity(seed: u8) -> InMemoryProvider {
    InMemoryProvider::from_seed([seed; 32])
}
fn root(seed: u8) -> [u8; 32] {
    identity(seed).master_public_key().to_bytes()
}

pub(super) fn retention() -> MootRetentionSettings {
    MootRetentionSettings {
        revision: PolicyRevision(proofs::Digest::blake3(b"relay-fixture")),
        availability: AvailabilityPolicy {
            promised_floor: KeepBound::Forever,
        },
        erasure: ErasurePolicy {
            history_ceiling: KeepBound::UntilCheckpoint,
        },
    }
}

async fn initialize<B: muniment::Backend + Clone>(moot: &Moot<B>) {
    initialize_for(moot, 100_000).await;
}
async fn initialize_for<B: muniment::Backend + Clone>(moot: &Moot<B>, expiry: u64) {
    let mut rules = ConstitutionRules::founder_only(root(1));
    rules.admission = mien::Policy::MembersOnly {
        rate_limit: 1000,
        rate_window_ms: 1000,
    };
    for (index, (subject, action)) in [
        (root(1), "manage"),
        (root(2), "contribute"),
        (root(3), "contribute"),
        (root(4), "use"),
    ]
    .into_iter()
    .enumerate()
    {
        rules.grant(CapabilityGrant {
            id: [index as u8 + 1; 32],
            subject,
            path_prefix: servitor::cap_path(&relay_cap(POOL, action).unwrap()),
            not_before_ms: 0,
            expires_at_ms: Some(expiry),
            delegation_depth: 0,
        });
    }
    moot.found([1; 32], None, None, rules, 0).await.unwrap();
    moot.update_membership_for_identity(
        &identity(1),
        MootMembershipAction::Create {
            initial_members: (1..=4)
                .map(|seed| MootMember {
                    member: root(seed),
                    access: if seed == 1 {
                        MootAccessLevel::Manage
                    } else {
                        MootAccessLevel::Write
                    },
                })
                .collect(),
        },
    )
    .await
    .unwrap();
}

fn distributed_keys() -> (GroupSession, GroupSession, GroupSession) {
    let group = GroupSessionId([71; 32]);
    let (mut a, ak) = GroupSession::new(group, &identity(1)).unwrap();
    let (mut b, bk) = GroupSession::new(group, &identity(2)).unwrap();
    let (mut c, ck) = GroupSession::new(group, &identity(3)).unwrap();
    a.register_prekey(&bk).unwrap();
    a.register_prekey(&ck).unwrap();
    b.register_prekey(&ak).unwrap();
    c.register_prekey(&ak).unwrap();
    a.create(&[]).unwrap();
    let add_b = a.add(b.member()).unwrap();
    b.process(root(1), &add_b.control, add_b.direct_for(b.member()))
        .unwrap();
    let add_c = a.add(c.member()).unwrap();
    for receiver in [&mut b, &mut c] {
        receiver
            .process(root(1), &add_c.control, add_c.direct_for(receiver.member()))
            .unwrap();
    }
    (a, b, c)
}

fn keys(session: &GroupSession) -> Arc<RwLock<Arc<DataKeyring>>> {
    Arc::new(RwLock::new(Arc::new(
        DataKeyring::from_bytes(&session.data_keyring_state().unwrap()).unwrap(),
    )))
}
fn source(keys: Arc<RwLock<Arc<DataKeyring>>>) -> PoolKeys {
    Arc::new(move || keys.read().unwrap().clone())
}

async fn fixture() -> (PoolStore<MemoryBackend>, Arc<RwLock<Arc<DataKeyring>>>) {
    let moot = Arc::new(Moot::in_memory(MootId([31; 32]), root(1), retention()));
    initialize(&moot).await;
    let config = PoolPolicy {
        moot: moot.moot_id(),
        pool: POOL,
        coordination: [72; 32],
        constitution_revision: moot.snapshot().await.unwrap().governance.revision,
        revision: [42; 32],
        service_key: root(9),
        max_records: 128,
        max_lease_ms: 60_000,
        max_authority_age_ms: 1000,
        authority_expires_at_ms: 60_000,
    };
    let (session, _, _) = distributed_keys();
    let keys = keys(&session);
    (
        PoolStore::new(moot, MemoryBackend::new(), config, source(keys.clone())).unwrap(),
        keys,
    )
}

fn contribution(seed: u8, device: [u8; 32]) -> PoolEvent {
    PoolEvent::Contribute(
        PoolContribution::attest(&identity(seed), POOL, device, 65_536, 65_536, 2, 0, 60_000)
            .unwrap(),
    )
}
async fn target(pool: &PoolStore<MemoryBackend>) {
    pool.author(
        &identity(1),
        PoolEvent::RegisterTarget(PoolTarget {
            id: TARGET,
            recipient_key: root(8),
            max_bytes: 32_768,
        }),
        1,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn independently_signed_contributors_reorder_duplicate_and_withdraw() {
    let (pool, keys) = fixture().await;
    target(&pool).await;
    let a = pool
        .author(&identity(2), contribution(2, DEVICE_A), 2)
        .await
        .unwrap();
    let b = pool
        .author(&identity(3), contribution(3, DEVICE_B), 2)
        .await
        .unwrap();
    let all = pool.operations().await.unwrap();
    let replica = PoolStore::new(
        pool.moot.clone(),
        MemoryBackend::new(),
        pool.config.clone(),
        source(keys),
    )
    .unwrap();
    for operation in all.iter().rev() {
        replica.accept(operation, 3).await.unwrap();
    }
    assert!(!replica.accept(&a, 3).await.unwrap());
    assert!(!replica.accept(&b, 3).await.unwrap());
    let view = replica.view(3).await.unwrap();
    assert!(!view.pending);
    assert!(view.contribution(DEVICE_A).is_some() && view.contribution(DEVICE_B).is_some());
    assert_eq!(pool.view(3).await.unwrap().revision, view.revision);
    assert_eq!(
        replica
            .authorize(root(4), DEVICE_A, TARGET, 4)
            .await
            .unwrap()
            .max_bytes,
        32_768
    );
    assert!(
        replica
            .authorize(root(5), DEVICE_A, TARGET, 4)
            .await
            .is_err()
    );
    assert!(
        replica
            .authorize(root(4), DEVICE_A, [0; 32], 4)
            .await
            .is_err()
    );
    // One owner cannot withdraw another's contribution.
    replica
        .author(&identity(3), PoolEvent::Withdraw { device: DEVICE_A }, 5)
        .await
        .unwrap();
    assert!(
        replica
            .authorize(root(4), DEVICE_A, TARGET, 5)
            .await
            .is_ok()
    );
    replica
        .author(&identity(2), PoolEvent::Withdraw { device: DEVICE_A }, 6)
        .await
        .unwrap();
    assert!(
        replica
            .authorize(root(4), DEVICE_A, TARGET, 6)
            .await
            .is_err()
    );
    replica
        .author(&identity(2), contribution(2, DEVICE_A), 7)
        .await
        .unwrap();
    assert!(
        replica
            .authorize(root(4), DEVICE_A, TARGET, 7)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn wrong_author_foreign_pool_and_missing_authority_are_refused_before_insert() {
    let (pool, keys) = fixture().await;
    assert!(
        pool.author(&identity(5), contribution(5, DEVICE_A), 2)
            .await
            .is_err()
    );
    assert!(
        pool.author(&identity(3), contribution(2, DEVICE_A), 2)
            .await
            .is_err()
    );
    let valid = pool
        .author(&identity(2), contribution(2, DEVICE_A), 2)
        .await
        .unwrap();
    let mut config = pool.config.clone();
    config.pool = [99; 32];
    let foreign = PoolStore::new(
        pool.moot.clone(),
        MemoryBackend::new(),
        config,
        source(keys.clone()),
    )
    .unwrap();
    assert!(foreign.accept(&valid, 3).await.is_err());
    assert!(foreign.operations().await.unwrap().is_empty());
    let unresolved = Arc::new(Moot::in_memory(pool.config.moot, root(1), retention()));
    let missing = PoolStore::new(
        unresolved,
        MemoryBackend::new(),
        pool.config.clone(),
        source(keys),
    )
    .unwrap();
    assert!(missing.accept(&valid, 3).await.is_err());
    assert!(missing.operations().await.unwrap().is_empty());
}

#[tokio::test]
async fn key_rotation_requires_existing_group_epoch_and_plaintext_is_not_stored() {
    let (pool, old_keys) = fixture().await;
    let (mut admin, mut member, mut other) = distributed_keys();
    let member_keys = keys(&member);
    let sender_keys = keys(&admin);
    let sender = PoolStore::new(
        pool.moot.clone(),
        MemoryBackend::new(),
        pool.config.clone(),
        source(sender_keys.clone()),
    )
    .unwrap();
    let receiver = PoolStore::new(
        pool.moot.clone(),
        MemoryBackend::new(),
        pool.config.clone(),
        source(member_keys.clone()),
    )
    .unwrap();
    let rotation = admin.update().unwrap();
    *sender_keys.write().unwrap() =
        Arc::new(DataKeyring::from_bytes(&admin.data_keyring_state().unwrap()).unwrap());
    let operation = sender
        .author(&identity(2), contribution(2, DEVICE_A), 2)
        .await
        .unwrap();
    assert!(receiver.accept(&operation, 3).await.is_err());
    assert!(receiver.operations().await.unwrap().is_empty());
    member
        .process(
            root(1),
            &rotation.control,
            rotation.direct_for(member.member()),
        )
        .unwrap();
    other
        .process(
            root(1),
            &rotation.control,
            rotation.direct_for(other.member()),
        )
        .unwrap();
    *member_keys.write().unwrap() =
        Arc::new(DataKeyring::from_bytes(&member.data_keyring_state().unwrap()).unwrap());
    assert!(receiver.accept(&operation, 3).await.unwrap());
    let body = operation.body.unwrap().to_bytes();
    assert!(!body.windows(32).any(|window| window == root(2)));
    let keyless = PoolStore::new(
        pool.moot.clone(),
        MemoryBackend::new(),
        pool.config.clone(),
        source(old_keys),
    )
    .unwrap();
    // A different group session with the same application group ID has no epoch.
    assert!(
        keyless
            .accept(&sender.operations().await.unwrap()[0], 3)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn fresh_probe_is_required_and_responses_cannot_be_replayed() {
    let (pool, _) = fixture().await;
    pool.author(&identity(2), contribution(2, DEVICE_A), 2)
        .await
        .unwrap();
    let view = pool.view(3).await.unwrap();
    let mut offers = OfferBook::default();
    assert!(offers.candidates(&view).is_empty());
    let probe = offers.probe(&view, DEVICE_A, 500, 3).unwrap();
    let device = identity(2)
        .derive_keypair(&device_salt(POOL, DEVICE_A))
        .unwrap();
    let signature = device.sign(&probe.signing_bytes()).to_bytes();
    assert!(offers.confirm(&view, &probe, signature).is_ok());
    assert!(offers.confirm(&view, &probe, signature).is_err());
    assert_eq!(offers.candidates(&view).len(), 1);
    let mut reopened = OfferBook::default();
    assert!(reopened.candidates(&view).is_empty());
    let fresh = reopened.probe(&view, DEVICE_A, 500, 4).unwrap();
    assert_ne!(fresh.nonce, probe.nonce);
    assert!(reopened.confirm(&view, &probe, signature).is_err());
    offers.failed(DEVICE_A);
    assert!(offers.candidates(&view).is_empty());
}

#[tokio::test]
async fn membership_revocation_invalidates_active_authority_and_snapshot_deadline_is_bounded() {
    let (pool, _) = fixture().await;
    target(&pool).await;
    pool.author(&identity(2), contribution(2, DEVICE_A), 2)
        .await
        .unwrap();
    let permission = pool.authorize(root(4), DEVICE_A, TARGET, 10).await.unwrap();
    assert_eq!(permission.expires_at_ms, 1010);
    pool.moot
        .update_membership_for_identity(
            &identity(1),
            MootMembershipAction::Remove { member: root(4) },
        )
        .await
        .unwrap();
    assert!(pool.authorize(root(4), DEVICE_A, TARGET, 11).await.is_err());
}

#[tokio::test]
async fn client_offer_has_service_signature_without_root_or_device_attestation() {
    let (pool, _) = fixture().await;
    let offer = ClientOffer {
        pool: POOL,
        alias: [91; 32],
        target: TARGET,
        recipient_key: root(8),
        native_route: "fixture-route".into(),
        native_host_visible: true,
        expires_at_ms: 1000,
    };
    let signing_identity = identity(9);
    let key = signing_identity.master_keypair();
    let signature = offer.sign(&pool.config, &key).unwrap();
    offer
        .verify(POOL, pool.config.service_key, signature, 10)
        .unwrap();
    assert!(
        offer
            .verify(POOL, pool.config.service_key, signature, 1000)
            .is_err()
    );
    assert!(
        offer
            .sign(&pool.config, identity(2).master_keypair())
            .is_err()
    );
    let hidden = ClientOffer {
        native_host_visible: false,
        ..offer
    };
    assert!(hidden.sign(&pool.config, &key).is_err());
}

#[tokio::test]
async fn causal_gap_prevents_forwarding_and_expired_contribution_stays_unavailable() {
    let (pool, keys) = fixture().await;
    target(&pool).await;
    let contribution = pool
        .author(&identity(2), contribution(2, DEVICE_A), 2)
        .await
        .unwrap();
    let replica = PoolStore::new(
        pool.moot.clone(),
        MemoryBackend::new(),
        pool.config.clone(),
        source(keys),
    )
    .unwrap();
    replica.accept(&contribution, 3).await.unwrap();
    assert!(replica.view(3).await.unwrap().pending);
    assert!(
        replica
            .authorize(root(4), DEVICE_A, TARGET, 3)
            .await
            .is_err()
    );
    for operation in pool.operations().await.unwrap() {
        replica.accept(&operation, 3).await.unwrap();
    }
    assert!(
        replica
            .authorize(root(4), DEVICE_A, TARGET, 3)
            .await
            .is_ok()
    );
    assert!(
        replica
            .authorize(root(4), DEVICE_A, TARGET, 60_000)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn durable_cold_reopen_restores_signed_consent_but_no_availability() {
    let directory = tempfile::tempdir().unwrap();
    let moot_path = directory.path().join("moot");
    let pool_path = directory.path().join("relay.redb");
    let moot = Arc::new(
        Moot::open(&moot_path, MootId([31; 32]), root(1), retention())
            .await
            .unwrap(),
    );
    initialize(&moot).await;
    let config = PoolPolicy {
        moot: moot.moot_id(),
        pool: POOL,
        coordination: [72; 32],
        constitution_revision: moot.snapshot().await.unwrap().governance.revision,
        revision: [42; 32],
        service_key: root(9),
        max_records: 128,
        max_lease_ms: 60_000,
        max_authority_age_ms: 1000,
        authority_expires_at_ms: 60_000,
    };
    let (session, _, _) = distributed_keys();
    let host_keys = keys(&session);
    let before = {
        let pool = PoolStore::new(
            moot.clone(),
            muniment::RedbBackend::open(&pool_path).unwrap(),
            config.clone(),
            source(host_keys.clone()),
        )
        .unwrap();
        pool.author(&identity(2), contribution(2, DEVICE_A), 2)
            .await
            .unwrap();
        pool.view(3).await.unwrap().revision
    };
    drop(moot);
    let reopened_moot = Arc::new(
        Moot::open_existing(&moot_path, config.moot, retention())
            .await
            .unwrap(),
    );
    let reopened = PoolStore::new(
        reopened_moot,
        muniment::RedbBackend::open(&pool_path).unwrap(),
        config,
        source(host_keys),
    )
    .unwrap();
    let view = reopened.view(3).await.unwrap();
    assert_eq!(view.revision, before);
    assert!(view.contribution(DEVICE_A).is_some());
    assert!(OfferBook::default().candidates(&view).is_empty());
}

#[tokio::test]
async fn sync_reader_hook_requires_operator_authority_even_when_namespace_is_known() {
    use murm_sync::{AfterHandshakeOutcome, SyncHooks};
    let (pool, _) = fixture().await;
    let contribution =
        PoolContribution::attest(&identity(2), POOL, DEVICE_A, 65_536, 65_536, 2, 0, 60_000)
            .unwrap();
    let device_key = contribution.service_key;
    pool.author(&identity(2), PoolEvent::Contribute(contribution), 2)
        .await
        .unwrap();
    let hook = super::store::PoolSyncGate {
        store: pool.clone(),
        clock: Arc::new(|| 10),
    };
    let topic = p2panda_core::Topic::from(pool.config.coordination);
    for seed in [2, 3] {
        assert!(matches!(
            hook.after_handshake(
                p2panda_core::VerifyingKey::from_bytes(&root(seed)).unwrap(),
                &topic
            )
            .await,
            AfterHandshakeOutcome::Accept
        ));
    }
    assert!(matches!(
        hook.after_handshake(
            p2panda_core::VerifyingKey::from_bytes(&device_key).unwrap(),
            &topic
        )
        .await,
        AfterHandshakeOutcome::Accept
    ));
    for seed in [4, 5] {
        assert!(matches!(
            hook.after_handshake(
                p2panda_core::VerifyingKey::from_bytes(&root(seed)).unwrap(),
                &topic
            )
            .await,
            AfterHandshakeOutcome::Reject
        ));
    }
    pool.moot
        .update_membership_for_identity(
            &identity(1),
            MootMembershipAction::Remove { member: root(2) },
        )
        .await
        .unwrap();
    assert!(matches!(
        hook.after_handshake(
            p2panda_core::VerifyingKey::from_bytes(&device_key).unwrap(),
            &topic
        )
        .await,
        AfterHandshakeOutcome::Reject
    ));
}
