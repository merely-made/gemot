// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

use super::super::host::{CustodyEpoch, OwnerClock, WorkerAccess, WorkerAuthority};
use super::*;
use murm::relay::RelayRequest;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

fn access() -> Vec<WorkerAccess> {
    vec![WorkerAccess {
        requester: root(4),
        target: PoolTarget {
            id: TARGET,
            recipient_key: root(8),
            max_bytes: 16_384,
        },
    }]
}
fn key() -> identity::Ed25519Keypair {
    identity(2)
        .derive_keypair(&device_salt(POOL, DEVICE_A))
        .unwrap()
}
fn request() -> RelayRequest {
    RelayRequest {
        pool: POOL,
        target: TARGET,
    }
}
fn host(
    pool: PoolStore<MemoryBackend>,
    clock: OwnerClock,
    custody: CustodyEpoch,
) -> WorkerAuthority<MemoryBackend> {
    WorkerAuthority::new(
        pool,
        DEVICE_A,
        key().public_key().to_bytes(),
        access(),
        clock,
        custody,
        Duration::from_secs(5),
    )
    .unwrap()
}
async fn ready(host: &WorkerAuthority<MemoryBackend>) {
    let probe = host.probe(Duration::from_secs(5)).await.unwrap();
    host.confirm(&probe, key().sign(&probe.signing_bytes()).to_bytes())
        .await
        .unwrap();
    assert_eq!(host.refresh().await.unwrap(), 1);
}
async fn records() -> PoolStore<MemoryBackend> {
    let (pool, _) = fixture().await;
    target(&pool).await;
    pool.author(&identity(2), contribution(2, DEVICE_A), 2)
        .await
        .unwrap();
    pool
}

#[tokio::test(start_paused = true)]
async fn host_requires_fresh_readiness_and_real_authority_after_reopen() {
    let pool = records().await;
    let worker = host(pool.clone(), Arc::new(|| Some(10)), Arc::new(|| Some(1)));
    assert_eq!(worker.refresh().await.unwrap(), 0);
    assert!(worker.authorize(root(4), &request()).is_none());
    let probe = worker.probe(Duration::from_secs(5)).await.unwrap();
    let bad = identity(3)
        .master_keypair()
        .sign(&probe.signing_bytes())
        .to_bytes();
    assert!(worker.confirm(&probe, bad).await.is_err());
    let signature = key().sign(&probe.signing_bytes()).to_bytes();
    worker.confirm(&probe, signature).await.unwrap();
    assert!(worker.confirm(&probe, signature).await.is_err());
    worker.refresh().await.unwrap();
    let granted = worker.authorize(root(4), &request()).unwrap();
    assert_eq!(granted.max_bytes, 16_384);
    assert!(worker.authorize(root(2), &request()).is_none());
    let reopened = host(pool.clone(), Arc::new(|| Some(10)), Arc::new(|| Some(1)));
    assert_eq!(reopened.refresh().await.unwrap(), 0);
    assert!(reopened.confirm(&probe, signature).await.is_err());
    pool.author(&identity(2), PoolEvent::Withdraw { device: DEVICE_A }, 11)
        .await
        .unwrap();
    assert_eq!(worker.refresh().await.unwrap(), 0);
    assert!(worker.authorize(root(4), &request()).is_none());
}

#[tokio::test(start_paused = true)]
async fn stalled_clock_cannot_extend_checkpoint_or_cached_grant() {
    let mut pool = records().await;
    pool.config.authority_expires_at_ms = 3010;
    let worker = host(pool, Arc::new(|| Some(10)), Arc::new(|| Some(1)));
    ready(&worker).await;
    tokio::time::advance(Duration::from_millis(1001)).await;
    assert!(worker.authorize(root(4), &request()).is_none());
    assert_eq!(worker.refresh().await.unwrap(), 1);
    tokio::time::advance(Duration::from_millis(1001)).await;
    worker.refresh().await.unwrap();
    tokio::time::advance(Duration::from_millis(1001)).await;
    assert!(worker.authorize(root(4), &request()).is_none());
    assert!(worker.refresh().await.is_err());
    assert!(worker.probe(Duration::from_secs(1)).await.is_err());
}

#[tokio::test(start_paused = true)]
async fn custody_generation_and_clock_regression_fail_closed() {
    let pool = records().await;
    let time = Arc::new(AtomicU64::new(10));
    let epoch = Arc::new(AtomicU64::new(1));
    let observed_time = time.clone();
    let observed_epoch = epoch.clone();
    let worker = host(
        pool.clone(),
        Arc::new(move || Some(observed_time.load(Ordering::SeqCst))),
        Arc::new(move || {
            let epoch = observed_epoch.load(Ordering::SeqCst);
            (epoch > 0).then_some(epoch)
        }),
    );
    ready(&worker).await;
    epoch.store(0, Ordering::SeqCst);
    assert!(worker.authorize(root(4), &request()).is_none());
    epoch.store(2, Ordering::SeqCst);
    assert!(worker.refresh().await.is_err());
    assert!(worker.authorize(root(4), &request()).is_none());
    let observed_time = time.clone();
    let new_host = host(
        pool,
        Arc::new(move || Some(observed_time.load(Ordering::SeqCst))),
        Arc::new(|| Some(2)),
    );
    ready(&new_host).await;
    time.store(9, Ordering::SeqCst);
    assert!(new_host.authorize(root(4), &request()).is_none());
    assert!(new_host.refresh().await.is_err());
    time.store(12, Ordering::SeqCst);
    assert!(new_host.refresh().await.is_err());
    let jumped = Arc::new(AtomicU64::new(10));
    let observed = jumped.clone();
    let forward = host(
        records().await,
        Arc::new(move || Some(observed.load(Ordering::SeqCst))),
        Arc::new(|| Some(1)),
    );
    ready(&forward).await;
    jumped.store(1011, Ordering::SeqCst);
    assert!(forward.authorize(root(4), &request()).is_none());
}

#[tokio::test]
async fn host_refuses_foreign_recipient_and_revoked_requester() {
    let pool = records().await;
    let mut bad = access();
    bad[0].target.recipient_key = root(9);
    let wrong = WorkerAuthority::new(
        pool.clone(),
        DEVICE_A,
        key().public_key().to_bytes(),
        bad,
        Arc::new(|| Some(10)),
        Arc::new(|| Some(1)),
        Duration::from_secs(5),
    )
    .unwrap();
    let probe = wrong.probe(Duration::from_secs(5)).await.unwrap();
    wrong
        .confirm(&probe, key().sign(&probe.signing_bytes()).to_bytes())
        .await
        .unwrap();
    assert_eq!(wrong.refresh().await.unwrap(), 0);
    let worker = host(pool.clone(), Arc::new(|| Some(10)), Arc::new(|| Some(1)));
    ready(&worker).await;
    pool.moot
        .update_membership_for_identity(
            &identity(1),
            MootMembershipAction::Remove { member: root(4) },
        )
        .await
        .unwrap();
    assert_eq!(worker.refresh().await.unwrap(), 0);
    assert!(worker.authorize(root(4), &request()).is_none());
}

#[tokio::test]
async fn private_control_keys_are_scoped_and_rechecked_against_real_membership() {
    use super::super::store::{PoolSyncGate, control_bindings};
    use murm_sync::{AfterHandshakeOutcome, SyncHooks};
    let pool = records().await;
    let peer = ControlPeer {
        device: DEVICE_A,
        attestation: identity(2)
            .attest_derived_key(&control_salt(POOL, DEVICE_A))
            .unwrap(),
    };
    assert!(control_bindings([99; 32], vec![peer.clone()]).is_err());
    assert!(control_bindings(POOL, vec![peer.clone(), peer.clone()]).is_err());
    let private_key = *peer.attestation.derived();
    assert_ne!(private_key, key().public_key().to_bytes());
    let gate = PoolSyncGate {
        store: pool.clone(),
        clock: Arc::new(|| 10),
        control: Some(control_bindings(POOL, vec![peer]).unwrap()),
    };
    let topic = p2panda_core::Topic::from(pool.config.coordination);
    let verify = |bytes| p2panda_core::VerifyingKey::from_bytes(&bytes).unwrap();
    assert!(matches!(
        gate.after_handshake(verify(private_key), &topic).await,
        AfterHandshakeOutcome::Accept
    ));
    for public in [root(2), key().public_key().to_bytes(), root(4)] {
        assert!(matches!(
            gate.after_handshake(verify(public), &topic).await,
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
        gate.after_handshake(verify(private_key), &topic).await,
        AfterHandshakeOutcome::Reject
    ));
}

#[tokio::test]
async fn durable_host_reopen_preserves_consent_but_requires_a_new_readiness_proof() {
    let dir = tempfile::tempdir().unwrap();
    let moot_dir = dir.path().join("moot");
    let db = dir.path().join("pool.redb");
    let moot = Arc::new(
        Moot::open(&moot_dir, MootId([31; 32]), root(1), retention())
            .await
            .unwrap(),
    );
    initialize(&moot).await;
    let (base, keys) = fixture().await;
    let mut config = base.config.clone();
    config.constitution_revision = moot.snapshot().await.unwrap().governance.revision;
    let old_probe = {
        let pool = PoolStore::new(
            moot.clone(),
            muniment::RedbBackend::open(&db).unwrap(),
            config.clone(),
            source(keys.clone()),
        )
        .unwrap();
        pool.author(
            &identity(1),
            PoolEvent::RegisterTarget(access()[0].target.clone()),
            1,
        )
        .await
        .unwrap();
        pool.author(&identity(2), contribution(2, DEVICE_A), 2)
            .await
            .unwrap();
        let worker = WorkerAuthority::new(
            pool,
            DEVICE_A,
            key().public_key().to_bytes(),
            access(),
            Arc::new(|| Some(10)),
            Arc::new(|| Some(1)),
            Duration::from_secs(5),
        )
        .unwrap();
        let probe = worker.probe(Duration::from_secs(5)).await.unwrap();
        worker
            .confirm(&probe, key().sign(&probe.signing_bytes()).to_bytes())
            .await
            .unwrap();
        assert_eq!(worker.refresh().await.unwrap(), 1);
        assert!(worker.authorize(root(4), &request()).is_some());
        probe
    };
    drop(moot);
    let reopened = Arc::new(
        Moot::open_existing(&moot_dir, config.moot, retention())
            .await
            .unwrap(),
    );
    let pool = PoolStore::new(
        reopened,
        muniment::RedbBackend::open(&db).unwrap(),
        config,
        source(keys),
    )
    .unwrap();
    assert!(
        pool.view(10)
            .await
            .unwrap()
            .contribution(DEVICE_A)
            .is_some()
    );
    let worker = WorkerAuthority::new(
        pool,
        DEVICE_A,
        key().public_key().to_bytes(),
        access(),
        Arc::new(|| Some(10)),
        Arc::new(|| Some(2)),
        Duration::from_secs(5),
    )
    .unwrap();
    assert_eq!(worker.refresh().await.unwrap(), 0);
    assert!(
        worker
            .confirm(
                &old_probe,
                key().sign(&old_probe.signing_bytes()).to_bytes()
            )
            .await
            .is_err()
    );
    let probe = worker.probe(Duration::from_secs(5)).await.unwrap();
    worker
        .confirm(&probe, key().sign(&probe.signing_bytes()).to_bytes())
        .await
        .unwrap();
    assert_eq!(worker.refresh().await.unwrap(), 1);
    worker.close();
    assert!(worker.authorize(root(4), &request()).is_none());
    assert!(worker.refresh().await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worker_shutdown_drains_a_stalled_secure_setup() {
    use super::super::host::{I2pWorker, WorkerAdmission, WorkerLimits, WorkerStop};
    use super::native::{budget, credentials_for, local_policy_for};
    use murm::relay::{FlowLimits, i2p::I2pRoute};
    use transport::i2p::{I2pAddress, I2pSession, Key, TunnelProfile, fixture::SamFixture};
    let fixture = SamFixture::start().await;
    let profile = TunnelProfile::new(2, 2, 2, true).unwrap();
    let server = I2pSession::create(
        fixture.bridge(),
        Key::Transient,
        profile,
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    let client = I2pSession::create(
        fixture.bridge(),
        Key::Transient,
        profile,
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    let authority = host(records().await, Arc::new(|| Some(10)), Arc::new(|| Some(1)));
    ready(&authority).await;
    let device = budget();
    let provider = Arc::new(identity(2));
    let credentials = credentials_for(provider.as_ref(), "murm.relay.i2p");
    let worker = I2pWorker::new(
        authority.clone(),
        server.clone(),
        vec![(
            TARGET,
            I2pRoute {
                address: I2pAddress::parse(&format!("{}.b32.i2p", "a".repeat(52))).unwrap(),
                service_key: root(8),
            },
        )],
        device.clone(),
        FlowLimits {
            max_sessions: 2,
            max_bytes: 65_536,
            bytes_per_second: 65_536,
            buffer_bytes: 1024,
            lifetime: Duration::from_secs(10),
            authority_interval: Duration::from_millis(10),
        },
        transport::security::SetupLimits {
            timeout: Duration::from_secs(10),
            ..Default::default()
        },
        provider.clone(),
        WorkerAdmission {
            policy: Arc::new(local_policy_for("murm.relay.i2p", false)),
            ledger: Arc::new(notochord::RevocationLedger::default()),
            identity: notochord::SecureIdentityPolicy::MatchCarrierWhenPresent,
            profile: credentials.profile,
            action: credentials.action,
            class: credentials.class,
            outbound_key_salt: b"mere/network-policy/session-signer/v1".to_vec(),
        },
    )
    .unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(worker.run(
        WorkerLimits {
            max_tasks: 2,
            refresh_interval: Duration::from_secs(1),
            refresh_timeout: Duration::from_secs(2),
            shutdown_timeout: Duration::from_secs(2),
        },
        async {
            let _ = stopped.await;
        },
    ));
    let stalled = client.connect(&server.address().unwrap()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while device.stats().pending_setups == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    stop.send(()).unwrap();
    let report = tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(report.reason, WorkerStop::Requested);
    assert!(report.drained);
    assert_eq!(report.accepted, 1);
    assert_eq!(report.device.pending_setups, 0);
    assert_eq!(report.device.active, 0);
    assert!(authority.authorize(root(4), &request()).is_none());
    drop((stalled, client, server));
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scoped_operator_endpoints_replicate_existing_encrypted_pool_records() {
    use transport::{P2pandaTransport, Transport};
    // Use this pool's actual key source, not another group's random epoch.
    let (source_pool, source_keys) = fixture().await;
    target(&source_pool).await;
    source_pool
        .author(&identity(2), contribution(2, DEVICE_A), 2)
        .await
        .unwrap();
    let replica = PoolStore::new(
        source_pool.moot.clone(),
        MemoryBackend::new(),
        source_pool.config.clone(),
        source(source_keys),
    )
    .unwrap();
    let left_identity = identity(2);
    let right_identity = identity(3);
    let left_key = left_identity
        .derived_keypair(&control_salt(POOL, DEVICE_A))
        .unwrap();
    let right_key = right_identity
        .derived_keypair(&control_salt(POOL, DEVICE_B))
        .unwrap();
    let left = P2pandaTransport::builder_for(&left_key)
        .gossip()
        .bind()
        .await
        .unwrap();
    let right = P2pandaTransport::builder_for(&right_key)
        .gossip()
        .bind()
        .await
        .unwrap();
    let left_peer = ControlPeer {
        device: DEVICE_A,
        attestation: left_identity
            .attest_derived_key(&control_salt(POOL, DEVICE_A))
            .unwrap(),
    };
    let right_peer = ControlPeer {
        device: DEVICE_B,
        attestation: right_identity
            .attest_derived_key(&control_salt(POOL, DEVICE_B))
            .unwrap(),
    };
    let (endpoint, gossip) = left.sync_parts().unwrap();
    let first = source_pool
        .join_with_control_peers(endpoint, gossip, Arc::new(|| 10), vec![right_peer])
        .await
        .unwrap();
    let (endpoint, gossip) = right.sync_parts().unwrap();
    let second = replica
        .join_with_control_peers(endpoint, gossip, Arc::new(|| 10), vec![left_peer])
        .await
        .unwrap();
    left.add_peer_ticket(&right.ticket().await.unwrap())
        .await
        .unwrap();
    right
        .add_peer_ticket(&left.ticket().await.unwrap())
        .await
        .unwrap();
    let topic = transport::sync_overlay_topic(source_pool.config.coordination);
    left.set_topics(right.local_peer_id(), &[topic])
        .await
        .unwrap();
    right
        .set_topics(left.local_peer_id(), &[topic])
        .await
        .unwrap();
    let expected = source_pool.operations().await.unwrap().len();
    let caught_up = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            first.resync().await;
            second.resync().await;
            if replica.operations().await.unwrap().len() == expected {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            source_pool.view(10).await.unwrap().revision,
            replica.view(10).await.unwrap().revision
        );
    })
    .await;
    drop((first, second));
    left.close().await.unwrap();
    right.close().await.unwrap();
    caught_up.unwrap();
}
