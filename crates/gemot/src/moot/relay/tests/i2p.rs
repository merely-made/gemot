// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

use super::super::host::{I2pWorker, WorkerAccess, WorkerAdmission, WorkerAuthority, WorkerLimits};
use super::native::{admission, budget, credentials_for, local_policy_for};
use super::*;
use murm::relay::i2p::{
    I2P_RECIPIENT_PROTOCOL, I2P_RELAY_PROTOCOL, I2pRelayChannel, I2pRelayStream, I2pRoute,
    I2pSession, TunnelProfile,
};
use murm::relay::{FlowLimits, RECIPIENT_PROTOCOL};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Instant, timeout};
use transport::i2p::fixture::SamFixture;
use transport::security::{PreparedStream, ServiceSecurityPolicy, SetupGate, SetupLimits};
use transport::{Alpn, PeerID};

mod live;
mod scenario;
const PROFILE: &str = "murm.relay.i2p";
fn setup(seconds: u64) -> SetupLimits {
    SetupLimits {
        timeout: Duration::from_secs(seconds),
        ..SetupLimits::default()
    }
}
struct Host {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
    device: murm::relay::DeviceBudget,
}
impl Host {
    async fn stop(mut self) {
        let _ = self.stop.take().unwrap().send(());
        timeout(Duration::from_secs(5), self.task.take().unwrap())
            .await
            .unwrap()
            .unwrap();
        tokio::task::yield_now().await;
        assert_eq!(self.device.stats().active, 0);
        assert_eq!(self.device.stats().pending_setups, 0);
    }
}
impl Drop for Host {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

fn worker(
    session: I2pSession,
    target: I2pRoute,
    seed: u8,
    authority: WorkerAuthority<MemoryBackend>,
    seconds: u64,
) -> Host {
    let device = budget();
    let allowance = device.clone();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let owner = Arc::new(identity(seed));
        let credentials = credentials_for(owner.as_ref(), PROFILE);
        let worker = I2pWorker::new(
            authority,
            session,
            vec![(TARGET, target)],
            allowance,
            FlowLimits {
                max_sessions: 2,
                max_bytes: 65_536,
                bytes_per_second: 65_536,
                buffer_bytes: 1024,
                lifetime: Duration::from_secs(seconds),
                authority_interval: Duration::from_millis(5),
            },
            setup(seconds),
            owner.clone(),
            WorkerAdmission {
                policy: Arc::new(local_policy_for(PROFILE, false)),
                ledger: Arc::new(notochord::RevocationLedger::default()),
                identity: notochord::SecureIdentityPolicy::MatchCarrierWhenPresent,
                profile: credentials.profile,
                action: credentials.action,
                class: credentials.class,
                outbound_key_salt: b"mere/network-policy/session-signer/v1".to_vec(),
            },
        )
        .unwrap();
        let report = worker
            .run(
                WorkerLimits {
                    max_tasks: 8,
                    refresh_interval: Duration::from_secs(1),
                    refresh_timeout: Duration::from_secs(2),
                    shutdown_timeout: Duration::from_secs(3),
                },
                async {
                    let _ = stopped.await;
                },
            )
            .await
            .unwrap();
        assert!(report.drained);
    });
    Host {
        stop: Some(stop),
        task: Some(task),
        device,
    }
}

fn worker_authority(
    pool: &PoolStore<MemoryBackend>,
    device: [u8; 32],
    started: Instant,
) -> WorkerAuthority<MemoryBackend> {
    let seed = if device == DEVICE_A { 2 } else { 3 };
    let key = identity(seed)
        .derive_keypair(&device_salt(POOL, device))
        .unwrap();
    WorkerAuthority::new(
        pool.clone(),
        device,
        key.public_key().to_bytes(),
        vec![WorkerAccess {
            requester: root(4),
            target: recipient_pin(),
        }],
        Arc::new(move || Some(10 + started.elapsed().as_millis() as u64)),
        Arc::new(|| Some(1)),
        Duration::from_secs(120),
    )
    .unwrap()
}
async fn refresh_worker(authority: &WorkerAuthority<MemoryBackend>, device: [u8; 32]) {
    let seed = if device == DEVICE_A { 2 } else { 3 };
    let probe = authority.probe(Duration::from_secs(120)).await.unwrap();
    let key = identity(seed)
        .derive_keypair(&device_salt(POOL, device))
        .unwrap();
    authority
        .confirm(&probe, key.sign(&probe.signing_bytes()).to_bytes())
        .await
        .unwrap();
    assert_eq!(authority.refresh().await.unwrap(), 1);
}

fn recipient(session: I2pSession, seconds: u64) -> Host {
    let device = budget();
    let (stop, mut stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let channel = I2pRelayChannel::new(I2P_RECIPIENT_PROTOCOL, 8, setup(seconds));
        let policy = Arc::new(local_policy_for(PROFILE, false));
        let mut tasks = JoinSet::new();
        // SAM ACCEPT is an in-flight command, not a cancellation-safe TCP listener.
        let mut next_accept = Box::pin(session.accept());
        loop {
            tokio::select! {
                _ = &mut stopped => break,
                incoming = &mut next_accept, if tasks.len() < 8 => {
                    let Ok(stream) = incoming else { break };
                    next_accept = Box::pin(session.accept());
                    let (channel,policy) = (channel.clone(),policy.clone());
                    tasks.spawn(async move {
                        let provider = identity(8);
                        let ledger = notochord::RevocationLedger::default();
                        let Ok((outer,principal)) = channel.accept(stream,provider.master_keypair(),admission(&policy,&ledger)).await else { return };
                        if ![root(2),root(3)].contains(&principal.subject) { return; }
                        let security = ServiceSecurityPolicy::noise(Alpn::from_bytes(RECIPIENT_PROTOCOL.to_vec()),
                            Some(PeerID::from_bytes(&root(4)).unwrap()),setup(seconds));
                        let gate = SetupGate::new(4);
                        let Ok((mut stream,_,guard)) = gate.noise_responder(provider.master_keypair(),outer,&security).await else { return };
                        if guard.admitted().is_err() { return; }
                        let mut buffer = [0;1024];
                        loop {
                            let Ok(count) = stream.read(&mut buffer).await else { return };
                            if count == 0 { let _ = stream.shutdown().await; return; }
                            if stream.write_all(&buffer[..count]).await.is_err() || stream.flush().await.is_err() { return; }
                        }
                    });
                },
                _ = tasks.join_next(), if !tasks.is_empty() => {},
            }
        }
        tasks.shutdown().await;
    });
    Host {
        stop: Some(stop),
        task: Some(task),
        device,
    }
}

async fn open(
    client: &I2pSession,
    offer: &VerifiedI2pOffer,
    seconds: u64,
    wrong_recipient: bool,
) -> Result<PreparedStream<I2pRelayStream>, PoolError> {
    let provider = identity(4);
    let channel = I2pRelayChannel::new(I2P_RELAY_PROTOCOL, 4, setup(seconds));
    let outer = offer
        .open(
            &channel,
            client,
            provider.master_keypair(),
            credentials_for(&provider, PROFILE),
        )
        .await
        .inspect_err(|error| eprintln!("MURM_POOL_CLIENT_OUTER {error}"))?;
    let expected = if wrong_recipient {
        root(9)
    } else {
        offer.recipient_key()
    };
    let policy = ServiceSecurityPolicy::noise(
        Alpn::from_bytes(RECIPIENT_PROTOCOL.to_vec()),
        Some(PeerID::from_bytes(&expected).unwrap()),
        setup(seconds),
    );
    let gate = SetupGate::new(2);
    let (stream, _, guard) = gate
        .noise_initiator(provider.master_keypair(), outer, &policy)
        .await
        .map_err(|error| {
            eprintln!("MURM_POOL_CLIENT_INNER {error}");
            PoolError::Unauthorized
        })?;
    guard.admitted().map_err(|_| PoolError::Unauthorized)?;
    Ok(stream)
}

async fn pool() -> PoolStore<MemoryBackend> {
    let (base, keys) = fixture().await;
    let moot = Arc::new(Moot::in_memory(base.config.moot, root(1), retention()));
    initialize_for(&moot, 600_000).await;
    let mut config = base.config.clone();
    config.constitution_revision = moot.snapshot().await.unwrap().governance.revision;
    config.max_lease_ms = 600_000;
    config.max_authority_age_ms = 90_000;
    config.authority_expires_at_ms = 600_000;
    let pool = PoolStore::new(moot, MemoryBackend::new(), config, source(keys)).unwrap();
    target(&pool).await;
    for (seed, device) in [(2, DEVICE_A), (3, DEVICE_B)] {
        pool.author(
            &identity(seed),
            PoolEvent::Contribute(
                PoolContribution::attest(
                    &identity(seed),
                    POOL,
                    device,
                    65_536,
                    65_536,
                    2,
                    0,
                    600_000,
                )
                .unwrap(),
            ),
            2,
        )
        .await
        .unwrap();
    }
    pool
}

fn recipient_pin() -> PoolTarget {
    PoolTarget {
        id: TARGET,
        recipient_key: root(8),
        max_bytes: 32_768,
    }
}

fn offer(policy: &PoolPolicy, device: [u8; 32], route: &I2pRoute, now: u64) -> I2pClientOffer {
    let offer = I2pClientOffer {
        pool: POOL,
        alias: if device == DEVICE_A {
            [91; 32]
        } else {
            [92; 32]
        },
        target: TARGET,
        worker_key: route.service_key,
        recipient_key: root(8),
        destination: route.address.as_str().into(),
        expires_at_ms: now + 120_000,
    };
    let signature = offer.sign(policy, identity(9).master_keypair()).unwrap();
    assert!(
        offer
            .verify(
                POOL,
                policy.service_key,
                signature,
                &recipient_pin(),
                now,
                120_000
            )
            .is_ok()
    );
    offer
}

#[tokio::test]
async fn signed_i2p_offer_refuses_native_fields_tampering_expiry_and_cached_reuse() {
    let pool = pool().await;
    let route = I2pRoute {
        address: transport::i2p::I2pAddress::parse(&format!("{}.b32.i2p", "a".repeat(52))).unwrap(),
        service_key: root(2),
    };
    let mut offer = offer(&pool.config, DEVICE_A, &route, 10);
    let signature = offer
        .sign(&pool.config, identity(9).master_keypair())
        .unwrap();
    assert!(
        offer
            .verify(
                POOL,
                pool.config.service_key,
                signature,
                &recipient_pin(),
                offer.expires_at_ms,
                120_000
            )
            .is_err()
    );
    // A valid pool signer still cannot substitute the application's recipient.
    let mut substituted = offer.clone();
    substituted.recipient_key = root(9);
    let forged = substituted
        .sign(&pool.config, identity(9).master_keypair())
        .unwrap();
    assert!(
        substituted
            .verify(
                POOL,
                pool.config.service_key,
                forged,
                &recipient_pin(),
                10,
                120_000
            )
            .is_err()
    );
    let mut json = serde_json::to_value(&offer).unwrap();
    for forbidden in ["native_route", "coordination", "attestation", "owner_root"] {
        json.as_object_mut()
            .unwrap()
            .insert(forbidden.into(), serde_json::json!("refused"));
        assert!(serde_json::from_value::<I2pClientOffer>(json.clone()).is_err());
        json.as_object_mut().unwrap().remove(forbidden);
    }
    offer.worker_key = root(3);
    assert!(
        offer
            .verify(
                POOL,
                pool.config.service_key,
                signature,
                &recipient_pin(),
                10,
                120_000
            )
            .is_err()
    );
    offer.destination = "127.0.0.1:7656".into();
    assert!(
        offer
            .sign(&pool.config, identity(9).master_keypair())
            .is_err()
    );
    let fixture = SamFixture::start().await;
    let session = I2pSession::create(
        fixture.bridge(),
        transport::i2p::Key::Transient,
        TunnelProfile::new(2, 2, 2, false).unwrap(),
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    offer.destination = route.address.as_str().into();
    offer.worker_key = route.service_key;
    offer.expires_at_ms = 11;
    let signature = offer
        .sign(&pool.config, identity(9).master_keypair())
        .unwrap();
    let verified = offer
        .verify(
            POOL,
            pool.config.service_key,
            signature,
            &recipient_pin(),
            10,
            1000,
        )
        .unwrap();
    tokio::time::sleep(Duration::from_millis(3)).await;
    let provider = identity(4);
    let channel = I2pRelayChannel::new(I2P_RELAY_PROTOCOL, 2, setup(2));
    assert!(
        verified
            .open(
                &channel,
                &session,
                provider.master_keypair(),
                credentials_for(&provider, PROFILE)
            )
            .await
            .is_err()
    );
    assert_eq!(fixture.connects(), 0);
    drop(session);
    fixture.shutdown().await;
}

#[tokio::test]
async fn sam_never_satisfies_a_carrier_identity_requirement() {
    let fixture = SamFixture::start().await;
    let server = scenario::session(fixture.bridge(), true).await;
    let client = scenario::session(fixture.bridge(), false).await;
    let route = I2pRoute {
        address: server.address().unwrap(),
        service_key: root(2),
    };
    let server_task = tokio::spawn(async move {
        let policy = local_policy_for(PROFILE, true);
        let ledger = notochord::RevocationLedger::default();
        let provider = identity(2);
        let channel = I2pRelayChannel::new(I2P_RECIPIENT_PROTOCOL, 2, setup(2));
        channel
            .accept(
                server.accept().await.unwrap(),
                provider.master_keypair(),
                admission(&policy, &ledger),
            )
            .await
    });
    tokio::time::sleep(Duration::from_millis(10)).await;
    let provider = identity(4);
    let channel = I2pRelayChannel::new(I2P_RECIPIENT_PROTOCOL, 2, setup(2));
    assert!(
        channel
            .connect(
                &client,
                &route,
                provider.master_keypair(),
                credentials_for(&provider, PROFILE)
            )
            .await
            .is_err()
    );
    assert!(matches!(
        server_task.await.unwrap(),
        Err(murm::relay::RelayError::Unauthorized)
    ));
    let debug = format!("{client:?} {:?}", route.address);
    assert!(!debug.contains("127.0.0.1") && !debug.contains(route.address.as_str()));
    drop(client);
    fixture.shutdown().await;
}
