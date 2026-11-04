// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

use super::*;
use murm::relay::{
    DeviceBudget, DeviceLimits, FlowLimits, RECIPIENT_PROTOCOL, RELAY_PROTOCOL, RelayChannel,
    RelayGrant, RelayRequest, RelayService, RelayTarget,
};
use murm::{Admission, Credentials};
use notochord::{
    LocalNetworkPolicy, NetworkId, ProfileRef, RequestedAction, RevocationLedger,
    SecureIdentityPolicy, ServiceAccess, ServiceRule, TrafficClass,
};
use std::collections::BTreeMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Instant, timeout};
use transport::security::{PreparedStream, ServiceSecurityPolicy, SetupGate, SetupLimits};

mod processes;
use transport::{Alpn, P2pandaTransport, PeerID, Transport};

const PATH: &str = "/services/murm/relay";
fn protocol(bytes: &[u8]) -> Alpn {
    Alpn::from_bytes(bytes.to_vec())
}
fn local_policy() -> LocalNetworkPolicy {
    let mut policy = LocalNetworkPolicy::closed(NetworkId(POOL));
    policy.accepted_profiles = vec![ProfileRef {
        id: "murm.relay.native".into(),
        revision: 1,
    }];
    // The transport entry verifies the channel-bound subject. The actual pool
    // target permission is separately checked against current signed Moot law.
    policy.services = BTreeMap::from([(
        PATH.into(),
        ServiceRule::new(
            ServiceAccess::Public,
            "mere.network",
            ["connect"],
            true,
            Some(16),
        ),
    )]);
    policy
}
fn credentials(provider: &InMemoryProvider) -> Credentials<'_, InMemoryProvider> {
    Credentials {
        identity: provider,
        network: NetworkId(POOL),
        profile: ProfileRef {
            id: "murm.relay.native".into(),
            revision: 1,
        },
        action: RequestedAction {
            domain: "mere.network".into(),
            path: PATH.into(),
            action: "connect".into(),
        },
        class: TrafficClass::Interactive,
        nonce: identity::Ed25519Keypair::generate().public_key().to_bytes(),
        delegations: vec![],
    }
}
fn admission<'a>(policy: &'a LocalNetworkPolicy, ledger: &'a RevocationLedger) -> Admission<'a> {
    Admission {
        policy,
        ledger,
        identity: SecureIdentityPolicy::MatchCarrierWhenPresent,
        now_ms: 10,
        active_sessions: 0,
    }
}
async fn bind(seed: u8) -> Arc<P2pandaTransport> {
    Arc::new(
        P2pandaTransport::builder(identity(seed).master_keypair())
            .alpns(vec![protocol(RELAY_PROTOCOL), protocol(RECIPIENT_PROTOCOL)])
            .gossip()
            .bind()
            .await
            .unwrap(),
    )
}
async fn pair(a: &P2pandaTransport, b: &P2pandaTransport) {
    a.add_peer_ticket(&b.ticket().await.unwrap()).await.unwrap();
    b.add_peer_ticket(&a.ticket().await.unwrap()).await.unwrap();
}
fn budget() -> DeviceBudget {
    DeviceBudget::new(DeviceLimits {
        max_pending: 8,
        max_sessions: 2,
        max_bytes: 1_048_576,
        bytes_per_second: 1_048_576,
    })
    .unwrap()
}

type Live = Arc<RwLock<Option<RelayGrant>>>;
fn permission(grant: PoolAuthorization) -> RelayGrant {
    grant
        .native_grant(10, Instant::now() + Duration::from_secs(10))
        .unwrap()
}

fn worker(
    carrier: Arc<P2pandaTransport>,
    target_peer: PeerID,
    seed: u8,
    live: Live,
    device: DeviceBudget,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let service = Arc::new(
            RelayService::new(
                POOL,
                vec![RelayTarget {
                    id: TARGET,
                    peer: target_peer,
                }],
                carrier.clone(),
                device,
                FlowLimits {
                    max_sessions: 2,
                    max_bytes: 65_536,
                    bytes_per_second: 65_536,
                    buffer_bytes: 1024,
                    lifetime: Duration::from_secs(10),
                    authority_interval: Duration::from_millis(5),
                },
                SetupLimits::default(),
            )
            .unwrap(),
        );
        let policy = Arc::new(local_policy());
        let mut tasks = JoinSet::new();
        loop {
            let accepted = carrier.accept(protocol(RELAY_PROTOCOL)).await.unwrap();
            let service = service.clone();
            let live = live.clone();
            let policy = policy.clone();
            tasks.spawn(async move {
                let provider = identity(seed);
                let ledger = RevocationLedger::default();
                let _ = service
                    .serve(
                        accepted,
                        admission(&policy, &ledger),
                        credentials(&provider),
                        |principal, request| {
                            if principal.subject != root(4) || request.target != TARGET {
                                return None;
                            }
                            *live.read().unwrap()
                        },
                    )
                    .await;
            });
        }
    })
}

fn recipient(carrier: Arc<P2pandaTransport>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let channel = RelayChannel::new(RECIPIENT_PROTOCOL, 8, SetupLimits::default());
        let policy = Arc::new(local_policy());
        let mut tasks = JoinSet::new();
        loop {
            let accepted = carrier.accept(protocol(RECIPIENT_PROTOCOL)).await.unwrap();
            let channel = channel.clone();
            let policy = policy.clone();
            tasks.spawn(async move {
                let ledger = RevocationLedger::default();
                let Ok((outer, principal)) =
                    channel.accept(accepted, admission(&policy, &ledger)).await
                else {
                    return;
                };
                if ![root(2), root(3)].contains(&principal.subject) {
                    return;
                }
                let provider = identity(8);
                let inner_policy = ServiceSecurityPolicy::noise(
                    protocol(RECIPIENT_PROTOCOL),
                    Some(PeerID::from_bytes(&root(4)).unwrap()),
                    SetupLimits::default(),
                );
                let gate = SetupGate::new(8);
                let Ok((mut stream, _, guard)) = gate
                    .noise_responder(provider.master_keypair(), outer, &inner_policy)
                    .await
                else {
                    return;
                };
                if guard.admitted().is_err() {
                    return;
                }
                let mut buffer = [0; 1024];
                loop {
                    let Ok(count) = stream.read(&mut buffer).await else {
                        return;
                    };
                    if count == 0 {
                        let _ = stream.shutdown().await;
                        return;
                    }
                    if stream.write_all(&buffer[..count]).await.is_err()
                        || stream.flush().await.is_err()
                    {
                        return;
                    }
                }
            });
        }
    })
}

async fn open(
    client: &P2pandaTransport,
    worker: PeerID,
    seed: u8,
    expected: u8,
) -> Result<PreparedStream<PreparedStream<transport::P2pandaStream>>, ()> {
    let provider = identity(seed);
    let outer = RelayChannel::new(RELAY_PROTOCOL, 2, SetupLimits::default())
        .open(
            client,
            worker,
            credentials(&provider),
            RelayRequest {
                pool: POOL,
                target: TARGET,
            },
        )
        .await
        .map_err(|_| ())?;
    let policy = ServiceSecurityPolicy::noise(
        protocol(RECIPIENT_PROTOCOL),
        Some(PeerID::from_bytes(&root(expected)).unwrap()),
        SetupLimits::default(),
    );
    let gate = SetupGate::new(2);
    let (stream, _, guard) = gate
        .noise_initiator(provider.master_keypair(), outer, &policy)
        .await
        .map_err(|_| ())?;
    guard.admitted().map_err(|_| ())?;
    Ok(stream)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_two_workers_encrypted_forwarding_failover_and_live_withdrawal() {
    timeout(Duration::from_secs(30), async {
        let (mut pool, keys) = fixture().await;
        pool.config.max_authority_age_ms = 10_000;
        target(&pool).await;
        pool.author(&identity(2), contribution(2, DEVICE_A), 2)
            .await
            .unwrap();
        pool.author(&identity(3), contribution(3, DEVICE_B), 2)
            .await
            .unwrap();
        let client = bind(4).await;
        let attacker = bind(5).await;
        let first = bind(2).await;
        let second = bind(3).await;
        let target_carrier = bind(8).await;
        for relay in [&first, &second] {
            pair(&client, relay).await;
            pair(&attacker, relay).await;
            pair(relay, &target_carrier).await;
        }
        pair(&first, &second).await;
        // Real JoinedSpace/LogSync uses ciphertext and the same validating intake.
        let replica = PoolStore::new(
            pool.moot.clone(),
            MemoryBackend::new(),
            pool.config.clone(),
            source(keys),
        )
        .unwrap();
        let (endpoint, gossip) = first.sync_parts().unwrap();
        let left = pool.join(endpoint, gossip, Arc::new(|| 10)).await.unwrap();
        let (endpoint, gossip) = second.sync_parts().unwrap();
        let right = replica
            .join(endpoint, gossip, Arc::new(|| 10))
            .await
            .unwrap();
        let topic = transport::sync_overlay_topic(pool.config.coordination);
        first
            .set_topics(second.local_peer_id(), &[topic])
            .await
            .unwrap();
        second
            .set_topics(first.local_peer_id(), &[topic])
            .await
            .unwrap();
        let expected = pool.operations().await.unwrap().len();
        timeout(Duration::from_secs(10), async {
            loop {
                left.resync().await;
                right.resync().await;
                if replica.operations().await.unwrap().len() == expected {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            pool.view(10).await.unwrap().revision,
            replica.view(10).await.unwrap().revision
        );
        let mut first_permission =
            permission(pool.authorize(root(4), DEVICE_A, TARGET, 10).await.unwrap());
        first_permission.max_sessions = 1;
        let first_live = Arc::new(RwLock::new(Some(first_permission)));
        let second_live = Arc::new(RwLock::new(Some(permission(
            pool.authorize(root(4), DEVICE_B, TARGET, 10).await.unwrap(),
        ))));
        let first_budget = budget();
        let second_budget = budget();
        let first_task = worker(
            first.clone(),
            target_carrier.local_peer_id(),
            2,
            first_live.clone(),
            first_budget.clone(),
        );
        let second_task = worker(
            second.clone(),
            target_carrier.local_peer_id(),
            3,
            second_live.clone(),
            second_budget.clone(),
        );
        let recipient_task = recipient(target_carrier.clone());
        let view = pool.view(10).await.unwrap();
        let mut offers = OfferBook::default();
        for (seed, device) in [(2, DEVICE_A), (3, DEVICE_B)] {
            let probe = offers.probe(&view, device, 20_000, 10).unwrap();
            let service_key = identity(seed)
                .derive_keypair(&device_salt(POOL, device))
                .unwrap();
            offers
                .confirm(
                    &view,
                    &probe,
                    service_key.sign(&probe.signing_bytes()).to_bytes(),
                )
                .unwrap();
        }
        assert_eq!(offers.candidates(&view)[0].device, DEVICE_A);
        let payload = b"fixture payload known only at authenticated Noise endpoints";
        let mut stream = open(&client, first.local_peer_id(), 4, 8).await.unwrap();
        stream.write_all(payload).await.unwrap();
        stream.flush().await.unwrap();
        let mut received = vec![0; payload.len()];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(received, payload);
        // The granted pool ceiling can be tighter than the local device slots.
        assert!(open(&client, first.local_peer_id(), 4, 8).await.is_err());
        assert!(open(&attacker, second.local_peer_id(), 5, 8).await.is_err());
        assert!(open(&client, second.local_peer_id(), 4, 9).await.is_err());
        first_task.abort();
        let _ = first_task.await;
        offers.failed(DEVICE_A);
        assert_eq!(
            offers
                .candidates(&view)
                .iter()
                .map(|o| o.device)
                .collect::<Vec<_>>(),
            vec![DEVICE_B]
        );
        assert!(matches!(
            timeout(Duration::from_secs(1), stream.read_u8()).await,
            Ok(Err(_))
        ));
        let mut failover = open(&client, second.local_peer_id(), 4, 8).await.unwrap();
        failover.write_all(payload).await.unwrap();
        failover.flush().await.unwrap();
        failover.read_exact(&mut received).await.unwrap();
        assert_eq!(received, payload);
        pool.author(&identity(3), PoolEvent::Withdraw { device: DEVICE_B }, 20)
            .await
            .unwrap();
        assert!(pool.authorize(root(4), DEVICE_B, TARGET, 20).await.is_err());
        *second_live.write().unwrap() = None;
        assert!(matches!(
            timeout(Duration::from_secs(1), failover.read_u8()).await,
            Ok(Err(_))
        ));
        assert!(open(&client, second.local_peer_id(), 4, 8).await.is_err());
        second_task.abort();
        recipient_task.abort();
        let _ = second_task.await;
        let _ = recipient_task.await;
        left.leave_and_wait().await.unwrap();
        right.leave_and_wait().await.unwrap();
        for carrier in [client, attacker, first, second, target_carrier] {
            carrier.close().await.unwrap();
        }
        tokio::task::yield_now().await;
        assert_eq!(first_budget.stats().active, 0);
        assert_eq!(second_budget.stats().active, 0);
        assert_eq!(first_budget.stats().pending_setups, 0);
        assert_eq!(second_budget.stats().pending_setups, 0);
    })
    .await
    .unwrap();
}
