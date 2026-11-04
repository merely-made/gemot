// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

use super::*;
use transport::i2p::{Bridge, Key};

pub(super) async fn session(bridge: Bridge, publish: bool) -> I2pSession {
    I2pSession::create(
        bridge,
        Key::Transient,
        TunnelProfile::new(2, 2, 2, publish).unwrap(),
        Duration::from_secs(300),
    )
    .await
    .unwrap()
}

pub(super) async fn run(client_bridge: Bridge, worker_bridge: Bridge, seconds: u64) {
    // Distinct providers are required by the live caller. The scripted caller
    // intentionally uses one fixture and makes no public-I2P claim.
    let client = session(client_bridge, false).await;
    println!("MURM_POOL_SESSION_READY client");
    let target_session = session(client_bridge, true).await;
    println!("MURM_POOL_SESSION_READY recipient");
    let first = session(worker_bridge, true).await;
    println!("MURM_POOL_SESSION_READY worker-a");
    let second = session(worker_bridge, true).await;
    println!("MURM_POOL_SESSION_READY worker-b");
    let pool = pool().await;
    let started = Instant::now();
    let now = || 10 + started.elapsed().as_millis() as u64;
    let target_route = I2pRoute {
        address: target_session.address().unwrap(),
        service_key: root(8),
    };
    let view = pool.view(now()).await.unwrap();
    let first_route = I2pRoute {
        address: first.address().unwrap(),
        service_key: view.contribution(DEVICE_A).unwrap().service_key,
    };
    let second_route = I2pRoute {
        address: second.address().unwrap(),
        service_key: view.contribution(DEVICE_B).unwrap().service_key,
    };
    let first_live = worker_authority(&pool, DEVICE_A, started);
    let second_live = worker_authority(&pool, DEVICE_B, started);
    let first_host = worker(
        first.clone(),
        target_route.clone(),
        2,
        first_live.clone(),
        seconds,
    );
    let second_host = worker(
        second.clone(),
        target_route,
        3,
        second_live.clone(),
        seconds,
    );
    let target_host = recipient(target_session.clone(), seconds);
    tokio::time::sleep(Duration::from_millis(20)).await;
    if client_bridge.addr() != worker_bridge.addr() {
        // Publication/build readiness is distinct from application admission.
        // These probes send no application payload and retry only through I2P.
        warmup(&client, &first_route, "ingress-a").await;
        warmup(&client, &second_route, "ingress-b").await;
        let target = I2pRoute {
            address: target_session.address().unwrap(),
            service_key: root(8),
        };
        warmup(&first, &target, "target").await;
    }
    let signed_a = offer(&pool.config, DEVICE_A, &first_route, now());
    let signed_b = offer(&pool.config, DEVICE_B, &second_route, now());
    let verify = |offer: &I2pClientOffer| {
        let signature = offer
            .sign(&pool.config, identity(9).master_keypair())
            .unwrap();
        offer
            .verify(
                POOL,
                pool.config.service_key,
                signature,
                &recipient_pin(),
                now(),
                120_000,
            )
            .unwrap()
    };
    let mut offers = OfferBook::default();
    for (seed, device) in [(2, DEVICE_A), (3, DEVICE_B)] {
        let probe = offers.probe(&view, device, 120_000, now()).unwrap();
        let key = identity(seed)
            .derive_keypair(&device_salt(POOL, device))
            .unwrap();
        offers
            .confirm(&view, &probe, key.sign(&probe.signing_bytes()).to_bytes())
            .unwrap();
    }
    refresh_worker(&first_live, DEVICE_A).await;
    refresh_worker(&second_live, DEVICE_B).await;
    let mut a = open(&client, &verify(&signed_a), seconds, false)
        .await
        .unwrap();
    let payload = b"I2P relay fixture: known only to authenticated inner endpoints";
    a.write_all(payload).await.unwrap();
    a.flush().await.unwrap();
    let mut received = vec![0; payload.len()];
    a.read_exact(&mut received).await.unwrap();
    assert_eq!(received, payload);

    let attacker = identity(5);
    let channel = I2pRelayChannel::new(I2P_RELAY_PROTOCOL, 2, setup(seconds));
    assert!(
        verify(&signed_b)
            .open(
                &channel,
                &client,
                attacker.master_keypair(),
                credentials_for(&attacker, PROFILE)
            )
            .await
            .is_err()
    );
    let mut wrong_worker = signed_b.clone();
    wrong_worker.worker_key = root(9);
    assert!(
        open(&client, &verify(&wrong_worker), seconds, false)
            .await
            .is_err()
    );
    assert!(
        open(&client, &verify(&signed_b), seconds, true)
            .await
            .is_err()
    );

    first_host.stop().await;
    offers.failed(DEVICE_A);
    assert_eq!(
        offers
            .candidates(&pool.view(now()).await.unwrap())
            .iter()
            .map(|o| o.device)
            .collect::<Vec<_>>(),
        vec![DEVICE_B]
    );
    assert!(matches!(
        timeout(Duration::from_secs(seconds), a.read_u8()).await,
        Ok(Err(_))
    ));
    refresh_worker(&second_live, DEVICE_B).await;
    let mut b = open(&client, &verify(&signed_b), seconds, false)
        .await
        .unwrap();
    b.write_all(payload).await.unwrap();
    b.flush().await.unwrap();
    b.read_exact(&mut received).await.unwrap();
    assert_eq!(received, payload);
    assert_eq!(signed_a.pool, signed_b.pool);

    pool.author(
        &identity(3),
        PoolEvent::Withdraw { device: DEVICE_B },
        now(),
    )
    .await
    .unwrap();
    assert!(
        pool.authorize(root(4), DEVICE_B, TARGET, now())
            .await
            .is_err()
    );
    assert_eq!(second_live.refresh().await.unwrap(), 0);
    assert!(matches!(
        timeout(Duration::from_secs(seconds), b.read_u8()).await,
        Ok(Err(_))
    ));
    assert!(
        open(&client, &verify(&signed_b), seconds, false)
            .await
            .is_err()
    );
    second_host.stop().await;
    target_host.stop().await;
    drop((a, b, first, second, target_session, client));
    tokio::task::yield_now().await;
    println!(
        "MURM_POOL_P2 {{\"two_workers\":true,\"two_i2p_legs\":true,\"inner_noise\":true,\"wrong_worker_refused\":true,\"wrong_recipient_refused\":true,\"outsider_refused\":true,\"failover\":true,\"withdrawal\":true,\"inbound_hops\":2,\"outbound_hops\":2,\"variance\":0}}"
    );
}

pub(super) async fn warmup(session: &I2pSession, route: &I2pRoute, name: &str) {
    timeout(Duration::from_secs(240), async {
        let mut attempts = 0;
        loop {
            attempts += 1;
            if let Ok(Ok(stream)) =
                timeout(Duration::from_secs(30), session.connect(&route.address)).await
            {
                drop(stream);
                println!("MURM_POOL_ROUTE_READY {name} attempts={attempts}");
                break;
            }
            println!("MURM_POOL_ROUTE_WAIT {name} attempts={attempts}");
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    })
    .await
    .expect("public I2P route did not become ready");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scripted_sam_two_workers_keep_privacy_profile_and_fail_closed() {
    let fixture = SamFixture::start().await;
    timeout(
        Duration::from_secs(15),
        run(fixture.bridge(), fixture.bridge(), 3),
    )
    .await
    .unwrap();
    let profiles = fixture.profiles();
    assert_eq!(profiles.len(), 4);
    for options in profiles {
        for (key, value) in [
            ("inbound.length", "2"),
            ("outbound.length", "2"),
            ("inbound.lengthVariance", "0"),
            ("outbound.lengthVariance", "0"),
        ] {
            assert!(options.contains(&(key.into(), value.into())));
        }
    }
    fixture.shutdown().await;
}
