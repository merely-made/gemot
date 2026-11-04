// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

//! Public-network gates use explicit, distinct local router bridges. They are
//! separate from scripted SAM behavior and never run as ordinary unit tests.
use super::*;
use transport::i2p::Bridge;

fn bridge(name: &str) -> Bridge {
    Bridge::new(
        std::env::var(name)
            .expect("explicit router bridge required")
            .parse()
            .unwrap(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "public I2P: needs distinct named client/worker routers with qualified nonzero-hop settings"]
async fn public_i2p_two_workers_on_distinct_routers() {
    let client = bridge("MURM_RELAY_I2P_CLIENT_SAM");
    let worker = bridge("MURM_RELAY_I2P_WORKER_SAM");
    assert_ne!(
        client.addr(),
        worker.addr(),
        "one provider can short-circuit local Destinations"
    );
    timeout(Duration::from_secs(1200), scenario::run(client, worker, 90))
        .await
        .unwrap();
}

// A carrier-lifecycle control, separate from the other test's authenticated
// relay payloads. Its repeated fixed probe is an idempotent diagnostic only.
async fn carrier_pair(
    client: &I2pSession,
    server: &I2pSession,
) -> (transport::i2p::I2pStream, transport::i2p::I2pStream) {
    let route = server.address().unwrap();
    let accepted = server.clone();
    let task = tokio::spawn(async move {
        loop {
            let mut stream = accepted.accept().await.unwrap();
            let mut bytes = [0; 9];
            if matches!(
                timeout(Duration::from_secs(10), stream.read_exact(&mut bytes)).await,
                Ok(Ok(_))
            ) && &bytes == b"lifecycle"
            {
                if stream.write_all(&bytes).await.is_err() || stream.flush().await.is_err() {
                    continue;
                }
                // Confirm the matching caller received this probe before handing
                // the stream back for the provider-termination assertion.
                if matches!(
                    timeout(Duration::from_secs(10), stream.read_u8()).await,
                    Ok(Ok(1))
                ) {
                    break stream;
                }
            }
        }
    });
    let outbound = timeout(Duration::from_secs(240), async {
        loop {
            if let Ok(Ok(mut stream)) =
                timeout(Duration::from_secs(30), client.connect(&route)).await
            {
                let exchange = async {
                    stream.write_all(b"lifecycle").await?;
                    stream.flush().await?;
                    let mut bytes = [0; 9];
                    stream.read_exact(&mut bytes).await?;
                    if &bytes != b"lifecycle" {
                        return Err(std::io::Error::other("carrier probe mismatch"));
                    }
                    stream.write_u8(1).await?;
                    stream.flush().await?;
                    Ok::<_, std::io::Error>(())
                };
                if matches!(timeout(Duration::from_secs(15), exchange).await, Ok(Ok(()))) {
                    break stream;
                }
            }
            println!("MURM_POOL_PROVIDER_ROUTE_WAIT");
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    })
    .await
    .expect("public carrier route unavailable");
    let inbound = timeout(Duration::from_secs(15), task)
        .await
        .unwrap()
        .unwrap();
    (outbound, inbound)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "public I2P: external owner must stop/restart its own worker router at printed markers"]
async fn public_provider_termination_closes_local_streams_and_restart_changes_alias() {
    assert_eq!(
        std::env::var("MURM_RELAY_PROVIDER_RESTART").as_deref(),
        Ok("external-control")
    );
    timeout(Duration::from_secs(900),async {
        let client = scenario::session(bridge("MURM_RELAY_I2P_CLIENT_SAM"),false).await;
        let worker_bridge = bridge("MURM_RELAY_I2P_WORKER_SAM");
        let server = scenario::session(worker_bridge,true).await;
        let old_alias = server.address().unwrap();
        let (outbound,mut inbound) = carrier_pair(&client,&server).await;
        println!("MURM_POOL_PROVIDER_STOP_READY");
        timeout(Duration::from_secs(90),server.closed()).await.expect("owner must stop its named router");
        assert!(inbound.read_u8().await.is_err());
        assert!(server.address().is_err());
        println!("MURM_POOL_PROVIDER_RESTART_READY");
        let replacement = timeout(Duration::from_secs(180),async {
            loop {
                if let Ok(session) = I2pSession::create(worker_bridge,transport::i2p::Key::Transient,
                    TunnelProfile::new(2,2,2,true).unwrap(),Duration::from_secs(60)).await { break session; }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }).await.expect("owner must restart its named router");
        println!("MURM_POOL_PROVIDER_SESSION_READY");
        let new_alias = replacement.address().unwrap();
        assert_ne!(new_alias,old_alias);
        assert!(server.connect(&new_alias).await.is_err());
        let (mut fresh_outbound,mut fresh_inbound) = carrier_pair(&client,&replacement).await;
        fresh_outbound.write_all(b"reopened").await.unwrap();
        fresh_outbound.flush().await.unwrap();
        let mut bytes = [0;8];
        fresh_inbound.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes,b"reopened");
        drop((outbound,inbound,fresh_outbound,fresh_inbound,server,replacement,client));
        println!("MURM_POOL_PROVIDER_LIFECYCLE {{\"termination\":true,\"old_session_refused\":true,\"fresh_alias\":true,\"carrier_reopen\":true}}");
    }).await.unwrap();
}
