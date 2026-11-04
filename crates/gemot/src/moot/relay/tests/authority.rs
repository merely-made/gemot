// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

use super::*;

#[tokio::test]
async fn replaying_local_authority_cannot_renew_its_checkpoint() {
    let (mut pool, _) = fixture().await;
    pool.config.authority_expires_at_ms = 30;
    target(&pool).await;
    pool.author(&identity(2), contribution(2, DEVICE_A), 2)
        .await
        .unwrap();
    assert_eq!(
        pool.authorize(root(4), DEVICE_A, TARGET, 29)
            .await
            .unwrap()
            .expires_at_ms,
        30
    );
    assert!(pool.authorize(root(4), DEVICE_A, TARGET, 30).await.is_err());
    assert!(
        pool.author(&identity(2), contribution(2, DEVICE_B), 30)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn one_personas_independent_devices_and_concurrent_withdrawal_converge() {
    let (first, keys) = fixture().await;
    let second = PoolStore::new(
        first.moot.clone(),
        MemoryBackend::new(),
        first.config.clone(),
        source(keys),
    )
    .unwrap();
    let a = first
        .author(&identity(2), contribution(2, DEVICE_A), 2)
        .await
        .unwrap();
    let b = second
        .author(&identity(2), contribution(2, DEVICE_B), 2)
        .await
        .unwrap();
    assert_ne!(a.header.verifying_key, b.header.verifying_key);
    assert_eq!(a.header.seq_num, 0);
    assert_eq!(b.header.seq_num, 0);
    // The owner can retire A from another replica without A's author counter.
    let withdrawal = second
        .author(&identity(2), PoolEvent::Withdraw { device: DEVICE_A }, 3)
        .await
        .unwrap();
    first.accept(&withdrawal, 4).await.unwrap();
    first.accept(&b, 4).await.unwrap();
    second.accept(&a, 4).await.unwrap();
    let left = first.view(4).await.unwrap();
    let right = second.view(4).await.unwrap();
    assert!(!left.pending && !right.pending);
    assert!(left.contribution(DEVICE_A).is_none());
    assert!(right.contribution(DEVICE_A).is_none());
    assert!(left.contribution(DEVICE_B).is_some());
    assert_eq!(left.revision, right.revision);
}

#[tokio::test]
async fn membership_and_capability_are_both_required() {
    let (pool, _) = fixture().await;
    target(&pool).await;
    pool.author(&identity(2), contribution(2, DEVICE_A), 2)
        .await
        .unwrap();
    // This member is authorized to contribute, but not to consume the service.
    assert!(pool.authorize(root(2), DEVICE_A, TARGET, 3).await.is_err());
    // This member can consume, but cannot commit device resources to the pool.
    assert!(
        pool.author(&identity(4), contribution(4, DEVICE_B), 3)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn altered_ciphertext_and_client_offer_are_refused() {
    let (pool, _) = fixture().await;
    let mut operation = pool
        .author(&identity(2), contribution(2, DEVICE_A), 2)
        .await
        .unwrap();
    let mut body = operation.body.as_ref().unwrap().to_bytes();
    let last = body.len() - 1;
    body[last] ^= 1;
    operation.body = Some(p2panda_core::Body::from_bytes(&body));
    assert!(pool.accept(&operation, 3).await.is_err());
    let mut offer = ClientOffer {
        pool: POOL,
        alias: [91; 32],
        target: TARGET,
        recipient_key: root(8),
        native_route: "fixture-route".into(),
        native_host_visible: true,
        expires_at_ms: 1000,
    };
    let provider = identity(9);
    let signature = offer.sign(&pool.config, provider.master_keypair()).unwrap();
    offer.recipient_key = root(5);
    assert!(
        offer
            .verify(POOL, pool.config.service_key, signature, 10)
            .is_err()
    );
    let encoded = serde_json::to_string(&offer).unwrap();
    assert!(!encoded.contains("attestation") && !encoded.contains("coordination"));
}

#[cfg(feature = "relay-pool-native")]
#[tokio::test]
async fn native_grant_cannot_outlive_authority_or_availability() {
    let (pool, _) = fixture().await;
    target(&pool).await;
    pool.author(&identity(2), contribution(2, DEVICE_A), 2)
        .await
        .unwrap();
    let authorization = pool.authorize(root(4), DEVICE_A, TARGET, 10).await.unwrap();
    let short = tokio::time::Instant::now() + std::time::Duration::from_millis(20);
    let grant = authorization.native_grant(10, short).unwrap();
    assert_eq!(grant.expires, short);
    assert_eq!(grant.max_sessions, 2);
    assert!(
        authorization
            .native_grant(authorization.expires_at_ms, short)
            .is_err()
    );
    assert!(
        authorization
            .native_grant(10, tokio::time::Instant::now())
            .is_err()
    );
}
