// SPDX-License-Identifier: MPL-2.0
use super::*;
use gemot::moot::workflow::discovery::*;
async fn hint(
    moot: &Moot<muniment::MemoryBackend>,
    sequence: u64,
    description: bool,
) -> SignedCatalogueAdvertisement {
    let collection = moot
        .authorized_collection(COLLECTION.collection_id, 20)
        .await
        .unwrap()
        .unwrap()
        .version;
    SignedCatalogueAdvertisement::sign(
        &person(7),
        CatalogueAdvertisement {
            version: 1,
            collection,
            provider: root(&person(7)),
            sequence,
            issued_at_ms: 20,
            expires_at_ms: 120,
            description: description.then(|| CatalogueDescription {
                address: "scroll://garden.test/".into(),
                title: "Garden".into(),
                abstract_text: "Music and painting".into(),
                scroll_subject: Some(7),
                language: Some("en".into()),
            }),
        },
    )
    .unwrap()
}
#[tokio::test]
async fn signed_ads_expire_withdraw_persist_watermarks_and_recheck_current_rights() {
    let (moot, share) = fixture().await;
    let reader = root(&person(10));
    let first = hint(&moot, 1, true).await;
    let mut cache = CatalogueDirectory::default();
    assert!(
        cache
            .receive(&moot, reader, &first.encode().unwrap(), 21, 100, 8)
            .await
            .unwrap()
    );
    assert_eq!(cache.visible(&moot, reader, 22, 100).await.len(), 1);
    assert!(
        cache
            .visible(&moot, root(&person(11)), 22, 100)
            .await
            .is_empty()
    );
    assert!(cache.visible(&moot, reader, 120, 100).await.is_empty());
    let withdrawal = hint(&moot, 2, false).await;
    cache
        .receive(&moot, reader, &withdrawal.encode().unwrap(), 23, 100, 8)
        .await
        .unwrap();
    let mut cache = CatalogueDirectory::decode(&cache.encode().unwrap(), 8).unwrap();
    assert!(
        !cache
            .receive(&moot, reader, &first.encode().unwrap(), 24, 100, 8)
            .await
            .unwrap()
    );
    assert!(cache.visible(&moot, reader, 24, 100).await.is_empty());
    let fresh = hint(&moot, 3, true).await;
    cache
        .receive(&moot, reader, &fresh.encode().unwrap(), 25, 100, 8)
        .await
        .unwrap();
    moot.withdraw_share_for_identity(&person(7), share.share, 26)
        .await
        .unwrap();
    assert!(cache.visible(&moot, reader, 27, 100).await.is_empty());
}
#[tokio::test]
async fn equivocation_tampering_foreign_scope_and_revocation_fail_closed() {
    let (moot, _) = fixture().await;
    let reader = root(&person(10));
    let good = hint(&moot, 1, true).await;
    let mut cache = CatalogueDirectory::default();
    cache
        .receive(&moot, reader, &good.encode().unwrap(), 21, 100, 8)
        .await
        .unwrap();
    let mut tampered = good.clone();
    tampered.advertisement.description.as_mut().unwrap().title = "changed".into();
    assert!(
        cache
            .receive(&moot, reader, &tampered.encode().unwrap(), 22, 100, 8)
            .await
            .is_err()
    );
    assert!(good.verify([99; 32], 22, 100).is_err());
    let conflicting =
        SignedCatalogueAdvertisement::sign(&person(7), tampered.advertisement).unwrap();
    cache
        .receive(&moot, reader, &conflicting.encode().unwrap(), 22, 100, 8)
        .await
        .unwrap();
    cache = CatalogueDirectory::decode(&cache.encode().unwrap(), 8).unwrap();
    assert!(cache.visible(&moot, reader, 22, 100).await.is_empty());
    let fresh = hint(&moot, 2, true).await;
    cache
        .receive(&moot, reader, &fresh.encode().unwrap(), 23, 100, 8)
        .await
        .unwrap();
    moot.update_membership_for_identity(
        &person(7),
        MootMembershipAction::Remove {
            member: root(&person(10)),
        },
    )
    .await
    .unwrap();
    assert!(cache.visible(&moot, reader, 24, 100).await.is_empty());
    let mut rules = moot.snapshot().await.unwrap().governance.rules;
    let path = servitor::cap_path(&catalogue_cap(COLLECTION.collection_id.0));
    let grant = rules
        .capability_grants
        .values()
        .find(|g| g.subject == root(&person(7)) && g.path_prefix == path)
        .unwrap()
        .id;
    rules.revoke_grant(&grant);
    moot.amend([7; 32], rules, 25).await.unwrap();
    assert!(
        cache
            .visible(&moot, root(&person(9)), 26, 100)
            .await
            .is_empty()
    );
}

#[test]
fn discovery_addresses_refuse_credentials_local_targets_and_active_schemes() {
    for address in [
        "javascript:alert(1)",
        "file:///private",
        "http://",
        "https://user:secret@example.test/",
        "scroll://localhost/",
        "gemini://127.0.0.1/",
    ] {
        let description = CatalogueDescription {
            address: address.into(),
            title: "Site".into(),
            abstract_text: String::new(),
            scroll_subject: Some(4),
            language: None,
        };
        assert!(!description.validate(), "{address}");
    }
}
