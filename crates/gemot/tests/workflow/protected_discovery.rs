// SPDX-License-Identifier: MPL-2.0
use super::*;
use gemot::moot::workflow::discovery::{protected::*, *};
use stickleback::{DataKeyring, GroupSession, GroupSessionId};
fn group() -> (GroupSession, GroupSession) {
    let (mut a, ap) = GroupSession::new(GroupSessionId(ID.0), &person(7)).unwrap();
    let (mut b, bp) = GroupSession::new(GroupSessionId(ID.0), &person(10)).unwrap();
    a.register_prekey(&bp).unwrap();
    b.register_prekey(&ap).unwrap();
    a.create(&[]).unwrap();
    let add = a.add(b.member()).unwrap();
    b.process(a.personae_root(), &add.control, add.direct_for(b.member()))
        .unwrap();
    (a, b)
}
fn keys(group: &GroupSession) -> DataKeyring {
    DataKeyring::from_bytes(&group.data_keyring_state().unwrap()).unwrap()
}
async fn protected_hint(
    moot: &Moot<muniment::MemoryBackend>,
    sequence: u64,
    description: bool,
) -> SignedCatalogueAdvertisement {
    let mut ad = super::discovery::hint(moot, sequence, description)
        .await
        .advertisement;
    ad.version = 2;
    ad.audience = Some(CatalogueAudience { members_of: ID.0 });
    SignedCatalogueAdvertisement::sign(&person(7), ad).unwrap()
}
fn hidden(bytes: &[u8]) {
    for secret in [
        b"scroll://garden.test/".as_slice(),
        b"Garden",
        b"Music and painting",
        b"scroll_subject",
    ] {
        assert!(!bytes.windows(secret.len()).any(|w| w == secret));
    }
}
#[tokio::test]
async fn protected_hints_hide_metadata_refuse_downgrade_and_preserve_replay_after_restart() {
    let (moot, _) = fixture().await;
    let (a, b) = group();
    let ak = keys(&a);
    let bk = keys(&b);
    let hint = protected_hint(&moot, 1, true).await;
    let bytes = seal_advertisement(ID.0, &ak, &hint).unwrap();
    hidden(&bytes);
    assert_ne!(bytes, seal_advertisement(ID.0, &ak, &hint).unwrap());
    let mut directory = CatalogueDirectory::default();
    let reader = root(&person(10));
    assert!(
        directory
            .receive(&moot, reader, &hint.encode().unwrap(), 21, 100, 8)
            .await
            .is_err()
    );
    assert!(
        directory
            .receive_protected(&moot, root(&person(11)), &bytes, &bk, 21, 100, 8)
            .await
            .is_err()
    );
    assert!(
        directory
            .receive_protected(&moot, reader, &bytes, &bk, 21, 100, 8)
            .await
            .unwrap()
    );
    assert_eq!(
        directory.visible(&moot, reader, 22, 100).await,
        vec![hint.clone()]
    );
    let cache = seal_cache(ID.0, &bk, &directory).unwrap();
    hidden(&cache);
    let mut restored = open_cache(ID.0, &bk, &cache, 8).unwrap();
    assert!(
        !restored
            .receive_protected(&moot, reader, &bytes, &bk, 23, 100, 8)
            .await
            .unwrap()
    );
    let withdrawal = protected_hint(&moot, 2, false).await;
    restored
        .receive_protected(
            &moot,
            reader,
            &seal_advertisement(ID.0, &ak, &withdrawal).unwrap(),
            &bk,
            24,
            100,
            8,
        )
        .await
        .unwrap();
    let mut restored =
        open_cache(ID.0, &bk, &seal_cache(ID.0, &bk, &restored).unwrap(), 8).unwrap();
    assert!(
        !restored
            .receive_protected(&moot, reader, &bytes, &bk, 25, 100, 8)
            .await
            .unwrap()
    );
    assert!(restored.visible(&moot, reader, 25, 100).await.is_empty());
    let public = super::discovery::hint(&moot, 3, true).await;
    assert!(
        !public
            .encode()
            .unwrap()
            .windows(8)
            .any(|w| w == b"audience"),
        "V1 signed bytes omit the new field"
    );
    assert!(seal_advertisement(ID.0, &ak, &public).is_err());
    assert!(
        restored
            .receive_protected(&moot, reader, &public.encode().unwrap(), &bk, 25, 100, 8)
            .await
            .is_err()
    );
    let mut downgrade = hint;
    downgrade.advertisement.version = 1;
    downgrade.advertisement.audience = None;
    assert!(downgrade.verify(ID.0, 25, 100).is_err());
}
#[tokio::test]
async fn group_rotation_hides_future_hints_and_old_wire_cannot_reenter_current_epoch() {
    let (moot, _) = fixture().await;
    let (mut a, b) = group();
    let old = keys(&a);
    let removed = keys(&b);
    let hint = protected_hint(&moot, 1, true).await;
    let first = seal_advertisement(ID.0, &old, &hint).unwrap();
    let mut directory = CatalogueDirectory::default();
    let reader = root(&person(10));
    directory
        .receive_protected(&moot, reader, &first, &removed, 21, 100, 8)
        .await
        .unwrap();
    let journal = seal_cache(ID.0, &old, &directory).unwrap();
    a.remove(b.member()).unwrap();
    let current = keys(&a);
    let next = seal_advertisement(ID.0, &current, &hint).unwrap();
    assert!(open_advertisement(ID.0, &removed, &next, 22, 100).is_err());
    assert!(open_advertisement(ID.0, &current, &first, 22, 100).is_err());
    assert!(open_advertisement(ID.0, &current, &next, 22, 100).is_ok());
    let restored = open_cache(ID.0, &current, &journal, 8).unwrap();
    moot.update_membership_for_identity(
        &person(7),
        MootMembershipAction::Remove { member: reader },
    )
    .await
    .unwrap();
    assert!(restored.visible(&moot, reader, 23, 100).await.is_empty());
}
#[tokio::test]
async fn protected_payloads_bind_domain_resource_audience_and_bounds_without_plaintext_fallback() {
    let (moot, _) = fixture().await;
    let (a, _) = group();
    let key = keys(&a);
    let hint = protected_hint(&moot, 1, true).await;
    let bytes = seal_advertisement(ID.0, &key, &hint).unwrap();
    let mut tampered = bytes.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(open_advertisement(ID.0, &key, &tampered, 21, 100).is_err());
    assert!(open_advertisement([9; 32], &key, &bytes, 21, 100).is_err());
    assert!(open_advertisement(ID.0, &key, &bytes, 120, 100).is_err());
    let description = hint.advertisement.description.unwrap();
    let body = seal_description(ID.0, COLLECTION.collection_id.0, &key, &description).unwrap();
    hidden(&body);
    assert_eq!(
        open_description(ID.0, COLLECTION.collection_id.0, &key, &body).unwrap(),
        description
    );
    assert!(open_description(ID.0, [9; 32], &key, &body).is_err());
    assert!(open_cache(ID.0, &key, &body, 8).is_err());
    let mut relabelled=bytes.clone();relabelled[..4].copy_from_slice(b"GCC1");
    assert!(open_cache(ID.0,&key,&relabelled,8).is_err());
    assert!(open_advertisement(ID.0, &key, &body, 21, 100).is_err());
    let (unjoined, _) = GroupSession::new(GroupSessionId(ID.0), &person(11)).unwrap();
    assert!(
        seal_description(
            ID.0,
            COLLECTION.collection_id.0,
            &keys(&unjoined),
            &description
        )
        .is_err()
    );
    assert!(
        open_advertisement(ID.0, &key, &vec![0; MAX_ADVERTISEMENT_BYTES + 1], 21, 100).is_err()
    );
}
