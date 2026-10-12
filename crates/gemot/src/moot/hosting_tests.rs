// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0
use super::super::constitution::{CapabilityGrant, ConstitutionRules};
use super::super::{
    AvailabilityPolicy, ErasurePolicy, KeepBound, MootAccessLevel, MootId, MootMember,
    MootMembershipAction, MootRetentionSettings, PolicyRevision,
};
use super::*;
use identity::{IdentityProvider, InMemoryProvider};
use muniment::MemoryBackend;
fn retention() -> MootRetentionSettings {
    MootRetentionSettings {
        revision: PolicyRevision(Digest::blake3(b"test")),
        availability: AvailabilityPolicy {
            promised_floor: KeepBound::Forever,
        },
        erasure: ErasurePolicy {
            history_ceiling: KeepBound::UntilCheckpoint,
        },
    }
}
async fn fixture() -> (
    Moot<MemoryBackend>,
    InMemoryProvider,
    HostingRequest,
    HostingPolicy,
) {
    let identity = InMemoryProvider::from_seed([7; 32]);
    let root = identity.master_public_key().to_bytes();
    let service = Moot::in_memory(MootId([1; 32]), root, retention());
    initialize(&service, &identity).await;
    let share = service
        .share_authorized_for_identity(&identity, [4; 32], "text/plain".into(), "Notes".into(), 2)
        .await
        .unwrap();
    let policy = HostingPolicy {
        constitution_revision: service.snapshot().await.unwrap().governance.revision,
        revision: [5; 32],
        audience: "public".into(),
        max_bytes: 20,
        max_duration_ms: 30,
    };
    let request = HostingRequest {
        contribution: share.operation,
        manifest: [4; 32],
        device: [6; 32],
        audience: "public".into(),
        max_bytes: 100,
        duration_ms: 100,
        at_ms: 10,
    };
    (service, identity, request, policy)
}
async fn initialize<B: Backend + Clone>(service: &Moot<B>, id: &InMemoryProvider) {
    let root = id.master_public_key().to_bytes();
    let mut rules = ConstitutionRules::founder_only(root);
    rules.admission = mien::Policy::MembersOnly {
        rate_limit: 100,
        rate_window_ms: 1000,
    };
    for (tag, cap) in [
        (1, super::super::records::fauna_cap()),
        (2, hosting_cap("public").unwrap()),
    ] {
        rules.grant(CapabilityGrant {
            id: [tag; 32],
            subject: root,
            path_prefix: cap_path(&cap),
            not_before_ms: 0,
            expires_at_ms: Some(100),
            delegation_depth: 0,
        });
    }
    service.found([7; 32], None, None, rules, 0).await.unwrap();
    service
        .update_membership_for_identity(
            id,
            MootMembershipAction::Create {
                initial_members: vec![MootMember {
                    member: root,
                    access: MootAccessLevel::Manage,
                }],
            },
        )
        .await
        .unwrap();
}
fn ceiling() -> DeviceCeiling {
    DeviceCeiling {
        max_bytes: 12,
        max_duration_ms: 15,
    }
}
#[tokio::test]
async fn malformed_typed_standing_cannot_poison_other_hosting_records() {
    let (service, id, request, policy) = fixture().await;
    let p = service
        .prepare_hosting(
            id.master_public_key().to_bytes(),
            &request,
            8,
            &policy,
            ceiling(),
        )
        .await
        .unwrap();
    service
        .commit_hosting(&id, &request, 8, &policy, ceiling(), &p)
        .await
        .unwrap();
    service
        .record_standing_for_identity(
            &id,
            StandingEvent::CommitmentMade {
                by: ChainRoot(id.master_public_key().to_bytes()),
                commitment: CommitmentId([99; 32]),
                scope: Scope("gemot/hosting/v1/not-cbor".into()),
                cadence_ms: 10,
                duration_ms: Some(10),
                at_ms: 11,
            },
        )
        .await
        .unwrap();
    assert_eq!(service.hosting_records().await.unwrap().len(), 1);
}
#[tokio::test]
async fn signed_bounded_promise_replays_and_expiry_is_not_availability() {
    let (service, id, request, policy) = fixture().await;
    let promise = service
        .prepare_hosting(
            id.master_public_key().to_bytes(),
            &request,
            8,
            &policy,
            ceiling(),
        )
        .await
        .unwrap();
    assert_eq!(promise.max_bytes, 12);
    assert_eq!(promise.expires_at_ms, 25);
    assert!(!promise.authority.constitution_operations.is_empty());
    assert!(!promise.authority.membership_heads.is_empty());
    let receipt = service
        .commit_hosting(&id, &request, 8, &policy, ceiling(), &promise)
        .await
        .unwrap();
    let records = service.hosting_records().await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].operation, receipt.operation);
    assert_eq!(records[0].promise, promise);
    service
        .check_hosting(&records[0], "public", &policy, ceiling(), 8, 20)
        .await
        .unwrap();
    assert!(
        service
            .check_hosting(&records[0], "public", &policy, ceiling(), 8, 25)
            .await
            .is_err()
    );
    assert!(
        service
            .check_hosting(&records[0], "friends", &policy, ceiling(), 8, 20)
            .await
            .is_err()
    );
}
#[tokio::test]
async fn denied_scopes_ceilings_revocation_and_stale_preparation_do_not_sign() {
    let (service, id, mut request, policy) = fixture().await;
    let before = service.standing_store().len().await.unwrap();
    assert!(
        service
            .prepare_hosting([9; 32], &request, 8, &policy, ceiling())
            .await
            .is_err()
    );
    assert!(
        service
            .prepare_hosting(
                id.master_public_key().to_bytes(),
                &request,
                13,
                &policy,
                ceiling()
            )
            .await
            .is_err()
    );
    request.audience = "public/*".into();
    assert!(
        service
            .prepare_hosting(
                id.master_public_key().to_bytes(),
                &request,
                8,
                &policy,
                ceiling()
            )
            .await
            .is_err()
    );
    request.audience = "public".into();
    let prepared = service
        .prepare_hosting(
            id.master_public_key().to_bytes(),
            &request,
            8,
            &policy,
            ceiling(),
        )
        .await
        .unwrap();
    let mut rules = service.snapshot().await.unwrap().governance.rules;
    rules.revoke_grant(&[2; 32]);
    service.amend([7; 32], rules, 11).await.unwrap();
    assert!(
        service
            .commit_hosting(&id, &request, 8, &policy, ceiling(), &prepared)
            .await
            .is_err()
    );
    assert_eq!(service.standing_store().len().await.unwrap(), before);
}
#[tokio::test]
async fn withdrawn_contribution_and_local_ceiling_changes_stop_serving() {
    let (service, id, request, policy) = fixture().await;
    let p = service
        .prepare_hosting(
            id.master_public_key().to_bytes(),
            &request,
            8,
            &policy,
            ceiling(),
        )
        .await
        .unwrap();
    service
        .commit_hosting(&id, &request, 8, &policy, ceiling(), &p)
        .await
        .unwrap();
    let record = service.hosting_records().await.unwrap().remove(0);
    assert!(
        service
            .check_hosting(
                &record,
                "public",
                &policy,
                DeviceCeiling {
                    max_bytes: 7,
                    ..ceiling()
                },
                8,
                20
            )
            .await
            .is_err()
    );
    service
        .withdraw_share_for_identity(&id, request.contribution, 20)
        .await
        .unwrap();
    assert!(
        service
            .check_hosting(&record, "public", &policy, ceiling(), 8, 21)
            .await
            .is_err()
    );
}
#[tokio::test]
async fn full_signed_record_reopens_from_the_existing_standing_backend() {
    let dir = tempfile::tempdir().unwrap();
    let id = InMemoryProvider::from_seed([7; 32]);
    let root = id.master_public_key().to_bytes();
    let expected;
    {
        let service = super::super::MootFile::open(dir.path(), MootId([1; 32]), root, retention())
            .await
            .unwrap();
        initialize(&service, &id).await;
        let contribution = service
            .share_authorized_for_identity(&id, [4; 32], "text/plain".into(), "Notes".into(), 2)
            .await
            .unwrap()
            .operation;
        let policy = HostingPolicy {
            constitution_revision: service.snapshot().await.unwrap().governance.revision,
            revision: [5; 32],
            audience: "public".into(),
            max_bytes: 20,
            max_duration_ms: 30,
        };
        let request = HostingRequest {
            contribution,
            manifest: [4; 32],
            device: [6; 32],
            audience: "public".into(),
            max_bytes: 10,
            duration_ms: 10,
            at_ms: 10,
        };
        let p = service
            .prepare_hosting(root, &request, 8, &policy, ceiling())
            .await
            .unwrap();
        service
            .commit_hosting(&id, &request, 8, &policy, ceiling(), &p)
            .await
            .unwrap();
        expected = service.hosting_records().await.unwrap();
    }
    let reopened = super::super::MootFile::open_existing(dir.path(), MootId([1; 32]), retention())
        .await
        .unwrap();
    assert_eq!(reopened.hosting_records().await.unwrap(), expected);
}
