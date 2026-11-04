// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

#[tokio::test]
async fn signed_admission_rule_uses_the_injected_membership_and_capability_inputs() {
    let founder = keypair(8);
    let founder_id = founder.public_key().to_bytes();
    let service = Moot::in_memory(ID, founder_id, retention());
    let mut rules = ConstitutionRules::founder_only(founder_id);
    rules.admission = Policy::MembersOnly {
        rate_limit: 20,
        rate_window_ms: 60_000,
    };
    service
        .found(founder.to_seed(), None, None, rules, 1)
        .await
        .unwrap();
    let request = MootAuthorizationRequest {
        subject: [9; 32],
        capability_path: "moot/fauna/write".into(),
        at_ms: 10,
    };

    assert_eq!(
        service
            .authorize(
                &Access {
                    capability_covers: false,
                    facts: StandingFacts {
                        is_member: true,
                        ..Default::default()
                    },
                },
                &request,
            )
            .await
            .unwrap(),
        GateDecision::Deny(DenyReason::NoCapability)
    );
    assert_eq!(
        service
            .authorize(
                &Access {
                    capability_covers: true,
                    facts: StandingFacts {
                        score: 1,
                        ..Default::default()
                    },
                },
                &request,
            )
            .await
            .unwrap(),
        GateDecision::Deny(DenyReason::NotAMember)
    );
    assert_eq!(
        service
            .authorize(
                &Access {
                    capability_covers: true,
                    facts: StandingFacts {
                        is_member: true,
                        ..Default::default()
                    },
                },
                &request,
            )
            .await
            .unwrap(),
        GateDecision::Allow
    );

    let mut amended = ConstitutionRules::founder_only(founder_id);
    amended.admission = Policy::OpenWithFloor(GateConfig {
        posting_threshold: 2,
        rate_limit: 20,
        rate_window_ms: 60_000,
    });
    service.amend(founder.to_seed(), amended, 11).await.unwrap();
    assert_eq!(
        service
            .authorize(
                &Access {
                    capability_covers: true,
                    facts: StandingFacts {
                        score: 1,
                        is_member: true,
                        ..Default::default()
                    },
                },
                &request,
            )
            .await
            .unwrap(),
        GateDecision::Deny(DenyReason::BelowThreshold)
    );
}

#[tokio::test]
async fn constitutional_grants_narrow_live_capability_inputs_and_revoke_by_amendment() {
    let founder = keypair(9);
    let founder_id = founder.public_key().to_bytes();
    let service = Moot::in_memory(ID, founder_id, retention());
    let grant_id = [0xa9; 32];
    let mut rules = ConstitutionRules::founder_only(founder_id);
    rules.admission = Policy::MembersOnly {
        rate_limit: 20,
        rate_window_ms: 60_000,
    };
    rules.grant(CapabilityGrant {
        id: grant_id,
        subject: [9; 32],
        path_prefix: "moot/fauna".into(),
        not_before_ms: 5,
        expires_at_ms: Some(20),
        delegation_depth: 0,
    });
    service
        .found(founder.to_seed(), None, None, rules.clone(), 1)
        .await
        .unwrap();
    let member = Access {
        capability_covers: true,
        facts: StandingFacts {
            is_member: true,
            ..Default::default()
        },
    };
    let request = MootAuthorizationRequest {
        subject: [9; 32],
        capability_path: "moot/fauna/write".into(),
        at_ms: 10,
    };
    assert_eq!(
        service
            .authorize_constitution_grant(&member, &request)
            .await
            .unwrap(),
        GateDecision::Allow
    );

    let sibling = MootAuthorizationRequest {
        capability_path: "moot/faunarium/write".into(),
        ..request.clone()
    };
    assert_eq!(
        service
            .authorize_constitution_grant(&member, &sibling)
            .await
            .unwrap(),
        GateDecision::Deny(DenyReason::NoCapability)
    );
    let expired = MootAuthorizationRequest {
        at_ms: 21,
        ..request.clone()
    };
    assert_eq!(
        service
            .authorize_constitution_grant(&member, &expired)
            .await
            .unwrap(),
        GateDecision::Deny(DenyReason::NoCapability)
    );

    rules.revoke_grant(&grant_id);
    service.amend(founder.to_seed(), rules, 22).await.unwrap();
    assert_eq!(
        service
            .authorize_constitution_grant(&member, &request)
            .await
            .unwrap(),
        GateDecision::Deny(DenyReason::NoCapability)
    );
}

#[tokio::test]
async fn authorized_fauna_applies_the_same_admission_policy_as_authoring() {
    let founder = keypair(0x19);
    let founder_id = founder.public_key().to_bytes();
    let sharer = InMemoryProvider::from_seed([0x71; 32]);
    let sharer_id = sharer.master_public_key().to_bytes();
    let service = Moot::in_memory(ID, founder_id, retention());
    let mut rules = ConstitutionRules::founder_only(founder_id);
    rules.admission = Policy::OpenWithFloor(GateConfig::default());
    rules.grant(CapabilityGrant {
        id: [0x72; 32],
        subject: sharer_id,
        path_prefix: cap_path(&fauna_cap()),
        not_before_ms: 1,
        expires_at_ms: None,
        delegation_depth: 0,
    });
    service
        .found(founder.to_seed(), None, None, rules, 1)
        .await
        .unwrap();
    service
        .update_membership(
            founder.to_seed(),
            MootMembershipAction::Create {
                initial_members: vec![
                    MootMember {
                        member: founder_id,
                        access: MootAccessLevel::Manage,
                    },
                    MootMember {
                        member: sharer_id,
                        access: MootAccessLevel::Write,
                    },
                ],
            },
        )
        .await
        .unwrap();

    service
        .share_for_identity(
            &sharer,
            [0x73; 32],
            "example.note.v1".into(),
            "note".into(),
            10,
        )
        .await
        .unwrap();
    assert_eq!(
        service
            .object_store()
            .roster(ID.0)
            .await
            .unwrap()
            .fauna
            .len(),
        1
    );
    assert!(matches!(
        service
            .share_authorized_for_identity(
                &sharer,
                [0x74; 32],
                "example.note.v1".into(),
                "refused".into(),
                11,
            )
            .await,
        Err(MootError::Unauthorized(DenyReason::BelowThreshold))
    ));
    assert!(service.authorized_fauna(11).await.unwrap().is_empty());
}

#[tokio::test]
async fn identity_withdrawal_refuses_unknown_and_wrong_targets_before_authoring() {
    let founder = keypair(0x2a);
    let sharer = InMemoryProvider::from_seed([0x2b; 32]);
    let stranger = InMemoryProvider::from_seed([0x2c; 32]);
    let service = Moot::in_memory(ID, founder.public_key().to_bytes(), retention());
    service
        .found(
            founder.to_seed(),
            None,
            None,
            ConstitutionRules::founder_only(founder.public_key().to_bytes()),
            1,
        )
        .await
        .unwrap();
    let share = service
        .share_for_identity(&sharer, [0xa1; 32], "fleece/v1".into(), "page".into(), 2)
        .await
        .unwrap();
    let before = service.object_store().ops(ID.0).await.unwrap().len();
    assert!(matches!(
        service
            .withdraw_share_for_identity(&sharer, [0xff; 32], 3)
            .await,
        Err(MootError::WithdrawalUnknownTarget)
    ));
    assert!(matches!(
        service
            .withdraw_share_for_identity(&stranger, share.operation, 3)
            .await,
        Err(MootError::WithdrawalWrongIdentity)
    ));
    assert_eq!(
        service.object_store().ops(ID.0).await.unwrap().len(),
        before
    );

    let withdrawal = service
        .withdraw_share_for_identity(&sharer, share.operation, 4)
        .await
        .unwrap();
    let roster = service.object_store().roster(ID.0).await.unwrap();
    assert_eq!(roster.fauna.len(), 1);
    assert_eq!(roster.withdrawals.len(), 1);
    assert_eq!(roster.withdrawals[0].target_share, share.operation);
    assert_eq!(
        roster.withdrawals[0].withdrawn_by,
        sharer.master_public_key().to_bytes()
    );
    assert_ne!(withdrawal.operation, share.operation);
}

#[tokio::test]
async fn delegated_grants_intersect_constitution_group_and_admission() {
    let founder = keypair(10);
    let founder_id = founder.public_key().to_bytes();
    let root_holder = InMemoryProvider::from_seed([0x31; 32]);
    let delegate = InMemoryProvider::from_seed([0x32; 32]);
    let root_id = [0xb1; 32];
    let service = Moot::in_memory(ID, founder_id, retention());
    let mut rules = ConstitutionRules::founder_only(founder_id);
    rules.admission = Policy::MembersOnly {
        rate_limit: 20,
        rate_window_ms: 60_000,
    };
    rules.grant(CapabilityGrant {
        id: root_id,
        subject: root_holder.master_public_key().to_bytes(),
        path_prefix: "moot/fauna".into(),
        not_before_ms: 5,
        expires_at_ms: Some(100),
        delegation_depth: 2,
    });
    service
        .found(founder.to_seed(), None, None, rules.clone(), 1)
        .await
        .unwrap();

    let scope = CapabilityScope {
        domain: MOOT_DELEGATION_DOMAIN.into(),
        resource: ID.0.to_vec(),
        path_prefix: "moot/fauna/research".into(),
        actions: [MOOT_ACT_ACTION.to_string()].into_iter().collect(),
    };
    let certificate = DelegationCertificate::new(
        DelegationParent::Root(root_id),
        root_holder.master_public_key().to_bytes(),
        delegate.master_public_key().to_bytes(),
        scope.clone(),
        5,
        10,
        Some(90),
        1,
        [0x41; 32],
    );
    let delegation_key = root_holder
        .derive_keypair(&delegation_signing_salt(&scope))
        .unwrap();
    service
        .delegation_store()
        .author_issue(
            &delegation_key,
            &rules,
            SignedDelegationCertificate::issue(&root_holder, certificate).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(service.snapshot().await.unwrap().delegated_certificates, 1);
    let request = MootAuthorizationRequest {
        subject: delegate.master_public_key().to_bytes(),
        capability_path: "moot/fauna/research/write".into(),
        at_ms: 50,
    };
    let member = Access {
        capability_covers: true,
        facts: StandingFacts {
            is_member: true,
            ..Default::default()
        },
    };
    assert_eq!(
        service
            .authorize_current_delegated(&member, &request)
            .await
            .unwrap(),
        GateDecision::Allow
    );
    assert_eq!(
        service
            .authorize_current_delegated(
                &Access {
                    capability_covers: false,
                    facts: member.facts.clone(),
                },
                &request,
            )
            .await
            .unwrap(),
        GateDecision::Deny(DenyReason::NoCapability)
    );

    rules.revoke_grant(&root_id);
    service.amend(founder.to_seed(), rules, 101).await.unwrap();
    assert_eq!(
        service
            .authorize_current_delegated(&member, &request)
            .await
            .unwrap(),
        GateDecision::Deny(DenyReason::NoCapability)
    );
}
