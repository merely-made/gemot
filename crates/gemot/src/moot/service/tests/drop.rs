// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

#[tokio::test]
async fn native_drop_bootstraps_independent_delegation_authority() {
    let founder = keypair(11);
    let founder_id = founder.public_key().to_bytes();
    let root_holder = InMemoryProvider::from_seed([0x51; 32]);
    let delegate = InMemoryProvider::from_seed([0x52; 32]);
    let root_id = [0xc1; 32];
    let mut rules = ConstitutionRules::founder_only(founder_id);
    rules.grant(CapabilityGrant {
        id: root_id,
        subject: root_holder.master_public_key().to_bytes(),
        path_prefix: "moot/fauna".into(),
        not_before_ms: 1,
        expires_at_ms: Some(100),
        delegation_depth: 1,
    });
    let source = Moot::in_memory(ID, founder_id, retention());
    source
        .found(founder.to_seed(), None, None, rules.clone(), 1)
        .await
        .unwrap();
    let scope = CapabilityScope {
        domain: MOOT_DELEGATION_DOMAIN.into(),
        resource: ID.0.to_vec(),
        path_prefix: "moot/fauna/notes".into(),
        actions: [MOOT_ACT_ACTION.to_string()].into_iter().collect(),
    };
    let signed = SignedDelegationCertificate::issue(
        &root_holder,
        DelegationCertificate::new(
            DelegationParent::Root(root_id),
            root_holder.master_public_key().to_bytes(),
            delegate.master_public_key().to_bytes(),
            scope.clone(),
            2,
            3,
            Some(90),
            0,
            [0x53; 32],
        ),
    )
    .unwrap();
    let certificate_id = signed.certificate.id();
    let delegation_key = root_holder
        .derive_keypair(&delegation_signing_salt(&scope))
        .unwrap();
    source
        .delegation_store()
        .author_issue(&delegation_key, &rules, signed)
        .await
        .unwrap();

    let mut bytes = Vec::new();
    source
        .export_plain_drop(
            &mut bytes,
            DropExportProfile::default(),
            DropLimits::default(),
        )
        .await
        .unwrap();
    let target = Moot::in_memory(ID, founder_id, retention());
    let receipt = target
        .import_plain_drop(Cursor::new(bytes), DropLimits::default())
        .await
        .unwrap();
    assert_eq!(receipt.delegation_operations, 1);
    assert_eq!(receipt.snapshot.delegated_certificates, 1);
    assert_eq!(
        target
            .authorize_current_delegated(
                &Access {
                    capability_covers: true,
                    facts: StandingFacts {
                        score: 1,
                        ..Default::default()
                    },
                },
                &MootAuthorizationRequest {
                    subject: delegate.master_public_key().to_bytes(),
                    capability_path: "moot/fauna/notes/write".into(),
                    at_ms: 50,
                },
            )
            .await
            .unwrap(),
        GateDecision::Allow
    );

    let revocation = SignedDelegationRevocation::issue(
        &root_holder,
        DelegationRevocation::new(
            certificate_id,
            root_holder.master_public_key().to_bytes(),
            scope.clone(),
            60,
            [0x54; 32],
        ),
    )
    .unwrap();
    source
        .delegation_store()
        .author_revoke(&delegation_key, &rules, revocation)
        .await
        .unwrap();
    let mut revoked_bytes = Vec::new();
    source
        .export_plain_drop(
            &mut revoked_bytes,
            DropExportProfile::default(),
            DropLimits::default(),
        )
        .await
        .unwrap();
    let revoked_receipt = target
        .import_plain_drop(Cursor::new(revoked_bytes), DropLimits::default())
        .await
        .unwrap();
    assert_eq!(revoked_receipt.delegation_operations, 1);
    assert_eq!(
        target.delegation_scope_key_epochs().await.unwrap()[0].epoch,
        1
    );
    assert!(
        target
            .delegation_projections(60)
            .await
            .unwrap()
            .iter()
            .all(|projection| !projection.active)
    );
    assert_eq!(
        target
            .authorize_current_delegated(
                &Access {
                    capability_covers: true,
                    facts: StandingFacts {
                        score: 1,
                        ..Default::default()
                    },
                },
                &MootAuthorizationRequest {
                    subject: delegate.master_public_key().to_bytes(),
                    capability_path: "moot/fauna/notes/write".into(),
                    at_ms: 60,
                },
            )
            .await
            .unwrap(),
        GateDecision::Deny(DenyReason::NoCapability)
    );
}

#[tokio::test]
async fn aggregate_drop_reconstructs_all_seven_retained_domains_for_late_peer() {
    let founder = keypair(12);
    let founder_id = founder.public_key().to_bytes();
    let member_identity = InMemoryProvider::from_seed([0x61; 32]);
    let member_root = member_identity.master_public_key().to_bytes();
    let root_holder = InMemoryProvider::from_seed([0x62; 32]);
    let delegate = InMemoryProvider::from_seed([0x63; 32]);
    let root_id = [0xd1; 32];
    let mut rules = ConstitutionRules::founder_only(founder_id);
    rules.grant(CapabilityGrant {
        id: root_id,
        subject: root_holder.master_public_key().to_bytes(),
        path_prefix: "moot/fauna".into(),
        not_before_ms: 1,
        expires_at_ms: Some(100),
        delegation_depth: 1,
    });

    let source = Moot::in_memory(ID, founder_id, retention());
    source
        .found(founder.to_seed(), None, None, rules.clone(), 1)
        .await
        .unwrap();
    let membership_receipt = source
        .update_membership_for_identity(
            &member_identity,
            MootMembershipAction::Create {
                initial_members: vec![MootMember {
                    member: member_root,
                    access: MootAccessLevel::Manage,
                }],
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        source.outbound(&membership_receipt).await.unwrap(),
        MootOutboundOperation::Membership(_)
    ));

    let scope = CapabilityScope {
        domain: MOOT_DELEGATION_DOMAIN.into(),
        resource: ID.0.to_vec(),
        path_prefix: "moot/fauna/notes".into(),
        actions: [MOOT_ACT_ACTION.to_string()].into_iter().collect(),
    };
    let signed = SignedDelegationCertificate::issue(
        &root_holder,
        DelegationCertificate::new(
            DelegationParent::Root(root_id),
            root_holder.master_public_key().to_bytes(),
            delegate.master_public_key().to_bytes(),
            scope.clone(),
            2,
            3,
            Some(90),
            0,
            [0x64; 32],
        ),
    )
    .unwrap();
    let delegation_key = root_holder
        .derive_keypair(&delegation_signing_salt(&scope))
        .unwrap();
    source
        .delegation_store()
        .author_issue(&delegation_key, &rules, signed)
        .await
        .unwrap();

    source
        .declare(
            founder.to_seed(),
            "peer press".into(),
            "shared place".into(),
            4,
        )
        .await
        .unwrap();
    source
        .join(founder.to_seed(), "founder".into(), 5)
        .await
        .unwrap();
    source
        .share(
            founder.to_seed(),
            [0x65; 32],
            "text/plain".into(),
            "field note".into(),
            6,
        )
        .await
        .unwrap();
    source
        .record_standing(
            founder.to_seed(),
            StandingEvent::GovernanceParticipation {
                by: ChainRoot(member_root),
                at_ms: 7,
            },
        )
        .await
        .unwrap();
    source
        .record_tulpa(
            founder.to_seed(),
            TulpaEvent::Proposed {
                proposal: TulpaProposalId([0x66; 32]),
                action: TulpaProposal::Adopt {
                    tulpa: TulpaId([0x67; 32]),
                    version: TulpaVersion([0x68; 32]),
                    artifact: ArtifactRef::blake3(b"drop Tulpa"),
                },
                recognition: RecognitionContext::new(
                    RecognitionPolicy::AnyEligible,
                    ElectorateSnapshot::new(ID.0, [0x69; 32], [founder_id]),
                ),
                at_ms: 8,
            },
        )
        .await
        .unwrap();
    source
        .record_flora(
            founder.to_seed(),
            FloraEvent::RoundProposed {
                spec: FloraRoundSpec {
                    round: FloraRoundId([0x6a; 32]),
                    base_model: ArtifactRef::blake3(b"drop base"),
                    rank_budget: 1,
                    participants: BTreeMap::from([(
                        founder_id,
                        FloraParticipant {
                            rank: 1,
                            weight: FloraWeight {
                                numerator: 1,
                                denominator: 1,
                            },
                        },
                    )]),
                },
                at_ms: 9,
            },
        )
        .await
        .unwrap();
    let expected = source.snapshot().await.unwrap();

    let mut bytes = Vec::new();
    source
        .export_plain_drop(
            &mut bytes,
            DropExportProfile::default(),
            DropLimits::default(),
        )
        .await
        .unwrap();
    let late_peer = Moot::in_memory(ID, founder_id, retention());
    let receipt = late_peer
        .import_plain_drop(Cursor::new(bytes), DropLimits::default())
        .await
        .unwrap();

    assert_eq!(receipt.constitution_operations, 1);
    assert_eq!(receipt.delegation_operations, 1);
    assert_eq!(receipt.membership_operations, 1);
    assert_eq!(receipt.standing_operations, 1);
    assert_eq!(receipt.tulpa_operations, 1);
    assert_eq!(receipt.flora_operations, 1);
    assert_eq!(receipt.snapshot, expected);
    assert_eq!(receipt.snapshot.membership.members[0].member, member_root);
    assert_eq!(receipt.snapshot.roster.members.len(), 1);
    assert_eq!(receipt.snapshot.roster.fauna.len(), 1);
    assert_eq!(receipt.snapshot.delegated_certificates, 1);
    assert_eq!(receipt.snapshot.standing_operations, 1);
    assert_eq!(receipt.snapshot.tulpa.facts.len(), 1);
    assert_eq!(receipt.snapshot.flora.rounds.len(), 1);
}

#[tokio::test]
async fn native_drop_bootstraps_checkpoint_and_roster_then_is_idempotent() {
    let founder = keypair(4);
    let founder_id = founder.public_key().to_bytes();
    let source = Moot::in_memory(ID, founder_id, retention());
    let destination = Moot::in_memory(ID, founder_id, retention());
    for service in [&source, &destination] {
        service
            .found(
                founder.to_seed(),
                None,
                None,
                ConstitutionRules::founder_only(founder_id),
                1,
            )
            .await
            .unwrap();
    }
    source
        .declare(
            founder.to_seed(),
            "drop circle".into(),
            "travels by file".into(),
            2,
        )
        .await
        .unwrap();
    source
        .join(founder.to_seed(), "mark".into(), 3)
        .await
        .unwrap();
    source.checkpoint(founder.to_seed(), 4).await.unwrap();

    let mut bytes = Vec::new();
    source
        .export_plain_drop(
            &mut bytes,
            DropExportProfile::default(),
            DropLimits::default(),
        )
        .await
        .unwrap();
    let first = destination
        .import_plain_drop(Cursor::new(bytes.clone()), DropLimits::default())
        .await
        .unwrap();
    assert_eq!(first.snapshot.roster.members.len(), 1);
    assert_eq!(
        first.snapshot.roster.declaration.unwrap().name,
        "drop circle"
    );
    assert!(first.snapshot.checkpoint.is_some());

    let repeated = destination
        .import_plain_drop(Cursor::new(bytes), DropLimits::default())
        .await
        .unwrap();
    assert!(repeated.import.receipt_hit);
}

#[tokio::test]
async fn aggregate_drop_bootstraps_rotated_checkpoint_authority() {
    let founder = keypair(5);
    let successor = keypair(6);
    let founder_id = founder.public_key().to_bytes();
    let source = Moot::in_memory(ID, founder_id, retention());
    let destination = Moot::in_memory(ID, founder_id, retention());
    source
        .found(
            founder.to_seed(),
            None,
            None,
            ConstitutionRules::founder_only(founder_id),
            1,
        )
        .await
        .unwrap();
    source
        .join(founder.to_seed(), "mark".into(), 2)
        .await
        .unwrap();
    source.checkpoint(founder.to_seed(), 3).await.unwrap();
    let mut rules = ConstitutionRules::founder_only(founder_id);
    rules.checkpoint_signers.clear();
    rules
        .checkpoint_signers
        .insert(successor.public_key().to_bytes());
    source.amend(founder.to_seed(), rules, 4).await.unwrap();
    let rotated = source.checkpoint(successor.to_seed(), 5).await.unwrap();

    let mut bytes = Vec::new();
    source
        .export_plain_drop(
            &mut bytes,
            DropExportProfile::default(),
            DropLimits::default(),
        )
        .await
        .unwrap();
    let imported = destination
        .import_plain_drop(Cursor::new(bytes), DropLimits::default())
        .await
        .unwrap();
    assert_eq!(imported.constitution_operations, 2);
    assert_eq!(
        imported.snapshot.checkpoint.unwrap().operation,
        rotated.operation
    );
    assert_eq!(imported.snapshot.roster.members.len(), 1);
}
