// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

#[tokio::test]
async fn one_service_runs_governance_roster_checkpoint_and_rotation() {
    let founder = keypair(1);
    let successor = keypair(2);
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
    service
        .declare(
            founder.to_seed(),
            "printing circle".into(),
            "shared type".into(),
            2,
        )
        .await
        .unwrap();
    service
        .join(founder.to_seed(), "mark".into(), 3)
        .await
        .unwrap();
    let first = service.checkpoint(founder.to_seed(), 10).await.unwrap();

    let mut rotated = ConstitutionRules::founder_only(founder.public_key().to_bytes());
    rotated.checkpoint_signers.clear();
    rotated
        .checkpoint_signers
        .insert(successor.public_key().to_bytes());
    service.amend(founder.to_seed(), rotated, 11).await.unwrap();
    assert!(matches!(
        service.checkpoint(founder.to_seed(), 12).await,
        Err(MootError::Store(MootStoreError::Process(_)))
    ));
    let second = service.checkpoint(successor.to_seed(), 13).await.unwrap();
    assert_eq!(
        second
            .snapshot
            .checkpoint
            .as_ref()
            .unwrap()
            .previous_checkpoint,
        Some(first.operation)
    );

    service.prune_current(founder.to_seed(), 14).await.unwrap();
    let snapshot = service.snapshot().await.unwrap();
    assert_eq!(snapshot.roster.declaration.unwrap().name, "printing circle");
    assert_eq!(snapshot.roster.members.len(), 1);
    assert_eq!(snapshot.checkpoint.unwrap().operation, second.operation);
}

#[tokio::test]
async fn durable_service_reopens_both_governance_and_roster() {
    let directory = tempfile::tempdir().unwrap();
    let founder = keypair(3);
    let founder_id = founder.public_key().to_bytes();
    let service = MootFile::open(directory.path(), ID, founder_id, retention())
        .await
        .unwrap();
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
    service
        .join(founder.to_seed(), "mark".into(), 2)
        .await
        .unwrap();
    drop(service);

    let reopened = MootFile::open(directory.path(), ID, founder_id, retention())
        .await
        .unwrap();
    assert_eq!(reopened.snapshot().await.unwrap().roster.members.len(), 1);
}

#[test]
fn legacy_tessera_file_is_opened_until_standing_file_exists() {
    let directory = tempfile::tempdir().unwrap();
    let legacy = directory.path().join("tessera.redb");
    StandingFileStore::open(&legacy).unwrap();
    assert_eq!(standing_store_path(directory.path()), legacy);

    let standing = directory.path().join("standing.redb");
    StandingFileStore::open(&standing).unwrap();
    assert_eq!(standing_store_path(directory.path()), standing);
}

#[test]
fn legacy_domain_drop_decodes_tessera_operations_as_standing() {
    #[derive(Serialize)]
    struct LegacyDomainEvidence {
        version: u16,
        membership_operations: Vec<DropRecord>,
        tessera_operations: Vec<DropRecord>,
    }

    let legacy = LegacyDomainEvidence {
        version: DOMAIN_EVIDENCE_VERSION,
        membership_operations: Vec::new(),
        tessera_operations: Vec::new(),
    };
    let bytes = encode_cbor(&legacy).unwrap();
    let decoded: DomainEvidence = decode_cbor(bytes.as_slice()).unwrap();
    assert_eq!(decoded.version, DOMAIN_EVIDENCE_VERSION);
    assert!(decoded.membership_operations.is_empty());
    assert!(decoded.standing_operations.is_empty());
    assert!(decoded.tulpa_operations.is_empty());
    assert!(decoded.flora_operations.is_empty());
}

#[tokio::test]
async fn protected_drop_and_standing_command_expose_publishable_operations() {
    let founder = keypair(7);
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
    destination
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
        .declare(
            founder.to_seed(),
            "private circle".into(),
            "sealed".into(),
            2,
        )
        .await
        .unwrap();
    let mut bytes = Vec::new();
    source
        .export_protected_drop(
            &mut bytes,
            &MootDropSelector::default(),
            DropExportBudget::default(),
            DropLimits::default(),
            &TestProtector,
        )
        .await
        .unwrap();
    let imported = destination
        .import_protected_drop(Cursor::new(bytes), DropLimits::default(), &TestProtector)
        .await
        .unwrap();
    assert_eq!(
        imported.snapshot.roster.declaration.unwrap().name,
        "private circle"
    );

    let receipt = source
        .record_standing(
            founder.to_seed(),
            StandingEvent::GovernanceParticipation {
                by: ChainRoot(founder_id),
                at_ms: 3,
            },
        )
        .await
        .unwrap();
    assert_eq!(receipt.lane, MootLane::Standing);
    assert!(matches!(
        source.outbound(&receipt).await.unwrap(),
        MootOutboundOperation::Standing(_)
    ));
}

#[tokio::test]
async fn tulpa_and_flora_commands_surface_distinct_lanes_and_snapshots() {
    let founder = keypair(71);
    let founder_id = founder.public_key().to_bytes();
    let service = Moot::in_memory(ID, founder_id, retention());
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

    let tulpa = service
        .record_tulpa(
            founder.to_seed(),
            TulpaEvent::Proposed {
                proposal: TulpaProposalId([1; 32]),
                action: TulpaProposal::Adopt {
                    tulpa: TulpaId([2; 32]),
                    version: TulpaVersion([3; 32]),
                    artifact: ArtifactRef::blake3(b"tulpa-v1"),
                },
                recognition: RecognitionContext::new(
                    RecognitionPolicy::AnyEligible,
                    ElectorateSnapshot::new(ID.0, [4; 32], [founder_id]),
                ),
                at_ms: 2,
            },
        )
        .await
        .unwrap();
    assert_eq!(tulpa.lane, MootLane::Tulpa);
    assert!(matches!(
        service.outbound(&tulpa).await.unwrap(),
        MootOutboundOperation::Tulpa(_)
    ));
    assert_eq!(tulpa.snapshot.tulpa.facts.len(), 1);

    let flora = service
        .record_flora(
            founder.to_seed(),
            FloraEvent::RoundProposed {
                spec: FloraRoundSpec {
                    round: FloraRoundId([5; 32]),
                    base_model: ArtifactRef::blake3(b"base-model"),
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
                at_ms: 3,
            },
        )
        .await
        .unwrap();
    assert_eq!(flora.lane, MootLane::Flora);
    assert!(matches!(
        service.outbound(&flora).await.unwrap(),
        MootOutboundOperation::Flora(_)
    ));
    assert_eq!(flora.snapshot.flora.rounds.len(), 1);
}
