// SPDX-License-Identifier: MPL-2.0
use super::*;
use identity::IdentityProvider;
use servitor::{AuthorityProvider, Cap, Mode, Subject};
struct Permit;
impl AuthorityProvider for Permit {
    fn covers(&self, _: Subject, _: &Cap, _: Mode) -> bool {
        true
    }
}

#[tokio::test]
async fn workflow_survives_governed_checkpoint_prune_and_out_of_order_replay() {
    let (moot, share) = fixture().await;
    let agreement = agree(&moot).await;
    moot.bind_for_identity(&person(7), binding("sites/catalog", vec![]))
        .await
        .unwrap();
    let submitted = moot
        .work_for_identity(
            &person(8),
            event(
                WorkAction::Submit {
                    agreement,
                    window: 0,
                    replaces: vec![],
                    outputs: vec![share],
                    evidence: vec![],
                },
                20,
            ),
        )
        .await
        .unwrap();
    moot.work_for_identity(
        &person(9),
        event(
            WorkAction::Review {
                submission: submitted.operation,
                replaces: vec![],
                approve: true,
                rationale: "qualified".into(),
            },
            21,
        ),
    )
    .await
    .unwrap();
    let objects = moot.object_store();
    let ops = objects.ops(ID.0).await.unwrap();
    let ordered = MootRoster::fold(ID.0, &ops);
    let reversed = MootRoster::fold(ID.0, ops.iter().rev());
    assert_eq!(ordered, reversed);
    let missing = MootRoster::fold(
        ID.0,
        ops.iter().filter(|op| *op.hash.as_bytes() != agreement),
    );
    assert!(missing.work(WORK, &Permit).agreements.is_empty());
    assert!(!missing.work(WORK, &Permit).pending.is_empty());
    let before = moot.work_view(WORK, 22).await.unwrap();
    let checkpoint = objects.build_checkpoint(ID.0, 23).await.unwrap();
    assert_eq!(checkpoint.snapshot.roster.workflow, ordered.workflow);
    // Even the governed checkpoint signer cannot impersonate a worker by
    // changing compacted fields while retaining somebody else's signed proof.
    let mut forged_snapshot = checkpoint.snapshot.clone();
    forged_snapshot.roster.workflow[0].by = root(&person(11));
    let forged = RetentionCheckpoint::new(
        checkpoint.moot_id,
        checkpoint.policy_revision.clone(),
        checkpoint.authority_revision.clone(),
        checkpoint.previous_checkpoint,
        checkpoint.frontier.clone(),
        forged_snapshot,
        checkpoint.at_ms,
    );
    assert!(
        objects
            .author_seed(
                [7; 32],
                ID.0,
                &MootEvent::RetentionCheckpoint {
                    checkpoint: Box::new(forged)
                }
            )
            .await
            .is_err()
    );
    let cp = objects
        .author_seed(
            [7; 32],
            ID.0,
            &MootEvent::RetentionCheckpoint {
                checkpoint: Box::new(checkpoint),
            },
        )
        .await
        .unwrap();
    for seed in [7, 8, 9] {
        let signer = person(seed)
            .derive_keypair(&object_identity_salt(ID.0))
            .unwrap()
            .to_seed();
        objects
            .author_prune_seed(signer, ID.0, *cp.hash.as_bytes(), 24)
            .await
            .unwrap();
    }
    assert_eq!(
        objects.roster(ID.0).await.unwrap().workflow,
        ordered.workflow
    );
    assert_eq!(moot.work_view(WORK, 25).await.unwrap(), before);
    let retained = objects.ops(ID.0).await.unwrap();
    assert!(!retained.iter().any(|op| *op.hash.as_bytes() == agreement));
    let directory = tempfile::tempdir().unwrap();
    let target = MootFile::open(directory.path(), ID, root(&person(7)), retention())
        .await
        .unwrap();
    let mut drop = Vec::new();
    moot.export_plain_drop(
        &mut drop,
        DropExportProfile::default(),
        DropLimits::default(),
    )
    .await
    .unwrap();
    target
        .import_plain_drop(Cursor::new(drop), DropLimits::default())
        .await
        .unwrap();
    assert_eq!(target.work_view(WORK, 26).await.unwrap(), before);
    assert!(
        target
            .resolve_name(root(&person(10)), "sites/catalog", 26)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn optional_standing_consumes_accepted_work_and_duplicate_fulfillment_rewards_once() {
    let (moot, share) = fixture().await;
    let worker = person(8);
    let by = mien::ChainRoot(root(&worker));
    let commitment = mien::CommitmentId([11; 32]);
    moot.record_standing_for_identity(
        &worker,
        mien::StandingEvent::CommitmentMade {
            by,
            commitment,
            scope: mien::Scope("catalogue contribution".into()),
            cadence_ms: 1000,
            duration_ms: None,
            at_ms: 4,
        },
    )
    .await
    .unwrap();
    let mut t = terms();
    t.kind = WorkKind::Contribution;
    t.standing_commitment = Some(commitment);
    let offer = moot
        .work_for_identity(
            &person(7),
            event(
                WorkAction::Offer {
                    terms: t,
                    replaces: None,
                },
                5,
            ),
        )
        .await
        .unwrap()
        .operation;
    moot.work_for_identity(&worker, event(WorkAction::Accept { offer }, 6))
        .await
        .unwrap();
    assert!(
        moot.work_view(WORK, 20)
            .await
            .unwrap()
            .accepted_work(offer)
            .is_none()
    );
    let submission = moot
        .work_for_identity(
            &worker,
            event(
                WorkAction::Submit {
                    agreement: offer,
                    window: 0,
                    replaces: vec![],
                    outputs: vec![share],
                    evidence: vec![],
                },
                20,
            ),
        )
        .await
        .unwrap()
        .operation;
    moot.work_for_identity(
        &person(9),
        event(
            WorkAction::Review {
                submission,
                replaces: vec![],
                approve: true,
                rationale: "met exact criteria".into(),
            },
            21,
        ),
    )
    .await
    .unwrap();
    let accepted = moot
        .work_view(WORK, 22)
        .await
        .unwrap()
        .accepted_work(offer)
        .unwrap();
    assert_eq!(accepted.worker, by.0);
    assert_eq!(accepted.standing_commitment, Some(commitment));
    let config = mien::StandingConfig::default();
    let before = moot
        .standing_store()
        .fold_moot(ID.0, config.clone())
        .await
        .unwrap()
        .score(&by, 22);
    // The host explicitly consumes the accepted-work receipt through Standing.
    for at_ms in [23, 24] {
        moot.record_standing_for_identity(
            &worker,
            mien::StandingEvent::CommitmentFulfilled {
                by,
                commitment: accepted.standing_commitment.unwrap(),
                at_ms,
            },
        )
        .await
        .unwrap();
    }
    let after = moot
        .standing_store()
        .fold_moot(ID.0, config.clone())
        .await
        .unwrap()
        .score(&by, 25);
    assert_eq!(after - before, config.fulfil_reward);
}

#[tokio::test]
async fn malformed_wire_and_foreign_targets_never_enter_the_store() {
    let (moot, _) = fixture().await;
    let mut invalid = binding("sites/catalog", vec![]);
    invalid.version = 77;
    let op = moot
        .object_store()
        .prepare_for_identity(
            &person(7),
            ID.0,
            &MootEvent::Workflow {
                event: WorkflowEvent::Namespace(invalid),
            },
        )
        .await
        .unwrap();
    assert!(moot.object_store().insert(&op).await.is_err());
    let mut foreign = terms();
    foreign.inputs = CollectionTarget::FollowAccepted(CollectionRef {
        moot_id: [99; 32],
        ..COLLECTION
    });
    assert!(
        moot.work_for_identity(
            &person(7),
            event(
                WorkAction::Offer {
                    terms: foreign,
                    replaces: None
                },
                4
            )
        )
        .await
        .is_err()
    );
}
