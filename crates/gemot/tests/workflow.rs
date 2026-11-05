// SPDX-License-Identifier: MPL-2.0
#[path = "workflow/common.rs"]
mod common;
#[path = "workflow/history.rs"]
mod history;
use common::*;
use gemot::moot::workflow::{WorkflowEvent, namespace::*, work::*};
use gemot::moot::*;
use std::io::Cursor;
use stickleback::{DropExportProfile, DropLimits};

#[tokio::test]
async fn names_conflicts_rename_pin_and_read_access_are_independent() {
    let (moot, _) = fixture().await;
    let first = moot
        .bind_for_identity(&person(7), binding("sites/garden", vec![]))
        .await
        .unwrap();
    assert!(
        moot.resolve_name(root(&person(10)), "sites/garden", 21)
            .await
            .is_ok()
    );
    assert!(
        moot.resolve_name(root(&person(11)), "sites/garden", 21)
            .await
            .is_err()
    );
    let left = moot
        .bind_for_identity(&person(7), binding("sites/left", vec![first.operation]))
        .await
        .unwrap();
    let right = moot
        .object_store()
        .author_for_identity(
            &person(8),
            ID.0,
            &MootEvent::Workflow {
                event: WorkflowEvent::Namespace(binding("sites/right", vec![first.operation])),
            },
        )
        .await
        .unwrap();
    assert!(moot.directory(22).await.unwrap()[0].conflict);
    assert!(
        moot.resolve_name(root(&person(10)), "sites/left", 22)
            .await
            .is_err()
    );
    assert!(
        moot.bind_for_identity(&person(7), binding("sites/stale", vec![left.operation]))
            .await
            .is_err()
    );
    let mut heads = vec![left.operation, *right.hash.as_bytes()];
    heads.sort();
    let merged = moot
        .bind_for_identity(&person(7), binding("sites/catalog", heads))
        .await
        .unwrap();
    let mut duplicate = binding("sites/catalog", vec![]);
    duplicate.binding = [99; 32];
    let dup = moot
        .bind_for_identity(&person(7), duplicate.clone())
        .await
        .unwrap();
    assert!(moot.directory(23).await.unwrap().iter().all(|v| v.conflict));
    duplicate.parents = vec![dup.operation];
    duplicate.value = None;
    moot.bind_for_identity(&person(7), duplicate).await.unwrap();
    let current = moot
        .resolve_name(root(&person(10)), "sites/catalog", 23)
        .await
        .unwrap();
    let pinned = CollectionTarget::Pinned(current.version.clone());
    let mut removed = binding("ignored", vec![merged.operation]);
    removed.value = None;
    moot.bind_for_identity(&person(7), removed).await.unwrap();
    assert!(
        moot.resolve_name(root(&person(10)), "sites/catalog", 23)
            .await
            .is_err()
    );
    assert_eq!(
        moot.collection_for_reader(root(&person(10)), &pinned, 23)
            .await
            .unwrap()
            .version,
        current.version
    );
    assert!(
        moot.bind_for_identity(&person(7), binding("sites/../bad", vec![]))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn exact_consent_reviews_replay_conflicts_and_settlement() {
    let (moot, share) = fixture().await;
    let agreement = agree(&moot).await;
    // Repeated consent refers to one agreement and cannot duplicate recognition.
    moot.work_for_identity(
        &person(8),
        event(WorkAction::Accept { offer: agreement }, 6),
    )
    .await
    .unwrap();
    assert_eq!(moot.work_view(WORK, 20).await.unwrap().agreements.len(), 1);
    assert!(
        moot.work_for_identity(
            &person(9),
            event(WorkAction::Accept { offer: agreement }, 7)
        )
        .await
        .is_err()
    );
    let submit = WorkAction::Submit {
        agreement,
        window: 0,
        replaces: vec![],
        outputs: vec![share],
        evidence: vec![],
    };
    let first = moot
        .work_for_identity(&person(8), event(submit.clone(), 20))
        .await
        .unwrap();
    assert!(
        moot.work_for_identity(&person(8), event(submit.clone(), 21))
            .await
            .is_err()
    );
    let other = moot
        .object_store()
        .author_for_identity(
            &person(8),
            ID.0,
            &MootEvent::Workflow {
                event: WorkflowEvent::Work(event(submit, 21)),
            },
        )
        .await
        .unwrap();
    let view = moot.work_view(WORK, 22).await.unwrap();
    assert!(view.submissions.values().all(|s| s.conflict && !s.accepted));
    let mut replaces = vec![first.operation, *other.hash.as_bytes()];
    replaces.sort();
    let merged = moot
        .work_for_identity(
            &person(8),
            event(
                WorkAction::Submit {
                    agreement,
                    window: 0,
                    replaces,
                    outputs: vec![share],
                    evidence: vec![],
                },
                22,
            ),
        )
        .await
        .unwrap();
    assert!(
        moot.work_for_identity(
            &person(8),
            event(
                WorkAction::Review {
                    submission: merged.operation,
                    replaces: vec![],
                    approve: true,
                    rationale: "self review".into()
                },
                23
            )
        )
        .await
        .is_err()
    );
    let yes = moot
        .work_for_identity(
            &person(9),
            event(
                WorkAction::Review {
                    submission: merged.operation,
                    replaces: vec![],
                    approve: true,
                    rationale: "checked".into(),
                },
                23,
            ),
        )
        .await
        .unwrap();
    assert!(moot.work_view(WORK, 24).await.unwrap().submissions[&merged.operation].accepted);
    let no = moot
        .object_store()
        .author_for_identity(
            &person(9),
            ID.0,
            &MootEvent::Workflow {
                event: WorkflowEvent::Work(event(
                    WorkAction::Review {
                        submission: merged.operation,
                        replaces: vec![],
                        approve: false,
                        rationale: "another branch".into(),
                    },
                    24,
                )),
            },
        )
        .await
        .unwrap();
    assert!(!moot.work_view(WORK, 25).await.unwrap().submissions[&merged.operation].accepted);
    let mut replaces = vec![yes.operation, *no.hash.as_bytes()];
    replaces.sort();
    moot.work_for_identity(
        &person(9),
        event(
            WorkAction::Review {
                submission: merged.operation,
                replaces,
                approve: true,
                rationale: "resolved".into(),
            },
            25,
        ),
    )
    .await
    .unwrap();
    moot.work_for_identity(
        &person(7),
        event(
            WorkAction::Settlement {
                submission: merged.operation,
                receipt: [4; 32],
                succeeded: false,
            },
            26,
        ),
    )
    .await
    .unwrap();
    let view = moot.work_view(WORK, 27).await.unwrap();
    assert!(view.submissions[&merged.operation].accepted);
    assert_eq!(
        view.submissions[&merged.operation].settlement,
        vec![([4; 32], false)]
    );
    moot.withdraw_share_for_identity(&person(7), share.share, 28)
        .await
        .unwrap();
    assert!(
        !moot
            .work_view(WORK, 29)
            .await
            .unwrap()
            .submissions
            .contains_key(&merged.operation)
    );
}

#[tokio::test]
async fn drop_restart_missing_dependencies_handoff_and_revocation() {
    let (moot, _) = fixture().await;
    let agreement = agree(&moot).await;
    let directory = tempfile::tempdir().unwrap();
    let mut drop_bytes = Vec::new();
    moot.export_plain_drop(
        &mut drop_bytes,
        DropExportProfile::default(),
        DropLimits::default(),
    )
    .await
    .unwrap();
    let receiver = MootFile::open(directory.path(), ID, root(&person(7)), retention())
        .await
        .unwrap();
    receiver
        .import_plain_drop(Cursor::new(drop_bytes.clone()), DropLimits::default())
        .await
        .unwrap();
    receiver
        .import_plain_drop(Cursor::new(drop_bytes), DropLimits::default())
        .await
        .unwrap();
    let before = receiver.work_view(WORK, 20).await.unwrap();
    assert_eq!(before.agreements.len(), 1);
    drop(receiver);
    let receiver = MootFile::open(directory.path(), ID, root(&person(7)), retention())
        .await
        .unwrap();
    assert_eq!(receiver.work_view(WORK, 20).await.unwrap(), before);
    // Cancellation persists independently; replacement needs successor consent.
    receiver
        .work_for_identity(
            &person(8),
            event(
                WorkAction::Cancel {
                    agreement,
                    reason: "handoff".into(),
                },
                20,
            ),
        )
        .await
        .unwrap();
    let mut next = terms();
    next.worker = root(&person(9));
    let offer = receiver
        .work_for_identity(
            &person(7),
            event(
                WorkAction::Offer {
                    terms: next,
                    replaces: Some(agreement),
                },
                21,
            ),
        )
        .await
        .unwrap();
    assert!(
        receiver
            .work_view(WORK, 22)
            .await
            .unwrap()
            .active_agreement()
            .is_none()
    );
    receiver
        .work_for_identity(
            &person(9),
            event(
                WorkAction::Accept {
                    offer: offer.operation,
                },
                22,
            ),
        )
        .await
        .unwrap();
    assert_eq!(
        receiver
            .work_view(WORK, 23)
            .await
            .unwrap()
            .active_agreement()
            .unwrap()
            .id,
        offer.operation
    );
    receiver
        .update_membership_for_identity(
            &person(7),
            MootMembershipAction::Remove {
                member: root(&person(9)),
            },
        )
        .await
        .unwrap();
    assert!(
        receiver
            .work_view(WORK, 24)
            .await
            .unwrap()
            .agreements
            .get(&offer.operation)
            .is_none()
    );
    assert!(
        receiver
            .work_view(WORK, 24)
            .await
            .unwrap()
            .active_agreement()
            .is_none()
    );
    assert!(
        receiver
            .work_view(WORK, 6000)
            .await
            .unwrap()
            .agreements
            .is_empty()
    );
}

#[tokio::test]
async fn concurrent_offers_can_be_resolved_by_declining_an_exact_offer() {
    let (moot, _) = fixture().await;
    let first = moot
        .work_for_identity(
            &person(7),
            event(
                WorkAction::Offer {
                    terms: terms(),
                    replaces: None,
                },
                4,
            ),
        )
        .await
        .unwrap()
        .operation;
    let mut changed = terms();
    changed.acceptance_criteria = "A different exact proposal".into();
    let second = moot
        .work_for_identity(
            &person(7),
            event(
                WorkAction::Offer {
                    terms: changed,
                    replaces: None,
                },
                5,
            ),
        )
        .await
        .unwrap()
        .operation;
    moot.work_for_identity(&person(8), event(WorkAction::Accept { offer: first }, 6))
        .await
        .unwrap();
    assert!(moot.work_view(WORK, 7).await.unwrap().conflict);
    // Declining an unaccepted offer is distinct from consent to another offer.
    moot.work_for_identity(
        &person(8),
        event(
            WorkAction::Cancel {
                agreement: second,
                reason: "decline competing terms".into(),
            },
            7,
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        moot.work_view(WORK, 8)
            .await
            .unwrap()
            .active_agreement()
            .unwrap()
            .id,
        first
    );
    assert!(
        moot.work_for_identity(&person(8), event(WorkAction::Accept { offer: second }, 8))
            .await
            .is_err()
    );
    // Replayed remote consent cannot revive an offer already declined.
    moot.object_store()
        .author_for_identity(
            &person(8),
            ID.0,
            &MootEvent::Workflow {
                event: WorkflowEvent::Work(event(WorkAction::Accept { offer: second }, 8)),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        moot.work_view(WORK, 9)
            .await
            .unwrap()
            .active_agreement()
            .unwrap()
            .id,
        first
    );
}

#[cfg(feature = "work-host")]
#[path = "workflow/keeper.rs"]
mod keeper;
