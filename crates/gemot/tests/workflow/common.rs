// SPDX-License-Identifier: MPL-2.0
#![allow(dead_code)]
use gemot::moot::constitution::{CapabilityGrant, ConstitutionRules};
use gemot::moot::records::fauna_cap;
use gemot::moot::workflow::namespace::*;
use gemot::moot::workflow::work::*;
use gemot::moot::*;
use identity::{IdentityProvider, InMemoryProvider};
use muniment::{Backend, MemoryBackend};
use proofs::Digest;
use servitor::cap_path;

pub const ID: MootId = MootId([0x71; 32]);
pub const WORK: [u8; 32] = [0x72; 32];
pub const BINDING: [u8; 32] = [0x73; 32];
pub const COLLECTION: CollectionRef = CollectionRef {
    moot_id: ID.0,
    collection_id: CollectionId([0x74; 32]),
};
pub fn person(seed: u8) -> InMemoryProvider {
    InMemoryProvider::from_seed([seed; 32])
}
pub fn root(id: &InMemoryProvider) -> [u8; 32] {
    id.master_public_key().to_bytes()
}
pub fn retention() -> MootRetentionSettings {
    MootRetentionSettings {
        revision: PolicyRevision(Digest::blake3(b"workflow-test")),
        availability: AvailabilityPolicy {
            promised_floor: KeepBound::Forever,
        },
        erasure: ErasurePolicy {
            history_ceiling: KeepBound::UntilCheckpoint,
        },
    }
}
pub async fn initialize<B: Backend + Clone>(moot: &Moot<B>) {
    let ids = [person(7), person(8), person(9), person(10)];
    let mut rules = ConstitutionRules::founder_only(root(&ids[0]));
    rules.admission = mien::Policy::MembersOnly {
        rate_limit: 1000,
        rate_window_ms: 1000,
    };
    let mut tag = 0u8;
    for (n, id) in ids.iter().enumerate() {
        let mut caps = vec![collection_read_cap(COLLECTION)];
        if n < 3 {
            caps.push(work_cap(WORK));
        }
        if n < 2 {
            caps.push(servitor::Cap::scope("moot/namespace").unwrap());
        }
        if n == 0 {
            caps.extend([
                fauna_cap(),
                collection_cap(COLLECTION),
                offer_cap(WORK),
                settlement_cap(WORK),
            ]);
        }
        for cap in caps {
            tag += 1;
            rules.grant(CapabilityGrant {
                id: [tag; 32],
                subject: root(id),
                path_prefix: cap_path(&cap),
                not_before_ms: 0,
                expires_at_ms: Some(5000),
                delegation_depth: 0,
            });
        }
    }
    moot.found([7; 32], None, None, rules, 0).await.unwrap();
    moot.update_membership_for_identity(
        &ids[0],
        MootMembershipAction::Create {
            initial_members: ids
                .iter()
                .enumerate()
                .map(|(n, id)| MootMember {
                    member: root(id),
                    access: if n == 0 {
                        MootAccessLevel::Manage
                    } else if n == 3 {
                        MootAccessLevel::Read
                    } else {
                        MootAccessLevel::Write
                    },
                })
                .collect(),
        },
    )
    .await
    .unwrap();
}
pub async fn fixture() -> (Moot<MemoryBackend>, ContributionRef) {
    let moot = Moot::in_memory(ID, root(&person(7)), retention());
    initialize(&moot).await;
    let share = populate(&moot, [0x55; 32]).await;
    (moot, share)
}
pub async fn populate<B: Backend + Clone>(moot: &Moot<B>, manifest: [u8; 32]) -> ContributionRef {
    let id = person(7);
    let share = moot
        .share_authorized_for_identity(
            &id,
            manifest,
            "gemot/catalogue-document/v1".into(),
            "Garden".into(),
            1,
        )
        .await
        .unwrap();
    let declared = moot
        .declare_collection_for_identity(
            &id,
            COLLECTION.collection_id,
            "Garden catalogue".into(),
            None,
            2,
        )
        .await
        .unwrap();
    let contribution = ContributionRef {
        moot_id: ID.0,
        share: share.operation,
    };
    moot.set_collection_membership_for_identity(
        &id,
        COLLECTION,
        vec![declared.operation],
        CollectionChange::SetMembership {
            contribution,
            included: true,
        },
        3,
    )
    .await
    .unwrap();
    contribution
}
pub fn terms() -> WorkTerms {
    WorkTerms {
        worker: root(&person(8)),
        title: "Keep the garden catalogue".into(),
        acceptance_criteria:
            "Exact retained bytes, retrieval evidence, reviewed searchable catalogue".into(),
        inputs: CollectionTarget::FollowAccepted(COLLECTION),
        kind: WorkKind::Hosting {
            evidence_every_ms: 100,
        },
        starts_at_ms: 10,
        ends_at_ms: 1010,
        max_bytes: 65536,
        reviewers: vec![root(&person(9))],
        approvals_required: 1,
        compensation: Compensation::None,
        standing_commitment: None,
        max_renewals: 2,
        allow_handoff: true,
    }
}
pub fn event(action: WorkAction, at_ms: u64) -> WorkEvent {
    WorkEvent {
        version: 1,
        work: WORK,
        action,
        at_ms,
    }
}
pub async fn agree<B: Backend + Clone>(moot: &Moot<B>) -> [u8; 32] {
    let offer = moot
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
        .unwrap();
    moot.work_for_identity(
        &person(8),
        event(
            WorkAction::Accept {
                offer: offer.operation,
            },
            5,
        ),
    )
    .await
    .unwrap();
    offer.operation
}
pub fn binding(name: &str, parents: Vec<[u8; 32]>) -> NamespaceEvent {
    NamespaceEvent {
        version: 1,
        binding: BINDING,
        parents,
        value: Some(NamespaceBinding {
            name: name.into(),
            target: CollectionTarget::FollowAccepted(COLLECTION),
        }),
        at_ms: 20,
    }
}
