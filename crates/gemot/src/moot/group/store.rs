// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Muniment-backed signed membership operation store.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use identity::{IdentityError, IdentityProvider};
use muniment::{Backend, MemoryBackend, RedbBackend, StoreError};
use p2panda_core::{Hash, Operation, SigningKey, Topic, VerifyingKey};
use p2panda_store::logs::LogStore;
use p2panda_store::topics::TopicStore;
use stickleback::{
    Admission, MunimentStore, OperationPolicy, OperationProcessor, ProcessError, Reject,
    StoreTarget, decode_operation_record, operation_record,
};

use super::wire::{
    MootGroupExt, MootGroupWireError, from_operation, membership_identity_salt, to_group_operation,
    to_operation_seed,
};
use super::{
    MootGroup, MootGroupError, MootGroupOperation, MootGroupSnapshot, MootMembershipAction,
    MootMembershipRecord,
};
use stickleback::DropRecord;

const LOG_ID: u64 = 0;
const MAX_DEPENDENCIES: usize = 64;
const MAX_INITIAL_MEMBERS: usize = 4096;

/// Durable membership storage or materialization failure.
#[derive(Debug, thiserror::Error)]
pub enum MootGroupStoreError {
    /// Shared backend failure.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Shared processor rejection.
    #[error(transparent)]
    Process(#[from] ProcessError),
    /// Stable membership wire validation failed.
    #[error(transparent)]
    Wire(#[from] MootGroupWireError),
    /// A locally authored action is invalid under the current membership fold.
    #[error(transparent)]
    Group(#[from] MootGroupError),
    /// Personae could not derive or attest the membership writer.
    #[error(transparent)]
    Identity(#[from] IdentityError),
    /// Native-drop membership evidence is malformed.
    #[error("membership drop evidence: {0}")]
    Drop(String),
}

#[derive(Clone, Copy)]
struct MembershipPolicy {
    moot_id: [u8; 32],
}

impl OperationPolicy<MootGroupExt> for MembershipPolicy {
    type LogId = u64;

    fn admit(&self, operation: &Operation<MootGroupExt>) -> Result<Admission<Self::LogId>, Reject> {
        if operation.header.extensions.moot_id != self.moot_id {
            return Err(Reject::new(
                "wrong-moot",
                "membership operation addresses another Moot",
            ));
        }
        let record = from_operation(operation)
            .map_err(|error| Reject::new("invalid-membership-record", error.to_string()))?;
        validate_record(&record)?;
        to_group_operation(operation)
            .map_err(|error| Reject::new("invalid-membership-author", error.to_string()))?;
        Ok(Admission::keep(StoreTarget::new(
            Topic::from(self.moot_id),
            LOG_ID,
        )))
    }
}

fn validate_record(record: &MootMembershipRecord) -> Result<(), Reject> {
    if record.dependencies.len() > MAX_DEPENDENCIES {
        return Err(Reject::new(
            "membership-dependencies",
            "membership dependency frontier exceeds its bound",
        ));
    }
    let unique: BTreeSet<_> = record.dependencies.iter().copied().collect();
    if unique.len() != record.dependencies.len() {
        return Err(Reject::new(
            "membership-dependencies",
            "membership dependency frontier contains duplicates",
        ));
    }
    match &record.action {
        MootMembershipAction::Create { initial_members } => {
            if !record.dependencies.is_empty() {
                return Err(Reject::new(
                    "membership-create-dependencies",
                    "membership creation cannot depend on an existing group state",
                ));
            }
            if initial_members.len() > MAX_INITIAL_MEMBERS {
                return Err(Reject::new(
                    "membership-initial-members",
                    "initial membership exceeds its bound",
                ));
            }
        }
        _ if record.dependencies.is_empty() => {
            return Err(Reject::new(
                "membership-missing-dependency",
                "a membership change must name its observed auth frontier",
            ));
        }
        _ => {}
    }
    Ok(())
}

/// One Moot's independent signed membership corpus.
#[derive(Clone)]
pub struct MootGroupStore<B> {
    moot_id: [u8; 32],
    store: MunimentStore<B, MootGroupExt>,
}

/// Durable redb membership store.
pub type MootGroupFileStore = MootGroupStore<RedbBackend>;

impl MootGroupStore<MemoryBackend> {
    /// Create an ephemeral membership store.
    pub fn in_memory(moot_id: [u8; 32]) -> Self {
        Self {
            moot_id,
            store: MunimentStore::new(MemoryBackend::new()),
        }
    }
}

impl MootGroupStore<RedbBackend> {
    /// Open durable membership state for one Moot.
    pub fn open(path: impl AsRef<Path>, moot_id: [u8; 32]) -> Result<Self, MootGroupStoreError> {
        Ok(Self {
            moot_id,
            store: MunimentStore::new(RedbBackend::open(path)?),
        })
    }
}

impl<B: Backend + Clone> MootGroupStore<B> {
    /// Shared LogSync store surface.
    pub fn sync_store(&self) -> MunimentStore<B, MootGroupExt> {
        self.store.clone()
    }

    /// Retain a structurally valid signed membership operation.
    ///
    /// Cross-author auth dependencies may still be absent. The deterministic
    /// materializer keeps those operations pending until their dependencies
    /// arrive and excludes actions rejected by p2panda-auth.
    pub async fn accept(
        &self,
        operation: &Operation<MootGroupExt>,
    ) -> Result<bool, MootGroupStoreError> {
        let processor = OperationProcessor::new(
            self.store.clone(),
            MembershipPolicy {
                moot_id: self.moot_id,
            },
        );
        Ok(processor.process(operation).await?.inserted())
    }

    /// Look up one retained membership operation.
    pub async fn get(
        &self,
        hash: &Hash,
    ) -> Result<Option<Operation<MootGroupExt>>, MootGroupStoreError> {
        Ok(self.store.get_operation(hash).await?)
    }

    /// Author directly under a stable identity key.
    pub async fn author_seed(
        &self,
        signing_seed: [u8; 32],
        action: MootMembershipAction,
    ) -> Result<Operation<MootGroupExt>, MootGroupStoreError> {
        self.author_record(signing_seed, None, action).await
    }

    /// Author under a Moot-scoped key certified by the stable Personae root.
    pub async fn author_for_identity<P: IdentityProvider + ?Sized>(
        &self,
        identity: &P,
        action: MootMembershipAction,
    ) -> Result<Operation<MootGroupExt>, MootGroupStoreError> {
        let salt = membership_identity_salt(self.moot_id);
        let keypair = identity.derive_keypair(&salt)?;
        let attestation = identity.attest_derived_key(&salt)?;
        self.author_record(keypair.to_seed(), Some(attestation), action)
            .await
    }

    async fn author_record(
        &self,
        signing_seed: [u8; 32],
        author_attestation: Option<identity::DerivedKeyAttestation>,
        action: MootMembershipAction,
    ) -> Result<Operation<MootGroupExt>, MootGroupStoreError> {
        let group = self.group().await?;
        let dependencies = group.auth_heads();
        let record = MootMembershipRecord {
            action,
            dependencies,
            author_attestation,
        };
        validate_record(&record).map_err(ProcessError::Rejected)?;
        let author = SigningKey::from_bytes(&signing_seed).verifying_key();
        let (seq_num, backlink) = match self.latest(&author).await? {
            Some(previous) => (previous.header.seq_num + 1, Some(*previous.hash.as_bytes())),
            None => (0, None),
        };
        let operation = to_operation_seed(signing_seed, self.moot_id, &record, seq_num, backlink);
        let translated = to_group_operation(&operation)?;
        let mut preflight = group;
        preflight.apply_verified(&translated)?;
        self.accept(&operation).await?;
        Ok(operation)
    }

    async fn latest(
        &self,
        author: &VerifyingKey,
    ) -> Result<Option<Operation<MootGroupExt>>, MootGroupStoreError> {
        Ok(self.store.get_latest_entry(author, &LOG_ID).await?)
    }

    /// Current effective p2panda-auth membership.
    pub async fn group(&self) -> Result<MootGroup, MootGroupStoreError> {
        Ok(self.materialize().await?.group)
    }

    /// Plain aggregate snapshot, including honest pending/rejected counts.
    pub async fn snapshot(&self) -> Result<MootGroupSnapshot, MootGroupStoreError> {
        let materialized = self.materialize().await?;
        Ok(MootGroupSnapshot {
            group: self.moot_id,
            epoch: materialized.group.epoch(),
            members: materialized.group.member_snapshots(),
            auth_heads: materialized.group.auth_heads(),
            retained_operations: materialized.retained,
            pending_operations: materialized.pending,
            rejected_operations: materialized.rejected,
        })
    }

    async fn materialize(&self) -> Result<MaterializedGroup, MootGroupStoreError> {
        let operations = self.operations().await?;
        let retained = operations.len();
        let mut pending: Vec<MootGroupOperation> = operations
            .iter()
            .map(to_group_operation)
            .collect::<Result<_, _>>()?;
        pending.sort_by_key(|operation| operation.id);

        let mut group = MootGroup::new(self.moot_id);
        let mut accepted = BTreeSet::new();
        let mut rejected = 0;
        loop {
            let before = pending.len();
            let mut next = Vec::new();
            for operation in pending {
                if operation
                    .dependencies
                    .iter()
                    .all(|dependency| accepted.contains(dependency))
                {
                    if group.apply_verified(&operation).is_ok() {
                        accepted.insert(operation.id);
                    } else {
                        rejected += 1;
                    }
                } else {
                    next.push(operation);
                }
            }
            if next.is_empty() || next.len() == before {
                pending = next;
                break;
            }
            pending = next;
        }
        Ok(MaterializedGroup {
            group,
            retained,
            pending: pending.len(),
            rejected,
        })
    }

    /// Retained, structurally valid operation corpus.
    pub async fn operations(&self) -> Result<Vec<Operation<MootGroupExt>>, MootGroupStoreError> {
        let logs: BTreeMap<VerifyingKey, Vec<u64>> =
            self.store.resolve(&Topic::from(self.moot_id)).await?;
        let mut operations = Vec::new();
        for (author, log_ids) in logs {
            for log_id in log_ids {
                if let Some(entries) = self
                    .store
                    .get_log_entries(&author, &log_id, None, None)
                    .await?
                {
                    operations.extend(entries.into_iter().map(|(operation, _)| operation));
                }
            }
        }
        Ok(operations)
    }

    /// Signed membership corpus for aggregate native-drop carriage.
    pub async fn drop_records(&self) -> Result<Vec<DropRecord>, MootGroupStoreError> {
        Ok(self
            .operations()
            .await?
            .iter()
            .map(|operation| operation_record(operation, true))
            .collect())
    }

    /// Admit native-drop membership records through the ordinary policy.
    pub async fn accept_drop_records(
        &self,
        records: &[DropRecord],
    ) -> Result<u64, MootGroupStoreError> {
        let mut accepted = 0;
        for record in records {
            let Some(operation) = decode_operation_record::<MootGroupExt>(record)
                .map_err(|error| MootGroupStoreError::Drop(error.to_string()))?
            else {
                continue;
            };
            if operation.body.is_none() {
                return Err(MootGroupStoreError::Wire(MootGroupWireError::MissingBody));
            }
            accepted += u64::from(self.accept(&operation).await?);
        }
        Ok(accepted)
    }
}

struct MaterializedGroup {
    group: MootGroup,
    retained: usize,
    pending: usize,
    rejected: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::moot::{MootAccessLevel, MootMember};
    use identity::{IdentityProvider, InMemoryProvider};

    const MOOT: [u8; 32] = [0x6d; 32];

    #[tokio::test]
    async fn personae_writer_materializes_as_its_stable_root() {
        let identity = InMemoryProvider::from_seed([1; 32]);
        let root = identity.master_public_key().to_bytes();
        let store = MootGroupStore::in_memory(MOOT);
        store
            .author_for_identity(
                &identity,
                MootMembershipAction::Create {
                    initial_members: vec![MootMember {
                        member: root,
                        access: MootAccessLevel::Manage,
                    }],
                },
            )
            .await
            .unwrap();

        let snapshot = store.snapshot().await.unwrap();
        assert_eq!(snapshot.members[0].member, root);
        assert_eq!(snapshot.retained_operations, 1);
        assert_eq!(snapshot.pending_operations, 0);
        assert_eq!(snapshot.rejected_operations, 0);
    }

    #[tokio::test]
    async fn attestation_for_another_moot_is_rejected_before_storage() {
        let identity = InMemoryProvider::from_seed([6; 32]);
        let foreign_salt = membership_identity_salt([7; 32]);
        let keypair = identity.derive_keypair(&foreign_salt).unwrap();
        let record = MootMembershipRecord {
            action: MootMembershipAction::Create {
                initial_members: vec![MootMember {
                    member: identity.master_public_key().to_bytes(),
                    access: MootAccessLevel::Manage,
                }],
            },
            dependencies: Vec::new(),
            author_attestation: Some(identity.attest_derived_key(&foreign_salt).unwrap()),
        };
        let operation = to_operation_seed(keypair.to_seed(), MOOT, &record, 0, None);
        let store = MootGroupStore::in_memory(MOOT);

        assert!(matches!(
            store.accept(&operation).await,
            Err(MootGroupStoreError::Process(_))
        ));
        assert_eq!(store.snapshot().await.unwrap().retained_operations, 0);
    }

    #[tokio::test]
    async fn durable_store_rebuilds_membership_from_signed_operations() {
        let identity = InMemoryProvider::from_seed([2; 32]);
        let root = identity.master_public_key().to_bytes();
        let member = [3; 32];
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("membership.redb");
        {
            let store = MootGroupFileStore::open(&path, MOOT).unwrap();
            store
                .author_for_identity(
                    &identity,
                    MootMembershipAction::Create {
                        initial_members: vec![MootMember {
                            member: root,
                            access: MootAccessLevel::Manage,
                        }],
                    },
                )
                .await
                .unwrap();
            store
                .author_for_identity(
                    &identity,
                    MootMembershipAction::Add {
                        member,
                        access: MootAccessLevel::Write,
                    },
                )
                .await
                .unwrap();
        }

        let reopened = MootGroupFileStore::open(&path, MOOT).unwrap();
        let snapshot = reopened.snapshot().await.unwrap();
        assert_eq!(snapshot.members.len(), 2);
        assert!(snapshot.members.iter().any(|entry| entry.member == member));
        assert_eq!(snapshot.retained_operations, 2);
    }

    #[tokio::test]
    async fn cross_author_dependency_stays_pending_then_materializes() {
        let founder_seed = [3; 32];
        let manager_seed = [4; 32];
        let founder = *SigningKey::from_bytes(&founder_seed)
            .verifying_key()
            .as_bytes();
        let manager = *SigningKey::from_bytes(&manager_seed)
            .verifying_key()
            .as_bytes();
        let newcomer = [5; 32];
        let create_record = MootMembershipRecord {
            action: MootMembershipAction::Create {
                initial_members: vec![
                    MootMember {
                        member: founder,
                        access: MootAccessLevel::Manage,
                    },
                    MootMember {
                        member: manager,
                        access: MootAccessLevel::Manage,
                    },
                ],
            },
            dependencies: Vec::new(),
            author_attestation: None,
        };
        let create = to_operation_seed(founder_seed, MOOT, &create_record, 0, None);
        let add_record = MootMembershipRecord {
            action: MootMembershipAction::Add {
                member: newcomer,
                access: MootAccessLevel::Read,
            },
            dependencies: vec![*create.hash.as_bytes()],
            author_attestation: None,
        };
        let add = to_operation_seed(manager_seed, MOOT, &add_record, 0, None);
        let store = MootGroupStore::in_memory(MOOT);

        store.accept(&add).await.unwrap();
        let pending = store.snapshot().await.unwrap();
        assert_eq!(pending.retained_operations, 1);
        assert_eq!(pending.pending_operations, 1);
        assert!(pending.members.is_empty());

        store.accept(&create).await.unwrap();
        let complete = store.snapshot().await.unwrap();
        assert_eq!(complete.pending_operations, 0);
        assert_eq!(complete.members.len(), 3);
        assert!(
            complete
                .members
                .iter()
                .any(|entry| entry.member == newcomer)
        );
    }
}
