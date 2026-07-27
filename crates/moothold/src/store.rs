// Copyright 2026 Mark AB (markik)
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeMap;
use std::path::Path;

use muniment::{Backend, MemoryBackend, RedbBackend, StoreError};
use p2panda_core::{Operation, SigningKey, Topic, VerifyingKey};
use p2panda_store::logs::LogStore;
use p2panda_store::topics::TopicStore;
use stickleback::{
    Admission, MunimentStore, OperationPolicy, OperationProcessor, ProcessError, Reject,
    StoreTarget,
};

use crate::{
    CompositionPolicy, MemberTerms, MootId, Moothold, MootholdError, MootholdEvent, MootholdExt,
    MootholdId, from_operation, to_operation_seed,
};

const LOG_ID: u64 = 0;

#[derive(Debug, thiserror::Error)]
pub enum MootholdStoreError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Process(#[from] ProcessError),
    #[error(transparent)]
    Moothold(#[from] MootholdError),
    #[error("Moothold is not founded")]
    NotFounded,
}

#[derive(Clone, Copy)]
struct MootholdPolicy {
    id: MootholdId,
    founder: [u8; 32],
}

impl OperationPolicy<MootholdExt> for MootholdPolicy {
    type LogId = u64;

    fn admit(&self, operation: &Operation<MootholdExt>) -> Result<Admission<Self::LogId>, Reject> {
        if operation.header.extensions.moothold_id != self.id.0 {
            return Err(Reject::new(
                "wrong-moothold",
                "operation addresses another Moothold",
            ));
        }
        let event = from_operation(operation).map_err(|_| {
            Reject::new(
                "invalid-moothold-event",
                "operation body is not a Moothold event",
            )
        })?;
        if !event.is_well_formed() {
            return Err(Reject::new(
                "invalid-moothold-event",
                "Moothold event settings are invalid",
            ));
        }
        let author = *operation.header.verifying_key.as_bytes();
        match event {
            MootholdEvent::Founded {
                moothold_id,
                founder,
                ..
            } if moothold_id == self.id && founder == self.founder && author == self.founder => {}
            MootholdEvent::Founded { .. } => {
                return Err(Reject::new(
                    "wrong-founder",
                    "foundation does not bind the configured founder",
                ));
            }
            _ if author != self.founder => {
                return Err(Reject::new(
                    "unauthorized-moothold-event",
                    "actor is not the Moothold founder",
                ));
            }
            _ => {}
        }
        Ok(Admission::keep(StoreTarget::new(
            Topic::from(self.id.0),
            LOG_ID,
        )))
    }
}

/// One Moothold's signed aggregate log over a shared backend.
#[derive(Clone)]
pub struct MootholdStore<B> {
    id: MootholdId,
    founder: [u8; 32],
    store: MunimentStore<B, MootholdExt>,
}

pub type MootholdFileStore = MootholdStore<RedbBackend>;

impl MootholdStore<MemoryBackend> {
    pub fn in_memory(id: MootholdId, founder: [u8; 32]) -> Self {
        Self {
            id,
            founder,
            store: MunimentStore::new(MemoryBackend::new()),
        }
    }
}

impl MootholdStore<RedbBackend> {
    pub fn open(
        path: impl AsRef<Path>,
        id: MootholdId,
        founder: [u8; 32],
    ) -> Result<Self, MootholdStoreError> {
        Ok(Self {
            id,
            founder,
            store: MunimentStore::new(RedbBackend::open(path)?),
        })
    }
}

impl<B: Backend + Clone> MootholdStore<B> {
    pub fn sync_store(&self) -> MunimentStore<B, MootholdExt> {
        self.store.clone()
    }

    pub async fn accept(
        &self,
        operation: &Operation<MootholdExt>,
    ) -> Result<bool, MootholdStoreError> {
        if self.store.has_operation(&operation.hash).await? {
            return Ok(false);
        }
        let event = from_operation(operation).map_err(|_| MootholdError::Malformed)?;
        let current = self.aggregate().await?;
        match (&current, &event) {
            (None, MootholdEvent::Founded { .. }) => {}
            (None, _) => return Err(MootholdStoreError::NotFounded),
            (Some(_), MootholdEvent::Founded { .. }) => {
                return Err(MootholdError::AlreadyFounded.into());
            }
            (Some(state), _) => {
                if event.previous() != Some(state.revision) {
                    return Err(MootholdError::StaleRevision.into());
                }
                if *operation.header.verifying_key.as_bytes() != state.founder {
                    return Err(MootholdError::Unauthorized.into());
                }
            }
        }
        let processor = OperationProcessor::new(
            self.store.clone(),
            MootholdPolicy {
                id: self.id,
                founder: self.founder,
            },
        );
        Ok(processor.process(operation).await?.inserted())
    }

    pub async fn aggregate(&self) -> Result<Option<Moothold>, MootholdStoreError> {
        let operations = self.operations().await?;
        Ok(Moothold::fold(self.id, self.founder, operations.iter()))
    }

    pub async fn author_foundation(
        &self,
        signing_seed: [u8; 32],
        name: String,
        initial_moot: MootId,
        initial_terms: MemberTerms,
        composition: CompositionPolicy,
        at_ms: u64,
    ) -> Result<Operation<MootholdExt>, MootholdStoreError> {
        if self.aggregate().await?.is_some() {
            return Err(MootholdError::AlreadyFounded.into());
        }
        let actor = *SigningKey::from_bytes(&signing_seed)
            .verifying_key()
            .as_bytes();
        if actor != self.founder {
            return Err(MootholdError::Unauthorized.into());
        }
        self.author_event(
            signing_seed,
            &MootholdEvent::Founded {
                moothold_id: self.id,
                name,
                founder: self.founder,
                initial_moot,
                initial_terms,
                composition,
                at_ms,
            },
        )
        .await
    }

    pub async fn admit_moot(
        &self,
        signing_seed: [u8; 32],
        moot: MootId,
        terms: MemberTerms,
        at_ms: u64,
    ) -> Result<Operation<MootholdExt>, MootholdStoreError> {
        let state = self
            .aggregate()
            .await?
            .ok_or(MootholdStoreError::NotFounded)?;
        self.author_event(
            signing_seed,
            &MootholdEvent::MootAdmitted {
                previous: state.revision,
                moot,
                terms,
                at_ms,
            },
        )
        .await
    }

    pub async fn remove_moot(
        &self,
        signing_seed: [u8; 32],
        moot: MootId,
        at_ms: u64,
    ) -> Result<Operation<MootholdExt>, MootholdStoreError> {
        let state = self
            .aggregate()
            .await?
            .ok_or(MootholdStoreError::NotFounded)?;
        self.author_event(
            signing_seed,
            &MootholdEvent::MootRemoved {
                previous: state.revision,
                moot,
                at_ms,
            },
        )
        .await
    }

    pub async fn change_composition(
        &self,
        signing_seed: [u8; 32],
        composition: CompositionPolicy,
        at_ms: u64,
    ) -> Result<Operation<MootholdExt>, MootholdStoreError> {
        let state = self
            .aggregate()
            .await?
            .ok_or(MootholdStoreError::NotFounded)?;
        self.author_event(
            signing_seed,
            &MootholdEvent::CompositionChanged {
                previous: state.revision,
                composition,
                at_ms,
            },
        )
        .await
    }

    async fn author_event(
        &self,
        signing_seed: [u8; 32],
        event: &MootholdEvent,
    ) -> Result<Operation<MootholdExt>, MootholdStoreError> {
        let author = SigningKey::from_bytes(&signing_seed).verifying_key();
        if *author.as_bytes() != self.founder {
            return Err(MootholdError::Unauthorized.into());
        }
        let (seq_num, backlink) = match self.latest(&author).await? {
            Some(previous) => (previous.header.seq_num + 1, Some(*previous.hash.as_bytes())),
            None => (0, None),
        };
        let operation = to_operation_seed(signing_seed, self.id, event, seq_num, backlink);
        self.accept(&operation).await?;
        Ok(operation)
    }

    async fn latest(
        &self,
        author: &VerifyingKey,
    ) -> Result<Option<Operation<MootholdExt>>, MootholdStoreError> {
        Ok(self.store.get_latest_entry(author, &LOG_ID).await?)
    }

    async fn operations(&self) -> Result<Vec<Operation<MootholdExt>>, MootholdStoreError> {
        let logs: BTreeMap<VerifyingKey, Vec<u64>> =
            self.store.resolve(&Topic::from(self.id.0)).await?;
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn founder(seed: u8) -> ([u8; 32], [u8; 32]) {
        let seed = [seed; 32];
        let author = *SigningKey::from_bytes(&seed).verifying_key().as_bytes();
        (seed, author)
    }

    #[tokio::test]
    async fn founder_builds_and_reopens_the_aggregate() {
        let id = MootholdId([8; 32]);
        let (seed, author) = founder(1);
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("holding.redb");
        let store = MootholdStore::open(&path, id, author).unwrap();
        store
            .author_foundation(
                seed,
                "river towns".into(),
                MootId([1; 32]),
                MemberTerms::new(10_000, 10).unwrap(),
                CompositionPolicy::CautiousImport,
                1,
            )
            .await
            .unwrap();
        store
            .admit_moot(
                seed,
                MootId([2; 32]),
                MemberTerms::new(5_000, 20).unwrap(),
                2,
            )
            .await
            .unwrap();
        drop(store);

        let reopened = MootholdStore::open(&path, id, author).unwrap();
        let state = reopened.aggregate().await.unwrap().unwrap();
        assert_eq!(state.name, "river towns");
        assert_eq!(state.members.len(), 2);
        assert_eq!(state.members[&MootId([2; 32])].reciprocity_tolerance, 20);
    }

    #[tokio::test]
    async fn non_founder_cannot_author_a_change() {
        let id = MootholdId([8; 32]);
        let (seed, author) = founder(1);
        let store = MootholdStore::in_memory(id, author);
        store
            .author_foundation(
                seed,
                "river towns".into(),
                MootId([1; 32]),
                MemberTerms::new(10_000, 10).unwrap(),
                CompositionPolicy::Insular,
                1,
            )
            .await
            .unwrap();
        let error = store
            .remove_moot([2; 32], MootId([1; 32]), 2)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            MootholdStoreError::Moothold(MootholdError::Unauthorized)
        ));
    }
}
