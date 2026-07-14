//! Muniment-backed constitution operation store.

use std::collections::BTreeMap;
use std::path::Path;

use muniment::{Backend, MemoryBackend, RedbBackend, StoreError};
use murm_replication::{
    Admission, MunimentStore, OperationPolicy, OperationProcessor, ProcessError, Reject,
    StoreTarget,
};
use p2panda_core::{Operation, SigningKey, Topic, VerifyingKey};
use p2panda_store::logs::LogStore;
use p2panda_store::topics::TopicStore;
use proofs::Digest;

use super::wire::{ConstitutionExt, from_operation};
use super::{
    Constitution, ConstitutionError, ConstitutionEvent, ConstitutionRules, GovernedAction,
    authorize_governed, to_operation_seed,
};

const LOG_ID: u64 = 0;

/// Constitution store or governance rejection.
#[derive(Debug, thiserror::Error)]
pub enum ConstitutionStoreError {
    /// Shared backend failure.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Shared processor rejection.
    #[error(transparent)]
    Process(#[from] ProcessError),
    /// Signed event was malformed or invalid under the current fold.
    #[error(transparent)]
    Constitution(#[from] ConstitutionError),
    /// The Moot has not accepted genesis.
    #[error("constitution is not founded")]
    NotFounded,
}

#[derive(Clone, Copy)]
struct ConstitutionPolicy {
    moot_id: [u8; 32],
    founder: [u8; 32],
}

impl OperationPolicy<ConstitutionExt> for ConstitutionPolicy {
    type LogId = u64;

    fn admit(
        &self,
        operation: &Operation<ConstitutionExt>,
    ) -> Result<Admission<Self::LogId>, Reject> {
        if operation.header.extensions.moot_id != self.moot_id {
            return Err(Reject::new(
                "wrong-moot",
                "constitution operation addresses another moot",
            ));
        }
        let event = from_operation(operation).map_err(|_| {
            Reject::new(
                "invalid-constitution-event",
                "operation body is not a constitution event",
            )
        })?;
        if !event.rules_are_bound() {
            return Err(Reject::new(
                "invalid-rules-digest",
                "constitution rules do not match their digest",
            ));
        }
        let author = *operation.header.verifying_key.as_bytes();
        match event {
            ConstitutionEvent::Genesis {
                moot_id, founder, ..
            } if moot_id == self.moot_id && founder == self.founder && author == self.founder => {}
            ConstitutionEvent::Amended { .. } if author == self.founder => {}
            ConstitutionEvent::Genesis { .. } => {
                return Err(Reject::new(
                    "wrong-founder",
                    "genesis does not bind the Moot founder",
                ));
            }
            ConstitutionEvent::Amended { .. } => {
                return Err(Reject::new(
                    "unauthorized-amendment",
                    "actor is not authorized by the founder-signed rule",
                ));
            }
        }
        Ok(Admission::keep(StoreTarget::new(
            Topic::from(self.moot_id),
            LOG_ID,
        )))
    }
}

/// One Moot's constitution log over a shared backend.
#[derive(Clone)]
pub struct ConstitutionStore<B> {
    moot_id: [u8; 32],
    founder: [u8; 32],
    store: MunimentStore<B, ConstitutionExt>,
}

/// Durable redb constitution store.
pub type ConstitutionFileStore = ConstitutionStore<RedbBackend>;

impl ConstitutionStore<MemoryBackend> {
    /// Create an ephemeral store rooted in the Moot declaration's founder.
    pub fn in_memory(moot_id: [u8; 32], founder: [u8; 32]) -> Self {
        Self {
            moot_id,
            founder,
            store: MunimentStore::new(MemoryBackend::new()),
        }
    }
}

impl ConstitutionStore<RedbBackend> {
    /// Open durable constitutional state for one declared Moot.
    pub fn open(
        path: impl AsRef<Path>,
        moot_id: [u8; 32],
        founder: [u8; 32],
    ) -> Result<Self, ConstitutionStoreError> {
        Ok(Self {
            moot_id,
            founder,
            store: MunimentStore::new(RedbBackend::open(path)?),
        })
    }
}

impl<B: Backend + Clone> ConstitutionStore<B> {
    /// Shared LogSync store surface.
    pub fn sync_store(&self) -> MunimentStore<B, ConstitutionExt> {
        self.store.clone()
    }

    /// Admit a signed operation after governance preflight.
    pub async fn accept(
        &self,
        operation: &Operation<ConstitutionExt>,
    ) -> Result<bool, ConstitutionStoreError> {
        if self.store.has_operation(&operation.hash).await? {
            return Ok(false);
        }
        let event = from_operation(operation).map_err(|_| ConstitutionError::Malformed)?;
        let current = self.constitution().await?;
        match (&current, &event) {
            (None, ConstitutionEvent::Genesis { .. }) => {}
            (None, ConstitutionEvent::Amended { .. }) => {
                return Err(ConstitutionStoreError::NotFounded);
            }
            (Some(_), ConstitutionEvent::Genesis { .. }) => {
                return Err(ConstitutionError::AlreadyFounded.into());
            }
            (Some(state), ConstitutionEvent::Amended { previous, .. }) => {
                if *previous != state.revision {
                    return Err(ConstitutionError::StaleRevision.into());
                }
                let actor = *operation.header.verifying_key.as_bytes();
                if !authorize_governed(GovernedAction::AmendConstitution, actor, state) {
                    return Err(ConstitutionError::Unauthorized.into());
                }
            }
        }
        let processor = OperationProcessor::new(
            self.store.clone(),
            ConstitutionPolicy {
                moot_id: self.moot_id,
                founder: self.founder,
            },
        );
        Ok(processor.process(operation).await?.inserted())
    }

    /// Fold every retained operation into the accepted current law.
    pub async fn constitution(&self) -> Result<Option<Constitution>, ConstitutionStoreError> {
        let operations = self.operations().await?;
        Ok(Constitution::fold(
            self.moot_id,
            self.founder,
            operations.iter(),
        ))
    }

    /// Author genesis with the configured founder key.
    pub async fn author_genesis(
        &self,
        signing_seed: [u8; 32],
        parent_constitution: Option<Digest>,
        divergence_point: Option<Digest>,
        rules: ConstitutionRules,
        at_ms: u64,
    ) -> Result<Operation<ConstitutionExt>, ConstitutionStoreError> {
        if self.constitution().await?.is_some() {
            return Err(ConstitutionError::AlreadyFounded.into());
        }
        let author = *SigningKey::from_bytes(&signing_seed)
            .verifying_key()
            .as_bytes();
        if author != self.founder {
            return Err(ConstitutionError::Unauthorized.into());
        }
        let event = ConstitutionEvent::genesis(
            self.moot_id,
            self.founder,
            parent_constitution,
            divergence_point,
            rules,
            at_ms,
        );
        self.author_event(signing_seed, &event).await
    }

    /// Author the next amendment under the prior accepted rule.
    pub async fn author_amendment(
        &self,
        signing_seed: [u8; 32],
        rules: ConstitutionRules,
        at_ms: u64,
    ) -> Result<Operation<ConstitutionExt>, ConstitutionStoreError> {
        let state = self
            .constitution()
            .await?
            .ok_or(ConstitutionStoreError::NotFounded)?;
        let actor = *SigningKey::from_bytes(&signing_seed)
            .verifying_key()
            .as_bytes();
        if !authorize_governed(GovernedAction::AmendConstitution, actor, &state) {
            return Err(ConstitutionError::Unauthorized.into());
        }
        let event = ConstitutionEvent::amended(state.revision, rules, at_ms);
        self.author_event(signing_seed, &event).await
    }

    async fn author_event(
        &self,
        signing_seed: [u8; 32],
        event: &ConstitutionEvent,
    ) -> Result<Operation<ConstitutionExt>, ConstitutionStoreError> {
        let author = SigningKey::from_bytes(&signing_seed).verifying_key();
        let (seq_num, backlink) = match self.latest(&author).await? {
            Some(previous) => (previous.header.seq_num + 1, Some(*previous.hash.as_bytes())),
            None => (0, None),
        };
        let operation = to_operation_seed(signing_seed, self.moot_id, event, seq_num, backlink);
        self.accept(&operation).await?;
        Ok(operation)
    }

    async fn latest(
        &self,
        author: &VerifyingKey,
    ) -> Result<Option<Operation<ConstitutionExt>>, ConstitutionStoreError> {
        Ok(self.store.get_latest_entry(author, &LOG_ID).await?)
    }

    async fn operations(&self) -> Result<Vec<Operation<ConstitutionExt>>, ConstitutionStoreError> {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::moot::GovernedCheckpointAuthority;
    use identity::{IdentityProvider, InMemoryProvider};
    use murm_replication::CheckpointAuthority;

    const MOOT: [u8; 32] = [0x63; 32];

    fn keypair(seed: u8) -> identity::Ed25519Keypair {
        InMemoryProvider::from_seed([seed; 32])
            .derive_keypair(b"constitution-store")
            .unwrap()
    }

    #[tokio::test]
    async fn founder_amends_and_two_stores_converge() {
        let founder = keypair(1);
        let founder_id = founder.public_key().to_bytes();
        let first = ConstitutionStore::in_memory(MOOT, founder_id);
        let genesis = first
            .author_genesis(
                founder.to_seed(),
                None,
                None,
                ConstitutionRules::founder_only(founder_id),
                1,
            )
            .await
            .unwrap();
        let mut next_rules = ConstitutionRules::founder_only(founder_id);
        next_rules.checkpoint_signers.insert([9; 32]);
        let amendment = first
            .author_amendment(founder.to_seed(), next_rules.clone(), 2)
            .await
            .unwrap();

        let second = ConstitutionStore::in_memory(MOOT, founder_id);
        second.accept(&genesis).await.unwrap();
        second.accept(&amendment).await.unwrap();
        let first_state = first.constitution().await.unwrap().unwrap();
        let second_state = second.constitution().await.unwrap().unwrap();
        assert_eq!(first_state, second_state);
        assert_eq!(first_state.rules, next_rules);

        let authority = GovernedCheckpointAuthority::from_state(&first_state);
        assert!(authority.permits_checkpoint([9; 32], &first_state.revision));
        assert!(!authority.permits_checkpoint([8; 32], &first_state.revision));
    }

    #[tokio::test]
    async fn non_founder_amendment_is_rejected_before_mutation() {
        let founder = keypair(1);
        let intruder = keypair(2);
        let founder_id = founder.public_key().to_bytes();
        let store = ConstitutionStore::in_memory(MOOT, founder_id);
        store
            .author_genesis(
                founder.to_seed(),
                None,
                None,
                ConstitutionRules::founder_only(founder_id),
                1,
            )
            .await
            .unwrap();
        let state = store.constitution().await.unwrap().unwrap();
        let event = ConstitutionEvent::amended(
            state.revision.clone(),
            ConstitutionRules::founder_only(founder_id),
            2,
        );
        let operation = to_operation_seed(intruder.to_seed(), MOOT, &event, 0, None);
        assert!(store.accept(&operation).await.is_err());
        assert_eq!(store.constitution().await.unwrap().unwrap(), state);
    }
}
