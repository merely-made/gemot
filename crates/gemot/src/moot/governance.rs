//! High-level constitutional governance for one Moot.
//!
//! This is the consumer boundary above the signed constitution log. Commands
//! take identity seeds and rule values; reads return plain snapshots. Network
//! adapters continue to replicate the underlying [`ConstitutionStore`] without
//! making p2panda operations part of the application API.

use std::path::Path;

use muniment::{Backend, MemoryBackend, RedbBackend};
use murm_replication::CheckpointAuthority;
use proofs::Digest;

use crate::constitution::{
    Constitution, ConstitutionRules, ConstitutionStore, ConstitutionStoreError,
};

use super::GovernedCheckpointAuthority;

/// Readable accepted constitutional state for one Moot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MootGovernanceSnapshot {
    /// Governed Moot.
    pub moot_id: [u8; 32],
    /// Governance root established by genesis.
    pub founder: [u8; 32],
    /// Parent constitution for a deliberate fork.
    pub parent_constitution: Option<Digest>,
    /// Parent revision where that fork diverged.
    pub divergence_point: Option<Digest>,
    /// Current accepted clauses.
    pub rules: ConstitutionRules,
    /// Signed operation identity of the accepted revision.
    pub revision: Digest,
}

impl From<Constitution> for MootGovernanceSnapshot {
    fn from(constitution: Constitution) -> Self {
        Self {
            moot_id: constitution.moot_id,
            founder: constitution.founder,
            parent_constitution: constitution.parent_constitution,
            divergence_point: constitution.divergence_point,
            rules: constitution.rules,
            revision: constitution.revision,
        }
    }
}

/// Failure of a high-level governance command.
#[derive(Debug, thiserror::Error)]
pub enum MootGovernanceError {
    /// Constitution storage, validation, or authorization failed.
    #[error(transparent)]
    Constitution(#[from] ConstitutionStoreError),
    /// The Moot has not accepted a founding constitution.
    #[error("moot governance is not founded")]
    NotFounded,
    /// The named constitution does not authorize this checkpoint signer.
    #[error("checkpoint is not authorized by the named constitution revision")]
    CheckpointDenied,
}

/// Constitutional command and query service for one Moot.
#[derive(Clone)]
pub struct MootGovernance<B> {
    store: ConstitutionStore<B>,
}

/// Durable redb-backed Moot governance service.
pub type MootGovernanceFile = MootGovernance<RedbBackend>;

impl MootGovernance<MemoryBackend> {
    /// Create ephemeral governance rooted in the declared founder.
    pub fn in_memory(moot_id: [u8; 32], founder: [u8; 32]) -> Self {
        Self {
            store: ConstitutionStore::in_memory(moot_id, founder),
        }
    }
}

impl MootGovernance<RedbBackend> {
    /// Open durable governance rooted in the declared founder.
    pub fn open(
        path: impl AsRef<Path>,
        moot_id: [u8; 32],
        founder: [u8; 32],
    ) -> Result<Self, MootGovernanceError> {
        Ok(Self {
            store: ConstitutionStore::open(path, moot_id, founder)?,
        })
    }
}

impl<B: Backend + Clone> MootGovernance<B> {
    /// Establish the first accepted constitution.
    pub async fn found(
        &self,
        founder_seed: [u8; 32],
        parent_constitution: Option<Digest>,
        divergence_point: Option<Digest>,
        rules: ConstitutionRules,
        at_ms: u64,
    ) -> Result<MootGovernanceSnapshot, MootGovernanceError> {
        self.store
            .author_genesis(
                founder_seed,
                parent_constitution,
                divergence_point,
                rules,
                at_ms,
            )
            .await?;
        self.snapshot().await
    }

    /// Replace the current clauses under the prior amendment rule.
    pub async fn amend(
        &self,
        actor_seed: [u8; 32],
        rules: ConstitutionRules,
        at_ms: u64,
    ) -> Result<MootGovernanceSnapshot, MootGovernanceError> {
        self.store
            .author_amendment(actor_seed, rules, at_ms)
            .await?;
        self.snapshot().await
    }

    /// Read the accepted constitutional state.
    pub async fn snapshot(&self) -> Result<MootGovernanceSnapshot, MootGovernanceError> {
        self.store
            .constitution()
            .await?
            .map(MootGovernanceSnapshot::from)
            .ok_or(MootGovernanceError::NotFounded)
    }

    /// Resolve checkpoint authority from the accepted constitution.
    pub async fn checkpoint_authority(
        &self,
    ) -> Result<GovernedCheckpointAuthority, MootGovernanceError> {
        let state = self
            .store
            .constitution()
            .await?
            .ok_or(MootGovernanceError::NotFounded)?;
        Ok(GovernedCheckpointAuthority::from_state(&state))
    }

    /// Require the accepted revision to authorize one checkpoint signer.
    pub async fn authorize_checkpoint(
        &self,
        signer: [u8; 32],
        named_revision: &Digest,
    ) -> Result<(), MootGovernanceError> {
        let authority = self.checkpoint_authority().await?;
        if authority.permits_checkpoint(signer, named_revision) {
            Ok(())
        } else {
            Err(MootGovernanceError::CheckpointDenied)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use identity::{IdentityProvider, InMemoryProvider};
    use tempfile::tempdir;

    const MOOT: [u8; 32] = [0x65; 32];

    fn founder() -> identity::Ed25519Keypair {
        InMemoryProvider::from_seed([90; 32])
            .derive_keypair(b"moot-governance")
            .unwrap()
    }

    #[tokio::test]
    async fn commands_return_plain_snapshots_and_govern_checkpoints() {
        let founder = founder();
        let founder_id = founder.public_key().to_bytes();
        let governance = MootGovernance::in_memory(MOOT, founder_id);
        let founded = governance
            .found(
                founder.to_seed(),
                None,
                None,
                ConstitutionRules::founder_only(founder_id),
                1,
            )
            .await
            .unwrap();

        let mut amended = ConstitutionRules::founder_only(founder_id);
        amended.checkpoint_signers.insert([9; 32]);
        let snapshot = governance
            .amend(founder.to_seed(), amended.clone(), 2)
            .await
            .unwrap();
        assert_ne!(snapshot.revision, founded.revision);
        assert_eq!(snapshot.rules, amended);
        governance
            .authorize_checkpoint([9; 32], &snapshot.revision)
            .await
            .unwrap();
        assert!(
            governance
                .authorize_checkpoint([8; 32], &snapshot.revision)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn durable_service_reopens_the_accepted_snapshot() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("constitution.redb");
        let founder = founder();
        let founder_id = founder.public_key().to_bytes();
        let governance = MootGovernance::open(&path, MOOT, founder_id).unwrap();
        let expected = governance
            .found(
                founder.to_seed(),
                None,
                None,
                ConstitutionRules::founder_only(founder_id),
                1,
            )
            .await
            .unwrap();
        drop(governance);

        let reopened = MootGovernance::open(path, MOOT, founder_id).unwrap();
        assert_eq!(reopened.snapshot().await.unwrap(), expected);
    }
}
