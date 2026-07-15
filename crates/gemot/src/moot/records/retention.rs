//! Constitution-fed retention checkpoints for a Moot.
//!
//! The constitution decides who may checkpoint. A separately governed
//! retention policy decides what the checkpoint may retire. The checkpoint
//! binds a compact roster snapshot and monotone event-log frontiers, so a late
//! peer can rebuild current state without retaining the discarded prefix.

use std::collections::{BTreeMap, BTreeSet};

use murm_replication::CheckpointAuthority;
use p2panda_core::cbor::encode_cbor;
use proofs::{BlobRef, Commitment, CommitmentDomain, Digest};
use serde::{Deserialize, Serialize};

use crate::moot::constitution::Constitution;

use super::roster::MootRoster;
use super::wire::MootLogId;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovernedCheckpointAuthority {
    authority_revision: Digest,
    signers: BTreeSet<[u8; 32]>,
}

impl GovernedCheckpointAuthority {
    pub fn from_constitution(
        authority_revision: Digest,
        signers: impl IntoIterator<Item = [u8; 32]>,
    ) -> Self {
        Self {
            authority_revision,
            signers: signers.into_iter().collect(),
        }
    }

    /// Resolve checkpoint authority from one accepted constitution fold.
    pub fn from_state(constitution: &Constitution) -> Self {
        Self::from_constitution(
            constitution.revision.clone(),
            constitution.rules.checkpoint_signers.iter().copied(),
        )
    }

    pub fn signers(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.signers.iter()
    }
}

impl CheckpointAuthority for GovernedCheckpointAuthority {
    fn authority_revision(&self) -> Digest {
        self.authority_revision.clone()
    }

    fn permits_checkpoint(&self, author: [u8; 32], named_revision: &Digest) -> bool {
        *named_revision == self.authority_revision && self.signers.contains(&author)
    }
}

/// A configured duration or logical retention boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeepBound {
    Forever,
    ForAgeMs(u64),
    UntilCheckpoint,
}

/// Hosting promise, kept distinct from permission to erase.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvailabilityPolicy {
    pub promised_floor: KeepBound,
}

/// Privacy-driven permission to retire replicated history.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErasurePolicy {
    pub history_ceiling: KeepBound,
}

/// Identity of the governed retention settings used for a checkpoint.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PolicyRevision(pub Digest);

/// Highest operation represented for one author/log pair.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogFrontier {
    pub author: [u8; 32],
    pub log_id: MootLogId,
    pub seq_num: u64,
    pub operation: [u8; 32],
}

/// Compact roster state retained when the event prefix is removed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MootRosterSnapshot {
    pub roster: MootRoster,
}

impl MootRosterSnapshot {
    pub fn from_roster(roster: &MootRoster) -> Self {
        Self {
            roster: roster.clone(),
        }
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        encode_cbor(self).expect("a MootRosterSnapshot always CBOR-encodes")
    }
}

/// Moot-specific retention checkpoint carried in a signed event body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionCheckpoint {
    pub version: u16,
    pub moot_id: [u8; 32],
    pub policy_revision: PolicyRevision,
    pub authority_revision: Digest,
    /// Previously accepted checkpoint operation. This gives authority
    /// rotation one causal chain across different signers' checkpoint logs.
    #[serde(default)]
    pub previous_checkpoint: Option<[u8; 32]>,
    pub frontier: Vec<LogFrontier>,
    pub snapshot: MootRosterSnapshot,
    pub snapshot_ref: BlobRef,
    pub snapshot_commitment: Commitment,
    pub at_ms: u64,
}

impl RetentionCheckpoint {
    pub fn new(
        moot_id: [u8; 32],
        policy_revision: PolicyRevision,
        authority_revision: Digest,
        previous_checkpoint: Option<[u8; 32]>,
        frontier: Vec<LogFrontier>,
        snapshot: MootRosterSnapshot,
        at_ms: u64,
    ) -> Self {
        let snapshot_bytes = snapshot.canonical_bytes();
        let snapshot_ref = BlobRef::blake3(&snapshot_bytes);
        let snapshot_commitment =
            Commitment::direct(CommitmentDomain::StorageCheckpoints, &snapshot_bytes);
        Self {
            version: 1,
            moot_id,
            policy_revision,
            authority_revision,
            previous_checkpoint,
            frontier,
            snapshot,
            snapshot_ref,
            snapshot_commitment,
            at_ms,
        }
    }

    /// Recheck an already-admitted checkpoint without applying today's
    /// authority to historical state. A constitution rotation must not
    /// invalidate a checkpoint accepted under its named revision.
    pub fn validate_retained(
        &self,
        expected_moot: [u8; 32],
        current: Option<([u8; 32], &RetentionCheckpoint)>,
    ) -> Result<(), CheckpointError> {
        if self.version != 1 {
            return Err(CheckpointError::UnsupportedVersion(self.version));
        }
        if self.moot_id != expected_moot {
            return Err(CheckpointError::ForeignMoot);
        }
        if self.previous_checkpoint != current.map(|(operation, _)| operation) {
            return Err(CheckpointError::StaleCheckpoint);
        }
        let snapshot_bytes = self.snapshot.canonical_bytes();
        if !self.snapshot_ref.verifies(&snapshot_bytes) {
            return Err(CheckpointError::FalseSnapshotReference);
        }
        if !self
            .snapshot_commitment
            .verifies_direct(CommitmentDomain::StorageCheckpoints, &snapshot_bytes)
        {
            return Err(CheckpointError::FalseSnapshotCommitment);
        }
        validate_frontier(current.map(|(_, checkpoint)| checkpoint), &self.frontier)
    }
}

/// Retention settings plus authority resolved from the accepted constitution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MootRetentionPolicy {
    pub revision: PolicyRevision,
    /// The authority used for fresh local checkpoints.
    pub checkpoint_authority: GovernedCheckpointAuthority,
    /// Earlier accepted constitutional authorities. These are retained for
    /// self-contained drop verification only; fresh checkpoints still name the
    /// current authority above.
    pub checkpoint_authority_history: Vec<GovernedCheckpointAuthority>,
    pub availability: AvailabilityPolicy,
    pub erasure: ErasurePolicy,
}

impl MootRetentionPolicy {
    fn authority_for(
        &self,
        revision: &Digest,
        include_history: bool,
    ) -> Option<&GovernedCheckpointAuthority> {
        if self.checkpoint_authority.authority_revision() == *revision {
            return Some(&self.checkpoint_authority);
        }
        if !include_history {
            return None;
        }
        self.checkpoint_authority_history
            .iter()
            .find(|authority| authority.authority_revision() == *revision)
    }

    pub fn validate_checkpoint(
        &self,
        expected_moot: [u8; 32],
        author: [u8; 32],
        current: Option<([u8; 32], &RetentionCheckpoint)>,
        candidate: &RetentionCheckpoint,
    ) -> Result<(), CheckpointError> {
        self.validate_checkpoint_with_authority_history(
            expected_moot,
            author,
            current,
            candidate,
            false,
        )
    }

    /// Validate a retained checkpoint while importing a carrier that supplied
    /// the complete constitution history. This is deliberately crate-private:
    /// historical authority proves past checkpoints, never authorizes a fresh
    /// local checkpoint after a rotation.
    pub(crate) fn validate_checkpoint_from_history(
        &self,
        expected_moot: [u8; 32],
        author: [u8; 32],
        current: Option<([u8; 32], &RetentionCheckpoint)>,
        candidate: &RetentionCheckpoint,
    ) -> Result<(), CheckpointError> {
        self.validate_checkpoint_with_authority_history(
            expected_moot,
            author,
            current,
            candidate,
            true,
        )
    }

    fn validate_checkpoint_with_authority_history(
        &self,
        expected_moot: [u8; 32],
        author: [u8; 32],
        current: Option<([u8; 32], &RetentionCheckpoint)>,
        candidate: &RetentionCheckpoint,
        include_history: bool,
    ) -> Result<(), CheckpointError> {
        let authority = self
            .authority_for(&candidate.authority_revision, include_history)
            .ok_or(CheckpointError::UnauthorizedAuthority)?;
        let signer_count = authority.signers().count();
        if signer_count != 1 {
            return Err(CheckpointError::UnsupportedAuthoritySet(signer_count));
        }
        candidate.validate_retained(expected_moot, current)?;
        if !authority.permits_checkpoint(author, &candidate.authority_revision) {
            return Err(CheckpointError::UnauthorizedAuthority);
        }
        if candidate.policy_revision != self.revision {
            return Err(CheckpointError::StalePolicy);
        }
        Ok(())
    }
}

fn validate_frontier(
    current: Option<&RetentionCheckpoint>,
    candidate: &[LogFrontier],
) -> Result<(), CheckpointError> {
    let mut next = BTreeMap::new();
    for entry in candidate {
        let key = (entry.author, entry.log_id);
        if next.insert(key, entry).is_some() {
            return Err(CheckpointError::DuplicateFrontier);
        }
    }
    let Some(current) = current else {
        return Ok(());
    };
    for previous in &current.frontier {
        let Some(candidate) = next.get(&(previous.author, previous.log_id)) else {
            return Err(CheckpointError::FrontierRewind);
        };
        if candidate.seq_num < previous.seq_num
            || (candidate.seq_num == previous.seq_num && candidate.operation != previous.operation)
        {
            return Err(CheckpointError::FrontierRewind);
        }
    }
    Ok(())
}

/// Why a checkpoint was refused before store mutation.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CheckpointError {
    #[error("checkpoint v1 requires exactly one active signer, found {0}")]
    UnsupportedAuthoritySet(usize),
    #[error("unsupported checkpoint version {0}")]
    UnsupportedVersion(u16),
    #[error("checkpoint addresses another moot")]
    ForeignMoot,
    #[error("checkpoint author is not authorized by the named constitution")]
    UnauthorizedAuthority,
    #[error("checkpoint names a stale retention policy revision")]
    StalePolicy,
    #[error("checkpoint does not advance the latest accepted checkpoint")]
    StaleCheckpoint,
    #[error("checkpoint snapshot blob reference is false")]
    FalseSnapshotReference,
    #[error("checkpoint snapshot commitment is false")]
    FalseSnapshotCommitment,
    #[error("checkpoint frontier contains a duplicate author/log")]
    DuplicateFrontier,
    #[error("checkpoint frontier would rewind accepted history")]
    FrontierRewind,
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOOT: [u8; 32] = [0x6d; 32];

    fn policy() -> MootRetentionPolicy {
        let revision = Digest::blake3(b"accepted constitution revision");
        MootRetentionPolicy {
            revision: PolicyRevision(Digest::blake3(b"retention settings")),
            checkpoint_authority: GovernedCheckpointAuthority::from_constitution(
                revision,
                [[1; 32]],
            ),
            checkpoint_authority_history: Vec::new(),
            availability: AvailabilityPolicy {
                promised_floor: KeepBound::Forever,
            },
            erasure: ErasurePolicy {
                history_ceiling: KeepBound::UntilCheckpoint,
            },
        }
    }

    fn frontier(seq_num: u64, operation: u8) -> LogFrontier {
        LogFrontier {
            author: [3; 32],
            log_id: MootLogId::Events,
            seq_num,
            operation: [operation; 32],
        }
    }

    fn checkpoint(frontier: Vec<LogFrontier>) -> RetentionCheckpoint {
        let policy = policy();
        RetentionCheckpoint::new(
            MOOT,
            policy.revision.clone(),
            policy.checkpoint_authority.authority_revision(),
            None,
            frontier,
            MootRosterSnapshot::default(),
            10,
        )
    }

    #[test]
    fn only_constitution_supplied_signers_share_the_named_revision() {
        let revision = Digest::blake3(b"accepted constitution revision");
        let authority = GovernedCheckpointAuthority::from_constitution(revision.clone(), [[1; 32]]);
        assert!(authority.permits_checkpoint([1; 32], &revision));
        assert!(!authority.permits_checkpoint([2; 32], &revision));
        assert!(!authority.permits_checkpoint([1; 32], &Digest::blake3(b"older revision")));
    }

    #[test]
    fn checkpoint_binds_policy_authority_and_snapshot() {
        let policy = policy();
        let valid = checkpoint(vec![frontier(2, 2)]);
        assert!(
            policy
                .validate_checkpoint(MOOT, [1; 32], None, &valid)
                .is_ok()
        );

        let mut false_snapshot = valid.clone();
        false_snapshot.snapshot_ref.digest.bytes[0] ^= 1;
        assert_eq!(
            policy.validate_checkpoint(MOOT, [1; 32], None, &false_snapshot),
            Err(CheckpointError::FalseSnapshotReference)
        );
        assert_eq!(
            policy.validate_checkpoint(MOOT, [2; 32], None, &valid),
            Err(CheckpointError::UnauthorizedAuthority)
        );

        let mut ambiguous = policy.clone();
        ambiguous.checkpoint_authority = GovernedCheckpointAuthority::from_constitution(
            ambiguous.checkpoint_authority.authority_revision(),
            [[1; 32], [2; 32]],
        );
        assert_eq!(
            ambiguous.validate_checkpoint(MOOT, [1; 32], None, &valid),
            Err(CheckpointError::UnsupportedAuthoritySet(2))
        );
    }

    #[test]
    fn accepted_frontier_never_rewinds() {
        let policy = policy();
        let current = checkpoint(vec![frontier(4, 4)]);
        let mut rewound = checkpoint(vec![frontier(3, 3)]);
        rewound.previous_checkpoint = Some([0xc4; 32]);
        assert_eq!(
            policy.validate_checkpoint(MOOT, [1; 32], Some(([0xc4; 32], &current)), &rewound),
            Err(CheckpointError::FrontierRewind)
        );
        let mut advanced = checkpoint(vec![frontier(5, 5)]);
        advanced.previous_checkpoint = Some([0xc4; 32]);
        assert!(
            policy
                .validate_checkpoint(MOOT, [1; 32], Some(([0xc4; 32], &current)), &advanced)
                .is_ok()
        );
    }
}
