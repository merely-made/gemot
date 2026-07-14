//! Constitution-fed checkpoint authority for a Moot.
//!
//! This type deliberately accepts an already-resolved authority revision and
//! signer set. The future constitution fold owns producing those values;
//! visible roster membership and transport access do not grant this power.

use std::collections::BTreeSet;

use murm_replication::CheckpointAuthority;
use proofs::Digest;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_constitution_supplied_signers_share_the_named_revision() {
        let revision = Digest::blake3(b"accepted constitution revision");
        let authority = GovernedCheckpointAuthority::from_constitution(revision.clone(), [[1; 32]]);
        assert!(authority.permits_checkpoint([1; 32], &revision));
        assert!(!authority.permits_checkpoint([2; 32], &revision));
        assert!(!authority.permits_checkpoint([1; 32], &Digest::blake3(b"older revision")));
    }
}
