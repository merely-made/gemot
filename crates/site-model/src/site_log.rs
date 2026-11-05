// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Site-log authority: a reader holding only an Ed25519 log key verifies a
//! chain of Stickleback editions and opens the snapshot the newest one names.
//!
//! No Gemot membership, Moot replica, carrier or provider identity is
//! involved; the key is the anchor and the log decides. Verification is
//! relative to the evidence supplied. A chain that ends early still verifies,
//! with [`EvidenceScope::SuppliedHistoryOnly`]. [`SiteLogHistory`] remembers
//! the head per key, so later reads refuse known rollback and equivocation.
//! This is the ordinary-site authority; governed sites use the Gemot adapter
//! behind the `publication` feature.

use std::fmt;

use muniment::Backend;
use serde::{Deserialize, Serialize};
use stickleback::edition::{
    ContentRef, Edition, EditionChain, EditionError, EditionKind, EditionLimits, encode_evidence,
    merge_evidence,
};

use crate::remembered::{Authority, EvidenceScope, ReaderObservation, Remembered, RememberedError};
use crate::{MAX_ENCODED_SNAPSHOT_BYTES, PublishedSnapshotV1};

/// The anchor for an ordinary site: any Ed25519 public key. It may be an
/// unassociated, associated or root key; this module does not care which.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiteLogTrust {
    pub log_key: [u8; 32],
}

/// Caller-owned bounds.
#[derive(Clone, Copy, Debug)]
pub struct SiteLogLimits {
    pub max_evidence_bytes: usize,
    pub edition: EditionLimits,
}

impl Default for SiteLogLimits {
    fn default() -> Self {
        Self {
            max_evidence_bytes: 8 * 1024 * 1024,
            edition: EditionLimits::default(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SiteLogError {
    /// The log failed verification: bad signature or body, a foreign signer,
    /// a gap, or an equivocation.
    Edition(EditionError),
    /// The newest edition does not name a site snapshot.
    NotASite,
    /// The snapshot bytes are over the limit or not canonical snapshot V1.
    Snapshot(String),
    /// The snapshot is not the one the newest known edition names and does not
    /// belong to any edition in the log.
    SnapshotMismatch,
    /// The snapshot belongs to an older edition than the newest known one.
    Rollback { head_seq: u32, snapshot_seq: u32 },
}

impl fmt::Display for SiteLogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Edition(e) => e.fmt(f),
            Self::NotASite => f.write_str("Newest edition does not name a site snapshot"),
            Self::Snapshot(e) => write!(f, "Reader snapshot refused: {e}"),
            Self::SnapshotMismatch => {
                f.write_str("Reader snapshot does not match the newest edition")
            }
            Self::Rollback {
                head_seq,
                snapshot_seq,
            } => write!(
                f,
                "Reader snapshot is edition {snapshot_seq}; the log is known to reach {head_seq}"
            ),
        }
    }
}
impl std::error::Error for SiteLogError {}

/// Failure of a remembered site-log read.
pub type SiteLogHistoryError = RememberedError<SiteLogError>;

/// A snapshot opened under a verified chain.
#[derive(Clone, Debug)]
pub struct VerifiedEdition {
    /// The newest edition the evidence showed, which named the snapshot.
    pub edition: Edition,
    /// Editions in the verified chain, counting this one.
    pub chain_len: usize,
    pub snapshot: PublishedSnapshotV1,
    pub evaluated_at_ms: u64,
    /// What history the verdict covers. Neither value proves the edition is
    /// the newest that exists.
    pub scope: EvidenceScope,
}

fn open_head(chain: &EditionChain, snapshot_bytes: &[u8]) -> Result<VerifiedEdition, SiteLogError> {
    if snapshot_bytes.len() > MAX_ENCODED_SNAPSHOT_BYTES {
        return Err(SiteLogError::Snapshot("exceeds the byte limit".into()));
    }
    let snapshot = PublishedSnapshotV1::decode(snapshot_bytes).map_err(SiteLogError::Snapshot)?;
    let digest = snapshot.digest().map_err(SiteLogError::Snapshot)?;
    let head = chain.head();
    let names = |edition: &Edition| {
        edition.body.kind == EditionKind::Site
            && matches!(edition.body.content, ContentRef::Snapshot { digest: d } if d.0 == digest)
    };
    if !names(head) {
        if head.body.kind != EditionKind::Site
            || !matches!(head.body.content, ContentRef::Snapshot { .. })
        {
            return Err(SiteLogError::NotASite);
        }
        return match chain.editions().iter().find(|e| names(e)) {
            Some(earlier) => Err(SiteLogError::Rollback {
                head_seq: head.seq_num,
                snapshot_seq: earlier.seq_num,
            }),
            None => Err(SiteLogError::SnapshotMismatch),
        };
    }
    Ok(VerifiedEdition {
        edition: head.clone(),
        chain_len: chain.editions().len(),
        snapshot,
        evaluated_at_ms: 0,
        scope: EvidenceScope::SuppliedHistoryOnly,
    })
}

/// Verify supplied evidence and snapshot bytes against a log key alone, with
/// no remembered state. Success is relative to the supplied chain.
///
/// # Errors
/// Fails on any chain, snapshot or rollback refusal in [`SiteLogError`].
pub fn verify_site_log(
    trust: &SiteLogTrust,
    evidence: &[u8],
    snapshot_bytes: &[u8],
    at_ms: u64,
    limits: SiteLogLimits,
) -> Result<VerifiedEdition, SiteLogError> {
    if evidence.len() > limits.max_evidence_bytes {
        return Err(SiteLogError::Edition(EditionError::Evidence(
            "evidence exceeds the byte limit".into(),
        )));
    }
    let chain = merge_evidence(&trust.log_key, None, evidence, limits.edition)
        .map_err(SiteLogError::Edition)?;
    let mut verified = open_head(&chain, snapshot_bytes)?;
    verified.evaluated_at_ms = at_ms;
    Ok(verified)
}

struct SiteLogAuthority {
    trust: SiteLogTrust,
    limits: SiteLogLimits,
}

impl Authority for SiteLogAuthority {
    type Anchor = SiteLogTrust;
    type Error = SiteLogError;
    const NAMESPACE: &'static str = "site-log/v1";
    const EVIDENCE_NAME: &'static str = "editions.bin";

    fn anchor(&self) -> &SiteLogTrust {
        &self.trust
    }

    fn max_evidence_bytes(&self) -> usize {
        self.limits.max_evidence_bytes
    }

    async fn merge(
        &self,
        remembered: Option<&[u8]>,
        supplied: &[u8],
    ) -> Result<Vec<u8>, SiteLogError> {
        let chain = merge_evidence(
            &self.trust.log_key,
            remembered,
            supplied,
            self.limits.edition,
        )
        .map_err(SiteLogError::Edition)?;
        Ok(encode_evidence(chain.operations()))
    }
}

/// Remembered head per log key. Older evidence merges into the remembered
/// chain, never replaces it; two editions at one position refuse as
/// equivocation, and an older snapshot refuses as rollback.
pub struct SiteLogHistory<B> {
    store: Remembered<B, SiteLogAuthority>,
}

impl<B: Backend + Sync> SiteLogHistory<B> {
    pub fn new(backend: B, trust: SiteLogTrust, limits: SiteLogLimits) -> Self {
        Self {
            store: Remembered::new(backend, SiteLogAuthority { trust, limits }),
        }
    }

    /// Verify and durably remember a chain even if no snapshot is opened.
    ///
    /// # Errors
    /// Fails on chain refusal, equivocation, clock rollback, capacity,
    /// corrupt remembered state or a concurrent change.
    pub async fn observe(
        &self,
        evidence: &[u8],
        at_ms: u64,
    ) -> Result<ReaderObservation, SiteLogHistoryError> {
        Ok(self.store.observe(evidence, at_ms).await?.0)
    }

    /// Remember the chain first, then open the snapshot against the merged
    /// head. A refused snapshot may still have advanced remembered authority.
    ///
    /// # Errors
    /// As [`observe`](Self::observe), plus snapshot refusals and rollback.
    pub async fn verify(
        &self,
        evidence: &[u8],
        snapshot_bytes: &[u8],
        at_ms: u64,
    ) -> Result<VerifiedEdition, SiteLogHistoryError> {
        let (observation, merged) = self.store.observe(evidence, at_ms).await?;
        let authority = self.store.authority();
        let chain = merge_evidence(
            &authority.trust.log_key,
            None,
            &merged,
            authority.limits.edition,
        )
        .map_err(|e| RememberedError::Authority(SiteLogError::Edition(e)))?;
        let mut verified = open_head(&chain, snapshot_bytes).map_err(RememberedError::Authority)?;
        if self.store.observation().await?.as_ref() != Some(&observation) {
            return Err(RememberedError::ConcurrentChange);
        }
        verified.evaluated_at_ms = at_ms;
        verified.scope = EvidenceScope::SuppliedAndRememberedHistory;
        Ok(verified)
    }
}
