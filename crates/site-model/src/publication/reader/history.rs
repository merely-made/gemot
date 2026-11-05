// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Gemot adapter for remembered reader authority (the optional solo-Moot path).
//! Persist full Gemot evidence, including changes that make a page
//! unreadable. The shared store in [`crate::remembered`] provides atomic
//! comparison, the clock high-water mark and the capacity bound.

use gemot::moot::{Moot, MootId, MootRetentionSettings};
use muniment::{Backend, StoreError};
use stickleback::DropExportProfile;

use super::{ReaderLimits, ReaderTrust, VerifiedPublication, verify_reader_evidence};
use crate::publication::PublicationError;
pub use crate::remembered::ReaderObservation;
use crate::remembered::{Authority, EvidenceScope, Remembered, RememberedError};

#[derive(Debug)]
pub enum ReaderHistoryError {
    Storage(StoreError),
    Verification(PublicationError),
    InvalidState(String),
    Capacity,
    ClockRollback,
    ConcurrentChange,
}

impl std::fmt::Display for ReaderHistoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(e) => e.fmt(f),
            Self::Verification(e) => e.fmt(f),
            Self::InvalidState(e) => write!(f, "Invalid remembered reader authority: {e}"),
            Self::Capacity => f.write_str("Reader authority history exceeds capacity"),
            Self::ClockRollback => {
                f.write_str("Reader evaluation time precedes remembered observation")
            },
            Self::ConcurrentChange => {
                f.write_str("Reader authority changed; retry with remembered state")
            },
        }
    }
}
impl std::error::Error for ReaderHistoryError {}
impl From<StoreError> for ReaderHistoryError {
    fn from(e: StoreError) -> Self {
        Self::Storage(e)
    }
}
impl From<PublicationError> for ReaderHistoryError {
    fn from(e: PublicationError) -> Self {
        Self::Verification(e)
    }
}
impl From<gemot::moot::MootError> for ReaderHistoryError {
    fn from(e: gemot::moot::MootError) -> Self {
        PublicationError::from(e).into()
    }
}

impl From<RememberedError<PublicationError>> for ReaderHistoryError {
    fn from(e: RememberedError<PublicationError>) -> Self {
        match e {
            RememberedError::Storage(e) => Self::Storage(e),
            RememberedError::Authority(e) => Self::Verification(e),
            RememberedError::InvalidState(e) => Self::InvalidState(e),
            RememberedError::Capacity => Self::Capacity,
            RememberedError::ClockRollback => Self::ClockRollback,
            RememberedError::ConcurrentChange => Self::ConcurrentChange,
        }
    }
}

struct GemotAuthority {
    trust: ReaderTrust,
    retention: MootRetentionSettings,
    limits: ReaderLimits,
}

impl Authority for GemotAuthority {
    type Anchor = ReaderTrust;
    type Error = PublicationError;
    const NAMESPACE: &'static str = "site-reader/v1";
    const EVIDENCE_NAME: &'static str = "history.drop";

    fn anchor(&self) -> &ReaderTrust {
        &self.trust
    }

    fn max_evidence_bytes(&self) -> usize {
        self.limits.max_history_bytes
    }

    async fn merge(
        &self,
        remembered: Option<&[u8]>,
        supplied: &[u8],
    ) -> Result<Vec<u8>, PublicationError> {
        let moot = Moot::in_memory(
            MootId(self.trust.collection.moot_id),
            self.trust.founder,
            self.retention.clone(),
        );
        if let Some(remembered) = remembered {
            moot.import_plain_drop(remembered, self.limits.drop).await?;
        }
        // Admission can have partial effects before refusal; all effects live
        // in this disposable Moot until the complete import/export succeeds.
        moot.import_plain_drop(supplied, self.limits.drop).await?;
        let mut merged = Vec::new();
        moot.export_plain_drop(&mut merged, DropExportProfile::default(), self.limits.drop)
            .await?;
        Ok(merged)
    }
}

/// Host-owned storage and trust. Old evidence is merged, never used to
/// replace remembered authority.
pub struct ReaderHistory<B> {
    store: Remembered<B, GemotAuthority>,
}

impl<B: Backend + Sync> ReaderHistory<B> {
    pub fn new(
        backend: B,
        trust: ReaderTrust,
        retention: MootRetentionSettings,
        limits: ReaderLimits,
    ) -> Self {
        let authority = GemotAuthority {
            trust,
            retention,
            limits,
        };
        Self {
            store: Remembered::new(backend, authority),
        }
    }

    /// Admit and durably remember authority even if no page can be opened.
    /// No requested snapshot, signing key or reader membership is involved.
    pub async fn observe(
        &self,
        history: &[u8],
        at_ms: u64,
    ) -> Result<ReaderObservation, ReaderHistoryError> {
        Ok(self.store.observe(history, at_ms).await?.0)
    }

    /// Remember valid authority first, then verify content against its union.
    /// A failed page read may still commit new authority, including revocation.
    /// Never returns a page if durable observation failed. Concurrent changes
    /// before the final check require a retry. Success is a point-in-time read.
    pub async fn verify(
        &self,
        history: &[u8],
        snapshot: &[u8],
        at_ms: u64,
    ) -> Result<VerifiedPublication, ReaderHistoryError> {
        let (observation, merged) = self.store.observe(history, at_ms).await?;
        let authority = self.store.authority();
        let mut verified = verify_reader_evidence(
            &authority.trust,
            &merged,
            snapshot,
            authority.retention.clone(),
            at_ms,
            authority.limits,
        )
        .await?;
        if self.store.observation().await?.as_ref() != Some(&observation) {
            return Err(ReaderHistoryError::ConcurrentChange);
        }
        verified.scope = EvidenceScope::SuppliedAndRememberedHistory;
        Ok(verified)
    }
}
