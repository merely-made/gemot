// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Remembered authority for portable readers. Persist full Gemot evidence,
//! including changes that make a page unreadable. Atomic comparison prevents
//! concurrent observations from overwriting history they have not seen.
//! The host must preserve storage; deletion or whole-store rollback is outside
//! this adapter's protection. No newest-state or availability promise is made.

use std::sync::{Arc, Mutex};

use gemot::moot::{Moot, MootId, MootRetentionSettings};
use muniment::{Backend, StoreError, WriteOp};
use serde::{Deserialize, Serialize};
use stickleback::DropExportProfile;

use super::{
    EvidenceScope, ReaderLimits, ReaderTrust, VerifiedPublication, verify_reader_evidence,
};
use crate::publication::PublicationError;

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

/// A local observation receipt, not a publication signature or custody promise.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReaderObservation {
    pub history_digest: [u8; 32],
    pub evaluated_at_ms: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u8,
    trust: ReaderTrust,
    observation: ReaderObservation,
}

type StoredPair = (Option<Vec<u8>>, Option<Vec<u8>>);

/// Host-owned storage and trust. Constructing a handle does not initialize or
/// reset any records. Each observation requires transactional backend support.
/// Old evidence is merged, never used to replace remembered authority. Restart
/// durability follows the supplied backend; use persistent storage for that gate.
pub struct ReaderHistory<B> {
    backend: B,
    trust: ReaderTrust,
    retention: MootRetentionSettings,
    limits: ReaderLimits,
    state_key: String,
    history_key: String,
}

impl<B: Backend + Sync> ReaderHistory<B> {
    pub fn new(
        backend: B,
        trust: ReaderTrust,
        retention: MootRetentionSettings,
        limits: ReaderLimits,
    ) -> Self {
        // ReaderTrust has a fixed, derived serialization; key identity includes
        // the external root as well as the intended Moot and collection.
        let identity = blake3::hash(&serde_json::to_vec(&trust).expect("reader trust encoding"));
        let prefix = format!("site-reader/v1/{}", identity.to_hex());
        Self {
            backend,
            trust,
            retention,
            limits,
            state_key: format!("{prefix}/state.json"),
            history_key: format!("{prefix}/history.drop"),
        }
    }

    async fn load(&self) -> Result<(StoredPair, Option<State>), ReaderHistoryError> {
        let pair = Arc::new(Mutex::new(None));
        let captured = pair.clone();
        let state_key = self.state_key.clone();
        let history_key = self.history_key.clone();
        self.backend
            .transact(Box::new(move |reader| {
                *captured.lock().expect("reader snapshot lock") = Some((|| {
                    Ok::<_, StoreError>((reader.get(&state_key)?, reader.get(&history_key)?))
                })());
                vec![]
            }))
            .await?;
        let pair = pair
            .lock()
            .expect("reader snapshot lock")
            .take()
            .ok_or_else(|| ReaderHistoryError::InvalidState("transaction did not run".into()))??;
        let state = match (&pair.0, &pair.1) {
            (None, None) => None,
            (Some(metadata), Some(history)) => {
                if metadata.len() > 4096 || history.len() > self.limits.max_history_bytes {
                    return Err(ReaderHistoryError::Capacity);
                }
                let state: State = serde_json::from_slice(metadata)
                    .map_err(|e| ReaderHistoryError::InvalidState(e.to_string()))?;
                if state.version != 1
                    || state.trust != self.trust
                    || state.observation.history_digest != *blake3::hash(history).as_bytes()
                {
                    return Err(ReaderHistoryError::InvalidState(
                        "identity or evidence digest mismatch".into(),
                    ));
                }
                Some(state)
            },
            _ => {
                return Err(ReaderHistoryError::InvalidState(
                    "incomplete state/evidence pair".into(),
                ));
            },
        };
        Ok((pair, state))
    }

    /// Admit and durably remember authority even if no page can be opened.
    /// No requested snapshot, signing key or reader membership is involved.
    pub async fn observe(
        &self,
        history: &[u8],
        at_ms: u64,
    ) -> Result<ReaderObservation, ReaderHistoryError> {
        Ok(self.observe_inner(history, at_ms).await?.0)
    }

    async fn observe_inner(
        &self,
        history: &[u8],
        at_ms: u64,
    ) -> Result<(ReaderObservation, Vec<u8>), ReaderHistoryError> {
        if history.len() > self.limits.max_history_bytes {
            return Err(ReaderHistoryError::Capacity);
        }
        let (previous, state) = self.load().await?;
        if state
            .as_ref()
            .is_some_and(|s| at_ms < s.observation.evaluated_at_ms)
        {
            return Err(ReaderHistoryError::ClockRollback);
        }
        let moot = Moot::in_memory(
            MootId(self.trust.collection.moot_id),
            self.trust.founder,
            self.retention.clone(),
        );
        if let Some(remembered) = &previous.1 {
            moot.import_plain_drop(remembered.as_slice(), self.limits.drop)
                .await?;
        }
        // Admission can have partial effects before refusal; all effects live
        // in this disposable Moot until the complete import/export succeeds.
        moot.import_plain_drop(history, self.limits.drop).await?;
        let mut merged = Vec::new();
        moot.export_plain_drop(&mut merged, DropExportProfile::default(), self.limits.drop)
            .await?;
        if merged.len() > self.limits.max_history_bytes {
            return Err(ReaderHistoryError::Capacity);
        }
        let observation = ReaderObservation {
            history_digest: *blake3::hash(&merged).as_bytes(),
            evaluated_at_ms: at_ms,
        };
        let next = serde_json::to_vec(&State {
            version: 1,
            trust: self.trust.clone(),
            observation: observation.clone(),
        })
        .map_err(|e| ReaderHistoryError::InvalidState(e.to_string()))?;
        let next_history = merged.clone();
        let state_key = self.state_key.clone();
        let history_key = self.history_key.clone();
        let outcome = Arc::new(Mutex::new(None));
        let captured = outcome.clone();
        self.backend
            .transact(Box::new(move |reader| {
                let check = (|| {
                    if (reader.get(&state_key)?, reader.get(&history_key)?) != previous {
                        return Err(ReaderHistoryError::ConcurrentChange);
                    }
                    Ok(())
                })();
                match check {
                    Ok(()) => vec![
                        WriteOp::Put {
                            key: state_key,
                            value: next,
                        },
                        WriteOp::Put {
                            key: history_key,
                            value: next_history,
                        },
                    ],
                    Err(error) => {
                        *captured.lock().expect("reader commit lock") = Some(error);
                        vec![]
                    },
                }
            }))
            .await?;
        if let Some(error) = outcome.lock().expect("reader commit lock").take() {
            return Err(error);
        }
        Ok((observation, merged))
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
        let (observation, merged) = self.observe_inner(history, at_ms).await?;
        let mut verified = verify_reader_evidence(
            &self.trust,
            &merged,
            snapshot,
            self.retention.clone(),
            at_ms,
            self.limits,
        )
        .await?;
        if self.load().await?.1.as_ref().map(|s| &s.observation) != Some(&observation) {
            return Err(ReaderHistoryError::ConcurrentChange);
        }
        verified.scope = EvidenceScope::SuppliedAndRememberedHistory;
        Ok(verified)
    }
}
