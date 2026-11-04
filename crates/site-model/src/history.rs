// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Optional saved-site checkpoints over a caller-supplied Muniment backend.
//! Snapshot V1 bytes are immutable blobs; a separate journal orders checkpoints.
//! Recording requires `Backend::transact`. A failed journal commit can leave an
//! unreferenced blob, but cannot publish a revision referencing missing bytes.
//! No retention, collection, serving, identity or merge policy is supplied here.

use std::sync::{Arc, Mutex};

use muniment::{Backend, BlobStore, Hash, Journal, StoreError, WriteOp};
use serde::{Deserialize, Serialize};

use crate::PublishedSnapshotV1;

/// Caller-assigned local history identity, independent of snapshot content.
/// This is not a network address, persona, or publication authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteId(pub [u8; 32]);

/// Explicit checkpoint metadata. The caller supplies the clock and label.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub recorded_at_unix_ms: u64,
    pub label: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteRevision {
    pub sequence: u64,
    pub snapshot_digest: [u8; 32],
    pub checkpoint: Checkpoint,
}

/// Capacity refusal preserves all previously recorded revisions. Hosts can
/// choose different limits; there is no implicit pruning or garbage collection.
#[derive(Clone, Copy, Debug)]
pub struct HistoryLimits {
    pub max_revisions: usize,
    pub max_journal_bytes: usize,
}

impl Default for HistoryLimits {
    fn default() -> Self {
        Self {
            max_revisions: 10_000,
            max_journal_bytes: 8 * 1024 * 1024,
        }
    }
}

#[derive(Debug)]
pub enum HistoryError {
    Storage(StoreError),
    Invalid(String),
    Capacity,
    ConcurrentChange,
    MissingSnapshot,
}

impl std::fmt::Display for HistoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(error) => write!(f, "{error}"),
            Self::Invalid(error) => write!(f, "invalid site history: {error}"),
            Self::Capacity => {
                f.write_str("site history capacity reached; existing revisions retained")
            },
            Self::ConcurrentChange => f.write_str("site history changed; retry the checkpoint"),
            Self::MissingSnapshot => f.write_str("site history snapshot is missing"),
        }
    }
}

impl std::error::Error for HistoryError {}
impl From<StoreError> for HistoryError {
    fn from(error: StoreError) -> Self {
        Self::Storage(error)
    }
}

#[derive(Serialize, Deserialize)]
struct HistoryJournal {
    version: u32,
    site: SiteId,
    revisions: Journal<SiteRevision>,
}

/// A stateless adapter: each operation reads committed state. Multiple handles
/// cannot silently overwrite a competing checkpoint; a stale writer is refused.
pub struct SiteHistory<B> {
    blobs: BlobStore<B>,
    limits: HistoryLimits,
}

fn journal_key(site: SiteId) -> String {
    format!(
        "site-history/v1/{}/journal.json",
        blake3::Hash::from_bytes(site.0).to_hex()
    )
}

impl<B: Backend + Sync> SiteHistory<B> {
    pub fn new(backend: B, limits: HistoryLimits) -> Self {
        Self {
            blobs: BlobStore::new(backend),
            limits,
        }
    }

    async fn journal(
        &self,
        site: SiteId,
    ) -> Result<(Option<Vec<u8>>, HistoryJournal), HistoryError> {
        let bytes = self.blobs.backend().get(&journal_key(site)).await?;
        let journal = match &bytes {
            Some(bytes) => {
                if bytes.len() > self.limits.max_journal_bytes {
                    return Err(HistoryError::Capacity);
                }
                serde_json::from_slice::<HistoryJournal>(bytes)
                    .map_err(|error| HistoryError::Invalid(error.to_string()))?
            },
            None => HistoryJournal {
                version: 1,
                site,
                revisions: Journal::new(),
            },
        };
        if journal.version != 1 || journal.site != site {
            return Err(HistoryError::Invalid(
                "version or site identity mismatch".into(),
            ));
        }
        for (index, revision) in journal.revisions.entries().iter().enumerate() {
            if revision.sequence != index as u64 || revision.checkpoint.label.len() > 1024 {
                return Err(HistoryError::Invalid("checkpoint sequence or label".into()));
            }
        }
        Ok((bytes, journal))
    }

    /// Record one explicit checkpoint, even when its bytes equal a prior one.
    /// Blob content deduplicates; checkpoint occurrences remain distinct.
    pub async fn record(
        &self,
        site: SiteId,
        snapshot: &PublishedSnapshotV1,
        checkpoint: Checkpoint,
    ) -> Result<SiteRevision, HistoryError> {
        if checkpoint.label.len() > 1024 {
            return Err(HistoryError::Invalid(
                "checkpoint label exceeds 1024 bytes".into(),
            ));
        }
        let encoded = snapshot.encode().map_err(HistoryError::Invalid)?;
        let (previous, mut journal) = self.journal(site).await?;
        if journal.revisions.len() >= self.limits.max_revisions {
            return Err(HistoryError::Capacity);
        }
        let revision = SiteRevision {
            sequence: journal.revisions.next_seq().0,
            snapshot_digest: *blake3::hash(&encoded).as_bytes(),
            checkpoint,
        };
        journal.revisions.append(revision.clone());
        let next =
            serde_json::to_vec(&journal).map_err(|e| HistoryError::Invalid(e.to_string()))?;
        if next.len() > self.limits.max_journal_bytes {
            return Err(HistoryError::Capacity);
        }
        let hash = self.blobs.put(&encoded).await?;
        let blob_key = format!("blob/{}", hash.to_hex());
        let key = journal_key(site);
        let outcome = Arc::new(Mutex::new(None));
        let checked = outcome.clone();
        self.blobs
            .backend()
            .transact(Box::new(move |reader| {
                let check = (|| {
                    if reader.get(&key)? != previous {
                        return Err(HistoryError::ConcurrentChange);
                    }
                    let bytes = reader
                        .get(&blob_key)?
                        .ok_or(HistoryError::MissingSnapshot)?;
                    if Hash::of(&bytes) != hash {
                        return Err(HistoryError::Invalid("snapshot digest mismatch".into()));
                    }
                    Ok(())
                })();
                match check {
                    Ok(()) => vec![WriteOp::Put { key, value: next }],
                    Err(error) => {
                        *checked.lock().expect("history outcome lock") = Some(error);
                        vec![]
                    },
                }
            }))
            .await?;
        if let Some(error) = outcome.lock().expect("history outcome lock").take() {
            return Err(error);
        }
        Ok(revision)
    }

    pub async fn list(&self, site: SiteId) -> Result<Vec<SiteRevision>, HistoryError> {
        Ok(self.journal(site).await?.1.revisions.entries().to_vec())
    }

    /// Load only a revision committed to this site's journal, validating both
    /// the blob's content address and the original canonical V1 encoding.
    pub async fn load(
        &self,
        site: SiteId,
        sequence: u64,
    ) -> Result<Option<PublishedSnapshotV1>, HistoryError> {
        let (_, journal) = self.journal(site).await?;
        let Some(revision) = journal
            .revisions
            .entries()
            .iter()
            .find(|r| r.sequence == sequence)
        else {
            return Ok(None);
        };
        let hash = Hash::from_bytes(revision.snapshot_digest);
        let bytes = self
            .blobs
            .get(&hash)
            .await?
            .ok_or(HistoryError::MissingSnapshot)?;
        if Hash::of(&bytes) != hash {
            return Err(HistoryError::Invalid("snapshot digest mismatch".into()));
        }
        PublishedSnapshotV1::decode(&bytes)
            .map(Some)
            .map_err(HistoryError::Invalid)
    }
}
