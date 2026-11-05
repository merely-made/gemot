// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! One remembered-authority store for portable readers, over any authority.
//!
//! A reader remembers evidence per trust anchor and merges what a provider
//! supplies into it; old evidence never replaces remembered authority. The
//! store owns the shared guarantees: atomic compare-and-write, a clock
//! high-water mark, a capacity bound and refusal of corrupt state. An
//! [`Authority`] adapter owns what evidence means and how two bodies of it
//! merge. The host must preserve storage; deletion or whole-store rollback is
//! outside this adapter's protection. No newest-state or availability promise
//! is made.

use std::fmt::{self, Display};
use std::future::Future;
use std::sync::{Arc, Mutex};

use muniment::{Backend, StoreError, WriteOp};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// History considered by verification. Neither scope proves global freshness.
/// A stateless verifier sees supplied history only; a remembered store also
/// preserves previously observed authority across reads and restarts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceScope {
    SuppliedHistoryOnly,
    /// Valid against supplied evidence merged with durably remembered authority.
    /// Unseen newer evidence elsewhere can still exist.
    SuppliedAndRememberedHistory,
}

/// A local observation receipt, not a publication signature or custody promise.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReaderObservation {
    pub history_digest: [u8; 32],
    pub evaluated_at_ms: u64,
}

/// What a kind of authority supplies to the store.
pub trait Authority: Sync {
    /// Independently obtained trust anchor; its serialization names the records.
    type Anchor: Serialize + DeserializeOwned + PartialEq + Clone + Send;
    type Error: Send;
    /// Record-key namespace, for example `site-reader/v1`.
    const NAMESPACE: &'static str;
    /// Record name of the evidence blob within the anchor's prefix.
    const EVIDENCE_NAME: &'static str;

    fn anchor(&self) -> &Self::Anchor;
    fn max_evidence_bytes(&self) -> usize;
    /// Verify `supplied` together with `remembered` and return the merged
    /// evidence to remember. Any refusal leaves stored state untouched.
    fn merge(
        &self,
        remembered: Option<&[u8]>,
        supplied: &[u8],
    ) -> impl Future<Output = Result<Vec<u8>, Self::Error>> + Send;
}

#[derive(Debug)]
pub enum RememberedError<E> {
    Storage(StoreError),
    Authority(E),
    InvalidState(String),
    Capacity,
    ClockRollback,
    ConcurrentChange,
}

impl<E: Display> Display for RememberedError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(e) => e.fmt(f),
            Self::Authority(e) => e.fmt(f),
            Self::InvalidState(e) => write!(f, "Invalid remembered reader authority: {e}"),
            Self::Capacity => f.write_str("Reader authority history exceeds capacity"),
            Self::ClockRollback => {
                f.write_str("Reader evaluation time precedes remembered observation")
            }
            Self::ConcurrentChange => {
                f.write_str("Reader authority changed; retry with remembered state")
            }
        }
    }
}
impl<E: fmt::Debug + Display> std::error::Error for RememberedError<E> {}
impl<E> From<StoreError> for RememberedError<E> {
    fn from(e: StoreError) -> Self {
        Self::Storage(e)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State<T> {
    version: u8,
    // Named `trust` in stored records written before the store was shared.
    trust: T,
    observation: ReaderObservation,
}

type StoredPair = (Option<Vec<u8>>, Option<Vec<u8>>);

/// Host-owned storage plus one authority adapter. Constructing a handle does
/// not initialize or reset any records. Each observation requires
/// transactional backend support. Restart durability follows the supplied
/// backend; use persistent storage for that gate.
pub struct Remembered<B, A: Authority> {
    backend: B,
    authority: A,
    state_key: String,
    evidence_key: String,
}

impl<B: Backend + Sync, A: Authority> Remembered<B, A> {
    pub fn new(backend: B, authority: A) -> Self {
        // The anchor has a fixed, derived serialization; key identity includes
        // everything the anchor names.
        let identity =
            blake3::hash(&serde_json::to_vec(authority.anchor()).expect("anchor encoding"));
        let prefix = format!("{}/{}", A::NAMESPACE, identity.to_hex());
        Self {
            backend,
            authority,
            state_key: format!("{prefix}/state.json"),
            evidence_key: format!("{prefix}/{}", A::EVIDENCE_NAME),
        }
    }

    pub fn authority(&self) -> &A {
        &self.authority
    }

    async fn load(
        &self,
    ) -> Result<(StoredPair, Option<State<A::Anchor>>), RememberedError<A::Error>> {
        let pair = Arc::new(Mutex::new(None));
        let captured = pair.clone();
        let (state_key, evidence_key) = (self.state_key.clone(), self.evidence_key.clone());
        self.backend
            .transact(Box::new(move |reader| {
                *captured.lock().expect("reader snapshot lock") = Some((|| {
                    Ok::<_, StoreError>((reader.get(&state_key)?, reader.get(&evidence_key)?))
                })());
                vec![]
            }))
            .await?;
        let pair = pair
            .lock()
            .expect("reader snapshot lock")
            .take()
            .ok_or_else(|| RememberedError::InvalidState("transaction did not run".into()))??;
        let state = match (&pair.0, &pair.1) {
            (None, None) => None,
            (Some(metadata), Some(evidence)) => {
                if metadata.len() > 4096 || evidence.len() > self.authority.max_evidence_bytes() {
                    return Err(RememberedError::Capacity);
                }
                let state: State<A::Anchor> = serde_json::from_slice(metadata)
                    .map_err(|e| RememberedError::InvalidState(e.to_string()))?;
                if state.version != 1
                    || state.trust != *self.authority.anchor()
                    || state.observation.history_digest != *blake3::hash(evidence).as_bytes()
                {
                    return Err(RememberedError::InvalidState(
                        "identity or evidence digest mismatch".into(),
                    ));
                }
                Some(state)
            }
            _ => {
                return Err(RememberedError::InvalidState(
                    "incomplete state/evidence pair".into(),
                ));
            }
        };
        Ok((pair, state))
    }

    /// The last durable observation, if any.
    pub async fn observation(
        &self,
    ) -> Result<Option<ReaderObservation>, RememberedError<A::Error>> {
        Ok(self.load().await?.1.map(|s| s.observation))
    }

    /// Admit and durably remember authority even if no content can be opened.
    /// Returns the receipt and the merged evidence now remembered.
    pub async fn observe(
        &self,
        evidence: &[u8],
        at_ms: u64,
    ) -> Result<(ReaderObservation, Vec<u8>), RememberedError<A::Error>> {
        if evidence.len() > self.authority.max_evidence_bytes() {
            return Err(RememberedError::Capacity);
        }
        let (previous, state) = self.load().await?;
        if state
            .as_ref()
            .is_some_and(|s| at_ms < s.observation.evaluated_at_ms)
        {
            return Err(RememberedError::ClockRollback);
        }
        let merged = self
            .authority
            .merge(previous.1.as_deref(), evidence)
            .await
            .map_err(RememberedError::Authority)?;
        if merged.len() > self.authority.max_evidence_bytes() {
            return Err(RememberedError::Capacity);
        }
        let observation = ReaderObservation {
            history_digest: *blake3::hash(&merged).as_bytes(),
            evaluated_at_ms: at_ms,
        };
        let next = serde_json::to_vec(&State {
            version: 1,
            trust: self.authority.anchor().clone(),
            observation: observation.clone(),
        })
        .map_err(|e| RememberedError::InvalidState(e.to_string()))?;
        let next_evidence = merged.clone();
        let (state_key, evidence_key) = (self.state_key.clone(), self.evidence_key.clone());
        let outcome: Arc<Mutex<Option<Result<(), StoreError>>>> = Arc::new(Mutex::new(None));
        let captured = outcome.clone();
        self.backend
            .transact(Box::new(move |reader| {
                let current = (|| {
                    Ok::<StoredPair, StoreError>((
                        reader.get(&state_key)?,
                        reader.get(&evidence_key)?,
                    ))
                })();
                match current {
                    Ok(current) if current == previous => vec![
                        WriteOp::Put {
                            key: state_key,
                            value: next,
                        },
                        WriteOp::Put {
                            key: evidence_key,
                            value: next_evidence,
                        },
                    ],
                    other => {
                        *captured.lock().expect("reader commit lock") =
                            Some(other.map(|_: StoredPair| ()));
                        vec![]
                    }
                }
            }))
            .await?;
        match outcome.lock().expect("reader commit lock").take() {
            None => {}
            Some(Ok(())) => return Err(RememberedError::ConcurrentChange),
            Some(Err(error)) => return Err(RememberedError::Storage(error)),
        }
        Ok((observation, merged))
    }
}
