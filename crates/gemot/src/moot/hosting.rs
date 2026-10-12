// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0
//! Full bounded hosting promises carried by the existing signed Standing lane.
//! Community bounds are owner-configured for a named accepted constitution;
//! device ceilings and requests are explicit. This is neither a custody claim
//! nor a retrieval observation. Hosts serialize commands with authority ingestion.
use super::{Moot, MootAuthorizationRequest, MootCommandReceipt, MootError};
use mien::{ChainRoot, CommitmentId, GateDecision, Scope, StandingEvent};
use muniment::Backend;
use p2panda_core::{
    Topic,
    cbor::{decode_cbor_strict, encode_cbor},
};
use p2panda_store::topics::TopicStore;
use proofs::Digest;
use serde::{Deserialize, Serialize};
use servitor::{Cap, cap_path};
use std::collections::BTreeSet;

const PREFIX: &str = "gemot/hosting/v1/";
const MAX_RECORD_BYTES: usize = 64 * 1024;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostingPolicy {
    pub constitution_revision: Digest,
    pub revision: [u8; 32],
    pub audience: String,
    pub max_bytes: u64,
    pub max_duration_ms: u64,
}
#[derive(Clone, Copy, Debug)]
pub struct DeviceCeiling {
    pub max_bytes: u64,
    pub max_duration_ms: u64,
}
#[derive(Clone, Debug)]
pub struct HostingRequest {
    pub contribution: [u8; 32],
    pub manifest: [u8; 32],
    pub device: [u8; 32],
    pub audience: String,
    pub max_bytes: u64,
    pub duration_ms: u64,
    pub at_ms: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityCut {
    pub constitution_revision: Digest,
    pub constitution_operations: Vec<[u8; 32]>,
    pub membership_heads: Vec<[u8; 32]>,
    pub delegation_operations: Vec<[u8; 32]>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostingPromise {
    pub version: u32,
    pub moot: [u8; 32],
    pub host: [u8; 32],
    pub device: [u8; 32],
    pub contribution: [u8; 32],
    pub manifest: [u8; 32],
    pub audience: String,
    pub max_bytes: u64,
    pub at_ms: u64,
    pub expires_at_ms: u64,
    pub policy_revision: [u8; 32],
    pub authority: AuthorityCut,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostingRecord {
    pub operation: [u8; 32],
    pub promise: HostingPromise,
}
#[derive(Debug, thiserror::Error)]
pub enum HostingError {
    #[error(transparent)]
    Moot(#[from] MootError),
    #[error("Hosting refused: {0}")]
    Refused(String),
}
fn refusal(reason: impl Into<String>) -> HostingError {
    HostingError::Refused(reason.into())
}
pub fn hosting_cap(audience: &str) -> Result<Cap, HostingError> {
    if audience.is_empty()
        || audience.len() > 128
        || !audience
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    {
        return Err(refusal("Audience must be one explicit scope name"));
    }
    Cap::scope(&format!("moot/hosting/{audience}")).map_err(|e| refusal(e.to_string()))
}
fn bytes(promise: &HostingPromise) -> Result<Vec<u8>, HostingError> {
    let bytes = encode_cbor(promise).map_err(|e| refusal(e.to_string()))?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(refusal("Authority cut exceeds hosting record budget"));
    }
    Ok(bytes)
}
fn commitment(promise: &HostingPromise) -> Result<CommitmentId, HostingError> {
    let mut encoded = b"gemot/hosting-promise/v1\0".to_vec();
    encoded.extend(bytes(promise)?);
    Ok(CommitmentId(
        Digest::blake3(&encoded)
            .as_32()
            .map_err(|e| refusal(e.to_string()))?,
    ))
}
fn scope(promise: &HostingPromise) -> Result<Scope, HostingError> {
    Ok(Scope(format!(
        "{PREFIX}{}",
        bytes(promise)?
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )))
}
fn decode(scope: &Scope) -> Result<Option<HostingPromise>, HostingError> {
    let Some(hex) = scope.0.strip_prefix(PREFIX) else {
        return Ok(None);
    };
    if hex.len() % 2 != 0
        || hex.len() > MAX_RECORD_BYTES * 2
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(refusal("Malformed hosting scope"));
    }
    let raw = hex
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect::<Vec<_>>();
    let promise: HostingPromise =
        decode_cbor_strict(raw.as_slice()).map_err(|e| refusal(e.to_string()))?;
    if bytes(&promise)? != raw || promise.version != 1 || promise.expires_at_ms <= promise.at_ms {
        return Err(refusal("Noncanonical or unsupported hosting promise"));
    }
    hosting_cap(&promise.audience)?;
    Ok(Some(promise))
}
impl<B: Backend + Clone> Moot<B> {
    async fn require_host(
        &self,
        host: [u8; 32],
        audience: &str,
        at_ms: u64,
    ) -> Result<(), HostingError> {
        let group = self.membership().await?;
        let request = MootAuthorizationRequest {
            subject: host,
            capability_path: cap_path(&hosting_cap(audience)?),
            at_ms,
        };
        match self.authorize_current_capability(&group, &request).await? {
            GateDecision::Allow => Ok(()),
            GateDecision::Deny(reason) => {
                Err(refusal(format!("Current hosting authority: {reason:?}")))
            },
        }
    }
    /// Bound a request before the content owner retains bytes. This authors nothing.
    pub async fn prepare_hosting(
        &self,
        host: [u8; 32],
        request: &HostingRequest,
        content_bytes: u64,
        policy: &HostingPolicy,
        ceiling: DeviceCeiling,
    ) -> Result<HostingPromise, HostingError> {
        self.require_host(host, &request.audience, request.at_ms)
            .await?;
        let current = self.snapshot().await?;
        if request.audience != policy.audience
            || current.governance.revision != policy.constitution_revision
        {
            return Err(refusal(
                "Hosting audience or configured policy revision changed",
            ));
        }
        if !self
            .authorized_fauna(request.at_ms)
            .await?
            .iter()
            .any(|f| f.op_hash == request.contribution && f.manifest_id == request.manifest)
        {
            return Err(refusal("Exact contribution is no longer authorized"));
        }
        let max_bytes = request
            .max_bytes
            .min(policy.max_bytes)
            .min(ceiling.max_bytes);
        let duration_ms = request
            .duration_ms
            .min(policy.max_duration_ms)
            .min(ceiling.max_duration_ms);
        if content_bytes > max_bytes || duration_ms == 0 {
            return Err(refusal(
                "Content exceeds hosting ceiling or duration is zero",
            ));
        }
        let expires_at_ms = request
            .at_ms
            .checked_add(duration_ms)
            .ok_or_else(|| refusal("Hosting expiry overflow"))?;
        let store = self.constitution_store();
        let mut constitution_operations = vec![];
        let logs: std::collections::BTreeMap<_, Vec<u64>> = store
            .resolve(&Topic::from(self.moot_id().0))
            .await
            .map_err(|e| refusal(e.to_string()))?;
        for (author, ids) in logs {
            for log in ids {
                if let Some(entries) = store
                    .get_log_entries(&author, &log, None, None)
                    .await
                    .map_err(|e| refusal(e.to_string()))?
                {
                    constitution_operations
                        .extend(entries.into_iter().map(|(op, _)| *op.hash.as_bytes()));
                }
            }
        }
        let mut delegation_operations = self
            .delegation_store()
            .operations()
            .await
            .map_err(|e| refusal(e.to_string()))?
            .into_iter()
            .map(|op| *op.hash.as_bytes())
            .collect::<Vec<_>>();
        constitution_operations.sort();
        delegation_operations.sort();
        let mut membership_heads = current.membership.auth_heads;
        membership_heads.sort();
        let promise = HostingPromise {
            version: 1,
            moot: self.moot_id().0,
            host,
            device: request.device,
            contribution: request.contribution,
            manifest: request.manifest,
            audience: request.audience.clone(),
            max_bytes,
            at_ms: request.at_ms,
            expires_at_ms,
            policy_revision: policy.revision,
            authority: AuthorityCut {
                constitution_revision: current.governance.revision,
                constitution_operations,
                membership_heads,
                delegation_operations,
            },
        };
        bytes(&promise)?;
        Ok(promise)
    }
    /// Recheck the complete preparation at signing. The host must serialize this
    /// with authority ingestion; Gemot's separate lane stores are not one transaction.
    /// Verified custody is the content owner's prerequisite, not inferred here.
    pub async fn commit_hosting<P: identity::IdentityProvider + ?Sized>(
        &self,
        identity: &P,
        request: &HostingRequest,
        content_bytes: u64,
        policy: &HostingPolicy,
        ceiling: DeviceCeiling,
        prepared: &HostingPromise,
    ) -> Result<MootCommandReceipt, HostingError> {
        let current = self
            .prepare_hosting(
                identity.master_public_key().to_bytes(),
                request,
                content_bytes,
                policy,
                ceiling,
            )
            .await?;
        if &current != prepared {
            return Err(refusal(
                "Hosting authority cut or policy changed before signing",
            ));
        }
        let event = StandingEvent::CommitmentMade {
            by: ChainRoot(current.host),
            commitment: commitment(&current)?,
            scope: scope(&current)?,
            cadence_ms: current.expires_at_ms - current.at_ms,
            duration_ms: Some(current.expires_at_ms - current.at_ms),
            at_ms: current.at_ms,
        };
        Ok(self
            .record_standing_authorized_for_identity(
                identity,
                event,
                &hosting_cap(&current.audience)?,
            )
            .await?)
    }
    /// Read signed promise evidence. Availability and current serving are separate.
    pub async fn hosting_records(&self) -> Result<Vec<HostingRecord>, HostingError> {
        let store = self.standing_store().sync_store();
        let logs: std::collections::BTreeMap<_, Vec<u64>> = store
            .resolve(&Topic::from(self.moot_id().0))
            .await
            .map_err(|e| refusal(e.to_string()))?;
        let mut records = vec![];
        let mut closed = BTreeSet::new();
        for (author, ids) in logs {
            for log in ids {
                if let Some(entries) = store
                    .get_log_entries(&author, &log, None, None)
                    .await
                    .map_err(|e| refusal(e.to_string()))?
                {
                    for (op, _) in entries {
                        let root = mien::stable_author(&op).map_err(|e| refusal(e.to_string()))?;
                        let (_, event) =
                            mien::from_operation(&op).map_err(|e| refusal(e.to_string()))?;
                        match event {
                            StandingEvent::CommitmentMade {
                                by,
                                commitment: cid,
                                scope: record_scope,
                                at_ms,
                                duration_ms,
                                ..
                            } if by == root => {
                                // Imported ordinary Standing remains wire-compatible.
                                // Malformed/future typed scopes cannot hide other hosts.
                                if let Ok(Some(promise)) = decode(&record_scope) {
                                    if promise.host != root.0
                                        || promise.moot != self.moot_id().0
                                        || commitment(&promise)? != cid
                                        || promise.at_ms != at_ms
                                        || duration_ms
                                            != Some(promise.expires_at_ms - promise.at_ms)
                                    {
                                        continue;
                                    }
                                    records.push(HostingRecord {
                                        operation: *op.hash.as_bytes(),
                                        promise,
                                    });
                                }
                            },
                            StandingEvent::CommitmentFulfilled { by, commitment, .. }
                                if by == root =>
                            {
                                closed.insert((by.0, commitment));
                            },
                            _ => {},
                        }
                    }
                }
            }
        }
        records.retain(|r| {
            !closed.contains(&(
                r.promise.host,
                commitment(&r.promise).expect("validated promise"),
            ))
        });
        records.sort_by_key(|r| (r.promise.at_ms, r.operation));
        Ok(records)
    }
    /// Gate one exact serving request using the latest policy and current authority.
    /// The content owner must also verify held bytes and its current local ceilings.
    pub async fn check_hosting(
        &self,
        record: &HostingRecord,
        audience: &str,
        policy: &HostingPolicy,
        ceiling: DeviceCeiling,
        content_bytes: u64,
        now_ms: u64,
    ) -> Result<(), HostingError> {
        if !self.hosting_records().await?.contains(record) {
            return Err(refusal("Hosting record is no longer live"));
        }
        let p = &record.promise;
        if audience != p.audience
            || policy.audience != p.audience
            || policy.revision != p.policy_revision
            || self
                .governance()
                .snapshot()
                .await
                .map_err(MootError::from)?
                .revision
                != policy.constitution_revision
            || now_ms < p.at_ms
            || now_ms >= p.expires_at_ms
            || p.expires_at_ms - p.at_ms > policy.max_duration_ms.min(ceiling.max_duration_ms)
            || content_bytes > p.max_bytes.min(policy.max_bytes).min(ceiling.max_bytes)
        {
            return Err(refusal(
                "Hosting audience, policy, expiry or local ceiling refused serving",
            ));
        }
        self.require_host(p.host, audience, now_ms).await?;
        if !self
            .authorized_fauna(now_ms)
            .await?
            .iter()
            .any(|f| f.op_hash == p.contribution && f.manifest_id == p.manifest)
        {
            return Err(refusal("Hosted contribution withdrawn or unauthorized"));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "hosting_tests.rs"]
mod tests;
