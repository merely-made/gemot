// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

use super::store::Record;
use super::{PoolContribution, PoolError, PoolEvent, PoolExt, PoolStore, PoolTarget};
use muniment::Backend;
use p2panda_core::{Operation, cbor::encode_cbor};
use std::collections::{BTreeMap, BTreeSet};
use stickleback::{CausalEntry, causal_projection};

/// Private projected coordination state. It is not a public service directory.
#[derive(Clone, Debug)]
pub struct PoolView {
    /// Stable pool ID.
    pub pool: [u8; 32],
    /// Internal revision binding retained facts and current known authority.
    pub revision: [u8; 32],
    /// Any missing dependency prevents forwarding until the prefix is complete.
    pub pending: bool,
    pub(crate) contributions: BTreeMap<([u8; 32], [u8; 32]), PoolContribution>,
    pub(crate) targets: BTreeMap<[u8; 32], PoolTarget>,
}

/// Short-lived authorization, independent of a worker's fresh liveness proof.
#[derive(Clone, Debug)]
pub struct PoolAuthorization {
    /// Authority revision checked by the runtime on every refresh.
    pub revision: [u8; 32],
    /// Expected worker's scoped service key.
    pub service_key: [u8; 32],
    /// Expected final recipient key, checked through the opaque relay stream.
    pub recipient_key: [u8; 32],
    /// Current contribution's concurrent-flow ceiling.
    pub max_sessions: usize,
    /// Intersected contribution and target byte allowance.
    pub max_bytes: u64,
    /// Contribution's forwarding rate allowance.
    pub bytes_per_second: u64,
    /// Local expiry including the maximum stale-authority window.
    pub expires_at_ms: u64,
}

#[cfg(feature = "relay-pool-native")]
impl PoolAuthorization {
    /// Intersect a freshly read authority snapshot with this receiver's verified
    /// liveness deadline. Refreshing authority never extends a live observation.
    pub fn relay_grant(
        &self,
        now_ms: u64,
        availability_deadline: tokio::time::Instant,
    ) -> Result<murm::relay::RelayGrant, PoolError> {
        let remaining = self
            .expires_at_ms
            .checked_sub(now_ms)
            .filter(|remaining| *remaining > 0)
            .ok_or(PoolError::Unauthorized)?;
        let expires = tokio::time::Instant::now()
            .checked_add(std::time::Duration::from_millis(remaining))
            .ok_or(PoolError::Invalid)?
            .min(availability_deadline);
        if expires <= tokio::time::Instant::now() {
            return Err(PoolError::Unauthorized);
        }
        Ok(murm::relay::RelayGrant {
            revision: self.revision,
            max_sessions: self.max_sessions,
            max_bytes: self.max_bytes,
            bytes_per_second: self.bytes_per_second,
            expires,
        })
    }
}

impl PoolView {
    pub(crate) async fn project<B: Backend + Clone>(
        store: &PoolStore<B>,
        ops: &[Operation<PoolExt>],
        records: Vec<(Record, [u8; 32])>,
        now_ms: u64,
    ) -> Result<Self, PoolError> {
        let entries: Vec<_> = ops
            .iter()
            .map(|op| CausalEntry::from_operation(op, 0u64, op.header.extensions.parents.clone()))
            .collect();
        let causal = causal_projection(&entries).map_err(|_| PoolError::Invalid)?;
        let mut contributions = BTreeMap::new();
        let mut retired = BTreeSet::new();
        let mut targets = BTreeMap::new();
        let mut conflicting_targets = BTreeSet::new();
        for index in causal.order {
            let (record, owner) = &records[index];
            match &record.event {
                PoolEvent::Contribute(c) => {
                    if store.permitted(*owner, "contribute", now_ms).await.is_ok()
                        && c.not_before_ms <= now_ms
                        && now_ms < c.expires_at_ms
                    {
                        contributions.insert((*owner, c.device), c.clone());
                    }
                }
                PoolEvent::Withdraw { device } => {
                    retired.insert((*owner, *device));
                }
                PoolEvent::RegisterTarget(target) => {
                    if store.permitted(*owner, "manage", now_ms).await.is_ok() {
                        if targets.get(&target.id).is_some_and(|old| old != target) {
                            conflicting_targets.insert(target.id);
                        }
                        targets.insert(target.id, target.clone());
                    }
                }
            }
        }
        contributions.retain(|id, _| !retired.contains(id));
        targets.retain(|id, _| !conflicting_targets.contains(id));
        let snapshot = store
            .moot
            .snapshot()
            .await
            .map_err(|_| PoolError::Storage)?;
        let delegation_ops = store
            .moot
            .delegation_store()
            .operations()
            .await
            .map_err(|_| PoolError::Storage)?;
        let mut hashes: Vec<_> = ops
            .iter()
            .map(|op| *op.hash.as_bytes())
            .chain(delegation_ops.iter().map(|op| *op.hash.as_bytes()))
            .collect();
        hashes.sort();
        let revision_bytes = encode_cbor(&(
            store.config.revision,
            snapshot.governance.revision,
            snapshot.membership.auth_heads,
            hashes,
        ))
        .map_err(|_| PoolError::Invalid)?;
        let revision = proofs::Digest::blake3(&revision_bytes)
            .as_32()
            .map_err(|_| PoolError::Invalid)?;
        Ok(Self {
            pool: store.config.pool,
            revision,
            pending: !causal.pending.is_empty(),
            contributions,
            targets,
        })
    }

    /// Get one unambiguous owner/device contribution from this private view.
    pub fn contribution(&self, device: [u8; 32]) -> Option<&PoolContribution> {
        if self.pending {
            return None;
        }
        let mut matching = self
            .contributions
            .iter()
            .filter(|((_, id), _)| *id == device)
            .map(|(_, c)| c);
        let first = matching.next()?;
        matching.next().is_none().then_some(first)
    }
}

impl<B: Backend + Clone> PoolStore<B> {
    /// Re-read actual Moot authority before deriving a short-lived permission.
    /// A cached positive result can last no longer than max_authority_age_ms.
    pub async fn authorize(
        &self,
        requester: [u8; 32],
        device: [u8; 32],
        target: [u8; 32],
        now_ms: u64,
    ) -> Result<PoolAuthorization, PoolError> {
        self.permitted(requester, "use", now_ms).await?;
        let view = self.view(now_ms).await?;
        let contribution = view.contribution(device).ok_or(PoolError::Unauthorized)?;
        let target = view.targets.get(&target).ok_or(PoolError::Unauthorized)?;
        Ok(PoolAuthorization {
            revision: view.revision,
            service_key: contribution.service_key,
            recipient_key: target.recipient_key,
            max_sessions: contribution.max_sessions as usize,
            max_bytes: contribution.max_bytes.min(target.max_bytes),
            bytes_per_second: contribution.bytes_per_second,
            expires_at_ms: contribution
                .expires_at_ms
                .min(self.config.authority_expires_at_ms)
                .min(now_ms.saturating_add(self.config.max_authority_age_ms)),
        })
    }
}
