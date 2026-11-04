// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

use super::{
    PoolError, PoolEvent, PoolKeys, PoolPolicy, PoolView, RELAY_POOL_LANE, device_salt,
    record_salt, relay_cap,
};
use crate::moot::{Moot, MootAuthorizationRequest};
use identity::{AttestationKeys, IdentityProvider};
use insigne::DerivedKeyAttestation;
use muniment::Backend;
use murm_sync::{AfterHandshakeOutcome, Endpoint, Gossip, JoinedSpace, SyncHooks};
use p2panda_core::cbor::{decode_cbor_strict, encode_cbor};
use p2panda_core::{Body, Hash, Header, Operation, SigningKey, Topic};
use p2panda_store::topics::TopicStore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use stickleback::{
    Admission, CausalEntry, CausalLimits, DataKeyring, GroupCiphertext, MunimentStore,
    OperationPolicy, OperationProcessor, Reject, StoreTarget, author_head, complete_frontier,
    stable_writer_subject, validate_causal_metadata,
};

const CAUSAL: CausalLimits = CausalLimits {
    max_parents: 32,
    max_payload_bytes: 65_536,
};

/// Visible causal/addressing metadata; no owner/device attestations in headers.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PoolExt {
    /// Version of this private lane grammar.
    pub version: u8,
    /// Pool synchronization topic; disclosure remains restricted to operators.
    pub pool: [u8; 32],
    /// Cross-author causal dependencies.
    pub parents: Vec<[u8; 32]>,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Record {
    pub moot: [u8; 32],
    pub event: PoolEvent,
    pub attestation: DerivedKeyAttestation,
    pub policy_revision: [u8; 32],
}

fn decode(
    keys: &DataKeyring,
    policy: &PoolPolicy,
    op: &Operation<PoolExt>,
) -> Result<(Record, [u8; 32]), PoolError> {
    if op.header.extensions.version != 1 || op.header.extensions.pool != policy.pool {
        return Err(PoolError::Invalid);
    }
    validate_causal_metadata(op, &op.header.extensions.parents, CAUSAL)
        .map_err(|_| PoolError::Invalid)?;
    let body = op.body.as_ref().ok_or(PoolError::Invalid)?.to_bytes();
    let ciphertext: GroupCiphertext =
        decode_cbor_strict(body.as_slice()).map_err(|_| PoolError::Invalid)?;
    let plain = keys.open(&ciphertext).map_err(|_| PoolError::Invalid)?;
    let record: Record = decode_cbor_strict(plain.as_slice()).map_err(|_| PoolError::Invalid)?;
    let owner = stable_writer_subject(
        *op.header.verifying_key.as_bytes(),
        Some(&record.attestation),
        &record_salt(policy.pool, &record.event),
    )
    .map_err(|_| PoolError::Invalid)?;
    if record.moot != policy.moot.0 || record.policy_revision != policy.revision {
        return Err(PoolError::Unauthorized);
    }
    if let PoolEvent::Contribute(c) = &record.event {
        let checked = c
            .device_attestation
            .check(&device_salt(policy.pool, c.device))
            .map_err(|_| PoolError::Invalid)?;
        if *checked.master() != owner
            || c.device_attestation
                .derived_public_key()
                .map_err(|_| PoolError::Invalid)?
                .to_bytes()
                != c.service_key
            || c.max_sessions == 0
            || c.max_sessions > 256
            || c.max_bytes == 0
            || c.bytes_per_second == 0
            || c.expires_at_ms <= c.not_before_ms
            || c.expires_at_ms - c.not_before_ms > policy.max_lease_ms
        {
            return Err(PoolError::Invalid);
        }
    }
    if matches!(&record.event, PoolEvent::RegisterTarget(t) if t.max_bytes == 0) {
        return Err(PoolError::Invalid);
    }
    Ok((record, owner))
}

struct Policy<'a> {
    config: &'a PoolPolicy,
    keys: Arc<DataKeyring>,
}
impl OperationPolicy<PoolExt> for Policy<'_> {
    type LogId = u64;
    fn admit(&self, op: &Operation<PoolExt>) -> Result<Admission<u64>, Reject> {
        decode(&self.keys, self.config, op)
            .map_err(|_| Reject::new("invalid-relay", "private record refused"))?;
        Ok(Admission::keep(StoreTarget::new(
            Topic::from(self.config.coordination),
            0,
        )))
    }
}

/// A private typed lane over existing storage, crypto and live synchronization.
pub struct PoolStore<B: Backend + Clone> {
    pub(crate) config: PoolPolicy,
    pub(crate) moot: Arc<Moot<B>>,
    store: MunimentStore<B, PoolExt>,
    keys: PoolKeys,
    mutation: Arc<tokio::sync::Mutex<()>>,
}

impl<B: Backend + Clone> Clone for PoolStore<B> {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            moot: self.moot.clone(),
            store: self.store.clone(),
            keys: self.keys.clone(),
            mutation: self.mutation.clone(),
        }
    }
}

impl<B: Backend + Clone> PoolStore<B> {
    /// Hosts serialize Moot authority ingestion with this lane's commands.
    /// Key custody and rotation remain with the existing group-session owner.
    pub fn new(
        moot: Arc<Moot<B>>,
        backend: B,
        config: PoolPolicy,
        keys: PoolKeys,
    ) -> Result<Self, PoolError> {
        if moot.moot_id() != config.moot
            || config.coordination == config.pool
            || config.coordination == [0; 32]
            || config.max_records == 0
            || config.max_records > 4096
            || config.max_lease_ms == 0
            || config.max_authority_age_ms == 0
            || config.authority_expires_at_ms == 0
        {
            return Err(PoolError::Invalid);
        }
        Ok(Self {
            config,
            moot,
            store: MunimentStore::new(backend),
            keys,
            mutation: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    pub(crate) async fn permitted(
        &self,
        owner: [u8; 32],
        action: &str,
        now_ms: u64,
    ) -> Result<(), PoolError> {
        if now_ms >= self.config.authority_expires_at_ms {
            return Err(PoolError::Unauthorized);
        }
        let snapshot = self.moot.snapshot().await.map_err(|_| PoolError::Storage)?;
        if snapshot.governance.revision != self.config.constitution_revision {
            return Err(PoolError::Unauthorized);
        }
        let group = self
            .moot
            .membership()
            .await
            .map_err(|_| PoolError::Storage)?;
        let request = MootAuthorizationRequest {
            subject: owner,
            capability_path: servitor::cap_path(&relay_cap(self.config.pool, action)?),
            at_ms: now_ms,
        };
        match self
            .moot
            .authorize_current_capability(&group, &request)
            .await
            .map_err(|_| PoolError::Storage)?
        {
            mien::GateDecision::Allow => Ok(()),
            _ => Err(PoolError::Unauthorized),
        }
    }

    /// Load bounded retained ciphertext operations for replay or transfer.
    pub async fn operations(&self) -> Result<Vec<Operation<PoolExt>>, PoolError> {
        let logs: BTreeMap<_, Vec<u64>> = self
            .store
            .resolve(&Topic::from(self.config.coordination))
            .await
            .map_err(|_| PoolError::Storage)?;
        let mut result = vec![];
        for (author, ids) in logs {
            for log in ids {
                if let Some(entries) = self
                    .store
                    .get_log_entries(&author, &log, None, None)
                    .await
                    .map_err(|_| PoolError::Storage)?
                {
                    result.extend(entries.into_iter().map(|(op, _)| op));
                    if result.len() > self.config.max_records {
                        return Err(PoolError::Capacity);
                    }
                }
            }
        }
        Ok(result)
    }

    async fn accept_locked(&self, op: &Operation<PoolExt>, now_ms: u64) -> Result<bool, PoolError> {
        let keys = (self.keys)();
        let processor = OperationProcessor::new(
            self.store.clone(),
            Policy {
                config: &self.config,
                keys: keys.clone(),
            },
        );
        processor.preflight(op).map_err(|_| PoolError::Invalid)?;
        let (record, owner) = decode(&keys, &self.config, op)?;
        self.permitted(
            owner,
            match record.event {
                PoolEvent::RegisterTarget(_) => "manage",
                _ => "contribute",
            },
            now_ms,
        )
        .await?;
        let existing = self.operations().await?;
        if existing.len() >= self.config.max_records && !existing.iter().any(|o| o.hash == op.hash)
        {
            return Err(PoolError::Capacity);
        }
        Ok(processor
            .process(op)
            .await
            .map_err(|_| PoolError::Storage)?
            .inserted())
    }

    /// Verify, decrypt and authorize before inserting. Unavailable authority fails closed.
    pub async fn accept(&self, op: &Operation<PoolExt>, now_ms: u64) -> Result<bool, PoolError> {
        let _lock = self.mutation.lock().await;
        self.accept_locked(op, now_ms).await
    }

    /// Author under the caller's scoped Personae writer, keeping lineage encrypted.
    pub async fn author<I: IdentityProvider + ?Sized>(
        &self,
        identity: &I,
        event: PoolEvent,
        now_ms: u64,
    ) -> Result<Operation<PoolExt>, PoolError> {
        let _lock = self.mutation.lock().await;
        let previous = self.operations().await?;
        let entries: Vec<_> = previous
            .iter()
            .map(|op| CausalEntry::from_operation(op, 0u64, op.header.extensions.parents.clone()))
            .collect();
        let salt = record_salt(self.config.pool, &event);
        let signer = identity
            .derive_keypair(&salt)
            .map_err(|_| PoolError::Invalid)?;
        let (seq_num, backlink) = author_head(&entries, signer.public_key().to_bytes(), &0)
            .map_err(|_| PoolError::Invalid)?;
        let parents = complete_frontier(&entries).map_err(|_| PoolError::Invalid)?;
        let record = Record {
            moot: self.config.moot.0,
            event,
            policy_revision: self.config.revision,
            attestation: identity
                .attest_derived_key(&salt)
                .map_err(|_| PoolError::Invalid)?,
        };
        let plain = encode_cbor(&record).map_err(|_| PoolError::Invalid)?;
        let envelope = (self.keys)()
            .seal_random(&plain)
            .map_err(|_| PoolError::Invalid)?;
        let body = encode_cbor(&envelope).map_err(|_| PoolError::Invalid)?;
        let header = Header::builder()
            .body(&body)
            .seq_num(seq_num)
            .backlink(backlink.map(Hash::from))
            .build(
                &SigningKey::from_bytes(&signer.to_seed()),
                PoolExt {
                    version: 1,
                    pool: self.config.pool,
                    parents,
                },
            );
        let op = Operation {
            hash: header.hash(),
            header,
            body: Some(Body::from_bytes(&body)),
        };
        self.accept_locked(&op, now_ms).await?;
        Ok(op)
    }

    /// Rebuild the authorized view. Reopen intentionally restores no live offers.
    pub async fn view(&self, now_ms: u64) -> Result<PoolView, PoolError> {
        let ops = self.operations().await?;
        let keys = (self.keys)();
        let records = ops
            .iter()
            .map(|op| decode(&keys, &self.config, op))
            .collect::<Result<Vec<_>, _>>()?;
        PoolView::project(self, &ops, records, now_ms).await
    }
}

impl<B: Backend + Clone + Send + Sync + 'static> PoolStore<B> {
    /// Join through the host's existing endpoint and shared validating intake.
    pub async fn join(
        &self,
        endpoint: Endpoint,
        gossip: Gossip,
        clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Result<JoinedSpace<PoolExt>, PoolError> {
        self.join_inner(endpoint, gossip, clock, None).await
    }

    /// Join with explicitly attested, operator-private control keys. This strict
    /// profile accepts neither public worker keys nor raw root endpoints.
    pub async fn join_with_control_peers(
        &self,
        endpoint: Endpoint,
        gossip: Gossip,
        clock: Arc<dyn Fn() -> u64 + Send + Sync>,
        peers: Vec<super::ControlPeer>,
    ) -> Result<JoinedSpace<PoolExt>, PoolError> {
        let peers = control_bindings(self.config.pool, peers)?;
        self.join_inner(endpoint, gossip, clock, Some(peers)).await
    }
    async fn join_inner(
        &self,
        endpoint: Endpoint,
        gossip: Gossip,
        clock: Arc<dyn Fn() -> u64 + Send + Sync>,
        control: Option<BTreeMap<[u8; 32], [u8; 32]>>,
    ) -> Result<JoinedSpace<PoolExt>, PoolError> {
        let intake = self.clone();
        let hooks = PoolSyncGate {
            store: self.clone(),
            clock: clock.clone(),
            control,
        };
        JoinedSpace::join_with_hooks::<_, u64, _, _, _>(
            stickleback::lane_id(RELAY_POOL_LANE, self.config.coordination),
            self.store.clone(),
            endpoint,
            gossip,
            self.config.coordination,
            move |op| {
                let intake = intake.clone();
                let now = clock();
                async move { matches!(intake.accept(&op, now).await, Ok(true)) }
            },
            hooks,
        )
        .await
        .map_err(|_| PoolError::Storage)
    }
}

pub(super) fn control_bindings(
    pool: [u8; 32],
    peers: Vec<super::ControlPeer>,
) -> Result<BTreeMap<[u8; 32], [u8; 32]>, PoolError> {
    if peers.len() > 256 {
        return Err(PoolError::Capacity);
    }
    let mut result = BTreeMap::new();
    for peer in peers {
        let (key, owner) = peer.binding(pool)?;
        if result.insert(key, owner).is_some() {
            return Err(PoolError::Invalid);
        }
    }
    Ok(result)
}

#[derive(Clone)]
pub(super) struct PoolSyncGate<B: Backend + Clone> {
    pub(super) store: PoolStore<B>,
    pub(super) clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    pub(super) control: Option<BTreeMap<[u8; 32], [u8; 32]>>,
}
impl<B: Backend + Clone> std::fmt::Debug for PoolSyncGate<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PoolSyncGate { private }")
    }
}
impl<B: Backend + Clone + Send + Sync + 'static> SyncHooks for PoolSyncGate<B> {
    type Handshake = Topic;
    async fn after_handshake(
        &self,
        remote: p2panda_core::VerifyingKey,
        topic: &Topic,
    ) -> AfterHandshakeOutcome {
        let now = (self.clock)();
        if topic != &Topic::from(self.store.config.coordination) {
            return AfterHandshakeOutcome::Reject;
        }
        if let Some(control) = &self.control {
            let Some(owner) = control.get(remote.as_bytes()) else {
                return AfterHandshakeOutcome::Reject;
            };
            return if self
                .store
                .permitted(*owner, "contribute", now)
                .await
                .is_ok()
                || self.store.permitted(*owner, "manage", now).await.is_ok()
            {
                AfterHandshakeOutcome::Accept
            } else {
                AfterHandshakeOutcome::Reject
            };
        }
        let root_allowed = self
            .store
            .permitted(*remote.as_bytes(), "contribute", now)
            .await
            .is_ok()
            || self
                .store
                .permitted(*remote.as_bytes(), "manage", now)
                .await
                .is_ok();
        let device_allowed = self.store.view(now).await.is_ok_and(|view| {
            !view.pending
                && view
                    .contributions
                    .values()
                    .any(|c| c.service_key == *remote.as_bytes())
        });
        if root_allowed || device_allowed {
            AfterHandshakeOutcome::Accept
        } else {
            AfterHandshakeOutcome::Reject
        }
    }
}
