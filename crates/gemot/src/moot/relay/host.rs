// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

//! Bounded composition of existing pool authority and disposable readiness.
//! The caller owns custody, verified authority checkpoints, clock and task lifetime.
//! Reopening retained records never supplies an availability observation.

use super::{LiveOffer, OfferBook, OfferProbe, PoolError, PoolStore, PoolTarget};
use muniment::Backend;
use murm::relay::{RelayGrant, RelayRequest};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::Instant;

mod worker;
pub use worker::{I2pWorker, WorkerAdmission, WorkerLimits, WorkerReport, WorkerStop};

/// Owner time, absent when its validity/uncertainty policy cannot be satisfied.
pub type OwnerClock = Arc<dyn Fn() -> Option<u64> + Send + Sync>;
/// Current custody binding, absent on lock/loss. A changed epoch needs a new host.
pub type CustodyEpoch = Arc<dyn Fn() -> Option<u64> + Send + Sync>;

/// A locally selected audience/target pair, additionally checked against Moot law.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerAccess {
    /// Requester's stable admitted subject, restricted to operator configuration.
    pub requester: [u8; 32],
    /// Independently selected recipient pin and an additional local byte ceiling.
    pub target: PoolTarget,
}

struct State<B: Backend + Clone> {
    store: PoolStore<B>,
    offers: OfferBook,
    last_time: u64,
    invalid: bool,
}
#[derive(Default)]
struct Snapshot {
    grants: BTreeMap<([u8; 32], [u8; 32]), CachedGrant>,
    owner_time: u64,
}
#[derive(Clone, Copy)]
struct CachedGrant {
    grant: RelayGrant,
    not_after_ms: u64,
}

/// One host's live, bounded authorization view. Clones share all observations.
/// No raw positive/negative permission setter is exposed.
pub struct WorkerAuthority<B: Backend + Clone> {
    state: Arc<Mutex<State<B>>>,
    snapshot: Arc<RwLock<Snapshot>>,
    access: Arc<Vec<WorkerAccess>>,
    device: [u8; 32],
    service_key: [u8; 32],
    pool: [u8; 32],
    clock: OwnerClock,
    custody: CustodyEpoch,
    epoch: u64,
    checkpoint_deadline: Instant,
    max_availability: Duration,
    closed: Arc<AtomicBool>,
}
impl<B: Backend + Clone> Clone for WorkerAuthority<B> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            snapshot: self.snapshot.clone(),
            access: self.access.clone(),
            device: self.device,
            service_key: self.service_key,
            pool: self.pool,
            clock: self.clock.clone(),
            custody: self.custody.clone(),
            epoch: self.epoch,
            checkpoint_deadline: self.checkpoint_deadline,
            max_availability: self.max_availability,
            closed: self.closed.clone(),
        }
    }
}
impl<B: Backend + Clone> WorkerAuthority<B> {
    /// Bind a host to an already-verified authority checkpoint and custody epoch.
    /// Refreshes cannot move this checkpoint's receiver-local monotonic deadline.
    /// A fresh checkpoint is installed by constructing a new host after verification.
    ///
    /// # Errors
    /// Refuses missing/expired custody or clock, invalid bounds and duplicate access.
    pub fn new(
        store: PoolStore<B>,
        device: [u8; 32],
        service_key: [u8; 32],
        access: Vec<WorkerAccess>,
        clock: OwnerClock,
        custody: CustodyEpoch,
        max_availability: Duration,
    ) -> Result<Self, PoolError> {
        let now = clock().ok_or(PoolError::Unauthorized)?;
        let epoch = custody()
            .filter(|epoch| *epoch != 0)
            .ok_or(PoolError::Unauthorized)?;
        let remaining = store
            .config
            .authority_expires_at_ms
            .checked_sub(now)
            .filter(|remaining| *remaining > 0)
            .ok_or(PoolError::Unauthorized)?;
        let mut pairs = BTreeSet::new();
        if access.is_empty()
            || access.len() > 256
            || max_availability.as_millis() == 0
            || max_availability.as_millis() > u128::from(store.config.max_lease_ms)
            || access
                .iter()
                .any(|a| a.target.max_bytes == 0 || !pairs.insert((a.requester, a.target.id)))
        {
            return Err(PoolError::Invalid);
        }
        let checkpoint_deadline = Instant::now()
            .checked_add(Duration::from_millis(remaining))
            .ok_or(PoolError::Invalid)?;
        Ok(Self {
            pool: store.config.pool,
            state: Arc::new(Mutex::new(State {
                store,
                offers: OfferBook::default(),
                last_time: now,
                invalid: false,
            })),
            snapshot: Arc::new(RwLock::new(Snapshot::default())),
            access: Arc::new(access),
            device,
            service_key,
            clock,
            custody,
            epoch,
            checkpoint_deadline,
            max_availability,
            closed: Arc::new(AtomicBool::new(false)),
        })
    }
    fn clear(&self) {
        self.snapshot
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .grants
            .clear();
    }
    /// Irreversibly stop this host binding, including all clones and late reads.
    /// Reopening requires a new host, fresh readiness and current authority.
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.clear();
    }
    fn time(&self, state: &mut State<B>) -> Result<u64, PoolError> {
        let now = (self.clock)();
        if state.invalid
            || self.closed.load(Ordering::SeqCst)
            || (self.custody)() != Some(self.epoch)
            || Instant::now() >= self.checkpoint_deadline
            || now.is_none_or(|now| now < state.last_time)
        {
            state.invalid = true;
            self.clear();
            return Err(PoolError::Unauthorized);
        }
        state.last_time = now.unwrap();
        Ok(state.last_time)
    }
    /// Start a fresh readiness challenge for this currently authorized enrollment.
    /// The owner selects whether its response represents local or remote readiness;
    /// a local response alone is not proof of public route reachability.
    ///
    /// # Errors
    /// Refuses unavailable authority/custody, invalid leases or an unknown device.
    pub async fn probe(&self, lease: Duration) -> Result<OfferProbe, PoolError> {
        if lease.is_zero() || lease > self.max_availability {
            return Err(PoolError::Invalid);
        }
        let mut state = self.state.lock().await;
        let now = self.time(&mut state)?;
        let view = state.store.view(now).await?;
        if view
            .contribution(self.device)
            .is_none_or(|c| c.service_key != self.service_key)
        {
            return Err(PoolError::Unauthorized);
        }
        state.offers.probe(
            &view,
            self.device,
            u64::try_from(lease.as_millis()).map_err(|_| PoolError::Invalid)?,
            now,
        )
    }
    /// Check a one-use response against the current encrypted pool records.
    ///
    /// # Errors
    /// Refuses stale, replayed, foreign or incorrectly signed observations.
    pub async fn confirm(
        &self,
        probe: &OfferProbe,
        signature: [u8; 64],
    ) -> Result<LiveOffer, PoolError> {
        let mut state = self.state.lock().await;
        let now = self.time(&mut state)?;
        if probe.device != self.device || probe.pool != self.pool {
            return Err(PoolError::Unauthorized);
        }
        let view = state.store.view(now).await?;
        state.offers.confirm(&view, probe, signature)
    }
    /// Refresh bounded grants from real current authority, independently of readiness.
    /// Failure clears the old cache. Cached grants also expire without this task.
    ///
    /// # Errors
    /// Refuses invalidated custody/clock/checkpoints or unreadable control state.
    pub async fn refresh(&self) -> Result<usize, PoolError> {
        let mut state = self.state.lock().await;
        let now = self.time(&mut state)?;
        let result = async {
            let view = state.store.view(now).await?;
            let live = state
                .offers
                .candidates(&view)
                .into_iter()
                .find(|o| o.device == self.device && o.service_key == self.service_key);
            let mut grants = BTreeMap::new();
            if let Some(live) = live {
                for access in self.access.iter() {
                    let Ok(auth) = state
                        .store
                        .authorize(access.requester, self.device, access.target.id, now)
                        .await
                    else {
                        continue;
                    };
                    if auth.service_key != self.service_key
                        || auth.recipient_key != access.target.recipient_key
                    {
                        continue;
                    }
                    let mut grant =
                        auth.relay_grant(now, live.expires.min(self.checkpoint_deadline))?;
                    grant.max_bytes = grant.max_bytes.min(access.target.max_bytes);
                    grants.insert(
                        (access.requester, access.target.id),
                        CachedGrant {
                            grant,
                            not_after_ms: auth.expires_at_ms,
                        },
                    );
                }
            }
            Ok::<_, PoolError>(grants)
        }
        .await;
        match result {
            Ok(grants) => {
                self.time(&mut state)?;
                let count = grants.len();
                *self.snapshot.write().unwrap_or_else(|p| p.into_inner()) = Snapshot {
                    grants,
                    owner_time: now,
                };
                Ok(count)
            }
            Err(error) => {
                self.clear();
                Err(error)
            }
        }
    }
    /// Synchronous live check for Murm's existing forwarding callback.
    pub fn authorize(&self, subject: [u8; 32], request: &RelayRequest) -> Option<RelayGrant> {
        if request.pool != self.pool
            || self.closed.load(Ordering::SeqCst)
            || (self.custody)() != Some(self.epoch)
            || Instant::now() >= self.checkpoint_deadline
        {
            return None;
        }
        let snapshot = self.snapshot.read().unwrap_or_else(|p| p.into_inner());
        let now = (self.clock)()?;
        if now < snapshot.owner_time {
            return None;
        }
        snapshot
            .grants
            .get(&(subject, request.target))
            .filter(|cached| now < cached.not_after_ms && cached.grant.expires > Instant::now())
            .map(|cached| cached.grant)
    }
}
