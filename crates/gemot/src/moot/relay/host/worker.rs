// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

use super::{PoolError, WorkerAuthority};
use identity::{Ed25519Keypair, IdentityProvider};
use muniment::Backend;
use murm::relay::i2p::{I2pRelayService, I2pRoute, I2pSession};
use murm::relay::{DeviceBudget, DeviceStats, FlowLimits};
use murm::{Admission, Credentials};
use notochord::{
    LocalNetworkPolicy, NetworkId, ProfileRef, RequestedAction, RevocationLedger,
    SecureIdentityPolicy, TrafficClass,
};
use std::{future::Future, sync::Arc, time::Duration};
use tokio::{
    task::JoinSet,
    time::{sleep, timeout},
};
use transport::security::SetupLimits;
use transport::security::{ServiceSecurityPolicy, SetupGate};

/// Explicit admission policy for the existing I2P relay application profile.
pub struct WorkerAdmission {
    /// Inbound Notochord policy, supplied by its owner.
    pub policy: Arc<LocalNetworkPolicy>,
    /// Current revocation ledger, shared with the authority owner.
    pub ledger: Arc<RevocationLedger>,
    /// Secure identity policy; SAM still contributes no carrier identity.
    pub identity: SecureIdentityPolicy,
    /// Outbound application profile.
    pub profile: ProfileRef,
    /// Requested recipient service action.
    pub action: RequestedAction,
    /// Host-selected traffic class.
    pub class: TrafficClass,
    /// Existing session-signer salt for the recipient's secure identity policy.
    /// This key stays on the private outgoing leg, distinct from the public worker key.
    pub outbound_key_salt: Vec<u8>,
}
/// Bounded task ownership. There is at most one additional pending SAM ACCEPT.
#[derive(Clone, Copy)]
pub struct WorkerLimits {
    /// Maximum combined setup/forwarding child tasks, between 1 and 256.
    pub max_tasks: usize,
    /// Interval between local authority reads; never renews the checkpoint.
    pub refresh_interval: Duration,
    /// One refresh's storage/authority deadline.
    pub refresh_timeout: Duration,
    /// Deadline for awaiting aborted children, at most 300 seconds.
    pub shutdown_timeout: Duration,
}
impl WorkerLimits {
    /// Validate task/time bounds before accepting any work.
    ///
    /// # Errors
    /// Refuses invalid task counts, zero durations or overflowing deadlines.
    pub fn validate(&self) -> Result<(), PoolError> {
        if self.max_tasks == 0
            || self.max_tasks > 256
            || self.refresh_interval.is_zero()
            || self.refresh_timeout.is_zero()
            || self.shutdown_timeout.is_zero()
            || self.shutdown_timeout > Duration::from_secs(300)
            || [
                self.refresh_interval,
                self.refresh_timeout,
                self.shutdown_timeout,
            ]
            .iter()
            .any(|duration| tokio::time::Instant::now().checked_add(*duration).is_none())
        {
            return Err(PoolError::Invalid);
        }
        Ok(())
    }
}
/// Why a host-owned worker ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkerStop {
    /// The owner supplied its stop signal.
    Requested,
    /// SAM parent session ended.
    Provider,
    /// Custody, clock, checkpoint or storage became unavailable.
    Authority,
    /// A bounded authority refresh did not finish.
    RefreshTimeout,
}
/// Counter-only shutdown receipt, without routes, lineage or payloads.
#[derive(Clone, Copy, Debug)]
pub struct WorkerReport {
    pub reason: WorkerStop,
    pub accepted: u64,
    pub completed: u64,
    pub refused: u64,
    /// False means this must not be reported as clean shutdown.
    pub drained: bool,
    pub device: DeviceStats,
}

/// Reusable I2P worker composition. The runner supplies process/configuration,
/// existing custody and sync lifetime, and awaits `run` at shutdown.
pub struct I2pWorker<B: Backend + Clone, I: IdentityProvider> {
    authority: WorkerAuthority<B>,
    session: I2pSession,
    service: Arc<I2pRelayService>,
    device: DeviceBudget,
    provider: Arc<I>,
    service_key: Arc<Ed25519Keypair>,
    target_key: Arc<Ed25519Keypair>,
    admission: Arc<WorkerAdmission>,
}
impl<B: Backend + Clone, I: IdentityProvider> Drop for I2pWorker<B, I> {
    fn drop(&mut self) {
        self.authority.close();
    }
}
impl<B, I> I2pWorker<B, I>
where
    B: Backend + Clone + Send + Sync + 'static,
    I: IdentityProvider + 'static,
{
    /// Compose existing services; this creates no router, endpoint or group manager.
    ///
    /// # Errors
    /// Refuses unavailable/scoped custody, mismatched routes and invalid limits.
    #[expect(
        clippy::too_many_arguments,
        reason = "Existing authority, custody and resource owners are injected separately"
    )]
    pub fn new(
        authority: WorkerAuthority<B>,
        session: I2pSession,
        targets: Vec<([u8; 32], I2pRoute)>,
        device: DeviceBudget,
        flow: FlowLimits,
        setup: SetupLimits,
        provider: Arc<I>,
        admission: WorkerAdmission,
    ) -> Result<Self, PoolError> {
        let security = ServiceSecurityPolicy::noise(
            transport::Alpn::from_bytes(murm::relay::i2p::I2P_RELAY_PROTOCOL.to_vec()),
            None,
            setup.clone(),
        );
        drop(
            SetupGate::new(1)
                .reserve(&security)
                .map_err(|_| PoolError::Invalid)?,
        );
        let key = provider
            .derive_keypair(&crate::moot::relay::device_salt(
                authority.pool,
                authority.device,
            ))
            .map_err(|_| PoolError::Unauthorized)?;
        if admission.outbound_key_salt.is_empty() {
            return Err(PoolError::Invalid);
        }
        let target_key = provider
            .derive_keypair(&admission.outbound_key_salt)
            .map_err(|_| PoolError::Unauthorized)?;
        if key.public_key().to_bytes() != authority.service_key
            || !session.is_alive()
            || authority
                .access
                .iter()
                .any(|a| !targets.iter().any(|(id, _)| *id == a.target.id))
        {
            return Err(PoolError::Unauthorized);
        }
        let service = I2pRelayService::new(
            authority.pool,
            session.clone(),
            targets,
            device.clone(),
            flow,
            setup,
        )
        .map_err(|_| PoolError::Invalid)?;
        Ok(Self {
            authority,
            session,
            service: Arc::new(service),
            device,
            provider,
            service_key: Arc::new(key),
            target_key: Arc::new(target_key),
            admission: Arc::new(admission),
        })
    }
    /// Serve until owner stop or loss of its current provider/authority binding.
    /// Stream refusals are counted; sensitive underlying errors are not emitted.
    ///
    /// # Errors
    /// Refuses invalid lifecycle bounds before entering the accept loop.
    pub async fn run(
        self,
        limits: WorkerLimits,
        stop: impl Future<Output = ()>,
    ) -> Result<WorkerReport, PoolError> {
        limits.validate()?;
        let mut tasks = JoinSet::new();
        let mut next_accept = Box::pin(self.session.accept());
        let refresh = || {
            let authority = self.authority.clone();
            async move {
                sleep(limits.refresh_interval).await;
                timeout(limits.refresh_timeout, authority.refresh()).await
            }
        };
        let mut refreshing = Box::pin(refresh());
        tokio::pin!(stop);
        let (mut accepted, mut completed, mut refused) = (0u64, 0u64, 0u64);
        let reason = loop {
            tokio::select! {
                _ = &mut stop => break WorkerStop::Requested,
                _ = self.session.closed() => break WorkerStop::Provider,
                result = &mut refreshing => {
                    match result {
                        Err(_) => break WorkerStop::RefreshTimeout,
                        Ok(Err(_)) => break WorkerStop::Authority,
                        Ok(Ok(_)) => refreshing = Box::pin(refresh()),
                    }
                },
                incoming = &mut next_accept, if tasks.len() < limits.max_tasks => {
                    let Ok(stream) = incoming else { break WorkerStop::Provider };
                    next_accept = Box::pin(self.session.accept());
                    accepted = accepted.saturating_add(1);
                    let (service,provider,key,target_key,admission,authority,device) = (
                        self.service.clone(),self.provider.clone(),self.service_key.clone(),
                        self.target_key.clone(),
                        self.admission.clone(),self.authority.clone(),self.device.clone());
                    tasks.spawn(async move {
                        let Some(now_ms) = (authority.clock)() else { return false };
                        let credentials = Credentials { identity: provider.as_ref(),
                            network:NetworkId(authority.pool),profile:admission.profile.clone(),
                            action:admission.action.clone(),class:admission.class,
                            nonce:Ed25519Keypair::generate().public_key().to_bytes(),delegations:vec![] };
                        let result = service.serve(stream,&key,Admission { policy:&admission.policy,
                            ledger:&admission.ledger,identity:admission.identity, now_ms,
                            active_sessions:device.stats().active as u32 },&target_key,credentials,
                            |principal,request| authority.authorize(principal.subject,request)).await;
                        #[cfg(test)]
                        if let Err(error) = &result { eprintln!("MURM_HOST_REFUSAL {error}"); }
                        result.is_ok()
                    });
                },
                result = tasks.join_next(), if !tasks.is_empty() => {
                    match result { Some(Ok(true)) => completed = completed.saturating_add(1),
                        _ => refused = refused.saturating_add(1) }
                },
            }
        };
        self.authority.close();
        let drained = timeout(limits.shutdown_timeout, tasks.shutdown())
            .await
            .is_ok();
        Ok(WorkerReport {
            reason,
            accepted,
            completed,
            refused,
            drained,
            device: self.device.stats(),
        })
    }
}
