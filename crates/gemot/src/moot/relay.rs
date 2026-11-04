// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

//! Moot-authorized relay contributions, separate from public record lanes.
//!
//! Group keys come from the host's existing group session. This module adds
//! no group/key manager and forwards no payloads. Native relay operation is a
//! Murm service; I2P host-location privacy remains a separate acceptance gate.

mod offers;
mod store;
#[cfg(test)]
mod tests;
mod view;

use super::MootId;
use identity::IdentityProvider;
use insigne::DerivedKeyAttestation;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use stickleback::DataKeyring;

pub use offers::{ClientOffer, LiveOffer, OfferBook, OfferProbe};
pub use store::{PoolExt, PoolStore};
pub use view::{PoolAuthorization, PoolView};

/// Versioned domain lane, distinct from the public Moot lanes.
pub const RELAY_POOL_LANE: &str = "gemot/relay/private/v1";
/// A host-owned current-key snapshot, reusable with an existing GroupSession.
pub type PoolKeys = Arc<dyn Fn() -> Arc<DataKeyring> + Send + Sync>;

/// An accepted pool definition. Its authority revision is checked at every use.
#[derive(Clone)]
pub struct PoolPolicy {
    /// Community that governs the service.
    pub moot: MootId,
    /// Stable pool identity; independent of a particular contributing device.
    pub pool: [u8; 32],
    /// Private coordination capability/topic, bootstrapped only to operators.
    /// Rotate it with operator-group access changes; never put it in an offer.
    pub coordination: [u8; 32],
    /// Accepted constitution revision, never inferred from arrival order.
    pub constitution_revision: proofs::Digest,
    /// Owner-selected policy revision.
    pub revision: [u8; 32],
    /// Public service signing key, separate from owner/device/root keys.
    pub service_key: [u8; 32],
    /// Bounded retained control history; at most 4096 operations.
    pub max_records: usize,
    /// Ceiling on one contribution's lifetime.
    pub max_lease_ms: u64,
    /// Maximum age of a derived authorization snapshot during partition.
    pub max_authority_age_ms: u64,
    /// Host-verified authority checkpoint deadline. Local reads never renew it.
    /// The host must obtain fresh authority evidence before replacing this policy.
    pub authority_expires_at_ms: u64,
}

/// The bounded resource contribution granted by an owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolContribution {
    /// Unique contribution/device enrollment ID. Withdrawal retires this ID.
    pub device: [u8; 32],
    /// Device service key attested by the contributing owner.
    pub service_key: [u8; 32],
    /// Verifiable scope/root binding, carried only inside encrypted coordination.
    pub device_attestation: DerivedKeyAttestation,
    /// Combined byte ceiling for a forwarded connection.
    pub max_bytes: u64,
    /// Maximum combined bytes per second.
    pub bytes_per_second: u64,
    /// Device's offered active-session ceiling.
    pub max_sessions: u32,
    /// Earliest valid owner time.
    pub not_before_ms: u64,
    /// Latest valid owner time; replay cannot extend it.
    pub expires_at_ms: u64,
}

/// A registered application recipient; contains no arbitrary host/URL/port.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolTarget {
    /// Logical target ID requested by clients.
    pub id: [u8; 32],
    /// Expected end-to-end application key, independently checked by the client.
    pub recipient_key: [u8; 32],
    /// Target's accepted byte ceiling.
    pub max_bytes: u64,
}

/// Retained pool facts. None is a heartbeat or a forwarded application payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PoolEvent {
    /// Device owner explicitly offers bounded carriage.
    Contribute(PoolContribution),
    /// Device owner permanently retires this enrollment ID.
    Withdraw { device: [u8; 32] },
    /// Moot-authorized manager registers one target and its expected key.
    RegisterTarget(PoolTarget),
}

/// Domain-specific failure without secret routes, keys or operation dumps.
#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    /// Malformed, foreign, unreadable or unbound record.
    #[error("invalid private relay record")]
    Invalid,
    /// Missing/stale authority, expiry, withdrawal or unregistered target.
    #[error("relay authority unavailable")]
    Unauthorized,
    /// Retained control history reached its explicit ceiling.
    #[error("relay control capacity exhausted")]
    Capacity,
    /// Unavailable or inconsistent retained history.
    #[error("relay control storage failed")]
    Storage,
}

/// Stable capability scope for one pool; actions never imply one another.
pub fn relay_cap(pool: [u8; 32], action: &str) -> Result<servitor::Cap, PoolError> {
    if !matches!(action, "contribute" | "manage" | "use") {
        return Err(PoolError::Invalid);
    }
    let id: String = pool.iter().map(|byte| format!("{byte:02x}")).collect();
    servitor::Cap::scope(&format!("moot/relay/{id}/{action}")).map_err(|_| PoolError::Invalid)
}

fn record_salt(pool: [u8; 32], event: &PoolEvent) -> Vec<u8> {
    // Separate per-device actor logs let one persona contribute several
    // devices concurrently without sharing one p2panda sequence counter.
    let (kind, id) = match event {
        PoolEvent::Contribute(c) => (b"device/".as_slice(), c.device),
        PoolEvent::Withdraw { device } => (b"withdraw/".as_slice(), *device),
        PoolEvent::RegisterTarget(target) => (b"target/".as_slice(), target.id),
    };
    [b"gemot/relay/record/v1/".as_slice(), &pool, kind, &id].concat()
}

/// Domain-separated service key for a specific device enrollment.
pub fn device_salt(pool: [u8; 32], device: [u8; 32]) -> Vec<u8> {
    [b"gemot/relay/device/v1/".as_slice(), &pool, &device].concat()
}

impl PoolContribution {
    /// Bind the caller's explicit resource offer to its scoped device key.
    pub fn attest<I: IdentityProvider + ?Sized>(
        identity: &I,
        pool: [u8; 32],
        device: [u8; 32],
        max_bytes: u64,
        bytes_per_second: u64,
        max_sessions: u32,
        not_before_ms: u64,
        expires_at_ms: u64,
    ) -> Result<Self, PoolError> {
        let salt = device_salt(pool, device);
        let key = identity
            .derive_keypair(&salt)
            .map_err(|_| PoolError::Invalid)?;
        let device_attestation = identity
            .attest_derived_key(&salt)
            .map_err(|_| PoolError::Invalid)?;
        Ok(Self {
            device,
            service_key: key.public_key().to_bytes(),
            device_attestation,
            max_bytes,
            bytes_per_second,
            max_sessions,
            not_before_ms,
            expires_at_ms,
        })
    }
}
