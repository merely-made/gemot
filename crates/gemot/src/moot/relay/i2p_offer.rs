// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

//! Public I2P service faces contain service keys, never contributor ancestry.
use super::{PoolError, PoolPolicy, PoolTarget};
use identity::{Ed25519Keypair, Ed25519PublicKey, Ed25519Signature, IdentityProvider};
use murm::relay::{
    RelayRequest,
    i2p::{I2pAddress, I2pRelayChannel, I2pRelayStream, I2pRoute, I2pSession},
};
use p2panda_core::cbor::encode_cbor;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::Instant;

/// A separately signed I2P-only offer. The sponsoring pool is deliberately
/// public; an opaque worker key has no included owner-root attestation chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct I2pClientOffer {
    /// Stable service identity.
    pub pool: [u8; 32],
    /// Public service alias, independent of the private device enrollment ID.
    pub alias: [u8; 32],
    /// Registered application target.
    pub target: [u8; 32],
    /// Expected worker's scoped Noise service key.
    pub worker_key: [u8; 32],
    /// Expected recipient's independent inner session key.
    pub recipient_key: [u8; 32],
    /// Canonical `.b32.i2p` locator; cannot contain an IP, ticket, URL or port.
    pub destination: String,
    /// Owner-clock expiry. Clients also enforce their configured maximum lease.
    pub expires_at_ms: u64,
}

impl I2pClientOffer {
    fn bytes(&self) -> Result<Vec<u8>, PoolError> {
        I2pAddress::parse(&self.destination).map_err(|_| PoolError::Invalid)?;
        let bytes = encode_cbor(self).map_err(|_| PoolError::Invalid)?;
        Ok([b"gemot/relay/client/i2p/v1/".as_slice(), &bytes].concat())
    }
    /// Sign with the pool service key, without exporting its private custody.
    ///
    /// # Errors
    /// Refuses a foreign pool/key or noncanonical locator.
    pub fn sign(&self, policy: &PoolPolicy, key: &Ed25519Keypair) -> Result<[u8; 64], PoolError> {
        if self.pool != policy.pool || key.public_key().to_bytes() != policy.service_key {
            return Err(PoolError::Unauthorized);
        }
        Ok(key.sign(&self.bytes()?).to_bytes())
    }
    /// Verify a persisted/wire offer, binding its remaining bounded lifetime to
    /// this receiver's monotonic clock. Reload always requires verification.
    /// `recipient` must come from independent application trust, never be
    /// copied from this offer. Pool signing authority cannot replace that key.
    ///
    /// # Errors
    /// Refuses bad signatures, foreign pools, expired/excessive leases or locators.
    pub fn verify(
        &self,
        pool: [u8; 32],
        service_key: [u8; 32],
        signature: [u8; 64],
        recipient: &PoolTarget,
        now_ms: u64,
        max_lease_ms: u64,
    ) -> Result<VerifiedI2pOffer, PoolError> {
        let remaining = self
            .expires_at_ms
            .checked_sub(now_ms)
            .filter(|remaining| *remaining > 0 && *remaining <= max_lease_ms)
            .ok_or(PoolError::Unauthorized)?;
        let key = Ed25519PublicKey::from_bytes(&service_key).map_err(|_| PoolError::Invalid)?;
        if self.pool != pool
            || self.target != recipient.id
            || self.recipient_key != recipient.recipient_key
            || !key.verify(&self.bytes()?, &Ed25519Signature::from_bytes(&signature))
        {
            return Err(PoolError::Unauthorized);
        }
        Ok(VerifiedI2pOffer {
            route: I2pRoute {
                address: I2pAddress::parse(&self.destination).map_err(|_| PoolError::Invalid)?,
                service_key: self.worker_key,
            },
            request: RelayRequest {
                pool: self.pool,
                target: self.target,
            },
            recipient_key: recipient.recipient_key,
            expires: Instant::now()
                .checked_add(Duration::from_millis(remaining))
                .ok_or(PoolError::Invalid)?,
        })
    }
}

/// Locally verified routing capability. It has no native route alternative and
/// is deliberately not serializable; persisted offers must be checked again.
pub struct VerifiedI2pOffer {
    route: I2pRoute,
    request: RelayRequest,
    recipient_key: [u8; 32],
    expires: Instant,
}
impl std::fmt::Debug for VerifiedI2pOffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedI2pOffer { profile: i2p, private }")
    }
}
impl VerifiedI2pOffer {
    /// Key required by the application's independent inner session.
    pub fn recipient_key(&self) -> [u8; 32] {
        self.recipient_key
    }
    /// Open exclusively through the selected I2P profile, under the original
    /// offer deadline. Failure does not invoke another transport or replay data.
    ///
    /// # Errors
    /// Refuses expiry or unsuccessful I2P/security/admission/routing setup.
    pub async fn open<I: IdentityProvider>(
        &self,
        channel: &I2pRelayChannel,
        session: &I2pSession,
        key: &Ed25519Keypair,
        credentials: murm::Credentials<'_, I>,
    ) -> Result<I2pRelayStream, PoolError> {
        if Instant::now() >= self.expires {
            return Err(PoolError::Unauthorized);
        }
        tokio::time::timeout_at(
            self.expires,
            channel.open(session, &self.route, key, credentials, self.request),
        )
        .await
        .map_err(|_| PoolError::Unauthorized)?
        .map_err(|_| PoolError::Unauthorized)
    }
}
