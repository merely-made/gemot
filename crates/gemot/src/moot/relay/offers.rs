// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

use super::{PoolError, PoolPolicy, PoolView};
use identity::{Ed25519Keypair, Ed25519PublicKey, Ed25519Signature};
use p2panda_core::cbor::encode_cbor;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;
use tokio::time::Instant;

/// Fresh challenge for one known contribution. Never persisted as availability.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OfferProbe {
    /// Exact pool and enrollment scope.
    pub pool: [u8; 32],
    /// Device enrollment ID.
    pub device: [u8; 32],
    /// Unpredictable one-use challenge, replaced on every probe.
    pub nonce: [u8; 32],
    /// Requested bounded availability duration.
    pub lease_ms: u64,
}

impl OfferProbe {
    /// Exact bytes the contribution's attested service key signs.
    pub fn signing_bytes(&self) -> Vec<u8> {
        [
            b"gemot/relay/liveness/v1/".as_slice(),
            &encode_cbor(self).expect("fixed offer probe"),
        ]
        .concat()
    }
}

/// An observed live offer, bound to one receiver's monotonic clock.
#[derive(Clone, Copy, Debug)]
pub struct LiveOffer {
    /// Exact pool checked by the challenge response.
    pub pool: [u8; 32],
    /// Enrollment ID, disclosed only to the coordination audience.
    pub device: [u8; 32],
    /// Key that proved liveness; a changed enrollment requires another probe.
    pub service_key: [u8; 32],
    /// Last moment this observation can route new work.
    pub expires: Instant,
}

/// Disposable, bounded liveness state. Reconstructing control history creates
/// an empty book; a captured response cannot revive an earlier probe.
#[derive(Default)]
pub struct OfferBook {
    pending: BTreeMap<[u8; 32], (OfferProbe, Instant, u64)>,
    live: BTreeMap<[u8; 32], LiveOffer>,
}

impl OfferBook {
    /// Probe only a currently authorized device. The caller supplies current
    /// owner time; freshness uses this receiver's monotonic clock.
    pub fn probe(
        &mut self,
        view: &PoolView,
        device: [u8; 32],
        lease_ms: u64,
        now_ms: u64,
    ) -> Result<OfferProbe, PoolError> {
        let contribution = view.contribution(device).ok_or(PoolError::Unauthorized)?;
        let lease_ms = lease_ms.min(contribution.expires_at_ms.saturating_sub(now_ms));
        if lease_ms == 0 {
            return Err(PoolError::Unauthorized);
        }
        // Existing cryptographic identity provider supplies OS-backed entropy.
        let nonce = Ed25519Keypair::generate().public_key().to_bytes();
        let probe = OfferProbe {
            pool: view.pool,
            device,
            nonce,
            lease_ms,
        };
        self.pending
            .insert(device, (probe.clone(), Instant::now(), now_ms));
        Ok(probe)
    }

    /// Verify a one-use service-key response against the current authorized view.
    pub fn confirm(
        &mut self,
        view: &PoolView,
        probe: &OfferProbe,
        signature: [u8; 64],
    ) -> Result<LiveOffer, PoolError> {
        let (pending, started, _) = self
            .pending
            .get(&probe.device)
            .ok_or(PoolError::Unauthorized)?;
        if pending != probe || probe.pool != view.pool {
            return Err(PoolError::Unauthorized);
        }
        let contribution = view
            .contribution(probe.device)
            .ok_or(PoolError::Unauthorized)?;
        let key = Ed25519PublicKey::from_bytes(&contribution.service_key)
            .map_err(|_| PoolError::Invalid)?;
        if !key.verify(
            &probe.signing_bytes(),
            &Ed25519Signature::from_bytes(&signature),
        ) {
            return Err(PoolError::Unauthorized);
        }
        let expires = started
            .checked_add(Duration::from_millis(probe.lease_ms))
            .ok_or(PoolError::Invalid)?;
        let offer = LiveOffer {
            pool: probe.pool,
            device: probe.device,
            service_key: contribution.service_key,
            expires,
        };
        if Instant::now() >= offer.expires {
            return Err(PoolError::Unauthorized);
        }
        self.pending.remove(&probe.device);
        self.live.insert(probe.device, offer);
        Ok(offer)
    }

    /// Available workers in stable order, always intersected with current authority.
    pub fn candidates(&self, view: &PoolView) -> Vec<LiveOffer> {
        self.live
            .values()
            .filter(|offer| {
                offer.pool == view.pool
                    && offer.expires > Instant::now()
                    && view
                        .contribution(offer.device)
                        .is_some_and(|c| c.service_key == offer.service_key)
            })
            .copied()
            .collect()
    }

    /// Forget a failed worker locally; new work may select another live worker.
    pub fn failed(&mut self, device: [u8; 32]) {
        self.live.remove(&device);
        self.pending.remove(&device);
    }
}

/// Sanitized client-visible profile. Native P1 explicitly exposes its host route.
/// It carries no member/owner attestation or coordination history.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientOffer {
    /// Stable service identity.
    pub pool: [u8; 32],
    /// Deliberately disclosed opaque alias, not a device enrollment ID.
    pub alias: [u8; 32],
    /// Approved application target.
    pub target: [u8; 32],
    /// Expected recipient key for the inner session.
    pub recipient_key: [u8; 32],
    /// Deliberately disclosed native route, bounded to 4096 bytes.
    pub native_route: String,
    /// Host-visible native profile; never advertised as I2P/host-hidden.
    pub native_host_visible: bool,
    /// Explicit expiry; no perpetual promise of availability.
    pub expires_at_ms: u64,
}

impl ClientOffer {
    /// Sign only with the pool's authorized public service key.
    pub fn sign(&self, policy: &PoolPolicy, key: &Ed25519Keypair) -> Result<[u8; 64], PoolError> {
        if self.pool != policy.pool
            || key.public_key().to_bytes() != policy.service_key
            || !self.native_host_visible
            || self.native_route.is_empty()
            || self.native_route.len() > 4096
        {
            return Err(PoolError::Unauthorized);
        }
        let bytes = encode_cbor(self).map_err(|_| PoolError::Invalid)?;
        Ok(key
            .sign(&[b"gemot/relay/client/v1/".as_slice(), &bytes].concat())
            .to_bytes())
    }

    /// Validate an offer against the pool key already trusted by the client.
    pub fn verify(
        &self,
        pool: [u8; 32],
        service_key: [u8; 32],
        signature: [u8; 64],
        now_ms: u64,
    ) -> Result<(), PoolError> {
        if self.pool != pool
            || !self.native_host_visible
            || self.expires_at_ms <= now_ms
            || self.native_route.is_empty()
            || self.native_route.len() > 4096
        {
            return Err(PoolError::Unauthorized);
        }
        let bytes = encode_cbor(self).map_err(|_| PoolError::Invalid)?;
        let key = Ed25519PublicKey::from_bytes(&service_key).map_err(|_| PoolError::Invalid)?;
        if !key.verify(
            &[b"gemot/relay/client/v1/".as_slice(), &bytes].concat(),
            &Ed25519Signature::from_bytes(&signature),
        ) {
            return Err(PoolError::Unauthorized);
        }
        Ok(())
    }
}
