// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

//! Operator-private endpoint bindings using existing Personae attestations.
use super::PoolError;
use insigne::DerivedKeyAttestation;
use serde::{Deserialize, Serialize};

/// Scope distinct from the public I2P worker key and from Personae roots.
pub fn control_salt(pool: [u8; 32], device: [u8; 32]) -> Vec<u8> {
    [b"gemot/relay/control/v1/".as_slice(), &pool, &device].concat()
}
/// Private bootstrap input. Never include this lineage in a client offer.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlPeer {
    pub device: [u8; 32],
    pub attestation: DerivedKeyAttestation,
}
impl ControlPeer {
    pub(crate) fn binding(&self, pool: [u8; 32]) -> Result<([u8; 32], [u8; 32]), PoolError> {
        let checked = self
            .attestation
            .check(&control_salt(pool, self.device))
            .map_err(|_| PoolError::Invalid)?;
        Ok((*checked.derived(), *checked.master()))
    }
}
