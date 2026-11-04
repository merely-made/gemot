// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Reticulum-independent Micron request preparation.
//!
//! Local form editing remains available, but preparing or sending a network
//! request reports that the optional backend is unavailable.

use std::{collections::BTreeMap, net::SocketAddr, time::Duration};

/// Request bounds retained by backend-free builds. The optional `retinue`
/// implementation also exposes its Reticulum-specific `map_limits` field.
#[derive(Clone, Copy, Debug)]
pub struct MicronSubmissionConfig {
    pub timeout: Duration,
    pub max_response_bytes: usize,
}

impl Default for MicronSubmissionConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_response_bytes: 4 * 1024 * 1024,
        }
    }
}

pub struct PreparedMicronRequest {
    target: String,
}

pub struct MicronResponse {
    pub body: Vec<u8>,
}

impl PreparedMicronRequest {
    pub fn new(
        _target: String,
        _values: BTreeMap<String, String>,
        _config: MicronSubmissionConfig,
    ) -> Result<Self, String> {
        Err("Micron request preparation is unavailable; rebuild with the optional `retinue` feature".into())
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub async fn send(
        self,
        _interface: SocketAddr,
        _config: MicronSubmissionConfig,
    ) -> Result<MicronResponse, String> {
        Err(
            "Micron network requests are unavailable; rebuild with the optional `retinue` feature"
                .into(),
        )
    }
}
