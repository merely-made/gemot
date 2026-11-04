// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The published-site handoff: Knot's contract with a resident that keeps
//! serving a completed snapshot after Knot exits.
//!
//! Knot selects a completed immutable snapshot and uploads it in bounded
//! chunks on the resident's [`PUBLISHED_SITE_ROUTE`]. The resident copies it
//! into its own custody and owns the Gemini listener afterwards. These types
//! are the intents and payloads both sides name; the listener is the
//! resident's.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

/// The resident route a handoff runs on.
pub const PUBLISHED_SITE_ROUTE: &str = "published-site-v1";
/// The projection session the route's intents address.
pub const PUBLISHED_SITE_SESSION: &str = "djinn.published-site/v1";
pub const PUBLISHED_SITE_PREPARE_INTENT: &str = "djinn.published-site.prepare";
pub const PUBLISHED_SITE_CHUNK_INTENT: &str = "djinn.published-site.chunk";
pub const PUBLISHED_SITE_COMMIT_INTENT: &str = "djinn.published-site.commit";
pub const PUBLISHED_SITE_STOP_INTENT: &str = "djinn.published-site.stop";
pub const PUBLISHED_SITE_REMOVE_INTENT: &str = "djinn.published-site.remove";
/// Largest upload chunk, below the application door's message cap.
pub const MAX_PUBLISHED_SITE_UPLOAD_CHUNK_BYTES: usize = 64 * 1024;
/// Most concurrent Gemini connections a listener policy may ask for.
pub const MAX_GEMINI_CONNECTIONS: u16 = 32;
/// Longest Gemini request timeout a listener policy may ask for.
pub const MAX_GEMINI_TIMEOUT_MS: u64 = 30_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeminiListenerPolicyV1 {
    /// A loopback port. Zero asks the OS for one on each start.
    pub port: u16,
    pub max_connections: u16,
    pub request_timeout_ms: u64,
    /// Serving resumes after a resident restart only when this is explicitly true.
    pub resume_on_restart: bool,
}

impl Default for GeminiListenerPolicyV1 {
    fn default() -> Self {
        Self {
            port: 0,
            max_connections: 8,
            request_timeout_ms: 2_000,
            resume_on_restart: false,
        }
    }
}

impl GeminiListenerPolicyV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.max_connections == 0 || self.max_connections > MAX_GEMINI_CONNECTIONS {
            return Err(format!(
                "Gemini max_connections must be 1–{MAX_GEMINI_CONNECTIONS}"
            ));
        }
        if self.request_timeout_ms == 0 || self.request_timeout_ms > MAX_GEMINI_TIMEOUT_MS {
            return Err(format!(
                "Gemini request_timeout_ms must be 1–{MAX_GEMINI_TIMEOUT_MS}"
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PublishedSiteStateV1 {
    Unavailable,
    Stopped {
        snapshot_digest: [u8; 32],
    },
    Serving {
        snapshot_digest: [u8; 32],
        address: SocketAddr,
        certificate_sha256: [u8; 32],
    },
}

/// Read-only status returned through the route's typed snapshot resource.
/// `resume_on_restart` is policy, separate from the current state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishedSiteStatusV1 {
    pub version: u8,
    pub state: PublishedSiteStateV1,
    pub resume_on_restart: bool,
    /// A descriptor was removed but its custody lease release must be retried.
    pub retained_custody: Option<[u8; 32]>,
}

/// A framed upload is intentionally bounded below the app-door message cap.
/// The resident holds incomplete bytes only in session memory and never
/// writes a descriptor until `commit` verifies the complete snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishedSitePrepareV1 {
    pub snapshot_digest: [u8; 32],
    pub total_bytes: u64,
    pub chunks: u32,
    pub policy: GeminiListenerPolicyV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishedSiteChunkV1 {
    pub index: u32,
    pub bytes: Vec<u8>,
}

impl PublishedSitePrepareV1 {
    /// Prepare `snapshot`'s encoded bytes for upload under `policy`.
    pub fn for_snapshot(snapshot: &[u8], policy: GeminiListenerPolicyV1) -> Self {
        Self {
            snapshot_digest: *blake3::hash(snapshot).as_bytes(),
            total_bytes: snapshot.len() as u64,
            chunks: snapshot.len().div_ceil(MAX_PUBLISHED_SITE_UPLOAD_CHUNK_BYTES) as u32,
            policy,
        }
    }
}

/// `snapshot`'s encoded bytes as the chunks a handoff uploads, in order.
pub fn upload_chunks(snapshot: &[u8]) -> impl Iterator<Item = PublishedSiteChunkV1> + '_ {
    snapshot
        .chunks(MAX_PUBLISHED_SITE_UPLOAD_CHUNK_BYTES)
        .enumerate()
        .map(|(index, bytes)| PublishedSiteChunkV1 {
            index: index as u32,
            bytes: bytes.to_vec(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_prepared_upload_names_every_chunk() {
        let snapshot = vec![7u8; MAX_PUBLISHED_SITE_UPLOAD_CHUNK_BYTES * 2 + 1];
        let prepare = PublishedSitePrepareV1::for_snapshot(&snapshot, GeminiListenerPolicyV1::default());
        let chunks: Vec<_> = upload_chunks(&snapshot).collect();
        assert_eq!(prepare.chunks as usize, chunks.len());
        assert_eq!(prepare.total_bytes as usize, snapshot.len());
        assert_eq!(chunks.last().unwrap().bytes.len(), 1);
        assert_eq!(prepare.snapshot_digest, *blake3::hash(&snapshot).as_bytes());
    }

    #[test]
    fn listener_policy_bounds_hold() {
        assert!(GeminiListenerPolicyV1::default().validate().is_ok());
        let wide = GeminiListenerPolicyV1 {
            max_connections: MAX_GEMINI_CONNECTIONS + 1,
            ..Default::default()
        };
        assert!(wide.validate().is_err());
        let slow = GeminiListenerPolicyV1 {
            request_timeout_ms: 0,
            ..Default::default()
        };
        assert!(slow.validate().is_err());
    }
}
