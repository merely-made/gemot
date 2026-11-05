// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Clips as editions, opened by address and republished as forks.
//!
//! A clip edition names a [`ClipPayloadV1`] by digest. Until blob manifests
//! land (murm runtime plan M12) the payload is one blob and its blake3 digest
//! stands in for the manifest root. [`open_clip`] verifies the author's log from
//! the address key alone and checks the payload against the edition. A reader
//! who republishes does not inherit the author's authority: [`fork_body`]
//! starts a new log under the republisher's own key whose first edition names
//! the source in `fork_of`. Signing and key custody stay with the caller.

use std::fmt;

use serde::{Deserialize, Serialize};
use stickleback::edition::{
    ContentRef, Edition, EditionBody, EditionError, EditionId, EditionKind, EditionLimits,
    EditionOperation, EditionWriter, Provenance, verify_edition_chain,
};

use crate::address::{AddressHost, KnotAddress};

/// Path a clip edition's address uses.
pub const CLIP_PATH: &str = "clip";
/// Upper bound on an encoded clip payload.
pub const MAX_CLIP_BYTES: usize = 1_048_576;

/// What a clip captured, and where from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipPayloadV1 {
    pub version: u8,
    /// The page the clip was taken from. Republishing keeps it.
    pub source_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
    /// The captured passage as a Knot body.
    pub knot_body: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ClipError {
    Edition(EditionError),
    /// The address names a Moot anchor; governed clips are not opened here.
    Governed,
    /// The address pins an edition the supplied evidence does not hold.
    PinNotInEvidence,
    NotAClip,
    /// The payload bytes are not the ones the edition names.
    PayloadMismatch,
    Payload(String),
}

impl fmt::Display for ClipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Edition(e) => e.fmt(f),
            Self::Governed => f.write_str("A Moot-anchored address is opened through its Moot"),
            Self::PinNotInEvidence => f.write_str("The pinned edition is not in the evidence"),
            Self::NotAClip => f.write_str("The edition is not a clip"),
            Self::PayloadMismatch => f.write_str("The clip payload does not match the edition"),
            Self::Payload(e) => write!(f, "Clip payload refused: {e}"),
        }
    }
}
impl std::error::Error for ClipError {}

impl From<EditionError> for ClipError {
    fn from(error: EditionError) -> Self {
        Self::Edition(error)
    }
}

impl ClipPayloadV1 {
    pub fn new(source_url: &str, title: Option<&str>, selector: Option<&str>, body: &str) -> Self {
        Self {
            version: 1,
            source_url: source_url.into(),
            title: title.map(Into::into),
            selector: selector.map(Into::into),
            knot_body: body.into(),
        }
    }

    /// Canonical bytes.
    ///
    /// # Errors
    /// Refuses a payload over [`MAX_CLIP_BYTES`] or with an empty source.
    pub fn encode(&self) -> Result<Vec<u8>, ClipError> {
        if self.version != 1 || self.source_url.is_empty() {
            return Err(ClipError::Payload(
                "unsupported version or empty source".into(),
            ));
        }
        let bytes = serde_json::to_vec(self).map_err(|e| ClipError::Payload(e.to_string()))?;
        if bytes.len() > MAX_CLIP_BYTES {
            return Err(ClipError::Payload("exceeds the byte limit".into()));
        }
        Ok(bytes)
    }

    /// Decode exact canonical bytes.
    ///
    /// # Errors
    /// Refuses oversized, malformed or non-canonical bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, ClipError> {
        if bytes.len() > MAX_CLIP_BYTES {
            return Err(ClipError::Payload("exceeds the byte limit".into()));
        }
        let payload: Self =
            serde_json::from_slice(bytes).map_err(|e| ClipError::Payload(e.to_string()))?;
        if payload.encode()? != bytes {
            return Err(ClipError::Payload("not canonically encoded".into()));
        }
        Ok(payload)
    }

    /// The digest an edition names this payload by.
    ///
    /// # Errors
    /// As [`Self::encode`].
    pub fn digest(&self) -> Result<EditionId, ClipError> {
        Ok(EditionId(*blake3::hash(&self.encode()?).as_bytes()))
    }
}

/// The body of a clip's first edition in a fresh log.
///
/// # Errors
/// As [`ClipPayloadV1::digest`].
pub fn clip_body(
    payload: &ClipPayloadV1,
    tool: &str,
    created_ms: u64,
) -> Result<EditionBody, ClipError> {
    Ok(EditionBody {
        kind: EditionKind::Clip,
        content: ContentRef::Manifest {
            root: payload.digest()?,
        },
        provenance: Provenance {
            source: tool.into(),
            created_ms,
        },
        fork_of: None,
        hints: Vec::new(),
        sealed: None,
    })
}

impl KnotAddress {
    /// The address of one clip edition, for Copy link.
    pub fn for_clip(key: [u8; 32], edition: EditionId) -> Self {
        Self {
            host: AddressHost::LogKey(key),
            path: CLIP_PATH.into(),
            pin: Some(edition.0),
        }
    }
}

/// A clip edition opened by address under a verified log.
#[derive(Clone, Debug)]
pub struct ClipFrame {
    pub key: [u8; 32],
    pub edition: Edition,
    pub payload: ClipPayloadV1,
}

/// Open the edition `address` names (the newest in the evidence when unpinned).
/// A Moot-anchored address is refused here.
///
/// # Errors
/// Refuses unverifiable evidence, a missing pin, a non-clip edition or payload
/// bytes that are not the ones the edition names.
pub fn open_clip(
    address: &KnotAddress,
    operations: &[EditionOperation],
    payload_bytes: &[u8],
) -> Result<ClipFrame, ClipError> {
    let key = *address.log_key().ok_or(ClipError::Governed)?;
    let chain = verify_edition_chain(&key, operations, EditionLimits::default())?;
    let edition = match address.pin {
        Some(pin) => chain
            .get(&EditionId(pin))
            .ok_or(ClipError::PinNotInEvidence)?,
        None => chain.head(),
    };
    let ContentRef::Manifest { root } = edition.body.content else {
        return Err(ClipError::NotAClip);
    };
    if edition.body.kind != EditionKind::Clip {
        return Err(ClipError::NotAClip);
    }
    let payload = ClipPayloadV1::decode(payload_bytes)?;
    if payload.digest()? != root {
        return Err(ClipError::PayloadMismatch);
    }
    Ok(ClipFrame {
        key,
        edition: edition.clone(),
        payload,
    })
}

/// The first edition of a fork of `frame`, carrying `payload` (the same clip
/// to keep it unedited, or an edit). `fork_of` names the source edition and a
/// hint carries its address; hints route and never decide.
///
/// # Errors
/// As [`ClipPayloadV1::digest`].
pub fn fork_body(
    frame: &ClipFrame,
    payload: &ClipPayloadV1,
    tool: &str,
    created_ms: u64,
) -> Result<EditionBody, ClipError> {
    let mut body = clip_body(payload, tool, created_ms)?;
    body.fork_of = Some(frame.edition.id);
    let hint = KnotAddress::for_clip(frame.key, frame.edition.id).to_string();
    if hint.len() <= EditionLimits::default().max_text_bytes {
        body.hints.push(hint);
    }
    Ok(body)
}

/// Republish `frame` as a fork on a fresh log. Returns the signed edition and
/// the payload bytes it names.
///
/// # Errors
/// Refuses a writer that is not at the start of a log, since a fork can only be
/// a log's first edition.
pub fn republish(
    frame: &ClipFrame,
    writer: &mut EditionWriter,
    payload: Option<&ClipPayloadV1>,
    tool: &str,
    created_ms: u64,
) -> Result<(EditionOperation, Vec<u8>), ClipError> {
    let payload = payload.unwrap_or(&frame.payload);
    let operation = writer.append(&fork_body(frame, payload, tool, created_ms)?)?;
    Ok((operation, payload.encode()?))
}
