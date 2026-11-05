// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The `knot://` address: one parser for Turnstone and Knot.
//!
//! ```text
//! knot://<64-hex key>/<path>[@<64-hex edition id>]
//! knot://<64-hex anchor>.moot/<path>[@<64-hex edition id>]
//! ```
//!
//! The first form's host is a release-log key. Its tier (root, associated or
//! unassociated) is a property of how the key was derived and is not visible
//! in the address; today's Personae-root addresses are the root tier and parse
//! unchanged. The second form is the governed form: the host is a Moot
//! collection anchor, marked by the `.moot` suffix so that no 64-hex host can
//! be read both ways. The path names a page or file. A trailing `@<edition id>`
//! pins an edition; a literal `@` ending the last segment must be written
//! `%40`. Hosts and pins are accepted in either case and rendered lowercase,
//! so [`KnotAddress`]'s `Display` output re-parses to an equal value.
//!
//! Parsing only checks shape. Nothing here resolves a host, verifies a log or
//! grants access: an address is a reference, and hints or carriers are not
//! part of it. Other `knot://` hosts (for example `knot://vault/...`) are not
//! release addresses and are refused as [`AddressError::Host`].

use std::fmt;
use std::str::FromStr;

const SCHEME: &str = "knot://";
const MOOT_SUFFIX: &str = ".moot";

/// What the address host names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AddressHost {
    /// A release-log key, of any tier.
    LogKey([u8; 32]),
    /// A Moot collection anchor: the governed form.
    MootAnchor([u8; 32]),
}

impl AddressHost {
    /// The 32 key or anchor bytes.
    pub fn bytes(&self) -> &[u8; 32] {
        match self {
            Self::LogKey(bytes) | Self::MootAnchor(bytes) => bytes,
        }
    }
}

/// A parsed release address.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct KnotAddress {
    pub host: AddressHost,
    /// Page or file path, without the leading slash, as written (not decoded).
    pub path: String,
    /// The pinned edition id, when the address names one.
    pub pin: Option<[u8; 32]>,
}

/// Why a string is not a release address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressError {
    /// Not a `knot://` address.
    Scheme,
    /// The host is not 64 hex characters, optionally followed by `.moot`.
    Host,
    /// The path is missing, empty or unsafe.
    Path,
    /// The text after `@` is not a 64-hex edition id.
    Pin,
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Scheme => "not a knot:// address",
            Self::Host => "the host is not a 64-hex key or anchor",
            Self::Path => "the path is missing or malformed",
            Self::Pin => "the pin is not a 64-hex edition id",
        })
    }
}
impl std::error::Error for AddressError {}

fn hex32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (slot, pair) in out.iter_mut().zip(text.as_bytes().chunks(2)) {
        *slot = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

fn write_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8; 32]) -> fmt::Result {
    bytes.iter().try_for_each(|b| write!(f, "{b:02x}"))
}

fn valid_path(path: &str) -> bool {
    if path.is_empty()
        || path
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == '\\')
    {
        return false;
    }
    if path.contains(['?', '#']) {
        return false;
    }
    // A trailing slash names a folder; any other empty or dot segment is refused.
    let body = path.strip_suffix('/').unwrap_or(path);
    !body.is_empty()
        && body
            .split('/')
            .all(|s| !s.is_empty() && s != "." && s != "..")
}

impl KnotAddress {
    /// Parse a release address.
    ///
    /// # Errors
    /// Names the first part that is malformed.
    pub fn parse(address: &str) -> Result<Self, AddressError> {
        let rest = address
            .get(..SCHEME.len())
            .filter(|scheme| scheme.eq_ignore_ascii_case(SCHEME))
            .and_then(|_| address.get(SCHEME.len()..))
            .ok_or(AddressError::Scheme)?;
        let (host, tail) = rest.split_once('/').ok_or(AddressError::Path)?;
        let host = Self::parse_host(host)?;
        let (path, pin) = match tail.rsplit_once('@') {
            Some((path, pin)) if !pin.contains('/') => {
                (path, Some(hex32(pin).ok_or(AddressError::Pin)?))
            }
            _ => (tail, None),
        };
        if !valid_path(path) {
            return Err(AddressError::Path);
        }
        Ok(Self {
            host,
            path: path.to_string(),
            pin,
        })
    }

    fn parse_host(host: &str) -> Result<AddressHost, AddressError> {
        let moot = host.len() == 64 + MOOT_SUFFIX.len()
            && host.is_char_boundary(64)
            && host[64..].eq_ignore_ascii_case(MOOT_SUFFIX);
        let key = hex32(if moot { &host[..64] } else { host }).ok_or(AddressError::Host)?;
        Ok(if moot {
            AddressHost::MootAnchor(key)
        } else {
            AddressHost::LogKey(key)
        })
    }

    /// The release-log key, when this is the ungoverned form.
    pub fn log_key(&self) -> Option<&[u8; 32]> {
        match &self.host {
            AddressHost::LogKey(key) => Some(key),
            AddressHost::MootAnchor(_) => None,
        }
    }

    /// The same address pinned to `edition`.
    #[must_use]
    pub fn pinned(mut self, edition: [u8; 32]) -> Self {
        self.pin = Some(edition);
        self
    }
}

impl FromStr for KnotAddress {
    type Err = AddressError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

impl fmt::Display for KnotAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(SCHEME)?;
        write_hex(f, self.host.bytes())?;
        if matches!(self.host, AddressHost::MootAnchor(_)) {
            f.write_str(MOOT_SUFFIX)?;
        }
        write!(f, "/{}", self.path)?;
        if let Some(pin) = &self.pin {
            f.write_str("@")?;
            write_hex(f, pin)?;
        }
        Ok(())
    }
}
