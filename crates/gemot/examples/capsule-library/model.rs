// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Proof-local catalogue adapters. Pack and collection wire types come from
//! their existing owners; this example does not define publication revisions.
use super::{AnyError, ensure, hex};
use eidetic::pack::{PackManifest, PackPart, PackPartRole, PackVerdict, sign_pack, verify_pack};
use eidetic::schema::{ManifestId, TrustEnvelope};
use identity::{IdentityProvider, InMemoryProvider};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedPack {
    pub manifest: PackManifest,
    pub trust: TrustEnvelope,
}

impl SignedPack {
    pub fn new(
        owner: &InMemoryProvider,
        name: &str,
        version: &str,
        parts: Vec<PackPart>,
        asks: Vec<String>,
    ) -> Self {
        let manifest = PackManifest {
            name: name.into(),
            version: version.into(),
            author: hex(&owner.master_public_key().to_bytes()),
            requested_scopes: asks,
            parts,
        };
        let mut trust = TrustEnvelope::self_asserted();
        trust
            .signatures
            .push(sign_pack(&manifest, owner.master_keypair()));
        Self { manifest, trust }
    }

    pub fn bytes(&self) -> Result<Vec<u8>, AnyError> {
        Ok(serde_json::to_vec(self)?)
    }

    pub fn verify(
        &self,
        contributor: &str,
        blobs: &BTreeMap<[u8; 32], Vec<u8>>,
    ) -> Result<(), AnyError> {
        ensure(
            verify_pack(&self.manifest, &self.trust) == PackVerdict::Trusted,
            "pack signature failed",
        )?;
        ensure(
            self.manifest.author == contributor,
            "contribution does not name pack author",
        )?;
        for part in &self.manifest.parts {
            let key = part.blob.0.as_bytes();
            let bytes = blobs.get(key).ok_or("pack part missing")?;
            ensure(
                part.bytes == bytes.len() as u64 && part.blob == ManifestId::of_blob(bytes),
                "pack part hash or size mismatch",
            )?;
        }
        Ok(())
    }
}

pub fn part(name: &str, role: PackPartRole, bytes: &[u8]) -> PackPart {
    PackPart {
        name: name.into(),
        role,
        blob: ManifestId::of_blob(bytes),
        bytes: bytes.len() as u64,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub title: String,
    pub author: String,
    pub revision: String,
    pub url: String,
    pub bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Catalogue {
    pub query: String,
    pub entries: Vec<Entry>,
}
