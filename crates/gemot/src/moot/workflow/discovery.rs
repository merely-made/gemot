// SPDX-License-Identifier: MPL-2.0
//! Signed, expiring catalogue hints. Murm carries bytes; Gemot owns semantics.
use super::namespace::CollectionTarget;
use super::{RecordId, canonical_ids, hex, text};
use crate::moot::{CollectionVersion, Moot, MootError};
use identity::{Ed25519PublicKey, Ed25519Signature, IdentityProvider};
use insigne::DerivedKeyAttestation;
use muniment::Backend;
use p2panda_core::{
    Hash,
    cbor::{decode_cbor_strict, encode_cbor},
};
use serde::{Deserialize, Serialize};
use servitor::Cap;
use std::collections::BTreeMap;

pub const MAX_ADVERTISEMENT_BYTES: usize = 16 * 1024;
fn salt(moot: RecordId) -> Vec<u8> {
    let mut s = b"gemot/catalogue-advertisement/v1/".to_vec();
    s.extend(moot);
    s
}
pub fn catalogue_cap(collection: RecordId) -> Cap {
    Cap::scope(&format!("moot/catalogue/{}", hex(collection))).expect("fixed scope")
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogueDescription {
    pub address: String,
    pub title: String,
    pub abstract_text: String,
    pub scroll_subject: Option<u8>,
    pub language: Option<String>,
}
impl CatalogueDescription {
    pub fn validate(&self) -> bool {
        let Ok(address) = url::Url::parse(&self.address) else {
            return false;
        };
        let Some(host) = address.host_str() else {
            return false;
        };
        if !address.username().is_empty()
            || address.password().is_some()
            || host == "localhost"
            || host.ends_with(".localhost")
            || host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback() || ip.is_unspecified())
        {
            return false;
        }
        let scheme = self.address.split_once("://").map(|(s, _)| s);
        text(&self.address, 2048)
            && matches!(
                scheme,
                Some("http" | "https" | "gemini" | "scroll" | "spartan" | "ipfs")
            )
            && text(&self.title, 512)
            && self.abstract_text.len() <= 4096
            && !self
                .abstract_text
                .chars()
                .any(|c| c.is_control() && c != '\n' && c != '\t')
            && self.scroll_subject.is_none_or(|v| v <= 9)
            && self.language.as_ref().is_none_or(|v| text(v, 64))
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogueAdvertisement {
    pub version: u16,
    pub collection: CollectionVersion,
    pub provider: RecordId,
    pub sequence: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    /// None withdraws this provider's hint, retaining its sequence watermark.
    pub description: Option<CatalogueDescription>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedCatalogueAdvertisement {
    pub advertisement: CatalogueAdvertisement,
    pub signer: RecordId,
    pub attestation: DerivedKeyAttestation,
    pub signature: Vec<u8>,
}
impl SignedCatalogueAdvertisement {
    fn message(ad: &CatalogueAdvertisement) -> Result<Vec<u8>, String> {
        let mut out = b"gemot/catalogue-advertisement-signature/v1\0".to_vec();
        out.extend(encode_cbor(ad).map_err(|e| e.to_string())?);
        Ok(out)
    }
    pub fn sign<P: IdentityProvider + ?Sized>(
        identity: &P,
        advertisement: CatalogueAdvertisement,
    ) -> Result<Self, String> {
        if advertisement.provider != identity.master_public_key().to_bytes() {
            return Err("advertisement provider mismatch".into());
        }
        let salt = salt(advertisement.collection.collection.moot_id);
        let key = identity.derive_keypair(&salt).map_err(|e| e.to_string())?;
        let signature = key
            .sign(&Self::message(&advertisement)?)
            .to_bytes()
            .to_vec();
        Ok(Self {
            advertisement,
            signer: key.public_key().to_bytes(),
            attestation: identity
                .attest_derived_key(&salt)
                .map_err(|e| e.to_string())?,
            signature,
        })
    }
    pub fn verify(&self, moot: RecordId, now: u64, max_lifetime_ms: u64) -> Result<(), String> {
        let ad = &self.advertisement;
        if ad.version != 1
            || ad.collection.collection.moot_id != moot
            || ad.sequence == 0
            || ad.issued_at_ms > now
            || ad.expires_at_ms <= now
            || ad
                .expires_at_ms
                .checked_sub(ad.issued_at_ms)
                .is_none_or(|n| n == 0 || n > max_lifetime_ms)
            || ad.collection.frontier.is_empty()
            || !canonical_ids(&ad.collection.frontier, 64)
            || ad.description.as_ref().is_some_and(|v| !v.validate())
        {
            return Err("invalid, foreign or expired advertisement".into());
        }
        let stable =
            stickleback::stable_writer_subject(self.signer, Some(&self.attestation), &salt(moot))
                .map_err(|e| e.to_string())?;
        let signature: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| "advertisement signature size")?;
        let key = Ed25519PublicKey::from_bytes(&self.signer).map_err(|e| e.to_string())?;
        if stable != ad.provider
            || !key.verify(
                &Self::message(ad)?,
                &Ed25519Signature::from_bytes(&signature),
            )
        {
            return Err("advertisement signature mismatch".into());
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let bytes = encode_cbor(self).map_err(|e| e.to_string())?;
        if bytes.len() > MAX_ADVERTISEMENT_BYTES {
            return Err("advertisement byte ceiling".into());
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_ADVERTISEMENT_BYTES {
            return Err("advertisement byte ceiling".into());
        }
        let value: Self = decode_cbor_strict(bytes).map_err(|e| e.to_string())?;
        if value.encode()? != bytes {
            return Err("noncanonical advertisement".into());
        }
        Ok(value)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Entry {
    hint: SignedCatalogueAdvertisement,
    conflict: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CatalogueDirectory {
    version: u16,
    entries: BTreeMap<(RecordId, RecordId), Entry>,
}
impl Default for CatalogueDirectory {
    fn default() -> Self {
        Self {
            version: 1,
            entries: BTreeMap::new(),
        }
    }
}
impl CatalogueDirectory {
    pub fn ensure_capacity(
        &self,
        provider: RecordId,
        collection: RecordId,
        max_entries: usize,
    ) -> Result<(), String> {
        if self.entries.contains_key(&(provider, collection)) || self.entries.len() < max_entries {
            Ok(())
        } else {
            Err("catalogue directory is full".into())
        }
    }
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        encode_cbor(self).map_err(|e| e.to_string())
    }
    /// Restore watermarks without trusting cached authority or expiry.
    pub fn decode(bytes: &[u8], max_entries: usize) -> Result<Self, String> {
        if bytes.len() > max_entries.saturating_mul(MAX_ADVERTISEMENT_BYTES + 128) {
            return Err("directory byte ceiling".into());
        }
        let value: Self = decode_cbor_strict(bytes).map_err(|e| e.to_string())?;
        if value.version != 1 || value.entries.len() > max_entries {
            return Err("directory entry ceiling or version".into());
        }
        for ((provider, collection), entry) in &value.entries {
            let ad = &entry.hint.advertisement;
            if ad.provider != *provider || ad.collection.collection.collection_id.0 != *collection {
                return Err("directory key mismatch".into());
            }
            entry
                .hint
                .verify(ad.collection.collection.moot_id, ad.issued_at_ms, u64::MAX)?;
        }
        Ok(value)
    }
    pub async fn receive<B: Backend + Clone>(
        &mut self,
        moot: &Moot<B>,
        reader: RecordId,
        bytes: &[u8],
        now: u64,
        max_lifetime_ms: u64,
        max_entries: usize,
    ) -> Result<bool, String> {
        let hint = SignedCatalogueAdvertisement::decode(bytes)?;
        moot.validate_catalogue_advertisement(reader, &hint, now, max_lifetime_ms)
            .await
            .map_err(|e| e.to_string())?;
        let ad = &hint.advertisement;
        let key = (ad.provider, ad.collection.collection.collection_id.0);
        if let Some(old) = self.entries.get_mut(&key) {
            if ad.sequence < old.hint.advertisement.sequence {
                return Ok(false);
            }
            if ad.sequence == old.hint.advertisement.sequence {
                if hint != old.hint {
                    let changed = !old.conflict;
                    old.conflict = true;
                    return Ok(changed);
                }
                return Ok(false);
            }
        } else if self.entries.len() >= max_entries {
            return Err("directory full; no watermark evicted".into());
        }
        self.entries.insert(
            key,
            Entry {
                hint,
                conflict: false,
            },
        );
        Ok(true)
    }
    pub async fn visible<B: Backend + Clone>(
        &self,
        moot: &Moot<B>,
        reader: RecordId,
        now: u64,
        max_lifetime_ms: u64,
    ) -> Vec<SignedCatalogueAdvertisement> {
        let mut out = Vec::new();
        for e in self.entries.values() {
            if !e.conflict
                && e.hint.advertisement.description.is_some()
                && moot
                    .validate_catalogue_advertisement(reader, &e.hint, now, max_lifetime_ms)
                    .await
                    .is_ok()
            {
                out.push(e.hint.clone());
            }
        }
        out
    }
    pub fn digest(hint: &SignedCatalogueAdvertisement) -> Result<RecordId, String> {
        Ok(*Hash::digest(hint.encode()?).as_bytes())
    }
    pub fn outgoing(&self, provider: RecordId, now: u64) -> Vec<SignedCatalogueAdvertisement> {
        self.entries
            .values()
            .filter(|e| {
                !e.conflict
                    && e.hint.advertisement.provider == provider
                    && e.hint.advertisement.issued_at_ms <= now
                    && now < e.hint.advertisement.expires_at_ms
            })
            .map(|e| e.hint.clone())
            .collect()
    }
    pub fn next_sequence(&self, provider: RecordId, collection: RecordId) -> Result<u64, String> {
        self.entries
            .get(&(provider, collection))
            .map_or(Some(1), |e| e.hint.advertisement.sequence.checked_add(1))
            .ok_or_else(|| "advertisement sequence exhausted".into())
    }
}
