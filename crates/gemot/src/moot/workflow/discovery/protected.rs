// SPDX-License-Identifier: MPL-2.0
//! Audience-bound catalogue payloads using Stickleback's group data encryption.
//! Routing and epoch ids remain visible. Old recipients can retain old plaintext.
use super::*;
use stickleback::{DataKeyring, GroupCiphertext};
const WIRE: &[u8; 4] = b"GCA2";
const CACHE: &[u8; 4] = b"GCC1";
const BODY: &[u8; 4] = b"GCM1";
pub const MAX_CACHE_BYTES: usize = 3 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
struct Envelope {
    version: u16,
    ciphertext: GroupCiphertext,
}
fn context(kind: &[u8; 4], moot: RecordId, resource: Option<RecordId>) -> Vec<u8> {
    let mut bytes = b"gemot/protected-catalogue/v1\0".to_vec();
    bytes.extend(kind);
    bytes.extend(moot);
    if let Some(resource) = resource {
        bytes.extend(resource);
    }
    bytes
}
fn seal(
    kind: &[u8; 4],
    moot: RecordId,
    resource: Option<RecordId>,
    keys: &DataKeyring,
    payload: &[u8],
    limit: usize,
) -> Result<Vec<u8>, String> {
    if payload.len() > limit {
        return Err("protected catalogue byte ceiling".into());
    }
    let mut plaintext = context(kind, moot, resource);
    plaintext.extend(payload);
    let envelope = Envelope {
        version: 1,
        ciphertext: keys.seal_random(&plaintext).map_err(|e| e.to_string())?,
    };
    let mut bytes = kind.to_vec();
    bytes.extend(encode_cbor(&envelope).map_err(|e| e.to_string())?);
    if bytes.len() > limit {
        return Err("protected catalogue byte ceiling".into());
    }
    Ok(bytes)
}
fn open(
    kind: &[u8; 4],
    moot: RecordId,
    resource: Option<RecordId>,
    keys: &DataKeyring,
    bytes: &[u8],
    limit: usize,
    current: bool,
) -> Result<Vec<u8>, String> {
    if bytes.len() > limit {
        return Err("protected catalogue byte ceiling".into());
    }
    let encoded = bytes
        .strip_prefix(kind)
        .ok_or("protected catalogue envelope marker")?;
    let envelope: Envelope = decode_cbor_strict(encoded).map_err(|e| e.to_string())?;
    if envelope.version != 1 || encode_cbor(&envelope).map_err(|e| e.to_string())? != encoded {
        return Err("noncanonical protected catalogue envelope".into());
    }
    if current && keys.current_epoch() != Some(envelope.ciphertext.epoch) {
        return Err("protected catalogue requires the current group epoch".into());
    }
    let plaintext = keys.open(&envelope.ciphertext).map_err(|e| e.to_string())?;
    plaintext
        .strip_prefix(context(kind, moot, resource).as_slice())
        .map(<[u8]>::to_vec)
        .ok_or_else(|| "protected catalogue context mismatch".into())
}
pub fn is_protected(bytes: &[u8]) -> bool {
    bytes.starts_with(WIRE)
}
pub fn seal_advertisement(
    moot: RecordId,
    keys: &DataKeyring,
    hint: &SignedCatalogueAdvertisement,
) -> Result<Vec<u8>, String> {
    if hint.advertisement.version != 2
        || hint.advertisement.audience != Some(CatalogueAudience { members_of: moot })
        || hint.advertisement.collection.collection.moot_id != moot
    {
        return Err("protected catalogue audience mismatch".into());
    }
    seal(
        WIRE,
        moot,
        None,
        keys,
        &hint.encode()?,
        MAX_ADVERTISEMENT_BYTES,
    )
}
pub fn open_advertisement(
    moot: RecordId,
    keys: &DataKeyring,
    bytes: &[u8],
    now: u64,
    max_lifetime_ms: u64,
) -> Result<SignedCatalogueAdvertisement, String> {
    let payload = open(WIRE, moot, None, keys, bytes, MAX_ADVERTISEMENT_BYTES, true)?;
    let hint = SignedCatalogueAdvertisement::decode(&payload)?;
    hint.verify(moot, now, max_lifetime_ms)?;
    if hint.advertisement.audience != Some(CatalogueAudience { members_of: moot }) {
        return Err("protected catalogue audience mismatch".into());
    }
    Ok(hint)
}
pub fn seal_cache(
    moot: RecordId,
    keys: &DataKeyring,
    directory: &CatalogueDirectory,
) -> Result<Vec<u8>, String> {
    directory.require_audience(Some(CatalogueAudience { members_of: moot }))?;
    seal(
        CACHE,
        moot,
        None,
        keys,
        &directory.encode()?,
        MAX_CACHE_BYTES,
    )
}
pub fn open_cache(
    moot: RecordId,
    keys: &DataKeyring,
    bytes: &[u8],
    max_entries: usize,
) -> Result<CatalogueDirectory, String> {
    // Retained old epochs reopen a journal after rotation. Wire ingress above
    // requires the current epoch, and listing still checks present authority.
    let payload = open(CACHE, moot, None, keys, bytes, MAX_CACHE_BYTES, false)?;
    let directory = CatalogueDirectory::decode(&payload, max_entries)?;
    directory.require_audience(Some(CatalogueAudience { members_of: moot }))?;
    Ok(directory)
}
pub fn seal_description(
    moot: RecordId,
    collection: RecordId,
    keys: &DataKeyring,
    description: &CatalogueDescription,
) -> Result<Vec<u8>, String> {
    if !description.validate() {
        return Err("invalid protected description".into());
    }
    seal(
        BODY,
        moot,
        Some(collection),
        keys,
        &encode_cbor(description).map_err(|e| e.to_string())?,
        MAX_ADVERTISEMENT_BYTES,
    )
}
pub fn open_description(
    moot: RecordId,
    collection: RecordId,
    keys: &DataKeyring,
    bytes: &[u8],
) -> Result<CatalogueDescription, String> {
    let payload = open(
        BODY,
        moot,
        Some(collection),
        keys,
        bytes,
        MAX_ADVERTISEMENT_BYTES,
        false,
    )?;
    let description: CatalogueDescription =
        decode_cbor_strict(payload.as_slice()).map_err(|e| e.to_string())?;
    if !description.validate() || encode_cbor(&description).map_err(|e| e.to_string())? != payload {
        return Err("invalid protected description".into());
    }
    Ok(description)
}
