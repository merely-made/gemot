/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! Moot operation-wire bridge — object events as signed p2panda operations.
//!
//! Mirrors the tessera and mesh wires: a [`MootEvent`] rides the synced
//! event-DAG as a signed `Operation<MootExt>`; the moot id is the signed
//! addressing extension, so an event for one moot cannot replay into
//! another; the author signs at its per-author log position, forming a
//! valid p2panda log LogSync reconciles.

use identity::Ed25519Keypair;
use p2panda_core::cbor::{decode_cbor, encode_cbor};
use p2panda_core::{Body, Hash, Header, Operation, SigningKey, Timestamp};
use serde::{Deserialize, Serialize};

/// The signed addressing extension on a moot operation: which moot the
/// event belongs to.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MootExt {
    pub moot_id: [u8; 32],
}

/// A moot object event — the records the roster folds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MootEvent {
    /// The founding statement. Competing declarations resolve
    /// deterministically in the fold (lowest declaring-op hash wins).
    Declared {
        name: String,
        charter: String,
        at_ms: u64,
    },
    /// A member announcing themselves; the author key is the identity,
    /// `name` is a display label. First join per author wins.
    Joined { name: String, at_ms: u64 },
    /// An engram reference shared into the moot's flora: the manifest id
    /// (CID) plus what it claims to be. Blob transfer is a later milestone;
    /// the reference is the hand-off.
    Shared {
        manifest_id: [u8; 32],
        schema_id: String,
        title: String,
        at_ms: u64,
    },
}

impl MootEvent {
    fn at_ms(&self) -> u64 {
        match self {
            MootEvent::Declared { at_ms, .. }
            | MootEvent::Joined { at_ms, .. }
            | MootEvent::Shared { at_ms, .. } => *at_ms,
        }
    }
}

/// A malformed moot operation.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    #[error("moot operation has no body")]
    MissingBody,
    #[error("moot operation body is not a MootEvent")]
    Malformed,
}

/// Sign a [`MootEvent`] into an operation on `moot_id`'s event-DAG at the
/// author's per-author log position (`0` / `None` for a first event).
pub fn to_operation(
    keypair: &Ed25519Keypair,
    moot_id: [u8; 32],
    event: &MootEvent,
    seq_num: u64,
    backlink: Option<[u8; 32]>,
) -> Operation<MootExt> {
    let signing_key = SigningKey::from_bytes(&keypair.to_seed());
    let body_bytes = encode_cbor(event).expect("a MootEvent always CBOR-encodes");
    let body = Body::new(&body_bytes);
    let mut header = Header {
        version: 1,
        verifying_key: signing_key.verifying_key(),
        signature: None,
        payload_size: body.size(),
        payload_hash: Some(body.hash()),
        timestamp: Timestamp::from(event.at_ms()),
        seq_num,
        backlink: backlink.map(Hash::from),
        extensions: MootExt { moot_id },
    };
    header.sign(&signing_key);
    let hash = header.hash();
    Operation {
        hash,
        header,
        body: Some(body),
    }
}

/// Decode the moot id + event from an operation. Does *not* check the
/// signature — call [`verify`] for that.
pub fn from_operation(op: &Operation<MootExt>) -> Result<([u8; 32], MootEvent), WireError> {
    let body = op.body.as_ref().ok_or(WireError::MissingBody)?;
    let event: MootEvent =
        decode_cbor(body.to_bytes().as_slice()).map_err(|_| WireError::Malformed)?;
    Ok((op.header.extensions.moot_id, event))
}

/// Whether the operation's signature is valid for its author and content.
pub fn verify(op: &Operation<MootExt>) -> bool {
    op.header.verify()
}

#[cfg(test)]
mod tests {
    use super::*;
    use identity::{IdentityProvider, InMemoryProvider};

    const MOOT: [u8; 32] = [0x6d; 32];

    fn keypair(seed: u8) -> Ed25519Keypair {
        InMemoryProvider::from_seed([seed; 32])
            .derive_keypair(b"moot-wire")
            .unwrap()
    }

    fn declared() -> MootEvent {
        MootEvent::Declared {
            name: "printing circle".to_string(),
            charter: "we share what we set in type".to_string(),
            at_ms: 42,
        }
    }

    #[test]
    fn an_event_round_trips_through_an_operation() {
        let kp = keypair(7);
        let event = declared();
        let op = to_operation(&kp, MOOT, &event, 0, None);
        let (moot_id, decoded) = from_operation(&op).expect("decode");
        assert_eq!(moot_id, MOOT);
        assert_eq!(decoded, event);
        assert!(verify(&op));
    }

    #[test]
    fn tampering_the_moot_id_breaks_verification() {
        let kp = keypair(7);
        let mut op = to_operation(&kp, MOOT, &declared(), 0, None);
        op.header.extensions.moot_id = [0xff; 32];
        assert!(!verify(&op), "the moot id is signed; cross-moot replay fails");
    }

    #[test]
    fn the_per_author_log_validates_under_p2panda() {
        use p2panda_core::operation::{validate_backlink, validate_header};
        let kp = keypair(7);
        let op0 = to_operation(&kp, MOOT, &declared(), 0, None);
        let join = MootEvent::Joined {
            name: "mark".to_string(),
            at_ms: 50,
        };
        let op1 = to_operation(&kp, MOOT, &join, 1, Some(*op0.hash.as_bytes()));
        assert!(validate_header(&op0.header).is_ok());
        assert!(validate_header(&op1.header).is_ok());
        assert!(validate_backlink(&op0.header, &op1.header).is_ok());
    }
}
