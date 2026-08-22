//! Signed p2panda wire form for constitution events.

use identity::Ed25519Keypair;
use p2panda_core::cbor::{decode_cbor, encode_cbor};
use p2panda_core::operation::validate_operation;
use p2panda_core::{Body, Hash, Header, Operation, SigningKey};
use serde::{Deserialize, Serialize};

use super::ConstitutionEvent;

/// Signed address of a constitution operation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstitutionExt {
    /// Moot whose constitution log carries the event.
    pub moot_id: [u8; 32],
}

/// Malformed constitution operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConstitutionWireError {
    /// A constitution event always requires its body.
    #[error("constitution operation has no body")]
    MissingBody,
    /// The body is not a constitution event.
    #[error("constitution operation body is malformed")]
    Malformed,
}

/// Sign an event at one position in the founder's constitution log.
pub fn to_operation(
    keypair: &Ed25519Keypair,
    moot_id: [u8; 32],
    event: &ConstitutionEvent,
    seq_num: u32,
    backlink: Option<[u8; 32]>,
) -> Operation<ConstitutionExt> {
    to_operation_seed(keypair.to_seed(), moot_id, event, seq_num, backlink)
}

/// Provider-neutral form of [`to_operation`].
pub fn to_operation_seed(
    signing_seed: [u8; 32],
    moot_id: [u8; 32],
    event: &ConstitutionEvent,
    seq_num: u32,
    backlink: Option<[u8; 32]>,
) -> Operation<ConstitutionExt> {
    let signing_key = SigningKey::from_bytes(&signing_seed);
    let bytes = encode_cbor(event).expect("a constitution event always CBOR-encodes");
    let body = Body::from_bytes(&bytes);
    // p2panda 0.7.1 made the header's CBOR cache, size and digest private
    // and folded signing into the builder: `build` encodes, signs and
    // caches the digest in one step, so the struct-literal + `sign` pair
    // has no equivalent. `body` sets payload_size and payload_hash.
    let header = Header::builder()
        .body(&bytes)
        .seq_num(seq_num)
        .backlink(backlink.map(Hash::from))
        .build(&signing_key, ConstitutionExt { moot_id });
    let hash = header.hash();
    Operation {
        hash,
        header,
        body: Some(body),
    }
}

/// Decode an event without independently verifying its signature.
pub fn from_operation(
    operation: &Operation<ConstitutionExt>,
) -> Result<ConstitutionEvent, ConstitutionWireError> {
    let body = operation
        .body
        .as_ref()
        .ok_or(ConstitutionWireError::MissingBody)?;
    decode_cbor(body.to_bytes().as_slice()).map_err(|_| ConstitutionWireError::Malformed)
}

/// Verify the signed header and body commitment.
pub fn verify(operation: &Operation<ConstitutionExt>) -> bool {
    validate_operation(operation).is_ok() && operation.hash == operation.header.hash()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::moot::constitution::ConstitutionRules;
    use identity::{IdentityProvider, InMemoryProvider};

    #[test]
    fn event_round_trips_and_binds_its_moot() {
        let keypair = InMemoryProvider::from_seed([1; 32])
            .derive_keypair(b"constitution-wire")
            .unwrap();
        let moot_id = [0x63; 32];
        let founder = keypair.public_key().to_bytes();
        let event = ConstitutionEvent::genesis(
            moot_id,
            founder,
            None,
            None,
            ConstitutionRules::founder_only(founder),
            1,
        );
        let operation = to_operation(&keypair, moot_id, &event, 0, None);
        assert_eq!(from_operation(&operation).unwrap(), event);
        assert!(verify(&operation));

        // The moot id is signed, but in-memory tampering no longer shows up:
        // p2panda 0.7.1 re-encodes a header from the CBOR cache it decoded, so
        // mutating `extensions` cannot change what was signed. The claim is
        // therefore tested on the bytes — a different moot id signs to
        // different header bytes, and corrupting the encoded extension region
        // (which `encode_header` appends last) makes the header fail to decode.
        let elsewhere = to_operation(&keypair, [9; 32], &event, 0, None);
        assert_ne!(operation.header.encode(), elsewhere.header.encode());
        let mut replayed = operation.header.encode();
        *replayed.last_mut().unwrap() ^= 0xff;
        assert!(Header::<ConstitutionExt>::decode(&replayed).is_err());

        let mut tampered = to_operation(&keypair, moot_id, &event, 0, None);
        tampered.body = Some(Body::from_bytes(b"different constitution"));
        assert!(!verify(&tampered));
    }
}
