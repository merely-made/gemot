// Copyright 2026 Mark AB (markik)
// SPDX-License-Identifier: MIT OR Apache-2.0

use p2panda_core::cbor::{decode_cbor, encode_cbor};
use p2panda_core::operation::validate_operation;
use p2panda_core::{Body, Hash, Header, Operation, SigningKey};
use serde::{Deserialize, Serialize};

use crate::{MootholdEvent, MootholdId};

/// Signed address of a Moothold operation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MootholdExt {
    pub moothold_id: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MootholdWireError {
    #[error("Moothold operation has no body")]
    MissingBody,
    #[error("Moothold operation body is malformed")]
    Malformed,
}

/// Sign one Moothold event using a protocol-scoped Ed25519 seed.
pub fn to_operation_seed(
    signing_seed: [u8; 32],
    moothold_id: MootholdId,
    event: &MootholdEvent,
    seq_num: u32,
    backlink: Option<[u8; 32]>,
) -> Operation<MootholdExt> {
    let signing_key = SigningKey::from_bytes(&signing_seed);
    let bytes = encode_cbor(event).expect("a Moothold event always CBOR-encodes");
    let body = Body::from_bytes(&bytes);
    // p2panda 0.7.1 made the header's CBOR cache, size and digest private
    // and folded signing into the builder: `build` encodes, signs and
    // caches the digest in one step, so the struct-literal + `sign` pair
    // has no equivalent. `body` sets payload_size and payload_hash.
    let header = Header::builder()
        .body(&bytes)
        .seq_num(seq_num)
        .backlink(backlink.map(Hash::from))
        .build(&signing_key, MootholdExt {
                moothold_id: moothold_id.0,
            });
    let hash = header.hash();
    Operation {
        hash,
        header,
        body: Some(body),
    }
}

pub fn from_operation(
    operation: &Operation<MootholdExt>,
) -> Result<MootholdEvent, MootholdWireError> {
    let body = operation
        .body
        .as_ref()
        .ok_or(MootholdWireError::MissingBody)?;
    decode_cbor(body.to_bytes().as_slice()).map_err(|_| MootholdWireError::Malformed)
}

pub fn verify(operation: &Operation<MootholdExt>) -> bool {
    validate_operation(operation).is_ok() && operation.hash == operation.header.hash()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CompositionPolicy, MemberTerms, MootId};

    #[test]
    fn event_round_trips_and_address_tampering_fails() {
        let id = MootholdId([3; 32]);
        let event = MootholdEvent::Founded {
            moothold_id: id,
            name: "river towns".into(),
            founder: *SigningKey::from_bytes(&[1; 32]).verifying_key().as_bytes(),
            initial_moot: MootId([7; 32]),
            initial_terms: MemberTerms::new(5_000, 20).unwrap(),
            composition: CompositionPolicy::CautiousImport,
            at_ms: 1,
        };
        let operation = to_operation_seed([1; 32], id, &event, 0, None);
        assert_eq!(from_operation(&operation).unwrap(), event);
        assert!(verify(&operation));

        // The moothold id is signed, but in-memory tampering no longer shows up:
        // p2panda 0.7.1 re-encodes a header from the CBOR cache it decoded, so
        // mutating `extensions` cannot change what was signed. The claim is
        // therefore tested on the bytes — a different moothold id signs to
        // different header bytes, and corrupting the encoded extension region
        // (which `encode_header` appends last) makes the header fail to decode.
        let elsewhere = to_operation_seed([1; 32], MootholdId([9; 32]), &event, 0, None);
        assert_ne!(operation.header.encode(), elsewhere.header.encode());
        let mut replayed = operation.header.encode();
        *replayed.last_mut().unwrap() ^= 0xff;
        assert!(Header::<MootholdExt>::decode(&replayed).is_err());
    }
}
