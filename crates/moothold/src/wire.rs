/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

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
    let body = Body::new(&bytes);
    let mut header = Header {
        version: 1,
        verifying_key: signing_key.verifying_key(),
        signature: None,
        payload_size: body.size(),
        payload_hash: Some(body.hash()),
        seq_num,
        backlink: backlink.map(Hash::from),
        extensions: MootholdExt {
            moothold_id: moothold_id.0,
        },
    };
    header.sign(&signing_key);
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

        let mut replay = operation;
        replay.header.extensions.moothold_id = [9; 32];
        assert!(!verify(&replay));
    }
}
