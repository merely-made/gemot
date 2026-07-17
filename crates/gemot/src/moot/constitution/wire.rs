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
    let body = Body::new(&bytes);
    let mut header = Header {
        version: 1,
        verifying_key: signing_key.verifying_key(),
        signature: None,
        payload_size: body.size(),
        payload_hash: Some(body.hash()),
        seq_num,
        backlink: backlink.map(Hash::from),
        extensions: ConstitutionExt { moot_id },
    };
    header.sign(&signing_key);
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

        let mut replay = operation;
        replay.header.extensions.moot_id = [9; 32];
        assert!(!verify(&replay));

        let mut tampered = to_operation(&keypair, moot_id, &event, 0, None);
        tampered.body = Some(Body::new(b"different constitution"));
        assert!(!verify(&tampered));
    }
}
