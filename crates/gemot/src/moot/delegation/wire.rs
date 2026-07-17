//! Signed p2panda wire form for independent delegation statements.

use identity::Ed25519Keypair;
use p2panda_core::cbor::{decode_cbor, encode_cbor};
use p2panda_core::operation::validate_operation;
use p2panda_core::{Body, Hash, Header, Operation, SigningKey, Timestamp};
use serde::{Deserialize, Serialize};

use super::MootDelegationEvent;

/// Signed address of a Moot delegation operation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MootDelegationExt {
    /// Moot whose grant lane carries the statement.
    pub moot_id: [u8; 32],
}

/// Malformed delegation operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MootDelegationWireError {
    /// Delegation operations always carry a body.
    #[error("delegation operation has no body")]
    MissingBody,
    /// Body is not a delegation statement.
    #[error("delegation operation body is malformed")]
    Malformed,
}

/// Sign a delegation statement at one position in its derived-key log.
pub fn to_operation(
    keypair: &Ed25519Keypair,
    moot_id: [u8; 32],
    event: &MootDelegationEvent,
    seq_num: u64,
    backlink: Option<[u8; 32]>,
) -> Operation<MootDelegationExt> {
    to_operation_seed(keypair.to_seed(), moot_id, event, seq_num, backlink)
}

/// Provider-neutral form of [`to_operation`].
pub fn to_operation_seed(
    signing_seed: [u8; 32],
    moot_id: [u8; 32],
    event: &MootDelegationEvent,
    seq_num: u64,
    backlink: Option<[u8; 32]>,
) -> Operation<MootDelegationExt> {
    let signing_key = SigningKey::from_bytes(&signing_seed);
    let bytes = encode_cbor(event).expect("delegation statements always CBOR-encode");
    let body = Body::new(&bytes);
    let mut header = Header {
        version: 1,
        verifying_key: signing_key.verifying_key(),
        signature: None,
        payload_size: body.size(),
        payload_hash: Some(body.hash()),
        timestamp: Timestamp::from(event.at_ms()),
        seq_num,
        backlink: backlink.map(Hash::from),
        extensions: MootDelegationExt { moot_id },
    };
    header.sign(&signing_key);
    let hash = header.hash();
    Operation {
        hash,
        header,
        body: Some(body),
    }
}

/// Decode a statement without independently verifying either signature layer.
pub fn from_operation(
    operation: &Operation<MootDelegationExt>,
) -> Result<MootDelegationEvent, MootDelegationWireError> {
    let body = operation
        .body
        .as_ref()
        .ok_or(MootDelegationWireError::MissingBody)?;
    decode_cbor(body.to_bytes().as_slice()).map_err(|_| MootDelegationWireError::Malformed)
}

/// Verify the p2panda header and body commitment.
pub fn verify(operation: &Operation<MootDelegationExt>) -> bool {
    validate_operation(operation).is_ok() && operation.hash == operation.header.hash()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use identity::delegation::{
        CapabilityScope, DelegationCertificate, DelegationParent, SignedDelegationCertificate,
        delegation_signing_salt,
    };
    use identity::{IdentityProvider, InMemoryProvider};

    use super::*;

    #[test]
    fn event_round_trips_with_matching_inner_and_outer_signers() {
        let provider = InMemoryProvider::from_seed([1; 32]);
        let subject = InMemoryProvider::from_seed([2; 32]);
        let scope = CapabilityScope {
            domain: "moot".into(),
            resource: vec![9; 32],
            path_prefix: "moot/fauna".into(),
            actions: BTreeSet::from(["act".into()]),
        };
        let signed = SignedDelegationCertificate::issue(
            &provider,
            DelegationCertificate::new(
                DelegationParent::Root([7; 32]),
                provider.master_public_key().to_bytes(),
                subject.master_public_key().to_bytes(),
                scope.clone(),
                1,
                2,
                Some(100),
                0,
                [3; 32],
            ),
        )
        .unwrap();
        let event = MootDelegationEvent::Issued(signed);
        let keypair = provider
            .derive_keypair(&delegation_signing_salt(&scope))
            .unwrap();
        let operation = to_operation(&keypair, [9; 32], &event, 0, None);
        assert!(verify(&operation));
        assert_eq!(from_operation(&operation).unwrap(), event);
        assert_eq!(event.signer(), Some(keypair.public_key().to_bytes()));
    }
}
