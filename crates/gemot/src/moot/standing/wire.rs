// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Standing operation-wire bridge — standing events as signed p2panda operations.
//!
//! Mirrors Murm's `Post` ↔ `Operation<CabalExt>` split: a [`StandingEvent`]
//! (the logical form the [ledger](super::ledger) folds) rides the synced
//! event-DAG as a signed `Operation<StandingExt>`, so peers replicate the standing
//! event log over the same LogSync substrate murm posts use and each computes the
//! same projected scores. The moot / space id is the signed addressing extension
//! (like a `cabal_id`, so an event cannot be replayed into another moot); the
//! event itself is the CBOR body, bound into the signature via the header's
//! payload hash. The author signs at its per-author log position
//! (`seq_num` / `backlink`), exactly as murm posts, so the events form a valid
//! p2panda log that LogSync reconciles.

use identity::{DerivedKeyAttestation, Ed25519Keypair};
use p2panda_core::cbor::{decode_cbor, encode_cbor};
use p2panda_core::operation::validate_operation;
use p2panda_core::{Body, Hash, Header, Operation, SigningKey};
use serde::{Deserialize, Serialize};
use stickleback::stable_writer_subject;

use crate::moot::standing::event::{ChainRoot, StandingEvent};

const STANDING_AUTHORED_VERSION: u16 = 1;

/// Versioned Standing body carrying an optional stable-Personae binding.
/// Legacy bodies containing a bare [`StandingEvent`] still decode.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct StandingAuthored {
    version: u16,
    pub(super) event: StandingEvent,
    #[serde(default)]
    pub(super) author_attestation: Option<DerivedKeyAttestation>,
}

/// The signed addressing extension on a standing operation: which moot's event-DAG
/// the event belongs to (like Murm's `cabal_id`). Signed into the header, so
/// an event cannot be replayed into a different moot.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandingExt {
    /// The moot / space this event addresses.
    pub moot_id: [u8; 32],
}

/// A malformed standing operation.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    /// The operation carries no body (a standing event is always the body).
    #[error("standing operation has no body")]
    MissingBody,
    /// The body is not a valid CBOR `StandingEvent`.
    #[error("standing operation body is malformed")]
    Malformed,
    /// Versioned authored body is not understood by this reader.
    #[error("unsupported authored Standing body version {0}")]
    UnsupportedVersion(u16),
    /// Personae could not authenticate the operation signer.
    #[error("{0}")]
    WriterBinding(String),
}

/// Domain-separated salt for one Moot's derived Standing signer.
pub fn standing_identity_salt(moot_id: [u8; 32]) -> Vec<u8> {
    let mut salt = Vec::with_capacity(63);
    salt.extend_from_slice(b"mere.gemot.standing.writer.v1/");
    salt.extend_from_slice(&moot_id);
    salt
}

/// Sign a [`StandingEvent`] into an operation on `moot_id`'s event-DAG at the
/// author's per-author log position (`seq_num` / `backlink`; `0` / `None` for the
/// author's first standing event in this moot).
pub fn to_operation(
    keypair: &Ed25519Keypair,
    moot_id: [u8; 32],
    event: &StandingEvent,
    seq_num: u32,
    backlink: Option<[u8; 32]>,
) -> Operation<StandingExt> {
    to_operation_seed(keypair.to_seed(), moot_id, event, seq_num, backlink)
}

/// Provider-neutral form of [`to_operation`].
pub fn to_operation_seed(
    signing_seed: [u8; 32],
    moot_id: [u8; 32],
    event: &StandingEvent,
    seq_num: u32,
    backlink: Option<[u8; 32]>,
) -> Operation<StandingExt> {
    build_operation(signing_seed, moot_id, event, None, seq_num, backlink)
}

/// Sign a Standing event under a derived key certified by its stable Personae
/// root. The attestation is part of the signed body.
pub fn to_operation_seed_with_attestation(
    signing_seed: [u8; 32],
    moot_id: [u8; 32],
    event: &StandingEvent,
    author_attestation: DerivedKeyAttestation,
    seq_num: u32,
    backlink: Option<[u8; 32]>,
) -> Operation<StandingExt> {
    build_operation(
        signing_seed,
        moot_id,
        event,
        Some(author_attestation),
        seq_num,
        backlink,
    )
}

fn build_operation(
    signing_seed: [u8; 32],
    moot_id: [u8; 32],
    event: &StandingEvent,
    author_attestation: Option<DerivedKeyAttestation>,
    seq_num: u32,
    backlink: Option<[u8; 32]>,
) -> Operation<StandingExt> {
    let signing_key = SigningKey::from_bytes(&signing_seed);
    let body_bytes = match author_attestation {
        Some(author_attestation) => encode_cbor(&StandingAuthored {
            version: STANDING_AUTHORED_VERSION,
            event: event.clone(),
            author_attestation: Some(author_attestation),
        })
        .expect("an authored Standing event always CBOR-encodes"),
        None => encode_cbor(event).expect("a StandingEvent always CBOR-encodes"),
    };
    let body = Body::from_bytes(&body_bytes);
    // p2panda 0.7.1 made the header's CBOR cache, size and digest private
    // and folded signing into the builder: `build` encodes, signs and
    // caches the digest in one step, so the struct-literal + `sign` pair
    // has no equivalent. `body` sets payload_size and payload_hash.
    let header = Header::builder()
        .body(&body_bytes)
        .seq_num(seq_num)
        .backlink(backlink.map(Hash::from))
        .build(&signing_key, StandingExt { moot_id });
    let hash = header.hash();
    Operation {
        hash,
        header,
        body: Some(body),
    }
}

/// Decode the moot id + standing event from an operation. Does *not* check the
/// signature — call [`verify`] for that.
pub fn from_operation(op: &Operation<StandingExt>) -> Result<([u8; 32], StandingEvent), WireError> {
    let record = authored_from_operation(op)?;
    Ok((op.header.extensions.moot_id, record.event))
}

pub(super) fn authored_from_operation(
    op: &Operation<StandingExt>,
) -> Result<StandingAuthored, WireError> {
    let body = op.body.as_ref().ok_or(WireError::MissingBody)?;
    let bytes = body.to_bytes();
    match decode_cbor::<StandingAuthored, _>(bytes.as_slice()) {
        Ok(record) => {
            if record.version != STANDING_AUTHORED_VERSION {
                return Err(WireError::UnsupportedVersion(record.version));
            }
            Ok(record)
        },
        Err(_) => {
            let event = decode_cbor(bytes.as_slice()).map_err(|_| WireError::Malformed)?;
            Ok(StandingAuthored {
                version: 0,
                event,
                author_attestation: None,
            })
        },
    }
}

/// Resolve this operation's signer to the stable Personae root it represents.
/// An unattested legacy operation resolves directly to its signing key.
pub fn stable_author(op: &Operation<StandingExt>) -> Result<ChainRoot, WireError> {
    let record = authored_from_operation(op)?;
    let root = stable_writer_subject(
        *op.header.verifying_key.as_bytes(),
        record.author_attestation.as_ref(),
        &standing_identity_salt(op.header.extensions.moot_id),
    )
    .map_err(|error| WireError::WriterBinding(error.to_string()))?;
    Ok(ChainRoot(root))
}

/// Verify the signed header and body commitment.
///
/// The signature itself is no longer re-checked and no longer can be: p2panda
/// 0.7.1 verifies it inside `Header::decode` and made `Header::verify`
/// test-only, so any `Operation` that exists was either decoded (verified) or
/// built locally by the builder (signed). What stays live here is the rest —
/// the payload hash and size against the actual body, the log's seq_num and
/// backlink rules, and the cached digest against the header.
pub fn verify(operation: &Operation<StandingExt>) -> bool {
    validate_operation(operation).is_ok() && operation.hash == operation.header.hash()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::moot::standing::event::{ChainRoot, CommitmentId, Scope};
    use identity::{IdentityProvider, InMemoryProvider};

    const MOOT: [u8; 32] = [0x30; 32];

    fn keypair() -> Ed25519Keypair {
        InMemoryProvider::from_seed([7; 32])
            .derive_keypair(b"standing-wire")
            .unwrap()
    }

    fn sample_event(root: ChainRoot) -> StandingEvent {
        StandingEvent::CommitmentMade {
            by: root,
            commitment: CommitmentId([1; 32]),
            scope: Scope("cluster/a".into()),
            cadence_ms: 1000,
            duration_ms: None,
            at_ms: 42,
        }
    }

    #[test]
    fn event_round_trips_through_an_operation() {
        let kp = keypair();
        let event = sample_event(ChainRoot(kp.public_key().to_bytes()));
        let op = to_operation(&kp, MOOT, &event, 0, None);
        let (moot_id, decoded) = from_operation(&op).expect("decode");
        assert_eq!(moot_id, MOOT);
        assert_eq!(decoded, event);
    }

    #[test]
    fn a_signed_operation_verifies() {
        let kp = keypair();
        let op = to_operation(&kp, MOOT, &sample_event(ChainRoot([1; 32])), 0, None);
        assert!(verify(&op));
    }

    #[test]
    fn tampering_the_moot_id_breaks_verification() {
        let kp = keypair();
        let event = sample_event(ChainRoot([1; 32]));
        let op = to_operation(&kp, MOOT, &event, 0, None);
        // The moot id is signed, but in-memory tampering no longer shows up:
        // p2panda 0.7.1 re-encodes a header from the CBOR cache it decoded, so
        // mutating `extensions` cannot change what was signed. The claim is
        // therefore tested on the bytes — a different moot id signs to
        // different header bytes, and corrupting the encoded extension region
        // (which `encode_header` appends last) makes the header fail to decode.
        let elsewhere = to_operation(&kp, [0xff; 32], &event, 0, None);
        assert_ne!(op.header.encode(), elsewhere.header.encode());
        let mut replayed = op.header.encode();
        *replayed.last_mut().unwrap() ^= 0xff;
        assert!(
            Header::<StandingExt>::decode(&replayed).is_err(),
            "the moot id is signed, so a cross-moot replay fails"
        );
    }

    #[test]
    fn the_per_author_log_validates_under_p2panda() {
        use p2panda_core::operation::{validate_backlink, validate_header};
        let kp = keypair();
        let op0 = to_operation(&kp, MOOT, &sample_event(ChainRoot([1; 32])), 0, None);
        let e1 = StandingEvent::GovernanceParticipation {
            by: ChainRoot([1; 32]),
            at_ms: 50,
        };
        let op1 = to_operation(&kp, MOOT, &e1, 1, Some(*op0.hash.as_bytes()));

        // The chain satisfies p2panda's own validators, so LogSync accepts it.
        assert!(validate_header(&op0.header).is_ok());
        assert!(validate_header(&op1.header).is_ok());
        assert!(validate_backlink(&op0.header, &op1.header).is_ok());
    }

    #[test]
    fn attested_derived_signer_resolves_to_its_stable_root() {
        let identity = InMemoryProvider::from_seed([0x41; 32]);
        let salt = standing_identity_salt(MOOT);
        let signer = identity.derive_keypair(&salt).unwrap();
        let root = ChainRoot(identity.master_public_key().to_bytes());
        let operation = to_operation_seed_with_attestation(
            signer.to_seed(),
            MOOT,
            &sample_event(root),
            identity.attest_derived_key(&salt).unwrap(),
            0,
            None,
        );

        assert_ne!(*operation.header.verifying_key.as_bytes(), root.0);
        assert_eq!(stable_author(&operation).unwrap(), root);
        assert_eq!(from_operation(&operation).unwrap().1, sample_event(root));
    }

    #[test]
    fn attestation_is_bound_to_both_signer_and_moot() {
        let identity = InMemoryProvider::from_seed([0x42; 32]);
        let salt = standing_identity_salt(MOOT);
        let signer = identity.derive_keypair(&salt).unwrap();
        let attestation = identity.attest_derived_key(&salt).unwrap();
        let wrong_signer = InMemoryProvider::from_seed([0x43; 32])
            .derive_keypair(&salt)
            .unwrap();
        let wrong_signer_operation = to_operation_seed_with_attestation(
            wrong_signer.to_seed(),
            MOOT,
            &sample_event(ChainRoot(identity.master_public_key().to_bytes())),
            attestation.clone(),
            0,
            None,
        );
        assert!(matches!(
            stable_author(&wrong_signer_operation),
            Err(WireError::WriterBinding(_))
        ));

        let wrong_moot_operation = to_operation_seed_with_attestation(
            signer.to_seed(),
            [0x31; 32],
            &sample_event(ChainRoot(identity.master_public_key().to_bytes())),
            attestation,
            0,
            None,
        );
        assert!(matches!(
            stable_author(&wrong_moot_operation),
            Err(WireError::WriterBinding(_))
        ));
    }
}
