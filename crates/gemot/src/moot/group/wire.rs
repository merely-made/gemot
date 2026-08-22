//! Signed p2panda wire form for Moot membership changes.
//!
//! The durable grammar is owned by Gemot. It translates into
//! `p2panda-auth` at materialization time, so the upstream CRDT's internal
//! serde representation is not part of the Moot protocol.

use identity::{DerivedKeyAttestation, IdentityError};
use p2panda_auth::group::{GroupAction, GroupMember};
use p2panda_auth::{Access, AccessLevel};
use p2panda_core::cbor::{decode_cbor, encode_cbor};
use p2panda_core::{Body, Hash, Header, Operation, SigningKey};
use serde::{Deserialize, Serialize};

use super::{
    MootGroupHandle, MootGroupOperation, MootGroupOperationId, MootMembershipAction,
    MootMembershipRecord,
};

/// Signed address of one Moot membership operation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MootGroupExt {
    /// Moot whose membership graph carries the operation.
    pub moot_id: [u8; 32],
}

/// Malformed or falsely attributed membership operation.
#[derive(Debug, thiserror::Error)]
pub enum MootGroupWireError {
    /// Membership operations always carry a body.
    #[error("membership operation has no body")]
    MissingBody,
    /// Body is not a Gemot membership record.
    #[error("membership operation body is malformed")]
    Malformed,
    /// Personae attestation does not verify for this Moot's membership lane.
    #[error("membership author attestation is invalid")]
    InvalidAttestation,
    /// Attestation does not bind the operation's signing key.
    #[error("membership author attestation does not bind the operation signer")]
    AttestationMismatch,
    /// Attestation contains an invalid root or derived public key.
    #[error("membership author attestation contains an invalid public key")]
    InvalidIdentity,
}

/// Domain-separated salt for one Moot's derived membership signing key.
pub fn membership_identity_salt(moot_id: [u8; 32]) -> Vec<u8> {
    let mut salt = Vec::with_capacity(58);
    salt.extend_from_slice(b"mere.gemot.membership.v1/");
    salt.extend_from_slice(&moot_id);
    salt
}

/// Sign one membership record at a position in the signer's p2panda log.
pub fn to_operation_seed(
    signing_seed: [u8; 32],
    moot_id: [u8; 32],
    record: &MootMembershipRecord,
    seq_num: u32,
    backlink: Option<[u8; 32]>,
) -> Operation<MootGroupExt> {
    let signing_key = SigningKey::from_bytes(&signing_seed);
    let bytes = encode_cbor(record).expect("a membership record always CBOR-encodes");
    let body = Body::from_bytes(&bytes);
    // p2panda 0.7.1 made the header's CBOR cache, size and digest private
    // and folded signing into the builder: `build` encodes, signs and
    // caches the digest in one step, so the struct-literal + `sign` pair
    // has no equivalent. `body` sets payload_size and payload_hash.
    let header = Header::builder()
        .body(&bytes)
        .seq_num(seq_num)
        .backlink(backlink.map(Hash::from))
        .build(&signing_key, MootGroupExt { moot_id });
    let hash = header.hash();
    Operation {
        hash,
        header,
        body: Some(body),
    }
}

/// Decode the stable Gemot record without independently checking its signature.
pub fn from_operation(
    operation: &Operation<MootGroupExt>,
) -> Result<MootMembershipRecord, MootGroupWireError> {
    let body = operation
        .body
        .as_ref()
        .ok_or(MootGroupWireError::MissingBody)?;
    decode_cbor(body.to_bytes().as_slice()).map_err(|_| MootGroupWireError::Malformed)
}

/// Translate a structurally verified wire operation into the p2panda-auth
/// operation consumed by [`super::MootGroup`].
pub fn to_group_operation(
    operation: &Operation<MootGroupExt>,
) -> Result<MootGroupOperation, MootGroupWireError> {
    let record = from_operation(operation)?;
    let author = stable_author(operation, record.author_attestation.as_ref())?;
    Ok(MootGroupOperation {
        id: MootGroupOperationId(*operation.hash.as_bytes()),
        author: MootGroupHandle(author),
        dependencies: record
            .dependencies
            .into_iter()
            .map(MootGroupOperationId)
            .collect(),
        group: MootGroupHandle(operation.header.extensions.moot_id),
        action: to_auth_action(record.action),
    })
}

fn stable_author(
    operation: &Operation<MootGroupExt>,
    attestation: Option<&DerivedKeyAttestation>,
) -> Result<[u8; 32], MootGroupWireError> {
    let signer = *operation.header.verifying_key.as_bytes();
    let Some(attestation) = attestation else {
        return Ok(signer);
    };
    if !attestation.verify(&membership_identity_salt(
        operation.header.extensions.moot_id,
    )) {
        return Err(MootGroupWireError::InvalidAttestation);
    }
    let derived = attestation
        .derived_public_key()
        .map_err(identity_error)?
        .to_bytes();
    if derived != signer {
        return Err(MootGroupWireError::AttestationMismatch);
    }
    attestation
        .master_public_key()
        .map(|key| key.to_bytes())
        .map_err(identity_error)
}

fn identity_error(_: IdentityError) -> MootGroupWireError {
    MootGroupWireError::InvalidIdentity
}

fn to_auth_action(action: MootMembershipAction) -> GroupAction<MootGroupHandle> {
    match action {
        MootMembershipAction::Create { initial_members } => GroupAction::Create {
            initial_members: initial_members
                .into_iter()
                .map(|member| {
                    (
                        GroupMember::Individual(MootGroupHandle(member.member)),
                        access(member.access),
                    )
                })
                .collect(),
        },
        MootMembershipAction::Add {
            member,
            access: level,
        } => GroupAction::Add {
            member: GroupMember::Individual(MootGroupHandle(member)),
            access: access(level),
        },
        MootMembershipAction::Remove { member } => GroupAction::Remove {
            member: GroupMember::Individual(MootGroupHandle(member)),
        },
        MootMembershipAction::Promote {
            member,
            access: level,
        } => GroupAction::Promote {
            member: GroupMember::Individual(MootGroupHandle(member)),
            access: access(level),
        },
        MootMembershipAction::Demote {
            member,
            access: level,
        } => GroupAction::Demote {
            member: GroupMember::Individual(MootGroupHandle(member)),
            access: access(level),
        },
    }
}

fn access(level: super::MootAccessLevel) -> Access<()> {
    Access {
        conditions: None,
        level: match level {
            super::MootAccessLevel::Pull => AccessLevel::Pull,
            super::MootAccessLevel::Read => AccessLevel::Read,
            super::MootAccessLevel::Write => AccessLevel::Write,
            super::MootAccessLevel::Manage => AccessLevel::Manage,
        },
    }
}
