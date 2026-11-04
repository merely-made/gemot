// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

pub(super) fn verify_revision(
    signed: &SignedPublicationRevisionV1,
    content: &[u8],
) -> Result<[u8; 32], AnyError> {
    let revision = &signed.revision;
    ensure(revision.version == 1, "unsupported publication revision")?;
    ensure(
        publication_id(revision.author_root, &revision.slug) == revision.publication_id,
        "publication id does not bind its author root and slug",
    )?;
    ensure(
        revision.path.starts_with('/'),
        "publication path is not rooted",
    )?;
    ensure(
        revision.media_type == "text/gemini",
        "publication media type is not served by this proof",
    )?;
    ensure(
        revision.content.verifies(content),
        "content reference is false",
    )?;
    let author = signed
        .author_attestation
        .check(PUBLICATION_SALT)
        .map_err(|fault| failure(format!("author derived-key attestation: {fault}")))?;
    ensure(
        author.master() == &revision.author_root,
        "author attestation belongs to another root",
    )?;
    let signature: [u8; 64] = signed
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| failure("publication signature is not 64 bytes"))?;
    ensure(
        signed.author_attestation.derived_public_key()?.verify(
            &signature_message(REVISION_SIGNATURE_DOMAIN, revision)?,
            &Ed25519Signature::from_bytes(&signature),
        ),
        "publication signature is false",
    )?;
    Ok(digest(&serde_json::to_vec(signed)?))
}

pub(super) fn verify_hosting(signed: &SignedHostingCommitmentV1) -> Result<(), AnyError> {
    let commitment = &signed.commitment;
    ensure(commitment.version == 1, "unsupported hosting commitment")?;
    let host = signed
        .host_attestation
        .check(HOSTING_SALT)
        .map_err(|fault| failure(format!("host derived-key attestation: {fault}")))?;
    ensure(
        host.master() == &commitment.host_root,
        "host attestation belongs to another root",
    )?;
    let signature: [u8; 64] = signed
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| failure("hosting signature is not 64 bytes"))?;
    ensure(
        signed.host_attestation.derived_public_key()?.verify(
            &signature_message(HOSTING_SIGNATURE_DOMAIN, commitment)?,
            &Ed25519Signature::from_bytes(&signature),
        ),
        "hosting signature is false",
    )
}

pub(super) fn validate_contribution(
    operation: &Operation<MootExt>,
    signed: &SignedPublicationRevisionV1,
    revision_id: [u8; 32],
    expected_moot: [u8; 32],
    policy: FixturePolicy,
) -> Result<(), AnyError> {
    ensure(verify_moot(operation), "contribution operation is invalid")?;
    let (moot_id, event) = moot_from_operation(operation)?;
    ensure(
        moot_id == expected_moot,
        "contribution addresses another moot",
    )?;
    ensure(
        signed.revision.author_root == policy.author_root,
        "publication update authority is not admitted",
    )?;
    ensure(
        stable_moot_author(operation)? == signed.revision.author_root,
        "contribution signer is not bound to the publication author root",
    )?;
    match event {
        MootEvent::Shared {
            manifest_id,
            schema_id,
            ..
        } => {
            ensure(
                manifest_id == revision_id,
                "contribution names another revision",
            )?;
            ensure(schema_id == SCHEMA_ID, "contribution has another schema")?;
        }
        _ => return Err(failure("contribution is not a Shared event")),
    }
    Ok(())
}

pub(super) fn validate_hosting(
    signed: &SignedHostingCommitmentV1,
    expected_revision: [u8; 32],
    content_len: usize,
    policy: FixturePolicy,
) -> Result<(), AnyError> {
    verify_hosting(signed)?;
    let commitment = &signed.commitment;
    ensure(
        commitment.moot_id == MOOT_ID,
        "hosting promise addresses another moot",
    )?;
    ensure(
        commitment.revision_id == expected_revision,
        "hosting promise names another revision",
    )?;
    ensure(
        commitment.host_root == policy.host_root,
        "host is not admitted",
    )?;
    ensure(
        commitment.audience == "public",
        "hosting audience is not public",
    )?;
    ensure(
        commitment.max_bytes <= policy.max_bytes && content_len as u64 <= commitment.max_bytes,
        "hosting byte bound is exceeded",
    )?;
    ensure(
        commitment.at_ms <= commitment.retain_until_ms,
        "hosting promise expires before it begins",
    )?;
    ensure(
        now_ms() <= commitment.retain_until_ms,
        "hosting promise has expired",
    )?;
    ensure(
        commitment.policy_revision == policy.policy_revision,
        "hosting policy revision is stale",
    )?;
    Ok(())
}

pub(super) fn validate_bundle(bundle: &PublicProofBundle, content: &[u8]) -> Result<(), AnyError> {
    let policy = policy();
    let revision_id = verify_revision(&bundle.revision, content)?;
    let contribution =
        decode_moot_operation(&bundle.contribution_header, &bundle.contribution_body)?;
    validate_contribution(
        &contribution,
        &bundle.revision,
        revision_id,
        MOOT_ID,
        policy,
    )?;
    validate_hosting(&bundle.hosting, revision_id, content.len(), policy)?;
    let standing = decode_standing_operation(&bundle.standing_header, &bundle.standing_body)?;
    ensure(verify_standing(&standing), "Standing operation is invalid")?;
    let (moot_id, event) = standing_from_operation(&standing)
        .map_err(|_| failure("Standing operation does not decode"))?;
    ensure(
        moot_id == MOOT_ID,
        "Standing operation addresses another moot",
    )?;
    ensure(
        mien::stable_author(&standing)?.0 == bundle.hosting.commitment.host_root,
        "Standing signer is not bound to the host root",
    )?;
    match event {
        StandingEvent::CommitmentMade {
            by,
            commitment,
            scope,
            ..
        } => {
            ensure(
                by.0 == bundle.hosting.commitment.host_root,
                "Standing names another host",
            )?;
            ensure(
                commitment.0 == digest(&serde_json::to_vec(&bundle.hosting)?),
                "Standing names another hosting promise",
            )?;
            ensure(
                scope.0.contains(&hex(&revision_id)),
                "Standing scope omits the revision",
            )?;
        }
        _ => return Err(failure("Standing operation is not a commitment")),
    }
    Ok(())
}
