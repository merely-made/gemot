// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Three-process proof that a moot member can retain and serve an author's
//! exact public page after the author exits.
//!
//! This is deliberately a rehearsal, not the shipping publication grammar.
//! The stable publication revision and full hosting promise are proof-local V1
//! records because neither domain type exists yet. Existing seams do the real
//! work around them: Personae roots and derived-key attestations, current Gemot
//! membership and typed capability authority, signed contribution and Standing
//! operations, Stickleback native drops, durable Muniment stores, Errand's
//! Source adapter, and a normal Gemini TLS client.
//!
//! Run the complete proof with:
//!
//! ```text
//! cargo run -p gemot --example author-offline-publication -- run [receipt-dir]
//! ```

use std::error::Error;
use std::fs;
use std::io::{Cursor, Error as IoError, ErrorKind};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use errand::serve::{Item, SourceRequest};
use gemot::moot::constitution::{CapabilityGrant, ConstitutionRules};
use gemot::moot::records::fauna_cap;
use gemot::moot::standing::wire::{
    StandingExt, from_operation as standing_from_operation, verify as verify_standing,
};
use gemot::moot::standing::{ChainRoot, CommitmentId, GateDecision, Scope, StandingEvent};
use gemot::moot::{
    AvailabilityPolicy, ErasurePolicy, KeepBound, MootAccessLevel, MootAuthorizationRequest,
    MootError, MootEvent, MootExt, MootFile, MootId, MootMember, MootMembershipAction,
    MootOutboundOperation, MootRetentionSettings, PolicyRevision,
    from_operation as moot_from_operation, stable_author as stable_moot_author,
    verify as verify_moot,
};
use identity::{DerivedKeyAttestation, Ed25519Signature, IdentityProvider, InMemoryProvider};
use p2panda_core::{Body, Header, Operation};
use proofs::BlobRef;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use servitor::{Cap, cap_path};
use stickleback::{
    DropExportProfile, DropLimits, DropRecord, decode_operation_record, read_plain_drop,
    write_plain_drop,
};
use transport::{BlobHash, BlobLease, BlobReadAuthorizer, BlobScope, BlobStore, P2pandaTransport};

type AnyError = Box<dyn Error + Send + Sync>;

const MOOT_ID: [u8; 32] = [0x6d; 32];
const POLICY_REVISION: [u8; 32] = [0x51; 32];
const PUBLICATION_SALT: &[u8] = b"gemot/publication-author/v1";
const HOSTING_SALT: &[u8] = b"gemot/publication-host/v1";
const PUBLICATION_DOMAIN: &[u8] = b"gemot/publication-id/v1\0";
const REVISION_SIGNATURE_DOMAIN: &[u8] = b"gemot/publication-revision/v1\0";
const HOSTING_SIGNATURE_DOMAIN: &[u8] = b"gemot/hosting-commitment/v1\0";
const SCHEMA_ID: &str = "gemot.publication-revision.v1";
const PAGE_PATH: &str = "/garden.gmi";
const PAGE: &[u8] =
    b"# The borrowed garden\n\nA page can outlive the machine that first shared it.\n";
const FOUNDER_SEED: [u8; 32] = [0xe5; 32];
const AUTHOR_GRANT: [u8; 32] = [0xa6; 32];
const HOST_GRANT: [u8; 32] = [0xb6; 32];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct PublicationRevisionV1 {
    version: u16,
    publication_id: [u8; 32],
    slug: String,
    author_root: [u8; 32],
    parent: Option<[u8; 32]>,
    path: String,
    media_type: String,
    content: BlobRef,
    at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SignedPublicationRevisionV1 {
    revision: PublicationRevisionV1,
    author_attestation: DerivedKeyAttestation,
    signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct HostingCommitmentV1 {
    version: u16,
    moot_id: [u8; 32],
    revision_id: [u8; 32],
    host_root: [u8; 32],
    audience: String,
    max_bytes: u64,
    retain_until_ms: u64,
    policy_revision: [u8; 32],
    at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SignedHostingCommitmentV1 {
    commitment: HostingCommitmentV1,
    host_attestation: DerivedKeyAttestation,
    signature: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PublicProofBundle {
    revision: SignedPublicationRevisionV1,
    contribution_header: Vec<u8>,
    contribution_body: Vec<u8>,
    standing_header: Vec<u8>,
    standing_body: Vec<u8>,
    hosting: SignedHostingCommitmentV1,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Ready {
    pid: u32,
    port: u16,
    certificate_blake3: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AuthorReceipt {
    pid: u32,
    root: [u8; 32],
    store: String,
    transport_store: String,
    ticket: String,
    drop_id: [u8; 32],
    drop_blob_hash: [u8; 32],
    publication_id: [u8; 32],
    revision_id: [u8; 32],
    content_hash: [u8; 32],
    contribution_operation: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct HostReceipt {
    pid: u32,
    root: [u8; 32],
    store: String,
    standing_store: String,
    transport_store: String,
    transfer_source: [u8; 32],
    imported_drop: [u8; 32],
    standing_operation: [u8; 32],
    corrupt_drop_refused: bool,
    foreign_moot_refused: bool,
    unauthorized_update_refused: bool,
    unauthorized_host_refused: bool,
    unadmitted_peer_refused: bool,
    live_peer_transfer: bool,
    constitution_operations: u64,
    membership_operations: u64,
    authorized_contribution_visible: bool,
    author_command_authorized: bool,
    host_command_authorized: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReaderReceipt {
    pid: u32,
    root: [u8; 32],
    cache_started_empty: bool,
    source: String,
    raw_status: u8,
    unpublished_path_status: u8,
    media_type: String,
    content_hash: [u8; 32],
    author_root: [u8; 32],
    contributor_key: [u8; 32],
    host_root: [u8; 32],
    hosting_signer: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct FinalReceipt {
    proof: String,
    transport: String,
    author_exited_before_host_restart: bool,
    independent_roots: bool,
    exact_page_after_restart: bool,
    author: AuthorReceipt,
    host: HostReceipt,
    serving: Ready,
    reader: ReaderReceipt,
    lifecycle: LifecycleReceipt,
    limitations: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LifecycleReceipt {
    author_ready_ms: u64,
    host_import_complete_ms: u64,
    author_exit_ms: u64,
    host_restart_ready_ms: u64,
    reader_complete_ms: u64,
    host_exit_ms: u64,
    author_exit_success: bool,
    host_exit_success: bool,
}

#[derive(Clone, Copy)]
struct FixturePolicy {
    author_root: [u8; 32],
    host_root: [u8; 32],
    max_bytes: u64,
    policy_revision: [u8; 32],
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn author() -> InMemoryProvider {
    InMemoryProvider::from_seed([0xa1; 32])
}

fn host() -> InMemoryProvider {
    InMemoryProvider::from_seed([0xb2; 32])
}

fn reader() -> InMemoryProvider {
    InMemoryProvider::from_seed([0xc3; 32])
}

fn intruder() -> InMemoryProvider {
    InMemoryProvider::from_seed([0xd4; 32])
}

fn founder() -> InMemoryProvider {
    InMemoryProvider::from_seed(FOUNDER_SEED)
}

fn retention() -> MootRetentionSettings {
    MootRetentionSettings {
        revision: PolicyRevision(proofs::Digest::blake3(b"author-offline publication proof")),
        availability: AvailabilityPolicy {
            promised_floor: KeepBound::Forever,
        },
        erasure: ErasurePolicy {
            history_ceiling: KeepBound::UntilCheckpoint,
        },
    }
}

fn hosting_cap() -> Cap {
    Cap::scope("moot/hosting/public").expect("fixed hosting scope is valid")
}

fn policy() -> FixturePolicy {
    FixturePolicy {
        author_root: author().master_public_key().to_bytes(),
        host_root: host().master_public_key().to_bytes(),
        max_bytes: 64 * 1024,
        policy_revision: POLICY_REVISION,
    }
}

fn publication_id(author_root: [u8; 32], slug: &str) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(PUBLICATION_DOMAIN.len() + 32 + 8 + slug.len());
    bytes.extend_from_slice(PUBLICATION_DOMAIN);
    bytes.extend_from_slice(&author_root);
    bytes.extend_from_slice(&(slug.len() as u64).to_le_bytes());
    bytes.extend_from_slice(slug.as_bytes());
    proofs::Digest::blake3(&bytes)
        .as_32()
        .expect("BLAKE3 is 32 bytes")
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    proofs::Digest::blake3(bytes)
        .as_32()
        .expect("BLAKE3 is 32 bytes")
}

fn signature_message(domain: &[u8], value: &impl Serialize) -> Result<Vec<u8>, AnyError> {
    let body = serde_json::to_vec(value)?;
    let mut message = Vec::with_capacity(domain.len() + body.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(&body);
    Ok(message)
}

fn sign_revision(
    provider: &InMemoryProvider,
    revision: PublicationRevisionV1,
) -> Result<SignedPublicationRevisionV1, AnyError> {
    let key = provider.derive_keypair(PUBLICATION_SALT)?;
    let signature = key
        .sign(&signature_message(REVISION_SIGNATURE_DOMAIN, &revision)?)
        .to_bytes()
        .to_vec();
    Ok(SignedPublicationRevisionV1 {
        revision,
        author_attestation: provider.attest_derived_key(PUBLICATION_SALT)?,
        signature,
    })
}

fn sign_hosting(
    provider: &InMemoryProvider,
    commitment: HostingCommitmentV1,
) -> Result<SignedHostingCommitmentV1, AnyError> {
    let key = provider.derive_keypair(HOSTING_SALT)?;
    let signature = key
        .sign(&signature_message(HOSTING_SIGNATURE_DOMAIN, &commitment)?)
        .to_bytes()
        .to_vec();
    Ok(SignedHostingCommitmentV1 {
        commitment,
        host_attestation: provider.attest_derived_key(HOSTING_SALT)?,
        signature,
    })
}

fn verify_revision(
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
    ensure(
        signed.author_attestation.verify(PUBLICATION_SALT),
        "author derived-key attestation is false",
    )?;
    ensure(
        signed.author_attestation.master_public_key()?.to_bytes() == revision.author_root,
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

fn verify_hosting(signed: &SignedHostingCommitmentV1) -> Result<(), AnyError> {
    let commitment = &signed.commitment;
    ensure(commitment.version == 1, "unsupported hosting commitment")?;
    ensure(
        signed.host_attestation.verify(HOSTING_SALT),
        "host derived-key attestation is false",
    )?;
    ensure(
        signed.host_attestation.master_public_key()?.to_bytes() == commitment.host_root,
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

fn decode_moot_operation(header: &[u8], body: &[u8]) -> Result<Operation<MootExt>, AnyError> {
    let header = Header::<MootExt>::decode(header).map_err(|error| failure(error.to_string()))?;
    let hash = header.hash();
    Ok(Operation {
        hash,
        header,
        body: Some(Body::from(body.to_vec())),
    })
}

fn decode_standing_operation(
    header: &[u8],
    body: &[u8],
) -> Result<Operation<StandingExt>, AnyError> {
    let header =
        Header::<StandingExt>::decode(header).map_err(|error| failure(error.to_string()))?;
    let hash = header.hash();
    Ok(Operation {
        hash,
        header,
        body: Some(Body::from(body.to_vec())),
    })
}

fn validate_contribution(
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
        },
        _ => return Err(failure("contribution is not a Shared event")),
    }
    Ok(())
}

fn validate_hosting(
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

fn validate_bundle(bundle: &PublicProofBundle, content: &[u8]) -> Result<(), AnyError> {
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
        gemot::moot::standing::stable_author(&standing)?.0 == bundle.hosting.commitment.host_root,
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
        },
        _ => return Err(failure("Standing operation is not a commitment")),
    }
    Ok(())
}

fn ensure(condition: bool, message: impl Into<String>) -> Result<(), AnyError> {
    if condition {
        Ok(())
    } else {
        Err(failure(message))
    }
}

fn failure(message: impl Into<String>) -> AnyError {
    Box::new(IoError::new(ErrorKind::Other, message.into()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), AnyError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, AnyError> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn receipt_path(root: &Path, name: &str) -> PathBuf {
    root.join("receipts").join(format!("{name}.json"))
}

async fn author_process(root: &Path) -> Result<(), AnyError> {
    let provider = author();
    let root_key = provider.master_public_key().to_bytes();
    let author_dir = root.join("author");
    fs::create_dir_all(&author_dir)?;
    let store_path = author_dir.join("moot");
    let founder_root = founder().master_public_key().to_bytes();
    let moot = MootFile::open(&store_path, MootId(MOOT_ID), founder_root, retention()).await?;
    let mut rules = ConstitutionRules::founder_only(founder_root);
    rules.admission = gemot::moot::standing::Policy::MembersOnly {
        rate_limit: 20,
        rate_window_ms: 60_000,
    };
    rules.grant(CapabilityGrant {
        id: AUTHOR_GRANT,
        subject: root_key,
        path_prefix: cap_path(&fauna_cap()),
        not_before_ms: 0,
        expires_at_ms: None,
        delegation_depth: 0,
    });
    rules.grant(CapabilityGrant {
        id: HOST_GRANT,
        subject: host().master_public_key().to_bytes(),
        path_prefix: cap_path(&hosting_cap()),
        not_before_ms: 0,
        expires_at_ms: None,
        delegation_depth: 0,
    });
    moot.found(FOUNDER_SEED, None, None, rules, now_ms())
        .await?;
    moot.update_membership_for_identity(
        &founder(),
        MootMembershipAction::Create {
            initial_members: vec![
                MootMember {
                    member: founder_root,
                    access: MootAccessLevel::Manage,
                },
                MootMember {
                    member: root_key,
                    access: MootAccessLevel::Write,
                },
                MootMember {
                    member: host().master_public_key().to_bytes(),
                    access: MootAccessLevel::Write,
                },
            ],
        },
    )
    .await?;
    let content = moot.object_store().sync_store().put_blob(PAGE).await?;

    let revision = PublicationRevisionV1 {
        version: 1,
        publication_id: publication_id(root_key, "borrowed-garden"),
        slug: "borrowed-garden".into(),
        author_root: root_key,
        parent: None,
        path: PAGE_PATH.into(),
        media_type: "text/gemini".into(),
        content: content.clone(),
        at_ms: now_ms(),
    };
    let signed = sign_revision(&provider, revision)?;
    let revision_bytes = serde_json::to_vec(&signed)?;
    let revision_ref = moot
        .object_store()
        .sync_store()
        .put_blob(&revision_bytes)
        .await?;
    let revision_id = revision_ref.digest.as_32()?;
    verify_revision(&signed, PAGE)?;

    let contribution_receipt = moot
        .share_authorized_for_identity(
            &provider,
            revision_id,
            SCHEMA_ID.into(),
            "The borrowed garden".into(),
            now_ms(),
        )
        .await?;
    let contribution = match moot.outbound(&contribution_receipt).await? {
        MootOutboundOperation::Object(operation) => operation,
        _ => return Err(failure("share command returned another lane")),
    };
    validate_contribution(&contribution, &signed, revision_id, MOOT_ID, policy())?;

    let content_hash = content.digest.as_32()?;
    let mut aggregate = Vec::new();
    moot.export_plain_drop(
        &mut aggregate,
        DropExportProfile::default(),
        DropLimits::default(),
    )
    .await?;
    let (_, mut records) = read_plain_drop(Cursor::new(aggregate), DropLimits::default())?;
    records.push(DropRecord::BlobChunk {
        blob_hash: revision_id,
        offset: 0,
        bytes: revision_bytes,
    });
    records.push(DropRecord::BlobChunk {
        blob_hash: content_hash,
        offset: 0,
        bytes: PAGE.to_vec(),
    });
    let mut drop_bytes = Vec::new();
    let drop_receipt = write_plain_drop(&mut drop_bytes, &records, DropLimits::default())?;
    let transfer_store = BlobStore::new();
    let transfer_hash = transfer_store.put_bytes(drop_bytes).await?;
    let scope = BlobScope::new(MOOT_ID);
    let transfer_authority = BlobReadAuthorizer::new();
    transfer_authority.retain(scope, transfer_hash);
    transfer_authority.allow_reader(scope, host().master_public_key().to_bytes());
    let transport = P2pandaTransport::builder(provider.master_keypair())
        .scoped_blobs(&transfer_store, scope, transfer_authority)
        .bind()
        .await?;
    let ticket = transport.ticket().await?;

    write_json(
        &receipt_path(root, "author"),
        &AuthorReceipt {
            pid: std::process::id(),
            root: root_key,
            store: store_path.display().to_string(),
            transport_store: "memory (author process lifetime)".into(),
            ticket,
            drop_id: drop_receipt.id.0,
            drop_blob_hash: transfer_hash.to_bytes(),
            publication_id: signed.revision.publication_id,
            revision_id,
            content_hash,
            contribution_operation: *contribution.hash.as_bytes(),
        },
    )?;
    let stop = root.join("author-stop");
    while !stop.exists() {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    transport.close().await?;
    transfer_store.shutdown().await?;
    Ok(())
}

async fn host_import_process(root: &Path) -> Result<(), AnyError> {
    let fixture_policy = policy();
    let host_provider = host();
    let host_root = host_provider.master_public_key().to_bytes();
    let host_dir = root.join("host");
    fs::create_dir_all(&host_dir)?;
    let store_path = host_dir.join("moot");
    let standing_path = store_path.join("standing.redb");
    let transport_store_path = host_dir.join("ingress-blobs");
    let moot = MootFile::open(
        &store_path,
        MootId(MOOT_ID),
        founder().master_public_key().to_bytes(),
        retention(),
    )
    .await?;
    let author_receipt: AuthorReceipt = read_json(&receipt_path(root, "author"))?;
    let ingress = BlobStore::open(&transport_store_path).await?;
    let host_transport = P2pandaTransport::builder(host_provider.master_keypair())
        .bind()
        .await?;
    let author_peer = host_transport
        .add_peer_ticket(&author_receipt.ticket)
        .await?;
    ensure(
        author_peer.to_bytes() == author_receipt.root,
        "author ticket carries another transport identity",
    )?;
    let transfer_hash = BlobHash::from_bytes(author_receipt.drop_blob_hash);

    let attacker_provider = intruder();
    let attacker_ingress = BlobStore::new();
    let attacker_transport = P2pandaTransport::builder(attacker_provider.master_keypair())
        .bind()
        .await?;
    let attacker_author_peer = attacker_transport
        .add_peer_ticket(&author_receipt.ticket)
        .await?;
    let unadmitted_peer_refused = attacker_ingress
        .fetch_from(&attacker_transport, attacker_author_peer, transfer_hash)
        .await
        .is_err();
    ensure(
        unadmitted_peer_refused,
        "unadmitted transport peer fetched the publication drop",
    )?;
    ensure(
        !attacker_ingress.has(transfer_hash).await?,
        "refused peer retained publication bytes",
    )?;
    attacker_transport.close().await?;

    let transfer_lease = BlobLease::new(
        BlobScope::new(MOOT_ID),
        "gemot.publication.drop",
        author_receipt.drop_id,
    )?;
    ingress
        .fetch_from_named(
            &host_transport,
            author_peer,
            transfer_hash,
            transfer_lease.as_bytes(),
        )
        .await?;
    ingress.flush().await?;
    let valid_drop = ingress.get_bytes(transfer_hash).await?.to_vec();
    let live_peer_transfer = digest(&valid_drop) == author_receipt.drop_blob_hash;
    ensure(
        live_peer_transfer,
        "live peer transfer changed the drop bytes",
    )?;

    let mut corrupt_drop = valid_drop.clone();
    let last = corrupt_drop
        .last_mut()
        .ok_or_else(|| failure("drop was empty"))?;
    *last ^= 0x01;
    let corrupt_drop_refused =
        read_plain_drop(Cursor::new(corrupt_drop), DropLimits::default()).is_err();
    ensure(corrupt_drop_refused, "corrupt drop was accepted")?;
    ensure(
        moot.object_store().ops(MOOT_ID).await?.is_empty(),
        "corrupt drop mutated host store",
    )?;

    let foreign_key = author().derive_keypair(PUBLICATION_SALT)?;
    let foreign = gemot::moot::to_operation_seed(
        foreign_key.to_seed(),
        [0xee; 32],
        &MootEvent::Shared {
            manifest_id: [1; 32],
            schema_id: SCHEMA_ID.into(),
            title: "foreign".into(),
            at_ms: now_ms(),
        },
        0,
        None,
    );
    let foreign_moot_refused = moot.object_store().accept(MOOT_ID, &foreign).await.is_err();
    ensure(foreign_moot_refused, "foreign moot operation was accepted")?;
    ensure(
        moot.object_store().ops(MOOT_ID).await?.is_empty(),
        "foreign operation mutated host store",
    )?;

    let (drop_report, records) = read_plain_drop(Cursor::new(&valid_drop), DropLimits::default())?;
    let contribution = records
        .iter()
        .filter_map(|record| decode_operation_record::<MootExt>(record).ok().flatten())
        .find(|operation| *operation.hash.as_bytes() == author_receipt.contribution_operation)
        .ok_or_else(|| failure("drop has no contribution"))?;
    let blobs = records
        .iter()
        .filter_map(|record| match record {
            DropRecord::BlobChunk {
                blob_hash, bytes, ..
            } => Some((*blob_hash, bytes.clone())),
            _ => None,
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let (_, event) = moot_from_operation(&contribution)?;
    let revision_id = match event {
        MootEvent::Shared { manifest_id, .. } => manifest_id,
        _ => return Err(failure("drop operation is not Shared")),
    };
    let revision_bytes = blobs
        .get(&revision_id)
        .ok_or_else(|| failure("drop omits publication revision"))?;
    let signed_revision: SignedPublicationRevisionV1 = serde_json::from_slice(revision_bytes)?;
    let content_hash = signed_revision.revision.content.digest.as_32()?;
    let content = blobs
        .get(&content_hash)
        .ok_or_else(|| failure("drop omits publication content"))?;
    let verified_revision_id = verify_revision(&signed_revision, content)?;
    ensure(
        verified_revision_id == revision_id,
        "revision blob has a false id",
    )?;
    validate_contribution(
        &contribution,
        &signed_revision,
        revision_id,
        MOOT_ID,
        fixture_policy,
    )?;

    let attacker = intruder();
    let attacker_root = attacker.master_public_key().to_bytes();
    let unauthorized_revision = sign_revision(
        &attacker,
        PublicationRevisionV1 {
            version: 1,
            publication_id: signed_revision.revision.publication_id,
            slug: signed_revision.revision.slug.clone(),
            author_root: signed_revision.revision.author_root,
            parent: Some(revision_id),
            path: PAGE_PATH.into(),
            media_type: "text/gemini".into(),
            content: BlobRef::blake3(content),
            at_ms: now_ms(),
        },
    )?;
    let unauthorized_bytes = serde_json::to_vec(&unauthorized_revision)?;
    let unauthorized_id = digest(&unauthorized_bytes);
    let forged_revision_refused = verify_revision(&unauthorized_revision, content).is_err();

    let import_receipt = moot
        .import_plain_drop(Cursor::new(&valid_drop), DropLimits::default())
        .await?;
    let authorized = moot.authorized_fauna(now_ms()).await?;
    let authorized_contribution_visible = authorized.len() == 1
        && authorized[0].manifest_id == revision_id
        && authorized[0].shared_by == signed_revision.revision.author_root;
    ensure(
        authorized_contribution_visible,
        "imported contribution is absent from the current authorized projection",
    )?;
    let before_unauthorized_share = moot.object_store().ops(MOOT_ID).await?.len();
    let unauthorized_command = moot
        .share_authorized_for_identity(
            &attacker,
            unauthorized_id,
            SCHEMA_ID.into(),
            "forged update".into(),
            now_ms(),
        )
        .await;
    let unauthorized_update_refused = forged_revision_refused
        && matches!(unauthorized_command, Err(MootError::Unauthorized(_)))
        && moot.object_store().ops(MOOT_ID).await?.len() == before_unauthorized_share;
    ensure(
        unauthorized_update_refused,
        "unauthorized update command changed the retained object lane",
    )?;
    ensure(
        moot.object_store()
            .sync_store()
            .get_blob(&signed_revision.revision.content)
            .await?
            == Some(content.clone()),
        "host did not retain exact content",
    )?;

    let commitment = HostingCommitmentV1 {
        version: 1,
        moot_id: MOOT_ID,
        revision_id,
        host_root,
        audience: "public".into(),
        max_bytes: content.len() as u64,
        retain_until_ms: now_ms() + 86_400_000,
        policy_revision: POLICY_REVISION,
        at_ms: now_ms(),
    };
    let hosting = sign_hosting(&host_provider, commitment)?;
    validate_hosting(&hosting, revision_id, content.len(), fixture_policy)?;

    let hosting_id = digest(&serde_json::to_vec(&hosting)?);
    let standing_event = StandingEvent::CommitmentMade {
        by: ChainRoot(host_root),
        commitment: CommitmentId(hosting_id),
        scope: Scope(format!(
            "publication/{}/{}/public/{}",
            hex(&MOOT_ID),
            hex(&revision_id),
            hosting.commitment.max_bytes
        )),
        cadence_ms: 3_600_000,
        duration_ms: Some(86_400_000),
        at_ms: hosting.commitment.at_ms,
    };
    let standing_before_refusal = moot.standing_store().len().await?;
    let unauthorized_event = StandingEvent::CommitmentMade {
        by: ChainRoot(attacker_root),
        commitment: CommitmentId(hosting_id),
        scope: Scope(format!(
            "publication/{}/{}/public/{}",
            hex(&MOOT_ID),
            hex(&revision_id),
            hosting.commitment.max_bytes
        )),
        cadence_ms: 3_600_000,
        duration_ms: Some(86_400_000),
        at_ms: hosting.commitment.at_ms,
    };
    let unauthorized_host_refused = matches!(
        moot.record_standing_authorized_for_identity(
            &attacker,
            unauthorized_event,
            &hosting_cap(),
        )
        .await,
        Err(MootError::Unauthorized(_))
    ) && moot.standing_store().len().await?
        == standing_before_refusal;
    ensure(unauthorized_host_refused, "unauthorized host passed policy")?;
    let standing_receipt = moot
        .record_standing_authorized_for_identity(&host_provider, standing_event, &hosting_cap())
        .await?;
    let host_command_authorized = true;
    let standing = match moot.outbound(&standing_receipt).await? {
        MootOutboundOperation::Standing(operation) => operation,
        _ => return Err(failure("hosting command returned another lane")),
    };

    let bundle = PublicProofBundle {
        revision: signed_revision,
        contribution_header: contribution.header.encode(),
        contribution_body: contribution.body.as_ref().unwrap().to_bytes(),
        standing_header: standing.header.encode(),
        standing_body: standing.body.as_ref().unwrap().to_bytes(),
        hosting,
    };
    validate_bundle(&bundle, content)?;
    write_json(&host_dir.join("proof-bundle.json"), &bundle)?;
    write_json(
        &receipt_path(root, "host-import"),
        &HostReceipt {
            pid: std::process::id(),
            root: host_root,
            store: store_path.display().to_string(),
            standing_store: standing_path.display().to_string(),
            transport_store: transport_store_path.display().to_string(),
            transfer_source: author_receipt.root,
            imported_drop: drop_report.id.0,
            standing_operation: *standing.hash.as_bytes(),
            corrupt_drop_refused,
            foreign_moot_refused,
            unauthorized_update_refused,
            unauthorized_host_refused,
            unadmitted_peer_refused,
            live_peer_transfer,
            constitution_operations: import_receipt.constitution_operations,
            membership_operations: import_receipt.membership_operations,
            authorized_contribution_visible,
            author_command_authorized: authorized_contribution_visible,
            host_command_authorized,
        },
    )?;
    host_transport.close().await?;
    ingress.shutdown().await?;
    Ok(())
}

async fn host_serve_process(root: &Path) -> Result<(), AnyError> {
    let host_dir = root.join("host");
    let author_receipt: AuthorReceipt = read_json(&receipt_path(root, "author"))?;
    let ingress = BlobStore::open(host_dir.join("ingress-blobs")).await?;
    let transfer_hash = BlobHash::from_bytes(author_receipt.drop_blob_hash);
    let transfer_lease = BlobLease::new(
        BlobScope::new(MOOT_ID),
        "gemot.publication.drop",
        author_receipt.drop_id,
    )?;
    ensure(
        ingress.lease_hash(&transfer_lease).await? == Some(transfer_hash),
        "restarted host lost its publication transfer lease",
    )?;
    ensure(
        digest(&ingress.get_bytes(transfer_hash).await?) == author_receipt.drop_blob_hash,
        "restarted host has changed publication carrier bytes",
    )?;
    ingress.shutdown().await?;
    let moot = MootFile::open_existing(host_dir.join("moot"), MootId(MOOT_ID), retention()).await?;
    let bundle: PublicProofBundle = read_json(&host_dir.join("proof-bundle.json"))?;
    let content = moot
        .object_store()
        .sync_store()
        .get_blob(&bundle.revision.revision.content)
        .await?
        .ok_or_else(|| failure("reopened host has no content"))?;
    validate_bundle(&bundle, &content)?;
    let contribution =
        decode_moot_operation(&bundle.contribution_header, &bundle.contribution_body)?;
    ensure(
        moot.object_store()
            .operation(&contribution.hash)
            .await?
            .is_some(),
        "reopened host has no contribution operation",
    )?;
    let revision_id = digest(&serde_json::to_vec(&bundle.revision)?);
    ensure(
        moot.authorized_fauna(now_ms())
            .await?
            .iter()
            .any(|entry| entry.manifest_id == revision_id),
        "restarted host no longer authorizes the publication contribution",
    )?;
    let standing = decode_standing_operation(&bundle.standing_header, &bundle.standing_body)?;
    ensure(
        moot.standing_store().get(&standing.hash).await?.is_some(),
        "reopened host has no Standing operation",
    )?;
    let membership = moot.membership().await?;
    ensure(
        moot.authorize_current_capability(
            &membership,
            &MootAuthorizationRequest {
                subject: bundle.hosting.commitment.host_root,
                capability_path: cap_path(&hosting_cap()),
                at_ms: now_ms(),
            },
        )
        .await?
            == GateDecision::Allow,
        "restarted host no longer has current hosting authority",
    )?;

    let page_path = bundle.revision.revision.path.clone();
    let proof_path = format!(
        "/.well-known/mere/{}.json",
        hex(&digest(&serde_json::to_vec(&bundle.revision)?))
    );
    let proof_bytes = serde_json::to_vec_pretty(&bundle)?;
    let source_store = moot.object_store().sync_store();
    let source_ref = bundle.revision.revision.content.clone();
    let source = move |request: &SourceRequest| {
        let request_path = request.path.clone();
        let page_path = page_path.clone();
        let proof_path = proof_path.clone();
        let proof_bytes = proof_bytes.clone();
        let source_store = source_store.clone();
        let source_ref = source_ref.clone();
        async move {
            if request_path == page_path {
                source_store
                    .get_blob(&source_ref)
                    .await
                    .ok()
                    .flatten()
                    .filter(|bytes| source_ref.verifies(bytes))
                    .map(Item::gemtext)
            } else if request_path == proof_path {
                Some(Item::Document {
                    mime: "application/json".into(),
                    body: proof_bytes,
                })
            } else {
                None
            }
        }
    };

    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_bytes = certified.cert.der().to_vec();
    let key_bytes = certified.key_pair.serialize_der();
    let acceptor = gemini_protocol::server::acceptor(
        vec![CertificateDer::from(cert_bytes.clone())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_bytes)),
    )?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let ready = Ready {
        pid: std::process::id(),
        port,
        certificate_blake3: digest(&cert_bytes),
    };
    write_json(&root.join("ready.json"), &ready)?;

    let stop = root.join("stop");
    gemini_protocol::server::serve(
        listener,
        acceptor,
        errand::serve::adapt::gemini(Arc::new(source)),
        gemini_protocol::server::ServerConfig::default(),
        async move {
            loop {
                if stop.exists() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        },
    )
    .await?;
    Ok(())
}

async fn fetch_retry(url: &str) -> Result<errand::Response, AnyError> {
    let mut last = None;
    for _ in 0..40 {
        match errand::fetch(url).await {
            Ok(response) => return Ok(response),
            Err(error) => last = Some(error.to_string()),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(failure(format!(
        "Gemini fetch never connected: {}",
        last.unwrap_or_else(|| "unknown error".into())
    )))
}

async fn reader_process(reader_dir: &Path, base: &str, proof_url: &str) -> Result<(), AnyError> {
    let provider = reader();
    let reader_root = provider.master_public_key().to_bytes();
    let cache = reader_dir.join("cache");
    fs::create_dir_all(&cache)?;
    let cache_started_empty = fs::read_dir(&cache)?.next().is_none();
    ensure(cache_started_empty, "reader cache was not empty")?;
    let proof_response = fetch_retry(proof_url).await?;
    ensure(
        proof_response.raw_status == Some(20),
        "proof bundle was not Gemini 20",
    )?;
    ensure(
        proof_response.meta == "application/json",
        "proof bundle MIME changed",
    )?;
    let bundle: PublicProofBundle = serde_json::from_slice(&proof_response.body)?;

    let page_url = format!("{base}{PAGE_PATH}");
    let page_response = fetch_retry(&page_url).await?;
    ensure(
        page_response.raw_status == Some(20),
        "page was not Gemini 20",
    )?;
    ensure(page_response.meta == "text/gemini", "page MIME changed")?;
    ensure(page_response.body == PAGE, "served page bytes changed")?;
    validate_bundle(&bundle, &page_response.body)?;
    let missing_response = fetch_retry(&format!("{base}/not-published.gmi")).await?;
    ensure(
        missing_response.raw_status == Some(51),
        "unpublished path was visible",
    )?;
    fs::write(cache.join("garden.gmi"), &page_response.body)?;

    let contribution =
        decode_moot_operation(&bundle.contribution_header, &bundle.contribution_body)?;
    let standing = decode_standing_operation(&bundle.standing_header, &bundle.standing_body)?;
    write_json(
        &reader_dir.join("reader.json"),
        &ReaderReceipt {
            pid: std::process::id(),
            root: reader_root,
            cache_started_empty,
            source: page_url,
            raw_status: page_response.raw_status.unwrap_or_default(),
            unpublished_path_status: missing_response.raw_status.unwrap_or_default(),
            media_type: page_response.meta,
            content_hash: digest(&page_response.body),
            author_root: bundle.revision.revision.author_root,
            contributor_key: *contribution.header.verifying_key.as_bytes(),
            host_root: bundle.hosting.commitment.host_root,
            hosting_signer: *standing.header.verifying_key.as_bytes(),
        },
    )?;
    Ok(())
}

fn run_child(exe: &Path, role: &str, root: &Path) -> Result<(), AnyError> {
    let status = Command::new(exe)
        .arg(role)
        .arg(root)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;
    ensure(status.success(), format!("{role} process failed: {status}"))
}

fn wait_for(path: &Path) -> Result<(), AnyError> {
    for _ in 0..200 {
        if path.exists() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Err(failure(format!("timed out waiting for {}", path.display())))
}

fn orchestrate(root: &Path) -> Result<(), AnyError> {
    if root.exists() {
        ensure(
            fs::read_dir(root)?.next().is_none(),
            format!("proof root is not empty: {}", root.display()),
        )?;
    }
    fs::create_dir_all(root)?;
    fs::create_dir_all(root.join("receipts"))?;
    let exe = std::env::current_exe()?;

    let mut author_process = Command::new(&exe)
        .arg("author")
        .arg(root)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    wait_for(&receipt_path(root, "author"))?;
    let author_ready_ms = now_ms();
    let author: AuthorReceipt = read_json(&receipt_path(root, "author"))?;
    let import_result = run_child(&exe, "host-import", root);
    let host_import_complete_ms = now_ms();
    fs::write(root.join("author-stop"), b"stop\n")?;
    let author_status = author_process.wait()?;
    let author_exit_ms = now_ms();
    ensure(
        author_status.success(),
        format!("author process failed: {author_status}"),
    )?;
    import_result?;
    let host: HostReceipt = read_json(&receipt_path(root, "host-import"))?;

    let mut server = Command::new(&exe)
        .arg("host-serve")
        .arg(root)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    wait_for(&root.join("ready.json"))?;
    let host_restart_ready_ms = now_ms();
    let ready: Ready = read_json(&root.join("ready.json"))?;
    let reader_dir = root.join("reader-sandbox");
    fs::create_dir(&reader_dir)?;
    let base = format!("gemini://localhost:{}", ready.port);
    let proof_url = format!("{base}/.well-known/mere/{}.json", hex(&author.revision_id));
    let reader_status = Command::new(&exe)
        .arg("reader")
        .arg(&reader_dir)
        .arg(&base)
        .arg(&proof_url)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;
    let reader_complete_ms = now_ms();
    fs::write(root.join("stop"), b"stop\n")?;
    let server_status = server.wait()?;
    let host_exit_ms = now_ms();
    ensure(
        server_status.success(),
        format!("host server failed: {server_status}"),
    )?;
    ensure(
        reader_status.success(),
        format!("reader process failed: {reader_status}"),
    )?;
    let reader: ReaderReceipt = read_json(&reader_dir.join("reader.json"))?;

    let roots = [author.root, host.root, reader.root];
    let independent_roots = roots[0] != roots[1] && roots[0] != roots[2] && roots[1] != roots[2];
    let final_receipt = FinalReceipt {
        proof: "author-offline community publication P1".into(),
        transport: "scoped iroh BlobStore transfer of a Stickleback NativeDrop, then ordinary Gemini TLS".into(),
        author_exited_before_host_restart: author.pid != host.pid
            && host.pid != ready.pid
            && author_status.success()
            && author_exit_ms <= host_restart_ready_ms,
        independent_roots,
        exact_page_after_restart: reader.content_hash == author.content_hash,
        author,
        host,
        serving: ready,
        reader,
        lifecycle: LifecycleReceipt {
            author_ready_ms,
            host_import_complete_ms,
            author_exit_ms,
            host_restart_ready_ms,
            reader_complete_ms,
            host_exit_ms,
            author_exit_success: author_status.success(),
            host_exit_success: server_status.success(),
        },
        limitations: vec![
            "PublicationRevisionV1 and HostingCommitmentV1 are proof-local candidate records; production owners and wire compatibility remain to be ruled.".into(),
            "Gemot membership and signed capability grants now authorize the contribution and hosting commands; FixturePolicy remains only for proof-local publication lineage and hosting byte/retention bounds.".into(),
            "The iroh transfer ran over authenticated loopback on one machine; a two-machine receipt remains open.".into(),
            "Fixture wiring uses each Personae master public key as its transport endpoint identity; production still needs the admitted-persona-to-device-key adapter.".into(),
            "The proof bundle remains a host sidecar; the canonical publication-linkage record still needs a durable governed owner.".into(),
            "Standing Scope rehearses the public promise but cannot itself encode the full audience, byte bound, and policy revision.".into(),
            "Current authority is reconstructed after restart; historical authority-at-publication still needs a signed constitution and membership frontier.".into(),
            "Aggregate import spans several durable stores and is not yet atomic across all Gemot lanes.".into(),
        ],
    };
    ensure(
        final_receipt.author_exited_before_host_restart,
        "roles did not use distinct processes",
    )?;
    ensure(
        final_receipt.independent_roots,
        "roles did not use independent roots",
    )?;
    ensure(
        final_receipt.exact_page_after_restart,
        "reader content differs from author content",
    )?;
    ensure(
        final_receipt.host.live_peer_transfer,
        "host receipt did not prove live peer transfer",
    )?;
    ensure(
        final_receipt.host.unadmitted_peer_refused,
        "host receipt did not prove scoped transport refusal",
    )?;
    ensure(
        final_receipt.host.constitution_operations > 0
            && final_receipt.host.membership_operations > 0
            && final_receipt.host.authorized_contribution_visible
            && final_receipt.host.author_command_authorized
            && final_receipt.host.host_command_authorized,
        "host did not reconstruct and exercise community authority",
    )?;
    let final_path = receipt_path(root, "author-offline-publication");
    write_json(&final_path, &final_receipt)?;
    println!("{}", serde_json::to_string_pretty(&final_receipt)?);
    println!("receipt={}", final_path.display());
    Ok(())
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), AnyError> {
    let mut args = std::env::args().skip(1);
    let role = args.next().unwrap_or_else(|| "run".into());
    let root = args.next().map(PathBuf::from).unwrap_or_else(|| {
        std::env::temp_dir().join(format!("mere-author-offline-proof-{}", std::process::id()))
    });
    match role.as_str() {
        "run" => orchestrate(&root),
        "author" => author_process(&root).await,
        "host-import" => host_import_process(&root).await,
        "host-serve" => host_serve_process(&root).await,
        "reader" => {
            let base = args
                .next()
                .ok_or_else(|| failure("reader requires a Gemini base URL"))?;
            let proof_url = args
                .next()
                .ok_or_else(|| failure("reader requires a proof URL"))?;
            reader_process(&root, &base, &proof_url).await
        },
        _ => Err(failure(format!(
            "usage: author-offline-publication [run|author|host-import|host-serve|reader] [receipt-dir]; got {role}"
        ))),
    }
}
