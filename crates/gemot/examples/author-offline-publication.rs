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

use identity::AttestationKeys;
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
use gemot::moot::{
    AvailabilityPolicy, ErasurePolicy, KeepBound, MootAccessLevel, MootAuthorizationRequest,
    MootError, MootEvent, MootExt, MootFile, MootId, MootMember, MootMembershipAction,
    MootOutboundOperation, MootRetentionSettings, PolicyRevision,
    from_operation as moot_from_operation, stable_author as stable_moot_author,
    verify as verify_moot,
};
use identity::{Ed25519Signature, IdentityProvider, InMemoryProvider};
use insigne::DerivedKeyAttestation;
use mien::wire::{
    StandingExt, from_operation as standing_from_operation, verify as verify_standing,
};
use mien::{ChainRoot, CommitmentId, GateDecision, Scope, StandingEvent};
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
        }
        _ => Err(failure(format!(
            "usage: author-offline-publication [run|author|host-import|host-serve|reader] [receipt-dir]; got {role}"
        ))),
    }
}

#[path = "author-offline-publication/processes.rs"]
mod processes;

use processes::{author_process, host_import_process};

#[path = "author-offline-publication/serving.rs"]
mod serving;

use serving::{host_serve_process, reader_process};

#[path = "author-offline-publication/orchestration.rs"]
mod orchestration;

use orchestration::orchestrate;

#[path = "author-offline-publication/validation.rs"]
mod validation;

use validation::{validate_bundle, validate_contribution, validate_hosting, verify_revision};
