// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Proof-only line-JSON peer for a retained Woodshed comparison space.
//!
//! One process owns one redb store.  A host may carry the canonical signed
//! operation records over HTTP, loopback, or another carrier; this example
//! implements no transport and makes no networking claim.

use std::fs;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};

use chartulary::{Author, Container};
use commons_spine::{
    CommonsExt, GemotAuthorityView, Replica, commons_write_capability, from_operation,
};
use gemot::moot::constitution::{CapabilityGrant, ConstitutionRules};
use gemot::moot::{MOOT_ACT_ACTION, MOOT_DELEGATION_DOMAIN, MootAuthority, MootDelegations};
use muniment::RedbBackend;
use p2panda_core::Topic;
use p2panda_core::cbor::{decode_cbor, encode_cbor};
use personae::delegation::{
    CapabilityScope, DelegationCertificate, DelegationParent, SignedDelegationCertificate,
};
use personae::{IdentityProvider, InMemoryProvider};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use servitor::cap_path;
use stickleback::{
    DropExportProfile, DropRecord, decode_operation_record, export_topic_operations,
    operation_record,
};

const FORMAT: u16 = 1;
const CONTAINER: [u8; 32] = [0xc3; 32];
const MOOT: [u8; 32] = [0x71; 32];
const ROOT_GRANT: [u8; 32] = [0x72; 32];
const NOW_MS: u64 = 50;
const FOUNDER_SEED: [u8; 32] = [0x61; 32];
const MEMBER_SEED: [u8; 32] = [0x62; 32];
const INTRUDER_SEED: [u8; 32] = [0x63; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Founder,
    Member,
    Intruder,
}

impl Role {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "founder" => Ok(Self::Founder),
            "member" => Ok(Self::Member),
            "intruder" => Ok(Self::Intruder),
            _ => Err("--role must be founder, member, or intruder".into()),
        }
    }

    fn seed(self) -> [u8; 32] {
        match self {
            Self::Founder => FOUNDER_SEED,
            Self::Member => MEMBER_SEED,
            Self::Intruder => INTRUDER_SEED,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Founder => "founder",
            Self::Member => "member",
            Self::Intruder => "intruder",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Invitation {
    format: u16,
    /// Canonical CBOR authority bytes carried as hex inside control JSON.
    authority_cbor_hex: String,
    moot_hex: String,
    container_hex: String,
    founder_root_hex: String,
}

/// This separately persisted fixture document is an explicit, public trust
/// anchor plus signed delegations.  It is not a replacement authority system.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct AuthorityEnvelope {
    format: u16,
    moot: [u8; 32],
    container: [u8; 32],
    trusted_founder: [u8; 32],
    rules: ConstitutionRules,
    certificates: Vec<SignedDelegationCertificate>,
}

struct AuthorityState {
    rules: ConstitutionRules,
    delegations: MootDelegations,
}

struct Peer {
    role: Role,
    container: [u8; 32],
    root: [u8; 32],
    replica: Replica<RedbBackend>,
    authority_path: PathBuf,
}

#[derive(Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
enum Request {
    #[serde(alias = "found", alias = "invite")]
    Init,
    #[serde(alias = "join")]
    InstallAuthority {
        invitation: Invitation,
    },
    Contribute {
        comparison_utf8_hex: String,
    },
    /// Negative-path-only command that makes a valid but unauthorized record.
    MintUnauthorized {
        comparison_utf8_hex: String,
    },
    Export,
    Import {
        operation_record_hex: String,
    },
    Status,
    Close,
}

fn usage() -> &'static str {
    "usage: commons_practice_peer --role founder|member|intruder --store DIR [--container HEX] [--self-check]"
}

fn parse_hex_32(value: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value).map_err(|_| "expected hex".to_string())?;
    bytes
        .try_into()
        .map_err(|_| "expected exactly 32 bytes of hex".to_string())
}

fn founder_root() -> [u8; 32] {
    InMemoryProvider::from_seed(FOUNDER_SEED)
        .master_public_key()
        .to_bytes()
}

fn authority_path(store: &Path) -> PathBuf {
    store.join("authority.json")
}

fn fixture_rules(container: [u8; 32]) -> ConstitutionRules {
    let founder = InMemoryProvider::from_seed(FOUNDER_SEED);
    let path = cap_path(&commons_write_capability(container));
    let mut rules = ConstitutionRules::founder_only(founder.master_public_key().to_bytes());
    rules.grant(CapabilityGrant {
        id: ROOT_GRANT,
        subject: founder.master_public_key().to_bytes(),
        path_prefix: path,
        not_before_ms: 10,
        expires_at_ms: Some(1_000),
        delegation_depth: 1,
    });
    rules
}

fn fixture_envelope(container: [u8; 32]) -> Result<AuthorityEnvelope, String> {
    let founder = InMemoryProvider::from_seed(FOUNDER_SEED);
    let member = InMemoryProvider::from_seed(MEMBER_SEED);
    let path = cap_path(&commons_write_capability(container));
    let rules = fixture_rules(container);
    let issue = |subject: &InMemoryProvider, nonce| {
        SignedDelegationCertificate::issue(
            &founder,
            DelegationCertificate::new(
                DelegationParent::Root(ROOT_GRANT),
                founder.master_public_key().to_bytes(),
                subject.master_public_key().to_bytes(),
                CapabilityScope {
                    domain: MOOT_DELEGATION_DOMAIN.into(),
                    resource: MOOT.to_vec(),
                    path_prefix: path.clone(),
                    actions: [MOOT_ACT_ACTION.to_owned()].into_iter().collect(),
                },
                15,
                20,
                Some(1_000),
                0,
                [nonce; 32],
            ),
        )
        .map_err(|error| error.to_string())
    };
    Ok(AuthorityEnvelope {
        format: FORMAT,
        moot: MOOT,
        container,
        trusted_founder: founder.master_public_key().to_bytes(),
        rules,
        certificates: vec![issue(&founder, 0x81)?, issue(&member, 0x82)?],
    })
}

fn write_authority(path: &Path, envelope: &AuthorityEnvelope) -> Result<(), String> {
    fs::write(
        path,
        encode_cbor(envelope).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())
}

fn read_authority(path: &Path) -> Result<AuthorityEnvelope, String> {
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    decode_cbor(bytes.as_slice()).map_err(|error| format!("authority CBOR: {error}"))
}

fn validate_authority(
    envelope: &AuthorityEnvelope,
    container: [u8; 32],
    required_subject: Option<[u8; 32]>,
) -> Result<AuthorityState, String> {
    if envelope.format != FORMAT || envelope.moot != MOOT || envelope.container != container {
        return Err("invitation is bound to another practice space or container".into());
    }
    if envelope.trusted_founder != founder_root() {
        return Err("invitation founder does not match the fixture trust anchor".into());
    }
    if envelope.rules != fixture_rules(container) {
        return Err("invitation rules differ from the preconfigured fixture constitution".into());
    }
    let path = cap_path(&commons_write_capability(container));
    let root = envelope
        .rules
        .capability_grants
        .get(&ROOT_GRANT)
        .ok_or("invitation lacks the founder root grant")?;
    if root.subject != founder_root()
        || root.path_prefix != path
        || !root.covers(founder_root(), &path, NOW_MS)
    {
        return Err("invitation root grant is not bound to this founder and container".into());
    }
    let mut delegations = MootDelegations::new();
    for certificate in envelope.certificates.iter().cloned() {
        if certificate.certificate.issuer != founder_root() {
            return Err("delegation issuer is not the trusted founder".into());
        }
        delegations
            .accept_certificate(MOOT, &envelope.rules, certificate)
            .map_err(|error| format!("delegation rejected: {error}"))?;
    }
    if let Some(subject) = required_subject
        && !delegations.covers(MOOT, &envelope.rules, subject, &path, NOW_MS)
    {
        return Err("invitation has no effective signed delegation for this peer".into());
    }
    Ok(AuthorityState {
        rules: envelope.rules.clone(),
        delegations,
    })
}

impl Peer {
    fn open(role: Role, store: &Path, container: [u8; 32]) -> Result<Self, String> {
        fs::create_dir_all(store).map_err(|error| error.to_string())?;
        let identity = InMemoryProvider::from_seed(role.seed());
        let root = identity.master_public_key().to_bytes();
        let backend =
            RedbBackend::open(store.join("commons.redb")).map_err(|error| error.to_string())?;
        let replica = Replica::for_identity(backend, container, &identity)
            .map_err(|error| error.to_string())?;
        Ok(Self {
            role,
            container,
            root,
            replica,
            authority_path: authority_path(store),
        })
    }

    fn authority(&self, require_self: bool) -> Result<AuthorityState, String> {
        validate_authority(
            &read_authority(&self.authority_path)?,
            self.container,
            require_self.then_some(self.root),
        )
    }

    fn invitation(&self) -> Result<Invitation, String> {
        Ok(Invitation {
            format: FORMAT,
            authority_cbor_hex: hex::encode(
                fs::read(&self.authority_path).map_err(|error| error.to_string())?,
            ),
            moot_hex: hex::encode(MOOT),
            container_hex: hex::encode(self.container),
            founder_root_hex: hex::encode(founder_root()),
        })
    }

    async fn operation_records(&self) -> Result<Vec<DropRecord>, String> {
        export_topic_operations::<_, CommonsExt, u64>(
            &self.replica.sync_store(),
            &Topic::from(self.container),
            DropExportProfile::default(),
        )
        .await
        .map_err(|error| error.to_string())
    }

    async fn contribute(&mut self, payload_hex: &str, unchecked: bool) -> Result<Value, String> {
        let body = String::from_utf8(
            hex::decode(payload_hex).map_err(|_| "comparison_utf8_hex is not hex".to_string())?,
        )
        .map_err(|_| "comparison payload must be valid UTF-8".to_string())?;
        if !unchecked {
            self.authority(true)?;
        }
        let ordinal = self.operation_records().await?.len();
        let id = format!("woodshed-comparison:{}:{ordinal}", self.role.name());
        let author = Author::new(format!("woodshed:{}", self.role.name()));
        let operation = self
            .replica
            .edit(|graph| {
                graph.insert_node(
                    &author,
                    Container::new(id.clone())
                        .with_title(format!("{} musical comparison", self.role.name()))
                        .with_tag("woodshed:comparison")
                        .with_inline_text(body, "application/vnd.woodshed.comparison+json"),
                );
            })
            .await
            .map_err(|error| error.to_string())?;
        let record =
            encode_cbor(&operation_record(&operation, true)).map_err(|error| error.to_string())?;
        Ok(json!({
            "ok": true,
            "operation_record_hex": hex::encode(record),
            "operation_id": hex::encode(operation.hash.as_bytes()),
            "author_root": hex::encode(self.root),
            "id": id,
            "unauthorized_negative_path": unchecked,
        }))
    }

    async fn import(&self, encoded: &str) -> Result<Value, String> {
        let bytes =
            hex::decode(encoded).map_err(|_| "operation_record_hex is not hex".to_string())?;
        let record: DropRecord = decode_cbor(bytes.as_slice())
            .map_err(|error| format!("operation record CBOR: {error}"))?;
        let operation = decode_operation_record::<CommonsExt>(&record)
            .map_err(|error| error.to_string())?
            .ok_or("record did not contain a Commons operation")?;
        if operation.header.extensions.container != self.container {
            return Err("operation addresses another Commons container".into());
        }
        let accepted = self
            .replica
            .accept(&operation)
            .await
            .map_err(|error| error.to_string())?;
        let root = from_operation(&operation)
            .ok()
            .and_then(|record| record.writer_attestation)
            .and_then(|attestation| attestation.master_public_key().ok())
            .map(|key| hex::encode(key.to_bytes()));
        Ok(json!({
            "ok": true,
            "accepted": accepted,
            "operation_id": hex::encode(operation.hash.as_bytes()),
            "author_root": root,
        }))
    }

    async fn status(&self) -> Result<Value, String> {
        let retained = self.operation_records().await?;
        let authority = self.authority(false).ok();
        let mut operations = Vec::new();
        for record in &retained {
            let operation = decode_operation_record::<CommonsExt>(record)
                .map_err(|error| error.to_string())?
                .ok_or("export returned a non-operation record")?;
            let root = from_operation(&operation)
                .ok()
                .and_then(|record| record.writer_attestation)
                .and_then(|attestation| attestation.master_public_key().ok())
                .map(|key| hex::encode(key.to_bytes()));
            operations.push(json!({
                "operation_id": hex::encode(operation.hash.as_bytes()),
                "writer": hex::encode(operation.header.verifying_key.as_bytes()),
                "author_root": root,
            }));
        }
        let (records, pending_authority_count, revoked_authority_count) =
            if let Some(authority) = authority.as_ref() {
                let view = GemotAuthorityView {
                    authority: MootAuthority {
                        delegations: &authority.delegations,
                        rules: &authority.rules,
                        moot_id: MOOT,
                        now_ms: NOW_MS,
                    },
                };
                let projection = self
                    .replica
                    .projection_with_authority(&view)
                    .await
                    .map_err(|error| error.to_string())?;
                let records = projection
                    .graph
                    .graph()
                    .nodes()
                    .filter(|(_, node)| node.tags.contains("woodshed:comparison"))
                    .map(|(_, node)| {
                        json!({
                            "id": node.id,
                            "body_utf8_hex": node.body.as_ref().map(hex::encode),
                            "media_type": node.media_type,
                        })
                    })
                    .collect();
                (
                    records,
                    projection.pending_authority.len(),
                    projection.revoked.len(),
                )
            } else {
                (Vec::new(), 0, 0)
            };
        Ok(json!({
            "ok": true,
            "role": self.role.name(),
            "container_hex": hex::encode(self.container),
            "local_root": hex::encode(self.root),
            "authority_installed": authority.is_some(),
            "retained_count": retained.len(),
            "operations": operations,
            "records": records,
            "pending_authority_count": pending_authority_count,
            "revoked_authority_count": revoked_authority_count,
        }))
    }
}

fn corrupt_signature(value: &mut Value) -> bool {
    match value {
        Value::Object(map) => {
            if let Some(Value::Array(bytes)) = map.get_mut("signature")
                && let Some(Value::Number(byte)) = bytes.first_mut()
            {
                *byte = serde_json::Number::from(byte.as_u64().unwrap_or(0) ^ 1);
                return true;
            }
            map.values_mut().any(corrupt_signature)
        },
        Value::Array(values) => values.iter_mut().any(corrupt_signature),
        _ => false,
    }
}

async fn self_check(store: &Path, container: [u8; 32]) -> Result<Value, String> {
    let envelope = fixture_envelope(container)?;
    let founder = Peer::open(Role::Founder, &store.join("self-check-founder"), container)?;
    write_authority(&founder.authority_path, &envelope)?;
    let invitation = founder.invitation()?;
    let mut member = Peer::open(Role::Member, &store.join("self-check-member"), container)?;
    let invitation_roundtrip_installed = handle(
        &mut member,
        Request::InstallAuthority {
            invitation: invitation.clone(),
        },
    )
    .await
    .is_ok();
    let mut encoded =
        serde_json::to_value(&envelope.certificates[0]).map_err(|error| error.to_string())?;
    if !corrupt_signature(&mut encoded) {
        return Err("could not find serialized delegation signature".into());
    }
    let tampered: SignedDelegationCertificate =
        serde_json::from_value(encoded).map_err(|error| error.to_string())?;
    let mut tampered_envelope = envelope.clone();
    tampered_envelope.certificates[0] = tampered;
    let tampered_grant_rejected = validate_authority(&tampered_envelope, container, None).is_err();
    let mut altered_rules = envelope.clone();
    altered_rules
        .rules
        .capability_grants
        .get_mut(&ROOT_GRANT)
        .expect("fixture root grant exists")
        .delegation_depth = 2;
    let unsigned_rule_mutation_rejected =
        validate_authority(&altered_rules, container, None).is_err();
    let wrong_space_invitation_rejected = validate_authority(&envelope, [0xee; 32], None).is_err();

    let mut intruder = Peer::open(
        Role::Intruder,
        &store.join("self-check-intruder"),
        container,
    )?;
    write_authority(&intruder.authority_path, &envelope)?;
    let unauthorized_writer_rejected = intruder.contribute("7b7d", false).await.is_err();

    let mut foreign = Peer::open(
        Role::Founder,
        &store.join("self-check-wrong-space"),
        [0xef; 32],
    )?;
    let foreign_record = foreign.contribute("7b7d", true).await?["operation_record_hex"]
        .as_str()
        .ok_or("self-check generated no operation record")?
        .to_owned();
    let receiver = Peer::open(Role::Founder, &store.join("self-check-receiver"), container)?;
    let wrong_container_operation_rejected = receiver.import(&foreign_record).await.is_err();
    Ok(json!({
        "ok": invitation_roundtrip_installed && tampered_grant_rejected
            && unsigned_rule_mutation_rejected && wrong_space_invitation_rejected
            && unauthorized_writer_rejected && wrong_container_operation_rejected,
        "invitation_roundtrip_installed": invitation_roundtrip_installed,
        "tampered_grant_rejected": tampered_grant_rejected,
        "unsigned_rule_mutation_rejected": unsigned_rule_mutation_rejected,
        "wrong_space_invitation_rejected": wrong_space_invitation_rejected,
        "unauthorized_writer_rejected": unauthorized_writer_rejected,
        "wrong_container_operation_rejected": wrong_container_operation_rejected,
    }))
}

async fn handle(peer: &mut Peer, request: Request) -> Result<(Value, bool), String> {
    match request {
        Request::Init => {
            if peer.role != Role::Founder {
                return Err("only the founder may create this fixture invitation".into());
            }
            let envelope = fixture_envelope(peer.container)?;
            validate_authority(&envelope, peer.container, Some(peer.root))?;
            if peer.authority_path.exists() {
                let existing = read_authority(&peer.authority_path)?;
                validate_authority(&existing, peer.container, Some(peer.root))?;
            } else {
                write_authority(&peer.authority_path, &envelope)?;
            }
            Ok((
                json!({ "ok": true, "invitation": peer.invitation()? }),
                false,
            ))
        },
        Request::InstallAuthority { invitation } => {
            if invitation.format != FORMAT
                || parse_hex_32(&invitation.moot_hex)? != MOOT
                || parse_hex_32(&invitation.container_hex)? != peer.container
                || parse_hex_32(&invitation.founder_root_hex)? != founder_root()
            {
                return Err("invitation metadata is not bound to this fixture space".into());
            }
            let bytes = hex::decode(invitation.authority_cbor_hex)
                .map_err(|_| "authority_cbor_hex is not hex".to_string())?;
            let envelope: AuthorityEnvelope = decode_cbor(bytes.as_slice())
                .map_err(|error| format!("authority CBOR: {error}"))?;
            validate_authority(
                &envelope,
                peer.container,
                (peer.role != Role::Intruder).then_some(peer.root),
            )?;
            write_authority(&peer.authority_path, &envelope)?;
            Ok((json!({ "ok": true, "authority_installed": true }), false))
        },
        Request::Contribute {
            comparison_utf8_hex,
        } => Ok((peer.contribute(&comparison_utf8_hex, false).await?, false)),
        Request::MintUnauthorized {
            comparison_utf8_hex,
        } => Ok((peer.contribute(&comparison_utf8_hex, true).await?, false)),
        Request::Export => {
            let mut operations = Vec::new();
            for record in peer.operation_records().await? {
                operations.push(hex::encode(
                    encode_cbor(&record).map_err(|error| error.to_string())?,
                ));
            }
            Ok((json!({ "ok": true, "operations": operations }), false))
        },
        Request::Import {
            operation_record_hex,
        } => Ok((peer.import(&operation_record_hex).await?, false)),
        Request::Status => Ok((peer.status().await?, false)),
        Request::Close => Ok((json!({ "ok": true, "closed": true }), true)),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut role = None;
    let mut store = None;
    let mut container = CONTAINER;
    let mut self_check_only = false;
    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--role" => role = Some(Role::parse(&args.next().ok_or(usage())?)?),
            "--store" => store = Some(PathBuf::from(args.next().ok_or(usage())?)),
            "--container" => container = parse_hex_32(&args.next().ok_or(usage())?)?,
            "--self-check" => self_check_only = true,
            _ => return Err(usage().into()),
        }
    }
    let role = role.ok_or(usage())?;
    let store = store.ok_or(usage())?;
    if self_check_only {
        println!(
            "{}",
            serde_json::to_string(&self_check(&store, container).await?)?
        );
        return Ok(());
    }
    let mut peer = Peer::open(role, &store, container)?;
    for line in io::stdin().lock().lines() {
        let response = match line {
            Ok(line) => match serde_json::from_str::<Request>(&line) {
                Ok(request) => match handle(&mut peer, request).await {
                    Ok((value, close)) => {
                        println!("{}", serde_json::to_string(&value)?);
                        if close {
                            break;
                        }
                        continue;
                    },
                    Err(error) => json!({ "ok": false, "error": error }),
                },
                Err(error) => json!({ "ok": false, "error": format!("request JSON: {error}") }),
            },
            Err(error) => json!({ "ok": false, "error": error.to_string() }),
        };
        println!("{}", serde_json::to_string(&response)?);
    }
    Ok(())
}
