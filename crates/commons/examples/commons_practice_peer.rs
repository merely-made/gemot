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
//!
//! Authority is evaluated at a store-local proof clock.  Leaving removes the
//! installed envelope and keeps history.  The founder revokes the member
//! through Gemot's delegation lane, whose signed records ride the same
//! export/import wire as Commons operations.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};

use chartulary::{Author, Container};
use commons_spine::{
    CommonsExt, GemotAuthorityView, Replica, commons_write_capability, from_operation,
};
use gemot::moot::constitution::{CapabilityGrant, ConstitutionRules};
use gemot::moot::delegation::{
    self, MootDelegationEvent, MootDelegationExt, MootDelegationFileStore,
};
use gemot::moot::{MOOT_ACT_ACTION, MOOT_DELEGATION_DOMAIN, MootAuthority, MootDelegations};
use muniment::RedbBackend;
use p2panda_core::Topic;
use p2panda_core::cbor::{decode_cbor, encode_cbor};
use personae::delegation::{
    CapabilityScope, DelegationCertificate, DelegationParent, DelegationRevocation,
    SignedDelegationCertificate, SignedDelegationRevocation, delegation_signing_salt,
};
use personae::{IdentityProvider, InMemoryProvider};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use servitor::{AuthorityProvider, Mode, Subject, cap_path};
use stickleback::{
    DropExportProfile, DropRecord, decode_operation_record, export_topic_operations,
    operation_record,
};

const FORMAT: u16 = 1;
const CONTAINER: [u8; 32] = [0xc3; 32];
const MOOT: [u8; 32] = [0x71; 32];
const ROOT_GRANT: [u8; 32] = [0x72; 32];
/// Store clock before any proof-only advance.
const DEFAULT_NOW_MS: u64 = 50;
const GRANT_EXPIRES_MS: u64 = 1_000;
const REVOCATION_NONCE: [u8; 32] = [0x91; 32];
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

/// Store-local proof clock and leave marker, persisted beside the envelope.
#[derive(Serialize, Deserialize)]
struct LocalRecord {
    now_ms: u64,
    left: bool,
}

struct AuthorityState {
    rules: ConstitutionRules,
    delegations: MootDelegations,
}

/// Lifecycle verdict reported by status and enforced before participation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lifecycle {
    NotJoined,
    Left,
    Joined,
    Expired,
    Revoked,
    NotAdmitted,
}

impl Lifecycle {
    fn name(self) -> &'static str {
        match self {
            Self::NotJoined => "not_joined",
            Self::Left => "left",
            Self::Joined => "joined",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::NotAdmitted => "not_admitted",
        }
    }

    /// Exchange needs an installed envelope; the host rechecks expiry and
    /// revocation before it syncs.
    fn installed(self) -> bool {
        !matches!(self, Self::NotJoined | Self::Left)
    }
}

struct Peer {
    role: Role,
    container: [u8; 32],
    root: [u8; 32],
    replica: Replica<RedbBackend>,
    lane: MootDelegationFileStore,
    authority_path: PathBuf,
    local_path: PathBuf,
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
    /// Remove the installed envelope; retained history stays.
    Leave,
    /// Refuse unless installed authority admits this peer at the store clock.
    Recheck,
    /// Proof-only: move the store clock forward.
    AdvanceClock {
        now_ms: u64,
    },
    RevokeMember,
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
        expires_at_ms: Some(GRANT_EXPIRES_MS),
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
                Some(GRANT_EXPIRES_MS),
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

/// Structural checks only; time and revocation are judged at the store clock.
fn validate_authority(
    envelope: &AuthorityEnvelope,
    container: [u8; 32],
) -> Result<MootDelegations, String> {
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
    if root.subject != founder_root() || root.path_prefix != path {
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
    Ok(delegations)
}

/// Classify `subject` with the Gemot authority the projection uses.
fn verdict(
    authority: &AuthorityState,
    container: [u8; 32],
    subject: [u8; 32],
    now_ms: u64,
) -> Lifecycle {
    let gemot = MootAuthority {
        delegations: &authority.delegations,
        rules: &authority.rules,
        moot_id: MOOT,
        now_ms,
    };
    if gemot.covers(
        Subject(subject),
        &commons_write_capability(container),
        Mode::Write,
    ) {
        return Lifecycle::Joined;
    }
    let grants: Vec<_> = authority
        .delegations
        .projections(MOOT, &authority.rules, now_ms)
        .into_iter()
        .filter(|grant| grant.subject == subject)
        .collect();
    if grants.iter().any(|grant| grant.directly_revoked) {
        Lifecycle::Revoked
    } else if grants
        .iter()
        .any(|grant| grant.expires_at_ms.is_some_and(|expires| now_ms > expires))
    {
        Lifecycle::Expired
    } else {
        Lifecycle::NotAdmitted
    }
}

/// Named reason a peer that is not joined may not participate.
fn refusal(
    authority: Option<&AuthorityState>,
    lifecycle: Lifecycle,
    subject: [u8; 32],
    now_ms: u64,
) -> String {
    match lifecycle {
        Lifecycle::Joined => "joined".into(),
        Lifecycle::NotJoined => "not joined: no invitation is installed in this store".into(),
        Lifecycle::Left => {
            "not joined: this peer left the space; install an invitation to join again".into()
        },
        Lifecycle::Expired => {
            let ended = authority.and_then(|authority| {
                authority
                    .delegations
                    .projections(MOOT, &authority.rules, now_ms)
                    .into_iter()
                    .filter(|grant| grant.subject == subject)
                    .filter_map(|grant| grant.expires_at_ms)
                    .max()
            });
            format!(
                "expired: this peer's grant ended at {} ms; store clock is {now_ms} ms",
                ended.unwrap_or(GRANT_EXPIRES_MS)
            )
        },
        Lifecycle::Revoked => "revoked: the issuer revoked this peer's delegation".into(),
        Lifecycle::NotAdmitted => {
            "invitation has no effective signed delegation for this peer".into()
        },
    }
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
        let lane = MootDelegationFileStore::open(store.join("delegations.redb"), MOOT)
            .map_err(|error| error.to_string())?;
        Ok(Self {
            role,
            container,
            root,
            replica,
            lane,
            authority_path: authority_path(store),
            local_path: store.join("lifecycle.json"),
        })
    }

    fn local(&self) -> Result<LocalRecord, String> {
        match fs::read(&self.local_path) {
            Ok(bytes) => {
                serde_json::from_slice(&bytes).map_err(|error| format!("lifecycle record: {error}"))
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(LocalRecord {
                now_ms: DEFAULT_NOW_MS,
                left: false,
            }),
            Err(error) => Err(error.to_string()),
        }
    }

    fn write_local(&self, record: &LocalRecord) -> Result<(), String> {
        let bytes = serde_json::to_vec(record).map_err(|error| error.to_string())?;
        fs::write(&self.local_path, bytes).map_err(|error| error.to_string())
    }

    /// Invitation certificates plus retained delegation-lane revocations.
    async fn authority_of(&self, envelope: &AuthorityEnvelope) -> Result<AuthorityState, String> {
        let mut delegations = validate_authority(envelope, self.container)?;
        // Lane issuances only duplicate the invitation's certificates. Gemot's
        // issuer and scope checks decide which revocations apply; the rest stay
        // retained but inert.
        for operation in self
            .lane
            .operations()
            .await
            .map_err(|error| error.to_string())?
        {
            if let Ok(MootDelegationEvent::Revoked(signed)) = delegation::from_operation(&operation)
            {
                let _ = delegations.accept_revocation(signed);
            }
        }
        Ok(AuthorityState {
            rules: envelope.rules.clone(),
            delegations,
        })
    }

    /// Installed authority, lifecycle verdict, and store clock.
    async fn standing(&self) -> Result<(Option<AuthorityState>, Lifecycle, u64), String> {
        let local = self.local()?;
        if !self.authority_path.exists() {
            let lifecycle = if local.left {
                Lifecycle::Left
            } else {
                Lifecycle::NotJoined
            };
            return Ok((None, lifecycle, local.now_ms));
        }
        let authority = self
            .authority_of(&read_authority(&self.authority_path)?)
            .await?;
        let lifecycle = verdict(&authority, self.container, self.root, local.now_ms);
        Ok((Some(authority), lifecycle, local.now_ms))
    }

    /// This peer's authority, or the named reason it may not participate.
    async fn admitted(&self) -> Result<AuthorityState, String> {
        match self.standing().await? {
            (Some(authority), Lifecycle::Joined, _) => Ok(authority),
            (authority, lifecycle, now_ms) => {
                Err(refusal(authority.as_ref(), lifecycle, self.root, now_ms))
            },
        }
    }

    async fn installed(&self) -> Result<(), String> {
        match self.standing().await? {
            (_, lifecycle, now_ms) if !lifecycle.installed() => {
                Err(refusal(None, lifecycle, self.root, now_ms))
            },
            _ => Ok(()),
        }
    }

    /// Refuse candidate authority that does not admit this peer now.
    async fn require_joined(&self, envelope: &AuthorityEnvelope) -> Result<(), String> {
        let authority = self.authority_of(envelope).await?;
        let now_ms = self.local()?.now_ms;
        match verdict(&authority, self.container, self.root, now_ms) {
            Lifecycle::Joined => Ok(()),
            lifecycle => Err(refusal(Some(&authority), lifecycle, self.root, now_ms)),
        }
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

    async fn lane_count(&self) -> Result<usize, String> {
        Ok(self
            .lane
            .operations()
            .await
            .map_err(|error| error.to_string())?
            .len())
    }

    async fn contribute(&mut self, payload_hex: &str, unchecked: bool) -> Result<Value, String> {
        let body = String::from_utf8(
            hex::decode(payload_hex).map_err(|_| "comparison_utf8_hex is not hex".to_string())?,
        )
        .map_err(|_| "comparison payload must be valid UTF-8".to_string())?;
        if !unchecked {
            self.admitted().await?;
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
        self.installed().await?;
        let bytes =
            hex::decode(encoded).map_err(|_| "operation_record_hex is not hex".to_string())?;
        let record: DropRecord = decode_cbor(bytes.as_slice())
            .map_err(|error| format!("operation record CBOR: {error}"))?;
        // Gemot delegation statements share this wire with Commons operations.
        if let Ok(Some(statement)) = decode_operation_record::<MootDelegationExt>(&record) {
            if statement.header.extensions.moot_id != MOOT {
                return Err("delegation statement addresses another practice space".into());
            }
            let accepted = self
                .lane
                .accept(&statement)
                .await
                .map_err(|error| error.to_string())?;
            return Ok(json!({
                "ok": true,
                "lane": "delegation",
                "accepted": accepted,
                "operation_id": hex::encode(statement.hash.as_bytes()),
            }));
        }
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
            "lane": "commons",
            "accepted": accepted,
            "operation_id": hex::encode(operation.hash.as_bytes()),
            "author_root": root,
        }))
    }

    /// Founder withdraws the member's delegation with a signed Gemot revocation.
    async fn revoke_member(&self) -> Result<Value, String> {
        if self.role != Role::Founder {
            return Err("only the founder may revoke a member".into());
        }
        let authority = self.admitted().await?;
        let now_ms = self.local()?.now_ms;
        let member_root = InMemoryProvider::from_seed(MEMBER_SEED)
            .master_public_key()
            .to_bytes();
        let certificate = read_authority(&self.authority_path)?
            .certificates
            .into_iter()
            .find(|signed| signed.certificate.subject == member_root)
            .ok_or("installed authority has no member delegation")?;
        let id = certificate.certificate.id();
        let projections = authority
            .delegations
            .projections(MOOT, &authority.rules, now_ms);
        if projections
            .iter()
            .any(|grant| grant.certificate == id && grant.directly_revoked)
        {
            return Err("the member's delegation is already revoked".into());
        }
        let founder = InMemoryProvider::from_seed(FOUNDER_SEED);
        let scope = certificate.certificate.scope.clone();
        let key = founder
            .derive_keypair(&delegation_signing_salt(&scope))
            .map_err(|error| error.to_string())?;
        // author_revoke preflights against the lane's own fold, so the lane
        // first records the issuance it withdraws.
        let lane_grants = self
            .lane
            .delegations(&authority.rules)
            .await
            .map_err(|error| error.to_string())?;
        if !lane_grants
            .projections(MOOT, &authority.rules, now_ms)
            .iter()
            .any(|grant| grant.certificate == id)
        {
            self.lane
                .author_issue(&key, &authority.rules, certificate)
                .await
                .map_err(|error| error.to_string())?;
        }
        let revocation = SignedDelegationRevocation::issue(
            &founder,
            DelegationRevocation::new(id, founder_root(), scope, now_ms, REVOCATION_NONCE),
        )
        .map_err(|error| error.to_string())?;
        let operation = self
            .lane
            .author_revoke(&key, &authority.rules, revocation)
            .await
            .map_err(|error| error.to_string())?;
        Ok(json!({
            "ok": true,
            "revoked_member_root": hex::encode(member_root),
            "revoked_certificate": hex::encode(id.0),
            "revocation_operation_id": hex::encode(operation.hash.as_bytes()),
            "at_ms": now_ms,
        }))
    }

    async fn status(&self) -> Result<Value, String> {
        let retained = self.operation_records().await?;
        let (authority, lifecycle, now_ms) = self.standing().await?;
        let projection = match authority.as_ref() {
            Some(authority) => Some(
                self.replica
                    .projection_with_authority(&GemotAuthorityView {
                        authority: MootAuthority {
                            delegations: &authority.delegations,
                            rules: &authority.rules,
                            moot_id: MOOT,
                            now_ms,
                        },
                    })
                    .await
                    .map_err(|error| error.to_string())?,
            ),
            None => None,
        };
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
            let hash = *operation.hash.as_bytes();
            let classification = projection.as_ref().map(|projection| {
                if projection
                    .revoked
                    .iter()
                    .any(|entry| entry.operation == hash)
                {
                    "revoked"
                } else if projection
                    .pending_authority
                    .iter()
                    .any(|entry| entry.operation == hash)
                {
                    "pending_authority"
                } else if projection
                    .pending
                    .iter()
                    .any(|entry| entry.operation == hash)
                {
                    "pending_causal"
                } else {
                    "effective"
                }
            });
            operations.push(json!({
                "operation_id": hex::encode(hash),
                "writer": hex::encode(operation.header.verifying_key.as_bytes()),
                "author_root": root,
                "authority": classification,
            }));
        }
        let records: Vec<Value> = projection
            .as_ref()
            .map(|projection| {
                projection
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
                    .collect()
            })
            .unwrap_or_default();
        let revoked_members: BTreeSet<String> = authority
            .as_ref()
            .map(|authority| {
                authority
                    .delegations
                    .projections(MOOT, &authority.rules, now_ms)
                    .into_iter()
                    .filter(|grant| grant.directly_revoked)
                    .map(|grant| hex::encode(grant.subject))
                    .collect()
            })
            .unwrap_or_default();
        Ok(json!({
            "ok": true,
            "role": self.role.name(),
            "container_hex": hex::encode(self.container),
            "local_root": hex::encode(self.root),
            "authority_installed": authority.is_some(),
            "now_ms": now_ms,
            "lifecycle": lifecycle.name(),
            "lifecycle_reason": (lifecycle != Lifecycle::Joined)
                .then(|| refusal(authority.as_ref(), lifecycle, self.root, now_ms)),
            "retained_count": retained.len(),
            "retained_delegation_count": self.lane_count().await?,
            "revoked_members": revoked_members,
            "operations": operations,
            "records": records,
            "pending_authority_count": projection.as_ref().map_or(0, |p| p.pending_authority.len()),
            "revoked_authority_count": projection.as_ref().map_or(0, |p| p.revoked.len()),
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

fn refused<T>(result: Result<T, String>, reason: &str) -> bool {
    matches!(result, Err(error) if error.starts_with(reason))
}

/// Leave keeps retained operations, refuses participation, and a new
/// invitation re-joins.
async fn check_leave(
    store: &Path,
    container: [u8; 32],
    invitation: &Invitation,
) -> Result<bool, String> {
    let mut peer = Peer::open(Role::Member, &store.join("self-check-leave"), container)?;
    let install = || Request::InstallAuthority {
        invitation: invitation.clone(),
    };
    handle(&mut peer, install()).await?;
    peer.contribute("7b7d", false).await?;
    let (left, _) = handle(&mut peer, Request::Leave).await?;
    Ok(left["lifecycle"] == "left"
        && left["retained_count"] == 1
        && refused(peer.contribute("7b7d", false).await, "not joined")
        && refused(handle(&mut peer, Request::Export).await, "not joined")
        && refused(handle(&mut peer, Request::Recheck).await, "not joined")
        && peer.status().await?["retained_count"] == 1
        && handle(&mut peer, install()).await.is_ok()
        && peer.contribute("7b7d", false).await.is_ok())
}

/// Past the grant's expiry contribution and recheck are refused, and the
/// clock never moves back.
async fn check_expiry(
    store: &Path,
    container: [u8; 32],
    invitation: &Invitation,
) -> Result<bool, String> {
    let mut peer = Peer::open(Role::Member, &store.join("self-check-expiry"), container)?;
    handle(
        &mut peer,
        Request::InstallAuthority {
            invitation: invitation.clone(),
        },
    )
    .await?;
    let admitted_before = handle(&mut peer, Request::Recheck).await.is_ok();
    handle(
        &mut peer,
        Request::AdvanceClock {
            now_ms: GRANT_EXPIRES_MS + 1,
        },
    )
    .await?;
    Ok(admitted_before
        && refused(peer.contribute("7b7d", false).await, "expired")
        && refused(handle(&mut peer, Request::Recheck).await, "expired")
        && refused(
            handle(
                &mut peer,
                Request::AdvanceClock {
                    now_ms: DEFAULT_NOW_MS,
                },
            )
            .await,
            "clock refuses",
        )
        && peer.status().await?["lifecycle"] == "expired")
}

/// A revocation carried over the operation wire refuses recheck and withdraws
/// a later write without deleting it.
async fn check_revocation(store: &Path, container: [u8; 32]) -> Result<bool, String> {
    let mut founder = Peer::open(
        Role::Founder,
        &store.join("self-check-revoke-founder"),
        container,
    )?;
    let (created, _) = handle(&mut founder, Request::Init).await?;
    let invitation: Invitation =
        serde_json::from_value(created["invitation"].clone()).map_err(|error| error.to_string())?;
    let mut member = Peer::open(
        Role::Member,
        &store.join("self-check-revoke-member"),
        container,
    )?;
    handle(&mut member, Request::InstallAuthority { invitation }).await?;
    let member_may_not_revoke = refused(
        handle(&mut member, Request::RevokeMember).await,
        "only the founder",
    );
    handle(&mut founder, Request::RevokeMember).await?;
    // Not yet synced, the member's local check still admits this later write.
    let later = member.contribute("7b7d", false).await?;
    founder
        .import(
            later["operation_record_hex"]
                .as_str()
                .ok_or("no operation record")?,
        )
        .await?;
    let (exported, _) = handle(&mut founder, Request::Export).await?;
    for record in exported["operations"]
        .as_array()
        .ok_or("no exported operations")?
    {
        member
            .import(record.as_str().ok_or("exported operation is not hex")?)
            .await?;
    }
    let withdrawn = |status: &Value| {
        status["retained_count"] == 1
            && status["records"].as_array().is_some_and(Vec::is_empty)
            && status["operations"].as_array().is_some_and(|operations| {
                operations.iter().any(|operation| {
                    operation["operation_id"] == later["operation_id"]
                        && operation["authority"] == "revoked"
                })
            })
    };
    let member_root = hex::encode(member.root);
    let founder_status = founder.status().await?;
    let member_status = member.status().await?;
    Ok(member_may_not_revoke
        && refused(handle(&mut member, Request::Recheck).await, "revoked")
        && refused(member.contribute("7b7d", false).await, "revoked")
        && withdrawn(&founder_status)
        && withdrawn(&member_status)
        && member_status["lifecycle"] == "revoked"
        && founder_status["revoked_members"]
            .as_array()
            .is_some_and(|roots| {
                roots
                    .iter()
                    .any(|root| root.as_str() == Some(member_root.as_str()))
            }))
}

async fn self_check(store: &Path, container: [u8; 32]) -> Result<Value, String> {
    if store.join("self-check-founder").exists() {
        return Err("self-check needs a fresh --store directory".into());
    }
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
    let tampered_grant_rejected = validate_authority(&tampered_envelope, container).is_err();
    let mut altered_rules = envelope.clone();
    altered_rules
        .rules
        .capability_grants
        .get_mut(&ROOT_GRANT)
        .expect("fixture root grant exists")
        .delegation_depth = 2;
    let unsigned_rule_mutation_rejected = validate_authority(&altered_rules, container).is_err();
    let wrong_space_invitation_rejected = validate_authority(&envelope, [0xee; 32]).is_err();

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
    // A joined receiver, so the refusal is the container binding itself.
    let receiver = Peer::open(Role::Founder, &store.join("self-check-receiver"), container)?;
    write_authority(&receiver.authority_path, &envelope)?;
    let wrong_container_operation_rejected = refused(
        receiver.import(&foreign_record).await,
        "operation addresses another Commons container",
    );
    let mut checks = json!({
        "invitation_roundtrip_installed": invitation_roundtrip_installed,
        "tampered_grant_rejected": tampered_grant_rejected,
        "unsigned_rule_mutation_rejected": unsigned_rule_mutation_rejected,
        "wrong_space_invitation_rejected": wrong_space_invitation_rejected,
        "unauthorized_writer_rejected": unauthorized_writer_rejected,
        "wrong_container_operation_rejected": wrong_container_operation_rejected,
        "leave_retains_and_refuses_contribution":
            check_leave(store, container, &invitation).await?,
        "expiry_refuses_contribution_and_recheck":
            check_expiry(store, container, &invitation).await?,
        "revocation_refuses_recheck_and_withdraws_later_operation":
            check_revocation(store, container).await?,
    });
    let ok = checks
        .as_object()
        .is_some_and(|checks| checks.values().all(|value| value.as_bool() == Some(true)));
    checks["ok"] = json!(ok);
    Ok(checks)
}

async fn handle(peer: &mut Peer, request: Request) -> Result<(Value, bool), String> {
    match request {
        Request::Init => {
            if peer.role != Role::Founder {
                return Err("only the founder may create this fixture invitation".into());
            }
            if peer.authority_path.exists() {
                peer.require_joined(&read_authority(&peer.authority_path)?)
                    .await?;
            } else {
                let envelope = fixture_envelope(peer.container)?;
                peer.require_joined(&envelope).await?;
                write_authority(&peer.authority_path, &envelope)?;
                peer.write_local(&LocalRecord {
                    left: false,
                    ..peer.local()?
                })?;
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
            if peer.role == Role::Intruder {
                validate_authority(&envelope, peer.container)?;
            } else {
                peer.require_joined(&envelope).await?;
            }
            write_authority(&peer.authority_path, &envelope)?;
            peer.write_local(&LocalRecord {
                left: false,
                ..peer.local()?
            })?;
            Ok((json!({ "ok": true, "authority_installed": true }), false))
        },
        Request::Contribute {
            comparison_utf8_hex,
        } => Ok((peer.contribute(&comparison_utf8_hex, false).await?, false)),
        Request::MintUnauthorized {
            comparison_utf8_hex,
        } => Ok((peer.contribute(&comparison_utf8_hex, true).await?, false)),
        Request::Export => {
            peer.installed().await?;
            let lane = peer
                .lane
                .drop_records()
                .await
                .map_err(|error| error.to_string())?;
            let mut operations = Vec::new();
            for record in peer.operation_records().await?.into_iter().chain(lane) {
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
        Request::Leave => {
            peer.installed().await?;
            peer.write_local(&LocalRecord {
                left: true,
                ..peer.local()?
            })?;
            fs::remove_file(&peer.authority_path).map_err(|error| error.to_string())?;
            Ok((
                json!({
                    "ok": true,
                    "lifecycle": Lifecycle::Left.name(),
                    "retained_count": peer.operation_records().await?.len(),
                    "retained_delegation_count": peer.lane_count().await?,
                }),
                false,
            ))
        },
        Request::Recheck => {
            peer.admitted().await?;
            Ok((
                json!({
                    "ok": true,
                    "lifecycle": Lifecycle::Joined.name(),
                    "now_ms": peer.local()?.now_ms,
                }),
                false,
            ))
        },
        Request::AdvanceClock { now_ms } => {
            let local = peer.local()?;
            if now_ms < local.now_ms {
                return Err(format!(
                    "clock refuses to move backwards from {} ms to {now_ms} ms",
                    local.now_ms
                ));
            }
            peer.write_local(&LocalRecord { now_ms, ..local })?;
            let (_, lifecycle, _) = peer.standing().await?;
            Ok((
                json!({
                    "ok": true,
                    "proof_only": true,
                    "now_ms": now_ms,
                    "lifecycle": lifecycle.name(),
                }),
                false,
            ))
        },
        Request::RevokeMember => Ok((peer.revoke_member().await?, false)),
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
