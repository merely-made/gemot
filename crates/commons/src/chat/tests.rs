// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use personae::delegation::Issue;
use std::io::Cursor;
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::time::Duration;

use crate::{AuthorityState, CommonsAuthority, GemotAuthorityView};
use gemot::moot::constitution::{CapabilityGrant, ConstitutionRules};
use gemot::moot::{MOOT_ACT_ACTION, MOOT_DELEGATION_DOMAIN, MootAuthority, MootDelegations};
use insigne::delegation::{
    CapabilityScope, DelegationCertificate, DelegationParent, DelegationRevocation,
    SignedDelegationCertificate, SignedDelegationRevocation,
};
use muniment::RedbBackend;
use murm::{CabalId, CabalKey, CabalKeyring};
use personae::{IdentityProvider, InMemoryProvider};
use servitor::{Mode, Subject, cap_path};
use stickleback::{
    DropLimits, DropRecord, decode_operation_record, operation_record, read_protected_drop,
    write_protected_drop,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use transport::{
    Alpn, P2pandaTransport, PeerID, ReticulumInterface, ReticulumTransport, Transport,
    sync_overlay_topic,
};

use super::*;
use p2panda_core::cbor::decode_cbor;

const SPACE: [u8; 32] = [0x51; 32];
const MOOT: [u8; 32] = [0x6d; 32];
const ROOT_GRANT: [u8; 32] = [0x67; 32];

/// Every retained record decrypted and no checkpoint consulted: the
/// reference a checkpoint-rooted projection must reproduce.
async fn full_replay<B: Backend + Clone>(
    replica: &ChatReplica<B>,
    authority: &impl CommonsAuthority,
) -> Result<ChatProjection, ChatError> {
    let records = replica.load_data_operations().await?;
    let keys = replica.keys.current();
    Ok(fold_chat(&keys, replica.space_id, &records, None, authority)?.projection)
}

fn paired_keys() -> (DataKeyring, DataKeyring) {
    let rng = p2panda_encryption::Rng::default();
    let mut alice = DataKeyring::new();
    let secret = alice.rotate(&rng).unwrap();
    let mut bob = DataKeyring::new();
    bob.install(secret);
    (alice, bob)
}

fn free_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

fn checkpoint_authority(seed: [u8; 32], revision: &[u8]) -> ChatCheckpointAuthority {
    let author = SigningKey::from_bytes(&seed).verifying_key();
    ChatCheckpointAuthority::new(Digest::blake3(revision), [*author.as_bytes()])
}

fn checkpoint_operation(
    replica: &ChatReplica<MemoryBackend>,
    checkpoint: &ChatCheckpoint,
    signing_seed: [u8; 32],
    seq_num: u32,
    backlink: Option<[u8; 32]>,
) -> Operation<ChatExt> {
    let link = ChatCheckpointLink {
        version: CHAT_CHECKPOINT_VERSION,
        previous: checkpoint.previous_checkpoint,
    };
    linked_checkpoint_operation(
        replica,
        checkpoint,
        signing_seed,
        seq_num,
        backlink,
        Some(link),
    )
}

fn linked_checkpoint_operation(
    replica: &ChatReplica<MemoryBackend>,
    checkpoint: &ChatCheckpoint,
    signing_seed: [u8; 32],
    seq_num: u32,
    backlink: Option<[u8; 32]>,
    link: Option<ChatCheckpointLink>,
) -> Operation<ChatExt> {
    let plaintext = encode_cbor(checkpoint).unwrap();
    let envelope = replica
        .keys
        .current()
        .seal(&plaintext, &p2panda_encryption::Rng::default())
        .unwrap();
    let body = Body::from_bytes(&encode_cbor(&envelope).unwrap());
    let signing_key = SigningKey::from_bytes(&signing_seed);
    // p2panda 0.7.1 made the header's CBOR cache, size and digest private
    // and folded signing into the builder: `build` encodes, signs and
    // caches the digest in one step, so the struct-literal + `sign` pair
    // has no equivalent. `body` sets payload_size and payload_hash.
    let header = Header::builder()
        .body(body.as_bytes())
        .seq_num(seq_num)
        .backlink(backlink.map(Hash::from))
        .build(
            &signing_key,
            ChatExt {
                space_id: replica.space_id,
                class: ChatClass::Checkpoint,
                parents: checkpoint.causal_frontier.clone(),
                checkpoint: link,
            },
        );
    Operation {
        hash: header.hash(),
        header,
        body: Some(body),
    }
}

fn event_operation(
    replica: &ChatReplica<MemoryBackend>,
    event: &ChatEvent,
    signing_seed: [u8; 32],
    parents: Vec<[u8; 32]>,
    seq_num: u32,
    backlink: Option<[u8; 32]>,
) -> Operation<ChatExt> {
    let plaintext = encode_cbor(event).unwrap();
    let envelope = replica
        .keys
        .current()
        .seal(&plaintext, &p2panda_encryption::Rng::default())
        .unwrap();
    let body = Body::from_bytes(&encode_cbor(&envelope).unwrap());
    let signing_key = SigningKey::from_bytes(&signing_seed);
    // p2panda 0.7.1 made the header's CBOR cache, size and digest private
    // and folded signing into the builder: `build` encodes, signs and
    // caches the digest in one step, so the struct-literal + `sign` pair
    // has no equivalent. `body` sets payload_size and payload_hash.
    let header = Header::builder()
        .body(body.as_bytes())
        .seq_num(seq_num)
        .backlink(backlink.map(Hash::from))
        .build(
            &signing_key,
            ChatExt {
                space_id: replica.space_id,
                class: event.class(),
                parents,
                checkpoint: None,
            },
        );
    Operation {
        hash: header.hash(),
        header,
        body: Some(body),
    }
}

fn bound_event_operation(
    replica: &ChatReplica<MemoryBackend>,
    event: ChatEvent,
    signing_seed: [u8; 32],
    author_attestation: DerivedKeyAttestation,
) -> Operation<ChatExt> {
    let record = ChatAuthored::new(event, Some(author_attestation));
    let plaintext = encode_cbor(&record).unwrap();
    let envelope = replica
        .keys
        .current()
        .seal(&plaintext, &p2panda_encryption::Rng::default())
        .unwrap();
    let body = Body::from_bytes(&encode_cbor(&envelope).unwrap());
    let signing_key = SigningKey::from_bytes(&signing_seed);
    // p2panda 0.7.1 made the header's CBOR cache, size and digest private
    // and folded signing into the builder: `build` encodes, signs and
    // caches the digest in one step, so the struct-literal + `sign` pair
    // has no equivalent. `body` sets payload_size and payload_hash.
    let header = Header::builder()
        .body(body.as_bytes())
        .seq_num(0)
        .backlink(None)
        .build(
            &signing_key,
            ChatExt {
                space_id: replica.space_id,
                class: record.payload.class(),
                parents: Vec::new(),
                checkpoint: None,
            },
        );
    Operation {
        hash: header.hash(),
        header,
        body: Some(body),
    }
}

/// Root a chat write capability in the founder's constitution and delegate
/// it to `subject`, optionally withdrawing it with a signed revocation.
fn chat_authority_fixture(
    founder: &InMemoryProvider,
    subject: [u8; 32],
    revoke: bool,
) -> (MootDelegations, ConstitutionRules) {
    let needed = cap_path(&chat_write_capability(SPACE));
    let mut rules = ConstitutionRules::founder_only(founder.master_public_key().to_bytes());
    rules.grant(CapabilityGrant {
        id: ROOT_GRANT,
        subject: founder.master_public_key().to_bytes(),
        path_prefix: needed.clone(),
        not_before_ms: 10,
        expires_at_ms: Some(1_000),
        delegation_depth: 2,
    });
    let delegation = SignedDelegationCertificate::issue(
        founder,
        DelegationCertificate::new(
            DelegationParent::Root(ROOT_GRANT),
            founder.master_public_key().to_bytes(),
            subject,
            CapabilityScope {
                domain: MOOT_DELEGATION_DOMAIN.into(),
                resource: MOOT.to_vec(),
                path_prefix: needed,
                actions: [MOOT_ACT_ACTION.to_string()].into_iter().collect(),
            },
            15,
            20,
            Some(900),
            0,
            [1; 32],
        ),
    )
    .unwrap();
    let delegation_id = delegation.certificate.id();
    let scope = delegation.certificate.scope.clone();
    let mut delegations = MootDelegations::new();
    assert!(
        delegations
            .accept_certificate(MOOT, &rules, delegation)
            .unwrap()
    );
    if revoke {
        let revocation = SignedDelegationRevocation::issue(
            founder,
            DelegationRevocation::new(
                delegation_id,
                founder.master_public_key().to_bytes(),
                scope,
                60,
                [2; 32],
            ),
        )
        .unwrap();
        assert!(delegations.accept_revocation(revocation).unwrap());
    }
    (delegations, rules)
}

fn gemot_view<'a>(
    delegations: &'a MootDelegations,
    rules: &'a ConstitutionRules,
) -> GemotAuthorityView<'a> {
    GemotAuthorityView {
        authority: MootAuthority {
            delegations,
            rules,
            moot_id: MOOT,
            now_ms: 50,
        },
    }
}

async fn seeded_author(
    writer: &InMemoryProvider,
) -> (ChatReplica<MemoryBackend>, Operation<ChatExt>) {
    let (keys, _) = paired_keys();
    let mut author = ChatReplica::in_memory_for_identity(SPACE, writer, keys).unwrap();
    author
        .author(ChatEvent::Channel(Channel {
            id: "hall".into(),
            title: "Hall".into(),
        }))
        .await
        .unwrap();
    let message = author
        .author(ChatEvent::Message(Message {
            channel: "hall".into(),
            body: "shared truth".into(),
            sent_at_ms: 1,
            reply_to: None,
        }))
        .await
        .unwrap();
    (author, message)
}

fn bodies(projection: &ChatProjection) -> Vec<&str> {
    projection
        .messages
        .iter()
        .map(|message| message.message.body.as_str())
        .collect()
}

/// A and B share one message; then A removes C, rotates and authors
/// `first` and `second`, which B's handle cannot open yet.
async fn behind_a_rotation(
    b_backend: MemoryBackend,
) -> (
    crate::keys::test_group::Group,
    ChatReplica<MemoryBackend>,
    ChatReplica<MemoryBackend>,
    [Operation<ChatExt>; 2],
) {
    use crate::keys::test_group::{Group, keyring};

    let mut group = Group::found();
    let a_keys = GroupKeys::new(keyring(&group.a));
    let mut a = ChatReplica::in_memory(SPACE, [0xa1; 32], a_keys.clone());
    let b = ChatReplica::new(b_backend, SPACE, [0xb2; 32], keyring(&group.b));
    let before = a.author(message("before rotation", 1)).await.unwrap();
    assert!(b.accept(&before).await.unwrap(), "positive control");
    group.remove_c_and_rotate();
    a_keys.replace(keyring(&group.a));
    let first = a.author(message("first after rotation", 2)).await.unwrap();
    let second = a.author(message("second after rotation", 3)).await.unwrap();
    (group, a, b, [first, second])
}

/// Sign a chosen envelope as a first chat record, bypassing sealing.
fn signed_envelope(
    space_id: [u8; 32],
    signing_seed: [u8; 32],
    envelope: &GroupCiphertext,
) -> Operation<ChatExt> {
    let body = Body::from_bytes(&encode_cbor(envelope).unwrap());
    let header = Header::builder()
        .body(body.as_bytes())
        .seq_num(0)
        .backlink(None)
        .build(
            &SigningKey::from_bytes(&signing_seed),
            ChatExt {
                space_id,
                class: ChatClass::Message,
                parents: Vec::new(),
                checkpoint: None,
            },
        );
    Operation {
        hash: header.hash(),
        header,
        body: Some(body),
    }
}

fn message(body: &str, sent_at_ms: u64) -> ChatEvent {
    ChatEvent::Message(Message {
        channel: "general".into(),
        body: body.into(),
        sent_at_ms,
        reply_to: None,
    })
}

/// The host path with chat as the only lane on the handle.
async fn host_prune(
    session: &mut stickleback::GroupSession,
    keys: &GroupKeys,
    chat: &ChatReplica<MemoryBackend>,
) -> Vec<GroupSecretId> {
    let report = chat.epoch_report(&[]).await.unwrap();
    crate::pruning::host::apply(session, keys, &[report]).release
}

/// Stores any chat record unchecked, standing in for an older store.
struct UncheckedChat;

impl OperationPolicy<ChatExt> for UncheckedChat {
    type LogId = u64;

    fn admit(&self, operation: &Operation<ChatExt>) -> Result<Admission<u64>, Reject> {
        let log = match operation.header.extensions.class {
            ChatClass::Checkpoint => CHAT_CHECKPOINT_LOG,
            _ => CHAT_LOG,
        };
        Ok(Admission::keep(StoreTarget::new(Topic::from(SPACE), log)))
    }
}

#[path = "tests/identity.rs"]
mod identity;

#[path = "tests/projection.rs"]
mod projection;

#[path = "tests/checkpoint_retention.rs"]
mod checkpoint_retention;

#[path = "tests/checkpoint_validation.rs"]
mod checkpoint_validation;

#[path = "tests/parking.rs"]
mod parking;

#[path = "tests/exchange.rs"]
mod exchange;
