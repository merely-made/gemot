// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

/// Domain-separated salt for one chat space's Personae-derived signing key.
pub fn chat_identity_salt(space_id: [u8; 32]) -> Vec<u8> {
    let mut salt = Vec::with_capacity(61);
    salt.extend_from_slice(b"mere.commons.chat.writer.v1/");
    salt.extend_from_slice(&space_id);
    salt
}

/// Typed write capability carried by every retained fact in one chat space.
pub fn chat_write_capability(space_id: [u8; 32]) -> Cap {
    let hex: String = space_id.iter().map(|byte| format!("{byte:02x}")).collect();
    Cap::scope(&format!("commons/chat/{hex}"))
        .expect("a fixed prefix plus lowercase hex is a valid scope")
}

pub(super) fn decode_authored<T: DeserializeOwned>(
    bytes: &[u8],
) -> Result<ChatAuthored<T>, ChatError> {
    match decode_cbor_strict::<ChatAuthored<T>, _>(bytes) {
        Ok(record) => {
            if record.version != CHAT_AUTHORED_VERSION {
                return Err(ChatAuthorBindingError::UnsupportedVersion(record.version).into());
            }
            Ok(record)
        }
        Err(_) => {
            let payload =
                decode_cbor_strict(bytes).map_err(|error| ChatError::Wire(error.to_string()))?;
            Ok(ChatAuthored {
                version: 0,
                payload,
                author_attestation: None,
            })
        }
    }
}

pub(super) fn stable_chat_author<T>(
    operation: &Operation<ChatExt>,
    record: &ChatAuthored<T>,
) -> Result<[u8; 32], ChatAuthorBindingError> {
    let signer = *operation.header.verifying_key.as_bytes();
    let Some(attestation) = &record.author_attestation else {
        return Ok(signer);
    };
    let checked = attestation
        .check(&chat_identity_salt(operation.header.extensions.space_id))
        .map_err(ChatAuthorBindingError::InvalidAttestation)?;
    let derived = attestation
        .derived_public_key()
        .map_err(|_| ChatAuthorBindingError::InvalidDerivedKey)?
        .to_bytes();
    if derived != signer {
        return Err(ChatAuthorBindingError::SignerMismatch);
    }
    // The check decoded the master key, so the root is well formed.
    Ok(*checked.master())
}

/// The checks admission makes before decrypting, which parking repeats:
/// space, causal metadata, envelope, and the log's link and authority.
pub(super) fn chat_header<'a>(
    space_id: [u8; 32],
    checkpoint_authority: Option<&'a ChatCheckpointAuthority>,
    operation: &Operation<ChatExt>,
) -> Result<(GroupCiphertext, ChatLog<'a>), Reject> {
    if operation.header.extensions.space_id != space_id {
        return Err(Reject::new(
            "wrong-chat-space",
            "operation addresses another Commons chat space",
        ));
    }
    validate_causal_metadata(operation, &operation.header.extensions.parents, CHAT_LIMITS)
        .map_err(|error| Reject::new("invalid-chat-causality", error.to_string()))?;
    let body = operation.body.as_ref().ok_or_else(|| {
        Reject::new(
            "missing-chat-ciphertext",
            "chat operation requires an encrypted body",
        )
    })?;
    let envelope = decode_cbor_strict::<GroupCiphertext, _>(body.to_bytes().as_slice())
        .map_err(|error| Reject::new("invalid-chat-ciphertext", error.to_string()))?;
    let log = match operation.header.extensions.class {
        ChatClass::Channel
        | ChatClass::Message
        | ChatClass::MessageEdit
        | ChatClass::MessageDelete => {
            if operation.header.extensions.checkpoint.is_some() {
                return Err(Reject::new(
                    "unexpected-checkpoint-link",
                    "only a checkpoint carries a checkpoint link",
                ));
            }
            ChatLog::Data
        }
        ChatClass::Checkpoint => {
            let authority = checkpoint_authority.ok_or_else(|| {
                Reject::new(
                    "checkpoint-authority-unconfigured",
                    "this Commons has no configured checkpoint authority",
                )
            })?;
            if authority.signers.len() != 1 {
                return Err(Reject::new(
                    "ambiguous-checkpoint-authority",
                    format!(
                        "checkpoint v1 requires one active signer, found {}",
                        authority.signers.len()
                    ),
                ));
            }
            let link = checkpoint_link(operation).map_err(|error| {
                Reject::new("unsupported-chat-checkpoint-version", error.to_string())
            })?;
            ChatLog::Checkpoint { authority, link }
        }
    };
    Ok((envelope, log))
}

/// Park one operation when it names an unheld epoch or backlinks a parked
/// record; otherwise admit it against the retained history. Shared by
/// [`ChatReplica::accept`] and the joined lane's accept closure.
pub(super) async fn accept_or_park<B: Backend + Clone>(
    store: &MunimentStore<B, ChatExt>,
    space_id: [u8; 32],
    keys: Arc<DataKeyring>,
    checkpoint_authority: Option<ChatCheckpointAuthority>,
    parking: &Parking,
    operation: &Operation<ChatExt>,
) -> Result<bool, ChatError> {
    if let Ok((envelope, log)) = chat_header(space_id, checkpoint_authority.as_ref(), operation)
        && parking
            .should_park(store, operation, log.id(), keys.contains(&envelope.epoch))
            .await?
        && parking.park(store.backend(), operation, log.id()).await?
    {
        return Ok(false);
    }
    let retained = split_chat_records(load_operations_from_store(store, space_id).await?);
    admit_onto(
        store,
        space_id,
        keys,
        checkpoint_authority,
        operation,
        retained,
        &[],
    )
    .await
}

/// Admit one operation with one key snapshot against its retained history,
/// never parking. `carried` writes commit in the insert's own batch: a
/// re-admission unparks the record there, and every other caller passes none.
pub(super) async fn admit_onto<B: Backend + Clone>(
    store: &MunimentStore<B, ChatExt>,
    space_id: [u8; 32],
    keys: Arc<DataKeyring>,
    checkpoint_authority: Option<ChatCheckpointAuthority>,
    operation: &Operation<ChatExt>,
    retained: RetainedChatRecords,
    carried: &[WriteOp],
) -> Result<bool, ChatError> {
    let policy = chat_policy(space_id, keys, checkpoint_authority, retained)?;
    let processor = OperationProcessor::new(store.clone(), policy);
    if carried.is_empty() {
        return Ok(processor.process(operation).await?.inserted());
    }
    Ok(processor.process_with_writes(operation, carried).await?)
}

/// Assemble the admission policy from one decode of the retained history.
pub(super) fn chat_policy(
    space_id: [u8; 32],
    keys: Arc<DataKeyring>,
    checkpoint_authority: Option<ChatCheckpointAuthority>,
    retained: RetainedChatRecords,
) -> Result<ChatPolicy, ChatError> {
    let current_checkpoint =
        latest_checkpoint_from_records(space_id, &keys, &retained.checkpoints)?;
    // Admission is structural: an operation is stored whatever the current
    // authority verdict says about its author, so revocation stays a projection
    // decision that a later re-evaluation can reverse.
    let projected_message_authors = fold_chat(
        &keys,
        space_id,
        &retained.data,
        current_checkpoint.as_ref().map(|stored| &stored.checkpoint),
        &AllowAllAuthority,
    )?
    .projection
    .messages
    .into_iter()
    .map(|message| (message.operation, message.author))
    .collect();
    Ok(ChatPolicy {
        space_id,
        keys,
        projected_message_authors,
        checkpoint_authority,
        current_checkpoint,
        data: retained.data,
    })
}

impl OperationPolicy<ChatExt> for ChatPolicy {
    type LogId = u64;

    fn admit(&self, operation: &Operation<ChatExt>) -> Result<Admission<u64>, Reject> {
        let (envelope, log) =
            chat_header(self.space_id, self.checkpoint_authority.as_ref(), operation)?;
        let keys = &self.keys;
        let log_id = log.id();
        match log {
            ChatLog::Data => {
                let plaintext = keys
                    .open(&envelope)
                    .map_err(|error| Reject::new("unreadable-chat-event", error.to_string()))?;
                let record: ChatAuthored<ChatEvent> = decode_authored(plaintext.as_slice())
                    .map_err(|error| Reject::new("invalid-chat-event", error.to_string()))?;
                let stable_author = stable_chat_author(operation, &record).map_err(|error| {
                    Reject::new("invalid-chat-author-binding", error.to_string())
                })?;
                let event = record.payload;
                if event.class() != operation.header.extensions.class {
                    return Err(Reject::new(
                        "mismatched-chat-class",
                        "signed content class does not match encrypted event",
                    ));
                }
                let original = match &event {
                    ChatEvent::MessageEdit(edit) => Some(edit.original),
                    ChatEvent::MessageDelete(delete) => Some(delete.original),
                    ChatEvent::Channel(_) | ChatEvent::Message(_) => None,
                };
                if let Some(original) = original {
                    let Some(author) = self.projected_message_authors.get(&original) else {
                        return Err(Reject::new(
                            "unprojected-message-mutation",
                            "edit or deletion must reference a current projected message",
                        ));
                    };
                    if author != &stable_author {
                        return Err(Reject::new(
                            "foreign-message-mutation",
                            "only the original author can edit or delete a message",
                        ));
                    }
                }
            }
            ChatLog::Checkpoint { authority, link } => {
                let plaintext = keys.open(&envelope).map_err(|error| {
                    Reject::new("unreadable-chat-checkpoint", error.to_string())
                })?;
                let record: ChatAuthored<ChatCheckpoint> = decode_authored(plaintext.as_slice())
                    .map_err(|error| Reject::new("invalid-chat-checkpoint", error.to_string()))?;
                let stable_author = stable_chat_author(operation, &record).map_err(|error| {
                    Reject::new("invalid-chat-author-binding", error.to_string())
                })?;
                let checkpoint = record.payload;
                let current = self.current_checkpoint.as_ref();
                validate_checkpoint_body(self.space_id, operation, link, &envelope, &checkpoint)
                    .and_then(|()| validate_checkpoint_succession(current, &checkpoint))
                    .and_then(|()| {
                        validate_current_checkpoint_authority(stable_author, authority, &checkpoint)
                    })
                    .and_then(|()| validate_checkpoint_epoch_inventory(keys, &checkpoint))
                    .and_then(|()| {
                        verify_checkpoint_content(
                            keys,
                            self.space_id,
                            current.map(|stored| &stored.checkpoint),
                            &self.data,
                            &checkpoint,
                        )
                    })
                    .map_err(|error| Reject::new("invalid-chat-checkpoint", error))?;
            }
        }
        Ok(Admission::keep(StoreTarget::new(
            Topic::from(self.space_id),
            log_id,
        )))
    }
}

impl ChatClass {
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Channel => "commons.channel",
            Self::Message => "commons.message",
            Self::Checkpoint => "commons.checkpoint",
            Self::MessageEdit => "commons.message.edit",
            Self::MessageDelete => "commons.message.delete",
        }
    }
}

impl ChatEvent {
    pub(super) fn class(&self) -> ChatClass {
        match self {
            Self::Channel(_) => ChatClass::Channel,
            Self::Message(_) => ChatClass::Message,
            Self::MessageEdit(_) => ChatClass::MessageEdit,
            Self::MessageDelete(_) => ChatClass::MessageDelete,
        }
    }
}

impl<T> ChatAuthored<T> {
    pub(super) fn new(payload: T, author_attestation: Option<DerivedKeyAttestation>) -> Self {
        Self {
            version: CHAT_AUTHORED_VERSION,
            payload,
            author_attestation,
        }
    }
}

impl ChatCheckpoint {
    pub(super) fn snapshot_commitment(
        snapshot: &ChatCheckpointSnapshot,
    ) -> Result<Digest, ChatError> {
        let bytes = encode_cbor(snapshot).map_err(|error| ChatError::Wire(error.to_string()))?;
        Ok(Digest::blake3(&bytes))
    }
}

impl ChatCheckpointAuthority {
    pub fn new(authority_revision: Digest, signers: impl IntoIterator<Item = [u8; 32]>) -> Self {
        Self {
            authority_revision,
            signers: signers.into_iter().collect(),
        }
    }
}

impl CheckpointAuthority for ChatCheckpointAuthority {
    fn authority_revision(&self) -> Digest {
        self.authority_revision.clone()
    }

    fn permits_checkpoint(&self, author: [u8; 32], named_revision: &Digest) -> bool {
        *named_revision == self.authority_revision && self.signers.contains(&author)
    }
}
