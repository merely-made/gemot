// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

pub(super) fn split_chat_records(records: Vec<StoredChatOperation>) -> RetainedChatRecords {
    let mut data = Vec::new();
    let mut checkpoints = Vec::new();
    for record in records {
        match record.log_id {
            CHAT_LOG => data.push(record),
            CHAT_CHECKPOINT_LOG => checkpoints.push(record),
            _ => {}
        }
    }
    RetainedChatRecords { data, checkpoints }
}

pub(super) fn causal_entries<'a>(
    records: impl IntoIterator<Item = &'a StoredChatOperation>,
) -> Vec<CausalEntry<u64>> {
    records
        .into_iter()
        .map(|record| {
            CausalEntry::from_operation(
                &record.operation,
                record.log_id,
                record.operation.header.extensions.parents.clone(),
            )
        })
        .collect()
}

pub(super) async fn load_operations_from_store<B: Backend + Clone>(
    store: &MunimentStore<B, ChatExt>,
    space_id: [u8; 32],
) -> Result<Vec<StoredChatOperation>, ChatError> {
    let logs: BTreeMap<VerifyingKey, Vec<u64>> = store.resolve(&Topic::from(space_id)).await?;
    let mut records = Vec::new();
    for (author, mut log_ids) in logs {
        log_ids.sort_unstable();
        log_ids.dedup();
        for log_id in log_ids {
            for (operation, _) in store
                .get_log_entries(&author, &log_id, None, None)
                .await?
                .unwrap_or_default()
            {
                records.push(StoredChatOperation { operation, log_id });
            }
        }
    }
    Ok(records)
}

/// Classify one decrypted record against the caller's converged authority.
///
/// An author's verdict is one evaluation of one stable Personae root, so a
/// message and its own later edit or deletion always classify together. That
/// keeps [`apply_event`]'s "mutation must reference a projected original"
/// invariant intact when a subject's capability is withdrawn.
pub(super) fn classify_record(
    authority: &impl CommonsAuthority,
    capability: &Cap,
    operation: &Operation<ChatExt>,
    author: [u8; 32],
) -> (AuthorityState, AuthorityOperation) {
    (
        authority.classify(Subject(author), capability, Mode::Write),
        AuthorityOperation {
            operation: *operation.hash.as_bytes(),
            subject: author,
            capability: capability.clone(),
        },
    )
}

/// Fold in causal order over every retained header, exactly as a full replay
/// would. Records the checkpoint covers come from its author index and
/// snapshot; only the rest are decrypted.
pub(super) fn fold_chat<A: CommonsAuthority>(
    keys: &DataKeyring,
    space_id: [u8; 32],
    records: &[StoredChatOperation],
    checkpoint: Option<&ChatCheckpoint>,
    authority: &A,
) -> Result<ChatFold, ChatError> {
    let covered = CheckpointIndex::new(checkpoint);
    let causal = causal_projection(&causal_entries(records))?;
    let capability = chat_write_capability(space_id);
    let mut channels = BTreeMap::new();
    let mut projection = ChatProjection::default();
    let mut authors = Vec::with_capacity(causal.order.len());
    let mut channel_writes = BTreeMap::new();
    for &index in &causal.order {
        let operation = &records[index].operation;
        let id = *operation.hash.as_bytes();
        let (author, event) = match covered.authors.get(&id) {
            Some(author) => (*author, None),
            None => {
                let (event, author) = decode_event_record(keys, operation)?;
                (author, Some(event))
            }
        };
        authors.push(author);
        let write = match &event {
            Some(ChatEvent::Channel(channel)) => Some(ChatChannelWrite {
                operation: id,
                author,
                channel: channel.clone(),
            }),
            Some(_) => None,
            // Absent when the same author overwrote it before the checkpoint.
            None => covered.channels.get(&id).map(|write| (*write).clone()),
        };
        if let Some(write) = &write {
            channel_writes.insert((write.channel.id.clone(), author), write.clone());
        }
        let (state, classified) = classify_record(authority, &capability, operation, author);
        match state {
            AuthorityState::Pending => {
                projection.pending_authority.push(classified);
                continue;
            }
            AuthorityState::Revoked => {
                projection.revoked.push(classified);
                continue;
            }
            AuthorityState::Effective => {}
        }
        match event {
            Some(event) => apply_event(
                &mut channels,
                &mut projection.messages,
                &mut projection.deleted_messages,
                operation,
                author,
                event,
            )?,
            // A covered message arrives with its covered edits already applied.
            None => {
                if let Some(write) = write {
                    channels.insert(write.channel.id.clone(), write.channel);
                }
                if let Some(message) = covered.messages.get(&id) {
                    projection.messages.push((*message).clone());
                }
                if let Some(deleted) = covered.deleted.get(&id) {
                    projection.deleted_messages.push((*deleted).clone());
                }
            }
        }
    }
    projection.channels = channels.into_values().collect();
    projection.pending = causal.pending;
    Ok(ChatFold {
        projection,
        order: causal.order,
        authors,
        channel_writes,
    })
}

pub(super) fn apply_event(
    channels: &mut BTreeMap<String, Channel>,
    messages: &mut Vec<AuthoredMessage>,
    deleted_messages: &mut Vec<DeletedMessage>,
    operation: &Operation<ChatExt>,
    stable_author: [u8; 32],
    event: ChatEvent,
) -> Result<(), ChatError> {
    if event.class() != operation.header.extensions.class {
        return Err(ChatError::Wire(
            "signed content class does not match encrypted event".into(),
        ));
    }
    match event {
        ChatEvent::Channel(channel) => {
            channels.insert(channel.id.clone(), channel);
        }
        ChatEvent::Message(message) => messages.push(AuthoredMessage {
            operation: *operation.hash.as_bytes(),
            author: stable_author,
            message,
            latest_edit: None,
            edited_at_ms: None,
        }),
        ChatEvent::MessageEdit(edit) => {
            let message = messages
                .iter_mut()
                .find(|message| message.operation == edit.original)
                .ok_or_else(|| {
                    ChatError::MessageMutation(
                        "edit does not reference a projected original message".into(),
                    )
                })?;
            require_original_author(message, stable_author)?;
            message.message.body = edit.body;
            message.latest_edit = Some(*operation.hash.as_bytes());
            message.edited_at_ms = Some(edit.edited_at_ms);
        }
        ChatEvent::MessageDelete(delete) => {
            let index = messages
                .iter()
                .position(|message| message.operation == delete.original)
                .ok_or_else(|| {
                    ChatError::MessageMutation(
                        "deletion does not reference a projected original message".into(),
                    )
                })?;
            require_original_author(&messages[index], stable_author)?;
            let message = messages.remove(index);
            deleted_messages.push(DeletedMessage {
                original: message.operation,
                author: message.author,
                deletion: *operation.hash.as_bytes(),
                deleted_at_ms: delete.deleted_at_ms,
            });
        }
    }
    Ok(())
}

pub(super) fn require_original_author(
    original: &AuthoredMessage,
    mutation_author: [u8; 32],
) -> Result<(), ChatError> {
    if original.author != mutation_author {
        return Err(ChatError::MessageMutation(
            "only the original author can edit or delete a message".into(),
        ));
    }
    Ok(())
}

pub(super) fn encrypted_body(operation: &Operation<ChatExt>) -> Result<GroupCiphertext, ChatError> {
    let body = operation
        .body
        .as_ref()
        .ok_or_else(|| ChatError::Wire("operation body is absent".into()))?;
    decode_cbor_strict(body.to_bytes().as_slice())
        .map_err(|error| ChatError::Wire(error.to_string()))
}

#[cfg(test)]
pub(super) fn decode_event(
    keys: &DataKeyring,
    operation: &Operation<ChatExt>,
) -> Result<ChatEvent, ChatError> {
    decode_event_record(keys, operation).map(|(event, _)| event)
}

pub(super) fn decode_event_record(
    keys: &DataKeyring,
    operation: &Operation<ChatExt>,
) -> Result<(ChatEvent, [u8; 32]), ChatError> {
    let envelope = encrypted_body(operation)?;
    let plaintext = keys.open(&envelope)?;
    let record: ChatAuthored<ChatEvent> = decode_authored(plaintext.as_slice())?;
    let stable_author = stable_chat_author(operation, &record)?;
    Ok((record.payload, stable_author))
}
