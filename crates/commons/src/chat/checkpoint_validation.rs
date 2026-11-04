// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

pub(super) fn validate_current_checkpoint_authority(
    author: [u8; 32],
    authority: &ChatCheckpointAuthority,
    candidate: &ChatCheckpoint,
) -> Result<(), String> {
    if !authority.permits_checkpoint(author, &candidate.authority_revision) {
        return Err("checkpoint author or authority revision is not current".into());
    }
    Ok(())
}

pub(super) fn validate_checkpoint_epoch_inventory(
    keys: &DataKeyring,
    candidate: &ChatCheckpoint,
) -> Result<(), String> {
    let Some(local_order) = keys.epochs_oldest_first() else {
        return Err("checkpoint admission requires proven local epoch chronology".into());
    };
    if candidate.epoch_inventory.len() > local_order.len()
        || local_order[..candidate.epoch_inventory.len()] != candidate.epoch_inventory
    {
        return Err("checkpoint epoch inventory is not a prefix of local chronology".into());
    }
    Ok(())
}

/// The signed chain link of a checkpoint record. A record without one is a
/// version 1 checkpoint.
pub(super) fn checkpoint_link(
    operation: &Operation<ChatExt>,
) -> Result<ChatCheckpointLink, ChatError> {
    match operation.header.extensions.checkpoint {
        Some(link) if link.version == CHAT_CHECKPOINT_VERSION => Ok(link),
        Some(link) => Err(ChatError::UnsupportedCheckpointVersion(link.version)),
        None => Err(ChatError::UnsupportedCheckpointVersion(1)),
    }
}

/// Checks one checkpoint needs no predecessor for.
pub(super) fn validate_checkpoint_body(
    expected_space: [u8; 32],
    operation: &Operation<ChatExt>,
    link: ChatCheckpointLink,
    envelope: &GroupCiphertext,
    candidate: &ChatCheckpoint,
) -> Result<(), String> {
    if candidate.version != CHAT_CHECKPOINT_VERSION {
        return Err(format!(
            "unsupported checkpoint version {}",
            candidate.version
        ));
    }
    if candidate.space_id != expected_space {
        return Err("checkpoint addresses another Commons".into());
    }
    if candidate.previous_checkpoint != link.previous {
        return Err("signed checkpoint link does not match its encrypted body".into());
    }
    let signed_parents = &operation.header.extensions.parents;
    if candidate.snapshot_commitment
        != ChatCheckpoint::snapshot_commitment(&candidate.snapshot)
            .map_err(|error| error.to_string())?
    {
        return Err("checkpoint snapshot commitment is false".into());
    }
    if *signed_parents != candidate.causal_frontier {
        return Err("signed checkpoint frontier does not match its encrypted body".into());
    }
    let unique_causal: BTreeSet<_> = candidate.causal_frontier.iter().copied().collect();
    if unique_causal.len() != candidate.causal_frontier.len() {
        return Err("checkpoint causal frontier contains duplicates".into());
    }
    if candidate.epoch_inventory.last().copied() != Some(candidate.current_epoch)
        || envelope.epoch != candidate.current_epoch
    {
        return Err("checkpoint is not protected under its named current epoch".into());
    }

    let authors: BTreeSet<_> = candidate
        .author_frontiers
        .iter()
        .map(|frontier| frontier.author)
        .collect();
    if authors.len() != candidate.author_frontiers.len() {
        return Err("checkpoint author frontier contains duplicates".into());
    }

    let mut held_operations = BTreeSet::new();
    for hold in &candidate.holds {
        if !candidate.epoch_inventory.contains(&hold.epoch) {
            return Err("checkpoint hold names an epoch outside its inventory".into());
        }
        if hold.operations.is_empty() {
            return Err("checkpoint hold contains no retained operation".into());
        }
        for operation in &hold.operations {
            if !held_operations.insert(*operation) {
                return Err("checkpoint hold repeats a retained operation".into());
            }
        }
    }
    Ok(())
}

/// A new checkpoint must extend the latest accepted one without rewinding.
pub(super) fn validate_checkpoint_succession(
    current: Option<&StoredChatCheckpoint>,
    candidate: &ChatCheckpoint,
) -> Result<(), String> {
    if candidate.previous_checkpoint != current.map(|stored| stored.operation) {
        return Err("checkpoint does not extend the latest accepted checkpoint".into());
    }
    let Some(current) = current else {
        return Ok(());
    };
    let next: BTreeMap<_, _> = candidate
        .author_frontiers
        .iter()
        .map(|frontier| (frontier.author, frontier))
        .collect();
    for previous in &current.checkpoint.author_frontiers {
        let Some(next) = next.get(&previous.author) else {
            return Err("checkpoint drops an existing author frontier".into());
        };
        if next.seq_num < previous.seq_num
            || (next.seq_num == previous.seq_num && next.operation != previous.operation)
        {
            return Err("checkpoint author frontier rewinds".into());
        }
    }
    Ok(())
}

/// Rebuild the candidate from the retained records it covers, folded onto
/// the current checkpoint, and require the same content. Covered records are
/// verified here, while they are still readable, so pruning can trust them.
pub(super) fn verify_checkpoint_content(
    keys: &DataKeyring,
    space_id: [u8; 32],
    current: Option<&ChatCheckpoint>,
    data: &[StoredChatOperation],
    candidate: &ChatCheckpoint,
) -> Result<(), String> {
    let covered: BTreeSet<_> = covered_operations(candidate).collect();
    let records: Vec<_> = data
        .iter()
        .filter(|record| covered.contains(record.operation.hash.as_bytes()))
        .cloned()
        .collect();
    if records.len() != covered.len() {
        return Err("checkpoint covers operations this replica does not retain".into());
    }
    let rebuilt =
        checkpoint_content(keys, space_id, &records, current).map_err(|error| error.to_string())?;
    if !rebuilt.pending.is_empty()
        || rebuilt.snapshot != candidate.snapshot
        || rebuilt.causal_frontier != candidate.causal_frontier
        || rebuilt.author_frontiers != candidate.author_frontiers
    {
        return Err("checkpoint content does not match the retained operations it covers".into());
    }
    Ok(())
}

pub(super) fn covered_operations(
    checkpoint: &ChatCheckpoint,
) -> impl Iterator<Item = [u8; 32]> + '_ {
    checkpoint
        .snapshot
        .covered
        .iter()
        .flat_map(|author| author.operations.iter().copied())
}

/// Walk the signed header links to the chain's tip and decrypt only the tip.
/// Each earlier link was checked against its predecessor at admission.
pub(super) fn latest_checkpoint_from_records(
    space_id: [u8; 32],
    keys: &DataKeyring,
    records: &[StoredChatOperation],
) -> Result<Option<StoredChatCheckpoint>, ChatError> {
    let mut successors = BTreeMap::new();
    for record in records {
        let link = checkpoint_link(&record.operation)?;
        if successors
            .insert(link.previous, &record.operation)
            .is_some()
        {
            return Err(ChatError::Checkpoint(
                "checkpoint history is forked or missing a predecessor".into(),
            ));
        }
    }
    let mut tip: Option<&Operation<ChatExt>> = None;
    while let Some(next) = successors.remove(&tip.map(|operation| *operation.hash.as_bytes())) {
        tip = Some(next);
    }
    if !successors.is_empty() {
        return Err(ChatError::Checkpoint(
            "checkpoint history is forked or missing a predecessor".into(),
        ));
    }
    let Some(operation) = tip else {
        return Ok(None);
    };
    let (checkpoint, envelope) = decode_checkpoint_operation(keys, operation)?;
    validate_checkpoint_body(
        space_id,
        operation,
        checkpoint_link(operation)?,
        &envelope,
        &checkpoint,
    )
    .map_err(ChatError::Checkpoint)?;
    Ok(Some(StoredChatCheckpoint {
        operation: *operation.hash.as_bytes(),
        checkpoint,
    }))
}

pub(super) fn checkpoint_content(
    keys: &DataKeyring,
    space_id: [u8; 32],
    records: &[StoredChatOperation],
    previous: Option<&ChatCheckpoint>,
) -> Result<CheckpointContent, ChatError> {
    let fold = fold_chat(keys, space_id, records, previous, &AllowAllAuthority)?;
    let effective = causal_entries(fold.order.iter().map(|index| &records[*index]));
    let mut causal_frontier = observed_frontier(&effective)?;
    causal_frontier.sort_unstable();
    let mut author_frontiers = BTreeMap::<[u8; 32], ChatAuthorFrontier>::new();
    let mut covered = BTreeMap::<[u8; 32], Vec<[u8; 32]>>::new();
    for (entry, author) in effective.iter().zip(&fold.authors) {
        if author_frontiers
            .get(&entry.author)
            .is_none_or(|current| current.seq_num < entry.seq_num)
        {
            author_frontiers.insert(
                entry.author,
                ChatAuthorFrontier {
                    author: entry.author,
                    seq_num: entry.seq_num,
                    operation: entry.operation,
                },
            );
        }
        covered.entry(*author).or_default().push(entry.operation);
    }
    let projection = fold.projection;
    Ok(CheckpointContent {
        causal_frontier,
        author_frontiers: author_frontiers.into_values().collect(),
        snapshot: ChatCheckpointSnapshot {
            channels: projection.channels,
            messages: projection.messages,
            deleted_messages: projection.deleted_messages,
            covered: covered
                .into_iter()
                .map(|(author, operations)| ChatCoveredAuthor { author, operations })
                .collect(),
            channel_writes: fold.channel_writes.into_values().collect(),
        },
        pending: projection.pending,
    })
}

pub(super) fn decode_checkpoint_operation(
    keys: &DataKeyring,
    operation: &Operation<ChatExt>,
) -> Result<(ChatCheckpoint, GroupCiphertext), ChatError> {
    if operation.header.extensions.class != ChatClass::Checkpoint {
        return Err(ChatError::Checkpoint(
            "checkpoint log contains a non-checkpoint operation".into(),
        ));
    }
    let envelope = encrypted_body(operation)?;
    let plaintext = keys.open(&envelope)?;
    let record: ChatAuthored<ChatCheckpoint> = decode_authored(plaintext.as_slice())?;
    stable_chat_author(operation, &record)?;
    Ok((record.payload, envelope))
}
