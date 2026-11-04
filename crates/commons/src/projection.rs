// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

pub(super) fn record_connect_counters(
    record: &CommonsRecord,
    writer: WriterId,
) -> Result<Vec<u64>, Reject> {
    let mut counters = Vec::new();
    for edit in &record.batch.edits {
        if let GraphEdit::Connect { id, .. } = edit {
            if id.writer != writer {
                return Err(Reject::new(
                    "edge-writer-mismatch",
                    "a connect id is not scoped to the operation signer",
                ));
            }
            counters.push(id.counter);
        }
    }
    if counters
        .windows(2)
        .any(|pair| pair[0].checked_add(1) != Some(pair[1]))
    {
        return Err(Reject::new(
            "edge-counter-sequence",
            "connect counters inside one batch are not contiguous",
        ));
    }
    Ok(counters)
}

/// Record checks both graph profiles run after decoding: batch size, writer
/// binding, and edge ids minted under the signer.
pub(super) fn check_batch<E: GraphHeader>(
    operation: &Operation<E>,
    record: &CommonsRecord,
) -> Result<(), Reject> {
    if record.batch.edits.len() > MAX_EDITS_PER_BATCH {
        return Err(Reject::new(
            "commons-edit-limit",
            format!(
                "batch contains {} edits; maximum is {MAX_EDITS_PER_BATCH}",
                record.batch.edits.len()
            ),
        ));
    }
    stable_subject(operation, record)?;
    let writer = WriterId(*operation.header.verifying_key.as_bytes());
    record_connect_counters(record, writer)?;
    Ok(())
}

pub(super) async fn load_plaintext_records<B: Backend + Clone + Send + Sync + 'static>(
    store: &MunimentStore<B, CommonsExt>,
    container: [u8; 32],
) -> Result<Vec<StoredRecord>, MaterializeError> {
    load_records(store, container, |operation| Ok(from_operation(operation)?)).await
}

/// Every stored operation for `container`, with its log id, undecoded.
pub(super) async fn load_operations<B, E>(
    store: &MunimentStore<B, E>,
    container: [u8; 32],
) -> Result<Vec<(Operation<E>, u64)>, MaterializeError>
where
    B: Backend + Clone + Send + Sync + 'static,
    E: GraphHeader,
{
    let by_author: BTreeMap<VerifyingKey, Vec<u64>> =
        TopicStore::<Topic, VerifyingKey, u64>::resolve(store, &Topic::from(container)).await?;
    let mut operations = Vec::new();
    for (author, mut logs) in by_author {
        logs.sort_unstable();
        logs.dedup();
        for log_id in logs {
            let entries = store
                .get_log_entries(&author, &log_id, None, None)
                .await?
                .unwrap_or_default();
            // The tuple's second element is encoded header bytes, not the
            // payload. The signed record is reconstructed from `operation.body`.
            for (operation, _header_bytes) in entries {
                operations.push((operation, log_id));
            }
        }
    }
    Ok(operations)
}

/// Every stored record for `container`, each decoded by the profile's `open`.
pub(super) async fn load_records<B, E, D>(
    store: &MunimentStore<B, E>,
    container: [u8; 32],
    open: D,
) -> Result<Vec<StoredRecord<E>>, MaterializeError>
where
    B: Backend + Clone + Send + Sync + 'static,
    E: GraphHeader,
    D: Fn(&Operation<E>) -> Result<CommonsRecord, MaterializeError>,
{
    load_operations(store, container)
        .await?
        .into_iter()
        .map(|(operation, log_id)| {
            Ok(StoredRecord {
                record: open(&operation)?,
                operation,
                log_id,
            })
        })
        .collect()
}

pub(super) fn causal_entries<E: GraphHeader>(records: &[StoredRecord<E>]) -> Vec<CausalEntry<u64>> {
    records
        .iter()
        .map(|record| {
            CausalEntry::from_operation(
                &record.operation,
                record.log_id,
                record.record.parents.clone(),
            )
        })
        .collect()
}

pub(super) fn causal_journal<E: GraphHeader>(
    records: &[StoredRecord<E>],
) -> Result<(Journal<CommonsBatch>, Vec<PendingCausalOperation>), MaterializeError> {
    let entries = causal_entries(records);
    let projection = causal_projection(&entries)?;
    let effective: BTreeSet<_> = projection.order.iter().copied().collect();
    let causal = CausalIndex::new(&entries);
    let removals = removal_index(records, &effective);
    let mut journal = Journal::new();
    for index in projection.order {
        journal.append(remove_wins_batch(
            records, &entries, &causal, &removals, index,
        ));
    }
    Ok((journal, projection.pending))
}

pub(super) fn removal_index<'a, E>(
    records: &'a [StoredRecord<E>],
    effective: &BTreeSet<usize>,
) -> RemovalIndex<'a> {
    let mut removals = RemovalIndex::new();
    for index in effective {
        for edit in &records[*index].record.batch.edits {
            if let GraphEdit::RemoveNode(id) = edit {
                removals.entry(id).or_default().push(*index);
            }
        }
    }
    removals
}

/// Suppress only inserts concurrent with a removal of the same identity.
/// Causally later inserts remain deliberate recreation.
///
/// `causal` and `removals` are built once per fold by the caller: this asks a
/// reachability question per insert edit per competing removal, and rebuilding
/// either of them here made the fold cubic in record count.
pub(super) fn remove_wins_batch<E>(
    records: &[StoredRecord<E>],
    entries: &[CausalEntry<u64>],
    causal: &CausalIndex<'_, u64>,
    removals: &RemovalIndex<'_>,
    index: usize,
) -> CommonsBatch {
    let operation = entries[index].operation;
    let mut batch = records[index].record.batch.clone();
    batch.edits.retain(|edit| {
        let GraphEdit::InsertNode(node) = edit else {
            return true;
        };
        !removals.get(&node.id).is_some_and(|candidates| {
            candidates.iter().any(|&other_index| {
                if other_index == index {
                    return false;
                }
                let removal = entries[other_index].operation;
                !causal.happens_before(removal, operation)
                    && !causal.happens_before(operation, removal)
            })
        })
    });
    batch
}

/// `open_stored` decodes the writer's already-stored records.
pub(super) async fn validate_counter_frontier<B, E, D>(
    store: &MunimentStore<B, E>,
    operation: &Operation<E>,
    record: &CommonsRecord,
    open_stored: D,
) -> Result<(), ProcessError>
where
    B: Backend + Clone + Send + Sync + 'static,
    E: GraphHeader,
    D: Fn(&Operation<E>) -> Result<CommonsRecord, Reject>,
{
    if store.has_operation(&operation.hash).await? {
        return Ok(());
    }
    let writer = WriterId(*operation.header.verifying_key.as_bytes());
    let counters = record_connect_counters(record, writer)?;
    if counters.is_empty() {
        return Ok(());
    }

    let entries = store
        .get_log_entries(&operation.header.verifying_key, &COMMONS_LOG, None, None)
        .await?
        .unwrap_or_default();
    let mut next = 0u64;
    for (stored, _header_bytes) in entries {
        let stored_record = open_stored(&stored)?;
        for counter in record_connect_counters(&stored_record, writer)? {
            next = next.max(counter.saturating_add(1));
        }
    }
    for counter in counters {
        if counter != next {
            return Err(Reject::new(
                "edge-counter-frontier",
                format!("connect counter {counter} does not continue frontier {next}"),
            )
            .into());
        }
        next = next
            .checked_add(1)
            .ok_or_else(|| Reject::new("edge-counter-exhausted", "edge counter exhausted"))?;
    }
    Ok(())
}

/// Fold the causally and authoritatively effective subset.
pub async fn materialize_with_authority<
    B: Backend + Clone + Send + Sync + 'static,
    A: CommonsAuthority,
>(
    store: &MunimentStore<B, CommonsExt>,
    container: [u8; 32],
    authority: &A,
) -> Result<CommonsProjection, MaterializeError> {
    fold_with_authority(
        load_plaintext_records(store, container).await?,
        container,
        authority,
    )
}

/// The authority-classified causal fold both graph profiles project with.
pub(super) fn fold_with_authority<E: GraphHeader, A: CommonsAuthority>(
    records: Vec<StoredRecord<E>>,
    container: [u8; 32],
    authority: &A,
) -> Result<CommonsProjection, MaterializeError> {
    let entries = causal_entries(&records);
    let causal = causal_projection(&entries)?;
    let capability = commons_write_capability(container);
    let mut journal = Journal::new();
    let mut effective = Vec::new();
    let mut pending_authority = Vec::new();
    let mut revoked = Vec::new();
    for index in causal.order {
        let record = &records[index];
        let subject = stable_subject(&record.operation, &record.record)
            .map_err(|error| MaterializeError::WriterBinding(error.to_string()))?;
        let classified = AuthorityOperation {
            operation: *record.operation.hash.as_bytes(),
            subject,
            capability: capability.clone(),
        };
        match authority.classify(Subject(subject), &capability, Mode::Write) {
            AuthorityState::Effective => effective.push(index),
            AuthorityState::Pending => pending_authority.push(classified),
            AuthorityState::Revoked => revoked.push(classified),
        }
    }
    let effective_set: BTreeSet<_> = effective.iter().copied().collect();
    let causal_index = CausalIndex::new(&entries);
    let removals = removal_index(&records, &effective_set);
    for index in effective {
        journal.append(remove_wins_batch(
            &records,
            &entries,
            &causal_index,
            &removals,
            index,
        ));
    }
    Ok(CommonsProjection {
        graph: GraphLog::replay(journal),
        pending: causal.pending,
        pending_authority,
        revoked,
    })
}

/// Fold the causally closed subset with structural admission as the authority
/// floor. Communal callers should prefer [`materialize_with_authority`].
pub async fn materialize_projection<B: Backend + Clone + Send + Sync + 'static>(
    store: &MunimentStore<B, CommonsExt>,
    container: [u8; 32],
) -> Result<CommonsProjection, MaterializeError> {
    materialize_with_authority(store, container, &AllowAllAuthority).await
}

/// Compatibility view for callers that only need the current graph.
pub async fn materialize<B: Backend + Clone + Send + Sync + 'static>(
    store: &MunimentStore<B, CommonsExt>,
    container: [u8; 32],
) -> Result<GraphLog<Container, Relation>, MaterializeError> {
    Ok(materialize_projection(store, container).await?.graph)
}
