// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Parking for records sealed to an epoch this member does not hold yet.
//!
//! A record that reaches a member before the rotation installing its epoch
//! would be refused, and its author's later records would then fail for want
//! of their predecessor. Chat and the encrypted graph instead park a record
//! whose signature, header and causal metadata validate but whose ciphertext
//! names an epoch the key handle lacks, and park a same-author successor that
//! backlinks a parked record. Parked records are not stored, so no lane counts
//! them as accepted. After the host replaces the key handle, each lane's
//! `readmit_parked` admits them in causal order through its ordinary
//! admission; records whose epoch is still unheld stay parked.
//!
//! Only an unheld epoch parks. A ciphertext that fails under a held epoch, or
//! a record addressed to another space, is refused as before. Epoch ids name
//! no group, so a record addressed here but sealed to another group's epoch
//! parks like any other until it is evicted.
//!
//! Records live under `<lane id>/parking/records/`, one key each naming
//! arrival, author, log, sequence and size, bounded by count and bytes.
//! Overflow evicts the oldest and adds to a durable eviction count. Unparking
//! follows the insert instead of sharing its batch, because stickleback keeps
//! its insert-with-extra-writes crate-private: a crash in between leaves a
//! stored record parked, which the next re-admission finds stored and drops
//! uncounted. A record parked and later admitted live is dropped the same way.

use std::collections::BTreeSet;

use muniment::{Backend, StoreError, WriteOp};
use p2panda_core::cbor::{decode_cbor, encode_cbor};
use p2panda_core::operation::validate_operation;
use p2panda_core::{Extensions, Operation};
use stickleback::{
    CausalEntry, CausalError, DropRecord, MunimentStore, causal_projection,
    decode_operation_record, lane_id, operation_record,
};

/// Bounds on one lane's parked records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParkingLimits {
    pub max_records: usize,
    /// Encoded records, signed header and ciphertext together.
    pub max_bytes: u64,
}

impl Default for ParkingLimits {
    fn default() -> Self {
        Self {
            max_records: 256,
            max_bytes: 16 * 1024 * 1024,
        }
    }
}

/// What one lane holds parked, and how many records it has evicted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ParkingStatus {
    pub parked: u64,
    pub parked_bytes: u64,
    pub evicted_total: u64,
}

/// One `readmit_parked` pass.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadmitReport {
    /// Newly stored by this pass.
    pub admitted: u64,
    /// Readable or undecodable now, refused by admission, and dropped.
    pub refused: u64,
    /// Still waiting on an epoch or a predecessor.
    pub still_parked: u64,
    pub evicted_total: u64,
}

/// What a lane reads from a parked record with one key snapshot.
pub(crate) struct ParkedHeader {
    pub parents: Vec<[u8; 32]>,
    pub epoch_held: bool,
}

/// What a lane's ordinary admission did with a readable parked record.
pub(crate) enum Readmitted {
    Inserted,
    Duplicate,
    Refused,
}

struct Slot {
    key: String,
    arrival: u64,
    author: String,
    log_id: u64,
    seq_num: u32,
    bytes: u64,
}

impl Slot {
    fn holds(&self, author: &str, log_id: u64, seq_num: u32) -> bool {
        self.author == author && self.log_id == log_id && self.seq_num == seq_num
    }
}

/// One lane's parking area in its replica's backend.
#[derive(Clone, Debug)]
pub(crate) struct Parking {
    prefix: String,
    pub limits: ParkingLimits,
}

impl Parking {
    pub fn new(lane: &str, space: [u8; 32]) -> Self {
        Self {
            prefix: format!("{}/parking/", lane_id(lane, space)),
            limits: ParkingLimits::default(),
        }
    }

    fn records(&self) -> String {
        format!("{}records/", self.prefix)
    }

    fn evicted_key(&self) -> String {
        format!("{}evicted", self.prefix)
    }

    fn parse(&self, key: String) -> Option<Slot> {
        let parts: Vec<&str> = key.strip_prefix(&self.records())?.split('/').collect();
        let [arrival, author, log_id, seq_num, bytes] = parts[..] else {
            return None;
        };
        let hex = |part: &str| u64::from_str_radix(part, 16).ok();
        let slot = Slot {
            arrival: hex(arrival)?,
            author: author.to_owned(),
            log_id: hex(log_id)?,
            seq_num: u32::from_str_radix(seq_num, 16).ok()?,
            bytes: hex(bytes)?,
            key: String::new(),
        };
        Some(Slot { key, ..slot })
    }

    /// Parked slots, oldest first.
    async fn slots<B: Backend>(&self, backend: &B) -> Result<Vec<Slot>, StoreError> {
        let mut slots: Vec<_> = backend
            .list(&self.records())
            .await?
            .into_iter()
            .filter_map(|key| self.parse(key))
            .collect();
        slots.sort_by(|left, right| left.key.cmp(&right.key));
        Ok(slots)
    }

    async fn load<B: Backend, E: Extensions>(
        &self,
        backend: &B,
        slot: &Slot,
    ) -> Result<Option<Operation<E>>, StoreError> {
        Ok(backend.get(&slot.key).await?.and_then(|bytes| {
            let record: DropRecord = decode_cbor(bytes.as_slice()).ok()?;
            decode_operation_record(&record).ok().flatten()
        }))
    }

    async fn evicted_total<B: Backend>(&self, backend: &B) -> Result<u64, StoreError> {
        let bytes = backend.get(&self.evicted_key()).await?;
        Ok(bytes
            .and_then(|bytes| bytes.try_into().ok())
            .map_or(0, u64::from_le_bytes))
    }

    pub async fn status<B: Backend>(&self, backend: &B) -> Result<ParkingStatus, StoreError> {
        let slots = self.slots(backend).await?;
        Ok(ParkingStatus {
            parked: slots.len() as u64,
            parked_bytes: slots.iter().map(|slot| slot.bytes).sum(),
            evicted_total: self.evicted_total(backend).await?,
        })
    }

    /// Whether a record past the lane's pre-decryption checks parks: it is
    /// valid, new, ahead of its author's stored log, and names an unheld
    /// epoch or backlinks the parked record just before it.
    pub async fn should_park<B: Backend, E: Extensions>(
        &self,
        store: &MunimentStore<B, E>,
        operation: &Operation<E>,
        log_id: u64,
        epoch_held: bool,
    ) -> Result<bool, StoreError> {
        if validate_operation(operation).is_err()
            || operation.hash != operation.header.hash()
            || store.has_operation(&operation.hash).await?
        {
            return Ok(false);
        }
        let author = &operation.header.verifying_key;
        let seq_num = operation.header.seq_num;
        let latest = store
            .get_latest_entry(author, &log_id)
            .await?
            .map(|entry| entry.header.seq_num);
        if latest.is_some_and(|latest| seq_num <= latest) {
            return Ok(false);
        }
        if !epoch_held {
            return Ok(true);
        }
        let (Some(previous), Some(backlink)) = (seq_num.checked_sub(1), operation.header.backlink)
        else {
            return Ok(false);
        };
        if latest == Some(previous) {
            return Ok(false);
        }
        let author = author.to_hex();
        let slots = self.slots(store.backend()).await?;
        let Some(slot) = slots
            .iter()
            .find(|slot| slot.holds(&author, log_id, previous))
        else {
            return Ok(false);
        };
        Ok(self
            .load::<B, E>(store.backend(), slot)
            .await?
            .is_some_and(|parked| parked.hash == backlink))
    }

    /// Park one record, evicting the oldest past the bounds. `true` also when
    /// this record is already parked; `false` when another record holds its
    /// slot or it alone exceeds the byte bound.
    pub async fn park<B: Backend, E: Extensions>(
        &self,
        backend: &B,
        operation: &Operation<E>,
        log_id: u64,
    ) -> Result<bool, StoreError> {
        let author = operation.header.verifying_key.to_hex();
        let seq_num = operation.header.seq_num;
        let slots = self.slots(backend).await?;
        if let Some(slot) = slots
            .iter()
            .find(|slot| slot.holds(&author, log_id, seq_num))
        {
            let parked = self.load::<B, E>(backend, slot).await?;
            return Ok(parked.is_some_and(|parked| parked.hash == operation.hash));
        }
        let value = encode_cbor(&operation_record(operation, true))
            .expect("an operation record always CBOR-encodes");
        let size = value.len() as u64;
        if self.limits.max_records == 0 || size > self.limits.max_bytes {
            return Ok(false);
        }
        let mut count = slots.len();
        let mut bytes: u64 = slots.iter().map(|slot| slot.bytes).sum();
        let mut writes = Vec::new();
        for slot in &slots {
            if count < self.limits.max_records && bytes + size <= self.limits.max_bytes {
                break;
            }
            writes.push(WriteOp::Delete {
                key: slot.key.clone(),
            });
            count -= 1;
            bytes -= slot.bytes;
        }
        if !writes.is_empty() {
            let evicted = self.evicted_total(backend).await? + writes.len() as u64;
            writes.push(WriteOp::Put {
                key: self.evicted_key(),
                value: evicted.to_le_bytes().to_vec(),
            });
        }
        let arrival = slots.last().map_or(0, |slot| slot.arrival + 1);
        writes.push(WriteOp::Put {
            key: format!(
                "{}{arrival:016x}/{author}/{log_id:x}/{seq_num:08x}/{size:x}",
                self.records()
            ),
            value,
        });
        backend.apply(&writes).await?;
        Ok(true)
    }

    /// Re-admit parked records in causal order. `header` reads a record with
    /// the caller's key snapshot, `None` when a pre-decryption check now
    /// fails; `admit` runs the lane's ordinary admission with that snapshot.
    /// A record stays parked while its epoch is unheld or its predecessor is
    /// not stored, and is unparked once admitted, found stored, or refused.
    pub async fn readmit<B, E, Error>(
        &self,
        store: &MunimentStore<B, E>,
        header: impl Fn(&Operation<E>) -> Option<ParkedHeader>,
        mut admit: impl AsyncFnMut(&Operation<E>) -> Result<Readmitted, Error>,
    ) -> Result<ReadmitReport, Error>
    where
        B: Backend,
        E: Extensions,
        Error: From<StoreError> + From<CausalError>,
    {
        let backend = store.backend();
        let mut report = ReadmitReport::default();
        let mut seen = BTreeSet::new();
        let mut parked = Vec::new();
        for slot in self.slots(backend).await? {
            let fresh = seen.insert((slot.author.clone(), slot.log_id, slot.seq_num));
            let operation = self.load::<B, E>(backend, &slot).await?;
            match operation.and_then(|operation| Some((header(&operation)?, operation))) {
                Some((header, operation)) if fresh => parked.push((slot, header, operation)),
                // A second record in one slot is a lost race; keep the first.
                Some(_) => backend.delete(&slot.key).await?,
                None => {
                    report.refused += 1;
                    backend.delete(&slot.key).await?;
                },
            }
        }

        // Dependencies outside the parked set are stored or absent, so the
        // projection over the set alone orders every record.
        let ids: BTreeSet<[u8; 32]> = parked
            .iter()
            .map(|(_, _, operation)| *operation.hash.as_bytes())
            .collect();
        let entries: Vec<_> = parked
            .iter()
            .map(|(slot, header, operation)| {
                let parents = header
                    .parents
                    .iter()
                    .copied()
                    .filter(|parent| ids.contains(parent))
                    .collect();
                let mut entry = CausalEntry::from_operation(operation, slot.log_id, parents);
                entry.backlink = entry.backlink.filter(|link| ids.contains(link));
                entry
            })
            .collect();

        for index in causal_projection(&entries)?.order {
            let (slot, header, operation) = &parked[index];
            if !store.has_operation(&operation.hash).await? {
                let seq_num = operation.header.seq_num;
                let latest = store
                    .get_latest_entry(&operation.header.verifying_key, &slot.log_id)
                    .await?
                    .map(|entry| entry.header.seq_num);
                let predecessor_missing =
                    seq_num > 0 && latest.is_none_or(|latest| latest.saturating_add(1) < seq_num);
                if !header.epoch_held || predecessor_missing {
                    report.still_parked += 1;
                    continue;
                }
                match admit(operation).await? {
                    Readmitted::Inserted => report.admitted += 1,
                    Readmitted::Duplicate => {},
                    Readmitted::Refused => report.refused += 1,
                }
            }
            backend.delete(&slot.key).await?;
        }
        report.evicted_total = self.evicted_total(backend).await?;
        Ok(report)
    }
}
