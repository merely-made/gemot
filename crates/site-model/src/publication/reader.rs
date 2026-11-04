// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Portable verification against an independently configured Gemot trust root.
//! Evidence is a public Gemot native drop plus canonical snapshot V1 bytes.
//! No provider identity, signing key, reader membership or network is required.
//! Success is relative to supplied history, never a claim of global freshness.

use gemot::moot::{CollectionRef, Moot, MootId, MootRetentionSettings};
use muniment::MemoryBackend;
use serde::{Deserialize, Serialize};
use stickleback::DropLimits;

use super::{
    OpenedSite, PublicationError, SiteBindingV1, SiteRevisionPolicy, open, refuse,
    selected_manifest, snapshot_schema,
};
use crate::{MAX_ENCODED_SNAPSHOT_BYTES, PublishedSnapshotV1};

pub mod history;

/// Obtain this anchor independently of the serving provider. The founder is
/// Gemot's constitutional root; a collection names the particular site to read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReaderTrust {
    pub founder: [u8; 32],
    pub collection: CollectionRef,
}

/// Caller-owned limits. Transports must also bound acquisition before buffering.
#[derive(Clone, Copy, Debug)]
pub struct ReaderLimits {
    pub max_history_bytes: usize,
    pub drop: DropLimits,
}

impl Default for ReaderLimits {
    fn default() -> Self {
        Self {
            max_history_bytes: 8 * 1024 * 1024,
            drop: DropLimits {
                max_records: 4096,
                max_record_bytes: 1024 * 1024,
                max_manifest_bytes: 1024 * 1024,
                ..DropLimits::default()
            },
        }
    }
}

/// History considered by verification. Neither scope proves global freshness.
/// The stateless verifier sees supplied history only; [`history::ReaderHistory`]
/// also preserves previously observed authority across reads and restarts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceScope {
    SuppliedHistoryOnly,
    /// Valid against supplied evidence merged with durably remembered authority.
    /// Unseen newer evidence elsewhere can still exist.
    SuppliedAndRememberedHistory,
}

#[derive(Clone, Debug)]
pub struct VerifiedPublication {
    pub site: OpenedSite,
    pub evaluated_at_ms: u64,
    pub scope: EvidenceScope,
}

/// Verify evidence from an untrusted provider using Gemot admission and the
/// existing authorized collection/contribution fold. Resolve selection locally;
/// the provider cannot choose a different collection or bypass ambiguity.
///
/// Each call imports into fresh disposable stores. Failure cannot contaminate
/// another read; success does not persist authority, grant membership, or prove
/// durable custody. `at_ms` and retention/limits are caller policy, not evidence.
pub async fn verify_reader_evidence(
    trust: &ReaderTrust,
    history: &[u8],
    snapshot_bytes: &[u8],
    retention: MootRetentionSettings,
    at_ms: u64,
    limits: ReaderLimits,
) -> Result<VerifiedPublication, PublicationError> {
    if history.len() > limits.max_history_bytes {
        return Err(refuse("Reader authority evidence exceeds the byte limit"));
    }
    if snapshot_bytes.len() > MAX_ENCODED_SNAPSHOT_BYTES {
        return Err(refuse("Reader snapshot exceeds the byte limit"));
    }
    // The existing decoder validates native records and exact canonical bytes.
    let snapshot =
        PublishedSnapshotV1::decode(snapshot_bytes).map_err(PublicationError::Refused)?;
    let moot = Moot::in_memory(MootId(trust.collection.moot_id), trust.founder, retention);
    moot.import_plain_drop(history, limits.drop).await?;
    let mut content = MemoryBackend::new();
    let binding = SiteBindingV1 {
        version: 1,
        collection: trust.collection,
        revision: SiteRevisionPolicy::FollowCollection,
    };
    // Resolve authority before retaining provider content, using the same
    // selection helper as the normal publication adapter.
    let selection = super::binding_selection(&moot, &binding, at_ms).await?;
    let expected = selected_manifest(&moot, &selection, at_ms).await?;
    if expected != eidetic::ManifestId::of_blob(snapshot_bytes) {
        return Err(refuse(
            "Reader snapshot does not match the selected contribution",
        ));
    }
    eidetic::schema_def::bootstrap_meta_schema(&mut content).await?;
    eidetic::schema_def::save_schema(
        &mut content,
        &snapshot_schema(),
        eidetic::PrivacyClass::PublicPortable,
        eidetic::ProvenanceRecord::self_imported("reader verification schema"),
        eidetic::TrustEnvelope::self_asserted(),
        eidetic::Timestamp(at_ms),
    )
    .await?;
    eidetic::typed::save_typed(
        &mut content,
        &snapshot,
        vec![],
        eidetic::PrivacyClass::PublicPortable,
        eidetic::ProvenanceRecord::self_imported("reader verified publication bytes"),
        eidetic::TrustEnvelope::self_asserted(),
        eidetic::Timestamp(at_ms),
    )
    .await?;
    let site = open(&moot, &mut content, &selection, at_ms).await?;
    Ok(VerifiedPublication {
        site,
        evaluated_at_ms: at_ms,
        scope: EvidenceScope::SuppliedHistoryOnly,
    })
}
