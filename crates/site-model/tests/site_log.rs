// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0
//! Site-log authority in default features: no Gemot, no carrier, a log key.

use gemot_site::PublishedSnapshotV1;
use gemot_site::remembered::{EvidenceScope, RememberedError};
use gemot_site::site_log::{
    SiteLogError, SiteLogHistory, SiteLogLimits, SiteLogTrust, verify_site_log,
};
use muniment::MemoryBackend;
use stickleback::edition::{
    ContentRef, EditionBody, EditionError, EditionId, EditionKind, EditionWriter, Provenance,
    SigningKey, encode_evidence,
};

struct Site {
    key: SigningKey,
    trust: SiteLogTrust,
    snapshots: Vec<Vec<u8>>,
    writer: EditionWriter,
}

fn snapshots() -> Vec<Vec<u8>> {
    let first = PublishedSnapshotV1::decode(include_bytes!("fixtures/scroll-v1.json")).unwrap();
    let mut out = vec![first.encode().unwrap()];
    for edit in ["one", "two", "three"] {
        let mut next = first.clone();
        next.pages
            .get_mut("/index.scroll")
            .unwrap()
            .source
            .extend_from_slice(format!("\r\n{edit}\r\n").as_bytes());
        out.push(next.encode().unwrap());
    }
    out
}

fn body(snapshot: &[u8], fork_of: Option<EditionId>) -> EditionBody {
    let digest = PublishedSnapshotV1::decode(snapshot)
        .unwrap()
        .digest()
        .unwrap();
    EditionBody {
        kind: EditionKind::Site,
        content: ContentRef::Snapshot {
            digest: EditionId(digest),
        },
        provenance: Provenance {
            source: "test".into(),
            created_ms: 1,
        },
        fork_of,
        hints: vec![],
        sealed: None,
    }
}

impl Site {
    fn new() -> Self {
        let key = SigningKey::generate();
        Self {
            trust: SiteLogTrust {
                log_key: *key.verifying_key().as_bytes(),
            },
            writer: EditionWriter::new(key.clone()),
            key,
            snapshots: snapshots(),
        }
    }

    /// Evidence for editions 0..=last, published from this site's writer state.
    fn publish(&mut self, count: usize) -> Vec<stickleback::edition::EditionOperation> {
        (0..count)
            .map(|i| self.writer.append(&body(&self.snapshots[i], None)).unwrap())
            .collect()
    }
}

const NOW: u64 = 1_000;

fn history(trust: SiteLogTrust) -> SiteLogHistory<MemoryBackend> {
    SiteLogHistory::new(MemoryBackend::new(), trust, SiteLogLimits::default())
}

#[test]
fn cold_reader_with_only_a_log_key_verifies_the_chain_and_opens_the_snapshot() {
    let mut site = Site::new();
    let evidence = encode_evidence(&site.publish(3));
    let verified = verify_site_log(
        &site.trust,
        &evidence,
        &site.snapshots[2],
        NOW,
        SiteLogLimits::default(),
    )
    .unwrap();
    assert_eq!(verified.edition.seq_num, 2);
    assert_eq!(verified.chain_len, 3);
    assert_eq!(verified.snapshot.encode().unwrap(), site.snapshots[2]);
    assert_eq!(verified.scope, EvidenceScope::SuppliedHistoryOnly);
}

#[test]
fn tampered_bytes_and_forged_operations_refuse() {
    let mut site = Site::new();
    let ops = site.publish(2);
    let evidence = encode_evidence(&ops);
    let limits = SiteLogLimits::default();
    // Wrong snapshot bytes for the named digest.
    assert_eq!(
        verify_site_log(&site.trust, &evidence, &site.snapshots[3], NOW, limits).unwrap_err(),
        SiteLogError::SnapshotMismatch
    );
    let mut tampered = site.snapshots[1].clone();
    tampered.push(b' ');
    assert!(matches!(
        verify_site_log(&site.trust, &evidence, &tampered, NOW, limits),
        Err(SiteLogError::Snapshot(_))
    ));
    // A flipped evidence byte inside a body breaks the payload hash or framing.
    let mut flipped = evidence.clone();
    let last = flipped.len() - 2;
    flipped[last] ^= 1;
    assert!(verify_site_log(&site.trust, &flipped, &site.snapshots[1], NOW, limits).is_err());
    // Another key's operations are not this log's.
    let mut other = Site::new();
    let forged = encode_evidence(&other.publish(2));
    assert_eq!(
        verify_site_log(&site.trust, &forged, &site.snapshots[1], NOW, limits).unwrap_err(),
        SiteLogError::Edition(EditionError::WrongAuthor)
    );
    // A key that is not the log's refuses honest evidence.
    let stranger = SiteLogTrust { log_key: [3; 32] };
    assert!(verify_site_log(&stranger, &evidence, &site.snapshots[1], NOW, limits).is_err());
}

#[test]
fn older_valid_chain_opens_with_limited_freshness_scope() {
    let mut site = Site::new();
    let full = site.publish(3);
    let older = encode_evidence(&full[..2]);
    let verified = verify_site_log(
        &site.trust,
        &older,
        &site.snapshots[1],
        NOW,
        SiteLogLimits::default(),
    )
    .unwrap();
    assert_eq!(verified.edition.seq_num, 1);
    assert_eq!(verified.scope, EvidenceScope::SuppliedHistoryOnly);
}

#[test]
fn remembered_head_refuses_known_rollback_but_keeps_authority() {
    pollster::block_on(async {
        let mut site = Site::new();
        let full = site.publish(3);
        let newer = encode_evidence(&full);
        let older = encode_evidence(&full[..2]);
        let reader = history(site.trust);
        let opened = reader
            .verify(&newer, &site.snapshots[2], NOW)
            .await
            .unwrap();
        assert_eq!(opened.scope, EvidenceScope::SuppliedAndRememberedHistory);
        // A provider now offers the older chain and its older snapshot.
        assert!(matches!(
            reader.verify(&older, &site.snapshots[1], NOW + 1).await,
            Err(RememberedError::Authority(SiteLogError::Rollback {
                head_seq: 2,
                snapshot_seq: 1
            }))
        ));
        // The remembered head survived and still opens.
        let again = reader
            .verify(&older, &site.snapshots[2], NOW + 2)
            .await
            .unwrap();
        assert_eq!(again.edition.seq_num, 2);
    });
}

#[test]
fn equivocation_refuses_even_when_each_branch_is_valid() {
    pollster::block_on(async {
        let mut site = Site::new();
        let honest = site.publish(2);
        let mut branch = EditionWriter::resume(
            site.key.clone(),
            &stickleback::edition::verify_edition_chain(
                &site.trust.log_key,
                &honest[..1],
                Default::default(),
            )
            .unwrap(),
        )
        .unwrap();
        let rival = branch.append(&body(&site.snapshots[3], None)).unwrap();
        let reader = history(site.trust);
        let evidence = encode_evidence(&honest);
        reader
            .verify(&evidence, &site.snapshots[1], NOW)
            .await
            .unwrap();
        let rival_evidence = encode_evidence(&[honest[0].clone(), rival]);
        assert!(matches!(
            reader.observe(&rival_evidence, NOW + 1).await,
            Err(RememberedError::Authority(SiteLogError::Edition(
                EditionError::Equivocation { seq_num: 1 }
            )))
        ));
        // Without memory, a single branch alone cannot be told from the truth;
        // the remembered head is what refuses it.
        let fresh = history(site.trust);
        assert!(fresh.observe(&rival_evidence, NOW).await.is_ok());
    });
}

#[test]
fn clock_rollback_and_corrupt_state_refuse() {
    pollster::block_on(async {
        let mut site = Site::new();
        let evidence = encode_evidence(&site.publish(1));
        let backend = MemoryBackend::new();
        let reader = SiteLogHistory::new(backend.clone(), site.trust, SiteLogLimits::default());
        reader.observe(&evidence, NOW).await.unwrap();
        assert!(matches!(
            reader.observe(&evidence, NOW - 1).await,
            Err(RememberedError::ClockRollback)
        ));
        let tiny = SiteLogLimits {
            max_evidence_bytes: 8,
            ..SiteLogLimits::default()
        };
        let small = SiteLogHistory::new(MemoryBackend::new(), site.trust, tiny);
        assert!(matches!(
            small.observe(&evidence, NOW).await,
            Err(RememberedError::Capacity)
        ));
    });
}

#[test]
fn a_fork_first_edition_resolves_its_source() {
    let mut site = Site::new();
    let source_ops = site.publish(2);
    let source = stickleback::edition::verify_edition_chain(
        &site.trust.log_key,
        &source_ops,
        Default::default(),
    )
    .unwrap();
    let fork_key = SigningKey::generate();
    let mut writer = EditionWriter::new(fork_key.clone());
    let first = writer
        .append(&body(&site.snapshots[1], Some(source.head().id)))
        .unwrap();
    let fork_trust = SiteLogTrust {
        log_key: *fork_key.verifying_key().as_bytes(),
    };
    let evidence = encode_evidence(std::slice::from_ref(&first));
    let verified = verify_site_log(
        &fork_trust,
        &evidence,
        &site.snapshots[1],
        NOW,
        SiteLogLimits::default(),
    )
    .unwrap();
    let fork = stickleback::edition::verify_edition_chain(
        &fork_trust.log_key,
        &[first],
        Default::default(),
    )
    .unwrap();
    assert_eq!(fork.resolve_fork(&source).unwrap(), source.head());
    assert_eq!(verified.edition.body.fork_of, Some(source.head().id));
}
