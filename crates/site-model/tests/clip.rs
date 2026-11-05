// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0
//! A clip becomes an edition, opens by address, and republishes as a fork.

use gemot_site::address::KnotAddress;
use gemot_site::clip::{
    ClipError, ClipPayloadV1, clip_address, clip_body, fork_body, open_clip, republish,
};
use stickleback::edition::{
    EditionError, EditionKind, EditionLimits, EditionWriter, SigningKey, verify_edition_chain,
};

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn public(key: &SigningKey) -> [u8; 32] {
    *key.verifying_key().as_bytes()
}

fn payload() -> ClipPayloadV1 {
    ClipPayloadV1::new(
        "https://example.test/essay",
        Some("An essay"),
        Some("p:nth-of-type(2)"),
        "A clipped passage.\n",
    )
}

fn author() -> (SigningKey, Vec<gemot_site_ops::Op>, Vec<u8>) {
    let signing = key(1);
    let mut writer = EditionWriter::new(signing.clone());
    let clip = payload();
    let op = writer
        .append(&clip_body(&clip, "turnstone", 7).unwrap())
        .unwrap();
    (signing, vec![op], clip.encode().unwrap())
}

mod gemot_site_ops {
    pub type Op = stickleback::edition::EditionOperation;
}

#[test]
fn clip_becomes_an_edition_with_provenance() {
    let (signing, ops, bytes) = author();
    let chain = verify_edition_chain(&public(&signing), &ops, EditionLimits::default()).unwrap();
    let edition = chain.head();
    assert_eq!(edition.body.kind, EditionKind::Clip);
    assert_eq!(edition.body.provenance.source, "turnstone");
    assert_eq!(edition.body.provenance.created_ms, 7);
    assert!(edition.body.fork_of.is_none());
    let address = clip_address(public(&signing), edition.id);
    let frame = open_clip(&address, &ops, &bytes).unwrap();
    assert_eq!(frame.payload.source_url, "https://example.test/essay");
    assert_eq!(frame.edition.id, edition.id);
    // Copy link output re-parses to the same address.
    assert_eq!(address.to_string().parse::<KnotAddress>().unwrap(), address);
}

#[test]
fn unpinned_address_opens_the_newest_edition() {
    let (signing, ops, bytes) = author();
    let address = format!("knot://{}/clip", hex(&public(&signing)))
        .parse()
        .unwrap();
    assert!(open_clip(&address, &ops, &bytes).is_ok());
}

#[test]
fn open_refuses_wrong_payload_foreign_log_and_governed_addresses() {
    let (signing, ops, bytes) = author();
    let id = verify_edition_chain(&public(&signing), &ops, EditionLimits::default())
        .unwrap()
        .head()
        .id;
    let address = clip_address(public(&signing), id);
    let mut other = payload();
    other.knot_body = "swapped\n".into();
    assert_eq!(
        open_clip(&address, &ops, &other.encode().unwrap()).unwrap_err(),
        ClipError::PayloadMismatch
    );
    let foreign = clip_address(public(&key(9)), id);
    assert!(matches!(
        open_clip(&foreign, &ops, &bytes),
        Err(ClipError::Edition(EditionError::WrongAuthor))
    ));
    let missing = clip_address(public(&signing), stickleback::edition::EditionId([3; 32]));
    assert_eq!(
        open_clip(&missing, &ops, &bytes).unwrap_err(),
        ClipError::PinNotInEvidence
    );
    let moot: KnotAddress = format!("knot://{}.moot/clip", hex(&public(&signing)))
        .parse()
        .unwrap();
    assert_eq!(
        open_clip(&moot, &ops, &bytes).unwrap_err(),
        ClipError::Governed
    );
}

#[test]
fn republished_edition_verifies_with_fork_of_pointing_at_the_source() {
    let (signing, ops, bytes) = author();
    let source_chain =
        verify_edition_chain(&public(&signing), &ops, EditionLimits::default()).unwrap();
    let source_id = source_chain.head().id;
    let frame = open_clip(&clip_address(public(&signing), source_id), &ops, &bytes).unwrap();

    let reader = key(2);
    let mut writer = EditionWriter::new(reader.clone());
    let mut edited = frame.payload.clone();
    edited.knot_body.push_str("My note.\n");
    let (fork_op, fork_bytes) = republish(&frame, &mut writer, Some(&edited), "knot", 9).unwrap();

    let fork_chain = verify_edition_chain(
        &public(&reader),
        &[fork_op.clone()],
        EditionLimits::default(),
    )
    .unwrap();
    assert_eq!(fork_chain.fork_source(), Some(source_id));
    assert_eq!(
        fork_chain.resolve_fork(&source_chain).unwrap().id,
        source_id
    );
    let fork = fork_chain.head();
    assert_eq!(fork.body.kind, EditionKind::Clip);
    assert_eq!(fork.body.provenance.source, "knot");
    assert_eq!(
        fork.body.hints,
        vec![format!(
            "knot://{}/clip@{}",
            hex(&public(&signing)),
            source_id.to_hex()
        )]
    );
    // The fork's payload keeps the original source and carries the edit.
    let reopened = open_clip(
        &clip_address(public(&reader), fork.id),
        &[fork_op],
        &fork_bytes,
    )
    .unwrap();
    assert_eq!(reopened.payload.source_url, frame.payload.source_url);
    assert!(reopened.payload.knot_body.ends_with("My note.\n"));
    assert_ne!(reopened.key, frame.key);
}

#[test]
fn unedited_republish_keeps_the_content_digest_and_a_fork_is_only_a_first_edition() {
    let (signing, ops, bytes) = author();
    let id = verify_edition_chain(&public(&signing), &ops, EditionLimits::default())
        .unwrap()
        .head()
        .id;
    let frame = open_clip(&clip_address(public(&signing), id), &ops, &bytes).unwrap();
    let mut writer = EditionWriter::new(key(3));
    let (_, same) = republish(&frame, &mut writer, None, "knot", 1).unwrap();
    assert_eq!(same, bytes);
    // A second fork edition in the same log is refused by the record rules.
    let second = fork_body(&frame, &frame.payload, "knot", 2).unwrap();
    assert!(writer.append(&second).is_err());
    // The author cannot fork inside their own log either.
    let mut own = EditionWriter::resume(
        signing.clone(),
        &verify_edition_chain(&public(&signing), &ops, EditionLimits::default()).unwrap(),
    )
    .unwrap();
    assert!(republish(&frame, &mut own, None, "knot", 3).is_err());
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
