// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use gemot_site::{PublishedSnapshotV1, SiteConfig, SiteFormat};

// These bytes and BLAKE3 digests passed through the original knot-site
// implementation before extraction on 2026-10-20. They include native metadata,
// Unicode and CRLF source; they are not regenerated from the extracted model.
const FIXTURES: &[(&[u8], &str)] = &[
    (
        include_bytes!("fixtures/scroll-v1.json"),
        include_str!("fixtures/scroll-v1.blake3"),
    ),
    (
        include_bytes!("fixtures/gemini-v1.json"),
        include_str!("fixtures/gemini-v1.blake3"),
    ),
    (
        include_bytes!("fixtures/spartan-v1.json"),
        include_str!("fixtures/spartan-v1.blake3"),
    ),
    (
        include_bytes!("fixtures/micron-v1.json"),
        include_str!("fixtures/micron-v1.blake3"),
    ),
];

#[test]
fn original_v1_bytes_and_digests_are_unchanged_for_every_profile() {
    for &(bytes, digest) in FIXTURES {
        let snapshot = PublishedSnapshotV1::decode(bytes).unwrap();
        assert_eq!(snapshot.encode().unwrap(), bytes);
        let actual = snapshot
            .digest()
            .unwrap()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(actual, digest.trim());
        assert_eq!(
            snapshot.pages.values().next().unwrap().metadata.author,
            "Zoë / 李"
        );
        assert!(
            snapshot
                .pages
                .values()
                .next()
                .unwrap()
                .source
                .ends_with(b"\r\n")
        );
    }
}

#[test]
fn old_manifest_without_profile_still_defaults_to_scroll() {
    let snapshot = PublishedSnapshotV1::decode(FIXTURES[0].0).unwrap();
    let mut value = serde_json::to_value(SiteConfig {
        version: 1,
        format: SiteFormat::Scroll,
        pages: snapshot
            .pages
            .into_values()
            .map(|page| page.metadata)
            .collect(),
    })
    .unwrap();
    value.as_object_mut().unwrap().remove("format");
    let config: SiteConfig = serde_json::from_value(value).unwrap();
    assert_eq!(config.format, SiteFormat::Scroll);
    config.validate().unwrap();
}

#[test]
fn custody_rejects_noncanonical_bytes_and_invalid_native_records() {
    let mut bytes = FIXTURES[1].0.to_vec();
    bytes.push(b'\n');
    assert!(PublishedSnapshotV1::decode(&bytes).is_err());

    let original = PublishedSnapshotV1::decode(FIXTURES[1].0).unwrap();
    let mut snapshot = original.clone();
    snapshot.pages.get_mut("/index.gmi").unwrap().metadata.path = "../index.gmi".into();
    assert!(snapshot.encode().is_err());
    let mut snapshot = original.clone();
    snapshot.pages.get_mut("/index.gmi").unwrap().source = vec![0xff];
    assert!(snapshot.encode().is_err());
    let mut snapshot = original;
    snapshot
        .pages
        .get_mut("/index.gmi")
        .unwrap()
        .metadata
        .modified = "2026-10-20".into();
    assert!(snapshot.encode().is_err());
}
