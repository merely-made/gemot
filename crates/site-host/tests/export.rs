// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use gemot_site_host::{Site, SiteFormat, export::export_micron_snapshot};
use std::fs;

fn saved_micron_snapshot(root: &std::path::Path) -> gemot_site_host::PublishedSnapshotV1 {
    let site_path = root.join("site");
    let site = Site::create_for(&site_path, SiteFormat::Micron).unwrap();
    let saved_bytes = b">Saved version\n\n`[Saved link`:/page/about.mu]\n";
    fs::write(site_path.join("index.mu"), saved_bytes).unwrap();
    site.publication().unwrap().to_snapshot_v1().unwrap()
}

#[test]
fn exports_canonical_snapshot_and_exact_saved_page_bytes_to_static_layout() {
    let temp = tempfile::tempdir().unwrap();
    let snapshot = saved_micron_snapshot(temp.path());
    let expected_digest = snapshot.digest().unwrap();
    let output = temp.path().join("handoff");

    let receipt = export_micron_snapshot(&snapshot, &output).unwrap();

    assert_eq!(receipt.page_count, snapshot.pages.len());
    assert_eq!(receipt.snapshot_digest, expected_digest);
    // Windows canonicalization may add the extended-length path prefix.
    assert_eq!(
        fs::canonicalize(&receipt.output_dir).unwrap(),
        fs::canonicalize(&output).unwrap()
    );
    assert_eq!(
        fs::read(output.join("snapshot.json")).unwrap(),
        snapshot.encode().unwrap()
    );
    for page in snapshot.pages.values() {
        assert_eq!(
            fs::read(output.join("pages").join(&page.metadata.path)).unwrap(),
            page.source
        );
    }
    assert_eq!(
        fs::read(output.join("pages/index.mu")).unwrap(),
        b">Saved version\n\n`[Saved link`:/page/about.mu]\n"
    );
}

#[test]
fn export_refuses_to_overwrite_existing_output_and_rejects_parent_escape() {
    let temp = tempfile::tempdir().unwrap();
    let snapshot = saved_micron_snapshot(temp.path());
    let existing = temp.path().join("existing");
    fs::create_dir(&existing).unwrap();
    fs::write(existing.join("keep"), b"original").unwrap();

    assert!(export_micron_snapshot(&snapshot, &existing).is_err());
    assert_eq!(fs::read(existing.join("keep")).unwrap(), b"original");
    assert!(export_micron_snapshot(&snapshot, &temp.path().join("../escape")).is_err());
    assert!(!temp.path().parent().unwrap().join("escape").exists());
}

#[cfg(unix)]
#[test]
fn export_refuses_symlink_destination() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let snapshot = saved_micron_snapshot(temp.path());
    let actual = temp.path().join("actual");
    fs::create_dir(&actual).unwrap();
    let alias = temp.path().join("alias");
    symlink(&actual, &alias).unwrap();

    assert!(export_micron_snapshot(&snapshot, &alias).is_err());
    assert!(fs::read_dir(actual).unwrap().next().is_none());
}

#[test]
fn export_only_accepts_micron_snapshots() {
    let temp = tempfile::tempdir().unwrap();
    let site = Site::create_for(&temp.path().join("site"), SiteFormat::Gemini).unwrap();
    let snapshot = site.publication().unwrap().to_snapshot_v1().unwrap();
    let output = temp.path().join("handoff");

    assert!(export_micron_snapshot(&snapshot, &output).is_err());
    assert!(!output.exists());
}

#[test]
fn export_uses_snapshot_bytes_after_the_live_site_changes() {
    let temp = tempfile::tempdir().unwrap();
    let site_path = temp.path().join("site");
    let site = Site::create_for(&site_path, SiteFormat::Micron).unwrap();
    let saved_bytes = b">Saved version\n";
    fs::write(site_path.join("index.mu"), saved_bytes).unwrap();
    let snapshot = site.publication().unwrap().to_snapshot_v1().unwrap();
    fs::write(site_path.join("index.mu"), b">Later live change\n").unwrap();

    let output = temp.path().join("handoff");
    export_micron_snapshot(&snapshot, &output).unwrap();
    assert_eq!(
        fs::read(output.join("pages/index.mu")).unwrap(),
        saved_bytes
    );
}

#[test]
fn export_rejects_invalid_snapshot_paths_before_creating_output() {
    let temp = tempfile::tempdir().unwrap();
    let mut snapshot = saved_micron_snapshot(temp.path());
    let mut page = snapshot.pages.remove("/index.mu").unwrap();
    page.metadata.path = "../outside.mu".into();
    snapshot.pages.insert("/../outside.mu".into(), page);
    let output = temp.path().join("handoff");

    assert!(export_micron_snapshot(&snapshot, &output).is_err());
    assert!(!output.exists());
    assert!(!temp.path().join("outside.mu").exists());
}

#[cfg(unix)]
#[test]
fn exported_files_have_no_execute_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let snapshot = saved_micron_snapshot(temp.path());
    let output = temp.path().join("handoff");
    export_micron_snapshot(&snapshot, &output).unwrap();

    for path in [output.join("snapshot.json"), output.join("pages/index.mu")] {
        let mode = fs::metadata(path).unwrap().permissions().mode();
        assert_eq!(mode & 0o111, 0);
    }
}
