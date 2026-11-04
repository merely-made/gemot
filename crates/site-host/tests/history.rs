// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0
#![cfg(feature = "history")]

use gemot_site_host::{
    Site, SiteFormat,
    history::{Checkpoint, HistoryLimits, SiteHistory},
};
use muniment::DirectoryBackend;

#[tokio::test]
async fn saved_files_and_hand_edits_checkpoint_without_serving_or_touching_drafts() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("working-site");
    let history_root = temp.path().join("history");
    let mut site = Site::create_for(&root, SiteFormat::Gemini).unwrap();
    let original = site.publication().unwrap().to_snapshot_v1().unwrap();
    let id = site.history_id();
    let manifest_before = std::fs::read(root.join("site.json")).unwrap();
    {
        let history = SiteHistory::new(
            DirectoryBackend::open(&history_root).unwrap(),
            HistoryLimits::default(),
        );
        site.config.pages[0].author = "unsaved metadata draft".into();
        let first = site
            .checkpoint(
                &history,
                Checkpoint {
                    recorded_at_unix_ms: 1,
                    label: "first".into(),
                },
            )
            .await
            .unwrap();
        assert_eq!(first.snapshot_digest, original.digest().unwrap());
        std::fs::write(root.join("index.gmi"), "# Hand edit\r\nZoë\r\n").unwrap();
        let mut manual_config: gemot_site_host::SiteConfig =
            serde_json::from_slice(&manifest_before).unwrap();
        manual_config.pages[0].author = "Saved by hand".into();
        std::fs::write(
            root.join("site.json"),
            serde_json::to_vec_pretty(&manual_config).unwrap(),
        )
        .unwrap();
        site.checkpoint(
            &history,
            Checkpoint {
                recorded_at_unix_ms: 2,
                label: "hand edit".into(),
            },
        )
        .await
        .unwrap();
    }
    let history = SiteHistory::new(
        DirectoryBackend::open(&history_root).unwrap(),
        HistoryLimits::default(),
    );
    let reopened_site = Site::open(&root).unwrap();
    assert_eq!(reopened_site.history_id(), id);
    assert_eq!(history.list(id).await.unwrap().len(), 2);
    assert_eq!(history.load(id, 0).await.unwrap().unwrap(), original);
    let edited = history.load(id, 1).await.unwrap().unwrap();
    assert_eq!(
        edited.pages["/index.gmi"].source,
        "# Hand edit\r\nZoë\r\n".as_bytes()
    );
    assert_eq!(edited.pages["/index.gmi"].metadata.author, "Saved by hand");
    assert_eq!(site.config.pages[0].author, "unsaved metadata draft");
    let saved = std::fs::read(root.join("index.gmi")).unwrap();
    assert_eq!(saved, edited.pages["/index.gmi"].source);
    // Loading an old revision does not restore over working files.
    history.load(id, 0).await.unwrap();
    assert_eq!(std::fs::read(root.join("index.gmi")).unwrap(), saved);
    std::fs::remove_file(root.join("index.gmi")).unwrap();
    assert!(
        site.checkpoint(
            &history,
            Checkpoint {
                recorded_at_unix_ms: 3,
                label: "missing file".into()
            }
        )
        .await
        .is_err()
    );
    assert_eq!(history.list(id).await.unwrap().len(), 2);
}
