// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Export a canonical saved Micron snapshot as a static directory handoff.
//! Existing NomadNet/MeshChatX installations can consume `OUTPUT/pages/`.
use gemot_site_host::{PublishedSnapshotV1, Site, export::export_micron_snapshot};
use std::{
    fs::{self, File},
    io::Read,
    path::Path,
};

fn main() -> Result<(), String> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 2 {
        return Err("Usage: export_nomadnet SAVED_SITE_DIR|SNAPSHOT.json NEW_OUTPUT_DIR".into());
    }
    let input = Path::new(&args[0]);
    let metadata = fs::metadata(input).map_err(|error| error.to_string())?;
    let snapshot = if metadata.is_dir() {
        Site::open(input)?.publication()?.to_snapshot_v1()?
    } else {
        let mut bytes = Vec::new();
        File::open(input)
            .map_err(|error| error.to_string())?
            .take((gemot_site_host::MAX_ENCODED_SNAPSHOT_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        if bytes.len() > gemot_site_host::MAX_ENCODED_SNAPSHOT_BYTES {
            return Err("Saved snapshot exceeds 24 MiB".into());
        }
        PublishedSnapshotV1::decode(&bytes)?
    };
    let receipt = export_micron_snapshot(&snapshot, Path::new(&args[1]))?;
    let digest = receipt
        .snapshot_digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    println!(
        "Exported {} saved Micron pages to {} (snapshot BLAKE3 {})",
        receipt.page_count,
        receipt.output_dir.display(),
        digest
    );
    println!("Give the existing node the read-only pages/ directory.");
    Ok(())
}
