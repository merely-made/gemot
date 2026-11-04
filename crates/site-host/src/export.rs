// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Backend-independent export of an explicitly saved Micron snapshot.
//!
//! The resulting directory is a static handoff: canonical snapshot custody at
//! the root and the exact saved page bytes under `pages/`. It does not expose a
//! live site directory or grant executable permissions to exported files.

use crate::{PublishedSnapshotV1, SiteFormat};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Component, Path, PathBuf},
};

/// Result of exporting one canonical saved snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MicronExportReceipt {
    /// Canonical destination directory created by the export.
    pub output_dir: PathBuf,
    /// Number of page files written beneath `pages/`.
    pub page_count: usize,
    /// BLAKE3 digest of the canonical `PublishedSnapshotV1` representation.
    pub snapshot_digest: [u8; 32],
}

/// Write an immutable saved Micron snapshot to a new static handoff directory.
///
/// The destination must not exist, and its existing parent path must contain
/// no symlink components. A failed write removes the newly-created output
/// directory. The snapshot is validated before any filesystem changes.
pub fn export_micron_snapshot(
    snapshot: &PublishedSnapshotV1,
    output_dir: &Path,
) -> Result<MicronExportReceipt, String> {
    snapshot.validate()?;
    if snapshot.format != SiteFormat::Micron {
        return Err("Static NomadNet export requires a Micron snapshot".into());
    }
    let encoded = snapshot.encode()?;
    let digest = snapshot.digest()?;
    let destination = checked_destination(output_dir)?;

    fs::create_dir(&destination).map_err(|error| {
        format!(
            "Could not create fresh export directory {}: {error}",
            destination.display()
        )
    })?;

    let result = (|| {
        let pages_dir = destination.join("pages");
        fs::create_dir(&pages_dir).map_err(|error| error.to_string())?;
        write_new_file(&destination.join("snapshot.json"), &encoded)?;
        for page in snapshot.pages.values() {
            // Snapshot validation restricts this to a plain Micron filename.
            write_new_file(&pages_dir.join(&page.metadata.path), &page.source)?;
        }
        Ok(())
    })();
    if let Err(error) = result {
        // The destination was just created by this call, so cleanup is scoped
        // to our own fresh output tree.
        let _ = fs::remove_dir_all(&destination);
        return Err(error);
    }

    Ok(MicronExportReceipt {
        output_dir: destination,
        page_count: snapshot.pages.len(),
        snapshot_digest: digest,
    })
}

fn checked_destination(path: &Path) -> Result<PathBuf, String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| error.to_string())?
            .join(path)
    };
    let mut current = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(component.as_os_str()),
            Component::CurDir => {},
            Component::ParentDir => {
                return Err("Export path must not contain parent-directory components".into());
            },
            Component::Normal(part) => current.push(part),
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!(
                    "Export path must not pass through symlink {}",
                    current.display()
                ));
            },
            Ok(metadata) if current != absolute && !metadata.is_dir() => {
                return Err(format!(
                    "Export parent {} is not a directory",
                    current.display()
                ));
            },
            Ok(_) => {},
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if current != absolute {
                    return Err(format!(
                        "Export parent {} does not exist",
                        current.display()
                    ));
                }
            },
            Err(error) => return Err(error.to_string()),
        }
    }
    if absolute.file_name().is_none() {
        return Err("Export destination must name a new directory".into());
    }
    Ok(absolute)
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| error.to_string())?;
    file.write_all(bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())
}
