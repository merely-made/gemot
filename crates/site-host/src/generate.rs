// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

//! Checked static artifacts. Exporting starts no listener or publication.

use crate::{Page, Publication, PublishedPageV1, PublishedSnapshotV1, Site, SiteFormat};
pub use site_model::generate::*;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

pub const ARTIFACT_FILE: &str = "site-v2.json";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportReceipt {
    pub directory: PathBuf,
    pub artifact_digest: [u8; 32],
    pub page_count: usize,
    pub asset_count: usize,
}

impl Site {
    pub fn generate(&self, options: BuildOptions) -> Result<GeneratedSiteV2, String> {
        BuildRequest::from_native(&self.publication()?.to_snapshot_v1()?, options)?.build()
    }
}

pub fn export(artifact: &GeneratedSiteV2, destination: &Path) -> Result<ExportReceipt, String> {
    let encoded = artifact.encode()?;
    let destination = crate::export::checked_destination(destination)?;
    fs::create_dir(&destination).map_err(|e| e.to_string())?;
    let result = (|| {
        crate::export::write_new_file(&destination.join(ARTIFACT_FILE), &encoded)?;
        if !artifact.assets.is_empty() {
            fs::create_dir(destination.join("assets")).map_err(|e| e.to_string())?;
        }
        for (name, page) in &artifact.pages {
            crate::export::write_new_file(&destination.join(name), &page.bytes)?;
        }
        for (name, asset) in &artifact.assets {
            crate::export::write_new_file(&destination.join(name), &asset.bytes)?;
        }
        Ok::<_, String>(())
    })();
    if let Err(error) = result {
        // Only this call's newly-created export directory is eligible for cleanup.
        let _ = fs::remove_dir_all(&destination);
        return Err(error);
    }
    Ok(ExportReceipt {
        directory: destination,
        artifact_digest: artifact.digest()?,
        page_count: artifact.pages.len(),
        asset_count: artifact.assets.len(),
    })
}

/// Load the envelope and compare every exported byte before accepting custody.
pub fn open_export(directory: &Path) -> Result<GeneratedSiteV2, String> {
    let directory = fs::canonicalize(directory).map_err(|e| e.to_string())?;
    let read = |name: &str, limit: usize| -> Result<Vec<u8>, String> {
        let path = fs::canonicalize(directory.join(name)).map_err(|e| e.to_string())?;
        let parent = if name.starts_with("assets/") {
            directory.join("assets")
        } else {
            directory.clone()
        };
        if !path.starts_with(&directory) || path.parent() != Some(parent.as_path()) {
            return Err("Exported file escapes its artifact directory".into());
        }
        crate::read_bounded(&path, limit)
    };
    let artifact =
        GeneratedSiteV2::decode(&read(ARTIFACT_FILE, crate::MAX_ENCODED_SNAPSHOT_BYTES)?)?;
    for (name, page) in &artifact.pages {
        if read(name, artifact.options.max_page_bytes)? != page.bytes {
            return Err("Exported page differs from its checked artifact".into());
        }
    }
    for (name, asset) in &artifact.assets {
        if read(name, artifact.options.max_page_bytes)? != asset.bytes {
            return Err("Exported asset differs from its checked artifact".into());
        }
    }
    Ok(artifact)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaticReply {
    pub media_type: String,
    pub bytes: Vec<u8>,
}

/// Protocol adapters receive an exact map lookup; no URL becomes a file path.
pub fn reply(
    artifact: &GeneratedSiteV2,
    request_path: &str,
) -> Result<Option<StaticReply>, String> {
    artifact.validate()?;
    let path = if request_path == "/" {
        format!("index.{}", artifact.options.target.extension())
    } else {
        request_path
            .strip_prefix('/')
            .ok_or("Request path must be absolute")?
            .to_owned()
    };
    if let Some(page) = artifact.pages.get(&path) {
        return Ok(Some(StaticReply {
            media_type: format!("{};charset=utf-8", artifact.options.target.media_type()),
            bytes: page.bytes.clone(),
        }));
    }
    Ok(artifact.assets.get(&path).map(|asset| StaticReply {
        media_type: asset.media_type.clone(),
        bytes: asset.bytes.clone(),
    }))
}

/// Feed generated native pages to the existing qualified protocol consumer.
/// Assets stay in V2 custody: native V1 has no asset contract.
pub fn native_publication(
    artifact: &GeneratedSiteV2,
    protocol: SiteFormat,
) -> Result<Publication, String> {
    artifact.validate()?;
    if !artifact.assets.is_empty()
        || !matches!(
            (artifact.options.target, protocol),
            (
                OutputFormat::Gemtext,
                SiteFormat::Gemini | SiteFormat::Spartan
            ) | (OutputFormat::Scroll, SiteFormat::Scroll)
        )
    {
        return Err("Selected artifact is not an asset-free native protocol profile".into());
    }
    let pages = artifact
        .pages
        .iter()
        .map(|(path, page)| {
            let metadata = Page {
                path: path.clone(),
                ..page.metadata.clone()
            };
            (
                format!("/{path}"),
                PublishedPageV1 {
                    metadata,
                    source: page.bytes.clone(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    Publication::from_snapshot_v1(PublishedSnapshotV1 {
        version: 1,
        format: protocol,
        pages,
    })
}
