// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Portable native-site manifests and the canonical published snapshot V1.

//!
//! This is the shared data contract for authoring and resident consumers. It owns
//! validation, exact bytes and content identity. Hosts supply file access,
//! publication authority, storage, protocol adapters and execution lifetimes.
//! V1 field order, native metadata and limits are preserved from Knot.

#[cfg(feature = "history")]
pub mod history;

#[cfg(feature = "publication")]
pub mod publication;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MAX_PAGE_BYTES: usize = 1_048_576;
pub const MAX_SITE_BYTES: usize = 16 * MAX_PAGE_BYTES;
/// The JSON handoff has its own bounded size, independent of native page bytes.
pub const MAX_ENCODED_SNAPSHOT_BYTES: usize = 24 * MAX_PAGE_BYTES;

/// Native site profile. Gemini and Spartan both author Gemtext; their effects differ.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SiteFormat {
    #[default]
    Scroll,
    Gemini,
    Spartan,
    Micron,
}

impl SiteFormat {
    /// Whether a plain page filename belongs to this V1 native profile.
    pub fn accepts_page_name(self, name: &str) -> bool {
        page_name(name, self)
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Scroll => "Scroll",
            Self::Gemini => "Gemini",
            Self::Spartan => "Spartan",
            Self::Micron => "Micron",
        }
    }
    pub fn extension(self) -> &'static str {
        match self {
            Self::Scroll => "scroll",
            Self::Gemini | Self::Spartan => "gmi",
            Self::Micron => "mu",
        }
    }
    pub fn index_file(self) -> &'static str {
        match self {
            Self::Scroll => "index.scroll",
            Self::Gemini | Self::Spartan => "index.gmi",
            Self::Micron => "index.mu",
        }
    }
    pub fn default_port(self) -> Option<u16> {
        match self {
            Self::Scroll => Some(5699),
            Self::Gemini => Some(1965),
            Self::Spartan => Some(300),
            Self::Micron => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Page {
    pub path: String,
    pub author: String,
    pub language: String,
    pub classification: u8,
    pub published: String,
    pub modified: String,
    pub abstract_source: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiteConfig {
    pub version: u8,
    #[serde(default)]
    pub format: SiteFormat,
    pub pages: Vec<Page>,
}

fn plain_line(value: &str) -> bool {
    value.len() <= 1024 && !value.chars().any(char::is_control)
}

fn page_name(value: &str, format: SiteFormat) -> bool {
    value.ends_with(&format!(".{}", format.extension()))
        && value.len() <= 128
        && !value.starts_with('.')
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
}

fn validate_page(page: &Page) -> Result<(), String> {
    if !plain_line(&page.author) || page.classification > 9 {
        return Err("Author must be one line; classification must be 0–9".into());
    }
    if !page.language.is_empty()
        && (page.language.len() > 128
            || page.language.parse::<language_tags::LanguageTag>().is_err())
    {
        return Err("Language must be a BCP47 tag, such as en-US, or empty".into());
    }
    for date in [&page.published, &page.modified] {
        if !date.is_empty()
            && (!date.ends_with('Z')
                || time::OffsetDateTime::parse(
                    date,
                    &time::format_description::well_known::Rfc3339,
                )
                .is_err())
        {
            return Err(
                "Dates must be UTC timestamps, such as 2026-09-11T12:00:00Z, or empty".into(),
            );
        }
    }
    if page.abstract_source.len() > MAX_PAGE_BYTES {
        return Err("Each abstract needs a level-1 title (# Title), within 1 MiB".into());
    }
    Ok(())
}

impl SiteConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != 1 || self.pages.is_empty() || self.pages.len() > 64 {
            return Err("Expected site version 1 with 1–64 pages".into());
        }
        let mut names = std::collections::BTreeSet::new();
        for page in &self.pages {
            if !page_name(&page.path, self.format) || !names.insert(page.path.to_ascii_lowercase())
            {
                return Err(
                    "Page names must be unique plain filenames for the selected site format".into(),
                );
            }
            validate_page(page)?;
            if self.format == SiteFormat::Scroll
                && !page
                    .abstract_source
                    .lines()
                    .any(|line| line.starts_with("# "))
            {
                return Err("Each abstract needs a level-1 title (# Title), within 1 MiB".into());
            }
        }
        if !self
            .pages
            .iter()
            .any(|page| page.path == self.format.index_file())
        {
            return Err(format!("A site needs {}", self.format.index_file()));
        }
        Ok(())
    }
}

/// One immutable page in a process-neutral saved-site snapshot.
///
/// This deliberately contains bytes read from a completed publication, never a
/// path into the author's working directory. Consumers can validate and retain
/// it without gaining authority over the editable site.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedPageV1 {
    pub metadata: Page,
    pub source: Vec<u8>,
}

/// Versioned handoff for an explicit saved publication.
///
/// `Publication` is the in-process serving shape. This record is the durable,
/// process-neutral boundary a resident service may accept after the editor has
/// selected and completed a saved revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishedSnapshotV1 {
    pub version: u8,
    pub format: SiteFormat,
    pub pages: BTreeMap<String, PublishedPageV1>,
}

impl PublishedSnapshotV1 {
    pub const VERSION: u8 = 1;

    pub fn validate(&self) -> Result<(), String> {
        if self.version != Self::VERSION {
            return Err("Unsupported published snapshot version".into());
        }
        if self.pages.is_empty() || self.pages.len() > 64 {
            return Err("Published snapshot must contain 1–64 pages".into());
        }
        let mut total = 0usize;
        let mut names = std::collections::BTreeSet::new();
        for (published_path, page) in &self.pages {
            let expected = format!("/{}", page.metadata.path);
            if published_path != &expected
                || !page_name(&page.metadata.path, self.format)
                || !names.insert(page.metadata.path.to_ascii_lowercase())
            {
                return Err(
                    "Published snapshot page path is invalid or duplicates another name".into(),
                );
            }
            validate_page(&page.metadata)?;
            if self.format == SiteFormat::Scroll
                && !page
                    .metadata
                    .abstract_source
                    .lines()
                    .any(|line| line.starts_with("# "))
            {
                return Err("Each Scroll abstract needs a level-1 title (# Title)".into());
            }
            if page.source.len() > MAX_PAGE_BYTES {
                return Err("Published snapshot page exceeds 1 MiB".into());
            }
            std::str::from_utf8(&page.source).map_err(|error| error.to_string())?;
            total = total
                .checked_add(page.source.len() + page.metadata.abstract_source.len())
                .ok_or("Published snapshot size overflow")?;
            if total > MAX_SITE_BYTES {
                return Err("Published snapshot exceeds 16 MiB".into());
            }
        }
        let index = format!("/{}", self.format.index_file());
        if !self.pages.contains_key(&index) {
            return Err("Published snapshot is missing its format index page".into());
        }
        Ok(())
    }

    /// Canonical JSON bytes used for transport custody and deterministic identity.
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        if bytes.len() > MAX_ENCODED_SNAPSHOT_BYTES {
            return Err("Published snapshot encoding exceeds 24 MiB".into());
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_ENCODED_SNAPSHOT_BYTES {
            return Err("Published snapshot encoding exceeds 24 MiB".into());
        }
        let snapshot = serde_json::from_slice::<Self>(bytes).map_err(|error| error.to_string())?;
        snapshot.validate()?;
        if snapshot.encode()? != bytes {
            return Err("Published snapshot is not canonical JSON".into());
        }
        Ok(snapshot)
    }

    pub fn digest(&self) -> Result<[u8; 32], String> {
        Ok(*blake3::hash(&self.encode()?).as_bytes())
    }
}
