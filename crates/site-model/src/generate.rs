// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

//! Explicit format writers. V2 artifacts do not change native V1 snapshots.

mod parse;
mod render;
mod validate;

use crate::{MAX_PAGE_BYTES, MAX_SITE_BYTES, Page, PublishedSnapshotV1, SiteFormat};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceFormat {
    Gemtext,
    Scroll,
    Markdown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    Gemtext,
    Scroll,
    Markdown,
    Html,
}

impl OutputFormat {
    pub fn extension(self) -> &'static str {
        match self {
            Self::Gemtext => "gmi",
            Self::Scroll => "scroll",
            Self::Markdown => "md",
            Self::Html => "html",
        }
    }
    pub fn media_type(self) -> &'static str {
        match self {
            Self::Gemtext => "text/gemini",
            Self::Scroll => "text/scroll",
            Self::Markdown => "text/markdown",
            Self::Html => "text/html",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourcePage {
    pub format: SourceFormat,
    pub title: String,
    pub metadata: Page,
    pub source: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Asset {
    pub media_type: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildOptions {
    pub target: OutputFormat,
    /// Fail rather than flatten constructs the target cannot express.
    pub reject_loss: bool,
    /// Copy an all-Gemtext or all-Scroll source profile literally, without parsing.
    pub preserve_native_bytes: bool,
    /// HTML template settings are data, never executable source.
    pub title_suffix: String,
    pub stylesheet: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub html_template: Option<HtmlTemplate>,
    pub allow_remote_images: bool,
    pub link_schemes: Vec<String>,
    pub max_page_bytes: usize,
    pub max_site_bytes: usize,
}

impl BuildOptions {
    pub fn new(target: OutputFormat) -> Self {
        Self {
            target,
            reject_loss: true,
            preserve_native_bytes: false,
            title_suffix: String::new(),
            stylesheet: None,
            html_template: None,
            allow_remote_images: false,
            link_schemes: [
                "https", "http", "gemini", "scroll", "spartan", "titan", "ipfs", "mailto",
            ]
            .map(str::to_owned)
            .to_vec(),
            max_page_bytes: MAX_PAGE_BYTES,
            max_site_bytes: MAX_SITE_BYTES,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HtmlContainer {
    Main,
    Article,
    Section,
}

impl HtmlContainer {
    pub fn tag(self) -> &'static str {
        match self {
            Self::Main => "main",
            Self::Article => "article",
            Self::Section => "section",
        }
    }
}

/// Declarative template data. Text is escaped; selecting a template runs no code.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HtmlTemplate {
    pub container: HtmlContainer,
    pub banner: String,
    pub footer: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildRequest {
    pub version: u8,
    pub options: BuildOptions,
    /// Flat, relative source filenames; output names are derived and collision checked.
    pub pages: BTreeMap<String, SourcePage>,
    /// Assets live under `assets/`, separate from page names and the artifact envelope.
    pub assets: BTreeMap<String, Asset>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Diagnostic {
    pub page: String,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratedPage {
    pub source_path: String,
    pub source_format: SourceFormat,
    pub source_digest: [u8; 32],
    pub title: String,
    /// Original author metadata, including the original source filename.
    pub metadata: Page,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratedSiteV2 {
    pub version: u8,
    pub options: BuildOptions,
    pub pages: BTreeMap<String, GeneratedPage>,
    pub assets: BTreeMap<String, Asset>,
    pub diagnostics: Vec<Diagnostic>,
}

impl BuildRequest {
    /// Supply an existing immutable native snapshot without editing its envelope.
    pub fn from_native(
        snapshot: &PublishedSnapshotV1,
        options: BuildOptions,
    ) -> Result<Self, String> {
        snapshot.validate()?;
        let format =
            match snapshot.format {
                SiteFormat::Gemini | SiteFormat::Spartan => SourceFormat::Gemtext,
                SiteFormat::Scroll => SourceFormat::Scroll,
                SiteFormat::Micron => return Err(
                    "Micron conversion has no declared writer profile; retain its native V1 bytes"
                        .into(),
                ),
            };
        let pages = snapshot
            .pages
            .values()
            .map(|page| {
                let title = page
                    .metadata
                    .abstract_source
                    .lines()
                    .find_map(|s| s.strip_prefix("# "))
                    .unwrap_or(&page.metadata.path)
                    .to_owned();
                Ok((
                    page.metadata.path.clone(),
                    SourcePage {
                        format,
                        title,
                        metadata: page.metadata.clone(),
                        source: String::from_utf8(page.source.clone())
                            .map_err(|e| e.to_string())?,
                    },
                ))
            })
            .collect::<Result<_, String>>()?;
        Ok(Self {
            version: 2,
            options,
            pages,
            assets: BTreeMap::new(),
        })
    }

    pub fn build(&self) -> Result<GeneratedSiteV2, String> {
        self.validate()?;
        let names: BTreeMap<_, _> = self
            .pages
            .keys()
            .map(|name| {
                let stem = name
                    .rsplit_once('.')
                    .map_or(name.as_str(), |(stem, _)| stem);
                (
                    name.clone(),
                    format!("{stem}.{}", self.options.target.extension()),
                )
            })
            .collect();
        let mut pages = BTreeMap::new();
        let mut diagnostics = Vec::new();
        for (name, page) in &self.pages {
            let bytes = if self.options.preserve_native_bytes {
                if !matches!(
                    (page.format, self.options.target),
                    (SourceFormat::Gemtext, OutputFormat::Gemtext)
                        | (SourceFormat::Scroll, OutputFormat::Scroll)
                ) {
                    return Err("Literal preservation requires matching all-native source and output profiles".into());
                }
                page.source.as_bytes().to_vec()
            } else {
                if page
                    .source
                    .chars()
                    .any(|c| c.is_control() && !"\n\r\t".contains(c))
                {
                    return Err("Source contains controls outside the text writer profile".into());
                }
                let markdown = parse::markdown(page)?;
                render::write(
                    name,
                    page,
                    &markdown,
                    &names,
                    &self.assets,
                    &self.options,
                    &mut diagnostics,
                )?
            };
            pages.insert(
                names[name].clone(),
                GeneratedPage {
                    source_path: name.clone(),
                    source_format: page.format,
                    source_digest: *blake3::hash(page.source.as_bytes()).as_bytes(),
                    title: page.title.clone(),
                    metadata: page.metadata.clone(),
                    bytes,
                },
            );
        }
        let result = GeneratedSiteV2 {
            version: 2,
            options: self.options.clone(),
            pages,
            assets: self.assets.clone(),
            diagnostics,
        };
        result.validate()?;
        Ok(result)
    }
}

impl GeneratedSiteV2 {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let encoded = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        if encoded.len() > crate::MAX_ENCODED_SNAPSHOT_BYTES {
            return Err("V2 artifact encoding exceeds custody budget".into());
        }
        Ok(encoded)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > crate::MAX_ENCODED_SNAPSHOT_BYTES {
            return Err("V2 artifact encoding exceeds custody budget".into());
        }
        let result: Self = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if result.encode()? != bytes {
            return Err("V2 artifact is not canonical JSON".into());
        }
        Ok(result)
    }
    pub fn digest(&self) -> Result<[u8; 32], String> {
        Ok(*blake3::hash(&self.encode()?).as_bytes())
    }
}
