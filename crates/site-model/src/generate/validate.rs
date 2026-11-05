// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

use super::*;
use std::collections::BTreeSet;

pub(super) fn filename(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
    !name.is_empty()
        && name.len() <= 128
        && !name.starts_with('.')
        && !name.ends_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        && ![
            "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
            "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        ]
        .contains(&stem.as_str())
}

fn options(options: &BuildOptions) -> Result<(), String> {
    if let Some(template) = &options.html_template {
        if options.target != OutputFormat::Html
            || !crate::plain_line(&template.banner)
            || !crate::plain_line(&template.footer)
        {
            return Err("HTML template needs an HTML target and bounded text fields".into());
        }
    }
    if options.max_page_bytes == 0
        || options.max_page_bytes > MAX_PAGE_BYTES
        || options.max_site_bytes == 0
        || options.max_site_bytes > MAX_SITE_BYTES
        || !crate::plain_line(&options.title_suffix)
    {
        return Err("Writer settings exceed the portable site profile".into());
    }
    for scheme in &options.link_schemes {
        if scheme.is_empty()
            || scheme.len() > 32
            || !scheme
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b"+-0123456789".contains(&b))
            || ["javascript", "vbscript", "data", "file"].contains(&scheme.as_str())
        {
            return Err("Writer link scheme is invalid or executable/local".into());
        }
    }
    Ok(())
}

fn assets(assets: &BTreeMap<String, Asset>, options: &BuildOptions) -> Result<usize, String> {
    if assets.len() > 256 {
        return Err("Too many site assets".into());
    }
    let mut names = BTreeSet::new();
    let mut total = 0usize;
    for (name, asset) in assets {
        if !name.strip_prefix("assets/").is_some_and(filename)
            || !names.insert(name.to_ascii_lowercase())
            || asset.bytes.len() > options.max_page_bytes
            || !crate::plain_line(&asset.media_type)
            || !asset
                .media_type
                .split_once('/')
                .is_some_and(|(kind, subtype)| {
                    [kind, subtype].iter().all(|part| {
                        !part.is_empty()
                            && part.bytes().all(|b| {
                                b.is_ascii_lowercase()
                                    || b.is_ascii_digit()
                                    || b"!#$&^_.+-".contains(&b)
                            })
                    })
                })
        {
            return Err("Invalid, duplicate or oversized site asset".into());
        }
        total = total
            .checked_add(asset.bytes.len())
            .ok_or("Asset size overflow")?;
    }
    if let Some(css) = &options.stylesheet {
        if options.target != OutputFormat::Html
            || assets
                .get(css)
                .is_none_or(|asset| asset.media_type != "text/css")
        {
            return Err("HTML stylesheet must identify an included text/css asset".into());
        }
    }
    Ok(total)
}

fn metadata(title: &str, metadata: &Page) -> Result<(), String> {
    crate::validate_page(metadata)?;
    if title.is_empty() || !crate::plain_line(title) {
        return Err("Page title must be a nonempty bounded line".into());
    }
    Ok(())
}

impl BuildRequest {
    pub fn validate(&self) -> Result<(), String> {
        options(&self.options)?;
        if self.version != 2 || self.pages.is_empty() || self.pages.len() > 64 {
            return Err("Build request requires V2 and 1–64 pages".into());
        }
        let mut total = assets(&self.assets, &self.options)?;
        let mut names = BTreeSet::new();
        let mut index = false;
        for (name, page) in &self.pages {
            metadata(&page.title, &page.metadata)?;
            let Some((stem, ext)) = name.rsplit_once('.') else {
                return Err("Source filename requires a format extension".into());
            };
            let expected = match page.format {
                SourceFormat::Gemtext => "gmi",
                SourceFormat::Scroll => "scroll",
                SourceFormat::Markdown => "md",
            };
            if !filename(name)
                || page.metadata.path != *name
                || ext != expected
                || !names.insert(stem.to_ascii_lowercase())
                || page.source.len() > self.options.max_page_bytes
            {
                return Err(
                    "Invalid source filename, colliding output name or oversized source".into(),
                );
            }
            index |= stem == "index";
            total = total
                .checked_add(page.source.len())
                .and_then(|n| n.checked_add(page.metadata.abstract_source.len()))
                .ok_or("Source size overflow")?;
        }
        if !index || total > self.options.max_site_bytes {
            return Err("Site requires index page within configured byte budget".into());
        }
        Ok(())
    }
}

impl GeneratedSiteV2 {
    pub fn validate(&self) -> Result<(), String> {
        options(&self.options)?;
        if self.version != 2
            || self.pages.is_empty()
            || self.pages.len() > 64
            || self.diagnostics.len() > 4096
        {
            return Err("Invalid V2 artifact version or record count".into());
        }
        let mut total = assets(&self.assets, &self.options)?;
        let mut names = BTreeSet::new();
        for (name, page) in &self.pages {
            metadata(&page.title, &page.metadata)?;
            let Some((stem, _)) = page.source_path.rsplit_once('.') else {
                return Err("Invalid original source path".into());
            };
            if !filename(name)
                || !filename(&page.source_path)
                || page.source_path != page.metadata.path
                || *name != format!("{stem}.{}", self.options.target.extension())
                || !names.insert(name.to_ascii_lowercase())
                || page.bytes.len() > self.options.max_page_bytes
                || std::str::from_utf8(&page.bytes).is_err()
            {
                return Err("Invalid, duplicate or oversized generated page".into());
            }
            total = total
                .checked_add(page.bytes.len())
                .and_then(|n| n.checked_add(page.metadata.abstract_source.len()))
                .ok_or("Artifact size overflow")?;
        }
        for diagnostic in &self.diagnostics {
            if !crate::plain_line(&diagnostic.message)
                || !self
                    .pages
                    .values()
                    .any(|page| page.source_path == diagnostic.page)
            {
                return Err("Invalid writer diagnostic".into());
            }
        }
        if !self
            .pages
            .contains_key(&format!("index.{}", self.options.target.extension()))
            || total > self.options.max_site_bytes
        {
            return Err("Generated site exceeds budget or lacks index".into());
        }
        Ok(())
    }
}
