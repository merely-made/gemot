// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

use super::*;
use gemini_protocol::gemtext::{self, GemLine};
use scroll_protocol::scrolltext::{self, ScrollLine, SpanKind};

pub(super) fn escape(text: &str) -> String {
    let mut result = String::new();
    for c in text.chars() {
        if "\\`*_{}[]<>()#+-.!|>&".contains(c) {
            result.push('\\');
        }
        result.push(c);
    }
    result
}

fn code(text: &str, hint: &str) -> String {
    let width = text
        .split(|c| c != '`')
        .map(str::len)
        .max()
        .unwrap_or(0)
        .max(2)
        + 1;
    let fence = "`".repeat(width);
    format!(
        "{fence}{hint}\n{text}{}{fence}\n\n",
        if text.ends_with('\n') { "" } else { "\n" }
    )
}
fn inline(text: &str) -> String {
    scrolltext::spans(text)
        .into_iter()
        .map(|span| match span.kind {
            SpanKind::Plain => escape(&span.text),
            SpanKind::Strong => format!("**{}**", escape(&span.text)),
            SpanKind::Emphasis => format!("*{}*", escape(&span.text)),
            SpanKind::Code => {
                let width = span
                    .text
                    .split(|c| c != '`')
                    .map(str::len)
                    .max()
                    .unwrap_or(0)
                    + 1;
                let fence = "`".repeat(width);
                format!("{fence} {} {fence}", span.text)
            }
        })
        .collect()
}
fn link(url: &str, label: &str) -> Result<String, String> {
    if url.is_empty() || url.contains(['<', '>']) {
        return Err("Invalid native link target".into());
    }
    Ok(format!(
        "[{}](<{url}>)\n\n",
        escape(if label.is_empty() { url } else { label })
    ))
}

pub(super) fn markdown(page: &SourcePage) -> Result<String, String> {
    if page.format == SourceFormat::Markdown {
        return Ok(page.source.clone());
    }
    let mut result = String::new();
    if page.format == SourceFormat::Gemtext {
        let mut pre = false;
        for line in page.source.lines() {
            if line.starts_with("```") { pre = !pre; }
            else if !pre && line.strip_prefix("=>").is_some_and(|s| s.trim().is_empty()) { return Err("Gemtext link has no target".into()); }
        }
        for line in gemtext::parse(&page.source) {
            match line {
                GemLine::Heading { level, text } => result.push_str(&format!(
                    "{} {}\n\n",
                    "#".repeat(level as usize),
                    escape(&text)
                )),
                GemLine::Text(text) => result.push_str(&format!("{}\n\n", escape(&text))),
                GemLine::Blank => result.push('\n'),
                GemLine::Link { url, label } => result.push_str(&link(&url, &label)?),
                GemLine::Item(text) => result.push_str(&format!("* {}\n", escape(&text))),
                GemLine::Quote(text) => result.push_str(&format!("> {}\n\n", escape(&text))),
                GemLine::Pre { alt, text } => {
                    result.push_str(&code(&text, alt.as_deref().unwrap_or("")))
                }
            }
        }
        return Ok(result);
    }
    let mut list_widths = [0usize; 4];
    let mut ordinals = [None; 4];
    for line in scrolltext::parse(&page.source) {
        match line {
            ScrollLine::Heading { level: 5, .. } => return Err("Scroll level-five textual titles require literal preservation; they are not outline headings".into()),
            ScrollLine::Heading { level, text } => result.push_str(&format!("{} {}\n\n", "#".repeat(level as usize), escape(&text))),
            ScrollLine::Text(text) => result.push_str(&format!("{}\n\n", inline(&text))),
            ScrollLine::Blank => { result.push('\n'); list_widths = [0; 4]; ordinals = [None; 4]; },
            ScrollLine::Link { relation: Some(_), .. } => return Err("Scroll link relations require literal preservation; the conversion profile has no relation envelope".into()),
            ScrollLine::InputLink { .. } => return Err("Scroll input links require literal preservation or a separately selected submission adapter".into()),
            ScrollLine::Link { url, label, .. } => {
                if url.starts_with('#') { return Err("Scroll heading-number links require literal preservation".into()); }
                result.push_str(&link(&url, &label)?);
            },
            ScrollLine::Quote { depth, text } => {
                if depth > 32 { return Err("Quote nesting exceeds writer budget".into()); }
                result.push_str(&format!("{} {}\n\n", "> ".repeat(depth as usize), inline(&text)));
            },
            ScrollLine::ListItem { depth, ordinal, text } => {
                let index = usize::from(depth - 1);
                if list_widths[..index].contains(&0) { return Err("Scroll list depth skips a parent".into()); }
                let marker = if let Some(marker) = ordinal {
                    let digits = marker.strip_suffix('.').ok_or("Unsupported Scroll ordinal")?;
                    if digits.len() > 9 { return Err("Scroll ordinal exceeds CommonMark profile".into()); }
                    let n = digits.parse::<u64>().map_err(|_| "Alphabetic Scroll ordinals require literal preservation")?;
                    if ordinals[index].is_some_and(|previous| previous + 1 != n) { return Err("Nonconsecutive Scroll ordinals require literal preservation; CommonMark would renumber them".into()); }
                    ordinals[index] = Some(n); format!("{n}. ")
                } else { ordinals[index] = None; "* ".to_owned() };
                let indent = " ".repeat(list_widths[..index].iter().sum());
                list_widths[index] = marker.len();
                for slot in index+1..4 { list_widths[slot]=0; ordinals[slot]=None; }
                result.push_str(&format!("{indent}{marker}{}\n", inline(&text)));
            },
            ScrollLine::ThematicBreak => result.push_str("---\n\n"),
            ScrollLine::CodeBlock { tag, lines } => result.push_str(&code(&lines.join("\n"), tag.as_deref().unwrap_or(""))),
        }
    }
    Ok(result)
}
