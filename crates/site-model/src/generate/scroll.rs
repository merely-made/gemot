// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

use super::*;
use scroll_protocol::scrolltext::{self, ScrollLine, SpanKind};

impl Writer<'_> {
    pub(super) fn scroll(&self) -> bool {
        self.options.target == OutputFormat::Scroll
    }

    pub(super) fn plain_inline(
        &mut self,
        nodes: &[Node],
        links: &mut Vec<(String, String)>,
    ) -> Result<String, String> {
        let previous = self.plain;
        self.plain = true;
        let result = self.inline(nodes, links);
        self.plain = previous;
        result
    }

    pub(super) fn text(&mut self, text: &str) -> Result<String, String> {
        if !self.native() {
            return Ok(parse::escape(text));
        }
        if self.scroll()
            && !self.plain
            && scrolltext::spans(text)
                .iter()
                .any(|s| s.kind != SpanKind::Plain)
        {
            self.loss(
                "Literal text conflicts with Scroll inline toggles; projected as inline code",
            )?;
            if text.contains('`') {
                return Err("Literal backticks require a Scroll preformatted source block".into());
            }
            return Ok(format!("`{text}`"));
        }
        Ok(text.to_owned())
    }

    pub(super) fn scroll_paragraph(&mut self, text: &str) -> Result<String, String> {
        let mut result = String::new();
        for line in text.lines() {
            let parsed = scrolltext::parse(line);
            match parsed.first() {
                Some(ScrollLine::Text(value)) if value != line => {
                    return Err(
                        "A literal Scroll escape prefix requires a preformatted source block"
                            .into(),
                    );
                }
                Some(ScrollLine::Text(_) | ScrollLine::Blank) | None => {}
                _ => result.push('\\'),
            }
            result.push_str(line);
            result.push('\n');
        }
        Ok(result.trim_end_matches('\n').to_owned())
    }

    pub(super) fn scroll_list(
        &mut self,
        start: Option<u64>,
        children: &[Node],
    ) -> Result<String, String> {
        self.list_depth += 1;
        if self.list_depth > 4 {
            return Err("Scroll list nesting exceeds four levels".into());
        }
        let mut output = String::new();
        for (n, child) in children.iter().enumerate() {
            let Node::Element(Tag::Item, items) = child else {
                return Err("Invalid list item".into());
            };
            let split = items
                .iter()
                .position(|node| matches!(node, Node::Element(Tag::List(_), _)))
                .unwrap_or(items.len());
            let head = &items[..split];
            let head = if let [Node::Element(Tag::Paragraph, text)] = head {
                text.as_slice()
            } else {
                head
            };
            let mut links = Vec::new();
            let text = self.inline(head, &mut links)?;
            if text.contains('\n') {
                return Err(
                    "Multiline list items require an explicit Scroll source profile".into(),
                );
            }
            let ordinal = start
                .map(|s| format!("{}. ", s.saturating_add(n as u64)))
                .unwrap_or_default();
            output.push_str(&format!(
                "{} {ordinal}{text}\n",
                "*".repeat(self.list_depth)
            ));
            for node in &items[split..] {
                let Node::Element(Tag::List(start), nested) = node else {
                    return Err("Scroll list item has unsupported block content".into());
                };
                output.push_str(&self.scroll_list(*start, nested)?);
            }
            for (url, label) in links {
                output.push_str(&format!("=> {url} {label}\n"));
            }
        }
        self.list_depth -= 1;
        if self.list_depth == 0 {
            output.push('\n');
        }
        Ok(output)
    }
}
