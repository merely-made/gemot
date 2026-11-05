// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

use super::*;
use pulldown_cmark::{CodeBlockKind, Event, Options, Parser, Tag, TagEnd, html};

enum Node {
    Element(Tag<'static>, Vec<Node>),
    Leaf(Event<'static>),
}

#[path = "scroll.rs"]
mod scroll;

fn loss(
    page: &str,
    message: &str,
    options: &BuildOptions,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<(), String> {
    if options.reject_loss {
        return Err(format!("{page}: {message}"));
    }
    if diagnostics.len() >= 4096 {
        return Err("Writer diagnostic budget exceeded".into());
    }
    let d = Diagnostic {
        page: page.to_owned(),
        message: message.to_owned(),
    };
    if !diagnostics.contains(&d) {
        diagnostics.push(d);
    }
    Ok(())
}

fn link(
    url: &str,
    names: &BTreeMap<String, String>,
    assets: &BTreeMap<String, Asset>,
    options: &BuildOptions,
) -> Result<String, String> {
    if url.is_empty()
        || url.len() > 4096
        || url
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == '\\')
        || url.starts_with("//")
    {
        return Err("Invalid or ambiguous site link".into());
    }
    if let Some((scheme, _)) = url.split(['?', '#']).next().unwrap_or(url).split_once(':') {
        if !options
            .link_schemes
            .iter()
            .any(|s| s == &scheme.to_ascii_lowercase())
        {
            return Err(format!(
                "Link scheme '{scheme}' is outside the selected writer profile"
            ));
        }
        return Ok(url.to_owned());
    }
    if url.starts_with('#') {
        return Ok(url.to_owned());
    }
    let end = url.find(['?', '#']).unwrap_or(url.len());
    let (path, suffix) = url.split_at(end);
    let path = path.strip_prefix('/').unwrap_or(path);
    let path = path.strip_prefix("./").unwrap_or(path);
    let output = names
        .get(path)
        .map(String::as_str)
        .or_else(|| assets.contains_key(path).then_some(path))
        .ok_or_else(|| format!("Unresolved local site link '{path}'"))?;
    Ok(format!(
        "{}{output}{suffix}",
        if url.starts_with('/') { "/" } else { "" }
    ))
}

pub(super) fn write(
    page_name: &str,
    page: &SourcePage,
    markdown: &str,
    names: &BTreeMap<String, String>,
    assets: &BTreeMap<String, Asset>,
    options: &BuildOptions,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<Vec<u8>, String> {
    let mut events = Vec::new();
    let mut image_links = Vec::new();
    for event in Parser::new_ext(markdown, Options::empty()) {
        let event = match event.into_static() {
            Event::Start(Tag::Link {
                link_type,
                dest_url,
                title,
                id,
            }) => Event::Start(Tag::Link {
                link_type,
                dest_url: link(&dest_url, names, assets, options)?.into(),
                title,
                id,
            }),
            Event::Start(Tag::Image {
                link_type,
                dest_url,
                title,
                id,
            }) => {
                let remote = dest_url.contains(':') || dest_url.starts_with("//");
                let dest_url = link(&dest_url, names, assets, options)?.into();
                let substitute = remote && !options.allow_remote_images;
                image_links.push(substitute);
                if substitute {
                    loss(
                        page_name,
                        "Remote image projected as a link; remote image loading is disabled",
                        options,
                        diagnostics,
                    )?;
                    Event::Start(Tag::Link {
                        link_type,
                        dest_url,
                        title,
                        id,
                    })
                } else {
                    Event::Start(Tag::Image {
                        link_type,
                        dest_url,
                        title,
                        id,
                    })
                }
            }
            Event::End(TagEnd::Image) if image_links.pop().unwrap_or(false) => {
                Event::End(TagEnd::Link)
            }
            Event::Html(text) | Event::InlineHtml(text) => {
                loss(
                    page_name,
                    "Raw HTML is rendered as literal text",
                    options,
                    diagnostics,
                )?;
                Event::Text(text)
            }
            event => event,
        };
        events.push(event);
    }
    let mut nesting = 0usize;
    for event in &events {
        match event {
            Event::Start(_) => {
                nesting += 1;
                if nesting > 64 {
                    return Err("Document nesting exceeds writer budget".into());
                }
            }
            Event::End(_) => nesting -= 1,
            _ => {}
        }
    }
    if options.target == OutputFormat::Html {
        let mut ids = BTreeMap::<String, usize>::new();
        let mut used_ids = std::collections::BTreeSet::new();
        for i in 0..events.len() {
            if matches!(events[i], Event::Start(Tag::Heading { .. })) {
                let text = events[i + 1..]
                    .iter()
                    .take_while(|event| !matches!(event, Event::End(TagEnd::Heading(_))))
                    .filter_map(|event| match event {
                        Event::Text(s) | Event::Code(s) => Some(s.as_ref()),
                        _ => None,
                    })
                    .collect::<String>();
                let slug = text
                    .to_lowercase()
                    .split(|c: char| !c.is_alphanumeric())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
                    .join("-");
                let slug = if slug.is_empty() {
                    "section".to_owned()
                } else {
                    slug
                };
                let count = ids.entry(slug.clone()).or_default();
                let mut unique = if *count == 0 {
                    slug.clone()
                } else {
                    format!("{slug}-{count}")
                };
                while !used_ids.insert(unique.clone()) {
                    *count += 1;
                    unique = format!("{slug}-{count}");
                }
                *count += 1;
                if let Event::Start(Tag::Heading { id, .. }) = &mut events[i] {
                    *id = Some(unique.into());
                }
            }
        }
        let mut body = String::new();
        html::push_html(&mut body, events.into_iter());
        if let Some(template) = &options.html_template {
            let tag = template.container.tag();
            let header = if template.banner.is_empty() {
                String::new()
            } else {
                format!("<header>{}</header>\n", html_escape(&template.banner))
            };
            let footer = if template.footer.is_empty() {
                String::new()
            } else {
                format!("<footer>{}</footer>\n", html_escape(&template.footer))
            };
            body = format!("{header}<{tag}>\n{body}</{tag}>\n{footer}");
        }
        let e = html_escape;
        let css = options
            .stylesheet
            .as_ref()
            .map(|path| format!("<link rel=\"stylesheet\" href=\"{}\">\n", e(path)))
            .unwrap_or_default();
        return Ok(format!("<!doctype html>\n<html lang=\"{}\">\n<head>\n<meta charset=\"utf-8\">\n<title>{}{}</title>\n<meta name=\"author\" content=\"{}\">\n<meta name=\"description\" content=\"{}\">\n<meta name=\"published\" content=\"{}\">\n<meta name=\"modified\" content=\"{}\">\n<meta name=\"classification\" content=\"{}\">\n{css}</head>\n<body>\n{body}</body>\n</html>\n", e(&page.metadata.language), e(&page.title), e(&options.title_suffix), e(&page.metadata.author), e(&page.metadata.abstract_source), e(&page.metadata.published), e(&page.metadata.modified), page.metadata.classification).into_bytes());
    }
    let mut stack: Vec<(Option<Tag<'static>>, Vec<Node>)> = vec![(None, vec![])];
    for event in events {
        match event {
            Event::Start(tag) => {
                if stack.len() >= 64 {
                    return Err("Document nesting exceeds writer budget".into());
                }
                stack.push((Some(tag), vec![]));
            }
            Event::End(end) => {
                let (tag, children) = stack.pop().ok_or("Unbalanced document")?;
                let tag = tag.ok_or("Unbalanced document")?;
                if tag.to_end() != end {
                    return Err("Unbalanced document tag".into());
                }
                stack
                    .last_mut()
                    .ok_or("Unbalanced document")?
                    .1
                    .push(Node::Element(tag, children));
            }
            leaf => stack.last_mut().unwrap().1.push(Node::Leaf(leaf)),
        }
    }
    let mut writer = Writer {
        page: page_name,
        options,
        diagnostics,
        plain: false,
        list_depth: 0,
    };
    Ok(writer
        .blocks(&stack.pop().ok_or("Missing document root")?.1, 0)?
        .into_bytes())
}

pub(super) fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

struct Writer<'a> {
    page: &'a str,
    options: &'a BuildOptions,
    diagnostics: &'a mut Vec<Diagnostic>,
    plain: bool,
    list_depth: usize,
}
impl Writer<'_> {
    fn native(&self) -> bool {
        matches!(
            self.options.target,
            OutputFormat::Gemtext | OutputFormat::Scroll
        )
    }
    fn loss(&mut self, message: &str) -> Result<(), String> {
        loss(self.page, message, self.options, self.diagnostics)
    }
    fn inline(
        &mut self,
        nodes: &[Node],
        links: &mut Vec<(String, String)>,
    ) -> Result<String, String> {
        let mut output = String::new();
        for node in nodes {
            match node {
                Node::Leaf(Event::Text(text)) => output.push_str(&self.text(text)?),
                Node::Leaf(Event::Code(text)) => {
                    if self.scroll() && !self.plain {
                        if text.contains('`') {
                            return Err(
                                "Inline code with backticks is outside the Scroll writer profile"
                                    .into(),
                            );
                        }
                        output.push_str(&format!("`{text}`"));
                    } else if self.native() {
                        self.loss("Inline code formatting is flattened")?;
                        output.push_str(text);
                    } else {
                        let width = text.split(|c| c != '`').map(str::len).max().unwrap_or(0) + 1;
                        let fence = "`".repeat(width);
                        output.push_str(&format!("{fence} {text} {fence}"));
                    }
                }
                Node::Leaf(Event::SoftBreak) => output.push('\n'),
                Node::Leaf(Event::HardBreak) => {
                    output.push_str(if self.native() { "\n" } else { "  \n" })
                }
                Node::Element(
                    Tag::Link {
                        dest_url, title, ..
                    },
                    children,
                )
                | Node::Element(
                    Tag::Image {
                        dest_url, title, ..
                    },
                    children,
                ) => {
                    let image = matches!(node, Node::Element(Tag::Image { .. }, _));
                    let label = if self.native() {
                        self.plain_inline(children, &mut vec![])?
                    } else {
                        self.inline(children, &mut vec![])?
                    };
                    if self.native() {
                        self.loss(if image {
                            "Image projected as a native link"
                        } else {
                            "Inline link projected as a native link line"
                        })?;
                        links.push((dest_url.to_string(), label.clone()));
                        output.push_str(&label);
                    } else {
                        let title = if title.is_empty() {
                            String::new()
                        } else {
                            format!(" \"{}\"", title.replace('\\', "\\\\").replace('"', "\\\""))
                        };
                        output.push_str(&format!(
                            "{}[{label}](<{}>{title})",
                            if image { "!" } else { "" },
                            dest_url.replace('>', "%3E").replace('<', "%3C")
                        ));
                    }
                }
                Node::Element(Tag::Emphasis | Tag::Strong, children) => {
                    let text = self.inline(children, links)?;
                    if self.scroll() && !self.plain {
                        if children
                            .iter()
                            .any(|n| !matches!(n, Node::Leaf(Event::Text(_))))
                        {
                            return Err("Nested inline styles are outside Scroll's single-style toggle profile".into());
                        }
                        let mark = if matches!(node, Node::Element(Tag::Strong, _)) {
                            "*"
                        } else {
                            "_"
                        };
                        output.push_str(&format!("{mark}{text}{mark}"));
                    } else if self.native() {
                        self.loss("Emphasis formatting is flattened")?;
                        output.push_str(&text);
                    } else {
                        let mark = if matches!(node, Node::Element(Tag::Strong, _)) {
                            "**"
                        } else {
                            "*"
                        };
                        output.push_str(&format!("{mark}{text}{mark}"));
                    }
                }
                _ => return Err("Unsupported inline construct in selected writer profile".into()),
            }
        }
        Ok(output)
    }

    fn blocks(&mut self, nodes: &[Node], depth: usize) -> Result<String, String> {
        let mut output = String::new();
        for node in nodes {
            let mut links = vec![];
            match node {
                Node::Element(Tag::Paragraph, children) => {
                    if self.native() && children.len() == 1 {
                        if let Node::Element(
                            Tag::Link {
                                dest_url, title, ..
                            },
                            label,
                        ) = &children[0]
                        {
                            if !title.is_empty() {
                                self.loss("Native link lines do not carry CommonMark link titles")?;
                            }
                            let label = self.plain_inline(label, &mut links)?;
                            output.push_str(&format!("=> {dest_url} {label}\n\n"));
                            continue;
                        }
                    }
                    let text = self.inline(children, &mut links)?;
                    if self.scroll() {
                        output.push_str(&self.scroll_paragraph(&text)?);
                    } else if self.native()
                        && text.lines().any(|line| {
                            ["# ", "## ", "### ", "=>", ">", "* ", "```"]
                                .iter()
                                .any(|prefix| line.starts_with(prefix))
                        })
                    {
                        self.loss("Literal paragraph collides with native control syntax; projected as preformatted text")?;
                        if text.lines().any(|line| line.starts_with("```")) {
                            return Err(
                                "Literal paragraph contains an unrepresentable native fence".into(),
                            );
                        }
                        output.push_str(&format!("```\n{text}\n```"));
                    } else {
                        output.push_str(&text);
                    }
                    output.push_str("\n\n");
                }
                Node::Element(Tag::Heading { level, .. }, children) => {
                    let mut level = *level as usize;
                    if self.scroll() && level >= 5 {
                        self.loss("Scroll level-five titles do not participate in outlines")?;
                        level = 5;
                    } else if self.native() && !self.scroll() && level > 3 {
                        self.loss("Heading level reduced to native level three")?;
                        level = 3;
                    }
                    output.push_str(&format!(
                        "{} {}\n\n",
                        "#".repeat(level),
                        if self.native() {
                            self.plain_inline(children, &mut links)?
                        } else {
                            self.inline(children, &mut links)?
                        }
                    ));
                }
                Node::Element(Tag::BlockQuote(_), children) => {
                    if self.native() && !self.scroll() && depth > 0 {
                        self.loss("Nested block quote is flattened")?;
                    }
                    let inner = self.blocks(children, depth + 1)?;
                    for line in inner.trim_end().lines() {
                        if self.scroll() && line.starts_with('>') {
                            output.push_str(&format!(">{line}\n"));
                        } else {
                            output.push_str(&format!("> {line}\n"));
                        }
                    }
                    output.push('\n');
                }
                Node::Element(Tag::List(start), children) => {
                    if self.scroll() {
                        output.push_str(&self.scroll_list(*start, children)?);
                        continue;
                    }
                    if self.native() && (start.is_some() || depth > 0) {
                        self.loss("Ordered or nested list projected as native bullet text")?;
                    }
                    for (n, child) in children.iter().enumerate() {
                        let Node::Element(Tag::Item, items) = child else {
                            return Err("Invalid list item".into());
                        };
                        let text = self.blocks(items, depth + 1)?;
                        let bullet = if self.native() || start.is_none() {
                            "* ".into()
                        } else {
                            format!("{}. ", start.unwrap().saturating_add(n as u64))
                        };
                        let indent = " ".repeat(bullet.len());
                        for (index, line) in text.trim_end().lines().enumerate() {
                            output.push_str(if index == 0 { &bullet } else { &indent });
                            output.push_str(line);
                            output.push('\n');
                        }
                    }
                    output.push('\n');
                }
                Node::Element(Tag::CodeBlock(kind), children) => {
                    let text = children
                        .iter()
                        .filter_map(|n| {
                            if let Node::Leaf(Event::Text(s)) = n {
                                Some(s.as_ref())
                            } else {
                                None
                            }
                        })
                        .collect::<String>();
                    let info = match kind {
                        CodeBlockKind::Fenced(s) => s.as_ref(),
                        CodeBlockKind::Indented => "",
                    };
                    let width = if self.native() {
                        if text.lines().any(|line| line.starts_with("```")) {
                            return Err("Code contains an unrepresentable native fence".into());
                        }
                        3
                    } else {
                        text.split(|c| c != '`')
                            .map(str::len)
                            .max()
                            .unwrap_or(0)
                            .max(2)
                            + 1
                    };
                    let fence = "`".repeat(width);
                    output.push_str(&format!(
                        "{fence}{info}\n{text}{}{fence}\n\n",
                        if text.ends_with('\n') { "" } else { "\n" }
                    ));
                }
                Node::Element(Tag::HtmlBlock, children) => {
                    output.push_str(&self.inline(children, &mut links)?);
                    output.push_str("\n\n");
                }
                Node::Leaf(Event::Rule) => {
                    if self.native() && !self.scroll() {
                        self.loss("Thematic break projected as native text")?;
                    }
                    output.push_str("---\n\n");
                }
                Node::Leaf(Event::Text(_)) => {
                    output.push_str(&self.inline(std::slice::from_ref(node), &mut links)?);
                }
                _ => return Err("Unsupported block construct in selected writer profile".into()),
            }
            for (url, label) in links {
                output.push_str(&format!("=> {url} {label}\n"));
            }
        }
        Ok(output)
    }
}
