// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

#![cfg(feature = "generate")]

use gemot_site::{PublishedSnapshotV1, generate::*};

fn project(target: OutputFormat) -> BuildRequest {
    let mut request: BuildRequest =
        serde_json::from_slice(include_bytes!("fixtures/writers/project.json")).unwrap();
    request.options.target = target;
    request
}

#[test]
fn all_writers_match_fixed_bodies_metadata_assets_and_canonical_identity() {
    for (target, body, digest) in [
        (
            OutputFormat::Gemtext,
            include_bytes!("fixtures/writers/index.gmi").as_slice(),
            include_str!("fixtures/writers/gemtext.blake3"),
        ),
        (
            OutputFormat::Scroll,
            include_bytes!("fixtures/writers/index.scroll").as_slice(),
            include_str!("fixtures/writers/scroll.blake3"),
        ),
        (
            OutputFormat::Markdown,
            include_bytes!("fixtures/writers/index.md").as_slice(),
            include_str!("fixtures/writers/markdown.blake3"),
        ),
        (
            OutputFormat::Html,
            include_bytes!("fixtures/writers/index.html").as_slice(),
            include_str!("fixtures/writers/html.blake3"),
        ),
    ] {
        let request = project(target);
        let artifact = request.build().unwrap();
        assert_eq!(
            artifact.pages[&format!("index.{}", target.extension())].bytes,
            body
        );
        assert_eq!(
            artifact
                .pages
                .values()
                .find(|page| page.source_path == "index.gmi")
                .unwrap()
                .metadata,
            request.pages["index.gmi"].metadata
        );
        assert_eq!(artifact.assets, request.assets);
        let encoded = artifact.encode().unwrap();
        assert_eq!(GeneratedSiteV2::decode(&encoded).unwrap(), artifact);
        assert_eq!(
            artifact
                .digest()
                .unwrap()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            digest.trim()
        );
        assert_eq!(request.build().unwrap().encode().unwrap(), encoded);
    }
}

#[test]
fn native_literal_mode_preserves_all_v1_bytes_and_identity() {
    for bytes in [
        include_bytes!("fixtures/gemini-v1.json").as_slice(),
        include_bytes!("fixtures/scroll-v1.json").as_slice(),
        include_bytes!("fixtures/spartan-v1.json").as_slice(),
    ] {
        let snapshot = PublishedSnapshotV1::decode(bytes).unwrap();
        let target = if snapshot.format == gemot_site::SiteFormat::Scroll {
            OutputFormat::Scroll
        } else {
            OutputFormat::Gemtext
        };
        let mut options = BuildOptions::new(target);
        options.preserve_native_bytes = true;
        let artifact = BuildRequest::from_native(&snapshot, options)
            .unwrap()
            .build()
            .unwrap();
        for page in snapshot.pages.values() {
            assert_eq!(artifact.pages[&page.metadata.path].bytes, page.source);
        }
        assert_eq!(snapshot.encode().unwrap(), bytes);
    }
    let micron = PublishedSnapshotV1::decode(include_bytes!("fixtures/micron-v1.json")).unwrap();
    assert!(BuildRequest::from_native(&micron, BuildOptions::new(OutputFormat::Html)).is_err());
}

#[test]
fn commonmark_links_code_images_and_html_template_are_explicit() {
    let mut request = project(OutputFormat::Html);
    let mut page = request.pages.remove("index.gmi").unwrap();
    page.format = SourceFormat::Markdown;
    page.metadata.path = "index.md".into();
    page.source = "# Hello\n\n## Hello\n\n## Hello 1\n\n[Next](about.gmi?source=http://a#next \"a title\")\n\n![local](assets/pixel.png)\n\n*one* **two** `three`\n\n```rust\nlet x = 1 < 2;\n```\n".into();
    request.pages.insert("index.md".into(), page);
    request.options.stylesheet = Some("assets/style.css".into());
    let artifact = request.build().unwrap();
    let html = String::from_utf8(artifact.pages["index.html"].bytes.clone()).unwrap();
    assert!(html.contains("id=\"hello\""));
    assert!(html.contains("id=\"hello-1\""));
    assert!(html.contains("id=\"hello-1-1\""));
    assert!(html.contains("href=\"about.html?source=http://a#next\" title=\"a title\""));
    assert!(html.contains("src=\"assets/pixel.png\""));
    assert!(html.contains("href=\"assets/style.css\""));
    assert!(html.contains("<em>one</em> <strong>two</strong> <code>three</code>"));
    assert!(html.contains("1 &lt; 2"));
    request.options.html_template = Some(HtmlTemplate {
        container: HtmlContainer::Main,
        banner: "<notes>".into(),
        footer: "A & B".into(),
    });
    let templated =
        String::from_utf8(request.build().unwrap().pages["index.html"].bytes.clone()).unwrap();
    assert!(templated.contains("<header>&lt;notes&gt;</header>"));
    assert!(templated.contains("<main>"));
    assert!(templated.contains("<footer>A &amp; B</footer>"));
    request.options.html_template = None;
    request.options.stylesheet = None;
    request.options.target = OutputFormat::Markdown;
    let md = request.build().unwrap();
    let md = String::from_utf8(md.pages["index.md"].bytes.clone()).unwrap();
    assert!(md.contains("about.md?source=http://a#next"));
    assert!(md.contains("\"a title\""));
    request.options.target = OutputFormat::Gemtext;
    assert!(request.build().is_err());
    request.options.reject_loss = false;
    let flattened = request.build().unwrap();
    assert!(!flattened.diagnostics.is_empty());
}

#[test]
fn unsupported_html_remote_images_and_native_syntax_do_not_silently_change_meaning() {
    let mut request = project(OutputFormat::Html);
    let page = request.pages.get_mut("index.gmi").unwrap();
    page.source = "<script>alert('x')</script>\n".into();
    page.format = SourceFormat::Markdown;
    page.metadata.path = "index.md".into();
    let page = request.pages.remove("index.gmi").unwrap();
    request.pages.insert("index.md".into(), page);
    assert!(request.build().is_err());
    request.options.reject_loss = false;
    let artifact = request.build().unwrap();
    let html = String::from_utf8(artifact.pages["index.html"].bytes.clone()).unwrap();
    assert!(!html.contains("<script>"));
    assert!(html.contains("&lt;script&gt;"));
    request.pages.get_mut("index.md").unwrap().source =
        "![private](https://example.test/pixel.png)".into();
    let html = request.build().unwrap();
    let html = String::from_utf8(html.pages["index.html"].bytes.clone()).unwrap();
    assert!(!html.contains("<img"));
    assert!(html.contains("<a href=\"https://example.test/pixel.png\""));
    request.options.allow_remote_images = true;
    assert!(
        String::from_utf8(request.build().unwrap().pages["index.html"].bytes.clone())
            .unwrap()
            .contains("<img")
    );
    request.options.target = OutputFormat::Gemtext;
    request.options.reject_loss = true;
    request.pages.get_mut("index.md").unwrap().source = "\\# literal heading".into();
    assert!(request.build().is_err());
}

#[test]
fn traversal_collisions_unresolved_links_executable_schemes_and_budgets_are_rejected() {
    let mut request = project(OutputFormat::Html);
    for url in [
        "javascript:alert(1)",
        "file:///secret",
        "../private.md",
        "missing.gmi",
        "//example.test/a",
    ] {
        request.pages.get_mut("index.gmi").unwrap().source = format!("=> {url} bad\n");
        assert!(request.build().is_err(), "{url}");
    }
    let mut request = project(OutputFormat::Html);
    request.options.max_page_bytes = 8;
    assert!(request.build().is_err());
    let mut request = project(OutputFormat::Html);
    let mut page = request.pages["index.gmi"].clone();
    page.format = SourceFormat::Markdown;
    page.metadata.path = "index.md".into();
    request.pages.insert("index.md".into(), page);
    assert!(request.build().is_err());
    let mut request = project(OutputFormat::Html);
    request.assets.insert(
        "assets/../secret".into(),
        Asset {
            media_type: "text/plain".into(),
            bytes: vec![],
        },
    );
    assert!(request.build().is_err());
    let mut request = project(OutputFormat::Html);
    request.options.preserve_native_bytes = true;
    assert!(request.build().is_err());
    let artifact = project(OutputFormat::Html).build().unwrap();
    let mut bytes = artifact.encode().unwrap();
    bytes.push(b'\n');
    assert!(GeneratedSiteV2::decode(&bytes).is_err());
}

#[test]
fn scroll_rich_structure_uses_the_protocol_parser_and_refuses_unmapped_actions() {
    let mut request = project(OutputFormat::Html);
    request.assets.clear();
    let mut page = request.pages.remove("index.gmi").unwrap();
    page.format = SourceFormat::Scroll;
    page.metadata.path = "index.scroll".into();
    page.source =
        "# Title\n\n*strong* _emphasis_ `code`\n\n* parent\n** nested\n\n>> quote\n\n---\n".into();
    request.pages.insert("index.scroll".into(), page);
    let html =
        String::from_utf8(request.build().unwrap().pages["index.html"].bytes.clone()).unwrap();
    assert!(html.contains("<strong>strong</strong> <em>emphasis</em> <code>code</code>"));
    assert!(html.matches("<ul>").count() >= 2);
    assert!(html.matches("<blockquote>").count() >= 2);
    assert!(html.contains("<hr />"));
    for source in [
        "=: titan://example.test/upload Prompt",
        "=> about.gmi Label [+Citation]",
        "##### textual",
        "* a. first",
        "* 1. one\n* 3. three",
    ] {
        request.pages.get_mut("index.scroll").unwrap().source = source.into();
        assert!(request.build().is_err(), "{source}");
    }
    request.options.target = OutputFormat::Scroll;
    request.options.preserve_native_bytes = true;
    request.pages.remove("about.gmi");
    let original = request.pages["index.scroll"].source.as_bytes().to_vec();
    assert_eq!(
        request.build().unwrap().pages["index.scroll"].bytes,
        original
    );
}

#[test]
fn scroll_output_preserves_supported_inline_nested_lists_and_line_escaping() {
    let mut request = project(OutputFormat::Scroll);
    request.assets.clear();
    request.pages.clear();
    let metadata = gemot_site::Page {
        path: "index.md".into(),
        author: String::new(),
        language: String::new(),
        classification: 0,
        published: String::new(),
        modified: String::new(),
        abstract_source: "# Title".into(),
    };
    request.pages.insert("index.md".into(),SourcePage { format:SourceFormat::Markdown,title:"Title".into(),metadata,source:"# Title\n\n**bold** *emphasis* `code`\n\n* parent\n  * child\n\n1. one\n2. two\n\n\\# literal\n\n---\n".into() });
    let bytes = request.build().unwrap().pages["index.scroll"].bytes.clone();
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.contains("*bold* _emphasis_ `code`"));
    assert!(text.contains("** child"));
    assert!(text.contains("* 1. one"));
    assert!(text.contains("\\# literal"));
    request.pages.get_mut("index.md").unwrap().source = "literal \\*stars\\*".into();
    assert!(request.build().is_err());
}
