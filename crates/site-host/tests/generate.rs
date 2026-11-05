// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

#![cfg(feature = "generate")]

use gemot_site_host::{Site, SiteFormat, generate::*};
use std::process::Command;

#[test]
fn exported_artifact_reopens_with_exact_page_and_asset_custody_and_detects_tampering() {
    let temp = tempfile::tempdir().unwrap();
    let site = Site::create(&temp.path().join("author")).unwrap();
    let mut request = BuildRequest::from_native(
        &site.publication().unwrap().to_snapshot_v1().unwrap(),
        BuildOptions::new(OutputFormat::Html),
    )
    .unwrap();
    request.assets.insert(
        "assets/style.css".into(),
        Asset {
            media_type: "text/css".into(),
            bytes: b"body { color: navy; }\n".to_vec(),
        },
    );
    request.options.stylesheet = Some("assets/style.css".into());
    let artifact = request.build().unwrap();
    let output = temp.path().join("published");
    let receipt = export(&artifact, &output).unwrap();
    assert_eq!(receipt.artifact_digest, artifact.digest().unwrap());
    assert_eq!(open_export(&output).unwrap(), artifact);
    assert!(export(&artifact, &output).is_err());
    let page = reply(&artifact, "/").unwrap().unwrap();
    assert_eq!(page.media_type, "text/html;charset=utf-8");
    assert!(page.bytes.starts_with(b"<!doctype html>"));
    assert!(reply(&artifact, "/../secret").unwrap().is_none());
    std::fs::write(output.join("assets/style.css"), b"changed").unwrap();
    assert!(open_export(&output).is_err());
}

#[test]
fn command_line_builds_a_checked_snapshot_and_native_consumer_preserves_the_selected_protocol() {
    let temp = tempfile::tempdir().unwrap();
    let site = Site::create(&temp.path().join("author")).unwrap();
    let output = temp.path().join("html");
    let result = Command::new(env!("CARGO_BIN_EXE_site-build"))
        .args([
            "native",
            site.root().to_str().unwrap(),
            "html",
            output.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let artifact = open_export(&output).unwrap();
    assert_eq!(artifact.pages.len(), 3);
    assert_eq!(artifact.options.target, OutputFormat::Html);
    let artifact = site
        .generate(BuildOptions::new(OutputFormat::Gemtext))
        .unwrap();
    let publication = native_publication(&artifact, SiteFormat::Gemini).unwrap();
    let url = url::Url::parse("gemini://localhost/index.gmi").unwrap();
    let _reply = publication.gemini_reply(&url, 1965);
    assert_eq!(
        publication.to_snapshot_v1().unwrap().pages["/index.gmi"].source,
        artifact.pages["index.gmi"].bytes
    );
    assert!(native_publication(&artifact, SiteFormat::Scroll).is_err());
}

#[test]
fn generated_gemtext_is_delivered_over_the_existing_spartan_listener() {
    use std::io::{Read, Write};
    let temp = tempfile::tempdir().unwrap();
    let site = Site::create(&temp.path().join("source")).unwrap();
    let artifact = site
        .generate(BuildOptions::new(OutputFormat::Gemtext))
        .unwrap();
    let server = gemot_site_host::LocalServer::start(
        native_publication(&artifact, SiteFormat::Spartan).unwrap(),
        0,
    )
    .unwrap();
    let mut socket = std::net::TcpStream::connect(server.address()).unwrap();
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(3)))
        .unwrap();
    socket.write_all(b"localhost /index.gmi 0\r\n").unwrap();
    let mut response = Vec::new();
    socket.read_to_end(&mut response).unwrap();
    assert!(response.starts_with(b"2 text/gemini;charset=utf-8\r\n"));
    assert!(response.ends_with(&artifact.pages["index.gmi"].bytes));
    drop(socket);
    server.stop().unwrap();
}
