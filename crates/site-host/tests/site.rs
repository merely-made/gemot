// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use gemot_site_host::{CONFIG, MAX_PAGE_BYTES, Site};
use std::fs;

#[test]
fn three_linked_pages_and_native_publication_boundary() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("site");
    let mut site = Site::create(&root).unwrap();
    assert!(Site::create(&root).is_err());
    assert_eq!(site.config.pages.len(), 3);
    for page in &site.config.pages {
        let body = fs::read_to_string(root.join(&page.path)).unwrap();
        for other in &site.config.pages {
            if page != other {
                assert!(body.contains(&format!("=> /{}", other.path)));
            }
        }
    }
    let source = "# Café\r\n\r\n*bold*  _italic_\r\n=> /about.scroll About [+Citation]\r\n";
    fs::write(root.join("index.scroll"), source).unwrap();
    site.config.pages[0].author = "A Writer".into();
    site.config.pages[0].language = "fr-CA".into();
    site.config.pages[0].classification = 8;
    site.config.pages[0].published = "2026-09-11T12:00:00Z".into();
    site.config.pages[0].abstract_source = "# Café\nA short abstract.\n".into();
    site.save_config_with(|path, _, after| fs::write(path, after).map_err(|e| e.to_string()))
        .unwrap();
    let snapshot = site.publication().unwrap();
    let request = "scroll://localhost:5699/ en\r\n";
    let response = String::from_utf8(snapshot.response(request, 5699)).unwrap();
    assert_eq!(
        response,
        format!(
            "28 text/scroll;charset=utf-8;lang=fr-CA\r\nA Writer\r\n2026-09-11T12:00:00Z\r\n\r\n{source}"
        )
    );
    assert!(
        String::from_utf8(snapshot.response("scroll://localhost:5699/ +en\r\n", 5699))
            .unwrap()
            .ends_with("# Café\nA short abstract.\n")
    );
    site.config.pages[0].author = "Unsaved author".into();
    fs::write(root.join("index.scroll"), "# Later draft\n").unwrap();
    assert_eq!(snapshot.response(request, 5699), response.as_bytes());
    let replacement =
        String::from_utf8(site.publication().unwrap().response(request, 5699)).unwrap();
    assert!(replacement.ends_with("# Later draft\n"));
    assert!(replacement.contains("\r\nA Writer\r\n"));
}

#[test]
fn rejects_escape_metadata_injection_and_external_config_changes() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("site");
    let mut site = Site::create(&root).unwrap();
    let baseline = site.config.clone();
    for path in [
        "../secret.scroll",
        "C:secret.scroll",
        "hidden/file.scroll",
        ".secret.scroll",
    ] {
        site.config.pages[0].path = path.into();
        assert!(site.config.validate().is_err());
    }
    site.config = baseline.clone();
    site.config.pages[0].author = "Writer\r\nInjected".into();
    assert!(site.config.validate().is_err());
    site.config = baseline.clone();
    site.config.pages[0].language = "en;bad=1".into();
    assert!(site.config.validate().is_err());
    site.config = baseline.clone();
    site.config.pages[0].modified = "yesterday".into();
    assert!(site.config.validate().is_err());
    site.config = baseline;
    fs::write(root.join(CONFIG), "external change").unwrap();
    assert!(
        site.save_config_with(|_, _, _| panic!("must refuse before write"))
            .is_err()
    );
}

#[test]
fn scroll_response_preserves_the_site_metadata_byte_limit() {
    let temp = tempfile::tempdir().unwrap();
    let mut site = Site::create(&temp.path().join("site")).unwrap();
    // The site's public limit counts UTF-8 bytes, excluding the wire CRLF.
    let author = "é".repeat(512);
    assert_eq!(author.len(), 1024);
    site.config.pages[0].author = author.clone();
    site.save_config_with(|path, _, after| fs::write(path, after).map_err(|e| e.to_string()))
        .unwrap();
    let response = site
        .publication()
        .unwrap()
        .response("scroll://localhost:5699/ en\r\n", 5699);
    let expected = format!("24 text/scroll;charset=utf-8;lang=en\r\n{author}\r\n\r\n\r\n");
    assert!(response.starts_with(expected.as_bytes()));
    site.config.pages[0].author.push('a');
    assert!(site.config.validate().is_err());
}

#[test]
fn scroll_response_preserves_accepted_fractional_timestamp_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let mut site = Site::create(&temp.path().join("site")).unwrap();
    let published = format!("2026-10-21T20:00:00.{}Z", "0".repeat(1100));
    let modified = format!("2026-10-21T20:01:00.{}Z", "1".repeat(1200));
    site.config.pages[0].published = published.clone();
    site.config.pages[0].modified = modified.clone();
    site.save_config_with(|path, _, after| fs::write(path, after).map_err(|e| e.to_string()))
        .unwrap();
    let source = "# Saved\r\n";
    fs::write(site.root().join("index.scroll"), source).unwrap();
    let publication = site.publication().unwrap();
    let encoded = publication.to_snapshot_v1().unwrap().encode().unwrap();
    assert_eq!(
        gemot_site_host::PublishedSnapshotV1::decode(&encoded)
            .unwrap()
            .encode()
            .unwrap(),
        encoded
    );
    assert_eq!(
        publication.response("scroll://localhost:5699/ en\r\n", 5699),
        format!(
            "24 text/scroll;charset=utf-8;lang=en\r\n\r\n{published}\r\n{modified}\r\n{source}"
        )
        .as_bytes()
    );
}

#[test]
fn only_manifest_resources_can_be_requested_and_bounds_are_enforced() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("site");
    let site = Site::create(&root).unwrap();
    let snapshot = site.publication().unwrap();
    for request in [
        "scroll://elsewhere:5699/ \r\n",
        "scroll://localhost:5698/ \r\n",
        "scroll://localhost:5699/?x=y \r\n",
        "scroll://localhost:5699/;x \r\n",
        "scroll://localhost:5699/\r\n",
        "scroll://localhost:5699/ \n",
    ] {
        assert!(
            snapshot.response(request, 5699).starts_with(b"59 "),
            "{request:?}"
        );
    }
    for path in [
        "site.json",
        "assets/test.txt",
        "%2e%2e/secret",
        "missing.scroll",
    ] {
        assert!(
            snapshot
                .response(&format!("scroll://localhost:5699/{path} \r\n"), 5699)
                .starts_with(b"51 ")
        );
    }
    fs::write(root.join("notes.scroll"), vec![b'a'; MAX_PAGE_BYTES + 1]).unwrap();
    assert!(site.publication().is_err());
}

#[test]
fn loopback_tls_stop_and_snapshot_replacement() {
    use gemot_site_host::LocalServer;
    let temp = tempfile::tempdir().unwrap();
    let site = Site::create(&temp.path().join("site")).unwrap();
    let server = LocalServer::start(site.publication().unwrap(), 0).unwrap();
    assert!(server.address().ip().is_loopback());
    assert!(
        server
            .certificate_pem
            .starts_with("-----BEGIN CERTIFICATE-----")
    );
    server.replace(site.publication().unwrap()).unwrap();
    let address = server.address();
    drop(server);
    assert!(std::net::TcpStream::connect(address).is_err());
}
