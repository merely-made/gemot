// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Literal donor compatibility fixtures. Expected wire bytes are deliberately
//! independent of the response encoder shared with resident publishers.

use gemot_site_host::{LocalServer, Publication, PublishedSnapshotV1, Site};
use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::Arc,
    time::Duration,
};

const SOURCE: &str =
    "# Café 雪\r\n\r\nSaved source: naïve, λ.\r\n=> /about.scroll À propos [+Citation]\r\n";
const ABSTRACT: &str = "# Résumé 雪\r\nA short café abstract.\r\n";
const FULL_WIRE: &str = "28 text/scroll;charset=utf-8;lang=fr-CA\r\nZoë 雪\r\n2026-09-11T12:00:00Z\r\n2026-10-21T19:30:00Z\r\n# Café 雪\r\n\r\nSaved source: naïve, λ.\r\n=> /about.scroll À propos [+Citation]\r\n";
const ABSTRACT_WIRE: &str = "28 text/scroll;charset=utf-8;lang=fr-CA\r\nZoë 雪\r\n2026-09-11T12:00:00Z\r\n2026-10-21T19:30:00Z\r\n# Résumé 雪\r\nA short café abstract.\r\n";
const REPLACEMENT_WIRE: &str = "28 text/scroll;charset=utf-8;lang=fr-CA\r\nZoë 雪\r\n2026-09-11T12:00:00Z\r\n2026-10-21T20:00:00Z\r\n# Nouveau 雪\r\nSaved replacement.\r\n";

fn fixture() -> (tempfile::TempDir, Site, Publication) {
    let temporary = tempfile::tempdir().unwrap();
    let mut site = Site::create(&temporary.path().join("site")).unwrap();
    fs::write(site.root().join("index.scroll"), SOURCE).unwrap();
    let page = &mut site.config.pages[0];
    page.author = "Zoë 雪".into();
    page.language = "fr-CA".into();
    page.classification = 8;
    page.published = "2026-09-11T12:00:00Z".into();
    page.modified = "2026-10-21T19:30:00Z".into();
    page.abstract_source = ABSTRACT.into();
    save(&mut site);
    let publication = site.publication().unwrap();
    (temporary, site, publication)
}

fn save(site: &mut Site) {
    site.save_config_with(|path, _, after| fs::write(path, after).map_err(|e| e.to_string()))
        .unwrap();
}

fn tls_request(server: &LocalServer, request: &str) -> Vec<u8> {
    let certificate = CertificateDer::from_pem_slice(server.certificate_pem.as_bytes()).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate.clone()).unwrap();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connection =
        rustls::ClientConnection::new(Arc::new(config), ServerName::try_from("localhost").unwrap())
            .unwrap();
    let socket = TcpStream::connect_timeout(&server.address(), Duration::from_secs(2)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut tls = rustls::StreamOwned::new(connection, socket);
    tls.write_all(request.as_bytes()).unwrap();
    tls.flush().unwrap();
    let mut response = Vec::new();
    tls.read_to_end(&mut response).unwrap();
    assert_eq!(tls.conn.peer_certificates().unwrap(), &[certificate]);
    response
}

fn request(address: SocketAddr, path: &str, preferences: &str) -> String {
    format!(
        "scroll://localhost:{}{path} {preferences}\r\n",
        address.port()
    )
}

#[test]
fn literal_scroll_full_abstract_and_snapshot_v1_bytes_are_stable() {
    let (_temporary, site, publication) = fixture();
    let before = publication.to_snapshot_v1().unwrap().encode().unwrap();
    assert_eq!(PublishedSnapshotV1::decode(&before).unwrap().version, 1);
    for preferences in ["en", "ja", "fr-CA", ""] {
        assert_eq!(
            publication.response(&format!("scroll://localhost:5699/ {preferences}\r\n"), 5699),
            FULL_WIRE.as_bytes(),
            "preferences do not negotiate this single declared language"
        );
    }
    assert_eq!(
        publication.response("scroll://localhost:5699/index.scroll +en\r\n", 5699),
        ABSTRACT_WIRE.as_bytes()
    );
    assert_eq!(
        publication.to_snapshot_v1().unwrap().encode().unwrap(),
        before
    );
    assert_eq!(
        PublishedSnapshotV1::decode(&before)
            .unwrap()
            .encode()
            .unwrap(),
        before
    );
    assert_eq!(
        Site::open(site.root())
            .unwrap()
            .publication()
            .unwrap()
            .to_snapshot_v1()
            .unwrap()
            .encode()
            .unwrap(),
        before
    );
}

#[test]
fn local_tls_scroll_exact_bytes_replacement_refusal_and_listener_close() {
    let (_temporary, mut site, publication) = fixture();
    let before = publication.to_snapshot_v1().unwrap().encode().unwrap();
    let server = LocalServer::start(publication, 0).unwrap();
    let address = server.address();
    assert!(address.ip().is_loopback());
    assert_eq!(
        tls_request(&server, &request(address, "/", "ja")),
        FULL_WIRE.as_bytes()
    );
    assert_eq!(
        tls_request(&server, &request(address, "/index.scroll", "+en")),
        ABSTRACT_WIRE.as_bytes()
    );
    assert_eq!(
        tls_request(&server, &request(address, "/missing.scroll", "en")),
        b"51 Not found\r\n"
    );
    assert_eq!(
        tls_request(&server, &request(address, "/?answer=private", "en")),
        b"59 Invalid request\r\n"
    );

    // Source edits do not mutate the already installed saved snapshot.
    fs::write(
        site.root().join("index.scroll"),
        "# Nouveau 雪\r\nSaved replacement.\r\n",
    )
    .unwrap();
    site.config.pages[0].modified = "2026-10-21T20:00:00Z".into();
    save(&mut site);
    assert_eq!(
        tls_request(&server, &request(address, "/", "en")),
        FULL_WIRE.as_bytes()
    );
    assert_eq!(
        PublishedSnapshotV1::decode(&before)
            .unwrap()
            .encode()
            .unwrap(),
        before
    );
    let replacement = site.publication().unwrap();
    assert_ne!(
        replacement.to_snapshot_v1().unwrap().encode().unwrap(),
        before
    );
    server.replace(replacement).unwrap();
    assert_eq!(
        tls_request(&server, &request(address, "/", "en")),
        REPLACEMENT_WIRE.as_bytes()
    );
    assert_eq!(
        tls_request(&server, &request(address, "/", "+ja")),
        "28 text/scroll;charset=utf-8;lang=fr-CA\r\nZoë 雪\r\n2026-09-11T12:00:00Z\r\n2026-10-21T20:00:00Z\r\n# Résumé 雪\r\nA short café abstract.\r\n".as_bytes()
    );
    drop(server);
    assert!(TcpStream::connect_timeout(&address, Duration::from_millis(500)).is_err());
}
