// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Native Gemini and Spartan lifecycle coverage for the Errand-backed listener.

use gemot_site_host::{LocalServer, LocalServerConfig, Site, SiteFormat};
use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
use std::sync::Arc;
use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

fn native_site(format: SiteFormat) -> (tempfile::TempDir, Site) {
    let temp = tempfile::tempdir().unwrap();
    let site = Site::create_for(&temp.path().join("site"), format).unwrap();
    (temp, site)
}

fn spartan_socket(address: SocketAddr) -> TcpStream {
    let stream = TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_millis(150)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
}

fn spartan_request(stream: &mut TcpStream, path: &str) {
    write!(stream, "localhost {path} 0\r\n").unwrap();
    stream.flush().unwrap();
}

fn read_to_end(stream: &mut TcpStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).unwrap();
    bytes
}

fn gemini_tls_with_timeout(
    server: &LocalServer,
    timeout: Duration,
) -> rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
    gemini_tls_at(server.address(), &server.certificate_pem, timeout)
}

fn gemini_tls_at(
    address: SocketAddr,
    certificate_pem: &str,
    timeout: Duration,
) -> rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
    let certificate = CertificateDer::from_pem_slice(certificate_pem.as_bytes()).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate).unwrap();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let tls =
        rustls::ClientConnection::new(Arc::new(config), ServerName::try_from("localhost").unwrap())
            .unwrap();
    let socket = TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap();
    socket.set_read_timeout(Some(timeout)).unwrap();
    socket.set_write_timeout(Some(timeout)).unwrap();
    rustls::StreamOwned::new(tls, socket)
}

fn gemini_tls(server: &LocalServer) -> rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
    gemini_tls_with_timeout(server, Duration::from_secs(2))
}

fn read_tls_to_end(
    stream: &mut rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    match stream.read_to_end(&mut bytes) {
        Ok(_) => bytes,
        // Errand may close a cancelled connection without a TLS close_notify.
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
            ) =>
        {
            bytes
        },
        Err(error) => panic!("TLS stream read failed: {error}"),
    }
}

fn listener_is_closed(address: SocketAddr) -> bool {
    TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_err()
}

#[test]
fn config_defaults_and_legacy_scroll_start_remain_available() {
    let config = LocalServerConfig::default();
    assert_eq!(config.max_connections, 32);
    assert_eq!(config.shutdown_grace, Duration::from_secs(5));
    assert_eq!(config.timeout, Duration::from_secs(2));

    let (_temp, scroll) = native_site(SiteFormat::Scroll);
    let server = LocalServer::start(scroll.publication().unwrap(), 0).unwrap();
    assert!(server.address().ip().is_loopback());
}

#[test]
fn configured_gemini_listener_uses_tls_and_returns_the_saved_snapshot_bytes() {
    let (_temp, site) = native_site(SiteFormat::Gemini);
    let page = site.page_path("index.gmi").unwrap();
    let saved = fs::read(&page).unwrap();
    let snapshot = site.publication().unwrap();
    let before = snapshot.to_snapshot_v1().unwrap().encode().unwrap();
    let server = LocalServer::start_with_config(snapshot, 0, LocalServerConfig::default()).unwrap();
    let address = server.address();
    let mut tls = gemini_tls(&server);
    write!(tls, "gemini://localhost:{}/\r\n", address.port()).unwrap();
    tls.flush().unwrap();
    let response = read_tls_to_end(&mut tls);
    let mut expected = b"20 text/gemini;charset=utf-8;lang=en\r\n".to_vec();
    expected.extend_from_slice(&saved);
    assert_eq!(response, expected);

    let replacement_body = b"# replacement\r\n";
    fs::write(page, replacement_body).unwrap();
    let replacement = site.publication().unwrap();
    let replacement_v1 = replacement.to_snapshot_v1().unwrap().encode().unwrap();
    assert_ne!(replacement_v1, before);
    server.replace(replacement).unwrap();
    let mut tls = gemini_tls(&server);
    write!(tls, "gemini://localhost:{}/\r\n", address.port()).unwrap();
    tls.flush().unwrap();
    let response = read_tls_to_end(&mut tls);
    let mut expected = b"20 text/gemini;charset=utf-8;lang=en\r\n".to_vec();
    expected.extend_from_slice(replacement_body);
    assert_eq!(response, expected);
    let (_other_temp, other) = native_site(SiteFormat::Scroll);
    assert!(server.replace(other.publication().unwrap()).is_err());

    assert_eq!(
        gemot_site_host::PublishedSnapshotV1::decode(&before)
            .unwrap()
            .encode()
            .unwrap(),
        before
    );
}

#[test]
fn gemini_grace_allows_a_handshaken_request_to_finish_during_stop() {
    let (_temp, site) = native_site(SiteFormat::Gemini);
    let saved = fs::read(site.page_path("index.gmi").unwrap()).unwrap();
    let config = LocalServerConfig {
        max_connections: 1,
        timeout: Duration::from_secs(5),
        shutdown_grace: Duration::from_secs(2),
    };
    let server = LocalServer::start_with_config(site.publication().unwrap(), 0, config).unwrap();
    let address = server.address();
    let mut tls = gemini_tls(&server);
    write!(tls, "gemini://localhost:{}/", address.port()).unwrap();
    tls.flush().unwrap();
    assert!(!tls.conn.is_handshaking(), "TLS handshake completed");

    let (done_tx, done_rx) = mpsc::channel();
    let stopper = thread::spawn(move || done_tx.send(server.stop()).unwrap());
    let until = Instant::now() + Duration::from_secs(1);
    while !listener_is_closed(address) && Instant::now() < until {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(listener_is_closed(address));
    tls.write_all(b"\r\n").unwrap();
    tls.flush().unwrap();
    let response = read_tls_to_end(&mut tls);
    assert!(response.starts_with(b"20 text/gemini;charset=utf-8;lang=en\r\n"));
    assert!(response.ends_with(&saved));
    assert!(
        done_rx
            .recv_timeout(Duration::from_secs(3))
            .unwrap()
            .is_ok()
    );
    stopper.join().unwrap();
}

#[test]
fn gemini_admission_cap_reuses_slot_after_an_incomplete_request_finishes() {
    let (_temp, site) = native_site(SiteFormat::Gemini);
    let saved = fs::read(site.page_path("index.gmi").unwrap()).unwrap();
    let config = LocalServerConfig {
        max_connections: 1,
        timeout: Duration::from_secs(3),
        ..LocalServerConfig::default()
    };
    let server = LocalServer::start_with_config(site.publication().unwrap(), 0, config).unwrap();
    let address = server.address();
    let mut first = gemini_tls(&server);
    write!(first, "gemini://localhost:{}/", address.port()).unwrap();
    first.flush().unwrap();
    assert!(
        !first.conn.is_handshaking(),
        "first TLS handshake completed"
    );

    let cert = server.certificate_pem.clone();
    let (ready_tx, ready_rx) = mpsc::channel();
    let (connected_tx, connected_rx) = mpsc::channel();
    let queued = thread::spawn(move || {
        let mut second = gemini_tls_at(address, &cert, Duration::from_secs(3));
        connected_tx.send(()).unwrap();
        write!(second, "gemini://localhost:{}/\r\n", address.port()).unwrap();
        second.flush().unwrap();
        ready_tx.send(second).unwrap();
    });
    connected_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(matches!(
        ready_rx.recv_timeout(Duration::from_millis(150)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));

    first.write_all(b"\r\n").unwrap();
    first.flush().unwrap();
    let first_response = read_tls_to_end(&mut first);
    assert!(first_response.ends_with(&saved));
    let mut second = ready_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    queued.join().unwrap();
    let second_response = read_tls_to_end(&mut second);
    assert!(second_response.ends_with(&saved));
}

#[test]
fn gemini_zero_grace_cancels_an_admitted_tls_carrier() {
    let (_temp, site) = native_site(SiteFormat::Gemini);
    let config = LocalServerConfig {
        shutdown_grace: Duration::ZERO,
        timeout: Duration::from_secs(10),
        ..LocalServerConfig::default()
    };
    let server = LocalServer::start_with_config(site.publication().unwrap(), 0, config).unwrap();
    let address = server.address();
    let mut tls = gemini_tls(&server);
    write!(tls, "gemini://localhost:{}/", address.port()).unwrap();
    tls.flush().unwrap();
    assert!(!tls.conn.is_handshaking(), "TLS handshake completed");

    server.stop().unwrap();
    assert!(listener_is_closed(address));
    assert!(read_tls_to_end(&mut tls).is_empty());
}

#[test]
fn gemini_request_timeout_is_independent_of_shutdown_grace() {
    let (_temp, site) = native_site(SiteFormat::Gemini);
    let config = LocalServerConfig {
        timeout: Duration::from_millis(500),
        shutdown_grace: Duration::from_secs(3),
        ..LocalServerConfig::default()
    };
    let server = LocalServer::start_with_config(site.publication().unwrap(), 0, config).unwrap();
    let mut tls = gemini_tls_with_timeout(&server, Duration::from_secs(2));
    write!(tls, "gemini://localhost:{}/", server.address().port()).unwrap();
    tls.flush().unwrap();
    assert!(!tls.conn.is_handshaking(), "TLS handshake completed");

    let started = Instant::now();
    let response = read_tls_to_end(&mut tls);
    assert!(response.is_empty());
    assert!(started.elapsed() < Duration::from_secs(2));
    server.stop().unwrap();
}

#[test]
fn configured_native_start_refuses_non_native_formats_before_bind() {
    let config = LocalServerConfig::default();
    for format in [SiteFormat::Scroll, SiteFormat::Micron] {
        let (_temp, site) = native_site(format);
        let reservation = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = reservation.local_addr().unwrap().port();
        let error = LocalServer::start_with_config(site.publication().unwrap(), port, config)
            .err()
            .expect("non-native format must be rejected");
        assert!(error.contains("only to Gemini and Spartan"), "{error}");
    }
}

#[test]
fn invalid_native_policies_are_rejected_before_bind() {
    let (_temp, site) = native_site(SiteFormat::Spartan);
    let reservation = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = reservation.local_addr().unwrap();
    for (config, expected) in [
        (
            LocalServerConfig {
                max_connections: 0,
                ..LocalServerConfig::default()
            },
            "max_connections",
        ),
        (
            LocalServerConfig {
                timeout: Duration::ZERO,
                ..LocalServerConfig::default()
            },
            "timeout",
        ),
        (
            LocalServerConfig {
                timeout: Duration::MAX,
                ..LocalServerConfig::default()
            },
            "timeout",
        ),
        (
            LocalServerConfig {
                shutdown_grace: Duration::MAX,
                ..LocalServerConfig::default()
            },
            "shutdown_grace",
        ),
    ] {
        let error =
            LocalServer::start_with_config(site.publication().unwrap(), address.port(), config)
                .err()
                .expect("invalid policy must be rejected");
        assert!(error.contains(expected), "{error}");
    }
}

#[test]
fn spartan_admission_cap_reuses_slot_after_an_incomplete_request_finishes() {
    let (_temp, site) = native_site(SiteFormat::Spartan);
    let config = LocalServerConfig {
        max_connections: 1,
        timeout: Duration::from_secs(3),
        ..LocalServerConfig::default()
    };
    let server = LocalServer::start_with_config(site.publication().unwrap(), 0, config).unwrap();
    let address = server.address();

    // The first carrier has supplied a complete request line but only part of
    // its declared body. The handler must retain its sole admission slot.
    let mut first = spartan_socket(address);
    first.write_all(b"localhost / 1\r\n").unwrap();
    first.flush().unwrap();
    let mut second = spartan_socket(address);
    spartan_request(&mut second, "/");
    let mut probe = [0; 1];
    assert!(
        matches!(second.read(&mut probe), Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut))
    );

    first.write_all(b"x").unwrap();
    first.flush().unwrap();
    first
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let first_reply = read_to_end(&mut first);
    assert_eq!(
        first_reply,
        b"4 This static site accepts read requests only\r\n"
    );
    second
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let reply = read_to_end(&mut second);
    assert!(reply.starts_with(b"2 text/gemini;charset=utf-8\r\n"));
}

#[test]
fn explicit_stop_closes_listener_and_finishes_an_admitted_spartan_request() {
    let (_temp, site) = native_site(SiteFormat::Spartan);
    let page = site.page_path("index.gmi").unwrap();
    let saved = fs::read(&page).unwrap();
    let snapshot = site.publication().unwrap();
    let snapshot_bytes = snapshot.to_snapshot_v1().unwrap().encode().unwrap();
    fs::write(&page, b"# later draft\n").unwrap();
    let config = LocalServerConfig {
        max_connections: 1,
        timeout: Duration::from_secs(3),
        ..LocalServerConfig::default()
    };
    let server = LocalServer::start_with_config(snapshot, 0, config).unwrap();
    let address = server.address();

    // Keep one request in flight by declaring one body byte and withholding it.
    let mut client = spartan_socket(address);
    client.write_all(b"localhost / 1\r\n").unwrap();
    client.flush().unwrap();
    // A second request cannot finish while the first request is still waiting
    // for its declared body byte. This also confirms the first carrier reached
    // the admission gate before shutdown begins.
    let mut queued = spartan_socket(address);
    spartan_request(&mut queued, "/");
    let mut probe = [0; 1];
    assert!(
        matches!(queued.read(&mut probe), Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut))
    );
    let (done_tx, done_rx) = mpsc::channel();
    let stopper = thread::spawn(move || {
        let result = server.stop();
        done_tx.send(result).unwrap();
    });

    // A listener shutdown is observable independently of a scheduler yield.
    let until = Instant::now() + Duration::from_secs(1);
    while !listener_is_closed(address) && Instant::now() < until {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(listener_is_closed(address));
    client.write_all(b"x").unwrap();
    client.flush().unwrap();
    let result = done_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    assert!(result.is_ok());
    stopper.join().unwrap();
    let response = read_to_end(&mut client);
    assert_eq!(
        response,
        b"4 This static site accepts read requests only\r\n"
    );
    assert_eq!(fs::read(&page).unwrap(), b"# later draft\n");
    assert_ne!(saved, fs::read(&page).unwrap());
    assert_eq!(
        gemot_site_host::PublishedSnapshotV1::decode(&snapshot_bytes)
            .unwrap()
            .encode()
            .unwrap(),
        snapshot_bytes
    );
}

#[test]
fn zero_shutdown_grace_finishes_stop_and_closes_existing_carrier() {
    let (_temp, site) = native_site(SiteFormat::Spartan);
    let config = LocalServerConfig {
        max_connections: 1,
        shutdown_grace: Duration::ZERO,
        timeout: Duration::from_secs(10),
    };
    let server = LocalServer::start_with_config(site.publication().unwrap(), 0, config).unwrap();
    let address = server.address();
    let mut stalled = spartan_socket(address);
    stalled.write_all(b"localhost / 1\r\n").unwrap();
    stalled.flush().unwrap();
    let mut queued = spartan_socket(address);
    spartan_request(&mut queued, "/");
    let mut probe = [0; 1];
    assert!(matches!(queued.read(&mut probe), Err(error) if matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )));

    let started = Instant::now();
    server.stop().unwrap();
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(listener_is_closed(address));
    stalled
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut response = Vec::new();
    let result = stalled.read_to_end(&mut response);
    assert!(response.is_empty());
    assert!(
        result.is_ok()
            || result.as_ref().is_err_and(|error| matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
            ))
    );
}

fn expired_grace_closes_carriers(format: SiteFormat, explicit: bool) {
    let (_temp, site) = native_site(format);
    let grace = Duration::from_millis(200);
    let server = LocalServer::start_with_config(
        site.publication().unwrap(),
        0,
        LocalServerConfig {
            max_connections: 1,
            shutdown_grace: grace,
            timeout: Duration::from_secs(10),
        },
    )
    .unwrap();
    let address = server.address();
    let mut queued = None;
    let mut held: Box<dyn Read> = if format == SiteFormat::Gemini {
        let mut tls = gemini_tls(&server);
        write!(tls, "gemini://localhost:{}/", address.port()).unwrap();
        tls.flush().unwrap();
        assert!(!tls.conn.is_handshaking());
        Box::new(tls)
    } else {
        let mut stream = spartan_socket(address);
        stream.write_all(b"localhost / 1\r\n").unwrap();
        let mut waiting = spartan_socket(address);
        spartan_request(&mut waiting, "/");
        assert!(matches!(waiting.read(&mut [0]), Err(error) if matches!(
            error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        )));
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        queued = Some(waiting);
        Box::new(stream)
    };
    let begin = Instant::now();
    if explicit {
        server.stop().unwrap();
    } else {
        drop(server);
    }
    assert!(begin.elapsed() >= grace, "native grace was skipped");
    assert!(
        begin.elapsed() < Duration::from_secs(3),
        "native read timeout replaced grace"
    );
    assert!(listener_is_closed(address));
    let mut bytes = Vec::new();
    match held.read_to_end(&mut bytes) {
        Ok(_) => {},
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
            ) => {},
        Err(error) => panic!("carrier remained open after joined shutdown: {error}"),
    }
    assert!(bytes.is_empty(), "incomplete request received a reply");
    if let Some(mut waiting) = queued {
        let mut bytes = Vec::new();
        match waiting.read_to_end(&mut bytes) {
            Ok(_) => {},
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                ) => {},
            Err(error) => panic!("queued peer remained open: {error}"),
        }
        assert!(bytes.is_empty(), "shutdown admitted a queued request");
    }
}

#[test]
fn explicit_stop_expires_grace_and_joins_both_native_hosts() {
    for format in [SiteFormat::Gemini, SiteFormat::Spartan] {
        expired_grace_closes_carriers(format, true);
    }
}

#[test]
fn drop_expires_grace_and_joins_both_native_hosts() {
    for format in [SiteFormat::Gemini, SiteFormat::Spartan] {
        expired_grace_closes_carriers(format, false);
    }
}

#[test]
fn spartan_body_timeout_is_independent_of_shutdown_grace() {
    let (_temp, site) = native_site(SiteFormat::Spartan);
    let server = LocalServer::start_with_config(
        site.publication().unwrap(),
        0,
        LocalServerConfig {
            timeout: Duration::from_millis(500),
            shutdown_grace: Duration::from_secs(3),
            ..LocalServerConfig::default()
        },
    )
    .unwrap();
    let mut stream = spartan_socket(server.address());
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream.write_all(b"localhost / 1\r\n").unwrap();
    let begin = Instant::now();
    assert!(read_to_end(&mut stream).is_empty());
    assert!(begin.elapsed() < Duration::from_secs(2));
    server.stop().unwrap();
}
