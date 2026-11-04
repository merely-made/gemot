// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use crate::Publication;
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

/// A process-local publication with an ephemeral localhost TLS identity.
/// Dropping this handle stops accepting clients; active reads time out.
pub struct ScrollServer {
    address: SocketAddr,
    publication: Arc<RwLock<Publication>>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
    pub certificate_pem: String,
}

impl ScrollServer {
    pub fn start(publication: Publication, port: u16) -> Result<Self, String> {
        let listener =
            TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).map_err(|e| e.to_string())?;
        let address = listener.local_addr().map_err(|e| e.to_string())?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
            .map_err(|e| e.to_string())?;
        let certificate_pem = cert.cert.pem();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key.into())
        .map_err(|e| e.to_string())?;
        let config = Arc::new(config);
        let publication = Arc::new(RwLock::new(publication));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let stop = stop.clone();
            let publication = publication.clone();
            thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((socket, _)) => {
                            // Windows accepts inherit the listener nonblocking flag.
                            if socket.set_nonblocking(false).is_err() {
                                continue;
                            }
                            let _ = socket.set_read_timeout(Some(Duration::from_millis(500)));
                            let _ = socket.set_write_timeout(Some(Duration::from_millis(500)));
                            let Ok(connection) = rustls::ServerConnection::new(config.clone())
                            else {
                                continue;
                            };
                            let mut tls = rustls::StreamOwned::new(connection, socket);
                            let mut line = Vec::new();
                            let deadline = std::time::Instant::now() + Duration::from_secs(2);
                            let mut byte = [0];
                            while line.len() < 4096
                                && !line.ends_with(b"\r\n")
                                && !stop.load(Ordering::Relaxed)
                                && std::time::Instant::now() < deadline
                            {
                                match tls.read(&mut byte) {
                                    Ok(1) => line.push(byte[0]),
                                    _ => break,
                                }
                            }
                            if let Ok(line) = std::str::from_utf8(&line) {
                                let response =
                                    publication.read().unwrap().response(line, address.port());
                                let _ = tls.write_all(&response);
                                tls.conn.send_close_notify();
                                let _ = tls.flush();
                            }
                        },
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(20))
                        },
                        Err(_) => break,
                    }
                }
            })
        };
        Ok(Self {
            address,
            publication,
            stop,
            thread: Some(thread),
            certificate_pem,
        })
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }
    pub fn url(&self) -> String {
        format!("scroll://localhost:{}/", self.address.port())
    }
    pub fn replace(&self, publication: Publication) {
        *self.publication.write().unwrap() = publication;
    }
}

impl Drop for ScrollServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
