use gemot_site_host::submission::PreparedSubmission;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::{
    fs,
    io::{Read, Write},
    sync::{Arc, atomic::{AtomicUsize, Ordering}},
    thread,
};

fn certificate() -> (tokio_rustls::TlsAcceptor, String) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let pem = cert.cert.pem();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let acceptor = gemini_protocol::server::acceptor(vec![cert.cert.der().clone()], key.into())
        .unwrap();
    (acceptor, pem)
}

async fn titan_fixture(
    listener: tokio::net::TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
    saw_application_bytes: Arc<AtomicUsize>,
) {
    let (stream, _) = listener.accept().await.unwrap();
    let mut tls = match acceptor.accept(stream).await {
        Ok(tls) => tls,
        Err(_) => return,
    };
    let mut header = Vec::new();
    let mut byte = [0u8; 1];
    while !header.ends_with(b"\r\n") {
        if tls.read_exact(&mut byte).await.is_err() {
            return;
        }
        header.push(byte[0]);
    }
    let line = String::from_utf8(header).unwrap();
    let size = line
        .split(';')
        .find_map(|part| part.strip_prefix("size=")?.trim_end_matches("\r\n").parse::<usize>().ok())
        .unwrap();
    let mut body = vec![0u8; size];
    tls.read_exact(&mut body).await.unwrap();
    saw_application_bytes.fetch_add(body.len(), Ordering::SeqCst);
    tls.write_all(b"20 text/gemini\r\naccepted\n").await.unwrap();
    tls.shutdown().await.unwrap();
}

#[test]
fn preparation_captures_saved_bytes_and_does_not_connect() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("note.gmi");
    fs::write(&path, b"saved source\n").unwrap();

    let prepared = PreparedSubmission::from_saved_file(
        &path,
        "spartan://localhost:9/note",
        "text/gemini",
    )
    .unwrap();
    fs::write(&path, b"later draft\n").unwrap();

    assert_eq!(prepared.body(), b"saved source\n");
    assert_eq!(prepared.byte_len(), 13);
    assert_eq!(prepared.target(), "spartan://localhost:9/note");
}

#[tokio::test]
async fn spartan_submission_sends_once_and_returns_redirect_without_retrying() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepts = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&accepts);
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        observed.fetch_add(1, Ordering::SeqCst);
        let mut header = Vec::new();
        let mut byte = [0u8; 1];
        while !header.ends_with(b"\r\n") {
            stream.read_exact(&mut byte).unwrap();
            header.push(byte[0]);
        }
        assert_eq!(header, format!("localhost /guestbook {}\r\n", 4).as_bytes());
        let mut body = [0u8; 4];
        stream.read_exact(&mut body).unwrap();
        assert_eq!(&body, b"sign");
        stream.write_all(b"3 /guestbook/1\r\n").unwrap();
    });

    let submission = PreparedSubmission::from_body(
        &format!("spartan://localhost:{port}/guestbook"),
        "text/plain",
        b"sign".to_vec(),
    )
    .unwrap();
    let receipt = submission.send(None).await.unwrap();
    assert_eq!(receipt.code, 3);
    assert_eq!(receipt.meta, "/guestbook/1");
    worker.join().unwrap();
    assert_eq!(accepts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn titan_trust_pin_survives_reinitialize_and_changed_cert_refuses_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let trust_path = temp.path().join("trust.json");
    gemot_site_host::submission::initialize_submission_trust(&trust_path).unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (acceptor_a, pem_a) = certificate();
    let seen_a = Arc::new(AtomicUsize::new(0));
    let server_a = tokio::spawn(titan_fixture(listener, acceptor_a, Arc::clone(&seen_a)));
    let target = format!("titan://localhost:{port}/upload");
    let first = gemini_protocol::titan::upload(
        &url::Url::parse(&target).unwrap(),
        b"first",
        "text/plain",
        None,
    )
    .await
    .unwrap();
    assert_eq!(first.code, 20);
    server_a.await.unwrap();
    assert_eq!(seen_a.load(Ordering::SeqCst), 5);
    assert!(fs::read_to_string(&trust_path).unwrap().contains("localhost"));

    gemot_site_host::submission::initialize_submission_trust(&trust_path).unwrap();
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    let (acceptor_b, pem_b) = certificate();
    assert_ne!(pem_a, pem_b);
    let seen_b = Arc::new(AtomicUsize::new(0));
    let server_b = tokio::spawn(titan_fixture(listener, acceptor_b, Arc::clone(&seen_b)));
    let error = gemini_protocol::titan::upload(
        &url::Url::parse(&target).unwrap(),
        b"second",
        "text/plain",
        None,
    )
    .await
    .unwrap_err();
    assert!(matches!(error, gemini_protocol::ClientError::CertificateChanged { .. }));
    server_b.await.unwrap();
    assert_eq!(seen_b.load(Ordering::SeqCst), 0);
}
