use gemot_site_host::{LocalServer, Site, SiteFormat};
use std::{
    fs,
    io::{Read, Write},
    net::TcpStream,
    time::{Duration, Instant},
};

#[test]
fn old_scroll_manifest_and_native_saved_snapshots() {
    let temp = tempfile::tempdir().unwrap();
    let scroll = Site::create(&temp.path().join("scroll")).unwrap();
    let config_path = scroll.root().join("site.json");
    let mut old: serde_json::Value =
        serde_json::from_slice(&fs::read(&config_path).unwrap()).unwrap();
    old.as_object_mut().unwrap().remove("format");
    fs::write(config_path, serde_json::to_vec(&old).unwrap()).unwrap();
    assert_eq!(
        Site::open(scroll.root()).unwrap().config.format,
        SiteFormat::Scroll
    );
    for format in [SiteFormat::Gemini, SiteFormat::Spartan, SiteFormat::Micron] {
        let site = Site::create_for(&temp.path().join(format.label()), format).unwrap();
        assert_eq!(site.config.pages.len(), 3);
        let path = site.page_path(format.index_file()).unwrap();
        if format == SiteFormat::Micron {
            let generated = String::from_utf8(fs::read(&path).unwrap()).unwrap();
            assert!(generated.starts_with(">My site\n"));
            assert!(generated.contains("`[about`:/page/about.mu]"));
            assert!(generated.contains("`[notes`:/page/notes.mu]"));
        }
        let body = "# Café\r\n``` art\r\n  * literal\r\n```\r\n=> /about.gmi About\r\n";
        fs::write(&path, body).unwrap();
        let snapshot = site.publication().unwrap();
        assert_eq!(snapshot.format, format);
        if format == SiteFormat::Gemini {
            let url = url::Url::parse("gemini://localhost:1965/").unwrap();
            fs::write(path, "later draft").unwrap();
            assert_eq!(snapshot.gemini_reply(&url, 1965).body, body.as_bytes());
            for target in [
                "gemini://elsewhere/",
                "gemini://localhost/?query",
                "gemini://localhost/#fragment",
                "gemini://localhost:1966/",
            ] {
                assert_eq!(
                    snapshot
                        .gemini_reply(&url::Url::parse(target).unwrap(), 1965)
                        .code,
                    59
                );
            }
            assert_eq!(
                snapshot
                    .gemini_reply(&url.join("site.json").unwrap(), 1965)
                    .code,
                51
            );
        }
        if format == SiteFormat::Micron {
            #[cfg(feature = "retinue")]
            {
                let server = LocalServer::start(snapshot, 0).unwrap();
                assert!(server.nomadnet_destination().is_some());
                assert!(server.url().contains("ephemeral destination"));
            }
            #[cfg(not(feature = "retinue"))]
            {
                let snapshot = snapshot.to_snapshot_v1().unwrap();
                assert_eq!(snapshot.format, SiteFormat::Micron);
                let error = match LocalServer::start(
                    gemot_site_host::Publication::from_snapshot_v1(snapshot).unwrap(),
                    0,
                ) {
                    Ok(_) => panic!("Micron serving unexpectedly found a backend"),
                    Err(error) => error,
                };
                assert!(error.contains("retinue"));
            }
        }
    }
}

fn spartan_exchange(server: &LocalServer, path: &str, body: &[u8]) -> Vec<u8> {
    let mut socket = TcpStream::connect(server.address()).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    write!(socket, "localhost {path} {}\r\n", body.len()).unwrap();
    socket.write_all(body).unwrap();
    let mut reply = Vec::new();
    socket.read_to_end(&mut reply).unwrap();
    reply
}

#[test]
fn spartan_static_site_refuses_effects_and_stops_active_connections() {
    let temp = tempfile::tempdir().unwrap();
    let site = Site::create_for(&temp.path().join("spartan"), SiteFormat::Spartan).unwrap();
    let path = site.page_path("index.gmi").unwrap();
    let before = fs::read(&path).unwrap();
    let server = LocalServer::start(site.publication().unwrap(), 0).unwrap();
    let response = spartan_exchange(&server, "/", &[]);
    assert!(response.starts_with(b"2 text/gemini;charset=utf-8\r\n"));
    assert!(response.ends_with(&before));
    assert!(spartan_exchange(&server, "/", b"untrusted upload").starts_with(b"4 "));
    assert_eq!(fs::read(&path).unwrap(), before);
    fs::write(&path, "# replacement\r\n").unwrap();
    assert!(spartan_exchange(&server, "/", &[]).ends_with(&before));
    server.replace(site.publication().unwrap()).unwrap();
    assert!(spartan_exchange(&server, "/", &[]).ends_with(b"# replacement\r\n"));
    let other = Site::create(&temp.path().join("scroll")).unwrap();
    assert!(server.replace(other.publication().unwrap()).is_err());
    let address = server.address();
    let _stalled = TcpStream::connect(address).unwrap();
    let started = Instant::now();
    drop(server);
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(TcpStream::connect(address).is_err());
}
