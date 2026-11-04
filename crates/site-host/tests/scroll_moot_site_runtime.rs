// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Native Scroll/TLS through independent publisher and resident processes.
//! Literal expected bytes do not use the protocol encoder under qualification.

#![cfg(feature = "runtime-acceptance")]

use gemot::moot::constitution::{CapabilityGrant, ConstitutionRules};
use gemot::moot::{
    AvailabilityPolicy, CollectionId, ErasurePolicy, KeepBound, MootAccessLevel, MootFile, MootId,
    MootMember, MootMembershipAction, MootRetentionSettings, PolicyRevision,
};
use gemot_site_host::{
    PublishedSnapshotV1, Site, SiteFormat,
    publication::{SiteBindingV1, SiteRevisionPolicy, SiteSelection},
};
use personae::{IdentityProvider, InMemoryProvider};
use proofs::Digest;
use serde_json::{Value, json};
use servitor::{Cap, cap_path};
use sha2::Digest as _;
use std::{
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use stickleback::{DropExportProfile, DropLimits};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MOOT: [u8; 32] = [81; 32];
const COLLECTION: CollectionId = CollectionId([82; 32]);
const SOURCE: &str =
    "# Café 雪\r\n\r\nSaved source: naïve, λ.\r\n=> /about.scroll À propos [+Citation]\r\n";
const ABSTRACT: &str = "# Résumé 雪\r\nA short café abstract.\r\n";
const FULL_WIRE: &str = "28 text/scroll;charset=utf-8;lang=fr-CA\r\nZoë 雪\r\n2026-09-11T12:00:00Z\r\n2026-10-21T19:30:00Z\r\n# Café 雪\r\n\r\nSaved source: naïve, λ.\r\n=> /about.scroll À propos [+Citation]\r\n";
const ABSTRACT_WIRE: &str = "28 text/scroll;charset=utf-8;lang=fr-CA\r\nZoë 雪\r\n2026-09-11T12:00:00Z\r\n2026-10-21T19:30:00Z\r\n# Résumé 雪\r\nA short café abstract.\r\n";
const NEXT_SOURCE: &str = "# Nouveau 雪\r\nSaved replacement, λ.\r\n";
const NEXT_ABSTRACT: &str = "# Nouveau résumé 雪\r\nA revised abstract.\r\n";
const NEXT_FULL_WIRE: &str = "27 text/scroll;charset=utf-8;lang=fr-CA\r\nRévisée 雪\r\n2026-09-11T12:00:00Z\r\n2026-10-21T20:00:00Z\r\n# Nouveau 雪\r\nSaved replacement, λ.\r\n";
const NEXT_ABSTRACT_WIRE: &str = "27 text/scroll;charset=utf-8;lang=fr-CA\r\nRévisée 雪\r\n2026-09-11T12:00:00Z\r\n2026-10-21T20:00:00Z\r\n# Nouveau résumé 雪\r\nA revised abstract.\r\n";
const BOUNDARY_SOURCE: &str = "# Metadata boundary 雪\r\nExact native source.\r\n";
const BOUNDARY_ABSTRACT: &str = "# Metadata abstract 雪\r\n";

fn boundary_metadata() -> (String, String) {
    let author = "é".repeat(512);
    assert_eq!(author.len(), 1024);
    // Valid UTC RFC3339 with retained fractional precision beyond the native
    // protocol encoder's default 4096-byte header cap.
    let published = format!("2026-09-11T12:00:00.{}Z", "0".repeat(5000));
    (author, published)
}

fn boundary_wire(metadata: bool) -> Vec<u8> {
    let (author, published) = boundary_metadata();
    [
        &b"29 text/scroll;charset=utf-8;lang=de-CH\r\n"[..],
        author.as_bytes(),
        b"\r\n",
        published.as_bytes(),
        b"\r\n2026-10-21T19:30:00Z\r\n",
        if metadata {
            BOUNDARY_ABSTRACT.as_bytes()
        } else {
            BOUNDARY_SOURCE.as_bytes()
        },
    ]
    .concat()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn retention() -> MootRetentionSettings {
    MootRetentionSettings {
        revision: PolicyRevision(Digest::blake3(b"scroll-resident-acceptance")),
        availability: AvailabilityPolicy {
            promised_floor: KeepBound::Forever,
        },
        erasure: ErasurePolicy {
            history_ceiling: KeepBound::UntilCheckpoint,
        },
    }
}

/// Kill and reap any fixture child if its command, output or assertions fail.
struct Process(Child);

impl Process {
    fn wait(&mut self, label: &str) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                assert!(status.success(), "{label} failed: {status}");
                return;
            }
            assert!(Instant::now() < deadline, "{label} did not exit");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

struct Resident {
    process: Process,
    input: ChildStdin,
    output: std::sync::mpsc::Receiver<Result<Value, String>>,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl Resident {
    fn launch(root: &Path, owners: &Path) -> (Self, Value) {
        let executable = std::env::var_os("DJINN_MOOT_SITE_EXE")
            .expect("Set DJINN_MOOT_SITE_EXE to the built resident executable");
        let mut process = Process(
            Command::new(executable)
                .arg(root)
                .arg(owners)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let input = process.0.stdin.take().unwrap();
        let mut output = BufReader::new(process.0.stdout.take().unwrap());
        let (tx, rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            loop {
                let mut line = Vec::new();
                let read = Read::by_ref(&mut output)
                    .take(65537)
                    .read_until(b'\n', &mut line);
                match read {
                    Ok(0) => break,
                    Ok(count) if count <= 65536 => {
                        if tx
                            .send(serde_json::from_slice(&line).map_err(|error| error.to_string()))
                            .is_err()
                        {
                            break;
                        }
                    },
                    _ => {
                        let _ = tx.send(Err("Invalid resident output".into()));
                        break;
                    },
                }
            }
        });
        let mut resident = Self {
            process,
            input,
            output: rx,
            reader: Some(reader),
        };
        let ready = resident.read();
        assert_eq!(ready["ok"], true, "{ready}");
        (resident, ready["status"].clone())
    }

    fn read(&mut self) -> Value {
        self.output
            .recv_timeout(Duration::from_secs(30))
            .expect("Resident did not reply")
            .expect("Invalid resident response")
    }

    fn send(&mut self, command: Value) -> Value {
        writeln!(self.input, "{command}").unwrap();
        self.input.flush().unwrap();
        self.read()
    }

    fn finish(mut self) -> Value {
        let reply = self.send(json!({"command":"shutdown"}));
        assert_eq!(reply["ok"], true, "{reply}");
        assert_eq!(reply["tasks"]["panicked"], 0);
        assert_eq!(reply["tasks"]["rejected"], 0);
        self.process.wait("Resident shutdown");
        reply["tasks"].clone()
    }
}

impl Drop for Resident {
    fn drop(&mut self) {
        // Release stdout's reader before joining it, including failed assertions.
        if self.process.0.try_wait().ok().flatten().is_none() {
            let _ = self.process.0.kill();
            let _ = self.process.0.wait();
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

async fn connect(
    root: &Path,
    status: &Value,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    let identity: Value =
        serde_json::from_slice(&std::fs::read(root.join("published-site-identity.json")).unwrap())
            .unwrap();
    let certificate = identity["certificate_der"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_u64().unwrap() as u8)
        .collect::<Vec<_>>();
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(certificate))
        .unwrap();
    let client = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
    let address: std::net::SocketAddr = serde_json::from_value(status["address"].clone()).unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
        connector
            .connect(
                rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                tcp,
            )
            .await
            .unwrap()
    })
    .await
    .unwrap()
}

async fn fetch(root: &Path, status: &Value, path: &str, preferences: &str) -> (Vec<u8>, [u8; 32]) {
    let address: std::net::SocketAddr = serde_json::from_value(status["address"].clone()).unwrap();
    exchange(
        root,
        status,
        &format!(
            "scroll://localhost:{}{path} {preferences}\r\n",
            address.port()
        ),
    )
    .await
}

async fn exchange(root: &Path, status: &Value, request: &str) -> (Vec<u8>, [u8; 32]) {
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut tls = connect(root, status).await;
        let fingerprint: [u8; 32] =
            sha2::Sha256::digest(tls.get_ref().1.peer_certificates().unwrap()[0].as_ref()).into();
        tls.write_all(request.as_bytes()).await.unwrap();
        let mut bytes = Vec::new();
        tls.take(65537).read_to_end(&mut bytes).await.unwrap();
        assert!(bytes.len() <= 65536, "Fixture response exceeded its bound");
        (bytes, fingerprint)
    })
    .await
    .unwrap()
}

async fn export(moot: &MootFile, path: &Path) {
    let mut file = std::fs::File::create(path).unwrap();
    moot.export_plain_drop(
        &mut file,
        DropExportProfile::default(),
        DropLimits::default(),
    )
    .await
    .unwrap();
    file.sync_all().unwrap();
}

fn publish_cli(
    root: &Path,
    replace: Option<gemot::moot::ContributionRef>,
    label: &str,
) -> (SiteSelection, PublishedSnapshotV1, PathBuf, PathBuf) {
    let records = root.join(format!("{label}.drop"));
    let snapshot_path = root.join(format!("{label}-snapshot.json"));
    let target = root.join(format!("{label}-target.json"));
    let policy = retention();
    std::fs::write(
        &target,
        serde_json::to_vec(&json!({
            "version":1,"moot_directory":root.join("author-moot"),"moot_id":MOOT,
            "content_database":root.join("author-content.redb"),
            "retention_revision":policy.revision,"availability":policy.availability,"erasure":policy.erasure,
            "collection_id":COLLECTION,"replace":replace,"title":"Scroll garden",
            "records_output":records,"snapshot_output":snapshot_path,
        }))
        .unwrap(),
    )
    .unwrap();
    let mut process = Process(
        Command::new(env!("CARGO_BIN_EXE_site-publish"))
            .arg(root.join("authored-site"))
            .arg(&target)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let mut input = process.0.stdin.take().unwrap();
    input.write_all(&[11; 32]).unwrap();
    drop(input);
    process.wait("Knot publisher");
    let mut output = Vec::new();
    process
        .0
        .stdout
        .take()
        .unwrap()
        .take(65537)
        .read_to_end(&mut output)
        .unwrap();
    assert!(
        output.len() <= 65536,
        "Publisher receipt exceeded its bound"
    );
    let receipt: Value = serde_json::from_slice(&output).unwrap();
    let selection = serde_json::from_value(receipt["selection"].clone()).unwrap();
    let raw = std::fs::read(&snapshot_path).unwrap();
    let snapshot = PublishedSnapshotV1::decode(&raw).unwrap();
    assert_eq!(snapshot.version, 1);
    assert_eq!(snapshot.format, SiteFormat::Scroll);
    assert_eq!(snapshot.encode().unwrap(), raw, "V1 bytes remain canonical");
    assert_eq!(
        serde_json::to_value(snapshot.digest().unwrap()).unwrap(),
        receipt["snapshot_digest"]
    );
    (selection, snapshot, records, snapshot_path)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires DJINN_MOOT_SITE_EXE; explicit cross-repository process receipt"]
async fn scroll_publication_reopens_and_revalidates_native_metadata_and_authority() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    let author = InMemoryProvider::from_seed([11; 32]);
    let manager = InMemoryProvider::from_seed([12; 32]);
    let author_root = author.master_public_key().to_bytes();
    let mut rules = ConstitutionRules::founder_only(author_root);
    rules.admission = mien::Policy::MembersOnly {
        rate_limit: 100,
        rate_window_ms: 1000,
    };
    rules.grant(CapabilityGrant {
        id: [43; 32],
        subject: author_root,
        path_prefix: cap_path(&Cap::scope("moot").unwrap()),
        not_before_ms: 1,
        expires_at_ms: None,
        delegation_depth: 0,
    });
    let author_moot = MootFile::open(
        root.join("author-moot"),
        MootId(MOOT),
        author_root,
        retention(),
    )
    .await
    .unwrap();
    author_moot
        .found(author.master_keypair().to_seed(), None, None, rules, 1)
        .await
        .unwrap();
    author_moot
        .update_membership_for_identity(
            &author,
            MootMembershipAction::Create {
                initial_members: vec![
                    MootMember {
                        member: author_root,
                        access: MootAccessLevel::Manage,
                    },
                    MootMember {
                        member: manager.master_public_key().to_bytes(),
                        access: MootAccessLevel::Manage,
                    },
                ],
            },
        )
        .await
        .unwrap();
    author_moot
        .declare_collection_for_identity(&author, COLLECTION, "Scroll garden".into(), None, now())
        .await
        .unwrap();
    let mut site = Site::create_for(&root.join("authored-site"), SiteFormat::Scroll).unwrap();
    std::fs::write(site.root().join("index.scroll"), SOURCE).unwrap();
    let page = &mut site.config.pages[0];
    page.author = "Zoë 雪".into();
    page.language = "fr-CA".into();
    page.classification = 8;
    page.published = "2026-09-11T12:00:00Z".into();
    page.modified = "2026-10-21T19:30:00Z".into();
    page.abstract_source = ABSTRACT.into();
    let (boundary_author, boundary_published) = boundary_metadata();
    let page = &mut site.config.pages[1];
    page.author = boundary_author;
    page.language = "de-CH".into();
    page.classification = 9;
    page.published = boundary_published;
    page.modified = "2026-10-21T19:30:00Z".into();
    page.abstract_source = BOUNDARY_ABSTRACT.into();
    std::fs::write(site.root().join("about.scroll"), BOUNDARY_SOURCE).unwrap();
    site.save_config_with(|path, _, after| std::fs::write(path, after).map_err(|e| e.to_string()))
        .unwrap();
    drop((author_moot, site, author, manager));
    let (first, first_snapshot, records_path, snapshot_path) = publish_cli(root, None, "first");
    // The publisher has exited. Its editable site path is unavailable while the
    // independently owned content replica serves and the resident restarts.
    std::fs::rename(
        root.join("authored-site"),
        root.join("offline-authored-site"),
    )
    .unwrap();
    assert!(!root.join("authored-site").exists());
    let frozen_v1 = first_snapshot.encode().unwrap();
    let host = MootFile::open(
        root.join("host-moot"),
        MootId(MOOT),
        author_root,
        retention(),
    )
    .await
    .unwrap();
    host.import_plain_drop(
        std::fs::File::open(&records_path).unwrap(),
        DropLimits::default(),
    )
    .await
    .unwrap();
    drop(host);
    let endpoint = root.join("endpoint");
    let owners_path = root.join("owners.json");
    let policy = retention();
    std::fs::write(
        &owners_path,
        serde_json::to_vec(&json!({
            "version":1,"moot_id":MOOT,"moot_directory":root.join("host-moot"),
            "content_database":root.join("host-content.redb"),
            "retention_revision":policy.revision,"availability":policy.availability,"erasure":policy.erasure,
        }))
        .unwrap(),
    )
    .unwrap();
    let (mut resident, status) = Resident::launch(&endpoint, &owners_path);
    assert!(status["address"].is_null());
    let imported =
        resident.send(json!({"command":"import","records":records_path,"snapshot":snapshot_path}));
    assert_eq!(imported["ok"], true, "{imported}");
    let binding = SiteBindingV1 {
        version: 1,
        collection: first.collection.collection,
        revision: SiteRevisionPolicy::FollowCollection,
    };
    let policy =
        json!({"port":0,"max_connections":2,"request_timeout_ms":30000,"resume_on_restart":true});
    let wrong_profile = resident.send(json!({
        "command":"configure","binding":binding,"policy":policy
    }));
    assert_eq!(wrong_profile["ok"], false);
    let unconfigured = resident.send(json!({"command":"status"}));
    assert!(unconfigured["status"]["address"].is_null());
    assert!(unconfigured["status"]["transport"].is_null());
    let configured = resident.send(json!({
        "command":"configure","transport":"scroll","binding":binding,"policy":policy
    }));
    assert_eq!(configured["ok"], true, "{configured}");
    assert_eq!(configured["status"]["transport"], "scroll");
    let started = resident.send(json!({"command":"start"}));
    assert_eq!(started["ok"], true, "{started}");
    let status = started["status"].clone();
    let (wire, fingerprint) = fetch(&endpoint, &status, "/", "ja,en").await;
    assert_eq!(wire, FULL_WIRE.as_bytes());
    assert_eq!(
        fetch(&endpoint, &status, "/index.scroll", "+en").await.0,
        ABSTRACT_WIRE.as_bytes()
    );
    assert_eq!(
        fetch(&endpoint, &status, "/", "").await.0,
        FULL_WIRE.as_bytes()
    );
    assert_eq!(
        fetch(&endpoint, &status, "/", "+").await.0,
        ABSTRACT_WIRE.as_bytes()
    );
    for (preferences, metadata) in [("en,fr", false), ("+ja,en", true)] {
        assert_eq!(
            fetch(&endpoint, &status, "/about.scroll", preferences)
                .await
                .0,
            boundary_wire(metadata)
        );
    }
    let address: std::net::SocketAddr = serde_json::from_value(status["address"].clone()).unwrap();
    let port = address.port();
    let other_port = if port == u16::MAX { port - 1 } else { port + 1 };
    for target in [
        format!("scroll://elsewhere:{port}/"),
        format!("scroll://localhost:{other_port}/"),
        format!("scroll://user:fixture@localhost:{port}/"),
        format!("scroll://localhost:{port}/?"),
        format!("scroll://localhost:{port}/#fragment"),
        format!("scroll://localhost:{port}/;parameter"),
        format!("gemini://localhost:{port}/"),
    ] {
        let refused = exchange(&endpoint, &status, &format!("{target} en\r\n"))
            .await
            .0;
        assert!(refused.starts_with(b"59 "));
        assert!(
            !refused
                .windows(SOURCE.len())
                .any(|bytes| bytes == SOURCE.as_bytes())
        );
    }
    assert_eq!(
        serde_json::to_value(fingerprint).unwrap(),
        status["certificate_sha256"]
    );
    assert_eq!(std::fs::read(&snapshot_path).unwrap(), frozen_v1);
    let first_shutdown = resident.finish();
    assert!(first_shutdown["joined"].as_u64().unwrap() >= 2);

    let (mut resident, status) = Resident::launch(&endpoint, &owners_path);
    assert_eq!(status["transport"], "scroll");
    let (wire, reopened_fingerprint) = fetch(&endpoint, &status, "/index.scroll", "en").await;
    assert_eq!(wire, FULL_WIRE.as_bytes());
    assert_eq!(reopened_fingerprint, fingerprint);
    assert_eq!(
        fetch(&endpoint, &status, "/", "+ja").await.0,
        ABSTRACT_WIRE.as_bytes()
    );
    assert!(
        fetch(&endpoint, &status, "/missing", "en")
            .await
            .0
            .starts_with(b"51 ")
    );
    assert!(
        fetch(&endpoint, &status, "/?query", "en")
            .await
            .0
            .starts_with(b"59 ")
    );
    assert!(!root.join("authored-site").exists());

    std::fs::rename(
        root.join("offline-authored-site"),
        root.join("authored-site"),
    )
    .unwrap();
    let mut site = Site::open(&root.join("authored-site")).unwrap();
    std::fs::write(site.root().join("index.scroll"), NEXT_SOURCE).unwrap();
    site.config.pages[0].author = "Révisée 雪".into();
    site.config.pages[0].classification = 7;
    site.config.pages[0].modified = "2026-10-21T20:00:00Z".into();
    site.config.pages[0].abstract_source = NEXT_ABSTRACT.into();
    site.save_config_with(|path, _, after| std::fs::write(path, after).map_err(|e| e.to_string()))
        .unwrap();
    drop(site);
    // A changed author directory alone cannot alter the resident's selected bytes.
    assert_eq!(
        fetch(&endpoint, &status, "/", "en").await.0,
        FULL_WIRE.as_bytes()
    );
    let (second, _, records_path, snapshot_path) =
        publish_cli(root, Some(first.contribution), "replacement");
    std::fs::rename(
        root.join("authored-site"),
        root.join("offline-authored-site"),
    )
    .unwrap();
    let imported =
        resident.send(json!({"command":"import","records":records_path,"snapshot":snapshot_path}));
    assert_eq!(imported["ok"], true, "{imported}");
    assert_eq!(
        fetch(&endpoint, &status, "/", "en").await.0,
        NEXT_FULL_WIRE.as_bytes()
    );
    assert_eq!(
        fetch(&endpoint, &status, "/", "+en").await.0,
        NEXT_ABSTRACT_WIRE.as_bytes()
    );

    let author = InMemoryProvider::from_seed([11; 32]);
    let manager = InMemoryProvider::from_seed([12; 32]);
    let author_moot = MootFile::open_existing(root.join("author-moot"), MootId(MOOT), retention())
        .await
        .unwrap();
    let authority_path = root.join("authority.drop");
    author_moot
        .update_membership_for_identity(
            &manager,
            MootMembershipAction::Remove {
                member: author_root,
            },
        )
        .await
        .unwrap();
    export(&author_moot, &authority_path).await;
    let imported =
        resident.send(json!({"command":"import","records":authority_path,"snapshot":null}));
    assert_eq!(imported["ok"], true, "{imported}");
    assert!(
        fetch(&endpoint, &status, "/", "en")
            .await
            .0
            .starts_with(b"51 ")
    );
    assert!(
        fetch(&endpoint, &status, "/", "+en")
            .await
            .0
            .starts_with(b"51 ")
    );
    author_moot
        .update_membership_for_identity(
            &manager,
            MootMembershipAction::Add {
                member: author_root,
                access: MootAccessLevel::Manage,
            },
        )
        .await
        .unwrap();
    export(&author_moot, &authority_path).await;
    let imported =
        resident.send(json!({"command":"import","records":authority_path,"snapshot":null}));
    assert_eq!(imported["ok"], true, "{imported}");
    assert_eq!(
        fetch(&endpoint, &status, "/", "en").await.0,
        NEXT_FULL_WIRE.as_bytes()
    );
    assert_eq!(
        fetch(&endpoint, &status, "/", "+en").await.0,
        NEXT_ABSTRACT_WIRE.as_bytes()
    );
    author_moot
        .withdraw_share_for_identity(&author, second.contribution.share, now())
        .await
        .unwrap();
    export(&author_moot, &authority_path).await;
    let imported =
        resident.send(json!({"command":"import","records":authority_path,"snapshot":null}));
    assert_eq!(imported["ok"], true, "{imported}");
    for preferences in ["en", "+en"] {
        let refused = fetch(&endpoint, &status, "/", preferences).await.0;
        assert!(refused.starts_with(b"51 "));
        for body in [NEXT_SOURCE, NEXT_ABSTRACT] {
            assert!(
                !refused
                    .windows(body.len())
                    .any(|bytes| bytes == body.as_bytes())
            );
        }
    }
    let rejected = resident.send(json!({
        "command":"configure","transport":"scroll","binding":binding,"policy":policy
    }));
    assert_eq!(rejected["ok"], false, "Running bindings cannot be replaced");
    let mut stalled = connect(&endpoint, &status).await;
    stalled.write_all(b"scroll://localhost/").await.unwrap();
    stalled.flush().await.unwrap();
    let final_shutdown = resident.finish();
    assert!(final_shutdown["cancelled"].as_u64().unwrap() > 0);
    drop(stalled);
    let (resident, status) = Resident::launch(&endpoint, &owners_path);
    assert_eq!(status["transport"], "scroll");
    assert!(status["address"].is_null());
    assert!(status["last_refusal"].is_string());
    resident.finish();
    println!(
        "{}",
        json!({
            "protocol":"scroll","publisher_processes":2,"resident_processes":3,
            "certificate_sha256":fingerprint,"first_shutdown":first_shutdown,"final_shutdown":final_shutdown,
            "full_and_abstract_exact":true,"native_metadata_exact":true,"snapshot_v1":true,
            "author_directory_unavailable":true,"replacement":true,"membership_revocation":true,"withdrawal":true,
        })
    );
}
