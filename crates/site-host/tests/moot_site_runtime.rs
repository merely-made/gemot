// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Real Gemini/TLS against independent resident processes and separately held
//! signed Moot/content stores. No renderer, peer discovery or remote network.

#![cfg(feature = "runtime-acceptance")]
use gemot::moot::constitution::{CapabilityGrant, ConstitutionRules};
use gemot::moot::{
    AvailabilityPolicy, CollectionId, ErasurePolicy, KeepBound, MootAccessLevel, MootFile, MootId,
    MootMember, MootMembershipAction, MootRetentionSettings, PolicyRevision,
};
use gemot_site_host::Site;
use gemot_site_host::{
    PublishedSnapshotV1, SiteFormat,
    publication::{SiteBindingV1, SiteRevisionPolicy, SiteSelection},
};
use personae::{IdentityProvider, InMemoryProvider};
use proofs::Digest;
use serde_json::{Value, json};
use servitor::{Cap, cap_path};
use sha2::Digest as _;
use std::{
    io::{BufRead, BufReader, Read, Write},
    path::Path,
    process::{Child, ChildStdin, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use stickleback::{DropExportProfile, DropLimits};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MOOT: [u8; 32] = [71; 32];
const COLLECTION: CollectionId = CollectionId([72; 32]);

fn success_wire(body: &[u8]) -> Vec<u8> {
    let mut bytes = b"20 text/gemini;charset=utf-8;lang=en\r\n".to_vec();
    bytes.extend_from_slice(body);
    bytes
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
fn retention() -> MootRetentionSettings {
    MootRetentionSettings {
        revision: PolicyRevision(Digest::blake3(b"gemini-resident-acceptance")),
        availability: AvailabilityPolicy {
            promised_floor: KeepBound::Forever,
        },
        erasure: ErasurePolicy {
            history_ceiling: KeepBound::UntilCheckpoint,
        },
    }
}

struct Resident {
    child: Child,
    input: ChildStdin,
    output: std::sync::mpsc::Receiver<Result<Value, String>>,
    reader: Option<std::thread::JoinHandle<()>>,
}
impl Resident {
    fn launch(root: &Path, owners: &Path) -> (Self, Value) {
        let executable = std::env::var_os("DJINN_MOOT_SITE_EXE")
            .expect("Set DJINN_MOOT_SITE_EXE to the built resident executable");
        let mut child = Command::new(executable)
            .arg(root)
            .arg(owners)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        let (tx, rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            loop {
                let mut line = Vec::new();
                let read = std::io::Read::by_ref(&mut output)
                    .take(65537)
                    .read_until(b'\n', &mut line);
                match read {
                    Ok(0) => break,
                    Ok(count) if count <= 65536 => {
                        if tx
                            .send(serde_json::from_slice(&line).map_err(|e| e.to_string()))
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
            child,
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
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(Instant::now() < deadline, "Resident did not join its tasks");
            std::thread::sleep(Duration::from_millis(10));
        }
        reply["tasks"].clone()
    }
}
impl Drop for Resident {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
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
        .map(|v| v.as_u64().unwrap() as u8)
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
async fn fetch(root: &Path, status: &Value, path: &str) -> (Vec<u8>, [u8; 32]) {
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut tls = connect(root, status).await;
        let fingerprint: [u8; 32] =
            sha2::Sha256::digest(tls.get_ref().1.peer_certificates().unwrap()[0].as_ref()).into();
        let address: std::net::SocketAddr =
            serde_json::from_value(status["address"].clone()).unwrap();
        tls.write_all(format!("gemini://localhost:{}{path}\r\n", address.port()).as_bytes())
            .await
            .unwrap();
        let mut bytes = Vec::new();
        tls.read_to_end(&mut bytes).await.unwrap();
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
) -> (
    SiteSelection,
    PublishedSnapshotV1,
    std::path::PathBuf,
    std::path::PathBuf,
) {
    let records = root.join(format!("{label}.drop"));
    let snapshot_path = root.join(format!("{label}-snapshot.json"));
    let target = root.join(format!("{label}-target.json"));
    let policy = retention();
    std::fs::write(&target,serde_json::to_vec(&json!({
        "version":1,"moot_directory":root.join("author-moot"),"moot_id":MOOT,
        "content_database":root.join("author-content.redb"),
        "retention_revision":policy.revision,"availability":policy.availability,"erasure":policy.erasure,
        "collection_id":COLLECTION,"replace":replace,"title":"Garden",
        "records_output":records,"snapshot_output":snapshot_path,
    })).unwrap()).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_site-publish"))
        .arg(root.join("authored-site"))
        .arg(&target)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    input.write_all(&[11; 32]).unwrap();
    drop(input);
    let result = child.wait_with_output().unwrap();
    assert!(result.status.success(), "Knot publisher failed");
    let receipt: Value = serde_json::from_slice(&result.stdout).unwrap();
    let selection: SiteSelection = serde_json::from_value(receipt["selection"].clone()).unwrap();
    let snapshot = PublishedSnapshotV1::decode(&std::fs::read(&snapshot_path).unwrap()).unwrap();
    assert_eq!(
        serde_json::to_value(snapshot.digest().unwrap()).unwrap(),
        receipt["snapshot_digest"]
    );
    (selection, snapshot, records, snapshot_path)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires DJINN_MOOT_SITE_EXE; explicit cross-repository process receipt"]
async fn knot_publication_reopens_in_resident_and_revalidates_live_authority() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let author = InMemoryProvider::from_seed([11; 32]);
    let manager = InMemoryProvider::from_seed([12; 32]);
    let author_root = author.master_public_key().to_bytes();
    let mut rules = ConstitutionRules::founder_only(author_root);
    rules.admission = mien::Policy::MembersOnly {
        rate_limit: 100,
        rate_window_ms: 1000,
    };
    rules.grant(CapabilityGrant {
        id: [41; 32],
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
        .declare_collection_for_identity(&author, COLLECTION, "Garden".into(), None, now())
        .await
        .unwrap();
    let site = Site::create_for(&root.join("authored-site"), SiteFormat::Gemini).unwrap();
    let first_bytes = b"# First saved page\r\n";
    std::fs::write(site.root().join("index.gmi"), first_bytes).unwrap();
    drop((author_moot, site, author, manager));
    let (first, _, records_path, snapshot_path) = publish_cli(root, None, "first");
    // Bootstrap the independent replica from signed public authority evidence.
    // The resident never receives the author's signing seed or editor directory.
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
    let retained_policy = retention();
    std::fs::write(&owners_path,serde_json::to_vec(&json!({
        "version":1,"moot_id":MOOT,"moot_directory":root.join("host-moot"),"content_database":root.join("host-content.redb"),
        "retention_revision":retained_policy.revision,"availability":retained_policy.availability,"erasure":retained_policy.erasure,
    })).unwrap()).unwrap();
    let (mut resident, status) = Resident::launch(&endpoint, &owners_path);
    assert!(status["address"].is_null());
    assert_eq!(
        resident.send(json!({"command":"import","records":records_path,"snapshot":snapshot_path}))
            ["ok"],
        true
    );
    let binding = SiteBindingV1 {
        version: 1,
        collection: first.collection.collection,
        revision: SiteRevisionPolicy::FollowCollection,
    };
    let policy =
        json!({"port":0,"max_connections":2,"request_timeout_ms":30000,"resume_on_restart":true});
    let configured =
        resident.send(json!({"command":"configure","binding":binding,"policy":policy}));
    assert_eq!(configured["ok"], true, "{configured}");
    let started = resident.send(json!({"command":"start"}));
    assert_eq!(started["ok"], true, "{started}");
    let status = started["status"].clone();
    let (wire, fingerprint) = fetch(&endpoint, &status, "/").await;
    assert_eq!(wire, success_wire(first_bytes));
    assert_eq!(
        serde_json::to_value(fingerprint).unwrap(),
        status["certificate_sha256"]
    );
    let first_shutdown = resident.finish();
    assert!(first_shutdown["joined"].as_u64().unwrap() > 0);
    let (mut resident, status) = Resident::launch(&endpoint, &owners_path);
    let (wire, reopened_fingerprint) = fetch(&endpoint, &status, "/index.gmi").await;
    assert_eq!(wire, success_wire(first_bytes));
    assert_eq!(reopened_fingerprint, fingerprint);
    assert!(
        fetch(&endpoint, &status, "/missing")
            .await
            .0
            .starts_with(b"51 ")
    );
    assert!(
        fetch(&endpoint, &status, "/?query")
            .await
            .0
            .starts_with(b"59 ")
    );
    let second_bytes = b"# Saved replacement\r\n";
    std::fs::write(root.join("authored-site/index.gmi"), second_bytes).unwrap();
    let (second, _, records_path, snapshot_path) =
        publish_cli(root, Some(first.contribution), "replacement");
    let result =
        resident.send(json!({"command":"import","records":records_path,"snapshot":snapshot_path}));
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(
        fetch(&endpoint, &status, "/").await.0,
        success_wire(second_bytes)
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
    let result =
        resident.send(json!({"command":"import","records":authority_path,"snapshot":null}));
    assert_eq!(result["ok"], true, "{result}");
    assert!(fetch(&endpoint, &status, "/").await.0.starts_with(b"51 "));
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
    let result =
        resident.send(json!({"command":"import","records":authority_path,"snapshot":null}));
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(
        fetch(&endpoint, &status, "/").await.0,
        success_wire(second_bytes)
    );
    author_moot
        .withdraw_share_for_identity(&author, second.contribution.share, now())
        .await
        .unwrap();
    export(&author_moot, &authority_path).await;
    let result =
        resident.send(json!({"command":"import","records":authority_path,"snapshot":null}));
    assert_eq!(result["ok"], true, "{result}");
    let refused = fetch(&endpoint, &status, "/").await.0;
    assert!(refused.starts_with(b"51 "));
    assert!(
        !refused
            .windows(second_bytes.len())
            .any(|bytes| bytes == second_bytes)
    );
    let bad = resident.send(json!({"command":"configure","binding":binding,"policy":policy}));
    assert_eq!(bad["ok"], false);
    let stalled = connect(&endpoint, &status).await;
    let final_shutdown = resident.finish();
    assert!(final_shutdown["cancelled"].as_u64().unwrap() > 0);
    drop(stalled);
    let (resident, status) = Resident::launch(&endpoint, &owners_path);
    assert!(status["address"].is_null());
    assert!(status["last_refusal"].is_string());
    resident.finish();
    println!(
        "{}",
        json!({"publisher_processes":2,"resident_processes":3,"certificate_sha256":fingerprint,"first_shutdown":first_shutdown,"final_shutdown":final_shutdown,"replacement":true,"membership_revocation":true,"withdrawal":true})
    );
}
