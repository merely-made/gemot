// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Native Retinue-to-Retinue process qualification. The optional
//! TURNSTONE_MICRON_RECEIVING_TEST_EXE hook additionally qualifies Turnstone's
//! product receiving/controller path against this governed host. It does not
//! qualify headed interaction, Python/Go readers, public interfaces or radio.

#![cfg(all(feature = "runtime-acceptance", feature = "retinue"))]

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
use retinue::{
    endpoint::{Endpoint, ResourceSession},
    hash::AddressHash,
    identity::{Identity, PrivateIdentity},
    nomadnet::StaticNode,
    request::{Request, Response, StringMapLimits, StringMapRequest},
};
use serde_json::{Value, json};
use servitor::{Cap, cap_path};
use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use stickleback::{DropExportProfile, DropLimits};

const MOOT: [u8; 32] = [91; 32];
const COLLECTION: CollectionId = CollectionId([92; 32]);
const SOURCE: &[u8] = "> Café 雪\r\nSaved `!source`!\r\n`[About`:/page/about.mu]\r\n".as_bytes();
const NEXT_SOURCE: &[u8] = "> Replacement 雪\r\nExactly saved, λ.\r\n".as_bytes();

fn large_source() -> Vec<u8> {
    // V1 accepts UTF-8 source. Exercise opaque native binary/Resource transport
    // with valid UTF-8, NUL and CRLF, without broadening that model contract.
    let mut bytes = "CRLF\r\nNUL\0Unicode 雪\r\n".as_bytes().to_vec();
    let mut state = 0x1234_5678u32;
    while bytes.len() < 128 * 1024 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        bytes.push(((state >> 24) & 0x7f) as u8);
    }
    assert!(std::str::from_utf8(&bytes).is_ok());
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
        revision: PolicyRevision(Digest::blake3(b"micron-resident-acceptance")),
        availability: AvailabilityPolicy {
            promised_floor: KeepBound::Forever,
        },
        erasure: ErasurePolicy {
            history_ceiling: KeepBound::UntilCheckpoint,
        },
    }
}

/// Every fixture child is bounded, killed and reaped even after an assertion.
struct Process(Child);

impl Process {
    fn wait(&mut self, label: &str) {
        self.wait_for(label, Duration::from_secs(30));
    }

    fn wait_for(&mut self, label: &str, timeout: Duration) {
        let deadline = Instant::now() + timeout;
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

/// The optional browser test runs while this fixture owns the resident. Its
/// output is read concurrently and capped so a full pipe cannot deadlock wait.
struct BrowserProbe {
    process: Process,
    reader: Option<std::thread::JoinHandle<std::io::Result<Vec<u8>>>>,
}

impl Drop for BrowserProbe {
    fn drop(&mut self) {
        if self.process.0.try_wait().ok().flatten().is_none() {
            let _ = self.process.0.kill();
            let _ = self.process.0.wait();
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

fn browser_receiving(root: &Path, status: &Value, destination: [u8; 16]) -> bool {
    let Some(executable) = std::env::var_os("TURNSTONE_MICRON_RECEIVING_TEST_EXE") else {
        return false;
    };
    let destination = AddressHash::from_bytes(destination);
    let fixture = root.join("browser-receiving.json");
    std::fs::write(
        &fixture,
        serde_json::to_vec(&json!({
            "version":1,
            "tcp":status["address"],
            "address":format!("{destination}:/page/index.mu"),
            "expected_index":root.join("offline-authored-site/index.mu"),
            "resource_address":format!("{destination}:/page/about.mu"),
            "expected_resource":root.join("offline-authored-site/about.mu"),
        }))
        .unwrap(),
    )
    .unwrap();
    let mut process = Process(
        Command::new(executable)
            .args([
                "--ignored",
                "--exact",
                "shell::effects::nomadnet_receiving_tests::governed_djinn_native_page_reaches_product_controller",
                "--nocapture",
            ])
            .env("TURNSTONE_MICRON_RECEIVING_FIXTURE", &fixture)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("Start optional Turnstone receiving test"),
    );
    let output = process.0.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        output.take(65537).read_to_end(&mut bytes)?;
        Ok(bytes)
    });
    let mut probe = BrowserProbe {
        process,
        reader: Some(reader),
    };
    probe
        .process
        .wait_for("Turnstone browser receiving", Duration::from_secs(60));
    let output = probe.reader.take().unwrap().join().unwrap().unwrap();
    assert!(output.len() <= 65536, "Browser receiving output exceeded 64 KiB");
    let output = String::from_utf8(output).expect("Browser receiving output is UTF-8");
    assert!(
        output.contains("1 passed; 0 failed"),
        "Exact browser receiving test did not run successfully: {output}"
    );
    let proof = output
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|value| value["governed_micron_browser_receiving"] == true)
        .unwrap_or_else(|| panic!("Browser receiving proof is missing: {output}"));
    println!("{proof}");
    true
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
        if self.process.0.try_wait().ok().flatten().is_none() {
            let _ = self.process.0.kill();
            let _ = self.process.0.wait();
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

async fn connect(status: &Value) -> (Endpoint, ResourceSession, [u8; 16], Vec<u8>) {
    tokio::time::timeout(Duration::from_secs(30), async {
        assert_eq!(status["transport"], "nomadnet");
        assert!(status["certificate_sha256"].is_null());
        let destination: [u8; 16] = serde_json::from_value(status["destination"].clone()).unwrap();
        let public: Vec<u8> = serde_json::from_value(status["public_identity"].clone()).unwrap();
        let identity = Identity::from_public_bytes(public.as_slice().try_into().unwrap()).unwrap();
        let address: std::net::SocketAddr =
            serde_json::from_value(status["address"].clone()).unwrap();
        assert!(address.ip().is_loopback());
        let destination_hash = AddressHash::from_bytes(destination);
        assert_eq!(StaticNode::new().destination(&identity), destination_hash);
        let endpoint = Endpoint::new(PrivateIdentity::from_secret_bytes(&[0x73; 64]));
        endpoint.attach_tcp_client(address).await.unwrap();
        endpoint.request_path(destination_hash);
        let peer = loop {
            if let Some(peer) = endpoint.resolve(destination_hash) {
                break peer;
            }
            endpoint.next_announcement().await.unwrap();
        };
        assert_eq!(
            peer, identity,
            "Announce must prove the persisted host identity"
        );
        let session = endpoint
            .open_resource(destination_hash, peer)
            .await
            .unwrap();
        (endpoint, session, destination, public)
    })
    .await
    .expect("Native discovery and link must complete")
}

async fn raw_request(session: &mut ResourceSession, packed: &[u8]) -> Vec<u8> {
    let response = tokio::time::timeout(Duration::from_secs(30), session.request_raw(packed))
        .await
        .expect("Native request must complete")
        .unwrap();
    assert!(response.metadata.is_none());
    let decoded = Response::unpack(&response.packed).unwrap();
    assert_eq!(decoded.request_id, response.request_id);
    decoded.data
}

async fn page(session: &mut ResourceSession, path: &[u8]) -> Vec<u8> {
    raw_request(session, &Request::pack_without_data(path, 0.0)).await
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
            "collection_id":COLLECTION,"replace":replace,"title":"Micron garden",
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
    assert_eq!(snapshot.format, SiteFormat::Micron);
    assert_eq!(snapshot.encode().unwrap(), raw);
    assert_eq!(
        serde_json::to_value(snapshot.digest().unwrap()).unwrap(),
        receipt["snapshot_digest"]
    );
    (selection, snapshot, records, snapshot_path)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires DJINN_MOOT_SITE_EXE; explicit cross-repository process receipt"]
async fn micron_publication_reopens_and_revalidates_each_request_on_one_link() {
    tokio::time::timeout(Duration::from_secs(180), async {
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
            id: [53; 32],
            subject: author_root,
            path_prefix: cap_path(&Cap::scope("moot").unwrap()),
            not_before_ms: 1,
            expires_at_ms: None,
            delegation_depth: 0,
        });
        let author_moot = MootFile::open(
            root.join("author-moot"), MootId(MOOT), author_root, retention(),
        ).await.unwrap();
        author_moot.found(author.master_keypair().to_seed(), None, None, rules, 1).await.unwrap();
        author_moot.update_membership_for_identity(&author, MootMembershipAction::Create {
            initial_members: vec![
                MootMember { member: author_root, access: MootAccessLevel::Manage },
                MootMember { member: manager.master_public_key().to_bytes(), access: MootAccessLevel::Manage },
            ],
        }).await.unwrap();
        author_moot.declare_collection_for_identity(&author, COLLECTION, "Micron garden".into(), None, now()).await.unwrap();
        let site = Site::create_for(&root.join("authored-site"), SiteFormat::Micron).unwrap();
        let large = large_source();
        std::fs::write(site.root().join("index.mu"), SOURCE).unwrap();
        std::fs::write(site.root().join("about.mu"), &large).unwrap();
        std::fs::write(site.root().join("unlisted.mu"), b"not in manifest").unwrap();
        drop((site, author_moot, author, manager));
        let (first, snapshot, records, snapshot_path) = publish_cli(root, None, "first");
        let frozen_v1 = snapshot.encode().unwrap();
        std::fs::rename(root.join("authored-site"), root.join("offline-authored-site")).unwrap();
        let host = MootFile::open(root.join("host-moot"), MootId(MOOT), author_root, retention()).await.unwrap();
        host.import_plain_drop(std::fs::File::open(&records).unwrap(), DropLimits::default()).await.unwrap();
        drop(host);
        let owners = root.join("owners.json");
        let policy = retention();
        std::fs::write(&owners, serde_json::to_vec(&json!({
            "version":1,"moot_id":MOOT,"moot_directory":root.join("host-moot"),
            "content_database":root.join("host-content.redb"),
            "retention_revision":policy.revision,"availability":policy.availability,"erasure":policy.erasure,
        })).unwrap()).unwrap();
        let endpoint_root = root.join("endpoint");
        let (mut resident, status) = Resident::launch(&endpoint_root, &owners);
        assert!(status["address"].is_null());
        let imported = resident.send(json!({"command":"import","records":records,"snapshot":snapshot_path}));
        assert_eq!(imported["ok"], true, "{imported}");
        let binding = SiteBindingV1 { version:1, collection:first.collection.collection, revision:SiteRevisionPolicy::FollowCollection };
        let policy = json!({
            "port":0,"max_connections":2,"max_sessions":2,
            "session_timeout_ms":300000,"request_timeout_ms":30000,"shutdown_grace_ms":1000,
            "max_request_bytes":65536,"max_resource_bytes":262144,"resume_on_restart":true,
        });
        let wrong = resident.send(json!({"command":"configure","binding":binding,"policy":{
            "port":0,"max_connections":2,"request_timeout_ms":30000,"resume_on_restart":true,
        }}));
        assert_eq!(wrong["ok"], false);
        let configured = resident.send(json!({"command":"configure_nomadnet","binding":binding,"policy":policy}));
        assert_eq!(configured["ok"], true, "{configured}");
        let started = resident.send(json!({"command":"start"}));
        assert_eq!(started["ok"], true, "{started}");
        let status = started["status"].clone();
        let (client, mut session, destination, public_identity) = connect(&status).await;
        assert_eq!(page(&mut session, b"/page/index.mu").await, SOURCE);
        assert_eq!(page(&mut session, b"/page/about.mu").await, large);
        assert_eq!(std::fs::read(&snapshot_path).unwrap(), frozen_v1);
        assert!(!root.join("authored-site").exists());
        drop(session);
        // Dropping the native link queues its final proof/LINKCLOSE. Drain it
        // within the already-selected grace before handing this resident to
        // the browser; abrupt close can leave a host admission slot occupied.
        client
            .shutdown(Duration::from_millis(policy["shutdown_grace_ms"].as_u64().unwrap()))
            .await;
        let browser_receiving_qualified = browser_receiving(root, &status, destination);
        let first_shutdown = resident.finish();
        assert!(first_shutdown["joined"].as_u64().unwrap() >= 1);

        let (mut resident, status) = Resident::launch(&endpoint_root, &owners);
        let address: std::net::SocketAddr = serde_json::from_value(status["address"].clone()).unwrap();
        let (client, mut session, reopened_destination, reopened_public) = connect(&status).await;
        assert_eq!(reopened_destination, destination);
        assert_eq!(reopened_public, public_identity);
        let link = session.link_id();
        assert_eq!(page(&mut session, b"/page/index.mu").await, SOURCE);
        // Both native nil and empty binary values are inert reads.
        assert_eq!(raw_request(&mut session, &Request::new(b"/page/index.mu", vec![], 0.0).pack()).await, SOURCE);
        for path in [b"/index.mu".as_slice(), b"/page/", b"/", b"/page/missing.mu", b"/page/unlisted.mu", b"/file/index.mu"] {
            assert!(page(&mut session, path).await.is_empty());
        }
        assert!(raw_request(&mut session, &Request::new(b"/page/index.mu", b"effect".to_vec(), 0.0).pack()).await.is_empty());
        for values in [BTreeMap::new(), BTreeMap::from([("field_value".into(), "must not submit".into())])] {
            let packed = StringMapRequest::new(b"/page/index.mu", values, 0.0).pack(StringMapLimits::default()).unwrap();
            assert!(raw_request(&mut session, &packed).await.is_empty());
        }
        assert_eq!(page(&mut session, b"/page/index.mu").await, SOURCE);
        assert_eq!(session.link_id(), link);
        assert_eq!(std::fs::read(&snapshot_path).unwrap(), frozen_v1);
        assert_eq!(std::fs::read(root.join("offline-authored-site/index.mu")).unwrap(), SOURCE);

        std::fs::rename(root.join("offline-authored-site"), root.join("authored-site")).unwrap();
        std::fs::write(root.join("authored-site/index.mu"), NEXT_SOURCE).unwrap();
        assert_eq!(page(&mut session, b"/page/index.mu").await, SOURCE, "Drafts cannot alter selected bytes");
        let (second, replacement, records, snapshot_path) = publish_cli(root, Some(first.contribution), "replacement");
        let frozen_replacement = replacement.encode().unwrap();
        std::fs::rename(root.join("authored-site"), root.join("offline-authored-site")).unwrap();
        let imported = resident.send(json!({"command":"import","records":records,"snapshot":snapshot_path}));
        assert_eq!(imported["ok"], true, "{imported}");
        assert_eq!(page(&mut session, b"/page/index.mu").await, NEXT_SOURCE);
        assert_eq!(page(&mut session, b"/page/about.mu").await, large);
        assert_eq!(session.link_id(), link);

        let author = InMemoryProvider::from_seed([11;32]);
        let manager = InMemoryProvider::from_seed([12;32]);
        let author_moot = MootFile::open_existing(root.join("author-moot"), MootId(MOOT), retention()).await.unwrap();
        let authority = root.join("authority.drop");
        author_moot.update_membership_for_identity(&manager, MootMembershipAction::Remove { member:author_root }).await.unwrap();
        export(&author_moot, &authority).await;
        assert_eq!(resident.send(json!({"command":"import","records":authority,"snapshot":null}))["ok"], true);
        assert!(page(&mut session, b"/page/index.mu").await.is_empty());
        assert!(page(&mut session, b"/page/about.mu").await.is_empty());
        assert_eq!(session.link_id(), link);
        let revoked = resident.send(json!({"command":"status"}));
        assert!(revoked["status"]["last_refusal"].is_string());

        author_moot.update_membership_for_identity(&manager, MootMembershipAction::Add { member:author_root, access:MootAccessLevel::Manage }).await.unwrap();
        export(&author_moot, &authority).await;
        assert_eq!(resident.send(json!({"command":"import","records":authority,"snapshot":null}))["ok"], true);
        assert_eq!(page(&mut session, b"/page/index.mu").await, NEXT_SOURCE);
        assert_eq!(page(&mut session, b"/page/about.mu").await, large);
        assert_eq!(session.link_id(), link);
        assert!(resident.send(json!({"command":"status"}))["status"]["last_refusal"].is_null());

        author_moot.withdraw_share_for_identity(&author, second.contribution.share, now()).await.unwrap();
        export(&author_moot, &authority).await;
        assert_eq!(resident.send(json!({"command":"import","records":authority,"snapshot":null}))["ok"], true);
        assert!(page(&mut session, b"/page/index.mu").await.is_empty());
        assert!(page(&mut session, b"/page/about.mu").await.is_empty());
        assert_eq!(session.link_id(), link);
        assert_eq!(std::fs::read(&snapshot_path).unwrap(), frozen_replacement);
        assert!(!root.join("authored-site").exists());
        assert_eq!(std::fs::read(root.join("offline-authored-site/index.mu")).unwrap(), NEXT_SOURCE);
        let rejected = resident.send(json!({"command":"configure_nomadnet","binding":binding,"policy":policy}));
        assert_eq!(rejected["ok"], false, "Running bindings cannot be replaced");
        // This admitted and proven link now stalls waiting for its next request.
        // Shutdown must cancel and join that work before returning and exiting.
        let final_shutdown = resident.finish();
        assert!(final_shutdown["cancelled"].as_u64().unwrap() > 0);
        assert!(final_shutdown["joined"].as_u64().unwrap() >= 1);
        assert!(std::net::TcpStream::connect(address).is_err());
        let stopped_request = tokio::time::timeout(Duration::from_secs(5), session.request(&Request::new(b"/page/index.mu", vec![], 0.0))).await;
        // A native client may retain its route until its own request deadline.
        // Process join and listener closure above prove physical host shutdown;
        // the old link must yield no successful response inside this bound.
        assert!(!matches!(stopped_request, Ok(Ok(_))));
        drop(session);
        client.close();
        let (resident, status) = Resident::launch(&endpoint_root, &owners);
        assert_eq!(status["transport"], "nomadnet");
        assert!(status["address"].is_null());
        assert!(status["last_refusal"].is_string());
        resident.finish();
        println!("{}", json!({
            "transport":"nomadnet","publisher_processes":2,"resident_processes":3,
            "destination":destination,"public_identity":public_identity,
            "first_shutdown":first_shutdown,"final_shutdown":final_shutdown,
            "native_page_bytes_exact":true,"resource_body_bytes":large.len(),"snapshot_v1":true,
            "author_directory_unavailable":true,"submission_maps_refused":true,
            "one_link_authority_transitions":true,"replacement":true,"membership_revocation":true,"restoration":true,"withdrawal":true,
            "browser_receiving_qualified":browser_receiving_qualified,
            "independent_python_go_browser_radio_qualified":false,
        }));
    }).await.expect("Micron process fixture must finish within its whole-case bound");
}
