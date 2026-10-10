// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Bounded Moot composition proof. Build the guest with wasm32-wasip2, then:
//! `cargo run -p gemot --example capsule-library -- run <component.wasm> <empty-root>`.
//! Run the browser build script against `<root>/site` afterward. The native
//! host is headless; the browser host is an example, not Graphshell integration.
#[path = "capsule-library/model.rs"]
mod model;
#[path = "capsule-library/native.rs"]
mod native;

use eidetic::pack::{PACK_SCHEMA, PackPartRole};
use gemot::moot::constitution::{CapabilityGrant, ConstitutionRules};
use gemot::moot::records::{
    CollectionChange, CollectionId, CollectionRef, ContributionRef, collection_cap, fauna_cap,
};
use gemot::moot::{
    AvailabilityPolicy, ErasurePolicy, KeepBound, MootAccessLevel, MootAuthorizationRequest,
    MootError, MootFile, MootId, MootMember, MootMembershipAction, MootRetentionSettings,
    PolicyRevision,
};
use identity::{IdentityProvider, InMemoryProvider};
use mien::{ChainRoot, CommitmentId, GateDecision, Scope, StandingEvent};
use model::{Catalogue, Entry, SignedPack, part};
use proofs::BlobRef;
use serde::{Deserialize, Serialize};
use servitor::{Cap, Subject, cap_path};
use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use stickleback::{DropExportProfile, DropLimits, DropRecord, read_plain_drop, write_plain_drop};
use transport::{BlobHash, BlobLease, BlobReadAuthorizer, BlobScope, BlobStore, P2pandaTransport};

type AnyError = Box<dyn Error + Send + Sync>;
const MOOT: [u8; 32] = [0x71; 32];
const COLLECTION: CollectionId = CollectionId([0x72; 32]);
const ALICE_1: &[u8] = b"# Alice's garden\n\nA tiny capsule, independently authored.\n";
const ALICE_2: &[u8] = b"# Alice's garden\n\nThe garden now has a pear tree.\n";
const BOB: &[u8] = b"# Bob's listening room\n\nA place to share music with friends.\n";

fn identity(seed: u8) -> InMemoryProvider {
    InMemoryProvider::from_seed([seed; 32])
}
fn founder() -> InMemoryProvider {
    identity(0xe5)
}
fn host() -> InMemoryProvider {
    identity(0xb2)
}
fn index_member() -> InMemoryProvider {
    identity(0xc3)
}
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
fn hash(bytes: &[u8]) -> [u8; 32] {
    *eidetic::schema::Hash::of(bytes).as_bytes()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn ensure(ok: bool, why: &str) -> Result<(), AnyError> {
    if ok { Ok(()) } else { Err(why.into()) }
}
fn write_json(path: &Path, value: &impl Serialize) -> Result<(), AnyError> {
    fs::create_dir_all(path.parent().ok_or("missing parent")?)?;
    let temp = path.with_extension("pending");
    fs::write(&temp, serde_json::to_vec_pretty(value)?)?;
    fs::rename(temp, path)?;
    Ok(())
}
fn read_json<T: for<'a> Deserialize<'a>>(path: &Path) -> Result<T, AnyError> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}
fn retention() -> MootRetentionSettings {
    MootRetentionSettings {
        revision: PolicyRevision(proofs::Digest::blake3(b"capsule-library proof")),
        availability: AvailabilityPolicy {
            promised_floor: KeepBound::Forever,
        },
        erasure: ErasurePolicy {
            history_ceiling: KeepBound::UntilCheckpoint,
        },
    }
}
async fn moot(root: &Path) -> Result<MootFile, AnyError> {
    fs::create_dir_all(root)?;
    Ok(MootFile::open(
        root,
        MootId(MOOT),
        founder().master_public_key().to_bytes(),
        retention(),
    )
    .await?)
}
fn collection() -> CollectionRef {
    CollectionRef {
        moot_id: MOOT,
        collection_id: COLLECTION,
    }
}

#[derive(Serialize, Deserialize)]
struct Published {
    pid: u32,
    full_ticket: String,
    index_ticket: String,
    full_hash: [u8; 32],
    index_hash: [u8; 32],
    component_hash: [u8; 32],
    app_pack: [u8; 32],
    replaced_share: [u8; 32],
    unauthorized_contribution_refused: bool,
    foreign_author_refused: bool,
    tampered_pack_refused: bool,
    changed_part_refused: bool,
}

async fn publish(root: &Path, component_path: &Path) -> Result<(), AnyError> {
    let source = moot(&root.join("publisher/moot")).await?;
    let alice = identity(0xa1);
    let bob = identity(0xa2);
    let owner = founder();
    let mut rules = ConstitutionRules::founder_only(owner.master_public_key().to_bytes());
    rules.admission = mien::Policy::MembersOnly {
        rate_limit: 100,
        rate_window_ms: 60_000,
    };
    for (i, member) in [&alice, &bob].into_iter().enumerate() {
        rules.grant(CapabilityGrant {
            id: [i as u8 + 1; 32],
            subject: member.master_public_key().to_bytes(),
            path_prefix: cap_path(&fauna_cap()),
            not_before_ms: 0,
            expires_at_ms: None,
            delegation_depth: 0,
        });
    }
    rules.grant(CapabilityGrant {
        id: [3; 32],
        subject: host().master_public_key().to_bytes(),
        path_prefix: cap_path(&Cap::scope("moot/hosting/capsule-library")?),
        not_before_ms: 0,
        expires_at_ms: None,
        delegation_depth: 0,
    });
    for (i, cap) in [collection_cap(collection()), fauna_cap()]
        .into_iter()
        .enumerate()
    {
        rules.grant(CapabilityGrant {
            id: [i as u8 + 4; 32],
            subject: owner.master_public_key().to_bytes(),
            path_prefix: cap_path(&cap),
            not_before_ms: 0,
            expires_at_ms: None,
            delegation_depth: 0,
        });
    }
    source
        .found([0xe5; 32], None, None, rules, now_ms())
        .await?;
    source
        .update_membership_for_identity(
            &owner,
            MootMembershipAction::Create {
                initial_members: [&owner, &alice, &bob, &host(), &index_member()]
                    .into_iter()
                    .enumerate()
                    .map(|(i, member)| MootMember {
                        member: member.master_public_key().to_bytes(),
                        access: if i == 0 {
                            MootAccessLevel::Manage
                        } else if i == 4 {
                            MootAccessLevel::Read
                        } else {
                            MootAccessLevel::Write
                        },
                    })
                    .collect(),
            },
        )
        .await?;
    source
        .declare_collection_for_identity(
            &owner,
            COLLECTION,
            "Friends' capsules".into(),
            None,
            now_ms(),
        )
        .await?;
    let component = fs::read(component_path)?;
    let app = SignedPack::new(
        &owner,
        "Capsule library",
        "1",
        vec![part(
            "library.wasm",
            PackPartRole::WasmComponent,
            &component,
        )],
        vec!["power:capsule-view".into(), "power:navigate".into()],
    );
    let packs = [
        SignedPack::new(
            &alice,
            "Alice's garden",
            "1",
            vec![part("index.gmi", PackPartRole::Asset, ALICE_1)],
            Vec::new(),
        ),
        SignedPack::new(
            &bob,
            "Bob's listening room",
            "1",
            vec![part("index.gmi", PackPartRole::Asset, BOB)],
            Vec::new(),
        ),
        SignedPack::new(
            &alice,
            "Alice's garden",
            "2",
            vec![part("index.gmi", PackPartRole::Asset, ALICE_2)],
            Vec::new(),
        ),
        app,
    ];
    let mut blobs = BTreeMap::new();
    for bytes in [ALICE_1, BOB, ALICE_2, component.as_slice()] {
        blobs.insert(hash(bytes), bytes.to_vec());
    }
    let mut shares = Vec::new();
    let owners = [&alice, &bob, &alice, &owner];
    let mut ids = Vec::new();
    for (pack, author) in packs.iter().zip(owners) {
        pack.verify(&hex(&author.master_public_key().to_bytes()), &blobs)?;
        let bytes = pack.bytes()?;
        let id = hash(&bytes);
        blobs.insert(id, bytes);
        let receipt = source
            .share_authorized_for_identity(
                author,
                id,
                PACK_SCHEMA.into(),
                pack.manifest.name.clone(),
                now_ms(),
            )
            .await?;
        shares.push(receipt.operation);
        ids.push(id);
    }
    // Select Alice v1 and Bob, then replace only the collection's Alice ref.
    // The old signed pack, payload and original Shared operation remain retained.
    for (index, included) in [(0, true), (1, true), (0, false), (2, true)] {
        let heads = source
            .authorized_collection(COLLECTION, now_ms())
            .await?
            .ok_or("collection missing")?
            .heads;
        source
            .set_collection_membership_for_identity(
                &owner,
                collection(),
                heads,
                CollectionChange::SetMembership {
                    contribution: ContributionRef {
                        moot_id: MOOT,
                        share: shares[index],
                    },
                    included,
                },
                now_ms(),
            )
            .await?;
    }
    let before = source.object_store().ops(MOOT).await?.len();
    let unauthorized_contribution_refused = matches!(
        source
            .share_authorized_for_identity(
                &identity(0xd4),
                [9; 32],
                PACK_SCHEMA.into(),
                "intruder".into(),
                now_ms()
            )
            .await,
        Err(MootError::Unauthorized(_))
    ) && source.object_store().ops(MOOT).await?.len()
        == before;
    let mut foreign = packs[2].clone();
    foreign.manifest.version = "3".into();
    foreign.trust.signatures = vec![eidetic::pack::sign_pack(
        &foreign.manifest,
        bob.master_keypair(),
    )];
    let foreign_author_refused = foreign
        .verify(&hex(&alice.master_public_key().to_bytes()), &blobs)
        .is_err();
    let mut forged = packs[2].clone();
    forged.manifest.version = "3".into();
    let tampered_pack_refused = forged
        .verify(&hex(&alice.master_public_key().to_bytes()), &blobs)
        .is_err();
    let mut changed = blobs.clone();
    changed.insert(hash(ALICE_2), b"substituted content".to_vec());
    let changed_part_refused = packs[2]
        .verify(&hex(&alice.master_public_key().to_bytes()), &changed)
        .is_err();
    ensure(
        unauthorized_contribution_refused
            && foreign_author_refused
            && tampered_pack_refused
            && changed_part_refused,
        "publisher negative control failed",
    )?;
    let mut metadata = Vec::new();
    source
        .export_plain_drop(
            &mut metadata,
            DropExportProfile::default(),
            DropLimits::default(),
        )
        .await?;
    let (_, mut records) = read_plain_drop(Cursor::new(&metadata), DropLimits::default())?;
    // export_plain_drop includes lane evidence blobs. Capsule/app payloads are
    // supplied explicitly, and absent from the separately served index drop.
    for (blob_hash, bytes) in blobs {
        records.push(DropRecord::BlobChunk {
            blob_hash,
            offset: 0,
            bytes,
        });
    }
    let mut full = Vec::new();
    write_plain_drop(&mut full, &records, DropLimits::default())?;
    let full_store = BlobStore::new();
    let full_hash = full_store.put_bytes(full).await?;
    let full_scope = BlobScope::new(MOOT);
    let full_auth = BlobReadAuthorizer::new();
    full_auth.retain(full_scope, full_hash);
    full_auth.allow_reader(full_scope, host().master_public_key().to_bytes());
    let full_transport = P2pandaTransport::builder(alice.master_keypair())
        .scoped_blobs(&full_store, full_scope, full_auth)
        .bind()
        .await?;
    let index_store = BlobStore::new();
    let index_hash = index_store.put_bytes(metadata).await?;
    let index_scope = BlobScope::new([0x73; 32]);
    let index_auth = BlobReadAuthorizer::new();
    index_auth.retain(index_scope, index_hash);
    index_auth.allow_reader(index_scope, index_member().master_public_key().to_bytes());
    let index_transport = P2pandaTransport::builder(owner.master_keypair())
        .scoped_blobs(&index_store, index_scope, index_auth)
        .bind()
        .await?;
    write_json(
        &root.join("published.json"),
        &Published {
            pid: std::process::id(),
            full_ticket: full_transport.ticket().await?,
            index_ticket: index_transport.ticket().await?,
            full_hash: full_hash.to_bytes(),
            index_hash: index_hash.to_bytes(),
            component_hash: hash(&component),
            app_pack: ids[3],
            replaced_share: shares[0],
            unauthorized_contribution_refused,
            foreign_author_refused,
            tampered_pack_refused,
            changed_part_refused,
        },
    )?;
    while !root.join("publisher-stop").exists() {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    full_transport.close().await?;
    index_transport.close().await?;
    full_store.shutdown().await?;
    index_store.shutdown().await?;
    Ok(())
}

fn blobs_from(bytes: &[u8]) -> Result<BTreeMap<[u8; 32], Vec<u8>>, AnyError> {
    let (_, records) = read_plain_drop(Cursor::new(bytes), DropLimits::default())?;
    let mut blobs = BTreeMap::new();
    for record in records {
        if let DropRecord::BlobChunk {
            blob_hash,
            offset,
            bytes,
        } = record
        {
            ensure(
                offset == 0 && hash(&bytes) == blob_hash,
                "proof requires one exact chunk per blob",
            )?;
            ensure(blobs.insert(blob_hash, bytes).is_none(), "duplicate blob")?;
        }
    }
    Ok(blobs)
}

async fn retain(root: &Path, index_only: bool) -> Result<(), AnyError> {
    let published: Published = read_json(&root.join("published.json"))?;
    let name = if index_only { "index" } else { "host" };
    let owner = if index_only { index_member() } else { host() };
    let receiving = moot(&root.join(name).join("moot")).await?;
    let store = BlobStore::open(root.join(name).join("ingress")).await?;
    let transport = P2pandaTransport::builder(owner.master_keypair())
        .bind()
        .await?;
    let ticket = if index_only {
        &published.index_ticket
    } else {
        &published.full_ticket
    };
    let peer = transport.add_peer_ticket(ticket).await?;
    let drop_hash = if index_only {
        published.index_hash
    } else {
        published.full_hash
    };
    let lease = BlobLease::new(BlobScope::new(MOOT), "proof.capsule-library", drop_hash)?;
    store
        .fetch_from_named(
            &transport,
            peer,
            BlobHash::from_bytes(drop_hash),
            lease.as_bytes(),
        )
        .await?;
    store.flush().await?;
    let bytes = store.get_bytes(BlobHash::from_bytes(drop_hash)).await?;
    receiving
        .import_plain_drop(Cursor::new(&bytes), DropLimits::default())
        .await?;
    let selection = receiving
        .authorized_collection(COLLECTION, now_ms())
        .await?
        .ok_or("imported collection missing")?;
    ensure(
        selection.effective_selected.len() == 2,
        "collection did not converge",
    )?;
    let blobs = blobs_from(&bytes)?;
    let payload_hashes = [
        hash(ALICE_1),
        hash(ALICE_2),
        hash(BOB),
        published.component_hash,
        published.app_pack,
    ];
    let no_capsule_or_applet_payloads = payload_hashes.iter().all(|id| !blobs.contains_key(id));
    let mut full_drop_refused = false;
    if index_only {
        ensure(
            no_capsule_or_applet_payloads,
            "index participant retained capsule or applet bytes",
        )?;
        let full_peer = transport.add_peer_ticket(&published.full_ticket).await?;
        full_drop_refused = store
            .fetch_from(
                &transport,
                full_peer,
                BlobHash::from_bytes(published.full_hash),
            )
            .await
            .is_err();
        ensure(
            full_drop_refused && !store.has(BlobHash::from_bytes(published.full_hash)).await?,
            "index participant fetched full drop",
        )?;
    } else {
        // Signed Standing records the distinct hosting undertaking. Full
        // production hosting bounds remain outside this proof's wire grammar.
        receiving
            .record_standing_authorized_for_identity(
                &owner,
                StandingEvent::CommitmentMade {
                    by: ChainRoot(owner.master_public_key().to_bytes()),
                    commitment: CommitmentId(drop_hash),
                    scope: Scope(format!("capsule-library/public/{}", bytes.len())),
                    cadence_ms: 3_600_000,
                    duration_ms: Some(86_400_000),
                    at_ms: now_ms(),
                },
                &Cap::scope("moot/hosting/capsule-library")?,
            )
            .await?;
    }
    write_json(
        &root.join(format!("{name}.json")),
        &serde_json::json!({
            "pid": std::process::id(), "root": hex(&owner.master_public_key().to_bytes()), "selected": selection.effective_selected,
            "received_drop": hex(&drop_hash), "received_bytes": bytes.len(), "no_capsule_or_applet_payloads": no_capsule_or_applet_payloads,
            "full_drop_refused": full_drop_refused, "graph_records": receiving.object_store().ops(MOOT).await?.len(),
        }),
    )?;
    transport.close().await?;
    store.shutdown().await?;
    Ok(())
}

async fn project(root: &Path) -> Result<(), AnyError> {
    let published: Published = read_json(&root.join("published.json"))?;
    let exited: serde_json::Value = read_json(&root.join("publisher-exited.json"))?;
    ensure(
        exited["pid"] == serde_json::json!(published.pid),
        "publisher exit receipt names another process",
    )?;
    let retained =
        MootFile::open_existing(root.join("host/moot"), MootId(MOOT), retention()).await?;
    ensure(
        retained
            .authorize_current_capability(
                &retained.membership().await?,
                &MootAuthorizationRequest {
                    subject: host().master_public_key().to_bytes(),
                    capability_path: cap_path(&Cap::scope("moot/hosting/capsule-library")?),
                    at_ms: now_ms(),
                },
            )
            .await?
            == GateDecision::Allow,
        "reopened host lacks current hosting authority",
    )?;
    ensure(
        retained.standing_store().len().await? == 1,
        "reopened host lost its Standing commitment",
    )?;
    let store = BlobStore::open(root.join("host/ingress")).await?;
    let lease = BlobLease::new(
        BlobScope::new(MOOT),
        "proof.capsule-library",
        published.full_hash,
    )?;
    ensure(
        store.lease_hash(&lease).await? == Some(BlobHash::from_bytes(published.full_hash)),
        "reopened host lost its retention lease",
    )?;
    let drop = store
        .get_bytes(BlobHash::from_bytes(published.full_hash))
        .await?;
    let blobs = blobs_from(&drop)?;
    let selected = retained
        .authorized_collection(COLLECTION, now_ms())
        .await?
        .ok_or("reopened collection missing")?;
    let fauna = retained.authorized_fauna(now_ms()).await?;
    ensure(fauna.len() == 4, "old revision or app pack lost")?;
    ensure(
        !selected
            .effective_selected
            .iter()
            .any(|s| s.share == published.replaced_share),
        "old revision still selected",
    )?;
    ensure(
        blobs.get(&hash(ALICE_1)) == Some(&ALICE_1.to_vec()),
        "old revision was destroyed",
    )?;
    let site = root.join("site");
    fs::create_dir_all(site.join("capsules"))?;
    let mut entries = Vec::new();
    let mut capsule_packs = Vec::new();
    for member in &selected.effective_selected {
        let entry = fauna
            .iter()
            .find(|e| e.op_hash == member.share)
            .ok_or("selection has no contribution")?;
        let pack_bytes = blobs
            .get(&entry.manifest_id)
            .ok_or("selected pack missing")?;
        let pack: SignedPack = serde_json::from_slice(pack_bytes)?;
        pack.verify(&hex(&entry.shared_by), &blobs)?;
        ensure(
            pack.manifest.parts.len() == 1 && pack.manifest.parts[0].role == PackPartRole::Asset,
            "not a capsule",
        )?;
        let part = &pack.manifest.parts[0];
        let body = &blobs[part.blob.0.as_bytes()];
        ensure(
            retained
                .object_store()
                .sync_store()
                .get_blob(&BlobRef::blake3(body))
                .await?
                == Some(body.clone()),
            "Moot store lost capsule bytes",
        )?;
        let revision = hex(&entry.manifest_id);
        fs::write(
            site.join("capsules").join(format!("{revision}.json")),
            pack_bytes,
        )?;
        fs::write(site.join("capsules").join(format!("{revision}.gmi")), body)?;
        entries.push(Entry {
            title: pack.manifest.name.clone(),
            author: pack.manifest.author.clone(),
            revision: revision.clone(),
            url: format!("mere://capsule/{revision}"),
            bytes: part.bytes,
        });
        capsule_packs.push(pack);
    }
    entries.sort_by(|a, b| a.title.cmp(&b.title));
    ensure(
        entries.len() == 2 && entries[0].author != entries[1].author,
        "capsule authors are not independent",
    )?;
    let app_entry = fauna
        .iter()
        .find(|e| e.manifest_id == published.app_pack)
        .ok_or("app contribution missing")?;
    fs::write(
        site.join("app-pack.json"),
        blobs.get(&published.app_pack).ok_or("app pack missing")?,
    )?;
    let app: SignedPack =
        serde_json::from_slice(blobs.get(&published.app_pack).ok_or("app pack missing")?)?;
    app.verify(&hex(&app_entry.shared_by), &blobs)?;
    let app_part = app.manifest.parts.first().ok_or("component part missing")?;
    ensure(
        app_part.role == PackPartRole::WasmComponent,
        "pack entry is not a component",
    )?;
    let component = &blobs[app_part.blob.0.as_bytes()];
    fs::write(site.join("library.wasm"), component)?;
    // Installation binds verified code to a local participant key. Artifact
    // revisions and keyholder identity are separate, as in Servitor's model.
    let native = native::run(
        component,
        entries.clone(),
        Subject(identity(0xf6).master_public_key().to_bytes()),
    )?;
    write_json(&root.join("native.json"), &native)?;
    write_json(
        &site.join("fixture.json"),
        &serde_json::json!({
            "catalogue": Catalogue { query: String::new(), entries }, "app": app, "capsule_packs": capsule_packs,
            "component_hash": hex(&published.component_hash), "app_pack_hash": hex(&published.app_pack),
            "moot": hex(&MOOT), "collection": selected.version,
            "hosting_root": hex(&host().master_public_key().to_bytes()),
            "publisher_exited": true, "proof_scope": "Same-machine example host; not Graphshell integration",
        }),
    )?;
    store.shutdown().await?;
    Ok(())
}

struct ManagedChild(Child);
impl Drop for ManagedChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
fn child(exe: &Path, args: &[&std::ffi::OsStr]) -> Result<ManagedChild, AnyError> {
    Ok(ManagedChild(
        Command::new(exe)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()?,
    ))
}
fn run_role(exe: &Path, role: &str, root: &Path) -> Result<(), AnyError> {
    let mut process = child(exe, &[role.as_ref(), root.as_os_str()])?;
    ensure(process.0.wait()?.success(), "proof child failed")
}
fn orchestrate(component: &Path, root: &Path) -> Result<(), AnyError> {
    ensure(
        !root.exists(),
        "proof root must be new; refuses to overwrite an earlier run",
    )?;
    fs::create_dir_all(root)?;
    let exe = std::env::current_exe()?;
    let mut publisher = child(
        &exe,
        &["publish".as_ref(), root.as_os_str(), component.as_os_str()],
    )?;
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while !root.join("published.json").exists() {
        ensure(
            publisher.0.try_wait()?.is_none(),
            "publisher exited before readiness",
        )?;
        ensure(
            std::time::Instant::now() < deadline,
            "publisher readiness timed out",
        )?;
        std::thread::sleep(Duration::from_millis(25));
    }
    run_role(&exe, "retain", root)?;
    run_role(&exe, "index", root)?;
    fs::write(root.join("publisher-stop"), b"stop")?;
    ensure(publisher.0.wait()?.success(), "publisher exit failed")?;
    let publisher_exit_ms = now_ms();
    write_json(
        &root.join("publisher-exited.json"),
        &serde_json::json!({ "pid": publisher.0.id(), "at_ms": publisher_exit_ms }),
    )?;
    run_role(&exe, "native", root)?;
    let published: Published = read_json(&root.join("published.json"))?;
    let host: serde_json::Value = read_json(&root.join("host.json"))?;
    let index: serde_json::Value = read_json(&root.join("index.json"))?;
    let native: serde_json::Value = read_json(&root.join("native.json"))?;
    ensure(
        host["pid"] != native["pid"]
            && host["pid"] != serde_json::json!(published.pid)
            && index["pid"] != host["pid"],
        "proof roles did not use distinct processes",
    )?;
    write_json(
        &root.join("proof.json"),
        &serde_json::json!({ "source": "capsule-library bounded composition",
        "source_blake3": { "example": hex(&hash(include_bytes!("capsule-library.rs"))),
            "model": hex(&hash(include_bytes!("capsule-library/model.rs"))),
            "native": hex(&hash(include_bytes!("capsule-library/native.rs"))),
            "guest": hex(&hash(include_bytes!("capsule-library/guest/src/lib.rs"))) },
        "publisher": published, "host": host, "index": index, "native": native, "publisher_exit_ms": publisher_exit_ms,
        "native_complete_ms": now_ms(), "author_offline_reopening_passed": true,
        "limitations": ["Authenticated loopback peers on one machine, fixture master keys as transport identities.",
            "Immutable pack versions rehearse revisions; they do not implement Eidetic's production publication lineage.",
            "Native host is headless; browser host is standalone. Graphshell/Turnstone mounting remains open.",
            "Local grants and Standing are separate from signatures and selection; production hosting bounds and historical authority proof remain open.",
            "Read-only catalogue and gemtext; no live coediting, WebRTC, Reticulum radio or cross-machine receipt."] }),
    )?;
    println!("proof={}", root.join("proof.json").display());
    println!("browser_input={}", root.join("site").display());
    Ok(())
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), AnyError> {
    let mut args = std::env::args_os().skip(1);
    let role = args
        .next()
        .ok_or("requires run/publish/retain/index/native")?;
    let path = PathBuf::from(args.next().ok_or("requires component or proof root")?);
    match role.to_str().ok_or("non-UTF8 role")? {
        "run" => orchestrate(
            &path,
            &PathBuf::from(args.next().ok_or("run requires a new proof root")?),
        ),
        "publish" => {
            publish(
                &path,
                &PathBuf::from(args.next().ok_or("publish requires component")?),
            )
            .await
        },
        "retain" => retain(&path, false).await,
        "index" => retain(&path, true).await,
        "native" => project(&path).await,
        _ => Err("unknown proof role".into()),
    }
}
