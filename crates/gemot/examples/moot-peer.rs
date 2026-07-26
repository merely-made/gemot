// Copyright 2026 Mark AB (markik)
// SPDX-License-Identifier: MIT OR Apache-2.0

//! moot-peer — the moot-object M1 rehearsal bin.
//!
//! Declare a moot, join it, share an engram reference into its fauna, and
//! watch the roster converge across devices — the moot-tier mirror of
//! `mesh-peer`. Both modes print the live roster and real sync status.
//!
//! ```text
//! moot-peer declare <name> <charter…> [--peer <ticket>]
//! moot-peer join <display-name> [--peer <ticket>]
//! moot-peer share <manifest-hex32> <schema-id> <title…> [--peer <ticket>]
//! moot-peer show [--peer <ticket>]
//!
//! env:
//!   MOOT_SPACE  shared passphrase naming the moot (hashed to the moot id);
//!               every participating device sets the same value
//!   MOOT_SEED   this device's identity seed string; distinct per device
//!   MOOT_DB     optional redb path for a durable store (default temporary)
//! ```
//!
//! Each mode prints this device's ticket; paste a peer's ticket on stdin
//! (or pass `--peer`) — both ways for the fast live lane. `declare`/`join`/
//! `share` author the event then stay up watching the roster; `show` just
//! watches.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gemot::moot::{MootEvent, MootExt, MootLogId, MootRoster, MootStoreFile, verify};
use identity::{Ed25519Keypair, IdentityProvider, InMemoryProvider};
use murm_replication::JoinedSpace;
use p2panda_core::{Hash, Operation, Topic};
use tokio::io::{AsyncBufReadExt, BufReader};
use transport::P2pandaTransport;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn hex8(bytes: &[u8]) -> String {
    bytes.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

fn env_hash(var: &str) -> Result<[u8; 32], String> {
    let value = std::env::var(var).map_err(|_| format!("set {var} (any string)"))?;
    Ok(*Hash::digest(value.as_bytes()).as_bytes())
}

fn parse_hex32(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim().trim_start_matches("blake3:");
    if s.len() != 64 {
        return Err("manifest id must be 64 hex chars (32 bytes)".to_string());
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16).ok_or("bad hex")?;
        let lo = (chunk[1] as char).to_digit(16).ok_or("bad hex")?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Ok(out)
}

enum Mode {
    Declare {
        name: String,
        charter: String,
    },
    Join {
        name: String,
    },
    Share {
        manifest_id: [u8; 32],
        schema_id: String,
        title: String,
    },
    Show,
}

fn parse_args() -> Result<(Mode, Vec<String>), String> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut peer_tickets = Vec::new();
    // Pull --peer pairs out wherever they appear.
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--peer" {
            args.remove(i);
            if i < args.len() {
                peer_tickets.push(args.remove(i));
            } else {
                return Err("--peer needs a ticket".to_string());
            }
        } else {
            i += 1;
        }
    }
    let usage = "usage: moot-peer declare <name> <charter…> | join <name> | \
                 share <manifest-hex32> <schema-id> <title…> | show  [--peer <ticket>]";
    let mode = match args.first().map(String::as_str) {
        Some("declare") => {
            let name = args.get(1).ok_or(usage)?.clone();
            let charter = args[2..].join(" ");
            Mode::Declare { name, charter }
        }
        Some("join") => Mode::Join {
            name: args.get(1).ok_or(usage)?.clone(),
        },
        Some("share") => Mode::Share {
            manifest_id: parse_hex32(args.get(1).ok_or(usage)?)?,
            schema_id: args.get(2).ok_or(usage)?.clone(),
            title: args[3..].join(" "),
        },
        Some("show") => Mode::Show,
        _ => return Err(usage.to_string()),
    };
    Ok((mode, peer_tickets))
}

async fn connect_ticket(
    transport: &P2pandaTransport,
    moot_id: [u8; 32],
    ticket: &str,
) -> Result<(), String> {
    let peer = transport
        .add_peer_ticket(ticket.trim())
        .await
        .map_err(|e| format!("bad ticket: {e}"))?;
    transport
        .set_topics(peer, &[transport::sync_overlay_topic(moot_id)])
        .await
        .map_err(|e| format!("set topics: {e}"))?;
    println!("connected peer {}", hex8(&peer.to_bytes()));
    Ok(())
}

fn print_roster(roster: &MootRoster) {
    match &roster.declaration {
        Some(d) => println!(
            "  moot: {:?} — {:?} (declared by {})",
            d.name,
            d.charter,
            hex8(&d.by)
        ),
        None => println!("  moot: (not yet declared)"),
    }
    println!("  members ({}):", roster.members.len());
    for (author, member) in &roster.members {
        println!("    {}  {}", hex8(author), member.name);
    }
    println!("  fauna ({}):", roster.fauna.len());
    for entry in &roster.fauna {
        println!(
            "    {}  [{}] {}  (shared by {})",
            hex8(&entry.manifest_id),
            entry.schema_id,
            entry.title,
            hex8(&entry.shared_by)
        );
    }
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let (mode, peer_tickets) = parse_args()?;
    let moot_id = env_hash("MOOT_SPACE")?;
    let seed = env_hash("MOOT_SEED")?;

    let provider = InMemoryProvider::from_seed(seed);
    let author_kp: Ed25519Keypair = provider
        .derive_keypair(b"moot-author")
        .map_err(|e| format!("derive author key: {e}"))?;
    let me = author_kp.public_key().to_bytes();

    let transport = Arc::new(
        P2pandaTransport::builder(provider.master_keypair())
            .gossip()
            .bind()
            .await
            .map_err(|e| format!("bind transport: {e}"))?,
    );
    let ticket = transport
        .ticket()
        .await
        .map_err(|e| format!("ticket: {e}"))?;
    let dialable = transport
        .endpoint_addr()
        .await
        .map_err(|e| format!("endpoint addr: {e}"))?
        .ip_addrs()
        .map(|a| a.to_string())
        .collect::<Vec<_>>()
        .join(", ");

    println!("moot-peer — moot-object M1 rehearsal");
    println!("moot   : {}", hex8(&moot_id));
    println!("me     : {}", hex8(&me));
    println!("addrs  : {dialable}");
    println!("ticket : {ticket}");
    println!("paste a peer's ticket on stdin (or pass --peer) to connect.\n");

    for t in &peer_tickets {
        connect_ticket(&transport, moot_id, t).await?;
    }
    let stdin_transport = Arc::clone(&transport);
    tokio::spawn(async move {
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let line = line.trim().to_string();
            if line.is_empty() {
                continue;
            }
            if let Err(e) = connect_ticket(&stdin_transport, moot_id, &line).await {
                eprintln!("{e}");
            }
        }
    });

    let temporary = std::env::var_os("MOOT_DB")
        .is_none()
        .then(|| tempfile::tempdir().map_err(|error| format!("temporary store: {error}")))
        .transpose()?;
    let store_path = std::env::var_os("MOOT_DB")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| temporary.as_ref().unwrap().path().join("moot.redb"));
    let store = MootStoreFile::at_path(store_path).map_err(|e| format!("store: {e}"))?;

    let (endpoint, gossip) = transport
        .sync_parts()
        .ok_or_else(|| "transport has no sync parts (gossip not enabled?)".to_string())?;
    // Host-composed pump: join the moot-object LogSync session via the shared
    // `JoinedSpace` (session + live-publish lane + drain, drop-ordered).
    // gemot owns no p2panda-net; the host wires the pump.
    let accept_store = store.clone();
    let joined: JoinedSpace<MootExt> = JoinedSpace::join::<_, MootLogId, _, _>(
        store.sync_store(),
        endpoint,
        gossip,
        Topic::from(moot_id),
        move |op: Operation<MootExt>| {
            let store = accept_store.clone();
            async move {
                verify(&op)
                    && op.header.extensions.moot_id == moot_id
                    && matches!(store.insert(&op).await, Ok(true))
            }
        },
    )
    .await
    .map_err(|e| e.to_string())?;

    match mode {
        Mode::Declare { name, charter } => {
            let op = store
                .author(
                    &author_kp,
                    moot_id,
                    &MootEvent::Declared {
                        name,
                        charter,
                        at_ms: now_ms(),
                    },
                )
                .await
                .map_err(|e| format!("declare: {e}"))?;
            joined.publish(op).map_err(|e| e.to_string())?;
            println!("declared.");
        }
        Mode::Join { name } => {
            let op = store
                .author(
                    &author_kp,
                    moot_id,
                    &MootEvent::Joined {
                        name,
                        at_ms: now_ms(),
                    },
                )
                .await
                .map_err(|e| format!("join: {e}"))?;
            joined.publish(op).map_err(|e| e.to_string())?;
            println!("joined.");
        }
        Mode::Share {
            manifest_id,
            schema_id,
            title,
        } => {
            let op = store
                .author(
                    &author_kp,
                    moot_id,
                    &MootEvent::Shared {
                        manifest_id,
                        schema_id,
                        title,
                        at_ms: now_ms(),
                    },
                )
                .await
                .map_err(|e| format!("share: {e}"))?;
            joined.publish(op).map_err(|e| e.to_string())?;
            println!("shared into the fauna.");
        }
        Mode::Show => {}
    }

    // Watch the roster, printing on change, with real sync status.
    let mut last = String::new();
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let roster = store
            .roster(moot_id)
            .await
            .map_err(|e| format!("roster: {e}"))?;
        let status = joined.sync_status();
        let mut snapshot = String::new();
        {
            use std::fmt::Write;
            let _ = write!(
                snapshot,
                "{:?}|{}|{}|{}|{}",
                roster.declaration.as_ref().map(|d| &d.name),
                roster.members.len(),
                roster.fauna.len(),
                status.sync_rounds,
                status.ops_received
            );
        }
        if snapshot != last {
            println!(
                "roster (sync: {} rounds, {} ops received):",
                status.sync_rounds, status.ops_received
            );
            print_roster(&roster);
            last = snapshot;
        }
    }
}
