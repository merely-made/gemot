// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Explicit saved-file publisher. Identity seed input is 32 binary bytes on
//! stdin; neither configuration, output nor command arguments contain it.

use gemot::moot::{
    AvailabilityPolicy, CollectionId, ContributionRef, ErasurePolicy, MootFile, MootId,
    MootRetentionSettings, PolicyRevision,
};
use gemot_site_host::Site;
use muniment::RedbBackend;
use personae::InMemoryProvider;
use serde::Deserialize;
use std::{
    io::{Read, Write},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use stickleback::{DropExportProfile, DropLimits};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Target {
    version: u8,
    moot_directory: PathBuf,
    moot_id: [u8; 32],
    content_database: PathBuf,
    retention_revision: PolicyRevision,
    availability: AvailabilityPolicy,
    erasure: ErasurePolicy,
    collection_id: CollectionId,
    replace: Option<ContributionRef>,
    title: String,
    records_output: PathBuf,
    snapshot_output: PathBuf,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.len() != 2 {
        return Err("usage: knot-site-publish SITE_DIR TARGET_JSON < IDENTITY_SEED".into());
    }
    let mut config = Vec::new();
    std::fs::File::open(&args[1])?
        .take(16385)
        .read_to_end(&mut config)?;
    if config.len() > 16384 {
        return Err("Publication target exceeds 16 KiB".into());
    }
    let target: Target = serde_json::from_slice(&config)?;
    if target.version != 1 {
        return Err("Unsupported publication target version".into());
    }
    let site = Site::open(std::path::Path::new(&args[0]))?;
    // Reserve new handoff files before authoring; existing source or evidence
    // files are never overwritten. Failed attempts remain available to inspect.
    let mut records = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target.records_output)?;
    let mut snapshot = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target.snapshot_output)?;
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    std::io::stdin().read_exact(seed.as_mut())?;
    let identity = InMemoryProvider::from_seed(*seed);
    let retention = MootRetentionSettings {
        revision: target.retention_revision,
        availability: target.availability,
        erasure: target.erasure,
    };
    let moot =
        MootFile::open_existing(target.moot_directory, MootId(target.moot_id), retention).await?;
    let mut content = RedbBackend::open(target.content_database)?;
    let at_ms: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?;
    let observed = moot
        .authorized_collection(target.collection_id, at_ms)
        .await?
        .ok_or("Unknown publication collection")?
        .version;
    let published = match site
        .publish_to_collection(
            &moot,
            &identity,
            &mut content,
            &observed,
            target.replace,
            target.title,
            at_ms,
        )
        .await
    {
        Ok(published) => published,
        Err(error) => {
            eprintln!(
                "{}",
                serde_json::json!({"error":error.reason,"contribution":error.contribution,"collection_operations":error.collection_operations})
            );
            return Err("Publication refused; inspect the reported durable effects".into());
        },
    };
    let handoff = async {
        snapshot.write_all(&published.snapshot.encode()?)?;
        snapshot.sync_all()?;
        moot.export_plain_drop(
            &mut records,
            DropExportProfile::default(),
            DropLimits::default(),
        )
        .await?;
        records.sync_all()?;
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    if let Err(error) = handoff {
        eprintln!(
            "{}",
            serde_json::json!({"error":error.to_string(),"selection":published.receipt.selection,"handoff_complete":false})
        );
        return Err(error);
    }
    println!(
        "{}",
        serde_json::json!({"selection":published.receipt.selection,"snapshot_digest":published.snapshot.digest()?})
    );
    Ok(())
}
