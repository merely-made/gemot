// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

//! Shared receiving setup. This opens custody and the existing sealed group
//! record; it creates no governed state, control endpoint or I2P session.

use super::config::{Config, ms, read};
use castellan_client::custody_identity::CustodyIdentity;
use gemot::moot::relay::{control_salt, device_salt};
use identity::sealed_record_storage::SealedRecordStorage;
use identity::{IdentityProvider, RetainedKeys};
use std::{path::Path, sync::Arc};
use stickleback::{DataKeyring, GroupSession, GroupSessionId};

pub struct Receiving {
    pub custody: Arc<CustodyIdentity>,
    pub epoch: u64,
    pub control: Vec<u8>,
    pub device: Vec<u8>,
    pub retained: Arc<RetainedKeys>,
    pub storage: SealedRecordStorage,
    pub keys: Arc<DataKeyring>,
}

/// The same receiving path for preflight and worker startup. The final status
/// fences lock/profile/custodian changes during the releases and group read.
pub fn open(config: &Config) -> Result<Receiving, &'static str> {
    config.contribution_enabled()?;
    let declaration = serde_json::from_slice(&read(&config.custody_declaration)?)
        .map_err(|_| "custody declaration invalid")?;
    let custody = Arc::new(
        CustodyIdentity::connect_declared_at_timeout(
            &config.custody_endpoint,
            &config.custody_app,
            declaration,
            ms(config.custody_timeout_ms),
        )
        .map_err(|_| "custody unavailable or refused")?,
    );
    if custody.connected_status().custody_epoch.is_none() {
        return Err("custody epoch evidence unavailable");
    }
    let epoch = custody.custody_epoch().ok_or("custody locked")?;
    let control = control_salt(config.pool.pool, config.device);
    let device = device_salt(config.pool.pool, config.device);
    let retained = Arc::new(
        RetainedKeys::capture(
            custody.as_ref(),
            &[
                control.clone(),
                device.clone(),
                config.outbound_key_salt.clone(),
            ],
        )
        .map_err(|_| "scoped custody release refused")?,
    );
    let sealing = custody
        .derive_keypair(&config.group_sealing_salt)
        .map_err(|_| "group custody release refused")?;
    let storage = SealedRecordStorage::open_with_key(&config.group_store, sealing.to_seed());
    drop(sealing);
    let keys = group_keys(
        &storage,
        &config.group_store,
        &config.group_record,
        config.group_id,
        retained.master_public_key().to_bytes(),
    )?;
    custody
        .status_timeout(ms(config.custody_timeout_ms))
        .map_err(|_| "custody status unavailable or refused")?;
    if custody.custody_epoch() != Some(epoch) {
        return Err("custody changed during setup");
    }
    Ok(Receiving {
        custody,
        epoch,
        control,
        device,
        retained,
        storage,
        keys,
    })
}

pub fn check(config: &Config) -> Result<(), &'static str> {
    let receiving = open(config)?;
    // Forget the SDK's cache and drop every caller-owned scoped key on return.
    // This does not lock or switch the operator's resident.
    receiving.custody.forget();
    println!(
        "{{\"custody\":\"checked\",\"sealed_group\":\"checked\",\"qualification\":\"not-run\"}}"
    );
    Ok(())
}

pub fn group_keys(
    storage: &SealedRecordStorage,
    root: &Path,
    record: &Path,
    expected: [u8; 32],
    expected_operator: [u8; 32],
) -> Result<Arc<DataKeyring>, &'static str> {
    if std::fs::metadata(root.join(record))
        .map_err(|_| "group state unavailable")?
        .len()
        > 1_048_576
    {
        return Err("sealed group state exceeds bound");
    }
    let bytes: Vec<u8> = storage
        .load_record(record)
        .map_err(|_| "sealed group record refused")?
        .ok_or("sealed group record absent")?;
    if bytes.len() > 1_048_576 {
        return Err("group state exceeds bound");
    }
    let session = GroupSession::from_bytes(&bytes).map_err(|_| "group state refused")?;
    if session.group() != GroupSessionId(expected) {
        return Err("group binding refused");
    }
    if session.personae_root() != expected_operator {
        return Err("group operator binding refused");
    }
    let keys = DataKeyring::from_bytes(
        &session
            .data_keyring_state()
            .map_err(|_| "group keys unavailable")?,
    )
    .map_err(|_| "group keys refused")?;
    Ok(Arc::new(keys))
}
