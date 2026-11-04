// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

use super::config::{Config, ms, read};
use castellan_client::custody_identity::CustodyIdentity;
use gemot::moot::Moot;
use gemot::moot::relay::{
    ControlPeer, PoolStore, control_salt, device_salt,
    host::{I2pWorker, OwnerClock, WorkerAdmission, WorkerAuthority, WorkerStop},
};
use identity::sealed_record_storage::SealedRecordStorage;
use identity::{IdentityProvider, RetainedKeys};
use murm::relay::DeviceBudget;
use murm::relay::i2p::{I2pRoute, I2pSession};
use notochord::{RevocationLedger, SecureIdentityPolicy};
use serde::Serialize;
use std::{
    fs::OpenOptions,
    path::Path,
    sync::{Arc, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};
use stickleback::{DataKeyring, GroupSession, GroupSessionId};
use tokio::time::Instant;
use transport::i2p::{Bridge, I2pAddress, Key};
use transport::{P2pandaTransport, PeerID};

fn wall() -> Option<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_millis(),
    )
    .ok()
}
fn clock(config: &Config) -> Result<OwnerClock, &'static str> {
    let base = wall().ok_or("clock unavailable")?;
    let start = Instant::now();
    let (tolerance, end) = (config.clock_tolerance_ms, config.clock_valid_until_ms);
    if base >= end || config.pool.authority_expires_at_ms > end {
        return Err("clock validity refused");
    }
    Ok(Arc::new(move || {
        let now = wall()?;
        let expected = base.checked_add(u64::try_from(start.elapsed().as_millis()).ok()?)?;
        (now < end && now.abs_diff(expected) <= tolerance).then_some(now)
    }))
}
fn group_keys(
    storage: &SealedRecordStorage,
    root: &Path,
    record: &Path,
    expected: [u8; 32],
) -> Result<Arc<DataKeyring>, &'static str> {
    // The existing owner chooses/guards this record path. Bound the sealed file
    // before delegating its authenticated format to Personae.
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
    let keys = DataKeyring::from_bytes(
        &session
            .data_keyring_state()
            .map_err(|_| "group keys unavailable")?,
    )
    .map_err(|_| "group keys refused")?;
    Ok(Arc::new(keys))
}
#[derive(Serialize)]
struct Bootstrap {
    audience: &'static str,
    control_ticket: String,
    control_binding: ControlPeer,
    worker_destination: String,
    worker_key: [u8; 32],
    readiness: &'static str,
}
pub fn run(config: Config) -> Result<(), &'static str> {
    if config.device_limits.pending == 0
        || config.device_limits.sessions == 0
        || config.device_limits.bytes == 0
        || config.device_limits.bytes_per_second == 0
    {
        return Err("device contribution disabled");
    }
    if config
        .private_export
        .try_exists()
        .map_err(|_| "bootstrap path unavailable")?
        || config
            .stop_file
            .try_exists()
            .map_err(|_| "stop path unavailable")?
    {
        return Err("bootstrap or stop output already exists");
    }
    if !config.moot_directory.join("constitution.redb").is_file() || !config.pool_database.is_file()
    {
        return Err("existing governed state required");
    }
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
    let key_source = Arc::new(RwLock::new(group_keys(
        &storage,
        &config.group_store,
        &config.group_record,
        config.group_id,
    )?));
    if custody.custody_epoch() != Some(epoch) {
        return Err("custody changed during setup");
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| "runtime unavailable")?;
    runtime.block_on(async {
        let clock=clock(&config)?;
        let moot=Arc::new(Moot::open_existing(&config.moot_directory,config.pool.moot,config.retention.settings())
            .await.map_err(|_|"governed state refused")?);
        let read_keys=key_source.clone();
        let pool=PoolStore::new(moot.clone(),muniment::RedbBackend::open(&config.pool_database).map_err(|_|"pool state unavailable")?,
            config.pool.clone(),Arc::new(move ||read_keys.read().unwrap_or_else(|p|p.into_inner()).clone()))
            .map_err(|_|"pool policy refused")?;
        let control_key=retained.derived_keypair(&control).map_err(|_|"control key unavailable")?;
        let carrier=P2pandaTransport::builder_for(&control_key).gossip().bind().await.map_err(|_|"control endpoint unavailable")?;
        let result=async {
            let (endpoint,gossip)=carrier.sync_parts().ok_or("control sync unavailable")?;
            let lanes=moot.join_lanes(endpoint.clone(),gossip.clone()).await.map_err(|_|"moot lanes unavailable")?;
            let sync_clock=clock.clone();
            let private=pool.join_with_control_peers(endpoint,gossip,Arc::new(move ||sync_clock().unwrap_or(u64::MAX)),
                config.control_peers.iter().map(|p|p.binding.clone()).collect()).await.map_err(|_|"operator sync refused")?;
            for peer in &config.control_peers {
                let added=carrier.add_peer_ticket(&peer.ticket).await.map_err(|_|"control peer unavailable")?;
                let expected=PeerID::from_bytes(peer.binding.attestation.derived()).map_err(|_|"control peer key refused")?;
                if added!=expected {return Err("control ticket binding refused");}
            }
            let session=I2pSession::create(Bridge::new(config.sam),Key::Transient,config.tunnels.profile()?,
                ms(config.session_timeout_ms)).await.map_err(|_|"I2P provider unavailable")?;
            let worker_key=retained.derive_keypair(&device).map_err(|_|"worker key unavailable")?;
            let watch=custody.clone();
            let authority=WorkerAuthority::new(pool,config.device,worker_key.public_key().to_bytes(),config.access.clone(),
                clock.clone(),Arc::new(move ||watch.custody_epoch()),ms(config.availability_ms)).map_err(|_|"worker authority refused")?;
            // Local readiness only. A directory issuer must probe the public route
            // independently before signing/publishing a client offer.
            let probe=authority.probe(ms(config.availability_ms)).await.map_err(|_|"local readiness refused")?;
            authority.confirm(&probe,worker_key.sign(&probe.signing_bytes()).to_bytes()).await.map_err(|_|"local readiness refused")?;
            if authority.refresh().await.map_err(|_|"authority refresh refused")?==0 {return Err("no authorized trial access");}
            let targets=config.targets.iter().map(|t|Ok((t.id,I2pRoute {address:I2pAddress::parse(&t.destination)
                .map_err(|_|"target refused")?,service_key:t.service_key}))).collect::<Result<Vec<_>,&'static str>>()?;
            let worker=I2pWorker::new(authority.clone(),session.clone(),targets,DeviceBudget::new(config.device_limits.limits())
                .map_err(|_|"device limits refused")?,config.flow_limits.limits(),config.setup_limits.limits(),retained.clone(),
                WorkerAdmission {policy:Arc::new(config.local_policy.clone()),ledger:Arc::new(RevocationLedger::default()),
                    identity:SecureIdentityPolicy::MatchCarrierWhenPresent,profile:config.profile.clone(),action:config.action.clone(),
                    class:config.class,outbound_key_salt:config.outbound_key_salt.clone()}).map_err(|_|"worker composition refused")?;
            let bootstrap=Bootstrap {audience:"operators",control_ticket:carrier.ticket().await.map_err(|_|"control export unavailable")?,
                control_binding:ControlPeer{device:config.device,attestation:retained.attest_derived_key(&control).map_err(|_|"control attestation unavailable")?},
                worker_destination:session.address().map_err(|_|"worker route unavailable")?.as_str().into(),
                worker_key:worker_key.public_key().to_bytes(),readiness:"local-session-only"};
            let output=OpenOptions::new().write(true).create_new(true).open(&config.private_export).map_err(|_|"private bootstrap output refused")?;
            serde_json::to_writer(output,&bootstrap).map_err(|_|"private bootstrap write failed")?;
            println!("{{\"worker\":\"ready\",\"readiness\":\"local-session-only\",\"qualification\":\"not-run\"}}");
            let mut stop_failure=None;
            let mut renewals=0u64;
            let run_started=Instant::now();
            let stop=async {
                let end=Instant::now()+ms(config.run_ms);
                loop {
                    tokio::time::sleep_until((Instant::now()+ms(config.worker_limits.refresh_ms)).min(end)).await;
                    if Instant::now()>=end || config.stop_file.try_exists().unwrap_or(true) {break;}
                    if custody.custody_epoch()!=Some(epoch) {stop_failure=Some("custody binding ended");break;}
                    let Ok(keys)=group_keys(&storage,&config.group_store,&config.group_record,config.group_id) else {
                        stop_failure=Some("group state reload refused");break;
                    };
                    *key_source.write().unwrap_or_else(|p|p.into_inner())=keys;
                    let Ok(probe)=authority.probe(ms(config.availability_ms)).await else {
                        stop_failure=Some("local readiness unavailable");break;
                    };
                    if authority.confirm(&probe,worker_key.sign(&probe.signing_bytes()).to_bytes()).await.is_err() {
                        stop_failure=Some("local readiness response refused");break;
                    }
                    renewals=renewals.saturating_add(1);
                }
            };
            let report=worker.run(config.worker_limits.limits(),stop).await.map_err(|_|"worker run refused")?;
            println!("{{\"worker\":\"stopped\",\"reason\":\"{:?}\",\"accepted\":{},\"completed\":{},\"refused\":{},\"drained\":{},\"active\":{},\"pending\":{},\"charged_bytes\":{}}}",
                report.reason,report.accepted,report.completed,report.refused,report.drained,report.device.active,report.device.pending_setups,report.device.charged_bytes);
            println!("{{\"run_ms\":{},\"local_readiness_renewals\":{},\"qualification\":\"not-run\"}}",
                run_started.elapsed().as_millis(),renewals);
            drop((private,lanes));
            if let Some(error)=stop_failure {return Err(error);}
            if !report.drained || report.device.active!=0 || report.device.pending_setups!=0 || report.reason!=WorkerStop::Requested {
                return Err("worker ended without a clean requested stop");
            }
            Ok(())
        }.await;
        tokio::time::timeout(ms(config.worker_limits.shutdown_ms),carrier.close()).await
            .map_err(|_|"control endpoint shutdown timed out")?.map_err(|_|"control endpoint shutdown failed")?;
        result
    })
}
