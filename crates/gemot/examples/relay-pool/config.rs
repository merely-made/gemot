// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

use gemot::moot::relay::{
    ControlPeer, PoolPolicy,
    host::{WorkerAccess, WorkerLimits},
};
use gemot::moot::{AvailabilityPolicy, ErasurePolicy, MootRetentionSettings, PolicyRevision};
use murm::relay::{DeviceLimits, FlowLimits};
use notochord::{LocalNetworkPolicy, ProfileRef, RequestedAction, TrafficClass};
use serde::Deserialize;
use std::{
    fs::File,
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};
use transport::i2p::TunnelProfile;
use transport::security::SetupLimits;

/// All files are operator-private. No root seed or group secret is a config field.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u8,
    pub pool: PoolPolicy,
    pub device: [u8; 32],
    pub access: Vec<WorkerAccess>,
    pub targets: Vec<Target>,
    pub custody_endpoint: String,
    pub custody_app: String,
    pub custody_declaration: PathBuf,
    pub custody_timeout_ms: u64,
    pub group_store: PathBuf,
    pub group_record: PathBuf,
    pub group_sealing_salt: Vec<u8>,
    pub group_id: [u8; 32],
    pub moot_directory: PathBuf,
    pub pool_database: PathBuf,
    pub retention: Retention,
    pub control_peers: Vec<Peer>,
    pub private_export: PathBuf,
    pub sam: SocketAddr,
    pub tunnels: Tunnels,
    pub session_timeout_ms: u64,
    pub local_policy: LocalNetworkPolicy,
    pub profile: ProfileRef,
    pub action: RequestedAction,
    pub class: TrafficClass,
    pub outbound_key_salt: Vec<u8>,
    pub device_limits: Device,
    pub flow_limits: Flow,
    pub setup_limits: Setup,
    pub worker_limits: Worker,
    pub availability_ms: u64,
    pub clock_tolerance_ms: u64,
    pub clock_valid_until_ms: u64,
    pub run_ms: u64,
    pub stop_file: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub id: [u8; 32],
    pub destination: String,
    pub service_key: [u8; 32],
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    pub ticket: String,
    pub binding: ControlPeer,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Retention {
    pub revision: PolicyRevision,
    pub availability: AvailabilityPolicy,
    pub erasure: ErasurePolicy,
}
impl Retention {
    pub fn settings(&self) -> MootRetentionSettings {
        MootRetentionSettings {
            revision: self.revision.clone(),
            availability: self.availability,
            erasure: self.erasure,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tunnels {
    pub inbound: u8,
    pub outbound: u8,
    pub quantity: u8,
    pub publish: bool,
}
impl Tunnels {
    pub fn profile(&self) -> Result<TunnelProfile, &'static str> {
        TunnelProfile::new(self.inbound, self.outbound, self.quantity, self.publish)
            .map_err(|_| "tunnel profile refused")
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    pub pending: usize,
    pub sessions: usize,
    pub bytes: u64,
    pub bytes_per_second: u64,
}
impl Device {
    pub fn limits(&self) -> DeviceLimits {
        DeviceLimits {
            max_pending: self.pending,
            max_sessions: self.sessions,
            max_bytes: self.bytes,
            bytes_per_second: self.bytes_per_second,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Flow {
    pub sessions: usize,
    pub bytes: u64,
    pub bytes_per_second: u64,
    pub buffer_bytes: usize,
    pub lifetime_ms: u64,
    pub authority_interval_ms: u64,
}
impl Flow {
    pub fn limits(&self) -> FlowLimits {
        FlowLimits {
            max_sessions: self.sessions,
            max_bytes: self.bytes,
            bytes_per_second: self.bytes_per_second,
            buffer_bytes: self.buffer_bytes,
            lifetime: ms(self.lifetime_ms),
            authority_interval: ms(self.authority_interval_ms),
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Setup {
    pub timeout_ms: u64,
    pub read_bytes: usize,
    pub write_bytes: usize,
    pub frame_bytes: usize,
    pub frames: usize,
    pub io_operations: usize,
}
impl Setup {
    pub fn limits(&self) -> SetupLimits {
        SetupLimits {
            timeout: ms(self.timeout_ms),
            max_read_bytes: self.read_bytes,
            max_write_bytes: self.write_bytes,
            max_frame_bytes: self.frame_bytes,
            max_frames: self.frames,
            max_io_operations: self.io_operations,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Worker {
    pub tasks: usize,
    pub refresh_ms: u64,
    pub refresh_timeout_ms: u64,
    pub shutdown_ms: u64,
}
impl Worker {
    pub fn limits(&self) -> WorkerLimits {
        WorkerLimits {
            max_tasks: self.tasks,
            refresh_interval: ms(self.refresh_ms),
            refresh_timeout: ms(self.refresh_timeout_ms),
            shutdown_timeout: ms(self.shutdown_ms),
        }
    }
}
pub fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
}
pub fn read(path: &Path) -> Result<Vec<u8>, &'static str> {
    let mut bytes = vec![];
    File::open(path)
        .map_err(|_| "input unavailable")?
        .take(1_048_577)
        .read_to_end(&mut bytes)
        .map_err(|_| "input unreadable")?;
    if bytes.len() > 1_048_576 {
        return Err("input exceeds bound");
    }
    Ok(bytes)
}
impl Config {
    pub fn contribution_enabled(&self) -> Result<(), &'static str> {
        if self.device_limits.pending == 0
            || self.device_limits.sessions == 0
            || self.device_limits.bytes == 0
            || self.device_limits.bytes_per_second == 0
        {
            return Err("device contribution disabled");
        }
        Ok(())
    }
    pub fn load(path: &Path) -> Result<Self, &'static str> {
        let config: Self =
            serde_json::from_slice(&read(path)?).map_err(|_| "configuration invalid")?;
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<(), &'static str> {
        self.worker_limits
            .limits()
            .validate()
            .map_err(|_| "worker bounds refused")?;
        if std::time::Instant::now()
            .checked_add(ms(self.run_ms))
            .is_none()
        {
            return Err("trial duration refused");
        }
        if [
            &self.custody_declaration,
            &self.group_store,
            &self.moot_directory,
            &self.pool_database,
            &self.private_export,
            &self.stop_file,
        ]
        .iter()
        .any(|p| !p.is_absolute())
            || self.group_record.as_os_str().is_empty()
        {
            return Err("absolute private paths and a relative group record required");
        }
        if self.version != 1
            || !self.sam.ip().is_loopback()
            || !self.tunnels.publish
            || self.run_ms == 0
            || self.clock_tolerance_ms == 0
            || self.clock_valid_until_ms == 0
            || self.session_timeout_ms == 0
            || self.session_timeout_ms > 300_000
            || self.custody_timeout_ms == 0
            || self.custody_timeout_ms > 300_000
            || self.custody_app.is_empty()
            || self.custody_endpoint.is_empty()
            || self.group_sealing_salt.is_empty()
            || self.outbound_key_salt.is_empty()
            || self.access.is_empty()
            || self.access.len() > 256
            || self.targets.is_empty()
            || self.targets.len() > 256
            || self.control_peers.len() > 256
            || self.availability_ms == 0
            || self.availability_ms > self.pool.max_lease_ms
            || self.worker_limits.tasks == 0
            || self.worker_limits.tasks > 256
            || self.worker_limits.refresh_ms == 0
            || self.worker_limits.refresh_timeout_ms == 0
            || self.worker_limits.shutdown_ms == 0
            || self.worker_limits.shutdown_ms > 300_000
            || self.worker_limits.refresh_ms >= self.availability_ms
            || self.worker_limits.refresh_ms >= self.pool.max_authority_age_ms
            || self
                .group_record
                .components()
                .any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            return Err("configuration bounds refused");
        }
        self.tunnels.profile()?;
        // Public worker identity, private control identity and group storage
        // protection must not become the same key through configuration.
        let control = gemot::moot::relay::control_salt(self.pool.pool, self.device);
        let device = gemot::moot::relay::device_salt(self.pool.pool, self.device);
        let salts = [
            &control,
            &device,
            &self.outbound_key_salt,
            &self.group_sealing_salt,
        ];
        for (index, salt) in salts.iter().enumerate() {
            if salts[..index].contains(salt) {
                return Err("custody key scopes overlap");
            }
        }
        for target in &self.targets {
            transport::i2p::I2pAddress::parse(&target.destination)
                .map_err(|_| "target locator refused")?;
        }
        for peer in &self.control_peers {
            let (ticket_key, _) = transport::decode_peer_ticket(&peer.ticket)
                .map_err(|_| "control ticket refused")?;
            if ticket_key.to_bytes() != *peer.binding.attestation.derived() {
                return Err("control ticket binding refused");
            }
            peer.binding
                .attestation
                .check(&gemot::moot::relay::control_salt(
                    self.pool.pool,
                    peer.binding.device,
                ))
                .map_err(|_| "control peer binding refused")?;
        }
        Ok(())
    }
}
