// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

use super::config::Config;
use gemot::moot::relay::{PoolPolicy, PoolTarget, host::WorkerAccess};
use gemot::moot::{AvailabilityPolicy, ErasurePolicy, KeepBound, MootId, PolicyRevision};
use notochord::{LocalNetworkPolicy, NetworkId, ProfileRef, RequestedAction, TrafficClass};
use serde_json::{Value, json};

fn value(dir: &std::path::Path) -> Value {
    let pool = PoolPolicy {
        moot: MootId([31; 32]),
        pool: [41; 32],
        coordination: [72; 32],
        constitution_revision: proofs::Digest::blake3(b"configuration-only"),
        revision: [42; 32],
        service_key: [9; 32],
        max_records: 128,
        max_lease_ms: 60_000,
        max_authority_age_ms: 1000,
        authority_expires_at_ms: 60_000,
    };
    json!({
        "version":1,"pool":pool,"device":vec![51u8;32],
        "access":[WorkerAccess{requester:[4;32],target:PoolTarget{id:[61;32],recipient_key:[8;32],max_bytes:32768}}],
        "targets":[{"id":vec![61u8;32],"destination":format!("{}.b32.i2p","a".repeat(52)),"service_key":vec![8u8;32]}],
        "custody_endpoint":"unused-configuration-reference","custody_app":"relay-pool-trial",
        "custody_declaration":dir.join("declaration.json"),"custody_timeout_ms":1000,
        "group_store":dir.join("sealed"),"group_record":"group.json","group_sealing_salt":b"trial/group/state".to_vec(),"group_id":vec![71u8;32],
        "moot_directory":dir.join("moot"),"pool_database":dir.join("pool.redb"),
        "retention":{"revision":PolicyRevision(proofs::Digest::blake3(b"trial-retention")),
            "availability":AvailabilityPolicy{promised_floor:KeepBound::Forever},"erasure":ErasurePolicy{history_ceiling:KeepBound::UntilCheckpoint}},
        "control_peers":[],"private_export":dir.join("bootstrap.json"),"sam":"127.0.0.1:7656",
        "tunnels":{"inbound":2,"outbound":2,"quantity":2,"publish":true},"session_timeout_ms":1000,
        "local_policy":LocalNetworkPolicy::closed(NetworkId([41;32])),
        "profile":ProfileRef{id:"murm.relay.i2p".into(),revision:1},
        "action":RequestedAction{domain:"mere.network".into(),path:"/services/murm/relay".into(),action:"connect".into()},
        "class":TrafficClass::Interactive,"outbound_key_salt":b"mere/network-policy/session-signer/v1".to_vec(),
        "device_limits":{"pending":4,"sessions":2,"bytes":65536,"bytes_per_second":65536},
        "flow_limits":{"sessions":2,"bytes":65536,"bytes_per_second":65536,"buffer_bytes":1024,"lifetime_ms":5000,"authority_interval_ms":50},
        "setup_limits":{"timeout_ms":1000,"read_bytes":65536,"write_bytes":65536,"frame_bytes":8192,"frames":32,"io_operations":4096},
        "worker_limits":{"tasks":8,"refresh_ms":250,"refresh_timeout_ms":2000,"shutdown_ms":3000},
        "availability_ms":5000,"clock_tolerance_ms":1000,"clock_valid_until_ms":60000,"run_ms":10000,"stop_file":dir.join("stop")
    })
}
fn load(dir: &std::path::Path, value: &Value) -> Result<Config, &'static str> {
    let path = dir.join("config.json");
    std::fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
    Config::load(&path)
}

#[test]
fn offline_check_is_inert_and_refuses_seeds_direct_routes_and_path_escape() {
    let dir = tempfile::tempdir().unwrap();
    let original = value(dir.path());
    assert!(load(dir.path(), &original).is_ok());
    assert!(!dir.path().join("moot").exists());
    assert!(!dir.path().join("sealed").exists());
    assert!(!dir.path().join("bootstrap.json").exists());
    let mut bad = original.clone();
    bad["master_seed"] = json!(vec![7u8; 32]);
    assert!(load(dir.path(), &bad).is_err());
    let mut bad = original.clone();
    bad["targets"][0]["destination"] = json!("127.0.0.1:7777");
    assert!(load(dir.path(), &bad).is_err());
    let mut bad = original.clone();
    bad["group_record"] = json!("../another-operator.json");
    assert!(load(dir.path(), &bad).is_err());
    let mut bad = original;
    bad["sam"] = json!("192.0.2.1:7656");
    assert!(load(dir.path(), &bad).is_err());
}

#[test]
fn disabled_contribution_never_opens_missing_custody_or_state() {
    let dir = tempfile::tempdir().unwrap();
    let mut disabled = value(dir.path());
    disabled["device_limits"]["sessions"] = json!(0);
    let config = load(dir.path(), &disabled).unwrap();
    assert_eq!(
        super::custody::check(&config),
        Err("device contribution disabled")
    );
    assert_eq!(super::run::run(config), Err("device contribution disabled"));
    assert!(!dir.path().join("moot").exists());
    assert!(!dir.path().join("bootstrap.json").exists());
}

#[test]
fn key_scope_collisions_are_refused_before_custody() {
    let dir = tempfile::tempdir().unwrap();
    let original = value(dir.path());
    let control = gemot::moot::relay::control_salt([41; 32], [51; 32]);
    let device = gemot::moot::relay::device_salt([41; 32], [51; 32]);
    for field in ["outbound_key_salt", "group_sealing_salt"] {
        for collision in [&control, &device] {
            let mut bad = original.clone();
            bad[field] = json!(collision);
            assert!(load(dir.path(), &bad).is_err());
        }
    }
    let mut bad = original;
    bad["group_sealing_salt"] = bad["outbound_key_salt"].clone();
    assert!(load(dir.path(), &bad).is_err());
}

#[test]
fn receiving_group_read_requires_the_operator_and_group_and_sealing_key() {
    use identity::sealed_record_storage::SealedRecordStorage;
    use identity::{IdentityProvider, InMemoryProvider};
    use stickleback::{GroupSession, GroupSessionId};
    let dir = tempfile::tempdir().unwrap();
    let operator = InMemoryProvider::from_seed([83; 32]);
    let root = operator.master_public_key().to_bytes();
    let (mut session, _) = GroupSession::new(GroupSessionId([71; 32]), &operator).unwrap();
    session.create(&[]).unwrap();
    let storage = SealedRecordStorage::open_with_key(dir.path(), [84; 32]);
    let record = std::path::Path::new("group.json");
    storage
        .save_record(record, &session.to_bytes().unwrap())
        .unwrap();
    let keys = super::custody::group_keys(&storage, dir.path(), record, [71; 32], root).unwrap();
    let sealed = session.seal_random(b"receiving group binding").unwrap();
    assert_eq!(keys.open(&sealed).unwrap(), b"receiving group binding");
    assert!(super::custody::group_keys(&storage, dir.path(), record, [72; 32], root).is_err());
    assert!(super::custody::group_keys(&storage, dir.path(), record, [71; 32], [85; 32]).is_err());
    let wrong = SealedRecordStorage::open_with_key(dir.path(), [86; 32]);
    assert!(super::custody::group_keys(&wrong, dir.path(), record, [71; 32], root).is_err());
}

#[cfg(windows)]
#[test]
fn absent_custody_is_bounded_and_creates_no_relay_state() {
    let dir = tempfile::tempdir().unwrap();
    let mut input = value(dir.path());
    input["custody_endpoint"] = json!(format!(
        r"\\.\pipe\gemot-absent-custody-{}",
        dir.path().file_name().unwrap().to_string_lossy()
    ));
    input["custody_timeout_ms"] = json!(200);
    std::fs::write(
        dir.path().join("declaration.json"),
        br#"{"routes":[{"exact":"custody"}],"custody":{"operations":["status","watch_lock"]}}"#,
    )
    .unwrap();
    let config = load(dir.path(), &input).unwrap();
    let start = std::time::Instant::now();
    assert_eq!(
        super::custody::check(&config),
        Err("custody unavailable or refused")
    );
    assert!(start.elapsed() < std::time::Duration::from_secs(3));
    for absent in ["moot", "pool.redb", "sealed", "bootstrap.json", "stop"] {
        assert!(!dir.path().join(absent).exists());
    }
}

#[test]
fn mismatched_control_ticket_is_refused_before_any_connection() {
    use identity::IdentityProvider;
    let dir = tempfile::tempdir().unwrap();
    let owner = identity::InMemoryProvider::random();
    let salt = gemot::moot::relay::control_salt([41; 32], [51; 32]);
    let binding = gemot::moot::relay::ControlPeer {
        device: [51; 32],
        attestation: owner.attest_derived_key(&salt).unwrap(),
    };
    let key = owner.derive_keypair(&salt).unwrap().public_key().to_bytes();
    let right =
        transport::encode_peer_ticket(transport::PeerID::from_bytes(&key).unwrap(), &[]).unwrap();
    let wrong = transport::encode_peer_ticket(
        transport::PeerID::from_bytes(&owner.master_public_key().to_bytes()).unwrap(),
        &[],
    )
    .unwrap();
    let mut config = value(dir.path());
    config["control_peers"] = json!([{"ticket":wrong,"binding":binding}]);
    assert!(load(dir.path(), &config).is_err());
    config["control_peers"][0]["ticket"] = json!(right);
    assert!(load(dir.path(), &config).is_ok());
    assert!(!dir.path().join("bootstrap.json").exists());
}
