// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

//! Separate-process data-plane qualification. Parent-owned policy injection
//! uses private test IPC; network coordination is qualified in the sibling test.

use super::*;
use std::io::{BufRead, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, sync_channel};

const ROLE_ENV: &str = "GEMOT_RELAY_FIXTURE_ROLE";
const ROLE_TEST: &str = "moot::relay::tests::native::processes::subprocess_role";

struct ProcessRole {
    child: Child,
    input: ChildStdin,
    output: Option<Receiver<String>>,
    reader: Option<std::thread::JoinHandle<()>>,
    ticket: String,
}
impl ProcessRole {
    fn start(role: &str) -> Self {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", ROLE_TEST, "--nocapture"])
            .env(ROLE_ENV, role)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = child.stdout.take().unwrap();
        let (send, receive) = sync_channel(16);
        let reader = std::thread::spawn(move || {
            for line in std::io::BufReader::new(output).lines() {
                match line {
                    Ok(line) => {
                        if send.send(line).is_err() {
                            break;
                        }
                    }
                    _ => break,
                }
            }
        });
        let mut role = Self {
            child,
            input,
            output: Some(receive),
            reader: Some(reader),
            ticket: String::new(),
        };
        role.ticket = role.wait_for("RELAY_READY ");
        role
    }
    fn wait_for(&self, prefix: &str) -> String {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let line = self
                .output
                .as_ref()
                .unwrap()
                .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
                .expect("bounded child response");
            if let Some(value) = line.strip_prefix(prefix) {
                return value.to_string();
            }
        }
    }
    fn command(&mut self, line: &str) {
        writeln!(self.input, "{line}").unwrap();
        self.input.flush().unwrap();
    }
    fn allow(&mut self, permission: PoolAuthorization, now_ms: u64) {
        self.command(&format!(
            "ALLOW {} {} {} {}",
            permission.max_bytes,
            permission.bytes_per_second,
            permission.expires_at_ms - now_ms,
            permission.max_sessions
        ));
        assert_eq!(self.wait_for("RELAY_ACK "), "allow");
    }
    fn stop(&mut self) {
        self.command("STOP");
        assert_eq!(self.wait_for("RELAY_DONE "), "0");
        assert!(self.child.wait().unwrap().success());
    }
}
impl Drop for ProcessRole {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.output.take();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}
fn emit(prefix: &str, value: &str) {
    println!("{prefix} {value}");
    std::io::stdout().flush().unwrap();
}

// Only the parent fixture supplies ROLE_ENV. Ordinary runs execute no role.
#[test]
fn subprocess_role() {
    let Ok(role) = std::env::var(ROLE_ENV) else {
        return;
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let seed = match role.as_str() {
            "recipient" => 8,
            "first" => 2,
            "second" => 3,
            _ => panic!("unknown fixture role"),
        };
        let carrier = bind(seed).await;
        let mut live = None;
        let mut task = None;
        let device = budget();
        if seed == 8 {
            task = Some(recipient(carrier.clone()));
        }
        emit("RELAY_READY", &carrier.ticket().await.unwrap());
        for line in std::io::stdin().lock().lines() {
            let line = line.unwrap();
            if let Some(ticket) = line.strip_prefix("TARGET ") {
                let target = carrier.add_peer_ticket(ticket).await.unwrap();
                let state: Live = Arc::new(RwLock::new(None));
                task = Some(worker(
                    carrier.clone(),
                    target,
                    seed,
                    state.clone(),
                    device.clone(),
                ));
                live = Some(state);
                emit("RELAY_ACK", "target");
            } else if let Some(limits) = line.strip_prefix("ALLOW ") {
                let values: Vec<u64> = limits
                    .split_whitespace()
                    .map(|s| s.parse().unwrap())
                    .collect();
                assert_eq!(values.len(), 4);
                *live.as_ref().unwrap().write().unwrap() = Some(RelayGrant {
                    revision: [42; 32],
                    max_sessions: values[3] as usize,
                    max_bytes: values[0],
                    bytes_per_second: values[1],
                    expires: Instant::now() + Duration::from_millis(values[2]),
                });
                emit("RELAY_ACK", "allow");
            } else if line == "REVOKE" {
                *live.as_ref().unwrap().write().unwrap() = None;
                emit("RELAY_ACK", "revoke");
            } else if line == "STOP" {
                break;
            }
        }
        if let Some(task) = task {
            task.abort();
            let _ = task.await;
        }
        carrier.close().await.unwrap();
        tokio::task::yield_now().await;
        emit("RELAY_DONE", &device.stats().active.to_string());
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_processes_keep_pool_identity_across_worker_loss_and_revocation() {
    let started = Instant::now();
    let (mut pool, _) = fixture().await;
    pool.config.max_authority_age_ms = 20_000;
    target(&pool).await;
    pool.author(&identity(2), contribution(2, DEVICE_A), 2)
        .await
        .unwrap();
    pool.author(&identity(3), contribution(3, DEVICE_B), 2)
        .await
        .unwrap();
    let mut recipient_process = ProcessRole::start("recipient");
    let mut first = ProcessRole::start("first");
    let mut second = ProcessRole::start("second");
    assert_ne!(first.child.id(), second.child.id());
    for (process, device) in [(&mut first, DEVICE_A), (&mut second, DEVICE_B)] {
        process.command(&format!("TARGET {}", recipient_process.ticket));
        assert_eq!(process.wait_for("RELAY_ACK "), "target");
        let permission = pool.authorize(root(4), device, TARGET, 10).await.unwrap();
        process.allow(permission, 10);
    }
    let client = bind(4).await;
    let first_peer = client.add_peer_ticket(&first.ticket).await.unwrap();
    let second_peer = client.add_peer_ticket(&second.ticket).await.unwrap();
    let channel = RelayChannel::new(RELAY_PROTOCOL, 4, SetupLimits::default());
    let request = RelayRequest {
        pool: POOL,
        target: TARGET,
    };
    let mut a = timeout(Duration::from_secs(10), open(&client, first_peer, 4, 8))
        .await
        .unwrap()
        .unwrap();
    let fixture = b"separate native processes; opaque relay fixture";
    a.write_all(fixture).await.unwrap();
    a.flush().await.unwrap();
    let mut reply = vec![0; fixture.len()];
    a.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, fixture);
    first.child.kill().unwrap();
    let _ = first.child.wait();
    assert!(matches!(
        // Abrupt UDP process death relies on the carrier's 30-second idle
        // detector; it cannot send a connection-close frame. Require an actual
        // read error inside that bound with scheduling slack.
        timeout(Duration::from_secs(40), a.read_u8()).await,
        Ok(Err(_))
    ));
    let now_ms = 10 + started.elapsed().as_millis() as u64;
    // The surviving worker's bounded authority snapshot may have expired while
    // the carrier detected abrupt loss. Re-read authority before offering work.
    second.allow(
        pool.authorize(root(4), DEVICE_B, TARGET, now_ms)
            .await
            .unwrap(),
        now_ms,
    );
    let mut b = timeout(Duration::from_secs(10), open(&client, second_peer, 4, 8))
        .await
        .unwrap()
        .unwrap();
    b.write_all(fixture).await.unwrap();
    b.flush().await.unwrap();
    b.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, fixture);
    pool.author(
        &identity(3),
        PoolEvent::Withdraw { device: DEVICE_B },
        now_ms,
    )
    .await
    .unwrap();
    assert!(
        pool.authorize(root(4), DEVICE_B, TARGET, now_ms)
            .await
            .is_err()
    );
    second.command("REVOKE");
    assert_eq!(second.wait_for("RELAY_ACK "), "revoke");
    assert!(matches!(
        timeout(Duration::from_secs(2), b.read_u8()).await,
        Ok(Err(_))
    ));
    let id = identity(4);
    assert!(
        channel
            .open(&client, second_peer, credentials(&id), request)
            .await
            .is_err()
    );
    second.stop();
    recipient_process.stop();
    client.close().await.unwrap();
}
