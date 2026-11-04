//! An explicit Micron request client. Knot's local publisher stays static; a
//! user supplies a reachable Reticulum TCP interface for a separately operated
//! remote request handler.

use retinue::{
    endpoint::Endpoint,
    hash::AddressHash,
    identity::PrivateIdentity,
    request::{Response, StringMapLimits, StringMapRequest},
};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Request bounds for Micron submission. `map_limits` is available when the
/// optional `retinue` feature is enabled; backend-free builds expose only the
/// transport-independent timeout and response-size bounds through the stub.
#[derive(Clone, Copy, Debug)]
pub struct MicronSubmissionConfig {
    pub timeout: Duration,
    pub max_response_bytes: usize,
    pub map_limits: StringMapLimits,
}

impl Default for MicronSubmissionConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_response_bytes: 4 * 1024 * 1024,
            map_limits: StringMapLimits::default(),
        }
    }
}

/// A reviewed native request. `target` must name both an announced destination
/// and an absolute request path; local `:/` aliases have no standalone meaning.
pub struct PreparedMicronRequest {
    target: String,
    destination: AddressHash,
    path: String,
    values: BTreeMap<String, String>,
}

pub struct MicronResponse {
    pub body: Vec<u8>,
}

impl PreparedMicronRequest {
    pub fn new(
        target: String,
        values: BTreeMap<String, String>,
        config: MicronSubmissionConfig,
    ) -> Result<Self, String> {
        let (destination, path) = parse_target(&target)?;
        let request = StringMapRequest::new(path.as_bytes(), values.clone(), now_seconds()?);
        request
            .pack(config.map_limits)
            .map_err(|_| "Micron request exceeds the supported map limit".to_string())?;
        Ok(Self {
            target,
            destination,
            path,
            values,
        })
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    /// One explicit request over the caller-configured TCP interface. A timeout
    /// after bytes leave the process has an unknown remote outcome; callers must
    /// not retry automatically.
    pub async fn send(
        self,
        interface: SocketAddr,
        config: MicronSubmissionConfig,
    ) -> Result<MicronResponse, String> {
        if config.timeout.is_zero() || config.max_response_bytes == 0 {
            return Err("Micron submission limits must be positive".into());
        }
        tokio::time::timeout(config.timeout, async move {
            let mut secret = [0u8; 64];
            getrandom::getrandom(&mut secret).map_err(|error| error.to_string())?;
            let identity = PrivateIdentity::from_secret_bytes(&secret);
            secret.fill(0);
            let endpoint = Endpoint::connect(interface, identity)
                .await
                .map_err(|error| error.to_string())?;
            endpoint.request_path(self.destination);
            let peer = loop {
                if let Some(peer) = endpoint.resolve(self.destination) {
                    break peer;
                }
                endpoint
                    .next_announcement()
                    .await
                    .map_err(|error| error.to_string())?;
            };
            let request = StringMapRequest::new(self.path.as_bytes(), self.values, now_seconds()?);
            let packed = request
                .pack(config.map_limits)
                .map_err(|_| "Micron request exceeds the supported map limit".to_string())?;
            let received = endpoint
                .request_raw(self.destination, peer, &packed)
                .await
                .map_err(|error| error.to_string())?;
            // Flush the Resource acknowledgement before abrupt Endpoint::Drop.
            // The enclosing timeout bounds this graceful shutdown as well.
            endpoint.shutdown(config.timeout).await;
            // Check the received bytes before decoding. An oversized reply
            // arrives as a single Resource that Response::unpack rejects, so a
            // post-unpack-only cap reported "invalid response" for what is
            // really a size refusal (2026-09-13 headed acceptance, finding 3).
            // The envelope allowance is a decode bound, not a wire ceiling.
            if received.packed.len() > config.max_response_bytes.saturating_add(64) {
                return Err(format!(
                    "Remote Micron response exceeds {} bytes",
                    config.max_response_bytes
                ));
            }
            let response = Response::unpack(&received.packed)
                .map_err(|_| "Remote Micron handler returned an invalid response".to_string())?;
            if response.data.len() > config.max_response_bytes {
                return Err(format!(
                    "Remote Micron response exceeds {} bytes",
                    config.max_response_bytes
                ));
            }
            Ok(MicronResponse {
                body: response.data,
            })
        })
        .await
        .map_err(|_| {
            "Micron request timed out; the remote outcome may be unknown. Review before retrying."
                .to_string()
        })?
    }
}

fn now_seconds() -> Result<f64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .map_err(|error| error.to_string())
}

fn parse_target(target: &str) -> Result<(AddressHash, String), String> {
    let (destination, path) = target
        .split_once(":/")
        .ok_or("Micron sending requires destination:/absolute/path, not a local :/ alias")?;
    if destination.len() != 32
        || !destination.bytes().all(|byte| byte.is_ascii_hexdigit())
        || path.is_empty()
        || path.starts_with('/')
        || path
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(
            "Micron target must be a 32-digit destination and a plain absolute path".into(),
        );
    }
    let mut bytes = [0u8; 16];
    for (index, part) in destination.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(part).map_err(|_| "Invalid Micron destination")?;
        bytes[index] = u8::from_str_radix(text, 16).map_err(|_| "Invalid Micron destination")?;
    }
    Ok((AddressHash::from_bytes(bytes), format!("/{path}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use retinue::{destination::DestinationName, endpoint::Endpoint};
    use std::sync::Arc;

    #[test]
    fn native_target_requires_a_full_destination_and_absolute_path() {
        assert!(parse_target(":/form").is_err());
        assert!(parse_target("not-a-destination:/form").is_err());
        assert!(parse_target("0123456789abcdef0123456789abcdef:/form").is_ok());
    }

    #[test]
    fn preparation_enforces_the_configured_map_bound_before_connecting() {
        let mut values = BTreeMap::new();
        values.insert("field_note".into(), "x".repeat(128));
        let config = MicronSubmissionConfig {
            map_limits: StringMapLimits {
                max_entries: 1,
                max_encoded_bytes: 32,
            },
            ..MicronSubmissionConfig::default()
        };
        assert!(
            PreparedMicronRequest::new(
                "0123456789abcdef0123456789abcdef:/form".into(),
                values,
                config,
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn explicit_client_sends_a_typed_map_to_a_loopback_handler() {
        let server = Arc::new(Endpoint::new(PrivateIdentity::from_secret_bytes(
            &[0x41; 64],
        )));
        let address = server.listen_tcp(([127, 0, 0, 1], 0).into()).await.unwrap();
        let name = DestinationName::new("nomadnetwork", ["node"]);
        let destination = name.destination_hash(server.identity());
        server.register_resource(name, &[]);
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
        let handler = {
            let server = Arc::clone(&server);
            tokio::spawn(async move {
                let accepted = server.accept_resource().await.unwrap();
                let mut session = accepted.session;
                let received = session.receive_raw_request().await.unwrap();
                let request =
                    StringMapRequest::unpack(&received.packed, StringMapLimits::default()).unwrap();
                assert_eq!(request.data.get("field_note"), Some(&"hello".into()));
                session
                    .respond_auto(received.request_id, vec![b'x'; 4096])
                    .await
                    .unwrap();
                let _ = done_rx.await;
            })
        };
        let mut values = BTreeMap::new();
        values.insert("field_note".into(), "hello".into());
        let response = PreparedMicronRequest::new(
            format!("{destination}:/capture"),
            values,
            MicronSubmissionConfig::default(),
        )
        .unwrap()
        .send(address, MicronSubmissionConfig::default())
        .await
        .unwrap();
        assert_eq!(response.body, vec![b'x'; 4096]);
        let _ = done_tx.send(());
        tokio::time::timeout(Duration::from_secs(10), handler)
            .await
            .unwrap()
            .unwrap();
        server.close();
    }

    /// An oversized Resource reply must name the cap, not report a decode
    /// failure: the pre-decode check runs on the received bytes.
    #[tokio::test]
    async fn an_oversized_resource_reply_is_refused_by_size_not_as_invalid() {
        let server = Arc::new(Endpoint::new(PrivateIdentity::from_secret_bytes(
            &[0x42; 64],
        )));
        let address = server.listen_tcp(([127, 0, 0, 1], 0).into()).await.unwrap();
        let name = DestinationName::new("nomadnetwork", ["node"]);
        let destination = name.destination_hash(server.identity());
        server.register_resource(name, &[]);
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
        let handler = {
            let server = Arc::clone(&server);
            tokio::spawn(async move {
                let accepted = server.accept_resource().await.unwrap();
                let mut session = accepted.session;
                let received = session.receive_raw_request().await.unwrap();
                session
                    .respond_auto(received.request_id, vec![b'x'; 4096])
                    .await
                    .unwrap();
                let _ = done_rx.await;
            })
        };
        let config = MicronSubmissionConfig {
            max_response_bytes: 1024,
            ..MicronSubmissionConfig::default()
        };
        let mut values = BTreeMap::new();
        values.insert("field_note".into(), "hello".into());
        let outcome = PreparedMicronRequest::new(format!("{destination}:/capture"), values, config)
            .unwrap()
            .send(address, config)
            .await;
        match outcome {
            Err(error) => assert_eq!(error, "Remote Micron response exceeds 1024 bytes"),
            Ok(response) => panic!("expected a size refusal, got {} bytes", response.body.len()),
        }
        let _ = done_tx.send(());
        tokio::time::timeout(Duration::from_secs(10), handler)
            .await
            .unwrap()
            .unwrap();
        server.close();
    }
}
