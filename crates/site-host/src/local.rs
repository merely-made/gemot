//! Process ownership around the shared wire servers. Native Gemini and Spartan
//! listeners stop admission, drain, then cancel and join through their supplier
//! before this host joins its dedicated runtime thread.
#[cfg(feature = "retinue")]
use crate::nomadnet::NomadNetServer;
use crate::{Publication, SiteFormat, server::ScrollServer};
use std::{
    future::Future,
    net::SocketAddr,
    sync::{Arc, RwLock},
    thread,
    time::{Duration, Instant},
};

async fn run_native_server(
    operation: impl Future<Output = std::io::Result<()>>,
    ready: std::sync::mpsc::SyncSender<Result<(), String>>,
) -> Result<(), String> {
    let mut operation = std::pin::pin!(operation);
    let mut ready = Some(ready);
    std::future::poll_fn(|cx| {
        let result = operation.as_mut().poll(cx);
        if let Some(ready) = ready.take() {
            let startup = match &result {
                std::task::Poll::Pending => Ok(()),
                std::task::Poll::Ready(Err(error)) => Err(error.to_string()),
                std::task::Poll::Ready(Ok(())) => {
                    Err("Local site server ended during startup".into())
                },
            };
            let _ = ready.send(startup);
        }
        result.map(|result| result.map_err(|error| error.to_string()))
    })
    .await
}

/// Host policy for Knot's native Gemini and Spartan loopback listeners.
/// This is runtime policy, separate from saved-site metadata and snapshot V1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalServerConfig {
    /// Maximum admitted connection tasks. At capacity, acceptance pauses;
    /// queued peers remain subject to the OS backlog. Default 32, nonzero.
    pub max_connections: usize,
    /// One fixed graceful-drain allowance after shutdown is observed. Default
    /// 5s; zero cancels immediately. Remaining tasks are then aborted and joined.
    pub shutdown_grace: Duration,
    /// Existing Knot native I/O allowance, default 2s. Gemini applies it to
    /// TLS and request reads; Spartan applies it to request/body reads. It is
    /// independent of shutdown grace and is not a whole-handler deadline.
    pub timeout: Duration,
}

impl Default for LocalServerConfig {
    fn default() -> Self {
        Self {
            max_connections: 32,
            shutdown_grace: Duration::from_secs(5),
            timeout: Duration::from_secs(2),
        }
    }
}

impl LocalServerConfig {
    fn validate(self) -> Result<(), String> {
        if self.max_connections == 0 {
            return Err("Local site max_connections must be nonzero".into());
        }
        if self.timeout.is_zero()
            || Instant::now().checked_add(self.timeout).is_none()
            || tokio::time::Instant::now()
                .checked_add(self.timeout)
                .is_none()
        {
            return Err("Local site timeout must be nonzero and representable".into());
        }
        if Instant::now().checked_add(self.shutdown_grace).is_none()
            || tokio::time::Instant::now()
                .checked_add(self.shutdown_grace)
                .is_none()
        {
            return Err("Local site shutdown_grace must be representable".into());
        }
        Ok(())
    }
}

pub struct LocalServer {
    backend: Backend,
    pub certificate_pem: String,
}

enum Backend {
    Scroll(ScrollServer),
    #[cfg(feature = "retinue")]
    NomadNet(crate::nomadnet::NomadNetServer),
    Native {
        address: SocketAddr,
        format: SiteFormat,
        publication: Arc<RwLock<Publication>>,
        shutdown: Option<tokio::sync::oneshot::Sender<()>>,
        worker: Option<thread::JoinHandle<Result<(), String>>>,
    },
}

impl LocalServer {
    pub fn start(publication: Publication, port: u16) -> Result<Self, String> {
        let format = publication.format;
        if format == SiteFormat::Scroll {
            let server = ScrollServer::start(publication, port)?;
            return Ok(Self {
                certificate_pem: server.certificate_pem.clone(),
                backend: Backend::Scroll(server),
            });
        }
        if format == SiteFormat::Micron {
            #[cfg(feature = "retinue")]
            return Self::start_nomadnet(publication, port, Default::default());
            #[cfg(not(feature = "retinue"))]
            return Err("Micron local serving requires the optional `retinue` feature".into());
        }
        Self::start_with_config(publication, port, LocalServerConfig::default())
    }

    /// Start a native Gemini or Spartan listener with caller-selected policy.
    /// Invalid policy refuses before binding or creating TLS/runtime state.
    /// Scroll and Micron keep their existing separately owned host APIs.
    pub fn start_with_config(
        publication: Publication,
        port: u16,
        config: LocalServerConfig,
    ) -> Result<Self, String> {
        let format = publication.format;
        if !matches!(format, SiteFormat::Gemini | SiteFormat::Spartan) {
            return Err("LocalServerConfig applies only to Gemini and Spartan hosts".into());
        }
        config.validate()?;
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
            .map_err(|e| e.to_string())?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let address = listener.local_addr().map_err(|e| e.to_string())?;
        let (acceptor, certificate_pem) = if format == SiteFormat::Gemini {
            let cert =
                rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
                    .map_err(|e| e.to_string())?;
            let pem = cert.cert.pem();
            let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
            (
                Some(
                    gemini_protocol::server::acceptor(vec![cert.cert.der().clone()], key.into())
                        .map_err(|e| e.to_string())?,
                ),
                pem,
            )
        } else {
            (None, String::new())
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        let publication = Arc::new(RwLock::new(publication));
        let shared = Arc::clone(&publication);
        let (shutdown, stopped) = tokio::sync::oneshot::channel();
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            runtime.block_on(async move {
                let listener = match tokio::net::TcpListener::from_std(listener) {
                    Ok(listener) => listener,
                    Err(e) => {
                        let error = e.to_string();
                        let _ = ready_tx.send(Err(error.clone()));
                        return Err(error);
                    },
                };
                if let Some(acceptor) = acceptor {
                    let handler = move |request: gemini_protocol::server::Request| {
                        let reply = shared
                            .read()
                            .unwrap()
                            .gemini_reply(&request.url, address.port());
                        async move { reply }
                    };
                    let config = gemini_protocol::server::ServerConfig {
                        timeout: config.timeout,
                        max_connections: config.max_connections,
                        shutdown_grace: config.shutdown_grace,
                        ..Default::default()
                    };
                    run_native_server(
                        gemini_protocol::server::serve(
                            listener,
                            acceptor,
                            handler,
                            config,
                            async {
                                let _ = stopped.await;
                            },
                        ),
                        ready_tx,
                    )
                    .await
                } else {
                    let handler = move |request: spartan_protocol::Request| {
                        let reply = shared.read().unwrap().spartan_reply(&request);
                        async move { reply }
                    };
                    let config = spartan_protocol::ServerConfig {
                        timeout: config.timeout,
                        max_connections: config.max_connections,
                        shutdown_grace: config.shutdown_grace,
                        ..Default::default()
                    };
                    run_native_server(
                        spartan_protocol::serve(listener, handler, config, async {
                            let _ = stopped.await;
                        }),
                        ready_tx,
                    )
                    .await
                }
            })
            // The native server joins accepted tasks before this runtime drops.
        });
        match ready_rx.recv() {
            Ok(Ok(())) => {},
            error => {
                let _ = worker.join();
                return Err(match error {
                    Ok(Err(error)) => error,
                    Err(error) => error.to_string(),
                    Ok(Ok(())) => unreachable!(),
                });
            },
        }
        Ok(Self {
            certificate_pem,
            backend: Backend::Native {
                address,
                format,
                publication,
                shutdown: Some(shutdown),
                worker: Some(worker),
            },
        })
    }

    pub fn address(&self) -> SocketAddr {
        match &self.backend {
            Backend::Scroll(server) => server.address(),
            #[cfg(feature = "retinue")]
            Backend::NomadNet(server) => server.address,
            Backend::Native { address, .. } => *address,
        }
    }

    /// Stop serving and wait for the host to release all of its accepted work.
    /// Gemini/Spartan stop admission, drain for the configured grace, cancel
    /// remaining connections, join them, then join the host thread. Native
    /// serve errors and host-thread panics are reported here. `Drop` performs
    /// the same wait but cannot report errors. This synchronous wait, including
    /// cancellation, requires cooperative handler and transport work.
    /// Other formats retain their existing host teardown behavior.
    pub fn stop(mut self) -> Result<(), String> {
        self.stop_native()
    }

    fn stop_native(&mut self) -> Result<(), String> {
        if let Backend::Native {
            shutdown, worker, ..
        } = &mut self.backend
        {
            if let Some(sender) = shutdown.take() {
                let _ = sender.send(());
            }
            if let Some(worker) = worker.take() {
                return worker
                    .join()
                    .map_err(|_| "Local site server thread panicked".to_string())?;
            }
        }
        Ok(())
    }

    pub fn url(&self) -> String {
        match &self.backend {
            Backend::Scroll(server) => server.url(),
            #[cfg(feature = "retinue")]
            Backend::NomadNet(server) => format!(
                "{}:/page/index.mu (ephemeral destination; Reticulum TCP interface {})",
                server.destination, server.address
            ),
            Backend::Native {
                address, format, ..
            } => format!(
                "{}://localhost:{}/",
                if *format == SiteFormat::Gemini {
                    "gemini"
                } else {
                    "spartan"
                },
                address.port()
            ),
        }
    }

    pub fn replace(&self, next: Publication) -> Result<(), String> {
        match &self.backend {
            #[cfg(feature = "retinue")]
            Backend::NomadNet(server) => server.replace(next),
            Backend::Scroll(server) if next.format == SiteFormat::Scroll => {
                server.replace(next);
                Ok(())
            },
            Backend::Native {
                format,
                publication,
                ..
            } if next.format == *format => {
                *publication.write().unwrap() = next;
                Ok(())
            },
            _ => Err("Stop serving before changing the site protocol".into()),
        }
    }

    /// Start a Micron saved snapshot with caller-selected connection limits.
    #[cfg(feature = "retinue")]
    pub fn start_nomadnet(
        publication: Publication,
        port: u16,
        config: crate::NomadNetServerConfig,
    ) -> Result<Self, String> {
        Ok(Self {
            certificate_pem: String::new(),
            backend: Backend::NomadNet(NomadNetServer::start(publication, port, config)?),
        })
    }

    /// The transient address for a running Micron server, when its optional
    /// Reticulum backend is available.
    #[cfg(feature = "retinue")]
    pub fn nomadnet_destination(&self) -> Option<retinue::hash::AddressHash> {
        match &self.backend {
            Backend::NomadNet(server) => Some(server.destination),
            _ => None,
        }
    }

    /// The transient Micron destination as text, when its optional backend is
    /// available. This accessor has the same signature in all feature sets.
    pub fn nomadnet_destination_string(&self) -> Option<String> {
        #[cfg(feature = "retinue")]
        {
            self.nomadnet_destination()
                .map(|destination| destination.to_string())
        }
        #[cfg(not(feature = "retinue"))]
        {
            None
        }
    }
}

impl Drop for LocalServer {
    fn drop(&mut self) {
        let _ = self.stop_native();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn startup_refuses_immediate_serve_failure_or_completion() {
        for outcome in [Err(std::io::Error::other("native startup refused")), Ok(())] {
            let (ready, receiver) = std::sync::mpsc::sync_channel(1);
            let expected = outcome.as_ref().err().map_or(
                "Local site server ended during startup".to_string(),
                ToString::to_string,
            );
            let _ = run_native_server(std::future::ready(outcome), ready).await;
            assert_eq!(receiver.try_recv().unwrap(), Err(expected));
        }
    }
}
