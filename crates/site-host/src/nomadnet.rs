//! Knot owns saved snapshots and the lifetime of this loopback interface.
use crate::{MAX_PAGE_BYTES, Publication, SiteFormat};
use retinue::{
    endpoint::{Endpoint, ResourceSession, ResourceTransferConfig},
    hash::AddressHash,
    identity::PrivateIdentity,
    nomadnet::{StaticNode, StaticPageConfig},
};
use std::{
    net::SocketAddr,
    sync::{Arc, RwLock},
    thread,
    time::Duration,
};

#[derive(Clone, Copy, Debug)]
pub struct NomadNetServerConfig {
    pub session_timeout: Duration,
    pub max_sessions: usize,
    pub transfer: ResourceTransferConfig,
}

impl Default for NomadNetServerConfig {
    fn default() -> Self {
        Self {
            session_timeout: Duration::from_secs(60),
            max_sessions: 16,
            transfer: ResourceTransferConfig::default(),
        }
    }
}

pub(crate) struct NomadNetServer {
    pub address: SocketAddr,
    pub destination: AddressHash,
    snapshot: Arc<RwLock<Arc<StaticNode>>>,
    config: NomadNetServerConfig,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    worker: Option<thread::JoinHandle<()>>,
}

fn snapshot(publication: Publication, config: NomadNetServerConfig) -> Result<StaticNode, String> {
    if publication.format != SiteFormat::Micron {
        return Err("NomadNet publication requires a Micron site".into());
    }
    let mut node = StaticNode::new();
    node.set_app_data(Vec::new());
    node.set_config(StaticPageConfig {
        max_page_bytes: MAX_PAGE_BYTES,
        transfer: config.transfer,
    });
    for (path, page) in publication.pages {
        node.insert_page(format!("/page{path}").as_bytes(), page.source)
            .map_err(|error| error.to_string())?;
    }
    Ok(node)
}

async fn serve_connection(
    mut session: ResourceSession,
    shared: Arc<RwLock<Arc<StaticNode>>>,
    config: NomadNetServerConfig,
) -> std::io::Result<()> {
    session.set_config(config.transfer);
    // A Resource proof confirms bytes, not the remote application's callback.
    // Keep the page link available until peer closure or the host's deadline.
    loop {
        let received = session.receive_request().await?;
        let node = Arc::clone(&shared.read().unwrap());
        node.respond_to_request(&mut session, received).await?;
    }
}

impl NomadNetServer {
    pub fn start(
        publication: Publication,
        port: u16,
        config: NomadNetServerConfig,
    ) -> Result<Self, String> {
        if config.max_sessions == 0 || config.session_timeout.is_zero() {
            return Err("NomadNet session limits must be positive".into());
        }
        let snapshot = Arc::new(RwLock::new(Arc::new(snapshot(publication, config)?)));
        let shared = Arc::clone(&snapshot);
        let mut secret = [0u8; 64];
        getrandom::getrandom(&mut secret).map_err(|error| error.to_string())?;
        let identity = PrivateIdentity::from_secret_bytes(&secret);
        secret.fill(0);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| error.to_string())?;
        let (shutdown, mut stopped) = tokio::sync::oneshot::channel();
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            runtime.block_on(async move {
            let endpoint = Arc::new(Endpoint::new(identity));
            let address = match endpoint.listen_tcp(([127, 0, 0, 1], port).into()).await {
                Ok(address) => address,
                Err(error) => { let _ = ready_tx.send(Err(error.to_string())); return; }
            };
            let destination = {
                let node = shared.read().unwrap();
                node.register(&endpoint);
                node.destination(endpoint.identity())
            };
            if ready_tx.send(Ok((address, destination))).is_err() { endpoint.close(); return; }
            let slots = Arc::new(tokio::sync::Semaphore::new(config.max_sessions));
            loop {
                tokio::select! {
                    _ = &mut stopped => break,
                    accepted = endpoint.accept_resource() => {
                        let Ok(accepted) = accepted else { break; };
                        let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else { continue; };
                        if accepted.destination != destination { continue; }
                        let shared = Arc::clone(&shared);
                        tokio::spawn(async move {
                            let _permit = permit;
                            let _ = tokio::time::timeout(config.session_timeout,
                                serve_connection(accepted.session, shared, config)).await;
                        });
                    }
                }
            }
            endpoint.close();
        })
        });
        let ready = ready_rx.recv().map_err(|error| error.to_string());
        let (address, destination) = match ready.and_then(|result| result) {
            Ok(ready) => ready,
            Err(error) => {
                let _ = worker.join();
                return Err(error);
            },
        };
        Ok(Self {
            address,
            destination,
            snapshot,
            config,
            shutdown: Some(shutdown),
            worker: Some(worker),
        })
    }

    pub fn replace(&self, publication: Publication) -> Result<(), String> {
        let next = snapshot(publication, self.config)?;
        *self.snapshot.write().unwrap() = Arc::new(next);
        Ok(())
    }
}

impl Drop for NomadNetServer {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
