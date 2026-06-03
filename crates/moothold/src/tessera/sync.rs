//! Tessera sync over LogSync — the moot's reputation log replicated.
//!
//! [`SyncedMoot`] runs the offline-catch-up + live lane for one moot's tessera
//! event log: a `LogSync` (RBSR) session over the moot's [`TesseraStore`], which
//! reconciles operations a peer missed while away and drains each received
//! operation into the store (verified + idempotent, content-addressed). It is
//! the tessera counterpart of murm's `gossip_sync::SyncedCabal`, trimmed to the
//! LogSync lane the [`tessera-logsync` probe] proved.
//!
//! It is **decoupled from the host transport**: `join` takes the raw p2panda-net
//! [`Endpoint`] + [`Gossip`] (which the host pulls from its `P2pandaTransport`
//! via `sync_parts`), so moothold drives the session without depending on the
//! `transport` crate. The moot id is the LogSync topic (the operation's signed
//! addressing extension), so a session syncs exactly that moot's log.
//!
//! Once peers converge, [`ledger`](SyncedMoot::ledger) folds the synced store
//! into the moot's [`Ledger`] — every member's log, deterministically ordered —
//! and the host reads `scores(now_ms)` from it. [`sync_status`] is real
//! (non-placebo) feedback: rounds finished, operations caught up, last activity.
//!
//! [`tessera-logsync` probe]: ../../../../crates/probes/tessera-logsync
//! [`sync_status`]: SyncedMoot::sync_status

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use p2panda_core::Topic;
use p2panda_net::{Endpoint, Gossip, LogSync};
use p2panda_sync::protocols::TopicLogSyncEvent;
use tokio::task::JoinHandle;
use tokio_stream::StreamExt;

use crate::tessera::ledger::{Ledger, TesseraConfig};
use crate::tessera::store::{TesseraStore, TesseraStoreError};
use crate::tessera::wire::verify;

/// Unix-epoch milliseconds, for stamping the last sync activity.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A moot sync failure (LogSync session setup or the underlying store).
#[derive(Debug, thiserror::Error)]
pub enum MootSyncError {
    #[error("moot sync: {0}")]
    Backend(String),
    #[error(transparent)]
    Store(#[from] TesseraStoreError),
}

/// A snapshot of a moot's tessera-sync activity, for a real sync indicator.
///
/// Counters accumulate over the moot's subscription; read a snapshot with
/// [`SyncedMoot::sync_status`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncStatus {
    /// A LogSync reconciliation round is currently in progress.
    pub syncing: bool,
    /// LogSync rounds that have finished (a peer's catch-up completing).
    pub sync_rounds: u64,
    /// Tessera operations caught up via LogSync.
    pub ops_received: u64,
    /// Unix-epoch milliseconds of the most recent sync activity, or `None` if
    /// nothing has arrived yet.
    pub last_activity_ms: Option<u64>,
}

/// The result of a manual [`SyncedMoot::resync`] checkpoint.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncRound {
    /// New operations that landed during the checkpoint window. `0` means
    /// already up to date.
    pub items_received: u64,
}

/// A moot joined to its tessera LogSync session.
///
/// Holds the store and a background task draining the LogSync session into it.
/// [`ledger`](Self::ledger) projects the synced store into the moot's reputation
/// state. Dropping it ends the session and stops the task.
pub struct SyncedMoot {
    store: TesseraStore,
    moot_id: [u8; 32],
    /// Drains operations the LogSync session reconciles into the store.
    logsync_task: JoinHandle<()>,
    /// Live sync activity, written by the drain task; read via [`sync_status`].
    ///
    /// [`sync_status`]: Self::sync_status
    status: Arc<Mutex<SyncStatus>>,
}

impl SyncedMoot {
    /// Join a moot's tessera LogSync session over `store`, driven by the host's
    /// `endpoint` + `gossip` (from its transport's `sync_parts`).
    ///
    /// Spawns a background task that reconciles the moot's log and drains each
    /// received operation into the store (verifying the signature, idempotent on
    /// the hash). The session syncs the topic `Topic::from(moot_id)`.
    pub async fn join(
        endpoint: Endpoint,
        gossip: Gossip,
        store: TesseraStore,
        moot_id: [u8; 32],
    ) -> Result<Self, MootSyncError> {
        let status = Arc::new(Mutex::new(SyncStatus::default()));

        let log_sync = LogSync::builder(store.clone(), endpoint, gossip)
            .spawn()
            .await
            .map_err(|e| MootSyncError::Backend(format!("logsync spawn: {e}")))?;
        let handle = log_sync
            .stream(Topic::from(moot_id), true)
            .await
            .map_err(|e| MootSyncError::Backend(format!("logsync stream: {e}")))?;
        let mut sub = handle
            .subscribe()
            .await
            .map_err(|e| MootSyncError::Backend(format!("logsync subscribe: {e}")))?;

        let task_store = store.clone();
        let task_status = Arc::clone(&status);
        let logsync_task = tokio::spawn(async move {
            // Hold the session handles for the task's lifetime; dropping them
            // ends the LogSync session.
            let _log_sync = log_sync;
            let _handle = handle;
            while let Some(item) = sub.next().await {
                let Ok(from_sync) = item else { continue };
                match from_sync.event {
                    TopicLogSyncEvent::SyncStarted { .. } => {
                        let mut s = task_status.lock().unwrap();
                        s.syncing = true;
                        s.last_activity_ms = Some(now_ms());
                    }
                    TopicLogSyncEvent::OperationReceived { operation, .. } => {
                        let op = *operation;
                        // Verify the signature (defence in depth behind the
                        // protocol's header validation) before folding it in;
                        // count only ops that verify and are new.
                        if verify(&op) && matches!(task_store.insert(&op), Ok(true)) {
                            let mut s = task_status.lock().unwrap();
                            s.ops_received += 1;
                            s.last_activity_ms = Some(now_ms());
                        }
                    }
                    TopicLogSyncEvent::SyncFinished { .. } => {
                        let mut s = task_status.lock().unwrap();
                        s.syncing = false;
                        s.sync_rounds += 1;
                        s.last_activity_ms = Some(now_ms());
                    }
                    _ => {}
                }
            }
        });

        Ok(Self {
            store,
            moot_id,
            logsync_task,
            status,
        })
    }

    /// The moot's operation store.
    pub fn store(&self) -> &TesseraStore {
        &self.store
    }

    /// The moot this session syncs.
    pub fn moot_id(&self) -> [u8; 32] {
        self.moot_id
    }

    /// Project the synced store into the moot's [`Ledger`] (every member's log,
    /// folded under `config`). Ask the returned ledger for `scores(now_ms)`.
    pub fn ledger(&self, config: TesseraConfig) -> Result<Ledger, TesseraStoreError> {
        self.store.fold_moot(self.moot_id, config)
    }

    /// A snapshot of this moot's sync activity, for a real sync indicator:
    /// whether a round is in progress, rounds finished, operations caught up, and
    /// when activity last happened.
    pub fn sync_status(&self) -> SyncStatus {
        self.status.lock().unwrap().clone()
    }

    /// Run a manual "sync now" checkpoint and report what arrived.
    ///
    /// LogSync already reconciles **continuously**, so this is not a fake spinner
    /// and not a forced re-fetch (p2panda 0.6.1 exposes no public "re-initiate"
    /// hook): it watches the live session until it goes quiet and returns the
    /// real count of operations that landed during the window. It returns as soon
    /// as activity settles, so a quiet, already-synced moot reports `0` quickly.
    pub async fn resync(&self) -> Result<SyncRound, MootSyncError> {
        let received = || self.status.lock().unwrap().ops_received;
        let start = received();
        let mut last = start;
        let mut quiet = 0u8;
        // Poll up to ~3s; stop after ~300ms with nothing new (settled).
        for _ in 0..30 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let now = received();
            if now == last {
                quiet += 1;
                if quiet >= 3 {
                    break;
                }
            } else {
                last = now;
                quiet = 0;
            }
        }
        Ok(SyncRound {
            items_received: last.saturating_sub(start),
        })
    }
}

impl Drop for SyncedMoot {
    fn drop(&mut self) {
        self.logsync_task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tessera::event::{ChainRoot, CommitmentId, Scope, TesseraEvent};
    use crate::tessera::wire::{to_operation, TesseraExt};
    use identity::{Ed25519Keypair, IdentityProvider, InMemoryProvider};
    use p2panda_core::Operation;
    use std::sync::Arc;
    use transport::{P2pandaTransport, PeerID};

    const MOOT: [u8; 32] = [0x33; 32];

    /// A `commit -> fulfil -> govern` chained log for `kp` (scores 11).
    fn commit_fulfil_govern(kp: &Ed25519Keypair) -> Vec<Operation<TesseraExt>> {
        let by = ChainRoot(kp.public_key().to_bytes());
        let cid = CommitmentId([0xc1; 32]);
        let e0 = TesseraEvent::CommitmentMade {
            by,
            commitment: cid,
            scope: Scope("host/cluster".into()),
            cadence_ms: 1_000,
            duration_ms: None,
            at_ms: 1_000,
        };
        let e1 = TesseraEvent::CommitmentFulfilled { by, commitment: cid, at_ms: 1_050 };
        let e2 = TesseraEvent::GovernanceParticipation { by, at_ms: 1_100 };
        let op0 = to_operation(kp, MOOT, &e0, 0, None);
        let op1 = to_operation(kp, MOOT, &e1, 1, Some(*op0.hash.as_bytes()));
        let op2 = to_operation(kp, MOOT, &e2, 2, Some(*op1.hash.as_bytes()));
        vec![op0, op1, op2]
    }

    /// Two real p2panda-net peers: A holds a tessera log before B connects, B
    /// catches up over LogSync, and both fold their stores to the same score.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_moots_converge_on_the_same_scores() {
        let alice_provider = Arc::new(InMemoryProvider::from_seed([40; 32]));
        let bob_provider = Arc::new(InMemoryProvider::from_seed([41; 32]));
        let alice_id = PeerID::from_public_key(alice_provider.master_public_key());
        let bob_id = PeerID::from_public_key(bob_provider.master_public_key());
        let alice_kp = alice_provider.master_keypair().clone();
        let bob_kp = bob_provider.master_keypair().clone();

        let alice_t = P2pandaTransport::builder(&alice_kp)
            .gossip()
            .bind()
            .await
            .expect("bind alice");
        let bob_t = P2pandaTransport::builder(&bob_kp)
            .gossip()
            .bind()
            .await
            .expect("bind bob");

        // The tessera author is a derived persona key; the transport runs on the
        // master key. Peer A authors, peer B only receives.
        let author = alice_provider.derive_keypair(b"tessera-author").unwrap();
        let author_root = ChainRoot(author.public_key().to_bytes());

        // LogSync joins gossip on the derived overlay topic — tag peers with it.
        let overlay = transport::sync_overlay_topic(MOOT);
        alice_t.add_peer(bob_t.endpoint_addr().await.unwrap()).await.unwrap();
        alice_t.set_topics(bob_id, &[overlay]).await.unwrap();
        bob_t.add_peer(alice_t.endpoint_addr().await.unwrap()).await.unwrap();
        bob_t.set_topics(alice_id, &[overlay]).await.unwrap();

        // Alice holds a 3-event tessera log before bob connects (offline catch-up).
        let alice_store = TesseraStore::in_memory().unwrap();
        for op in commit_fulfil_govern(&author) {
            alice_store.insert(&op).unwrap();
        }
        let bob_store = TesseraStore::in_memory().unwrap();

        let (a_ep, a_gossip) = alice_t.sync_parts().expect("alice sync parts");
        let (b_ep, b_gossip) = bob_t.sync_parts().expect("bob sync parts");
        let alice_moot = SyncedMoot::join(a_ep, a_gossip, alice_store, MOOT)
            .await
            .expect("alice join");
        let bob_moot = SyncedMoot::join(b_ep, b_gossip, bob_store, MOOT)
            .await
            .expect("bob join");

        // Bob catches up over LogSync and folds the synced log to score 11.
        let converged = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let ledger = bob_moot.ledger(TesseraConfig::default()).unwrap();
                if ledger.score(&author_root, 5_000) == 11 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await;
        assert!(
            converged.is_ok(),
            "bob converged on alice's tessera score over LogSync within the timeout"
        );

        // Both peers compute the identical score from their own stores.
        let alice_score = alice_moot
            .ledger(TesseraConfig::default())
            .unwrap()
            .score(&author_root, 5_000);
        let bob_score = bob_moot
            .ledger(TesseraConfig::default())
            .unwrap()
            .score(&author_root, 5_000);
        assert_eq!(bob_score, alice_score, "both peers project the same score");
        assert_eq!(bob_score, 11, "+10 fulfil, +1 govern");

        // Real (non-placebo) sync feedback recorded the catch-up.
        let status = bob_moot.sync_status();
        assert!(
            status.ops_received >= 3,
            "sync status recorded the caught-up ops (got {})",
            status.ops_received
        );
        assert!(status.last_activity_ms.is_some());

        // The manual checkpoint returns quickly (already synced).
        let round = bob_moot.resync().await.expect("resync runs");
        println!("tessera resync checkpoint: items_received={}", round.items_received);
    }

    /// The same convergence, bootstrapped by **ticket** — the host's "connect to
    /// peer" path. Each side parses the other's ticket string (not its raw
    /// `EndpointAddr`), proving `transport::ticket` / `add_peer_ticket` drive a
    /// real LogSync convergence end to end.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_moots_converge_bootstrapped_by_ticket() {
        let alice_provider = Arc::new(InMemoryProvider::from_seed([50; 32]));
        let bob_provider = Arc::new(InMemoryProvider::from_seed([51; 32]));
        let alice_kp = alice_provider.master_keypair().clone();
        let bob_kp = bob_provider.master_keypair().clone();

        let alice_t = P2pandaTransport::builder(&alice_kp)
            .gossip()
            .bind()
            .await
            .expect("bind alice");
        let bob_t = P2pandaTransport::builder(&bob_kp)
            .gossip()
            .bind()
            .await
            .expect("bind bob");

        let author = alice_provider.derive_keypair(b"tessera-author").unwrap();
        let author_root = ChainRoot(author.public_key().to_bytes());

        // Bootstrap by ticket: each side parses the other's ticket (learning its
        // PeerID + transport info) and tags it on the derived overlay topic.
        let overlay = transport::sync_overlay_topic(MOOT);
        let bob_learns_alice = bob_t
            .add_peer_ticket(&alice_t.ticket().await.unwrap())
            .await
            .unwrap();
        bob_t.set_topics(bob_learns_alice, &[overlay]).await.unwrap();
        let alice_learns_bob = alice_t
            .add_peer_ticket(&bob_t.ticket().await.unwrap())
            .await
            .unwrap();
        alice_t.set_topics(alice_learns_bob, &[overlay]).await.unwrap();

        let alice_store = TesseraStore::in_memory().unwrap();
        for op in commit_fulfil_govern(&author) {
            alice_store.insert(&op).unwrap();
        }
        let bob_store = TesseraStore::in_memory().unwrap();

        let (a_ep, a_gossip) = alice_t.sync_parts().expect("alice sync parts");
        let (b_ep, b_gossip) = bob_t.sync_parts().expect("bob sync parts");
        let alice_moot = SyncedMoot::join(a_ep, a_gossip, alice_store, MOOT)
            .await
            .expect("alice join");
        let bob_moot = SyncedMoot::join(b_ep, b_gossip, bob_store, MOOT)
            .await
            .expect("bob join");

        let converged = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let score = bob_moot
                    .ledger(TesseraConfig::default())
                    .unwrap()
                    .score(&author_root, 5_000);
                if score == 11 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await;
        assert!(
            converged.is_ok(),
            "bob converged on alice's score via a ticket-bootstrapped connection"
        );
        let alice_score = alice_moot
            .ledger(TesseraConfig::default())
            .unwrap()
            .score(&author_root, 5_000);
        let bob_score = bob_moot
            .ledger(TesseraConfig::default())
            .unwrap()
            .score(&author_root, 5_000);
        assert_eq!(bob_score, alice_score, "both peers agree after a ticket bootstrap");
        assert_eq!(bob_score, 11);
    }
}
