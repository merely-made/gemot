/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! Moot sync over LogSync — the moot's object log, replicated.
//!
//! [`SyncedMootSpace`] is the `SyncedMesh` shape over the moot lane: a
//! LogSync (RBSR) catch-up + live session over the [`MootStore`], a
//! verifying drain task, an authoring path
//! ([`author`](SyncedMootSpace::author): sign at the device's next log
//! position, persist, push onto the live gossip lane), the folded
//! [`roster`](SyncedMootSpace::roster), and **real** [`SyncStatus`] (the
//! no-placebo rule). Decoupled from the host transport: `join` takes raw
//! p2panda-net [`Endpoint`] + [`Gossip`] from the host's `sync_parts`.
//!
//! (The tessera lane's `SyncedMoot` is the receive-only sibling on the same
//! moot id; the one-endpoint unification of the two lanes is a named later
//! slice — see the M1 plan.)

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use identity::Ed25519Keypair;
use p2panda_core::{Operation, SigningKey, Topic};
use p2panda_net::sync::SyncHandle;
use p2panda_net::{Endpoint, Gossip, LogSync};
use p2panda_store::SqliteStore;
use p2panda_sync::protocols::TopicLogSyncEvent;
use tokio::task::JoinHandle;
use tokio_stream::StreamExt;

use super::roster::MootRoster;
use super::store::{MootStore, MootStoreError};
use super::wire::{MootEvent, MootExt, to_operation, verify};

type MootLogSync = LogSync<SqliteStore, [u8; 32], MootExt>;
type MootSyncHandle = SyncHandle<Operation<MootExt>, TopicLogSyncEvent<MootExt>>;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A moot sync failure (session setup, publish, or the store).
#[derive(Debug, thiserror::Error)]
pub enum MootSyncError {
    #[error("moot sync: {0}")]
    Backend(String),
    #[error(transparent)]
    Store(#[from] MootStoreError),
}

/// A snapshot of a moot's sync activity, for a real sync indicator.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncStatus {
    pub syncing: bool,
    pub sync_rounds: u64,
    pub ops_received: u64,
    pub last_activity_ms: Option<u64>,
}

/// The result of a manual [`SyncedMootSpace::resync`] checkpoint.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncRound {
    /// New operations that landed during the checkpoint window.
    pub items_received: u64,
}

/// A device joined to a moot's object-log session.
pub struct SyncedMootSpace {
    store: MootStore,
    moot_id: [u8; 32],
    _log_sync: MootLogSync,
    handle: MootSyncHandle,
    logsync_task: JoinHandle<()>,
    status: Arc<Mutex<SyncStatus>>,
}

impl SyncedMootSpace {
    /// Join a moot's object-log session over `store`, driven by the host's
    /// `endpoint` + `gossip`. Spawns the verifying drain task; syncs
    /// `Topic::from(moot_id)` in live mode.
    pub async fn join(
        endpoint: Endpoint,
        gossip: Gossip,
        store: MootStore,
        moot_id: [u8; 32],
    ) -> Result<Self, MootSyncError> {
        let status = Arc::new(Mutex::new(SyncStatus::default()));

        let log_sync = MootLogSync::builder(store.sqlite(), endpoint, gossip)
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
                        if verify(&op)
                            && op.header.extensions.moot_id == moot_id
                            && matches!(task_store.insert(&op).await, Ok(true))
                        {
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
            _log_sync: log_sync,
            handle,
            logsync_task,
            status,
        })
    }

    /// The moot's operation store.
    pub fn store(&self) -> &MootStore {
        &self.store
    }

    /// The moot this session syncs.
    pub fn moot_id(&self) -> [u8; 32] {
        self.moot_id
    }

    /// Sign `event` at `keypair`'s next log position, persist it, and push
    /// it onto the live lane. One authoring path per device key (concurrent
    /// authors on one keypair would race the log position).
    pub async fn author(
        &self,
        keypair: &Ed25519Keypair,
        event: &MootEvent,
    ) -> Result<Operation<MootExt>, MootSyncError> {
        let author = SigningKey::from_bytes(&keypair.to_seed()).verifying_key();
        let latest = self.store.latest(&author, self.moot_id).await?;
        let (seq_num, backlink) = match latest {
            Some(prev) => (prev.header.seq_num + 1, Some(*prev.hash.as_bytes())),
            None => (0, None),
        };
        let op = to_operation(keypair, self.moot_id, event, seq_num, backlink);
        self.store.insert(&op).await?;
        self.handle
            .publish(op.clone())
            .await
            .map_err(|e| MootSyncError::Backend(format!("publish: {e}")))?;
        Ok(op)
    }

    /// Fold the synced store into the moot's [`MootRoster`].
    pub async fn roster(&self) -> Result<MootRoster, MootStoreError> {
        self.store.roster(self.moot_id).await
    }

    /// A snapshot of this moot's sync activity.
    pub fn sync_status(&self) -> SyncStatus {
        self.status.lock().unwrap().clone()
    }

    /// A manual "sync now" checkpoint: watch the live session until it goes
    /// quiet and report the real count of operations that landed.
    pub async fn resync(&self) -> Result<SyncRound, MootSyncError> {
        let received = || self.status.lock().unwrap().ops_received;
        let start = received();
        let mut last = start;
        let mut quiet = 0u8;
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

impl Drop for SyncedMootSpace {
    fn drop(&mut self) {
        self.logsync_task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use identity::{IdentityProvider, InMemoryProvider};
    use std::sync::Arc as StdArc;
    use transport::P2pandaTransport;

    const MOOT: [u8; 32] = [0x6e; 32];

    /// Two bound transports tagged with each other on the moot's overlay
    /// topic (the proven two-peer bootstrap).
    async fn two_peers() -> (P2pandaTransport, P2pandaTransport) {
        let founder_provider = StdArc::new(InMemoryProvider::from_seed([70; 32]));
        let friend_provider = StdArc::new(InMemoryProvider::from_seed([71; 32]));
        let founder_id = transport::PeerID::from_public_key(founder_provider.master_public_key());
        let friend_id = transport::PeerID::from_public_key(friend_provider.master_public_key());

        let founder_t = P2pandaTransport::builder(founder_provider.master_keypair())
            .gossip()
            .bind()
            .await
            .expect("bind founder");
        let friend_t = P2pandaTransport::builder(friend_provider.master_keypair())
            .gossip()
            .bind()
            .await
            .expect("bind friend");

        let overlay = transport::sync_overlay_topic(MOOT);
        founder_t
            .add_peer(friend_t.endpoint_addr().await.unwrap())
            .await
            .unwrap();
        founder_t.set_topics(friend_id, &[overlay]).await.unwrap();
        friend_t
            .add_peer(founder_t.endpoint_addr().await.unwrap())
            .await
            .unwrap();
        friend_t.set_topics(founder_id, &[overlay]).await.unwrap();
        (founder_t, friend_t)
    }

    async fn join(t: &P2pandaTransport) -> SyncedMootSpace {
        let (ep, gossip) = t.sync_parts().expect("sync parts");
        let store = MootStore::in_memory().await.expect("store");
        SyncedMootSpace::join(ep, gossip, store, MOOT)
            .await
            .expect("join")
    }

    async fn wait_for_roster(
        space: &SyncedMootSpace,
        pred: impl Fn(&MootRoster) -> bool,
        what: &str,
    ) {
        let outcome = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if pred(&space.roster().await.unwrap()) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await;
        assert!(outcome.is_ok(), "timed out waiting for: {what}");
    }

    /// The M1 shape, in process: founder declares + joins + shares; a
    /// friend joins live; both rosters agree on founding, members, flora.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn declare_join_share_converges_on_both_peers() {
        let (founder_t, friend_t) = two_peers().await;
        let founder_space = join(&founder_t).await;
        let friend_space = join(&friend_t).await;

        let founder_kp = InMemoryProvider::from_seed([70; 32])
            .derive_keypair(b"moot-author")
            .unwrap();
        let friend_kp = InMemoryProvider::from_seed([71; 32])
            .derive_keypair(b"moot-author")
            .unwrap();

        founder_space
            .author(
                &founder_kp,
                &MootEvent::Declared {
                    name: "printing circle".into(),
                    charter: "we share what we set in type".into(),
                    at_ms: 10,
                },
            )
            .await
            .expect("declare");
        founder_space
            .author(
                &founder_kp,
                &MootEvent::Joined {
                    name: "mark".into(),
                    at_ms: 11,
                },
            )
            .await
            .expect("founder joins");

        // The friend sees the founding, then joins and shares.
        wait_for_roster(
            &friend_space,
            |r| r.declaration.is_some(),
            "friend sees the declaration",
        )
        .await;
        friend_space
            .author(
                &friend_kp,
                &MootEvent::Joined {
                    name: "alex".into(),
                    at_ms: 20,
                },
            )
            .await
            .expect("friend joins");
        friend_space
            .author(
                &friend_kp,
                &MootEvent::Shared {
                    manifest_id: [0xaa; 32],
                    schema_id: "eidetic.SearchIndexSpec/v1".into(),
                    title: "my trail index".into(),
                    at_ms: 21,
                },
            )
            .await
            .expect("friend shares");

        // Both rosters converge to the same picture.
        for (space, who) in [(&founder_space, "founder"), (&friend_space, "friend")] {
            wait_for_roster(
                space,
                |r| {
                    r.declaration.as_ref().map(|d| d.name.as_str()) == Some("printing circle")
                        && r.members.len() == 2
                        && r.flora.len() == 1
                        && r.flora[0].title == "my trail index"
                },
                &format!("{who} converges on the full roster"),
            )
            .await;
        }

        // Real (non-placebo) sync feedback on both sides.
        assert!(founder_space.sync_status().ops_received >= 2);
        assert!(friend_space.sync_status().ops_received >= 2);
        assert!(founder_space.sync_status().last_activity_ms.is_some());
    }

    /// The catch-up lane: a roster authored before the friend connects
    /// converges over RBSR.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_late_joiner_catches_up_on_an_existing_moot() {
        let (founder_t, friend_t) = two_peers().await;

        let founder_kp = InMemoryProvider::from_seed([70; 32])
            .derive_keypair(b"moot-author")
            .unwrap();
        let store = MootStore::in_memory().await.unwrap();
        let declared = to_operation(
            &founder_kp,
            MOOT,
            &MootEvent::Declared {
                name: "early circle".into(),
                charter: "founded before you arrived".into(),
                at_ms: 5,
            },
            0,
            None,
        );
        store.insert(&declared).await.unwrap();

        let (ep, gossip) = founder_t.sync_parts().expect("founder sync parts");
        let _founder_space = SyncedMootSpace::join(ep, gossip, store, MOOT)
            .await
            .expect("founder join");
        let friend_space = join(&friend_t).await;

        wait_for_roster(
            &friend_space,
            |r| r.declaration.as_ref().map(|d| d.name.as_str()) == Some("early circle"),
            "friend catches up on the founding",
        )
        .await;
        assert!(friend_space.sync_status().ops_received >= 1);
    }
}
