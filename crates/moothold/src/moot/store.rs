/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! The moot lane's store of record — p2panda-store's SQLite backend, wrapped.
//!
//! The `MeshStore` recipe verbatim: one store, one write path.
//! [`MootStore::insert`] persists an operation *and* indexes it for sync in
//! a single transaction (op row via `OperationStore`, topic → author/log
//! association via `TopicStore`), so authored and drained operations alike
//! are served on the next reconciliation. Reads ride the pool. A moot log
//! is one append-only log per author per moot: the log id *is* the moot id.
//! (The tessera lane keeps its own proven redb store; converging the two is
//! the one-endpoint unification slice, not this module's concern.)

use std::collections::BTreeMap;

use identity::Ed25519Keypair;
use p2panda_core::{Operation, SigningKey, Topic, VerifyingKey};
use p2panda_store::logs::LogStore;
use p2panda_store::operations::OperationStore;
use p2panda_store::topics::TopicStore;
use p2panda_store::{SqliteError, SqliteStore, SqliteStoreBuilder, Transaction};

use super::roster::MootRoster;
use super::wire::{MootEvent, MootExt, to_operation};

/// A moot store failure (the underlying SQLite store).
#[derive(Debug, thiserror::Error)]
pub enum MootStoreError {
    #[error("moot store: {0}")]
    Backend(#[from] SqliteError),
}

/// The moot lane's operation store. Clone-cheap (shares the pool).
#[derive(Clone, Debug)]
pub struct MootStore {
    sqlite: SqliteStore,
}

impl MootStore {
    /// An ephemeral in-memory store (tests, the `moot-peer` rehearsal).
    /// One connection — with `sqlite::memory:` every pooled connection is
    /// its own empty database.
    pub async fn in_memory() -> Result<Self, MootStoreError> {
        let sqlite = SqliteStoreBuilder::new().max_connections(1).build().await?;
        Ok(Self { sqlite })
    }

    /// A store at a SQLite URL (`sqlite://path/to/moot.db`); database and
    /// schema created if missing. Use forward slashes in the path.
    pub async fn at_url(url: &str) -> Result<Self, MootStoreError> {
        let sqlite = SqliteStoreBuilder::new().database_url(url).build().await?;
        Ok(Self { sqlite })
    }

    /// A clone of the underlying SQLite store, for `LogSync::builder`.
    pub fn sqlite(&self) -> SqliteStore {
        self.sqlite.clone()
    }

    /// Persist + index one operation, atomically. Returns `true` when new,
    /// `false` when already present (idempotent on the hash). Callers
    /// verify signatures first; the store is the dumb of-record layer.
    pub async fn insert(&self, op: &Operation<MootExt>) -> Result<bool, MootStoreError> {
        let moot_id = op.header.extensions.moot_id;
        let permit = self.sqlite.begin().await?;
        // An error before commit drops the permit, rolling the transaction
        // back — the op row and its index entry land together or not at all.
        let fresh = self.sqlite.insert_operation(&op.hash, op, &moot_id).await?;
        self.sqlite
            .associate(&Topic::from(moot_id), &op.header.verifying_key, &moot_id)
            .await?;
        self.sqlite.commit(permit).await?;
        Ok(fresh)
    }

    /// The latest operation in `author`'s log on this moot — the
    /// seq/backlink source for authoring. `None` for a first event.
    pub async fn latest(
        &self,
        author: &VerifyingKey,
        moot_id: [u8; 32],
    ) -> Result<Option<Operation<MootExt>>, MootStoreError> {
        Ok(self.sqlite.get_latest_entry(author, &moot_id).await?)
    }

    /// Sign `event` at `keypair`'s next log position on `moot_id`, persist it,
    /// and return the operation. This is the sign-and-store half of authoring;
    /// the **host** broadcasts the returned op on the live lane
    /// (`SyncHandle::publish`), and LogSync reconciliation covers peers that were
    /// away. One authoring path per device key (concurrent authors on one
    /// keypair would race the log position).
    pub async fn author(
        &self,
        keypair: &Ed25519Keypair,
        moot_id: [u8; 32],
        event: &MootEvent,
    ) -> Result<Operation<MootExt>, MootStoreError> {
        let author = SigningKey::from_bytes(&keypair.to_seed()).verifying_key();
        let (seq_num, backlink) = match self.latest(&author, moot_id).await? {
            Some(prev) => (prev.header.seq_num + 1, Some(*prev.hash.as_bytes())),
            None => (0, None),
        };
        let op = to_operation(keypair, moot_id, event, seq_num, backlink);
        self.insert(&op).await?;
        Ok(op)
    }

    /// Every operation on `moot_id`, across all known authors' logs.
    pub async fn ops(&self, moot_id: [u8; 32]) -> Result<Vec<Operation<MootExt>>, MootStoreError> {
        let logs: BTreeMap<VerifyingKey, Vec<[u8; 32]>> =
            self.sqlite.resolve(&Topic::from(moot_id)).await?;
        let mut out = Vec::new();
        for (author, log_ids) in logs {
            for log_id in log_ids {
                if let Some(entries) = self
                    .sqlite
                    .get_log_entries(&author, &log_id, None, None)
                    .await?
                {
                    out.extend(entries.into_iter().map(|(op, _raw_header)| op));
                }
            }
        }
        Ok(out)
    }

    /// Fold the store's view of `moot_id` into its [`MootRoster`].
    pub async fn roster(&self, moot_id: [u8; 32]) -> Result<MootRoster, MootStoreError> {
        let ops = self.ops(moot_id).await?;
        Ok(MootRoster::fold(moot_id, ops.iter()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::moot::wire::{MootEvent, to_operation};
    use identity::{Ed25519Keypair, IdentityProvider, InMemoryProvider};

    const MOOT: [u8; 32] = [0x6d; 32];

    fn keypair(seed: u8) -> Ed25519Keypair {
        InMemoryProvider::from_seed([seed; 32])
            .derive_keypair(b"moot-store")
            .unwrap()
    }

    #[tokio::test]
    async fn insert_is_idempotent_and_feeds_the_roster() {
        let store = MootStore::in_memory().await.unwrap();
        let kp = keypair(1);
        let op = to_operation(
            &kp,
            MOOT,
            &MootEvent::Declared {
                name: "circle".into(),
                charter: "c".into(),
                at_ms: 1,
            },
            0,
            None,
        );

        assert!(store.insert(&op).await.unwrap(), "first insert is new");
        assert!(!store.insert(&op).await.unwrap(), "re-insert is a no-op");

        let roster = store.roster(MOOT).await.unwrap();
        assert_eq!(roster.declaration.unwrap().name, "circle");
    }

    #[tokio::test]
    async fn latest_walks_the_author_log() {
        let store = MootStore::in_memory().await.unwrap();
        let kp = keypair(1);
        let author = {
            use p2panda_core::SigningKey;
            SigningKey::from_bytes(&kp.to_seed()).verifying_key()
        };
        assert!(store.latest(&author, MOOT).await.unwrap().is_none());

        let op0 = to_operation(
            &kp,
            MOOT,
            &MootEvent::Joined {
                name: "m".into(),
                at_ms: 1,
            },
            0,
            None,
        );
        store.insert(&op0).await.unwrap();
        let latest = store.latest(&author, MOOT).await.unwrap().unwrap();
        assert_eq!(latest.header.seq_num, 0);
        assert_eq!(latest.hash, op0.hash);
    }
}
