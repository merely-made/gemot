// SPDX-License-Identifier: MPL-2.0

//! R25 probe: p2panda-spaces (the `intake-20261105` branch of merely-made/p2mere,
//! upstream p2panda d01898bf) against Gemot's `MootGroup` and Stickleback's group
//! session and lane. Each test name starts with its R25 criterion number:
//! 1 concurrent add and remove, 2 nested devices, 3 key rotation, 4 offline
//! revoked peers, 5 cold reopen, 6 Muniment storage without SQLite, 7 durable-data
//! versus forward-secrecy profile. `spaces_side.rs` runs spaces, `family_side.rs`
//! the current code, `storage_graph.rs` reads the dependency graph.
//!
//! The probe is its own workspace and joins no default build. It carries a map
//! store ([`mapstore::MapStore`]) that implements the six store traits `Manager`
//! needs, so every spaces test runs without SQLite at runtime.

pub mod mapstore;

use p2core::{Header, SigningKey, VerifyingKey};

use mapstore::{MapError, MapStore};
use p2enc::Rng;
use p2spaces::manager::{Manager, ManagerError};
use p2spaces::member::AuthenticatedMember;
use p2spaces::test_utils::{TestConditions, TestOperation};
use p2spaces::{Config, Credentials, Forge, MemberStatus, SpacesArgs};

#[derive(Clone, Debug)]
pub struct MapForge {
    store: MapStore,
    key: SigningKey,
}

impl Forge<TestConditions> for MapForge {
    type Message = TestOperation;
    type Error = MapError;

    fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    async fn forge(&self, args: SpacesArgs<TestConditions>) -> Result<Self::Message, MapError> {
        tokio::task::yield_now().await;
        let (seq_num, backlink) = self
            .store
            .latest_of(&self.key.verifying_key())
            .map(|operation| (operation.header.seq_num + 1, Some(operation.hash)))
            .unwrap_or((0, None));
        let header = Header::builder()
            .seq_num(seq_num)
            .backlink(backlink)
            .build(&self.key, args);
        let operation = TestOperation::from_parts(header, None);
        self.store.put_operation(&operation);
        Ok(operation)
    }
}

pub type MapManager = Manager<MapStore, MapForge, TestConditions>;
pub type MapManagerError = ManagerError<MapForge, TestConditions>;

/// One spaces peer: manager over a map store.
pub struct MapPeer {
    pub manager: MapManager,
    pub store: MapStore,
    pub credentials: Credentials,
}

impl MapPeer {
    pub fn new(seed: u8) -> Self {
        let rng = Rng::from_seed([seed; 32]);
        let credentials = Credentials::from_rng(&rng).unwrap();
        Self::reopen(MapStore::default(), credentials, rng)
    }

    /// Cold start: a fresh manager over whatever the store already holds.
    pub fn reopen(store: MapStore, credentials: Credentials, rng: Rng) -> Self {
        let forge = MapForge {
            store: store.clone(),
            key: credentials.signing_key(),
        };
        let manager = MapManager::new_with_config(
            store.clone(),
            forge,
            credentials.clone(),
            Config::default(),
            rng,
        )
        .unwrap();
        Self {
            manager,
            store,
            credentials,
        }
    }

    pub async fn me(&self) -> Result<AuthenticatedMember, MapManagerError> {
        if self.manager.is_key_bundle_rotation_due().await? {
            self.manager.rotate_key_bundle().await?;
        }
        match self.manager.me().await? {
            MemberStatus::NotAvailable | MemberStatus::Expired => unreachable!("rotated above"),
            MemberStatus::Healthy(member) | MemberStatus::RotationDue(member) => Ok(member),
        }
    }

    /// Hand a peer's operation to this peer's store, then to its manager.
    pub async fn receive(
        &self,
        operation: &TestOperation,
    ) -> Result<Vec<p2spaces::Event<TestConditions>>, MapManagerError> {
        self.store.put_operation(operation);
        self.manager.process(operation).await
    }
}

/// Everyone learns everyone's key bundle (bundles travel as ordinary messages).
pub async fn exchange_bundles(peers: &[&MapPeer]) {
    for peer in peers {
        let me = peer.me().await.unwrap();
        for other in peers {
            if other.manager.id() != peer.manager.id() {
                other.manager.register_member(&me).await.unwrap();
            }
        }
    }
}
