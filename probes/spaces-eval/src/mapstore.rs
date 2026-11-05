// SPDX-License-Identifier: MPL-2.0

//! A spaces store with no SQLite at runtime: state blobs in a map, one writer at a
//! time. It implements the six store traits `Manager` is bounded by, which is the
//! whole persistence surface p2panda-spaces needs. A Muniment backend would hold
//! the same blobs in typed slots; the map stands in for it here so the probe does
//! not pull a second storage engine into the comparison.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use p2auth::group::GroupCrdtState;
use p2auth::traits::{Conditions, Operation as AuthOperation};
use p2core::cbor::{decode_cbor, encode_cbor};
use p2core::{Hash, VerifyingKey};
use p2enc::key_manager::PreKeyBundlesState;
use p2enc::key_registry::KeyRegistryState;
use p2spaces::test_utils::TestOperation;
use p2store::Transaction;
use p2store::groups::GroupsStore;
use p2store::key_registry::KeyRegistryStore;
use p2store::key_secrets::PreKeyBundlesStore;
use p2store::spaces::{SpacesMessageStore, SpacesStore};
use serde::{Deserialize, Serialize};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Debug, thiserror::Error)]
pub enum MapError {
    #[error("state codec: {0}")]
    Codec(String),
    #[error("transaction: {0}")]
    Transaction(String),
}

#[derive(Clone, Debug, Default)]
struct Data {
    spaces: HashMap<Hash, Vec<u8>>,
    groups: HashMap<Hash, Vec<u8>>,
    registry: Option<Vec<u8>>,
    prekeys: Option<Vec<u8>>,
    operations: HashMap<Hash, TestOperation>,
}

#[derive(Debug)]
struct Shared {
    writer: Arc<Semaphore>,
    data: Mutex<Data>,
}

#[derive(Clone, Debug)]
pub struct MapStore(Arc<Shared>);

impl Default for MapStore {
    fn default() -> Self {
        Self(Arc::new(Shared {
            writer: Arc::new(Semaphore::new(1)),
            data: Mutex::new(Data::default()),
        }))
    }
}

impl MapStore {
    pub fn put_operation(&self, operation: &TestOperation) {
        self.data()
            .operations
            .insert(operation.hash, operation.clone());
    }

    pub fn latest_of(&self, author: &VerifyingKey) -> Option<TestOperation> {
        self.data()
            .operations
            .values()
            .filter(|operation| &operation.header.verifying_key == author)
            .max_by_key(|operation| operation.header.seq_num)
            .cloned()
    }

    fn data(&self) -> std::sync::MutexGuard<'_, Data> {
        self.0.data.lock().unwrap()
    }
}

pub struct MapPermit {
    _writer: OwnedSemaphorePermit,
    before: Data,
}

impl Transaction for MapStore {
    type Error = MapError;
    type Permit = MapPermit;

    async fn begin(&self) -> Result<Self::Permit, Self::Error> {
        let writer = self
            .0
            .writer
            .clone()
            .acquire_owned()
            .await
            .map_err(|error| MapError::Transaction(error.to_string()))?;
        let before = self.data().clone();
        Ok(MapPermit {
            _writer: writer,
            before,
        })
    }

    async fn rollback(&self, permit: Self::Permit) -> Result<(), Self::Error> {
        *self.data() = permit.before;
        Ok(())
    }

    async fn commit(&self, _permit: Self::Permit) -> Result<(), Self::Error> {
        Ok(())
    }
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, MapError> {
    encode_cbor(value).map_err(|error| MapError::Codec(error.to_string()))
}

fn decode<T: for<'a> Deserialize<'a>>(bytes: &[u8]) -> Result<T, MapError> {
    decode_cbor(bytes).map_err(|error| MapError::Codec(error.to_string()))
}

impl SpacesMessageStore<TestOperation> for MapStore {
    type Error = MapError;

    async fn get_spaces_message_tx(&self, id: &Hash) -> Result<Option<TestOperation>, MapError> {
        Ok(self.data().operations.get(id).cloned())
    }
}

impl<S> SpacesStore<S> for MapStore
where
    S: for<'a> Deserialize<'a> + Serialize,
{
    type Error = MapError;

    async fn get_space_state(&self, id: &Hash) -> Result<Option<S>, MapError> {
        let bytes = self.data().spaces.get(id).cloned();
        bytes.map(|bytes| decode(&bytes)).transpose()
    }

    async fn get_space_state_tx(&self, id: &Hash) -> Result<Option<S>, MapError> {
        SpacesStore::<S>::get_space_state(self, id).await
    }

    async fn set_space_state_tx(&self, id: &Hash, y: &S) -> Result<(), MapError> {
        let bytes = encode(y)?;
        self.data().spaces.insert(*id, bytes);
        Ok(())
    }

    async fn has_space(&self, id: &Hash) -> Result<bool, MapError> {
        Ok(self.data().spaces.contains_key(id))
    }

    async fn has_space_tx(&self, id: &Hash) -> Result<bool, MapError> {
        Ok(self.data().spaces.contains_key(id))
    }

    async fn space_ids(&self) -> Result<Vec<Hash>, MapError> {
        Ok(self.data().spaces.keys().copied().collect())
    }
}

impl<M, C> GroupsStore<M, C> for MapStore
where
    C: Conditions + Serialize + for<'a> Deserialize<'a>,
    M: AuthOperation<VerifyingKey, Hash, C> + Serialize + for<'a> Deserialize<'a>,
{
    type Error = MapError;

    async fn get_groups_state(
        &self,
        id: Hash,
    ) -> Result<Option<GroupCrdtState<VerifyingKey, Hash, M, C>>, MapError> {
        let bytes = self.data().groups.get(&id).cloned();
        bytes.map(|bytes| decode(&bytes)).transpose()
    }

    async fn get_groups_state_tx(
        &self,
        id: Hash,
    ) -> Result<Option<GroupCrdtState<VerifyingKey, Hash, M, C>>, MapError> {
        GroupsStore::<M, C>::get_groups_state(self, id).await
    }

    async fn set_groups_state_tx(
        &self,
        id: Hash,
        state: &GroupCrdtState<VerifyingKey, Hash, M, C>,
    ) -> Result<(), MapError> {
        let bytes = encode(state)?;
        self.data().groups.insert(id, bytes);
        Ok(())
    }
}

impl KeyRegistryStore for MapStore {
    type Error = MapError;

    async fn get_key_registry(&self) -> Result<Option<KeyRegistryState<VerifyingKey>>, MapError> {
        let bytes = self.data().registry.clone();
        bytes.map(|bytes| decode(&bytes)).transpose()
    }

    async fn get_key_registry_tx(
        &self,
    ) -> Result<Option<KeyRegistryState<VerifyingKey>>, MapError> {
        self.get_key_registry().await
    }

    async fn set_key_registry_tx(
        &self,
        state: &KeyRegistryState<VerifyingKey>,
    ) -> Result<(), MapError> {
        let bytes = encode(state)?;
        self.data().registry = Some(bytes);
        Ok(())
    }
}

impl PreKeyBundlesStore for MapStore {
    type Error = MapError;

    async fn get_prekey_secrets(&self) -> Result<Option<PreKeyBundlesState>, MapError> {
        let bytes = self.data().prekeys.clone();
        bytes.map(|bytes| decode(&bytes)).transpose()
    }

    async fn get_prekey_secrets_tx(&self) -> Result<Option<PreKeyBundlesState>, MapError> {
        self.get_prekey_secrets().await
    }

    async fn set_prekey_secrets_tx(&self, state: &PreKeyBundlesState) -> Result<(), MapError> {
        let bytes = encode(state)?;
        self.data().prekeys = Some(bytes);
        Ok(())
    }
}
