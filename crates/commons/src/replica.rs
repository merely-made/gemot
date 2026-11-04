// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

impl<B: Backend + Clone + Send + Sync + 'static> Replica<B> {
    /// A replica writing directly under `signing_seed`, whose verifying key is
    /// both the stable authority subject and the chartulary `WriterId` that
    /// scopes minted edge ids.
    ///
    /// Product hosts with a Personae identity should use [`Self::for_identity`]
    /// so the wire record carries the root binding.
    pub fn new(backend: B, container: [u8; 32], signing_seed: [u8; 32]) -> Self {
        let writer = WriterId(
            *SigningKey::from_bytes(&signing_seed)
                .verifying_key()
                .as_bytes(),
        );
        Self {
            store: MunimentStore::new(backend),
            container,
            writer,
            signing_seed,
            writer_attestation: None,
        }
    }

    /// A replica writing under this container's derived Personae key.
    ///
    /// The master secret remains behind `identity`. Each authored operation
    /// carries the master-signed attestation, so authority is evaluated against
    /// the stable Personae root while edge ids remain scoped to the derived
    /// writer key.
    pub fn for_identity<P: IdentityProvider + ?Sized>(
        backend: B,
        container: [u8; 32],
        identity: &P,
    ) -> Result<Self, ReplicaIdentityError> {
        let (writer, signing_seed, writer_attestation) = derived_writer(identity, container)?;
        Ok(Self {
            store: MunimentStore::new(backend),
            container,
            writer,
            signing_seed,
            writer_attestation: Some(writer_attestation),
        })
    }

    /// The store, for `JoinedSpace::join`.
    pub fn sync_store(&self) -> MunimentStore<B, CommonsExt> {
        self.store.clone()
    }

    /// Join this container's live lane, draining received operations through
    /// the same structural admission local authoring uses. The counterpart to
    /// [`chat::ChatReplica::join`], so a host holds handles instead of
    /// assembling p2panda sessions.
    pub async fn join(
        &self,
        endpoint: murm_sync::Endpoint,
        gossip: murm_sync::Gossip,
    ) -> Result<murm_sync::JoinedSpace<CommonsExt>, stickleback::JoinError> {
        let accept_store = self.store.clone();
        let container = self.container;
        murm_sync::JoinedSpace::join::<_, u64, _, _>(
            stickleback::lane_id(COMMONS_GRAPH_LANE, container),
            self.sync_store(),
            endpoint,
            gossip,
            container,
            move |operation: Operation<CommonsExt>| {
                let store = accept_store.clone();
                async move {
                    accept_into(&store, container, &operation)
                        .await
                        .unwrap_or(false)
                }
            },
        )
        .await
    }

    /// This replica's writer identity.
    pub fn writer(&self) -> WriterId {
        self.writer
    }

    /// Edit the current shared projection, sign the resulting batch, and store
    /// it. Returns the operation so a caller can publish it on a live lane.
    ///
    /// The graph and both authoring frontiers are reconstructed from the store
    /// on every turn. That makes a peer's synced nodes and edges editable and
    /// makes restart resume both the p2panda log and the writer-scoped edge
    /// counter instead of returning either to zero.
    pub async fn edit(
        &mut self,
        edit: impl FnOnce(&mut GraphLog<Container, Relation>),
    ) -> Result<Operation<CommonsExt>, ReplicaError> {
        let records = load_plaintext_records(&self.store, self.container).await?;
        let author = *SigningKey::from_bytes(&self.signing_seed)
            .verifying_key()
            .as_bytes();
        let authored = author_batch(&records, self.writer, author, edit)?;
        let op = to_operation_with_attestation(
            self.signing_seed,
            self.container,
            &authored.batch,
            authored.parents,
            authored.seq_num,
            authored.backlink,
            self.writer_attestation.clone(),
        );
        self.accept(&op).await?;
        Ok(op)
    }

    /// Validate and store one operation. The `accept` closure a joined space
    /// drains into. Storing only: the graph is a fold, see the module docs.
    pub async fn accept(
        &self,
        op: &Operation<CommonsExt>,
    ) -> Result<bool, stickleback::ProcessError> {
        accept_into(&self.store, self.container, op).await
    }

    /// This replica's view of the container: see [`materialize`].
    pub async fn materialize(&self) -> Result<GraphLog<Container, Relation>, MaterializeError> {
        materialize(&self.store, self.container).await
    }

    /// Current graph plus operations waiting on unavailable causal parents.
    pub async fn projection(&self) -> Result<CommonsProjection, MaterializeError> {
        materialize_projection(&self.store, self.container).await
    }

    /// Current graph classified by the caller's converged authority view.
    /// Product ports must use this for communal projection; the authority view
    /// receives retained Personae/Gemot facts, never relay or session identity.
    pub async fn projection_with_authority<A: CommonsAuthority>(
        &self,
        authority: &A,
    ) -> Result<CommonsProjection, MaterializeError> {
        materialize_with_authority(&self.store, self.container, authority).await
    }
}
