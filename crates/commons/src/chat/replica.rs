// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

impl<B: Backend + Clone> ChatReplica<B> {
    /// Direct-root compatibility constructor.
    ///
    /// Product hosts with a Personae identity should use
    /// [`Self::for_identity`]. Every constructor takes a [`GroupKeys`] clone
    /// to share a refreshable handle, or a `DataKeyring` for a fresh one.
    pub fn new(
        backend: B,
        space_id: [u8; 32],
        signing_seed: [u8; 32],
        keys: impl Into<GroupKeys>,
    ) -> Self {
        debug_assert_eq!(COMMONS_CHAT_PROFILE.mode, GroupEncryptionMode::Data);
        let stable_author = *SigningKey::from_bytes(&signing_seed)
            .verifying_key()
            .as_bytes();
        Self {
            store: MunimentStore::new(backend),
            space_id,
            signing_seed,
            stable_author,
            author_attestation: None,
            keys: keys.into(),
            checkpoint_authority: None,
            parking: Parking::new(COMMONS_CHAT_LANE, space_id),
        }
    }

    /// Replica writing under this chat space's derived Personae key.
    ///
    /// Every authored encrypted record carries the root attestation. Admission
    /// verifies it against the operation signer and projection exposes the
    /// stable root as the message author.
    pub fn for_identity<P: IdentityProvider + ?Sized>(
        backend: B,
        space_id: [u8; 32],
        identity: &P,
        keys: impl Into<GroupKeys>,
    ) -> Result<Self, ChatReplicaIdentityError> {
        debug_assert_eq!(COMMONS_CHAT_PROFILE.mode, GroupEncryptionMode::Data);
        let salt = chat_identity_salt(space_id);
        let keypair = identity.derive_keypair(&salt)?;
        let author_attestation = identity.attest_derived_key(&salt)?;
        let checked = author_attestation
            .check(&salt)
            .map_err(ChatReplicaIdentityError::InvalidAttestation)?;
        if *checked.derived() != keypair.public_key().to_bytes() {
            return Err(ChatReplicaIdentityError::WriterMismatch);
        }
        let stable_author = *checked.master();
        if stable_author != identity.master_public_key().to_bytes() {
            return Err(ChatReplicaIdentityError::RootMismatch);
        }
        Ok(Self {
            store: MunimentStore::new(backend),
            space_id,
            signing_seed: keypair.to_seed(),
            stable_author,
            author_attestation: Some(author_attestation),
            keys: keys.into(),
            checkpoint_authority: None,
            parking: Parking::new(COMMONS_CHAT_LANE, space_id),
        })
    }

    /// Bound this replica's parked records; see [`crate::parking`].
    pub fn with_parking_limits(mut self, limits: ParkingLimits) -> Self {
        self.parking.limits = limits;
        self
    }

    /// Stable Personae root used for author and authority projection.
    pub fn stable_author(&self) -> [u8; 32] {
        self.stable_author
    }

    /// The addressed space whose encrypted chat records this replica owns.
    pub fn space_id(&self) -> [u8; 32] {
        self.space_id
    }

    /// Install the current Commons-governed checkpoint authority.
    pub fn set_checkpoint_authority(&mut self, authority: ChatCheckpointAuthority) {
        self.checkpoint_authority = Some(authority);
    }

    pub fn sync_store(&self) -> MunimentStore<B, ChatExt> {
        self.store.clone()
    }

    pub fn key_state(&self) -> Result<Vec<u8>, GroupCryptoError> {
        self.keys.to_bytes()
    }

    /// The key handle this replica and its joined lane read. Replace its
    /// keyring after draining a rotation; no rejoin is needed.
    pub fn keys(&self) -> &GroupKeys {
        &self.keys
    }

    /// Causally closed chat state with structural admission as the authority
    /// floor. Communal callers should prefer [`Self::projection_with_authority`].
    pub async fn projection(&self) -> Result<ChatProjection, ChatError> {
        self.projection_with_authority(&AllowAllAuthority).await
    }

    /// Chat state classified by the caller's converged authority view.
    ///
    /// Product ports must use this for communal projection. The authority view
    /// receives retained Personae/Gemot facts; session, relay, and transport
    /// identity never enter the decision. Every retained record is classified,
    /// checkpoint-covered ones included, so a withdrawn capability retracts
    /// that author's whole contribution. Covered records are read from the
    /// latest checkpoint instead of being decrypted.
    pub async fn projection_with_authority<A: CommonsAuthority>(
        &self,
        authority: &A,
    ) -> Result<ChatProjection, ChatError> {
        self.load_retained()
            .await?
            .fold(&self.keys.current(), self.space_id, authority)
    }

    #[cfg(test)]
    pub(super) async fn load_data_operations(&self) -> Result<Vec<StoredChatOperation>, ChatError> {
        Ok(self.load_retained().await?.data)
    }
}
