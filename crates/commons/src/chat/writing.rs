// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

impl<B: Backend + Clone> ChatReplica<B> {
    pub async fn author(&mut self, event: ChatEvent) -> Result<Operation<ChatExt>, ChatError> {
        let retained = self.load_retained().await?;
        self.author_onto(event, retained).await
    }

    /// Author one event onto an already-loaded retained history.
    ///
    /// The frontier scan and the admission of the resulting operation read the
    /// same snapshot -- nothing else can have written to this replica in between
    /// -- so authoring costs one store load rather than one per check.
    pub(super) async fn author_onto(
        &mut self,
        event: ChatEvent,
        retained: RetainedChatRecords,
    ) -> Result<Operation<ChatExt>, ChatError> {
        let entries = causal_entries(&retained.data);
        let parents = observed_frontier(&entries)?;
        let signing_key = SigningKey::from_bytes(&self.signing_seed);
        let author = signing_key.verifying_key();
        let (seq_num, backlink) = author_head(&entries, *author.as_bytes(), &CHAT_LOG)?;
        let class = event.class();
        let record = ChatAuthored::new(event, self.author_attestation.clone());
        let plaintext = encode_cbor(&record).map_err(|error| ChatError::Wire(error.to_string()))?;
        let envelope = self
            .keys
            .current()
            .seal(&plaintext, &p2panda_encryption::Rng::default())?;
        let body_bytes =
            encode_cbor(&envelope).map_err(|error| ChatError::Wire(error.to_string()))?;
        let body = Body::from_bytes(&body_bytes);
        // p2panda 0.7.1 made the header's CBOR cache, size and digest private
        // and folded signing into the builder: `build` encodes, signs and
        // caches the digest in one step, so the struct-literal + `sign` pair
        // has no equivalent. The builder derives verifying_key from the
        // signing key -- the same value `author` already held.
        let header = Header::builder()
            .body(&body_bytes)
            .seq_num(seq_num)
            .backlink(backlink.map(Hash::from))
            .build(
                &signing_key,
                ChatExt {
                    space_id: self.space_id,
                    class,
                    parents,
                    checkpoint: None,
                },
            );
        let operation = Operation {
            hash: header.hash(),
            header,
            body: Some(body),
        };
        self.accept_onto(&operation, retained).await?;
        Ok(operation)
    }

    /// Author an immutable edit of this member's projected message.
    pub async fn edit_message(
        &mut self,
        original: [u8; 32],
        body: String,
        edited_at_ms: u64,
    ) -> Result<Operation<ChatExt>, ChatError> {
        let retained = self.load_retained().await?;
        self.ensure_owned_projected_message(&retained, original)?;
        self.author_onto(
            ChatEvent::MessageEdit(MessageEdit {
                original,
                body,
                edited_at_ms,
            }),
            retained,
        )
        .await
    }

    /// Author an immutable deletion of this member's projected message.
    pub async fn delete_message(
        &mut self,
        original: [u8; 32],
        deleted_at_ms: u64,
    ) -> Result<Operation<ChatExt>, ChatError> {
        let retained = self.load_retained().await?;
        self.ensure_owned_projected_message(&retained, original)?;
        self.author_onto(
            ChatEvent::MessageDelete(MessageDelete {
                original,
                deleted_at_ms,
            }),
            retained,
        )
        .await
    }

    pub(super) fn ensure_owned_projected_message(
        &self,
        retained: &RetainedChatRecords,
        original: [u8; 32],
    ) -> Result<(), ChatError> {
        let projection = retained.fold(&self.keys.current(), self.space_id, &AllowAllAuthority)?;
        let message = projection
            .messages
            .iter()
            .find(|message| message.operation == original)
            .ok_or_else(|| {
                ChatError::MessageMutation(
                    "the original message is absent from the current projection".into(),
                )
            })?;
        if message.author != self.stable_author {
            return Err(ChatError::MessageMutation(
                "only the original author can edit or delete a message".into(),
            ));
        }
        Ok(())
    }

    /// Verify and store one record. A record sealed to an epoch the handle
    /// lacks, or backlinking a parked one, parks and returns `false`.
    pub async fn accept(&self, operation: &Operation<ChatExt>) -> Result<bool, ChatError> {
        accept_or_park(
            &self.store,
            self.space_id,
            self.keys.current(),
            self.checkpoint_authority.clone(),
            &self.parking,
            operation,
        )
        .await
    }

    /// Re-admit parked records with the handle's current keys, in causal
    /// order. A host calls this after it replaces the key handle.
    pub async fn readmit_parked(&self) -> Result<ReadmitReport, ChatError> {
        let keys = self.keys.current();
        let authority = self.checkpoint_authority.as_ref();
        self.parking
            .readmit(
                &self.store,
                |operation| {
                    let (envelope, _) = chat_header(self.space_id, authority, operation).ok()?;
                    Some(ParkedHeader {
                        parents: operation.header.extensions.parents.clone(),
                        epoch_held: keys.contains(&envelope.epoch),
                    })
                },
                async |operation, unpark| {
                    let retained = self.load_retained().await?;
                    match admit_onto(
                        &self.store,
                        self.space_id,
                        keys.clone(),
                        self.checkpoint_authority.clone(),
                        operation,
                        retained,
                        unpark,
                    )
                    .await
                    {
                        Ok(true) => Ok(Readmitted::Inserted),
                        Ok(false) => Ok(Readmitted::Duplicate),
                        Err(ChatError::Process(ProcessError::Store(error))) => Err(error.into()),
                        // The record's own refusal; other errors are this replica's.
                        Err(ChatError::Process(_)) => Ok(Readmitted::Refused),
                        Err(error) => Err(error),
                    }
                },
            )
            .await
    }

    pub async fn parking_status(&self) -> Result<ParkingStatus, ChatError> {
        Ok(self.parking.status(self.store.backend()).await?)
    }

    /// Admit one operation against an already-loaded retained history.
    ///
    /// Both admission inputs -- the latest checkpoint and the current projected
    /// message authors -- come out of one load and one decode of the retained
    /// history. They used to be two independent full replays of it.
    pub(super) async fn accept_onto(
        &self,
        operation: &Operation<ChatExt>,
        retained: RetainedChatRecords,
    ) -> Result<bool, ChatError> {
        admit_onto(
            &self.store,
            self.space_id,
            self.keys.current(),
            self.checkpoint_authority.clone(),
            operation,
            retained,
            &[],
        )
        .await
    }
}
