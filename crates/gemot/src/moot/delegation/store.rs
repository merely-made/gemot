// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Muniment-backed p2panda store for independent delegation statements.

use std::collections::BTreeMap;
use std::path::Path;

use identity::Ed25519Keypair;
use muniment::{Backend, MemoryBackend, RedbBackend, StoreError};
use p2panda_core::{Operation, Topic, VerifyingKey};
use p2panda_store::logs::LogStore;
use p2panda_store::topics::TopicStore;
use stickleback::{
    Admission, DropRecord, MunimentStore, OperationPolicy, OperationProcessor, ProcessError,
    Reject, StoreTarget, decode_operation_record, operation_record,
};

use super::wire::{MootDelegationExt, from_operation, to_operation, verify};
use super::{
    ConstitutionRules, MootDelegationError, MootDelegationEvent, MootDelegations, is_moot_scope,
};

const LOG_ID: u64 = 0;

/// Durable delegation-lane rejection.
#[derive(Debug, thiserror::Error)]
pub enum MootDelegationStoreError {
    /// Shared storage failure.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Shared processor rejected the p2panda operation.
    #[error(transparent)]
    Process(#[from] ProcessError),
    /// Authored statement exceeds its current parent authority.
    #[error(transparent)]
    Delegation(#[from] MootDelegationError),
    /// Operation body is missing or malformed.
    #[error("delegation operation body is malformed")]
    Malformed,
    /// Outer p2panda author differs from the Personae-attested signer.
    #[error("delegation operation author does not match its signer proof")]
    WrongAuthor,
    /// Native-drop operation record is malformed.
    #[error("delegation drop record: {0}")]
    Drop(String),
}

#[derive(Clone, Copy)]
struct DelegationPolicy {
    moot_id: [u8; 32],
}

impl OperationPolicy<MootDelegationExt> for DelegationPolicy {
    type LogId = u64;

    fn admit(
        &self,
        operation: &Operation<MootDelegationExt>,
    ) -> Result<Admission<Self::LogId>, Reject> {
        if operation.header.extensions.moot_id != self.moot_id {
            return Err(Reject::new(
                "wrong-moot",
                "delegation operation addresses another moot",
            ));
        }
        if !verify(operation) {
            return Err(Reject::new(
                "invalid-operation",
                "delegation operation header or body commitment is invalid",
            ));
        }
        let event = from_operation(operation).map_err(|_| {
            Reject::new(
                "invalid-delegation-event",
                "operation body is not a delegation statement",
            )
        })?;
        if !event.verifies() {
            return Err(Reject::new(
                "invalid-delegation-proof",
                "inner delegation signature or signer proof is invalid",
            ));
        }
        if !is_moot_scope(event.scope(), self.moot_id) {
            return Err(Reject::new(
                "wrong-inner-moot",
                "delegation statement scope addresses another moot",
            ));
        }
        if event.signer() != Some(*operation.header.verifying_key.as_bytes()) {
            return Err(Reject::new(
                "wrong-delegation-author",
                "outer operation author differs from inner signer proof",
            ));
        }
        Ok(Admission::keep(StoreTarget::new(
            Topic::from(self.moot_id),
            LOG_ID,
        )))
    }
}

/// One Moot's independent delegation operation corpus.
///
/// Remote statements are retained after cryptographic validation even when a
/// parent has not arrived yet. The materializer activates them only after the
/// full authority chain resolves, so sync and native drops remain order-free.
#[derive(Clone)]
pub struct MootDelegationStore<B> {
    moot_id: [u8; 32],
    store: MunimentStore<B, MootDelegationExt>,
}

/// Durable redb delegation store.
pub type MootDelegationFileStore = MootDelegationStore<RedbBackend>;

impl MootDelegationStore<MemoryBackend> {
    /// Create an ephemeral delegation store.
    pub fn in_memory(moot_id: [u8; 32]) -> Self {
        Self {
            moot_id,
            store: MunimentStore::new(MemoryBackend::new()),
        }
    }
}

impl MootDelegationStore<RedbBackend> {
    /// Open durable delegation state for one Moot.
    pub fn open(
        path: impl AsRef<Path>,
        moot_id: [u8; 32],
    ) -> Result<Self, MootDelegationStoreError> {
        Ok(Self {
            moot_id,
            store: MunimentStore::new(RedbBackend::open(path)?),
        })
    }
}

impl<B: Backend + Clone> MootDelegationStore<B> {
    /// Shared LogSync store surface.
    pub fn sync_store(&self) -> MunimentStore<B, MootDelegationExt> {
        self.store.clone()
    }

    /// Retain a remotely authored, cryptographically valid statement.
    /// Authority resolution is deliberately deferred to [`Self::delegations`].
    pub async fn accept(
        &self,
        operation: &Operation<MootDelegationExt>,
    ) -> Result<bool, MootDelegationStoreError> {
        if self.store.has_operation(&operation.hash).await? {
            return Ok(false);
        }
        let processor = OperationProcessor::new(
            self.store.clone(),
            DelegationPolicy {
                moot_id: self.moot_id,
            },
        );
        Ok(processor.process(operation).await?.inserted())
    }

    /// Author and retain a locally preflighted certificate issuance.
    pub async fn author_issue(
        &self,
        keypair: &Ed25519Keypair,
        rules: &ConstitutionRules,
        signed: identity::delegation::SignedDelegationCertificate,
    ) -> Result<Operation<MootDelegationExt>, MootDelegationStoreError> {
        let event = MootDelegationEvent::Issued(signed);
        self.preflight(keypair, rules, &event).await?;
        self.author_event(keypair, &event).await
    }

    /// Author and retain a locally preflighted certificate revocation.
    pub async fn author_revoke(
        &self,
        keypair: &Ed25519Keypair,
        rules: &ConstitutionRules,
        signed: identity::delegation::SignedDelegationRevocation,
    ) -> Result<Operation<MootDelegationExt>, MootDelegationStoreError> {
        let event = MootDelegationEvent::Revoked(signed);
        self.preflight(keypair, rules, &event).await?;
        self.author_event(keypair, &event).await
    }

    /// Materialize all currently valid chains under the supplied constitution.
    pub async fn delegations(
        &self,
        rules: &ConstitutionRules,
    ) -> Result<MootDelegations, MootDelegationStoreError> {
        let mut pending: Vec<MootDelegationEvent> = self
            .operations()
            .await?
            .iter()
            .filter_map(|operation| from_operation(operation).ok())
            .collect();
        let mut state = MootDelegations::new();
        loop {
            let mut progressed = false;
            let mut next = Vec::new();
            for event in pending {
                let result = match event.clone() {
                    MootDelegationEvent::Issued(signed) => {
                        state.accept_certificate(self.moot_id, rules, signed)
                    }
                    MootDelegationEvent::Revoked(signed) => state.accept_revocation(signed),
                };
                match result {
                    Ok(_) => progressed = true,
                    Err(_) => next.push(event),
                }
            }
            if !progressed || next.is_empty() {
                break;
            }
            pending = next;
        }
        Ok(state)
    }

    async fn preflight(
        &self,
        keypair: &Ed25519Keypair,
        rules: &ConstitutionRules,
        event: &MootDelegationEvent,
    ) -> Result<(), MootDelegationStoreError> {
        if event.signer() != Some(keypair.public_key().to_bytes()) {
            return Err(MootDelegationStoreError::WrongAuthor);
        }
        let mut state = self.delegations(rules).await?;
        match event.clone() {
            MootDelegationEvent::Issued(signed) => {
                state.accept_certificate(self.moot_id, rules, signed)?;
            }
            MootDelegationEvent::Revoked(signed) => {
                state.accept_revocation(signed)?;
            }
        }
        Ok(())
    }

    async fn author_event(
        &self,
        keypair: &Ed25519Keypair,
        event: &MootDelegationEvent,
    ) -> Result<Operation<MootDelegationExt>, MootDelegationStoreError> {
        let author = p2panda_core::SigningKey::from_bytes(&keypair.to_seed()).verifying_key();
        let (seq_num, backlink) = match self.latest(&author).await? {
            Some(previous) => (previous.header.seq_num + 1, Some(*previous.hash.as_bytes())),
            None => (0, None),
        };
        let operation = to_operation(keypair, self.moot_id, event, seq_num, backlink);
        self.accept(&operation).await?;
        Ok(operation)
    }

    async fn latest(
        &self,
        author: &VerifyingKey,
    ) -> Result<Option<Operation<MootDelegationExt>>, MootDelegationStoreError> {
        Ok(self.store.get_latest_entry(author, &LOG_ID).await?)
    }

    /// Retained, cryptographically valid operation corpus.
    pub async fn operations(
        &self,
    ) -> Result<Vec<Operation<MootDelegationExt>>, MootDelegationStoreError> {
        let logs: BTreeMap<VerifyingKey, Vec<u64>> =
            self.store.resolve(&Topic::from(self.moot_id)).await?;
        let mut operations = Vec::new();
        for (author, log_ids) in logs {
            for log_id in log_ids {
                if let Some(entries) = self
                    .store
                    .get_log_entries(&author, &log_id, None, None)
                    .await?
                {
                    operations.extend(entries.into_iter().map(|(operation, _)| operation));
                }
            }
        }
        Ok(operations)
    }

    /// Full signed delegation corpus for aggregate native-drop carriage.
    pub async fn drop_records(&self) -> Result<Vec<DropRecord>, MootDelegationStoreError> {
        Ok(self
            .operations()
            .await?
            .iter()
            .map(|operation| operation_record(operation, true))
            .collect())
    }

    /// Admit verified native-drop delegation records through the ordinary
    /// cryptographic operation policy.
    pub async fn accept_drop_records(
        &self,
        records: &[DropRecord],
    ) -> Result<u64, MootDelegationStoreError> {
        let mut accepted = 0;
        for record in records {
            let Some(operation) = decode_operation_record::<MootDelegationExt>(record)
                .map_err(|error| MootDelegationStoreError::Drop(error.to_string()))?
            else {
                continue;
            };
            if operation.body.is_none() {
                return Err(MootDelegationStoreError::Malformed);
            }
            accepted += u64::from(self.accept(&operation).await?);
        }
        Ok(accepted)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use identity::delegation::{
        CapabilityScope, DelegationCertificate, DelegationParent, SignedDelegationCertificate,
        delegation_signing_salt,
    };
    use identity::{IdentityProvider, InMemoryProvider};

    use super::*;
    use crate::moot::constitution::CapabilityGrant;
    use crate::moot::delegation::{MOOT_ACT_ACTION, MOOT_DELEGATION_DOMAIN};

    const MOOT: [u8; 32] = [9; 32];
    const ROOT: [u8; 32] = [7; 32];

    fn scope(path: &str) -> CapabilityScope {
        CapabilityScope {
            domain: MOOT_DELEGATION_DOMAIN.into(),
            resource: MOOT.to_vec(),
            path_prefix: path.into(),
            actions: BTreeSet::from([MOOT_ACT_ACTION.into()]),
        }
    }

    fn rules(holder: [u8; 32]) -> ConstitutionRules {
        let mut rules = ConstitutionRules::founder_only(holder);
        rules.grant(CapabilityGrant {
            id: ROOT,
            subject: holder,
            path_prefix: "moot/fauna".into(),
            not_before_ms: 1,
            expires_at_ms: Some(100),
            delegation_depth: 3,
        });
        rules
    }

    fn signed(
        issuer: &InMemoryProvider,
        subject: &InMemoryProvider,
        parent: DelegationParent,
        scope: CapabilityScope,
        depth: u16,
        nonce: u8,
    ) -> SignedDelegationCertificate {
        SignedDelegationCertificate::issue(
            issuer,
            DelegationCertificate::new(
                parent,
                issuer.master_public_key().to_bytes(),
                subject.master_public_key().to_bytes(),
                scope,
                2,
                3,
                Some(90),
                depth,
                [nonce; 32],
            ),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn child_received_before_parent_activates_after_parent_arrives() {
        let root = InMemoryProvider::from_seed([1; 32]);
        let child = InMemoryProvider::from_seed([2; 32]);
        let leaf = InMemoryProvider::from_seed([3; 32]);
        let rules = rules(root.master_public_key().to_bytes());
        let store = MootDelegationStore::in_memory(MOOT);

        let parent = signed(
            &root,
            &child,
            DelegationParent::Root(ROOT),
            scope("moot/fauna"),
            2,
            1,
        );
        let child_scope = scope("moot/fauna/notes");
        let descendant = signed(
            &child,
            &leaf,
            DelegationParent::Certificate(parent.certificate.id()),
            child_scope.clone(),
            1,
            2,
        );
        let child_key = child
            .derive_keypair(&delegation_signing_salt(&child_scope))
            .unwrap();
        let child_operation = to_operation(
            &child_key,
            MOOT,
            &MootDelegationEvent::Issued(descendant),
            0,
            None,
        );
        assert!(store.accept(&child_operation).await.unwrap());
        assert_eq!(
            store.delegations(&rules).await.unwrap().certificate_count(),
            0
        );

        let parent_scope = parent.certificate.scope.clone();
        let parent_key = root
            .derive_keypair(&delegation_signing_salt(&parent_scope))
            .unwrap();
        store
            .author_issue(&parent_key, &rules, parent)
            .await
            .unwrap();
        let state = store.delegations(&rules).await.unwrap();
        assert_eq!(state.certificate_count(), 2);
        assert!(state.covers(
            MOOT,
            &rules,
            leaf.master_public_key().to_bytes(),
            "moot/fauna/notes/write",
            50,
        ));
    }

    #[tokio::test]
    async fn store_rejects_an_inner_scope_for_another_moot() {
        let root = InMemoryProvider::from_seed([1; 32]);
        let child = InMemoryProvider::from_seed([2; 32]);
        let foreign_scope = CapabilityScope {
            resource: vec![8; 32],
            ..scope("moot/fauna")
        };
        let signed = signed(
            &root,
            &child,
            DelegationParent::Root(ROOT),
            foreign_scope.clone(),
            2,
            1,
        );
        let key = root
            .derive_keypair(&delegation_signing_salt(&foreign_scope))
            .unwrap();
        let operation = to_operation(&key, MOOT, &MootDelegationEvent::Issued(signed), 0, None);

        assert!(matches!(
            MootDelegationStore::in_memory(MOOT)
                .accept(&operation)
                .await,
            Err(MootDelegationStoreError::Process(_))
        ));
    }

    #[tokio::test]
    async fn durable_store_reopens_the_same_delegated_authority() {
        let root = InMemoryProvider::from_seed([1; 32]);
        let child = InMemoryProvider::from_seed([2; 32]);
        let rules = rules(root.master_public_key().to_bytes());
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("delegations.redb");
        let signed = signed(
            &root,
            &child,
            DelegationParent::Root(ROOT),
            scope("moot/fauna"),
            2,
            1,
        );
        let key = root
            .derive_keypair(&delegation_signing_salt(&signed.certificate.scope))
            .unwrap();
        {
            let store = MootDelegationFileStore::open(&path, MOOT).unwrap();
            store.author_issue(&key, &rules, signed).await.unwrap();
        }
        let reopened = MootDelegationFileStore::open(&path, MOOT).unwrap();
        assert!(reopened.delegations(&rules).await.unwrap().covers(
            MOOT,
            &rules,
            child.master_public_key().to_bytes(),
            "moot/fauna/write",
            50,
        ));
    }
}
