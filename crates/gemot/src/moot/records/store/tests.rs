// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;
use crate::moot::records::retention::{
    AvailabilityPolicy, ErasurePolicy, GovernedCheckpointAuthority, KeepBound, PolicyRevision,
};
use identity::{IdentityProvider, InMemoryProvider};
use proofs::Digest;
use servitor::{AuthorityProvider, Cap, Mode, Subject};

const MOOT: [u8; 32] = [0x6d; 32];

fn keypair(seed: u8) -> Ed25519Keypair {
    InMemoryProvider::from_seed([seed; 32])
        .derive_keypair(b"moot-store")
        .unwrap()
}

fn retention(authority: &Ed25519Keypair) -> MootRetentionPolicy {
    MootRetentionPolicy {
        revision: PolicyRevision(Digest::blake3(b"moot retention policy")),
        checkpoint_authority: GovernedCheckpointAuthority::from_constitution(
            Digest::blake3(b"moot constitution"),
            [authority.public_key().to_bytes()],
        ),
        checkpoint_authority_history: Vec::new(),
        availability: AvailabilityPolicy {
            promised_floor: KeepBound::Forever,
        },
        erasure: ErasurePolicy {
            history_ceiling: KeepBound::UntilCheckpoint,
        },
    }
}

struct RootAuthority([u8; 32]);

impl AuthorityProvider for RootAuthority {
    fn covers(&self, subject: Subject, _: &Cap, mode: Mode) -> bool {
        subject.0 == self.0 && mode == Mode::Write
    }
}

#[tokio::test]
async fn insert_is_idempotent_and_feeds_the_roster() {
    let store = MootStore::in_memory();
    let keypair = keypair(1);
    let operation = super::super::wire::to_operation(
        &keypair,
        MOOT,
        &MootEvent::Declared {
            name: "circle".into(),
            charter: "c".into(),
            at_ms: 1,
        },
        0,
        None,
    );
    assert!(store.insert(&operation).await.unwrap());
    assert!(!store.insert(&operation).await.unwrap());
    assert_eq!(
        store.roster(MOOT).await.unwrap().declaration.unwrap().name,
        "circle"
    );
}

#[tokio::test]
async fn derived_share_projects_and_authorizes_as_the_stable_persona() {
    let store = MootStore::in_memory();
    let identity = InMemoryProvider::from_seed([0x21; 32]);
    let operation = store
        .author_for_identity(
            &identity,
            MOOT,
            &MootEvent::Shared {
                manifest_id: [0xaa; 32],
                schema_id: "fleece.snapshot/v1".into(),
                title: "the remembered page".into(),
                at_ms: 5,
            },
        )
        .await
        .unwrap();

    let root = identity.master_public_key().to_bytes();
    assert_ne!(*operation.header.verifying_key.as_bytes(), root);
    let roster = store.roster(MOOT).await.unwrap();
    assert_eq!(roster.fauna[0].shared_by, root);
    assert_eq!(
        roster.authorized_fauna(&RootAuthority(root)),
        vec![&roster.fauna[0]]
    );
}

#[tokio::test]
async fn false_derived_writer_binding_is_rejected_before_storage() {
    let claimed = InMemoryProvider::from_seed([0x31; 32]);
    let signer = InMemoryProvider::from_seed([0x32; 32]);
    let salt = object_identity_salt(MOOT);
    let signer_key = signer.derive_keypair(&salt).unwrap();
    let operation = to_operation_seed_with_attestation(
        signer_key.to_seed(),
        MOOT,
        &MootEvent::Shared {
            manifest_id: [0xbb; 32],
            schema_id: "fleece.snapshot/v1".into(),
            title: "forged attribution".into(),
            at_ms: 6,
        },
        0,
        None,
        Some(claimed.attest_derived_key(&salt).unwrap()),
    );

    let error = store_error(&MootStore::in_memory(), &operation).await;
    assert!(
        error.contains("invalid-moot-author") && error.contains("does not bind"),
        "unexpected refusal: {error}"
    );
}

async fn store_error(store: &MootStore, operation: &Operation<MootExt>) -> String {
    store
        .accept(MOOT, operation)
        .await
        .expect_err("false attribution must fail")
        .to_string()
}

#[tokio::test]
async fn file_store_survives_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("moot.redb");
    let authority = keypair(1);
    {
        let store = MootStoreFile::at_path(&path).unwrap();
        store
            .author(
                &authority,
                MOOT,
                &MootEvent::Joined {
                    name: "mark".into(),
                    at_ms: 1,
                },
            )
            .await
            .unwrap();
    }
    let reopened = MootStoreFile::at_path(path).unwrap();
    assert_eq!(reopened.roster(MOOT).await.unwrap().members.len(), 1);
}

#[path = "tests/checkpoint.rs"]
mod checkpoint;
