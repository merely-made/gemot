// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retained_authority_reprojects_pending_effective_and_revoked() {
    let author = Author::new("ui");
    let mut origin = Replica::new(MemoryBackend::new(), CONTAINER, [90; 32]);
    let operation = origin
        .edit(|graph| {
            graph.insert_node(&author, Container::new("authority-fact"));
        })
        .await
        .unwrap();
    let subject = *operation.header.verifying_key.as_bytes();

    // A different replica is merely the relay/holder. Its own writer key
    // does not participate in the authority decision.
    let relay = Replica::new(MemoryBackend::new(), CONTAINER, [91; 32]);
    relay.accept(&operation).await.unwrap();
    let retained = relay.sync_store();
    for (state, nodes, pending, revoked) in [
        (AuthorityState::Pending, 0, 1, 0),
        (AuthorityState::Effective, 1, 0, 0),
        (AuthorityState::Revoked, 0, 0, 1),
    ] {
        let projection =
            materialize_with_authority(&retained, CONTAINER, &FixedAuthority { subject, state })
                .await
                .unwrap();
        assert_eq!(projection.graph.graph().node_count(), nodes);
        assert_eq!(projection.pending_authority.len(), pending);
        assert_eq!(projection.revoked.len(), revoked);
        assert_eq!(retained.operation_count().await.unwrap(), 1);
    }
}

/// A retained fact is governed by its stable writer subject and the
/// converged Gemot delegation state. The holder that relays the operation
/// has no input to the decision, and neither does a session or carrier.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gemot_delegation_reprojects_retained_write_and_revocation() {
    let root = InMemoryProvider::from_seed([0x71; 32]);
    let writer = InMemoryProvider::from_seed([0x72; 32]);
    let capability = commons_write_capability(CONTAINER);
    let rules = gemot_rules(&root, cap_path(&capability));
    let delegation = issue_gemot_delegation(&root, &writer, cap_path(&capability), Some(900), 1);
    let delegation_id = delegation.certificate.id();
    let delegation_scope = delegation.certificate.scope.clone();
    let mut delegations = MootDelegations::new();
    assert!(
        delegations
            .accept_certificate(MOOT, &rules, delegation)
            .expect("live delegation is admitted")
    );

    let mut author = Replica::for_identity(MemoryBackend::new(), CONTAINER, &writer).unwrap();
    let operation = author
        .edit(|graph| {
            graph.insert_node(&Author::new("turnstone"), Container::new("retained"));
        })
        .await
        .expect("author writes a retained fact");
    let relay = Replica::new(MemoryBackend::new(), CONTAINER, [0x73; 32]);
    relay
        .accept(&operation)
        .await
        .expect("relay retains the fact");
    let retained = relay.sync_store();

    let effective = relay
        .projection_with_authority(&gemot_authority(&delegations, &rules))
        .await
        .expect("Gemot grants the writer capability");
    assert_eq!(effective.graph.graph().node_count(), 1);
    assert!(effective.pending_authority.is_empty());
    assert!(effective.revoked.is_empty());

    let revocation = SignedDelegationRevocation::issue(
        &root,
        DelegationRevocation::new(
            delegation_id,
            root.master_public_key().to_bytes(),
            delegation_scope,
            60,
            [2; 32],
        ),
    )
    .expect("test revocation signs");
    assert!(
        delegations
            .accept_revocation(revocation)
            .expect("Gemot accepts the issuer revocation")
    );

    let withdrawn = relay
        .projection_with_authority(&gemot_authority(&delegations, &rules))
        .await
        .expect("authority reprojects without reinserting the fact");
    assert_eq!(withdrawn.graph.graph().node_count(), 0);
    assert!(withdrawn.pending_authority.is_empty());
    assert_eq!(withdrawn.revoked.len(), 1);
    assert_eq!(
        retained
            .operation_count()
            .await
            .expect("retained fact count"),
        1,
        "revocation changes projection, never retained history"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gemot_expired_unrelated_and_insufficient_delegations_stay_pending() {
    let root = InMemoryProvider::from_seed([0x81; 32]);
    let writer = InMemoryProvider::from_seed([0x82; 32]);
    let capability = commons_write_capability(CONTAINER);
    let needed = cap_path(&capability);
    let mut author = Replica::new(MemoryBackend::new(), CONTAINER, [0x82; 32]);
    let operation = author
        .edit(|graph| {
            graph.insert_node(&Author::new("turnstone"), Container::new("pending"));
        })
        .await
        .expect("author writes one retained fact");
    let relay = Replica::new(MemoryBackend::new(), CONTAINER, [0x83; 32]);
    relay
        .accept(&operation)
        .await
        .expect("relay retains the fact");
    let retained = relay.sync_store();

    let cases = [
        ("expired", needed.clone(), needed.clone(), Some(40)),
        (
            "unrelated",
            "scope/commons".to_string(),
            "scope/commons/other".to_string(),
            Some(900),
        ),
        (
            "insufficient",
            "scope/commons".to_string(),
            format!("{needed}/child"),
            Some(900),
        ),
    ];

    for (index, (name, root_path, delegation_path, expires_at_ms)) in cases.into_iter().enumerate()
    {
        let rules = gemot_rules(&root, root_path);
        let delegation = issue_gemot_delegation(
            &root,
            &writer,
            delegation_path,
            expires_at_ms,
            index as u8 + 3,
        );
        let mut delegations = MootDelegations::new();
        assert!(
            delegations
                .accept_certificate(MOOT, &rules, delegation)
                .expect("structurally valid delegation is retained")
        );

        let projection = relay
            .projection_with_authority(&gemot_authority(&delegations, &rules))
            .await
            .expect("authority fold succeeds");
        assert_eq!(projection.graph.graph().node_count(), 0, "{name}");
        assert_eq!(projection.pending_authority.len(), 1, "{name}");
        assert!(projection.revoked.is_empty(), "{name} is not revocation");
    }
    assert_eq!(
        retained
            .operation_count()
            .await
            .expect("retained fact count"),
        1,
        "ineffective authority never deletes the retained fact"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_derived_writer_is_bound_to_its_personae_root() {
    let root = InMemoryProvider::from_seed([0xa7; 32]);
    let author = Author::new("ui");
    let mut origin =
        Replica::for_identity(MemoryBackend::new(), CONTAINER, &root).expect("bind identity");
    let operation = origin
        .edit(|graph| {
            graph.insert_node(&author, Container::new("derived"));
        })
        .await
        .expect("identity-backed replica authors");
    let record = from_operation(&operation).unwrap();
    let attestation = record
        .writer_attestation
        .expect("the authoring path carries its stable-root binding");
    assert_eq!(
        attestation.master_public_key().unwrap(),
        root.master_public_key()
    );
    assert_eq!(
        attestation.derived_public_key().unwrap().to_bytes(),
        origin.writer().0
    );

    let receiver = Replica::new(MemoryBackend::new(), CONTAINER, [91; 32]);
    receiver.accept(&operation).await.unwrap();
    let projection = materialize_with_authority(
        &receiver.sync_store(),
        CONTAINER,
        &FixedAuthority {
            subject: root.master_public_key().to_bytes(),
            state: AuthorityState::Effective,
        },
    )
    .await
    .unwrap();
    assert_eq!(projection.graph.graph().node_count(), 1);

    let forged = to_operation_with_attestation(
        [0xb8; 32],
        CONTAINER,
        &record.batch,
        Vec::new(),
        0,
        None,
        Some(attestation),
    );
    let empty = Replica::new(MemoryBackend::new(), CONTAINER, [92; 32]);
    let error = empty
        .accept(&forged)
        .await
        .expect_err("another signer cannot claim the certified derived key");
    assert!(error.to_string().contains("writer-attestation-mismatch"));
    assert_eq!(empty.sync_store().operation_count().await.unwrap(), 0);
}

#[test]
fn a_replica_rejects_an_attestation_for_another_derived_writer() {
    let identity = CrossWiredIdentity {
        writer: InMemoryProvider::from_seed([0xc1; 32]),
        attester: InMemoryProvider::from_seed([0xc2; 32]),
    };
    let error = Replica::for_identity(MemoryBackend::new(), CONTAINER, &identity)
        .err()
        .expect("cross-wired identity must fail closed");
    assert!(matches!(error, ReplicaIdentityError::WriterMismatch));
}
