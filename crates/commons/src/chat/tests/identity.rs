// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

#[tokio::test]
async fn personae_chat_author_binds_to_gemot_subject_and_revocation() {
    let founder = InMemoryProvider::from_seed([0x71; 32]);
    let writer = InMemoryProvider::from_seed([0x72; 32]);
    let stranger = InMemoryProvider::from_seed([0x73; 32]);
    let (author_keys, relay_keys) = paired_keys();
    let mut author = ChatReplica::in_memory_for_identity(SPACE, &writer, author_keys).unwrap();
    assert_eq!(
        author.stable_author(),
        writer.master_public_key().to_bytes()
    );
    assert_ne!(
        *SigningKey::from_bytes(&author.signing_seed)
            .verifying_key()
            .as_bytes(),
        author.stable_author()
    );

    let message = Message {
        channel: "general".into(),
        body: "bound author".into(),
        sent_at_ms: 1,
        reply_to: None,
    };
    let operation = author
        .author(ChatEvent::Message(message.clone()))
        .await
        .unwrap();
    let edit = author
        .edit_message(*operation.hash.as_bytes(), "root-bound edit".into(), 2)
        .await
        .unwrap();
    author.set_checkpoint_authority(ChatCheckpointAuthority::new(
        Digest::blake3(b"root-bound checkpoint"),
        [writer.master_public_key().to_bytes()],
    ));
    let checkpoint = author.author_checkpoint().await.unwrap();
    assert!(decode_checkpoint_operation(&author.keys.current(), &checkpoint).is_ok());

    let relay = ChatReplica::in_memory(SPACE, [0x74; 32], relay_keys);
    let forged = bound_event_operation(
        &author,
        ChatEvent::Message(message.clone()),
        author.signing_seed,
        stranger
            .attest_derived_key(&chat_identity_salt(SPACE))
            .unwrap(),
    );
    let error = relay
        .accept(&forged)
        .await
        .expect_err("a foreign root cannot claim the derived chat signer");
    assert!(error.to_string().contains("invalid-chat-author-binding"));
    assert_eq!(relay.sync_store().operation_count().await.unwrap(), 0);

    let cross_space = bound_event_operation(
        &author,
        ChatEvent::Message(message),
        author.signing_seed,
        writer
            .attest_derived_key(&chat_identity_salt([0x52; 32]))
            .unwrap(),
    );
    let error = relay
        .accept(&cross_space)
        .await
        .expect_err("a derived-key attestation cannot be replayed into another chat space");
    assert!(error.to_string().contains("invalid-chat-author-binding"));
    assert_eq!(relay.sync_store().operation_count().await.unwrap(), 0);

    relay.accept(&operation).await.unwrap();
    relay.accept(&edit).await.unwrap();
    let projection = relay.projection().await.unwrap();
    assert_eq!(projection.messages.len(), 1);
    assert_eq!(projection.messages[0].message.body, "root-bound edit");
    assert_eq!(
        projection.messages[0].author,
        writer.master_public_key().to_bytes()
    );

    let capability = chat_write_capability(SPACE);
    let needed = cap_path(&capability);
    let mut rules = ConstitutionRules::founder_only(founder.master_public_key().to_bytes());
    rules.grant(CapabilityGrant {
        id: ROOT_GRANT,
        subject: founder.master_public_key().to_bytes(),
        path_prefix: needed.clone(),
        not_before_ms: 10,
        expires_at_ms: Some(1_000),
        delegation_depth: 2,
    });
    let delegation = SignedDelegationCertificate::issue(
        &founder,
        DelegationCertificate::new(
            DelegationParent::Root(ROOT_GRANT),
            founder.master_public_key().to_bytes(),
            writer.master_public_key().to_bytes(),
            CapabilityScope {
                domain: MOOT_DELEGATION_DOMAIN.into(),
                resource: MOOT.to_vec(),
                path_prefix: needed,
                actions: [MOOT_ACT_ACTION.to_string()].into_iter().collect(),
            },
            15,
            20,
            Some(900),
            0,
            [1; 32],
        ),
    )
    .unwrap();
    let delegation_id = delegation.certificate.id();
    let delegation_scope = delegation.certificate.scope.clone();
    let mut delegations = MootDelegations::new();
    assert!(
        delegations
            .accept_certificate(MOOT, &rules, delegation)
            .unwrap()
    );
    let view = GemotAuthorityView {
        authority: MootAuthority {
            delegations: &delegations,
            rules: &rules,
            moot_id: MOOT,
            now_ms: 50,
        },
    };
    assert_eq!(
        view.classify(
            Subject(projection.messages[0].author),
            &capability,
            Mode::Write
        ),
        AuthorityState::Effective
    );

    let revocation = SignedDelegationRevocation::issue(
        &founder,
        DelegationRevocation::new(
            delegation_id,
            founder.master_public_key().to_bytes(),
            delegation_scope,
            60,
            [2; 32],
        ),
    )
    .unwrap();
    assert!(delegations.accept_revocation(revocation).unwrap());
    let withdrawn = GemotAuthorityView {
        authority: MootAuthority {
            delegations: &delegations,
            rules: &rules,
            moot_id: MOOT,
            now_ms: 50,
        },
    };
    assert_eq!(
        withdrawn.classify(
            Subject(projection.messages[0].author),
            &capability,
            Mode::Write
        ),
        AuthorityState::Revoked
    );
    assert_eq!(relay.sync_store().operation_count().await.unwrap(), 2);
}

#[tokio::test]
async fn revoked_chat_author_leaves_the_projection_but_stays_retained() {
    let founder = InMemoryProvider::from_seed([0x71; 32]);
    let writer = InMemoryProvider::from_seed([0x72; 32]);
    let subject = writer.master_public_key().to_bytes();
    let (author, message) = seeded_author(&writer).await;

    let (granted, rules) = chat_authority_fixture(&founder, subject, false);
    let effective = author
        .projection_with_authority(&gemot_view(&granted, &rules))
        .await
        .unwrap();
    assert_eq!(effective.messages.len(), 1);
    assert_eq!(effective.channels.len(), 1);
    assert!(effective.pending_authority.is_empty());
    assert!(effective.revoked.is_empty());

    let (withdrawn, rules) = chat_authority_fixture(&founder, subject, true);
    let filtered = author
        .projection_with_authority(&gemot_view(&withdrawn, &rules))
        .await
        .unwrap();
    assert!(
        filtered.messages.is_empty(),
        "revoked content must not project"
    );
    assert!(filtered.channels.is_empty());
    assert!(filtered.pending_authority.is_empty());
    assert_eq!(filtered.revoked.len(), 2);
    assert!(
        filtered
            .revoked
            .iter()
            .any(|operation| operation.operation == *message.hash.as_bytes())
    );
    assert!(
        filtered
            .revoked
            .iter()
            .all(|operation| operation.subject == subject)
    );

    // Filtering is a projection decision, not erasure: the retained facts
    // stay stored and a re-evaluation can still reach them.
    assert_eq!(author.sync_store().operation_count().await.unwrap(), 2);
    assert_eq!(author.projection().await.unwrap().messages.len(), 1);
}

#[tokio::test]
async fn chat_author_without_a_grant_is_pending_not_revoked() {
    let founder = InMemoryProvider::from_seed([0x71; 32]);
    let writer = InMemoryProvider::from_seed([0x72; 32]);
    let stranger = InMemoryProvider::from_seed([0x73; 32]);
    let (author, _) = seeded_author(&writer).await;

    // The capability is delegated to someone else, so this author never
    // held it. That is "not yet admitted", not "withdrawn".
    let (delegations, rules) =
        chat_authority_fixture(&founder, stranger.master_public_key().to_bytes(), false);
    let projection = author
        .projection_with_authority(&gemot_view(&delegations, &rules))
        .await
        .unwrap();
    assert!(projection.messages.is_empty());
    assert!(projection.revoked.is_empty());
    assert_eq!(projection.pending_authority.len(), 2);
    assert!(
        projection
            .pending_authority
            .iter()
            .all(|operation| operation.subject == writer.master_public_key().to_bytes())
    );
}
