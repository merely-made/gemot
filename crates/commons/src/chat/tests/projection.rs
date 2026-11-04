// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

#[tokio::test]
async fn revoked_author_mutations_filter_with_their_original() {
    // An edit or deletion referencing a filtered-out original would fail
    // `apply_event`'s projected-original check. One verdict per stable root
    // is what keeps the fold from turning revocation into a hard error.
    let founder = InMemoryProvider::from_seed([0x71; 32]);
    let writer = InMemoryProvider::from_seed([0x72; 32]);
    let subject = writer.master_public_key().to_bytes();
    let (mut author, message) = seeded_author(&writer).await;
    author
        .edit_message(*message.hash.as_bytes(), "second draft".into(), 2)
        .await
        .unwrap();
    let doomed = author
        .author(ChatEvent::Message(Message {
            channel: "hall".into(),
            body: "retracted".into(),
            sent_at_ms: 3,
            reply_to: None,
        }))
        .await
        .unwrap();
    author
        .delete_message(*doomed.hash.as_bytes(), 4)
        .await
        .unwrap();

    let (withdrawn, rules) = chat_authority_fixture(&founder, subject, true);
    let filtered = author
        .projection_with_authority(&gemot_view(&withdrawn, &rules))
        .await
        .unwrap();
    assert!(filtered.messages.is_empty());
    assert!(
        filtered.deleted_messages.is_empty(),
        "a filtered deletion must not surface its retracted original either"
    );
    assert_eq!(filtered.revoked.len(), 5);
    assert!(filtered.pending_authority.is_empty());
}

#[tokio::test]
async fn immutable_edit_changes_only_the_projected_message_body() {
    let seed = [0x91; 32];
    let (keys, _) = paired_keys();
    let mut replica = ChatReplica::in_memory(SPACE, seed, keys);
    let original = replica
        .author(ChatEvent::Message(Message {
            channel: "general".into(),
            body: "first draft".into(),
            sent_at_ms: 10,
            reply_to: None,
        }))
        .await
        .unwrap();
    replica
        .author(ChatEvent::Channel(Channel {
            id: "general".into(),
            title: "General".into(),
        }))
        .await
        .unwrap();

    let edit = replica
        .edit_message(*original.hash.as_bytes(), "second draft".into(), 12)
        .await
        .unwrap();
    let projection = replica.projection().await.unwrap();
    assert_eq!(projection.messages.len(), 1);
    assert_eq!(projection.messages[0].operation, *original.hash.as_bytes());
    assert_eq!(projection.messages[0].message.body, "second draft");
    assert_eq!(
        projection.messages[0].latest_edit,
        Some(*edit.hash.as_bytes())
    );
    assert_eq!(projection.messages[0].edited_at_ms, Some(12));

    let records = replica.load_data_operations().await.unwrap();
    assert_eq!(records.len(), 3);
    assert!(records.iter().any(|record| {
        matches!(
            decode_event(&replica.keys.current(), &record.operation),
            Ok(event)
                if event == ChatEvent::Message(Message {
                    channel: "general".into(),
                    body: "first draft".into(),
                    sent_at_ms: 10,
                    reply_to: None,
                })
        )
    }));
    assert!(records.iter().any(|record| {
        matches!(
            decode_event(&replica.keys.current(), &record.operation),
            Ok(event)
                if event == ChatEvent::MessageEdit(MessageEdit {
                    original: *original.hash.as_bytes(),
                    body: "second draft".into(),
                    edited_at_ms: 12,
                })
        )
    }));
}

#[tokio::test]
async fn deletion_retracts_projection_but_survives_checkpoint_and_storage() {
    let seed = [0x92; 32];
    let (keys, _) = paired_keys();
    let mut replica = ChatReplica::in_memory(SPACE, seed, keys);
    replica.set_checkpoint_authority(checkpoint_authority(seed, b"mutation checkpoint"));
    let original = replica
        .author(ChatEvent::Message(Message {
            channel: "general".into(),
            body: "remove me".into(),
            sent_at_ms: 20,
            reply_to: None,
        }))
        .await
        .unwrap();
    let deletion = replica
        .delete_message(*original.hash.as_bytes(), 21)
        .await
        .unwrap();

    let projection = replica.projection().await.unwrap();
    assert!(projection.messages.is_empty());
    assert_eq!(
        projection.deleted_messages,
        vec![DeletedMessage {
            original: *original.hash.as_bytes(),
            author: *SigningKey::from_bytes(&seed).verifying_key().as_bytes(),
            deletion: *deletion.hash.as_bytes(),
            deleted_at_ms: 21,
        }]
    );
    assert!(matches!(
        replica
            .edit_message(*original.hash.as_bytes(), "resurrect".into(), 22)
            .await,
        Err(ChatError::MessageMutation(_))
    ));

    replica.author_checkpoint().await.unwrap();
    assert_eq!(replica.projection().await.unwrap(), projection);
    assert_eq!(
        full_replay(&replica, &AllowAllAuthority).await.unwrap(),
        projection
    );
    let records = replica.load_data_operations().await.unwrap();
    assert_eq!(records.len(), 2);
    assert!(records.iter().any(|record| {
        matches!(
            decode_event(&replica.keys.current(), &record.operation),
            Ok(ChatEvent::Message(_))
        )
    }));
    assert!(records.iter().any(|record| {
        matches!(
            decode_event(&replica.keys.current(), &record.operation),
            Ok(ChatEvent::MessageDelete(_))
        )
    }));
}

#[tokio::test]
async fn another_author_cannot_mutate_a_message() {
    let seed = [0x93; 32];
    let (keys, _) = paired_keys();
    let mut replica = ChatReplica::in_memory(SPACE, seed, keys);
    let original = replica
        .author(ChatEvent::Message(Message {
            channel: "general".into(),
            body: "mine".into(),
            sent_at_ms: 30,
            reply_to: None,
        }))
        .await
        .unwrap();
    let foreign = event_operation(
        &replica,
        &ChatEvent::MessageDelete(MessageDelete {
            original: *original.hash.as_bytes(),
            deleted_at_ms: 31,
        }),
        [0x94; 32],
        vec![*original.hash.as_bytes()],
        0,
        None,
    );
    assert!(matches!(
        replica.accept(&foreign).await,
        Err(ChatError::Process(ProcessError::Rejected(reject)))
            if reject.code == "foreign-message-mutation"
    ));
    let projection = replica.projection().await.unwrap();
    assert_eq!(projection.messages.len(), 1);
    assert!(projection.deleted_messages.is_empty());
}
