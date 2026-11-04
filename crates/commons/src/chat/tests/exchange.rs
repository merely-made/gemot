// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

#[tokio::test]
async fn two_partitioned_members_converge_through_memory_accept() {
    let (alice_keys, bob_keys) = paired_keys();
    let mut alice = ChatReplica::in_memory(SPACE, [0xa1; 32], alice_keys);
    let mut bob = ChatReplica::in_memory(SPACE, [0xb2; 32], bob_keys);

    let channel = alice
        .author(ChatEvent::Channel(Channel {
            id: "general".into(),
            title: "General".into(),
        }))
        .await
        .unwrap();
    bob.accept(&channel).await.unwrap();
    let a_message = alice
        .author(ChatEvent::Message(Message {
            channel: "general".into(),
            body: "amber".into(),
            sent_at_ms: 1,
            reply_to: None,
        }))
        .await
        .unwrap();
    let b_message = bob
        .author(ChatEvent::Message(Message {
            channel: "general".into(),
            body: "blue".into(),
            sent_at_ms: 2,
            reply_to: Some(*a_message.hash.as_bytes()),
        }))
        .await
        .unwrap();
    alice.accept(&b_message).await.unwrap();
    bob.accept(&a_message).await.unwrap();

    let a = alice.projection().await.unwrap();
    let b = bob.projection().await.unwrap();
    assert_eq!(a, b);
    assert_eq!(a.channels.len(), 1);
    assert_eq!(a.messages.len(), 2);
    assert!(a.pending.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_members_converge_over_real_logsync() {
    let alice_identity = Arc::new(InMemoryProvider::from_seed([0xa1; 32]));
    let bob_identity = Arc::new(InMemoryProvider::from_seed([0xb2; 32]));
    let alice_transport = P2pandaTransport::builder(alice_identity.master_keypair())
        .gossip()
        .bind()
        .await
        .unwrap();
    let bob_transport = P2pandaTransport::builder(bob_identity.master_keypair())
        .gossip()
        .bind()
        .await
        .unwrap();
    let overlay = sync_overlay_topic(SPACE);
    alice_transport
        .add_peer(bob_transport.endpoint_addr().await.unwrap())
        .await
        .unwrap();
    alice_transport
        .set_topics(
            PeerID::from_public_key(bob_identity.master_public_key()),
            &[overlay],
        )
        .await
        .unwrap();
    bob_transport
        .add_peer(alice_transport.endpoint_addr().await.unwrap())
        .await
        .unwrap();
    bob_transport
        .set_topics(
            PeerID::from_public_key(alice_identity.master_public_key()),
            &[overlay],
        )
        .await
        .unwrap();

    let (alice_keys, bob_keys) = paired_keys();
    let mut alice =
        ChatReplica::in_memory(SPACE, alice_identity.master_keypair().to_seed(), alice_keys);
    let mut bob = ChatReplica::in_memory(SPACE, bob_identity.master_keypair().to_seed(), bob_keys);
    alice
        .author(ChatEvent::Message(Message {
            channel: "general".into(),
            body: "over the lane".into(),
            sent_at_ms: 3,
            reply_to: None,
        }))
        .await
        .unwrap();
    bob.author(ChatEvent::Message(Message {
        channel: "general".into(),
        body: "from the other side".into(),
        sent_at_ms: 4,
        reply_to: None,
    }))
    .await
    .unwrap();

    let (a_endpoint, a_gossip) = alice_transport.sync_parts().unwrap();
    let (b_endpoint, b_gossip) = bob_transport.sync_parts().unwrap();
    let alice_joined = alice.join(a_endpoint, a_gossip).await.unwrap();
    let bob_joined = bob.join(b_endpoint, b_gossip).await.unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if alice.projection().await.unwrap().messages.len() == 2
                && bob.projection().await.unwrap().messages.len() == 2
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("Commons chat peers did not converge");
    assert_eq!(
        alice.projection().await.unwrap(),
        bob.projection().await.unwrap()
    );
    assert!(alice_joined.ops_received() >= 1);
    assert!(bob_joined.ops_received() >= 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn identical_signed_ciphertext_survives_native_drop_and_reticulum_tcp() {
    let (alice_keys, _) = paired_keys();
    let mut alice = ChatReplica::in_memory(SPACE, [0xa1; 32], alice_keys);
    let operation = alice
        .author(ChatEvent::Message(Message {
            channel: "general".into(),
            body: "same bytes on every carrier".into(),
            sent_at_ms: 5,
            reply_to: None,
        }))
        .await
        .unwrap();
    let canonical_record = operation_record(&operation, true);
    let canonical = encode_cbor(&canonical_record).unwrap();

    let protector =
        CabalKeyring::from_cabal_key(CabalId::new([0xd1; 32]), &CabalKey::new([0xd2; 32]));
    let mut drop_bytes = Vec::new();
    write_protected_drop(
        &mut drop_bytes,
        &[operation_record(&operation, true)],
        DropLimits::default(),
        &protector,
    )
    .unwrap();
    let (_, records) =
        read_protected_drop(Cursor::new(drop_bytes), DropLimits::default(), &protector).unwrap();
    assert_eq!(records[0], canonical_record);
    let recovered = decode_operation_record::<ChatExt>(&records[0])
        .unwrap()
        .unwrap();
    assert_eq!(operation_record(&recovered, true), canonical_record);

    let server_identity = InMemoryProvider::from_seed([0xe1; 32]);
    let client_identity = InMemoryProvider::from_seed([0xe2; 32]);
    let server_peer = PeerID::from_public_key(server_identity.master_public_key());
    let server_keypair = server_identity.master_keypair();
    let client_keypair = client_identity.master_keypair();
    let addr = free_addr();
    let alpn = Alpn::new("mere/commons-operation/v1");
    let server = ReticulumTransport::builder(server_keypair)
        .alpns(vec![alpn.clone()])
        .interfaces(vec![ReticulumInterface::TcpServer { bind: addr }])
        .announce_interval(Duration::from_millis(100))
        .bind()
        .await
        .unwrap();
    let client = ReticulumTransport::builder(client_keypair)
        .alpns(vec![alpn.clone()])
        .interfaces(vec![ReticulumInterface::TcpClient { addr }])
        .announce_interval(Duration::from_millis(100))
        .connect_timeout(Duration::from_secs(10))
        .bind()
        .await
        .unwrap();
    let expected = canonical.clone();
    let accept = tokio::spawn(async move {
        let accepted = server.accept(alpn).await.unwrap();
        let mut stream = accepted.into_stream();
        let len = stream.read_u32_le().await.unwrap();
        let mut received = vec![0; len as usize];
        stream.read_exact(&mut received).await.unwrap();
        received
    });
    let mut stream = client
        .connect(server_peer, Alpn::new("mere/commons-operation/v1"))
        .await
        .unwrap();
    stream.write_u32_le(canonical.len() as u32).await.unwrap();
    stream.write_all(&canonical).await.unwrap();
    stream.flush().await.unwrap();
    let received = tokio::time::timeout(Duration::from_secs(15), accept)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, expected);
    let decoded_record: DropRecord = decode_cbor(received.as_slice()).unwrap();
    assert_eq!(decoded_record, canonical_record);
    // `decode_operation_record` goes through `Header::decode`, which
    // verifies the signature before it will return a header, so reaching
    // this unwrap IS the signature assertion. The body commitment and log
    // rules still get asserted explicitly.
    let decoded = decode_operation_record::<ChatExt>(&decoded_record)
        .unwrap()
        .unwrap();
    assert!(p2panda_core::operation::validate_operation(&decoded).is_ok());
    assert_eq!(decoded.hash, decoded.header.hash());
}
