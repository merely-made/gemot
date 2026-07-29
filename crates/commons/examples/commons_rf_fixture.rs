//! Emit and verify the exact signed encrypted Commons-profile operation used by the
//! direct-PHY RF receipt.
//!
//! `emit FIXTURE PAYLOAD` writes a local verification fixture plus the
//! canonical operation record to carry. `verify FIXTURE RECEIVED` proves that
//! the received bytes are identical, the p2panda signature verifies, and the
//! encrypted Commons message still opens under the fixture keyring.

use commons_spine::chat::{ChatEvent, ChatExt, ChatReplica, Message};
use p2panda_core::cbor::{decode_cbor, encode_cbor};
use serde::{Deserialize, Serialize};
use stickleback::{DataKeyring, GroupCiphertext, decode_operation_record, operation_record};

const SPACE: [u8; 32] = [0x51; 32];
const AUTHOR: [u8; 32] = [0xa1; 32];

#[derive(Serialize, Deserialize)]
struct RfFixture {
    version: u16,
    operation: [u8; 32],
    key_state: Vec<u8>,
    canonical_record: Vec<u8>,
}

fn expected_event() -> ChatEvent {
    ChatEvent::Message(Message {
        channel: "general".into(),
        body: "same signed ciphertext after direct PHY".into(),
        sent_at_ms: 6,
        reply_to: None,
    })
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mode = args
        .next()
        .ok_or("usage: commons_rf_fixture emit FIXTURE PAYLOAD | verify FIXTURE RECEIVED")?;
    let fixture_path = args
        .next()
        .ok_or("usage: commons_rf_fixture emit FIXTURE PAYLOAD | verify FIXTURE RECEIVED")?;
    let bytes_path = args
        .next()
        .ok_or("usage: commons_rf_fixture emit FIXTURE PAYLOAD | verify FIXTURE RECEIVED")?;
    if args.next().is_some() {
        return Err("unexpected extra argument".into());
    }

    match mode.as_str() {
        "emit" => emit(&fixture_path, &bytes_path).await?,
        "verify" => verify(&fixture_path, &bytes_path)?,
        _ => return Err("mode must be emit or verify".into()),
    }
    Ok(())
}

async fn emit(fixture_path: &str, payload_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut keys = DataKeyring::new();
    keys.rotate_random()?;
    let mut replica = ChatReplica::in_memory(SPACE, AUTHOR, keys);
    let operation = replica.author(expected_event()).await?;
    let canonical_record = encode_cbor(&operation_record(&operation, true))?;
    let fixture = RfFixture {
        version: 1,
        operation: *operation.hash.as_bytes(),
        key_state: replica.key_state()?,
        canonical_record: canonical_record.clone(),
    };
    std::fs::write(fixture_path, encode_cbor(&fixture)?)?;
    std::fs::write(payload_path, &canonical_record)?;
    println!(
        "emitted Commons operation {} ({} bytes)",
        hex::encode(fixture.operation),
        canonical_record.len()
    );
    Ok(())
}

fn verify(fixture_path: &str, received_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let fixture: RfFixture = decode_cbor(std::fs::read(fixture_path)?.as_slice())?;
    if fixture.version != 1 {
        return Err("unsupported RF fixture version".into());
    }
    let received = std::fs::read(received_path)?;
    if received != fixture.canonical_record {
        return Err("RF carriage changed the canonical operation bytes".into());
    }

    let record = decode_cbor(received.as_slice())?;
    let operation = decode_operation_record::<ChatExt>(&record)?
        .ok_or("canonical record did not contain an operation")?;
    if *operation.hash.as_bytes() != fixture.operation || !operation.header.verify() {
        return Err("received operation identity or signature is invalid".into());
    }
    let body = operation.body.ok_or("received operation body is absent")?;
    let envelope: GroupCiphertext = decode_cbor(body.to_bytes().as_slice())?;
    let keys = DataKeyring::from_bytes(&fixture.key_state)?;
    let plaintext = keys.open(&envelope)?;
    let event: ChatEvent = decode_cbor(plaintext.as_slice())?;
    if event != expected_event() {
        return Err("received operation decrypts to the wrong Commons event".into());
    }

    println!(
        "verified Commons operation {} after direct PHY ({} bytes)",
        hex::encode(fixture.operation),
        received.len()
    );
    println!("COMMONS DIRECT-PHY RF RECEIPT PASSED");
    Ok(())
}
