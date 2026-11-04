//! Local interoperability receipt helper. Arguments explicitly authorize one
//! send of saved bytes; redirects are returned without following them.
use gemot_site_host::submission::{PreparedSubmission, initialize_submission_trust};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), String> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 4 {
        return Err("Usage: submit SAVED_FILE ENDPOINT MIME TRUST_RECORD_PATH".into());
    }
    let prepared =
        PreparedSubmission::from_saved_file(std::path::Path::new(&args[0]), &args[1], &args[2])?;
    initialize_submission_trust(std::path::Path::new(&args[3]))?;
    println!(
        "Sending {} saved bytes to {}",
        prepared.byte_len(),
        prepared.target()
    );
    let receipt = prepared.send(None).await?;
    println!(
        "Response {} {}; {} response bytes",
        receipt.code,
        receipt.meta,
        receipt.body.len()
    );
    Ok(())
}
