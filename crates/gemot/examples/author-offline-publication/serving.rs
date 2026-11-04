// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

pub(super) async fn host_serve_process(root: &Path) -> Result<(), AnyError> {
    let host_dir = root.join("host");
    let author_receipt: AuthorReceipt = read_json(&receipt_path(root, "author"))?;
    let ingress = BlobStore::open(host_dir.join("ingress-blobs")).await?;
    let transfer_hash = BlobHash::from_bytes(author_receipt.drop_blob_hash);
    let transfer_lease = BlobLease::new(
        BlobScope::new(MOOT_ID),
        "gemot.publication.drop",
        author_receipt.drop_id,
    )?;
    ensure(
        ingress.lease_hash(&transfer_lease).await? == Some(transfer_hash),
        "restarted host lost its publication transfer lease",
    )?;
    ensure(
        digest(&ingress.get_bytes(transfer_hash).await?) == author_receipt.drop_blob_hash,
        "restarted host has changed publication carrier bytes",
    )?;
    ingress.shutdown().await?;
    let moot = MootFile::open_existing(host_dir.join("moot"), MootId(MOOT_ID), retention()).await?;
    let bundle: PublicProofBundle = read_json(&host_dir.join("proof-bundle.json"))?;
    let content = moot
        .object_store()
        .sync_store()
        .get_blob(&bundle.revision.revision.content)
        .await?
        .ok_or_else(|| failure("reopened host has no content"))?;
    validate_bundle(&bundle, &content)?;
    let contribution =
        decode_moot_operation(&bundle.contribution_header, &bundle.contribution_body)?;
    ensure(
        moot.object_store()
            .operation(&contribution.hash)
            .await?
            .is_some(),
        "reopened host has no contribution operation",
    )?;
    let revision_id = digest(&serde_json::to_vec(&bundle.revision)?);
    ensure(
        moot.authorized_fauna(now_ms())
            .await?
            .iter()
            .any(|entry| entry.manifest_id == revision_id),
        "restarted host no longer authorizes the publication contribution",
    )?;
    let standing = decode_standing_operation(&bundle.standing_header, &bundle.standing_body)?;
    ensure(
        moot.standing_store().get(&standing.hash).await?.is_some(),
        "reopened host has no Standing operation",
    )?;
    let membership = moot.membership().await?;
    ensure(
        moot.authorize_current_capability(
            &membership,
            &MootAuthorizationRequest {
                subject: bundle.hosting.commitment.host_root,
                capability_path: cap_path(&hosting_cap()),
                at_ms: now_ms(),
            },
        )
        .await?
            == GateDecision::Allow,
        "restarted host no longer has current hosting authority",
    )?;

    let page_path = bundle.revision.revision.path.clone();
    let proof_path = format!(
        "/.well-known/mere/{}.json",
        hex(&digest(&serde_json::to_vec(&bundle.revision)?))
    );
    let proof_bytes = serde_json::to_vec_pretty(&bundle)?;
    let source_store = moot.object_store().sync_store();
    let source_ref = bundle.revision.revision.content.clone();
    let source = move |request: &SourceRequest| {
        let request_path = request.path.clone();
        let page_path = page_path.clone();
        let proof_path = proof_path.clone();
        let proof_bytes = proof_bytes.clone();
        let source_store = source_store.clone();
        let source_ref = source_ref.clone();
        async move {
            if request_path == page_path {
                source_store
                    .get_blob(&source_ref)
                    .await
                    .ok()
                    .flatten()
                    .filter(|bytes| source_ref.verifies(bytes))
                    .map(Item::gemtext)
            } else if request_path == proof_path {
                Some(Item::Document {
                    mime: "application/json".into(),
                    body: proof_bytes,
                })
            } else {
                None
            }
        }
    };

    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_bytes = certified.cert.der().to_vec();
    let key_bytes = certified.key_pair.serialize_der();
    let acceptor = gemini_protocol::server::acceptor(
        vec![CertificateDer::from(cert_bytes.clone())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_bytes)),
    )?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let ready = Ready {
        pid: std::process::id(),
        port,
        certificate_blake3: digest(&cert_bytes),
    };
    write_json(&root.join("ready.json"), &ready)?;

    let stop = root.join("stop");
    gemini_protocol::server::serve(
        listener,
        acceptor,
        errand::serve::adapt::gemini(Arc::new(source)),
        gemini_protocol::server::ServerConfig::default(),
        async move {
            loop {
                if stop.exists() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        },
    )
    .await?;
    Ok(())
}

pub(super) async fn fetch_retry(url: &str) -> Result<errand::Response, AnyError> {
    let mut last = None;
    for _ in 0..40 {
        match errand::fetch(url).await {
            Ok(response) => return Ok(response),
            Err(error) => last = Some(error.to_string()),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(failure(format!(
        "Gemini fetch never connected: {}",
        last.unwrap_or_else(|| "unknown error".into())
    )))
}

pub(super) async fn reader_process(
    reader_dir: &Path,
    base: &str,
    proof_url: &str,
) -> Result<(), AnyError> {
    let provider = reader();
    let reader_root = provider.master_public_key().to_bytes();
    let cache = reader_dir.join("cache");
    fs::create_dir_all(&cache)?;
    let cache_started_empty = fs::read_dir(&cache)?.next().is_none();
    ensure(cache_started_empty, "reader cache was not empty")?;
    let proof_response = fetch_retry(proof_url).await?;
    ensure(
        proof_response.raw_status == Some(20),
        "proof bundle was not Gemini 20",
    )?;
    ensure(
        proof_response.meta == "application/json",
        "proof bundle MIME changed",
    )?;
    let bundle: PublicProofBundle = serde_json::from_slice(&proof_response.body)?;

    let page_url = format!("{base}{PAGE_PATH}");
    let page_response = fetch_retry(&page_url).await?;
    ensure(
        page_response.raw_status == Some(20),
        "page was not Gemini 20",
    )?;
    ensure(page_response.meta == "text/gemini", "page MIME changed")?;
    ensure(page_response.body == PAGE, "served page bytes changed")?;
    validate_bundle(&bundle, &page_response.body)?;
    let missing_response = fetch_retry(&format!("{base}/not-published.gmi")).await?;
    ensure(
        missing_response.raw_status == Some(51),
        "unpublished path was visible",
    )?;
    fs::write(cache.join("garden.gmi"), &page_response.body)?;

    let contribution =
        decode_moot_operation(&bundle.contribution_header, &bundle.contribution_body)?;
    let standing = decode_standing_operation(&bundle.standing_header, &bundle.standing_body)?;
    write_json(
        &reader_dir.join("reader.json"),
        &ReaderReceipt {
            pid: std::process::id(),
            root: reader_root,
            cache_started_empty,
            source: page_url,
            raw_status: page_response.raw_status.unwrap_or_default(),
            unpublished_path_status: missing_response.raw_status.unwrap_or_default(),
            media_type: page_response.meta,
            content_hash: digest(&page_response.body),
            author_root: bundle.revision.revision.author_root,
            contributor_key: *contribution.header.verifying_key.as_bytes(),
            host_root: bundle.hosting.commitment.host_root,
            hosting_signer: *standing.header.verifying_key.as_bytes(),
        },
    )?;
    Ok(())
}
