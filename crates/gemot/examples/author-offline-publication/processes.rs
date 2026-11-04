// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

pub(super) async fn author_process(root: &Path) -> Result<(), AnyError> {
    let provider = author();
    let root_key = provider.master_public_key().to_bytes();
    let author_dir = root.join("author");
    fs::create_dir_all(&author_dir)?;
    let store_path = author_dir.join("moot");
    let founder_root = founder().master_public_key().to_bytes();
    let moot = MootFile::open(&store_path, MootId(MOOT_ID), founder_root, retention()).await?;
    let mut rules = ConstitutionRules::founder_only(founder_root);
    rules.admission = mien::Policy::MembersOnly {
        rate_limit: 20,
        rate_window_ms: 60_000,
    };
    rules.grant(CapabilityGrant {
        id: AUTHOR_GRANT,
        subject: root_key,
        path_prefix: cap_path(&fauna_cap()),
        not_before_ms: 0,
        expires_at_ms: None,
        delegation_depth: 0,
    });
    rules.grant(CapabilityGrant {
        id: HOST_GRANT,
        subject: host().master_public_key().to_bytes(),
        path_prefix: cap_path(&hosting_cap()),
        not_before_ms: 0,
        expires_at_ms: None,
        delegation_depth: 0,
    });
    moot.found(FOUNDER_SEED, None, None, rules, now_ms())
        .await?;
    moot.update_membership_for_identity(
        &founder(),
        MootMembershipAction::Create {
            initial_members: vec![
                MootMember {
                    member: founder_root,
                    access: MootAccessLevel::Manage,
                },
                MootMember {
                    member: root_key,
                    access: MootAccessLevel::Write,
                },
                MootMember {
                    member: host().master_public_key().to_bytes(),
                    access: MootAccessLevel::Write,
                },
            ],
        },
    )
    .await?;
    let content = moot.object_store().sync_store().put_blob(PAGE).await?;

    let revision = PublicationRevisionV1 {
        version: 1,
        publication_id: publication_id(root_key, "borrowed-garden"),
        slug: "borrowed-garden".into(),
        author_root: root_key,
        parent: None,
        path: PAGE_PATH.into(),
        media_type: "text/gemini".into(),
        content: content.clone(),
        at_ms: now_ms(),
    };
    let signed = sign_revision(&provider, revision)?;
    let revision_bytes = serde_json::to_vec(&signed)?;
    let revision_ref = moot
        .object_store()
        .sync_store()
        .put_blob(&revision_bytes)
        .await?;
    let revision_id = revision_ref.digest.as_32()?;
    verify_revision(&signed, PAGE)?;

    let contribution_receipt = moot
        .share_authorized_for_identity(
            &provider,
            revision_id,
            SCHEMA_ID.into(),
            "The borrowed garden".into(),
            now_ms(),
        )
        .await?;
    let contribution = match moot.outbound(&contribution_receipt).await? {
        MootOutboundOperation::Object(operation) => operation,
        _ => return Err(failure("share command returned another lane")),
    };
    validate_contribution(&contribution, &signed, revision_id, MOOT_ID, policy())?;

    let content_hash = content.digest.as_32()?;
    let mut aggregate = Vec::new();
    moot.export_plain_drop(
        &mut aggregate,
        DropExportProfile::default(),
        DropLimits::default(),
    )
    .await?;
    let (_, mut records) = read_plain_drop(Cursor::new(aggregate), DropLimits::default())?;
    records.push(DropRecord::BlobChunk {
        blob_hash: revision_id,
        offset: 0,
        bytes: revision_bytes,
    });
    records.push(DropRecord::BlobChunk {
        blob_hash: content_hash,
        offset: 0,
        bytes: PAGE.to_vec(),
    });
    let mut drop_bytes = Vec::new();
    let drop_receipt = write_plain_drop(&mut drop_bytes, &records, DropLimits::default())?;
    let transfer_store = BlobStore::new();
    let transfer_hash = transfer_store.put_bytes(drop_bytes).await?;
    let scope = BlobScope::new(MOOT_ID);
    let transfer_authority = BlobReadAuthorizer::new();
    transfer_authority.retain(scope, transfer_hash);
    transfer_authority.allow_reader(scope, host().master_public_key().to_bytes());
    let transport = P2pandaTransport::builder(provider.master_keypair())
        .scoped_blobs(&transfer_store, scope, transfer_authority)
        .bind()
        .await?;
    let ticket = transport.ticket().await?;

    write_json(
        &receipt_path(root, "author"),
        &AuthorReceipt {
            pid: std::process::id(),
            root: root_key,
            store: store_path.display().to_string(),
            transport_store: "memory (author process lifetime)".into(),
            ticket,
            drop_id: drop_receipt.id.0,
            drop_blob_hash: transfer_hash.to_bytes(),
            publication_id: signed.revision.publication_id,
            revision_id,
            content_hash,
            contribution_operation: *contribution.hash.as_bytes(),
        },
    )?;
    let stop = root.join("author-stop");
    while !stop.exists() {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    transport.close().await?;
    transfer_store.shutdown().await?;
    Ok(())
}

pub(super) async fn host_import_process(root: &Path) -> Result<(), AnyError> {
    let fixture_policy = policy();
    let host_provider = host();
    let host_root = host_provider.master_public_key().to_bytes();
    let host_dir = root.join("host");
    fs::create_dir_all(&host_dir)?;
    let store_path = host_dir.join("moot");
    let standing_path = store_path.join("standing.redb");
    let transport_store_path = host_dir.join("ingress-blobs");
    let moot = MootFile::open(
        &store_path,
        MootId(MOOT_ID),
        founder().master_public_key().to_bytes(),
        retention(),
    )
    .await?;
    let author_receipt: AuthorReceipt = read_json(&receipt_path(root, "author"))?;
    let ingress = BlobStore::open(&transport_store_path).await?;
    let host_transport = P2pandaTransport::builder(host_provider.master_keypair())
        .bind()
        .await?;
    let author_peer = host_transport
        .add_peer_ticket(&author_receipt.ticket)
        .await?;
    ensure(
        author_peer.to_bytes() == author_receipt.root,
        "author ticket carries another transport identity",
    )?;
    let transfer_hash = BlobHash::from_bytes(author_receipt.drop_blob_hash);

    let attacker_provider = intruder();
    let attacker_ingress = BlobStore::new();
    let attacker_transport = P2pandaTransport::builder(attacker_provider.master_keypair())
        .bind()
        .await?;
    let attacker_author_peer = attacker_transport
        .add_peer_ticket(&author_receipt.ticket)
        .await?;
    let unadmitted_peer_refused = attacker_ingress
        .fetch_from(&attacker_transport, attacker_author_peer, transfer_hash)
        .await
        .is_err();
    ensure(
        unadmitted_peer_refused,
        "unadmitted transport peer fetched the publication drop",
    )?;
    ensure(
        !attacker_ingress.has(transfer_hash).await?,
        "refused peer retained publication bytes",
    )?;
    attacker_transport.close().await?;

    let transfer_lease = BlobLease::new(
        BlobScope::new(MOOT_ID),
        "gemot.publication.drop",
        author_receipt.drop_id,
    )?;
    ingress
        .fetch_from_named(
            &host_transport,
            author_peer,
            transfer_hash,
            transfer_lease.as_bytes(),
        )
        .await?;
    ingress.flush().await?;
    let valid_drop = ingress.get_bytes(transfer_hash).await?.to_vec();
    let live_peer_transfer = digest(&valid_drop) == author_receipt.drop_blob_hash;
    ensure(
        live_peer_transfer,
        "live peer transfer changed the drop bytes",
    )?;

    let mut corrupt_drop = valid_drop.clone();
    let last = corrupt_drop
        .last_mut()
        .ok_or_else(|| failure("drop was empty"))?;
    *last ^= 0x01;
    let corrupt_drop_refused =
        read_plain_drop(Cursor::new(corrupt_drop), DropLimits::default()).is_err();
    ensure(corrupt_drop_refused, "corrupt drop was accepted")?;
    ensure(
        moot.object_store().ops(MOOT_ID).await?.is_empty(),
        "corrupt drop mutated host store",
    )?;

    let foreign_key = author().derive_keypair(PUBLICATION_SALT)?;
    let foreign = gemot::moot::to_operation_seed(
        foreign_key.to_seed(),
        [0xee; 32],
        &MootEvent::Shared {
            manifest_id: [1; 32],
            schema_id: SCHEMA_ID.into(),
            title: "foreign".into(),
            at_ms: now_ms(),
        },
        0,
        None,
    );
    let foreign_moot_refused = moot.object_store().accept(MOOT_ID, &foreign).await.is_err();
    ensure(foreign_moot_refused, "foreign moot operation was accepted")?;
    ensure(
        moot.object_store().ops(MOOT_ID).await?.is_empty(),
        "foreign operation mutated host store",
    )?;

    let (drop_report, records) = read_plain_drop(Cursor::new(&valid_drop), DropLimits::default())?;
    let contribution = records
        .iter()
        .filter_map(|record| decode_operation_record::<MootExt>(record).ok().flatten())
        .find(|operation| *operation.hash.as_bytes() == author_receipt.contribution_operation)
        .ok_or_else(|| failure("drop has no contribution"))?;
    let blobs = records
        .iter()
        .filter_map(|record| match record {
            DropRecord::BlobChunk {
                blob_hash, bytes, ..
            } => Some((*blob_hash, bytes.clone())),
            _ => None,
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let (_, event) = moot_from_operation(&contribution)?;
    let revision_id = match event {
        MootEvent::Shared { manifest_id, .. } => manifest_id,
        _ => return Err(failure("drop operation is not Shared")),
    };
    let revision_bytes = blobs
        .get(&revision_id)
        .ok_or_else(|| failure("drop omits publication revision"))?;
    let signed_revision: SignedPublicationRevisionV1 = serde_json::from_slice(revision_bytes)?;
    let content_hash = signed_revision.revision.content.digest.as_32()?;
    let content = blobs
        .get(&content_hash)
        .ok_or_else(|| failure("drop omits publication content"))?;
    let verified_revision_id = verify_revision(&signed_revision, content)?;
    ensure(
        verified_revision_id == revision_id,
        "revision blob has a false id",
    )?;
    validate_contribution(
        &contribution,
        &signed_revision,
        revision_id,
        MOOT_ID,
        fixture_policy,
    )?;

    let attacker = intruder();
    let attacker_root = attacker.master_public_key().to_bytes();
    let unauthorized_revision = sign_revision(
        &attacker,
        PublicationRevisionV1 {
            version: 1,
            publication_id: signed_revision.revision.publication_id,
            slug: signed_revision.revision.slug.clone(),
            author_root: signed_revision.revision.author_root,
            parent: Some(revision_id),
            path: PAGE_PATH.into(),
            media_type: "text/gemini".into(),
            content: BlobRef::blake3(content),
            at_ms: now_ms(),
        },
    )?;
    let unauthorized_bytes = serde_json::to_vec(&unauthorized_revision)?;
    let unauthorized_id = digest(&unauthorized_bytes);
    let forged_revision_refused = verify_revision(&unauthorized_revision, content).is_err();

    let import_receipt = moot
        .import_plain_drop(Cursor::new(&valid_drop), DropLimits::default())
        .await?;
    let authorized = moot.authorized_fauna(now_ms()).await?;
    let authorized_contribution_visible = authorized.len() == 1
        && authorized[0].manifest_id == revision_id
        && authorized[0].shared_by == signed_revision.revision.author_root;
    ensure(
        authorized_contribution_visible,
        "imported contribution is absent from the current authorized projection",
    )?;
    let before_unauthorized_share = moot.object_store().ops(MOOT_ID).await?.len();
    let unauthorized_command = moot
        .share_authorized_for_identity(
            &attacker,
            unauthorized_id,
            SCHEMA_ID.into(),
            "forged update".into(),
            now_ms(),
        )
        .await;
    let unauthorized_update_refused = forged_revision_refused
        && matches!(unauthorized_command, Err(MootError::Unauthorized(_)))
        && moot.object_store().ops(MOOT_ID).await?.len() == before_unauthorized_share;
    ensure(
        unauthorized_update_refused,
        "unauthorized update command changed the retained object lane",
    )?;
    ensure(
        moot.object_store()
            .sync_store()
            .get_blob(&signed_revision.revision.content)
            .await?
            == Some(content.clone()),
        "host did not retain exact content",
    )?;

    let commitment = HostingCommitmentV1 {
        version: 1,
        moot_id: MOOT_ID,
        revision_id,
        host_root,
        audience: "public".into(),
        max_bytes: content.len() as u64,
        retain_until_ms: now_ms() + 86_400_000,
        policy_revision: POLICY_REVISION,
        at_ms: now_ms(),
    };
    let hosting = sign_hosting(&host_provider, commitment)?;
    validate_hosting(&hosting, revision_id, content.len(), fixture_policy)?;

    let hosting_id = digest(&serde_json::to_vec(&hosting)?);
    let standing_event = StandingEvent::CommitmentMade {
        by: ChainRoot(host_root),
        commitment: CommitmentId(hosting_id),
        scope: Scope(format!(
            "publication/{}/{}/public/{}",
            hex(&MOOT_ID),
            hex(&revision_id),
            hosting.commitment.max_bytes
        )),
        cadence_ms: 3_600_000,
        duration_ms: Some(86_400_000),
        at_ms: hosting.commitment.at_ms,
    };
    let standing_before_refusal = moot.standing_store().len().await?;
    let unauthorized_event = StandingEvent::CommitmentMade {
        by: ChainRoot(attacker_root),
        commitment: CommitmentId(hosting_id),
        scope: Scope(format!(
            "publication/{}/{}/public/{}",
            hex(&MOOT_ID),
            hex(&revision_id),
            hosting.commitment.max_bytes
        )),
        cadence_ms: 3_600_000,
        duration_ms: Some(86_400_000),
        at_ms: hosting.commitment.at_ms,
    };
    let unauthorized_host_refused = matches!(
        moot.record_standing_authorized_for_identity(
            &attacker,
            unauthorized_event,
            &hosting_cap(),
        )
        .await,
        Err(MootError::Unauthorized(_))
    ) && moot.standing_store().len().await?
        == standing_before_refusal;
    ensure(unauthorized_host_refused, "unauthorized host passed policy")?;
    let standing_receipt = moot
        .record_standing_authorized_for_identity(&host_provider, standing_event, &hosting_cap())
        .await?;
    let host_command_authorized = true;
    let standing = match moot.outbound(&standing_receipt).await? {
        MootOutboundOperation::Standing(operation) => operation,
        _ => return Err(failure("hosting command returned another lane")),
    };

    let bundle = PublicProofBundle {
        revision: signed_revision,
        contribution_header: contribution.header.encode(),
        contribution_body: contribution.body.as_ref().unwrap().to_bytes(),
        standing_header: standing.header.encode(),
        standing_body: standing.body.as_ref().unwrap().to_bytes(),
        hosting,
    };
    validate_bundle(&bundle, content)?;
    write_json(&host_dir.join("proof-bundle.json"), &bundle)?;
    write_json(
        &receipt_path(root, "host-import"),
        &HostReceipt {
            pid: std::process::id(),
            root: host_root,
            store: store_path.display().to_string(),
            standing_store: standing_path.display().to_string(),
            transport_store: transport_store_path.display().to_string(),
            transfer_source: author_receipt.root,
            imported_drop: drop_report.id.0,
            standing_operation: *standing.hash.as_bytes(),
            corrupt_drop_refused,
            foreign_moot_refused,
            unauthorized_update_refused,
            unauthorized_host_refused,
            unadmitted_peer_refused,
            live_peer_transfer,
            constitution_operations: import_receipt.constitution_operations,
            membership_operations: import_receipt.membership_operations,
            authorized_contribution_visible,
            author_command_authorized: authorized_contribution_visible,
            host_command_authorized,
        },
    )?;
    host_transport.close().await?;
    ingress.shutdown().await?;
    Ok(())
}
