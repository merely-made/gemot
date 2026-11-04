// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

pub(super) fn run_child(exe: &Path, role: &str, root: &Path) -> Result<(), AnyError> {
    let status = Command::new(exe)
        .arg(role)
        .arg(root)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;
    ensure(status.success(), format!("{role} process failed: {status}"))
}

pub(super) fn wait_for(path: &Path) -> Result<(), AnyError> {
    for _ in 0..200 {
        if path.exists() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Err(failure(format!("timed out waiting for {}", path.display())))
}

pub(super) fn orchestrate(root: &Path) -> Result<(), AnyError> {
    if root.exists() {
        ensure(
            fs::read_dir(root)?.next().is_none(),
            format!("proof root is not empty: {}", root.display()),
        )?;
    }
    fs::create_dir_all(root)?;
    fs::create_dir_all(root.join("receipts"))?;
    let exe = std::env::current_exe()?;

    let mut author_process = Command::new(&exe)
        .arg("author")
        .arg(root)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    wait_for(&receipt_path(root, "author"))?;
    let author_ready_ms = now_ms();
    let author: AuthorReceipt = read_json(&receipt_path(root, "author"))?;
    let import_result = run_child(&exe, "host-import", root);
    let host_import_complete_ms = now_ms();
    fs::write(root.join("author-stop"), b"stop\n")?;
    let author_status = author_process.wait()?;
    let author_exit_ms = now_ms();
    ensure(
        author_status.success(),
        format!("author process failed: {author_status}"),
    )?;
    import_result?;
    let host: HostReceipt = read_json(&receipt_path(root, "host-import"))?;

    let mut server = Command::new(&exe)
        .arg("host-serve")
        .arg(root)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    wait_for(&root.join("ready.json"))?;
    let host_restart_ready_ms = now_ms();
    let ready: Ready = read_json(&root.join("ready.json"))?;
    let reader_dir = root.join("reader-sandbox");
    fs::create_dir(&reader_dir)?;
    let base = format!("gemini://localhost:{}", ready.port);
    let proof_url = format!("{base}/.well-known/mere/{}.json", hex(&author.revision_id));
    let reader_status = Command::new(&exe)
        .arg("reader")
        .arg(&reader_dir)
        .arg(&base)
        .arg(&proof_url)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;
    let reader_complete_ms = now_ms();
    fs::write(root.join("stop"), b"stop\n")?;
    let server_status = server.wait()?;
    let host_exit_ms = now_ms();
    ensure(
        server_status.success(),
        format!("host server failed: {server_status}"),
    )?;
    ensure(
        reader_status.success(),
        format!("reader process failed: {reader_status}"),
    )?;
    let reader: ReaderReceipt = read_json(&reader_dir.join("reader.json"))?;

    let roots = [author.root, host.root, reader.root];
    let independent_roots = roots[0] != roots[1] && roots[0] != roots[2] && roots[1] != roots[2];
    let final_receipt = FinalReceipt {
        proof: "author-offline community publication P1".into(),
        transport: "scoped iroh BlobStore transfer of a Stickleback NativeDrop, then ordinary Gemini TLS".into(),
        author_exited_before_host_restart: author.pid != host.pid
            && host.pid != ready.pid
            && author_status.success()
            && author_exit_ms <= host_restart_ready_ms,
        independent_roots,
        exact_page_after_restart: reader.content_hash == author.content_hash,
        author,
        host,
        serving: ready,
        reader,
        lifecycle: LifecycleReceipt {
            author_ready_ms,
            host_import_complete_ms,
            author_exit_ms,
            host_restart_ready_ms,
            reader_complete_ms,
            host_exit_ms,
            author_exit_success: author_status.success(),
            host_exit_success: server_status.success(),
        },
        limitations: vec![
            "PublicationRevisionV1 and HostingCommitmentV1 are proof-local candidate records; production owners and wire compatibility remain to be ruled.".into(),
            "Gemot membership and signed capability grants now authorize the contribution and hosting commands; FixturePolicy remains only for proof-local publication lineage and hosting byte/retention bounds.".into(),
            "The iroh transfer ran over authenticated loopback on one machine; a two-machine receipt remains open.".into(),
            "Fixture wiring uses each Personae master public key as its transport endpoint identity; production still needs the admitted-persona-to-device-key adapter.".into(),
            "The proof bundle remains a host sidecar; the canonical publication-linkage record still needs a durable governed owner.".into(),
            "Standing Scope rehearses the public promise but cannot itself encode the full audience, byte bound, and policy revision.".into(),
            "Current authority is reconstructed after restart; historical authority-at-publication still needs a signed constitution and membership frontier.".into(),
            "Aggregate import spans several durable stores and is not yet atomic across all Gemot lanes.".into(),
        ],
    };
    ensure(
        final_receipt.author_exited_before_host_restart,
        "roles did not use distinct processes",
    )?;
    ensure(
        final_receipt.independent_roots,
        "roles did not use independent roots",
    )?;
    ensure(
        final_receipt.exact_page_after_restart,
        "reader content differs from author content",
    )?;
    ensure(
        final_receipt.host.live_peer_transfer,
        "host receipt did not prove live peer transfer",
    )?;
    ensure(
        final_receipt.host.unadmitted_peer_refused,
        "host receipt did not prove scoped transport refusal",
    )?;
    ensure(
        final_receipt.host.constitution_operations > 0
            && final_receipt.host.membership_operations > 0
            && final_receipt.host.authorized_contribution_visible
            && final_receipt.host.author_command_authorized
            && final_receipt.host.host_command_authorized,
        "host did not reconstruct and exercise community authority",
    )?;
    let final_path = receipt_path(root, "author-offline-publication");
    write_json(&final_path, &final_receipt)?;
    println!("{}", serde_json::to_string_pretty(&final_receipt)?);
    println!("receipt={}", final_path.display());
    Ok(())
}
