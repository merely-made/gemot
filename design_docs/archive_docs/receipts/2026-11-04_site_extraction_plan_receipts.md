# Shared site extraction receipts

## 2026-11-04: native receiving source

Donors: Mere `a9fa5c85c` in the reused extraction worktree and Knot
`7e66a1dfd644e74fea775d5782a4436ebc09ff95`. Full donor revisions, tracked blobs,
raw hashes and package input identities are under
`Code/testing/subsystem-extractions-20261104`; the two crates also keep
`source-import.json`. Ten model and twenty-seven host Rust files compare with
only package import/binary-lookup renames. All eight native V1 fixture files
are unchanged. History salts, intent strings and runtime function bodies retain
their original behavior. Two existing source-size exceptions follow their files.

Original and receiving suites: **31 model tests** and **44 host tests**, with
five separate ignored process/helper cases. Both default library MSRV checks
pass on Rust 1.97.1. Unused donor patches were removed with identical full
resolved package identities and features. Older Cargo normalized the model
lockfile without changing any package identity. Default normal/build graphs
contain 47 model and 102 host packages and exclude the community runtime,
editor and renderer; all-feature graphs also contain no Mere or Genet source.

Detailed commands, outcomes, warnings and intermediate failed setup checks stay
in `gates.jsonl` and its logs. The initial missing donor-relative patch and
lockfile-normalization failures are not acceptance receipts. New Markdown/HTML
writers, scripting, the general agreed-work workflow, physical peers and headed
acceptance are outside this receiving source gate.

## 2026-11-04: actual consumers and integrated native processes

Knot `1c752bcf034c1f03fc6c76d0088836c9df5e7010` consumes the shared host
library and removes its donor. Mere `f9e8cea6491aa3151c06c31d8ec280a9ff2e92b2`
removes its model donor, with 86 remaining members. Locked workspace/all-target
checks pass for both, as does Knot's explicit site-handoff client check. Mere's
hooks pass; the cut rebases cleanly over newer main without graph-input or
resident-source changes, and the combined locked check passes again.

The integrated resident binary is SHA-256
`e703241a662e71460bf528693cde11b5853ac31ff9c589b64eb67b34c4a03bb5`.
All three explicitly invoked publisher/resident process fixtures pass: Gemini
and Scroll over local TLS, and Micron over local Retinue. They exercise native
metadata, exact bodies, restart and current authority. The 75 standard cases
and three explicit process cases pass. These are synthetic local processes,
without headed, hardware, remote-machine or personal-wallet qualification.

Renderer, storage, identity and transport source identities in both consumers
remain unchanged. Primary Mere foreign files/index entries and concurrent Gemot
relay work are preserved. Two pre-existing generated-cache deletion blocks are
not retried; the reused Mere worktree remains available for the following cuts.

## 2026-11-04, S3 format writers

V2 writer artifacts are separate from native V1. Model all-feature/all-target suites pass 38 tests, with two existing ignored cases; host suites pass 47 tests, with three existing ignored process cases. Seven writer tests include four fixed body/digest goldens, unchanged V1 byte preservation, richer Scroll parsing, unsafe/unsupported input refusal, deterministic links/metadata/assets and declarative template escaping. Three host tests exercise a separate `site-build` process, reopened exact-file custody, changed-asset refusal and generated Gemtext over a real loopback Spartan listener. Model/host selected Rust 1.97.1 gates and both Clippy gates pass. These are library, process and loopback scopes; existing headed/physical/remote receipts retain their inputs.

Commands, baseline inventory, immutable build artifacts and compact summaries are in `Code/testing/gemot/site-workflow-20261104`, sharing a 100 MB cap with S4. Original V1 fixtures and format bytes remain unchanged. Default generation is opt-in and adds only the maintained parser profile; the ordinary model stays free of editor, renderer and community runtime dependencies. HTML input, unmapped Scroll action/relation conversion and JavaScript/Lua execution are outside these selected writer profiles.

## 2026-11-04, S4 namespace, agreed work and keeper

Implemented in `crates/gemot/src/moot/workflow/` with aggregate commands in
`service/workflow.rs`. Namespace and work facts use the objects lane, normal
outbound operations, drops and roster checkpoints. Checkpoints carry complete
signed workflow operation proofs and reject mismatched field/author/body/hash
claims, including a forged snapshot signed by the legitimate checkpoint owner.
Empty historical rosters keep their old encoding through omitted empty fields.

The final dedicated suite (`workflow-signed-tests`) passes **11 cases**, with
one separately ignored process entry invoked five times by the parent process
case. The workspace/all-target suite (`workflow-final-tests`) passes all five
members with `gemot/work-host`; the final proof hardening is covered by the
subsequent dedicated suite. Controls include conflicting/renamed/removed names,
exact pinned targets and separate read access; repeated/wrong-worker consent;
conflicting offers, submissions and review branches; failed settlement; frozen
reviewers through Mooting; current membership/grant expiry; withdrawal; bounded
renewal/handoff consent; missing facts, reverse-order fold and duplicate import;
redb reopen, governed checkpoint and actual prefix pruning; malformed wire and
checkpoint forgery refusal. Optional Standing is exercised separately after
accepted work, with duplicate fulfillment rewarding once.

The process case starts an independent contributor source, acquires its exact
catalogue into Eidetic retention, stops the source, reconstructs the keeper from
redb and uses a fresh reader process to retrieve, hash-check and locally search
the permitted collection before signed review. `processes-signed/` contains
compact keeper/reader receipts. The fixture uses a fixed authenticated-subject
input and a synthetic loopback socket adapter; this is not remote identity,
two-machine, protected-key, headed or physical qualification. Source metadata
includes Scroll broad class 7 and a searchable abstract. Class 5 returns no hit.
Private-without-sealer, corrupt-byte and restart-integrity refusals are tested.
A renewed job reuses one owner copy for two distinct job records; retiring the
old job does not erase the new job's bytes. Physical release/GC policy and
cross-owner deduplication are not selected here.

`workflow-clippy` passes across workspace/all-targets with `work-host` (561
warnings, including existing documentation/style warnings; not a warnings-clean
gate). New search dependencies reuse Mere's already qualified `eidetic-search`
7a3453a and `genet-text` ad362723 cohort. Existing source identities are unchanged.
Initial compile failures and the interrupted, unseeded dependency resolution are
preserved as non-acceptance attempts. Full command/results are in
`Code/testing/gemot/site-workflow-20261104/gates.jsonl`; all logs and compact
receipts remain below the 100 MB cap. No new worktree or Cargo home was created;
the existing `C:/t/cargo-targets/gemot` remains the shared reusable build owner.

`workflow-msrv` passes the feature-enabled Gemot library on Rust 1.97.1,
locked and offline. The signed-proof suite is compiler-warning free; Clippy
retains the warning scope stated above.
