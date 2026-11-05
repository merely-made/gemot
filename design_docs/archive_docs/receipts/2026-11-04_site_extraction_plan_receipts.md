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

## 2026-11-04, discovery receiving source

Murm carrier source `e33a430574057d259b2acd8f19bd44291a4e2873`, followed by
reannouncement fix `2d5760aac0d9f77813b45bc9f7695b9f8c1e120e`, is public.
The Murm sync suite passes 14 cases. The real two-endpoint gossip case passes
again with identical application bytes delivered twice through fresh carrier
nonces; sender/receiver byte ceilings and pending queues remain bounded.

Gemot `gemot-discovery-final` passes 14 workflow cases (one helper separately
ignored and exercised by its parent). Three new discovery cases cover signed
metadata, exact current collection selection, recipient and publisher authority,
withdrawal, expiry, stale/repeated sequences, persisted equivocation, protected
watermarks, scope/signature tampering, and refusal of credentials, local targets
and active schemes. The previous keeper/reviewer process case also passes on
the new Murm cohort. The bounded authority/record prelude compiles in this gate.

Command logs and compact receipts are under
`Code/testing/gemot/discovery-ui-20261104`, cap 100 MB. This receives shared
source for app integration; app, headed and remote-machine outcomes are recorded
separately as they are exercised. Public descriptions are deliberate disclosures;
restricted metadata encryption is not qualified by this carrier.

## 2026-11-04, application receiving closure

Shared source is public at Gemot `89a5935` and Murm `2d5760a`. Turnstone's
functional integration is `cb9bd91a`, followed by the explicit production Mien
feature dependency at `10ccc41e`. Knot's generation controls are `2279669`, with
canonical receipts and relocated library commands at `e8e5bac`.

`turnstone-place-qualified` passes all 85 place cases. Its live case founds a
place, advertises before invitation, admits and connects a later peer, receives
and opens the signed hint through worker validation, withdraws it and refuses
the old navigation. Existing projection, rotation, revocation, restart and
session cases pass. `turnstone-ui-final` runs the same final native executable's
four catalogue UI cases: semantic filtering, expiry/focus refusal, host-only
publication and stale/duplicate navigation guards. `turnstone-peer-production`
passes locked all-target Clippy with peers, including the normal shipping app;
Mien is explicitly selected rather than leaking through a test-only dependency.
Clippy has warnings; this is not a warnings-clean receipt.

`knot-desktop-suite` passes 374 tests with one ignored helper, including the new
saved-source build cases. `knot-full-site-widget` passes all three writer-control
cases and clicks the actual complete site tile through Genet layout/hit testing.
It verifies Markdown export, native exact-byte output, dirty-source refusal,
checked export reopening, unchanged existing output and absence of a publisher.
Default locked all-target Clippy and line-ceiling commit hooks pass for both
apps. No size exception was added: catalogue actions have a separate typed home.

Initial failed compilation attempts are retained. The unconditional catalogue
timer made a quiet-state place test stall; the corrected timer wakes only active
catalogue state and the original regression passes. Its interrupted suite and
an overlapping Windows linker refusal are non-acceptance attempts. The first
feature-enabled production check exposed the test-only Mien dependency, then
the corrected production gate passed. Logs and `gates.jsonl` preserve all attempts.

`source-cohorts.json` and `receiving-graph-audit.json` compare the baseline and
receiving lock records and edges. Turnstone changes only its nine Gemot/Murm
package sources, with no duplicate shared package versions and no registry or
other Git record change. Knot changes the two shared site sources and enables
pulldown-cmark's escape dependency/edge for HTML output. Renderer, storage and
other Git records remain unchanged in both consumers. The preexisting Mere WIP
and five unrelated Gemot working-tree statuses are preserved.

The aggregate receipt at `Code/testing/gemot/discovery-ui-20261104` remains below
100 MB. Stable targets `C:/t/cargo-targets/{murm,gemot,turnstone,knot}` are reused;
no isolated target, Cargo home or worktree was created. Local-peer command and
native widget receipts do not qualify a headed window, remote machine,
protected-description encryption or the keeper's production remote protocol.

## 2026-11-05, headed controls and protected receiving source

`Code/testing/gemot/headed-protected-20261105/headed-receipt.json` records the
actual Windows windows, inputs, captures and marked synthetic fixtures. The
first Knot run exposed the missing generation busy flag; the corrected native
trial reports completion without another input and refuses existing output and
unsaved source. Turnstone's ignored native trial passes after public publication,
subject/query filtering, invoked opening and withdrawal; its journal contains
the signed withdrawal. The lane's cap is refined from 100 to 200 MB to preserve
preallocated native storage; original evidence and the refinement are retained.

`gemot-protected-suite` passes 17 workflow cases with one process helper ignored
and exercised through its parent. Three protected cases cover hidden hint/cache/
body bytes, separately bound domains and resources, current-epoch delivery,
recipient removal, present read authority, replay after encrypted-cache restart,
withdrawal, tamper, byte bounds, and refusal to downgrade a protected signed hint
onto public ingress. Public V1 signed messages omit the new audience field.
The independent keeper-process scenario still passes. Actual protected app
receiving is recorded after the shared source is published. Local privacy does
not establish anonymous peer traffic, erase old plaintext, or qualify remote
machines or personal installed custody.

## 2026-11-05, protected application receiving closure

Public source: Gemot `495e5e65f250023ef5a6d8db40389f933ba274be`, Turnstone
`69550c0ec640411b4cc0f91ee96f7cf82af2b200`, and Knot's native correction
`0bccade` with regression closeout `c0013fc`. Murm's unchanged `2d5760a`
continues carrying opaque bounded advertisements. Turnstone's source audit
changes only four Gemot package source records; every other registry and Git
record, including renderer and storage, is unchanged.

The receipt lane's `protected-headed-receipt.json` and three member captures
record the actual native shell: explicit encrypted prompt, Members-labelled Arts
result, invoked owner-validated opening, withdrawal and empty results. After
closing, the test opens the encrypted journal with retained actual group keys
and verifies the signed withdrawal. Its prior public V1 fixture also restores.
These are synthetic public test keys and offline document acquisition, separate
from installed personal custody and remote-machine acceptance.

`turnstone-protected-lock` passes 14 cases: five UI controls, five worker cases,
two live-peer cases and two existing palette cases. The complete place suite
passes 88. Four identity declarations and three exact custody lifecycle cases
pass. Locked all-target Clippy passes both with production `peers` and in the
commit's ordinary configuration, retaining existing warnings. A broader custody
name filter also selects ten capture fixtures that fail at unchanged graph-save
setup with Windows `Access is denied`; the retained pre-encryption executable
reproduces the same four-pass/ten-fail outcome before the changed method runs.
Both attempts are preserved. Knot's corrected desktop suite passes 374 cases
with one helper ignored at two test threads. Its earlier timing failure, passing
exact retry and qualified full run remain alongside the headed evidence.

All generated build output reuses stable repository targets. No isolated target,
Cargo home or worktree was created, and owned native windows were closed. The
lane's aggregate cap remains 200 MB; `closure.json` records final heads and
retained bytes. Group key holders are the cryptographic audience; current
membership and collection-read grants remain separate listing/open authority.
Encryption does not erase prior disclosures or hide routing and epoch traffic.
