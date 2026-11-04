# Moot publication: author-offline publishing, hosting, collections and co-op

**Status:** 2026-11-01: cut from `2026-06-12_moot_object_m1_plan.md`, archived
whole in `archive_docs/2026-11-01/`. Landed there: Moot object M1 (declare, join,
share; 2026-06-12); the same-machine author-offline publication proof with
stable-Persona binding and current command authority (2026-09-05); Fleece 0.5
preservation adoption, capture evidence and the `captured-web` search seam
(2026-09-06 to 2026-09-08); contribution withdrawal (P3b) and same-Moot
collection lineage (P3d) in Gemot's records lane (2026-09-09); Turnstone's P3a
source capture and P3c collection consumer (2026-09-09, 2026-09-10); the
capsule-library proof, Graphshell capsule mount and independent readings
(2026-10-09, 2026-10-10); the conversation/coop CPU slice (2026-10-10); resource
owners, Cambium controls, bounded retention and signed hosting handlers, the
admitted Graphshell resource mount and durable readings (2026-10-11 to
2026-10-13); Mere's native site-profile binding (2026-10-21). Open: the
production publication and hosting records and historical authority (P1), updates
and honest retention (P2), the remaining collection gates (P3), application co-op
(P4), addressed delivery (P5) and the host and consumer residue (P6).

**For:** making a moot a useful distribution community without waiting for
ranking, reputation economics or a universal graph editor. An author publishes;
a different member accepts a bounded hosting commitment, retains the bytes and
serves them after the author stops; a reader with no access to the author
retrieves the exact revision and can inspect authorship, the moot submission and
the host's distinct commitment. The three roles use independent Personae roots
and distinct stores.

Not here:
- ordinary saved-site serving, the publication host, wider smolweb coverage and
  Turnstone's adoption of the effects rule:
  `mere/design_docs/mere_docs/implementation_strategy/2026-10-28_site_publication_plan.md`,
  which names this plan as the owner of the production publication and hosting
  records;
- Turnstone's page capture lanes (P3a and its successors):
  `turnstone/design_docs/2026-08-28_page_capture_plan.md` (see Open questions);
- Fleece's preservation contract and cross-standard ledger:
  `genet/design_docs/2026-09-05_fleece_preservation_contract_plan.md`;
- Murm's bilateral conversation owner, recorded in Mere's archived
  `archive_docs/2026-10-28/2026-07-12_murm_peer_runtime_and_moot_domain_plan.md`.

Receipts from this plan's runs go to
`archive_docs/receipts/2026-11-01_moot_publication_plan_receipts.md`, never into
this plan (DOC_POLICY §8). Evidence that matters is a test in the repository or a
line in Findings. The earlier receipts stay in the archived plan.

## Constraints

The following are semantic requirements, not new wire types. Before adding a
type, map it to the existing owner and record any extension needed there.

| Fact | Meaning and owner |
|---|---|
| Space identity and accepted history | A mere is share-ready; adding participants does not migrate its format. Gemot owns community admission and authority; Commons retains graph edits; Stickleback accepts and replicates canonical operations. |
| Publication and revision | A continuing publication names immutable content revisions and their parents. Eidetic stores typed manifests/payloads; an existing domain authorizes updates. Current host location is separate from publication identity. |
| Contribution | A signed submission to a moot references a revision and carries its own context. Republishing preserves the origin and adds a contribution. It does not replace authorship with the host or moot identity. |
| Hosting commitment | A host names the content, audience, byte limit, retention bound and applicable policy revision it accepts. Gemot owns it as a Standing fact; Mesh's compute leases and Stickleback's carrier records are unchanged. |
| Availability observation | Retrieval and integrity checks establish observed availability. A promise, an accepted transfer and demonstrated service are separate facts. |
| Extraction and search | Fleece extracts supplied DOMs; the host owns acquisition and snapshot custody. Eidetic retains the extraction contract; search is a derived projection of admitted, selected content. |
| Application interaction | Woodshed and other apps own domain facts/actions. Graphshell exposes granted views and intents. Live presence and playback coordination have distinct lifetimes from retained material. |

- **Identities stay separate.** Content, capture, publication and contribution
  identity are distinct. Identical payload bytes may be shared by different
  captures or contributions. A snapshot's source URL, time and extraction
  contract are not deducible from its payload hash.
- **Production ownership is ruled.** Eidetic owns the signed immutable
  publication revision as a typed artifact; Gemot's `Shared` event contributes
  its manifest without duplicating authorship. Gemot owns the full hosting
  promise. The production hosting command derives `moot/hosting/<audience>`
  from the requested audience, intersects community bounds with the device's
  local ceilings and binds the observed authority frontier before signing. The
  generic Standing command stays a lower-level primitive.
- **Historical authority is a signed causal cut, not a wall-clock claim.**
  Contribution and hosting records bind the constitution revision plus observed
  constitution, membership and delegation heads. Resolution reports `proven`,
  `denied`, `pending missing evidence` or `legacy unbound`; an incomplete
  imported prefix is never treated as denial. Current authority remains the
  moderation and serving view.
- **Personae and recognition.** Independent personae may build independent
  histories without publishing links to other roots. Device identities name
  offers and observations; owner and community authority are checked separately.
  Recognition between moots is explicit policy; ancestry transfers no
  membership, obligations or governing power. RF reception grants no membership.
- **Observation grants nothing.** Membership, presence, completion feedback and
  display metadata never become write authority; owners recheck current
  authority and keys at dispatch.

## Phases

### P1. Production publication and hosting records

The same-machine form passed on 2026-09-05, and bounded signed hosting promises
landed on 2026-10-12 (`crates/gemot/src/moot/hosting.rs`). Remaining: the
Eidetic publication revision artifact; the full hosting record owner with
automatic heartbeats and Standing completion; the authority-at-publication
frontier and its four-way resolution (the bound `AuthorityCut` is evidence, not
a verdict); atomic cross-lane import; the Persona-to-device-key adapter; and the
two-machine transport receipt.

Done when the three-role sequence passes across two machines, including host
close/reopen; changed/corrupt bytes are refused; a foreign-moot or unauthorized
hosting/update operation is refused; an ordinary Gemini client retrieves the
public page from the volunteer host while the author is stopped; and historical
resolution reports all four outcomes over real imported prefixes. A signed
revision and a raw Gemini response have separate checks. A self-issued fixture
secret on both peers does not satisfy independent-persona admission. The
historical M1 two-machine `moot-peer` run (Mark's verification: same
`MOOT_SPACE`, distinct `MOOT_SEED`s, tickets both ways) is the first transport
receipt this phase can take.

### P2. Updates and honest retention

Publish a second revision under the same publication identity. Show exact-version
retrieval and a policy-selected current revision; detect competing heads rather
than treating arrival order as authority. Expose requested, accepted, available,
expired or withdrawn state in the existing Graphshell surface. Re-evaluate
visibility and serving authority when grants or policies change, including after
restart.

Done when an old exact reference remains identifiable, accepted update authority
is checked, an expired promise is not reported as live hosting, an offline host
is not reported as measured availability, and withdrawn content leaves the
current search and serving projection. Withdrawal does not claim to erase copies
already held by recipients. Hosting already refuses expired and withdrawn serving
(`signed_bounded_promise_replays_and_expiry_is_not_availability`,
`withdrawn_contribution_and_local_ceiling_changes_stop_serving`); the second
revision, competing heads and the Graphshell states are open. Availability
floors, erasure policy and checkpoint pruning stay under the existing
deletion/retention plan.

### P3. Captured collections: the remaining gates

P3a to P3d landed (Status). Remaining: shared-corpus measurements (unique
content/capture counts, extraction and replay bytes, index build/update cost,
heap use, query latency); held-out relevance cases and browser validation of the
current Eidetic `DocumentIndex` consumer (the index is a derived projection;
Tantivy is already retired from the inspected dependency graphs); cross-Moot
lineage verification; collection merge UI;
private collection encryption; hosted Weld DOM capture through a correlated
source or serialized-DOM engine seam; WARC-grade full-response custody (Genet's
`ResourceResponse` lacks requested URL, status, lossless headers and truncation
state); near-duplicate grouping; distributed indexes; the full official JSON-LD
and Web Annotation test suites.

Done when real selected pages survive peer transfer and reopen, a body-only query
finds them, duplicate submissions preserve both contributors while results group
content, a changed page cannot silently retarget an old annotation, and the
measurements above are recorded. Each later gate above lands with its own
done-condition when opened.

### P4. Application co-op and lineage

Reuse the active Woodshed/Graphshell co-op work after checking its final
implementing receipt. A friend joins a selected Set or comparison space;
independent local views issue granted domain intents. Retain material, edits and
chosen analysis records after both applications close. Record analysis input
revisions, relation selection/depth, musical constraints, method or model
version and accepted result. Personal chronological trails remain separately
selected for retention and sharing.

Done when a second participant reopens the shared work without the original
host, a fork retains ancestry without inheriting ungranted membership or
resources, and Woodshed continues to own musical meaning. A published edition
can use P1's hosting path. Verify live coordination separately from retained
edit exchange.

### P5. Addressed delivery through a mesh

Add bounded acceptance of addressed content for later delivery using the
existing Stickleback/native-drop path. Keep receive-for-delivery,
retain-for-a-period and publish-to-an-audience explicit.

Done when an intermediary restarts while the recipient is absent, then delivers
the same canonical addressed record once the recipient returns; wrong-recipient,
duplicate and over-budget handling is demonstrated. The intermediary gains no
right to publish or edit by carrying bytes. LoRa airtime/range and Signalman
device management need their own later consumer receipts.

### P6. Host and consumer residue

Open items the archived plan carried for consumers in other repositories. No
other live plan carries them; each names its owner. Each is done when its owner
lands it with a receipt; record the landing here.

- **Graphshell conversation mount** (Mere `ports/moot`, `ports/graphshell`):
  mount the derived conversation and coop states through ordinary Cambium
  controls, with independent selection and drafts, explicit send intent and
  owner-confirmed success or refusal. Presence, media and a general applet ABI
  need their own owners.
- **Resource controls** (Mere `ports/moot` resource owner and handlers): live
  peer dispatch and signed revocation across peers; content-fork and
  content-copy writes (reference forks exist); activity participation with real
  application sessions; a private access/key adapter; a streaming reader beyond
  the 4 MiB local limit; production themes and keyboard/focus; Turnstone
  mounting; protected hosting and key distribution.
- **Capsule host** (Mere `crates/script/app-host`, `ports/graphshell`): native
  `AppScript` epoch-deadline renewal per lifecycle call for sustained sessions;
  browser Gemot replay; host-page offline boot; live collection subscription;
  generic and concurrent applets; native and Turnstone mounting; remote
  projection fallback; private publication/key epochs; live coediting.
- **Retention backends** (Eidetic Muniment): transactional custody on backends
  that refuse it (Fjall returned `NotTransactional` on 2026-10-12); bounded
  backend reads, since stores materialize a value before the size check.

## Open questions

- Where are P3a and P3c tracked from here: in this plan, or in Turnstone's page
  capture plan as their authority? (Raised 2026-10-06; Turnstone's plan still
  calls P3a in progress although its capture landed.)
- The one-endpoint finding of 2026-06-12: p2panda-net registers LogSync under a
  constant protocol id, so tessera, mesh and moot lanes on one transport need one
  LogSync with one shared extension type and lanes separated by topic, or an
  upstream patch. Does this still bind under current Stickleback carriage, and
  which plan owns the unification?

## Findings

- 2026-11-04: reviewed the older namespace/agreed-work proposal against current
  source. Stable collection identities and causal versions exist in
  `crates/gemot/src/moot/records/collection.rs`; authorized mutation is now in
  `crates/gemot/src/moot/service/records.rs`. The general governed name-binding
  and offer/agreement/submission/review domain is not implemented. Its eventual
  records must participate in authority, folds, native drops and retention
  checkpoints, rather than only surviving a local append.
- The existing site binding already supports a pinned contribution or following
  an effective collection (`mere/crates/domain/site/src/publication.rs`); that
  host-selected binding is not a governed namespace directory. The shared site
  generator is one producer of immutable deliverables. Community review,
  publication selection, hosting consent and observed availability retain their
  distinct authority and records; ordinary site generation remains usable
  independently of Moot membership.
- The proposed unpaid contribution/review, volunteer keeper and fresh-reader
  search demonstration remains a useful candidate, not a qualified workflow.
  Reuse `crates/mooting/src/recognition.rs` for frozen-electorate evaluation.
  `crates/mien/src/ledger.rs` already rewards an open owned commitment only once;
  acceptance-to-Standing integration still needs evidence and stable effect
  identity. Bounded relay workers in `crates/gemot/src/moot/relay/host.rs` provide
  a concrete host-lifecycle precedent, with separate live readiness.
- Eidetic retention still writes owner/manifest-specific bodies
  (`eidetic/crates/eidetic-core/src/retention.rs`); shared physical bytes and
  independent retention claims, permission, quota and release/GC semantics remain
  separate design work. Community search already exchanges admitted capture
  records and rebuilds `DocumentIndex`; the captured collection adapter lives in
  `mere/ports/moot/src/captured_web.rs`. These findings are source inspection,
  without new builds or peer/restart acceptance. Older context is in
  `mere/design_docs/mere_docs/research/2026-06-04_resource_coordination_brief.md`
  and the retired, explicitly unbuilt
  `mere/design_docs/archive_docs/2026-10-06_retired_plans/2026-06-30_bounty_verification_economy_plan.md`.

- 2026-09-04: `crates/commons/src/lib.rs` exposes `Replica::accept` (line 955)
  and `projection_with_authority` (line 975); use the retained/effective split
  rather than an arrival-ordered shared graph.
- 2026-09-04: `eidetic/crates/eidetic-core/src/manifest.rs` (`BlobManifest`)
  separates content hash, sources, privacy, provenance and trust.
  `mere/crates/mesh/mesh/src/retention.rs` (`AvailabilityPolicy`) distinguishes a
  hosting promise from erasure; `lease.rs` is job-scoped, not publication
  hosting.
- 2026-09-09: withdrawal and collections are Gemot service commands with stable
  identity: `Moot::withdraw_share_for_identity`,
  `declare_collection_for_identity` and `set_collection_membership_for_identity`
  (`crates/gemot/src/moot/service.rs:809,872,912`). `authorized_fauna`
  (`records/roster.rs:153`) excludes withdrawn shares; `authorized_collection`
  (`records/collection.rs:184`) reports curated and effective selections. A
  collection fork copies no membership, grants, delegations, key epochs,
  Standing facts, leases, hosting promises or payloads.
- 2026-10-09: a JSON value projection reorders a signed pack wrapper's fields,
  so re-serializing cannot recover its content address; hosts fetch, hash and
  retain exact original pack bytes before parsing. A signature on the original
  component does not authenticate JavaScript claimed to be its translation; the
  derivation must be pinned from a trusted build.
- 2026-10-12: `gemot::moot::hosting` carries the full promise in the signed
  Standing scope, derives audience capability internally and binds an
  `AuthorityCut` (`crates/gemot/src/moot/hosting.rs:49`). Community limits are
  host-supplied settings for a named accepted constitution, not a constitutional
  clause. Copy and Standing are separate transactions: failure after custody
  leaves the copy.
- 2026-10-12: Eidetic retention commits quota, owner copy receipt, manifest and
  payload atomically and refuses non-transactional backends; Muniment's default
  `transact` returns `NotTransactional` (`eidetic/crates/muniment/src/backend.rs:139-146`).

## Progress

- 2026-11-01: cut from the Moot object M1 plan after a closure audit. That plan's
  landed work, run narratives and receipts stay with it in
  `archive_docs/2026-11-01/`.
