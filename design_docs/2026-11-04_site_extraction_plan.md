# Shared site generation and serving

**Status, 2026-11-04: S1–S3 landed; S4 first namespace/work/keeper slice implemented and locally qualified.** Gemot receives the portable model from
Mere and the filesystem/publication/listener library from Knot. This plan owns
the shared libraries; Mere's site-publication plan retains resident/browser
integration. Existing listener receipts keep their original machine, protocol
and authority scope. A source relocation is not another physical or peer trial.

## Direction

Mark accepted a static-site generator in Gemot spanning Gemtext, Scroll,
Markdown and HTML, with CSS, JavaScript and Lua as later possibilities. Formats
and delivery protocols are separate choices. Ordinary sites remain usable
without Moot membership, Knot's editor, or an already running resident. Knot
supplies authoring controls; Mere and Turnstone supply their application and
browser integration. Generated artifacts are checked immutable inputs to an
explicit publication action. Building a site starts no listener or replication.

The extraction retains the existing native contract first. `gemot-site` owns
manifest validation, canonical snapshots, content identities and the optional
history/community-publication adapters. `gemot-site-host` owns saved folders,
bounded publication, protocol handlers, submissions and resident handoff. Each
is an independent workspace under `crates/`, excluded from the community root's
default build. Their optional community adapters retain the qualified supplier
cohort; sharing a repository does not force its root runtime into ordinary sites.

The previous `mere-site` and `knot-site` package names become the shared Gemot
packages. Import aliases in applications may describe their role, but no donor
facade or duplicate implementation remains. Preserve MPL notices, canonical V1
fixtures and field order, metadata, hashes, history salts, intent strings and
first-owner/explicit-submit behavior. Historical identities keep their recorded
names even when source package identifiers change.

## Phases and done conditions

### S1. Receive the native libraries

Copy tracked source, tests, fixtures and notices; record donor commits and blobs.
Compare original and receiving test inventories. Preserve the existing optional
history, publication, runtime-acceptance and Retinue feature boundaries. Carry
the existing publication and Scroll process-test size exceptions with their source instead
of inventing a new allowance. Resolve one supplier source per shared package
version; do not advance renderer, storage, identity or transport pins casually.

Done when model tests cover default/history/publication, the host tests cover
native serving/submission/history, selected features compile, and the model's
declared MSRV library gate passes. Default normal/build graphs must contain no
editor, renderer or community runtime dependency. Keep ignored process tests
distinct from actual exercised resident integration.

### S2. Switch the real consumers and retire donors

Publish the receiving source before changing Git consumers. Knot's editor and
desktop import the shared host library; Mere's resident imports both packages
directly from Gemot. The browser receives the same snapshot/reader contract.
Update workspace membership, patch tables, tests, scripts and CI paths together.
Mere has concurrent source work, so its cut uses the existing clean extraction
worktree and stable build outputs, then integrates without disturbing that work.

Done when locked receiving checks pass for Knot's actual roots and Mere's
remaining workspace, the resident's publication/handoff cases pass, and donor
blob comparisons justify removing both source copies. A live independent
publisher/resident protocol run is recorded only if actually executed. Preserve
existing consumer pins that do not need this cut; old published Git revisions
and receipts remain available.

### S3. Add the wider generation profiles

After the source cut, reuse existing parsers and writers for explicit target
profiles. Preserve native pages byte-for-byte when requested. New Markdown/HTML
artifacts need their own versioned envelope rather than changing V1 native
snapshot meanings. Targets, templates, paths and limits are caller-selected.
Unsupported constructs produce explicit diagnostics; conversion between every
format pair is not assumed lossless. CSS can be emitted assets. JavaScript/Lua
execution roles require their own build, client or server decision and reuse of
the existing execution owners.

Done when each selected writer has deterministic metadata/link/asset fixtures
and the real consumers use its checked artifact. Qualify protocol delivery
separately from writing a format. The existing native cut does not close S3.

### S4. Preserve the community workflow scope

The community domain lives in `crates/gemot/src/moot/workflow/`; its signed
facts extend the existing objects lane. Full signed workflow operations survive
checkpoints, and signature/body/author bindings are rechecked after pruning; a
checkpoint author cannot fabricate a worker's consent. `NamespaceEvent` binds a stable id to a
same-Moot pinned collection version or explicitly followed accepted collection.
Exact-head updates support rename, removal and conflict resolution. Conflicting
values and duplicate names fail closed. Names confer no access; readers need
Read membership, current admission and the separate stable collection read scope.

`WorkTerms` freezes a designated worker, criteria, inputs, windows/cadence, byte
ceiling, reviewers/quorum, compensation (including explicit None), optional
Standing commitment, renewal ceiling and handoff permission. Signed consent to
an exact offer is one stable agreement even when repeated. Submissions and a
reviewer's decisions have explicit replacement heads. Conflicts abstain until
resolved; Mooting evaluates the frozen reviewers. Issuers may withdraw exact
offers and named workers may decline them; later replayed consent cannot revive
a cancelled offer. Cancellation, a new exact offer
and successor consent form renewal/handoff. Cancellation survives later loss of
a grant; it chooses no physical deletion policy. An `AcceptedWork` receipt needs
an accepted result in every required window. Hosts can explicitly consume its
optional commitment through the existing Standing API; the ledger rewards an
owned commitment once.
Settlement receipts are independent of acceptance, including payment failure.

The optional `work-host` feature supplies `Keeper`, host-selected limits and a
bounded `WorkFetcher` seam. It saves acquisition intent before fetching, verifies
and retains via Eidetic transactions, and reconciles actual copies after restart.
Serving and derived `DocumentIndex` search recheck worker/reader access, current
collection selection, withdrawal, expiry and byte integrity. Same-owner copies
are reused; jobs remain distinct claims. Protected payloads require a supplied
wallet sealer. Releasing physical copies, cross-owner deduplication and GC policy
remain with Eidetic and explicit host policy.

The first demonstration is qualified with independent local processes and redb:
contributor acquisition, source exit, keeper restart, fresh-reader retrieval,
permitted local search and signed review. Tests cover withdrawal, revocation,
replay, conflicting updates, missing dependencies, drops and checkpoint pruning.
The process transport is a synthetic loopback adapter with a fixed reader root;
it is not a new authenticated remote protocol, a two-machine or physical trial,
or a mounted application UI. Broader P1 historical-authority proof, protected
peer key distribution, automatic scheduling and compensation execution remain
separate owner work in the Moot publication plan.

### S5. Discovery advertisements and application controls

Authorized 2026-11-04: Murm carries bounded opaque gossip advertisements on the
existing endpoint; Gemot owns canonical signed hints, exact collection versions,
provider authority, recipient read checks, lifetime ceilings, replay watermarks,
withdrawal and conflict handling. Subject classes never determine topics. This
slice advertises explicitly public site descriptions; confidential descriptions
need an encrypted audience path. Cached hints are never access capabilities.

The receiving source implements `workflow::discovery` and a bounded publication
of the authority/record prelude through existing Moot lanes. Murm delivery nonces
allow unchanged signed hints to be repeated for late history and newly joined
peers without weakening application sequence/expiry checks. Restore retains
watermarks; current collection, membership and grants are rechecked at listing
and opening. Credential-bearing, active-script and loopback addresses refuse.

Turnstone owns public publishing intent, subject/abstract browsing, withdrawal
and worker-validated navigation. Knot owns saved-site format selection and
checked artifact export. New app controls must reject changed focus, stale
sessions/generations and expired/withdrawn hints, and never make building a
publication action. Canonical app scope remains in their existing site/place
plans. Required local carrier, signature/state and app consumer receipts have a
100 MB aggregate cap at `Code/testing/gemot/discovery-ui-20261104`. Remote-machine,
physical and headed qualification remain separate from model/native tests.

### S6. Protected descriptions and headed qualification

Authorized 2026-11-05 after S5's local native trials. Knot's real site tile
qualifies generation, existing-output and dirty-source refusal; its completion
wake is corrected. Turnstone's real shell qualifies public advertisement,
subject/query browsing, invoked opening and withdrawal with a marked public test
identity. Installed personal custody and remote-machine qualification remain
separate.

Protected advertisements bind a member audience into the signed V2 message.
Public V1 messages omit the new optional field, preserving their signed bytes.
Stickleback group data encryption seals the wire hint, local journal and metadata
body with separate authenticated contexts bound to the Moot and, for bodies,
the resource. Wire ingress requires the current group epoch, then applies the
same reader/provider authority, exact-version, expiry and replay checks as public
hints. Protected plaintext refuses public ingress. Retained epochs may reopen a
journal after rotation; visibility still requires present authority.

Hosts must keep protected titles, URLs, abstracts and subjects out of clear
record fields and public caches. Turnstone uses opaque collection ids derived
under a private per-profile namespace, generic record labels, encrypted bodies
and a separate encrypted journal. Each audience keeps its own bounded directory.
Explicit public publishing stays public; choosing a member advertisement cannot
make an older public disclosure secret. Current members receive group keys
through the existing invitation/rotation path. Removed recipients cannot open
future epochs; old keys or learned plaintext cannot be remotely erased.

Encryption protects descriptions, not peer traffic, group epoch identifiers or
all community record structure. Keyless, stale-epoch and tampered payloads fail
without a plaintext fallback. Required receipts: cross-context/audience/tamper,
legacy public wire, replay/restart/withdrawal and epoch-removal tests, actual
consumer persistence and live peer controls. The aggregate lane is
`Code/testing/gemot/headed-protected-20261105`, explicitly refined to **200 MB**
to preserve the headed fixture's preallocated storage. Original evidence is kept.

Qualified receiving source is public: Gemot `495e5e6` and Turnstone `69550c0e`.
Turnstone's member native-window trial exercises the explicit encrypted prompt,
Arts browsing, validated opening, withdrawal and encrypted-journal reopening.
The prior public V1 journal also restores in that profile. Fourteen focused
catalogue/palette cases and the 88-case place suite pass, including live
late-invitee delivery through rotation and retained-file plaintext inspection.
The production `peers` all-target Clippy gate passes with existing warnings.
Core workflow tests pass 17 cases plus the parent-exercised ignored process
helper; the Rust 1.97.1 check passes. Knot's native fix is `0bccade`, with its
374-case, one-ignored desktop regression qualified at two test threads and
documented at `c0013fc`. The earlier timing attempt is preserved.

Current custody lifecycle controls pass. Ten unrelated Windows capture fixtures
fail during graph-persistence setup with `Access is denied` in both the receiving
and retained pre-encryption executable; both logs remain. The source audit
changes only Turnstone's four Gemot package sources. Installed personal custody,
remote machines, anonymous traffic and production remote keeper serving retain
their separate qualification gates.

## Findings

- 2026-11-04: the model has no editor dependency. Knot's host library already
  owns reusable snapshot-only serving and handoff, rather than an editor buffer.
  Its native V1 history salt and resident intent strings are durable contracts.
- 2026-11-04: both receiving packages have standalone roots, retaining their
  original optional feature gates and explicitly selected supplier identities.

- 2026-11-06: Mere cycle_breaks D3/P5 (`mere/design_docs/mere_docs/implementation_strategy/2026-11-06_cycle_breaks_plan.md`):
  `murm-resolve` owns the release-address trait and no longer names `gemot-address`.
  Gemot implements it in `gemot-site-host` (feature `murm-resolve`, `ReleaseAddressRef`),
  chosen over `gemot-address` to keep the grammar crate free of Murm; its four tests pin the
  mapping of the log and governed forms.

## Evidence and progress

Required retained evidence: donor/receiver source and fixture comparisons,
commands/results, selected source graphs, locked consumer checks and public
revisions. Aggregate cap for all four ordered extractions: **100 MB**, under
`Code/testing/subsystem-extractions-20261104`. Use stable reusable Cargo targets
and set both target/build-directory variables. No isolated Cargo home is needed.
The plan's receipt record is
`archive_docs/receipts/2026-11-04_site_extraction_plan_receipts.md`.

- 2026-11-04: receiving suites match the donor: 31 model and 44 host tests pass;
  five process/helper fixtures remain separately ignored. Both libraries pass
  their Rust 1.97.1 default library checks. Default normal/build graphs have 47
  and 102 packages, with no editor, renderer or community runtime. Donor removal
  waits for published receiving source and actual consumer qualification.

- 2026-11-04: S1/S2 source cut and actual receiving landed: Gemot `4492351`,
  Knot `1c752bc`, Mere `f9e8cea64`. The integrated 86-member Mere workspace
  compiles locked; its resident executable passes independent Gemini/TLS,
  Scroll/TLS and Micron/Retinue loopback publisher/resident cases. These are
  synthetic local process receipts, separate from remote/physical acceptance.

- 2026-11-04: implementation authorized for S3 followed by S4. New writer artifacts use V2; existing native V1 bytes remain unchanged. The work uses the existing clean main checkout and stable Gemot target. New bounded evidence is `Code/testing/gemot/site-workflow-20261104` with a 100 MB aggregate cap. Namespace/work facts extend the existing objects lane so normal replication, drops and retention snapshots carry them. Detailed command, conflict and host lifecycle semantics are recorded as code/tests land.

- 2026-11-04: S3 writer/host implementation covers three source profiles and four output profiles through versioned checked artifacts, declarative HTML templates, source metadata/identity, assets, explicit loss refusal and native literal preservation. Native parsers come from the pinned Errand cohort; richer Scroll input links and relations are never silently treated as read links. `site-build`, reopened export custody and generated native delivery are the actual consumers. HTML input, richer unmapped Scroll conversions and JS/Lua execution retain their separate extension scope.

- 2026-11-04: Scroll metadata is carried into `CatalogueDocument`: abstract,
  language and raw broad subject suffix 0..9. The Scroll specification uses a
  UDC-inspired class digit, with 4 general/unclassified; this is not full UDC
  notation. Catalogue search can filter that digit and index the abstract.
  Murm's `p2panda-discovery` finds peers sharing opaque topics. Gemot owns
  semantic catalogues and their audience, and never derives confidential topics
  from predictable subject classes. Source: [Scroll specification](https://raw.githubusercontent.com/michael-lazar/smolnet-portal/master/docs/scroll_spec.txt).

- 2026-11-04: S5's public-description receiving chain is qualified and public.
  Murm `2d5760a` carries bounded repeatable opaque hints; Gemot `89a5935` owns
  signed catalogue validation. Turnstone `cb9bd91a` supplies host-only public
  advertising, subject/abstract browsing, withdrawal and owner-validated opening;
  `10ccc41e` explicitly supplies Mien to production peer builds. Knot `2279669`
  supplies saved-site format selection and checked export, with receipt/command
  corrections at `e8e5bac`. Murm passes 14 sync cases, Gemot 14 workflow cases
  plus its separately ignored helper, Turnstone 85 place and four catalogue UI
  cases, and Knot 374 desktop cases with one ignored helper. The full site tile
  also passes its three focused writer/widget cases. Both app commit checks and
  Turnstone's feature-enabled all-target production Clippy gate pass. These are
  automated Windows/native and local-peer receipts. S6 above closes the local
  headed and protected-description gates; remote-machine and production keeper
  serving qualification remain open.
