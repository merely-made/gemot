# Shared site generation and serving

**Status, 2026-11-04: in progress.** Gemot receives the portable model from
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

The namespace/agreed-work candidate remains in
`design_docs/moothold_docs/implementation_strategy/2026-11-01_moot_publication_plan.md`,
2026-11-04 Findings. A generated site is one possible deliverable. Governed
bindings, offers, agreements, submissions and review still need their domain
records and deterministic authority/fold/export/retention coverage. Recognition,
publication selection, hosting consent, verified custody, observed availability
and optional settlement remain separate outcomes. Reuse existing collections,
Mooting, Standing, retention and derived `DocumentIndex` machinery.

The proposed first demonstration is unpaid contribution/review, a volunteer
keeper, and a fresh reader after contributor shutdown and keeper restart.
Done only after actual acquisition, retention, retrieval and permitted search
are exercised with revocation, withdrawal, replay and concurrent-update controls.
The source extraction keeps this in scope without claiming that workflow built.

## Findings

- 2026-11-04: the model has no editor dependency. Knot's host library already
  owns reusable snapshot-only serving and handoff, rather than an editor buffer.
  Its native V1 history salt and resident intent strings are durable contracts.
- 2026-11-04: both receiving packages have standalone roots, retaining their
  original optional feature gates and explicitly selected supplier identities.

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
