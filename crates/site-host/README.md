# Gemot site host

Shared saved-site files, immutable publication, native serving, submissions and
resident handoff. The default build needs neither an editor nor Moot membership.
The server sees an explicit immutable snapshot and never an editor buffer.

`gemot-site` supplies the portable manifest and native snapshot V1. Optional
`history` stores saved-file checkpoints; `publication` composes explicit Gemot
collection authority and Eidetic custody. `retinue` enables NomadNet separately.
The default-off `runtime-acceptance` fixtures require a real resident executable
through `DJINN_MOOT_SITE_EXE` and are invoked explicitly for that receiving gate.

Run `cargo test --manifest-path crates/site-host/Cargo.toml --all-features`.
The shared command is `site-publish`; an application supplies its own authoring
and publication controls. Protocol and stored-contract identifiers preserve the
original qualified native behavior.

Scope, qualification and the wider generation profiles are in
`design_docs/2026-11-04_site_extraction_plan.md` at the repository root.

## Format generation (V2)

Enable `generate` for `BuildRequest`, `BuildOptions` and checked `GeneratedSiteV2` artifacts. Source profiles are Gemtext, Scroll and CommonMark; writers target Gemtext, Scroll, Markdown and HTML. Errand owns both native grammars; Pulldown Cmark owns CommonMark parsing/HTML rendering. `reject_loss` defaults to true. Unsupported input actions, relation metadata, nonconsecutive/alphabetic Scroll ordinals and level-five textual-title conversion refuse explicitly; a matching native profile can instead set `preserve_native_bytes` to retain exact bodies. Literal native V1 envelopes and their digests stay unchanged.

HTML template/container, escaped banner/footer, title suffix, included CSS, remote-image policy, link schemes and smaller byte ceilings are caller-selected. Pages use bounded flat filenames; assets use `assets/NAME`. Local links are rewritten to output names, unknown local targets refuse, and lossy native projections need explicit opt-in with diagnostics. The V2 envelope retains original author metadata and input hashes, output bytes, settings, assets and diagnostics. It promises deterministic artifacts for that input/profile, rather than lossless conversion among every pair. HTML is an output profile; arbitrary HTML input and JavaScript/Lua execution are separate extensions.

The host's `site-build native SITE_DIR html OUTPUT_DIR` reads a completed saved site; `site-build project REQUEST.json markdown OUTPUT_DIR` reads a V2 `BuildRequest` (see the fixed writer project fixture). Output directories must be new. `open_export` compares every page/asset against the canonical envelope; `reply` is a protocol-neutral map lookup. `native_publication` feeds asset-free Gemtext/Scroll artifacts to the existing matching protocol handler. Building/exporting does not publish or start a listener.
