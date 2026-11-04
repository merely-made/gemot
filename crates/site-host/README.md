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
