# mere-site

Portable native-site profiles, page metadata, manifest validation and canonical
`PublishedSnapshotV1` records shared by Knot and Djinn. The default library has
no editor, filesystem, protocol server, runtime, identity or persistence dependencies.

Optional feature `history` adds `history::SiteHistory<B>` over a host-supplied
Muniment backend: explicit record/list/load operations, separately versioned
checkpoint journals and exact V1 snapshot blobs. Hosts assign `SiteId`, clock,
labels and capacity limits. Recording requires transactional read/write support;
competing changes refuse rather than overwrite. Failed journal commits may
leave unreferenced blobs. No pruning, collection or publication is automatic.

The snapshot's exact JSON representation and BLAKE3 digest preserve Knot's V1
handoff. Fixed compatibility fixtures cover Scroll, Gemini, Spartan and Micron,
including Unicode, CRLF and native metadata. V1's profile-specific filenames,
validation and byte ceilings are unchanged.

Knot supplies saved files and protocol-serving adapters. Djinn supplies durable
custody and listener lifetime. Replication and publication authority remain
owned by their existing layers.

Optional `publication` binds retained Gemini, Scroll and Micron snapshots to
Gemot's signed contributions and causal collections. Eidetic's `save_schema`
and `save_typed` retain `publication::snapshot_schema()` and the snapshot itself;
the typed binding preserves exact canonical V1 bytes. The host explicitly chooses
privacy, provenance, trust, backend and any acquisition. No content is promoted
to public automatically.

`publication::contribute` verifies locally retained PublicPortable content and
calls Gemot's stable-identity membership/capability gate. Select the returned
operation with Gemot's existing collection command and observed heads.
`SiteSelection` names that contribution at an exact `CollectionVersion`;
`publication::open` rechecks current effective selection around local resolution.
Anonymous public readers do not need Moot membership. `OpenedSite::page("/")`
maps to the native index and returns complete native metadata and bytes.

`SiteBindingV1` supplies explicit endpoint policy: pin a contribution, or follow
a collection with exactly one effective site. `open_binding` observes current
authority before opening the exact version. Pinning still requires effective
collection membership; it cannot override withdrawal or revoked authority.
Following refuses empty or ambiguous collections and never chooses by timestamp.

`publish_public_snapshot` explicitly retains public bytes, authors the signed
contribution and selects it against observed heads. Optional replacement uses
existing collection operations. A later refusal returns already-authored
contribution/operation references; it does not claim those effects rolled back.

Opening is a point-in-time read. Hosts revalidate when their serving policy
requires current authority. This feature supplies neither a listener nor a
hosting promise, actor, automatic latest-version rule or cross-Moot signed
publication revision. Protocol replies and peer acquisition remain separate.
Spartan's existing V1 model stays available but is outside this first binding.

Run `cargo test --manifest-path crates/site-model/Cargo.toml` from the Gemot repository.
Run `cargo test --manifest-path crates/site-model/Cargo.toml --features history` for durable reopen, failure and
concurrent-checkpoint controls.
Run `cargo test --manifest-path crates/site-model/Cargo.toml --features publication,history` for signed selection,
fork/withdrawal controls and all three native publication profiles after reopen.
