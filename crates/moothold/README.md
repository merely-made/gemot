# moothold

`moothold` is Gemot's Tier 3 federation crate: a holding of autonomous moots.

The package was originally published as the umbrella for Mere's social layer.
That umbrella is now [`gemot`](https://crates.io/crates/gemot). From 0.1.0,
`moothold` has the narrower meaning the tier model always wanted: direct
agreements and reciprocal resource sharing between moots.

## What it owns

- Direct, one-hop concords between moots.
- Settings-selected composition of reputation from concorded moots.
- Inter-moot reciprocity credits for storage, compute, and hosting.
- The signed Moothold aggregate: founding agreement, member Moot identities,
  configurable concord terms, and deterministic founder-governed revisions.
- Future federation constitution, cross-moot requests, retention, and clean
  forks.

Gemot retains per-Moot constitutional law, Tessera facts, rosters, and signed
Moot operations. Moothold consumes those facts at the federation boundary; it
does not turn reputation into authority or silently trust transitive concords.

## Status

The first promoted slice contains concord and reciprocity models plus the
signed, durable Moothold aggregate. Peer-session wiring and governed succession
remain to be built.

## License

MIT OR Apache-2.0.
