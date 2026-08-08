# moothold

Tier 3 federation for [`gemot`](https://crates.io/crates/gemot) moots: a
holding of autonomous moots bound by direct, one-hop concords and reciprocal
resource sharing. Each member Moot keeps its own constitution, roster, trust
facts, and storage.

The package name was previously used for Mere's whole social layer. That layer
is now `gemot`; from 0.1.0 `moothold` means the tier.

## Modules

| Path | Contents |
| --- | --- |
| (root) | `VERSION`, plus re-exports of everything below |
| `concord` | `CompositionPolicy` (`Insular`, `WeightedSum`, `CautiousImport`), `RepLens` with `concord`, `weight`, and `composite_score`; `MootId` re-exported from gemot |
| `reciprocity` | `Reciprocity` with `record`, `balance`, and `may_request` |
| `event` (via root) | `MootholdId`, `MemberTerms` (`concord_weight_bp`, `reciprocity_tolerance`, `MAX_CONCORD_WEIGHT_BP`), `MootholdEvent` (`Founded`, `MootAdmitted`, `MootRemoved`, `CompositionChanged`) |
| `fold` (via root) | `Moothold` aggregate state (`id`, `name`, `founder`, `revision`, `composition`, `members`) and `Moothold::fold`; `MootholdError` |
| `store` (via root) | `MootholdStore<B>`, `MootholdFileStore` (redb), `MootholdStoreError` |
| `wire` (via root) | `MootholdExt`, `to_operation_seed`, `from_operation`, `verify`, `MootholdWireError` |

`RepLens::composite_score` folds a persona's own-moot standing together with
its concorded moots' depreciated scores, weighted in basis points. Concords are
one hop: a lens never traverses another moot's concords. Concorded moots whose
`TesseraConfig` differs from the viewer's are dropped from the sum.

`Reciprocity` is a directed `(provider, beneficiary)` credit ledger.
`may_request` returns false once a requester's unreciprocated balance exceeds
the given tolerance.

## The aggregate

`MootholdStore<B>` (`B: muniment::Backend`) admits founder-signed operations
through `stickleback::OperationProcessor` and folds them:

- `in_memory`, `open`
- `author_foundation`, `admit_moot`, `remove_moot`, `change_composition`
- `aggregate` returns the current `Moothold`
- `accept` for operations arriving over sync
- `sync_store` hands out the `MunimentStore` a host joins with

Every non-founding event names the prior accepted revision; a stale or
non-founder operation is rejected (`MootholdError::StaleRevision`,
`Unauthorized`).

## Dependencies

`gemot` for `MootId`, `Ledger`, `TesseraConfig`, and `PersonaChains`.
`stickleback` for admission and the muniment-backed store, `muniment` (`redb`)
for durable backing, `p2panda-core` and `p2panda-store` (0.7) for signed
operations, `serde`, `thiserror`. `tempfile` and `tokio` are dev-only.
The crate declares no cargo features.

## Status

Pre-1.0. Concord composition, reciprocity credits, and the signed durable
Moothold aggregate are implemented. Peer-session wiring, governed succession,
a federation constitution, and cross-moot resource requests are not built.

## License

MIT OR Apache-2.0.
