# mooting

`mooting` provides backend-neutral p2panda storage primitives for signed,
multi-writer spaces. It lives in Mere's Moot family, but its store is generic
over operation extensions, log identifiers, and a
[`muniment`](https://github.com/mark-ik/muniment) backend, so applications can
reuse it without adopting Moot's social model.

## What it owns

- `MunimentStore<B, E>`, implementing p2panda's `OperationStore`, `LogStore`,
  and `TopicStore` traits.
- A stable flat-key schema for operations, per-author logs, and topic indexes.
- Backend-neutral persistence through Muniment: memory for tests, redb on
  desktop, and future browser backends behind the same contract.
- `insert_indexed_operation`, which encodes the safe cross-trait write order:
  associate the topic/log first, then insert the operation. An interrupted
  write can leave a harmless empty index, never an operation LogSync cannot
  discover.
- `RecognitionPolicy` and `RecognitionContext`, which evaluate endorsements
  against a membership set frozen at a commitment over the winning signed Moot
  membership operations and scoped to that Moot's ID. Fixed thresholds,
  fractional thresholds, unanimity, and one-member acceptance share one
  deterministic, inspectable result shape.

## What it does not own

- Domain event grammars, validation, folds, governance, or conflict policy.
- Iroh endpoints, gossip, LogSync sessions, or background tasks.
- Identity-provider types.

Moot, Isometry, mesh, and other consumers define their own signed extension and
materializer. Recognition policy evaluation is generic plumbing; choosing or
changing a policy is still the domain's signed governance act. The host
composes the store with p2panda LogSync and Mere's
`transport::SyncedSpace`. Signing keys may come from Mere identity, Personae,
or another provider through raw Ed25519 seed material at the transport/wire
boundary.

## Storage shape

```text
log/<author>/<cbor-log-id>/<sequence>  -> encoded operation
op/<operation-hash>                   -> log entry key
topic/<topic>/<author>/<cbor-log-id>   -> empty index marker
```

Sequence numbers are fixed-width hexadecimal, preserving log order under
Muniment's lexicographic `scan`. Log identifiers are CBOR-encoded before being
placed in keys, so one adapter supports `u64`, `[u8; 32]`, and other p2panda
`LogId` types.

## Status

Pre-1.0. The generic store adapter is implemented and tested with
`MemoryBackend`. It is used by Mere's sync domains and by Isometry's campaign
collaboration space. Domain APIs and standalone Moot repository promotion are
tracked separately.

## License

MPL-2.0.
