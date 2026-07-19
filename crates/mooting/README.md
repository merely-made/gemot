# mooting

`mooting` provides deterministic recognition policy for governed Moot spaces.
It evaluates endorsements against a membership set frozen at one signed
revision and scoped to one Moot.

## What it owns

- `RecognitionPolicy` and `RecognitionContext`.
- Fixed, fractional, unanimous, and one-member thresholds.
- Deterministic decisions with inspectable supporting members and revision.

Choosing or changing a recognition policy remains a signed Moot governance
act. This crate supplies the evaluation vocabulary, not a second policy engine.

## Status

Pre-1.0. Recognition policy is implemented. Replicated storage is consumed
directly from `murm-replication` by domain crates.

## License

MIT OR Apache-2.0.
