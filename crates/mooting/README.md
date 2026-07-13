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

## Compatibility

The generic `MunimentStore<B, E>` moved to `murm-replication`, alongside the
shared LogSync drain. `mooting` temporarily re-exports `MunimentStore` so
existing consumers can migrate without a flag day. New code should import it
from `murm_replication`.

## Status

Pre-1.0. Recognition policy is implemented. The compatibility store re-export
will be removed before the standalone Moot promotion.

## License

MPL-2.0.
