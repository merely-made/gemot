# mooting

Deterministic recognition policy for governed Moot spaces. It evaluates a set
of endorsements against a membership set frozen at one signed revision and
scoped to one group.

## Public items

All of it lives in `mooting::recognition` and is re-exported from the crate
root.

| Item | What it is |
| --- | --- |
| `MemberKey` | `[u8; 32]`, a member's signing-key bytes |
| `ElectorateSnapshot` | `group_id`, `revision`, and the `BTreeSet<MemberKey>` frozen at that revision |
| `RecognitionPolicy` | `AnyEligible`, `Threshold { required }`, `Fraction { numerator, denominator, minimum }` (rounds up, with a floor), `Unanimous`; `validate()` rejects a zero threshold, a zero minimum, and a fraction outside `0 < n <= d` |
| `RecognitionContext` | Policy plus electorate; `evaluate(&BTreeSet<MemberKey>)` and `fingerprint()` (BLAKE3 over domain-separated CBOR) |
| `RecognitionDecision` | `group_id`, `electorate_revision`, `electorate_size`, `required`, `eligible_endorsements`, `ineligible_endorsements`, `accepted` |
| `RecognitionPolicyError` | `ZeroThreshold`, `InvalidFraction`, `ZeroMinimum`, `Encoding` |
| `VERSION`, `STAGE` | Crate version and lifecycle marker |

Endorsements outside the frozen electorate are reported separately rather than
counted. An empty electorate never recognizes.

## Dependencies

`p2panda-core` (0.7) for `Hash` and CBOR encoding, `serde`, `thiserror`. The
crate declares no cargo features, and every entry point is synchronous.

## Consumers

`gemot` builds a `RecognitionContext` from a folded roster
(`MootRoster::recognition_context`). Replicated storage is consumed directly
from `stickleback` by the domain crates; it is not here.

## Status

Pre-1.0. Recognition policy is implemented; domain folds stay in `gemot`.

## License

MPL-2.0 (see LICENSE).
