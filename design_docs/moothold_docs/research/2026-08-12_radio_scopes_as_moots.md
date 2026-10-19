# Radio Scopes Are Moots

Research note, 2026-08-12. Ratified by Mark the same day. The first ratified
consumer of the
[boundary, identity, and grant composition](2026-08-09_boundary_identity_and_grant_composition.md)
model outside mere itself: retinue's civic-deployment **scopes** (the
policy groups a radio node may defer to: a county, a trail-stewards
community, a radio club) are moots. The radio-tier counterpart carrying the
deployment design is retinue's
[civic deployment doc](https://github.com/merely-made/murm/blob/main/design_docs/2026-08-11_civic_deployment_prescribed_paths.md).

## The split

Governance lives here; the radio tier consumes an artifact.

- **Host side (`gemot`, not `moothold`):** the scope is an ordinary moot. Its constitution
  governs the settings it publishes; authority rosters (who may sign county
  alerts) are grants under that constitution, attributed and revertible;
  enrollment, revocation, and succession are petitions, never key-custody
  ceremonies. The unvotable floor (founding key, constitution location)
  stays a paragraph a person can read, per the composition doc.
- **Radio side (retinue):** a board holds only the moot's **published
  policy artifact**: a small signed record of governed settings, the
  authority roster, and a revision mark, verifiable cold by the mechanical
  half of the validity relation. Boards never petition, vote, or hold
  governing secrets ("smart enough to verify, too poor to authorize", the
  field-node posture). Scope membership belongs to the owner's persona in
  signalman, never to the relay keypair on the pole.

## What the model buys the radio tier

- **Miscible scopes for free.** A persona is a participant of many moots;
  overlapping community membership needs no new mechanism. Composition of
  overlapping policies is per domain on the radio side (duties union under
  the owner's ceiling, divisible dwell fractions, exclusive knobs by owner
  order), and stays the owner's call by construction.
- **Honored-here-now covers partition.** Two nodes honoring different
  policy revisions at hour-scale propagation are both correct; this doc's
  open partition merge rule is now a named dependency of retinue's CV4
  (scope-deferred settings) and should be decided here, consumed there.
- **Suzerainty is consent-for-carriage.** Containment cannot imply
  authority: a county moot placing itself above a community moot gains no
  power over member nodes. Carriage is a granted duty, never absorbed.
- **Cast economics is the corroboration sybil answer.** Retinue's
  corroboration primitive (countersign + carry + pin + serve; reach and
  persistence, never validity) meters amplification weight by persona
  reputation and tessera stake: pseudonyms spend, personas earn, ten
  pseudonyms amplify nothing. Each scope's masking policy (a governed moot
  setting) decides what identity resolution corroboration requires there.

## What the radio tier hands back

- **Corroboration is the pinning layer wearing a signature.** The
  cost-metered-refusal law's pinning surface, exercised on someone else's
  message, with the vouch attached. Unifying the corroboration envelope
  with the petition/pin wire shapes is now the default design, not a
  speculation; the remaining work is the format spec (and retinue's R4
  formats must not preclude it).
- **A clean instance of emergence versus declaration.** An island is a
  measured airtime shadow; a scope is a chosen membership; a node has one
  island and many scopes. RF reach must never confer scope membership and
  scope membership must never assert RF reach, which is this doc's
  cross-cutting law with a radio accent ("antenna reach defining moot
  membership" was already named here as the failure mode).
- **A deanonymization consumer.** Several personae active across
  overlapping scopes deanonymize by intersection (cast section); since
  scope membership is host-side, signalman owes the owner a warning when
  they join overlapping scopes under linked personae.

**Crate-location correction, 2026-08-12 (code audit).** The constitution and
tessera modules live in **`crates/moot/gemot/`**
(`src/moot/constitution/`, `src/moot/tessera/`), not in `moothold`, which is
federation only and merely imports gemot's tessera `Ledger`. `DOC_README`
asserts otherwise and is wrong; work started from the index writes into the
wrong crate.

## Open here, consumed there

Three findings from the same audit reshape this list. They are rulings for
Mark to write, not streams to code, and they are **post-deadline** per
retinue's [program sequencing](https://github.com/merely-made/murm/blob/main/design_docs/2026-08-12_program_sequencing_and_deadline_order.md).

- **The partition merge rule is unreachable, not undecided.**
  `ConstitutionStore::accept` returns `StaleRevision` *before* the operation
  is inserted (`store.rs:218-221`) and it is the sole ingestion path:
  p2panda-store 0.7's `LogStore` is read/prune-only and stickleback's impl
  exposes no write, so LogSync cannot persist behind `accept`. Two partitions
  permanently refuse each other's operations and `fold.rs`'s hash tie-break
  can never run in a real deployment. **The retention gate must change first;
  the merge rule is downstream of that.**
- **Revision is a content digest, not an ordinal**, so a cold board cannot
  order two artifacts it holds. A monotonic ordinal alongside the digest is
  the second ruling.
- **The artifact is not blocked on size.** A minimal record is roughly 200
  bytes plus 32 per member against an `ENCRYPTED_MDU` of 383, and
  `ConstitutionRules` is already canonically CBOR-encoded with a blake3
  digest and an encoding-stability test. The real blockers are that no
  standalone attestation of *which revision is accepted* exists (that fact is
  only the output of folding the whole chain), and that retinue carries
  neither blake3 nor CBOR, so a `no_std` verifier crate is unavoidable. The
  digest/codec boundary is the third ruling.
- Whether corroboration stake draws tessera specifically or a
  reputation-adjacent balance; interacts with the bounty economy plan's
  verification economics.
- **M1's two-machine run gates none of this.** `moot-peer` joins exactly one
  lane (`gemot/records/v1`, declare/join/share and roster convergence) and
  never touches the constitution, delegation, membership, or tessera lanes.
