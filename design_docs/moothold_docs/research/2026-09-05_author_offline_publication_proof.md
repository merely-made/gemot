# Author-offline community publication proof

**Date:** 2026-09-05  
**Result:** passed as a same-machine, separate-process, live-peer rehearsal with stable-Persona signer binding and current Gemot authority on contribution and hosting commands. P1 remains partial until the publication and full hosting records have production owners and the transfer has a two-machine receipt.

The runnable proof is `crates/gemot/examples/author-offline-publication.rs`. It composes existing seams and keeps the missing publication grammar proof-local:

- Personae supplies independent roots, derived signing keys, and root attestations.
- Gemot `MootEvent::Shared` supplies an attested contribution operation that projects to the stable Persona root.
- Standing supplies an attested host commitment operation that accrues to the stable Persona root.
- Stickleback packages constitution, membership, contribution, immutable revision, and exact page as one verified NativeDrop.
- The transport crate serves that drop as one hash-scoped iroh blob to an admitted host identity and refuses an unadmitted identity.
- Muniment stores retain the accepted operations and blobs across host restart.
- Errand projects the reopened store through `Source`; `gemini-protocol` serves and fetches it over a loopback TLS socket.

## Reproduction

```powershell
$env:CARGO_TARGET_DIR='C:\Users\mark_\Code\target\moot-author-offline-proof'
cargo run -p gemot --example author-offline-publication -j 1 -- run C:\Users\mark_\Code\target\proofs\author-offline-publication-20260905-authority-b
```

The original authority proof gate passed all 132 tests in 12.52s. The subsequent current-projection parity repair raised the focused library gate to 133 passing tests in 14.11s. The final incremental example check completed in 8.01s. The executable build completed in 58.99s, followed by the same-machine proof sequence. These are build and execution receipts, not network performance measurements.

## Observed sequence

1. Author process `45884` opened its own redb stores, founded a constitution, admitted the host and author, and granted typed contribution and hosting capabilities. It signed an immutable publication revision and called Gemot's authorized contribution command through an attested derived key. It encoded constitution, membership, contribution, revision, and exact page into one NativeDrop, then served only that drop hash through a scoped iroh endpoint.
2. The unadmitted peer was unable to fetch the blob and retained no bytes. Host-import process `48644` fetched the exact NativeDrop, pinned it under a durable scoped lease, refused corrupt carrier bytes and a foreign-Moot operation, and imported one constitution operation plus one membership operation into cold stores. The authorized projection exposed the contribution under the author's stable root.
3. The host attempted an unauthorized contribution and an unauthorized hosting command. Gemot refused both before signing or storage, and the corresponding store counts remained unchanged. The admitted host then recorded its Standing commitment through the same current membership and signed-capability gate.
4. The orchestrator stopped the author and observed a successful exit at `1788589779047`. It started host-serve only afterward, at `1788589779364`.
5. Host-serve process `44016` reopened the durable ingress blob store, Moot store, and Standing store, reconstructed current authority, and rechecked the host's capability before serving the retained page through Errand's Gemini adapter.
6. Reader process `33432` received only an isolated cache path, Gemini base URL, and proof URL. It fetched `gemini://localhost:58799/garden.gmi`, received status `20`, MIME `text/gemini`, and the exact author bytes. It verified stable-root attestations, signatures, contribution and Standing operation bodies, and all cross-references. An unpublished path returned status `51`.

Author, host, and reader roots were distinct. The machine receipt is [2026-09-05_author_offline_publication.json](receipts/2026-09-05_author_offline_publication.json).

## Exact identities

| Fact | BLAKE3 or operation identity |
|---|---|
| Stable publication | `d0ee84c4f217ffa2e24344ebbc8eb7fc8ed9ece933ebc90d76640f05e3f32b45` |
| Immutable revision | `9fe6402999022bd7c92ec1fe7210d1815dc4cfbac45d3441ac5032c9528df03d` |
| Gemtext content | `262cdf6d6ff6b9cdcaab80cc72bd303d95e8fb67e576cfa3699d241d2987667e` |
| NativeDrop identity | `e95e5fd6464c47d2ff718c4b2b0ecf0244d4bea02b663be755072b8215b877bc` |
| Iroh blob hash | `8d0c83cdbd367f5f2c79399d9cfb02ce8c34d600a0aab50cf9ea28ea5f16f959` |
| Contribution operation | `9b741275abee772441299e10ca396743b33883ba81fa8f7c607284838741c792` |
| Standing operation | `9bf24777f50bb3a8f99a3420c4c2b4f2820e5c0b067272ed11f93cb7f6fd703c` |

## Design result

The useful object remains a signed immutable revision under a stable publication id, followed by a separate submission to a Moot and a separate hosting promise. The stable id derives from the author's Personae root and publication slug. An update must verify under that root; contribution and hosting do not transfer authorship. The revision binds the content reference, parent, serving path, and media type.

Contribution and Standing authoring can now use distinct protocol-derived keys while both resolve to one stable Persona root. Invalid derived-key attestations are rejected before storage. Legacy unattested contribution and Standing encodings remain byte-compatible; legacy Standing claims whose body root differs from the outer signer remain retainable but do not accrue standing.

Gemot now authorizes the two local commands from current constitution grants or live delegations, current write membership, and admission policy. Revocation therefore changes the current projection without deleting cryptographically valid remote operations. Host serving repeats the current capability check after restart.

The live transfer closes the carrier question for same-machine P1. The remaining production gaps are:

- `PublicationRevisionV1` and the full `HostingCommitmentV1` are candidate records inside the example. Their production owner, compatibility grammar, and durable governed linkage still need a ruling. The proof bundle is currently a host sidecar.
  **Corrected 2026-10-06 (S14 pass):** ownership was ruled on 2026-09-06 in the [Moot object plan](../implementation_strategy/2026-06-12_moot_object_m1_plan.md) (`724b613d`): Eidetic owns the signed immutable publication revision, and Gemot owns the full hosting promise as a Standing fact. Both types are still unimplemented outside the example; the compatibility grammar and governed linkage may still be open.
- The constitution can grant a typed hosting capability, but it does not yet own the hosting promise's audience, byte, retention, and policy-revision bounds. `FixturePolicy` still checks those proof-local fields and publication lineage.
- Current authority is reconstructed after restart. Proving authority at publication time still needs a signed constitution and membership frontier.
- Aggregate import spans several durable stores and is not yet atomic across all Gemot lanes.
- The iroh run used authenticated loopback on one machine and equated each Persona master key with its transport identity. The admitted-Persona-to-device-key adapter and a two-machine receipt remain open.
