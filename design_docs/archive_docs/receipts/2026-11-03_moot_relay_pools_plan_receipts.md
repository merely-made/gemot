# Moot relay pools: P0/P1 receipts, 2026-11-03

Canonical plan: [Moot relay pools](../../moothold_docs/implementation_strategy/2026-11-03_moot_relay_pools_plan.md).

## Scope and supplier comparison

P0 inspected the already pinned p2panda checkout `1f69c9bc`, tag
`mere-p2panda-net-0.7.5-upstream-20261013`, including `p2panda-spaces` 0.7.1
Manager, storage traits, state serialization and Cargo features. The plan's
comparison table records the API verdict. Spaces supplies nested groups,
device membership and decentralized key orchestration. Current MunimentStore
lacks its five required store adapters and transaction composition; Spaces
unconditionally selects SQLite/spaces store features. Persistence/history and
offline-revocation parity remain behavioral gates. Spaces was not adopted.

P1 retains Moot authority, scoped Personae keys, Stickleback GroupSession and
DataKeyring, shared causal admission/projection and host-owned Murm endpoints.
It adds typed relay records, disposable liveness, signed native client offers,
upstream peer/topic sync hooks and a bounded admitted application stream pump.
It adds no group manager, key manager, endpoint owner or replication engine.

## Qualification ledger

All native runs use Rust 1.99.1 on this Windows host, one Cargo job and one test
thread. Both `CARGO_TARGET_DIR` and `CARGO_BUILD_BUILD_DIR` point under the
stable `C:\t\cargo-targets\gemot` or `C:\t\cargo-targets\murm` tree.

| Gate | Result | Boundary |
|---|---|---|
| Unchanged Gemot `cargo test -p gemot --lib --locked --offline --quiet` | 102 passed | Existing library baseline |
| Initial control-lane test slice | 6 passed | Earlier source, superseded by final gate |
| Murm `cargo test -p murm -p murm-sync --lib --features murm/relay --frozen -- --test-threads=1` | 75 + 13 passed | Isolated supplier source; includes 6 relay limit/cancellation tests |
| Final Gemot `cargo test -p gemot --features relay-pool-native --lib -- --test-threads=1` | 119 passed | Exact published Murm pin, without local override; 87.24 seconds test execution |
| Gemot `cargo metadata --frozen --no-deps --format-version 1` | Passed | Confirms all three manifest edges at the published revision; optional native dependencies remain opt-in |
| Repository commit checks | Passed | Line ceiling and configured Clippy: Gemot default all-targets and Murm radio workspace; opt-in native behavior is covered by the library gates above |

The local supplier overlay was a three-package Cargo patch in
`Code/testing/gemot/moot-relay-pools/local-suppliers.toml`. It is qualification
scaffolding only. The delivered Cargo manifest/lock uses immutable Git
identities, without a worktree path override.

## Source and receiving identities

- Gemot implementation:
  `6a076e294c942beb83f96b798f7c2e4c14e5d66c`. This code and lock are the final
  receiving source tested above; this ledger and the plan/index follow in a
  documentation-only commit.
- Murm implementation on `main`:
  `5710d5e11ffde49af3952bc6d1c180286b2f0e1b`. Its native Murm and murm-sync
  source trees are identical to the tested isolated commit `fdf73998ef7`.
  The documentation index follows at `87906e04174`. Both are published.
- Gemot's three Murm workspace edges (`murm`, `murm-sync`, `transport`) use
  that exact implementation revision. The transitive Retinue source resolves
  there as well. The receiving suite runs without the local patch config.
- The Dramatis lock moves from `dc593a34` to
  `e26b434a1011b2ff509d0d6a1553cbbb03902669`, providing the reused secure v2
  Notochord session APIs absent at the older lock revision. Identity, Insigne
  and Notochord retain one supplier revision; this introduces no key manager.
- Eidetic remains `7a3453a02bc7dea391ef18814c1bfa1a46e67160`; p2panda remains
  `1f69c9bcb9f2a9d798b1c25b2ec2f47c0416bd65`. Neither migration is broadened.
- The new registry packages are the existing Noise implementation `snow`
  0.10.0 and its `blake2` 0.10.6 dependency. The lock also resolves existing
  tempfile's allowed getrandom edge to already-present 0.4.3; its package
  version is unchanged.

The private-record controls cover independent owners and multiple devices of
one persona, reorder/duplicate convergence, concurrent terminal withdrawal,
causal gaps, wrong author/scope/authority/ciphertext, capability separation,
group epoch changes, signed-offer tampering, replay-resistant liveness, reader
authorization, revoked membership, fixed authority-checkpoint expiry and real
Redb cold reopen without restored availability.

The in-process native fixture uses real iroh/QUIC endpoints, encrypted
JoinedSpace/LogSync coordination, Notochord admission and an independent inner
Noise session. It covers byte-exact forwarding through each worker, a wrong
recipient key, unauthorized requester, a pool grant tighter than local device
slots, failed-worker removal, new-connection failover, live withdrawal and
zero final pending/active reservations after session/task/socket teardown.

The separate-process fixture runs worker A, worker B and the recipient in
distinct child processes. The parent verifies actual Moot authority and sends
bounded grants through private test IPC. It kills A abruptly, requires an
actual read error within the carrier detection bound, rechecks B's authority,
transfers the same fixture on a fresh stream and tests observed withdrawal.
The child-role helper is inert without its explicit fixture environment.
This process test does not claim distributed group custody or network control
sync; the sibling fixture qualifies the latter.

The bounded pump tests use small duplex streams to exercise bidirectional
cumulative bytes, shared device slots/bytes/rate across pool reservations,
slow-reader backpressure, expiry, cancellation and zero contribution. The pump
has two fixed buffers, no application write replay and no payload persistence.
Fixed one-second rate windows allow bursts at their boundaries.

## Failed and superseded attempts

- An early primary-checkout Murm invocation selected zero relay tests after a
  concurrent source update removed the feature wiring. It is not a pass. The
  actual collision justified the isolated Murm worktree.
- The first local-supplier native run passed 10 tests and failed both native
  fixtures at route setup. Routing messages incorrectly bypassed the frame
  format retained by the secure setup gate. They now use existing bounded
  Notochord frame helpers before the gate lifts.
- A later run passed 14 tests and failed abrupt process-loss detection at an
  assumed two seconds. UDP process death sends no close frame. The fixture now
  requires a real error within the carrier's 30-second idle detector plus
  scheduling slack (40 seconds), then refreshes the survivor's bounded grant.
  A timeout remains a failure. The corrected earlier source passed 15 tests.
- Adding a fixed authority-checkpoint deadline exposed one missing field in
  the durable fixture during compilation. Both fixtures now supply it.
- The first commit hook inherited no target override and started a wider
  radio-workspace Clippy check. That task-owned run was stopped, then restarted
  with both stable target settings and one job. It is not a relay test receipt.

## Privacy and deployment limits

P1 is explicitly native and host-visible. Operator control bodies are
encrypted and read-authorized at sync establishment; authenticated operators
still see their peers and sync metadata. Existing public Moot membership and
capability evidence can narrow the operator set. Already obtained history or
keys cannot be recalled; hosts rotate group access/private topics and leave
old sessions on departure. Active forwarding is reauthorized and expires at
the intersected authority, availability and contribution deadlines.

The workers possess no inner requester/recipient payload keys. This test does
not qualify traffic-analysis resistance, independent networks, physical
devices, deployed unattended operation, public proxy/exit service or a product
resident accept loop. P2 I2P qualification remains required, including exact
provider/tunnels, nonzero hops, both legs, service/target authentication,
public-authority linkage, offers/diagnostics/persistence and refusal without
direct fallback. P1 cannot sign a client offer claiming a hidden native host.

## Retained evidence and cleanup

The plan allows 100 MB overall and 10 MB for P1. This compact ledger and source
tests are the retained evidence; no payload/packet captures or full compiler
logs are needed. The compact receipt is below 10 KB and the archived local
patch recipe is 348 bytes, well below the P1 cap. Source tests contain the
fixtures; no operator credentials, live group-key material or traffic capture
is stored in this receipt.

The isolated Murm worktree was integrated by verified native source-tree
equality, then removed with `git worktree remove`; its task branch was removed.
That also removed the stopped hook's marker-identified generated target.
No task-owned isolated target, Cargo home, worktree, endpoint or child process
is retained. Stable shared Cargo targets remain under their repository owners.
