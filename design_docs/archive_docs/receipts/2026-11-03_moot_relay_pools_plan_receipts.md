# Moot relay pools: P0-P2 receipts, 2026-11-03

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

## P2 implementation and public trial, 2026-11-03

P2 adds opt-in `mere-transport/i2p`, Murm `relay-i2p` and Gemot
`relay-pool-i2p`. It reuses Truchman 0.1.1, the shared Noise/setup gate,
Notochord admission and the native forwarding budget/pump. Retinue's identity
defaults, p2panda-spaces adoption and group-key orchestration are unchanged.
The accepting SAM adapter reports no carrier-authenticated Personae subject.
The client verifies the pool signature and an independently trusted target ID
and recipient key; pool signing authority cannot replace that recipient.

### Recorded checks

| Gate | Result | Qualification boundary |
|---|---|---|
| Gemot full opt-in library suite, local supplier overlay | 122 passed, 2 ignored | Includes all P1 controls and three scripted P2 tests; public gates are separate |
| Gemot full opt-in library suite, published Murm pin | 122 passed, 2 ignored; 98.80 s | No path overlay; includes independent target/recipient pin checks |
| Gemot final focused I2P controls, `--frozen` | 3 passed, 2 ignored; 5.72 s and 5.36 s | After refining the public lifecycle probe; no new supplier resolution |
| Murm + murm-sync library suites with `murm/relay-i2p` | 75 + 13 passed | Native workspace's locked dependency graph |
| mere-transport library suite with `i2p,noise,notochord,test-identity` | 99 passed, 1 ignored | Includes canonical locator/hop refusal, session poisoning and fresh-alias controls; ignored item is the existing killed-peer child helper |
| Murm opt-in Clippy | Exit 0, warnings retained | Existing/general documentation/style warnings; not a warning-free claim |
| Public two-worker pool, `p2-public-05.txt` | Passed, 153.99 s | Emissary 0.4.0 client/recipient router and distinct i2pd 3.0.0 worker router on this Windows host |
| Public two-worker pool, final supplier pin, `p2-public-06.txt` | Passed, 129.94 s | Published Murm pin, independent recipient trust, same explicit provider/tunnel profile |
| Public provider termination/restart, `p2-provider-lifecycle-03.txt` | Passed, 182.72 s | Real i2pd termination; local stream/session refusal, fresh alias and carrier byte exchange after restart; authenticated relay payloads are covered separately above |

The public two-worker run creates four SAM sessions. Each selects two inbound
and two outbound hops, zero variance and two tunnels per direction. Client
LeaseSet publication is disabled; worker and recipient publication is enabled.
Both router providers have transit and router-address publication disabled.
The client and worker bridges are distinct, preventing a same-router shortcut
between local Destinations on either relay leg. Physical machines/uplinks are
not independent in this test.

The passing public run checked byte-exact inner-Noise payloads through both
workers, unrelated requester refusal, wrong worker and recipient keys, an
established stream failing when its worker stops, a new connection through the
other worker under the same pool, and observed withdrawal cancelling active
work/refusing new work. Worker/recipient task owners await cancellation and
check zero remaining reservations. Setup refusals expose only sanitized stage
facts, never SAM messages, private keys or direct locators.

Public offers use canonical I2P locators and contain no contributor ancestry,
private topic, operator roster, native ticket, URL or direct-address fallback.
The scripted controls additionally reject those foreign fields, a valid pool
signer's recipient substitution, stale/altered signatures and cached offers
whose receiver-local monotonic deadline has passed. A carrier-identity-required
rule refuses SAM even after Noise succeeds.

### Failed/superseded P2 attempts

- `p2-public-01.txt` and `p2-public-03.txt` stopped at Cargo's shared cache lock;
  neither is a network acceptance attempt or passing result.
- `p2-public-02.txt`: failed creating the first Emissary session at a 60-second
  endpoint-creation allowance, before relay traffic. The host creation bound
  was raised to 300 seconds, leaving tunnel lengths/security unchanged.
- `p2-public-04.txt`: all sessions and three route probes became ready, then
  secure setup failed before payload transfer. The accept loop was cancelling
  an in-flight SAM ACCEPT whenever another task completed. Keeping that command
  pinned across task reaping made the subsequent public run pass.
- The first scripted fixture reused native policy's carrier-identity
  requirement. SAM correctly could not satisfy it. The I2P fixture explicitly
  requires Noise/secure admission while leaving raw carrier authentication
  absent; a separate negative control preserves the stricter refusal.
- Immediate post-abort reservation checks raced child-task cancellation.
  Explicit shutdown now waits for the owned JoinSet before asserting release.
- The first provider lifecycle fixture failed route readiness before any
  provider stop. Its replacement separates a fixed, idempotent carrier probe
  from the other gate's authenticated relay/application payloads.
- `p2-provider-lifecycle-02.txt`: local stream termination and old-session
  refusal passed after stopping i2pd. Replacement-session creation then hit
  its 180-second total bound while each individual attempt allowed only three
  seconds. A direct TCP probe confirmed SAM was reachable; Windows' socket
  inventory had misleadingly omitted its loopback listener. The next fixture
  permits 60 seconds per creation attempt without extending the total bound.

### Provider and source facts

i2pd prints `3.0.0 (0.9.71)`, Boost 1.92.0 and OpenSSL 3.6.5. The reused binary
SHA-256 is `6f501e1f4625ad5f3f1075e2fd4f4096aaf664386b04c526cee9b05a7301c2a2`.
Its Windows GUI refuses a second instance even with a separate data directory;
the [named source check](https://github.com/PurpleI2P/i2pd/blob/3.0.0/Win32/Win32App.cpp)
checks for the existing application window. The unused second process was
stopped. Emissary uses the existing `murm-i2p` provider, including its retained
debug-assertion mitigation. Its SAM implementation consumes the requested
nonzero hop/count settings; it does not establish a raw carrier Persona.

Murm implementation is committed at
`5b45742f87ecbd67ffbca814f8e1945e33cb55a0`. The receiving pin/lock and final
qualification follow below. The temporary P2 Cargo overlay is retained as
`Code/testing/gemot/moot-relay-pools/p2-local-suppliers.toml`; final delivered
builds must not depend on it. The two source-owner workspace graphs differ:
Murm's native lock selects iroh 1.4.1/Dramatis `6aa0daa4`, while Gemot retains
its existing iroh 1.0.3/Dramatis `e26b434a` cohort. No broad repin is implied.

The published-pin receiving command was `cargo test -p gemot --lib --features
relay-pool-i2p -- --test-threads=1`, run at the Gemot root with
`CARGO_TARGET_DIR=C:\t\cargo-targets\gemot`,
`CARGO_BUILD_BUILD_DIR=C:\t\cargo-targets\gemot\build` and
`CARGO_BUILD_JOBS=1`. All five Murm-family source entries in the receiving lock
(transport, Murm, sync, Retinue and Truchman) resolve to `5b45742f87ecbd67ffbca814f8e1945e33cb55a0`.

Gemot implementation and receiving lock are committed/pushed at
`10658f6227e2b08ca9f4ec0cc6670039acba6c8b`. Its line-ceiling and configured
`cargo clippy --locked --all-targets` commit checks passed. Murm's ownership
crosslinks are committed/pushed at `9733d3e93dbe6aa08fba3d42b3acce6712aa55af`.
The embedded `sam_provider.exe` SHA-256 is
`130596c2040adada836a4bb4f2df211d613a8091020277f848d19544a1fd0491`.

The public repeat ran the receiving test artifact directly, selecting
`moot::relay::tests::i2p::live::public_i2p_two_workers_on_distinct_routers`
with `--exact --ignored --nocapture --test-threads=1`. Environment variables
`MURM_RELAY_I2P_CLIENT_SAM` and `MURM_RELAY_I2P_WORKER_SAM` name the explicit
loopback bridges. The source equivalent is the receiving Cargo command above
with that test filter and `-- --ignored --nocapture --test-threads=1`.

The lifecycle gate selects
`moot::relay::tests::i2p::live::public_provider_termination_closes_local_streams_and_restart_changes_alias`
with the same runner flags and `MURM_RELAY_PROVIDER_RESTART=external-control`.
Its owner stops only its named i2pd process at `MURM_POOL_PROVIDER_STOP_READY`,
then starts the same binary/configuration/data directory at
`MURM_POOL_PROVIDER_RESTART_READY`. The gate checked local stream failure,
refused use of the old session, a different transient alias and byte-exact
carrier traffic after reopening. Its fixed retry probe carries only the
idempotent `lifecycle` diagnostic. The other public gate supplies the
independently authenticated relay-payload proof. The refreshed Emissary helper
reported stored bootstrap state and ended with `Exited` on its stop marker.

### Privacy boundary

This qualification is for the named I2P service path and providers. Public
Moot membership/capability records can still identify authorized operator
candidates; service offers do not include private contributor lineage.
Pool identities, repeated service keys and Destinations remain linkable. Direct
operator control links retain their existing metadata exposure. Independent
machines/networks, global traffic correlation, public exit/proxy use and
unattended product deployment remain outside these receipts.

The plan allocates 20 MB to P2. At the pre-cleanup measurement, all task-local
runtime/configuration/compact outputs together occupy 3,486,767 bytes. Private
router identity/runtime files remain local, outside the source receipt; no
SAM private-key response, raw packet capture or user payload is published.

Final cleanup, 2026-11-03 21:08:44 -05:00: task-owned Emissary stopped through
its control marker, and task-owned i2pd stopped. Process inventory found no
remaining i2pd, `sam_provider` or public Gemot I2P test process. Fixture owners
also checked zero active/pending relay reservations. Shared Cargo targets were
reused; no isolated target, Cargo home or worktree was introduced. Concurrent
Murm wire-lane changes remain untouched.

The final task-local retained size is **4,632,367 bytes** across configuration,
private runtime state and compact successful/failed outputs, within P2's 20 MB
allocation and the plan's 100 MB total cap. Owner: `moot-relay-pools-p2`.
Private router state under `Code/testing/gemot/moot-relay-pools/` remains local
for reproducing this named-provider qualification; it is not published with
the source receipt. P2 is qualified at this exact scope. P3 independent
machines/networks and unattended product deployment remain open.
