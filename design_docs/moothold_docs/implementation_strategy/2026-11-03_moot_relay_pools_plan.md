# Moot relay pools

**Status, 2026-11-04: P0/P1 complete; P2 qualified; P3a software implemented, deployment gates open.**
P2's host-location privacy gate passes for Emissary 0.4.0 and i2pd 3.0.0 with
explicit two-hop tunnels on this Windows host. Independent machines/networks,
product deployment and the Spaces migration remain separate.
Exact receiving pins and qualification are recorded in the
[P0-P2 receipt](../../archive_docs/receipts/2026-11-03_moot_relay_pools_plan_receipts.md).

## Purpose and agreed direction

A moot may operate a relay pool as a shared service. Its members contribute
connectivity because it keeps their community reachable. One member may offer
an uplink, another a radio route, another intermittent capacity. The service
can persist as its contributing devices change.

Mark's direction in the founding discussion:

> "moots could serve as a relay pool"

> "it's basically a public face of a mesh (multiple identities, potentially
> multiple devices), which compares nicely to the personal mesh (one or few
> identities, a few devices)"

> "A community makes relaying and working together worth it!"

These are descriptions of participation, not identity-count requirements.
People/personae, devices, the moot and the relay service have separate
identities. A member may contribute several devices or none. Membership does
not commit bandwidth, battery, storage or transit. Each contribution requires
bounded, revocable owner consent. The service audience may be members, named
partner moots or the public; discoverability and permission to use it are
separate settings.

The first service forwards live, opaque application streams to registered
targets. Ordinary iroh relay servers, TURN servers, message propagation and
content hosting have different protocols and obligations. Reusing their
engines does not make this service automatically speak those protocols.

## Existing plans this consumes

- [Moot publication](2026-11-01_moot_publication_plan.md): community authority,
  bounded volunteer hosting and authority cuts. Content retention and relay
  carriage remain separate promises.
- [Radio scopes as moots](../research/2026-08-12_radio_scopes_as_moots.md) and
  [identity and grant composition](../research/2026-08-09_boundary_identity_and_grant_composition.md):
  consent for carriage, independent personae and explicit recognition.
- `murm/design_docs/2026-10-28_transport_consolidation_plan.md`, T6 and T7:
  shared service setup/admission and the new home of live sync sessions.
- `murm/design_docs/2026-11-02_i2p_sam_seam_plan.md`: existing STREAM carriage,
  provider controls, unresolved identity policy and qualified router scopes.
- `mere/design_docs/mere_docs/implementation_strategy/2026-10-29_stack_reduction_plan.md`
  and its `../research/2026-10-29_stack_ownership_audit/network.md` dossier:
  R25 evaluates p2panda-spaces; R26 evaluates generic causal processing.
  Relay pools are a concrete consumer for those comparisons, rather than a
  reason to build another group, key, storage or networking engine.

## Ownership and reuse

| Owner | Reuse | New work for the pool |
|---|---|---|
| Gemot | Moot constitution, membership, Personae delegations, current authorization and signed authority cuts | Pool service policy, contribution/withdrawal grammar, permitted audiences and target registrations |
| Dramatis | Scoped Personae keys, custody, revocation and Notochord session admission | Explicit grants for contributing and using the relay service; no new membership credential |
| Eidetic / Stickleback | Verified operations, causal admission before insertion, group encryption, epochs, Muniment storage and replay | Small typed pool records and projections through existing mechanisms |
| Murm / murm-sync | Injected endpoint ownership, JoinedSpace, group-key sync, address books and session shutdown | Join/publish the pool's authorized coordination space without another endpoint or sync loop |
| Murm / mere-transport | Transport streams, carrier facts, secure setup gate, Noise and existing iroh connections | Bounded opaque stream forwarding, route selection and per-device enforcement |
| Murm I2P family | Truchman SAM STREAM, optional embedded Emissary, external-router alternative, Retinue I2P interface | A qualified anonymous-access stream adapter and honest I2P ingress facts |
| Product or resident host | Process lifetime, settings, approved custody and device ownership | Start/stop the pool service and expose availability and refusal facts |

Gemot defines authority; the contributing host enforces its own ceilings.
Effective per-flow limits intersect community policy, the contribution grant,
the client's grant and local ceilings. Reservations also charge shared device
limits across every pool using that device. Overlapping moots cannot multiply
the same bandwidth or pending-session allowance.

Notochord's current session admission and anonymous Reticulum transit are
separate policy axes. A pool grant does not enable public I2P transit,
Reticulum routing, a TURN allocation service or unrestricted Internet egress.

### Where p2panda fits

Use signed operations and deterministic materialization for durable policy,
contribution authority, withdrawals and target registration. Use existing
group encryption for restricted coordination. Keep the current operation
identity, author chains and causal references; pool/application commitments
belong in typed bodies or projections, not a replacement operation header.

Before growing key orchestration, compare the pinned supplier's
[p2panda-spaces Manager](https://github.com/mark-ik/p2panda/blob/mere-p2panda-net-0.7.5-upstream-20261013/p2panda-spaces/README.md)
with current Gemot/Commons/Stickleback mechanisms. It combines auth groups,
encryption contexts, nested device groups and private space identifiers. Its
API is unstable and requires signed, verified, causally ordered messages.
This is R25's comparison, not an already-adopted dependency or a replacement
for the Moot constitution, contribution consent or local resource limits.

The deciding comparison must preserve concurrent add/remove, independent
device delegation, departure rotation, offline revoked-writer catch-up,
withheld epochs, crash/reopen, scoped writers, namespace separation and
Muniment-backed storage. Retained control records and disposable live traffic
need explicit encryption/history profiles. Do not change durable-data history
into forward-secure history as an incidental library choice.

P1 consumes a narrow authorized-record/group interface over the current
mechanisms. Record which generic orchestration can be delegated to Spaces;
adopt only after the comparison passes, without a second bespoke key manager.
R26's broader high-level runtime comparison remains independent: neither
SQLite nor another actor lifecycle becomes a relay prerequisite.

Live capacity, liveness and queue occupancy are expiring observations. They
need not become an append-only operation for every heartbeat. Forwarded bytes
never enter LogSync, the Moot public record, Standing or a content store.
Persistence may restore consent and configuration; a fresh availability probe
is required before a restarted host advertises capacity.

## Service and coordination model

P1 implements the following contracts behind opt-in owner features. Their
versioned identifiers are local application protocols, not upstream relay APIs:

| Record/view | Meaning and audience |
|---|---|
| Pool policy | Stable pool ID, service verification key, accepted Moot authority revision, required security/privacy profile, use audience, targets and bounds |
| Contribution | Owner-authorized device/service key, capabilities, validity, resource ceilings and the authority evidence used to accept it; restricted to its coordination audience |
| Target registration | A permitted application service and expected recipient key; the relay resolves an authorized route rather than accepting an arbitrary host, URL or port |
| Live offer | Contribution reference, local generation, measured availability and bounded lease; a routing hint that confers no authority |
| Client offer | A deliberately disclosed service alias, profile and expiring locator, authenticated by the pool's delegated service authority; contains no internal roster or direct address in the hidden profile |

The public service identity is distinct from the owner root, member identities,
device keys and transport endpoints. Scoped device keys receive explicit
authority to advertise service offers. Pool root secrets stay in custody;
they are not copied to every worker. A stable pool identity can authenticate
several service aliases without assuming shared I2P Destination private keys.

Keep operator coordination separate from ordinary member content and public
records. The seven current Moot lanes do not automatically form an
operator-private space. Select the smallest existing authorized/encrypted
record boundary that meets that audience; any new domain lane needs an
explicit owner and lane ID through the existing lane machinery.

An offer becomes usable only after current known authority, profile, target,
capacity and freshness checks pass. Replay cannot extend its lease. Use an
issuer generation and bounded receiver-local monotonic lifetime, together with
the signed validity limits and explicit clock policy. Reopen and excessive
clock uncertainty require fresh liveness rather than resurrecting an old offer.
Routing is a derived view of accepted offers, never the source of membership.

The client selects a compatible worker for each new connection. Pin the stream
to that worker. Worker loss ends that stream with an explicit failure; a new
connection may use another worker. Automatic replay of application writes,
live stream migration and packet striping require separate semantics.

## Privacy boundaries

Encryption, membership disclosure, host-location privacy and resistance to
traffic analysis are separate claims. Record the selected profile and its
limits in every acceptance result.

| Observer | Intended boundary |
|---|---|
| Unauthorized client | Cannot use restricted targets, join coordination, enumerate the operator roster or obtain its private records |
| Authorized ordinary member/client | Sees the service offer and permitted target identifiers; operator/device disclosure follows explicit policy rather than general membership |
| Relay worker/operator | Can observe forwarding metadata and the next route, but receives no sender-to-recipient payload key |
| Registered recipient | Receives the worker's admitted application subject and delegation proof on the outer leg; anonymity of operator identity from that recipient is unqualified |
| Pool administrator | Can administer policy; that role alone grants neither payload decryption nor root-key export |
| Immediate carrier peer / network observer | May observe IP/RF participation, timing and volume; a direct connection exposes its network address |
| Observer correlating both ends | Outside the anonymous-access acceptance claim; encryption and I2P do not establish protection against all traffic correlation |

An outer iroh, Noise or I2P connection may terminate at a relay. Maintain an
independent authenticated sender-to-recipient encrypted session across the
forwarded stream. Existing Noise is reusable here because this service changes
the connection endpoints. Ordinary iroh relaying already protects its payloads;
extra Noise is not required merely to hide an iroh payload from an iroh relay.

Encrypted p2panda bodies do not conceal every signer, operation size, topic,
relationship or synchronization event. Never expose the private coordination
log as a public directory. A sanitized client offer has separate scoped
signing material and disclosure rules. Private space IDs do not turn a direct
network connection into an anonymous connection.

A community-branded service deliberately identifies its sponsoring Moot.
Existing public membership can narrow the possible operator set even when
device-to-service mappings remain private. A less linkable service face needs
its own explicit publication policy. Public service verification must stop at
the pool key; client offers carry no contributor-root attestations or private
delegation ancestry. The recipient's admission exchange has the distinct
identity disclosure described above.

For the hidden profile, client-facing locators are I2P service destinations;
all advertised client and target legs must satisfy the selected privacy
contract. Failure refuses or waits according to policy. It never silently
retries a direct iroh endpoint, direct IP, WebRTC candidate or radio announce.
Protect discovery, diagnostics, errors, persisted tickets and key attestations
as well as the successful data path. Revealing a service key's ancestry or
publishing its direct address elsewhere can defeat the intended separation.

Clients can recognize the sponsoring pool and link repeated use of a service
key or Destination. Alias rotation belongs to the host's explicit identity
policy; cross-session unlinkability remains outside P2.

I2P hides the association between a service Destination and its hosting router;
it does not make all participating routers invisible. Enabling Emissary
transit is a separate contribution to the I2P network. I2P multihoming exists,
but shared-key publication, provider behavior, load distribution and key custody
require qualification before using it for the pool's stable public identity.

The initial control plane may use private, authenticated iroh links between
operators. Its endpoints and synchronization metadata remain visible to those
peers and their network observers. P2 must state that exposure explicitly; it
must not claim that all pool participation or control traffic is hidden.

Multiple devices on one uplink share its capacity, outage and observation
boundary. Distinct moots can share operators, so a different Moot ID is not
evidence of an independent anonymity hop. Route diversity requires observed
ownership/network information with its own disclosure policy.

## Phases and done-conditions

### P0. Pin the reuse and authority boundary

**Completed source comparison, 2026-11-03.** The supplier inspected is
`mark-ik/p2panda` at `1f69c9bc`, the already-selected tag. No new group/key
engine or Spaces dependency is introduced for P1.

| Requirement | Spaces API/mechanism | P1 decision |
|---|---|---|
| Nested community/member/device groups | `manager::Manager`, `group::Group`, p2panda-auth integration | Good generic fit; Gemot keeps its existing `MootGroup` and independently scoped device attestations |
| Decentralized key agreement and departure changes | `space::Space`, identity/pre-key management and encryption membership integration | Reuse current Stickleback `GroupSession` and host-injected `DataKeyring`; no relay-owned key manager |
| Restricted coordination identifiers | Spaces IDs, encrypted application/control messages | Dedicated typed encrypted pool lane through existing Stickleback admission and Murm `JoinedSpace`; no public log/directory |
| Causal verified operations | Manager requires callers to order and verify; it does not replace that caller obligation | Use shared `CausalEntry`, frontier/projection helpers and `OperationProcessor` |
| Persistence and reopen | Manager is generic over `SpacesStore`, `SpacesMessageStore`, `GroupsStore`, `KeyRegistryStore`, `KeySecretsStore` and `Transaction` | Those adapters are not implemented by current MunimentStore; preserve existing encrypted GroupSession custody |
| Dependency/target footprint | Spaces 0.7.1 explicitly enables p2panda-store `sqlite` and `spaces` in its Cargo manifest | Not a drop-in fit for the current non-SQLite boundary; adapter and feature split are an R25 follow-up |
| Moot authority and bounded consent | No constitution, device-resource ceiling or relay-target authorization | Gemot supplies these domain rules; Murm enforces admitted forwarding |
| Stable data history and export | `SpacesStoreState` serialization has upstream versioning TODOs; transport/history profile parity is not established | Keep existing durable-data epochs and replay formats; do not infer a migration pass |

This is a source/API fit verdict, not a behavioral qualification of Spaces.
Its nested-group and generic key orchestration remain a promising reduction.
The adoption checkpoint is a narrow Muniment store/feature adapter plus the
existing concurrent membership, rotation, offline catch-up and reopen controls.
P1 only adds typed relay facts, current authority checks, leases and forwarding.

Re-read the current sources, T7 receiving cohort, R25/R26 comparison and the
Moot publication plan. Inventory pool-required operations against existing
group/session/encryption APIs. Specify typed policy, contribution, withdrawal,
target and client-offer records, including who may read and author each.
Reserve a service profile only after checking existing identifiers.

**Done when:** every required behavior has an existing owner/API or a named
small addition; the Spaces comparison records fit, gaps and adoption status;
authority and encryption/history profiles are explicit; no second endpoint,
replication loop, key manager or broad dependency repin is introduced.
An unresolved upstream comparison must not be presented as completed adoption.

### P1. First implementation slice: two native volunteer relays

Use one Moot, two independently owned contributor identities, one worker per
contributor, one authorized requester and one registered recipient service.
These are logical roles; the first fixture may run separate native processes
on one machine. Keep the runtime under existing Murm native service ownership
and pool authority/records under Gemot. Add modules behind the owning feature
boundaries before considering another crate or daemon.

The operator opts in with configurable session, byte, rate, queue, pending
setup, lease and lifetime limits. Zero contribution disables offers. Feed
authorized contributions into an encrypted coordination space over
host-injected murm-sync sessions. P1 may use private iroh for this plane.

Implement an admitted application stream relay over existing Murm streams.
Reuse the secure setup gate before connecting and retain its permit through
admission on each hop. The requester names an approved target, not an arbitrary
network destination. The final recipient authenticates the requester through
the inner encrypted session. Relay-use authority grants no target application
privilege. Keep this separate from implementing the iroh relay or TURN wire
protocol.

**Done when all controls pass:**

1. Both contributors can independently offer capacity under the same pool ID;
   an unrelated Moot/member or undelegated device cannot contribute or use a
   restricted target. Missing authority evidence is unavailable/pending, never
   accepted merely because an operation has a valid signature.
2. The requester transfers a byte-exact fixture through each worker to the
   recipient. The inner expected-key check rejects a substituted recipient;
   the relay has no payload decryption keys. Public offers and operator
   observations contain only their permitted fields.
3. Stop one worker. Its established connection reports failure, and a fresh
   request succeeds through the other without changing pool identity or
   replaying the failed stream's application writes.
4. Withdraw a contribution or revoke use authority. Once the serving worker
   observes that change, it refuses new work and cancels affected active work
   on its next authority check. Use a configured refresh/lease deadline to
   bound stale authority during partition; do not claim instantaneous global
   revocation or remote deletion of already-held keys/records.
5. Independent signed operations converge under reorder/duplication, survive
   cold reopen and never revive expired capacity. Concurrent withdrawal and
   offer changes fail closed for forwarding until authority is resolved.
6. Byte/rate/concurrency/queue limits are enforced across both directions,
   cancellation frees reservations, slow readers cannot grow storage without
   bound, and sharing one device across two pools respects its global ceiling.
7. Teardown leaves no listening socket, task or reservation owned by this
   fixture. Record native/process scope separately from physical-machine and
   network scopes. P1 reports host-location privacy as unqualified.

P1 is a pool foundation, not completion of the anonymous-access goal. Keep its
profile explicit and do not advertise it as host-hidden. Its limits and tests
must not change existing ordinary transport defaults.

#### P1 host integration

Enable Gemot `relay-pool` for records and offers, or `relay-pool-native` for
the Murm adapter. Murm's corresponding feature is `relay`, off by default.

1. Accept a `PoolPolicy` under current Moot authority and supply the existing
   operator group's `DataKeyring` snapshot through `PoolKeys`. Use a separate,
   unpredictable coordination ID. Group key distribution, durable custody and
   departures remain the host's existing GroupSession responsibility.
2. Author `PoolEvent` records through `PoolStore`. It derives independent
   device/withdrawal writer scopes through Personae, validates before storing
   ciphertext and replays with Stickleback causal helpers. Withdrawal retires
   an owner/device enrollment permanently; re-enrollment uses a new ID.
3. Join with the host's existing endpoint/gossip handles. `JoinedSpace` now
   exposes upstream `SyncHooks`; the pool checks current operator authority
   before a sync handshake can exchange history. Ordinary use-only clients
   cannot read coordination even if they know its namespace. Already supplied
   ciphertext/keys cannot be recalled, and an admitted sync transaction is not
   continuously reauthorized. Departures require leaving old sessions and
   rotating the private topic and group access under host ownership.
4. Probe a current contribution with `OfferBook`. A one-use signed challenge
   produces a receiver-local monotonic deadline. Nothing restores live offers
   after reopen. A different pool or service key cannot reuse a live proof.
5. `PoolStore::authorize` rechecks membership, capability, constitution,
   targets and consent. Its expiry intersects the contribution, the host's
   verified authority-checkpoint deadline and the snapshot-age ceiling.
   Replaying local history never renews the checkpoint; a host must obtain
   fresh authority evidence before replacing that policy.
6. Intersect the result with the verified availability deadline using
   `PoolAuthorization::relay_grant`. Inject current grants and the registered
   route map into Murm `RelayService`; share the exact `DeviceBudget` across
   every pool on that device. The host owns accept loops and refreshes grant
   snapshots. Failure to refresh expires active work. Local ceilings may be
   tighter than a community grant.
7. `RelayChannel` uses existing secure setup/Notochord admission on both
   native legs. Forwarded application bytes still require an independent
   sender-to-recipient Noise session with the expected recipient key and
   recipient-owned application admission. Register routes from accepted target
   records, never from a requester-supplied Internet address.

The worker has two fixed buffers, no payload queue or persistence, bounded
pending setup, pool/device concurrency, cumulative device bytes, bidirectional
per-flow bytes and combined fixed one-second rate windows. Rate windows allow
boundary bursts; they do not promise smooth packet pacing. Setup and active
work share cancellation/lifetime bounds, with reservations released by drop.
For native abrupt process loss, failure detection follows the carrier's idle
timeout rather than an application replay or seamless migration.

`ClientOffer` carries a separately signed pool alias, target/recipient key,
expiring native locator and a mandatory host-visible flag. It contains no
operator attestation or private coordination ID. P1 does not hide direct
endpoints or public Moot membership/capability linkage. P2 must inspect those
authority and publication paths before making a stronger operator-privacy claim.

### P2. Required I2P anonymous-access slice

The implementation uses host-owned Truchman sessions and the existing Noise,
Notochord and forwarding limits. The qualified public provider pair is
external i2pd 3.0.0 and embedded Emissary 0.4.0, with two-hop inbound/outbound
tunnels, zero variance and explicit LeaseSet publication. The Windows i2pd GUI
refuses a second instance independently of its data directory, so the trial
uses the existing embedded provider for the other router. Service aliases are
independent of owner identities; Retinue identity defaults and Destination
key-sharing behavior remain unchanged. The public-I2P gate must pass separately
from scripted SAM. Reserve at most 20 MB of retained P2 receipts, using compact
configuration/route/refusal summaries rather than packet or router logs.

#### Implemented P2 interfaces and limits

- `mere-transport/i2p`: `TunnelProfile` requires nonzero hops and explicit
  publication. `I2pSession` wraps the existing SAM client, requires a trusted
  loopback bridge, and accepts only canonical unblinded b32 service locators.
  The host selects transient or persistent keys. Parent-session termination
  poisons its streams; a restarted provider does not revive old sessions.
- Murm `relay-i2p`: `I2pRelayChannel` requires Noise and secure Notochord
  admission. SAM supplies no Personae authentication; carrier facts remain
  honest `Other`/unauthenticated. A rule requiring carrier identity refuses it.
  `I2pRelayService` accepts only I2P target routes and shares native forwarding's
  admission framing, pool/device reservations, byte/rate pump and live rechecks.
  It owns no provider, accept loop or group/key manager.
- Gemot `relay-pool-i2p`: `I2pClientOffer` uses a separate signature domain,
  contains the expected scoped worker and recipient keys, rejects native
  locator/ancestry fields, and verifies a bounded monotonic remaining lease.
  Verification requires an independently trusted application target ID/key;
  a valid pool signature cannot substitute a recipient. The application must
  establish its inner authenticated session before sending private payloads.
  `VerifiedI2pOffer::open` enforces that deadline and the I2P-only channel.
  Persisted offers require verification again. `relay_grant` is shared by the
  native and I2P profiles and intersects authority with observed liveness.
- The test-only scripted SAM provider makes no anonymity claim. The public
  fixture requires distinct router bridges, authenticates inner payloads,
  and has separate provider termination/restart controls. New connection
  readiness probes may retry through I2P; application writes are not replayed.
  Forwarding counters charge inner ciphertext, while outer channel/tunnel
  overhead remains the provider's resource-accounting responsibility.

An I2P-only service face does not conceal already public Moot membership or
capability grants. Public contribution grants can identify authorized operator
candidates. The offer contains no contributor-root proof or private roster,
but broader operator-identity anonymity needs an explicit publication policy.
Operator control links may remain authenticated direct links at the already
stated exposure boundary. A scripted run, a valid locator or typed nonzero-hop
configuration does not qualify host-location privacy on a public router.

Connect existing Truchman STREAMs to the Murm service/session boundary using
honest carrier facts and inner authenticated security. The raw SAM stream
does not by itself prove a Personae identity. Retinue's lower I2P interface
already exists, while the current generic ReticulumTransport builder exposes
TCP client/server interfaces only. A direct SAM adapter can serve the
application relay without requiring a Reticulum detour; mixed-link forwarding
continues to use Retinue in its own profile.

Qualify a named router/provider and tunnel configuration, including a
nonzero-hop privacy setting, its publication controls and its exact restart
behavior. Preserve the I2P plan's unresolved stable-versus-ephemeral identity
checkpoint. Use separately authorized service aliases initially; shared-key
multihoming is not needed to establish one logical pool identity.

**Done when:** P1's two-worker scenario passes over the selected I2P ingress
and target routes; unrelated clients receive no roster, owner-root linkage or
direct locator; wrong service/target keys are refused; unavailable I2P produces
no direct fallback; stale offers, restart and provider termination are handled;
and signaling, diagnostics and persisted client state retain the same boundary.
Inspect configured routes and emitted traffic/locators, not just UI labels.
Separate public-I2P trials from local fixtures and operator-only control links.
No claim of global-observer anonymity follows from this gate.

### P3a. Two independently operated I2P workers

**First slice:** one pool, two worker machines on separate uplinks, two
independent operators, one authorized requester and one registered recipient.
Audience is the trial's named members. Keep P2's I2P-only profile on both legs.

#### Topology and custody

- Each operator supplies their own bounded contribution, scoped worker key,
  durable state and local router. Record actual operator/machine/uplink
  independence privately; different Moot IDs or processes do not prove it.
- Requester and recipient use a third named router, distinct from both worker
  routers. Keep their test host outside the injected failure boundary. Any
  co-location must be recorded and limits the host/uplink-loss claims.
- Pool signing authority stays in its existing custody; workers receive scoped
  authority and signed offers. Provision each operator's existing group/session
  access independently. Root seeds and shared Destination keys are not trial
  provisioning mechanisms. Clients pin the recipient independently of the pool.

#### Implementation and remaining order

1. **Reusable host implemented.** `relay/host.rs::WorkerAuthority` derives
   grants from real pool records, custody, clock and disposable readiness;
   refresh cannot extend the checkpoint's monotonic deadline. `host/worker.rs`
   composes Murm forwarding, pins SAM ACCEPT, bounds tasks and awaits shutdown.
   The I2P fixture now uses it, including actual withdrawal rather than a grant setter.
2. **Runner implemented; operator custody receiving run open.** The opt-in
   `relay-pool` example uses `relay-pool-runner` and existing Castellan client
   releases, founded Moot/Redb records and an existing sealed GroupSession.
   `PoolStore::join_with_control_peers` authenticates separately scoped,
   attested operator keys, avoiding direct reuse of the public worker key.
   Existing group ownership supplies rotations; the runner reloads its record.
   Its create-new bootstrap is operator-private and denotes local readiness;
   a directory issuer still needs a remote probe before signing client offers.
   `check <config>` is inert. `custody-check <config>` shares startup's scoped
   releases and sealed-group read, with a fresh status/authoritative epoch
   fence; it opens no relay transports. The record must belong to the custody
   persona and configured group. Four key scopes must be distinct. Receiving
   instructions live with the example; actual owner grants/lock delivery stay open.
   `run <config>` owns process/sync/session lifetime and explicit resource/time bounds.
   Fresh checkpoint evidence requires a newly verified host binding; local
   reads and restart never create that evidence. The old ALLOW/REVOKE IPC remains test-only.
3. **Independent-host trial open.** Run the same receiving source/dependency cohort
   on both workers, with explicit provider versions and tunnel settings. Start
   with the qualified P2 profile. Use synthetic inner-encrypted payloads and
   observe actual cross-machine routes, refusal facts and resource counters.

Operator configuration names custody references, storage, private control peers,
I2P bridge/profile/publication, approved targets, clock/authority validity,
availability leases, setup/queue/session/byte/rate/buffer limits, shutdown bounds
and total trial duration. Offer no capacity until these bounds are valid. Keep
relay ciphertext accounting and router/tunnel overhead accounting distinct.

#### Done-conditions

| Gate | Required result |
|---|---|
| Host code | Opt-in receiving build and lifecycle controls pass outside test-only helpers; ordinary feature boundaries still build |
| Two workers | Byte-exact inner-encrypted traffic through each independently operated worker under the same pool identity; wrong requester/worker/recipient keys refused |
| Failure and restart | Stop each worker/provider separately and interrupt each worker uplink while the test endpoints survive; old streams fail explicitly, new connections select the survivor, restarted workers require fresh sessions/probes |
| Withdrawal and partition | Observed withdrawal/revocation cancels active work and refuses new work; isolated authority expires within configured validity/check bounds; replay/reopen cannot renew it; fresh verified catch-up restores eligible service |
| Limits and unattended run | Exercise configured pending/active/byte/rate/buffer ceilings and a bounded run spanning offer expiry and authority refresh; record duration and renewals; shutdown returns reservations/tasks to zero |
| Privacy | Client offers, persisted state and diagnostics retain P2's locator/ancestry boundary; I2P loss fails closed; operator control links and public membership remain explicitly exposed at their stated scope |

Publish compact receipts for exact pins/platforms, labeled topology, custody
checks, provider/tunnel settings, fault/refusal outcomes, configured bounds,
observed counters and cleanup. Keep identifying network/custody details private.
P3a retains at most **20 MB across all trial hosts**, within the plan's 100 MB
cap, in the existing receipt ledger/testing location. Preserve failed attempts.
Local rehearsals qualify only host behavior; the independent-host gate remains
open until suitable machines, operators and uplinks actually pass these checks.

### P3b. Later deployment and relay profiles

Product UI/integration, public discovery/use, Moothold reciprocity, WebRTC,
iroh relay/TURN pools, radio and LXMF need separate receiving-consumer slices.
Exit/proxy service, persistent payload custody, migration and bonding also need
their own protocol, audience, privacy, admission, resource and failure contracts.
Moothold accounting does not prove delivery or independent anonymity paths.

## Required receipts and retained-byte budget

The total retained evidence cap for this plan is **100 MB across repositories**.
P0 uses a compact API/ownership comparison; P1 uses at most **10 MB** for a
structured native result, exact source/dependency identities, reproducible
commands and bounded failure summaries. P2/P3 share the remaining budget;
capture only the route/metadata evidence needed for their done-conditions.
No full payload captures or compiler-output trees are required.

Append implementation receipt summaries to
`archive_docs/receipts/2026-11-03_moot_relay_pools_plan_receipts.md` at the Gemot
doc root. Generated external evidence, if required, belongs under
`Code/testing/gemot/moot-relay-pools/`, with uniquely named files per run so
cited receipts are never overwritten. Reuse stable approved Cargo targets;
introduce no isolated Cargo home or worktree without an actual need. The cap
does not authorize deleting existing evidence or another lane's output.

## Findings, 2026-11-03 to 2026-11-04

- Initial P0 comparison: Gemot `3766de4`, Murm `ba9aa84e844`, Eidetic
  `7a3453a`. Gemot's workspace pins murm-sync `ce53cebb...`; Murm's native
  workspace pins Stickleback 0.2.0 at `6f1256aa...`. These differ from local
  checkout heads; subsequent receiving qualification is recorded in the receipt.
  `Cargo.toml` and `native/Cargo.toml` establish those edges.
- Gemot `crates/gemot/src/moot/{group.rs,delegation.rs,lanes.rs}` already owns
  membership/delegation and uses `murm_sync::JoinedSpace`; its seven lanes are
  existing domain history, not a relay roster. `hosting.rs` demonstrates
  authority cuts and intersected community/device bounds but records a
  hosting promise, not a transit reservation.
- `crates/commons/src/{encrypted.rs,keys.rs}` and Eidetic
  `crates/stickleback/src/{group_session.rs,group_crypto.rs}` already compose
  p2panda group encryption, current key epochs and causal admission. The
  Spaces trial must measure an actual reduction against these mechanisms.
- Murm `native/crates/sync/src/lib.rs` owns live sessions and address books;
  `native/crates/transport/src/security.rs` supplies configurable setup bounds
  and explicit security profiles. Murm's `relay/budget.rs` now supplies shared
  forwarding limits; Gemot supplies pool authority and host composition.
- Dramatis `crates/notochord/src/lib.rs` keeps session admission, membership
  authority and anonymous transit policy separate. Its current first action
  is a Murm connection; Gemot's `relay_cap` supplies the relay-specific grants.
- Murm `crates/truchman/README.md` documents STREAM support and the absence of
  datagram sessions; `crates/retinue/src/endpoint/i2p.rs` and
  `native/crates/murm-i2p/src/lib.rs` provide existing integration/provider
  pieces. The current I2P successor plan retains unqualified variants and
  identity-policy questions. Earlier receipts are not a pool acceptance run.
- The stack audit's R25/R26 recommendations are comparisons, not adoption
  receipts. The pinned Spaces README was inspected; no dependency was changed.
- P2 source/API reuse is implemented in Murm's `transport/src/i2p.rs` and
  `murm/src/relay/{channel.rs,i2p.rs}` and Gemot's `relay/i2p_offer.rs`. No
  p2panda-spaces adoption or new group/key orchestration is introduced.
- P2 public qualification passes on distinct Emissary 0.4.0 and i2pd 3.0.0
  routers, both on this Windows machine, with two-hop inbound/outbound tunnels
  and zero variance. Provider termination invalidates local streams and old
  sessions; restart requires a fresh session/alias. Public membership, service
  linkability and direct operator control metadata retain their stated bounds.
- P3a host composition now lives under `relay/host`; the worker fixture reuses
  it. `relay/control.rs` binds private control endpoints through existing
  Personae attestations. Local/public same-host tests establish software
  behavior, while operator custody receiving and independent deployment remain open.

External protocol references: [I2P router/destination separation](https://i2p.net/en/docs/overview/intro/),
[I2pd multihoming](https://docs.i2pd.website/en/latest/tutorials/glossary/),
and [iroh 1.0.3 encryption/relay behavior](https://docs.rs/iroh/1.0.3/iroh/).
These describe protocol capabilities; receiving qualification is in the receipt.

## Progress

- 2026-11-03: recorded the founding direction, source/reuse findings and privacy gates.
- 2026-11-03: completed P0/P1, retaining existing group/key ownership and adding
  private records, authorized sync, fresh offers and bounded native forwarding.
  Windows native/process scope and exact receiving evidence are in the receipt.
- 2026-11-03: landed P2's I2P-only adapter and independently pinned offers;
  named-provider forwarding/failover/withdrawal and restart controls pass.
  Exact source/test identities and privacy limits are in the receipt.
- 2026-11-03: narrowed P3a to reusable host composition followed by a two-worker,
  independent-uplink trial with separate custody, partition/limit/restart gates
  and a 20 MB receipt cap. Planning only; no P3 implementation or trial claim.
- 2026-11-04: implemented host composition, separate private control keys and
  the bounded headless runner. Reused current group/custody/sync mechanisms.
  Qualification and failed probes are in the receipt; P3a deployment gates stay open.
- 2026-11-04: added shared custody preflight, group/operator and key-scope
  checks, plus operator receiving instructions. Live custody and independent hosts stay open.
- 2026-11-04: Dramatis's corrected O-PC receiver passed native unlock and fleet
  SSH with a fixed weekly limit. P3a still needs provisioned operator/group
  state; this dependency check does not qualify relay traffic or independent uplinks.
