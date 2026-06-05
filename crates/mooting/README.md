# mooting

`mooting` is the protocol-core layer for moot internal coordination
plus thin protocol-client orchestration for foreign resources linked
from a moot, in the [mere](https://crates.io/crates/mere) browser.

It is the modular layer within
[`moothold`](https://crates.io/crates/moothold) that defines the
`MootProtocol` trait, dispatches moot-internal coordination over
MereEvents, and routes members to foreign-protocol clients (Matrix
rooms, IRC channels, Nostr feeds, etc.) when they open a resource node
from the moot's graph view.

## What `mooting` actually does

Two distinct concerns:

1. **Internal moot coordination** — handled by `mooting-mere` (the
   canonical adapter): governance events, capability evaluation,
   tessera issuance, hosting negotiation, member announcements. All
   over the Mere-native event DAG (CBOR-encoded MereEvents over iroh
   streams).

2. **Thin client orchestration for linked resources** — handled by
   per-protocol sibling adapter crates (`mooting-matrix`,
   `mooting-nostr`, …). Their job is to *help members reach foreign
   resources*, not to translate foreign protocols into moot
   abstractions. When a member clicks a Matrix-room node in the moot
   graph, `mooting-matrix` opens the right client (system webview,
   embedded matrix-rust-sdk, etc.). When a member is *committed to host*
   a Matrix homeserver for the moot, `mooting-matrix` exposes
   operational telemetry (status, failover handoff, resource use) to
   the moot's governance layer.

Foreign protocols stay themselves. The moot links to and stores
resources; mooting helps members consume or host them.

## Naming

The gerund form (*mooting* = the act of holding a moot) names the
protocol plumbing; the singular noun (*moot* = a single community) is
the user-facing object. Each enabled protocol provides its own
`mooting-*` adapter; consumers of
[`moothold`](https://crates.io/crates/moothold) see a unified
moot-internal coordination API regardless of which client adapters are
active.

## What `mooting` will own

When implementation lands, this crate will hold:

- **`MootProtocol`** (trait) — the contract concrete adapters
  implement. Methods cover moot-internal coordination (publish
  governance event, evaluate capability, issue tessera, negotiate
  hosting) plus client orchestration (resolve resource node → client
  invocation; expose host telemetry when committed).
- **Dispatcher** — given a moot graph node's protocol tag, route the
  operation to the correct adapter implementation.
- **Per-moot configuration** — a moot's "constitution" declares which
  protocol backends are active, transport policy (iroh default vs
  Veilid privacy-required), default capability shape.
- **Cross-protocol primitives** — types reused across all backends:
  `MootId`, `MemberId`, `CapabilityScope`, `TesseraReceipt`,
  `EngramRef`, governance event categories, resource-node tags.
- **Common errors** — `MootingError`.

The trait surface stays small. Protocol-specific encoding, wire format,
and federation mechanics live in the sibling adapter crates.

## Multi-protocol moot ecology

Following the same pattern [`nematic`](https://crates.io/crates/nematic)
uses for smolweb (one engine, many protocol-specific sibling parser
crates following the `middlenet-{gemini, gopher, finger, markdown,
feed, spartan, nex, titan, scroll, guppy, misfin}` precedent), each
p2p protocol that a moot links to gets a sibling adapter crate. But
mooting adapters render and orchestrate **faithfully per protocol** —
they don't normalize foreign content into a unified internal form.

Planned adapters:

- **`mooting-mere`** — Mere-native MereEvent DAG over iroh streams.
  The canonical / default backend; handles all moot-internal
  coordination.
- **`mooting-matrix`** — open Matrix rooms (web client / embedded SDK);
  optionally host Matrix homeservers for the moot when committed.
- **`mooting-nostr`** — fetch / subscribe to Nostr feeds; publish
  signed Nostr events from moot members.
- **`mooting-atproto`** — bsky-shaped feeds; reading and (where
  applicable) hosting.
- **`mooting-activitypub`** — fediverse Group actors; reading and
  publishing.
- *…and more, as new p2p protocols emerge that the community wants to
  link to.*

Each `mooting-*` adapter must answer the discipline question: **what
does this complement that mere-native doesn't already do?** Adapters
earn their slots by adding distinctive value (rooms + WebRTC, an
existing user base, fediverse reach, etc.), not by default. Protocols
that don't fit Pattern A (bidirectional native consumption / hosting)
become outbound-only bridges in separate `mere-bridge-*` crates above
moothold.

## How it relates to other workspace crates

```text
                       moothold
              moot lifecycle, federation,
              tessera, engram flora,
              capability scopes, pin tracking
                          │
                          ▼
                       mooting
              (this crate; trait + dispatcher;
               coordination over MereEvents +
               foreign client orchestration)
                          │
       ┌──────────┬───────┼──────────┬──────────┐
       ▼          ▼       ▼          ▼          ▼
    mooting-   mooting-  mooting-  mooting-   mooting-
     mere       matrix    nostr     atproto    activitypub  …

   protocol-specific transports / encodings / clients,
   each addressed via its own external infrastructure
```

- [`moothold`](https://crates.io/crates/moothold) — wraps mooting with
  tier lifecycle (t1 orrery → t2 moot → t3 moothold → t4 coalition),
  federation reciprocity, governance, tessera, capability scopes,
  forking. moothold owns the user-facing moot abstraction; mooting
  owns the protocol-coordination abstraction.
- **`mooting-*` adapter crates** (planned) — one per p2p protocol that
  the moot links to or members host. Thin protocol clients, not
  translators.
- [`identity`](https://crates.io/crates/identity) — adapters
  use identity for member addressing and capability signing. Each
  adapter decides which identity surface it uses (master pubkey,
  chain-rooted persona key, protocol-specific derived key).
- [`transport`](https://crates.io/crates/transport) —
  adapters that ride iroh use transport directly. Adapters that
  ride foreign transports (Matrix homeservers, Nostr relays, ATProto
  PDSs) bring their own.
- [`murm`](https://crates.io/crates/murm) /
  [`murmuring`](https://crates.io/crates/murmuring) — bilateral cabal
  flows; orthogonal to mooting. A moot may use murm-style cabals for
  private sub-channels, but bilateral comms aren't moot-shaped.
- **`mere-bridge-*` crates** (planned, separate) — outbound-only
  Pattern B bridges for systems that can't host moots natively or
  where mere only wants to publish.

## Why this lives in its own crate (not inside moothold)

- **Adding a new p2p protocol = adding one sibling crate**, not
  modifying moothold.
- **moothold consumes the abstract `MootProtocol` trait** without
  pulling in every concrete adapter; adapters can be feature-gated.
- **A non-`moothold` consumer** (test harness, alternative federation
  layer, future research crate) could in principle use `mooting`
  directly with its own lifecycle layer.

## Status

Pre-1.0 placeholder. Currently exposes only `VERSION` and `STAGE`
constants. The trait surface and the first concrete adapter
(`mooting-mere`) land in subsequent slices.

Forward direction is tracked in the
[moot-tiers brief](https://github.com/mark-ik/mere/blob/main/design_docs/mere_docs/implementation_strategy/2026-05-07_moot_tiers_and_voluntary_hosting_brief.md)
and the
[event-DAG substrate brief](https://github.com/mark-ik/mere/blob/main/design_docs/mere_docs/implementation_strategy/2026-05-07_event_dag_substrate_brief.md):

- **Define the `MootProtocol` trait surface.** Small, protocol-agnostic.
  Coordination + client orchestration as the two concerns.
- **Ship `mooting-mere` first.** Mere-native MereEvent DAG over iroh
  streams; the canonical reference implementation.
- **Add adapter crates for additional p2p protocols** as demand
  surfaces and protocol semantics solidify.
- **Outbound bridges** (`mere-bridge-*`) for non-hostable systems
  remain separate; mooting is bidirectional adapters only.

## License

MPL-2.0.
