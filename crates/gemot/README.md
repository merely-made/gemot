# gemot

`gemot` is the assembly crate for the [mere](https://crates.io/crates/mere)
browser: the community and federation layer, across every tier of mere's
social-graph scale.

*Gemot* is the Old English word for the assembly itself (as in *witena-gemot*,
the meeting of the wise), and it is the word *moot* descends from. The crate is
the gemot; the groups it convenes are moots.

Renamed from `moothold` (2026-07-14). That name was a tier, not a layer: this
crate implements **all four** tiers (orrery, moot, moothold, coalition), so
naming it after the third one described a part as the whole. The tier keeps its
name; the crate no longer borrows it.

A *moot* is a single persistent themed federatable graph-view community
(t2). A *moothold* is a federation of moots (t3) — *a holding of moots*,
in the Anglo-Saxon sense (cf. *household*, *stronghold*, *freehold*). A
*coalition* (t4) is a sovereign cluster of mootholds, a future tier that
provides organizing defaults member mootholds can adopt or override.

The big bet: **moots are a durable, crowd-hostable substrate for
decentralized communities to take root in and interoperate across.**
Communities should outlive any single host, span protocols, and travel
with their members.

## Moot layout

`Moot` is the public community aggregate and owns the namespace below. The
modules make the three persistence lanes explicit without making callers
assemble them themselves:

```text
gemot::moot
├── constitution  signed governance law, folds, checkpoints, and sync
├── records       the public community object and retention lane
└── tessera       trust facts, persona lineage, storage, and sync
```

`moot::Moot` composes those lanes at the command, snapshot, and native-drop
boundary. `records` retains compatibility re-exports for the raw object lane;
new code should enter through the aggregate unless it is deliberately working
at a lane boundary.

## What `gemot` owns

Moots are **graph views that link to and store** community resources —
*not* protocol-translation layers. The crate's job is coordination,
governance, routing, and durable memory; foreign protocols stay
themselves and members reach them via thin clients.

- **The graph view itself** — persistent, shared, signed, replicated. The
  moot's "table of contents."
- **Members + capabilities** — who's in, what scope they have. Capability
  scopes are meadowcap-shaped: signed credentials over `(subspace,
  path-prefix, time-interval, mode)`, delegable in subsets, time-bounded.
- **Pinned content** — engrams, archives, page snapshots, files,
  content-addressed via BLAKE3 and replicated via iroh-blobs.
- **Resource pointers** — links to Matrix rooms, IRC channels, Nostr
  feeds, Gemini capsules, websites, anything addressable. Each is a
  graph node with a URL and a protocol tag; `mooting-*` adapters help
  members open them.
- **Hosting commitments** — signed events naming who's running which
  service, with heartbeats and successor chains. **Voluntary; never
  imposed.** Tessera rewards follow-through and penalizes ghosting.
- **Engram fauna** — durable contributions accumulated over time,
  forming the moot's culture / geist.
- **Tier transitions** — moot → moothold (federation), moothold →
  coalition. Each transition is a first-class governance
  event.
- **Forking primitives** — all structures are forkable. A fork copies
  graph state, inherits some/all members per the fork's terms, commits
  its own pin set, declares its governance.

## Naming

The crate is called `gemot`. The product term *moothold* refers
specifically to **Tier 3** (federation of moots) per the
[2026-05-07 moot-tiers brief](https://github.com/mark-ik/mere/blob/main/design_docs/mere_docs/implementation_strategy/2026-05-07_moot_tiers_and_voluntary_hosting_brief.md).
Earlier docs may use *moothold* as an umbrella term — that's the older
framing.

The Anglo-Saxon *-hold* (household, stronghold, freehold) connotes a
**holding of bounded units**. A federation of moots is literally a
holding-of-moots. Tier 4, **coalition**, is the sovereign cluster of
mootholds (originally named *demesne* for the Latin sense of a
directly-controlled domain; renamed 2026-06-04 because *demesne* sounds like
*domain*, which already names the domain layer).

## The tier framework

| Tier | Term | What it is | Storage model |
| --- | --- | --- | --- |
| **T1** | **orrery** | A user's root graph view. *"Your orrery is your moot."* | Personal eidetic. |
| **T2** | **moot** | A persistent themed federatable graph-view community. | Voluntary pin pool. Dissolves if nobody pins. |
| **T3** | **moothold** | A federation of moots. | ILL-shaped reciprocity between member moots. |
| **T4** | **coalition** | A sovereign cluster of mootholds. | Coalition-wide reciprocity ledger; per-moothold override; fork-out always possible. |

**Practical t2 ceiling: 5K–10K active members** before a moothold of
related moots is healthier than a single mega-moot. T4 is a future tier;
t1–t3 are sufficient for personal / communal / topical-federation
scales.

## Voluntary hosting

The most important architectural commitment in the design: **no hosting
is ever imposed on anyone.** Tessera-weighted voting governs how a
community uses its resources or apportions capabilities; it does NOT
distribute burdens. Burdens are picked up voluntarily.

- **Honey:** reputation accrues through follow-through.
- **Stick:** reputation is lost when public commitments are not
  fulfilled — *visible-failure-to-follow-through*, never coercion.
  Saying no costs nothing.
- **Cheesecloth pinning:** liveness for static content emerges from
  overlapping individually-unreliable contributions. Casual hosting is
  enough; nobody owes 24/7 uptime.
- **Lapse and revive is a normal life cycle.** If nobody pins, content
  is offline; members' eidetic still has copies; re-host at a new
  address whenever you want. *Whether something is currently online is
  not its total existence.*
- **Capability scopes are tessera-gated.** What you can pledge is capped
  by your reputation, preventing rug-pulls and rep-farming exploits.

For live services (Matrix homeservers, IRC daemons, real-time chat),
single-leadership commitments with named successors apply rather than
cheesecloth — those need at least one continuous host with graceful
failover.

## ILL-shaped reciprocity at t3 / t4

At Tier 3 and above, member structures contribute storage / compute /
replication shares to the federation; reciprocity credits accrue
proportional to contribution and reputation. The model is **library
interlibrary loan**, not crypto-economic:

- Capacity-based, not cash-based.
- Reciprocity is reputational, not monetary.
- Identity is institutional (the moot's track record, not its founder's
  clout).
- Resists cash exploitation: you can't deposit money to make the
  federation preserve your stuff; you have to be a participating
  institution with capacity.

A moothold is **instantiated** via stake + agreement: members of a
forming moothold pay a real infrastructure cost (their old laptop
running a mooting server, their bandwidth, their pinned storage
allocation) and mutually agree (signed events) to establish the
federation. Once stakes are met, the structure goes live; if any stake
lapses with no successor, that portion goes offline until someone puts
it back up.

## How it relates to other workspace crates

```text
                 Merecat community UI
                            │
                            ▼
                          gemot
              (this crate; tier 1–3 lifecycle,
               graph view, pins, tessera, capabilities,
               fauna, federation, forking)
                            │
        ┌───────────────────┼─────────────────────┐
        ▼                   ▼                     ▼
     mooting          identity        transport
   (protocol-core +    (members,            (moot streams,
    thin client        capabilities,        gossip topics,
    orchestration      chain-rooted         iroh-blobs for
    for foreign        personas)            pinned content,
    resources)                              optional Veilid)

   bidirectional thin clients (siblings of mooting):
     mooting-mere | mooting-matrix | mooting-nostr |
     mooting-atproto | mooting-activitypub | …

   outbound-only bridges (separate, for non-hostable / publish-only):
     mere-bridge-{matrix, nostr, activitypub, atproto, irc, …}
```

- [`mooting`](https://crates.io/crates/mooting) — the protocol-core.
  Defines `MootProtocol` (small surface for moot-internal coordination
  over MereEvents) plus client orchestration for foreign-protocol
  resources linked from a moot.
- [`identity`](https://crates.io/crates/identity) — moot
  members are identified by master pubkey or chain-rooted persona
  pubkeys. Tessera accrues against the chain root, not the leaf
  persona; capabilities are signed Ed25519 credentials.
- [`transport`](https://crates.io/crates/transport) —
  moot-scoped streams (per-moot ALPN), iroh-gossip topics for
  cross-member event broadcast, iroh-blobs for content-addressed
  pinning. Optional Veilid backend activates when a moot declares a
  privacy-required transport policy.
- [`murm`](https://crates.io/crates/murm) — bilateral / small-group
  conversations. gemot handles many-to-many federation. A moot may
  use murm-style cabals for private sub-channels.
- [`eidetic`](https://crates.io/crates/eidetic) — owner-private memory
  substrate. Pinned content and engrams cached locally via eidetic's
  `Store`; cross-moot replication is moothold's job. The Tier 1 orrery
  lives entirely on eidetic.
- **`mooting-*` adapter crates** (planned) — thin protocol clients per
  foreign protocol that members can use to interact with linked
  resources. Bidirectional, but they don't translate foreign protocols
  into moot-shape — they help members **reach** foreign resources.
- **`mere-bridge-*` crates** (planned) — outbound-only Pattern B
  bridges, distinct from `mooting-*` adapters. For systems that can't
  host moot semantics or where mere only wants to publish.
- [`moothold`](https://crates.io/crates/moothold) — Tier 3 federation:
  direct concords, reciprocity, and cross-Moot resource coordination.
- [`mere`](https://crates.io/crates/mere) — supplies the reusable graph-browser
  library; Merecat composes Gemot and Moothold into the product.

## Status

Pre-1.0. Signed Moot declarations, membership, fauna, deterministic roster
folds, Tessera, constitutional governance, shared muniment stores,
constitution-bound retention checkpoints, prefix pruning, and host-composed
sync proofs are implemented. The aggregate `Moot` service composes governance,
object and Tessera commands, snapshots, checkpointing, pruning, and authority
rotation without exposing p2panda types. Plain and protected aggregate drops
carry critical constitution evidence, bootstrap a rotated checkpoint chain on a
fresh recipient, and refresh the materialized view through the shared atomic
importer. A receipt resolves to an explicit typed outbound operation for the
host to publish. Quorum rules and capability grants remain. The next slices land per the
[moot-tiers brief](https://github.com/mark-ik/mere/blob/main/design_docs/mere_docs/implementation_strategy/2026-05-07_moot_tiers_and_voluntary_hosting_brief.md)
§13:

- **T1 milestone**: orrery as a one-member moot-of-self with local
  pin tracking, public node sharing.
- **T2 milestone**: two-member moot; signed stake + agreement; engram
  authoring + pinning; live-service hosting commitments with
  heartbeats.
- **T3 milestone**: two moots federate into a moothold; reciprocity
  pledges; cross-moot pin requests via the reciprocity ledger.
- **T4 (coalition)**: deferred until t3 is solid.

Forward direction:

- **Voluntary commitment + reputational stakes** — public signed
  commitments, heartbeats, clean handoffs, tessera-gated scopes.
- **Cheesecloth pinning + leadership commitments** — hybrid model;
  archives use cheesecloth, live services use named-successor
  leadership.
- **Tessera against chain root** — reputation accrues against the
  master identity; pseudonymous personas inherit a depreciated
  fraction.
- **Capability delegation (meadowcap-shaped)** — moot-scoped capability
  tokens, delegable in subsets, time-bounded.
- **Optional privacy transport** — moots can declare a Veilid-required
  policy; member clients enforce it.
- **First-seen aggregation across mootholds** — tessera-aware federation
  corroborates provenance claims; deduplicated content credits the
  original submitter.
- **Settings, not hardcodes** — heartbeat cadence, capability decay,
  pinning quotas, vote thresholds, reciprocity ratios all per-tier
  configurable.

## License

MPL-2.0.
