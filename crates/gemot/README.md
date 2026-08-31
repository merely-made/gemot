# gemot

Community and assembly layer for the [mere](https://crates.io/crates/mere)
workspace. A *moot* is one persistent, themed, federatable graph-view
community. `gemot` owns a Moot's lifecycle, governance, membership, public
records, trust facts, and replication lanes. Tier 3 federation lives in the
sibling [`moothold`](https://crates.io/crates/moothold) crate.

Tier vocabulary used throughout: **orrery** (t1, a user's own root graph view),
**moot** (t2), **moothold** (t3, a holding of moots), **coalition** (t4, a
cluster of mootholds; not implemented). The crate was named `moothold` before
2026-07; the tier kept the name, the crate did not.

## Modules

`gemot::moot` is the whole public surface, plus the crate-root consts `VERSION`
and `STAGE`. Every row below is a path under `gemot::moot`.

| Module | Contents |
| --- | --- |
| (root) | `Moot`, `MootFile`, `MootId`, `MootSnapshot`, `MootCommandReceipt`, `MootLane`, `MootOutboundOperation`, `MootError`, `MootLanes` and the seven `GEMOT_*_LANE` ids |
| `constitution` | `Constitution` fold, `ConstitutionEvent`, `ConstitutionRules`, `TulpaRules`, `AmendmentRule`, `CapabilityGrant`, `GovernedAction`, `authorize_governed`, `MootGovernance`, `ConstitutionStore` / `ConstitutionFileStore`, `ConstitutionExt` |
| `delegation` | `MootDelegations` fold over Personae `SignedDelegationCertificate` / `SignedDelegationRevocation`, `MootDelegationProjection`, `MootScopeKeyEpoch`, `MOOT_DELEGATION_DOMAIN`, `MOOT_ACT_ACTION`, `MootDelegationStore`, `MootDelegationExt` |
| `group` | p2panda-auth membership: `MootGroup`, `MootMember`, `MootMembershipRecord`, `MootAccessLevel`, `MootMembershipAction`, `MootGroupTransition`, `P2pandaGroupKeyEpoch`, `P2pandaScopeKeyEpoch`, `MootGroupStore`, `MootGroupExt`, `membership_identity_salt` |
| `records` | The public record lane: `Declaration`, `Member`, `FaunaEntry`, `MootRoster`, `MootEvent`, `MootStore`, `MootExt`, `MootLogId`, plus retention (`MootRetentionPolicy`, `RetentionCheckpoint`, `KeepBound`, `LogFrontier`, `AvailabilityPolicy`, `ErasurePolicy`, `GovernedCheckpointAuthority`, `PolicyRevision`) |
| `standing` | Trust receipts: `StandingEvent`, `ChainRoot`, `CommitmentId`, `Scope`, `Ledger`, `StandingConfig`, `PersonaChains`, `PersonaId`, the policy slot (`StandingFacts`, `GateConfig`, `GateDecision`, `Policy`, `DenyReason`, `authorize`, `may_act`), `StandingStore`, `StandingExt`, and `persona_vault` for vault-derived persona keys |
| `tulpa` | Community-adopted revisioned artifacts: proposal facts, frozen-electorate `RecognitionContext` endorsements, adopted-version projection, revocation, rollback, `TulpaStore`, and `TulpaExt`. `ArtifactRef` carries digest plus byte count only. |
| `flora` | Federated LoRA receipt lane: `FloraRoundSpec`, heterogeneous participant ranks, exact `FloraContributionReceipt` and candidate artifact refs, rank-budget validation, `FloraStore`, and `FloraExt`. The only stack is A vertical / B horizontal with scaling on B. |
| `typed_authorization` | `TypedMootAuthorization` answers gemot's `MootAuthorizationProvider` from the shared `mere-capability` algebra; `MootAuthority` presents the same certificates as a `servitor::AuthorityProvider` |

Each domain module has the same shape: an event grammar, a deterministic fold,
a `*Store` over `muniment`, and a `*Ext` p2panda operation extension with its
own `to_operation_seed` and `from_operation`. Constitution, delegation,
records, Standing, Tulpa, and FLORA also export `verify`; the membership lane validates
through its store instead.

## The `Moot` aggregate

`Moot<B>` (`B: muniment::Backend`) is the command and snapshot boundary over
all seven domains. `MootFile` is the redb-backed alias.

| Area | Items |
| --- | --- |
| Open | `in_memory`, `open`, `open_existing`, `moot_id` |
| Stores | `constitution_store`, `object_store`, `standing_store`, `tulpa_store`, `flora_store`, `delegation_store`, `membership_store`, `governance` |
| Governance | `found`, `amend`, `authorize`, `authorize_constitution_grant` |
| Delegation | `delegations`, `delegation_projections`, `delegation_scope_key_epochs`, `authorize_current_delegated`, `authorize_delegated` |
| Records | `declare`, `join`, `share`, `authorized_fauna`, `checkpoint`, `prune_current` |
| Membership | `membership`, `update_membership`, `update_membership_for_identity` |
| Standing | `record_standing` |
| Tulpa / FLORA | `record_tulpa`, `record_flora` |
| Drops | `export_plain_drop`, `export_protected_drop`, `import_plain_drop`, `import_protected_drop` |
| Views | `snapshot`, `outbound` |

Commands return a `MootCommandReceipt` naming the operation hash, the `MootLane`
it belongs on, and a refreshed `MootSnapshot`. `outbound` resolves a receipt to
a typed `MootOutboundOperation` for the host to publish.

## Replication

A Moot replicates over seven independent LogSync lanes, all subscribing to the
Moot id as topic:

```text
gemot/constitution/v1   GEMOT_CONSTITUTION_LANE
gemot/delegation/v1     GEMOT_DELEGATION_LANE
gemot/membership/v1     GEMOT_MEMBERSHIP_LANE
gemot/records/v1        GEMOT_RECORDS_LANE
gemot/standing/v1        GEMOT_STANDING_LANE
gemot/tulpa/v1           GEMOT_TULPA_LANE
gemot/flora/v1           GEMOT_FLORA_LANE
```

`Moot::join_lanes(endpoint, gossip)` joins all seven through
`stickleback::JoinedSpace` and returns `MootLanes`, whose `sync_status()` and
`status_handles()` report per-lane state. The host owns the endpoint and gossip
handles and publishes authored operations; gemot's own code names no network
session type.

## Dependencies

`p2panda-core`, `p2panda-auth`, `p2panda-store` (0.7), and `p2panda-encryption`
(`data_scheme`) for signed operations, group materialization, and group-secret
ids. `stickleback` for `MunimentStore`, `OperationProcessor`, `JoinedSpace`, and
native drops. `muniment` (`redb`) for durable backing. `identity` (the
`personae` package, renamed by the workspace alias) for keypairs, derived-key
attestations, and delegation certificates. `mere-capability` for the shared
typed vocabulary; `servitor` for the denizen-gate adapter. `mooting` for
`RecognitionContext`, used by
`MootRoster::recognition_context`. `proofs`, `serde`, `redb`, `thiserror`.

`p2panda-net`, `p2panda-sync`, `transport`, `chartulary`, and `tokio` are
dev-dependencies only, for the two-peer convergence tests and the `moot-peer`
example, which play the host. `p2panda-net` is still in the normal build graph
transitively through `stickleback`. The crate declares no cargo features.

## Consumers

`moothold` (tier 3 federation) and `commons-spine` (the technical Commons
profile) consume gemot inside this workspace.

## Status

Pre-1.0. Implemented: signed Moot declarations, deterministic roster folds,
fauna, constitutional governance with quorum amendments, a p2panda-auth
membership adapter with derived-key attestation and group-secret epochs,
Personae-signed delegation certificates with cascading revocation, Standing
events plus the ledger and gate projections, constitution-bound retention
checkpoints, prefix pruning, and plain and protected native drops that
reconstruct all seven domains on a fresh recipient. Tulpa retains all
proposal/revocation facts while projecting effective adopted artifact versions.
FLORA validates the social contract and exact artifact receipts for FLoRA, but
does not carry raw tensors or training corpus bytes. Adapter artifacts can leak
training information; their audience, retention, and release policy remain an
explicit community decision rather than an implicit public-default claim.

Not built yet: tier transitions, hosting commitments with heartbeats, pin
tracking, and the `mooting-*` foreign-protocol adapters. Milestones are listed
in the
[moot-tiers brief](https://github.com/merely-made/mere/blob/main/design_docs/mere_docs/implementation_strategy/2026-05-07_moot_tiers_and_voluntary_hosting_brief.md)
§13.

## License

MPL-2.0 (see LICENSE).
