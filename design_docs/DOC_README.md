# Gemot documentation

Network-session ownership (2026-11-03): Gemot keeps its group ACL, membership
and lane policy; its join helpers now use Murm's `murm-sync`. Stickleback in
Eidetic retains validated operation storage and group-encryption mechanisms.
Scope and qualification: `murm/design_docs/2026-10-28_transport_consolidation_plan.md`, T7.

Preserve host-owned authority, existing formats and independent crate feature boundaries. Read [documentation policy](DOC_POLICY.md) before editing.

Relay-pool working principle: membership never commits a device's resources.
Contributions require bounded, revocable owner consent; public service offers
and restricted operator coordination have distinct disclosure rules. Live sync
uses Murm, and encrypted records alone do not establish host-location privacy.

Canonical migration and receipts: `mere/design_docs/archive_docs/2026-10-28/2026-10-19_family_promotion_plan.md` (archived 2026-10-28); open items continue in `mere/design_docs/mere_docs/implementation_strategy/2026-10-28_family_promotion_plan.md`.

## Community authority and publishing

- [2026-11-03_moot_relay_pools_plan](moothold_docs/implementation_strategy/2026-11-03_moot_relay_pools_plan.md): P0 comparison and opt-in P1 native relay pools, using current group encryption, private authorized sync and bounded Murm forwarding. [Qualification](archive_docs/receipts/2026-11-03_moot_relay_pools_plan_receipts.md) separates same-host native/process tests from the required P2 I2P privacy and P3 deployment gates; Spaces is not adopted.
- [2026-11-01_moot_publication_plan](moothold_docs/implementation_strategy/2026-11-01_moot_publication_plan.md): live plan. Production publication and hosting records with historical authority, updates and honest retention, the remaining collection gates, application co-op, addressed delivery, and host and consumer residue.
- [2026-08-09_boundary_identity_and_grant_composition](moothold_docs/research/2026-08-09_boundary_identity_and_grant_composition.md): how the moot layer composes with a high-latency, multi-transport substrate.
- [2026-08-12_radio_scopes_as_moots](moothold_docs/research/2026-08-12_radio_scopes_as_moots.md): civic-deployment radio scopes modelled as moots; ratified 2026-08-12.
- [2026-09-05_author_offline_publication_proof](moothold_docs/research/2026-09-05_author_offline_publication_proof.md): the same-machine author-offline publication proof and its receipt.

The Moot object M1 plan (2026-06-12), with its landed work and run receipts, is
archived whole under `archive_docs/2026-11-01/`.
