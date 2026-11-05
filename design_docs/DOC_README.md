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
An I2P Destination supplies routing; Noise and Notochord supply channel identity
and admission. Applications pin recipients independently of pool signing keys.
Direct operator endpoints use separate attested control keys; their bootstrap
bindings stay private. Recipient admission still discloses the worker's application identity.

Canonical migration and receipts: `mere/design_docs/archive_docs/2026-10-28/2026-10-19_family_promotion_plan.md` (archived 2026-10-28); open items continue in `mere/design_docs/mere_docs/implementation_strategy/2026-10-28_family_promotion_plan.md`.

## Site generation and serving

- [Shared site extraction](2026-11-04_site_extraction_plan.md): native model and
  host libraries from Mere/Knot, checked Gemtext/Scroll/Markdown/HTML writer
  artifacts, and the locally qualified namespace/agreed-work keeper workflow.

Native site libraries landed, 2026-11-04: `gemot-site` and `gemot-site-host`
are consumed directly by Knot and Mere. The [site extraction plan](2026-11-04_site_extraction_plan.md)
records native qualification and the landed versioned Gemtext/Scroll/Markdown/HTML
writers (`generate`, `site-build`). Formats and protocols are separate choices; ordinary sites keep an
optional Moot adapter. CSS/assets and JavaScript/Lua extensions remain separately
scoped. Mere's site-publication plan retains resident and browser integration.

## Community authority and publishing

- [2026-11-03_moot_relay_pools_plan](moothold_docs/implementation_strategy/2026-11-03_moot_relay_pools_plan.md): P0/P1 native and P2 I2P relay pools; [qualification](archive_docs/receipts/2026-11-03_moot_relay_pools_plan_receipts.md) names exact scopes. P3a host composition, private control keys, bounded custody-client runner and shared preflight are implemented. Single-operator three-router preparation/execution lives in `scripts/relay_fleet{,_run}.py`; the public rehearsal passed with application workers on the controller. Actual operator custody, distributed workers and independent uplinks stay open; wider profiles remain P3b. Spaces is not adopted.
- [2026-11-01_moot_publication_plan](moothold_docs/implementation_strategy/2026-11-01_moot_publication_plan.md): live plan. Publication/hosting authority, honest retention, collections, co-op and addressed delivery; the November 4 findings record the first namespace/agreed-work keeper workflow and its remaining production boundaries.
- [2026-08-09_boundary_identity_and_grant_composition](moothold_docs/research/2026-08-09_boundary_identity_and_grant_composition.md): how the moot layer composes with a high-latency, multi-transport substrate.
- [2026-08-12_radio_scopes_as_moots](moothold_docs/research/2026-08-12_radio_scopes_as_moots.md): civic-deployment radio scopes modelled as moots; ratified 2026-08-12.
- [2026-09-05_author_offline_publication_proof](moothold_docs/research/2026-09-05_author_offline_publication_proof.md): the same-machine author-offline publication proof and its receipt.

The Moot object M1 plan (2026-06-12), with its landed work and run receipts, is
archived whole under `archive_docs/2026-11-01/`.

- [Source splits, H8](moothold_docs/implementation_strategy/2026-11-04_source_splits_plan.md): 13 additional originals landed, zero exceptions remain; Mere owns the aggregate and existing acceptance boundaries remain separate.
