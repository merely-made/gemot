//! Tessera — the event-sourced community-trust receipt.
//!
//! Tessera is a **receipt of followed-through commitment**, not a coin. You earn
//! it by doing what you said (hosting, pinning, governance) and lose it by
//! visibly failing to (ghosting a commitment). Like the rest of the substrate it
//! is event-sourced: signed [`TesseraEvent`]s on the DAG are authoritative, and
//! the score is a [projection](ledger). It accrues against a persona-chain
//! **root**, so reputation is the cost of continuity and anonymity is the cost
//! of starting over.
//!
//! ## Layering (this is Phase 1)
//!
//! - [`event`] — the event grammar (the authoritative layer): the logical
//!   tessera events, decoupled from the operation wire (a later phase bridges
//!   them to signed operations, exactly as Murm's `Post` ↔ `Operation`).
//! - [`ledger`] — the projection: folds an event sequence into a per-chain-root
//!   score, deriving lapse from missing heartbeats. Deterministic integer math,
//!   so every peer computing it over the same events + clock agrees.
//! - [`store`] — the operation store over the muniment substrate (the shared
//!   `murm_replication::MunimentStore` adapter murm and mesh also ride): persists a moot's
//!   tessera operations, exposes the `LogStore` + `TopicStore` LogSync reconciles,
//!   and folds the moot-wide projection ([`fold_moot`](store::TesseraStore::fold_moot),
//!   every member's log into one ledger). Sync is host-composed after the
//!   sibling-posture purity split: gemot provides the store, wire-level
//!   admission, and fold, and the host builds the `LogSync` +
//!   `murm_replication::SyncedSpace` pump (the test-only `sync` module plays
//!   that host for the two-peer convergence tests).
//! - [`persona_chain`] (Phase 2) — the persona forest over the root-keyed ledger:
//!   resolves a leaf persona to its chain root + depth, and presents a
//!   depreciated *effective* score (the Sybil cost of a fresh face), while debt
//!   carries fully to forks (no laundering).
//! - [`concord`] (Phase 5) — the federation layer: reputation is per-moot
//!   primary, and a viewer moot's *composite* reputation folds its concorded
//!   moots' standings (one hop, weighted, schema-gated) under a moot-operator-
//!   chosen composition policy.
//! - [`reciprocity`] (Phase 5) — the t3 ILL facet: inter-moot give-and-take
//!   credits, where a freeloader moot runs up debt and is cut off.
//! - [`gate`] (Phase 4) — the §8.8 policy slot: tessera [facts](gate::TesseraFacts)
//!   plus a reference gate that allows an action only when a structural cap covers
//!   it *and* the facts clear the moot's threshold + rate limit.
//!
//! Tessera is the **facts** layer for the §8.8 capability stack's policy slot
//! (the score / freshness / role a policy engine reads); it is deliberately not
//! the policy *engine* (the Biscuit candidate) itself.

pub mod concord;
pub mod event;
pub mod gate;
pub mod ledger;
pub mod persona_chain;
pub mod persona_vault;
pub mod reciprocity;
pub mod store;
#[cfg(test)]
mod sync;
pub mod wire;

pub use crate::tessera::concord::{CompositionPolicy, MootId, RepLens};
pub use crate::tessera::event::{ChainRoot, CommitmentId, Scope, TesseraEvent};
pub use crate::tessera::gate::{
    DenyReason, GateConfig, GateDecision, Policy, TesseraFacts, authorize, may_act,
};
pub use crate::tessera::ledger::{Ledger, TesseraConfig};
pub use crate::tessera::persona_chain::{PersonaChains, PersonaId};
pub use crate::tessera::reciprocity::Reciprocity;
pub use crate::tessera::store::{TesseraFileStore, TesseraStore, TesseraStoreError};
pub use crate::tessera::wire::{TesseraExt, WireError, from_operation, to_operation, verify};
