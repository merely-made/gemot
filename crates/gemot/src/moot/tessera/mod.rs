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
//!   `stickleback::MunimentStore` adapter murm and mesh also ride): persists a moot's
//!   tessera operations, exposes the `LogStore` + `TopicStore` LogSync reconciles,
//!   and folds the moot-wide projection ([`fold_moot`](store::TesseraStore::fold_moot),
//!   every member's log into one ledger). Sync is host-composed after the
//!   sibling-posture purity split: gemot provides the store, wire-level
//!   admission, and fold, and the host builds the `LogSync` +
//!   `stickleback::SyncedSpace` pump (the test-only `sync` module plays
//!   that host for the two-peer convergence tests).
//! - [`persona_chain`] (Phase 2) — the persona forest over the root-keyed ledger:
//!   resolves a leaf persona to its chain root + depth, and presents a
//!   depreciated *effective* score (the Sybil cost of a fresh face), while debt
//!   carries fully to forks (no laundering).
//!
//! Federation-level concord and reciprocity consume these facts from the
//! separate `moothold` crate; they are not per-Moot Tessera state.
//! - [`gate`] (Phase 4) — the §8.8 policy slot: tessera [facts](gate::TesseraFacts)
//!   plus a reference gate that allows an action only when a structural cap covers
//!   it *and* the facts clear the moot's threshold + rate limit.
//!
//! Tessera is the **facts** layer for the §8.8 capability stack's policy slot
//! (the score / freshness / role a policy engine reads); it is deliberately not
//! the policy *engine* (the Biscuit candidate) itself.

pub mod event;
pub mod gate;
pub mod ledger;
pub mod persona_chain;
pub mod persona_vault;
pub mod store;
#[cfg(test)]
mod sync;
pub mod wire;

pub use crate::moot::tessera::event::{ChainRoot, CommitmentId, Scope, TesseraEvent};
pub use crate::moot::tessera::gate::{
    DenyReason, GateConfig, GateDecision, Policy, TesseraFacts, authorize, may_act,
};
pub use crate::moot::tessera::ledger::{Ledger, TesseraConfig};
pub use crate::moot::tessera::persona_chain::{PersonaChains, PersonaId};
pub use crate::moot::tessera::store::{TesseraFileStore, TesseraStore, TesseraStoreError};
pub use crate::moot::tessera::wire::{
    TesseraExt, WireError, from_operation, to_operation, to_operation_seed, verify,
};
