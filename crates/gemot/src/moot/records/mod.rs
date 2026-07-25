//! The Moot's replicated public record: declaration, roster, fauna, and
//! retention checkpoints. This is one lane within a Moot, not the Moot's
//! application boundary.

pub mod retention;
pub mod roster;
pub mod store;
pub mod wire;

#[cfg(test)]
mod sync;

pub use retention::{
    AvailabilityPolicy, CheckpointError, ErasurePolicy, GovernedCheckpointAuthority, KeepBound,
    LogFrontier, MootRetentionPolicy, MootRosterSnapshot, PolicyRevision, RetentionCheckpoint,
};
pub use roster::{Declaration, FaunaEntry, Member, MootRoster, fauna_cap};
pub use store::{MootStore, MootStoreError, MootStoreFile, StoredCheckpoint};
pub use wire::{
    MootEvent, MootExt, MootLogId, WireError, from_operation, to_operation, to_operation_seed,
    to_prune_operation, to_prune_operation_seed, verify,
};
