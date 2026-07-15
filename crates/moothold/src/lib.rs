//! Tier 3 federation for autonomous Gemot moots.
//!
//! A moothold is a holding of moots. It owns direct concords and reciprocal
//! resource sharing between member communities while each Moot retains its own
//! law, reputation facts, storage, and ability to fork.

#![doc(html_root_url = "https://docs.rs/moothold/0.1.0")]

pub mod concord;
mod event;
mod fold;
pub mod reciprocity;
mod store;
mod wire;

pub use concord::{CompositionPolicy, MootId, RepLens};
pub use event::{MemberTerms, MootholdEvent, MootholdId};
pub use fold::{Moothold, MootholdError};
pub use reciprocity::Reciprocity;
pub use store::{MootholdFileStore, MootholdStore, MootholdStoreError};
pub use wire::{MootholdExt, MootholdWireError, from_operation, to_operation_seed, verify};

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
