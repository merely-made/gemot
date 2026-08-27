// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

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
