// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! A Moot's signed, amendable shared law.
//!
//! Constitution is a separate governance log beside Tessera. Tessera supplies
//! reputation facts; the constitution supplies the amendable rule that consumes
//! such facts. The first rule is founder-signed and feeds an explicit governed
//! checkpoint signer set.

mod event;
mod fold;
mod governance;
mod store;
mod wire;

#[cfg(test)]
mod sync;

pub use event::{AmendmentRule, CapabilityGrant, ConstitutionEvent, ConstitutionRules};
pub use fold::{Constitution, ConstitutionError, GovernedAction, authorize_governed};
pub use governance::{
    MootGovernance, MootGovernanceError, MootGovernanceFile, MootGovernanceSnapshot,
};
pub use store::{ConstitutionFileStore, ConstitutionStore, ConstitutionStoreError};
pub use wire::{
    ConstitutionExt, ConstitutionWireError, from_operation, to_operation, to_operation_seed, verify,
};
