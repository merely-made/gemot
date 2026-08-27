// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! # Mooting
//!
//! Recognition policy for governed Moot spaces.
//!
//! [`RecognitionContext`] evaluates a recognition policy against a membership
//! set frozen at one signed revision. Generic replicated storage lives in the
//! sibling `stickleback` crate.
//!
//! ## Status
//!
//! Pre-1.0. Recognition policy is implemented; domain folds stay in Gemot.

#![doc(html_root_url = "https://docs.rs/mooting/0.1.0")]

pub mod recognition;

pub use recognition::{
    ElectorateSnapshot, MemberKey, RecognitionContext, RecognitionDecision, RecognitionPolicy,
    RecognitionPolicyError,
};

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Lifecycle stage marker.
pub const STAGE: &str = "pre-alpha";
