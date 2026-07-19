// Copyright 2026 Mark Boykin
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::{Deserialize, Serialize};

use crate::{CompositionPolicy, MootId};

/// Stable identity of a holding of autonomous moots.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MootholdId(pub [u8; 32]);

/// Settings governing one member moot's direct relationship to the holding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberTerms {
    /// Weight assigned to this moot's reputation facts, in basis points.
    pub concord_weight_bp: u16,
    /// Unreciprocated service credit tolerated before further requests stop.
    pub reciprocity_tolerance: u64,
}

impl MemberTerms {
    pub const MAX_CONCORD_WEIGHT_BP: u16 = 10_000;

    pub fn new(concord_weight_bp: u16, reciprocity_tolerance: u64) -> Option<Self> {
        (concord_weight_bp <= Self::MAX_CONCORD_WEIGHT_BP).then_some(Self {
            concord_weight_bp,
            reciprocity_tolerance,
        })
    }

    pub(crate) fn is_valid(self) -> bool {
        self.concord_weight_bp <= Self::MAX_CONCORD_WEIGHT_BP
    }
}

/// Founder-signed changes to one Moothold aggregate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MootholdEvent {
    Founded {
        moothold_id: MootholdId,
        name: String,
        founder: [u8; 32],
        initial_moot: MootId,
        initial_terms: MemberTerms,
        composition: CompositionPolicy,
        at_ms: u64,
    },
    MootAdmitted {
        previous: [u8; 32],
        moot: MootId,
        terms: MemberTerms,
        at_ms: u64,
    },
    MootRemoved {
        previous: [u8; 32],
        moot: MootId,
        at_ms: u64,
    },
    CompositionChanged {
        previous: [u8; 32],
        composition: CompositionPolicy,
        at_ms: u64,
    },
}

impl MootholdEvent {
    pub(crate) fn previous(&self) -> Option<[u8; 32]> {
        match self {
            Self::Founded { .. } => None,
            Self::MootAdmitted { previous, .. }
            | Self::MootRemoved { previous, .. }
            | Self::CompositionChanged { previous, .. } => Some(*previous),
        }
    }

    pub(crate) fn is_well_formed(&self) -> bool {
        match self {
            Self::Founded {
                name,
                initial_terms,
                ..
            } => !name.trim().is_empty() && initial_terms.is_valid(),
            Self::MootAdmitted { terms, .. } => terms.is_valid(),
            Self::MootRemoved { .. } | Self::CompositionChanged { .. } => true,
        }
    }
}
