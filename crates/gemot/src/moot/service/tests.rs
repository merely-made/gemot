// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;
use crate::moot::constitution::CapabilityGrant;
use crate::moot::delegation::{MOOT_ACT_ACTION, MOOT_DELEGATION_DOMAIN};
use crate::moot::tulpa::{TulpaEvent, TulpaId, TulpaProposal, TulpaProposalId, TulpaVersion};
use crate::moot::{
    ArtifactRef, FloraEvent, FloraParticipant, FloraRoundId, FloraRoundSpec, FloraWeight,
    KeepBound, MootAccessLevel, MootMember, MootMembershipAction, MootStoreError,
};
use identity::delegation::Issue;
use identity::{IdentityProvider, InMemoryProvider};
use insigne::delegation::{
    CapabilityScope, DelegationCertificate, DelegationParent, DelegationRevocation,
    SignedDelegationCertificate, SignedDelegationRevocation, delegation_signing_salt,
};
use mien::{ChainRoot, DenyReason, GateConfig, GateDecision, Policy, StandingEvent, StandingFacts};
use mooting::{ElectorateSnapshot, RecognitionContext, RecognitionPolicy};
use p2panda_core::cbor::decode_cbor;
use std::collections::BTreeMap;
use std::io::Cursor;
use stickleback::NativeDropError;

const ID: MootId = MootId([0x6d; 32]);

fn keypair(seed: u8) -> identity::Ed25519Keypair {
    InMemoryProvider::from_seed([seed; 32])
        .derive_keypair(b"moot-service")
        .unwrap()
}

fn retention() -> MootRetentionSettings {
    MootRetentionSettings {
        revision: PolicyRevision(Digest::blake3(b"moot retention settings")),
        availability: AvailabilityPolicy {
            promised_floor: KeepBound::Forever,
        },
        erasure: ErasurePolicy {
            history_ceiling: KeepBound::UntilCheckpoint,
        },
    }
}

struct Access {
    capability_covers: bool,
    facts: StandingFacts,
}

impl MootAuthorizationProvider for Access {
    fn inputs(&self, _: &MootAuthorizationRequest) -> MootAuthorizationInputs {
        MootAuthorizationInputs {
            capability_covers: self.capability_covers,
            facts: self.facts.clone(),
        }
    }
}

struct TestProtector;

impl DropProtector for TestProtector {
    fn suite_id(&self) -> u16 {
        77
    }

    fn protect(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, NativeDropError> {
        Ok(plaintext
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ aad[index % aad.len()])
            .collect())
    }

    fn unprotect(
        &self,
        protected: &[u8],
        aad: &[u8],
        max_plaintext_bytes: u64,
    ) -> Result<Vec<u8>, NativeDropError> {
        if protected.len() as u64 > max_plaintext_bytes {
            return Err(NativeDropError::Limit {
                limit: "test plaintext bytes",
                actual: protected.len() as u64,
                maximum: max_plaintext_bytes,
            });
        }
        self.protect(protected, aad)
    }
}

#[path = "tests/authority.rs"]
mod authority;

#[path = "tests/drop.rs"]
mod drop;

#[path = "tests/history.rs"]
mod history;
