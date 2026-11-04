// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The moot authorization seam over the TYPED capability vocabulary — the
//! capability-model round's OQ3 unification (ruled 2026-07-24: unify, on the
//! trait, when the caller exists; this is that caller).
//!
//! Both tiers already speak personae's signed delegation certificates: the
//! participant tier through `servitor::DelegationTable`, the moot tier through
//! [`MootDelegations`]. What they did NOT share until now is the capability
//! vocabulary. [`MootGroup`](super::group::MootGroup)'s provider answers `capability_covers` from the
//! member's access level and **ignores the request's path entirely**, so a
//! Write member covers every capability — membership standing in for
//! authority.
//!
//! [`TypedMootAuthorization`] closes that: the request's `capability_path`
//! is parsed as a shared [`Cap`] **at the seam** (D2's rule — strings are
//! parsed at boundaries, never compared inside a decision) and answered from
//! the moot's delegation certificates through the same `power/...` /
//! `scope/...` encoding servitor writes. A moot capability check and a
//! participant capability check are now the SAME question in the SAME vocabulary
//! against the SAME certificate grammar; the two tiers differ only in where
//! chains root (a constitution grant here, the profile identity there).
//!
//! The unification runs BOTH directions, one type per seam:
//!
//! - [`TypedMootAuthorization`] is the **moot-facing** face: it answers
//!   gemot's own [`MootAuthorizationProvider`] seam from typed capabilities.
//! - [`MootAuthority`] is the **servitor-facing** face: it presents direct
//!   constitutional grants and moot certificates as a
//!   [`servitor::AuthorityProvider`], so a moot peer's
//!   petition runs through the very `servitor::Gate` a script's and a wasm
//!   component's do. That is the participant-gate doctrine's third actor
//!   kind, and it needs no new gate — only this adapter.
//!
//! Typed means typed: a certificate issued with a raw path (`moot/fauna`)
//! does not answer a typed request, and a bare-string request parses as the
//! scope it always was — never accidentally a power. Moots that have not
//! adopted the typed vocabulary keep [`MootGroup`](super::group::MootGroup)'s membership provider or
//! raw [`MootDelegations::covers`]; there is no silent bridge between the
//! vocabularies, because a silent bridge is the F1 ambiguity again.

use servitor::cap::{Cap, Mode};
use servitor::{AuthorityProvider, Subject, cap_path};

use super::constitution::ConstitutionRules;
use super::delegation::MootDelegations;
use super::service::{
    MootAuthorizationInputs, MootAuthorizationProvider, MootAuthorizationRequest,
};

/// A provider that composes membership facts (from any inner provider —
/// [`MootGroup`](super::group::MootGroup) in production) with typed
/// capability coverage from the moot's delegation certificates.
///
/// The inner provider's `capability_covers` is deliberately DISCARDED: this
/// provider exists to replace path-blind membership authority with per-path
/// delegated authority. Its facts (membership, standing) pass through
/// unchanged.
pub struct TypedMootAuthorization<'a, M: MootAuthorizationProvider> {
    /// The membership/standing source; its facts pass through.
    pub membership: &'a M,
    /// The moot's converged delegation certificates.
    pub delegations: &'a MootDelegations,
    /// The accepted constitution, whose capability grants root the chains.
    pub rules: &'a ConstitutionRules,
    /// Which moot's scopes count.
    pub moot_id: [u8; 32],
}

impl<M: MootAuthorizationProvider> MootAuthorizationProvider for TypedMootAuthorization<'_, M> {
    fn inputs(&self, request: &MootAuthorizationRequest) -> MootAuthorizationInputs {
        let membership = self.membership.inputs(request);
        // Parse at the seam; an unparseable capability fails closed.
        let capability_covers = Cap::parse(&request.capability_path)
            .ok()
            .is_some_and(|cap| {
                self.delegations.covers(
                    self.moot_id,
                    self.rules,
                    request.subject,
                    &cap_path(&cap),
                    request.at_ms,
                )
            });
        MootAuthorizationInputs {
            capability_covers,
            facts: membership.facts,
        }
    }
}

/// The moot's delegated authority as a **servitor** [`AuthorityProvider`].
///
/// This is what makes "one gate for every participant" true rather than aspirational:
/// a moot peer petitions a shared graph through the same `servitor::Gate` a
/// resident script or wasm component uses, with the same projection guard,
/// scope check, and attributed revision-checked commit. Only the AUTHORITY
/// differs — chains root at a constitutional capability grant here, at the
/// profile identity in turnstone's participant table.
///
/// **Mode mapping.** The moot vocabulary carries a single action today
/// ([`MOOT_ACT_ACTION`](super::delegation::MOOT_ACT_ACTION)): holding it means
/// "may act in this scope", which satisfies [`Mode::Read`] and [`Mode::Write`].
/// [`Mode::Delegate`] is **not** answerable through this seam — a moot
/// expresses delegability as the certificate's `remaining_delegation_depth`,
/// a different axis from its action set — so a delegate-mode need fails
/// closed here rather than being approximated by "act".
pub struct MootAuthority<'a> {
    /// The moot's converged delegation certificates, beside direct grants in
    /// `rules`.
    pub delegations: &'a MootDelegations,
    /// The accepted constitution, whose capability grants root the chains.
    pub rules: &'a ConstitutionRules,
    /// Which moot's scopes count.
    pub moot_id: [u8; 32],
    /// The host-set evaluation clock. Gemot and servitor both take time as
    /// input; neither reads a clock of its own.
    pub now_ms: u64,
}

impl AuthorityProvider for MootAuthority<'_> {
    fn covers(&self, subject: Subject, needed: &Cap, mode: Mode) -> bool {
        if matches!(mode, Mode::Delegate) {
            // Not expressible in the moot action vocabulary; see the type doc.
            return false;
        }
        let path = cap_path(needed);
        self.rules.grant_covers(subject.0, &path, self.now_ms)
            || self
                .delegations
                .covers(self.moot_id, self.rules, subject.0, &path, self.now_ms)
    }
}

#[cfg(test)]
#[path = "typed_authorization/tests.rs"]
mod tests;
