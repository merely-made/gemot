//! The moot authorization seam over the TYPED capability vocabulary — the
//! capability-model round's OQ3 unification (ruled 2026-07-24: unify, on the
//! trait, when the caller exists; this is that caller).
//!
//! Both tiers already speak personae's signed delegation certificates: the
//! denizen tier through `servitor::DelegationTable`, the moot tier through
//! [`MootDelegations`]. What they did NOT share until now is the capability
//! vocabulary. [`MootGroup`]'s provider answers `capability_covers` from the
//! member's access level and **ignores the request's path entirely**, so a
//! Write member covers every capability — membership standing in for
//! authority.
//!
//! [`TypedMootAuthorization`] closes that: the request's `capability_path`
//! is parsed as a servitor [`Cap`] **at the seam** (D2's rule — strings are
//! parsed at boundaries, never compared inside a decision) and answered from
//! the moot's delegation certificates through the same `power/...` /
//! `scope/...` encoding servitor writes. A moot capability check and a
//! denizen capability check are now the SAME question in the SAME vocabulary
//! against the SAME certificate grammar; the two tiers differ only in where
//! chains root (a constitution grant here, the profile identity there).
//!
//! Typed means typed: a certificate issued with a raw path (`moot/fauna`)
//! does not answer a typed request, and a bare-string request parses as the
//! scope it always was — never accidentally a power. Moots that have not
//! adopted the typed vocabulary keep [`MootGroup`]'s membership provider or
//! raw [`MootDelegations::covers`]; there is no silent bridge between the
//! vocabularies, because a silent bridge is the F1 ambiguity again.

use servitor::{Cap, cap_path};

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

impl<M: MootAuthorizationProvider> MootAuthorizationProvider
    for TypedMootAuthorization<'_, M>
{
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::moot::constitution::CapabilityGrant;
    use crate::moot::delegation::{MOOT_ACT_ACTION, MOOT_DELEGATION_DOMAIN};
    use crate::moot::tessera::gate::TesseraFacts;
    use identity::delegation::{
        CapabilityScope, DelegationCertificate, DelegationParent, SignedDelegationCertificate,
    };
    use identity::{IdentityProvider, InMemoryProvider};

    const MOOT: [u8; 32] = [9; 32];
    const ROOT_GRANT: [u8; 32] = [7; 32];

    /// Membership-only stub: a member with standing, but a provider that is
    /// PATH-BLIND-DENYING — proving coverage comes from the typed layer, not
    /// smuggled through the inner provider.
    struct MemberOnly;

    impl MootAuthorizationProvider for MemberOnly {
        fn inputs(&self, _request: &MootAuthorizationRequest) -> MootAuthorizationInputs {
            MootAuthorizationInputs {
                capability_covers: false,
                facts: TesseraFacts {
                    is_member: true,
                    ..Default::default()
                },
            }
        }
    }

    /// A moot whose constitution roots one TYPED capability — the `curate`
    /// power — and delegates it to `member`.
    fn typed_moot(
        holder: &InMemoryProvider,
        member: &InMemoryProvider,
    ) -> (MootDelegations, ConstitutionRules) {
        let power = Cap::power("curate").unwrap();
        let mut rules =
            ConstitutionRules::founder_only(holder.master_public_key().to_bytes());
        rules.grant(CapabilityGrant {
            id: ROOT_GRANT,
            subject: holder.master_public_key().to_bytes(),
            path_prefix: cap_path(&power),
            not_before_ms: 10,
            expires_at_ms: Some(1_000),
            delegation_depth: 3,
        });
        let certificate = DelegationCertificate::new(
            DelegationParent::Root(ROOT_GRANT),
            holder.master_public_key().to_bytes(),
            member.master_public_key().to_bytes(),
            CapabilityScope {
                domain: MOOT_DELEGATION_DOMAIN.into(),
                resource: MOOT.to_vec(),
                path_prefix: cap_path(&power),
                actions: [MOOT_ACT_ACTION.to_string()].into_iter().collect(),
            },
            15,
            20,
            Some(900),
            0,
            [3; 32],
        );
        let signed = SignedDelegationCertificate::issue(holder, certificate).unwrap();
        let mut delegations = MootDelegations::new();
        delegations
            .accept_certificate(MOOT, &rules, signed)
            .unwrap();
        (delegations, rules)
    }

    fn request(subject: [u8; 32], capability: &str) -> MootAuthorizationRequest {
        MootAuthorizationRequest {
            subject,
            capability_path: capability.to_string(),
            at_ms: 500,
        }
    }

    #[test]
    fn a_typed_request_is_answered_from_the_delegation_chain() {
        let holder = InMemoryProvider::from_seed([1; 32]);
        let member = InMemoryProvider::from_seed([2; 32]);
        let (delegations, rules) = typed_moot(&holder, &member);
        let provider = TypedMootAuthorization {
            membership: &MemberOnly,
            delegations: &delegations,
            rules: &rules,
            moot_id: MOOT,
        };

        let inputs = provider.inputs(&request(
            member.master_public_key().to_bytes(),
            "power:curate",
        ));
        assert!(inputs.capability_covers, "the delegated power covers");
        assert!(inputs.facts.is_member, "membership facts pass through");

        // The membership stub denies path-blind, so this coverage came from
        // the certificate chain and nowhere else.
        let undelegated = provider.inputs(&request(
            holder.master_public_key().to_bytes(),
            "power:curate",
        ));
        assert!(
            !undelegated.capability_covers,
            "even the grant HOLDER does not cover without a certificate to the subject"
        );
    }

    #[test]
    fn powers_stay_closed_and_vocabularies_never_cross() {
        let holder = InMemoryProvider::from_seed([1; 32]);
        let member = InMemoryProvider::from_seed([2; 32]);
        let (delegations, rules) = typed_moot(&holder, &member);
        let provider = TypedMootAuthorization {
            membership: &MemberOnly,
            delegations: &delegations,
            rules: &rules,
            moot_id: MOOT,
        };
        let subject = member.master_public_key().to_bytes();

        assert!(
            !provider.inputs(&request(subject, "power:curate-admin")).capability_covers,
            "a longer power name is a different power (the F1 hazard, dead at the moot tier too)"
        );
        assert!(
            !provider.inputs(&request(subject, "curate")).capability_covers,
            "a bare string is the scope it always was, never accidentally the power"
        );
        assert!(
            !provider.inputs(&request(subject, "scope:curate")).capability_covers,
            "a scope spelled like the power is not the power"
        );
    }

    #[test]
    fn expiry_rides_the_certificate_not_the_seam() {
        let holder = InMemoryProvider::from_seed([1; 32]);
        let member = InMemoryProvider::from_seed([2; 32]);
        let (delegations, rules) = typed_moot(&holder, &member);
        let provider = TypedMootAuthorization {
            membership: &MemberOnly,
            delegations: &delegations,
            rules: &rules,
            moot_id: MOOT,
        };
        let subject = member.master_public_key().to_bytes();

        let mut late = request(subject, "power:curate");
        late.at_ms = 950; // past the certificate's 900 bound
        assert!(
            !provider.inputs(&late).capability_covers,
            "the certificate's own expiry decides, with no seam-side state"
        );
    }
}
