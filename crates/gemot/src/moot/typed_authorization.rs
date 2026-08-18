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
//! is parsed as a shared [`Cap`] **at the seam** (D2's rule — strings are
//! parsed at boundaries, never compared inside a decision) and answered from
//! the moot's delegation certificates through the same `power/...` /
//! `scope/...` encoding servitor writes. A moot capability check and a
//! denizen capability check are now the SAME question in the SAME vocabulary
//! against the SAME certificate grammar; the two tiers differ only in where
//! chains root (a constitution grant here, the profile identity there).
//!
//! The unification runs BOTH directions, one type per seam:
//!
//! - [`TypedMootAuthorization`] is the **moot-facing** face: it answers
//!   gemot's own [`MootAuthorizationProvider`] seam from typed capabilities.
//! - [`MootAuthority`] is the **servitor-facing** face: it presents the same
//!   moot certificates as a [`servitor::AuthorityProvider`], so a moot peer's
//!   petition runs through the very `servitor::Gate` a script's and a wasm
//!   component's do. That is the participant-gate doctrine's third actor
//!   kind, and it needs no new gate — only this adapter.
//!
//! Typed means typed: a certificate issued with a raw path (`moot/fauna`)
//! does not answer a typed request, and a bare-string request parses as the
//! scope it always was — never accidentally a power. Moots that have not
//! adopted the typed vocabulary keep [`MootGroup`]'s membership provider or
//! raw [`MootDelegations::covers`]; there is no silent bridge between the
//! vocabularies, because a silent bridge is the F1 ambiguity again.

use capability::{Cap, Mode};
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
/// This is what makes "one gate for every denizen" true rather than aspirational:
/// a moot peer petitions a shared graph through the same `servitor::Gate` a
/// resident script or wasm component uses, with the same projection guard,
/// scope check, and attributed revision-checked commit. Only the AUTHORITY
/// differs — chains root at a constitutional capability grant here, at the
/// profile identity in turnstone's denizen table.
///
/// **Mode mapping.** The moot vocabulary carries a single action today
/// ([`MOOT_ACT_ACTION`](super::delegation::MOOT_ACT_ACTION)): holding it means
/// "may act in this scope", which satisfies [`Mode::Read`] and [`Mode::Write`].
/// [`Mode::Delegate`] is **not** answerable through this seam — a moot
/// expresses delegability as the certificate's `remaining_delegation_depth`,
/// a different axis from its action set — so a delegate-mode need fails
/// closed here rather than being approximated by "act".
pub struct MootAuthority<'a> {
    /// The moot's converged delegation certificates.
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
        self.delegations.covers(
            self.moot_id,
            self.rules,
            subject.0,
            &cap_path(needed),
            self.now_ms,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::moot::constitution::CapabilityGrant;
    use crate::moot::delegation::{MOOT_ACT_ACTION, MOOT_DELEGATION_DOMAIN};
    use crate::moot::tessera::gate::TesseraFacts;
    use capability::ScopePath;
    use chartulary::{Container, EditSpec, GraphLog, Relation};
    use identity::delegation::{
        CapabilityScope, DelegationCertificate, DelegationId, DelegationParent,
        DelegationRevocation, SignedDelegationCertificate, SignedDelegationRevocation,
    };
    use identity::{IdentityProvider, InMemoryProvider};
    use servitor::{Gate, GateError};

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
        let (delegations, rules, _) =
            typed_moot_for(holder, member, &Cap::power("curate").unwrap());
        (delegations, rules)
    }

    /// The same, over any typed capability, returning the certificate id so a
    /// test can revoke it.
    fn typed_moot_for(
        holder: &InMemoryProvider,
        member: &InMemoryProvider,
        power: &Cap,
    ) -> (MootDelegations, ConstitutionRules, DelegationId) {
        let mut rules = ConstitutionRules::founder_only(holder.master_public_key().to_bytes());
        rules.grant(CapabilityGrant {
            id: ROOT_GRANT,
            subject: holder.master_public_key().to_bytes(),
            path_prefix: cap_path(power),
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
                path_prefix: cap_path(power),
                actions: [MOOT_ACT_ACTION.to_string()].into_iter().collect(),
            },
            15,
            20,
            Some(900),
            0,
            [3; 32],
        );
        let signed = SignedDelegationCertificate::issue(holder, certificate).unwrap();
        let id = signed.certificate.id();
        let mut delegations = MootDelegations::new();
        delegations
            .accept_certificate(MOOT, &rules, signed)
            .unwrap();
        (delegations, rules, id)
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
            !provider
                .inputs(&request(subject, "power:curate-admin"))
                .capability_covers,
            "a longer power name is a different power (the F1 hazard, dead at the moot tier too)"
        );
        assert!(
            !provider
                .inputs(&request(subject, "curate"))
                .capability_covers,
            "a bare string is the scope it always was, never accidentally the power"
        );
        assert!(
            !provider
                .inputs(&request(subject, "scope:curate"))
                .capability_covers,
            "a scope spelled like the power is not the power"
        );
    }

    #[test]
    fn facet_namespaces_use_the_shared_order_at_the_moot_tier() {
        let holder = InMemoryProvider::from_seed([1; 32]);
        let member = InMemoryProvider::from_seed([2; 32]);
        let (delegations, rules, _) =
            typed_moot_for(&holder, &member, &Cap::facet("web.").unwrap());
        let provider = TypedMootAuthorization {
            membership: &MemberOnly,
            delegations: &delegations,
            rules: &rules,
            moot_id: MOOT,
        };
        let subject = member.master_public_key().to_bytes();

        assert!(
            provider
                .inputs(&request(subject, "facet:web.viewer"))
                .capability_covers,
            "the web namespace covers one of its facets"
        );
        assert!(
            !provider
                .inputs(&request(subject, "facet:website.viewer"))
                .capability_covers,
            "dot segments, not raw string prefixes, define containment"
        );
        assert!(
            !provider
                .inputs(&request(subject, "facet:denizen.binding"))
                .capability_covers,
            "a different facet family is outside the grant"
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

    // ── The peer lane: one gate, three actor kinds ────────────────────────

    /// The participant-gate doctrine's third actor kind, made real: a moot
    /// peer petitions a shared graph through the SAME `servitor::Gate` a
    /// resident script or wasm component uses. No peer-specific gate, no
    /// second authority model — only a different root for the chain.
    #[test]
    fn a_moot_peer_petitions_a_shared_graph_through_the_same_gate() {
        let holder = InMemoryProvider::from_seed([1; 32]);
        let peer = InMemoryProvider::from_seed([2; 32]);
        let shared = Cap::scope("shared").unwrap();
        let (delegations, rules, _) = typed_moot_for(&holder, &peer, &shared);
        let authority = MootAuthority {
            delegations: &delegations,
            rules: &rules,
            moot_id: MOOT,
            now_ms: 500,
        };
        let peer_subject = Subject::new(peer.master_public_key().to_bytes());
        let gate = Gate::new();
        let mut graph = GraphLog::<Container, Relation>::new();
        let claimed = ScopePath::parse("shared").unwrap();

        // In scope: commits, attributed to the PEER — the same attributed
        // revision-checked commit a denizen gets.
        let revision = graph.revision();
        let committed = gate
            .petition(
                &authority,
                &mut graph,
                peer_subject,
                &claimed,
                revision,
                vec![EditSpec::InsertNode(Container::new("shared/note"))],
            )
            .expect("a delegated peer's in-scope petition commits");
        let entry = &graph.log().entries()[committed.batch.0 as usize];
        assert_eq!(
            entry.author,
            peer_subject.to_author(),
            "attributed to the peer"
        );
        assert_eq!(graph.graph().node_count(), 1);

        // Out of scope: the gate's own scope check, unchanged.
        let revision = graph.revision();
        let err = gate
            .petition(
                &authority,
                &mut graph,
                peer_subject,
                &claimed,
                revision,
                vec![EditSpec::InsertNode(Container::new("private/secret"))],
            )
            .unwrap_err();
        assert!(matches!(err, GateError::OutOfScope { .. }), "{err:?}");

        // An undelegated peer: refused, though it is a real identity.
        let stranger = Subject::new(
            InMemoryProvider::from_seed([9; 32])
                .master_public_key()
                .to_bytes(),
        );
        let revision = graph.revision();
        let err = gate
            .petition(
                &authority,
                &mut graph,
                stranger,
                &claimed,
                revision,
                vec![EditSpec::InsertNode(Container::new("shared/intrusion"))],
            )
            .unwrap_err();
        assert!(matches!(err, GateError::Unauthorized { .. }), "{err:?}");
        assert_eq!(graph.graph().node_count(), 1, "nothing else applied");
    }

    /// Revoking the moot certificate stops the peer AT THE GATE — the moot
    /// tier's revocation reaching the same petition path the denizen tier's
    /// uninstall reaches.
    #[test]
    fn revoking_the_moot_certificate_stops_the_peer_at_the_gate() {
        let holder = InMemoryProvider::from_seed([1; 32]);
        let peer = InMemoryProvider::from_seed([2; 32]);
        let shared = Cap::scope("shared").unwrap();
        let (mut delegations, rules, certificate) = typed_moot_for(&holder, &peer, &shared);
        let peer_subject = Subject::new(peer.master_public_key().to_bytes());
        let gate = Gate::new();
        let mut graph = GraphLog::<Container, Relation>::new();
        let claimed = ScopePath::parse("shared").unwrap();

        let revocation = DelegationRevocation::new(
            certificate,
            holder.master_public_key().to_bytes(),
            CapabilityScope {
                domain: MOOT_DELEGATION_DOMAIN.into(),
                resource: MOOT.to_vec(),
                path_prefix: cap_path(&shared),
                actions: [MOOT_ACT_ACTION.to_string()].into_iter().collect(),
            },
            400,
            [5; 32],
        );
        delegations
            .accept_revocation(SignedDelegationRevocation::issue(&holder, revocation).unwrap())
            .unwrap();

        let authority = MootAuthority {
            delegations: &delegations,
            rules: &rules,
            moot_id: MOOT,
            now_ms: 500,
        };
        let revision = graph.revision();
        let err = gate
            .petition(
                &authority,
                &mut graph,
                peer_subject,
                &claimed,
                revision,
                vec![EditSpec::InsertNode(Container::new("shared/after"))],
            )
            .unwrap_err();
        assert!(matches!(err, GateError::Unauthorized { .. }), "{err:?}");
        assert_eq!(
            graph.graph().node_count(),
            0,
            "nothing applied after revocation"
        );
    }

    #[test]
    fn delegate_mode_fails_closed_rather_than_approximating_act() {
        // The moot expresses delegability as certificate depth, not as an
        // action, so this seam refuses to answer for it.
        let holder = InMemoryProvider::from_seed([1; 32]);
        let peer = InMemoryProvider::from_seed([2; 32]);
        let shared = Cap::scope("shared").unwrap();
        let (delegations, rules, _) = typed_moot_for(&holder, &peer, &shared);
        let authority = MootAuthority {
            delegations: &delegations,
            rules: &rules,
            moot_id: MOOT,
            now_ms: 500,
        };
        let peer_subject = Subject::new(peer.master_public_key().to_bytes());
        assert!(authority.covers(peer_subject, &shared, Mode::Write));
        assert!(
            authority.covers(peer_subject, &shared, Mode::Read),
            "act implies read"
        );
        assert!(!authority.covers(peer_subject, &shared, Mode::Delegate));
    }

    // ── The commons, as converged authority sees it ───────────────────────

    /// `MootPolicy::admit` accepts a `Shared` event on wire grammar and moot
    /// address alone, so the raw fauna is whatever anyone put there. The
    /// authorized projection is the capability answer over it — and it is
    /// evaluated at READ, because authority converges separately from the
    /// operations it authorizes.
    #[test]
    fn the_authorized_commons_filters_shares_by_capability() {
        use crate::moot::records::{FaunaEntry, MootRoster};

        let holder = InMemoryProvider::from_seed([1; 32]);
        let sharer = InMemoryProvider::from_seed([2; 32]);
        let stranger = InMemoryProvider::from_seed([3; 32]);
        // The moot roots the fauna capability and delegates it to `sharer`.
        let (delegations, rules, _) =
            typed_moot_for(&holder, &sharer, &crate::moot::records::fauna_cap());

        // Two contributions to the commons: one from the delegated sharer,
        // one from an identity that was never granted anything.
        let mut roster = MootRoster::default();
        let entry = |who: &InMemoryProvider, title: &str, tag: u8| FaunaEntry {
            manifest_id: [tag; 32],
            schema_id: "mere.pack/v1".into(),
            title: title.into(),
            shared_by: who.master_public_key().to_bytes(),
            at_ms: 100,
            op_hash: [tag; 32],
        };
        roster.fauna.push(entry(&sharer, "granted", 1));
        roster.fauna.push(entry(&stranger, "ungranted", 2));

        let authority = MootAuthority {
            delegations: &delegations,
            rules: &rules,
            moot_id: MOOT,
            now_ms: 500,
        };
        let authorized = roster.authorized_fauna(&authority);
        assert_eq!(authorized.len(), 1, "only the delegated share counts");
        assert_eq!(authorized[0].title, "granted");
        assert_eq!(
            roster.fauna.len(),
            2,
            "the unfiltered record keeps both, so a surface can show the other as pending"
        );
    }

    /// The read-time property that makes this the right layer: revoking the
    /// sharer's certificate removes their contribution from the commons with
    /// **no change to stored operations**. Nothing was discarded on the way
    /// in, and nothing has to be rewritten on the way out.
    #[test]
    fn revoking_a_sharer_withdraws_their_contribution_without_touching_storage() {
        use crate::moot::records::{FaunaEntry, MootRoster};

        let holder = InMemoryProvider::from_seed([1; 32]);
        let sharer = InMemoryProvider::from_seed([2; 32]);
        let fauna = crate::moot::records::fauna_cap();
        let (mut delegations, rules, certificate) = typed_moot_for(&holder, &sharer, &fauna);

        let mut roster = MootRoster::default();
        roster.fauna.push(FaunaEntry {
            manifest_id: [1; 32],
            schema_id: "mere.pack/v1".into(),
            title: "contribution".into(),
            shared_by: sharer.master_public_key().to_bytes(),
            at_ms: 100,
            op_hash: [1; 32],
        });

        let visible = |delegations: &MootDelegations| {
            roster
                .authorized_fauna(&MootAuthority {
                    delegations,
                    rules: &rules,
                    moot_id: MOOT,
                    now_ms: 500,
                })
                .len()
        };
        assert_eq!(
            visible(&delegations),
            1,
            "visible while the certificate stands"
        );

        let revocation = DelegationRevocation::new(
            certificate,
            holder.master_public_key().to_bytes(),
            CapabilityScope {
                domain: MOOT_DELEGATION_DOMAIN.into(),
                resource: MOOT.to_vec(),
                path_prefix: cap_path(&fauna),
                actions: [MOOT_ACT_ACTION.to_string()].into_iter().collect(),
            },
            400,
            [5; 32],
        );
        delegations
            .accept_revocation(SignedDelegationRevocation::issue(&holder, revocation).unwrap())
            .unwrap();

        assert_eq!(
            visible(&delegations),
            0,
            "withdrawn from the commons on revocation"
        );
        assert_eq!(
            roster.fauna.len(),
            1,
            "and the stored record is untouched: authority decided, not the log"
        );
    }
}
