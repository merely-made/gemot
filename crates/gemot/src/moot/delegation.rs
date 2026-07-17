//! Independent capability delegation beneath constitutional grant roots.
//!
//! Personae owns portable certificates, signing-key proofs, and attenuation.
//! Gemot owns the meaning of a Moot root and the converged current grant set.
//! Participant graphs may project this state for inspection, but graph
//! statements are never accepted as authority by this fold.

use std::collections::{BTreeMap, BTreeSet};

use identity::delegation::{
    CapabilityScope, DelegationCertificate, DelegationId, DelegationParent,
    SignedDelegationCertificate, SignedDelegationRevocation,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::constitution::{CapabilityGrant, ConstitutionRules};

mod store;
mod wire;

pub use store::{MootDelegationFileStore, MootDelegationStore, MootDelegationStoreError};
pub use wire::{
    MootDelegationExt, MootDelegationWireError, from_operation, to_operation, to_operation_seed,
    verify,
};

/// Personae delegation domain assigned to Moot authority.
pub const MOOT_DELEGATION_DOMAIN: &str = "moot";
/// Current Gemot capability action. The structural request path carries the
/// finer operation vocabulary until the gate grows a typed action field.
pub const MOOT_ACT_ACTION: &str = "act";

/// One portable statement in a Moot's independent delegation lane.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MootDelegationEvent {
    /// Introduce a signed, independently verifiable child certificate.
    Issued(SignedDelegationCertificate),
    /// Withdraw a certificate under its original issuer's authority.
    Revoked(SignedDelegationRevocation),
}

impl MootDelegationEvent {
    /// Issuer-asserted authored time committed by the inner signature.
    pub fn at_ms(&self) -> u64 {
        match self {
            Self::Issued(signed) => signed.certificate.issued_at_ms,
            Self::Revoked(signed) => signed.revocation.at_ms,
        }
    }

    fn signer(&self) -> Option<[u8; 32]> {
        let signer = match self {
            Self::Issued(signed) => &signed.signer,
            Self::Revoked(signed) => &signed.signer,
        };
        signer.derived_public_key().ok().map(|key| key.to_bytes())
    }

    fn verifies(&self) -> bool {
        match self {
            Self::Issued(signed) => signed.verify(),
            Self::Revoked(signed) => signed.verify(),
        }
    }

    fn scope(&self) -> &CapabilityScope {
        match self {
            Self::Issued(signed) => &signed.certificate.scope,
            Self::Revoked(signed) => &signed.revocation.scope,
        }
    }
}

/// Current independently delegated grants for one Moot.
#[derive(Clone, Debug, Default)]
pub struct MootDelegations {
    certificates: BTreeMap<DelegationId, SignedDelegationCertificate>,
    revoked: BTreeSet<DelegationId>,
}

impl MootDelegations {
    /// Start with no independently delegated authority.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of accepted certificate records, including currently revoked
    /// certificates retained for audit and descendant resolution.
    pub fn certificate_count(&self) -> usize {
        self.certificates.len()
    }

    /// Accept a signed certificate beneath a currently valid root or parent.
    ///
    /// Parents must arrive first. A durable p2panda lane expresses this as an
    /// operation dependency and can retry a child after its parent arrives.
    pub fn accept_certificate(
        &mut self,
        moot_id: [u8; 32],
        rules: &ConstitutionRules,
        signed: SignedDelegationCertificate,
    ) -> Result<bool, MootDelegationError> {
        if !signed.verify() {
            return Err(MootDelegationError::InvalidSignature);
        }
        let certificate = &signed.certificate;
        if !is_moot_scope(&certificate.scope, moot_id) {
            return Err(MootDelegationError::WrongMoot);
        }
        match certificate.parent {
            DelegationParent::Root(root_id) => {
                let root = rules
                    .capability_grants
                    .get(&root_id)
                    .ok_or(MootDelegationError::UnknownRoot)?;
                if !attenuates_root(certificate, root, moot_id) {
                    return Err(MootDelegationError::Escalation);
                }
            }
            DelegationParent::Certificate(parent_id) => {
                let parent = self
                    .certificates
                    .get(&parent_id)
                    .ok_or(MootDelegationError::UnknownParent)?;
                if !self.chain_is_live(parent_id, rules, moot_id) {
                    return Err(MootDelegationError::InactiveParent);
                }
                if !certificate.attenuates(&parent.certificate) {
                    return Err(MootDelegationError::Escalation);
                }
            }
        }

        let id = certificate.id();
        match self.certificates.get(&id) {
            Some(existing) if existing == &signed => Ok(false),
            Some(_) => Err(MootDelegationError::IdentifierCollision),
            None => {
                self.certificates.insert(id, signed);
                Ok(true)
            }
        }
    }

    /// Accept a signed revocation by the certificate's original issuer.
    pub fn accept_revocation(
        &mut self,
        signed: SignedDelegationRevocation,
    ) -> Result<bool, MootDelegationError> {
        if !signed.verify() {
            return Err(MootDelegationError::InvalidSignature);
        }
        let target = self
            .certificates
            .get(&signed.revocation.certificate)
            .ok_or(MootDelegationError::UnknownCertificate)?;
        if target.certificate.issuer != signed.revocation.issuer
            || target.certificate.scope != signed.revocation.scope
        {
            return Err(MootDelegationError::WrongRevoker);
        }
        Ok(self.revoked.insert(signed.revocation.certificate))
    }

    /// Whether one identity currently holds a live delegated capability.
    ///
    /// Removing or narrowing the constitutional root immediately invalidates
    /// its descendants. Revoking any certificate invalidates its full subtree.
    pub fn covers(
        &self,
        moot_id: [u8; 32],
        rules: &ConstitutionRules,
        subject: [u8; 32],
        path: &str,
        at_ms: u64,
    ) -> bool {
        self.certificates.iter().any(|(id, signed)| {
            signed.certificate.subject == subject
                && is_moot_scope(&signed.certificate.scope, moot_id)
                && signed.certificate.covers(path, MOOT_ACT_ACTION, at_ms)
                && self.chain_is_live(*id, rules, moot_id)
        })
    }

    fn chain_is_live(
        &self,
        id: DelegationId,
        rules: &ConstitutionRules,
        moot_id: [u8; 32],
    ) -> bool {
        if self.revoked.contains(&id) {
            return false;
        }
        let Some(signed) = self.certificates.get(&id) else {
            return false;
        };
        match signed.certificate.parent {
            DelegationParent::Root(root_id) => rules
                .capability_grants
                .get(&root_id)
                .is_some_and(|root| attenuates_root(&signed.certificate, root, moot_id)),
            DelegationParent::Certificate(parent) => {
                self.chain_is_live(parent, rules, moot_id)
                    && self
                        .certificates
                        .get(&parent)
                        .is_some_and(|parent| signed.certificate.attenuates(&parent.certificate))
            }
        }
    }
}

/// Rejection while folding independent Moot delegation state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum MootDelegationError {
    /// Certificate or revocation signature/identity proof failed.
    #[error("delegation signature or identity proof is invalid")]
    InvalidSignature,
    /// Certificate is bound to a different Moot id.
    #[error("delegation addresses another Moot")]
    WrongMoot,
    /// Constitutional root does not exist in the accepted rules.
    #[error("delegation names an unknown constitutional root")]
    UnknownRoot,
    /// Parent certificate has not been accepted.
    #[error("delegation names an unknown parent certificate")]
    UnknownParent,
    /// Parent or one ancestor is revoked or constitutionally inactive.
    #[error("delegation parent is revoked or constitutionally inactive")]
    InactiveParent,
    /// Child path, lifetime, actions, or depth exceed its parent.
    #[error("delegation widens its parent's authority")]
    Escalation,
    /// Content hash collision with different signed content.
    #[error("delegation id resolves to different signed content")]
    IdentifierCollision,
    /// Revocation target has not been accepted.
    #[error("revocation names an unknown certificate")]
    UnknownCertificate,
    /// Revocation issuer or scope differs from the target certificate.
    #[error("revocation was not signed by the certificate issuer")]
    WrongRevoker,
}

fn root_scope(root: &CapabilityGrant, moot_id: [u8; 32]) -> CapabilityScope {
    CapabilityScope {
        domain: MOOT_DELEGATION_DOMAIN.into(),
        resource: moot_id.to_vec(),
        path_prefix: root.path_prefix.clone(),
        actions: [MOOT_ACT_ACTION.to_string()].into_iter().collect(),
    }
}

fn attenuates_root(
    certificate: &DelegationCertificate,
    root: &CapabilityGrant,
    moot_id: [u8; 32],
) -> bool {
    certificate.parent == DelegationParent::Root(root.id)
        && certificate.issuer == root.subject
        && certificate.scope.attenuates(&root_scope(root, moot_id))
        && certificate.not_before_ms >= root.not_before_ms
        && expiry_within(certificate.expires_at_ms, root.expires_at_ms)
        && root.delegation_depth > 0
        && certificate.remaining_delegation_depth < root.delegation_depth
}

fn is_moot_scope(scope: &CapabilityScope, moot_id: [u8; 32]) -> bool {
    scope.domain == MOOT_DELEGATION_DOMAIN && scope.resource.as_slice() == moot_id
}

fn expiry_within(child: Option<u64>, parent: Option<u64>) -> bool {
    match (child, parent) {
        (_, None) => true,
        (Some(child), Some(parent)) => child <= parent,
        (None, Some(_)) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use identity::delegation::{DelegationRevocation, SignedDelegationRevocation};
    use identity::{IdentityProvider, InMemoryProvider};

    const MOOT: [u8; 32] = [9; 32];
    const ROOT: [u8; 32] = [7; 32];

    fn scope(path: &str, moot: [u8; 32]) -> CapabilityScope {
        CapabilityScope {
            domain: MOOT_DELEGATION_DOMAIN.into(),
            resource: moot.to_vec(),
            path_prefix: path.into(),
            actions: [MOOT_ACT_ACTION.to_string()].into_iter().collect(),
        }
    }

    fn root_rules(holder: [u8; 32]) -> ConstitutionRules {
        let mut rules = ConstitutionRules::founder_only(holder);
        rules.grant(CapabilityGrant {
            id: ROOT,
            subject: holder,
            path_prefix: "moot/fauna".into(),
            not_before_ms: 10,
            expires_at_ms: Some(100),
            delegation_depth: 3,
        });
        rules
    }

    #[allow(clippy::too_many_arguments)]
    fn issue(
        issuer: &InMemoryProvider,
        subject: &InMemoryProvider,
        parent: DelegationParent,
        path: &str,
        depth: u16,
        nonce: u8,
        moot: [u8; 32],
    ) -> SignedDelegationCertificate {
        SignedDelegationCertificate::issue(
            issuer,
            DelegationCertificate::new(
                parent,
                issuer.master_public_key().to_bytes(),
                subject.master_public_key().to_bytes(),
                scope(path, moot),
                15,
                20,
                Some(90),
                depth,
                [nonce; 32],
            ),
        )
        .unwrap()
    }

    #[test]
    fn root_and_child_delegations_attenuate_and_authorize() {
        let root_holder = InMemoryProvider::from_seed([1; 32]);
        let child = InMemoryProvider::from_seed([2; 32]);
        let leaf = InMemoryProvider::from_seed([3; 32]);
        let rules = root_rules(root_holder.master_public_key().to_bytes());
        let mut grants = MootDelegations::new();

        let first = issue(
            &root_holder,
            &child,
            DelegationParent::Root(ROOT),
            "moot/fauna/research",
            2,
            1,
            MOOT,
        );
        let first_id = first.certificate.id();
        assert!(grants.accept_certificate(MOOT, &rules, first).unwrap());

        let second = issue(
            &child,
            &leaf,
            DelegationParent::Certificate(first_id),
            "moot/fauna/research/notes",
            1,
            2,
            MOOT,
        );
        assert!(grants.accept_certificate(MOOT, &rules, second).unwrap());
        assert!(grants.covers(
            MOOT,
            &rules,
            leaf.master_public_key().to_bytes(),
            "moot/fauna/research/notes/write",
            50,
        ));
        assert!(!grants.covers(
            MOOT,
            &rules,
            leaf.master_public_key().to_bytes(),
            "moot/fauna/private",
            50,
        ));
    }

    #[test]
    fn parent_revocation_and_root_removal_cascade() {
        let root_holder = InMemoryProvider::from_seed([1; 32]);
        let child = InMemoryProvider::from_seed([2; 32]);
        let leaf = InMemoryProvider::from_seed([3; 32]);
        let mut rules = root_rules(root_holder.master_public_key().to_bytes());
        let mut grants = MootDelegations::new();
        let first = issue(
            &root_holder,
            &child,
            DelegationParent::Root(ROOT),
            "moot/fauna",
            2,
            1,
            MOOT,
        );
        let first_id = first.certificate.id();
        let first_scope = first.certificate.scope.clone();
        grants.accept_certificate(MOOT, &rules, first).unwrap();
        let second = issue(
            &child,
            &leaf,
            DelegationParent::Certificate(first_id),
            "moot/fauna/notes",
            1,
            2,
            MOOT,
        );
        grants.accept_certificate(MOOT, &rules, second).unwrap();

        let revocation = SignedDelegationRevocation::issue(
            &root_holder,
            DelegationRevocation::new(
                first_id,
                root_holder.master_public_key().to_bytes(),
                first_scope,
                50,
                [4; 32],
            ),
        )
        .unwrap();
        assert!(grants.accept_revocation(revocation).unwrap());
        assert!(!grants.covers(
            MOOT,
            &rules,
            leaf.master_public_key().to_bytes(),
            "moot/fauna/notes",
            50,
        ));

        rules.revoke_grant(&ROOT);
        assert!(!grants.covers(
            MOOT,
            &rules,
            child.master_public_key().to_bytes(),
            "moot/fauna",
            50,
        ));
    }

    #[test]
    fn rejects_wider_or_cross_moot_certificates() {
        let root_holder = InMemoryProvider::from_seed([1; 32]);
        let child = InMemoryProvider::from_seed([2; 32]);
        let rules = root_rules(root_holder.master_public_key().to_bytes());
        let mut grants = MootDelegations::new();
        let wider = issue(
            &root_holder,
            &child,
            DelegationParent::Root(ROOT),
            "moot",
            2,
            1,
            MOOT,
        );
        assert!(matches!(
            grants.accept_certificate(MOOT, &rules, wider),
            Err(MootDelegationError::Escalation)
        ));

        let foreign = issue(
            &root_holder,
            &child,
            DelegationParent::Root(ROOT),
            "moot/fauna",
            2,
            2,
            [8; 32],
        );
        assert!(matches!(
            grants.accept_certificate(MOOT, &rules, foreign),
            Err(MootDelegationError::WrongMoot)
        ));
    }
}
