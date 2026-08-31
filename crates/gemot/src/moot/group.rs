// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! P2panda group membership at the Moot authorization seam.
//!
//! Signed operations are retained by [`MootGroupStore`] and translated from
//! Gemot's stable wire grammar into `p2panda-auth` for deterministic
//! materialization. The module deliberately carries only a data-scheme
//! group-secret *identifier*: running the p2panda encryption protocol still
//! belongs to the host which holds device key bundles and the identity
//! registry.

pub mod store;
pub mod wire;

use std::collections::BTreeSet;

use identity::DerivedKeyAttestation;
use p2panda_auth::group::resolver::StrongRemove;
use p2panda_auth::group::{GroupAction, GroupCrdt, GroupCrdtState};
use p2panda_auth::traits::Operation;
// p2panda 0.7 moved these two out of `p2panda-auth`: an actor is now
// `p2panda_core::Author` (the `IdentityHandle` name is gone), and
// `OperationId` lives with the operation substrate in `p2panda-core`. Only the
// import moved; both bounds mean what they meant. 0.7.1 then moved `Author`
// again, from `identity` to `traits`, where it sits beside `OperationId`.
use p2panda_auth::{Access, AccessLevel};
use p2panda_core::traits::{Author, OperationId};
use p2panda_encryption::data_scheme::GroupSecretId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::delegation::MootScopeKeyEpoch;
use super::service::{
    MootAuthorizationInputs, MootAuthorizationProvider, MootAuthorizationRequest,
};
use super::standing::StandingFacts;

/// A local identity wrapper required by p2panda-auth's generic group graph.
///
/// Serde rides here because p2panda 0.7's `Author` requires it, where the old
/// `IdentityHandle` did not: an actor is now something the substrate can put
/// on the wire itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct MootGroupHandle(pub [u8; 32]);

impl Author for MootGroupHandle {}

/// A local operation-id wrapper required by p2panda-auth's group graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MootGroupOperationId(pub [u8; 32]);

impl OperationId for MootGroupOperationId {}

/// Stable access vocabulary carried by Gemot membership operations and
/// snapshots.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MootAccessLevel {
    Pull,
    Read,
    Write,
    Manage,
}

impl From<&AccessLevel> for MootAccessLevel {
    fn from(level: &AccessLevel) -> Self {
        match level {
            AccessLevel::Pull => Self::Pull,
            AccessLevel::Read => Self::Read,
            AccessLevel::Write => Self::Write,
            AccessLevel::Manage => Self::Manage,
        }
    }
}

/// One stable Personae root and its resolved Moot access.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MootMember {
    pub member: [u8; 32],
    pub access: MootAccessLevel,
}

/// Durable membership action grammar owned by Gemot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MootMembershipAction {
    Create {
        initial_members: Vec<MootMember>,
    },
    Add {
        member: [u8; 32],
        access: MootAccessLevel,
    },
    Remove {
        member: [u8; 32],
    },
    Promote {
        member: [u8; 32],
        access: MootAccessLevel,
    },
    Demote {
        member: [u8; 32],
        access: MootAccessLevel,
    },
}

/// One membership action plus the exact auth frontier its author observed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MootMembershipRecord {
    pub action: MootMembershipAction,
    pub dependencies: Vec<[u8; 32]>,
    /// Master-signed binding when the operation uses a Moot-derived Personae
    /// key. An absent attestation means the signer is the stable identity.
    #[serde(default)]
    pub author_attestation: Option<DerivedKeyAttestation>,
}

/// Plain materialized membership state exposed through the Moot aggregate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MootGroupSnapshot {
    pub group: [u8; 32],
    pub epoch: u64,
    pub members: Vec<MootMember>,
    pub auth_heads: Vec<[u8; 32]>,
    pub retained_operations: usize,
    pub pending_operations: usize,
    pub rejected_operations: usize,
}

/// A verified membership action translated out of a signed host operation.
///
/// `MootGroup::apply_verified` does not authenticate this value. The caller
/// must first verify its source `p2panda-core` operation and preserve its
/// author, operation id, group id, and dependencies exactly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MootGroupOperation {
    pub id: MootGroupOperationId,
    pub author: MootGroupHandle,
    pub dependencies: Vec<MootGroupOperationId>,
    pub group: MootGroupHandle,
    pub action: GroupAction<MootGroupHandle>,
}

impl Operation<MootGroupHandle, MootGroupOperationId> for MootGroupOperation {
    fn id(&self) -> MootGroupOperationId {
        self.id
    }

    fn author(&self) -> MootGroupHandle {
        self.author
    }

    fn dependencies(&self) -> Vec<MootGroupOperationId> {
        self.dependencies.clone()
    }

    fn group_id(&self) -> MootGroupHandle {
        self.group
    }

    fn action(&self) -> GroupAction<MootGroupHandle> {
        self.action.clone()
    }
}

type MootGroupResolver =
    StrongRemove<MootGroupHandle, MootGroupOperationId, MootGroupOperation, ()>;
type MootGroupCrdt =
    GroupCrdt<MootGroupHandle, MootGroupOperationId, MootGroupOperation, (), MootGroupResolver>;
type MootGroupState = GroupCrdtState<MootGroupHandle, MootGroupOperationId, MootGroupOperation, ()>;

/// The membership transition which may require the host encryption engine to
/// advance its group-key epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MootGroupTransition {
    pub epoch: u64,
    pub membership_changed: bool,
    pub members: Vec<[u8; 32]>,
    pub auth_heads: Vec<[u8; 32]>,
}

/// A binding between converged membership and a p2panda data-scheme secret.
///
/// This names a secret held by the host. It never exports secret bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P2pandaGroupKeyEpoch {
    pub group: [u8; 32],
    pub epoch: u64,
    pub secret_id: GroupSecretId,
    pub members: Vec<[u8; 32]>,
    pub auth_heads: Vec<[u8; 32]>,
}

/// Host-secret binding for one revoked delegation scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P2pandaScopeKeyEpoch {
    pub group: [u8; 32],
    pub path_prefix: String,
    pub epoch: u64,
    pub secret_id: GroupSecretId,
}

#[derive(Debug, Error)]
pub enum MootGroupError {
    #[error("membership operation targets another group")]
    WrongGroup,
    #[error("p2panda-auth rejected membership operation")]
    Auth,
    #[error("cannot bind a group secret before the group has a member")]
    EmptyGroup,
    #[error("scope-key epoch belongs to another Moot group")]
    WrongScopeGroup,
    #[error("scope-key epoch must follow at least one accepted revocation")]
    UnrotatedScope,
}

/// Converged p2panda-auth membership for one Moot group.
///
/// An epoch advances whenever the resolved member set changes. Access-level
/// changes keep the epoch stable, since they change authorization but do not
/// alter who can decrypt an already-distributed group secret.
#[derive(Debug)]
pub struct MootGroup {
    group: MootGroupHandle,
    state: MootGroupState,
    /// Accepted operations let us restore state after p2panda-auth consumes an
    /// invalid candidate while attempting validation.
    operations: Vec<MootGroupOperation>,
    epoch: u64,
}

impl MootGroup {
    pub fn new(group: [u8; 32]) -> Self {
        Self {
            group: MootGroupHandle(group),
            state: MootGroupCrdt::init(),
            operations: Vec::new(),
            epoch: 0,
        }
    }

    pub fn group(&self) -> [u8; 32] {
        self.group.0
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn members(&self) -> Vec<([u8; 32], Access<()>)> {
        let mut members: Vec<_> = self
            .state
            .members(self.group)
            .into_iter()
            .map(|(member, access)| (member.0, access))
            .collect();
        members.sort_by_key(|(member, _)| *member);
        members
    }

    pub fn member_snapshots(&self) -> Vec<MootMember> {
        self.members()
            .into_iter()
            .map(|(member, access)| MootMember {
                member,
                access: MootAccessLevel::from(&access.level),
            })
            .collect()
    }

    pub fn auth_heads(&self) -> Vec<[u8; 32]> {
        let mut heads: Vec<_> = self.state.heads().into_iter().map(|head| head.0).collect();
        heads.sort_unstable();
        heads
    }

    /// Apply one already-authenticated membership operation.
    pub fn apply_verified(
        &mut self,
        operation: &MootGroupOperation,
    ) -> Result<MootGroupTransition, MootGroupError> {
        if operation.group != self.group {
            return Err(MootGroupError::WrongGroup);
        }

        let before = self.member_set();
        let state = std::mem::take(&mut self.state);
        match MootGroupCrdt::process(state, operation) {
            Ok(next) => {
                self.state = next;
                self.operations.push(operation.clone());
            }
            Err(_) => {
                self.state = self.rebuild_state();
                return Err(MootGroupError::Auth);
            }
        }
        let members = self.member_set();
        let membership_changed = before != members;
        if membership_changed {
            self.epoch = self.epoch.saturating_add(1);
        }

        Ok(MootGroupTransition {
            epoch: self.epoch,
            membership_changed,
            members: members.into_iter().collect(),
            auth_heads: self.auth_heads(),
        })
    }

    /// Bind the host's current data-scheme group secret to the resolved epoch.
    pub fn bind_group_secret(
        &self,
        secret_id: GroupSecretId,
    ) -> Result<P2pandaGroupKeyEpoch, MootGroupError> {
        let members = self.member_set();
        if members.is_empty() {
            return Err(MootGroupError::EmptyGroup);
        }
        Ok(P2pandaGroupKeyEpoch {
            group: self.group.0,
            epoch: self.epoch,
            secret_id,
            members: members.into_iter().collect(),
            auth_heads: self.auth_heads(),
        })
    }

    /// Bind a host-held p2panda data-scheme secret to a delegation revocation
    /// epoch. Gemot names the required epoch; the host owns secret bytes and
    /// recipient distribution.
    pub fn bind_scope_secret(
        &self,
        scope: &MootScopeKeyEpoch,
        secret_id: GroupSecretId,
    ) -> Result<P2pandaScopeKeyEpoch, MootGroupError> {
        if scope.resource.as_slice() != self.group.0 {
            return Err(MootGroupError::WrongScopeGroup);
        }
        if scope.epoch == 0 {
            return Err(MootGroupError::UnrotatedScope);
        }
        Ok(P2pandaScopeKeyEpoch {
            group: self.group.0,
            path_prefix: scope.path_prefix.clone(),
            epoch: scope.epoch,
            secret_id,
        })
    }

    fn member_set(&self) -> BTreeSet<[u8; 32]> {
        self.members()
            .into_iter()
            .map(|(member, _)| member)
            .collect()
    }

    fn rebuild_state(&self) -> MootGroupState {
        self.operations
            .iter()
            .fold(MootGroupCrdt::init(), |state, operation| {
                MootGroupCrdt::process(state, operation)
                    .expect("previously accepted p2panda-auth operation must replay")
            })
    }
}

impl MootAuthorizationProvider for MootGroup {
    fn inputs(&self, request: &MootAuthorizationRequest) -> MootAuthorizationInputs {
        let access = self
            .members()
            .into_iter()
            .find_map(|(member, access)| (member == request.subject).then_some(access));
        let is_member = access.is_some();
        let capability_covers = access.is_some_and(|access| access.level >= AccessLevel::Write);
        MootAuthorizationInputs {
            capability_covers,
            facts: StandingFacts {
                is_member,
                ..Default::default()
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p2panda_auth::group::GroupMember;

    fn id(value: u8) -> [u8; 32] {
        [value; 32]
    }

    fn operation(
        id_byte: u8,
        author: u8,
        dependencies: Vec<u8>,
        group: u8,
        action: GroupAction<MootGroupHandle>,
    ) -> MootGroupOperation {
        MootGroupOperation {
            id: MootGroupOperationId(id(id_byte)),
            author: MootGroupHandle(id(author)),
            dependencies: dependencies
                .into_iter()
                .map(|dependency| MootGroupOperationId(id(dependency)))
                .collect(),
            group: MootGroupHandle(id(group)),
            action,
        }
    }

    #[test]
    fn membership_changes_rotate_the_bound_group_key_epoch() {
        let mut group = MootGroup::new(id(9));
        let founder = MootGroupHandle(id(1));
        let reader = MootGroupHandle(id(2));

        let created = group
            .apply_verified(&operation(
                10,
                1,
                vec![],
                9,
                GroupAction::Create {
                    initial_members: vec![(GroupMember::Individual(founder), Access::manage())],
                },
            ))
            .unwrap();
        assert!(created.membership_changed);
        assert_eq!(created.epoch, 1);

        group
            .apply_verified(&operation(
                11,
                1,
                vec![10],
                9,
                GroupAction::Add {
                    member: GroupMember::Individual(reader),
                    access: Access::read(),
                },
            ))
            .unwrap();
        let reader_inputs = group.inputs(&MootAuthorizationRequest {
            subject: id(2),
            capability_path: "/notes".into(),
            at_ms: 0,
        });
        assert!(reader_inputs.facts.is_member);
        assert!(!reader_inputs.capability_covers);

        let promoted = group
            .apply_verified(&operation(
                12,
                1,
                vec![11],
                9,
                GroupAction::Promote {
                    member: GroupMember::Individual(reader),
                    access: Access::write(),
                },
            ))
            .unwrap();
        assert!(!promoted.membership_changed);
        assert_eq!(promoted.epoch, 2);
        assert!(
            group
                .inputs(&MootAuthorizationRequest {
                    subject: id(2),
                    capability_path: "/notes".into(),
                    at_ms: 0,
                })
                .capability_covers
        );

        let removed = group
            .apply_verified(&operation(
                13,
                1,
                vec![12],
                9,
                GroupAction::Remove {
                    member: GroupMember::Individual(reader),
                },
            ))
            .unwrap();
        assert!(removed.membership_changed);
        assert_eq!(removed.epoch, 3);
        let key_epoch = group.bind_group_secret(id(77)).unwrap();
        assert_eq!(key_epoch.epoch, 3);
        assert_eq!(key_epoch.members, vec![id(1)]);
        let scope_epoch = MootScopeKeyEpoch {
            resource: id(9).to_vec(),
            path_prefix: "moot/fauna".into(),
            epoch: 1,
            revoked_certificates: vec![identity::delegation::DelegationId(id(88))],
        };
        let bound_scope = group.bind_scope_secret(&scope_epoch, id(78)).unwrap();
        assert_eq!(bound_scope.group, id(9));
        assert_eq!(bound_scope.path_prefix, "moot/fauna");
        assert_eq!(bound_scope.epoch, 1);
    }

    #[test]
    fn rejects_an_operation_for_another_group() {
        let mut group = MootGroup::new(id(9));
        let error = group
            .apply_verified(&operation(
                10,
                1,
                vec![],
                8,
                GroupAction::Create {
                    initial_members: vec![],
                },
            ))
            .unwrap_err();
        assert!(matches!(error, MootGroupError::WrongGroup));
    }
}
