// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

impl<B: Backend + Clone> Moot<B> {
    pub async fn declare(
        &self,
        actor_seed: [u8; 32],
        name: String,
        charter: String,
        at_ms: u64,
    ) -> Result<MootCommandReceipt, MootError> {
        self.governance.snapshot().await?;
        self.author_object(
            actor_seed,
            MootEvent::Declared {
                name,
                charter,
                at_ms,
            },
        )
        .await
    }

    pub async fn join(
        &self,
        actor_seed: [u8; 32],
        name: String,
        at_ms: u64,
    ) -> Result<MootCommandReceipt, MootError> {
        self.governance.snapshot().await?;
        self.author_object(actor_seed, MootEvent::Joined { name, at_ms })
            .await
    }

    pub async fn share(
        &self,
        actor_seed: [u8; 32],
        manifest_id: [u8; 32],
        schema_id: String,
        title: String,
        at_ms: u64,
    ) -> Result<MootCommandReceipt, MootError> {
        self.governance.snapshot().await?;
        self.author_object(
            actor_seed,
            MootEvent::Shared {
                manifest_id,
                schema_id,
                title,
                at_ms,
            },
        )
        .await
    }

    /// Share under this Moot's derived Personae key while retaining the
    /// stable root as the fauna attribution and authorization subject.
    pub async fn share_for_identity<P: identity::IdentityProvider + ?Sized>(
        &self,
        identity: &P,
        manifest_id: [u8; 32],
        schema_id: String,
        title: String,
        at_ms: u64,
    ) -> Result<MootCommandReceipt, MootError> {
        self.governance.snapshot().await?;
        let event = MootEvent::Shared {
            manifest_id,
            schema_id,
            title,
            at_ms,
        };
        let operation = self
            .objects
            .author_for_identity(identity, self.moot_id.0, &event)
            .await?;
        Ok(MootCommandReceipt {
            operation: *operation.hash.as_bytes(),
            lane: MootLane::Objects,
            snapshot: self.snapshot().await?,
        })
    }

    /// Author a contribution only after current community membership and
    /// capability authority allow this stable Personae root to write fauna.
    pub async fn share_authorized_for_identity<P: identity::IdentityProvider + ?Sized>(
        &self,
        identity: &P,
        manifest_id: [u8; 32],
        schema_id: String,
        title: String,
        at_ms: u64,
    ) -> Result<MootCommandReceipt, MootError> {
        let group = self.membership().await?;
        let request = MootAuthorizationRequest {
            subject: identity.master_public_key().to_bytes(),
            capability_path: cap_path(&fauna_cap()),
            at_ms,
        };
        match self.authorize_current_capability(&group, &request).await? {
            GateDecision::Allow => {
                self.share_for_identity(identity, manifest_id, schema_id, title, at_ms)
                    .await
            }
            GateDecision::Deny(reason) => Err(MootError::Unauthorized(reason)),
        }
    }

    /// Withdraw one of this stable identity's own shared contributions.
    ///
    /// The target must already be a retained `Shared` operation authored by
    /// this identity. The command deliberately has no seed-only counterpart:
    /// stable-root binding is required before a withdrawal can be authored.
    pub async fn withdraw_share_for_identity<P: identity::IdentityProvider + ?Sized>(
        &self,
        identity: &P,
        target_share: [u8; 32],
        at_ms: u64,
    ) -> Result<MootCommandReceipt, MootError> {
        let roster = self.objects.roster(self.moot_id.0).await?;
        let share = roster
            .fauna
            .iter()
            .find(|entry| entry.op_hash == target_share)
            .ok_or(MootError::WithdrawalUnknownTarget)?;
        if share.shared_by != identity.master_public_key().to_bytes() {
            return Err(MootError::WithdrawalWrongIdentity);
        }
        self.governance.snapshot().await?;
        let operation = self
            .objects
            .author_for_identity(
                identity,
                self.moot_id.0,
                &MootEvent::Withdrawn {
                    target_share,
                    at_ms,
                },
            )
            .await?;
        Ok(MootCommandReceipt {
            operation: *operation.hash.as_bytes(),
            lane: MootLane::Objects,
            snapshot: self.snapshot().await?,
        })
    }

    /// Resolve a collection through current membership, typed capability, and
    /// contribution authority. Raw history remains in the object roster.
    pub async fn authorized_collection(
        &self,
        collection_id: CollectionId,
        at_ms: u64,
    ) -> Result<Option<CollectionView>, MootError> {
        let rules = self.governance.snapshot().await?.rules;
        let delegations = self.delegations.delegations(&rules).await?;
        let group = self.membership().await?;
        let authority = CurrentCollectionAuthority {
            typed: MootAuthority {
                delegations: &delegations,
                rules: &rules,
                moot_id: self.moot_id.0,
                now_ms: at_ms,
            },
            group: &group,
            rules: &rules,
            at_ms,
        };
        Ok(self
            .objects
            .roster(self.moot_id.0)
            .await?
            .authorized_collection(self.moot_id.0, collection_id, &authority))
    }

    /// Mint a same-Moot collection root under a stable Personae identity.
    pub async fn declare_collection_for_identity<P: identity::IdentityProvider + ?Sized>(
        &self,
        identity: &P,
        collection_id: CollectionId,
        name: String,
        fork: Option<CollectionFork>,
        at_ms: u64,
    ) -> Result<MootCommandReceipt, MootError> {
        if let Some(seed) = &fork {
            if seed.parent.collection.moot_id != self.moot_id.0
                || seed
                    .selected
                    .iter()
                    .any(|member| member.moot_id != self.moot_id.0)
            {
                return Err(MootError::ForeignCollection);
            }
            if !seed.verifies() {
                return Err(MootError::InvalidCollectionFork);
            }
            let source = self
                .authorized_collection(seed.parent.collection.collection_id, at_ms)
                .await?
                .ok_or(MootError::CollectionUnknown)?;
            if source.version != seed.parent {
                return Err(MootError::InvalidCollectionFork);
            }
            let effective: std::collections::BTreeSet<_> =
                source.effective_selected.into_iter().collect();
            if seed
                .selected
                .iter()
                .any(|member| !effective.contains(member))
            {
                return Err(MootError::IneffectiveCollectionContribution);
            }
        }
        let collection = CollectionRef {
            moot_id: self.moot_id.0,
            collection_id,
        };
        self.author_collection_for_identity(
            identity,
            collection,
            CollectionEvent::Declared {
                collection_id,
                name,
                fork,
                at_ms,
            },
            at_ms,
        )
        .await
    }

    /// Apply one membership decision against the exact observed collection heads.
    pub async fn set_collection_membership_for_identity<P: identity::IdentityProvider + ?Sized>(
        &self,
        identity: &P,
        collection: CollectionRef,
        mut parents: Vec<[u8; 32]>,
        change: CollectionChange,
        at_ms: u64,
    ) -> Result<MootCommandReceipt, MootError> {
        if collection.moot_id != self.moot_id.0 {
            return Err(MootError::ForeignCollection);
        }
        parents.sort();
        parents.dedup();
        let view = self
            .authorized_collection(collection.collection_id, at_ms)
            .await?
            .ok_or(MootError::CollectionUnknown)?;
        if parents != view.heads {
            return Err(MootError::StaleCollectionHeads);
        }
        let CollectionChange::SetMembership {
            contribution,
            included,
        } = change;
        if contribution.moot_id != self.moot_id.0 {
            return Err(MootError::ForeignCollection);
        }
        if included {
            let effective = self.authorized_fauna(at_ms).await?;
            if !effective
                .iter()
                .any(|entry| entry.op_hash == contribution.share)
            {
                return Err(MootError::IneffectiveCollectionContribution);
            }
        }
        self.author_collection_for_identity(
            identity,
            collection,
            CollectionEvent::Changed {
                collection,
                parents,
                change: CollectionChange::SetMembership {
                    contribution,
                    included,
                },
                at_ms,
            },
            at_ms,
        )
        .await
    }

    pub(super) async fn author_collection_for_identity<P: identity::IdentityProvider + ?Sized>(
        &self,
        identity: &P,
        collection: CollectionRef,
        event: CollectionEvent,
        at_ms: u64,
    ) -> Result<MootCommandReceipt, MootError> {
        let group = self.membership().await?;
        let request = MootAuthorizationRequest {
            subject: identity.master_public_key().to_bytes(),
            capability_path: cap_path(&collection_cap(collection)),
            at_ms,
        };
        match self.authorize_current_capability(&group, &request).await? {
            GateDecision::Allow => {}
            GateDecision::Deny(reason) => return Err(MootError::Unauthorized(reason)),
        }
        let operation = self
            .objects
            .author_for_identity(identity, self.moot_id.0, &MootEvent::Collection { event })
            .await?;
        Ok(MootCommandReceipt {
            operation: *operation.hash.as_bytes(),
            lane: MootLane::Objects,
            snapshot: self.snapshot().await?,
        })
    }

    pub(super) async fn author_object(
        &self,
        actor_seed: [u8; 32],
        event: MootEvent,
    ) -> Result<MootCommandReceipt, MootError> {
        let operation = self
            .objects
            .author_seed(actor_seed, self.moot_id.0, &event)
            .await?;
        Ok(MootCommandReceipt {
            operation: *operation.hash.as_bytes(),
            lane: MootLane::Objects,
            snapshot: self.snapshot().await?,
        })
    }

    /// Author a membership change directly under a stable identity key.
    pub async fn update_membership(
        &self,
        actor_seed: [u8; 32],
        action: MootMembershipAction,
    ) -> Result<MootCommandReceipt, MootError> {
        self.governance.snapshot().await?;
        let operation = self.membership.author_seed(actor_seed, action).await?;
        Ok(MootCommandReceipt {
            operation: *operation.hash.as_bytes(),
            lane: MootLane::Membership,
            snapshot: self.snapshot().await?,
        })
    }

    /// Author a membership change under a Moot-derived key certified by the
    /// stable Personae root.
    pub async fn update_membership_for_identity<P: identity::IdentityProvider + ?Sized>(
        &self,
        identity: &P,
        action: MootMembershipAction,
    ) -> Result<MootCommandReceipt, MootError> {
        self.governance.snapshot().await?;
        let operation = self
            .membership
            .author_for_identity(identity, action)
            .await?;
        Ok(MootCommandReceipt {
            operation: *operation.hash.as_bytes(),
            lane: MootLane::Membership,
            snapshot: self.snapshot().await?,
        })
    }

    /// Record one Standing fact through the same aggregate command surface.
    /// The receipt can be resolved with [`outbound`](Self::outbound) and
    /// published by the host on its Standing LogSync handle.
    pub async fn record_standing(
        &self,
        actor_seed: [u8; 32],
        event: StandingEvent,
    ) -> Result<MootCommandReceipt, MootError> {
        self.governance.snapshot().await?;
        let operation = self
            .standing
            .author_seed(actor_seed, self.moot_id.0, &event)
            .await?;
        Ok(MootCommandReceipt {
            operation: *operation.hash.as_bytes(),
            lane: MootLane::Standing,
            snapshot: self.snapshot().await?,
        })
    }

    /// Record one Standing fact under a Moot-scoped derived key certified by
    /// the stable Personae root named in the event.
    pub async fn record_standing_for_identity<P: identity::IdentityProvider + ?Sized>(
        &self,
        identity: &P,
        event: StandingEvent,
    ) -> Result<MootCommandReceipt, MootError> {
        self.governance.snapshot().await?;
        let operation = self
            .standing
            .author_for_identity(identity, self.moot_id.0, &event)
            .await?;
        Ok(MootCommandReceipt {
            operation: *operation.hash.as_bytes(),
            lane: MootLane::Standing,
            snapshot: self.snapshot().await?,
        })
    }

    /// Record a stable-root Standing assertion only after current community
    /// membership and the caller-selected typed capability allow it.
    pub async fn record_standing_authorized_for_identity<P: identity::IdentityProvider + ?Sized>(
        &self,
        identity: &P,
        event: StandingEvent,
        capability: &Cap,
    ) -> Result<MootCommandReceipt, MootError> {
        let group = self.membership().await?;
        let request = MootAuthorizationRequest {
            subject: identity.master_public_key().to_bytes(),
            capability_path: cap_path(capability),
            at_ms: event.at_ms(),
        };
        match self.authorize_current_capability(&group, &request).await? {
            GateDecision::Allow => self.record_standing_for_identity(identity, event).await,
            GateDecision::Deny(reason) => Err(MootError::Unauthorized(reason)),
        }
    }

    /// Retain one Tulpa proposal or endorsement. Recognition remains a
    /// projection over the proposal's frozen electorate, so recording this fact
    /// never grants its author a separate governance power.
    pub async fn record_tulpa(
        &self,
        actor_seed: [u8; 32],
        event: TulpaEvent,
    ) -> Result<MootCommandReceipt, MootError> {
        self.governance.snapshot().await?;
        let operation = self
            .tulpa
            .author_seed(actor_seed, self.moot_id.0, &event)
            .await?;
        Ok(MootCommandReceipt {
            operation: *operation.hash.as_bytes(),
            lane: MootLane::Tulpa,
            snapshot: self.snapshot().await?,
        })
    }

    /// Retain a FLORA round specification, contribution receipt, or candidate
    /// artifact reference. The operation contains no training or tensor bytes.
    pub async fn record_flora(
        &self,
        actor_seed: [u8; 32],
        event: FloraEvent,
    ) -> Result<MootCommandReceipt, MootError> {
        self.governance.snapshot().await?;
        let operation = self
            .flora
            .author_seed(actor_seed, self.moot_id.0, &event)
            .await?;
        Ok(MootCommandReceipt {
            operation: *operation.hash.as_bytes(),
            lane: MootLane::Flora,
            snapshot: self.snapshot().await?,
        })
    }

    /// The moot's commons **as converged authority sees it**: fauna entries
    /// whose sharer is admitted by the current constitutional policy, is a
    /// current Write member, and holds the typed `moot/fauna` capability at
    /// `at_ms`.
    ///
    /// Today `MootPolicy::admit` accepts a `Shared` event on wire grammar and
    /// moot address alone, so the raw
    /// [`roster.fauna`](super::super::MootRoster::fauna) is *everything anyone put
    /// there*. This is the authorized view over it, evaluated at read for the
    /// reason recorded on
    /// [`MootRoster::authorized_fauna`](super::super::MootRoster::authorized_fauna):
    /// authority converges separately from the operations it authorizes, so
    /// refusing at admission would discard operations that become authorized
    /// a moment later.
    ///
    /// Both views are deliberately available. Which one a surface shows is a
    /// product call — the unfiltered record lets a UI show an unauthorized
    /// contribution as *pending* rather than making it vanish.
    pub async fn authorized_fauna(&self, at_ms: u64) -> Result<Vec<FaunaEntry>, MootError> {
        let rules = self.governance.snapshot().await?.rules;
        let delegations = self.delegations.delegations(&rules).await?;
        let roster = self.objects.roster(self.moot_id.0).await?;
        let authority = MootAuthority {
            delegations: &delegations,
            rules: &rules,
            moot_id: self.moot_id.0,
            now_ms: at_ms,
        };
        let group = self.membership().await?;
        let capability_path = cap_path(&fauna_cap());
        Ok(roster
            .authorized_fauna(&authority)
            .into_iter()
            .filter(|entry| {
                let inputs = group.inputs(&MootAuthorizationRequest {
                    subject: entry.shared_by,
                    capability_path: capability_path.clone(),
                    at_ms,
                });
                matches!(
                    authorize(
                        &rules.admission,
                        inputs.capability_covers,
                        &inputs.facts,
                        at_ms,
                    ),
                    GateDecision::Allow
                )
            })
            .cloned()
            .collect())
    }

    pub async fn snapshot(&self) -> Result<MootSnapshot, MootError> {
        let governance = self.governance.snapshot().await?;
        let membership = self.membership.snapshot().await?;
        let roster = self.objects.roster(self.moot_id.0).await?;
        let checkpoint = self
            .objects
            .latest_checkpoint(self.moot_id.0)
            .await?
            .map(|stored| MootCheckpointSnapshot {
                operation: stored.operation,
                policy_revision: stored.checkpoint.policy_revision,
                authority_revision: stored.checkpoint.authority_revision,
                previous_checkpoint: stored.checkpoint.previous_checkpoint,
                frontier_count: stored.checkpoint.frontier.len(),
                at_ms: stored.checkpoint.at_ms,
            });
        let delegated_certificates = self
            .delegations
            .delegations(&governance.rules)
            .await?
            .certificate_count();
        let standing_operations = self.standing.len().await?;
        let tulpa = self.tulpa.fold_moot(self.moot_id.0).await?;
        let flora = self.flora.fold_moot(self.moot_id.0).await?;
        Ok(MootSnapshot {
            moot_id: self.moot_id,
            governance,
            membership,
            roster,
            checkpoint,
            delegated_certificates,
            standing_operations,
            tulpa,
            flora,
        })
    }
}
