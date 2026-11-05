// SPDX-License-Identifier: MPL-2.0
use super::*;
use crate::moot::workflow::namespace::{
    BindingView, CollectionTarget, NamespaceEvent, collection_read_cap,
};
use crate::moot::workflow::work::{WorkAction, WorkEvent, WorkView};
use crate::moot::workflow::{RecordId, WorkflowEvent, WorkflowFact};

impl<B: Backend + Clone> Moot<B> {
    pub async fn validate_catalogue_advertisement(
        &self,
        reader: RecordId,
        hint: &crate::moot::workflow::discovery::SignedCatalogueAdvertisement,
        now: u64,
        max_lifetime_ms: u64,
    ) -> Result<(), MootError> {
        use crate::moot::workflow::discovery::catalogue_cap;
        hint.verify(self.moot_id.0, now, max_lifetime_ms)
            .map_err(MootError::Workflow)?;
        let ad = &hint.advertisement;
        let view = self
            .collection_for_reader(
                reader,
                &CollectionTarget::FollowAccepted(ad.collection.collection),
                now,
            )
            .await?;
        if ad.description.is_some() {
            if view.version != ad.collection || view.effective_selected.is_empty() {
                return Err(MootError::Workflow(
                    "stale or empty advertised collection".into(),
                ));
            }
            let group = self.membership().await?;
            let request = MootAuthorizationRequest {
                subject: ad.provider,
                capability_path: cap_path(&catalogue_cap(ad.collection.collection.collection_id.0)),
                at_ms: now,
            };
            if let GateDecision::Deny(reason) =
                self.authorize_current_capability(&group, &request).await?
            {
                return Err(MootError::Unauthorized(reason));
            }
        }
        Ok(())
    }
    async fn project_workflow<R>(
        &self,
        at_ms: u64,
        project: impl FnOnce(&MootRoster, &CurrentCollectionAuthority<'_>) -> R,
    ) -> Result<R, MootError> {
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
        let roster = self.objects.roster(self.moot_id.0).await?;
        Ok(project(&roster, &authority))
    }
    pub async fn directory(&self, at_ms: u64) -> Result<Vec<BindingView>, MootError> {
        self.project_workflow(at_ms, |r, a| r.directory(a)).await
    }
    pub async fn work_view(&self, work: RecordId, at_ms: u64) -> Result<WorkView, MootError> {
        self.project_workflow(at_ms, |r, a| r.work(work, a)).await
    }
    /// Names never supply access. The reader needs Read membership, the stable
    /// collection read scope and current admission, including after every rename.
    pub async fn collection_for_reader(
        &self,
        subject: RecordId,
        target: &CollectionTarget,
        at_ms: u64,
    ) -> Result<CollectionView, MootError> {
        if !target.validate(self.moot_id.0) {
            return Err(MootError::Workflow("foreign collection".into()));
        }
        let rules = self.governance.snapshot().await?.rules;
        let delegations = self.delegations.delegations(&rules).await?;
        let group = self.membership().await?;
        let cap = collection_read_cap(target.collection());
        let typed = MootAuthority {
            delegations: &delegations,
            rules: &rules,
            moot_id: self.moot_id.0,
            now_ms: at_ms,
        };
        let member = group
            .member_snapshots()
            .iter()
            .any(|m| m.member == subject && m.access >= super::super::MootAccessLevel::Read);
        let decision = authorize(
            &rules.admission,
            member && typed.covers(Subject::new(subject), &cap, Mode::Read),
            &StandingFacts {
                is_member: member,
                ..Default::default()
            },
            at_ms,
        );
        if let GateDecision::Deny(reason) = decision {
            return Err(MootError::Unauthorized(reason));
        }
        self.project_workflow(at_ms, |r, a| target.resolve(r, a))
            .await?
            .ok_or(MootError::CollectionUnknown)
    }
    pub async fn resolve_name(
        &self,
        subject: RecordId,
        name: &str,
        at_ms: u64,
    ) -> Result<CollectionView, MootError> {
        let directory = self.directory(at_ms).await?;
        let value = directory
            .iter()
            .filter(|v| !v.conflict)
            .filter_map(|v| v.value.as_ref())
            .find(|v| v.name == name)
            .ok_or_else(|| MootError::Workflow("name absent or conflicted".into()))?;
        self.collection_for_reader(subject, &value.target, at_ms)
            .await
    }
    pub async fn bind_for_identity<P: identity::IdentityProvider + ?Sized>(
        &self,
        identity: &P,
        event: NamespaceEvent,
    ) -> Result<MootCommandReceipt, MootError> {
        event
            .validate(self.moot_id.0)
            .map_err(MootError::Workflow)?;
        self.project_workflow(event.at_ms, |r, a| {
            let view = r.namespace(event.binding, a);
            if view.heads != event.parents {
                return Err(MootError::Workflow("stale binding heads".into()));
            }
            if event
                .value
                .as_ref()
                .is_some_and(|v| v.target.resolve(r, a).is_none())
            {
                return Err(MootError::CollectionUnknown);
            }
            Ok(())
        })
        .await??;
        self.author_workflow(identity, WorkflowEvent::Namespace(event))
            .await
    }
    pub async fn work_for_identity<P: identity::IdentityProvider + ?Sized>(
        &self,
        identity: &P,
        event: WorkEvent,
    ) -> Result<MootCommandReceipt, MootError> {
        event
            .validate(self.moot_id.0)
            .map_err(MootError::Workflow)?;
        self.project_workflow(event.at_ms, |r, a| {
            if let WorkAction::Offer { terms, .. } = &event.action {
                if terms.inputs.resolve(r, a).is_none() {
                    return Err(MootError::CollectionUnknown);
                }
            }
            let view = r.work(event.work, a);
            if let WorkAction::Accept { offer } = &event.action {
                if view.cancelled_offers.contains(offer) {
                    return Err(MootError::Workflow("offer withdrawn or declined".into()));
                }
            }

            if let WorkAction::Submit {
                agreement,
                window,
                replaces,
                ..
            } = &event.action
            {
                let heads: Vec<_> = view
                    .submissions
                    .values()
                    .filter(|s| s.agreement == *agreement && s.window == *window && !s.superseded)
                    .map(|s| s.id)
                    .collect();
                if &heads != replaces {
                    return Err(MootError::Workflow("stale submission heads".into()));
                }
                if view.active_agreement().is_none_or(|v| v.id != *agreement) {
                    return Err(MootError::Workflow(
                        "agreement cancelled, replaced or conflicted".into(),
                    ));
                }
            }
            Ok(())
        })
        .await??;
        self.author_workflow(identity, WorkflowEvent::Work(event))
            .await
    }
    async fn author_workflow<P: identity::IdentityProvider + ?Sized>(
        &self,
        identity: &P,
        event: WorkflowEvent,
    ) -> Result<MootCommandReceipt, MootError> {
        let subject = identity.master_public_key().to_bytes();
        let group = self.membership().await?;
        let request = MootAuthorizationRequest {
            subject,
            capability_path: cap_path(&event.cap()),
            at_ms: event.at_ms(),
        };
        if !matches!(
            &event,
            WorkflowEvent::Work(WorkEvent {
                action: WorkAction::Cancel { .. },
                ..
            })
        ) {
            if let GateDecision::Deny(reason) =
                self.authorize_current_capability(&group, &request).await?
            {
                return Err(MootError::Unauthorized(reason));
            }
        }
        let wire = MootEvent::Workflow {
            event: event.clone(),
        };
        let operation = self
            .objects
            .prepare_for_identity(identity, self.moot_id.0, &wire)
            .await?;
        let id = *operation.hash.as_bytes();
        self.project_workflow(event.at_ms(), |r, a| {
            let mut r = r.clone();
            r.workflow.push(
                WorkflowFact::from_operation(&operation)
                    .expect("prepared valid workflow operation"),
            );
            match &event {
                WorkflowEvent::Namespace(e) if r.namespace(e.binding, a).heads.contains(&id) => {
                    Ok(())
                }
                WorkflowEvent::Work(e) if r.work(e.work, a).applied.contains(&id) => Ok(()),
                _ => Err(MootError::Workflow(
                    "invalid role, missing dependency or ineffective transition".into(),
                )),
            }
        })
        .await??;
        self.objects.accept(self.moot_id.0, &operation).await?;
        Ok(MootCommandReceipt {
            operation: id,
            lane: MootLane::Objects,
            snapshot: self.snapshot().await?,
        })
    }
}
