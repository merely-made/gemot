// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

impl<B: Backend + Clone> Moot<B> {
    pub(super) async fn refresh_retention_authority(&self) -> Result<(), MootError> {
        let authority = self.governance.checkpoint_authority().await?;
        let history = self.governance.checkpoint_authority_history().await?;
        self.objects
            .set_retention_policy(Some(self.retention.resolve(authority, history)));
        Ok(())
    }

    /// Establish this Moot's first constitution and activate its checkpoint
    /// authority for subsequent object commands.
    pub async fn found(
        &self,
        founder_seed: [u8; 32],
        parent_constitution: Option<Digest>,
        divergence_point: Option<Digest>,
        rules: ConstitutionRules,
        at_ms: u64,
    ) -> Result<MootSnapshot, MootError> {
        self.governance
            .found(
                founder_seed,
                parent_constitution,
                divergence_point,
                rules,
                at_ms,
            )
            .await?;
        self.refresh_retention_authority().await?;
        self.snapshot().await
    }

    /// Amend the constitution and atomically switch future checkpoint
    /// admission to the accepted authority revision.
    pub async fn amend(
        &self,
        actor_seed: [u8; 32],
        rules: ConstitutionRules,
        at_ms: u64,
    ) -> Result<MootSnapshot, MootError> {
        self.governance.amend(actor_seed, rules, at_ms).await?;
        self.refresh_retention_authority().await?;
        self.snapshot().await
    }

    /// Evaluate a capability-scoped action under the currently accepted,
    /// signed admission rule.
    ///
    /// The provider supplies mutable membership/capability facts; the rule it
    /// is evaluated against comes only from the accepted constitution. This
    /// prevents a host from quietly changing a Moot from open to members-only
    /// or weakening its standing floor outside the replicated law.
    pub async fn authorize<P: MootAuthorizationProvider>(
        &self,
        provider: &P,
        request: &MootAuthorizationRequest,
    ) -> Result<GateDecision, MootError> {
        let policy = self.governance.snapshot().await?.rules.admission;
        let inputs = provider.inputs(request);
        Ok(authorize(
            &policy,
            inputs.capability_covers,
            &inputs.facts,
            request.at_ms,
        ))
    }

    /// Evaluate a current signed constitutional grant and a provider's live
    /// structural decision together.
    ///
    /// Both checks must pass. The constitutional grant is portable, signed
    /// authority; the provider supplies the present group/session condition
    /// that can narrow it immediately. This permits future group-key rotation
    /// or local device policy to deny access without rewriting constitutional
    /// history.
    pub async fn authorize_constitution_grant<P: MootAuthorizationProvider>(
        &self,
        provider: &P,
        request: &MootAuthorizationRequest,
    ) -> Result<GateDecision, MootError> {
        let governance = self.governance.snapshot().await?;
        let inputs = provider.inputs(request);
        let grant_covers =
            governance
                .rules
                .grant_covers(request.subject, &request.capability_path, request.at_ms);
        Ok(authorize(
            &governance.rules.admission,
            grant_covers && inputs.capability_covers,
            &inputs.facts,
            request.at_ms,
        ))
    }

    /// Evaluate independently delegated authority and the provider's current
    /// structural decision under the accepted constitutional admission rule.
    pub async fn delegations(&self) -> Result<MootDelegations, MootError> {
        let rules = self.governance.snapshot().await?.rules;
        Ok(self.delegations.delegations(&rules).await?)
    }

    /// Deterministic authority projections for a participant graph. Callers
    /// may replace their projection nodes from this value, never petition the
    /// graph to mutate the underlying authority ledger.
    pub async fn delegation_projections(
        &self,
        at_ms: u64,
    ) -> Result<Vec<MootDelegationProjection>, MootError> {
        let rules = self.governance.snapshot().await?.rules;
        Ok(self
            .delegations
            .delegations(&rules)
            .await?
            .projections(self.moot_id.0, &rules, at_ms))
    }

    /// Scope-key epochs the host encryption engine must bind and distribute.
    pub async fn delegation_scope_key_epochs(&self) -> Result<Vec<MootScopeKeyEpoch>, MootError> {
        Ok(self.delegations().await?.scope_key_epochs())
    }

    /// Evaluate the aggregate's retained independent delegation lane.
    pub async fn authorize_current_delegated<P: MootAuthorizationProvider>(
        &self,
        provider: &P,
        request: &MootAuthorizationRequest,
    ) -> Result<GateDecision, MootError> {
        let governance = self.governance.snapshot().await?;
        let delegations = self.delegations.delegations(&governance.rules).await?;
        self.authorize_delegated(&delegations, provider, request)
            .await
    }

    /// Evaluate direct constitutional and independently delegated capability
    /// authority together with current membership and Standing facts.
    pub async fn authorize_current_capability<P: MootAuthorizationProvider>(
        &self,
        provider: &P,
        request: &MootAuthorizationRequest,
    ) -> Result<GateDecision, MootError> {
        let governance = self.governance.snapshot().await?;
        let delegations = self.delegations.delegations(&governance.rules).await?;
        let inputs = provider.inputs(request);
        let capability_covers =
            governance
                .rules
                .grant_covers(request.subject, &request.capability_path, request.at_ms)
                || delegations.covers(
                    self.moot_id.0,
                    &governance.rules,
                    request.subject,
                    &request.capability_path,
                    request.at_ms,
                );
        Ok(authorize(
            &governance.rules.admission,
            capability_covers && inputs.capability_covers,
            &inputs.facts,
            request.at_ms,
        ))
    }

    /// Evaluate caller-supplied delegated authority. Prefer
    /// [`Self::authorize_current_delegated`] for the aggregate-owned lane.
    pub async fn authorize_delegated<P: MootAuthorizationProvider>(
        &self,
        delegations: &super::super::MootDelegations,
        provider: &P,
        request: &MootAuthorizationRequest,
    ) -> Result<GateDecision, MootError> {
        let governance = self.governance.snapshot().await?;
        let inputs = provider.inputs(request);
        let grant_covers = delegations.covers(
            self.moot_id.0,
            &governance.rules,
            request.subject,
            &request.capability_path,
            request.at_ms,
        );
        Ok(authorize(
            &governance.rules.admission,
            grant_covers && inputs.capability_covers,
            &inputs.facts,
            request.at_ms,
        ))
    }
}
