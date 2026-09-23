// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The Moot's live lane set, joined as one act.
//!
//! A Moot replicates over seven independent LogSync lanes — constitution,
//! delegation, membership, records, standing, Tulpa, and FLORA — all subscribing to the Moot id
//! as their sync topic and each carrying its own extension type and accept
//! path. Joining them one by one is the ceremony every host would repeat;
//! this owns it once, the way `JoinedSpace` owns the per-lane ceremony.
//!
//! Each lane names itself through [`stickleback::lane_id`], scoped to the
//! Moot: the endpoint routes inbound sync by exactly that identifier, and two
//! lanes (or two Moots' same lane) sharing one id would silently starve each
//! other (see `lane_coexistence`).

use std::sync::{Arc, Mutex};

use muniment::Backend;
use p2panda_core::Operation;
use stickleback::{Endpoint, Gossip, JoinError, JoinedSpace, SyncStatus, lane_id};

use super::MootGroupExt;
use super::constitution::ConstitutionExt;
use super::delegation::MootDelegationExt;
use super::flora::FloraExt;
use super::records::{MootExt, MootLogId};
use super::service::Moot;
use mien::StandingExt;
use super::tulpa::TulpaExt;

/// Lane kinds, one spelling each, so both peers derive identical protocol ids.
pub const GEMOT_CONSTITUTION_LANE: &str = "gemot/constitution/v1";
pub const GEMOT_DELEGATION_LANE: &str = "gemot/delegation/v1";
pub const GEMOT_MEMBERSHIP_LANE: &str = "gemot/membership/v1";
pub const GEMOT_RECORDS_LANE: &str = "gemot/records/v1";
pub const GEMOT_STANDING_LANE: &str = "gemot/standing/v1";
pub const GEMOT_TULPA_LANE: &str = "gemot/tulpa/v1";
pub const GEMOT_FLORA_LANE: &str = "gemot/flora/v1";

/// One Moot's joined lane set. Dropping it leaves every lane.
pub struct MootLanes {
    pub constitution: JoinedSpace<ConstitutionExt>,
    pub delegation: JoinedSpace<MootDelegationExt>,
    pub membership: JoinedSpace<MootGroupExt>,
    pub records: JoinedSpace<MootExt>,
    pub standing: JoinedSpace<StandingExt>,
    pub tulpa: JoinedSpace<TulpaExt>,
    pub flora: JoinedSpace<FloraExt>,
}

impl MootLanes {
    /// Sync activity across the set, in lane order, for a host's status
    /// surface. Per-lane rather than summed: a Steward that can only say
    /// "some lane is behind" cannot say which.
    pub fn sync_status(&self) -> [SyncStatus; 7] {
        [
            self.constitution.sync_status(),
            self.delegation.sync_status(),
            self.membership.sync_status(),
            self.records.sync_status(),
            self.standing.sync_status(),
            self.tulpa.sync_status(),
            self.flora.sync_status(),
        ]
    }

    /// Shared counter handles, in the same lane order, for a host watching
    /// arrivals from a task that cannot borrow the lanes.
    pub fn status_handles(&self) -> [Arc<Mutex<SyncStatus>>; 7] {
        [
            self.constitution.status_handle(),
            self.delegation.status_handle(),
            self.membership.status_handle(),
            self.records.status_handle(),
            self.standing.status_handle(),
            self.tulpa.status_handle(),
            self.flora.status_handle(),
        ]
    }

    /// Push one freshly authored operation onto its live lane.
    ///
    /// Initial reconciliation covers retained history for a late joiner; an
    /// operation authored after peers are connected reaches them only through
    /// these. Storing it is what makes it survive, publishing is what makes it
    /// arrive.
    pub fn publish_constitution(
        &self,
        operation: Operation<ConstitutionExt>,
    ) -> Result<(), JoinError> {
        self.constitution.publish(operation)
    }

    pub fn publish_delegation(
        &self,
        operation: Operation<MootDelegationExt>,
    ) -> Result<(), JoinError> {
        self.delegation.publish(operation)
    }

    pub fn publish_membership(&self, operation: Operation<MootGroupExt>) -> Result<(), JoinError> {
        self.membership.publish(operation)
    }

    pub fn publish_records(&self, operation: Operation<MootExt>) -> Result<(), JoinError> {
        self.records.publish(operation)
    }

    pub fn publish_standing(&self, operation: Operation<StandingExt>) -> Result<(), JoinError> {
        self.standing.publish(operation)
    }

    pub fn publish_tulpa(&self, operation: Operation<TulpaExt>) -> Result<(), JoinError> {
        self.tulpa.publish(operation)
    }

    pub fn publish_flora(&self, operation: Operation<FloraExt>) -> Result<(), JoinError> {
        self.flora.publish(operation)
    }
}

impl<B: Backend + Clone + Send + Sync + 'static> Moot<B> {
    /// Join all seven of this Moot's lanes over the host transport's parts.
    ///
    /// Every accept closure delegates to the lane's own validating store, so
    /// nothing arriving over the wire bypasses the admission each lane already
    /// enforces for local authoring and drop import.
    pub async fn join_lanes(
        &self,
        endpoint: Endpoint,
        gossip: Gossip,
    ) -> Result<MootLanes, JoinError> {
        let moot = self.moot_id().0;

        let governance = self.governance().clone();
        let constitution = JoinedSpace::join::<_, u64, _, _>(
            lane_id(GEMOT_CONSTITUTION_LANE, moot),
            self.governance().sync_store(),
            endpoint.clone(),
            gossip.clone(),
            moot,
            move |operation: Operation<ConstitutionExt>| {
                let governance = governance.clone();
                async move { matches!(governance.accept(&operation).await, Ok(true)) }
            },
        )
        .await?;

        let delegations = self.delegation_store().clone();
        let delegation = JoinedSpace::join::<_, u64, _, _>(
            lane_id(GEMOT_DELEGATION_LANE, moot),
            self.delegation_store().sync_store(),
            endpoint.clone(),
            gossip.clone(),
            moot,
            move |operation: Operation<MootDelegationExt>| {
                let store = delegations.clone();
                async move { matches!(store.accept(&operation).await, Ok(true)) }
            },
        )
        .await?;

        let members = self.membership_store().clone();
        let membership = JoinedSpace::join::<_, u64, _, _>(
            lane_id(GEMOT_MEMBERSHIP_LANE, moot),
            self.membership_store().sync_store(),
            endpoint.clone(),
            gossip.clone(),
            moot,
            move |operation: Operation<MootGroupExt>| {
                let store = members.clone();
                async move { matches!(store.accept(&operation).await, Ok(true)) }
            },
        )
        .await?;

        let objects = self.object_store().clone();
        let records = JoinedSpace::join::<_, MootLogId, _, _>(
            lane_id(GEMOT_RECORDS_LANE, moot),
            self.object_store().sync_store(),
            endpoint.clone(),
            gossip.clone(),
            moot,
            move |operation: Operation<MootExt>| {
                let store = objects.clone();
                async move { matches!(store.accept(moot, &operation).await, Ok(true)) }
            },
        )
        .await?;

        let standing_store = self.standing_store().clone();
        let standing = JoinedSpace::join::<_, u64, _, _>(
            lane_id(GEMOT_STANDING_LANE, moot),
            self.standing_store().sync_store(),
            endpoint.clone(),
            gossip.clone(),
            moot,
            move |operation: Operation<StandingExt>| {
                let store = standing_store.clone();
                async move { matches!(store.accept(moot, &operation).await, Ok(true)) }
            },
        )
        .await?;

        let tulpa_store = self.tulpa_store().clone();
        let tulpa = JoinedSpace::join::<_, u64, _, _>(
            lane_id(GEMOT_TULPA_LANE, moot),
            self.tulpa_store().sync_store(),
            endpoint.clone(),
            gossip.clone(),
            moot,
            move |operation: Operation<TulpaExt>| {
                let store = tulpa_store.clone();
                async move { matches!(store.accept(moot, &operation).await, Ok(true)) }
            },
        )
        .await?;

        let flora_store = self.flora_store().clone();
        let flora = JoinedSpace::join::<_, u64, _, _>(
            lane_id(GEMOT_FLORA_LANE, moot),
            self.flora_store().sync_store(),
            endpoint,
            gossip,
            moot,
            move |operation: Operation<FloraExt>| {
                let store = flora_store.clone();
                async move { matches!(store.accept(moot, &operation).await, Ok(true)) }
            },
        )
        .await?;

        Ok(MootLanes {
            constitution,
            delegation,
            membership,
            records,
            standing,
            tulpa,
            flora,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The publish set exists, one method per lane, each taking that lane's
    /// own extension type. Compile-level: live lanes need a transport pair, so
    /// a unit test cannot hold a `MootLanes` to call them on. What can go
    /// wrong silently is a method bound to the wrong lane, and naming each
    /// item at its signature catches exactly that.
    #[test]
    fn the_publish_set_names_every_lane_at_its_own_extension() {
        let _: fn(&MootLanes, Operation<ConstitutionExt>) -> Result<(), JoinError> =
            MootLanes::publish_constitution;
        let _: fn(&MootLanes, Operation<MootDelegationExt>) -> Result<(), JoinError> =
            MootLanes::publish_delegation;
        let _: fn(&MootLanes, Operation<MootGroupExt>) -> Result<(), JoinError> =
            MootLanes::publish_membership;
        let _: fn(&MootLanes, Operation<MootExt>) -> Result<(), JoinError> =
            MootLanes::publish_records;
        let _: fn(&MootLanes, Operation<StandingExt>) -> Result<(), JoinError> =
            MootLanes::publish_standing;
        let _: fn(&MootLanes, Operation<TulpaExt>) -> Result<(), JoinError> =
            MootLanes::publish_tulpa;
        let _: fn(&MootLanes, Operation<FloraExt>) -> Result<(), JoinError> =
            MootLanes::publish_flora;
    }
}
