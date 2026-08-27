// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The Moot's live lane set, joined as one act.
//!
//! A Moot replicates over five independent LogSync lanes — constitution,
//! delegation, membership, records, tessera — all subscribing to the Moot id
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
use super::records::{MootExt, MootLogId};
use super::service::Moot;
use super::tessera::TesseraExt;

/// Lane kinds, one spelling each, so both peers derive identical protocol ids.
pub const GEMOT_CONSTITUTION_LANE: &str = "gemot/constitution/v1";
pub const GEMOT_DELEGATION_LANE: &str = "gemot/delegation/v1";
pub const GEMOT_MEMBERSHIP_LANE: &str = "gemot/membership/v1";
pub const GEMOT_RECORDS_LANE: &str = "gemot/records/v1";
pub const GEMOT_TESSERA_LANE: &str = "gemot/tessera/v1";

/// One Moot's joined lane set. Dropping it leaves every lane.
pub struct MootLanes {
    pub constitution: JoinedSpace<ConstitutionExt>,
    pub delegation: JoinedSpace<MootDelegationExt>,
    pub membership: JoinedSpace<MootGroupExt>,
    pub records: JoinedSpace<MootExt>,
    pub tessera: JoinedSpace<TesseraExt>,
}

impl MootLanes {
    /// Sync activity across the set, in lane order, for a host's status
    /// surface. Per-lane rather than summed: a Steward that can only say
    /// "some lane is behind" cannot say which.
    pub fn sync_status(&self) -> [SyncStatus; 5] {
        [
            self.constitution.sync_status(),
            self.delegation.sync_status(),
            self.membership.sync_status(),
            self.records.sync_status(),
            self.tessera.sync_status(),
        ]
    }

    /// Shared counter handles, in the same lane order, for a host watching
    /// arrivals from a task that cannot borrow the lanes.
    pub fn status_handles(&self) -> [Arc<Mutex<SyncStatus>>; 5] {
        [
            self.constitution.status_handle(),
            self.delegation.status_handle(),
            self.membership.status_handle(),
            self.records.status_handle(),
            self.tessera.status_handle(),
        ]
    }
}

impl<B: Backend + Clone + Send + Sync + 'static> Moot<B> {
    /// Join all five of this Moot's lanes over the host transport's parts.
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

        let tesserae = self.tessera_store().clone();
        let tessera = JoinedSpace::join::<_, u64, _, _>(
            lane_id(GEMOT_TESSERA_LANE, moot),
            self.tessera_store().sync_store(),
            endpoint,
            gossip,
            moot,
            move |operation: Operation<TesseraExt>| {
                let store = tesserae.clone();
                async move { matches!(store.accept(moot, &operation).await, Ok(true)) }
            },
        )
        .await?;

        Ok(MootLanes {
            constitution,
            delegation,
            membership,
            records,
            tessera,
        })
    }
}
