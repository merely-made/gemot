// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Explicit saved-file publication into host-supplied community and content
//! owners. Captured bytes accompany the signed receipt for exact handoff.

use crate::{PublishedSnapshotV1, Site};
use gemot::moot::{CollectionVersion, ContributionRef, Moot};
pub use site_model::publication::*;

pub struct SavedSitePublication {
    pub snapshot: PublishedSnapshotV1,
    pub receipt: SitePublishReceipt,
}

impl Site {
    #[allow(clippy::too_many_arguments)]
    pub async fn publish_to_collection<
        B: muniment::Backend + Clone,
        P: personae::IdentityProvider + ?Sized,
    >(
        &self,
        moot: &Moot<B>,
        identity: &P,
        content: &mut dyn muniment::Backend,
        observed: &CollectionVersion,
        replace: Option<ContributionRef>,
        title: String,
        at_ms: u64,
    ) -> Result<SavedSitePublication, SitePublishError> {
        let snapshot = self
            .publication()
            .and_then(|publication| publication.to_snapshot_v1())
            .map_err(|reason| SitePublishError {
                reason,
                contribution: None,
                collection_operations: vec![],
            })?;
        let receipt = publish_public_snapshot(
            moot, identity, content, &snapshot, observed, replace, title, at_ms,
        )
        .await?;
        Ok(SavedSitePublication { snapshot, receipt })
    }
}
