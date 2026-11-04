// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Saved-file checkpoint capture. Storage is supplied by the caller, never
//! opened implicitly beside the working files or by starting a local server.
pub use site_model::history::*;

use crate::Site;

impl Site {
    /// Local history binding for this canonical folder. Moving a site to a
    /// different folder starts a different local history. This does not assign
    /// a public site identity and never changes the portable site manifest.
    pub fn history_id(&self) -> SiteId {
        let mut hash = blake3::Hasher::new();
        hash.update(b"knot-saved-site-folder-v1\0");
        hash.update(self.root().as_os_str().as_encoded_bytes());
        SiteId(*hash.finalize().as_bytes())
    }

    /// Capture only saved manifest/source, including hand edits since open.
    /// In-memory metadata drafts and editor buffers never enter this record.
    pub async fn checkpoint<B: muniment::Backend + Sync>(
        &self,
        history: &SiteHistory<B>,
        checkpoint: Checkpoint,
    ) -> Result<SiteRevision, HistoryError> {
        let snapshot = self
            .publication()
            .and_then(|publication| publication.to_snapshot_v1())
            .map_err(HistoryError::Invalid)?;
        history
            .record(self.history_id(), &snapshot, checkpoint)
            .await
    }
}
