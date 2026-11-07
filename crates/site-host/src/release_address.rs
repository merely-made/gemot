// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Gemot's `knot://` address as a Murm release address.
//!
//! `murm-resolve` owns the trait ([`murm_resolve::ReleaseAddress`]) and no
//! grammar; Gemot owns the grammar ([`site_model::address::KnotAddress`]).
//! Neither type is local to this crate, so the trait is implemented for a
//! borrowing wrapper. The grammar crate stays free of Murm and of every other
//! carrier or storage dependency, which is why the implementation lives here,
//! behind the `murm-resolve` feature, and not beside `gemot-address`.
//!
//! ```ignore
//! let address: KnotAddress = text.parse()?;
//! resolver.resolve(&ReleaseAddressRef(&address), &hints).await?;
//! ```

use murm_resolve::{AddressHost, MootCollection, ReleaseAddress};
use site_model::address::{AddressHost as GemotHost, KnotAddress};

/// A parsed [`KnotAddress`], borrowed, for `Resolver::resolve`.
#[derive(Clone, Copy, Debug)]
pub struct ReleaseAddressRef<'a>(pub &'a KnotAddress);

impl ReleaseAddress for ReleaseAddressRef<'_> {
    fn host(&self) -> AddressHost {
        match self.0.host {
            GemotHost::LogKey(key) => AddressHost::LogKey(key),
            GemotHost::MootId(id) => AddressHost::MootId(id),
        }
    }

    fn collection(&self) -> Option<MootCollection> {
        self.0.collection().map(|parts| MootCollection {
            moot_id: parts.moot_id,
            collection_id: parts.collection_id,
            page: parts.page.to_owned(),
        })
    }

    fn pin(&self) -> Option<[u8; 32]> {
        self.0.pin
    }

    fn path(&self) -> &str {
        &self.0.path
    }
}
