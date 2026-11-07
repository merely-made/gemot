// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Gemot's parsed `knot://` address satisfies Murm's resolver trait.

use gemot_site_host::release_address::ReleaseAddressRef;
use murm_resolve::{AddressHost, MootCollection, ReleaseAddress, ResolveError, Resolver};
use site_model::address::KnotAddress;

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn the_log_form_maps_host_pin_and_path() {
    let text = format!("knot://{}/docs/index.gmi@{}", hex(&[3; 32]), hex(&[4; 32]));
    let address: KnotAddress = text.parse().unwrap();
    let view = ReleaseAddressRef(&address);
    assert_eq!(view.host(), AddressHost::LogKey([3; 32]));
    assert_eq!(view.pin(), Some([4; 32]));
    assert_eq!(view.path(), "docs/index.gmi");
    assert_eq!(view.collection(), None);
}

#[test]
fn the_governed_form_maps_its_collection() {
    let text = format!("knot://{}.moot/{}/index.gmi", hex(&[7; 32]), hex(&[8; 32]));
    let address: KnotAddress = text.parse().unwrap();
    let view = ReleaseAddressRef(&address);
    assert_eq!(view.host(), AddressHost::MootId([7; 32]));
    assert_eq!(
        view.collection(),
        Some(MootCollection {
            moot_id: [7; 32],
            collection_id: [8; 32],
            page: "index.gmi".to_owned(),
        })
    );
}

#[tokio::test]
async fn the_resolver_hands_the_governed_form_back_through_the_trait() {
    let text = format!("knot://{}.moot/{}/index.gmi", hex(&[7; 32]), hex(&[8; 32]));
    let address: KnotAddress = text.parse().unwrap();
    let refused = Resolver::new().resolve(&ReleaseAddressRef(&address), &[]).await;
    let Err(ResolveError::Governed {
        moot_id,
        collection_id,
        page,
    }) = refused
    else {
        panic!("governed addresses are not resolved here");
    };
    assert_eq!(
        (moot_id, collection_id, page.as_str()),
        ([7; 32], [8; 32], "index.gmi")
    );
}

#[tokio::test]
async fn a_log_address_with_no_carrier_is_unresolved() {
    let text = format!("knot://{}/index.gmi", hex(&[3; 32]));
    let address: KnotAddress = text.parse().unwrap();
    let refused = Resolver::new().resolve(&ReleaseAddressRef(&address), &[]).await;
    assert!(matches!(refused, Err(ResolveError::Unresolved { .. })));
}
