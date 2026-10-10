// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! A portable catalogue projection over host-disclosed metadata. The guest
//! never fetches a capsule or owns the community's selection or storage.
wit_bindgen::generate!({
    path: "../../../../../script/wit",
    world: "app-core",
});

use mere::script::{
    actions::{ActionEnvelope, emit},
    caps::granted,
    log::log,
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
struct Entry {
    title: String,
    author: String,
    revision: String,
    url: String,
    bytes: u64,
}

#[derive(Deserialize)]
struct Catalogue {
    query: String,
    entries: Vec<Entry>,
}

struct Applet;

fn try_emit(name: &str, payload: String) {
    if let Err(error) = emit(&ActionEnvelope {
        name: name.into(),
        payload,
    }) {
        log(&format!("{name}: {error:?}"));
    }
}

impl Guest for Applet {
    fn activate() {
        log(&format!("capsule library ready; {:?}", granted()));
    }

    fn on_event(kind: String, payload: String) {
        match kind.as_str() {
            "catalogue" => {
                if !granted().iter().any(|cap| cap == "power:capsule-view") {
                    log("missing power:capsule-view; catalogue unavailable");
                    return;
                }
                match serde_json::from_str::<Catalogue>(&payload) {
                    Ok(catalogue) => {
                        let query = catalogue.query.to_lowercase();
                        let entries: Vec<_> = catalogue
                            .entries
                            .into_iter()
                            .filter(|entry| {
                                entry.title.to_lowercase().contains(&query)
                                    || entry.author.to_lowercase().contains(&query)
                            })
                            .collect();
                        try_emit(
                            "capsule-library-view",
                            serde_json::to_string(&entries).unwrap(),
                        );
                    },
                    Err(error) => log(&format!("malformed catalogue: {error}")),
                }
            },
            "open" => try_emit("open-address", payload),
            // Negative controls use the ordinary ABI, not privileged test imports.
            "probe" => {
                try_emit("confirm-install-participant", String::new());
                try_emit(
                    "open-address",
                    "{\"url\":\"https://outside.invalid/\"}".into(),
                );
                try_emit("open-address", "{}".into());
                try_emit("unknown-action", String::new());
            },
            "spin" => loop {
                std::hint::spin_loop();
            },
            _ => log("unknown event"),
        }
    }

    fn deactivate() {
        log("capsule library stopped");
    }
}

export!(Applet);
