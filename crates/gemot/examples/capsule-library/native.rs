// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Native host for the proof's two action names. It uses signed Servitor
//! delegations, independently of pack signatures and community admission.
use super::{
    AnyError, ensure,
    model::{Catalogue, Entry},
    now_ms,
};
use app_host::{ActionSink, AppScript, Refusal, Watchdog, guarded_engine};
use identity::delegation::Issue;
use identity::{IdentityProvider, InMemoryProvider};
use insigne::SignedDelegationCertificate;
use serde::{Deserialize, Serialize};
use servitor::delegation::root_certificate;
use servitor::{AuthorityProvider, Cap, DelegationTable, Mode, Subject};
use std::collections::BTreeSet;
use std::time::Duration;
use wasmtime::StoreLimitsBuilder;

pub struct Sink {
    authority: DelegationTable,
    subject: Subject,
    entries: Vec<Entry>,
    views: Vec<Vec<Entry>>,
    opened: Vec<String>,
    pub refusals: Vec<String>,
}

impl Default for Sink {
    fn default() -> Self {
        Self {
            authority: DelegationTable::default(),
            subject: Subject([0; 32]),
            entries: Vec::new(),
            views: Vec::new(),
            opened: Vec::new(),
            refusals: Vec::new(),
        }
    }
}

impl ActionSink for Sink {
    fn emit(&mut self, name: &str, payload: &str) -> Result<(), Refusal> {
        let result = self.check(name, payload);
        if let Err(error) = &result {
            self.refusals.push(format!("{error:?}"));
        }
        result
    }
}

impl Sink {
    fn check(&mut self, name: &str, payload: &str) -> Result<(), Refusal> {
        let cap = match name {
            "capsule-library-view" => Cap::Power("capsule-view".into()),
            "open-address" => Cap::Power("navigate".into()),
            "confirm-install-participant" => return Err(Refusal::Denied("host-only".into())),
            _ => return Err(Refusal::Unknown(name.into())),
        };
        if !self.authority.covers(self.subject, &cap, Mode::Write) {
            return Err(Refusal::Denied(servitor::cap_path(&cap)));
        }
        match name {
            "capsule-library-view" => {
                let entries: Vec<Entry> =
                    serde_json::from_str(payload).map_err(|e| Refusal::Malformed(e.to_string()))?;
                // A projection cannot mint new addresses or change authorship.
                let mut seen = BTreeSet::new();
                if entries
                    .iter()
                    .any(|e| !self.entries.contains(e) || !seen.insert(&e.revision))
                {
                    return Err(Refusal::Denied("outside disclosed catalogue".into()));
                }
                self.views.push(entries);
            },
            "open-address" => {
                #[derive(Deserialize)]
                struct Open {
                    url: String,
                }
                let open: Open =
                    serde_json::from_str(payload).map_err(|e| Refusal::Malformed(e.to_string()))?;
                if !self.entries.iter().any(|e| e.url == open.url) {
                    return Err(Refusal::Denied("outside disclosed catalogue".into()));
                }
                self.opened.push(open.url);
            },
            _ => unreachable!(),
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub struct NativeReceipt {
    pub pid: u32,
    pub browse: Vec<Entry>,
    pub search: Vec<Entry>,
    pub opened: Vec<String>,
    pub refusals: Vec<String>,
    pub missing_capability_reported: bool,
    pub signed_grant_revocation_refused: bool,
    pub runaway_interrupted: bool,
    pub logs: Vec<String>,
}

pub fn run(
    component: &[u8],
    entries: Vec<Entry>,
    subject: Subject,
) -> Result<NativeReceipt, AnyError> {
    let local_owner = InMemoryProvider::from_seed([0xb2; 32]);
    let mut authority = DelegationTable::new(local_owner.master_public_key().to_bytes());
    authority.set_now(now_ms());
    let mut grants = Vec::new();
    for (i, name) in ["capsule-view", "navigate"].into_iter().enumerate() {
        let cert = root_certificate(
            authority.root(),
            subject,
            &Cap::Power(name.into()),
            Mode::Write,
            b"capsule-library-instance".to_vec(),
            0,
            None,
            0,
            [i as u8 + 1; 32],
        );
        let signed = SignedDelegationCertificate::issue(&local_owner, cert)?;
        grants.push(signed.certificate.id());
        authority.adopt(signed);
    }
    let sink = Sink {
        authority,
        subject,
        entries: entries.clone(),
        ..Default::default()
    };
    let engine = guarded_engine()?;
    let _watchdog = Watchdog::start(engine.clone(), Duration::from_millis(5));
    let mut guest = AppScript::attach_blocking_bytes(
        &engine,
        component,
        sink,
        vec!["power:capsule-view".into(), "power:navigate".into()],
        StoreLimitsBuilder::new()
            .memory_size(64 * 1024 * 1024)
            .build(),
        Some(400),
    )?;
    guest.activate_blocking()?;
    for query in ["", "garden"] {
        guest.on_event_blocking(
            "catalogue",
            &serde_json::to_string(&Catalogue {
                query: query.into(),
                entries: entries.clone(),
            })?,
        )?;
    }
    guest.on_event_blocking(
        "open",
        &serde_json::json!({"url": entries[0].url}).to_string(),
    )?;
    guest.on_event_blocking("probe", "")?;
    ensure(guest.sink().views.len() == 2, "native projection missing")?;
    ensure(
        guest.sink().views[0].len() == 2 && guest.sink().views[1].len() == 1,
        "native search incorrect",
    )?;
    ensure(
        guest.sink().refusals.len() == 4,
        "negative controls did not refuse",
    )?;
    let refused_before = guest.sink().refusals.len();
    guest.sink_mut().authority.revoke(grants[1]);
    guest.on_event_blocking(
        "open",
        &serde_json::json!({"url": entries[0].url}).to_string(),
    )?;
    let signed_grant_revocation_refused = guest.sink().refusals.len() == refused_before + 1;
    let mut limited = AppScript::attach_blocking_bytes(
        &engine,
        component,
        Sink::default(),
        Vec::new(),
        StoreLimitsBuilder::new()
            .memory_size(64 * 1024 * 1024)
            .build(),
        Some(400),
    )?;
    limited.activate_blocking()?;
    limited.on_event_blocking(
        "catalogue",
        &serde_json::to_string(&Catalogue {
            query: String::new(),
            entries,
        })?,
    )?;
    let missing_capability_reported = limited
        .logs()
        .iter()
        .any(|l| l.contains("missing power:capsule-view"));
    guest.deactivate_blocking()?;
    // Another instance keeps a trapping guest from poisoning the useful session.
    let runaway_interrupted = limited.on_event_blocking("spin", "").is_err();
    ensure(
        missing_capability_reported && signed_grant_revocation_refused && runaway_interrupted,
        "grant or containment negative control failed",
    )?;
    Ok(NativeReceipt {
        pid: std::process::id(),
        browse: guest.sink().views[0].clone(),
        search: guest.sink().views[1].clone(),
        opened: guest.sink().opened.clone(),
        refusals: guest.sink().refusals.clone(),
        missing_capability_reported,
        signed_grant_revocation_refused,
        runaway_interrupted,
        logs: guest.logs().to_vec(),
    })
}
