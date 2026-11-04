// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

//! Bounded relay runner: `relay-pool check|custody-check|run <private-config.json>`.
//! `check` validates structural configuration without opening custody, stores or networks.
//! `custody-check` requests the runner's scoped releases and reads its sealed
//! group record, then drops them without opening relay transports or stores.
//! `run` uses an existing Djinn grant, founded Moot, encrypted pool records and
//! sealed GroupSession record. Provision these through their existing owners.
//! It generates no root identity and exports no client offer. Its create-new
//! bootstrap file is OPERATOR-PRIVATE: it includes direct control locators and
//! an owner attestation. Public route/independent-host qualification is separate.
//!
//! Run: `cargo run -p gemot --example relay-pool --features relay-pool-runner --
//! run <config>`. Configuration is the deny-unknown-fields schema in
//! `relay-pool/config.rs`; all timing/resource settings are explicit. The
//! outgoing key salt for the retained Notochord v2 profile is
//! `mere/network-policy/session-signer/v1` (UTF-8 bytes). A recipient using
//! MatchCarrierWhenPresent requires this transcript-signer key on its Noise leg.
//!
//! Operator receiving order:
//! 1. Have the existing owners provision the founded Moot, current authority
//!    checkpoint, encrypted pool records and this operator's GroupSession.
//!    Seal the session's `to_bytes()` as a `Vec<u8>` application record with
//!    Personae SealedRecordStorage and the configured group-sealing derived key.
//!    The session's group ID and persona root must match this configuration and
//!    the custody persona. Use separate private directories for each operator.
//! 2. In Djinn's existing application admission UI/configuration, review the
//!    declaration and grant only the required custody operations and salts.
//!    The declaration states a request; the owner's grant permits it. The
//!    runner neither grants itself access nor switches/unlocks a persona.
//! 3. Run `check <config>`, then `custody-check <config>`. The latter contacts
//!    the configured resident, requests scoped keys and reads the sealed group.
//!    It requires authoritative custodian epoch evidence and a fresh status
//!    check. It creates no Moot/pool state, bootstrap, control or I2P session.
//!    Its success is a point-in-time receiving check, not lock-delivery proof.
//! 4. Run `run <config>` using fresh bootstrap/stop paths. In the trial, lock
//!    custody, withdraw authority, expire offers and stop the provider; retain
//!    counter/refusal/cleanup summaries, with keys and identifying paths private.
//!    Reconnect with owner-verified state; check never renews authority.
//!
//! Declare and grant the `custody` route and custody operations `status`,
//! `watch_lock`, `release`, `attest`. All four salts use the persona source:
//! - `gemot/relay/control/v1/` + binary pool ID + binary device ID;
//! - `gemot/relay/device/v1/` + binary pool ID + binary device ID;
//! - the configured outbound key salt;
//! - the configured group-sealing salt, separate from all transport keys.
//! Ostiary represents the binary-suffix scopes with its existing UTF-8 prefix
//! patterns. Use exact patterns for text-only salts. A prefix grant reaches
//! its full namespace: choose that scope deliberately in existing admission.
//! Custody-check prints only stage results, without roots, locators or secrets.
//! Independent operators/machines/uplinks, a third requester/recipient router
//! and public I2P fault/refusal checks remain deployment qualification gates.

#[path = "relay-pool/config.rs"]
mod config;
#[path = "relay-pool/custody.rs"]
mod custody;
#[path = "relay-pool/run.rs"]
mod run;
#[cfg(test)]
#[path = "relay-pool/tests.rs"]
mod tests;

fn main() -> std::process::ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let result = (|| {
        if args.len() != 2 {
            return Err("usage: relay-pool check|custody-check|run <private-config.json>");
        }
        let config = config::Config::load(std::path::Path::new(&args[1]))?;
        match args[0].to_str() {
            Some("check") => {
                println!("{{\"configuration\":\"checked\",\"qualification\":\"not-run\"}}");
                Ok(())
            }
            Some("custody-check") => custody::check(&config),
            Some("run") => run::run(config),
            _ => Err("usage: relay-pool check|custody-check|run <private-config.json>"),
        }
    })();
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(stage) => {
            eprintln!("relay-pool: {stage}");
            std::process::ExitCode::FAILURE
        }
    }
}
