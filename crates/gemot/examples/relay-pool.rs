// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

//! Bounded operator-owned relay runner: `relay-pool check|run <private-config.json>`.
//! `check` validates structural configuration without opening custody, stores or networks.
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

#[path = "relay-pool/config.rs"]
mod config;
#[path = "relay-pool/run.rs"]
mod run;
#[cfg(test)]
#[path = "relay-pool/tests.rs"]
mod tests;

fn main() -> std::process::ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let result = (|| {
        if args.len() != 2 {
            return Err("usage: relay-pool check|run <private-config.json>");
        }
        let config = config::Config::load(std::path::Path::new(&args[1]))?;
        match args[0].to_str() {
            Some("check") => {
                println!("{{\"configuration\":\"checked\",\"qualification\":\"not-run\"}}");
                Ok(())
            }
            Some("run") => run::run(config),
            _ => Err("usage: relay-pool check|run <private-config.json>"),
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
