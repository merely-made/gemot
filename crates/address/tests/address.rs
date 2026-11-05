// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0
//! The release address grammar: round trips, refusals, the old root form.

use gemot_address::{AddressError, AddressHost, KnotAddress};

const KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const PIN: &str = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";

fn parse(text: &str) -> Result<KnotAddress, AddressError> {
    KnotAddress::parse(text)
}

#[test]
fn personae_root_addresses_still_parse() {
    let address = parse(&format!("knot://{KEY}/notes/today.scroll")).unwrap();
    assert_eq!(address.path, "notes/today.scroll");
    assert_eq!(address.pin, None);
    assert!(matches!(address.host, AddressHost::LogKey(k) if k[0] == 0x00 && k[31] == 0xff));
    assert_eq!(address.log_key().map(|k| k[1]), Some(0x11));
}

#[test]
fn round_trips_every_form() {
    for text in [
        format!("knot://{KEY}/index.scroll"),
        format!("knot://{KEY}/a/b/c.gmi@{PIN}"),
        format!("knot://{KEY}.moot/index.scroll"),
        format!("knot://{KEY}.moot/dir/@{PIN}"),
        format!("knot://{KEY}/dir/"),
        format!("knot://{KEY}/100%40home"),
        format!("knot://{KEY}/@team/page"),
        format!("knot://{KEY}/My Notes/field note.knot"),
        format!("knot://{KEY}/me@home.knot"),
        format!("knot://{KEY}/a?b#c"),
    ] {
        let parsed = parse(&text).unwrap_or_else(|e| panic!("{text}: {e}"));
        assert_eq!(parsed.to_string(), text);
        assert_eq!(parse(&parsed.to_string()).unwrap(), parsed);
    }
}

#[test]
fn case_is_accepted_and_rendered_lowercase() {
    let upper = format!("KNOT://{}/p@{}", KEY.to_uppercase(), PIN.to_uppercase());
    let parsed = parse(&upper).unwrap();
    assert_eq!(parsed.to_string(), format!("knot://{KEY}/p@{PIN}"));
    let moot = parse(&format!("knot://{}.MOOT/p", KEY.to_uppercase())).unwrap();
    assert!(matches!(moot.host, AddressHost::MootAnchor(_)));
    assert_eq!(moot.to_string(), format!("knot://{KEY}.moot/p"));
}

#[test]
fn moot_marker_cannot_be_read_as_a_key() {
    let moot = parse(&format!("knot://{KEY}.moot/p")).unwrap();
    let key = parse(&format!("knot://{KEY}/p")).unwrap();
    assert_ne!(moot, key);
    assert!(moot.log_key().is_none());
}

#[test]
fn refuses_malformed_hosts() {
    for host in [
        "vault".to_string(),
        KEY[..63].to_string(),
        format!("{KEY}0"),
        format!("{}g", &KEY[..63]),
        format!("{KEY}.moo"),
        format!("{KEY}.moot.moot"),
        format!("{}.moot", &KEY[..62]),
        String::new(),
        "é".repeat(32),
    ] {
        assert_eq!(
            parse(&format!("knot://{host}/p")),
            Err(AddressError::Host),
            "{host}"
        );
    }
}

#[test]
fn refuses_malformed_paths() {
    assert_eq!(parse(&format!("knot://{KEY}")), Err(AddressError::Path));
    for path in ["", "a//b", "../x", "a/./b", "a/..", "a\tb", "a\\b", "/"] {
        assert_eq!(
            parse(&format!("knot://{KEY}/{path}")),
            Err(AddressError::Path),
            "{path:?}"
        );
    }
    assert_eq!(
        parse(&format!("knot://{KEY}/@{PIN}")),
        Err(AddressError::Path)
    );
}

#[test]
fn refuses_malformed_pins() {
    for pin in ["", "abc", &PIN[..63], &format!("{PIN}0"), "a@b"] {
        assert_eq!(
            parse(&format!("knot://{KEY}/p@{pin}")),
            Err(AddressError::Pin),
            "{pin}"
        );
    }
}

#[test]
fn refuses_other_schemes_and_vault_addresses() {
    for text in [
        "",
        "knot:/x",
        "mere://x/y",
        "http://x/y",
        &format!("{KEY}/p"),
    ] {
        assert_eq!(parse(text), Err(AddressError::Scheme), "{text}");
    }
    assert_eq!(parse("knot://vault/field-note"), Err(AddressError::Host));
}

#[test]
fn pinned_builder_matches_written_pin() {
    let base = parse(&format!("knot://{KEY}/p")).unwrap();
    let pin = parse(&format!("knot://{KEY}/p@{PIN}")).unwrap();
    assert_eq!(base.pinned(pin.pin.unwrap()), pin);
}

#[test]
fn non_hex_text_after_at_stays_in_the_path() {
    let address = parse(&format!("knot://{KEY}/p@{}z", &PIN[..63])).unwrap();
    assert_eq!(address.pin, None);
    assert!(address.path.starts_with("p@ffee"));
}
