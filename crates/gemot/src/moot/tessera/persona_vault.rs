// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Persona-vault adapter — tessera's abstract persona ids resolved to real keys.
//!
//! Tessera's [`PersonaId`] is opaque (Phase 2). In the running system a persona
//! is a key the identity vault derives from `master + persona_id`
//! (`derive_keypair(BLAKE3("persona" || persona_id))`, per the persona model).
//! This adapter is the bridge: it derives a persona's signing keypair from the
//! vault, maps it to the tessera [`PersonaId`] (the derived public key), and
//! builds a [`PersonaChains`] forest from the persona model's parent links — so
//! tessera operations are signed by the right persona ([`crate::moot::tessera::wire`])
//! and the depreciation chain resolves to real chain roots.
//!
//! `persona_id` here is a persona's *logical* id (e.g. a UUID's bytes), distinct
//! from the tessera [`PersonaId`] (its derived public key). The vault holds the
//! master secret; this module only consumes the public derivation. The parent
//! links it folds into a chain come from the persona store (identity-side, still
//! being built); the adapter is ready for them.

use identity::{Ed25519Keypair, IdentityError, IdentityProvider};
use p2panda_core::Hash;

use crate::moot::tessera::persona_chain::{PersonaChains, PersonaId};

/// The vault salt for a persona's keypair: `BLAKE3("persona" || persona_id)`,
/// where `persona_id` is the persona's logical id.
pub fn persona_salt(persona_id: &[u8]) -> [u8; 32] {
    *Hash::digest([b"persona".as_slice(), persona_id].concat()).as_bytes()
}

/// Derive a persona's signing keypair from the master identity. This keypair
/// signs that persona's tessera operations.
pub fn persona_keypair(
    provider: &dyn IdentityProvider,
    persona_id: &[u8],
) -> Result<Ed25519Keypair, IdentityError> {
    provider.derive_keypair(&persona_salt(persona_id))
}

/// A persona's tessera [`PersonaId`] — the public key the vault derives for it.
pub fn tessera_persona_id(
    provider: &dyn IdentityProvider,
    persona_id: &[u8],
) -> Result<PersonaId, IdentityError> {
    Ok(PersonaId(
        persona_keypair(provider, persona_id)?
            .public_key()
            .to_bytes(),
    ))
}

/// Build a tessera [`PersonaChains`] forest from the persona model's parent links
/// `(persona_id, parent_persona_id)`, deriving each persona's tessera id from the
/// vault. A `None` parent marks a chain root (no fork link recorded).
pub fn build_chains<'a>(
    provider: &dyn IdentityProvider,
    links: impl IntoIterator<Item = (&'a [u8], Option<&'a [u8]>)>,
) -> Result<PersonaChains, IdentityError> {
    let mut chains = PersonaChains::new();
    for (child, parent) in links {
        if let Some(parent) = parent {
            let child_id = tessera_persona_id(provider, child)?;
            let parent_id = tessera_persona_id(provider, parent)?;
            chains.fork(child_id, parent_id);
        }
    }
    Ok(chains)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::moot::tessera::ChainRoot;
    use identity::InMemoryProvider;

    fn provider() -> InMemoryProvider {
        InMemoryProvider::from_seed([5; 32])
    }

    #[test]
    fn a_persona_id_is_stable_and_distinct() {
        let p = provider();
        let work = tessera_persona_id(&p, b"work").unwrap();
        let work_again = tessera_persona_id(&p, b"work").unwrap();
        let throwaway = tessera_persona_id(&p, b"throwaway").unwrap();
        assert_eq!(work, work_again, "same persona derives the same tessera id");
        assert_ne!(work, throwaway, "different personas, different ids");
    }

    #[test]
    fn build_chains_resolves_a_fork_to_its_root() {
        let p = provider();
        let work = tessera_persona_id(&p, b"work").unwrap();
        // `throwaway` is a fork of `work` — same human, a fresh face.
        let links: Vec<(&[u8], Option<&[u8]>)> =
            vec![(b"work", None), (b"throwaway", Some(b"work"))];
        let chains = build_chains(&p, links).unwrap();
        let throwaway = tessera_persona_id(&p, b"throwaway").unwrap();
        let (root, depth) = chains.root_and_depth(throwaway);
        assert_eq!(
            root,
            ChainRoot(work.0),
            "the fork resolves to work's chain root"
        );
        assert_eq!(depth, 1);
    }

    #[test]
    fn the_derived_keypair_signs_a_verifiable_tessera_operation() {
        use crate::moot::tessera::event::{ChainRoot, TesseraEvent};
        use crate::moot::tessera::wire::{to_operation, verify};
        let p = provider();
        let kp = persona_keypair(&p, b"work").unwrap();
        let event = TesseraEvent::GovernanceParticipation {
            by: ChainRoot(kp.public_key().to_bytes()),
            at_ms: 1,
        };
        let op = to_operation(&kp, [0x30; 32], &event, 0, None);
        assert!(
            verify(&op),
            "a vault-derived persona key signs a valid tessera op"
        );
    }
}
