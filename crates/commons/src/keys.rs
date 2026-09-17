// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The refreshable group keyring shared by chat and the encrypted graph.
//!
//! A keyring captured when a lane joins goes stale at the next rotation. Every
//! clone of a [`GroupKeys`] reads the same current keyring, so a host that
//! drains a rotation from the group-key lane replaces it once and every
//! replica and joined lane holding a clone admits, authors and projects with
//! the new epochs from its next operation on, without rejoining.

use std::sync::{Arc, PoisonError, RwLock};

use stickleback::{DataKeyring, GroupCryptoError};

/// Cheap-to-clone shared handle over a group's current data keyring.
#[derive(Clone, Debug)]
pub struct GroupKeys(Arc<RwLock<Arc<DataKeyring>>>);

impl GroupKeys {
    pub fn new(keys: DataKeyring) -> Self {
        Self(Arc::new(RwLock::new(Arc::new(keys))))
    }

    /// A handle over persisted keyring bytes, e.g.
    /// `GroupSession::data_keyring_state`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, GroupCryptoError> {
        DataKeyring::from_bytes(bytes).map(Self::new)
    }

    /// A snapshot of the current keyring. One admission, authoring turn or
    /// projection reads one snapshot; a concurrent replace does not change it.
    pub fn current(&self) -> Arc<DataKeyring> {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Swap in a new keyring for every holder of this handle.
    pub fn replace(&self, keys: DataKeyring) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(keys);
    }

    /// [`Self::replace`] from persisted keyring bytes.
    pub fn replace_from_bytes(&self, bytes: &[u8]) -> Result<(), GroupCryptoError> {
        self.replace(DataKeyring::from_bytes(bytes)?);
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, GroupCryptoError> {
        self.current().to_bytes()
    }
}

impl From<DataKeyring> for GroupKeys {
    fn from(keys: DataKeyring) -> Self {
        Self::new(keys)
    }
}

/// A founded three-member group for rotation tests, built with stickleback's
/// `GroupSession` the way the group-key lane tests build theirs, minus the
/// lane: frames are processed directly, in order.
#[cfg(test)]
pub(crate) mod test_group {
    use personae::InMemoryProvider;
    use stickleback::{DataKeyring, GroupPrekeyBundle, GroupSession, GroupSessionId};

    const GROUP: GroupSessionId = GroupSessionId([0x4b; 32]);

    pub(crate) struct Group {
        pub a: GroupSession,
        pub b: GroupSession,
        pub c: GroupSession,
        a_prekey: GroupPrekeyBundle,
    }

    fn member(seed: u8) -> (GroupSession, GroupPrekeyBundle) {
        GroupSession::new(GROUP, &InMemoryProvider::from_seed([seed; 32])).unwrap()
    }

    impl Group {
        /// A founds alone, then adds B and C; everyone holds the founding epoch.
        pub fn found() -> Self {
            let (mut a, a_prekey) = member(0xa1);
            let (mut b, b_prekey) = member(0xb2);
            let (mut c, c_prekey) = member(0xc3);
            a.register_prekey(&b_prekey).unwrap();
            a.register_prekey(&c_prekey).unwrap();
            b.register_prekey(&a_prekey).unwrap();
            c.register_prekey(&a_prekey).unwrap();
            a.create(&[]).unwrap();
            let root = a.personae_root();
            let add_b = a.add(b.member()).unwrap();
            b.process(root, &add_b.control, add_b.direct_for(b.member()))
                .unwrap();
            let add_c = a.add(c.member()).unwrap();
            c.process(root, &add_c.control, add_c.direct_for(c.member()))
                .unwrap();
            b.process(root, &add_c.control, add_c.direct_for(b.member()))
                .unwrap();
            Self { a, b, c, a_prekey }
        }

        /// A adds a new member, which B and C also process; returns it.
        pub fn invite(&mut self, seed: u8) -> GroupSession {
            let (mut invitee, prekey) = member(seed);
            self.a.register_prekey(&prekey).unwrap();
            invitee.register_prekey(&self.a_prekey).unwrap();
            let root = self.a.personae_root();
            let add = self.a.add(invitee.member()).unwrap();
            for session in [&mut self.b, &mut self.c, &mut invitee] {
                let direct = add.direct_for(session.member());
                session.process(root, &add.control, direct).unwrap();
            }
            invitee
        }

        /// A rotates; B and C process the frame.
        pub fn rotate(&mut self) {
            let root = self.a.personae_root();
            let rotation = self.a.update().unwrap();
            for session in [&mut self.b, &mut self.c] {
                let direct = rotation.direct_for(session.member());
                session.process(root, &rotation.control, direct).unwrap();
            }
        }

        /// A removes C and rotates. B and C both process both frames in order;
        /// only B installs the new epochs.
        pub fn remove_c_and_rotate(&mut self) {
            let root = self.a.personae_root();
            let removal = self.a.remove(self.c.member()).unwrap();
            let rotation = self.a.update().unwrap();
            for dispatch in [&removal, &rotation] {
                for session in [&mut self.b, &mut self.c] {
                    let direct = dispatch.direct_for(session.member());
                    session.process(root, &dispatch.control, direct).unwrap();
                }
            }
        }
    }

    /// The keyring a host loads beside `session` after draining.
    pub(crate) fn keyring(session: &GroupSession) -> DataKeyring {
        DataKeyring::from_bytes(&session.data_keyring_state().unwrap()).unwrap()
    }
}
