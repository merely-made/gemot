/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use serde::{Deserialize, Serialize};

/// A moot's stable identity: the community key.
///
/// The bytes remain opaque to the domain model. Protocol adapters decide how
/// a founding declaration or public key yields them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MootId(pub [u8; 32]);

impl From<[u8; 32]> for MootId {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl AsRef<[u8; 32]> for MootId {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_opaque_identity_bytes() {
        let bytes = [7; 32];
        let id = MootId::from(bytes);

        assert_eq!(id.as_ref(), &bytes);
    }
}
