// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Neutral exact references to artifacts held by another subsystem.
//!
//! Gemot may govern, cite, and receipt an artifact without becoming its blob
//! store. In particular these references carry neither a URL nor raw bytes:
//! Eidetic/Muniment decides persistence and availability, and Distillery/ESP
//! decides how tensor bytes are interpreted.

/// A content identity plus the exact number of bytes it names.
///
/// This is the neutral `proofs` form rather than an Eidetic object type, so
/// Gemot can carry exact references without acquiring a storage dependency.
pub type ArtifactRef = proofs::BlobRef;
