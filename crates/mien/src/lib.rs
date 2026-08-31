// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Name reservation for **mien**, reputation in the Mere platform's moot tier.
//!
//! A mien is a persona's standing *as one moot sees it*. Reputation here is
//! per-moot primary: standing lives in each moot's own ledger, and there is no
//! single global score. A viewer moot folds its own ledger together with the
//! moots it concords — one hop and no further, so trust never launders down a
//! chain of agreements — under a composition policy that moot chooses.
//!
//! The word is the architecture. A *mien* is the impression you make on a
//! beholder: there is no objective mien, only how you appear to someone in
//! particular. That is the invariant this tier is built on, and it is why the
//! name is not `standing` or `score`, which both suggest a fact about the
//! persona rather than a view held by a moot.
//!
//! Accrual and depreciation are standing-denominated; the mien is what a moot
//! reads off its ledger, alone or composed.
//!
//! Not the proof of who you are: that is `insigne`.
//!
//! No implementation yet. The working code is in `moothold`'s concord module
//! and `gemot`'s standing store.

#![doc(html_no_source)]
