// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Host-owned epoch pruning for the lanes that share one [`crate::GroupKeys`].
//!
//! Each lane reports what its retained records still need and what it could
//! release; no lane touches the handle. [`release_epochs`] keeps every epoch
//! any lane needs, and the current one. The host forgets the rest in its group
//! session, persists the session, then refreshes the handle from it:
//!
//! ```ignore
//! let reports = [chat.epoch_report(&[]).await?, graph.epoch_report().await?];
//! let release = release_epochs(inventory, &reports);
//! session.forget_epochs(&release.release)?;
//! save(session.to_bytes()?);
//! keys.replace_from_bytes(&session.data_keyring_state()?)?;
//! ```

use std::collections::BTreeSet;

use stickleback::{EpochRetentionReason, GroupSecretId};

/// Why one lane keeps one epoch.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EpochNeedReason {
    /// The sealing epoch is never released.
    Current,
    /// Chat's retention proposal keeps it.
    Chat(EpochRetentionReason),
    /// This many retained encrypted-graph records are sealed under it.
    EncryptedGraph { records: usize },
    /// A lane's report names it neither needed nor releasable.
    Unreported { lane: &'static str },
}

/// One epoch one lane needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochNeed {
    pub epoch: GroupSecretId,
    pub reason: EpochNeedReason,
}

/// One lane's view of the epochs in its key snapshot. Changes nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaneEpochReport {
    pub lane: &'static str,
    pub needed: Vec<EpochNeed>,
    /// What this lane alone could release.
    pub releasable: Vec<GroupSecretId>,
}

/// An epoch kept, with every lane's reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldEpoch {
    pub epoch: GroupSecretId,
    pub reasons: Vec<EpochNeedReason>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EpochRelease {
    /// For `GroupSession::forget_epochs`, oldest first.
    pub release: Vec<GroupSecretId>,
    pub retained_with_reasons: Vec<HeldEpoch>,
}

/// Release an epoch only when it is not current and every report lists it
/// releasable. `inventory` is oldest first, as
/// `DataKeyring::epochs_oldest_first`, so its last epoch is current.
pub fn release_epochs(inventory: &[GroupSecretId], reports: &[LaneEpochReport]) -> EpochRelease {
    let mut outcome = EpochRelease::default();
    for (index, epoch) in inventory.iter().enumerate() {
        let mut reasons = BTreeSet::new();
        if index + 1 == inventory.len() {
            reasons.insert(EpochNeedReason::Current);
        }
        for report in reports {
            let needs: Vec<_> = report
                .needed
                .iter()
                .filter(|need| need.epoch == *epoch)
                .map(|need| need.reason.clone())
                .collect();
            if needs.is_empty() && !report.releasable.contains(epoch) {
                reasons.insert(EpochNeedReason::Unreported { lane: report.lane });
            }
            reasons.extend(needs);
        }
        if reasons.is_empty() {
            outcome.release.push(*epoch);
        } else {
            outcome.retained_with_reasons.push(HeldEpoch {
                epoch: *epoch,
                reasons: reasons.into_iter().collect(),
            });
        }
    }
    outcome
}

/// The host path the tests drive.
#[cfg(test)]
pub(crate) mod host {
    use stickleback::{DataKeyring, GroupSession};

    use super::*;
    use crate::GroupKeys;

    /// Release, forget in the session, persist it, refresh the handle from
    /// the persisted session.
    pub(crate) fn apply(
        session: &mut GroupSession,
        keys: &GroupKeys,
        reports: &[LaneEpochReport],
    ) -> EpochRelease {
        let inventory = DataKeyring::from_bytes(&session.data_keyring_state().unwrap())
            .unwrap()
            .epochs_oldest_first()
            .unwrap()
            .to_vec();
        let release = release_epochs(&inventory, reports);
        session.forget_epochs(&release.release).unwrap();
        *session = GroupSession::from_bytes(&session.to_bytes().unwrap()).unwrap();
        keys.replace_from_bytes(&session.data_keyring_state().unwrap())
            .unwrap();
        release
    }
}

#[cfg(test)]
mod tests {
    use chartulary::{Author, Container};
    use muniment::MemoryBackend;
    use p2panda_core::SigningKey;
    use proofs::Digest;
    use stickleback::DataKeyring;

    use super::*;
    use crate::GroupKeys;
    use crate::chat::{ChatCheckpointAuthority, ChatEvent, ChatReplica, Message};
    use crate::encrypted::EncryptedReplica;
    use crate::keys::test_group::{Group, keyring};
    use crate::tests::fingerprint;

    /// Chat and the encrypted graph on one handle, each with a record under
    /// the founding epoch, then nine rotations and a chat checkpoint.
    struct Lanes {
        group: Group,
        keys: GroupKeys,
        chat: ChatReplica<MemoryBackend>,
        graph: EncryptedReplica<MemoryBackend>,
        epochs: Vec<GroupSecretId>,
    }

    async fn lanes() -> Lanes {
        let mut group = Group::found();
        let keys = GroupKeys::new(keyring(&group.a));
        let seed = [0xa1; 32];
        let mut chat = ChatReplica::in_memory([0x51; 32], seed, keys.clone());
        chat.set_checkpoint_authority(ChatCheckpointAuthority::new(
            Digest::blake3(b"lanes"),
            [*SigningKey::from_bytes(&seed).verifying_key().as_bytes()],
        ));
        chat.author(ChatEvent::Message(Message {
            channel: "general".into(),
            body: "founding".into(),
            sent_at_ms: 1,
            reply_to: None,
        }))
        .await
        .unwrap();
        let mut graph =
            EncryptedReplica::new(MemoryBackend::new(), [0xc0; 32], [0xa2; 32], keys.clone());
        graph
            .edit(|g| {
                g.insert_node(&Author::new("ui"), Container::new("founding"));
            })
            .await
            .unwrap();
        for _ in 0..9 {
            group.rotate();
        }
        keys.replace(keyring(&group.a));
        chat.author_checkpoint().await.unwrap();
        let epochs = keys.current().epochs_oldest_first().unwrap().to_vec();
        assert_eq!(epochs.len(), 10);
        Lanes {
            group,
            keys,
            chat,
            graph,
            epochs,
        }
    }

    impl Lanes {
        async fn reports(&self) -> [LaneEpochReport; 2] {
            [
                self.chat.epoch_report(&[]).await.unwrap(),
                self.graph.epoch_report().await.unwrap(),
            ]
        }

        async fn assert_both_project(&self) {
            let chat = self.chat.projection().await.unwrap();
            assert_eq!(chat.messages.len(), 1);
            assert_eq!(chat.messages[0].message.body, "founding");
            let (nodes, _) = fingerprint(&self.graph.projection().await.unwrap().graph);
            assert_eq!(nodes.len(), 1);
            assert_eq!(nodes[0].0, "founding");
        }
    }

    #[test]
    fn an_unreported_epoch_is_kept_and_the_last_is_current() {
        let inventory = [[1; 32], [2; 32], [3; 32]];
        let quiet = LaneEpochReport {
            lane: "quiet",
            needed: Vec::new(),
            releasable: vec![[1; 32], [3; 32]],
        };
        let release = release_epochs(&inventory, &[quiet]);
        assert_eq!(release.release, [[1; 32]]);
        assert_eq!(
            release.retained_with_reasons,
            [
                HeldEpoch {
                    epoch: [2; 32],
                    reasons: vec![EpochNeedReason::Unreported { lane: "quiet" }],
                },
                HeldEpoch {
                    epoch: [3; 32],
                    reasons: vec![EpochNeedReason::Current],
                },
            ]
        );
    }

    #[tokio::test]
    async fn an_epoch_the_encrypted_graph_needs_is_retained_with_its_reason() {
        let mut lanes = lanes().await;
        let founding = lanes.epochs[0];
        let [chat, graph] = lanes.reports().await;
        assert!(
            chat.releasable.contains(&founding),
            "chat alone could release it: {chat:?}"
        );
        assert!(graph.needed.contains(&EpochNeed {
            epoch: founding,
            reason: EpochNeedReason::EncryptedGraph { records: 1 },
        }));
        assert!(!graph.releasable.contains(&founding));

        let release = host::apply(&mut lanes.group.a, &lanes.keys, &[chat, graph]);
        assert!(!release.release.contains(&founding));
        let held = release
            .retained_with_reasons
            .iter()
            .find(|held| held.epoch == founding)
            .unwrap();
        assert_eq!(
            held.reasons,
            [EpochNeedReason::EncryptedGraph { records: 1 }]
        );
        assert!(lanes.keys.current().contains(&founding));
        lanes.assert_both_project().await;
    }

    #[tokio::test]
    async fn an_epoch_no_lane_needs_is_forgotten_and_stays_forgotten() {
        let mut lanes = lanes().await;
        let unneeded = lanes.epochs[1];
        let reports = lanes.reports().await;
        let release = host::apply(&mut lanes.group.a, &lanes.keys, &reports);
        assert_eq!(release.release, [unneeded]);

        let session_keys =
            DataKeyring::from_bytes(&lanes.group.a.data_keyring_state().unwrap()).unwrap();
        assert!(!session_keys.contains(&unneeded));
        assert!(session_keys.contains(&lanes.epochs[0]), "positive control");
        assert!(!lanes.keys.current().contains(&unneeded));

        // A refresh after draining a later rotation does not bring it back.
        lanes.group.rotate();
        lanes.keys.replace(keyring(&lanes.group.a));
        assert!(!lanes.keys.current().contains(&unneeded));
        assert_eq!(lanes.keys.current().epoch_count(), 10);

        // Nor does a later invitee's welcome carry it.
        let invitee = lanes.group.invite(0xd4);
        let invited = keyring(&invitee);
        assert!(!invited.contains(&unneeded));
        assert_eq!(invited.epoch_ids(), lanes.keys.current().epoch_ids());

        lanes.assert_both_project().await;
    }
}
