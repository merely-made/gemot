// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use p2panda_core::cbor::{decode_cbor, encode_cbor};
use proptest::prelude::*;

use super::*;

const OWNER: ParticipantId = [0x11; 32];
const INVITEE: ParticipantId = [0x22; 32];
const NOW: u64 = 1_000;

fn invitation() -> CallInvitation {
    CallInvitation {
        version: CALL_WIRE_VERSION,
        call_id: [0x33; 32],
        space_id: [0x44; 32],
        owner: OWNER,
        invitee: INVITEE,
        created_at_ms: 100,
        expires_at_ms: 2_000,
    }
}

fn frame(sender: ParticipantId, sequence: u64, control: CallControl) -> CallControlFrame {
    let invitation = invitation();
    CallControlFrame {
        version: CALL_WIRE_VERSION,
        call_id: invitation.call_id,
        space_id: invitation.space_id,
        sender,
        sequence,
        expires_at_ms: 1_500,
        control,
    }
}

fn receipt_frames() -> Vec<CallControlFrame> {
    vec![
        frame(OWNER, 0, CallControl::Ring),
        frame(INVITEE, 0, CallControl::Accept),
        frame(INVITEE, 1, CallControl::Mute { muted: true }),
        frame(OWNER, 1, CallControl::End),
    ]
}

fn each_permutation<T>(items: &mut [T], start: usize, visit: &mut impl FnMut(&[T])) {
    if start == items.len() {
        visit(items);
        return;
    }
    for index in start..items.len() {
        items.swap(start, index);
        each_permutation(items, start + 1, visit);
        items.swap(start, index);
    }
}

#[test]
fn two_peers_fold_every_permutation_to_the_same_visible_state() {
    let invitation = invitation();
    let mut frames = receipt_frames();
    let expected = fold_call(&invitation, &[], &frames, NOW)
        .unwrap()
        .projection;
    let mut permutations = 0;
    each_permutation(&mut frames, 0, &mut |permutation| {
        let alice = fold_call(&invitation, &[], permutation, NOW)
            .unwrap()
            .projection;
        let mut bob_order = permutation.to_vec();
        bob_order.reverse();
        bob_order.push(permutation[1].clone());
        let bob = fold_call(&invitation, &[], &bob_order, NOW)
            .unwrap()
            .projection;
        assert_eq!(alice, expected);
        assert_eq!(bob, expected);
        permutations += 1;
    });
    assert_eq!(permutations, 24);
    assert_eq!(expected.phase, CallPhase::Ended);
    assert_eq!(
        expected.terminal,
        Some(CallTerminalOutcome {
            participant: OWNER,
            reason: CallTerminalReason::Ended,
            source: TerminalSource::Live { sequence: 1 },
        })
    );
}

proptest! {
    #[test]
    fn duplicate_and_reordered_controls_do_not_change_visible_state(
        indices in prop::collection::vec(0usize..4, 0..48),
    ) {
        let invitation = invitation();
        let base = receipt_frames();
        let observed = indices
            .iter()
            .map(|index| base[*index].clone())
            .collect::<Vec<_>>();
        let mut reverse = observed.clone();
        reverse.reverse();
        let left = fold_call(&invitation, &[], &observed, NOW).unwrap().projection;
        let right = fold_call(&invitation, &[], &reverse, NOW).unwrap().projection;
        prop_assert_eq!(left, right);
    }

    #[test]
    fn expired_controls_are_inert(
        sequence in any::<u64>(),
        action in 0u8..5,
    ) {
        let invitation = invitation();
        let (sender, control) = match action {
            0 => (OWNER, CallControl::Ring),
            1 => (INVITEE, CallControl::Accept),
            2 => (INVITEE, CallControl::Decline),
            3 => (OWNER, CallControl::End),
            _ => (OWNER, CallControl::Mute { muted: true }),
        };
        let mut expired = frame(sender, sequence, control);
        expired.expires_at_ms = NOW;
        let expected = fold_call(&invitation, &[], &[], NOW).unwrap().projection;
        let observed = fold_call(&invitation, &[], &[expired], NOW).unwrap().projection;
        prop_assert_eq!(observed, expected);
    }

    #[test]
    fn concurrent_terminal_controls_settle_independently_of_sequence_and_arrival(
        owner_sequence in any::<u64>(),
        invitee_sequence in any::<u64>(),
        reverse in any::<bool>(),
    ) {
        let invitation = invitation();
        let mut frames = vec![
            frame(OWNER, owner_sequence, CallControl::Cancel),
            frame(INVITEE, invitee_sequence, CallControl::Decline),
        ];
        if reverse {
            frames.reverse();
        }
        let projection = fold_call(&invitation, &[], &frames, NOW).unwrap().projection;
        prop_assert_eq!(projection.phase, CallPhase::Cancelled);
        prop_assert_eq!(
            projection.terminal.map(|terminal| terminal.reason),
            Some(CallTerminalReason::Cancelled)
        );
    }
}

#[test]
fn expired_controls_cannot_accept_or_reopen_a_call() {
    let invitation = invitation();
    let mut accept = frame(INVITEE, 0, CallControl::Accept);
    accept.expires_at_ms = 900;
    let folded = fold_call(&invitation, &[], &[accept], 2_100).unwrap();
    assert_eq!(folded.projection.phase, CallPhase::Missed);
    assert_eq!(folded.projection.terminal, None);
    assert_eq!(folded.diagnostics.expired_frames, 1);
}

#[test]
fn terminal_controls_dominate_later_nonterminal_sequences() {
    let invitation = invitation();
    let terminal_frames = vec![
        frame(INVITEE, 1, CallControl::Decline),
        frame(OWNER, 1, CallControl::End),
    ];
    let terminal_only = fold_call(&invitation, &[], &terminal_frames, NOW)
        .unwrap()
        .projection;
    let mut later_nonterminal = terminal_frames;
    later_nonterminal.extend([
        frame(INVITEE, 2, CallControl::Accept),
        frame(INVITEE, 3, CallControl::Mute { muted: true }),
        frame(OWNER, 2, CallControl::Ring),
    ]);
    let folded = fold_call(&invitation, &[], &later_nonterminal, NOW).unwrap();
    assert_eq!(&folded.projection, &terminal_only);
    assert_eq!(folded.projection.phase, CallPhase::Ended);
    assert_eq!(
        folded.projection.terminal.unwrap().reason,
        CallTerminalReason::Ended
    );
}

#[test]
fn concurrent_terminal_reasons_settle_without_wall_clock_order() {
    let invitation = invitation();
    let frames = vec![
        frame(INVITEE, 8, CallControl::Decline),
        frame(OWNER, 3, CallControl::Cancel),
    ];
    let forward = fold_call(&invitation, &[], &frames, NOW)
        .unwrap()
        .projection;
    let reverse = fold_call(
        &invitation,
        &[],
        &frames.iter().rev().cloned().collect::<Vec<_>>(),
        NOW,
    )
    .unwrap()
    .projection;
    assert_eq!(forward, reverse);
    assert_eq!(forward.phase, CallPhase::Cancelled);
}

#[test]
fn retained_terminal_fact_dominates_live_acceptance() {
    let invitation = invitation();
    let terminal = CallTerminalFact {
        version: CALL_WIRE_VERSION,
        call_id: invitation.call_id,
        space_id: invitation.space_id,
        participant: INVITEE,
        reason: CallTerminalReason::Declined,
        observed_at_ms: 800,
    };
    let folded = fold_call(
        &invitation,
        &[terminal],
        &[frame(INVITEE, 99, CallControl::Accept)],
        NOW,
    )
    .unwrap();
    assert_eq!(folded.projection.phase, CallPhase::Declined);
    assert_eq!(
        folded.projection.terminal.unwrap().source,
        TerminalSource::Retained
    );
}

#[test]
fn conflicting_frames_at_one_sender_sequence_fail_closed() {
    let invitation = invitation();
    let frames = vec![
        frame(INVITEE, 4, CallControl::Accept),
        frame(INVITEE, 4, CallControl::Decline),
    ];
    assert_eq!(
        fold_call(&invitation, &[], &frames, NOW),
        Err(CallFoldError::Equivocation {
            participant: INVITEE,
            sequence: 4,
        })
    );
}

#[test]
fn retained_and_live_grammars_round_trip() {
    let invitation = invitation();
    let retained = RetainedCallFact::Invitation(invitation.clone());
    let retained_bytes = encode_cbor(&retained).unwrap();
    assert_eq!(
        decode_cbor::<RetainedCallFact, _>(retained_bytes.as_slice()).unwrap(),
        retained
    );

    let control = frame(
        OWNER,
        7,
        CallControl::OfferAudio {
            formats: vec![AudioParameters {
                codec: "probe-mono".into(),
                sample_rate_hz: 48_000,
                channels: 1,
                frame_duration_ms: 20,
            }],
        },
    );
    let control_bytes = encode_cbor(&control).unwrap();
    assert_eq!(
        decode_cbor::<CallControlFrame, _>(control_bytes.as_slice()).unwrap(),
        control
    );
}
