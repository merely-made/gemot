// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Reusable sans-I/O control grammar and deterministic fold for a two-person Commons call.
//!
//! Retained invitations and sparse terminal facts are Commons records. Ringing,
//! acceptance, media negotiation, mute state, and reconnect state are expiring
//! live controls. This module owns neither admission nor audio I/O: A1 admits
//! the control stream through Notochord, and A2 selects device and codec
//! dependencies from a measured loopback probe.

use std::collections::{BTreeMap, btree_map::Entry};

use serde::{Deserialize, Serialize};

pub const COMMONS_CALL_PROFILE: &str = "commons.call.v1";
pub const COMMONS_CALL_ALPN: &str = "mere/commons-call/v1";
pub const CALL_WIRE_VERSION: u16 = 1;

pub type CallId = [u8; 32];
pub type SpaceId = [u8; 32];
pub type ParticipantId = [u8; 32];

/// The durable fact which lets an offline member discover a call attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallInvitation {
    pub version: u16,
    pub call_id: CallId,
    pub space_id: SpaceId,
    pub owner: ParticipantId,
    pub invitee: ParticipantId,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

impl CallInvitation {
    pub fn participants(&self) -> [ParticipantId; 2] {
        [self.owner, self.invitee]
    }

    fn validate(&self) -> Result<(), CallFoldError> {
        if self.version != CALL_WIRE_VERSION {
            return Err(CallFoldError::UnsupportedVersion(self.version));
        }
        if self.owner == self.invitee {
            return Err(CallFoldError::SameParticipant);
        }
        if self.expires_at_ms <= self.created_at_ms {
            return Err(CallFoldError::InvalidInvitationExpiry);
        }
        Ok(())
    }

    fn contains(&self, participant: ParticipantId) -> bool {
        participant == self.owner || participant == self.invitee
    }
}

/// The optional durable history fact for one terminal outcome.
///
/// `observed_at_ms` is display metadata. It never settles concurrent facts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallTerminalFact {
    pub version: u16,
    pub call_id: CallId,
    pub space_id: SpaceId,
    pub participant: ParticipantId,
    pub reason: CallTerminalReason,
    pub observed_at_ms: u64,
}

/// The Commons facts used by the call product. Live control frames are not
/// members of this enum and are never retained by this fold.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RetainedCallFact {
    Invitation(CallInvitation),
    Terminal(CallTerminalFact),
}

/// A format description only. A2 chooses actual codec implementations after
/// measuring the local audio path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AudioParameters {
    pub codec: String,
    pub sample_rate_hz: u32,
    pub channels: u8,
    pub frame_duration_ms: u16,
}

impl AudioParameters {
    fn validate(&self) -> bool {
        !self.codec.is_empty()
            && self.codec.len() <= 32
            && self
                .codec
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            && self.sample_rate_hz > 0
            && self.channels > 0
            && self.frame_duration_ms > 0
    }
}

/// One expiring live call-control frame.
///
/// `sequence` is monotone only for `sender`. Cross-participant wall-clock or
/// sequence comparisons are deliberately absent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallControlFrame {
    pub version: u16,
    pub call_id: CallId,
    pub space_id: SpaceId,
    pub sender: ParticipantId,
    pub sequence: u64,
    pub expires_at_ms: u64,
    pub control: CallControl,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallControl {
    Ring,
    Accept,
    Decline,
    Cancel,
    Leave,
    End,
    Fail,
    Reconnect,
    Resume,
    Mute { muted: bool },
    PushToTalk { transmitting: bool },
    OfferAudio { formats: Vec<AudioParameters> },
    SelectAudio { format: AudioParameters },
}

impl CallControl {
    fn terminal_reason(&self) -> Option<CallTerminalReason> {
        match self {
            Self::Decline => Some(CallTerminalReason::Declined),
            Self::Cancel => Some(CallTerminalReason::Cancelled),
            Self::Leave | Self::End => Some(CallTerminalReason::Ended),
            Self::Fail => Some(CallTerminalReason::Failed),
            Self::Ring
            | Self::Accept
            | Self::Reconnect
            | Self::Resume
            | Self::Mute { .. }
            | Self::PushToTalk { .. }
            | Self::OfferAudio { .. }
            | Self::SelectAudio { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CallTerminalReason {
    Missed,
    Failed,
    Declined,
    Cancelled,
    Ended,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallPhase {
    Inviting,
    Ringing,
    Connected,
    Reconnecting,
    Declined,
    Missed,
    Cancelled,
    Failed,
    Ended,
}

impl CallTerminalReason {
    fn phase(self) -> CallPhase {
        match self {
            Self::Declined => CallPhase::Declined,
            Self::Missed => CallPhase::Missed,
            Self::Cancelled => CallPhase::Cancelled,
            Self::Failed => CallPhase::Failed,
            Self::Ended => CallPhase::Ended,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TerminalSource {
    Retained,
    Live { sequence: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallTerminalOutcome {
    pub participant: ParticipantId,
    pub reason: CallTerminalReason,
    pub source: TerminalSource,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallParticipantState {
    pub participant: ParticipantId,
    pub latest_sequence: Option<u64>,
    pub muted: bool,
    pub transmitting: bool,
    pub offered_audio: Vec<AudioParameters>,
    pub selected_audio: Option<AudioParameters>,
}

impl CallParticipantState {
    fn new(participant: ParticipantId) -> Self {
        Self {
            participant,
            latest_sequence: None,
            muted: false,
            transmitting: false,
            offered_audio: Vec::new(),
            selected_audio: None,
        }
    }
}

/// Visible state derived from the retained invitation and an unordered set of
/// live frames.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallProjection {
    pub call_id: CallId,
    pub space_id: SpaceId,
    pub phase: CallPhase,
    pub terminal: Option<CallTerminalOutcome>,
    pub participants: Vec<CallParticipantState>,
}

/// Receipt-local facts about discarded controls. They are not visible call
/// state because different carriers may observe different duplicates.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CallFoldDiagnostics {
    pub duplicate_frames: usize,
    pub expired_frames: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallFold {
    pub projection: CallProjection,
    pub diagnostics: CallFoldDiagnostics,
}

#[derive(Clone, Debug)]
struct ParticipantAccumulator {
    state: CallParticipantState,
    phase: Option<(u64, ParticipantPhase)>,
    mute: Option<(u64, bool)>,
    push_to_talk: Option<(u64, bool)>,
    offered_audio: Option<(u64, Vec<AudioParameters>)>,
    selected_audio: Option<(u64, AudioParameters)>,
}

impl ParticipantAccumulator {
    fn new(participant: ParticipantId) -> Self {
        Self {
            state: CallParticipantState::new(participant),
            phase: None,
            mute: None,
            push_to_talk: None,
            offered_audio: None,
            selected_audio: None,
        }
    }

    fn observe(&mut self, frame: &CallControlFrame) {
        self.state.latest_sequence = Some(
            self.state
                .latest_sequence
                .map_or(frame.sequence, |sequence| sequence.max(frame.sequence)),
        );
        match &frame.control {
            CallControl::Ring => {
                replace_latest(&mut self.phase, frame.sequence, ParticipantPhase::Ringing)
            }
            CallControl::Accept | CallControl::Resume => {
                replace_latest(&mut self.phase, frame.sequence, ParticipantPhase::Connected)
            }
            CallControl::Reconnect => replace_latest(
                &mut self.phase,
                frame.sequence,
                ParticipantPhase::Reconnecting,
            ),
            CallControl::Mute { muted } => replace_latest(&mut self.mute, frame.sequence, *muted),
            CallControl::PushToTalk { transmitting } => {
                replace_latest(&mut self.push_to_talk, frame.sequence, *transmitting)
            }
            CallControl::OfferAudio { formats } => {
                replace_latest(&mut self.offered_audio, frame.sequence, formats.clone())
            }
            CallControl::SelectAudio { format } => {
                replace_latest(&mut self.selected_audio, frame.sequence, format.clone())
            }
            CallControl::Decline
            | CallControl::Cancel
            | CallControl::Leave
            | CallControl::End
            | CallControl::Fail => {}
        }
    }

    fn finish(mut self) -> (CallParticipantState, Option<ParticipantPhase>) {
        self.state.muted = self.mute.is_some_and(|(_, muted)| muted);
        self.state.transmitting = self
            .push_to_talk
            .is_some_and(|(_, transmitting)| transmitting);
        self.state.offered_audio = self
            .offered_audio
            .map_or_else(Vec::new, |(_, formats)| formats);
        self.state.selected_audio = self.selected_audio.map(|(_, format)| format);
        (self.state, self.phase.map(|(_, phase)| phase))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ParticipantPhase {
    Ringing,
    Connected,
    Reconnecting,
}

fn replace_latest<T>(slot: &mut Option<(u64, T)>, sequence: u64, value: T) {
    if slot.as_ref().is_none_or(|(current, _)| sequence > *current) {
        *slot = Some((sequence, value));
    }
}

/// Fold one call from retained facts and unordered live controls.
///
/// Exact duplicates are harmless. Two different frames with one sender and
/// sequence are equivocation and fail closed. A terminal from either
/// participant dominates every non-terminal frame, including a later sequence.
pub fn fold_call(
    invitation: &CallInvitation,
    retained_terminals: &[CallTerminalFact],
    frames: &[CallControlFrame],
    now_ms: u64,
) -> Result<CallFold, CallFoldError> {
    invitation.validate()?;

    let mut diagnostics = CallFoldDiagnostics::default();
    let mut unique = BTreeMap::<(ParticipantId, u64), CallControlFrame>::new();
    for frame in frames {
        validate_frame(invitation, frame)?;
        match unique.entry((frame.sender, frame.sequence)) {
            Entry::Vacant(entry) => {
                entry.insert(frame.clone());
            }
            Entry::Occupied(entry) if entry.get() == frame => {
                diagnostics.duplicate_frames += 1;
            }
            Entry::Occupied(_) => {
                return Err(CallFoldError::Equivocation {
                    participant: frame.sender,
                    sequence: frame.sequence,
                });
            }
        }
    }

    let mut participants = BTreeMap::from([
        (
            invitation.owner,
            ParticipantAccumulator::new(invitation.owner),
        ),
        (
            invitation.invitee,
            ParticipantAccumulator::new(invitation.invitee),
        ),
    ]);
    let mut terminals = Vec::<RankedTerminal>::new();
    let mut live_state_frames = Vec::new();

    for terminal in retained_terminals {
        validate_terminal(invitation, terminal)?;
        terminals.push(RankedTerminal {
            participant: terminal.participant,
            reason: terminal.reason,
            sequence: None,
            source: TerminalSource::Retained,
        });
    }

    for frame in unique.into_values() {
        if frame.expires_at_ms <= now_ms {
            diagnostics.expired_frames += 1;
            continue;
        }
        if let Some(reason) = frame.control.terminal_reason() {
            terminals.push(RankedTerminal {
                participant: frame.sender,
                reason,
                sequence: Some(frame.sequence),
                source: TerminalSource::Live {
                    sequence: frame.sequence,
                },
            });
        } else {
            live_state_frames.push(frame);
        }
    }

    let terminal = terminals
        .into_iter()
        .max_by(|left, right| left.rank().cmp(&right.rank()))
        .map(RankedTerminal::outcome);
    if terminal.is_none() {
        for frame in &live_state_frames {
            participants
                .get_mut(&frame.sender)
                .expect("validated participant")
                .observe(frame);
        }
    }
    let mut states = Vec::with_capacity(2);
    let mut participant_phases = Vec::with_capacity(2);
    for participant in invitation.participants() {
        let (state, phase) = participants
            .remove(&participant)
            .expect("invitation participants were initialized")
            .finish();
        states.push(state);
        participant_phases.push(phase);
    }
    let phase = if let Some(terminal) = &terminal {
        terminal.reason.phase()
    } else if participant_phases.contains(&Some(ParticipantPhase::Reconnecting)) {
        CallPhase::Reconnecting
    } else if participant_phases.contains(&Some(ParticipantPhase::Connected)) {
        CallPhase::Connected
    } else if now_ms >= invitation.expires_at_ms {
        CallPhase::Missed
    } else if participant_phases.contains(&Some(ParticipantPhase::Ringing)) {
        CallPhase::Ringing
    } else {
        CallPhase::Inviting
    };

    Ok(CallFold {
        projection: CallProjection {
            call_id: invitation.call_id,
            space_id: invitation.space_id,
            phase,
            terminal,
            participants: states,
        },
        diagnostics,
    })
}

#[derive(Clone, Debug)]
struct RankedTerminal {
    participant: ParticipantId,
    reason: CallTerminalReason,
    sequence: Option<u64>,
    source: TerminalSource,
}

impl RankedTerminal {
    /// Semantic reason first, then participant and sender-local sequence. No
    /// clock participates in concurrent settlement.
    fn rank(&self) -> (CallTerminalReason, ParticipantId, Option<u64>) {
        (self.reason, self.participant, self.sequence)
    }

    fn outcome(self) -> CallTerminalOutcome {
        CallTerminalOutcome {
            participant: self.participant,
            reason: self.reason,
            source: self.source,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CallFoldError {
    #[error("unsupported Commons call wire version {0}")]
    UnsupportedVersion(u16),
    #[error("call owner and invitee must differ")]
    SameParticipant,
    #[error("invitation expiry must follow creation")]
    InvalidInvitationExpiry,
    #[error("control expiry must follow invitation creation")]
    InvalidFrameExpiry,
    #[error("control addresses another call")]
    WrongCall,
    #[error("control addresses another Commons")]
    WrongSpace,
    #[error("control participant is not invited: {0:?}")]
    ForeignParticipant(ParticipantId),
    #[error("control is not valid for this participant role")]
    InvalidRole,
    #[error("audio parameters are empty, malformed, or unbounded")]
    InvalidAudioParameters,
    #[error("participant {participant:?} equivocated at sequence {sequence}")]
    Equivocation {
        participant: ParticipantId,
        sequence: u64,
    },
}

#[cfg(test)]
#[path = "call/tests.rs"]
mod tests;

#[path = "call/validation.rs"]
mod validation;

use validation::{validate_frame, validate_terminal};
