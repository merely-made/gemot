// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

pub(super) fn validate_frame(
    invitation: &CallInvitation,
    frame: &CallControlFrame,
) -> Result<(), CallFoldError> {
    if frame.version != CALL_WIRE_VERSION {
        return Err(CallFoldError::UnsupportedVersion(frame.version));
    }
    if frame.call_id != invitation.call_id {
        return Err(CallFoldError::WrongCall);
    }
    if frame.space_id != invitation.space_id {
        return Err(CallFoldError::WrongSpace);
    }
    if !invitation.contains(frame.sender) {
        return Err(CallFoldError::ForeignParticipant(frame.sender));
    }
    if frame.expires_at_ms <= invitation.created_at_ms {
        return Err(CallFoldError::InvalidFrameExpiry);
    }
    match &frame.control {
        CallControl::Ring | CallControl::Cancel | CallControl::End
            if frame.sender != invitation.owner =>
        {
            return Err(CallFoldError::InvalidRole);
        }
        CallControl::Accept | CallControl::Decline if frame.sender != invitation.invitee => {
            return Err(CallFoldError::InvalidRole);
        }
        CallControl::OfferAudio { formats }
            if formats.is_empty()
                || formats.len() > 16
                || formats.iter().any(|format| !format.validate()) =>
        {
            return Err(CallFoldError::InvalidAudioParameters);
        }
        CallControl::SelectAudio { format } if !format.validate() => {
            return Err(CallFoldError::InvalidAudioParameters);
        }
        CallControl::Ring
        | CallControl::Accept
        | CallControl::Decline
        | CallControl::Cancel
        | CallControl::Leave
        | CallControl::End
        | CallControl::Fail
        | CallControl::Reconnect
        | CallControl::Resume
        | CallControl::Mute { .. }
        | CallControl::PushToTalk { .. }
        | CallControl::OfferAudio { .. }
        | CallControl::SelectAudio { .. } => {}
    }
    Ok(())
}

pub(super) fn validate_terminal(
    invitation: &CallInvitation,
    terminal: &CallTerminalFact,
) -> Result<(), CallFoldError> {
    if terminal.version != CALL_WIRE_VERSION {
        return Err(CallFoldError::UnsupportedVersion(terminal.version));
    }
    if terminal.call_id != invitation.call_id {
        return Err(CallFoldError::WrongCall);
    }
    if terminal.space_id != invitation.space_id {
        return Err(CallFoldError::WrongSpace);
    }
    if !invitation.contains(terminal.participant) {
        return Err(CallFoldError::ForeignParticipant(terminal.participant));
    }
    match terminal.reason {
        CallTerminalReason::Declined | CallTerminalReason::Missed
            if terminal.participant != invitation.invitee =>
        {
            Err(CallFoldError::InvalidRole)
        }
        CallTerminalReason::Cancelled if terminal.participant != invitation.owner => {
            Err(CallFoldError::InvalidRole)
        }
        CallTerminalReason::Failed
        | CallTerminalReason::Declined
        | CallTerminalReason::Missed
        | CallTerminalReason::Cancelled
        | CallTerminalReason::Ended => Ok(()),
    }
}
