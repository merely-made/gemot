//! Tessera facts + the policy gate — Phase 4 / the §8.8 policy slot.
//!
//! Tessera is the **facts** source for the capability stack's policy slot, not
//! the policy *engine*. This module exposes the facts a moot's policy reads about
//! a persona ([`TesseraFacts`]), a set of configurable policy presets
//! ([`Policy`]) a moot operator picks from, and the [`authorize`] reference
//! authorizer that evaluates a chosen policy against the facts and the
//! structural-cap decision: an action passes iff a cap covers the cluster-path
//! **and** the policy admits the persona (over a standing threshold, or vouched,
//! or a member) **and** they are within the rate limit.
//!
//! The presets are the **configurability**: the gating rule is the moot
//! operator's choice, not a project default. They are the accessible layer over
//! the eventual Biscuit policy *language* (attenuable Datalog over these same
//! facts) — a preset compiles to a Biscuit policy, and raw Datalog is the power
//! user's escape hatch. The fresh-chain flood is thrown out here: zero standing
//! sits below any threshold, and the rate limit caps a burst.

/// A moot's policy parameters for the gate. Per-moot configurable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateConfig {
    /// Minimum effective / composite tessera a persona needs to act (post, pin).
    pub posting_threshold: i64,
    /// Maximum actions one persona may take within [`rate_window_ms`](Self::rate_window_ms).
    pub rate_limit: u32,
    /// The rolling window the rate limit counts over (ms).
    pub rate_window_ms: u64,
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            // A fresh chain (0) cannot post; you earn standing or get vouched in.
            posting_threshold: 1,
            rate_limit: 20,
            rate_window_ms: 60_000, // 20 actions per minute
        }
    }
}

/// The tessera facts a moot's gate reads about a persona, assembled by the moot
/// from the reputation layer (`score`, e.g. a concord composite) and its own
/// recent-activity log (`recent_action_ms`).
#[derive(Clone, Debug, Default)]
pub struct TesseraFacts {
    /// The persona's effective / composite standing in the gating moot.
    pub score: i64,
    /// Timestamps (ms) of the persona's recent actions, for the rate limit.
    pub recent_action_ms: Vec<u64>,
    /// Whether the persona was vouched into the gating moot (lets the
    /// [`Policy::VouchedOrScore`] preset waive the standing floor).
    pub vouched: bool,
    /// Whether the persona is an admitted member of the gating moot (gates the
    /// [`Policy::MembersOnly`] preset).
    pub is_member: bool,
}

/// Why the gate denied an action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenyReason {
    /// No structural capability covers the action's cluster-path (§8.8 caps).
    NoCapability,
    /// The persona's standing is below the moot's posting threshold.
    BelowThreshold,
    /// A members-only moot, and the persona is not an admitted member.
    NotAMember,
    /// The persona exceeded the moot's rate limit for the window.
    RateLimited,
}

/// The gate's verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateDecision {
    Allow,
    Deny(DenyReason),
}

/// A moot's chosen gating policy — the configurable part, the moot operator's
/// call. Each preset is an admission rule layered over the shared structural-cap
/// and rate-limit checks; they are the accessible front end of the eventual
/// Biscuit policy language (a preset compiles to a Biscuit policy, with raw
/// Datalog as the power user's escape hatch).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Policy {
    /// Admit anyone whose standing clears the threshold. The open-but-floored moot.
    OpenWithFloor(GateConfig),
    /// Admit anyone over the threshold *or* explicitly vouched in — the reputation
    /// floor with a vouch bypass for trusted newcomers.
    VouchedOrScore(GateConfig),
    /// Admit only admitted members; standing is not consulted. The closed moot.
    MembersOnly {
        rate_limit: u32,
        rate_window_ms: u64,
    },
}

/// Evaluate a moot's [`Policy`] for a persona — the reference **authorizer**.
///
/// The §8.8 conjunction, in order: the structural cap must cover the action
/// (`cap_covers`), then the policy's admission rule must pass, then the persona
/// must be within the rate limit. The cap is checked first, so a persona without
/// the capability is refused before their reputation is read at all.
pub fn authorize(
    policy: &Policy,
    cap_covers: bool,
    facts: &TesseraFacts,
    now_ms: u64,
) -> GateDecision {
    if !cap_covers {
        return GateDecision::Deny(DenyReason::NoCapability);
    }
    // The admission rule (preset-specific), then the rate limit it shares.
    let (rate_limit, rate_window_ms) = match policy {
        Policy::OpenWithFloor(config) => {
            if facts.score < config.posting_threshold {
                return GateDecision::Deny(DenyReason::BelowThreshold);
            }
            (config.rate_limit, config.rate_window_ms)
        }
        Policy::VouchedOrScore(config) => {
            if facts.score < config.posting_threshold && !facts.vouched {
                return GateDecision::Deny(DenyReason::BelowThreshold);
            }
            (config.rate_limit, config.rate_window_ms)
        }
        Policy::MembersOnly {
            rate_limit,
            rate_window_ms,
        } => {
            if !facts.is_member {
                return GateDecision::Deny(DenyReason::NotAMember);
            }
            (*rate_limit, *rate_window_ms)
        }
    };
    let in_window = facts
        .recent_action_ms
        .iter()
        .filter(|&&t| now_ms.saturating_sub(t) < rate_window_ms)
        .count() as u32;
    if in_window >= rate_limit {
        return GateDecision::Deny(DenyReason::RateLimited);
    }
    GateDecision::Allow
}

/// The default open-with-floor gate: [`authorize`] under [`Policy::OpenWithFloor`].
/// A convenience for the common case; richer moots pick another [`Policy`].
pub fn may_act(
    cap_covers: bool,
    facts: &TesseraFacts,
    now_ms: u64,
    config: &GateConfig,
) -> GateDecision {
    authorize(
        &Policy::OpenWithFloor(config.clone()),
        cap_covers,
        facts,
        now_ms,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(score: i64, recent_action_ms: Vec<u64>) -> TesseraFacts {
        TesseraFacts {
            score,
            recent_action_ms,
            ..Default::default()
        }
    }

    #[test]
    fn allows_when_cap_and_facts_pass() {
        assert_eq!(
            may_act(
                true,
                &facts(50, vec![1, 2, 3]),
                1_000,
                &GateConfig::default()
            ),
            GateDecision::Allow
        );
    }

    #[test]
    fn denies_without_a_capability_before_consulting_reputation() {
        // Even a high-standing persona is refused if no cap covers the action.
        assert_eq!(
            may_act(false, &facts(10_000, vec![]), 1_000, &GateConfig::default()),
            GateDecision::Deny(DenyReason::NoCapability)
        );
    }

    #[test]
    fn a_fresh_chain_is_below_threshold() {
        // The Sybil/flood floor: zero standing cannot post even with a cap.
        assert_eq!(
            may_act(true, &facts(0, vec![]), 1_000, &GateConfig::default()),
            GateDecision::Deny(DenyReason::BelowThreshold)
        );
    }

    #[test]
    fn rate_limit_throttles_a_burst() {
        let config = GateConfig {
            posting_threshold: 1,
            rate_limit: 3,
            rate_window_ms: 1_000,
        };
        // 3 actions already in the window.
        assert_eq!(
            may_act(true, &facts(100, vec![10, 20, 30]), 100, &config),
            GateDecision::Deny(DenyReason::RateLimited)
        );
    }

    #[test]
    fn actions_outside_the_window_do_not_count() {
        let config = GateConfig {
            posting_threshold: 1,
            rate_limit: 3,
            rate_window_ms: 1_000,
        };
        // The three actions are older than the 1s window as of now = 5_000.
        assert_eq!(
            may_act(true, &facts(100, vec![10, 20, 30]), 5_000, &config),
            GateDecision::Allow
        );
    }

    #[test]
    fn vouched_or_score_lets_a_vouched_newcomer_in() {
        let policy = Policy::VouchedOrScore(GateConfig::default());
        // A zero-standing newcomer is admitted if vouched, refused if not.
        let vouched = TesseraFacts {
            score: 0,
            vouched: true,
            ..Default::default()
        };
        let stranger = TesseraFacts {
            score: 0,
            vouched: false,
            ..Default::default()
        };
        assert_eq!(authorize(&policy, true, &vouched, 0), GateDecision::Allow);
        assert_eq!(
            authorize(&policy, true, &stranger, 0),
            GateDecision::Deny(DenyReason::BelowThreshold)
        );
    }

    #[test]
    fn members_only_admits_only_members() {
        let policy = Policy::MembersOnly {
            rate_limit: 20,
            rate_window_ms: 60_000,
        };
        // High standing does not help a non-member; membership is what counts.
        let member = TesseraFacts {
            score: 0,
            is_member: true,
            ..Default::default()
        };
        let outsider = TesseraFacts {
            score: 10_000,
            is_member: false,
            ..Default::default()
        };
        assert_eq!(authorize(&policy, true, &member, 0), GateDecision::Allow);
        assert_eq!(
            authorize(&policy, true, &outsider, 0),
            GateDecision::Deny(DenyReason::NotAMember)
        );
    }
}
