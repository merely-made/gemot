//! Tessera facts + the posting gate — Phase 4 (the §8.8 policy slot).
//!
//! Tessera is the **facts** source for the capability stack's policy slot, not
//! the policy *engine*. This module exposes the facts a moot's policy reads about
//! a persona ([`TesseraFacts`]) and a concrete reference gate ([`may_act`]) that
//! combines them with the structural-cap decision: a member may act iff a cap
//! covers the cluster-path **and** the tessera facts pass (standing over the
//! moot's threshold, within its rate limit). The general policy *language* — the
//! Biscuit candidate, expressing these as attenuable Datalog — is a sibling plan;
//! this gate is the direct reference policy a moot can run today.
//!
//! The fresh-chain flood (many zero-standing personas trying to post) is thrown
//! out here: each sits below the posting threshold, and the rate limit caps any
//! single persona's burst.

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
}

/// Why the gate denied an action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenyReason {
    /// No structural capability covers the action's cluster-path (§8.8 caps).
    NoCapability,
    /// The persona's standing is below the moot's posting threshold.
    BelowThreshold,
    /// The persona exceeded the moot's rate limit for the window.
    RateLimited,
}

/// The gate's verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateDecision {
    Allow,
    Deny(DenyReason),
}

/// May this persona act now? Both halves of the §8.8 slot must pass: a structural
/// cap must cover the action (`cap_covers`, supplied by the caps layer) **and**
/// the tessera facts must clear the moot's policy (standing over threshold,
/// within the rate limit). The cap is checked first (a member without the
/// capability is refused before their reputation is even consulted).
pub fn may_act(
    cap_covers: bool,
    facts: &TesseraFacts,
    now_ms: u64,
    config: &GateConfig,
) -> GateDecision {
    if !cap_covers {
        return GateDecision::Deny(DenyReason::NoCapability);
    }
    if facts.score < config.posting_threshold {
        return GateDecision::Deny(DenyReason::BelowThreshold);
    }
    let in_window = facts
        .recent_action_ms
        .iter()
        .filter(|&&t| now_ms.saturating_sub(t) < config.rate_window_ms)
        .count() as u32;
    if in_window >= config.rate_limit {
        return GateDecision::Deny(DenyReason::RateLimited);
    }
    GateDecision::Allow
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_when_cap_and_facts_pass() {
        let facts = TesseraFacts {
            score: 50,
            recent_action_ms: vec![1, 2, 3],
        };
        assert_eq!(
            may_act(true, &facts, 1_000, &GateConfig::default()),
            GateDecision::Allow
        );
    }

    #[test]
    fn denies_without_a_capability_before_consulting_reputation() {
        // Even a high-standing persona is refused if no cap covers the action.
        let facts = TesseraFacts {
            score: 10_000,
            recent_action_ms: vec![],
        };
        assert_eq!(
            may_act(false, &facts, 1_000, &GateConfig::default()),
            GateDecision::Deny(DenyReason::NoCapability)
        );
    }

    #[test]
    fn a_fresh_chain_is_below_threshold() {
        // The Sybil/flood floor: zero standing cannot post even with a cap.
        let facts = TesseraFacts {
            score: 0,
            recent_action_ms: vec![],
        };
        assert_eq!(
            may_act(true, &facts, 1_000, &GateConfig::default()),
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
        let facts = TesseraFacts {
            score: 100,
            recent_action_ms: vec![10, 20, 30], // 3 actions already in the window
        };
        assert_eq!(
            may_act(true, &facts, 100, &config),
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
        // Three actions, but all older than the 1s window as of now = 5_000.
        let facts = TesseraFacts {
            score: 100,
            recent_action_ms: vec![10, 20, 30],
        };
        assert_eq!(
            may_act(true, &facts, 5_000, &config),
            GateDecision::Allow
        );
    }
}
