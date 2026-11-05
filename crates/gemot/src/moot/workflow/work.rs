// SPDX-License-Identifier: MPL-2.0
//! Exact offers and worker consent, distinct from evidence, review and settlement.
mod fold;
use super::namespace::CollectionTarget;
use super::{RecordId, canonical_ids, hex, text};
use crate::moot::ContributionRef;
use serde::{Deserialize, Serialize};
use servitor::Cap;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Compensation {
    None,
    /// An external contract identifier. Acceptance never executes a payment.
    External {
        contract: RecordId,
        description: String,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkKind {
    Contribution,
    Hosting { evidence_every_ms: u64 },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkTerms {
    pub worker: RecordId,
    pub title: String,
    pub acceptance_criteria: String,
    pub inputs: CollectionTarget,
    pub kind: WorkKind,
    pub starts_at_ms: u64,
    pub ends_at_ms: u64,
    pub max_bytes: u64,
    /// Frozen reviewers; each identity counts at most once per submission.
    pub reviewers: Vec<RecordId>,
    pub approvals_required: u16,
    pub compensation: Compensation,
    /// Optional existing worker-owned Standing commitment. Review and reward
    /// remain separate commands; None is an ordinary unpaid completion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub standing_commitment: Option<mien::CommitmentId>,
    pub max_renewals: u16,
    pub allow_handoff: bool,
}
impl WorkTerms {
    pub fn windows(&self) -> u32 {
        match self.kind {
            WorkKind::Contribution => 1,
            WorkKind::Hosting { evidence_every_ms } => {
                if evidence_every_ms == 0 {
                    0
                } else {
                    self.ends_at_ms
                        .saturating_sub(self.starts_at_ms)
                        .div_ceil(evidence_every_ms)
                        .min(512) as u32
                }
            }
        }
    }
    pub fn window_at(&self, at_ms: u64) -> Option<u32> {
        if at_ms < self.starts_at_ms || at_ms >= self.ends_at_ms {
            return None;
        }
        Some(match self.kind {
            WorkKind::Contribution => 0,
            WorkKind::Hosting { evidence_every_ms } => {
                (at_ms - self.starts_at_ms).checked_div(evidence_every_ms)? as u32
            }
        })
    }
    pub fn validate(&self, moot: RecordId) -> bool {
        text(&self.title, 512)
            && text(&self.acceptance_criteria, 8192)
            && self.inputs.validate(moot)
            && self.starts_at_ms < self.ends_at_ms
            && self.max_bytes > 0
            && self.max_renewals <= 64
            && !self.reviewers.is_empty()
            && canonical_ids(&self.reviewers, 64)
            && self.approvals_required > 0
            && usize::from(self.approvals_required) <= self.reviewers.len()
            && match self.kind {
                WorkKind::Contribution => true,
                WorkKind::Hosting { evidence_every_ms } => {
                    evidence_every_ms > 0
                        && (self.ends_at_ms - self.starts_at_ms).div_ceil(evidence_every_ms) <= 512
                }
            }
            && match &self.compensation {
                Compensation::None => true,
                Compensation::External { description, .. } => text(description, 2048),
            }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkAction {
    /// Replacement is a renewal or handoff after explicit cancellation of the
    /// predecessor. The new worker must consent before the replacement activates.
    Offer {
        terms: WorkTerms,
        replaces: Option<RecordId>,
    },
    /// The signed acceptance names exact immutable offer bytes by operation hash.
    Accept {
        offer: RecordId,
    },
    Submit {
        agreement: RecordId,
        window: u32,
        replaces: Vec<RecordId>,
        outputs: Vec<ContributionRef>,
        evidence: Vec<RecordId>,
    },
    Review {
        submission: RecordId,
        replaces: Vec<RecordId>,
        approve: bool,
        rationale: String,
    },
    Cancel {
        agreement: RecordId,
        reason: String,
    },
    /// Signed observation is evidence for review, not independently verified availability.
    Observe {
        agreement: RecordId,
        window: u32,
        manifest: RecordId,
        bytes: u64,
    },
    /// Settlement result is independent of acceptance; failure preserves accepted work.
    Settlement {
        submission: RecordId,
        receipt: RecordId,
        succeeded: bool,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkEvent {
    pub version: u16,
    pub work: RecordId,
    pub action: WorkAction,
    pub at_ms: u64,
}
impl WorkEvent {
    pub fn validate(&self, moot: RecordId) -> Result<(), String> {
        let valid = self.version == 1
            && match &self.action {
                WorkAction::Offer { terms, .. } => terms.validate(moot),
                WorkAction::Submit {
                    replaces,
                    outputs,
                    evidence,
                    ..
                } => {
                    canonical_ids(replaces, 64)
                        && canonical_ids(evidence, 64)
                        && !outputs.is_empty()
                        && outputs.len() <= 64
                        && outputs.windows(2).all(|p| p[0] < p[1])
                        && outputs.iter().all(|r| r.moot_id == moot)
                }
                WorkAction::Review {
                    replaces,
                    rationale,
                    ..
                } => canonical_ids(replaces, 64) && text(rationale, 4096),
                WorkAction::Cancel { reason, .. } => text(reason, 4096),
                WorkAction::Observe { bytes, .. } => *bytes > 0,
                _ => true,
            };
        if valid {
            Ok(())
        } else {
            Err("invalid work grammar, terms or foreign outputs".into())
        }
    }
}
pub fn work_cap(work: RecordId) -> Cap {
    Cap::scope(&format!("moot/work/{}", hex(work))).expect("fixed scope")
}
pub fn offer_cap(work: RecordId) -> Cap {
    Cap::scope(&format!("moot/offer/{}", hex(work))).expect("fixed scope")
}
pub fn settlement_cap(work: RecordId) -> Cap {
    Cap::scope(&format!("moot/settlement/{}", hex(work))).expect("fixed scope")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Offer {
    pub id: RecordId,
    pub issuer: RecordId,
    pub terms: WorkTerms,
    pub replaces: Option<RecordId>,
    pub renewals: u16,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Agreement {
    pub id: RecordId,
    pub offer: Offer,
    pub accepted_at_ms: u64,
    pub cancelled: bool,
    pub superseded: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Submission {
    pub id: RecordId,
    pub agreement: RecordId,
    pub window: u32,
    pub outputs: Vec<ContributionRef>,
    pub evidence: Vec<RecordId>,
    pub superseded: bool,
    pub conflict: bool,
    pub accepted: bool,
    pub approvals: BTreeSet<RecordId>,
    pub settlement: Vec<(RecordId, bool)>,
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct WorkView {
    pub offers: BTreeMap<RecordId, Offer>,
    pub agreements: BTreeMap<RecordId, Agreement>,
    pub submissions: BTreeMap<RecordId, Submission>,
    pub applied: BTreeSet<RecordId>,
    pub pending: Vec<RecordId>,
    pub conflict: bool,
    pub cancelled_offers: BTreeSet<RecordId>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedWork {
    pub agreement: RecordId,
    pub worker: RecordId,
    pub submissions: Vec<RecordId>,
    pub standing_commitment: Option<mien::CommitmentId>,
}
impl WorkView {
    /// All required service windows must have one unambiguous accepted result.
    /// This receipt grants neither publication nor payment nor Standing.
    pub fn accepted_work(&self, agreement: RecordId) -> Option<AcceptedWork> {
        if self.conflict {
            return None;
        }
        let a = self.agreements.get(&agreement)?;
        let mut submissions = Vec::new();
        for window in 0..a.offer.terms.windows() {
            let mut matches = self
                .submissions
                .values()
                .filter(|s| s.agreement == agreement && s.window == window && s.accepted);
            submissions.push(matches.next()?.id);
            if matches.next().is_some() {
                return None;
            }
        }
        Some(AcceptedWork {
            agreement,
            worker: a.offer.terms.worker,
            submissions,
            standing_commitment: a.offer.terms.standing_commitment,
        })
    }
    pub fn active_agreement(&self) -> Option<&Agreement> {
        if self.conflict {
            return None;
        }
        let mut active = self
            .agreements
            .values()
            .filter(|a| !a.cancelled && !a.superseded);
        let a = active.next()?;
        if active.next().is_some() {
            None
        } else {
            Some(a)
        }
    }
}
