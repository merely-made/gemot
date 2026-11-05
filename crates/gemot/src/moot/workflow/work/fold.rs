// SPDX-License-Identifier: MPL-2.0
use super::*;
use crate::moot::MootRoster;
use crate::moot::workflow::{WorkflowEvent, WorkflowFact};
use servitor::{AuthorityProvider, Mode, Subject};
use std::collections::{BTreeMap, BTreeSet};

impl MootRoster {
    pub fn work(&self, work: RecordId, authority: &impl AuthorityProvider) -> WorkView {
        let facts: BTreeMap<_, _> = self
            .workflow
            .iter()
            .filter(|f| f.authentic())
            .filter_map(|f| match &f.event {
                WorkflowEvent::Work(e)
                    if e.work == work
                        && (matches!(e.action, WorkAction::Cancel { .. })
                            || authority.covers(
                                Subject::new(f.by),
                                &f.event.cap(),
                                Mode::Write,
                            )) =>
                {
                    Some((f.op_hash, (f, e)))
                }
                _ => None,
            })
            .collect();
        // An issuer may withdraw an offer, and its named worker may decline it.
        // These negative facts survive grant loss and also stop later replayed consent.
        let cancelled_offers: BTreeSet<_> = facts
            .values()
            .filter_map(|(f, e)| match &e.action {
                WorkAction::Cancel { agreement, .. } => {
                    facts
                        .get(agreement)
                        .and_then(|(offer, ev)| match &ev.action {
                            WorkAction::Offer { terms, .. }
                                if (f.by == offer.by || f.by == terms.worker)
                                    && e.at_ms >= ev.at_ms =>
                            {
                                Some(*agreement)
                            }
                            _ => None,
                        })
                }
                _ => None,
            })
            .collect();
        let roots = facts
            .values()
            .filter(|(f, e)| {
                matches!(e.action, WorkAction::Offer { replaces: None, .. })
                    && !cancelled_offers.contains(&f.op_hash)
            })
            .count();
        let mut view = WorkView {
            cancelled_offers,
            ..Default::default()
        };
        let mut remaining = facts.clone();
        let effective: BTreeSet<_> = self
            .authorized_fauna(authority)
            .iter()
            .map(|f| f.op_hash)
            .collect();
        loop {
            let mut progress = false;
            for (id, (fact, event)) in &remaining.clone() {
                if apply(&mut view, fact, event, &facts, &effective, authority) {
                    view.applied.insert(*id);
                    remaining.remove(id);
                    progress = true;
                }
            }
            if !progress {
                break;
            }
        }
        view.pending = remaining.into_keys().collect();
        for (fact, event) in facts.values() {
            if !view.applied.contains(&fact.op_hash) {
                continue;
            }
            match &event.action {
                WorkAction::Accept { offer } => {
                    if let Some(old) = view.offers[offer].replaces {
                        view.agreements
                            .get_mut(&old)
                            .expect("accepted predecessor")
                            .superseded = true;
                    }
                }
                WorkAction::Cancel { agreement, .. } => {
                    if let Some(a) = view.agreements.get_mut(agreement) {
                        a.cancelled = true;
                    }
                }
                WorkAction::Submit { replaces, .. } => {
                    for id in replaces {
                        view.submissions.get_mut(id).expect("submission").superseded = true;
                    }
                }
                _ => {}
            }
        }
        let active = view
            .agreements
            .values()
            .filter(|a| !a.superseded && !a.cancelled)
            .count();
        view.conflict = roots > 1 || active > 1;
        let mut slots = BTreeMap::<_, usize>::new();
        for s in view.submissions.values().filter(|s| !s.superseded) {
            *slots.entry((s.agreement, s.window)).or_default() += 1;
        }
        for s in view.submissions.values_mut() {
            s.conflict = !s.superseded && slots[&(s.agreement, s.window)] > 1;
            let a = &view.agreements[&s.agreement];
            let reviews: Vec<_> = facts
                .values()
                .filter(|(f, e)| {
                    view.applied.contains(&f.op_hash)
                        && matches!(e.action,WorkAction::Review {submission,..} if submission==s.id)
                })
                .collect();
            let replaced: BTreeSet<_> = reviews
                .iter()
                .flat_map(|(_, e)| match &e.action {
                    WorkAction::Review { replaces, .. } => replaces.clone(),
                    _ => vec![],
                })
                .collect();
            let mut voters = BTreeMap::<RecordId, Vec<bool>>::new();
            for (f, e) in reviews {
                if !replaced.contains(&f.op_hash) {
                    if let WorkAction::Review { approve, .. } = e.action {
                        voters.entry(f.by).or_default().push(approve);
                    }
                }
            }
            s.approvals = voters
                .into_iter()
                .filter(|(_, votes)| votes.iter().all(|v| *v))
                .map(|(by, _)| by)
                .collect();
            let review = mooting::RecognitionContext::new(
                mooting::RecognitionPolicy::Threshold {
                    required: u32::from(a.offer.terms.approvals_required),
                },
                mooting::ElectorateSnapshot::new(
                    a.offer.terms.inputs.collection().moot_id,
                    a.offer.id,
                    a.offer.terms.reviewers.iter().copied(),
                ),
            );
            s.accepted = !s.superseded
                && !s.conflict
                && review
                    .evaluate(&s.approvals)
                    .is_ok_and(|decision| decision.accepted);
        }
        view
    }
}

type Facts<'a> = BTreeMap<RecordId, (&'a WorkflowFact, &'a WorkEvent)>;
fn apply(
    view: &mut WorkView,
    fact: &WorkflowFact,
    e: &WorkEvent,
    facts: &Facts<'_>,
    effective: &BTreeSet<RecordId>,
    authority: &impl AuthorityProvider,
) -> bool {
    let id = fact.op_hash;
    match &e.action {
        WorkAction::Offer { terms, replaces } => {
            let renewals = if let Some(old) = replaces {
                let Some(a) = view.agreements.get(old) else {
                    return false;
                };
                if !a.cancelled
                    || fact.by != a.offer.issuer
                    || a.offer.renewals >= a.offer.terms.max_renewals
                    || terms.max_renewals > a.offer.terms.max_renewals
                    || (terms.worker != a.offer.terms.worker && !a.offer.terms.allow_handoff)
                {
                    return false;
                }
                a.offer.renewals + 1
            } else {
                0
            };
            if e.at_ms >= terms.ends_at_ms {
                return false;
            }
            view.offers.insert(
                id,
                Offer {
                    id,
                    issuer: fact.by,
                    terms: terms.clone(),
                    replaces: *replaces,
                    renewals,
                },
            );
        }
        WorkAction::Accept { offer } => {
            let Some(o) = view.offers.get(offer) else {
                return false;
            };
            if fact.by != o.terms.worker
                || e.at_ms >= o.terms.ends_at_ms
                || e.at_ms < facts[offer].1.at_ms
            {
                return false;
            }
            // Consent may be repeated; the exact offer is the stable agreement id.
            view.agreements
                .entry(*offer)
                .and_modify(|a| a.accepted_at_ms = a.accepted_at_ms.min(e.at_ms))
                .or_insert(Agreement {
                    id: *offer,
                    offer: o.clone(),
                    accepted_at_ms: e.at_ms,
                    cancelled: view.cancelled_offers.contains(offer),
                    superseded: false,
                });
        }
        WorkAction::Submit {
            agreement,
            window,
            replaces,
            outputs,
            evidence,
        } => {
            let Some(a) = view.agreements.get(agreement) else {
                return false;
            };
            if fact.by != a.offer.terms.worker
                || a.offer.terms.window_at(e.at_ms) != Some(*window)
                || e.at_ms < a.accepted_at_ms
                || replaces.iter().any(|p| {
                    !view
                        .submissions
                        .get(p)
                        .is_some_and(|s| s.agreement == *agreement && s.window == *window)
                })
                || evidence.iter().any(|p| {
                    !view.applied.contains(p)
                        || !matches!(&facts[p].1.action,
                    WorkAction::Observe {agreement:ag,window:w,..} if ag==agreement && w==window)
                })
            {
                return false;
            }
            // Withdrawal and current authority are re-evaluated on every projection.
            if outputs.iter().any(|r| !effective.contains(&r.share)) {
                return false;
            }
            view.submissions.insert(
                id,
                Submission {
                    id,
                    agreement: *agreement,
                    window: *window,
                    outputs: outputs.clone(),
                    evidence: evidence.clone(),
                    superseded: false,
                    conflict: false,
                    accepted: false,
                    approvals: BTreeSet::new(),
                    settlement: vec![],
                },
            );
        }
        WorkAction::Review {
            submission,
            replaces,
            ..
        } => {
            let Some(s) = view.submissions.get(submission) else {
                return false;
            };
            let a = &view.agreements[&s.agreement];
            if !a.offer.terms.reviewers.contains(&fact.by) || e.at_ms<facts[submission].1.at_ms
                || replaces.iter().any(|p|!view.applied.contains(p) || !facts.get(p).is_some_and(|(f,ev)| f.by==fact.by
                    && matches!(ev.action,WorkAction::Review {submission:prior,..} if prior==*submission))) {return false;}
        }
        WorkAction::Cancel { agreement, .. } => {
            let Some(o) = view.offers.get(agreement) else {
                return false;
            };
            if (fact.by != o.issuer && fact.by != o.terms.worker)
                || e.at_ms < facts[agreement].1.at_ms
            {
                return false;
            }
            if let Some(a) = view.agreements.get_mut(agreement) {
                a.cancelled = true;
            }
        }
        WorkAction::Observe {
            agreement,
            window,
            bytes,
            ..
        } => {
            let Some(a) = view.agreements.get(agreement) else {
                return false;
            };
            if a.offer.terms.window_at(e.at_ms) != Some(*window)
                || *bytes > a.offer.terms.max_bytes
                || e.at_ms < a.accepted_at_ms
            {
                return false;
            }
        }
        WorkAction::Settlement {
            submission,
            receipt,
            succeeded,
        } => {
            let Some(s) = view.submissions.get_mut(submission) else {
                return false;
            };
            if !authority.covers(Subject::new(fact.by), &settlement_cap(e.work), Mode::Write)
                || e.at_ms < facts[submission].1.at_ms
            {
                return false;
            }
            s.settlement.push((*receipt, *succeeded));
            s.settlement.sort();
            s.settlement.dedup();
        }
    }
    true
}
