//! Inter-moot reciprocity credits — Phase 5 (the t3 ILL facet).
//!
//! The federation's give-and-take, kept as credits rather than cash. A moot earns
//! standing with a peer by *providing* for it (hosting a service, pinning a
//! cluster) and spends that standing by *requesting* the same. A moot that only
//! takes runs up an unreciprocated debt and is cut off — it loses privileges, not
//! money (moot tiers §7). It is a sibling of the reputation ledger on the same
//! event idea, keyed by moot pair rather than persona.

use std::collections::HashMap;

use crate::tessera::concord::MootId;

/// The directed give-and-take ledger between moots: how much each moot has
/// provided to each other moot.
#[derive(Clone, Debug, Default)]
pub struct Reciprocity {
    /// `(provider, beneficiary)` -> cumulative amount provided.
    given: HashMap<(MootId, MootId), u64>,
}

impl Reciprocity {
    /// An empty ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `provider` did `amount` of work (hosted, pinned) for
    /// `beneficiary`.
    pub fn record(&mut self, provider: MootId, beneficiary: MootId, amount: u64) {
        *self.given.entry((provider, beneficiary)).or_default() += amount;
    }

    fn provided(&self, provider: MootId, beneficiary: MootId) -> u64 {
        self.given
            .get(&(provider, beneficiary))
            .copied()
            .unwrap_or(0)
    }

    /// Net amount `a` has provided to `b`: positive means `b` is in `a`'s debt
    /// (b has taken more from a than it has given back).
    pub fn balance(&self, a: MootId, b: MootId) -> i64 {
        self.provided(a, b) as i64 - self.provided(b, a) as i64
    }

    /// May `requester` ask `from` for more service now? Yes unless `requester`
    /// has already run up an unreciprocated debt to `from` beyond `tolerance` —
    /// the freeloader cut-off (lose privileges, not money).
    pub fn may_request(&self, requester: MootId, from: MootId, tolerance: u64) -> bool {
        self.balance(from, requester) <= tolerance as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn moot(n: u8) -> MootId {
        MootId([n; 32])
    }

    #[test]
    fn provided_work_sets_the_balance() {
        let (a, b) = (moot(1), moot(2));
        let mut r = Reciprocity::new();
        r.record(a, b, 10);
        assert_eq!(r.balance(a, b), 10, "B is in A's debt");
        assert_eq!(r.balance(b, a), -10);
    }

    #[test]
    fn reciprocation_nets_out() {
        let (a, b) = (moot(1), moot(2));
        let mut r = Reciprocity::new();
        r.record(a, b, 10);
        r.record(b, a, 10);
        assert_eq!(r.balance(a, b), 0);
    }

    #[test]
    fn a_reciprocating_peer_may_keep_requesting() {
        let (a, b) = (moot(1), moot(2));
        let mut r = Reciprocity::new();
        r.record(a, b, 30);
        r.record(b, a, 25);
        // B's net debt to A is 5, within the tolerance.
        assert!(r.may_request(b, a, 10));
    }

    #[test]
    fn a_freeloader_is_cut_off_until_it_reciprocates() {
        let (a, b) = (moot(1), moot(2));
        let mut r = Reciprocity::new();
        // A keeps hosting for B; B never gives back. B's debt climbs past the
        // tolerance and B can no longer request.
        r.record(a, b, 50);
        assert!(!r.may_request(b, a, 10));
        // Until B reciprocates enough to bring the debt back under tolerance.
        r.record(b, a, 45);
        assert!(r.may_request(b, a, 10));
    }
}
