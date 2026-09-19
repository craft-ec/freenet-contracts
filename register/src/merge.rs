//! The merge: a semilattice, and fork detection layered on top of it.
//!
//! [`join`] is `(max of records, min of evidence)` — commutative, associative and
//! idempotent, with no exceptions and no tie-break that looks at which side is
//! "held". Detection is deliberately NOT part of it: [`detect`] originates
//! evidence when two records equivocate, and [`update`] is
//! `join(join(a, b), detect(a, b))`.
//!
//! That split is what bounds the effect of delivery order. `join` alone can
//! never disagree between replicas; what an unlucky order can change is only
//! WHETHER a fork was noticed, never what two synced replicas hold.

use crate::wire::{conflicts, Authority, Evidence, Record, RegState};
use core::cmp::Ordering;

/// The order the merge takes the maximum of, strongest field first:
///
/// 1. **terminal beats non-terminal** — a register that has been moved is
///    finished, and no later write can reopen it;
/// 2. **higher `seq`**;
/// 3. **lower `BLAKE3(value)`** — the deterministic tie-break for two different
///    values at one `seq`, which is also an equivocation;
/// 4. **lower `BLAKE3(record)`** — this only ever chooses between two encodings
///    of the SAME decision (two signer subsets), so it never means a fork.
pub fn order(x: &Record, y: &Record, a: &Authority) -> Ordering {
    x.signed
        .terminal
        .cmp(&y.signed.terminal)
        .then_with(|| x.signed.seq.cmp(&y.signed.seq))
        // Reversed: the LOWER hash wins, so it is the greater under this order.
        // `then_with` keeps the record hash lazy — it is only ever computed for
        // two encodings of one decision, which is rare.
        .then_with(|| y.signed.value_hash.cmp(&x.signed.value_hash))
        .then_with(|| record_hash(y, a).cmp(&record_hash(x, a)))
}

fn record_hash(r: &Record, a: &Authority) -> [u8; 32] {
    *blake3::hash(&r.encode(a)).as_bytes()
}

fn max_record(x: Option<Record>, y: Option<Record>, a: &Authority) -> Option<Record> {
    match (x, y) {
        (Some(x), Some(y)) => Some(match order(&x, &y, a) {
            Ordering::Less => y,
            _ => x,
        }),
        (x, y) => x.or(y),
    }
}

/// Evidence is sticky: absent is the identity, and of two proofs the lower
/// encoding wins, so every replica keeps the same one.
fn min_evidence(x: Option<Evidence>, y: Option<Evidence>, a: &Authority) -> Option<Evidence> {
    match (x, y) {
        (Some(x), Some(y)) => Some(if x.encode(a) <= y.encode(a) { x } else { y }),
        (x, y) => x.or(y),
    }
}

/// `J((r1,e1),(r2,e2)) = (max(r1,r2), min(e1,e2))`.
pub fn join(x: &RegState, y: &RegState, a: &Authority) -> RegState {
    RegState {
        record: max_record(x.record.clone(), y.record.clone(), a),
        evidence: min_evidence(x.evidence.clone(), y.evidence.clone(), a),
    }
}

/// Evidence originated from two states whose records equivocate. Nothing else
/// about the states matters, and this is the only place evidence is created.
pub fn detect(x: &RegState, y: &RegState, a: &Authority) -> RegState {
    let evidence = match (&x.record, &y.record) {
        (Some(r), Some(s)) if conflicts(&r.signed, &s.signed) => {
            Evidence::new(&r.signed, &s.signed, a)
        }
        _ => None,
    };
    RegState {
        record: None,
        evidence,
    }
}

/// The contract's merge: join, then fold in anything the pair itself proves.
pub fn update(x: &RegState, y: &RegState, a: &Authority) -> RegState {
    join(&join(x, y, a), &detect(x, y, a), a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::*;

    /// The three laws, on `join` alone and with evidence in play. `update` is not
    /// asserted associative — it is not, by design; the laws belong to the join.
    #[test]
    fn join_is_a_semilattice() {
        // Both modes: the encodings differ (mode 0 stores no signer bitmap), and
        // the order breaks ties on encodings.
        for w in [world(), keyset(1, 1, true)] {
            check_laws(&w);
        }
    }

    fn check_laws(w: &World) {
        let states = w.sample_states();
        assert!(states.len() >= 12, "{} states", states.len());
        for x in &states {
            assert_eq!(join(x, x, &w.auth), *x, "idempotent");
            for y in &states {
                assert_eq!(
                    join(x, y, &w.auth),
                    join(y, x, &w.auth),
                    "commutative:\n{x:?}\n{y:?}"
                );
                for z in &states {
                    assert_eq!(
                        join(&join(x, y, &w.auth), z, &w.auth),
                        join(x, &join(y, z, &w.auth), &w.auth),
                        "associative"
                    );
                }
            }
        }
    }

    /// Every replica that has synced holds the same bytes, whatever order the
    /// records reached it in — and if any replica noticed the fork, all of them
    /// end up holding the same proof of it.
    #[test]
    fn replicas_converge_in_every_order() {
        let w = world();
        for seed in 0..40u64 {
            for with_terminal in [false, true] {
                let (ends, _) = w.gossip(seed, with_terminal, update);
                let first = ends[0].encode(&w.auth);
                for e in &ends {
                    assert_eq!(
                        e.encode(&w.auth),
                        first,
                        "replicas disagree (seed {seed}, terminal {with_terminal})"
                    );
                }
                // "If at least one replica detected, all end forked with the
                // same evidence" — after syncing, that is one assertion.
                let forked = ends[0].forked();
                assert!(ends.iter().all(|e| e.forked() == forked));
            }
        }
    }

    /// Negative control: the laws above must be doing work. A merge that keeps
    /// the HELD record when the order cannot separate two records — the shape a
    /// "first writer wins" implementation naturally has — has to fail the
    /// convergence test, or that test proves nothing.
    #[test]
    fn a_merge_that_prefers_the_held_record_fails_to_converge() {
        let w = world();
        let biased = |x: &RegState, y: &RegState, a: &Authority| -> RegState {
            let mut out = update(x, y, a);
            if let (Some(xr), Some(_)) = (&x.record, &y.record) {
                // Prefer what is already held whenever neither terminal nor seq
                // separates the two.
                if x.record.as_ref().map(|r| (r.signed.terminal, r.signed.seq))
                    == y.record.as_ref().map(|r| (r.signed.terminal, r.signed.seq))
                {
                    out.record = Some(xr.clone());
                }
            }
            out
        };
        // No terminal record: a terminal beats everything on the first field, so
        // it would settle every run before a tie-break was ever reached.
        let diverged = (0..40u64).any(|seed| {
            let (ends, _) = w.gossip(seed, false, biased);
            let first = ends[0].encode(&w.auth);
            ends.iter().any(|e| e.encode(&w.auth) != first)
        });
        assert!(
            diverged,
            "the biased merge converged, so the convergence test cannot detect bias"
        );
    }

    /// Detection is order-sensitive and the join is not: replicas may or may not
    /// catch a fork depending on delivery, but they never disagree once synced.
    /// This pins the difference rather than leaving it to prose.
    #[test]
    fn only_whether_a_fork_is_caught_depends_on_order() {
        let w = world();
        let (a, b) = (w.record(false, 7, b"one"), w.record(false, 7, b"two"));
        let (x, y) = (w.state(a.clone()), w.state(b.clone()));
        // Seen together: caught.
        assert!(update(&x, &y, &w.auth).forked());
        // Seen one after the other by a replica that only ever holds the max:
        // the second arrives against a state whose record it equivocates with,
        // so it is still caught. A fork escapes only when the loser never meets
        // the winner at all.
        let empty = RegState::default();
        let stepwise = update(&update(&empty, &x, &w.auth), &y, &w.auth);
        assert!(stepwise.forked());
        assert_eq!(
            stepwise.encode(&w.auth),
            update(&x, &y, &w.auth).encode(&w.auth)
        );
    }

    #[test]
    fn a_terminal_record_can_never_be_displaced() {
        let w = world();
        let terminal = w.state(w.record(true, 0, b"moved-to"));
        let loud = w.state(w.record(false, u64::MAX, b"later"));
        let merged = update(&terminal, &loud, &w.auth);
        assert_eq!(merged.record, terminal.record, "seq must not beat terminal");
        assert!(!merged.forked(), "a higher seq is not an equivocation");
        // Two different terminals are a fork whatever their seqs, with the same
        // winner from either side.
        let other = w.state(w.record(true, u64::MAX, b"elsewhere"));
        let ab = update(&terminal, &other, &w.auth);
        let ba = update(&other, &terminal, &w.auth);
        assert!(ab.forked() && ba.forked());
        assert_eq!(ab.encode(&w.auth), ba.encode(&w.auth));
    }

    /// The same decision signed by two different quorum subsets is one decision
    /// spelled two ways: it converges on the lower record hash and is NOT a fork.
    #[test]
    fn two_signer_subsets_of_one_decision_are_not_a_fork() {
        let w = world();
        let a = w.record_signed_by(false, 3, b"same", &[0, 1]);
        let b = w.record_signed_by(false, 3, b"same", &[1, 2]);
        assert_ne!(a.encode(&w.auth), b.encode(&w.auth), "different encodings");
        let m = update(&w.state(a.clone()), &w.state(b.clone()), &w.auth);
        assert!(!m.forked(), "same value, so no equivocation");
        let lower = if blake3::hash(&a.encode(&w.auth)).as_bytes()
            <= blake3::hash(&b.encode(&w.auth)).as_bytes()
        {
            a
        } else {
            b
        };
        assert_eq!(m.record.unwrap().encode(&w.auth), lower.encode(&w.auth));
    }
}
