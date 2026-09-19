//! The join: union, keep the top M.
//!
//! Top-M under a fixed total order on immutable names is a semilattice join —
//! commutative, associative, idempotent — and that is the whole of the merge.
//! There are no versions here, so nothing can be resurrected and nothing has a
//! held witness: a name either met the price or it did not.

use crate::wire::{BagState, Held, Params, Pointer, HASH_LEN, TRUNC};

/// Truncations copied out of a summary. A summary arrives from a stranger and
/// is SORTED, so its length is work it can impose on every host — counted so a
/// test can assert the price of refusing one. Thread-local for the reason given
/// on [`crate::wire::hashed`].
#[cfg(any(test, feature = "testing"))]
pub mod summary_entries {
    use core::cell::Cell;
    thread_local! { static N: Cell<usize> = const { Cell::new(0) }; }
    /// Truncations copied on this thread since the last [`reset`].
    pub fn count() -> usize {
        N.with(|n| n.get())
    }
    pub fn reset() {
        N.with(|n| n.set(0));
    }
    pub(crate) fn tick() {
        N.with(|n| n.set(n.get() + 1));
    }
}

/// `union, then keep the best M`.
///
/// Commutative and associative because the order is total and fixed on names
/// that cannot change; idempotent because the union of a set with itself is
/// itself. The `M` cut does not break any of the three: taking the best M of a
/// union is taking the best M of the best-M's, since anything dropped was below
/// something kept.
pub fn join(a: &BagState, b: &BagState, m: u16) -> BagState {
    let mut held: Vec<Held> = Vec::with_capacity(a.held.len() + b.held.len());
    held.extend(a.held.iter().cloned());
    held.extend(b.held.iter().cloned());
    held.sort_by_key(|h| h.rank());
    held.dedup_by(|x, y| x.name == y.name);
    held.truncate(m as usize);
    BagState { held }
}

/// What a peer needs to know to ask for what it lacks.
///
/// `count(2) ‖ lowest work(1) ‖ lowest name(32) ‖ trunc*`, the truncations
/// sorted.
///
/// **There is no fullness flag.** A bag is full exactly when its count equals
/// `M`, and `M` is in the params, so a flag would be a second encoding of a
/// fact already on the wire — and one encoding per fact is the rule this format
/// is built on. The reader derives it.
///
/// **`count` is a claim a stranger can buy**, not a fact: a bag is filled by
/// whoever pays the work. The lowest kept carries the FULL name, not
/// a truncation — at equal work a truncated name would leave the boundary
/// undecidable, and work ties are ordinary.
pub fn summarize(s: &BagState) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + HASH_LEN + s.held.len() * TRUNC);
    out.extend_from_slice(&(s.held.len() as u16).to_le_bytes());
    match s.held.last() {
        Some(low) => {
            out.push(low.work.min(u8::MAX as u32) as u8);
            out.extend_from_slice(&low.name);
        }
        // An empty bag keeps nothing, so there is no cut: work 0 and the
        // all-ones name sort below everything, which is what "no cut" means.
        None => {
            out.push(0);
            out.extend_from_slice(&[0xff; HASH_LEN]);
        }
    }
    let mut trunc: Vec<&[u8]> = s.held.iter().map(|h| &h.name[..TRUNC]).collect();
    trunc.sort_unstable();
    for t in trunc {
        out.extend_from_slice(t);
    }
    out
}

/// A summary as the sender reads it.
pub struct Summary {
    /// How many truncations follow — a claim, cross-checked against the body.
    pub count: u16,
    /// Derived from `count` and `M`, never carried on the wire.
    pub full: bool,
    pub lowest: (u32, [u8; HASH_LEN]),
    /// Sorted, for a binary search per candidate.
    pub trunc: Vec<[u8; TRUNC]>,
}

impl Summary {
    /// Read a peer's summary. `m` is this bag's capacity, which is in the
    /// params and therefore the same for both sides.
    pub fn parse(b: &[u8], m: u16) -> Option<Summary> {
        let (head, rest) = b.split_at_checked(2 + 1 + HASH_LEN)?;
        if rest.len() % TRUNC != 0 {
            return None;
        }
        // A bag holds at most `m` pointers, so a summary of more than `m`
        // truncations is not a summary of a bag. Checked BEFORE anything is
        // copied or sorted: a stranger's multi-megabyte summary would
        // otherwise buy a large sort inside `get_state_delta` on every host
        // that serves it.
        if rest.len() > m as usize * TRUNC {
            return None;
        }
        let count = u16::from_le_bytes([head[0], head[1]]);
        // One spelling: the count must be the number of truncations that
        // follow. An unused field is a field two encodings can disagree on.
        if count as usize != rest.len() / TRUNC {
            return None;
        }
        let mut lowest = [0u8; HASH_LEN];
        lowest.copy_from_slice(&head[3..]);
        let mut trunc: Vec<[u8; TRUNC]> = rest
            .chunks_exact(TRUNC)
            .map(|c| {
                #[cfg(any(test, feature = "testing"))]
                summary_entries::tick();
                c.try_into().expect("chunk")
            })
            .collect();
        // A stranger's summary need not arrive sorted; sorting it here costs
        // one sort and makes the lookup below a binary search rather than a
        // scan per candidate.
        trunc.sort_unstable();
        Some(Summary {
            // Derived, never carried. `count` is already cross-checked against
            // the number of truncations that follow, and the bound above makes
            // it at most `m`, so "full" is exactly "count reached the cap".
            count,
            full: count >= m,
            lowest: (head[2] as u32, lowest),
            trunc,
        })
    }

    /// Does the peer already have this name?
    ///
    /// By 16 bytes. Missing a pointer because of a collision costs an attacker
    /// a 2^128 search (2^128/M to hit any of M targets); at 8 bytes it would be
    /// 2^64/M, which is buyable.
    fn has(&self, name: &[u8; HASH_LEN]) -> bool {
        self.trunc
            .binary_search(&name[..TRUNC].try_into().expect("prefix"))
            .is_ok()
    }

    /// Would this pointer make the peer's top M?
    ///
    /// When the peer is full, that is exactly "does it rank above the lowest it
    /// keeps". When it is NOT full it has room, so anything it lacks qualifies
    /// — and the sender must not try to work out which of its own pointers will
    /// survive the peer's merge, because that depends on the union and the peer
    /// decides it. Sending one the peer drops costs bytes, never correctness.
    fn wants(&self, h: &Held) -> bool {
        if !self.full {
            return true;
        }
        (core::cmp::Reverse(h.work), h.name) < (core::cmp::Reverse(self.lowest.0), self.lowest.1)
    }
}

/// The pointers this state holds that the peer lacks and can use.
pub fn delta(s: &BagState, summary: &[u8], m: u16) -> Option<BagState> {
    let sum = Summary::parse(summary, m)?;
    Some(BagState {
        held: s
            .held
            .iter()
            .filter(|h| !sum.has(&h.name) && sum.wants(h))
            .cloned()
            .collect(),
    })
}

/// Read a delta the way a state is read: a delta IS a bag, checked identically.
/// One parser, so a delta cannot carry anything a state could not.
pub fn read_delta(b: &[u8], p: &Params) -> Option<BagState> {
    BagState::parse(b, p)
}

/// Build a bag from pointers, for tests and for callers assembling one.
pub fn collect(ptrs: impl IntoIterator<Item = Pointer>, p: &Params) -> BagState {
    let ph = p.hash();
    let mut held: Vec<Held> = ptrs
        .into_iter()
        .map(|ptr| Held::of(ptr, &ph))
        .filter(|h| h.work >= p.work_bits as u32 && h.ptr.payload.len() <= p.payload_cap as usize)
        .collect();
    held.sort_by_key(|h| h.rank());
    held.dedup_by(|x, y| x.name == y.name);
    held.truncate(p.m as usize);
    BagState { held }
}
