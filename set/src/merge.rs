//! The join: union the slots, keep the best decision in each, cut to capacity.
//!
//! Rank belongs to the SLOT and never to a version. A slot's name is
//! `BLAKE3(domain ‖ params ‖ signer ‖ item key)`, so its rank is identical for
//! every version of it, cannot be improved by writing, and cannot be touched by
//! anyone but the signer choosing the key in the first place. That is what
//! makes the cut associative: a slot in the global top M is in the top M of
//! every subset containing it, whatever versions anyone holds.
//!
//! **What the laws are stated over.** The join is commutative, associative and
//! idempotent **on decisions**, not on bytes. A decision can have many
//! witnesses — another signature over the same decision, a different stamp
//! nonce, a different capability — and on an exact tie the incumbent's witness
//! is kept, so `J(a,b)` and `J(b,a)` can spell one state two ways. That is the
//! same choice the Register makes and for the same reason: if a second witness
//! of the decision already held rewrote the state, any key holder could make
//! every host rewrite and every subscriber wake, for free, for ever.
//! `SetState::decisions` is the projection the law tests compare.

use crate::wire::{Decision, Deny, Held, Params, SetState, Tier, HASH_LEN, KEY_LEN, TRUNC};

/// Truncations copied out of a summary. A summary arrives from a stranger and
/// is sorted here, so its length is work it can impose on every host — counted
/// so a test can assert the price of refusing one. Thread-local for the reason
/// given on [`crate::wire::verifications`].
#[cfg(any(test, feature = "testing"))]
pub mod summary_entries {
    use core::cell::Cell;
    thread_local! { static N: Cell<usize> = const { Cell::new(0) }; }
    pub fn reset() {
        N.with(|n| n.set(0));
    }
    pub fn count() -> usize {
        N.with(|n| n.get())
    }
    pub(crate) fn tick() {
        N.with(|n| n.set(n.get() + 1));
    }
}

/// Keep the best `quota` slots of each signer and the best `M` of each tier.
///
/// One pass rather than two, and that is not a shortcut: a tier is a property
/// of the SIGNER, so every slot of one signer is in one tier, and "top quota
/// per signer, then top M per tier" and "in rank order, keep while both have
/// room" select the same slots. Pinned by a test.
///
/// **The cut is deliberately blind to denials** — see [`join`].
pub fn cut(mut slots: Vec<Held>, p: &Params) -> Vec<Held> {
    slots.sort_by_key(|h| h.rank());
    let mut per_signer: Vec<([u8; KEY_LEN], u16)> = Vec::new();
    let mut per_tier = [0u16; 2];
    let mut kept: Vec<Held> = Vec::with_capacity(slots.len().min(2 * p.m as usize));
    for h in slots {
        let tier = h.tier as usize;
        if per_tier[tier] >= p.m {
            continue;
        }
        let key = *h.item.signer.as_bytes();
        let seen = match per_signer.iter().position(|(k, _)| *k == key) {
            Some(i) => &mut per_signer[i].1,
            None => {
                per_signer.push((key, 0));
                &mut per_signer.last_mut().expect("just pushed").1
            }
        };
        if *seen >= p.quota {
            continue;
        }
        *seen += 1;
        per_tier[tier] += 1;
        kept.push(h);
    }
    kept
}

/// `union the slots, best decision per slot, cut`. Denials do not enter this.
///
/// **A denied slot is RETAINED and hidden, never dropped from the state**, and
/// that is forced rather than chosen. A denial arrives later than the items it
/// denies, and the capacity cut discards its losers irrecoverably. Whichever
/// way a dropping join is ordered, some triple disagrees with itself:
///
/// ```text
/// drop, then cut — with M = 1, x denied later by C:
///   J(J({x},{y}), C) → {}        J({x}, J({y},C)) → {y}
/// cut, then drop — the same three facts, the denial moved inwards:
///   J(J({x},C), {y}) → {y}       J({x}, J(C,{y})) → {}
/// ```
///
/// The cause is common to both: if the stored state omits the denied slot, the
/// slot stops consuming its place on a replica that learned the denial early
/// and still consumes it on one that learned it late. No ordering of "cut" and
/// "drop" repairs that, because the cut has already thrown `y` away and a
/// removal cannot bring it back.
///
/// So the state keeps the slot — the whole signed item, not a placeholder:
/// a placeholder would not be self-certifying, and anyone could then fabricate
/// top-ranked "denied" slots to starve the Set. The cut becomes a pure function
/// of the slot union on every replica, the deny set is an independent grow-only
/// union, and the join is the product of two semilattices. What a READER sees
/// is [`SetState::visible`].
///
/// This also settles what happens to a denied signer's LATER items: they are
/// admitted, retained and hidden, exactly like its earlier ones, and they count
/// in the cut. Refusing them at admission would make a slot's existence depend
/// on whether the denial had arrived yet, which is the same order-dependence by
/// another route. A denied signer can therefore hold its `quota` of places in
/// the cap-holder tier for the life of the bucket, and no more.
pub fn join(a: &SetState, b: &SetState, p: &Params) -> SetState {
    let mut deny: Vec<Deny> = Vec::with_capacity(a.deny.len() + b.deny.len());
    deny.extend(a.deny.iter().cloned());
    deny.extend(b.deny.iter().cloned());
    deny.sort_by_key(|d| d.signer);
    deny.dedup_by(|x, y| x.signer == y.signer);

    // One entry per slot, holding the best decision offered for it.
    let mut slots: Vec<Held> = Vec::with_capacity(a.held.len() + b.held.len());
    for h in a.held.iter().chain(b.held.iter()) {
        match slots.iter().position(|s| s.slot == h.slot) {
            None => slots.push(h.clone()),
            Some(i) => {
                // Strictly greater, so an equal decision keeps the incumbent's
                // witness: another witness of what is held changes nothing.
                if h.item.decision().rank() > slots[i].item.decision().rank() {
                    slots[i] = h.clone();
                }
            }
        }
    }

    let mut held = cut(slots, p);
    held.sort_by_key(|h| h.rank());
    SetState { deny, held }
}

/// `BLAKE3(deny keys) ‖ owner count(2) ‖ cap count(2) ‖ trunc*`, the
/// truncations of the held DECISIONS, sorted.
///
/// Decisions, not encodings: two replicas can legitimately hold different
/// witnesses of one decision, and a summary that read the witness would leave
/// them seeing each other as stale for ever, re-sending on every exchange, over
/// a difference neither of them needs resolved.
///
/// **There is no fullness flag.** A tier is full exactly when its count equals
/// `M`, which is in the params, so a flag would be a second encoding of a fact
/// already on the wire — and one encoding per fact is the rule this format is
/// built on. The counts remain CLAIMS: a summary comes from a stranger, and
/// nothing here makes one true.
///
/// The deny set is summarised by a hash rather than by its keys. It is
/// grow-only and at most 64 entries, so sending it whole when the hashes differ
/// costs at most a few kilobytes; naming which denials a peer lacks would cost
/// 32 bytes each in every summary to save that.
pub fn summarize(s: &SetState, p: &Params) -> Vec<u8> {
    let ph = p.hash();
    let mut out = Vec::with_capacity(HASH_LEN + 4 + s.held.len() * TRUNC);
    out.extend_from_slice(&deny_hash(&s.deny));
    for tier in [Tier::Owner, Tier::CapHolder] {
        let n = s.held.iter().filter(|h| h.tier == tier).count() as u16;
        out.extend_from_slice(&n.to_le_bytes());
    }
    let mut trunc: Vec<[u8; TRUNC]> = s
        .held
        .iter()
        .map(|h| {
            let d = h.item.decision().hash(&ph);
            d[..TRUNC].try_into().expect("TRUNC < HASH_LEN")
        })
        .collect();
    trunc.sort_unstable();
    for t in trunc {
        out.extend_from_slice(&t);
    }
    out
}

/// The denial set's identity: the denied KEYS, in order. The signatures are
/// witnesses, so re-signing a denial must not make two replicas disagree.
pub fn deny_hash(deny: &[Deny]) -> [u8; HASH_LEN] {
    let mut h = blake3::Hasher::new();
    for d in deny {
        h.update(&d.signer);
    }
    *h.finalize().as_bytes()
}

/// A summary as the sender reads it.
pub struct Summary {
    pub deny_hash: [u8; HASH_LEN],
    pub counts: [u16; 2],
    /// Sorted, for a binary search per candidate.
    pub trunc: Vec<[u8; TRUNC]>,
}

pub const SUMMARY_HEAD: usize = HASH_LEN + 2 + 2;

impl Summary {
    /// Read a peer's summary. `p` supplies `M`, which is in the params and so is
    /// the same for both sides.
    pub fn parse(b: &[u8], p: &Params) -> Option<Summary> {
        let (head, rest) = b.split_at_checked(SUMMARY_HEAD)?;
        if rest.len() % TRUNC != 0 {
            return None;
        }
        // A set holds at most `M` slots per tier, so a summary of more than
        // `2M` truncations is not a summary of a set. Checked BEFORE anything
        // is copied or sorted: otherwise a stranger's multi-megabyte summary
        // buys a large sort inside `get_state_delta` on every host that serves
        // it, and the verdict "refused" would look identical either way.
        if rest.len() > 2 * p.m as usize * TRUNC {
            return None;
        }
        let counts = [
            u16::from_le_bytes([head[HASH_LEN], head[HASH_LEN + 1]]),
            u16::from_le_bytes([head[HASH_LEN + 2], head[HASH_LEN + 3]]),
        ];
        // One spelling: the counts must be the number of truncations that
        // follow. A field nothing checks is a field two encodings can disagree
        // on, and a count that cannot be cross-checked is a claim with no
        // referent at all.
        if counts[0] as usize + counts[1] as usize != rest.len() / TRUNC {
            return None;
        }
        if counts[0] > p.m || counts[1] > p.m {
            return None;
        }
        let mut trunc: Vec<[u8; TRUNC]> = rest
            .chunks_exact(TRUNC)
            .map(|c| {
                #[cfg(any(test, feature = "testing"))]
                summary_entries::tick();
                c.try_into().expect("chunk")
            })
            .collect();
        // A stranger's summary need not arrive sorted; one sort here makes the
        // lookup below a binary search rather than a scan per candidate.
        trunc.sort_unstable();
        Some(Summary {
            deny_hash: head[..HASH_LEN].try_into().ok()?,
            counts,
            trunc,
        })
    }

    fn has(&self, d: &Decision, ph: &[u8; HASH_LEN]) -> bool {
        let h = d.hash(ph);
        self.trunc
            .binary_search(&h[..TRUNC].try_into().expect("prefix"))
            .is_ok()
    }
}

/// What this state holds that the peer's summary does not mention.
///
/// Exactly the items whose DECISION the peer lacks — a peer holding another
/// witness of the same decision is sent nothing, which is the whole reason the
/// summary hashes decisions. Denials travel whole or not at all.
pub fn delta(s: &SetState, summary: &[u8], p: &Params) -> Option<SetState> {
    let sum = Summary::parse(summary, p)?;
    let ph = p.hash();
    let deny = if sum.deny_hash == deny_hash(&s.deny) {
        Vec::new()
    } else {
        s.deny.clone()
    };
    Some(SetState {
        deny,
        held: s
            .held
            .iter()
            .filter(|h| !sum.has(&h.item.decision(), &ph))
            .cloned()
            .collect(),
    })
}

/// Read a delta the way a state is read: a delta IS a set, checked identically,
/// so nothing can arrive through a delta that could not arrive as a state.
pub fn read_delta(b: &[u8], p: &Params) -> Option<SetState> {
    SetState::parse(b, p)
}
