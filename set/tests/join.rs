//! The merge is a join, or the Set is not a CRDT. Laws first.
//!
//! The laws are stated over `decisions()` — the state's facts with every
//! witness dropped. Comparing encodings would call two replicas that hold
//! different signatures over the SAME decision a disagreement, which is exactly
//! the difference the format exists to make invisible.

use craftec_set_contract::merge::{cut, join};
use craftec_set_contract::testing::{world, world_with};
use craftec_set_contract::wire::{
    leading_zeros, Admission, Held, Item, Params, SetState, Tier, MAX_DENY, MAX_ITEM_KEY,
};
use craftec_set_contract::MAX_STATE;

fn facts(s: &SetState) -> impl PartialEq + core::fmt::Debug {
    s.decisions()
}

/// Every association and every order of three states, compared on facts.
fn laws(a: &SetState, b: &SetState, c: &SetState, p: &Params, what: &str) {
    assert_eq!(
        facts(&join(a, b, p)),
        facts(&join(b, a, p)),
        "{what}: not commutative"
    );
    assert_eq!(
        facts(&join(&join(a, b, p), c, p)),
        facts(&join(a, &join(b, c, p), p)),
        "{what}: not associative"
    );
    assert_eq!(facts(&join(a, a, p)), facts(a), "{what}: not idempotent");
    // And the join really is doing something, or the three above are about
    // nothing. At least one pairing must differ from one of its inputs.
    let ab = join(a, b, p);
    assert!(
        facts(&ab) != facts(a) || facts(&ab) != facts(b) || facts(a) == facts(b),
        "{what}: the fixture merges two states that were already equal"
    );
}

#[test]
fn the_join_is_commutative_associative_and_idempotent() {
    let w = world_with(3, 4, Admission::Cap, 3, 2, 0);
    // Overlapping slots, competing versions of shared slots, tombstones, and
    // more slots than the capacity so the cut is always live.
    let a = w.state(vec![
        w.item(0, b"alpha", 5, b"a5"),
        w.item(1, b"beta", 2, b"b2"),
        w.item(1, b"gamma", 9, b"g9"),
        w.item(2, b"delta", 1, b"d1"),
    ]);
    let b = w.state(vec![
        w.item(0, b"alpha", 7, b"a7"), // newer version of a shared slot
        w.item(1, b"beta", 2, b"b2"),  // the same decision, same witness
        w.tombstone(2, b"delta", 4),   // deletes a slot a holds
        w.item(3, b"eps", 3, b"e3"),
    ]);
    let c = w.state(vec![
        w.item(0, b"zeta", 6, b"z6"),
        w.item(1, b"gamma", 1, b"g1"), // older version: must lose
        w.item(3, b"eta", 8, b"h8"),
    ]);
    laws(&a, &b, &c, &w.params, "mixed");
    laws(
        &a,
        &SetState::default(),
        &c,
        &w.params,
        "with the empty state",
    );

    // The empty state is the identity.
    assert_eq!(
        facts(&join(&a, &SetState::default(), &w.params)),
        facts(&a),
        "the empty set is not the identity"
    );
}

/// The reason rank belongs to the slot and not to a version.
///
/// The OLD rule — rank a slot by the work of the VERSION held — is implemented
/// here as a control and shown to break associativity on the spec's fixture, by
/// resurrecting a tombstone. Without this control the test below asserts only
/// that the current rule works, and a rule that did nothing would pass it.
mod version_ranked_control {
    use super::*;

    /// The rejected rule: the held VERSION's decision hash decides the rank.
    fn rank(h: &Held, ph: &[u8; 32]) -> (Tier, core::cmp::Reverse<u32>, [u8; 32]) {
        let d = h.item.decision().hash(ph);
        (h.tier, core::cmp::Reverse(leading_zeros(&d)), d)
    }

    pub fn join_old(a: &SetState, b: &SetState, p: &Params, ph: &[u8; 32]) -> SetState {
        let mut slots: Vec<Held> = Vec::new();
        for h in a.held.iter().chain(b.held.iter()) {
            match slots.iter().position(|s| s.slot == h.slot) {
                None => slots.push(h.clone()),
                Some(i) => {
                    if h.item.decision().rank() > slots[i].item.decision().rank() {
                        slots[i] = h.clone();
                    }
                }
            }
        }
        slots.sort_by_key(|h| rank(h, ph));
        slots.truncate(p.m as usize);
        SetState {
            deny: Vec::new(),
            held: slots,
        }
    }
}

#[test]
fn a_strangers_item_cannot_resurrect_a_tombstone() {
    // M = 1, so every arrival competes for the single place.
    let w = world_with(4, 4, Admission::Cap, 1, 1, 0);
    let ph = w.ph();
    let lz = |it: &Item| leading_zeros(&it.decision().hash(&ph));

    // p2: the old version. p1: the newer tombstone of the SAME slot. x: a
    // stranger's slot whose version-work sits between them — which is the only
    // thing the old rule needed to go wrong.
    let find = |mk: &dyn Fn(u64) -> Item, want: u32| -> Item {
        (0..4000)
            .map(mk)
            .find(|it| lz(it) == want)
            .expect("a decision with this much version-work exists")
    };
    let p2 = find(&|t| w.item(1, b"page", 100 + t * 4, b"live"), 2);
    let p1 = find(&|t| w.tombstone(1, b"page", 200_000 + t), 0);
    let x = find(&|t| w.item(2, b"other", 50 + t, b"stranger"), 1);
    assert!(p1.ts > p2.ts, "the tombstone must be the newer version");
    assert_eq!(
        (lz(&p2), lz(&x), lz(&p1)),
        (2, 1, 0),
        "the fixture needs version-work strictly between"
    );

    let (sp2, sp1, sx) = (
        w.state(vec![p2.clone()]),
        w.state(vec![p1.clone()]),
        w.state(vec![x.clone()]),
    );

    // The control: under the OLD rule the two associations disagree, and the
    // second brings the deleted item back.
    let left = version_ranked_control::join_old(
        &version_ranked_control::join_old(&sp2, &sx, &w.params, &ph),
        &sp1,
        &w.params,
        &ph,
    );
    let right = version_ranked_control::join_old(
        &sp2,
        &version_ranked_control::join_old(&sx, &sp1, &w.params, &ph),
        &w.params,
        &ph,
    );
    assert_ne!(
        left.decisions(),
        right.decisions(),
        "the OLD rule must fail here, or this test proves nothing"
    );
    assert!(
        right
            .held
            .iter()
            .any(|h| !h.item.tombstone && h.item.item_key == b"page"),
        "the OLD rule must resurrect the deleted item"
    );

    // The rule in force: both associations agree.
    let left = join(&join(&sp2, &sx, &w.params), &sp1, &w.params);
    let right = join(&sp2, &join(&sx, &sp1, &w.params), &w.params);
    assert_eq!(left.decisions(), right.decisions(), "still not associative");
    // And wherever the slot survives the cut, it is the tombstone that is held.
    for s in [&left, &right] {
        for h in &s.held {
            if h.item.item_key == b"page" {
                assert!(h.item.tombstone, "a deleted item came back");
            }
        }
    }
}

#[test]
fn a_slots_rank_is_the_same_for_every_version_of_it() {
    let w = world();
    let ph = w.ph();
    let base = w.item(1, b"key", 1, b"first");
    let held = craftec_set_contract::wire::Held::of(base.clone(), &w.params, &ph);
    for other in [
        w.item(1, b"key", 900, b"much later and much longer payload"),
        w.tombstone(1, b"key", 5000),
        w.sealed(1, b"key", 6000, b"sealed"),
        w.item_full(1, b"key", 1, b"first", false, false, 77), // another witness
    ] {
        let h2 = craftec_set_contract::wire::Held::of(other, &w.params, &ph);
        assert_eq!(held.slot, h2.slot, "the slot's NAME moved between versions");
        assert_eq!(held.rank(), h2.rank(), "the slot's RANK moved");
    }
}

#[test]
fn nobody_but_the_signer_can_change_a_slots_rank() {
    let w = world();
    let other = craftec_set_contract::testing::elsewhere();
    let ph = w.ph();
    let mine = craftec_set_contract::wire::Held::of(w.item(1, b"key", 1, b"v"), &w.params, &ph);
    // Same key bytes, a different signer: a different slot, so a stranger can
    // only ever name its own.
    let theirs = craftec_set_contract::wire::Held::of(w.item(2, b"key", 1, b"v"), &w.params, &ph);
    assert_ne!(mine.slot, theirs.slot);
    // Same signer and key under other params: also a different slot, so work
    // mined for one Set is worth nothing in another.
    let elsewhere = craftec_set_contract::wire::Held::of(
        other.item(1, b"key", 1, b"v"),
        &other.params,
        &other.ph(),
    );
    assert_ne!(mine.slot, elsewhere.slot);
}

/// The work term in the order is documentation, not a decision: work IS the
/// leading zeros of the slot hash, so a hash with more of them is numerically
/// smaller and the two comparisons cannot disagree. Pinned, because a mutation
/// that deletes the work term changes nothing and would otherwise look like a
/// surviving mutant rather than an equivalent one.
#[test]
fn the_work_term_and_the_slot_hash_never_disagree() {
    let w = world_with(5, 4, Admission::Cap, 64, 64, 0);
    let ph = w.ph();
    let mut held: Vec<Held> = (0..200u32)
        .map(|i| {
            craftec_set_contract::wire::Held::of(
                w.item(1, &i.to_le_bytes(), 1, b"v"),
                &w.params,
                &ph,
            )
        })
        .collect();
    held.sort_by_key(|h| h.slot);
    for pair in held.windows(2) {
        let (x, y) = (&pair[0], &pair[1]);
        assert!(
            leading_zeros(&x.slot) >= leading_zeros(&y.slot),
            "more leading zeros must mean a smaller hash"
        );
        assert!(x.rank() < y.rank(), "and the rank must follow the hash");
    }
}

/// One pass over the rank order, keeping while both the signer's quota and the
/// tier have room, selects exactly what "top quota per signer, then top M per
/// tier" selects — because a tier is a property of the SIGNER, so all of one
/// signer's slots are in one tier.
#[test]
fn the_one_pass_cut_selects_what_two_phases_would() {
    let w = world_with(6, 4, Admission::Cap, 5, 2, 0);
    let ph = w.ph();
    let mut all: Vec<Held> = Vec::new();
    for who in 0..4 {
        for i in 0..4u32 {
            all.push(craftec_set_contract::wire::Held::of(
                w.item(who, &[b'k', i as u8], 1, b"v"),
                &w.params,
                &ph,
            ));
        }
    }
    let one_pass = cut(all.clone(), &w.params);

    // Two phases, written out independently.
    let mut sorted = all.clone();
    sorted.sort_by_key(|h| h.rank());
    let mut phase1: Vec<Held> = Vec::new();
    for h in sorted {
        let n = phase1
            .iter()
            .filter(|x| x.item.signer == h.item.signer)
            .count();
        if n < w.params.quota as usize {
            phase1.push(h);
        }
    }
    let mut phase2: Vec<Held> = Vec::new();
    for h in phase1 {
        let n = phase2.iter().filter(|x| x.tier == h.tier).count();
        if n < w.params.m as usize {
            phase2.push(h);
        }
    }
    // The join re-sorts its output, which is a no-op because `cut` already
    // emits in rank order — pinned here so that redundancy is a recorded
    // equivalence rather than a mutant that looks like a hole.
    assert!(
        one_pass.windows(2).all(|p| p[0].rank() < p[1].rank()),
        "the cut must emit in rank order"
    );
    let mut a: Vec<[u8; 32]> = one_pass.iter().map(|h| h.slot).collect();
    let mut b: Vec<[u8; 32]> = phase2.iter().map(|h| h.slot).collect();
    a.sort_unstable();
    b.sort_unstable();
    assert_eq!(a, b);
    assert!(!a.is_empty() && a.len() < 16, "the cut must actually cut");
}

/// Sealing has to mean something or it is a flag the contract invites a reader
/// to trust and never enforces. Both directions, so the test cannot pass by the
/// order simply ignoring the flag.
#[test]
fn a_sealed_decision_is_not_superseded_by_a_later_unsealed_one() {
    let w = world();
    let sealed = w.state(vec![w.sealed(1, b"page", 10, b"final")]);
    let later = w.state(vec![w.item(1, b"page", 9_999, b"edit after sealing")]);
    let merged = join(&sealed, &later, &w.params);
    assert_eq!(merged.held.len(), 1);
    assert!(merged.held[0].item.sealed, "an unsealed edit won");
    assert_eq!(merged.held[0].item.payload, b"final");
    // Order does not matter.
    assert_eq!(
        join(&later, &sealed, &w.params).decisions(),
        merged.decisions()
    );

    // Control: without the seal, the later decision DOES win — so the assertion
    // above is about sealing and not about `ts` being ignored.
    let unsealed = w.state(vec![w.item(1, b"page", 10, b"first")]);
    let after = join(&unsealed, &later, &w.params);
    assert_eq!(after.held[0].item.payload, b"edit after sealing");

    // And a sealed slot is still deletable by its writer — with a sealed
    // tombstone, which is what "no ordinary edit" means.
    let killed = w.state(vec![w.item_full(1, b"page", 20, b"", true, true, 0)]);
    let done = join(&sealed, &killed, &w.params);
    assert!(done.held[0].item.tombstone, "a sealed tombstone must win");
}

/// The two orderings of "cut" and "drop" that were tried and rejected.
///
/// Both are implemented here and both are shown to disagree with themselves on
/// some placement of the denial. Without them this file would assert only that
/// the shipped rule works, and a rule that did nothing would pass that.
mod dropping_controls {
    use super::*;
    use craftec_set_contract::merge::cut;

    fn slot_union(a: &SetState, b: &SetState) -> Vec<Held> {
        let mut slots: Vec<Held> = Vec::new();
        for h in a.held.iter().chain(b.held.iter()) {
            match slots.iter().position(|s| s.slot == h.slot) {
                None => slots.push(h.clone()),
                Some(i) => {
                    if h.item.decision().rank() > slots[i].item.decision().rank() {
                        slots[i] = h.clone();
                    }
                }
            }
        }
        slots
    }

    fn denies(deny: &[craftec_set_contract::wire::Deny], h: &Held) -> bool {
        deny.binary_search_by_key(h.item.signer.as_bytes(), |d| d.signer)
            .is_ok()
    }

    fn deny_union(a: &SetState, b: &SetState) -> Vec<craftec_set_contract::wire::Deny> {
        let mut d = a.deny.clone();
        d.extend(b.deny.iter().cloned());
        d.sort_by_key(|x| x.signer);
        d.dedup_by(|x, y| x.signer == y.signer);
        d
    }

    /// Rejected order 1: drop the denied, then cut to capacity.
    pub fn drop_then_cut(a: &SetState, b: &SetState, p: &Params) -> SetState {
        let deny = deny_union(a, b);
        let mut slots = slot_union(a, b);
        slots.retain(|h| !denies(&deny, h));
        let mut held = cut(slots, p);
        held.sort_by_key(|h| h.rank());
        SetState { deny, held }
    }

    /// Rejected order 2: cut to capacity, then drop the denied.
    pub fn cut_then_drop(a: &SetState, b: &SetState, p: &Params) -> SetState {
        let deny = deny_union(a, b);
        let mut held = cut(slot_union(a, b), p);
        held.retain(|h| !denies(&deny, h));
        held.sort_by_key(|h| h.rank());
        SetState { deny, held }
    }
}

/// A denial must give the same answer wherever it sits among the operands.
///
/// Both rejected orders are run over every placement first and each is shown to
/// disagree with itself on at least one of them — which is the whole finding:
/// the first version of this contract dropped denied slots and tested only the
/// placement where the denial came LAST, and that is the one placement where
/// cut-then-drop happens to be right.
#[test]
fn a_denial_gives_one_answer_wherever_it_sits_among_the_operands() {
    let w = world_with(7, 4, Admission::Cap, 1, 1, 0);
    let ph = w.ph();
    let a = w.item(1, b"x", 1, b"from the signer who gets denied");
    let b = w.item(2, b"y", 1, b"from an honest signer");
    let (ha, hb) = (
        Held::of(a.clone(), &w.params, &ph),
        Held::of(b.clone(), &w.params, &ph),
    );
    // The fixture bites only when the DENIED slot is the one the cut prefers.
    let (denied_who, x, y) = if ha.rank() < hb.rank() {
        (1, a, b)
    } else {
        (2, b, a)
    };
    let sx = w.state(vec![x]);
    let sy = w.state(vec![y]);
    let c = SetState {
        deny: vec![w.deny_of(denied_who)],
        held: Vec::new(),
    };

    // Every association of every ordering of the three operands.
    let placements = |j: &dyn Fn(&SetState, &SetState, &Params) -> SetState| {
        let mut out = Vec::new();
        for (p, q, r) in [
            (&sx, &sy, &c),
            (&sx, &c, &sy),
            (&sy, &sx, &c),
            (&sy, &c, &sx),
            (&c, &sx, &sy),
            (&c, &sy, &sx),
        ] {
            out.push(j(&j(p, q, &w.params), r, &w.params).decisions());
            out.push(j(p, &j(q, r, &w.params), &w.params).decisions());
        }
        out
    };

    for (what, control) in [
        (
            "drop then cut",
            &dropping_controls::drop_then_cut as &dyn Fn(&SetState, &SetState, &Params) -> SetState,
        ),
        ("cut then drop", &dropping_controls::cut_then_drop),
    ] {
        let got = placements(control);
        assert!(
            got.iter().any(|r| *r != got[0]),
            "{what} must disagree with itself somewhere, or this test proves nothing"
        );
    }

    // The rule in force agrees on all twelve.
    let got = placements(&|a, b, p| join(a, b, p));
    for (i, r) in got.iter().enumerate() {
        assert_eq!(*r, got[0], "placement {i} disagrees");
    }
    // And the denied slot is retained but invisible, wherever it landed.
    let merged = join(&join(&sx, &c, &w.params), &sy, &w.params);
    let denied_key = w.keys[denied_who].verifying_key().to_bytes();
    assert!(
        merged
            .held
            .iter()
            .any(|h| *h.item.signer.as_bytes() == denied_key),
        "the denied slot must be RETAINED, or the cut is not a function of the slots"
    );
    assert!(
        !merged
            .visible()
            .any(|h| *h.item.signer.as_bytes() == denied_key),
        "a denied signer's item was visible to a reader"
    );
}

/// `visible()` is the only reader-facing view, and it must hide a denied
/// signer's items whether they arrived before the denial or after it.
#[test]
fn a_denied_signers_items_are_retained_and_hidden_whenever_they_arrive() {
    let w = world();
    let before = w.state(vec![
        w.item(1, b"early", 1, b"v"),
        w.item(2, b"keep", 1, b"v"),
    ]);
    let denial = SetState {
        deny: vec![w.deny_of(1)],
        held: Vec::new(),
    };
    let after = join(
        &join(&before, &denial, &w.params),
        &w.state(vec![w.item(1, b"late", 9, b"written after the denial")]),
        &w.params,
    );

    assert_eq!(after.held.len(), 3, "every slot must be retained");
    let visible: Vec<&[u8]> = after
        .visible()
        .map(|h| h.item.item_key.as_slice())
        .collect();
    assert_eq!(
        visible,
        vec![b"keep".as_slice()],
        "only the undenied signer is visible"
    );
    // Both the early and the late item are there, and both are hidden.
    for key in [b"early".as_slice(), b"late".as_slice()] {
        assert!(after.held.iter().any(|h| h.item.item_key == key));
        assert!(!after.visible().any(|h| h.item.item_key == key));
    }
}

/// The denial itself is a grow-only union, and re-signing one changes nothing:
/// the identity of a denial is WHO is denied, so a second witness of it must
/// not make two replicas disagree.
#[test]
fn denials_union_and_survive_re_signing() {
    let w = world();
    let a = w.state_with(vec![w.item(0, b"k", 1, b"v")], vec![w.deny_of(1)]);
    let b = w.state_with(vec![], vec![w.deny_of(2)]);
    let both = join(&a, &b, &w.params);
    assert_eq!(both.deny.len(), 2, "denials must union");
    assert_eq!(
        join(&b, &a, &w.params).decisions(),
        both.decisions(),
        "and the union must not depend on the order"
    );
    let again = join(&both, &w.state_with(vec![], vec![w.deny_of(1)]), &w.params);
    assert_eq!(again.decisions(), both.decisions());
}

/// The laws over GENERATED states — because a hand-picked triple is how three
/// people in a row missed a case on this contract.
///
/// Every boundary below sits on OPPOSITE SIDES of a merge. One inside a single
/// state is settled by the cut before any join sees it, and the sweep then
/// passes with the rule it was meant to test removed.
///
/// The pool is drawn from the BOUNDARIES the parser enforces, not from
/// comfortable middles: a payload at the cap and an empty one, a live-empty
/// item beside a tombstone at the same `ts` (D2 lived exactly there), equal
/// timestamps competing on payload hash, a sealed item and a sealed tombstone,
/// an item key at its maximum length, and deny lists whose union overflows
/// `MAX_DENY` (D1 lived exactly there). Capacity is small enough that the cut
/// is live in nearly every merge.
///
/// Every result is also PARSED: a bound the parser enforces that the join does
/// not enforce on its output lets the contract manufacture a state it refuses,
/// and under F23 that is a pair of replicas which never converge.
#[test]
fn the_laws_hold_over_every_triple_of_the_generated_states() {
    let keys = MAX_DENY as usize + 20;
    // quota = 1 with M = 2, DELIBERATELY: at quota == M the tier cut reaches
    // every union the quota cut would have reached, so the quota check can be
    // deleted without the sweep noticing. The two bounds have to be able to
    // bite separately or only the tighter one is tested.
    let w = world_with(11, keys, Admission::Cap, 2, 1, 0);
    let cap = w.params.payload_cap as usize;
    let pool: Vec<Item> = vec![
        w.item(0, b"a", 3, b"a3"),
        w.item(0, b"a", 7, &vec![0xab; cap]), // payload exactly at the cap
        w.item(1, b"b", 2, b""),              // live, empty payload
        w.tombstone(1, b"b", 2),              // same ts, same empty payload
        w.tombstone(1, b"b", 5),
        w.sealed(1, b"c", 4, b"c4"),
        w.item(1, b"c", 900, b"late edit of a sealed slot"),
        w.item_full(1, b"c", 901, b"", true, true, 0), // sealed tombstone
        w.item(2, b"d", 6, b"d-one"),
        w.item(2, b"d", 6, b"d-two"), // equal ts, decided on hash
        w.item(
            2,
            &[b'e'; MAX_ITEM_KEY],
            1,
            b"longest key the format allows",
        ),
        w.item(3, b"f", 8, b"f8"),
    ];
    // Two big disjoint blocks of denials: any two of them overflow the cap.
    let block = |from: usize| -> Vec<_> {
        (from..from + MAX_DENY as usize / 2 + 5)
            .map(|i| w.deny_of(i))
            .collect()
    };
    // A windowed pool puts competing decisions in the SAME state, where the
    // cut settles them before any join is asked — so every pair that must
    // disagree is given a state each, explicitly. Without this the sweep
    // passes with `tombstone` removed from the decision order (D2), and the
    // same is true of every boundary below: a boundary inside ONE state is
    // settled before any join sees it.
    let mut states: Vec<SetState> = vec![
        SetState::default(),
        // D2: a live-empty item and a tombstone at one ts.
        w.state(vec![w.item(1, b"b", 2, b"")]),
        w.state(vec![w.tombstone(1, b"b", 2)]),
        // One signer's quota straddling a merge: `quota` slots each side, all
        // different, so the union is over quota while the TIER still has room
        // — which is the only shape in which the quota bound decides anything.
        w.state(vec![w.item(1, b"p", 1, b"v")]),
        w.state(vec![w.item(1, b"q", 1, b"v")]),
        // A FULL cap tier each side, of different slots: the union is 2M.
        w.state(vec![w.item(1, b"t", 1, b"v"), w.item(2, b"u", 1, b"v")]),
        w.state(vec![w.item(3, b"x", 1, b"v"), w.item(4, b"y", 1, b"v")]),
        // A newer decision for a slot that the OTHER side is about to evict:
        // a decision must never rescue a slot the cut drops, and the dropped
        // side's version must not leak into what is kept.
        w.state(vec![w.item(
            1,
            b"p",
            5_000,
            b"newest version of a doomed slot",
        )]),
        // Timestamp extremes on opposite sides, and unsealed-max against
        // sealed-zero, which is where "sealed leads" has to hold or not at all.
        w.state(vec![w.item(
            1,
            b"z",
            u64::MAX,
            b"unsealed, latest possible",
        )]),
        w.state(vec![w.sealed(1, b"z", 0, b"sealed, earliest possible")]),
        // Equal ts at the extreme, decided on payload hash alone.
        w.state(vec![w.item(2, b"w", u64::MAX, b"one")]),
        w.state(vec![w.item(2, b"w", u64::MAX, b"two")]),
    ];
    let hand_built = states.len();
    for i in 0..9 {
        let items: Vec<Item> = (0..3).map(|k| pool[(i + k) % pool.len()].clone()).collect();
        let deny = match i % 4 {
            1 => vec![w.deny_of(1)],
            2 => block(1),
            3 => block(MAX_DENY as usize / 2 + 6),
            _ => Vec::new(),
        };
        states.push(w.state_with(items, deny));
    }
    assert!(
        states.len() > hand_built,
        "the windowed states must be added too"
    );
    assert_ne!(
        states[1].decisions(),
        states[2].decisions(),
        "the live-empty and the tombstone must really be different states"
    );
    for s in &states {
        assert!(
            craftec_set_contract::read(&w.params_bytes, &s.encode()).is_some(),
            "every generated state must itself parse"
        );
    }

    let mut nontrivial = 0;
    let mut overflowed = 0;
    let mut straddled = 0;
    let mut tier_full = 0;
    for a in &states {
        assert_eq!(
            join(a, a, &w.params).decisions(),
            a.decisions(),
            "idempotence"
        );
        for b in &states {
            let ab = join(a, b, &w.params);
            assert_eq!(
                ab.decisions(),
                join(b, a, &w.params).decisions(),
                "commutativity"
            );
            // Closure: the join of two states that parse must parse.
            assert!(
                craftec_set_contract::read(&w.params_bytes, &ab.encode()).is_some(),
                "the join produced a state the contract refuses"
            );
            if a.deny.len() + b.deny.len() > MAX_DENY as usize {
                overflowed += 1;
            }
            let per_signer = |s: &SetState, k: &[u8; 32]| {
                s.held
                    .iter()
                    .filter(|h| h.item.signer.as_bytes() == k)
                    .count()
            };
            for h in a.held.iter() {
                let k = h.item.signer.as_bytes();
                if per_signer(a, k) + per_signer(b, k) > w.params.quota as usize {
                    straddled += 1;
                    break;
                }
            }
            let tier = |s: &SetState| s.held.iter().filter(|h| h.tier == Tier::CapHolder).count();
            if tier(a) + tier(b) > w.params.m as usize {
                tier_full += 1;
            }
            for c in &states {
                let l = join(&join(a, b, &w.params), c, &w.params);
                let r = join(a, &join(b, c, &w.params), &w.params);
                assert_eq!(l.decisions(), r.decisions(), "associativity");
                if l.decisions() != a.decisions() && l.decisions() != c.decisions() {
                    nontrivial += 1;
                }
            }
        }
    }
    assert!(
        nontrivial > 1000,
        "only {nontrivial} of 1728 triples actually merged anything"
    );
    assert!(
        overflowed > 0,
        "no pair in the sweep overflowed the deny cap: D1's boundary is untested"
    );
    // The boundaries are only tested if the merges that straddle them are
    // actually decided by the cut, so that is asserted rather than assumed.
    assert!(
        straddled > 0,
        "no pair's union exceeded a signer's quota: the straddle is untested"
    );
    assert!(
        tier_full > 0,
        "no pair's union filled a tier twice over: the straddle is untested"
    );
}

/// Every bound `parse` enforces, `join` must enforce on its OUTPUT — or the
/// contract can manufacture a state it then refuses.
///
/// D1 (architect): `parse` refuses more than `MAX_DENY` denials and the join
/// unioned the deny lists without a cut, so two states that each parse could
/// merge into one that does not. Under F23 the host validates its own merge
/// result, refuses it, and the two replicas never converge — reachable by one
/// honest owner denying from two devices that were apart.
#[test]
fn the_join_of_any_two_states_that_parse_parses() {
    let n = MAX_DENY as usize + 40;
    let w = world_with(13, n, Admission::Cap, 4, 2, 0);
    let parses = |s: &SetState| craftec_set_contract::read(&w.params_bytes, &s.encode()).is_some();
    // Two honest halves, disjoint, each within the cap.
    let half = MAX_DENY as usize / 2 + 5;
    let a = w.state_with(
        vec![w.item(0, b"a", 1, b"v")],
        (1..=half).map(|i| w.deny_of(i)).collect(),
    );
    let b = w.state_with(
        vec![w.item(0, b"b", 1, b"v")],
        (half + 1..=2 * half).map(|i| w.deny_of(i)).collect(),
    );
    assert!(
        parses(&a) && parses(&b),
        "both halves must parse on their own"
    );
    assert!(
        a.deny.len() + b.deny.len() > MAX_DENY as usize,
        "the fixture must actually overflow the cap"
    );
    let merged = join(&a, &b, &w.params);
    assert!(
        merged.deny.len() <= MAX_DENY as usize,
        "the join produced {} denials, over the cap of {MAX_DENY}",
        merged.deny.len()
    );
    assert!(parses(&merged), "the join produced a state it would refuse");
    // And the cut is a join in its own right: same answer either way round.
    assert_eq!(join(&b, &a, &w.params).decisions(), merged.decisions());
}

/// D2 (architect): the decision order must be TOTAL on decisions, or the join
/// is not commutative on the projection the laws are stated over.
///
/// A tombstone carries an empty payload and a live item may carry one too, so
/// before `tombstone` entered the order the two had equal rank at one `ts` —
/// different decisions, equal rank, incumbent wins, and two replicas disagree
/// for ever about whether the slot is deleted while their summaries differ, so
/// they re-send to each other on every exchange without either changing.
#[test]
fn equal_rank_means_equal_decision() {
    let w = world();
    let live_empty = w.item(1, b"k", 5, b"");
    let dead = w.tombstone(1, b"k", 5);
    assert_ne!(
        live_empty.decision(),
        dead.decision(),
        "the fixture must be two different decisions"
    );
    assert_ne!(
        live_empty.decision().rank(),
        dead.decision().rank(),
        "equal rank for two different decisions: the order is not total"
    );

    // The join therefore agrees on the projection, both ways round.
    let (a, b) = (w.state(vec![live_empty]), w.state(vec![dead]));
    assert_eq!(
        join(&a, &b, &w.params).decisions(),
        join(&b, &a, &w.params).decisions(),
        "not commutative on decisions"
    );
    // A delete beats a live item at the same ts: a slot deleted stays deleted.
    assert!(join(&a, &b, &w.params).held[0].item.tombstone);

    // The property, over every decision the format allows at one ts.
    let all = [
        w.item(1, b"k", 5, b""),
        w.item(1, b"k", 5, b"x"),
        w.tombstone(1, b"k", 5),
        w.sealed(1, b"k", 5, b""),
        w.sealed(1, b"k", 5, b"x"),
        w.item_full(1, b"k", 5, b"", true, true, 0),
    ];
    for x in &all {
        for y in &all {
            assert_eq!(
                x.decision().rank() == y.decision().rank(),
                x.decision() == y.decision(),
                "rank and decision disagree about equality"
            );
        }
    }
}

/// The owner cannot deny itself.
///
/// The owner signs denials, so it can always produce a valid one naming its own
/// key — nothing else in the format would stop it, and the result is a second
/// way to empty a Set: hide the owner's whole tier. Refused at parse, where a
/// fetched state is the only thing a host checks, and dropped by the join so
/// the join cannot manufacture a state the parser refuses.
#[test]
fn a_denial_of_the_owners_own_key_is_refused() {
    let w = world();
    let good = SetState {
        deny: vec![w.deny_of(1)],
        held: Vec::new(),
    };
    assert!(
        craftec_set_contract::read(&w.params_bytes, &good.encode()).is_some(),
        "the control: denying someone else is fine"
    );

    let self_denial = SetState {
        deny: vec![w.deny_of(0)],
        held: Vec::new(),
    };
    assert!(
        craftec_set_contract::read(&w.params_bytes, &self_denial.encode()).is_none(),
        "a denial of the owner's own key must be refused at parse"
    );

    // And the join cannot produce one, even from a candidate that never parsed
    // as a whole state — the same closure rule as the deny cap.
    let held = w.state(vec![w.item(0, b"k", 1, b"owner's item")]);
    let merged = join(&held, &self_denial, &w.params);
    assert!(
        merged.deny.is_empty(),
        "the join kept a denial of the owner's own key"
    );
    assert!(
        craftec_set_contract::read(&w.params_bytes, &merged.encode()).is_some(),
        "the join produced a state the contract refuses"
    );
    assert_eq!(
        merged.visible().count(),
        1,
        "the owner's item is still visible"
    );
}

/// The BYTE bound is closed under join too.
///
/// `MAX_STATE` is derived from the format's own maxima, so "the join cannot
/// exceed it" is an argument — and an argument about a bound is exactly what
/// was wrong about the deny cap. Asserted instead, on the largest pair the
/// format allows: both tiers full on both sides with different slots, every
/// item at its maximum encoded size, and a full deny list each side.
#[test]
fn the_join_of_two_maximal_states_stays_within_max_state() {
    let keys = MAX_DENY as usize * 2 + 8;
    let m = 4;
    let w = world_with(21, keys, Admission::Cap, m, m, 0);
    let cap = w.params.payload_cap as usize;
    let big = |who: usize, tag: u8, n: u8| {
        let mut key = vec![tag; MAX_ITEM_KEY];
        key[0] = n;
        w.item(who, &key, u64::MAX, &vec![0xcd; cap])
    };
    // Each side: a full owner tier and a full cap-holder tier, all distinct.
    let side = |tag: u8, who_base: usize| {
        let mut items: Vec<Item> = (0..m as u8).map(|n| big(0, tag, n)).collect();
        items.extend((0..m as u8).map(|n| big(who_base + n as usize, tag, n)));
        items
    };
    let a = w.state_with(
        side(b'a', 1),
        (1..=MAX_DENY as usize).map(|i| w.deny_of(i)).collect(),
    );
    let b = w.state_with(
        side(b'b', 1),
        (MAX_DENY as usize + 1..=2 * MAX_DENY as usize)
            .map(|i| w.deny_of(i))
            .collect(),
    );
    for s in [&a, &b] {
        assert_eq!(
            s.held.len(),
            2 * m as usize,
            "each side must be full in both tiers"
        );
        assert!(
            craftec_set_contract::read(&w.params_bytes, &s.encode()).is_some(),
            "each side must parse on its own"
        );
    }
    let j = join(&a, &b, &w.params);
    assert!(
        j.encode().len() <= MAX_STATE,
        "the join encodes to {} B, over MAX_STATE of {MAX_STATE}",
        j.encode().len()
    );
    assert!(
        craftec_set_contract::read(&w.params_bytes, &j.encode()).is_some(),
        "the join produced a state the contract refuses"
    );
}

/// The empty state is the identity, byte for byte — the WITNESS included.
///
/// Stated on bytes rather than on decisions because this is the one law where
/// "the same facts" is not enough: merging with nothing must not swap a
/// signature, a stamp nonce or a grant for an equivalent one, or every host
/// rewrites its state and wakes every subscriber the first time it merges with
/// a peer that has nothing.
#[test]
fn the_empty_state_is_the_identity_byte_for_byte() {
    let w = world();
    let empty = SetState::default();
    for s in [
        w.state(vec![w.item(0, b"a", 1, b"v")]),
        w.state(vec![w.item(1, b"b", 2, b"v"), w.tombstone(2, b"c", 3)]),
        w.state_with(vec![w.item(1, b"d", 4, b"v")], vec![w.deny_of(2)]),
        empty.clone(),
    ] {
        assert_eq!(join(&s, &empty, &w.params).encode(), s.encode());
        assert_eq!(join(&empty, &s, &w.params).encode(), s.encode());
    }
}
