//! What a host decides on its own.
//!
//! A node storing a Set fetched from a peer runs `validate_state` and nothing
//! else (F23), so every rule this contract has must be decidable there. Each
//! refusal below is paired with the control that shows the unmodified state IS
//! accepted, so no refusal can come from the fixture being broken.
//!
//! The cost of refusing is asserted separately from the verdict. A verifier
//! that correctly rejects a hostile input after 128 signature checks is a
//! denial of service on the host that ran them, and no assertion about the
//! answer can see it.

use craftec_set_contract::merge::{delta, deny_hash, summarize, summary_entries, Summary};
use craftec_set_contract::testing::{elsewhere, world, world_with};
use craftec_set_contract::wire::{
    verifications, Admission, Held, Item, Params, SetState, HASH_LEN, MAX_M, TRUNC,
};
use craftec_set_contract::{read, read_unverified, MAX_STATE};

fn valid(p: &[u8], s: &[u8]) -> bool {
    read(p, s).is_some()
}

#[test]
fn a_well_formed_set_is_accepted_and_the_empty_one_too() {
    let w = world();
    let s = w.encode(&w.state(vec![
        w.item(0, b"a", 1, b"owner writes"),
        w.item(1, b"b", 2, b"cap holder writes"),
    ]));
    assert!(valid(&w.params_bytes, &s));
    assert!(valid(&w.params_bytes, &w.encode(&SetState::default())));
}

#[test]
fn an_item_is_refused_unless_its_signature_holds() {
    let w = world();
    let other = elsewhere();
    let good = w.item(1, b"key", 5, b"value");
    assert!(valid(
        &w.params_bytes,
        &w.encode(&w.state(vec![good.clone()]))
    ));

    let mut unsigned = good.clone();
    unsigned.sig = [0u8; 64];

    // A real signature by the right key over ANOTHER set's params.
    let mut foreign = good.clone();
    foreign.sig = other.item(1, b"key", 5, b"value").sig;

    // Someone else's signature on this item.
    let mut wrong_key = good.clone();
    wrong_key.sig = w.item(2, b"key", 5, b"value").sig;

    // The payload changed after signing: the signature covers the decision,
    // which covers the payload HASH.
    let mut tampered = good.clone();
    tampered.payload = b"other".to_vec();

    // The ts changed after signing.
    let mut retimed = good.clone();
    retimed.ts = 9_999;

    for (what, it) in [
        ("unsigned", unsigned),
        ("signed for another set", foreign),
        ("signed by another key", wrong_key),
        ("payload changed after signing", tampered),
        ("ts changed after signing", retimed),
    ] {
        let s = raw_state(&w, vec![it]);
        assert!(!valid(&w.params_bytes, &s), "{what} must be refused");
    }
    assert!(valid(&w.params_bytes, &w.encode(&w.state(vec![good]))));
}

/// The fixture's `state` runs items through the join, which would drop a
/// malformed one before it ever reached the wire. These refusals need the item
/// written out as it stands.
fn raw_state(w: &craftec_set_contract::testing::World, items: Vec<Item>) -> Vec<u8> {
    let ph = w.ph();
    let mut held: Vec<Held> = items
        .into_iter()
        .map(|i| Held::of(i, &w.params, &ph))
        .collect();
    held.sort_by_key(|h| h.rank());
    SetState {
        deny: Vec::new(),
        held,
    }
    .encode()
}

#[test]
fn a_capability_is_bound_to_the_params_without_the_bucket() {
    let w = world();
    let good = w.item(1, b"key", 1, b"v");
    assert!(valid(
        &w.params_bytes,
        &w.encode(&w.state(vec![good.clone()]))
    ));

    // Out of range: the cap names buckets 0..=3 and this set is bucket 7.
    let mut narrow = good.clone();
    narrow.cap = Some(w.cap_for(1, 0, 3));
    w.resign(&mut narrow, 1);
    assert!(
        !valid(&w.params_bytes, &raw_state(&w, vec![narrow])),
        "a bucket outside the cap's range must be refused"
    );

    // A cap from a set with the same label and owner but different LIMITS.
    // Binding to params-sans-bucket is what stops it carrying over.
    let tighter = world_with(1, 4, Admission::Cap, 4, 2, 0);
    assert_ne!(
        tighter.params.m, w.params.m,
        "the fixture must really differ"
    );
    assert_eq!(
        tighter.params.owner, w.params.owner,
        "same owner, so only the params binding can refuse it"
    );
    let mut cross = good.clone();
    cross.cap = Some(tighter.cap_for(1, 0, u32::MAX));
    w.resign(&mut cross, 1);
    assert!(
        !valid(&w.params_bytes, &raw_state(&w, vec![cross])),
        "a cap for a differently-limited set must be refused"
    );

    // A cap signed by someone who does not own this set.
    let mut forged = good.clone();
    forged.cap = Some(elsewhere().cap_for(1, 0, u32::MAX));
    w.resign(&mut forged, 1);
    assert!(!valid(&w.params_bytes, &raw_state(&w, vec![forged])));

    // And under owner-only admission a valid cap admits nobody.
    let closed = world_with(1, 4, Admission::OwnerOnly, 8, 4, 0);
    assert!(!valid(
        &closed.params_bytes,
        &raw_state(&closed, vec![closed.item(1, b"key", 1, b"v")])
    ));
    assert!(
        valid(
            &closed.params_bytes,
            &raw_state(&closed, vec![closed.item(0, b"key", 1, b"v")])
        ),
        "the owner still writes"
    );
}

#[test]
fn the_owner_carrying_a_capability_is_a_second_encoding_and_is_refused() {
    let w = world();
    let mut it = w.item(0, b"key", 1, b"v");
    it.cap = Some(w.cap_for(0, 0, u32::MAX));
    w.resign(&mut it, 0);
    assert!(!valid(&w.params_bytes, &raw_state(&w, vec![it])));
}

#[test]
fn an_item_without_the_required_stamp_is_refused() {
    // Twelve bits of work per DECISION: the price of an update, paid again for
    // every version, so churning one slot is not free.
    let w = world_with(2, 4, Admission::Cap, 8, 4, 12);
    let good = w.item(1, b"key", 1, b"v");
    assert!(valid(&w.params_bytes, &raw_state(&w, vec![good.clone()])));
    assert!(good.stamp_work(&w.ph()) >= 12);

    let mut unstamped = good.clone();
    unstamped.stamp_nonce = [0u8; 8];
    w.resign(&mut unstamped, 1);
    assert!(
        unstamped.stamp_work(&w.ph()) < 12,
        "the fixture must really be under-worked"
    );
    assert!(!valid(&w.params_bytes, &raw_state(&w, vec![unstamped])));

    // The stamp is bound to the DECISION, so a new version cannot reuse the
    // one already paid for. Sixty-four successive versions, all reusing the
    // accepted nonce, and none of them meets the bar.
    let reused = (2..66u64)
        .map(|ts| {
            let mut v = w.item(1, b"key", ts, b"v");
            v.stamp_nonce = good.stamp_nonce;
            v.stamp_work(&w.ph())
        })
        .filter(|work| *work >= 12)
        .count();
    assert_eq!(reused, 0, "a stamp was reusable across decisions");
}

#[test]
fn the_limits_are_part_of_validity() {
    let w = world_with(3, 4, Admission::Cap, 2, 1, 0);
    // Two cap-holders, one slot each: exactly at both limits.
    let ok = raw_state(&w, vec![w.item(1, b"a", 1, b"v"), w.item(2, b"b", 1, b"v")]);
    assert!(valid(&w.params_bytes, &ok));

    // One signer over its quota of 1.
    let over_quota = raw_state(&w, vec![w.item(1, b"a", 1, b"v"), w.item(1, b"b", 1, b"v")]);
    assert!(!valid(&w.params_bytes, &over_quota), "quota exceeded");

    // Three cap-holders in a tier of 2.
    let over_tier = raw_state(
        &w,
        vec![
            w.item(1, b"a", 1, b"v"),
            w.item(2, b"b", 1, b"v"),
            w.item(3, b"c", 1, b"v"),
        ],
    );
    assert!(
        !valid(&w.params_bytes, &over_tier),
        "tier capacity exceeded"
    );

    // A payload one byte over the cap, and the control at exactly the cap.
    let at = w.item(1, b"a", 1, &vec![7u8; w.params.payload_cap as usize]);
    assert!(valid(&w.params_bytes, &raw_state(&w, vec![at])));
    let over = w.item(1, b"a", 1, &vec![7u8; w.params.payload_cap as usize + 1]);
    assert!(!valid(&w.params_bytes, &raw_state(&w, vec![over])));
}

#[test]
fn a_state_is_refused_unless_its_encoding_is_canonical() {
    let w = world();
    let s = w.encode(&w.state(vec![w.item(0, b"a", 1, b"v"), w.item(1, b"b", 2, b"w")]));
    assert!(valid(&w.params_bytes, &s));

    let mut swapped = w.state(vec![w.item(0, b"a", 1, b"v"), w.item(1, b"b", 2, b"w")]);
    swapped.held.swap(0, 1);

    let mut doubled = w.state(vec![w.item(0, b"a", 1, b"v")]);
    doubled.held.push(doubled.held[0].clone());

    for (what, bad) in [
        ("no magic", b"ZZ01\x00\x00\x00\x00".to_vec()),
        ("items out of rank order", swapped.encode()),
        ("one slot twice", doubled.encode()),
        ("trailing byte", {
            let mut b = s.clone();
            b.push(0);
            b
        }),
        ("truncated", s[..s.len() - 1].to_vec()),
        ("a tombstone carrying a payload", {
            let mut t = w.tombstone(1, b"k", 3);
            t.payload = b"not empty".to_vec();
            w.resign(&mut t, 1);
            raw_state(&w, vec![t])
        }),
        ("an undefined flag bit", {
            let mut b = raw_state(&w, vec![w.item(0, b"a", 1, b"v")]);
            // flags sit just after signer(32) + klen(1) + key(1) + ts(8).
            let at = 6 + 32 + 1 + 1 + 8;
            b[at] |= 0b1000;
            b
        }),
        ("an empty item key", {
            let mut it = w.item(0, b"", 1, b"v");
            w.resign(&mut it, 0);
            raw_state(&w, vec![it])
        }),
    ] {
        assert!(!valid(&w.params_bytes, &bad), "{what} must be refused");
    }
    assert!(valid(&w.params_bytes, &s), "the control is still accepted");
}

#[test]
fn params_are_refused_unless_canonical() {
    let w = world();
    let good = w.params_bytes.clone();
    assert!(Params::parse(&good).is_some());
    let with = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut b = good.clone();
        f(&mut b);
        b
    };
    let at = 5 + 32;
    for (what, b) in [
        ("no magic", with(&|b| b[0] = b'X')),
        // The reserved mode byte: a Set written for a mode this build does not
        // implement must not be read as one it does.
        ("an unimplemented mode", with(&|b| b[4] = 1)),
        ("another unimplemented mode", with(&|b| b[4] = 255)),
        ("unknown admission", with(&|b| b[at] = 9)),
        (
            "m = 0",
            with(&|b| b[at + 1..at + 3].copy_from_slice(&0u16.to_le_bytes())),
        ),
        (
            "m over the ceiling",
            with(&|b| b[at + 1..at + 3].copy_from_slice(&(MAX_M + 1).to_le_bytes())),
        ),
        (
            "quota = 0",
            with(&|b| b[at + 3..at + 5].copy_from_slice(&0u16.to_le_bytes())),
        ),
        (
            "quota over m",
            with(&|b| b[at + 3..at + 5].copy_from_slice(&999u16.to_le_bytes())),
        ),
        (
            "payload cap = 0",
            with(&|b| b[at + 6..at + 8].copy_from_slice(&0u16.to_le_bytes())),
        ),
        ("stamp bits past a hash", with(&|b| b[at + 5] = 200)),
        (
            "label too long",
            with(&|b| b.extend_from_slice(&[b'x'; 70])),
        ),
        ("truncated", good[..10].to_vec()),
    ] {
        assert!(Params::parse(&b).is_none(), "{what} must be refused");
        assert!(!valid(&b, &[]), "{what}: and nothing is valid under it");
    }
}

#[test]
fn a_denied_signers_item_cannot_be_in_a_valid_state() {
    let w = world();
    let it = w.item(1, b"k", 1, b"v");
    // Control: without the denial the state is fine.
    assert!(valid(
        &w.params_bytes,
        &w.encode(&w.state(vec![it.clone()]))
    ));

    let mut s = w.state(vec![it]);
    s.deny = vec![w.deny_of(1)];
    assert!(
        !valid(&w.params_bytes, &s.encode()),
        "a state holding a denied signer's item must be refused"
    );

    // A denial has to be the owner's, and it has to be for THIS set.
    let forged = SetState {
        deny: vec![elsewhere().deny_of(1)],
        held: Vec::new(),
    };
    assert!(!valid(&w.params_bytes, &forged.encode()));
    // Denials must be sorted and unique: one denial, one encoding.
    let twice = SetState {
        deny: vec![w.deny_of(1), w.deny_of(1)],
        held: Vec::new(),
    };
    assert!(!valid(&w.params_bytes, &twice.encode()));
}

/// Slot names, stamps and signatures bind `BLAKE3(params)` and nothing else. A
/// contract's key moves when its code is upgraded (#8), and every item must
/// stay valid and re-publishable across that — so validity has to be a function
/// of the params and the state alone.
#[test]
fn validity_does_not_depend_on_the_code_hosting_the_set() {
    let w = world();
    let s = w.encode(&w.state(vec![w.item(1, b"k", 1, b"v")]));
    assert!(valid(&w.params_bytes, &s));

    // Re-derive everything a host needs from the PARAMS BYTES alone — which is
    // all a differently-keyed build of this contract would have. If any of it
    // ever took the code's identity as an input, this could not be written.
    let reparsed = Params::parse(&w.params_bytes).expect("params round-trip");
    assert_eq!(reparsed.hash(), w.ph());
    let (_, parsed) = read(&w.params_bytes, &s).expect("still valid");
    for h in &parsed.held {
        assert_eq!(
            h.slot,
            h.item.slot_hash(&reparsed.hash()),
            "a slot name moved with something outside the params"
        );
        assert!(h.item.verify(&reparsed, &reparsed.hash()));
    }
}

#[test]
fn a_summary_of_one_state_is_a_function_of_its_decisions_not_its_witnesses() {
    let w = world();
    let a = w.state(vec![w.item_full(1, b"k", 4, b"v", false, false, 0)]);
    let b = w.state(vec![w.item_full(1, b"k", 4, b"v", false, false, 91)]);
    assert_ne!(
        a.encode(),
        b.encode(),
        "two real witnesses, different bytes"
    );
    assert!(valid(&w.params_bytes, &a.encode()) && valid(&w.params_bytes, &b.encode()));
    assert_eq!(
        summarize(&a, &w.params),
        summarize(&b, &w.params),
        "two witnesses of one decision must summarise the same"
    );
    // So neither asks the other for anything.
    assert!(delta(&a, &summarize(&b, &w.params), &w.params)
        .unwrap()
        .held
        .is_empty());
    assert!(delta(&b, &summarize(&a, &w.params), &w.params)
        .unwrap()
        .held
        .is_empty());
}

#[test]
fn a_delta_carries_exactly_what_the_peer_lacks_in_both_directions() {
    let w = world();
    let shared = w.item(0, b"shared", 1, b"s");
    let mine = w.item(1, b"mine", 2, b"m");
    let theirs = w.item(2, b"theirs", 3, b"t");
    let a = w.state(vec![shared.clone(), mine.clone()]);
    let b = w.state(vec![shared.clone(), theirs.clone()]);

    let for_b = delta(&a, &summarize(&b, &w.params), &w.params).unwrap();
    assert_eq!(for_b.held.len(), 1);
    assert_eq!(for_b.held[0].item.item_key, b"mine");

    let for_a = delta(&b, &summarize(&a, &w.params), &w.params).unwrap();
    assert_eq!(for_a.held.len(), 1);
    assert_eq!(for_a.held[0].item.item_key, b"theirs");

    // A peer with nothing gets everything; a peer that is level gets nothing.
    let empty = summarize(&SetState::default(), &w.params);
    assert_eq!(
        delta(&a, &empty, &w.params).unwrap().held.len(),
        a.held.len()
    );
    assert!(delta(&a, &summarize(&a, &w.params), &w.params)
        .unwrap()
        .held
        .is_empty());
}

/// Sixteen bytes, not eight. "You already have it" is an assertion a stranger
/// can aim at, and suppressing an item it does not want a peer to see is the
/// whole prize. A pair that agrees on eight bytes must still sync.
#[test]
fn eight_bytes_of_agreement_do_not_suppress_an_item() {
    let w = world();
    let s = w.state(vec![w.item(1, b"k", 1, b"secret")]);
    let ph = w.ph();
    let real: [u8; TRUNC] = s.held[0].item.decision().hash(&ph)[..TRUNC]
        .try_into()
        .unwrap();

    // The best an attacker with 2^32 work can do: the first eight bytes.
    let mut near = real;
    near[8] ^= 0xff;
    assert_eq!(near[..8], real[..8], "the fixture must collide on 8 bytes");
    assert_ne!(near, real, "and differ on 16");

    let summary_of = |t: [u8; TRUNC]| {
        let mut out = Vec::new();
        out.extend_from_slice(&deny_hash(&[]));
        out.extend_from_slice(&0u16.to_le_bytes()); // owner tier
        out.extend_from_slice(&1u16.to_le_bytes()); // cap tier
        out.extend_from_slice(&t);
        out
    };
    assert_eq!(
        delta(&s, &summary_of(near), &w.params).unwrap().held.len(),
        1,
        "an 8-byte match suppressed an item"
    );
    // Control: the true 16 bytes DO suppress it, so the test is about the
    // width and not about the lookup being broken.
    assert!(delta(&s, &summary_of(real), &w.params)
        .unwrap()
        .held
        .is_empty());
}

#[test]
fn an_oversized_state_is_refused_before_a_single_signature_is_checked() {
    let w = world();
    let huge = vec![0u8; MAX_STATE + 1];
    verifications::reset();
    assert!(!valid(&w.params_bytes, &huge));
    assert_eq!(
        verifications::count(),
        0,
        "an oversized state bought signature checks"
    );
    // Control: a state at a legitimate size still costs, so the zero above is
    // the length gate and not verification being switched off.
    let s = w.encode(&w.state(vec![w.item(0, b"a", 1, b"v"), w.item(1, b"b", 1, b"v")]));
    verifications::reset();
    assert!(valid(&w.params_bytes, &s));
    assert!(
        verifications::count() >= 3,
        "two items and a capability must cost at least three checks"
    );
}

#[test]
fn an_oversized_summary_is_refused_before_it_is_copied_or_sorted() {
    let w = world();
    let mut hostile = Vec::new();
    hostile.extend_from_slice(&deny_hash(&[]));
    // A count that AGREES with the body, so the cheap cross-check cannot be
    // what refuses it: the length bound has to.
    let n = 40_000u16;
    hostile.extend_from_slice(&n.to_le_bytes());
    hostile.extend_from_slice(&0u16.to_le_bytes());
    hostile.extend_from_slice(&vec![0xab; n as usize * TRUNC]);
    assert!(hostile.len() > 600_000, "the fixture must really be large");

    summary_entries::reset();
    assert!(Summary::parse(&hostile, &w.params).is_none());
    assert_eq!(
        summary_entries::count(),
        0,
        "a hostile summary was copied before it was refused"
    );

    // Control: an honest summary IS copied, so the zero above is the bound and
    // not the counter being dead.
    let s = w.state(vec![w.item(0, b"a", 1, b"v"), w.item(1, b"b", 1, b"v")]);
    summary_entries::reset();
    assert!(Summary::parse(&summarize(&s, &w.params), &w.params).is_some());
    assert_eq!(summary_entries::count(), 2);
}

#[test]
fn a_summarys_counts_must_agree_with_what_follows_them() {
    let w = world();
    let s = w.state(vec![w.item(0, b"a", 1, b"v"), w.item(1, b"b", 1, b"v")]);
    let good = summarize(&s, &w.params);
    assert!(Summary::parse(&good, &w.params).is_some());
    for (what, bad) in [
        ("count too high", {
            let mut b = good.clone();
            b[HASH_LEN] = 9;
            b
        }),
        ("count too low", {
            let mut b = good.clone();
            b[HASH_LEN + 2] = 0;
            b
        }),
        ("a partial truncation", {
            let mut b = good.clone();
            b.pop();
            b
        }),
        ("a tier over M", {
            let mut b = good.clone();
            b[HASH_LEN..HASH_LEN + 2].copy_from_slice(&(MAX_M + 1).to_le_bytes());
            b
        }),
        ("truncated head", good[..8].to_vec()),
    ] {
        assert!(
            Summary::parse(&bad, &w.params).is_none(),
            "{what} must be refused"
        );
    }
}

#[test]
fn the_state_a_host_already_holds_is_read_without_checking_it_again() {
    let w = world();
    let s = w.encode(&w.state(vec![w.item(0, b"a", 1, b"v"), w.item(1, b"b", 1, b"v")]));
    verifications::reset();
    assert!(read_unverified(&w.params_bytes, &s).is_some());
    assert_eq!(
        verifications::count(),
        0,
        "reading the held state re-verified it"
    );
}
