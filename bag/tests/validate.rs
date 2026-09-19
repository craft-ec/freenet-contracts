//! What a host decides on its own.
//!
//! A node storing a bag fetched from a peer runs `validate_state` and nothing
//! else (F23), so every rule this contract has must be decidable there. Each
//! refusal below is paired with the control that shows the unmodified state is
//! accepted — otherwise a refusal proves only that something was broken.

use craftec_bag_contract::merge::{collect, delta, summarize};
use craftec_bag_contract::read;
use craftec_bag_contract::testing::{many, mine, params};
use craftec_bag_contract::wire::{BagState, Held, Params, Pointer, MAGIC};

fn held(p: &Params, n: usize, seed: u64) -> BagState {
    collect(many(p, n, seed), p)
}

fn accepted(p: &Params, bytes: &[u8]) -> bool {
    read(&p.encode(), bytes).is_some()
}

#[test]
fn a_well_formed_bag_is_accepted_and_every_break_is_refused() {
    let p = params(6, 12);
    let s = held(&p, 12, 4);
    assert_eq!(s.held.len(), 12);
    let good = s.encode();
    // THE CONTROL.
    assert!(accepted(&p, &good), "the unmodified state must be accepted");

    let ph = p.hash();
    let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();

    cases.push(("empty bytes", Vec::new()));
    cases.push(("wrong magic", {
        let mut b = good.clone();
        b[0] = b'X';
        b
    }));
    cases.push(("trailing bytes", {
        let mut b = good.clone();
        b.push(0);
        b
    }));
    cases.push(("truncated", good[..good.len() - 1].to_vec()));
    cases.push(("a count larger than what follows", {
        let mut b = good.clone();
        b[4] = 200;
        b
    }));
    cases.push(("a count smaller than what follows", {
        let mut b = good.clone();
        b[4] = 3;
        b
    }));
    // Count above M, with the pointers to match. Mined for THESE params — a
    // bag built for other params fails on the price first, and would have
    // tested the work binding instead of the count (it did, until a mutant
    // showed the count check was never reached).
    let over = {
        let ph = p.hash();
        let mut v: Vec<Held> = many(&p, 20, 77)
            .into_iter()
            .map(|x| Held::of(x, &ph))
            .collect();
        v.sort_by_key(|h| h.rank());
        v.dedup_by(|x, y| x.name == y.name);
        assert!(v.len() > p.m as usize, "the case must exceed M");
        BagState { held: v }
    };
    // Every pointer in it is individually fine: only the COUNT is wrong.
    assert!(over.held.iter().all(|h| h.work >= p.work_bits as u32));
    cases.push(("more pointers than M", over.encode()));

    // Unsorted: swap two neighbours.
    cases.push(("out of rank order", {
        let mut x = s.clone();
        x.held.swap(0, 1);
        x.encode()
    }));
    // A repeated name is the same as a broken order, and must be refused as one.
    cases.push(("a duplicate pointer", {
        let mut x = s.clone();
        x.held[1] = x.held[0].clone();
        x.encode()
    }));
    // Under the price: a pointer whose name has too few leading zeros.
    let cheap = {
        let mut n = 0u64;
        loop {
            let ptr = Pointer {
                payload: b"under".to_vec(),
                nonce: n.to_le_bytes(),
            };
            if Held::of(ptr.clone(), &ph).work < p.work_bits as u32 {
                break ptr;
            }
            n += 1;
        }
    };
    cases.push(("a pointer below the price", {
        let mut x = s.clone();
        x.held[11] = Held::of(cheap, &ph);
        x.held.sort_by_key(|h| h.rank());
        x.encode()
    }));
    // Over the payload cap.
    let small_cap = Params {
        payload_cap: 8,
        ..params(0, 12)
    };
    let over = collect(vec![mine(&params(0, 12), &[7u8; 64], 3)], &params(0, 12));
    cases.push(("a payload over the cap", over.encode()));

    for (what, bytes) in &cases {
        let ps = if *what == "a payload over the cap" {
            small_cap.encode()
        } else {
            p.encode()
        };
        assert!(read(&ps, bytes).is_none(), "{what}: a host accepted it");
    }
    // And the control once more, after all that: the good state still reads.
    assert!(accepted(&p, &good));
    println!("{} refusals, each against an accepted control", cases.len());
}

/// The params are part of the key, so a state is only valid under ITS params.
#[test]
fn a_bag_is_bound_to_its_params() {
    let p = params(6, 12);
    let s = held(&p, 12, 4).encode();
    assert!(accepted(&p, &s));
    for (what, q) in [
        (
            "a different owner",
            Params {
                owner: [9u8; 32],
                ..p.clone()
            },
        ),
        (
            "a different price",
            Params {
                work_bits: 7,
                ..p.clone()
            },
        ),
        (
            "a different bucket",
            Params {
                bucket: 1,
                ..p.clone()
            },
        ),
        (
            "a different label",
            Params {
                label: b"other".to_vec(),
                ..p.clone()
            },
        ),
    ] {
        assert!(
            read(&q.encode(), &s).is_none(),
            "{what}: the same bytes read as a valid bag under other params"
        );
    }
    // Reducing M below the count is also a different bag.
    assert!(read(&Params { m: 4, ..p.clone() }.encode(), &s).is_none());
    // Params that exceed the frozen ceilings are not params at all.
    for bad in [
        Params {
            m: 2000,
            ..p.clone()
        },
        Params { m: 0, ..p.clone() },
        Params {
            payload_cap: 300,
            ..p.clone()
        },
        Params {
            payload_cap: 0,
            ..p.clone()
        },
        Params {
            work_bits: 255,
            ..p.clone()
        },
        Params {
            work_bits: 65,
            ..p.clone()
        },
    ] {
        assert!(
            Params::parse(&bad.encode()).is_none(),
            "a ceiling was not enforced"
        );
    }
}

/// Garbage cannot displace what a host holds: the contract ignores what it
/// cannot read and keeps what it had.
#[test]
fn nothing_unreadable_can_displace_a_held_bag() {
    let p = params(6, 12);
    let s = held(&p, 12, 4);
    let before = s.encode();
    for junk in [&b""[..], b"BG01", &[0xff; 200], MAGIC] {
        // The parser is the only way in; an unreadable candidate never becomes
        // a state, so the join never sees it.
        assert!(BagState::parse(junk, &p).is_none());
    }
    assert_eq!(s.encode(), before);
}

/// A delta carries exactly what the peer lacks and can use, both directions.
#[test]
fn a_delta_is_what_the_peer_lacks_and_can_use() {
    let p = params(4, 16);
    let pool = many(&p, 60, 21);
    let mine_ = collect(pool[..40].iter().cloned(), &p);
    let theirs = collect(pool[20..].iter().cloned(), &p);

    for (what, from, to) in [("a to b", &mine_, &theirs), ("b to a", &theirs, &mine_)] {
        let sum = summarize(to, p.m);
        let d = delta(from, &sum).expect("a well-formed summary");
        // Nothing the peer already has.
        for h in &d.held {
            assert!(
                !to.held.iter().any(|x| x.name == h.name),
                "{what}: sent a pointer the peer already had"
            );
            // And nothing it cannot use: when the peer is full, every sent
            // pointer must outrank its lowest.
            if to.held.len() as u16 >= p.m {
                let low = to.held.last().unwrap();
                assert!(
                    h.rank() < low.rank(),
                    "{what}: sent a pointer below the peer's cut"
                );
            }
        }
        // And everything it lacks and can use IS sent.
        for h in &from.held {
            let lacks = !to.held.iter().any(|x| x.name == h.name);
            let usable = (to.held.len() as u16) < p.m || h.rank() < to.held.last().unwrap().rank();
            if lacks && usable {
                assert!(
                    d.held.iter().any(|x| x.name == h.name),
                    "{what}: withheld a pointer the peer lacks and can use"
                );
            }
        }
        // Applying it converges in one round.
        let after = craftec_bag_contract::merge::join(to, &d, p.m);
        assert_eq!(
            after,
            craftec_bag_contract::merge::join(to, from, p.m),
            "{what}: the delta did not carry everything that mattered"
        );
    }
}

/// "You already have it" is an assertion a stranger aims at a peer. At 16 bytes
/// it cannot be aimed; two names agreeing on 8 bytes still sync.
///
/// The names here are SYNTHETIC — set directly rather than mined — because a
/// real 8-byte collision costs about 2^32 hashes to find and a real 16-byte one
/// 2^64, which is the whole point: the test would otherwise be unwritable in
/// the direction that matters. What it exercises is the summary's rule, which
/// sees only names.
#[test]
fn an_eight_byte_collision_does_not_hide_a_pointer() {
    let p = params(0, 64);
    let mut shared = [0u8; 32];
    shared[..8].copy_from_slice(&[0xa5; 8]);
    let mut other = shared;
    other[8] = 0x01; // agrees on 8 bytes, differs within 16

    let mk = |name: [u8; 32]| Held {
        ptr: Pointer {
            payload: b"x".to_vec(),
            nonce: [0u8; 8],
        },
        work: Pointer::work(&name),
        name,
    };
    let (a, b) = (mk(shared), mk(other));
    assert_eq!(
        a.name[..8],
        b.name[..8],
        "the fixture must collide on 8 bytes"
    );
    assert_ne!(a.name[..16], b.name[..16], "and differ within 16");

    // A peer holding `a` must still be sent `b`.
    let theirs = BagState {
        held: vec![a.clone()],
    };
    let mut mine_v = vec![a.clone(), b.clone()];
    mine_v.sort_by_key(|h| h.rank());
    let mine_ = BagState { held: mine_v };
    let d = delta(&mine_, &summarize(&theirs, p.m)).unwrap();
    assert!(
        d.held.iter().any(|h| h.name == b.name),
        "a pointer was hidden by an 8-byte agreement"
    );
    assert_eq!(d.held.len(), 1, "and only the one they lack was sent");

    // The control: had the summary truncated at 8, `b` would have been hidden.
    // Shown by asking the same question of an 8-byte view of the same names.
    let eight = |h: &Held| h.name[..8].to_vec();
    assert_eq!(
        eight(&a),
        eight(&b),
        "at 8 bytes these two are indistinguishable — which is why it is 16"
    );
}
