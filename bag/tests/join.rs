//! The merge is a join, or the bag is not a CRDT. Laws first.

use craftec_bag_contract::merge::{collect, join, summarize};
use craftec_bag_contract::testing::{many, mine, params};
use craftec_bag_contract::wire::{BagState, Held, Params, Pointer};

fn rng(seed: u64) -> impl FnMut() -> u64 {
    let mut s = seed | 1;
    move || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    }
}

fn bag(p: &Params, ptrs: &[Pointer]) -> BagState {
    collect(ptrs.iter().cloned(), p)
}

/// Random subsets of a shared pool, so two bags overlap the way replicas do.
fn subsets(p: &Params, pool: &[Pointer], n: usize, seed: u64) -> Vec<BagState> {
    let mut r = rng(seed);
    (0..n)
        .map(|_| {
            let picked: Vec<Pointer> = pool
                .iter()
                .filter(|_| !r().is_multiple_of(3))
                .cloned()
                .collect();
            bag(p, &picked)
        })
        .collect()
}

#[test]
fn the_merge_is_commutative_associative_and_idempotent() {
    // work_bits 0 so the pool is cheap; the laws are about the ORDER, and ties
    // in work are what make them interesting, so a low price is the hard case.
    let p = params(0, 8);
    let pool = many(&p, 40, 1);
    let bags = subsets(&p, &pool, 12, 99);
    let mut checked = 0;
    for a in &bags {
        for b in &bags {
            assert_eq!(join(a, b, p.m), join(b, a, p.m), "commutative");
            assert_eq!(join(a, a, p.m), *a, "idempotent: a ∨ a = a");
            for c in &bags {
                assert_eq!(
                    join(&join(a, b, p.m), c, p.m),
                    join(a, &join(b, c, p.m), p.m),
                    "associative"
                );
                checked += 1;
            }
        }
    }
    assert!(checked >= 1000, "only {checked} triples");

    // Work ties really occur at work_bits 0 — otherwise the order is decided by
    // work alone and the name tiebreak is never exercised.
    let all = bag(&p, &pool);
    let ties = all
        .held
        .windows(2)
        .filter(|w| w[0].work == w[1].work)
        .count();
    assert!(ties > 0, "the fixture must contain work ties");
    println!("{checked} triples, {ties} work ties in the kept set");
}

/// The cut cannot make the join lie: a pointer in the global top M is in every
/// merge of every order.
#[test]
fn the_global_top_m_survives_every_order() {
    let p = params(0, 16);
    let pool = many(&p, 200, 5);
    let whole = bag(&p, &pool);
    assert_eq!(whole.held.len(), p.m as usize);

    let mut r = rng(7);
    for _ in 0..30 {
        // Shuffle the pool into random bags, then merge them in a random order.
        let mut parts: Vec<Vec<Pointer>> = vec![Vec::new(); 5];
        for ptr in &pool {
            parts[(r() % 5) as usize].push(ptr.clone());
        }
        let mut order: Vec<BagState> = parts.iter().map(|x| bag(&p, x)).collect();
        for i in (1..order.len()).rev() {
            order.swap(i, (r() % (i as u64 + 1)) as usize);
        }
        let merged = order
            .into_iter()
            .fold(BagState::default(), |acc, b| join(&acc, &b, p.m));
        assert_eq!(merged, whole, "a different order gave a different bag");
    }
}

/// A flood of pointers that merely meet the price cannot move a bag whose
/// contents cost more. Paying more evicts, and only from the bottom.
#[test]
fn a_flood_of_cheap_names_cannot_move_what_is_held() {
    use craftec_bag_contract::testing::mine_at;
    let p = params(8, 16);
    // Held: names that cost 14 bits, well above the 8-bit price of entry.
    let good: Vec<Pointer> = (0..16)
        .map(|i| mine_at(&p, format!("kept/{i}").as_bytes(), 1 + i * 13, 14))
        .collect();
    let held = bag(&p, &good);
    assert_eq!(held.held.len(), 16);
    let floor = held.held.last().unwrap().work;
    assert!(floor >= 14);

    // 10x M names that merely meet the price. None of them may get in.
    let junk: Vec<Pointer> = (0..160)
        .map(|i| mine(&p, format!("junk/{i}").as_bytes(), 900_000 + i * 31))
        .collect();
    let cheap = junk
        .iter()
        .filter(|x| craftec_bag_contract::wire::Held::of((*x).clone(), &p.hash()).work < floor)
        .count();
    assert!(
        cheap > 140,
        "the flood must be cheap: only {cheap} of 160 below the floor"
    );
    let flooded = join(&held, &bag(&p, &junk), p.m);
    assert_eq!(flooded.held.len(), 16);
    // The invariant is not "nothing changed" — a flood of 160 names mined to at
    // least 8 bits will contain a few that happened to reach 14, and those have
    // PAID for their place. What may never happen is a name below the floor
    // getting in.
    let entered: Vec<_> = flooded
        .held
        .iter()
        .filter(|h| !held.held.iter().any(|x| x.name == h.name))
        .collect();
    for h in &entered {
        assert!(
            h.work >= floor,
            "a name worth {} bits displaced one worth {floor}",
            h.work
        );
    }
    assert!(
        entered.len() <= 4,
        "{} of 160 cheap names got in; the fixture is not cheap",
        entered.len()
    );

    // Names that cost MORE evict, and from the bottom: the best kept stays.
    let best = held.held[0].clone();
    let strong: Vec<Pointer> = (0..4)
        .map(|i| mine_at(&p, format!("strong/{i}").as_bytes(), 7 + i * 29, 18))
        .collect();
    let after = join(&held, &bag(&p, &strong), p.m);
    assert_eq!(after.held.len(), 16);
    assert!(
        after.held.iter().any(|h| h.name == best.name),
        "the best was evicted"
    );
    let took = after
        .held
        .iter()
        .filter(|h| !held.held.iter().any(|x| x.name == h.name))
        .count();
    assert_eq!(took, 4, "4 higher-work names should take exactly 4 places");
    // And what they displaced was the bottom 4 of the bag they joined, nothing
    // else: the twelve dearest names are all still there.
    for (i, h) in held.held.iter().enumerate().take(12) {
        assert!(
            after.held.iter().any(|x| x.name == h.name),
            "held rank {i} was evicted although it outranked the newcomers"
        );
    }
    println!(
        "flood: floor {floor} bits; of 160 names at the 8-bit price, {} reached the floor \
         and took a place; 4 names worth 18 bits took 4",
        entered.len()
    );
}

/// Work is bound to the bag. A name mined for one bag is worth nothing in
/// another, so a pointer cannot be moved and the price is paid per bag.
#[test]
fn work_mined_for_another_bag_is_worthless_here() {
    use craftec_bag_contract::testing::mine_at;
    use craftec_bag_contract::wire::Held;
    let here = params(10, 16);
    let mut there = params(10, 16);
    there.bucket = 1; // a different bag of the same shape

    let mined: Vec<Pointer> = (0..40)
        .map(|i| mine_at(&there, format!("ptr/{i}").as_bytes(), 5 + i * 17, 14))
        .collect();
    // Every one of them is expensive THERE.
    let ph_there = there.hash();
    assert!(mined
        .iter()
        .all(|x| Held::of(x.clone(), &ph_there).work >= 14));
    // Here, their work is whatever the hash happens to give — and almost none
    // of them even meet the 10-bit price.
    let ph_here = here.hash();
    let admitted = mined
        .iter()
        .filter(|x| Held::of((*x).clone(), &ph_here).work >= here.work_bits as u32)
        .count();
    assert!(
        admitted <= 1,
        "{admitted} of 40 names mined for another bag were admitted here"
    );
    assert!(bag(&here, &mined).held.len() <= 1);
    println!("work binding: {admitted} of 40 foreign names met the price here");
}

/// Gossip in random orders converges, including from asymmetric starts.
#[test]
fn replicas_converge_under_gossip() {
    let p = params(4, 12);
    let pool = many(&p, 60, 3);
    let mut r = rng(13);

    for round in 0..10 {
        // One replica full, one empty, one holding only the cheapest names.
        let full = bag(&p, &pool[..30]);
        let empty = BagState::default();
        let mut cheap: Vec<Held> = collect(pool.iter().cloned(), &p).held;
        cheap.sort_by_key(|h| h.work);
        let junk_only = bag(
            &p,
            &cheap[..6].iter().map(|h| h.ptr.clone()).collect::<Vec<_>>(),
        );
        let mut reps = [full, empty, junk_only, bag(&p, &pool[30..])];

        // Random pairwise gossip until nothing changes.
        for _ in 0..200 {
            let (i, j) = ((r() % 4) as usize, (r() % 4) as usize);
            if i != j {
                let merged = join(&reps[i], &reps[j], p.m);
                reps[i] = merged.clone();
                reps[j] = merged;
            }
        }
        let want = reps[0].clone();
        for (k, rep) in reps.iter().enumerate() {
            assert_eq!(*rep, want, "round {round}: replica {k} did not converge");
        }
        assert_eq!(want.held.len(), p.m as usize);
        // And they converged on the truth, not merely on each other.
        assert_eq!(want, bag(&p, &pool), "converged on the wrong bag");
    }
}

/// A summary is what a peer reads; it must say what the bag holds.
#[test]
fn a_summary_says_full_only_when_it_is() {
    let p = params(0, 8);
    let pool = many(&p, 20, 2);
    let partial = bag(&p, &pool[..3]);
    let full = bag(&p, &pool);

    let s = summarize(&partial, p.m);
    assert_eq!(s[2], 0, "3 of 8 is not full");
    let s = summarize(&full, p.m);
    assert_eq!(s[2], 1, "8 of 8 is full");
    // The lowest kept is the last in rank order, with its FULL name.
    assert_eq!(&s[4..36], &full.held.last().unwrap().name[..]);
    assert_eq!(summarize(&BagState::default(), p.m)[2], 0);
}

/// The bag keeps the top M BY WORK. Ordering by name alone would still be a
/// join and would still converge — and would keep the wrong pointers.
#[test]
fn what_is_kept_is_the_dearest_not_merely_a_consistent_choice() {
    use craftec_bag_contract::testing::mine_at;
    let p = params(0, 16);
    // A spread of known prices, so "kept" and "dearest" can disagree.
    let mut ptrs: Vec<Pointer> = Vec::new();
    for (bits, n) in [(0u32, 30usize), (4, 20), (8, 10), (12, 6)] {
        for i in 0..n {
            ptrs.push(mine_at(
                &p,
                format!("w{bits}/{i}").as_bytes(),
                1 + i as u64 * 7,
                bits,
            ));
        }
    }
    let all = collect(ptrs.clone(), &p);
    assert_eq!(all.held.len(), 16);

    // Everything kept is at least as dear as everything dropped.
    let ph = p.hash();
    let every: Vec<Held> = ptrs.iter().map(|x| Held::of(x.clone(), &ph)).collect();
    let kept_min = all.held.iter().map(|h| h.work).min().unwrap();
    for h in &every {
        if !all.held.iter().any(|k| k.name == h.name) {
            assert!(
                h.work <= kept_min,
                "a pointer worth {} bits was dropped while one worth {kept_min} was kept",
                h.work
            );
        }
    }
    // And the kept set really is the expensive end, not an arbitrary 16.
    assert!(kept_min >= 8, "the cheapest kept is only {kept_min} bits");
    let dearest = every.iter().map(|h| h.work).max().unwrap();
    assert!(
        all.held.iter().any(|h| h.work == dearest),
        "the dearest was not kept"
    );
    println!(
        "kept 16 of {}: cheapest kept {kept_min} bits, dearest {dearest}",
        every.len()
    );
}

/// The bag's order is written as `(work desc, name asc)`, and that is the same
/// order as `name asc` — because work IS the leading zeros of the name, so more
/// work means a numerically smaller name.
///
/// Worth pinning rather than leaving implicit: it is why a mutant that drops
/// the work term from the comparison changes nothing, and it would stop being
/// true the moment work meant anything other than leading zeros. The explicit
/// form stays in the code because it says what the order is FOR.
#[test]
fn ordering_by_work_then_name_is_ordering_by_name() {
    let p = params(0, 1024);
    let ph = p.hash();
    let every: Vec<Held> = many(&p, 400, 99)
        .into_iter()
        .map(|x| Held::of(x, &ph))
        .collect();

    let mut by_rank = every.clone();
    by_rank.sort_by_key(|h| h.rank());
    let mut by_name = every.clone();
    by_name.sort_by_key(|h| h.name);
    assert_eq!(
        by_rank.iter().map(|h| h.name).collect::<Vec<_>>(),
        by_name.iter().map(|h| h.name).collect::<Vec<_>>(),
        "the two orders differ, so work is no longer the leading zeros of the name"
    );

    // And the direction is right: the dearest name sorts first.
    let works: Vec<u32> = by_rank.iter().map(|h| h.work).collect();
    assert!(
        works.windows(2).all(|w| w[0] >= w[1]),
        "work is not descending along the order"
    );
    assert!(
        works[0] > works[works.len() - 1],
        "the fixture has no spread"
    );
    println!(
        "order: {} names, work {} down to {}, identical under both keys",
        every.len(),
        works[0],
        works[works.len() - 1]
    );
}
