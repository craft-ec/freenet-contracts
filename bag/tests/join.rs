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
                .filter(|_| r() % 3 != 0)
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

/// Filling a bag with junk changes nothing; paying more evicts from the bottom.
#[test]
fn a_flood_of_cheap_names_cannot_move_what_is_held() {
    let p = params(8, 16);
    let good = many(&p, 16, 11);
    let held = bag(&p, &good);
    assert_eq!(held.held.len(), 16);
    let floor = held.held.last().unwrap().work;

    // 10x M pointers that merely meet the price.
    let junk: Vec<Pointer> = (0..160)
        .map(|i| mine(&p, format!("junk/{i}").as_bytes(), 900_000 + i * 31))
        .collect();
    let flooded = join(&held, &bag(&p, &junk), p.m);
    assert_eq!(flooded.held.len(), 16);
    // Only pointers that outrank the floor may enter.
    for h in &flooded.held {
        assert!(
            h.work > floor || (h.work == floor && held.held.iter().any(|x| x.name == h.name)),
            "a pointer below the cut got in"
        );
    }

    // A higher-work flood evicts from the BOTTOM only: the best kept stays.
    let strong = params(16, 16);
    let mined: Vec<Pointer> = (0..8)
        .map(|i| mine(&strong, format!("strong/{i}").as_bytes(), 1 + i * 17))
        .collect();
    let best_before = held.held[0].clone();
    let after = join(&held, &bag(&p, &mined), p.m);
    assert_eq!(after.held.len(), 16);
    assert!(
        after.held.iter().any(|h| h.name == best_before.name),
        "the best pointer was evicted by a flood"
    );
    println!(
        "flood: floor {floor} bits; 160 cheap names changed {} of 16; 8 strong names took {}",
        flooded
            .held
            .iter()
            .filter(|h| !held.held.iter().any(|x| x.name == h.name))
            .count(),
        after
            .held
            .iter()
            .filter(|h| mined.iter().any(|m| m.nonce == h.ptr.nonce))
            .count()
    );
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
        let mut reps = vec![full, empty, junk_only, bag(&p, &pool[30..])];

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
