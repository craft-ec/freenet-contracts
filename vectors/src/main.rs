//! Writes the frozen accept/refuse corpus that the wasm-opt differential
//! replays through each build of each contract.
//!
//! The corpus is generated from the contracts' OWN code rather than written by
//! hand, for one reason: a hand-written "valid" state is valid only until a
//! format changes, and a corpus that has quietly stopped containing any
//! accepted case still passes a differential — both builds refuse everything,
//! identically. So every accepted vector here is built through the crate's
//! test helpers and its expectation is taken from the crate's own checker, and
//! `main` REFUSES to write a corpus that has no accepted cases for a contract.
//!
//! Each line is one case: contract, name, params, state, and what the native
//! code says about it. The differential's question is whether two wasm builds
//! AGREE; the native expectation is a second, independent oracle, and the two
//! failures it catches are different — a disagreement between builds means the
//! optimiser changed behaviour, a disagreement with native means the wasm
//! boundary is being driven wrong.

use std::fmt::Write as _;

struct Case {
    contract: &'static str,
    name: String,
    params: Vec<u8>,
    state: Vec<u8>,
    expect: bool,
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

/// Derive refusals from an accepted case by damaging it in the ways a stranger
/// can: the key no longer matching the bytes, the bytes truncated, a bit
/// flipped, the length pushed over its bound.
///
/// These are the GENERATED boundary cases. They are all expected to be refused,
/// and that is precisely why they are worth replaying: a build that accepts one
/// of them has changed what the network will keep.
fn derived(contract: &'static str, base: &Case, check: &dyn Fn(&[u8], &[u8]) -> bool) -> Vec<Case> {
    let mut out = Vec::new();
    let mut push = |name: String, params: Vec<u8>, state: Vec<u8>| {
        let expect = check(&params, &state);
        out.push(Case {
            contract,
            name,
            params,
            state,
            expect,
        });
    };
    // The parameters, damaged.
    for (what, p) in [
        ("params-empty", Vec::new()),
        ("params-short", base.params[..base.params.len().saturating_sub(1)].to_vec()),
        ("params-long", {
            let mut p = base.params.clone();
            p.push(0);
            p
        }),
        ("params-zeroed", vec![0u8; base.params.len()]),
    ] {
        push(format!("{}/{what}", base.name), p, base.state.clone());
    }
    // The state, damaged. Offsets are structural — the first byte decides the
    // kind, the last is the tail, and the middle is where a length field lives
    // in every one of these formats.
    let n = base.state.len();
    if n > 0 {
        for (what, off) in [("first", 0usize), ("middle", n / 2), ("last", n - 1)] {
            for bit in [0u8, 7] {
                let mut s = base.state.clone();
                s[off] ^= 1 << bit;
                push(
                    format!("{}/flip-{what}-bit{bit}", base.name),
                    base.params.clone(),
                    s,
                );
            }
        }
        for (what, s) in [
            ("truncate-1", base.state[..n - 1].to_vec()),
            ("truncate-half", base.state[..n / 2].to_vec()),
            ("truncate-all", Vec::new()),
            ("extend-1", {
                let mut s = base.state.clone();
                s.push(0);
                s
            }),
        ] {
            push(format!("{}/{what}", base.name), base.params.clone(), s);
        }
    }
    out
}


/// A base case is DECLARED to be accepted, and a declaration that turns out
/// false is a failure here, not a smaller number in the summary.
///
/// This is the observation guard, applied to the corpus itself: a fixture that
/// stops producing an accepted state leaves a corpus that still has hundreds of
/// cases and still passes a differential, because two builds that both refuse
/// everything agree perfectly.
fn declared_accept(name: &str, got: bool) {
    assert!(
        got,
        "{name} was built to be ACCEPTED and the contract refused it — the \
         fixture is broken, and a corpus that quietly loses its accepted cases \
         makes a differential pass while comparing nothing"
    );
}

fn block_cases() -> Vec<Case> {
    use craftec_block_contract::{check, encode, kind, max_body};
    use freenet_prolly::block_id;
    use freenet_prolly::boundary::{splits_after, MAX_LOGICAL};
    use freenet_prolly::node::{NodeBuilder, Value};

    // The same construction the contract's own worst-case test uses: keys
    // chosen so the split rule never fires, entries as small as the format
    // allows, stopping just under the measure.
    let worst_case_leaf = || {
        let mut b = NodeBuilder::leaf();
        let mut i = 0u32;
        loop {
            let base = b.logical_len();
            if base + 13 + 6 > MAX_LOGICAL {
                break;
            }
            let Some(key) = (0..200u32)
                .map(|j| format!("{i:04}{j:02}").into_bytes())
                .find(|k| !splits_after(0, k, base, base + 13 + k.len()))
            else {
                break;
            };
            if base + 13 + key.len() > MAX_LOGICAL {
                break;
            }
            b.push(&key, Value::Inline(b"")).unwrap();
            i += 1;
        }
        b.finish().unwrap()
    };

    let mut accepted: Vec<(String, u8, Vec<u8>)> = vec![
        ("raw-empty-body".into(), kind::RAW, Vec::new()),
        ("raw-1k".into(), kind::RAW, vec![0xa5; 1024]),
        ("raw-at-bound".into(), kind::RAW, vec![7u8; max_body(kind::RAW)]),
        ("tree-node-worst-case".into(), kind::TREE_NODE, worst_case_leaf()),
        ("parity-empty".into(), kind::PARITY, Vec::new()),
    ];
    accepted.push(("parity-at-bound".into(), kind::PARITY, vec![3u8; max_body(kind::PARITY)]));

    let mut out = Vec::new();
    for (name, k, body) in accepted {
        let state = encode(k, &body);
        let params = block_id(k, &body).to_vec();
        declared_accept(&name, check(&params, &state));
        out.push(Case {
            contract: "block",
            name,
            params,
            state,
            expect: true,
        });
    }
    // Refusals a stranger can reach without touching an accepted case: kinds
    // that are reserved and therefore refused, and a body one byte over its
    // bound.
    for k in 0u8..=8 {
        let body = vec![1u8; 8];
        let state = encode(k, &body);
        let params = block_id(k, &body).to_vec();
        let expect = state.is_empty() || check(&params, &state);
        out.push(Case {
            contract: "block",
            name: format!("kind-{k}-8-byte-body"),
            params,
            state,
            expect,
        });
    }
    for k in [kind::RAW, kind::PARITY] {
        let body = vec![9u8; max_body(k) + 1];
        let state = encode(k, &body);
        let params = block_id(k, &body).to_vec();
        out.push(Case {
            contract: "block",
            name: format!("kind-{k}-one-over-bound"),
            params,
            state,
            expect: false,
        });
    }
    // The ORACLE has to be validate_state, not `check`. The contract accepts
    // an empty state before `check` is ever called, so an oracle built on
    // `check` alone calls twelve truncated-to-empty cases refusals that the
    // wasm rightly accepts — and a "native mismatch" that is the oracle's
    // fault teaches the next reader to ignore the column.
    let verdict = |p: &[u8], st: &[u8]| st.is_empty() || check(p, st);
    let base: Vec<Case> = out.iter().filter(|c| c.expect).map(|c| Case {
        contract: c.contract,
        name: c.name.clone(),
        params: c.params.clone(),
        state: c.state.clone(),
        expect: c.expect,
    }).collect();
    for b in &base {
        out.extend(derived("block", b, &verdict));
    }
    out
}


/// The web container (builder#104): content-addressed, framed as the node serves it.
fn webapp_cases() -> Vec<Case> {
    use craftec_webapp_contract::{check, encode, MAX_METADATA};
    let key = |st: &[u8]| blake3::hash(st).as_bytes().to_vec();
    let accepted: Vec<(&str, Vec<u8>, Vec<u8>)> = vec![
        ("no-metadata-one-byte-web", Vec::new(), vec![1]),
        ("json-metadata", br#"{"app":"notes"}"#.to_vec(), vec![2; 100]),
        ("metadata-at-bound", vec![b'm'; MAX_METADATA], vec![3]),
        ("web-4k", Vec::new(), vec![4; 4096]),
        ("web-64k", b"m".to_vec(), vec![5; 65_536]),
        ("web-256k", b"m".to_vec(), (0..262_144u32).map(|i| (i % 251) as u8).collect()),
        ("xz-magic-web", b"{}".to_vec(), [&[0xFD, b'7', b'z', b'X', b'Z', 0][..], &[0u8; 58]].concat()),
        ("binary-metadata", vec![0, 255, 0, 255], vec![6; 17]),
    ];
    let mut out = Vec::new();
    for (name, meta, web) in accepted {
        let state = encode(&meta, &web);
        let params = key(&state);
        declared_accept(name, check(&params, &state));
        out.push(Case { contract: "webapp", name: name.into(), params, state, expect: true });
    }
    // Framing defects UNDER THEIR OWN HASH, so the hash is not what refuses them.
    let good = encode(b"m", &[7; 32]);
    let mut trailing = good.clone();
    trailing.push(0);
    let mut lying = good.clone();
    lying[..8].copy_from_slice(&5000u64.to_be_bytes());
    for (name, state) in [
        ("trailing-byte", trailing),
        ("metadata-length-lies", lying),
        ("metadata-over-bound", encode(&vec![b'm'; MAX_METADATA + 1], b"w")),
        ("empty-web", encode(b"m", b"")),
        ("web-shorter-than-said", good[..good.len() - 1].to_vec()),
    ] {
        let params = key(&state);
        out.push(Case { contract: "webapp", name: name.into(), params, state, expect: false });
    }
    let verdict = |p: &[u8], st: &[u8]| st.is_empty() || check(p, st);
    let base: Vec<Case> = out.iter().filter(|c| c.expect).map(|c| Case {
        contract: c.contract,
        name: c.name.clone(),
        params: c.params.clone(),
        state: c.state.clone(),
        expect: c.expect,
    }).collect();
    for b in &base {
        out.extend(derived("webapp", b, &verdict));
    }
    out
}

/// The three contracts whose `validate_state` is `read(params, state).is_some()`.
///
/// One builder each, because the only thing that differs is how an ACCEPTED
/// state is constructed; everything after that — the damage, the oracle, the
/// bookkeeping — is shared.
fn bag_cases() -> Vec<Case> {
    use craftec_bag_contract::merge::collect;
    use craftec_bag_contract::read;
    use craftec_bag_contract::testing::{many, params};

    let verdict = |p: &[u8], s: &[u8]| read(p, s).is_some();
    // work_bits 0: mining is the only slow part of this fixture and the work
    // rule is not what a differential is asking about.
    let p = params(0, 12);
    let pb = p.encode();
    let mut out = Vec::new();
    for (name, n) in [("bag-empty", 0usize), ("bag-1", 1), ("bag-2", 2), ("bag-half", 6), ("bag-full", 12)] {
        let state = collect(many(&p, n, 4), &p).encode();
        let expect = verdict(&pb, &state);
        declared_accept(name, expect);
        out.push(Case { contract: "bag", name: name.into(), params: pb.clone(), state, expect });
    }
    let base: Vec<Case> = out.iter().filter(|c| c.expect)
        .map(|c| Case { contract: c.contract, name: c.name.clone(), params: c.params.clone(), state: c.state.clone(), expect: c.expect })
        .collect();
    for b in &base { out.extend(derived("bag", b, &verdict)); }
    out
}

fn set_cases() -> Vec<Case> {
    use craftec_set_contract::read;
    use craftec_set_contract::testing::world;
    use craftec_set_contract::wire::{SetState, MAX_M};

    let verdict = |p: &[u8], s: &[u8]| read(p, s).is_some();
    let w = world();
    let pb = w.params_bytes.clone();
    let mut out = Vec::new();
    // Drawn from the same pool the merge sweep uses, so the corpus sits ON the
    // boundaries the parser enforces rather than in the easy interior: empty
    // payloads, EQUAL timestamps (the tie the ordering has to settle), a
    // tombstone, a sealed item, and a state at the item cap.
    let equal_ts = vec![w.item(0, b"e1", 7, b""), w.item(0, b"e2", 7, b"")];
    let mixed = vec![
        w.item(0, b"a", 1, b"owner writes"),
        w.tombstone(0, b"gone", 2),
        w.sealed(0, b"s", 3, b"sealed payload"),
        w.item(1, b"b", 2, b"cap holder writes"),
    ];
    let at_cap: Vec<_> = (0..MAX_M.min(16))
        .map(|i| w.item(0, format!("k{i:03}").as_bytes(), i as u64 + 1, b""))
        .collect();
    for (name, items) in [
        ("set-empty", vec![]),
        ("set-two", vec![w.item(0, b"a", 1, b"owner writes"), w.item(1, b"b", 2, b"cap holder writes")]),
        ("set-empty-payloads-equal-ts", equal_ts),
        ("set-tombstone-and-sealed", mixed),
        ("set-at-cap", at_cap),
        ("set-one-item", vec![w.item(0, b"only", 1, b"x")]),
        ("set-multi-signer", vec![
            w.item(0, b"o", 1, b"owner"),
            w.item(1, b"c1", 2, b"cap one"),
            w.item(2, b"c2", 3, b"cap two"),
        ]),
    ] {
        let state = if items.is_empty() { w.encode(&SetState::default()) } else { w.encode(&w.state(items)) };
        let expect = verdict(&pb, &state);
        declared_accept(name, expect);
        out.push(Case { contract: "set", name: name.into(), params: pb.clone(), state, expect });
    }
    // A DENY list is a second lattice inside the same state, with its own cap,
    // and it is the part a merge has to cut correctly — so it belongs in the
    // corpus rather than only in the merge sweep.
    for (name, deny) in [
        ("set-one-deny", vec![w.deny_of(1)]),
        ("set-two-denies", vec![w.deny_of(1), w.deny_of(2)]),
    ] {
        let state = w.encode(&w.state_with(vec![w.item(0, b"a", 1, b"owner")], deny));
        let expect = verdict(&pb, &state);
        declared_accept(name, expect);
        out.push(Case { contract: "set", name: name.into(), params: pb.clone(), state, expect });
    }
    let base: Vec<Case> = out.iter().filter(|c| c.expect)
        .map(|c| Case { contract: c.contract, name: c.name.clone(), params: c.params.clone(), state: c.state.clone(), expect: c.expect })
        .collect();
    for b in &base { out.extend(derived("set", b, &verdict)); }
    out
}

fn register_cases() -> Vec<Case> {
    use craftec_register_contract::read;
    use craftec_register_contract::testing::world;

    let verdict = |p: &[u8], s: &[u8]| read(p, s).is_some();
    let w = world();
    let pb = w.params_bytes.clone();
    let mut out = Vec::new();
    // A terminal record was here and was silently REFUSED — a fixture fault,
    // not a contract rule, and exactly the way a corpus quietly shrinks while
    // still looking full. `declared_accept` below now makes that a hard error
    // instead of a smaller number nobody reads.
    for (name, seq, value) in [
        ("register-1", 1u64, &b"value"[..]),
        ("register-2", 7u64, &b"another value"[..]),
        ("register-empty-value", 3u64, &b""[..]),
        ("register-seq-0", 0u64, &b"first"[..]),
        ("register-seq-max", u64::MAX, &b"last"[..]),
    ] {
        let state = w.encode(&w.state(w.record(false, seq, value)));
        let expect = verdict(&pb, &state);
        declared_accept(name, expect);
        out.push(Case { contract: "register", name: name.into(), params: pb.clone(), state, expect });
    }
    // Every legal ENCODING of one record. The contract accepts more than one
    // byte string for the same logical record (signer subsets, and mode-0's
    // absent bitmap), and an optimiser bug that rejected one of them would be
    // invisible to a corpus that only ever built the canonical form.
    for (i, r) in w.all_encodings(false, 5, b"encodings").into_iter().enumerate() {
        let state = w.encode(&w.state(r));
        let expect = verdict(&pb, &state);
        let name = format!("register-encoding-{i}");
        declared_accept(&name, expect);
        out.push(Case { contract: "register", name, params: pb.clone(), state, expect });
    }
    let base: Vec<Case> = out.iter().filter(|c| c.expect)
        .map(|c| Case { contract: c.contract, name: c.name.clone(), params: c.params.clone(), state: c.state.clone(), expect: c.expect })
        .collect();
    for b in &base { out.extend(derived("register", b, &verdict)); }
    out
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "corpus".into());
    std::fs::create_dir_all(&dir).unwrap();
    let mut all = Vec::new();
    all.extend(block_cases());
    all.extend(webapp_cases());
    all.extend(bag_cases());
    all.extend(register_cases());
    all.extend(set_cases());

    let mut lines = String::new();
    for c in &all {
        let _ = writeln!(
            lines,
            r#"{{"contract":"{}","name":"{}","params":"{}","state":"{}","expect":"{}"}}"#,
            c.contract,
            c.name,
            hex(&c.params),
            hex(&c.state),
            if c.expect { "accept" } else { "refuse" }
        );
    }
    let path = format!("{dir}/cases.jsonl");
    std::fs::write(&path, lines).unwrap();

    // A corpus with no accepted cases passes any differential while proving
    // nothing, so it is a FAILURE here rather than a quiet success.
    // Floors on BOTH columns, per contract. "At least one accepted" is too weak
    // to be a floor: a corpus can lose most of its accepted cases to a fixture
    // change and still pass it, and a thin ACCEPTED column is where an
    // optimiser bug hides — refusals mostly fail at the first length check and
    // never reach the code an optimiser rearranged.
    const MIN_ACCEPTED: usize = 8;
    const MIN_REFUSED: usize = 20;
    let mut short = Vec::new();
    for contract in ["block", "bag", "register", "set", "webapp"] {
        let n = all.iter().filter(|c| c.contract == contract).count();
        let acc = all
            .iter()
            .filter(|c| c.contract == contract && c.expect)
            .count();
        let ref_ = n - acc;
        println!(
            "{contract:10} {n:5} cases, {acc:4} accepted, {ref_:4} refused{}",
            if acc < MIN_ACCEPTED || ref_ < MIN_REFUSED { "   BELOW FLOOR" } else { "" }
        );
        if acc < MIN_ACCEPTED || ref_ < MIN_REFUSED {
            short.push(format!("{contract} ({acc} accepted, {ref_} refused)"));
        }
    }
    assert!(
        short.is_empty(),
        "below the corpus floor ({MIN_ACCEPTED} accepted, {MIN_REFUSED} refused per \
         contract): {}. A thin corpus still passes a differential — it just stops \
         being evidence.",
        short.join("; ")
    );
    println!("wrote {path}");
}
