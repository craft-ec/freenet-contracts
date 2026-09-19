//! Times the block contract's validation where it actually runs: inside wasm32.
//!
//! The case is the worst one a host can be handed — a leaf filled to the
//! boundary rule's 12 KiB measure with the smallest entries the format allows,
//! so the per-entry pass runs as many times as it ever can. Driven by
//! `../check-wasm.sh`; the timing is taken on the JS side because
//! wasm32-unknown-unknown has no clock.

//! Every entry point below takes back the handle [`prepare`] returned and
//! trusts it; nothing but `../check-wasm.sh` calls them.

use craftec_block_contract::{check, encode, kind};
use freenet_prolly::boundary::{check_node, splits_after, MAX_LOGICAL};
use freenet_prolly::node::{Node, NodeBuilder, Value};

// Handles are passed to JS as u32, which is a pointer only here. Building this
// for any other target would truncate them silently, so it does not build.
const _: () = assert!(
    core::mem::size_of::<usize>() == 4,
    "wasm-check is wasm32-only: build it with --target wasm32-unknown-unknown"
);

/// One prepared block: the state bytes and the params they hash to.
pub struct Case {
    params: [u8; 32],
    state: Vec<u8>,
    entries: u32,
}

/// The same construction as the contract's `worst_case_leaf` test: keys are
/// chosen so the split rule never fires, entries are as small as the format
/// allows, and the node stops just under the measure.
fn worst_case_leaf() -> Vec<u8> {
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
}

/// Build the case; returns a handle the other calls take back.
#[no_mangle]
pub extern "C" fn prepare() -> u32 {
    let body = worst_case_leaf();
    let entries = Node::parse(&body).unwrap().len() as u32;
    let case = Case {
        params: freenet_prolly::block_id(kind::TREE_NODE, &body),
        state: encode(kind::TREE_NODE, &body),
        entries,
    };
    Box::into_raw(Box::new(case)) as u32
}

/// # Safety
/// `h` must be a handle from [`prepare`] that has not been freed.
unsafe fn case<'a>(h: u32) -> &'a Case {
    &*(h as *const Case)
}

#[no_mangle]
pub extern "C" fn entries(h: u32) -> u32 {
    unsafe { case(h) }.entries
}

#[no_mangle]
pub extern "C" fn state_len(h: u32) -> u32 {
    unsafe { case(h) }.state.len() as u32
}

/// The contract's whole check, `runs` times: hash, size cap, well-formedness.
/// Returns how many passed, so nothing can be optimised away.
#[no_mangle]
pub extern "C" fn check_n(h: u32, runs: u32) -> u32 {
    let c = unsafe { case(h) };
    (0..runs)
        .filter(|_| {
            check(
                std::hint::black_box(&c.params),
                std::hint::black_box(&c.state),
            )
        })
        .count() as u32
}

/// Correctness, not cost: the same state with one byte of its key area flipped
/// must be refused here too. Returns 1 if the good state is accepted and the
/// corrupted one is not — so a build where the check does nothing fails the
/// script instead of reporting a very fast time.
#[no_mangle]
pub extern "C" fn accepts_good_refuses_corrupt(h: u32) -> u32 {
    let c = unsafe { case(h) };
    let mut bad = c.state.clone();
    let at = bad.len() / 2;
    bad[at] ^= 1;
    let bad_params = freenet_prolly::block_id(bad[0], &bad[1..]);
    u32::from(check(&c.params, &c.state) && !check(&bad_params, &bad))
}

/// Only the tree library's part: parse plus the per-node boundary check, with
/// no hashing. The difference from [`check_n`] is what BLAKE3 costs.
#[no_mangle]
pub extern "C" fn well_formed_n(h: u32, runs: u32) -> u32 {
    let c = unsafe { case(h) };
    (0..runs)
        .filter(|_| {
            let body = std::hint::black_box(&c.state[1..]);
            Node::parse(body).is_ok_and(|n| check_node(&n).is_ok())
        })
        .count() as u32
}

/// One prepared register: the worst case a host can be handed, mode 1 with
/// `n = 16, k = 16`, so every validation verifies sixteen signatures over a
/// full-size value, and the state carries evidence as well as a record.
pub struct Reg {
    params: Vec<u8>,
    state: Vec<u8>,
    /// A record the held state already beats — the cheapest thing an attacker
    /// can replay at a host, and the case verifying late exists for.
    stale: Vec<u8>,
}

#[no_mangle]
pub extern "C" fn prepare_register() -> u32 {
    let (params, state, stale) = craftec_register_contract::testing::worst_case();
    Box::into_raw(Box::new(Reg {
        params,
        state,
        stale,
    })) as u32
}

/// # Safety
/// `h` must be a handle from [`prepare_register`] that has not been freed.
unsafe fn reg<'a>(h: u32) -> &'a Reg {
    &*(h as *const Reg)
}

#[no_mangle]
pub extern "C" fn register_state_len(h: u32) -> u32 {
    unsafe { reg(h) }.state.len() as u32
}

/// Validate the register `runs` times; returns how many passed.
#[no_mangle]
pub extern "C" fn register_validate_n(h: u32, runs: u32) -> u32 {
    let r = unsafe { reg(h) };
    (0..runs)
        .filter(|_| {
            craftec_register_contract::read(
                std::hint::black_box(&r.params),
                std::hint::black_box(&r.state),
            )
            .is_some()
        })
        .count() as u32
}

/// Correctness inside wasm32: the good state validates and a one-bit change to
/// it does not. A build where verification silently did nothing would be very
/// fast and would fail here.
#[no_mangle]
pub extern "C" fn register_accepts_good_refuses_corrupt(h: u32) -> u32 {
    let r = unsafe { reg(h) };
    let mut bad = r.state.clone();
    let at = bad.len() - 1; // inside the last signature
    bad[at] ^= 1;
    u32::from(
        craftec_register_contract::read(&r.params, &r.state).is_some()
            && craftec_register_contract::read(&r.params, &bad).is_none(),
    )
}

/// Replaying a record the state already beats, `runs` times, the way the
/// contract does it now: parse, compare decisions, verify nothing.
#[no_mangle]
pub extern "C" fn register_stale_replay_n(h: u32, runs: u32) -> u32 {
    let r = unsafe { reg(h) };
    (0..runs)
        .filter(|_| {
            craftec_register_contract::cost::verify_late(
                std::hint::black_box(&r.params),
                std::hint::black_box(&r.state),
                std::hint::black_box(&r.stale),
            )
            .is_some()
        })
        .count() as u32
}

/// The same replay with the pre-verify-late policy: verify everything first.
#[no_mangle]
pub extern "C" fn register_stale_replay_eager_n(h: u32, runs: u32) -> u32 {
    let r = unsafe { reg(h) };
    (0..runs)
        .filter(|_| {
            craftec_register_contract::cost::verify_eagerly(
                std::hint::black_box(&r.params),
                std::hint::black_box(&r.state),
                std::hint::black_box(&r.stale),
            )
            .is_some()
        })
        .count() as u32
}

// ---------------------------------------------------------------------------
// Bag: what a host pays per admitted update, and per replayed no-op delta.
// ---------------------------------------------------------------------------

/// A full bag at the worst size a host can be handed: M pointers, each with a
/// payload at the cap, so every per-pointer hash runs as many times as it can.
pub struct BagCase {
    params: Vec<u8>,
    state: Vec<u8>,
    /// A delta carrying ONE pointer that is below the bag's cut: the merge
    /// changes nothing, and the host still pays update + a full validate (F24).
    noop: Vec<u8>,
    count: u32,
}

#[no_mangle]
pub extern "C" fn bag_prepare(m: u32) -> u32 {
    bag_prepare_with(m, 256)
}

/// The same, at a chosen payload size: the worst case is dominated by the cap,
/// and a real pointer is a reference of about fifty bytes.
#[no_mangle]
pub extern "C" fn bag_prepare_with(m: u32, payload: u32) -> u32 {
    use craftec_bag_contract::merge::{collect, join};
    use craftec_bag_contract::testing::{many, params};
    use craftec_bag_contract::wire::BagState;
    // work_bits 0: mining is not what is being timed, and validation hashes
    // every name whatever the price was.
    let mut p = params(0, m as u16);
    p.payload_cap = 256;
    let ptrs: Vec<_> = many(&p, m as usize + 1, 1)
        .into_iter()
        .map(|mut x| {
            x.payload = vec![0xab; payload as usize];
            x
        })
        .collect();
    // Distinct payloads, so the names differ.
    let ptrs: Vec<_> = ptrs
        .into_iter()
        .enumerate()
        .map(|(i, mut x)| {
            x.payload[..8].copy_from_slice(&(i as u64).to_le_bytes());
            x
        })
        .collect();
    let full = collect(ptrs.clone(), &p);
    // The one left over is below the cut once the bag is full.
    let extra = collect(ptrs.clone(), &p);
    let lowest = full.held.last().expect("full").rank();
    let below: Vec<_> = extra
        .held
        .iter()
        .filter(|h| h.rank() > lowest)
        .take(1)
        .cloned()
        .collect();
    let noop = BagState {
        held: if below.is_empty() {
            // Every mined name made the cut; take the lowest instead — merging
            // it changes nothing either, which is what is being timed.
            vec![full.held.last().expect("full").clone()]
        } else {
            below
        },
    };
    // Sanity: merging the no-op really does change nothing.
    let merged = join(&full, &noop, p.m);
    assert!(merged == full, "the no-op delta is not a no-op");
    let case = BagCase {
        params: p.encode(),
        state: full.encode(),
        noop: noop.encode(),
        count: full.held.len() as u32,
    };
    Box::into_raw(Box::new(case)) as u32
}

fn bag_case(h: u32) -> &'static BagCase {
    unsafe { &*(h as *const BagCase) }
}

#[no_mangle]
pub extern "C" fn bag_count(h: u32) -> u32 {
    bag_case(h).count
}

#[no_mangle]
pub extern "C" fn bag_state_len(h: u32) -> u32 {
    bag_case(h).state.len() as u32
}

#[no_mangle]
pub extern "C" fn bag_summary_len(h: u32) -> u32 {
    use craftec_bag_contract::merge::summarize;
    let c = bag_case(h);
    let (p, s) = craftec_bag_contract::read(&c.params, &c.state).expect("prepared");
    summarize(&s, p.m).len() as u32
}

/// `validate_state` over the whole bag: what F23 charges per admitted update,
/// on every hosting node.
#[no_mangle]
pub extern "C" fn bag_validate_n(h: u32, runs: u32) -> u32 {
    let c = bag_case(h);
    let mut ok = 0;
    for _ in 0..runs {
        if craftec_bag_contract::read(&c.params, &c.state).is_some() {
            ok += 1;
        }
    }
    ok
}

/// ONE no-op delta, the whole cost a host pays for it: parse the held state,
/// merge the delta, re-encode — and then the full `validate_state` F23 runs
/// over the result before anything is persisted.
#[no_mangle]
pub extern "C" fn bag_noop_delta_n(h: u32, runs: u32) -> u32 {
    use craftec_bag_contract::merge::join;
    use craftec_bag_contract::wire::BagState;
    let c = bag_case(h);
    let mut ok = 0;
    for _ in 0..runs {
        let (p, held) = craftec_bag_contract::read(&c.params, &c.state).expect("prepared");
        let cand = BagState::parse(&c.noop, &p).expect("a valid delta");
        let merged = join(&held, &cand, p.m);
        let out = merged.encode();
        // F23: the host re-runs validate over the FULL new state.
        if craftec_bag_contract::read(&c.params, &out).is_some() {
            ok += 1;
        }
    }
    ok
}

/// The control: a bag that should not validate must not.
#[no_mangle]
pub extern "C" fn bag_accepts_good_refuses_corrupt(h: u32) -> u32 {
    let c = bag_case(h);
    let good = craftec_bag_contract::read(&c.params, &c.state).is_some();
    let mut bad = c.state.clone();
    let at = bad.len() / 2;
    bad[at] ^= 0x01;
    let refused = craftec_bag_contract::read(&c.params, &bad).is_none();
    u32::from(good && refused)
}
