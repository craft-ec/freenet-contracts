//! Block contract: immutable, hash-keyed bytes (ARCHITECTURE.md §1).
//!
//! Params = blake3(state), 32 bytes.
//! State  = kind(1) ‖ body.
//! Valid  = hash matches, size within cap, body well-formed for its kind.
//! Merge  = an empty state adopts the first valid candidate; a held state never
//!          changes. Exactly one byte string hashes to `params`, so this is
//!          trivially commutative, associative and idempotent.

use freenet_stdlib::prelude::*;

pub const PARAMS_LEN: usize = 32;
/// Largest body: one 256 KiB media piece plus sealing overhead.
pub const MAX_BODY: usize = 256 * 1024 + 64;
pub const MAX_STATE: usize = 1 + MAX_BODY;

/// Block kinds. Well-formedness per kind is added as each format lands.
///
/// A kind byte is hashed into every block id, so the tree library and this
/// contract must agree on it exactly. The two it also needs are re-exported
/// rather than restated: one definition cannot drift from itself. The values
/// are frozen against literals in `kind_bytes_are_frozen`, which is what fails
/// if a bumped `freenet-prolly` rev ever changes them.
pub mod kind {
    pub use freenet_prolly::kind::{RAW, TREE_NODE};
    pub const MEDIA_CHUNK: u8 = 2;
    pub const FRAGMENT: u8 = 3;
    pub const PARITY: u8 = 4;
    pub const SCHEMA: u8 = 5;
}

/// The state bytes for a block of `kind` holding `body`.
pub fn encode(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + body.len());
    v.push(kind);
    v.extend_from_slice(body);
    v
}

/// Is `body` well-formed for `kind`? Unknown kinds are refused: a host must
/// never keep bytes it cannot check.
///
/// For `TREE_NODE` this proves two things about **this block, by itself**
/// (ARCHITECTURE.md §12):
///
/// - it is a well-formed node — magic, sorted keys, entries tiling the node
///   exactly, the stored prefix being the longest common one, the aggregate
///   equalling the fold of the entries, keys ≤ 512 B, one encoding per value;
/// - it was not cut in the wrong place in its interior — no entry but the last
///   satisfies the split rule where it sits, and the entries are within the
///   12 KiB measure.
///
/// It proves nothing that needs another block: not that the children exist or
/// hold what their aggregates claim, not that the node's own last entry ended
/// it correctly (the last node of a level, and a node closed by the hard limit,
/// legitimately end without a split), and not that keys are unique across
/// nodes. Those belong to the writer's engine and are re-checked by readers.
/// A host runs the part it can decide from the bytes in front of it.
fn well_formed(kind: u8, body: &[u8]) -> bool {
    match kind {
        // One bounded pass over at most 16 KiB, no allocation beyond a key per
        // entry, and it never panics — safe to run on bytes a stranger sent.
        kind::TREE_NODE => freenet_prolly::node::Node::parse(body)
            .is_ok_and(|node| freenet_prolly::boundary::check_node(&node).is_ok()),
        // Formats not landed yet: any body, as before.
        kind::RAW | kind::MEDIA_CHUNK | kind::FRAGMENT | kind::PARITY | kind::SCHEMA => true,
        _ => false,
    }
}

/// The one check every entry point shares.
pub fn check(params: &[u8], state: &[u8]) -> bool {
    params.len() == PARAMS_LEN
        && !state.is_empty()
        && state.len() <= MAX_STATE
        && well_formed(state[0], &state[1..])
        && blake3::hash(state).as_bytes() == params
}

pub struct Block;

#[contract]
impl ContractInterface for Block {
    fn validate_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        _related: RelatedContracts<'static>,
    ) -> Result<ValidateResult, ContractError> {
        let s = state.as_ref();
        Ok(if s.is_empty() || check(parameters.as_ref(), s) {
            ValidateResult::Valid
        } else {
            ValidateResult::Invalid
        })
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        if !state.as_ref().is_empty() {
            return Ok(UpdateModification::valid(state));
        }
        let params = parameters.as_ref();
        for item in data {
            let candidates: [Option<&[u8]>; 2] = match &item {
                UpdateData::State(s) => [Some(s.as_ref()), None],
                UpdateData::Delta(d) => [Some(d.as_ref()), None],
                UpdateData::StateAndDelta { state, delta } => {
                    [Some(state.as_ref()), Some(delta.as_ref())]
                }
                _ => [None, None],
            };
            for bytes in candidates.into_iter().flatten() {
                if check(params, bytes) {
                    return Ok(UpdateModification::valid(State::from(bytes.to_vec())));
                }
            }
        }
        Ok(UpdateModification::valid(state))
    }

    fn summarize_state(
        _parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        Ok(StateSummary::from(vec![u8::from(
            !state.as_ref().is_empty(),
        )]))
    }

    fn get_state_delta(
        _parameters: Parameters<'static>,
        state: State<'static>,
        summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        if summary.as_ref() == [1] || state.as_ref().is_empty() {
            return Ok(StateDelta::from(Vec::new()));
        }
        Ok(StateDelta::from(state.as_ref().to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use freenet_prolly::boundary::{check_node, splits_after, BoundaryError, MAX_LOGICAL};
    use freenet_prolly::build::TreeBuilder;
    use freenet_prolly::node::{Agg, Node, NodeBuilder, NodeError, Value, HEADER, MAX_INLINE};

    fn params_of(state: &[u8]) -> Parameters<'static> {
        Parameters::from(blake3::hash(state).as_bytes().to_vec())
    }
    fn validate(p: Parameters<'static>, s: Vec<u8>) -> ValidateResult {
        Block::validate_state(p, State::from(s), Default::default()).unwrap()
    }
    fn update(p: Parameters<'static>, held: Vec<u8>, data: Vec<Vec<u8>>) -> Vec<u8> {
        let data = data
            .into_iter()
            .map(|d| UpdateData::State(State::from(d)))
            .collect();
        Block::update_state(p, State::from(held), data)
            .unwrap()
            .new_state
            .map(|s| s.as_ref().to_vec())
            .unwrap_or_default()
    }

    /// A leaf the tree library itself produced: two entries sharing the prefix
    /// `k/`, so the suffixes `aaa` and `bbb` are what the search index is over.
    fn leaf_node() -> Vec<u8> {
        let mut b = NodeBuilder::leaf();
        b.push(b"k/aaa", Value::Inline(b"one")).unwrap();
        b.push(b"k/bbb", Value::Inline(b"two")).unwrap();
        b.finish().unwrap()
    }

    /// A branch pointing at that leaf, keyed by the leaf's smallest key.
    fn branch_node() -> Vec<u8> {
        let leaf = leaf_node();
        let agg = Node::parse(&leaf).unwrap().agg();
        let mut b = NodeBuilder::branch(1);
        b.push_child(
            b"k/aaa",
            freenet_prolly::block_id(kind::TREE_NODE, &leaf),
            agg,
        )
        .unwrap();
        b.push_child(b"k/zzz", [9u8; 32], Agg { count: 1, bytes: 8 })
            .unwrap();
        b.finish().unwrap()
    }

    /// Replace every occurrence of `a` with `b` and vice versa. Used to reorder
    /// two keys *and* their entries in the 4-byte search index in one step, so
    /// the only thing wrong with the result is the ordering.
    fn swap_all(v: &mut [u8], a: &[u8], b: &[u8]) {
        assert_eq!(a.len(), b.len());
        let orig = v.to_vec();
        for i in 0..=orig.len() - a.len() {
            if &orig[i..i + a.len()] == a {
                v[i..i + a.len()].copy_from_slice(b);
            } else if &orig[i..i + b.len()] == b {
                v[i..i + b.len()].copy_from_slice(a);
            }
        }
    }

    /// A leaf holding one 1025 B inline value: one byte over the cap that forces
    /// a longer value to be stored by reference. The builder refuses to make
    /// one, so it is patched — the node is otherwise exactly canonical.
    fn oversized_inline_value() -> Vec<u8> {
        let mut b = NodeBuilder::leaf();
        b.push(b"k", Value::Inline(&vec![7u8; MAX_INLINE])).unwrap();
        let mut v = b.finish().unwrap();
        // One entry, so the stored prefix is the whole key and the suffix empty.
        let off = HEADER + 1 + 6;
        assert_eq!(v[off + 2], 0, "entry is an inline value");
        v[off + 3..off + 7].copy_from_slice(&((MAX_INLINE + 1) as u32).to_le_bytes());
        // Aggregate bytes = key length + value length, and the value grew by one.
        let bytes = u64::from_le_bytes(v[16..24].try_into().unwrap()) + 1;
        v[16..24].copy_from_slice(&bytes.to_le_bytes());
        v.push(7);
        v
    }

    /// Every way a tree-node body can be wrong, each paired with the parse error
    /// that proves the corruption is the one named — a test that only checked
    /// "invalid" would pass even if a corruption broke something else.
    fn malformed_nodes() -> Vec<(&'static str, Vec<u8>, NodeError)> {
        let truncated = {
            let mut v = leaf_node();
            v.pop();
            v
        };
        let flipped_key = {
            let mut v = leaf_node();
            let at = v.windows(3).position(|w| w == b"aaa").unwrap();
            v[at] ^= 1;
            v
        };
        let unsorted = {
            let mut v = leaf_node();
            swap_all(&mut v, b"aaa", b"bbb");
            v
        };
        let wrong_agg = {
            let mut v = leaf_node();
            v[8] ^= 1; // agg.count
            v
        };
        vec![
            // The last entry now runs past the end of the node.
            ("truncated", truncated, NodeError::BadEntry),
            ("flipped key byte", flipped_key, NodeError::BadKeyPrefix),
            ("unsorted keys", unsorted, NodeError::KeysNotSorted),
            ("wrong aggregate", wrong_agg, NodeError::AggMismatch),
            (
                "1025 B inline value",
                oversized_inline_value(),
                NodeError::NonCanonicalValue,
            ),
            (
                "not a node at all",
                b"hello, this is plainly not a PT01 node".to_vec(),
                NodeError::BadMagic,
            ),
            (
                "too short to be a node",
                b"PT01".to_vec(),
                NodeError::TooShort,
            ),
        ]
    }

    /// Control split rule: close a node once it reaches 4 KiB. It depends on
    /// position, not content — exactly what the format's rule is not.
    fn by_size(_: u8, _: &[u8], _: usize, after: usize) -> bool {
        after >= 4096
    }

    /// Every node of a real tree over the same 2000 entries, cut by `rule`.
    fn tree_nodes(rule: fn(u8, &[u8], usize, usize) -> bool) -> Vec<Vec<u8>> {
        let mut nodes: Vec<Vec<u8>> = Vec::new();
        let mut t = TreeBuilder::with_rule(rule, |_, b: &[u8]| nodes.push(b.to_vec()));
        let value = vec![b'v'; 100];
        for i in 0..2000u32 {
            t.push(format!("d/post/{i:08}").as_bytes(), Value::Inline(&value))
                .unwrap();
        }
        t.finish().unwrap();
        nodes
    }

    /// A node that **parses** but was cut in the wrong place: the same entries
    /// chunked by position instead of by content. A node the format's rule
    /// would have ended earlier is refused, so this is the case that separates
    /// "well-formed bytes" from "a node this tree could have produced".
    fn miscut_node() -> Vec<u8> {
        let found = tree_nodes(by_size).into_iter().find(|b| {
            matches!(
                check_node(&Node::parse(b).unwrap()),
                Err(BoundaryError::InteriorSplit(_))
            )
        });
        // About half of them should be; assert rather than assume.
        found.expect("a positionally cut node that breaks the split rule")
    }

    /// The worst case a host can be handed: a leaf filled to the 12 KiB measure
    /// with the smallest entries the format allows, so the per-entry pass runs
    /// as many times as it ever can. Keys are chosen so the rule never fires.
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

    /// The same vectors are frozen in freenet-prolly (`tests/vectors.txt`, `id`
    /// lines): a tree's child pointers must be exactly these params.
    ///
    /// An id is about addressing, not about content: the third vector is the id
    /// of a tree-node block whose body is not a node, so it is the right id for
    /// a state the contract now refuses to hold. Both halves are asserted.
    #[test]
    fn block_ids_match_the_tree_library() {
        fn hex(b: &[u8]) -> String {
            b.iter().map(|x| format!("{x:02x}")).collect()
        }
        for (k, body, want) in [
            (
                kind::RAW,
                &b""[..],
                "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
            ),
            (
                kind::RAW,
                b"value",
                "2585d5bd187a38e8206be259760a812f6746eed27edbad08606d7d52e38a0e74",
            ),
            (
                kind::TREE_NODE,
                b"value",
                "89e4038bf5c0681ed10512a02b00493e0473e1e09e7d8914d4cb00c66cfd1507",
            ),
        ] {
            let s = encode(k, body);
            assert_eq!(hex(blake3::hash(&s).as_bytes()), want);
            let expect = if k == kind::TREE_NODE {
                ValidateResult::Invalid // "value" is not a PT01 node
            } else {
                ValidateResult::Valid
            };
            assert_eq!(validate(params_of(&s), s), expect);
        }
        // A real node under the same id rule is held.
        let s = encode(kind::TREE_NODE, &leaf_node());
        assert_eq!(validate(params_of(&s), s), ValidateResult::Valid);
    }

    #[test]
    fn a_block_is_valid_only_under_its_own_hash() {
        let s = encode(kind::RAW, b"hello");
        assert_eq!(validate(params_of(&s), s.clone()), ValidateResult::Valid);
        assert_eq!(validate(params_of(b"other"), s), ValidateResult::Invalid);
    }

    #[test]
    fn unknown_kind_and_oversize_are_refused() {
        let s = encode(200, b"x");
        assert_eq!(validate(params_of(&s), s), ValidateResult::Invalid);
        let big = encode(kind::RAW, &vec![0u8; MAX_BODY + 1]);
        assert_eq!(validate(params_of(&big), big), ValidateResult::Invalid);
    }

    #[test]
    fn empty_adopts_the_valid_candidate_and_ignores_garbage() {
        let s = encode(kind::TREE_NODE, &leaf_node());
        let got = update(params_of(&s), vec![], vec![b"garbage".to_vec(), s.clone()]);
        assert_eq!(got, s);
    }

    #[test]
    fn a_held_block_never_changes() {
        let s = encode(kind::RAW, b"first");
        let other = encode(kind::RAW, b"second");
        assert_eq!(update(params_of(&s), s.clone(), vec![other]), s);
    }

    /// Negative control: with the hash check removed the test above would pass
    /// for the wrong reason, so prove a wrong-hash candidate is NOT adopted.
    #[test]
    fn wrong_hash_candidate_is_not_adopted() {
        let s = encode(kind::RAW, b"real");
        let forged = encode(kind::RAW, b"forged");
        assert!(update(params_of(&s), vec![], vec![forged]).is_empty());
    }

    #[test]
    fn delta_is_sent_only_to_a_peer_that_lacks_the_block() {
        let s = encode(kind::RAW, b"x");
        let p = params_of(&s);
        let d = |sum: Vec<u8>| {
            Block::get_state_delta(p.clone(), State::from(s.clone()), StateSummary::from(sum))
                .unwrap()
                .as_ref()
                .to_vec()
        };
        assert!(d(vec![1]).is_empty());
        assert_eq!(d(vec![0]), s);
    }

    /// The kind byte is hashed into every block id, so a change to one of the
    /// two the tree library also names would silently re-address every block.
    /// The literals are the frozen wire values; the re-export makes the two
    /// crates one definition, and this is what fails if that definition moves.
    #[test]
    fn kind_bytes_are_frozen() {
        // These two carry the test: they are the frozen wire values.
        assert_eq!(kind::RAW, 0);
        assert_eq!(kind::TREE_NODE, 1);
        // Identity by construction while the re-export stands, not a drift
        // check — they are here so that restating the constants locally, which
        // is what could drift, fails this test instead of passing it.
        assert_eq!(kind::RAW, freenet_prolly::kind::RAW);
        assert_eq!(kind::TREE_NODE, freenet_prolly::kind::TREE_NODE);
        // Kinds the tree library does not define keep their own bytes here.
        assert_eq!(
            [
                kind::MEDIA_CHUNK,
                kind::FRAGMENT,
                kind::PARITY,
                kind::SCHEMA
            ],
            [2, 3, 4, 5]
        );
    }

    #[test]
    fn nodes_the_tree_library_built_are_valid() {
        for body in [leaf_node(), branch_node()] {
            assert!(Node::parse(&body).is_ok());
            let s = encode(kind::TREE_NODE, &body);
            assert_eq!(validate(params_of(&s), s), ValidateResult::Valid);
        }
    }

    /// The direction that matters more than refusing bad nodes: a host that
    /// refused *good* ones would drop data the network is meant to keep. Every
    /// node of a real multi-level tree — leaves, branches, the root, the last
    /// node of each level, which legitimately ends without a split — is Valid.
    #[test]
    fn every_node_of_a_real_tree_is_valid() {
        let nodes = tree_nodes(splits_after);
        assert!(nodes.len() > 20, "{} nodes is not a real tree", nodes.len());
        let mut levels = std::collections::BTreeSet::new();
        for body in &nodes {
            levels.insert(Node::parse(body).unwrap().level());
            let s = encode(kind::TREE_NODE, body);
            assert_eq!(
                validate(params_of(&s), s),
                ValidateResult::Valid,
                "a node the format's own chunker produced was refused"
            );
        }
        assert!(
            levels.len() > 1,
            "only level(s) {levels:?} — not multi-level"
        );
    }

    #[test]
    fn a_malformed_node_is_refused_even_at_its_own_hash() {
        for (what, body, want) in malformed_nodes() {
            assert_eq!(Node::parse(&body).unwrap_err(), want, "{what}");
            let s = encode(kind::TREE_NODE, &body);
            // params = blake3(state): the hash is right, only the body is wrong.
            assert_eq!(
                validate(params_of(&s), s),
                ValidateResult::Invalid,
                "{what}"
            );
        }
    }

    /// A node can be well-formed and still not be a node this tree could have
    /// produced. One cut in the wrong place is refused, and the entries are
    /// intact — so the refusal is about the boundary, nothing else.
    #[test]
    fn a_well_formed_but_mis_cut_node_is_refused() {
        let body = miscut_node();
        let node = Node::parse(&body).expect("it parses");
        assert!(node.len() > 1);
        assert!(matches!(
            check_node(&node),
            Err(BoundaryError::InteriorSplit(_))
        ));
        let s = encode(kind::TREE_NODE, &body);
        assert_eq!(validate(params_of(&s), s), ValidateResult::Invalid);
    }

    /// Negative control: the same bytes are kept under a kind with no format
    /// yet, so the rejections above come from the kind check and not from
    /// hashing, sizing, or the bodies being odd in some other way.
    #[test]
    fn the_same_bodies_are_valid_as_raw_blocks() {
        let bodies = malformed_nodes()
            .into_iter()
            .map(|(what, body, _)| (what, body))
            .chain([("mis-cut but well-formed", miscut_node())]);
        for (what, body) in bodies {
            let s = encode(kind::RAW, &body);
            assert_eq!(validate(params_of(&s), s), ValidateResult::Valid, "{what}");
        }
    }

    /// The cost of the check on the worst case a host can be handed. Printed by
    /// `cargo test --release -- --nocapture`; the assertion only keeps the
    /// measurement honest about what it measured.
    #[test]
    fn worst_case_validate_cost() {
        let body = worst_case_leaf();
        let entries = Node::parse(&body).unwrap().len();
        let s = encode(kind::TREE_NODE, &body);
        let p = blake3::hash(&s).as_bytes().to_vec();
        assert!(check(&p, &s));
        let runs = 200;
        let t = std::time::Instant::now();
        for _ in 0..runs {
            assert!(check(&p, &s));
        }
        println!(
            "worst case: {entries} entries, {} B body; check() = {:?} each",
            body.len(),
            t.elapsed() / runs
        );
        assert!(entries > 500, "{entries} entries is not the worst case");
    }

    /// A held tree node is never displaced, and a malformed one is never
    /// adopted — not by an empty candidate, not by garbage, and not by a
    /// malformed node carrying its own correct hash.
    #[test]
    fn a_tree_node_block_cannot_be_displaced_or_poisoned() {
        let held = encode(kind::TREE_NODE, &leaf_node());
        let p = params_of(&held);
        let mut attempts = vec![Vec::new(), b"garbage".to_vec()];
        attempts.extend(
            malformed_nodes()
                .into_iter()
                .map(|(_, body, _)| body)
                // The dangerous one: a body that parses, so only the boundary
                // check stands between it and the store.
                .chain([miscut_node()])
                .map(|body| encode(kind::TREE_NODE, &body)),
        );
        assert_eq!(
            update(p.clone(), held.clone(), attempts.clone()),
            held,
            "held state changed"
        );
        // From empty, none of them is adopted even under its own params.
        for a in attempts {
            assert!(
                update(params_of(&a), Vec::new(), vec![a.clone()]).is_empty(),
                "adopted {a:?}"
            );
        }
    }
}
