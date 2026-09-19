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
pub mod kind {
    pub const RAW: u8 = 0;
    pub const TREE_NODE: u8 = 1;
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
fn well_formed(kind: u8, _body: &[u8]) -> bool {
    matches!(
        kind,
        kind::RAW
            | kind::TREE_NODE
            | kind::MEDIA_CHUNK
            | kind::FRAGMENT
            | kind::PARITY
            | kind::SCHEMA
    )
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

    /// The same vectors are frozen in freenet-prolly (`tests/vectors.txt`, `id`
    /// lines): a tree's child pointers must be exactly these params.
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
            assert_eq!(validate(params_of(&s), s), ValidateResult::Valid);
        }
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
        let s = encode(kind::TREE_NODE, b"node");
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
}
