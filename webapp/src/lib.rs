//! Web app contract: an immutable, hash-keyed WEB CONTAINER (builder#104).
//!
//! The node serves `/v1/contract/web/<key>/` from any contract whose STATE is
//! its web container (freenet 0.2.136, `server/app_packaging.rs`):
//!
//! ```text
//! [metadata length: u64 BE][metadata: ≤ 1 KiB][web length: u64 BE][web: an xz-compressed tar]
//! ```
//!
//! This contract decides only which states are valid:
//!
//! - **Params = blake3(state)**, 32 bytes. The ADDRESS is the hash, so a
//!   container cannot change without changing its address — no key, no
//!   signature, nothing to steal. The same bytes published twice are one
//!   contract.
//! - **Valid** = the hash matches, the state is within [`MAX_STATE`], and it
//!   parses as the node's framing EXACTLY: metadata ≤ [`MAX_METADATA`], the web
//!   part's length is what is left, no trailing bytes. One encoding per content.
//!   The web part is not decompressed here: the node unpacks it (refusing links
//!   and escaping paths) when it serves it, and a contract that inflated xz on
//!   every validation would hand every stranger a decompression bomb.
//! - **Merge** = an empty state adopts the first valid candidate; a held state
//!   never changes (as Block's). Exactly one byte string hashes to `params`.
//!
//! Entry points: the node's ABI by hand (`abi.rs`), the answers' bytes in
//! `doors.rs` — the same shape as `block/`, copied rather than shared, because
//! sharing code with `block/` would change block's bytes and so its released hash.

pub mod doors;
#[cfg(all(target_family = "wasm", feature = "freenet-main-contract"))]
mod abi;

#[cfg(test)]
use freenet_stdlib::prelude::*;
#[cfg(test)]
pub use stdlib_shape::Block as WebApp;

pub const PARAMS_LEN: usize = 32;
/// The node's own metadata limit (`MAX_METADATA_SIZE`, 1 KiB).
pub const MAX_METADATA: usize = 1024;
/// The largest container, framing included. Below the node's 100 MiB web limit
/// by design: an app's container carries JavaScript and its definition, and the
/// shared artefacts container four wasm files (~1.7 MB today) — a stated bound on
/// what one PUT asks every host to store.
pub const MAX_STATE: usize = 16 * 1024 * 1024;

/// The node's framing, parsed exactly. `None` for anything else.
pub fn framing(state: &[u8]) -> Option<(&[u8], &[u8])> {
    let (m, rest) = state.split_at_checked(8)?;
    let mlen = usize::try_from(u64::from_be_bytes(m.try_into().ok()?)).ok()?;
    if mlen > MAX_METADATA {
        return None;
    }
    let (meta, rest) = rest.split_at_checked(mlen)?;
    let (w, web) = rest.split_at_checked(8)?;
    let wlen = usize::try_from(u64::from_be_bytes(w.try_into().ok()?)).ok()?;
    // EXACTLY the rest: a trailing byte would give one content two encodings,
    // and so two addresses.
    (wlen == web.len() && wlen > 0).then_some((meta, web))
}

/// The one check every entry point shares.
pub fn check(params: &[u8], state: &[u8]) -> bool {
    params.len() == PARAMS_LEN
        && !state.is_empty()
        // Size first: an oversized state costs a comparison, not a hash.
        && state.len() <= MAX_STATE
        // THE HASH BEFORE THE FORM: one BLAKE3 pass settles whether these
        // bytes belong under this key at all, and the parse only ever runs on
        // the one string that does.
        && blake3::hash(state).as_bytes() == params
        && framing(state).is_some()
}

/// A container in the node's framing, for tests and for the vectors corpus.
pub fn encode(metadata: &[u8], web: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(16 + metadata.len() + web.len());
    v.extend_from_slice(&(metadata.len() as u64).to_be_bytes());
    v.extend_from_slice(metadata);
    v.extend_from_slice(&(web.len() as u64).to_be_bytes());
    v.extend_from_slice(web);
    v
}
#[cfg(test)]
mod stdlib_shape {
    use freenet_stdlib::prelude::*;

    pub struct Block;

    /// Decode a door's answer, and require it to be the stdlib's own encoding of what it decodes to.
    fn read<'a, T: serde::Deserialize<'a> + serde::Serialize>(bytes: &'a [u8]) -> T {
        let v: T = bincode::deserialize(bytes).expect("a door's bytes decode as the stdlib type");
        assert_eq!(
            bincode::serialize(&v).expect("re-encodes"),
            bytes,
            "a door's bytes are not the stdlib encoding of what they decode to"
        );
        v
    }

    impl ContractInterface for Block {
        fn validate_state(
            p: Parameters<'static>,
            s: State<'static>,
            _: RelatedContracts<'static>,
        ) -> Result<ValidateResult, ContractError> {
            read(crate::doors::validate(p.as_ref(), s.as_ref()))
        }

        fn update_state(
            p: Parameters<'static>,
            s: State<'static>,
            data: Vec<UpdateData<'static>>,
        ) -> Result<UpdateModification<'static>, ContractError> {
            let wire = bincode::serialize(&data).expect("updates encode");
            let bytes = crate::doors::update(p.as_ref(), s.as_ref(), &wire);
            let r: Result<UpdateModification<'_>, ContractError> = read(&bytes);
            r.map(|m| m.into_owned())
        }

        fn summarize_state(
            _: Parameters<'static>,
            s: State<'static>,
        ) -> Result<StateSummary<'static>, ContractError> {
            let bytes = crate::doors::summarize(s.as_ref());
            let r: Result<StateSummary<'_>, ContractError> = read(&bytes);
            r.map(|x| StateSummary::from(x.as_ref().to_vec()))
        }

        fn get_state_delta(
            _: Parameters<'static>,
            s: State<'static>,
            summary: StateSummary<'static>,
        ) -> Result<StateDelta<'static>, ContractError> {
            let bytes = crate::doors::delta(s.as_ref(), summary.as_ref());
            let r: Result<StateDelta<'_>, ContractError> = read(&bytes);
            r.map(|x| StateDelta::from(x.as_ref().to_vec()))
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn container(web_len: usize) -> Vec<u8> {
        encode(br#"{"app":"t"}"#, &vec![0x5a; web_len])
    }
    fn params_of(state: &[u8]) -> Parameters<'static> {
        Parameters::from(blake3::hash(state).as_bytes().to_vec())
    }
    fn validate(p: Parameters<'static>, s: Vec<u8>) -> ValidateResult {
        WebApp::validate_state(p, State::from(s), Default::default()).unwrap()
    }

    #[test]
    fn a_well_formed_container_is_valid_under_its_own_hash_and_no_other() {
        let s = container(4096);
        assert_eq!(validate(params_of(&s), s.clone()), ValidateResult::Valid);
        assert_eq!(validate(params_of(b"other"), s), ValidateResult::Invalid);
    }

    /// Each framing defect, under ITS OWN hash, so the hash is not what refuses it.
    #[test]
    fn every_framing_defect_is_refused_even_under_its_own_hash() {
        let good = container(100);
        let mut trailing = good.clone();
        trailing.push(0);
        let mut short_web = good.clone();
        short_web.pop();
        let mut lying_meta = good.clone();
        lying_meta[..8].copy_from_slice(&5000u64.to_be_bytes());
        let big_meta = encode(&vec![b'm'; MAX_METADATA + 1], b"w");
        let empty_web = encode(b"m", b"");
        for (what, s) in [
            ("a trailing byte", trailing),
            ("a web part shorter than it says", short_web),
            ("a metadata length that lies", lying_meta),
            ("metadata over the node's 1 KiB", big_meta),
            ("an empty web part", empty_web),
            ("seven bytes", vec![0; 7]),
        ] {
            assert_eq!(validate(params_of(&s), s), ValidateResult::Invalid, "{what} was accepted");
        }
        // THE CONTROL: at the metadata limit exactly, it parses.
        let at_limit = encode(&vec![b'm'; MAX_METADATA], b"w");
        assert_eq!(validate(params_of(&at_limit), at_limit), ValidateResult::Valid);
    }

    #[test]
    fn a_container_over_the_cap_is_refused_and_one_at_it_is_not() {
        let at = container(MAX_STATE - 16 - 11);
        assert_eq!(at.len(), MAX_STATE);
        assert_eq!(validate(params_of(&at), at), ValidateResult::Valid);
        let over = container(MAX_STATE - 16 - 11 + 1);
        assert_eq!(validate(params_of(&over), over), ValidateResult::Invalid);
    }

    #[test]
    fn a_held_container_never_changes_and_an_empty_one_adopts_the_valid_one() {
        let s = container(64);
        let p = params_of(&s);
        let held = WebApp::update_state(p.clone(), State::from(s.clone()), vec![UpdateData::State(State::from(container(65)))])
            .unwrap();
        assert_eq!(held.new_state.map(|x| x.as_ref().to_vec()), Some(s.clone()));
        let adopted = WebApp::update_state(p, State::from(vec![]), vec![
            UpdateData::State(State::from(container(65))),
            UpdateData::State(State::from(s.clone())),
        ])
        .unwrap();
        assert_eq!(adopted.new_state.map(|x| x.as_ref().to_vec()), Some(s));
    }
}
