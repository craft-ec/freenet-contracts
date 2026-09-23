//! Site contract: a publisher's web app at ONE stable address, updated in
//! place (builder#117). The address is the contract key, so it names the
//! PUBLISHER and the APP, never the bytes: republishing moves the version,
//! not the link — Freenet's standard web container (River's
//! web-container-contract, freenet-core's website-contract), with the
//! identity's Register authority instead of one key.
//!
//! The node serves `/v1/contract/web/<key>/` from a state in its web framing
//! (freenet 0.2.136, `server/app_packaging.rs`):
//!
//! ```text
//! [metadata length: u64 BE][metadata: ≤ 1 KiB][web length: u64 BE][web: an xz-compressed tar]
//! ```
//!
//! - **Params** = the identity's Register params, `RG01 ‖ mode ‖ authority ‖
//!   label`, with the label `site:<app id>` (the app id under the SDK's
//!   `app::check` rule). One key or k of n — every device of one person
//!   publishes the same app at the same address (rule 15).
//! - **Metadata** = a Register STATE whose record is `(seq = version, value =
//!   blake3(web))`, carrying fork evidence when there is any. Parsed and
//!   verified by the Register's own code: one authority scheme, and
//!   register.wasm untouched (any edit to it re-keys every head).
//! - **Valid** = the exact framing, a verified metadata state holding a
//!   non-terminal record whose value is blake3 of the web part, within the
//!   sizes below. The web part is not decompressed here (the node unpacks it
//!   when it serves it).
//! - **Merge** = the Register's own join on the metadata (`merge::update`:
//!   the higher version, then the LOWER bundle hash, fork evidence kept), and
//!   the web part is the one the winning record names. A semilattice because
//!   the Register's is, and the web follows a record by its hash.
//! - **Signing** is the Register's: `RG01-sig ‖ blake3(params) ‖ terminal ‖
//!   seq ‖ value hash`. The label keeps each app's signatures, and the head's,
//!   apart (architect, builder#117).
//!
//! Entry points: the node's ABI by hand (`abi.rs`), the answers' bytes in
//! `doors.rs` — copies of webapp's, because sharing code with another contract
//! changes that contract's bytes and so its released hash.

pub mod doors;

#[cfg(all(target_family = "wasm", feature = "freenet-main-contract"))]
mod abi;

use craftec_register_contract::merge;
use craftec_register_contract::wire::{Authority, Params, RegState};

/// The node's own metadata limit (`MAX_METADATA_SIZE`, 1 KiB).
pub const MAX_METADATA: usize = 1024;
/// The largest site, framing included: webapp's bound, for the same reason.
pub const MAX_STATE: usize = 16 * 1024 * 1024;
/// A site's label: `site:` then its app id.
pub const LABEL_PREFIX: &[u8] = b"site:";
/// The app id rule, the SDK's `app::check`: 1–32 of `[a-z0-9_-]`.
pub const MAX_APP_ID: usize = 32;

/// Is `id` an app id by the SDK's rule (`app::check`: `^[a-z0-9_-]{1,32}$`)?
pub fn app_id_ok(id: &[u8]) -> bool {
    (1..=MAX_APP_ID).contains(&id.len())
        && id.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}

/// The largest metadata `a` can ever need: a record with its signatures AND
/// fork evidence (two signed decisions). A same-version publish from two
/// devices is exactly what creates evidence, so the bound is the worst case,
/// not the common one (architect, builder#117 condition 2). The Register's
/// encoding: `RG01 flags | record (terminal, seq, vlen, 32-byte value,
/// signatures) | evidence (2 × (terminal, seq, value hash, signatures))`.
pub fn worst_metadata(a: &Authority) -> usize {
    let bitmap = match a {
        Authority::One(_) => 0,
        Authority::Quorum { .. } => 2,
    };
    let sigs = bitmap + a.sigs_required() * 64;
    let record = 1 + 8 + 2 + 32 + sigs;
    let signed = 1 + 8 + 32 + sigs;
    4 + 1 + record + 2 * signed
}

/// A site's params: the Register's, labelled `site:<app id>`, whose worst-case
/// metadata fits the node's limit. `None` for anything else — including an
/// authority too large to ever carry its own fork evidence (k ≤ 4 in k-of-n).
pub fn params(b: &[u8]) -> Option<Params> {
    let p = Params::parse(b)?;
    let app = p.label.strip_prefix(LABEL_PREFIX)?;
    (app_id_ok(app) && worst_metadata(&p.authority) <= MAX_METADATA).then_some(p)
}

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
    // EXACTLY the rest: a trailing byte would give one content two encodings.
    (wlen == web.len() && wlen > 0).then_some((meta, web))
}

/// A state in the node's framing.
pub fn encode(metadata: &[u8], web: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(16 + metadata.len() + web.len());
    v.extend_from_slice(&(metadata.len() as u64).to_be_bytes());
    v.extend_from_slice(metadata);
    v.extend_from_slice(&(web.len() as u64).to_be_bytes());
    v.extend_from_slice(web);
    v
}

/// A valid site, parsed: its metadata state and its web part.
pub struct Site<'a> {
    pub reg: RegState,
    pub web: &'a [u8],
}

/// Parse and verify a whole state against its params.
pub fn parse<'a>(p: &Params, state: &'a [u8]) -> Option<Site<'a>> {
    if state.is_empty() || state.len() > MAX_STATE {
        return None;
    }
    let (meta, web) = framing(state)?;
    let reg = RegState::parse(meta, p)?;
    let rec = reg.record.as_ref()?;
    // A version names its bundle: the record's value IS the web part's hash.
    // A terminal record would end the site; a site is superseded by its next
    // version, never ended.
    (!rec.signed.terminal && rec.value.as_slice() == blake3::hash(web).as_bytes()).then_some(Site { reg, web })
}

/// The one validity check every entry point shares.
pub fn check(params_bytes: &[u8], state: &[u8]) -> bool {
    params(params_bytes).is_some_and(|p| parse(&p, state).is_some())
}

/// The merge of two VALID states: the Register's join on the metadata, and the
/// web part the winning record names. On equal decisions the Register keeps the
/// FIRST argument's record (the held one), so a re-signed duplicate changes
/// nothing — and the web follows it.
pub fn merge(p: &Params, held: &Site<'_>, other: &Site<'_>) -> Vec<u8> {
    let reg = merge::update(&held.reg, &other.reg, &p.authority);
    let winner = reg.record.as_ref().expect("a join of two records holds one");
    let web = if winner.value == held.reg.record.as_ref().expect("valid").value { held.web } else { other.web };
    encode(&reg.encode(&p.authority), web)
}

#[cfg(test)]
mod tests;
