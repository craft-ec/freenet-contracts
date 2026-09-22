//! The node's contract ABI, by hand (the entry points `#[contract]` used to generate). Wasm only, behind
//! `freenet-main-contract`, so nothing that links this crate natively -- or into another wasm (`wasm-check`) --
//! gets these exports. (A copy of `block/src/abi.rs`: see lib.rs for why not shared.)
//!
//! - `__frnt__initiate_buffer(cap)`: the host asks for one buffer per argument and writes it WHOLE. This module
//!   imports nothing from `freenet_contract_io`, so the node takes its LEGACY path (freenet 0.2.136,
//!   `module_has_streaming_io`): no length header and no refills; the argument is `start .. start + *last_write`.
//! - each entry point returns a `ContractInterfaceResult { ptr, kind, size }` over the bytes [`crate::doors`] made.
//!
//! The node drops the instance after each call, so what is allocated here is never freed.

use crate::doors;

/// freenet-stdlib's `BufferBuilder`, `#[repr(C)]`.
#[repr(C)]
struct BufferBuilder {
    start: i64,
    capacity: u32,
    last_read: i64,
    last_write: i64,
}

#[no_mangle]
pub extern "C" fn __frnt__initiate_buffer(capacity: u32) -> i64 {
    let buf: Vec<u8> = Vec::with_capacity(capacity as usize);
    let start = buf.as_ptr() as i64;
    core::mem::forget(buf);
    let last_read = Box::into_raw(Box::new(0u32)) as i64;
    let last_write = Box::into_raw(Box::new(0u32)) as i64;
    Box::into_raw(Box::new(BufferBuilder {
        start,
        capacity,
        last_read,
        last_write,
    })) as i64
}

/// The bytes the host wrote into buffer `ptr`.
///
/// # Safety
/// `ptr` is a buffer `__frnt__initiate_buffer` made, written by the host.
unsafe fn arg<'a>(ptr: i64) -> &'a [u8] {
    let b = &*(ptr as usize as *const BufferBuilder);
    let written = *(b.last_write as usize as *const u32) as usize;
    core::slice::from_raw_parts(
        b.start as usize as *const u8,
        written.min(b.capacity as usize),
    )
}

/// freenet-stdlib's `ContractInterfaceResult`, `#[repr(C)]`.
#[repr(C)]
struct Answer {
    ptr: i64,
    kind: i32,
    size: u32,
}

fn answer(kind: i32, bytes: &[u8]) -> i64 {
    let bytes: &'static [u8] = Vec::leak(bytes.to_vec());
    Box::into_raw(Box::new(Answer {
        ptr: bytes.as_ptr() as i64,
        kind,
        size: bytes.len() as u32,
    })) as i64
}

#[no_mangle]
pub unsafe extern "C" fn validate_state(params: i64, state: i64, _related: i64) -> i64 {
    answer(
        doors::KIND_VALIDATE,
        doors::validate(arg(params), arg(state)),
    )
}

#[no_mangle]
pub unsafe extern "C" fn update_state(params: i64, state: i64, updates: i64) -> i64 {
    answer(
        doors::KIND_UPDATE,
        &doors::update(arg(params), arg(state), arg(updates)),
    )
}

#[no_mangle]
pub unsafe extern "C" fn summarize_state(_params: i64, state: i64) -> i64 {
    answer(doors::KIND_SUMMARIZE, &doors::summarize(arg(state)))
}

#[no_mangle]
pub unsafe extern "C" fn get_state_delta(_params: i64, state: i64, summary: i64) -> i64 {
    answer(doors::KIND_DELTA, &doors::delta(arg(state), arg(summary)))
}
