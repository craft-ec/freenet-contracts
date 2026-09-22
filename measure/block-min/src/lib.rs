//! MEASUREMENT ONLY (sdk, owner's ask): the smallest Block contract freenet 0.2.136 will run.
//! NOT wired, NOT released, NOT a hash anywhere: a different block contract re-keys every block, and that is the
//! owner's decision alone.
//!
//! Valid = `blake3(state) == params`, where state = kind ‖ body, so this is `block_id(kind, body) == params`.
//! It is WEAKER than `block/`: no size cap, no per-kind well-formedness (tree-node boundaries, packs, parity).
//! update_state refuses (`InvalidUpdate`); summarize / delta answer empty.
//!
//! No freenet-stdlib, no std, no formatting, no allocator crate. The node's contract ABI is restated by hand:
//! - the host asks `__frnt__initiate_buffer(cap) -> *BufferBuilder` for each argument and writes it whole
//!   (the LEGACY path, taken because this module does not import `__frnt__fill_buffer`);
//! - each entry point returns `*ContractInterfaceResult { ptr, kind, size }` over bincode (fixint, LE) bytes.
//! Memory is a bump allocator over `__heap_base`, grown with `memory.grow`, never freed: the node drops the
//! instance after each call.
#![no_std]

use core::arch::wasm32;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    wasm32::unreachable()
}

extern "C" {
    static __heap_base: u8;
}

static mut NEXT: usize = 0;

/// `n` bytes, 8-aligned; null when memory cannot grow.
unsafe fn alloc(n: usize) -> *mut u8 {
    if NEXT == 0 {
        NEXT = core::ptr::addr_of!(__heap_base) as usize;
    }
    let start = (NEXT + 7) & !7;
    let end = start + n;
    let have = wasm32::memory_size(0) * 65536;
    if end > have {
        let pages = (end - have).div_ceil(65536);
        if wasm32::memory_grow(0, pages) == usize::MAX {
            return core::ptr::null_mut();
        }
    }
    NEXT = end;
    start as *mut u8
}

/// freenet-stdlib's `BufferBuilder`, `#[repr(C)]`.
#[repr(C)]
struct BufferBuilder {
    start: i64,
    capacity: u32,
    last_read: i64,
    last_write: i64,
}

#[no_mangle]
pub unsafe extern "C" fn __frnt__initiate_buffer(capacity: u32) -> i64 {
    let data = alloc(capacity as usize);
    let counters = alloc(8) as *mut u32;
    let b = alloc(core::mem::size_of::<BufferBuilder>()) as *mut BufferBuilder;
    if data.is_null() || counters.is_null() || b.is_null() {
        wasm32::unreachable()
    }
    *counters = 0;
    *counters.add(1) = 0;
    *b = BufferBuilder {
        start: data as i64,
        capacity,
        last_read: counters as i64,
        last_write: counters.add(1) as i64,
    };
    b as i64
}

/// The bytes the host wrote into a buffer.
unsafe fn arg<'a>(ptr: i64) -> &'a [u8] {
    let b = &*(ptr as usize as *const BufferBuilder);
    let written = *(b.last_write as usize as *const u32) as usize;
    core::slice::from_raw_parts(b.start as usize as *const u8, written.min(b.capacity as usize))
}

/// freenet-stdlib's `ContractInterfaceResult`, `#[repr(C)]`.
#[repr(C)]
struct Answer {
    ptr: i64,
    kind: i32,
    size: u32,
}

static mut ANSWER: Answer = Answer { ptr: 0, kind: 0, size: 0 };

// bincode 1 (fixint, little-endian, u32 variant tags) of each answer this contract gives.
static OK_VALID: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0]; // Ok(ValidateResult::Valid)
static OK_INVALID: [u8; 8] = [0, 0, 0, 0, 1, 0, 0, 0]; // Ok(ValidateResult::Invalid)
static ERR_INVALID_UPDATE: [u8; 8] = [1, 0, 0, 0, 1, 0, 0, 0]; // Err(ContractError::InvalidUpdate)
static OK_EMPTY_BYTES: [u8; 12] = [0; 12]; // Ok(StateSummary / StateDelta of zero bytes)

unsafe fn answer(kind: i32, bytes: &'static [u8]) -> i64 {
    ANSWER = Answer {
        ptr: bytes.as_ptr() as i64,
        kind,
        size: bytes.len() as u32,
    };
    core::ptr::addr_of!(ANSWER) as i64
}

#[no_mangle]
pub unsafe extern "C" fn validate_state(params: i64, state: i64, _related: i64) -> i64 {
    let (p, s) = (arg(params), arg(state));
    let ok = p.len() == 32 && !s.is_empty() && blake3::hash(s).as_bytes()[..] == p[..];
    answer(0, if ok { &OK_VALID } else { &OK_INVALID })
}

#[no_mangle]
pub unsafe extern "C" fn update_state(_params: i64, _state: i64, _delta: i64) -> i64 {
    answer(2, &ERR_INVALID_UPDATE)
}

#[no_mangle]
pub unsafe extern "C" fn summarize_state(_params: i64, _state: i64) -> i64 {
    answer(3, &OK_EMPTY_BYTES)
}

#[no_mangle]
pub unsafe extern "C" fn get_state_delta(_params: i64, _state: i64, _summary: i64) -> i64 {
    answer(4, &OK_EMPTY_BYTES)
}
