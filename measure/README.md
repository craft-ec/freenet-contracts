# MEASUREMENT ONLY: how small can the Block contract be?

The owner asked for this number. **Nothing here is wired, released, or hashed.** Root `build.sh` builds only
`*/build.sh`, and nothing under `measure/` has one. A different block contract re-keys every block, so changing
it is the owner's decision alone.

## The contracts

| | wasm (after `wasm-opt -Os`, the flags `block/` ships with) | before wasm-opt |
|---|---:|---:|
| `block/` (released, the control) | **101,641 B** | — |
| `block-stdlib-min/`: block-min's rule, written through freenet-stdlib's `#[contract]` | **76,271 B** | 88,388 B |
| `block-min/`: the same rule, hand-written against the node's ABI, `no_std` | **9,718 B** | 10,996 B |

- **The rule, in both minimal crates:**
  - valid = `blake3(state) == params`, where state = kind ‖ body, which is `freenet_prolly::block_id(kind, body)`;
  - `update_state` refuses (`InvalidUpdate`);
  - summary and delta are empty.
- **Both are WEAKER than `block/`.** They have no size cap and no per-kind well-formedness checks (tree-node
  boundaries, packs, parity).
- **Where the bytes go** (read from the table):
  - freenet-stdlib's `#[contract]` interface on its own is ~76 KB;
  - `block/`'s own logic is the other ~25 KB;
  - block-min's 9,718 B is 9,421 B of code, almost all blake3.
- **block-min has 0 imports.** It exports `memory`, `__frnt__initiate_buffer`, `validate_state`, `update_state`,
  `summarize_state` and `get_state_delta`. It does not import `__frnt__fill_buffer`, so the node takes the legacy
  buffer path and writes each argument whole. It uses a bump allocator over `__heap_base`, since the node drops
  the instance after each call. There is no std, no formatting and no allocator crate.
- **Build:**
  - block-min: `RUSTC_BOOTSTRAP=1 RUSTFLAGS=-Zlocation-detail=none cargo build --release --target wasm32-unknown-unknown`;
  - then `wasm-opt -Os --enable-bulk-memory-opt --enable-bulk-memory` (binaryen 125);
  - the toolchain is the repo's 1.97.1.

## Does freenet 0.2.136 load it? Yes (live, 2026-09-22)

`live-min-block.rs` ran as a scratch bin inside the SDK's `probe` crate. It used one private node in isolated
network mode, with its ports refused if in use and its own temp dirs. Each contract got the same five calls:

| | block-min | block-stdlib-min | block (control) |
|---|---|---|---|
| client PUT of a real 701 B block | put response, 65 ms | put response, 59 ms | put response, 63 ms |
| GET it back | identical state | identical state | identical state |
| PUT a state that does NOT hash to its params | refused, "invalid put" | refused, "invalid put" | refused, "invalid put" |
| re-PUT the same block | put response | put response | put response |
| UPDATE with its own state | update response | update response | update response |

- **The mismatched PUT being refused is the control.** It shows `validate_state` really decides; a contract
  that answered Valid to everything would accept it.
- **UPDATE with the same state is answered "update response" even though block-min's `update_state` refuses.**
  Whether the node called `update_state` at all for an unchanged state was NOT measured.
- **Not measured:**
  - a peered node;
  - a GET of a block-min block by a node that did not hold it (the code travels with the contract);
  - the size-cap and kind checks `block/` has.
