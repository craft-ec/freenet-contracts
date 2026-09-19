# freenet-contracts

The platform's Freenet contracts. Each is its own Cargo workspace with its own
lockfile, because a contract's wasm hash is part of its network key.

| Contract | Holds | Status |
|---|---|---|
| `block` | immutable, hash-keyed bytes | built |
| `register` | one signed value per writer (key or k-of-n keyset) | built |
| `set` | union of signed items | phase 2 |
| `bag` | unsigned immutable pointers, top-M by work | phase 2 |

`./build.sh` → `build/*.wasm` (reproducible). Spec: `craftworks-docs/ARCHITECTURE.md` §1.

### What a terminal Register record names

A Register can say "I moved to that one". The value it carries is the
successor's **identity** — `BLAKE3("RG01-succ" ‖ successor params)`, computed by
`register::succ::successor_value` — and never a Freenet instance id.

An instance id is `BLAKE3(code hash ‖ params)`, so it names CODE. A terminal
record is signed and immutable, so a record naming code would point under a
dead build the moment the Register contract is upgraded. An identity names the
register; a reader turns it into a current key through the epoch table, which
is the one thing that should know about code.

The exception is the HEAD's terminal, which does carry an instance id, because
nothing above the head supplies a table to resolve an identity with. That is
specified where the head is.

### The wasm hash moves with the LINE COUNT of `register/src/wire.rs`

Measured, not assumed: adding a single comment line to `wire.rs` changes
`register.wasm` (`a3be5ec4…` → `b5f09452…`), while rewriting a comment's text
without changing how many lines it occupies leaves the hash exactly as it was.
`lib.rs` and `merge.rs` are not sensitive. The cause is panic locations —
`file:line:col` for `unwrap`/`expect`/indexing — reaching the binary from the
file that has those call sites.

So a documentation change to `wire.rs` re-keys every register in existence
unless it keeps the line count. That is a sharp edge worth knowing about before
editing, and the reason the successor helper lives in its own file.

### What a contract's wasm hash commits to

The hash is part of the contract's network key, so what goes into it matters.
It commits to **the compiled code** — this repo's source, the pinned source of
every dependency, the toolchain and the build flags. It does **not** commit to
where any of that lived on disk, and in particular not to the name of the git
revision a dependency came from: cargo unpacks a git dependency into a
directory named after the revision, and that name reaches the binary through
panic locations. `build.sh` remaps each checkout to `/dep/<package>`, derived
from what is on disk rather than hard-coded, so two revisions whose compiled
code is identical produce identical wasm and a no-op dependency bump does not
re-key the contract. Bumping a rev that DOES change the code still changes the
hash, which is the point.

`./check-wasm.sh` runs each contract's validation inside wasm32, where it
actually runs: for every contract it checks that a good state is accepted and a
corrupt one is not, then times the worst case a host can be handed — for `block`
a leaf filled to the boundary rule's 12 KiB measure with the smallest entries the
format allows, for `register` a 16-of-16 keyset with a full-size value and
evidence. It needs `node` and the `wasm32-unknown-unknown` target, and fails if
either is missing rather than skipping.
