# freenet-contracts

The platform's Freenet contracts. Each is its own Cargo workspace with its own
lockfile, because a contract's wasm hash is part of its network key.

| Contract | Holds | Status |
|---|---|---|
| `block` | immutable, hash-keyed bytes | built |
| `register` | one signed value per writer (key or k-of-n keyset) | built |
| `set` | union of signed items | phase 2 |
| `derived` | host-verified digests of child contracts | phase 2 |

`./build.sh` → `build/*.wasm` (reproducible). Spec: `craftworks-docs/ARCHITECTURE.md` §1.

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
