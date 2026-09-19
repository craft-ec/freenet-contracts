# freenet-contracts

The platform's Freenet contracts. Each is its own Cargo workspace with its own
lockfile, because a contract's wasm hash is part of its network key.

| Contract | Holds | Status |
|---|---|---|
| `block` | immutable, hash-keyed bytes | built |
| `register` | one signed value per writer (key or k-of-n keyset) | phase 2 |
| `set` | union of signed items | phase 2 |
| `derived` | host-verified digests of child contracts | phase 2 |

`./build.sh` → `build/*.wasm` (reproducible). Spec: `craftworks-docs/ARCHITECTURE.md` §1.

`./check-wasm.sh` runs the block contract's validation inside wasm32, where it
actually runs: it checks that a good node is accepted and a corrupt one is not,
then times both on the worst case a host can be handed (a leaf filled to the
boundary rule's 12 KiB measure with the smallest entries the format allows). It
needs `node` and the `wasm32-unknown-unknown` target, and fails if either is
missing rather than skipping.
