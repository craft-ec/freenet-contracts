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
