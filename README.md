# vca-eval

Performance-evaluation artifact for the **Verifiable Compliance Affidavit (VCA)**
protocol — a privacy-preserving compliance mechanism for P2P cryptocurrency
transactions. It implements the core protocol primitives and measures the cost of
generating and verifying a **Verifiable Compliance Record (VCR)**: execution time,
serialized size, and estimated Ethereum calldata gas.

This repository accompanies the paper *"Verifiable Compliance Affidavit: Prove Your
Due Diligence in P2P Transactions"* and reproduces the numbers in its evaluation
section.

## Directory layout

```
.
├── Cargo.toml            # Crate manifest and dependencies
├── src/
│   ├── lib.rs            # Public API surface and `prelude` re-exports
│   ├── merkle.rs         # Sorted Merkle tree + non-membership proofs (GenNP / VerifyNP)
│   ├── vcr.rs            # VCR types, GenVCR (Algorithm 1), VerifyVCR (Algorithm 2)
│   ├── registry.rs       # In-memory mock CryptoWatchlist registry
│   └── encoding.rs       # Calldata serialization and gas estimation
├── benches/
│   └── benchmark.rs      # Criterion micro-benchmarks
└── examples/
    └── eval.rs           # Parameter-sweep evaluation, writes eval_results.csv
```

### Module responsibilities

- **`merkle`** — Builds a sorted Merkle tree whose leaves are the addresses
  themselves (left-padded to 32 bytes) in ascending order, with keccak256 internal
  nodes. `generate_non_membership_proof` returns an adjacency-optimized proof (the
  two bounding addresses, the full left path, and the right leaf's siblings below
  the divergence level); `NonMembershipProof::verify` checks that the target sorts
  strictly between the bounding addresses and that they are adjacent leaves under
  the committed root.
- **`vcr`** — `Context = (pkR, NS)`, `Policy = {URIᵢ}`, and `VCR = (M, σ)` with
  `M = (P, C, Π)`. `generate_with_registry` implements GenVCR;
  `verify_with_registry` implements VerifyVCR (policy-coverage, binding, signature,
  and per-policy non-membership checks).
- **`registry`** — Maps a watchlist URI to a tree and a registration timestamp,
  returning the historical root for a queried time.
- **`encoding`** — Serializes a VCR to a calldata-style byte string and estimates
  gas (4 gas per zero byte, 16 gas per non-zero byte).

## Build & test

```bash
cargo build --release    # optimized build
cargo test               # unit + doc tests
```

## Reproducing the evaluation

```bash
cargo run --release --example eval
```

Prints summary tables and writes `eval_results.csv`. The sweep covers two
experiments with fixed seed (`42`) and 1000 iterations per configuration:

| Parameter            | Values                  |
|----------------------|-------------------------|
| Watchlist size `N`   | 1K, 10K, 50K, 100K      |
| Policy count `k`     | 1, 3, 5, 10             |

`eval_results.csv` columns:

```
experiment, timestamp, watchlist_size, policy_count,
vcr_gen_time_us, vcr_verify_time_us, vcr_size_bytes,
vcr_zero_bytes, vcr_nonzero_bytes, calldata_gas_estimate
```

Size and gas are deterministic; timing values depend on hardware.

## Benchmarks

```bash
cargo bench
```

Runs Criterion benchmarks for tree construction, GenNP, GenVCR, and VerifyVCR.
HTML reports are written to `target/criterion/report/index.html`.

## Dependencies

- `sha3` — keccak256 hashing
- `k256` — secp256k1 ECDSA
- `alloy-primitives` — Ethereum `Address` type
- `serde` / `serde_json` — serialization
- `thiserror` — error types
- `criterion`, `csv`, `chrono` (dev) — benchmarking and CSV output

## Scope

Implemented: sorted Merkle tree, non-membership proofs, VCR generation and
verification, calldata size/gas estimation. Out of scope: on-chain smart-contract
verification, a production CryptoWatchlist registry, address authentication, and
the watcher/scoring mechanisms discussed in the paper's later sections.
