//! Criterion benchmarks for the VCA protocol evaluation.
//!
//! Covers Merkle tree construction, non-membership proof generation (GenNP),
//! VCR generation (GenVCR) and VCR verification (VerifyVCR).

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use k256::ecdsa::SigningKey;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use vca_eval::prelude::*;

use alloy_primitives::Address;

fn generate_random_addresses(count: usize, seed: u64) -> Vec<Address> {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut addresses = Vec::with_capacity(count);
    for _ in 0..count {
        let mut bytes = [0u8; 20];
        rng.fill(&mut bytes);
        addresses.push(Address::from(bytes));
    }
    addresses.sort_unstable();
    addresses.dedup();
    addresses
}

fn generate_non_member_address(addresses: &[Address], seed: u64) -> Address {
    let mut rng = StdRng::seed_from_u64(seed);
    loop {
        let mut bytes = [0u8; 20];
        rng.fill(&mut bytes);
        let addr = Address::from(bytes);
        if let Err(pos) = addresses.binary_search(&addr) {
            if pos > 0 && pos < addresses.len() {
                return addr;
            }
        }
    }
}

/// Build a registry with `k` watchlists (all backed by the same tree) and the
/// matching policy.
fn build_registry(tree: &SortedMerkleTree, k: usize) -> (MockRegistry, Policy) {
    let mut registry = MockRegistry::new();
    let policy: Policy = (0..k).map(|i| format!("watchlist://bench-{}", i)).collect();
    for uri in &policy {
        registry.register_watchlist(uri.clone(), tree.clone(), 1704067200);
    }
    (registry, policy)
}

fn bench_tree_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("tree_construction");
    for size in [1_000, 10_000, 50_000, 100_000] {
        let addresses = generate_random_addresses(size, 42);
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                let tree = SortedMerkleTree::new(black_box(addresses.clone())).unwrap();
                black_box(tree);
            });
        });
    }
    group.finish();
}

fn bench_gen_np(c: &mut Criterion) {
    let mut group = c.benchmark_group("gen_np");
    for size in [1_000, 10_000, 50_000, 100_000] {
        let addresses = generate_random_addresses(size, 42);
        let tree = SortedMerkleTree::new(addresses.clone()).unwrap();
        let target = generate_non_member_address(&addresses, 123);
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                let proof = tree.generate_non_membership_proof(black_box(&target)).unwrap();
                black_box(proof);
            });
        });
    }
    group.finish();
}

fn bench_gen_vcr(c: &mut Criterion) {
    let mut group = c.benchmark_group("gen_vcr");

    let addresses = generate_random_addresses(10_000, 42);
    let tree = SortedMerkleTree::new(addresses.clone()).unwrap();
    let addr_sender = generate_non_member_address(&addresses, 123);
    let signing_key = SigningKey::random(&mut StdRng::seed_from_u64(999));

    for k in [1, 3, 5, 10] {
        let (registry, policy) = build_registry(&tree, k);
        group.bench_with_input(BenchmarkId::from_parameter(k), &k, |b, _| {
            b.iter(|| {
                let vcr = VCR::generate_with_registry(
                    black_box(&signing_key),
                    black_box(policy.clone()),
                    black_box(&addr_sender),
                    1,
                    black_box(&registry),
                )
                .unwrap();
                black_box(vcr);
            });
        });
    }
    group.finish();
}

fn bench_verify_vcr(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_vcr");

    let addresses = generate_random_addresses(10_000, 42);
    let tree = SortedMerkleTree::new(addresses.clone()).unwrap();
    let addr_sender = generate_non_member_address(&addresses, 123);
    let signing_key = SigningKey::random(&mut StdRng::seed_from_u64(999));

    for k in [1, 3, 5, 10] {
        let (registry, policy) = build_registry(&tree, k);
        let vcr =
            VCR::generate_with_registry(&signing_key, policy.clone(), &addr_sender, 1, &registry)
                .unwrap();
        let tx = Transaction {
            addr_sender,
            addr_receiver: vcr.message.context.receiver_address(),
            nonce: 1,
            time: 1704067200,
            payload: vec![],
        };
        assert!(vcr.verify_with_registry(&tx, &policy, &registry));

        group.bench_with_input(BenchmarkId::from_parameter(k), &k, |b, _| {
            b.iter(|| {
                let valid = vcr.verify_with_registry(
                    black_box(&tx),
                    black_box(&policy),
                    black_box(&registry),
                );
                black_box(valid);
            });
        });
    }
    group.finish();
}

/// GenVCR with a fixed policy count (k=1) while varying the watchlist size.
fn bench_gen_vcr_varying_n(c: &mut Criterion) {
    let mut group = c.benchmark_group("gen_vcr_varying_n");
    let signing_key = SigningKey::random(&mut StdRng::seed_from_u64(999));

    for n in [1_000, 10_000, 50_000, 100_000] {
        let addresses = generate_random_addresses(n, 42);
        let tree = SortedMerkleTree::new(addresses.clone()).unwrap();
        let addr_sender = generate_non_member_address(&addresses, 123);
        let (registry, policy) = build_registry(&tree, 1);

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                let vcr = VCR::generate_with_registry(
                    black_box(&signing_key),
                    black_box(policy.clone()),
                    black_box(&addr_sender),
                    1,
                    black_box(&registry),
                )
                .unwrap();
                black_box(vcr);
            });
        });
    }
    group.finish();
}

/// VerifyVCR with a fixed policy count (k=1) while varying the watchlist size.
fn bench_verify_vcr_varying_n(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_vcr_varying_n");
    let signing_key = SigningKey::random(&mut StdRng::seed_from_u64(999));

    for n in [1_000, 10_000, 50_000, 100_000] {
        let addresses = generate_random_addresses(n, 42);
        let tree = SortedMerkleTree::new(addresses.clone()).unwrap();
        let addr_sender = generate_non_member_address(&addresses, 123);
        let (registry, policy) = build_registry(&tree, 1);
        let vcr =
            VCR::generate_with_registry(&signing_key, policy.clone(), &addr_sender, 1, &registry)
                .unwrap();
        let tx = Transaction {
            addr_sender,
            addr_receiver: vcr.message.context.receiver_address(),
            nonce: 1,
            time: 1704067200,
            payload: vec![],
        };
        assert!(vcr.verify_with_registry(&tx, &policy, &registry));

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                let valid = vcr.verify_with_registry(
                    black_box(&tx),
                    black_box(&policy),
                    black_box(&registry),
                );
                black_box(valid);
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_tree_construction,
    bench_gen_np,
    bench_gen_vcr,
    bench_verify_vcr,
    bench_gen_vcr_varying_n,
    bench_verify_vcr_varying_n
);
criterion_main!(benches);
