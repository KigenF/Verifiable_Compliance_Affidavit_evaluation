//! VCA Protocol Evaluation Script
//!
//! This script performs focused performance evaluation of VCR generation and verification.
//!
//! Experiments:
//! 1. Fixed N=10,000, varying k={1,3,5,10}: VCR gen/verify time, size, gas cost
//! 2. Fixed k=1, varying N={1K,10K,50K,100K}: VCR gen/verify time, size, gas cost
//!
//! Usage: cargo run --release --example eval

use alloy_primitives::Address;
use chrono::Utc;
use csv::Writer;
use k256::ecdsa::SigningKey;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::fs::File;
use std::time::Instant;
use vca_eval::prelude::*;

/// Evaluation parameters
const ITERATIONS: usize = 1000; // Number of iterations for averaging
const SEED: u64 = 42;

/// Evaluation result for a single configuration
#[derive(Debug, Clone)]
struct EvalResult {
    experiment: String,
    timestamp: String,
    watchlist_size: usize,
    policy_count: usize,
    vcr_gen_time_us: u128,
    vcr_verify_time_us: u128,
    vcr_size_bytes: usize,
    vcr_zero_bytes: usize,
    vcr_nonzero_bytes: usize,
    calldata_gas_estimate: u64,
}

/// Generate random Ethereum addresses
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

/// Generate a random address not in the list
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

/// Run evaluation for a specific configuration
fn evaluate_config(
    experiment: &str,
    watchlist_size: usize,
    policy_count: usize,
) -> EvalResult {
    let timestamp = Utc::now().to_rfc3339();

    // Generate addresses and build tree (not timed)
    let addresses = generate_random_addresses(watchlist_size, SEED);
    let tree = SortedMerkleTree::new(addresses.clone()).unwrap();
    let addr_sender = generate_non_member_address(&addresses, SEED + 1);

    // Create signing key (Receiver's key)
    let mut rng = StdRng::seed_from_u64(SEED + 2);
    let signing_key = SigningKey::random(&mut rng);

    // Create MockRegistry and register all watchlists
    let mut registry = MockRegistry::new();
    for i in 0..policy_count {
        let uri = format!("watchlist://eval-{}", i);
        registry.register_watchlist(uri, tree.clone(), 1704067200);
    }

    // Create policy (Vec<String>)
    let policy: Vec<String> = (0..policy_count)
        .map(|i| format!("watchlist://eval-{}", i))
        .collect();

    let nonce_sender = 1u64;

    // Measure VCR generation time (Algorithm 1: GenVCR)
    // Accumulate in nanoseconds to avoid per-iteration microsecond truncation.
    let mut total_gen_time_ns = 0u128;
    let mut vcr = None;
    for _ in 0..ITERATIONS {
        let start = Instant::now();

        // Generate VCR using Algorithm 1
        vcr = Some(
            VCR::generate_with_registry(
                &signing_key,
                policy.clone(),
                &addr_sender,
                nonce_sender,
                &registry,
            )
            .unwrap(),
        );

        total_gen_time_ns += start.elapsed().as_nanos();
    }
    let vcr_gen_time_us = total_gen_time_ns / 1000 / ITERATIONS as u128;
    let vcr = vcr.unwrap();

    // Create Transaction for verification
    let addr_receiver = vcr.message.context.receiver_address();
    let tx = Transaction {
        addr_sender,
        addr_receiver,
        nonce: nonce_sender,
        time: 1704067200,
        payload: vec![], // Not used in this evaluation
    };

    // Create verifier's policy (same as sender's policy for now)
    let policy_verifier = policy.clone();

    // Sanity check: the generated VCR must actually verify. This guards the
    // measurement against silently timing a rejected (early-returning) path.
    assert!(
        vcr.verify_with_registry(&tx, &policy_verifier, &registry),
        "generated VCR failed verification (N={}, k={})",
        watchlist_size,
        policy_count
    );

    // Measure VCR verification time (Algorithm 2: VerifyVCR)
    let mut total_verify_time_ns = 0u128;
    for _ in 0..ITERATIONS {
        let start = Instant::now();
        let valid = vcr.verify_with_registry(&tx, &policy_verifier, &registry);
        std::hint::black_box(valid);
        total_verify_time_ns += start.elapsed().as_nanos();
    }
    let vcr_verify_time_us = total_verify_time_ns / 1000 / ITERATIONS as u128;

    // Calculate gas estimate
    let gas_estimate = GasEstimate::from_vcr(&vcr);

    EvalResult {
        experiment: experiment.to_string(),
        timestamp,
        watchlist_size,
        policy_count,
        vcr_gen_time_us,
        vcr_verify_time_us,
        vcr_size_bytes: gas_estimate.size_bytes,
        vcr_zero_bytes: gas_estimate.zero_bytes,
        vcr_nonzero_bytes: gas_estimate.nonzero_bytes,
        calldata_gas_estimate: gas_estimate.total_gas,
    }
}

fn main() {
    println!("=== VCA Protocol VCR Performance Evaluation ===\n");

    println!("Configuration:");
    println!("  Iterations per measurement: {}", ITERATIONS);
    println!("  Seed: {}", SEED);
    println!();

    let mut results = Vec::new();

    // Experiment 1: Fixed N=10,000, varying k
    println!("=== Experiment 1: Fixed Watchlist Size (N=10,000) ===");
    println!("Varying Policy Count (k)...\n");

    let fixed_n = 10_000;
    let policy_counts = [1, 3, 5, 10];

    for &k in &policy_counts {
        print!("  N={:>6}, k={:>2} ... ", fixed_n, k);
        std::io::Write::flush(&mut std::io::stdout()).unwrap();

        let result = evaluate_config("fixed_N", fixed_n, k);

        println!(
            "Gen: {:>6}µs, Verify: {:>6}µs, Size: {:>6}B, Gas: {:>8}",
            result.vcr_gen_time_us,
            result.vcr_verify_time_us,
            result.vcr_size_bytes,
            result.calldata_gas_estimate
        );

        results.push(result);
    }

    println!();

    // Experiment 2: Fixed k=1, varying N
    println!("=== Experiment 2: Fixed Policy Count (k=1) ===");
    println!("Varying Watchlist Size (N)...\n");

    let fixed_k = 1;
    let watchlist_sizes = [1_000, 10_000, 50_000, 100_000];

    for &n in &watchlist_sizes {
        print!("  N={:>6}, k={:>2} ... ", n, fixed_k);
        std::io::Write::flush(&mut std::io::stdout()).unwrap();

        let result = evaluate_config("fixed_k", n, fixed_k);

        println!(
            "Gen: {:>6}µs, Verify: {:>6}µs, Size: {:>6}B, Gas: {:>8}",
            result.vcr_gen_time_us,
            result.vcr_verify_time_us,
            result.vcr_size_bytes,
            result.calldata_gas_estimate
        );

        results.push(result);
    }

    println!("\n=== Writing Results to CSV ===\n");

    // Write to CSV
    let file = File::create("eval_results.csv").expect("Failed to create CSV file");
    let mut writer = Writer::from_writer(file);

    // Write header
    writer
        .write_record(&[
            "experiment",
            "timestamp",
            "watchlist_size",
            "policy_count",
            "vcr_gen_time_us",
            "vcr_verify_time_us",
            "vcr_size_bytes",
            "vcr_zero_bytes",
            "vcr_nonzero_bytes",
            "calldata_gas_estimate",
        ])
        .expect("Failed to write CSV header");

    // Write data
    for result in &results {
        writer
            .write_record(&[
                result.experiment.clone(),
                result.timestamp.clone(),
                result.watchlist_size.to_string(),
                result.policy_count.to_string(),
                result.vcr_gen_time_us.to_string(),
                result.vcr_verify_time_us.to_string(),
                result.vcr_size_bytes.to_string(),
                result.vcr_zero_bytes.to_string(),
                result.vcr_nonzero_bytes.to_string(),
                result.calldata_gas_estimate.to_string(),
            ])
            .expect("Failed to write CSV row");
    }

    writer.flush().expect("Failed to flush CSV writer");

    println!("Results written to: eval_results.csv");

    // Print summary tables
    println!("\n=== Summary: Experiment 1 (N=10,000, varying k) ===\n");
    println!("  k  | Gen (µs) | Verify (µs) | Size (bytes) | Gas Cost");
    println!("-----|----------|-------------|--------------|----------");

    for &k in &policy_counts {
        if let Some(r) = results
            .iter()
            .find(|r| r.experiment == "fixed_N" && r.policy_count == k)
        {
            println!(
                " {:>2}  | {:>8} | {:>11} | {:>12} | {:>8}",
                k, r.vcr_gen_time_us, r.vcr_verify_time_us, r.vcr_size_bytes, r.calldata_gas_estimate
            );
        }
    }

    println!("\n=== Summary: Experiment 2 (k=1, varying N) ===\n");
    println!("    N   | Gen (µs) | Verify (µs) | Size (bytes) | Gas Cost");
    println!("--------|----------|-------------|--------------|----------");

    for &n in &watchlist_sizes {
        if let Some(r) = results
            .iter()
            .find(|r| r.experiment == "fixed_k" && r.watchlist_size == n)
        {
            println!(
                " {:>6} | {:>8} | {:>11} | {:>12} | {:>8}",
                n, r.vcr_gen_time_us, r.vcr_verify_time_us, r.vcr_size_bytes, r.calldata_gas_estimate
            );
        }
    }

    println!("\n=== Evaluation Complete ===");
}
