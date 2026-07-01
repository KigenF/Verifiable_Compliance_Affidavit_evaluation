//! VCA Protocol Evaluation Library
//!
//! This library provides tools to evaluate the performance of the VCA
//! (Verifiable Compliance Affidavit) protocol for P2P cryptocurrency transactions.
//!
//! # Modules
//!
//! - [`merkle`]: Sorted Merkle tree with non-membership proofs
//! - [`vcr`]: Verifiable Compliance Record types, generation and verification
//! - [`registry`]: In-memory mock CryptoWatchlist registry
//! - [`encoding`]: Ethereum calldata encoding and gas estimation
//!
//! # Example
//!
//! ```no_run
//! use vca_eval::prelude::*;
//! use alloy_primitives::address;
//! use k256::ecdsa::{SigningKey, VerifyingKey};
//! use rand::rngs::OsRng;
//!
//! // Create a watchlist
//! let addresses = vec![
//!     address!("0000000000000000000000000000000000000001"),
//!     address!("0000000000000000000000000000000000000003"),
//!     address!("0000000000000000000000000000000000000005"),
//! ];
//!
//! // Build Merkle tree
//! let tree = SortedMerkleTree::new(addresses).unwrap();
//!
//! // Generate non-membership proof
//! let target = address!("0000000000000000000000000000000000000004");
//! let proof = tree.generate_non_membership_proof(&target).unwrap();
//!
//! // Create VCR
//! let signing_key = SigningKey::random(&mut OsRng);
//! let pk_receiver = VerifyingKey::from(&signing_key);
//! let policy = vec!["test://watchlist".to_string()];
//! let context = Context::new(pk_receiver, 1);
//!
//! let vcr = VCR::generate(&signing_key, policy, context, vec![proof]).unwrap();
//!
//! // Estimate gas cost
//! let gas_estimate = GasEstimate::from_vcr(&vcr);
//! println!("VCR size: {} bytes, gas: {}", gas_estimate.size_bytes, gas_estimate.total_gas);
//! ```

pub mod encoding;
pub mod merkle;
pub mod registry;
pub mod vcr;

/// Convenience re-exports
pub mod prelude {
    pub use crate::encoding::{calculate_vcr_size, encode_vcr, estimate_vcr_gas, GasEstimate};
    pub use crate::merkle::{MerkleError, NonMembershipProof, SortedMerkleTree};
    pub use crate::registry::MockRegistry;
    pub use crate::vcr::{
        ComplianceMessage, Context, Policy, Transaction, VcrError, VcrSignature, VCR,
    };
}
