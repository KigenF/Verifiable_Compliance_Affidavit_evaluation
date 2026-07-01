//! Ethereum ABI encoding and size calculation for VCR
//!
//! This module provides functions to serialize VCR data in a format
//! compatible with Ethereum calldata and estimate gas costs.

use crate::vcr::{Context, VCR};

/// Encode a VCR for Ethereum calldata
///
/// This is a simplified encoding for size estimation purposes.
/// A production implementation would use proper ABI encoding.
pub fn encode_vcr(vcr: &VCR) -> Vec<u8> {
    let mut encoded = Vec::new();

    // Encode policy (now just Vec<String>)
    encoded.extend_from_slice(&(vcr.message.policy.len() as u32).to_be_bytes());
    for uri in &vcr.message.policy {
        encoded.extend_from_slice(&encode_uri(uri));
    }

    // Encode context
    encoded.extend_from_slice(&encode_context(&vcr.message.context));

    // Encode proofs
    encoded.extend_from_slice(&(vcr.message.proofs.len() as u32).to_be_bytes());
    for proof in &vcr.message.proofs {
        encoded.extend_from_slice(&encode_proof(proof));
    }

    // Encode signature
    encoded.extend_from_slice(&vcr.signature.r);
    encoded.extend_from_slice(&vcr.signature.s);
    encoded.push(vcr.signature.v);

    encoded
}

/// Encode a URI
fn encode_uri(uri: &str) -> Vec<u8> {
    let mut encoded = Vec::new();
    let uri_bytes = uri.as_bytes();
    encoded.extend_from_slice(&(uri_bytes.len() as u32).to_be_bytes());
    encoded.extend_from_slice(uri_bytes);
    encoded
}

/// Encode a context: 33-byte compressed pubkey followed by an 8-byte nonce.
fn encode_context(context: &Context) -> Vec<u8> {
    let mut encoded = Vec::new();
    let pk_bytes = context.pk_receiver.to_encoded_point(true);
    encoded.extend_from_slice(pk_bytes.as_bytes());
    encoded.extend_from_slice(&context.nonce_sender.to_be_bytes());
    encoded
}

/// Encode a non-membership proof (optimized - no right_path)
fn encode_proof(proof: &crate::merkle::NonMembershipProof) -> Vec<u8> {
    let mut encoded = Vec::new();

    // Addr (20 bytes)
    encoded.extend_from_slice(proof.addr.as_slice());

    // Root (32 bytes)
    encoded.extend_from_slice(&proof.root);

    // Left and right bounding addresses (20 bytes each)
    encoded.extend_from_slice(proof.left_addr.as_slice());
    encoded.extend_from_slice(proof.right_addr.as_slice());

    // Left path (only)
    encoded.extend_from_slice(&(proof.left_path.len() as u32).to_be_bytes());
    for hash in &proof.left_path {
        encoded.extend_from_slice(hash);
    }

    // Left indices (only)
    encoded.extend_from_slice(&encode_bit_vector(&proof.left_indices));

    // Right lower path (right leaf's siblings below the divergence level)
    encoded.extend_from_slice(&(proof.right_lower_path.len() as u32).to_be_bytes());
    for hash in &proof.right_lower_path {
        encoded.extend_from_slice(hash);
    }

    // Divergence level (8 bytes as u64)
    encoded.extend_from_slice(&(proof.divergence_level as u64).to_be_bytes());

    encoded
}

/// Encode a boolean vector as packed bits
fn encode_bit_vector(bits: &[bool]) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&(bits.len() as u32).to_be_bytes());

    let mut current_byte = 0u8;
    let mut bit_index = 0;

    for &bit in bits {
        if bit {
            current_byte |= 1 << bit_index;
        }
        bit_index += 1;

        if bit_index == 8 {
            encoded.push(current_byte);
            current_byte = 0;
            bit_index = 0;
        }
    }

    // Push remaining bits
    if bit_index > 0 {
        encoded.push(current_byte);
    }

    encoded
}

/// Calculate the size of encoded VCR in bytes
pub fn calculate_vcr_size(vcr: &VCR) -> usize {
    encode_vcr(vcr).len()
}

/// Estimate Ethereum calldata gas cost
///
/// Gas costs:
/// - Zero byte: 4 gas
/// - Non-zero byte: 16 gas
pub fn estimate_calldata_gas(data: &[u8]) -> u64 {
    data.iter()
        .map(|&byte| if byte == 0 { 4 } else { 16 })
        .sum()
}

/// Estimate gas cost for a VCR
pub fn estimate_vcr_gas(vcr: &VCR) -> u64 {
    let encoded = encode_vcr(vcr);
    estimate_calldata_gas(&encoded)
}

/// Gas statistics for a VCR
#[derive(Debug, Clone)]
pub struct GasEstimate {
    /// Total size in bytes
    pub size_bytes: usize,
    /// Number of zero bytes
    pub zero_bytes: usize,
    /// Number of non-zero bytes
    pub nonzero_bytes: usize,
    /// Total gas cost
    pub total_gas: u64,
}

impl GasEstimate {
    /// Calculate gas estimate for encoded data
    pub fn from_data(data: &[u8]) -> Self {
        let zero_bytes = data.iter().filter(|&&b| b == 0).count();
        let nonzero_bytes = data.len() - zero_bytes;
        let total_gas = (zero_bytes as u64 * 4) + (nonzero_bytes as u64 * 16);

        Self {
            size_bytes: data.len(),
            zero_bytes,
            nonzero_bytes,
            total_gas,
        }
    }

    /// Calculate gas estimate for a VCR
    pub fn from_vcr(vcr: &VCR) -> Self {
        let encoded = encode_vcr(vcr);
        Self::from_data(&encoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::SortedMerkleTree;
    use crate::vcr::VCR;
    use alloy_primitives::address;
    use k256::ecdsa::{SigningKey, VerifyingKey};
    use rand::rngs::OsRng;

    #[test]
    fn test_encode_context() {
        let signing_key = SigningKey::random(&mut OsRng);
        let pk_receiver = VerifyingKey::from(&signing_key);

        let context = Context::new(pk_receiver, 1);

        let encoded = encode_context(&context);
        assert_eq!(encoded.len(), 41); // 33 (compressed pubkey) + 8 (nonce)
    }

    #[test]
    fn test_encode_uri() {
        let uri = "ofac://2024-01";
        let encoded = encode_uri(uri);

        // 4 bytes (length) + URI length
        assert_eq!(encoded.len(), 4 + uri.len());
    }

    #[test]
    fn test_bit_vector_encoding() {
        let bits = vec![true, false, true, true, false, false, true, false];
        let encoded = encode_bit_vector(&bits);

        // 4 bytes for length + 1 byte for bits
        assert_eq!(encoded.len(), 5);

        // Check the bit pattern: 0b01001101 = 0x4D
        assert_eq!(encoded[4], 0b01001101);
    }

    #[test]
    fn test_vcr_encoding_and_size() {
        let signing_key = SigningKey::random(&mut OsRng);
        let pk_receiver = VerifyingKey::from(&signing_key);

        let addresses = vec![
            address!("0000000000000000000000000000000000000001"),
            address!("0000000000000000000000000000000000000003"),
            address!("0000000000000000000000000000000000000005"),
        ];
        let tree = SortedMerkleTree::new(addresses).unwrap();

        let policy = vec!["test://watchlist".to_string()];

        let context = Context::new(pk_receiver, 1);

        let target = address!("0000000000000000000000000000000000000004");
        let proof = tree.generate_non_membership_proof(&target).unwrap();

        let vcr = VCR::generate(&signing_key, policy, context, vec![proof]).unwrap();

        let encoded = encode_vcr(&vcr);
        let size = calculate_vcr_size(&vcr);

        assert_eq!(encoded.len(), size);
        assert!(size > 0);
    }

    #[test]
    fn test_gas_estimation() {
        // All zero bytes
        let zeros = vec![0u8; 100];
        let gas = estimate_calldata_gas(&zeros);
        assert_eq!(gas, 400); // 100 * 4

        // All non-zero bytes
        let ones = vec![1u8; 100];
        let gas = estimate_calldata_gas(&ones);
        assert_eq!(gas, 1600); // 100 * 16

        // Mixed
        let mixed = vec![0u8, 1u8, 0u8, 1u8];
        let gas = estimate_calldata_gas(&mixed);
        assert_eq!(gas, 40); // 2 * 4 + 2 * 16
    }

    #[test]
    fn test_gas_estimate_struct() {
        let data = vec![0u8, 0u8, 1u8, 2u8, 3u8];
        let estimate = GasEstimate::from_data(&data);

        assert_eq!(estimate.size_bytes, 5);
        assert_eq!(estimate.zero_bytes, 2);
        assert_eq!(estimate.nonzero_bytes, 3);
        assert_eq!(estimate.total_gas, 56); // 2 * 4 + 3 * 16
    }

    #[test]
    fn test_vcr_gas_estimate() {
        let signing_key = SigningKey::random(&mut OsRng);
        let pk_receiver = VerifyingKey::from(&signing_key);

        let addresses = vec![
            address!("0000000000000000000000000000000000000001"),
            address!("0000000000000000000000000000000000000003"),
        ];
        let tree = SortedMerkleTree::new(addresses).unwrap();

        let policy = vec!["test://watchlist".to_string()];

        let context = Context::new(pk_receiver, 1);

        let target = address!("0000000000000000000000000000000000000002");
        let proof = tree.generate_non_membership_proof(&target).unwrap();

        let vcr = VCR::generate(&signing_key, policy, context, vec![proof]).unwrap();

        let estimate = GasEstimate::from_vcr(&vcr);

        assert!(estimate.size_bytes > 0);
        assert!(estimate.total_gas > 0);
        assert_eq!(
            estimate.size_bytes,
            estimate.zero_bytes + estimate.nonzero_bytes
        );
    }
}
