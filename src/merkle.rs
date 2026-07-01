//! Sorted Merkle Tree implementation for VCA Protocol
//!
//! This module implements a sorted Merkle tree that supports efficient
//! non-membership proofs for Ethereum addresses.

use alloy_primitives::Address;
use sha3::{Digest, Keccak256};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MerkleError {
    #[error("Address list is empty")]
    EmptyList,

    #[error("Address list is not sorted")]
    NotSorted,

    #[error("Address {0} exists in the tree")]
    AddressExists(Address),

    #[error("Cannot generate non-membership proof: address is out of range")]
    OutOfRange,
}

/// A sorted Merkle tree for Ethereum addresses
#[derive(Debug, Clone)]
pub struct SortedMerkleTree {
    /// Original sorted addresses (leaves)
    addresses: Vec<Address>,
    /// All nodes in the tree (leaves + internal nodes)
    /// Index 0 is root, leaves start from the end
    nodes: Vec<[u8; 32]>,
    /// Tree depth (0 for single element)
    depth: usize,
}

impl SortedMerkleTree {
    /// Construct a new sorted Merkle tree from a list of addresses
    ///
    /// # Arguments
    /// * `addresses` - A sorted list of Ethereum addresses
    ///
    /// # Errors
    /// Returns an error if the list is empty or not sorted
    pub fn new(mut addresses: Vec<Address>) -> Result<Self, MerkleError> {
        if addresses.is_empty() {
            return Err(MerkleError::EmptyList);
        }

        // Leaves are kept in ascending address order; duplicates are dropped.
        addresses.sort_unstable();
        addresses.dedup();

        let leaf_count = addresses.len();
        let depth = if leaf_count == 1 {
            0
        } else {
            (leaf_count as f64).log2().ceil() as usize
        };

        // Build the tree
        let nodes = Self::build_tree(&addresses);

        Ok(Self {
            addresses,
            nodes,
            depth,
        })
    }

    /// Build the Merkle tree from sorted addresses
    fn build_tree(addresses: &[Address]) -> Vec<[u8; 32]> {
        // Leaves are the addresses themselves (left-padded to 32 bytes), so the tree is sorted by leaf value == address.
        let mut current_level: Vec<[u8; 32]> =
            addresses.iter().map(Self::leaf_node).collect();

        let mut all_nodes = current_level.clone();

        // Build tree bottom-up
        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            for chunk in current_level.chunks(2) {
                let hash = if chunk.len() == 2 {
                    Self::hash_pair(&chunk[0], &chunk[1])
                } else {
                    // Odd number of nodes: duplicate the last one
                    Self::hash_pair(&chunk[0], &chunk[0])
                };
                next_level.push(hash);
            }

            all_nodes.extend_from_slice(&next_level);
            current_level = next_level;
        }

        all_nodes
    }

    /// Leaf node value: the 20-byte address left-padded into a 32-byte word.
    /// This keeps leaves ordered by address (their numeric value).
    fn leaf_node(addr: &Address) -> [u8; 32] {
        let mut leaf = [0u8; 32];
        leaf[12..].copy_from_slice(addr.as_slice());
        leaf
    }

    /// Hash a pair of nodes
    fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().into()
    }

    /// Get the Merkle root
    pub fn root(&self) -> [u8; 32] {
        *self.nodes.last().expect("Tree is never empty")
    }

    /// Get the depth of the tree
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Get the number of addresses in the tree
    pub fn len(&self) -> usize {
        self.addresses.len()
    }

    /// Check if the tree is empty
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    /// Find the two adjacent addresses that bound the target address
    /// Returns (left_index, right_index) where addresses[left] < target < addresses[right]
    fn find_bounding_indices(&self, target: &Address) -> Result<(usize, usize), MerkleError> {
        // Binary search to find insertion point
        let pos = self.addresses.binary_search(target);

        if pos.is_ok() {
            return Err(MerkleError::AddressExists(*target));
        }

        let insert_pos = pos.unwrap_err();

        // Check boundary cases
        if insert_pos == 0 {
            return Err(MerkleError::OutOfRange);
        }
        if insert_pos >= self.addresses.len() {
            return Err(MerkleError::OutOfRange);
        }

        Ok((insert_pos - 1, insert_pos))
    }

    /// Generate a Merkle path from a leaf to the root
    fn generate_path(&self, leaf_index: usize) -> (Vec<[u8; 32]>, Vec<bool>) {
        let mut path = Vec::new();
        let mut indices = Vec::new();
        let mut current_level_start = 0;
        let mut current_level_size = self.addresses.len();
        let mut current_index = leaf_index;

        while current_level_size > 1 {
            // Determine sibling index
            let is_right = current_index % 2 == 1;
            let sibling_index = if is_right {
                current_index - 1
            } else {
                (current_index + 1).min(current_level_size - 1)
            };

            // Get sibling hash
            let sibling_hash = self.nodes[current_level_start + sibling_index];
            path.push(sibling_hash);
            indices.push(is_right);

            // Move to parent level
            current_level_start += current_level_size;
            current_level_size = (current_level_size + 1) / 2;
            current_index /= 2;
        }

        (path, indices)
    }

    /// Generate a non-membership proof for an address
    ///
    /// # Arguments
    /// * `target` - The address to prove non-membership for
    ///
    /// # Returns
    /// A `NonMembershipProof` containing the bounding addresses and their Merkle paths
    ///
    /// # Errors
    /// Returns an error if the address exists in the tree or is out of range
    pub fn generate_non_membership_proof(
        &self,
        target: &Address,
    ) -> Result<NonMembershipProof, MerkleError> {
        let (left_idx, right_idx) = self.find_bounding_indices(target)?;

        let left_address = self.addresses[left_idx];
        let right_address = self.addresses[right_idx];

        let (left_path, left_indices) = self.generate_path(left_idx);
        let (right_path, _right_indices) = self.generate_path(right_idx);

        // Calculate divergence level: the lowest level where the two paths merge.
        // Adjacent nodes (left_idx, right_idx) share their path above this level.
        let divergence_level = self.calculate_divergence_level(left_idx, right_idx);

        // Optimization: above the divergence level the right leaf follows the exact same siblings as the left leaf, so we only keep the right leaf's own siblings *below* the divergence level (length == divergence_level).
        let right_lower_path = right_path[..divergence_level].to_vec();

        Ok(NonMembershipProof {
            addr: *target,
            root: self.root(),
            left_addr: left_address,
            right_addr: right_address,
            left_path,
            left_indices,
            right_lower_path,
            divergence_level,
        })
    }

    /// Calculate the level at which two leaf indices diverge
    /// Returns the level where left and right nodes are siblings
    /// For adjacent leaves, this is always 0
    fn calculate_divergence_level(&self, left_idx: usize, right_idx: usize) -> usize {
        // For adjacent indices (e.g., 2 and 3), they are siblings at the leaf level
        // We want the level counting from leaves (0) to root
        let mut l = left_idx;
        let mut r = right_idx;

        // If they're the same parent at level 0, they're siblings
        if l / 2 == r / 2 && l != r {
            return 0;
        }

        // Otherwise, find the level where they share a parent
        for level in 0..self.depth {
            l /= 2;
            r /= 2;
            if l == r {
                return level;
            }
        }

        // Should not reach here for valid adjacent nodes
        0
    }
}

/// Non-membership proof: πnm = (Addr, Root, path).
///
/// Proves that `addr` lies strictly between two *adjacent* leaves `left_addr` and `right_addr` of the sorted tree, hence it is absent from the set.
///
/// Optimization: the two bounding leaves share the same siblings above their divergence level. We store the full left path plus only the right leaf's own siblings *below* the divergence level. Below it the left leaf is always a right child (rightmost in its subtree) and the right leaf is always a left child (leftmost in its subtree), so the right leaf's directions are implied.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NonMembershipProof {
    /// Queried address (20 bytes)
    pub addr: Address,
    /// Merkle root (32 bytes)
    pub root: [u8; 32],
    /// Left bounding address (`left_addr < addr`)
    pub left_addr: Address,
    /// Right bounding address (`addr < right_addr`)
    pub right_addr: Address,
    /// Full Merkle path for the left leaf (length == tree depth)
    pub left_path: Vec<[u8; 32]>,
    /// Path indices for left (true = right sibling, false = left sibling)
    pub left_indices: Vec<bool>,
    /// Right leaf's sibling hashes *below* the divergence level
    /// (length == `divergence_level`). Above it, the right leaf reuses `left_path`.
    pub right_lower_path: Vec<[u8; 32]>,
    /// Level at which the left and right paths merge (they are siblings here).
    pub divergence_level: usize,
}

impl NonMembershipProof {
    /// Calculate the proof size in bytes (optimized - right path only below divergence)
    pub fn size_bytes(&self) -> usize {
        20 + // addr
        32 + // root
        20 + // left_addr
        20 + // right_addr
        4 + self.left_path.len() * 32 + // left_path with length prefix
        4 + (self.left_indices.len() + 7) / 8 + // left_indices with length prefix (bits packed)
        4 + self.right_lower_path.len() * 32 + // right_lower_path with length prefix
        8 // divergence_level (usize/u64)
    }

    /// Verify a Merkle path
    fn verify_path(
        leaf: &[u8; 32],
        path: &[[u8; 32]],
        indices: &[bool],
        root: &[u8; 32],
    ) -> bool {
        let mut current = *leaf;

        for (sibling, &is_right) in path.iter().zip(indices.iter()) {
            current = if is_right {
                // Current is right child, sibling is left
                SortedMerkleTree::hash_pair(sibling, &current)
            } else {
                // Current is left child, sibling is right
                SortedMerkleTree::hash_pair(&current, sibling)
            };
        }

        &current == root
    }

    /// Verify this non-membership proof against a Merkle root.
    ///
    /// Establishes that `target` sorts strictly between two *adjacent* leaves (`left_addr`, `right_addr`) committed to by `root`, hence it is absent.
    ///
    /// # Arguments
    /// * `root` - The Merkle root to verify against
    /// * `target` - The queried address; must satisfy `left_addr < target < right_addr`
    ///
    /// # Returns
    /// True if the proof is valid
    pub fn verify(&self, root: &[u8; 32], target: &Address) -> bool {
        let depth = self.left_path.len();

        // Shape checks: divergence must lie strictly below the root, and the right lower path must carry exactly one sibling per level below it.
        if self.divergence_level >= depth {
            return false;
        }
        if self.left_indices.len() != depth {
            return false;
        }
        if self.right_lower_path.len() != self.divergence_level {
            return false;
        }

        // 0. Bounding: the target must sort strictly between the two leaves.
        if !(&self.left_addr < target && target < &self.right_addr) {
            return false;
        }

        // Reconstruct the leaf values from the bounding addresses.
        let left_leaf = SortedMerkleTree::leaf_node(&self.left_addr);
        let right_leaf = SortedMerkleTree::leaf_node(&self.right_addr);

        // 1. The left leaf must hash up to the root along its full path.
        if !Self::verify_path(&left_leaf, &self.left_path, &self.left_indices, root) {
            return false;
        }

        // 2. Adjacency constraints. Below the divergence level the left leaf must be the rightmost node of its subtree (always a right child), and at the divergence level it must be a left child so that (left, right) form an ordered sibling pair.
        for &is_right in &self.left_indices[..self.divergence_level] {
            if !is_right {
                return false;
            }
        }
        if self.left_indices[self.divergence_level] {
            return false;
        }

        // 3. Climb the right leaf to the divergence level. Below it the right leaf is always a left child, so its sibling sits on the right.
        let mut right_current = right_leaf;
        for sibling in &self.right_lower_path {
            right_current = SortedMerkleTree::hash_pair(&right_current, sibling);
        }

        // At the divergence level the right leaf's ancestor must equal the left leaf's recorded sibling (already bound to the root by step 1).
        &right_current == &self.left_path[self.divergence_level]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    #[test]
    fn test_single_address_tree() {
        let addr = address!("0000000000000000000000000000000000000001");
        let tree = SortedMerkleTree::new(vec![addr]).unwrap();
        assert_eq!(tree.len(), 1);
        assert_eq!(tree.depth(), 0);
    }

    #[test]
    fn test_tree_construction() {
        let addresses = vec![
            address!("0000000000000000000000000000000000000001"),
            address!("0000000000000000000000000000000000000002"),
            address!("0000000000000000000000000000000000000003"),
            address!("0000000000000000000000000000000000000004"),
        ];
        let tree = SortedMerkleTree::new(addresses).unwrap();
        assert_eq!(tree.len(), 4);
        assert_eq!(tree.depth(), 2);
    }

    #[test]
    fn test_unsorted_input_gets_sorted() {
        let addresses = vec![
            address!("0000000000000000000000000000000000000003"),
            address!("0000000000000000000000000000000000000001"),
            address!("0000000000000000000000000000000000000002"),
        ];
        let tree = SortedMerkleTree::new(addresses).unwrap();
        assert_eq!(tree.len(), 3);
        assert_eq!(
            tree.addresses[0],
            address!("0000000000000000000000000000000000000001")
        );
    }

    #[test]
    fn test_non_membership_proof_generation() {
        let addresses = vec![
            address!("0000000000000000000000000000000000000001"),
            address!("0000000000000000000000000000000000000003"),
            address!("0000000000000000000000000000000000000005"),
            address!("0000000000000000000000000000000000000007"),
        ];
        let tree = SortedMerkleTree::new(addresses).unwrap();

        // Proof for address between 0x03 and 0x05
        let target = address!("0000000000000000000000000000000000000004");
        let proof = tree.generate_non_membership_proof(&target).unwrap();

        assert_eq!(proof.left_path.len(), tree.depth());
        assert!(proof.divergence_level < tree.depth());
        assert_eq!(proof.right_lower_path.len(), proof.divergence_level);
        // The generated proof must verify against the tree root.
        assert!(proof.verify(&tree.root(), &target));
    }

    /// Regression: every valid non-membership proof must verify, regardless of where the bounding leaves sit (including across subtree boundaries).
    #[test]
    fn test_non_membership_verifies_on_deep_trees() {
        use rand::rngs::StdRng;
        use rand::{Rng, SeedableRng};

        for &n in &[2usize, 3, 4, 5, 7, 8, 16, 31, 100, 1000] {
            let mut rng = StdRng::seed_from_u64(42);
            let mut addrs: Vec<Address> = (0..n)
                .map(|_| {
                    let mut b = [0u8; 20];
                    rng.fill(&mut b);
                    Address::from(b)
                })
                .collect();
            addrs.sort_unstable();
            addrs.dedup();
            let tree = SortedMerkleTree::new(addrs.clone()).unwrap();

            // Probe many random in-range non-members.
            let mut probe = StdRng::seed_from_u64(7);
            let mut checked = 0;
            let mut tries = 0;
            while checked < 100 && tries < 100_000 {
                tries += 1;
                let mut b = [0u8; 20];
                probe.fill(&mut b);
                let target = Address::from(b);
                if let Ok(proof) = tree.generate_non_membership_proof(&target) {
                    assert!(
                        proof.verify(&tree.root(), &target),
                        "valid proof failed to verify: n={}, target={}",
                        n,
                        target
                    );
                    checked += 1;
                }
            }
        }
    }

    /// A proof must not verify against a different (tampered) root.
    #[test]
    fn test_tampered_proof_rejected() {
        let addresses = vec![
            address!("0000000000000000000000000000000000000001"),
            address!("0000000000000000000000000000000000000003"),
            address!("0000000000000000000000000000000000000005"),
            address!("0000000000000000000000000000000000000007"),
        ];
        let tree = SortedMerkleTree::new(addresses).unwrap();
        let target = address!("0000000000000000000000000000000000000004");
        let proof = tree.generate_non_membership_proof(&target).unwrap();
        assert!(proof.verify(&tree.root(), &target));

        // Tampering with the root must break verification.
        let mut tampered_root = tree.root();
        tampered_root[0] ^= 0xff;
        assert!(!proof.verify(&tampered_root, &target));
    }

    /// A proof for (L, R) must not verify for a target outside (L, R).
    #[test]
    fn test_out_of_bounds_target_rejected() {
        let addresses = vec![
            address!("0000000000000000000000000000000000000001"),
            address!("0000000000000000000000000000000000000003"),
            address!("0000000000000000000000000000000000000005"),
            address!("0000000000000000000000000000000000000007"),
        ];
        let tree = SortedMerkleTree::new(addresses).unwrap();
        // Proof bounds are (0x03, 0x05).
        let proof = tree
            .generate_non_membership_proof(&address!(
                "0000000000000000000000000000000000000004"
            ))
            .unwrap();

        // A different in-tree gap (0x06, between 0x05 and 0x07) is not covered.
        let outside = address!("0000000000000000000000000000000000000006");
        assert!(!proof.verify(&tree.root(), &outside));
    }

    #[test]
    fn test_existing_address_fails() {
        let addresses = vec![
            address!("0000000000000000000000000000000000000001"),
            address!("0000000000000000000000000000000000000002"),
        ];
        let tree = SortedMerkleTree::new(addresses).unwrap();

        let target = address!("0000000000000000000000000000000000000001");
        let result = tree.generate_non_membership_proof(&target);
        assert!(matches!(result, Err(MerkleError::AddressExists(_))));
    }

    #[test]
    fn test_out_of_range_address_fails() {
        let addresses = vec![
            address!("0000000000000000000000000000000000000002"),
            address!("0000000000000000000000000000000000000003"),
        ];
        let tree = SortedMerkleTree::new(addresses).unwrap();

        // Address below minimum
        let target = address!("0000000000000000000000000000000000000001");
        let result = tree.generate_non_membership_proof(&target);
        assert!(matches!(result, Err(MerkleError::OutOfRange)));

        // Address above maximum
        let target = address!("0000000000000000000000000000000000000004");
        let result = tree.generate_non_membership_proof(&target);
        assert!(matches!(result, Err(MerkleError::OutOfRange)));
    }
}
