//! In-memory mock CryptoWatchlist registry for evaluation.
//!
//! In the real protocol this role is served by an on-chain registry of signed, timestamped Merkle roots. Here each URI maps to a single tree registered at a timestamp; a root is considered available for any query time at or after it.

use crate::merkle::SortedMerkleTree;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct MockRegistry {
    watchlists: HashMap<String, WatchlistEntry>,
}

#[derive(Debug, Clone)]
struct WatchlistEntry {
    tree: SortedMerkleTree,
    /// Registration time; the root is available for queries at or after it.
    registered_at: u64,
    root: [u8; 32],
}

impl MockRegistry {
    pub fn new() -> Self {
        Self {
            watchlists: HashMap::new(),
        }
    }

    /// Register a watchlist tree under `uri`, effective from `timestamp`.
    pub fn register_watchlist(&mut self, uri: String, tree: SortedMerkleTree, timestamp: u64) {
        let root = tree.root();
        self.watchlists.insert(
            uri,
            WatchlistEntry {
                tree,
                registered_at: timestamp,
                root,
            },
        );
    }

    /// Fetch the tree backing `uri` (used by GenVCR to build proofs).
    pub fn get_tree(&self, uri: &str) -> Option<&SortedMerkleTree> {
        self.watchlists.get(uri).map(|entry| &entry.tree)
    }

    /// Fetch the root of `uri` as of `timestamp`. Returns `None` if the URI is unknown or was registered after the queried time.
    pub fn get_historical_root(&self, uri: &str, timestamp: u64) -> Option<[u8; 32]> {
        self.watchlists
            .get(uri)
            .filter(|entry| timestamp >= entry.registered_at)
            .map(|entry| entry.root)
    }

    /// Fetch the current root of `uri`.
    pub fn get_root(&self, uri: &str) -> Option<[u8; 32]> {
        self.watchlists.get(uri).map(|entry| entry.root)
    }

    pub fn contains(&self, uri: &str) -> bool {
        self.watchlists.contains_key(uri)
    }

    pub fn len(&self) -> usize {
        self.watchlists.len()
    }

    pub fn is_empty(&self) -> bool {
        self.watchlists.is_empty()
    }
}

impl Default for MockRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    #[test]
    fn test_registry_creation() {
        let registry = MockRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn test_register_and_retrieve() {
        let mut registry = MockRegistry::new();

        let addresses = vec![
            address!("0000000000000000000000000000000000000001"),
            address!("0000000000000000000000000000000000000003"),
        ];
        let tree = SortedMerkleTree::new(addresses).unwrap();
        let root = tree.root();

        registry.register_watchlist("test://list1".to_string(), tree, 1704067200);

        assert!(registry.contains("test://list1"));
        assert_eq!(registry.len(), 1);

        let retrieved_tree = registry.get_tree("test://list1").unwrap();
        assert_eq!(retrieved_tree.root(), root);

        let retrieved_root = registry.get_root("test://list1").unwrap();
        assert_eq!(retrieved_root, root);
    }

    #[test]
    fn test_historical_root() {
        let mut registry = MockRegistry::new();

        let addresses = vec![
            address!("0000000000000000000000000000000000000001"),
        ];
        let tree = SortedMerkleTree::new(addresses).unwrap();
        let root = tree.root();

        let timestamp = 1704067200u64;
        registry.register_watchlist("test://list1".to_string(), tree, timestamp);

        // Get historical root (in this simplified version, always returns current)
        let historical_root = registry.get_historical_root("test://list1", timestamp).unwrap();
        assert_eq!(historical_root, root);
    }

    #[test]
    fn test_missing_watchlist() {
        let registry = MockRegistry::new();

        assert!(!registry.contains("missing://list"));
        assert!(registry.get_tree("missing://list").is_none());
        assert!(registry.get_root("missing://list").is_none());
        assert!(registry.get_historical_root("missing://list", 0).is_none());
    }

    #[test]
    fn test_multiple_watchlists() {
        let mut registry = MockRegistry::new();

        let addresses1 = vec![address!("0000000000000000000000000000000000000001")];
        let tree1 = SortedMerkleTree::new(addresses1).unwrap();

        let addresses2 = vec![address!("0000000000000000000000000000000000000002")];
        let tree2 = SortedMerkleTree::new(addresses2).unwrap();

        registry.register_watchlist("test://list1".to_string(), tree1.clone(), 1704067200);
        registry.register_watchlist("test://list2".to_string(), tree2.clone(), 1704067300);

        assert_eq!(registry.len(), 2);
        assert!(registry.contains("test://list1"));
        assert!(registry.contains("test://list2"));

        assert_eq!(registry.get_root("test://list1").unwrap(), tree1.root());
        assert_eq!(registry.get_root("test://list2").unwrap(), tree2.root());
    }
}
