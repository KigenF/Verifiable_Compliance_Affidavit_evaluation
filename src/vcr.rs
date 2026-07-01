//! Verifiable Compliance Record (VCR): types, generation and verification.
//!
//! Implements GenVCR (Algorithm 1) and VerifyVCR (Algorithm 2) with ECDSA signatures over keccak256-hashed messages.

use alloy_primitives::Address;
use k256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use thiserror::Error;

use crate::merkle::NonMembershipProof;
use crate::registry::MockRegistry;

#[derive(Error, Debug)]
pub enum VcrError {
    #[error("Signature generation failed: {0}")]
    SignatureError(String),

    #[error("Policy and proofs count mismatch")]
    PolicyProofMismatch,

    #[error("Invalid policy: {0}")]
    InvalidPolicy(String),

    #[error("Watchlist not found in registry: {0}")]
    WatchlistNotFound(String),

    #[error("Merkle tree error: {0}")]
    MerkleError(#[from] crate::merkle::MerkleError),
}

/// Context binding a VCR to a specific transaction: `C = (pkR, NS)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Context {
    /// Receiver's ECDSA public key (compressed, 33 bytes).
    #[serde(serialize_with = "serialize_verifying_key")]
    #[serde(deserialize_with = "deserialize_verifying_key")]
    pub pk_receiver: VerifyingKey,
    /// Sender's transaction nonce.
    pub nonce_sender: u64,
}

fn serialize_verifying_key<S>(key: &VerifyingKey, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let bytes = key.to_encoded_point(true);
    serializer.serialize_bytes(bytes.as_bytes())
}

fn deserialize_verifying_key<'de, D>(deserializer: D) -> Result<VerifyingKey, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use k256::EncodedPoint;

    let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
    let point = EncodedPoint::from_bytes(&bytes)
        .map_err(|e| serde::de::Error::custom(format!("Invalid point: {}", e)))?;

    let key = VerifyingKey::from_encoded_point(&point)
        .map_err(|e| serde::de::Error::custom(format!("Invalid verifying key: {}", e)))?;

    Ok(key)
}

impl Context {
    pub fn new(pk_receiver: VerifyingKey, nonce_sender: u64) -> Self {
        Self {
            pk_receiver,
            nonce_sender,
        }
    }

    /// Serialized size: 33-byte compressed pubkey + 8-byte nonce.
    pub fn size_bytes(&self) -> usize {
        33 + 8
    }

    /// Derive the receiver's address `H(pkR) = keccak256(pkR)[12..32]`.
    pub fn receiver_address(&self) -> Address {
        let point = self.pk_receiver.to_encoded_point(false);
        let pubkey_bytes = &point.as_bytes()[1..]; // drop the 0x04 prefix

        let mut hasher = Keccak256::new();
        hasher.update(pubkey_bytes);
        let hash = hasher.finalize();

        Address::from_slice(&hash[12..32])
    }
}

/// Compliance policy: a set of CryptoWatchlist URIs `P = {URI₁, ..., URIₖ}`.
/// Merkle roots are resolved from the registry at verification time.
pub type Policy = Vec<String>;

/// Signed message `M = (P, C, Π)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceMessage {
    pub policy: Policy,
    pub context: Context,
    /// One non-membership proof per policy entry (positional 1:1 mapping).
    pub proofs: Vec<NonMembershipProof>,
}

/// Verifiable Compliance Record `VCR = (M, σ)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VCR {
    pub message: ComplianceMessage,
    pub signature: VcrSignature,
}

/// Minimal transaction structure consumed by VerifyVCR.
#[derive(Debug, Clone)]
pub struct Transaction {
    pub addr_sender: Address,
    pub addr_receiver: Address,
    pub nonce: u64,
    /// Unix timestamp used to fetch the historical watchlist root.
    pub time: u64,
    /// Transaction payload carrying the serialized VCR.
    pub payload: Vec<u8>,
}

/// ECDSA signature `(r, s, v)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VcrSignature {
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub v: u8,
}

impl VcrSignature {
    pub fn from_signature(sig: &Signature, recovery_id: u8) -> Self {
        let sig_bytes = sig.to_bytes();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&sig_bytes[..32]);
        s.copy_from_slice(&sig_bytes[32..]);

        Self {
            r,
            s,
            v: recovery_id,
        }
    }

    /// Serialized size: r(32) + s(32) + v(1).
    pub fn size_bytes(&self) -> usize {
        65
    }
}

impl VCR {
    /// GenVCR (Algorithm 1): build and sign a VCR, fetching watchlists from the registry and generating one non-membership proof per policy entry.
    pub fn generate_with_registry(
        signing_key: &SigningKey,
        policy: Policy,
        addr_sender: &Address,
        nonce_sender: u64,
        registry: &MockRegistry,
    ) -> Result<Self, VcrError> {
        let context = Context::new(VerifyingKey::from(signing_key), nonce_sender);

        let mut proofs = Vec::new();
        for uri in &policy {
            if uri.is_empty() {
                return Err(VcrError::InvalidPolicy("Empty URI".to_string()));
            }
            let tree = registry
                .get_tree(uri)
                .ok_or_else(|| VcrError::WatchlistNotFound(uri.clone()))?;
            proofs.push(tree.generate_non_membership_proof(addr_sender)?);
        }

        let message = ComplianceMessage {
            policy,
            context,
            proofs,
        };
        Ok(Self {
            signature: Self::sign(signing_key, &message)?,
            message,
        })
    }

    /// GenVCR variant that accepts pre-generated proofs (testing/benchmarking).
    pub fn generate(
        signing_key: &SigningKey,
        policy: Policy,
        context: Context,
        proofs: Vec<NonMembershipProof>,
    ) -> Result<Self, VcrError> {
        if policy.len() != proofs.len() {
            return Err(VcrError::PolicyProofMismatch);
        }
        for uri in &policy {
            if uri.is_empty() {
                return Err(VcrError::InvalidPolicy("Empty URI".to_string()));
            }
        }

        let message = ComplianceMessage {
            policy,
            context,
            proofs,
        };
        Ok(Self {
            signature: Self::sign(signing_key, &message)?,
            message,
        })
    }

    fn sign(signing_key: &SigningKey, message: &ComplianceMessage) -> Result<VcrSignature, VcrError> {
        let digest = Self::hash_message(&Self::create_message_bytes(message));
        let signature: Signature = signing_key
            .try_sign(&digest)
            .map_err(|e| VcrError::SignatureError(e.to_string()))?;
        // Recovery id is unused: verification uses the public key from the context.
        Ok(VcrSignature::from_signature(&signature, 0))
    }

    /// Canonical message bytes for signing. JSON is used for simplicity; a production deployment would use ABI encoding.
    fn create_message_bytes(message: &ComplianceMessage) -> Vec<u8> {
        serde_json::to_vec(&message).expect("Serialization should not fail")
    }

    fn hash_message(message: &[u8]) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(message);
        hasher.finalize().into()
    }

    /// Verify only the ECDSA signature over the message.
    pub fn verify_signature(&self, verifying_key: &VerifyingKey) -> bool {
        use k256::ecdsa::signature::Verifier;

        let digest = Self::hash_message(&Self::create_message_bytes(&self.message));

        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&self.signature.r);
        sig_bytes[32..].copy_from_slice(&self.signature.s);

        let signature = match Signature::from_bytes(&sig_bytes.into()) {
            Ok(sig) => sig,
            Err(_) => return false,
        };
        verifying_key.verify(&digest, &signature).is_ok()
    }

    /// VerifyVCR (Algorithm 2): full stateless verification against a transaction and the verifier's policy. Returns true iff every check passes.
    pub fn verify_with_registry(
        &self,
        tx: &Transaction,
        policy_verifier: &Policy,
        registry: &MockRegistry,
    ) -> bool {
        let policy = &self.message.policy;
        let context = &self.message.context;
        let proofs = &self.message.proofs;

        // Step 1: Policy coverage — Pverifier ⊆ P.
        for uri in policy_verifier {
            if !policy.contains(uri) {
                return false;
            }
        }

        // Step 2: Binding — H(pkR) = Tx.AddrR and NS = Tx.Nonce.
        if context.receiver_address() != tx.addr_receiver {
            return false;
        }
        if context.nonce_sender != tx.nonce {
            return false;
        }

        // Step 3: Integrity — signature over M under pkR.
        if !self.verify_signature(&context.pk_receiver) {
            return false;
        }

        // Step 4: Non-membership — one proof per policy entry (positional).
        for (proof, uri) in proofs.iter().zip(policy.iter()) {
            if proof.addr != tx.addr_sender {
                return false;
            }
            let historical_root = match registry.get_historical_root(uri, tx.time) {
                Some(root) => root,
                None => return false,
            };
            if proof.root != historical_root {
                return false;
            }
            if !proof.verify(&proof.root, &proof.addr) {
                return false;
            }
        }

        true
    }

    /// Verify the signature and every non-membership proof against the proofs' own roots (without the transaction-binding checks of VerifyVCR).
    pub fn verify(&self, verifying_key: &VerifyingKey) -> bool {
        if !self.verify_signature(verifying_key) {
            return false;
        }
        if self.message.policy.len() != self.message.proofs.len() {
            return false;
        }
        self.message
            .proofs
            .iter()
            .all(|proof| proof.verify(&proof.root, &proof.addr))
    }

    /// Total serialized VCR size in bytes.
    pub fn size_bytes(&self) -> usize {
        let policy_size: usize = self.message.policy.iter().map(|uri| uri.len()).sum();
        let proofs_size: usize = self.message.proofs.iter().map(|p| p.size_bytes()).sum();

        policy_size + self.message.context.size_bytes() + proofs_size + self.signature.size_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::SortedMerkleTree;
    use crate::registry::MockRegistry;
    use alloy_primitives::address;
    use k256::ecdsa::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn test_context_creation() {
        let signing_key = SigningKey::random(&mut OsRng);
        let pk_receiver = VerifyingKey::from(&signing_key);

        let ctx = Context::new(pk_receiver, 1);

        assert_eq!(ctx.nonce_sender, 1);
        assert_eq!(ctx.size_bytes(), 41);
    }

    #[test]
    fn test_context_receiver_address() {
        let signing_key = SigningKey::random(&mut OsRng);
        let pk_receiver = VerifyingKey::from(&signing_key);

        let ctx = Context::new(pk_receiver, 1);
        assert_eq!(ctx.receiver_address().len(), 20);
    }

    #[test]
    fn test_vcr_generation() {
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

        assert_eq!(vcr.message.policy.len(), 1);
        assert_eq!(vcr.message.proofs.len(), 1);
        assert_eq!(vcr.signature.size_bytes(), 65);
    }

    #[test]
    fn test_vcr_signature_verification() {
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

        assert!(vcr.verify_signature(&pk_receiver));
        assert!(vcr.verify(&pk_receiver));
    }

    #[test]
    fn test_policy_proof_mismatch() {
        let signing_key = SigningKey::random(&mut OsRng);
        let pk_receiver = VerifyingKey::from(&signing_key);

        let policy = vec![
            "test1://watchlist".to_string(),
            "test2://watchlist".to_string(),
        ];
        let context = Context::new(pk_receiver, 1);

        let result = VCR::generate(&signing_key, policy, context, vec![]);
        assert!(matches!(result, Err(VcrError::PolicyProofMismatch)));
    }

    #[test]
    fn test_vcr_with_registry() {
        let signing_key = SigningKey::random(&mut OsRng);

        let addresses = vec![
            address!("0000000000000000000000000000000000000001"),
            address!("0000000000000000000000000000000000000003"),
        ];
        let tree = SortedMerkleTree::new(addresses).unwrap();

        let mut registry = MockRegistry::new();
        registry.register_watchlist("test://watchlist".to_string(), tree, 1704067200);

        let policy = vec!["test://watchlist".to_string()];
        let addr_sender = address!("0000000000000000000000000000000000000002");

        let vcr =
            VCR::generate_with_registry(&signing_key, policy.clone(), &addr_sender, 1, &registry)
                .unwrap();

        assert_eq!(vcr.message.policy.len(), 1);
        assert_eq!(vcr.message.proofs.len(), 1);

        let addr_receiver = vcr.message.context.receiver_address();
        let tx = Transaction {
            addr_sender,
            addr_receiver,
            nonce: 1,
            time: 1704067200,
            payload: vec![],
        };

        assert!(vcr.verify_with_registry(&tx, &policy, &registry));
    }
}
