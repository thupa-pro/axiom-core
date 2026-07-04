//! Certificate Transparency (CT) integration for the Verax Protocol.
//!
//! This module implements RFC 9162-style Merkle tree inclusion proofs and
//! signed tree head verification, binding Verax statements to public CT logs.
//!
//! # Overview
//!
//! A [`TemporalAnchor`] is embedded in the unprotected header of a COSE_Sign1
//! envelope and proves that a statement's payload hash was included in a
//! transparency log at a particular point in time. It consists of two parts:
//!
//! 1. **[`LogInclusionProof`]** — a Merkle tree audit path from the leaf
//!    containing the payload hash up to the root hash. Verified via
//!    [`verify`](LogInclusionProof::verify) using SHA-256 with the RFC 9162
//!    node labeling scheme (`0x00` for leaves, `0x01` for internal nodes).
//! 2. **[`SignedTreeHead`]** — the log's signed commitment at a given tree
//!    size and timestamp, carrying a root hash and an Ed25519 signature over
//!    `(timestamp ‖ tree_size ‖ root_hash)`.
//!
//! The top-level [`extract_temporal_anchor`] function parses the anchor from
//! a COSE envelope's unprotected header by looking for the text-map keys
//! `"log_inclusion_proof"` and `"log_sth"`.

use crate::error::{Error, Result};
use alloc::vec::Vec;
use sha2::Digest as _;

/// A Merkle tree inclusion proof for a single leaf, as defined in RFC 9162.
///
/// The proof consists of the leaf's index in the tree and the audit path
/// (sibling hashes) needed to recompute the root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogInclusionProof {
    /// Index of the leaf in the Merkle tree (0-based).
    pub leaf_index: u64,
    /// Audit path: sibling hashes from the leaf up to the root. Each hash
    /// is 32 bytes (SHA-256 output).
    pub siblings: Vec<[u8; 32]>,
}

/// A signed tree head (STH) from a CT log, committing to the state of the
/// Merkle tree at a given timestamp.
///
/// The STH is signed by the log's Ed25519 key over the byte string
/// `timestamp (8-byte BE) ‖ tree_size (8-byte BE) ‖ root_hash (32 bytes)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTreeHead {
    /// Timestamp (seconds since epoch) when the STH was issued.
    pub timestamp: u64,
    /// Number of leaves in the tree at this STH.
    pub tree_size: u64,
    /// Root hash of the Merkle tree (SHA-256).
    pub root_hash: [u8; 32],
    /// Ed25519 signature over `(timestamp ‖ tree_size ‖ root_hash)` (64 bytes).
    pub signature: Vec<u8>,
    /// Log's Ed25519 public key (32 bytes).
    pub log_pubkey: Vec<u8>,
    /// Log identifier, computed as `BLAKE3(log_pubkey)` (32 bytes).
    pub log_id: Vec<u8>,
    /// Tree hash algorithm identifier. Must be 0 (SHA-256) for verification.
    pub tree_hash_algorithm: u64,
}

impl SignedTreeHead {
    /// Create a new [`SignedTreeHead`].
    ///
    /// The `log_id` is automatically computed as `BLAKE3(log_pubkey)` and
    /// `tree_hash_algorithm` defaults to 0 (SHA-256).
    pub fn new(
        timestamp: u64,
        tree_size: u64,
        root_hash: [u8; 32],
        signature: Vec<u8>,
        log_pubkey: Vec<u8>,
    ) -> Self {
        let log_id = crate::hash::blake3(&log_pubkey).to_vec();
        Self {
            timestamp,
            tree_size,
            root_hash,
            signature,
            log_pubkey,
            log_id,
            tree_hash_algorithm: 0,
        }
    }
}

/// A temporal anchor binding a signed statement to a CT log entry.
///
/// Contains both the Merkle inclusion proof and the corresponding signed
/// tree head. Extracted from the COSE_Sign1 unprotected header via
/// [`extract_temporal_anchor`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemporalAnchor {
    /// Merkle tree inclusion proof for the statement's payload hash.
    pub inclusion_proof: LogInclusionProof,
    /// Signed tree head committing to the root hash and timestamp.
    pub signed_tree_head: SignedTreeHead,
}

impl LogInclusionProof {
    /// Verify the inclusion proof against a leaf hash and a root hash.
    ///
    /// Recomputes the Merkle root by walking the audit path following the
    /// RFC 9162 labeling scheme:
    /// - Leaf nodes are hashed as `SHA-256(0x00 ‖ leaf_hash)`.
    /// - Internal nodes are hashed as `SHA-256(0x01 ‖ left ‖ right)`.
    ///
    /// Returns `true` if the computed root matches the given `root`.
    pub fn verify(&self, leaf_hash: &[u8; 32], root: &[u8; 32]) -> bool {
        let computed = self.compute_root(leaf_hash);
        computed == *root
    }

    fn compute_root(&self, leaf_hash: &[u8; 32]) -> [u8; 32] {
        let mut current: [u8; 32] = sha2::Sha256::new()
            .chain_update([0x00u8])
            .chain_update(leaf_hash)
            .finalize()
            .into();
        let mut idx = self.leaf_index;
        for sibling in &self.siblings {
            let mut hasher = sha2::Sha256::new();
            if idx.is_multiple_of(2) {
                hasher.update([0x01u8]);
                hasher.update(current);
                hasher.update(sibling);
            } else {
                hasher.update([0x01u8]);
                hasher.update(sibling);
                hasher.update(current);
            }
            current = hasher.finalize().into();
            idx /= 2;
        }
        current
    }
}

impl LogInclusionProof {
    /// Deserialize a [`LogInclusionProof`] from CBOR at the given offset.
    ///
    /// Expected CBOR map layout:
    /// - Key 1: `leaf_index` (uint)
    /// - Key 2: `siblings` (array of 32-byte byte strings)
    pub fn from_cbor(data: &[u8], offset: &mut usize) -> Result<Self> {
        let map_len = crate::cbor::decode_map_len(data, offset)?;
        let mut leaf_index = 0u64;
        let mut siblings = Vec::new();
        for _ in 0..map_len {
            let key = crate::cbor::decode_uint(data, offset)?;
            match key {
                1 => leaf_index = crate::cbor::decode_uint(data, offset)?,
                2 => {
                    let arr_len = crate::cbor::decode_array_len(data, offset)?;
                    for _ in 0..arr_len {
                        let bstr = crate::cbor::decode_bstr(data, offset)?;
                        if bstr.len() != 32 {
                            return Err(Error::InvalidLogProof(
                                "sibling hash must be 32 bytes".into(),
                            ));
                        }
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bstr);
                        siblings.push(arr);
                    }
                }
                _ => crate::cbor::skip_value(data, offset)?,
            }
        }
        Ok(Self {
            leaf_index,
            siblings,
        })
    }
}

impl SignedTreeHead {
    /// Deserialize a [`SignedTreeHead`] from CBOR at the given offset.
    ///
    /// Expected CBOR map layout:
    /// - Key 1: `timestamp` (uint)
    /// - Key 2: `tree_size` (uint)
    /// - Key 3: `root_hash` (32-byte bstr)
    /// - Key 4: `signature` (bstr)
    /// - Key 5: `log_pubkey` (bstr)
    /// - Key 6: `log_id` (bstr, optional — computed from `log_pubkey` if absent)
    /// - Key 7: `tree_hash_algorithm` (uint, optional — defaults to 0)
    pub fn from_cbor(data: &[u8], offset: &mut usize) -> Result<Self> {
        let map_len = crate::cbor::decode_map_len(data, offset)?;
        let mut timestamp = 0u64;
        let mut tree_size = 0u64;
        let mut root_hash = [0u8; 32];
        let mut signature = Vec::new();
        let mut log_pubkey = Vec::new();
        let mut log_id = Vec::new();
        let mut tree_hash_algorithm = 0u64;
        for _ in 0..map_len {
            let key = crate::cbor::decode_uint(data, offset)?;
            match key {
                1 => timestamp = crate::cbor::decode_uint(data, offset)?,
                2 => tree_size = crate::cbor::decode_uint(data, offset)?,
                3 => {
                    let bstr = crate::cbor::decode_bstr(data, offset)?;
                    if bstr.len() != 32 {
                        return Err(Error::InvalidLogProof("root hash must be 32 bytes".into()));
                    }
                    root_hash.copy_from_slice(&bstr);
                }
                4 => {
                    signature = crate::cbor::decode_bstr(data, offset)?;
                }
                5 => {
                    log_pubkey = crate::cbor::decode_bstr(data, offset)?;
                }
                6 => {
                    log_id = crate::cbor::decode_bstr(data, offset)?;
                }
                7 => {
                    tree_hash_algorithm = crate::cbor::decode_uint(data, offset)?;
                }
                _ => crate::cbor::skip_value(data, offset)?,
            }
        }
        if log_id.is_empty() {
            log_id = crate::hash::blake3(&log_pubkey).to_vec();
        }
        Ok(Self {
            timestamp,
            tree_size,
            root_hash,
            signature,
            log_pubkey,
            log_id,
            tree_hash_algorithm,
        })
    }

    /// Serialize the [`SignedTreeHead`] to CBOR.
    ///
    /// Produces a 7-key map with keys 1 through 7 corresponding to the
    /// fields `timestamp`, `tree_size`, `root_hash`, `signature`,
    /// `log_pubkey`, `log_id`, and `tree_hash_algorithm`.
    pub fn to_cbor(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        crate::cbor::encode_uint_head(&mut buf, 0xa0, 7);
        crate::cbor::encode_uint_head(&mut buf, 0x00, 1);
        crate::cbor::encode_uint(&mut buf, self.timestamp);
        crate::cbor::encode_uint_head(&mut buf, 0x00, 2);
        crate::cbor::encode_uint(&mut buf, self.tree_size);
        crate::cbor::encode_uint_head(&mut buf, 0x00, 3);
        crate::cbor::encode_uint_head(&mut buf, 0x40, 32);
        buf.extend_from_slice(&self.root_hash);
        crate::cbor::encode_uint_head(&mut buf, 0x00, 4);
        crate::cbor::encode_uint_head(&mut buf, 0x40, self.signature.len() as u64);
        buf.extend_from_slice(&self.signature);
        crate::cbor::encode_uint_head(&mut buf, 0x00, 5);
        crate::cbor::encode_uint_head(&mut buf, 0x40, self.log_pubkey.len() as u64);
        buf.extend_from_slice(&self.log_pubkey);
        crate::cbor::encode_uint_head(&mut buf, 0x00, 6);
        crate::cbor::encode_uint_head(&mut buf, 0x40, self.log_id.len() as u64);
        buf.extend_from_slice(&self.log_id);
        crate::cbor::encode_uint_head(&mut buf, 0x00, 7);
        crate::cbor::encode_uint(&mut buf, self.tree_hash_algorithm);
        buf
    }
}

fn try_read_text_key(data: &[u8], offset: &mut usize) -> Option<Vec<u8>> {
    let saved = *offset;
    match crate::cbor::decode_text_string(data, offset) {
        Ok(key) => Some(key),
        Err(_) => {
            *offset = saved;
            None
        }
    }
}

/// Extract a [`TemporalAnchor`] from the unprotected header of a COSE_Sign1
/// envelope.
///
/// Looks for the text-map keys `"log_inclusion_proof"` and `"log_sth"` in
/// the unprotected header and deserializes the corresponding CBOR-encoded
/// values. Returns `None` if either key is missing or deserialization fails.
pub fn extract_temporal_anchor(cose_bytes: &[u8]) -> Option<TemporalAnchor> {
    let unprotected = crate::cose::extract_unprotected(cose_bytes).ok()?;
    let mut offset = 0usize;
    let map_len = crate::cbor::decode_map_len(&unprotected, &mut offset).ok()?;
    let mut inclusion_proof = None;
    let mut signed_tree_head = None;
    for _ in 0..map_len {
        if let Some(key) = try_read_text_key(&unprotected, &mut offset) {
            if key == b"log_inclusion_proof" {
                let bstr = crate::cbor::decode_bstr(&unprotected, &mut offset).ok()?;
                let mut off = 0;
                inclusion_proof = LogInclusionProof::from_cbor(&bstr, &mut off).ok();
            } else if key == b"log_sth" {
                let bstr = crate::cbor::decode_bstr(&unprotected, &mut offset).ok()?;
                let mut off = 0;
                signed_tree_head = SignedTreeHead::from_cbor(&bstr, &mut off).ok();
            } else {
                crate::cbor::skip_value(&unprotected, &mut offset).ok()?;
            }
        } else {
            crate::cbor::skip_value(&unprotected, &mut offset).ok()?;
            crate::cbor::skip_value(&unprotected, &mut offset).ok()?;
        }
    }
    match (inclusion_proof, signed_tree_head) {
        (Some(proof), Some(sth)) => Some(TemporalAnchor {
            inclusion_proof: proof,
            signed_tree_head: sth,
        }),
        _ => None,
    }
}

impl TemporalAnchor {
    /// Verify that the inclusion proof matches the payload hash against the
    /// STH root hash.
    ///
    /// Checks:
    /// - `tree_size > 0`
    /// - `leaf_index < tree_size`
    /// - The computed Merkle root from the inclusion proof equals the STH's
    ///   `root_hash` (via [`LogInclusionProof::verify`]).
    pub fn verify_inclusion(&self, payload_hash: &[u8; 32]) -> Result<()> {
        if self.signed_tree_head.tree_size == 0 {
            return Err(Error::InvalidLogProof(
                "STH tree_size must be greater than 0".into(),
            ));
        }
        if self.inclusion_proof.leaf_index >= self.signed_tree_head.tree_size {
            return Err(Error::InvalidLogProof(
                "leaf_index exceeds tree_size".into(),
            ));
        }
        if !self
            .inclusion_proof
            .verify(payload_hash, &self.signed_tree_head.root_hash)
        {
            return Err(Error::InvalidLogProof(
                "inclusion proof does not match STH".into(),
            ));
        }
        Ok(())
    }

    /// Verify the Ed25519 signature on the signed tree head.
    ///
    /// Checks:
    /// - `log_pubkey` must be exactly 32 bytes.
    /// - `log_id` must be exactly 32 bytes.
    /// - `tree_hash_algorithm` must be 0 (only SHA-256 is supported).
    /// - If a `trusted_key` is provided, the STH's `log_pubkey` must match.
    /// - The signature over `(timestamp ‖ tree_size ‖ root_hash)` is verified
    ///   using Ed25519.
    ///
    /// Returns an error if the STH is untrusted (`trusted_key` is `None`).
    pub fn verify_sth_signature(&self, trusted_key: Option<&[u8; 32]>) -> Result<()> {
        if self.signed_tree_head.log_pubkey.len() != 32 {
            return Err(Error::InvalidLogProof(
                "STH must carry a 32-byte log public key".into(),
            ));
        }
        if self.signed_tree_head.log_id.len() != 32 {
            return Err(Error::InvalidLogProof(
                "STH must carry a 32-byte log_id".into(),
            ));
        }
        if self.signed_tree_head.tree_hash_algorithm != 0 {
            return Err(Error::InvalidLogProof(
                "unsupported tree hash algorithm; only SHA-256 (0) is supported".into(),
            ));
        }
        let mut stm_pubkey = [0u8; 32];
        stm_pubkey.copy_from_slice(&self.signed_tree_head.log_pubkey);

        let resolved_key = match trusted_key {
            Some(tk) => {
                if &stm_pubkey != tk {
                    return Err(Error::InvalidLogProof(
                        "STH public key does not match trusted key".into(),
                    ));
                }
                *tk
            }
            None => {
                return Err(Error::InvalidLogProof("STH from untrusted log".into()));
            }
        };

        let mut data = Vec::new();
        data.extend_from_slice(&self.signed_tree_head.timestamp.to_be_bytes());
        data.extend_from_slice(&self.signed_tree_head.tree_size.to_be_bytes());
        data.extend_from_slice(&self.signed_tree_head.root_hash);

        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&resolved_key)
            .map_err(|_| Error::Crypto("invalid CT log public key".into()))?;

        if self.signed_tree_head.signature.len() != 64 {
            return Err(Error::InvalidLogProof(
                "STH signature must be 64 bytes".into(),
            ));
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&self.signed_tree_head.signature);

        use ed25519_dalek::ed25519::signature::Verifier;
        verifying_key
            .verify(&data, &ed25519_dalek::Signature::from_bytes(&sig_bytes))
            .map_err(|_| Error::InvalidLogProof("STH signature verification failed".into()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash;
    use alloc::vec;

    #[test]
    fn test_inclusion_proof_single_leaf() {
        let data = hash::blake3(b"single leaf");
        let root: [u8; 32] = sha2::Sha256::new()
            .chain_update([0x00u8])
            .chain_update(&data)
            .finalize()
            .into();
        let proof = LogInclusionProof {
            leaf_index: 0,
            siblings: vec![],
        };
        assert!(proof.verify(&data, &root));
    }

    fn sha256_leaf(leaf: &[u8; 32]) -> [u8; 32] {
        sha2::Sha256::new()
            .chain_update([0x00u8])
            .chain_update(leaf)
            .finalize()
            .into()
    }

    fn sha256_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        sha2::Sha256::new()
            .chain_update([0x01u8])
            .chain_update(left)
            .chain_update(right)
            .finalize()
            .into()
    }

    #[test]
    fn test_inclusion_proof_two_leaves() {
        let leaf0 = hash::blake3(b"leaf0");
        let leaf1 = hash::blake3(b"leaf1");

        let h0 = sha256_leaf(&leaf0);
        let h1 = sha256_leaf(&leaf1);
        let root = sha256_node(&h0, &h1);

        let proof = LogInclusionProof {
            leaf_index: 0,
            siblings: vec![h1],
        };
        assert!(proof.verify(&leaf0, &root));
    }

    #[test]
    fn test_inclusion_proof_rejects_wrong_leaf() {
        let leaf0 = hash::blake3(b"leaf0");
        let leaf1 = hash::blake3(b"leaf1");
        let wrong = hash::blake3(b"wrong");

        let h0 = sha256_leaf(&leaf0);
        let h1 = sha256_leaf(&leaf1);
        let root = sha256_node(&h0, &h1);

        let proof = LogInclusionProof {
            leaf_index: 0,
            siblings: vec![h1],
        };
        assert!(!proof.verify(&wrong, &root));
    }
}
