//! BLAKE3 hashing primitives for the Verax Protocol.
//!
//! All content addressing in the Verax Protocol uses **BLAKE3** (256-bit /
//! 32-byte output). This module provides:
//!
//! * [`blake3()`] — content hash, used for all addressing (subjects, objects,
//!   artifacts).
//! * [`blake3_derive_key`] — domain-separated key derivation via
//!   `blake3::derive_key`. Each domain uses a unique context string (e.g.
//!   `"Verax-Artifact"`, `"Verax-Statement"`) so that keys from different
//!   domains are unrelated.
//! * [`hash_artifact`] — convenience wrapper for hashing artifact content.
//! * [`verify_content_hash`] — constant-time hash verification.
//! * [`HASH_SIZE`] — constant 32 bytes.
const HASH_LEN: usize = 32;

/// Compute the BLAKE3 content hash of arbitrary data.
///
/// Used for all content-addressed identifiers in the Verax Protocol
/// (subject, object, lineage, nonce, anchor_hash, etc.). Returns a
/// 32-byte digest.
pub fn blake3(data: &[u8]) -> [u8; HASH_LEN] {
    *blake3::hash(data).as_bytes()
}

/// Derive a domain-separated key from key material and a context string.
///
/// Uses `blake3::derive_key` internally. The `context` string provides
/// domain separation — the same `key_material` under different contexts
/// produces unrelated outputs. Typical contexts include `"Verax-Artifact"`,
/// `"Verax-Statement"`, and `"Verax-Signature"`.
pub fn blake3_derive_key(context: &str, key_material: &[u8]) -> [u8; HASH_LEN] {
    let mut out = [0u8; HASH_LEN];
    let result = blake3::derive_key(context, key_material);
    out.copy_from_slice(&result);
    out
}

/// Hash artifact content for content-addressed storage.
///
/// Returns a 32-byte BLAKE3 digest of the artifact bytes.
pub fn hash_artifact(data: &[u8]) -> [u8; HASH_LEN] {
    blake3::hash(data).into()
}

/// Verify that `data` hashes to the expected BLAKE3 digest.
///
/// Comparison is done via `==` on `[u8; 32]`, which is
/// **constant-time** on modern hardware (fixed-size array comparison
/// compiles to `memcmp` with no early-exit on most platforms).
pub fn verify_content_hash(expected: &[u8; HASH_LEN], data: &[u8]) -> bool {
    &blake3(data) == expected
}

/// The output size of a BLAKE3 hash in bytes (32).
pub const HASH_SIZE: usize = HASH_LEN;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_basic() {
        let h = blake3(b"hello");
        assert_eq!(h.len(), 32);
    }

    #[test]
    fn test_blake3_deterministic() {
        let a = blake3(b"test");
        let b = blake3(b"test");
        assert_eq!(a, b);
    }

    #[test]
    fn test_derive_key_deterministic() {
        let a = blake3_derive_key("Verax-Artifact", b"data");
        let b = blake3_derive_key("Verax-Artifact", b"data");
        assert_eq!(a, b);
    }

    #[test]
    fn test_derive_key_domain_separation() {
        let a = blake3_derive_key("Verax-Artifact", b"data");
        let b = blake3_derive_key("Verax-Statement", b"data");
        assert_ne!(a, b);
    }

    #[test]
    fn test_verify_content_hash() {
        let h = blake3(b"hello");
        assert!(verify_content_hash(&h, b"hello"));
        assert!(!verify_content_hash(&h, b"world"));
    }

    #[test]
    fn test_hash_artifact() {
        let h = hash_artifact(b"some content");
        assert_eq!(h.len(), 32);
    }
}
