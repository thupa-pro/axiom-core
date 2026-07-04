//! # Artifact
//!
//! Content-addressed artifact hashing. An [`Artifact`] wraps a BLAKE3 hash and
//! provides verification that a given byte slice matches the hash. This is used
//! throughout the Verax protocol for content-addressed references: statements
//! refer to other statements by their BLAKE3 hash, and artifacts provide the
//! primitive to check that fetched content matches the expected hash.

use crate::error::{Error, Result};
use crate::hash;

/// A content-addressed artifact identified by its BLAKE3 hash.
///
/// `Artifact` represents a commitment to a piece of data: given the hash,
/// you can later verify that some data matches it. This is the fundamental
/// building block for content-addressed references in the Verax graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Artifact {
    hash: [u8; 32],
}

impl Artifact {
    /// Create a new `Artifact` by hashing `data` with BLAKE3.
    pub fn new(data: &[u8]) -> Self {
        Self {
            hash: hash::blake3(data),
        }
    }

    /// Create an `Artifact` from a pre-computed 32-byte hash.
    ///
    /// No verification is performed — the caller guarantees the hash is correct.
    pub fn from_hash(hash: [u8; 32]) -> Self {
        Self { hash }
    }

    /// Return a reference to the inner 32-byte BLAKE3 hash.
    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    /// Verify that `data` matches this artifact's stored hash.
    ///
    /// Returns `true` if `BLAKE3(data) == self.hash`, `false` otherwise.
    pub fn verify(&self, data: &[u8]) -> bool {
        hash::verify_content_hash(&self.hash, data)
    }

    /// Strict version of [`verify`](Self::verify) that returns a [`Result`].
    ///
    /// Returns `Ok(())` on match, or `Err(Error::Crypto)` with a descriptive
    /// message on mismatch.
    pub fn verify_strict(&self, data: &[u8]) -> Result<()> {
        if self.verify(data) {
            Ok(())
        } else {
            Err(Error::Crypto("artifact content hash mismatch".into()))
        }
    }
}

/// Convert a raw 32-byte hash directly into an [`Artifact`].
impl From<[u8; 32]> for Artifact {
    fn from(hash: [u8; 32]) -> Self {
        Self { hash }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_artifact_from_data() {
        let data = b"hello world";
        let art = Artifact::new(data);
        assert!(art.verify(data));
        assert!(!art.verify(b"wrong data"));
    }

    #[test]
    fn test_artifact_deterministic() {
        let a = Artifact::new(b"test");
        let b = Artifact::new(b"test");
        assert_eq!(a.hash(), b.hash());
    }

    #[test]
    fn test_artifact_verify_strict() {
        let art = Artifact::new(b"correct");
        assert!(art.verify_strict(b"correct").is_ok());
        assert!(art.verify_strict(b"wrong").is_err());
    }

    #[test]
    fn test_artifact_from_hash() {
        let hash = [0xabu8; 32];
        let art = Artifact::from_hash(hash);
        assert_eq!(art.hash(), &hash);
    }
}
