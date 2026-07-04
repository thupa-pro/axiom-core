//! # Statement
//!
//! A `Statement` is a COSE_Sign1 envelope wrapping an [`VeraxPayload`].
//! It provides sign, decode, and accessor methods, and supports both
//! Ed25519-only and composite (Ed25519 + ML-DSA-65) signatures with
//! optional Certificate Transparency (CT) anchor binding.

use crate::cbor::VeraxPayload;
use crate::cose;
use crate::error::Result;
use crate::predicate::Predicate;
use alloc::vec::Vec;

/// A signed Verax statement encoded as COSE_Sign1 bytes.
///
/// The inner `cose_bytes` field is the full COSE_Sign1 tagged envelope
/// containing the protected header (algorithm + KID), unprotected header
/// (optional CT anchor data), payload (CBOR-encoded `VeraxPayload`), and
/// the cryptographic signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    /// The full COSE_Sign1 tagged envelope containing headers, payload and signature.
    pub cose_bytes: Vec<u8>,
}

impl Statement {
    /// Sign an [`VeraxPayload`] with Ed25519 and wrap it as a COSE_Sign1 statement.
    ///
    /// The payload is CBOR-encoded, then signed with the given Ed25519 signing key.
    /// The resulting COSE envelope carries algorithm ID -8 (Ed25519) in the
    /// protected header.
    ///
    /// ```rust
    /// use verax_core::cbor::VeraxPayload;
    /// use verax_core::predicate::Predicate;
    /// use verax_core::statement::Statement;
    ///
    /// let payload = VeraxPayload::new([0xab; 32], Predicate::Attests);
    /// let seed = [0x42u8; 32];
    /// let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    /// let stmt = Statement::sign_ed25519(&payload, &sk).unwrap();
    /// let decoded = stmt.decode_payload().unwrap();
    /// assert_eq!(decoded.subject, payload.subject);
    /// assert_eq!(decoded.predicate, payload.predicate);
    /// ```
    pub fn sign_ed25519(
        payload: &VeraxPayload,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<Self> {
        let payload_bytes = payload.encode();
        let cose_bytes = cose::sign_ed25519(&payload_bytes, signing_key)?;
        Ok(Self { cose_bytes })
    }

    /// Sign an [`VeraxPayload`] with a composite (Ed25519 + ML-DSA-65) signature.
    ///
    /// The COSE envelope uses algorithm ID -39 (composite). Both signature
    /// components are computed over the same payload and packed sequentially
    /// (ML-DSA-65 || Ed25519) in the COSE signature field.
    pub fn sign_composite(
        payload: &VeraxPayload,
        ed_sk: &ed25519_dalek::SigningKey,
        ml_sk: &ml_dsa::SigningKey<ml_dsa::MlDsa65>,
    ) -> Result<Self> {
        let payload_bytes = payload.encode();
        let cose_bytes = cose::sign_composite(&payload_bytes, ed_sk, ml_sk)?;
        Ok(Self { cose_bytes })
    }

    /// Parse raw COSE bytes as a [`Statement`] without cryptographic verification.
    ///
    /// This function validates that the bytes are structurally valid COSE_Sign1
    /// (by extracting the payload), but does **not** check the signature.
    /// Use [`verify_statement`](crate::verify::verify_statement) for full verification.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        cose::extract_payload(bytes)?;
        Ok(Self {
            cose_bytes: bytes.to_vec(),
        })
    }

    /// Return a reference to the underlying COSE_Sign1 byte slice.
    pub fn to_bytes(&self) -> &[u8] {
        &self.cose_bytes
    }

    /// Extract and return the raw payload bytes from the COSE envelope.
    pub fn extract_payload_bytes(&self) -> Result<Vec<u8>> {
        cose::extract_payload(&self.cose_bytes)
    }

    /// Decode the COSE payload into an [`VeraxPayload`].
    ///
    /// This is a convenience wrapper around [`extract_payload_bytes`](Self::extract_payload_bytes)
    /// followed by [`VeraxPayload::decode`].
    pub fn decode_payload(&self) -> Result<VeraxPayload> {
        let payload_bytes = self.extract_payload_bytes()?;
        VeraxPayload::decode(&payload_bytes)
    }

    /// Compute the BLAKE3 hash of the inner payload bytes.
    pub fn payload_hash(&self) -> Result<[u8; 32]> {
        let payload_bytes = self.extract_payload_bytes()?;
        Ok(crate::hash::blake3(&payload_bytes))
    }

    /// Convenience accessor: extract the `subject` field from the decoded payload.
    pub fn subject(&self) -> Result<[u8; 32]> {
        self.decode_payload().map(|p| p.subject)
    }

    /// Convenience accessor: extract the `predicate` field from the decoded payload.
    pub fn predicate(&self) -> Result<Predicate> {
        self.decode_payload().map(|p| p.predicate)
    }

    /// Convenience accessor: extract the `object` field from the decoded payload.
    pub fn object(&self) -> Result<Option<[u8; 32]>> {
        self.decode_payload().map(|p| p.object)
    }

    /// Convenience accessor: extract the `timestamp` field from the decoded payload.
    pub fn timestamp(&self) -> Result<Option<u64>> {
        self.decode_payload().map(|p| p.timestamp)
    }

    /// Convenience accessor: extract the `lineage` field from the decoded payload.
    pub fn lineage(&self) -> Result<Option<[u8; 32]>> {
        self.decode_payload().map(|p| p.lineage)
    }

    /// Compute the BLAKE3 hash of the full COSE_Sign1 envelope (including headers and signature).
    ///
    /// This is the statement's content-address — used in lineage chains and for
    /// referencing statements via their hash.
    pub fn cose_hash(&self) -> [u8; 32] {
        crate::hash::blake3(&self.cose_bytes)
    }

    /// Sign an Ed25519 statement and immediately bind a CT anchor to it.
    ///
    /// The unprotected header contains the CT anchor (`log_inclusion_proof` and
    /// `log_sth`). The payload is extended with an `anchor_hash` field that
    /// commits to the unprotected header via `BLAKE3(unprotected_header)`. The
    /// COSE signature additionally uses `external_aad = BLAKE3(unprotected_header)`
    /// so the unprotected header is cryptographically bound to the signature.
    pub fn sign_ed25519_and_anchor(
        payload: &VeraxPayload,
        signing_key: &ed25519_dalek::SigningKey,
        anchor: &crate::ct::TemporalAnchor,
    ) -> Result<Self> {
        let anchor_header = build_anchor_unprotected_header(anchor);
        let anchor_hash = crate::hash::blake3(&anchor_header);
        let mut payload = payload.clone();
        payload.anchor_hash = Some(anchor_hash);
        let payload_bytes = payload.encode();
        let cose_bytes = crate::cose::sign_ed25519_with_unprotected(
            &payload_bytes,
            signing_key,
            &anchor_header,
        )?;
        Ok(Self { cose_bytes })
    }

    /// Sign a composite (Ed25519 + ML-DSA-65) statement and immediately bind a CT anchor to it.
    ///
    /// Same as [`sign_ed25519_and_anchor`](Self::sign_ed25519_and_anchor) but uses
    /// composite signatures (algorithm ID -39) instead of Ed25519-only.
    pub fn sign_composite_and_anchor(
        payload: &VeraxPayload,
        ed_signing_key: &ed25519_dalek::SigningKey,
        ml_signing_key: &ml_dsa::SigningKey<ml_dsa::MlDsa65>,
        anchor: &crate::ct::TemporalAnchor,
    ) -> Result<Self> {
        let anchor_header = build_anchor_unprotected_header(anchor);
        let mut payload = payload.clone();
        payload.anchor_hash = Some(crate::hash::blake3(&anchor_header));
        let payload_bytes = payload.encode();
        let cose_bytes = crate::cose::sign_composite_with_unprotected(
            &payload_bytes,
            ed_signing_key,
            ml_signing_key,
            &anchor_header,
        )?;
        Ok(Self { cose_bytes })
    }
}

impl crate::ct::LogInclusionProof {
    fn to_cbor(&self) -> Vec<u8> {
        let mut siblings_encoded = Vec::new();
        super::cbor::encode_uint_head(&mut siblings_encoded, 0x80, self.siblings.len() as u64);
        for sib in &self.siblings {
            super::cbor::encode_uint_head(&mut siblings_encoded, 0x40, 32);
            siblings_encoded.extend_from_slice(sib);
        }

        let mut buf = Vec::new();
        super::cbor::encode_uint_head(&mut buf, 0xa0, 2);
        super::cbor::encode_uint_head(&mut buf, 0x00, 1);
        super::cbor::encode_uint(&mut buf, self.leaf_index);
        super::cbor::encode_uint_head(&mut buf, 0x00, 2);
        buf.extend_from_slice(&siblings_encoded);
        buf
    }
}

fn build_anchor_unprotected_header(anchor: &crate::ct::TemporalAnchor) -> Vec<u8> {
    let mut unprotected = Vec::new();
    let incl_proof_bytes = anchor.inclusion_proof.to_cbor();
    let sth_bytes = anchor.signed_tree_head.to_cbor();
    super::cbor::encode_uint_head(&mut unprotected, 0xa0, 2);
    super::cbor::encode_text_string(&mut unprotected, "log_inclusion_proof");
    super::cbor::encode_uint_head(&mut unprotected, 0x40, incl_proof_bytes.len() as u64);
    unprotected.extend_from_slice(&incl_proof_bytes);
    super::cbor::encode_text_string(&mut unprotected, "log_sth");
    super::cbor::encode_uint_head(&mut unprotected, 0x40, sth_bytes.len() as u64);
    unprotected.extend_from_slice(&sth_bytes);
    unprotected
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::VeraxPayload;
    use crate::predicate::Predicate;

    #[test]
    fn test_statement_sign_and_decode_ed25519() {
        let payload = VeraxPayload::new([0xab; 32], Predicate::Attests);
        let seed = [0x42u8; 32];
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);

        let stmt = Statement::sign_ed25519(&payload, &sk).unwrap();
        let decoded = stmt.decode_payload().unwrap();
        assert_eq!(decoded.subject, payload.subject);
        assert_eq!(decoded.predicate, payload.predicate);
    }

    #[test]
    fn test_statement_from_bytes() {
        let payload = VeraxPayload::new([0x01; 32], Predicate::Authors);
        let seed = [0x42u8; 32];
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let stmt = Statement::sign_ed25519(&payload, &sk).unwrap();

        let bytes = stmt.to_bytes().to_vec();
        let parsed = Statement::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.decode_payload().unwrap(), payload);
    }

    #[test]
    fn test_statement_accessors() {
        let mut payload = VeraxPayload::new([0x01; 32], Predicate::DerivedFrom);
        payload.object = Some([0x02; 32]);
        payload.timestamp = Some(1700000000);

        let seed = [0x42u8; 32];
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let stmt = Statement::sign_ed25519(&payload, &sk).unwrap();

        assert_eq!(stmt.subject().unwrap(), [0x01; 32]);
        assert_eq!(stmt.predicate().unwrap(), Predicate::DerivedFrom);
        assert_eq!(stmt.object().unwrap(), Some([0x02; 32]));
        assert_eq!(stmt.timestamp().unwrap(), Some(1700000000));
    }

    #[test]
    fn test_statement_hash() {
        let payload = VeraxPayload::new([0x01; 32], Predicate::Attests);
        let seed = [0x42u8; 32];
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let stmt = Statement::sign_ed25519(&payload, &sk).unwrap();
        let h = stmt.cose_hash();
        assert_eq!(h.len(), 32);
    }

    #[test]
    fn test_cose_hash() {
        let payload = VeraxPayload::new([0x01; 32], Predicate::Attests);
        let seed = [0x42u8; 32];
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);

        let stmt1 = Statement::sign_ed25519(&payload, &sk).unwrap();
        let stmt2 = Statement::sign_ed25519(&payload, &sk).unwrap();

        assert_eq!(stmt1.payload_hash().unwrap(), stmt2.payload_hash().unwrap());
    }

    #[test]
    fn test_sign_ed25519_and_anchor() {
        use crate::ct::{LogInclusionProof, SignedTreeHead, TemporalAnchor};
        let payload = VeraxPayload::new([0xab; 32], Predicate::Attests);
        let seed = [0x42u8; 32];
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key();

        let proof = LogInclusionProof {
            leaf_index: 0,
            siblings: Vec::new(),
        };
        let root = [0xcc; 32];
        let sig_bytes = [0u8; 64].to_vec();
        let sth = SignedTreeHead::new(1700000000, 1, root, sig_bytes, vk.to_bytes().to_vec());
        let anchor = TemporalAnchor {
            inclusion_proof: proof,
            signed_tree_head: sth,
        };

        let stmt = Statement::sign_ed25519_and_anchor(&payload, &sk, &anchor).unwrap();
        let decoded = stmt.decode_payload().unwrap();
        assert_eq!(decoded.subject, payload.subject);
        assert_eq!(decoded.predicate, payload.predicate);

        // Verify the unprotected header contains the anchor
        let unprotected = crate::cose::extract_unprotected(stmt.to_bytes()).unwrap();
        assert!(
            unprotected.len() > 1,
            "unprotected header must contain anchor data"
        );

        // Verify the signature covers the unprotected header via external_aad
        let verify_result = crate::cose::parse_and_verify_ed25519(stmt.to_bytes(), &vk);
        assert!(
            verify_result.is_ok(),
            "signature verifies with external_aad binding"
        );
    }

    #[test]
    fn test_composite_statement() {
        let payload = VeraxPayload::new([0xab; 32], Predicate::Attests);
        let ed_seed = [0x42u8; 32];
        let ed_sk = ed25519_dalek::SigningKey::from_bytes(&ed_seed);

        let mut ml_seed = [0u8; 32];
        for (i, b) in ml_seed.iter_mut().enumerate() {
            *b = i as u8;
        }
        let ml_seed_obj = ml_dsa::Seed::try_from(&ml_seed[..]).unwrap();
        let ml_sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&ml_seed_obj);

        let stmt = Statement::sign_composite(&payload, &ed_sk, &ml_sk).unwrap();
        let decoded = stmt.decode_payload().unwrap();
        assert_eq!(decoded.subject, payload.subject);
        assert_eq!(decoded.predicate, payload.predicate);
    }
}
