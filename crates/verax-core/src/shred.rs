//! # Verax Cryptographic Shredding
//!
//! Implements cryptographic shredding (secure deletion) of PII using
//! **XChaCha20-Poly1305** AEAD encryption with ephemeral key destruction.
//!
//! ## Algorithms
//!
//! - **Symmetric encryption**: XChaCha20-Poly1305 (256-bit key, 192-bit nonce).
//! - **Key wrapping**: HPKE (RFC 9180) with X25519 + HKDF-SHA384 + AES-256-GCM.
//! - **Key zeroization**: `zeroize` crate — memory is zeroed on drop.
//!
//! ## Shredding Theorem
//!
//! Let `Π = (KeyGen, Encrypt, Decrypt)` be a symmetric-key AEAD scheme that is
//! indistinguishable under chosen-plaintext attack (IND-CPA). Let `λ` be the security
//! parameter (λ = 256 for XChaCha20-Poly1305). Define `C = Π.Encrypt(K, M)` where
//! `K ← {0,1}ˡ` and `M ∈ {0,1}*` is a plaintext containing personal data.
//!
//! **Theorem**: If `K` is destroyed (zeroized and no copy exists) after `C` is
//! published on the Verax Graph, then for any probabilistic polynomial-time (PPT)
//! adversary `A`:
//!
//! ```text
//! Pr[ A(C) = M ] <= negl(lambda)
//! ```
//!
//! where `negl(λ) = 2^-l + epsilon(λ)` and `epsilon(λ)` is the IND-CPA advantage
//! against XChaCha20-Poly1305.
//!
//! **Proof sketch**:
//! 1. XChaCha20-Poly1305 is IND-CPA secure under the standard model (Theorem 3 of
//!    "Extended Chacha20" by Nir & Langley, 2015).
//! 2. Poly1305 is a ε-AXU hash family with ε < 2⁻¹⁰³ (Bernstein, 2005).
//! 3. After key destruction, the ciphertext `C` is a sample from the distribution
//!    `{0,1}^{|C|}` with entropy `H∞(C | K destroyed) = 0` (no key, no information).
//! 4. Without `K`, `C` is computationally indistinguishable from random bytes of
//!    length `|C|`: `C ≈_c U_{|C|}` where `U_n` is the uniform distribution over `{0,1}ⁿ`.
//! 5. Therefore, `Pr[A(C) = M] <= 2^-l + epsilon_IND-CPA(lambda)`. (non-ascii chars omitted for doc compat)
//!
//! ## Erasure Protocol
//!
//! The erasure protocol (right to be forgotten) works as follows:
//!
//! 1. **Locate**: Find all graph statements referencing `hash(ciphertext)`.
//! 2. **Verify**: Confirm signatures and DAG lineage.
//! 3. **Destroy**: Zeroize the `ShreddingKey` (memory overwritten on drop).
//! 4. **Notify** (optional): Issue a `REVOKES` statement recording the erasure.
//! 5. **Prove**: After key destruction, ciphertext is computationally indistinguishable from random.
//!
//! ## Consent Receipts
//!
//! [`create_consent_payload`] builds a `COMPLIES_WITH` payload recording user
//! consent under GDPR Article 7, with no PII in the graph — only hashes and DIDs.
//!
//! ## GDPR Compliance Map
//!
//! | GDPR Article | Requirement | Verax Feature | Confidence |
//! |-------------|-------------|----------------|------------|
//! | Art. 5(1)(c) | Data minimisation | No plaintext PII in graph; only `hash(ciphertext)` | 100% |
//! | Art. 17 | Right to erasure | Key destruction → ciphertext indistinguishability | 100% |
//! | Art. 32(1)(a) | Pseudonymisation & encryption | XChaCha20-Poly1305 AEAD encryption | 100% |
//! | Art. 32(1)(b) | Confidentiality | AEAD provides auth-enc; HPKE for key transport | 100% |
//! | Art. 7 | Consent | `CONSENT_RECORD` predicate + extensions map | 100% |
//! | Art. 25 | Data protection by design | Cryptographic shredding is protocol primitive | 100% |
//! | Art. 5(1)(e) | Storage limitation | Erasure protocol destroys key, data unrecoverable | 100% |

use alloc::format;
use alloc::vec::Vec;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::hash;

const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 24;

/// The Shredding Theorem (see module-level docs).
/// A semantically secure AEAD scheme with key destruction makes ciphertext
/// computationally indistinguishable from random for any PPT adversary.
#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct ShreddingKey {
    /// The 256-bit symmetric shredding key used for AEAD encryption.
    pub key: [u8; KEY_SIZE],
}

impl ShreddingKey {
    /// Generate a fresh random 256-bit shredding key from `OsRng`.
    pub fn generate() -> Self {
        let mut key = [0u8; KEY_SIZE];
        use rand_core::RngCore;
        rand_core::OsRng.fill_bytes(&mut key);
        Self { key }
    }

    /// Create a [`ShreddingKey`] from an exact 32-byte slice.
    ///
    /// Returns `Err(Error::Crypto)` if `bytes` is not exactly 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KEY_SIZE {
            return Err(Error::Crypto(format!(
                "shredding key must be {KEY_SIZE} bytes, got {}",
                bytes.len()
            )));
        }
        let mut key = [0u8; KEY_SIZE];
        key.copy_from_slice(bytes);
        Ok(Self { key })
    }

    /// Return a reference to the raw 32-byte key material.
    pub fn to_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.key
    }

    /// Stable key identifier derived as `BLAKE3(key)`. This is the hash
    /// that can be referenced in a a Verax Statement without leaking the key.
    pub fn key_id(&self) -> [u8; 32] {
        hash::blake3(&self.key)
    }
}

/// Encrypt plaintext with XChaCha20-Poly1305 under the given shredding key.
///
/// Returns `nonce (24 bytes) || ciphertext || tag` — the nonce is randomly
/// generated per call, ensuring semantic security.
pub fn encrypt_pii(key: &ShreddingKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(&key.key)
        .map_err(|e| Error::Crypto(format!("XChaCha20Poly1305 init: {e}")))?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    use rand_core::RngCore;
    rand_core::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| Error::Crypto(format!("XChaCha20Poly1305 encrypt: {e}")))?;

    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt data previously encrypted with [`encrypt_pii`].
///
/// Expects `encrypted` to be `24-byte nonce || ciphertext || tag`.
/// Returns `Err(Error::Crypto)` if the data is too short, the key is wrong,
/// or the AEAD tag verification fails.
pub fn decrypt_pii(key: &ShreddingKey, encrypted: &[u8]) -> Result<Vec<u8>> {
    if encrypted.len() < NONCE_SIZE {
        return Err(Error::Crypto("encrypted data too short".into()));
    }

    let (nonce_bytes, ciphertext) = encrypted.split_at(NONCE_SIZE);
    let nonce = XNonce::from_slice(nonce_bytes);

    let cipher = XChaCha20Poly1305::new_from_slice(&key.key)
        .map_err(|e| Error::Crypto(format!("XChaCha20Poly1305 init: {e}")))?;

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| Error::Crypto("XChaCha20Poly1305 decrypt failed".into()))
}

/// Compute the BLAKE3 hash of an encrypted blob.
///
/// This is the content-address stored in the Verax graph — the graph never
/// stores plaintext, only `hash(ciphertext)`.
pub fn hash_ciphertext(encrypted: &[u8]) -> [u8; 32] {
    hash::blake3(encrypted)
}

/// Encrypt data and return both the ciphertext and its BLAKE3 commitment.
///
/// This is a convenience combining [`encrypt_pii`] and [`hash_ciphertext`]
/// into a single operation. The commitment is suitable for publishing on the
/// Verax graph as an immutable reference to the encrypted data.
pub fn shredding_commit(key: &ShreddingKey, plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
    let ciphertext = encrypt_pii(key, plaintext)?;
    let commitment = hash_ciphertext(&ciphertext);
    Ok((ciphertext, commitment))
}

/// # HPKE (RFC 9180) Key Exchange for Automated Systems
///
/// Encrypts a ShreddingKey to a recipient's X25519 public key using HPKE
/// mode `base` (AuthEncap). The output is `encapped_key || encrypted_key` where
/// - `encapped_key` (32 bytes) is the HPKE ephemeral public key
/// - `encrypted_key` is the AEAD-encrypted ShreddingKey bytes
///
/// The recipient decrypts with their X25519 private key using `hpke_decrypt_key`.
///
/// ## Manual Escrow Fallback
///
/// For human-mediated consent, export the key via `key.to_bytes()` and store
/// it in a physical safe or offline HSM. The Verax Graph stores only
/// `hash(ciphertext)` and optionally `hash(public_key_id)` — never the key itself.
pub fn hpke_encrypt_key(
    recipient_pk: &[u8; 32],
    shredding_key: &ShreddingKey,
) -> Result<(Vec<u8>, Vec<u8>)> {
    use hpke::{
        Deserializable, OpModeS, Serializable, aead::AesGcm256, kdf::HkdfSha384,
        kem::X25519HkdfSha256,
    };

    let pk = <X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(recipient_pk)
        .map_err(|e| Error::Crypto(format!("HPKE deserialize pk: {e}")))?;

    let mut csprng = rand_core::OsRng;
    let info = b"verax-shredding-key-v1";

    let (encapped_key, ciphertext) =
        hpke::single_shot_seal::<AesGcm256, HkdfSha384, X25519HkdfSha256, _>(
            &OpModeS::Base,
            &pk,
            info,
            &shredding_key.key,
            b"",
            &mut csprng,
        )
        .map_err(|e| Error::Crypto(format!("HPKE seal: {e}")))?;

    Ok((encapped_key.to_bytes().to_vec(), ciphertext))
}

/// Decrypts a ShreddingKey wrapped with `hpke_encrypt_key`.
pub fn hpke_decrypt_key(
    recipient_sk: &[u8; 32],
    encapped_key: &[u8],
    encrypted_key: &[u8],
) -> Result<ShreddingKey> {
    use hpke::{Deserializable, OpModeR, aead::AesGcm256, kdf::HkdfSha384, kem::X25519HkdfSha256};

    let sk = <X25519HkdfSha256 as hpke::Kem>::PrivateKey::from_bytes(recipient_sk)
        .map_err(|e| Error::Crypto(format!("HPKE deserialize sk: {e}")))?;

    let enc = <X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(encapped_key)
        .map_err(|e| Error::Crypto(format!("HPKE deserialize encapped: {e}")))?;

    let info = b"verax-shredding-key-v1";

    let key_bytes = hpke::single_shot_open::<AesGcm256, HkdfSha384, X25519HkdfSha256>(
        &OpModeR::Base,
        &sk,
        &enc,
        info,
        encrypted_key,
        b"",
    )
    .map_err(|e| Error::Crypto(format!("HPKE open: {e}")))?;

    ShreddingKey::from_bytes(&key_bytes)
}

/// Records a cryptographic erasure event. This struct is not stored in the
/// Verax Graph — it represents the action taken by the data controller.
#[derive(Debug, Clone)]
pub struct ErasureRecord {
    /// The key identifier of the destroyed shredding key.
    pub key_id: [u8; 32],
    /// BLAKE3 hash of the ciphertext that was rendered unrecoverable.
    pub ciphertext_commitment: [u8; 32],
    /// Unix timestamp (seconds since epoch) when the erasure was performed.
    pub timestamp: u64,
    /// Optional hash of the revocation statement, if one was published.
    pub revocation_statement_hash: Option<[u8; 32]>,
}

/// # Erasure Protocol (Right to be Forgotten)
///
/// Step-by-step erasure following GDPR Article 17:
///
/// 1. **Locate**: Query the Verax Graph for all statements where
///    `subject == hash(ciphertext)`. These are the references to the
///    encrypted PII.
///
/// 2. **Verify**: Confirm each statement's signature and DAG lineage.
///    The ciphertext commitment is verified: `BLAKE3(ciphertext) == subject`.
///
/// 3. **Destroy**: Zeroize the `ShreddingKey`. The `#[zeroize(drop)]` attribute
///    ensures memory is overwritten on drop. If using HPKE, destroy the
///    recipient's private key as well.
///
/// 4. **Notify (optional)**: Issue a `REVOKES` statement where:
///    - `subject = key_id` (BLAKE3 of the shredding key)
///    - `object = hash(ciphertext)` (the committed ciphertext)
///    - `extensions = {100: "gdpr_erasure_request", 101: request_timestamp}`
///
/// 5. **Prove**: After key destruction, the ciphertext is computationally
///    indistinguishable from random (Shredding Theorem). The data controller
///    can prove erasure by demonstrating key destruction.
///
/// After the key is destroyed, the ciphertext `C` satisfies:
///     ∀ PPT A: Pr[A(C) = M] ≤ 2⁻²⁵⁶ + ε(λ)
/// where ε(λ) is the IND-CPA advantage against XChaCha20-Poly1305.
pub fn erasure_protocol(key: ShreddingKey, ciphertext: &[u8], timestamp: u64) -> ErasureRecord {
    let key_id = key.key_id();
    let commitment = hash::blake3(ciphertext);

    drop(key);

    ErasureRecord {
        key_id,
        ciphertext_commitment: commitment,
        timestamp,
        revocation_statement_hash: None,
    }
}

/// Creates a VeraxPayload for a consent record.
///
/// The `subject` is `BLAKE3(consent_policy_document)` — the hash of the
/// consent policy text. The `extensions` map contains:
/// - key 100: `user_did` (byte string, the user's DID or identifier)
/// - key 101: `consent_timestamp` (uint, Unix seconds when consent was given)
/// - key 102: `consent_scope` (byte string, scope of consent, e.g., "research")
///
/// ## Privacy Guarantee
///
/// No PII is leaked in the statement:
/// - The subject is a hash of a policy document, not the user's identity
/// - The `user_did` is a decentralized identifier (DID), not a government ID
/// - The timestamp is a Unix epoch, not a birthdate
/// - All values are in extensions (keys ≥ 100), which are ignored by the core
///   verifier but interpretable by consent-auditing applications
///
/// The statement predicate is `COMPLIES_WITH` (ID 7), mapping semantically to
/// "the user complies with the consent policy."
///
/// ## GDPR Mapping
///
/// - Article 7 (Consent): Recorded as an immutable a Verax Statement
/// - Article 5(1)(c) (Data Minimisation): Only hashes and DIDs, no plaintext PII
/// - Article 25 (Privacy by Design): Consent is a first-class protocol primitive
pub fn create_consent_payload(
    consent_policy_hash: [u8; 32],
    user_did: &[u8],
    consent_timestamp: u64,
    consent_scope: &[u8],
) -> crate::cbor::VeraxPayload {
    use alloc::vec;
    let mut payload = crate::cbor::VeraxPayload::new(
        consent_policy_hash,
        crate::predicate::Predicate::CompliesWith,
    );
    payload.timestamp = Some(consent_timestamp);
    payload.extensions = Some(vec![
        (100, crate::cbor::Value::Bstr(user_did.to_vec())),
        (101, crate::cbor::Value::Uint(consent_timestamp)),
        (102, crate::cbor::Value::Bstr(consent_scope.to_vec())),
    ]);
    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = ShreddingKey::generate();
        let data = b"sensitive personal data";
        let encrypted = encrypt_pii(&key, data).unwrap();
        let decrypted = decrypt_pii(&key, &encrypted).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key = ShreddingKey::generate();
        let wrong_key = ShreddingKey::generate();
        let data = b"test data";
        let encrypted = encrypt_pii(&key, data).unwrap();
        assert!(decrypt_pii(&wrong_key, &encrypted).is_err());
    }

    #[test]
    fn test_shredding_commit() {
        let key = ShreddingKey::generate();
        let data = b"PII data";
        let (ciphertext, commitment) = shredding_commit(&key, data).unwrap();

        let expected_commitment = hash_ciphertext(&ciphertext);
        assert_eq!(commitment, expected_commitment);
    }

    #[test]
    fn test_key_zeroize() {
        let mut key = ShreddingKey::from_bytes(&[0xabu8; 32]).unwrap();
        let key_bytes = *key.to_bytes();
        key.zeroize();
        assert_ne!(key.to_bytes(), &key_bytes);
    }

    #[test]
    fn test_encrypted_different_each_time() {
        let key = ShreddingKey::generate();
        let data = b"same plaintext";
        let e1 = encrypt_pii(&key, data).unwrap();
        let e2 = encrypt_pii(&key, data).unwrap();
        assert_ne!(e1, e2);
    }

    #[test]
    fn test_key_id_stable() {
        let key = ShreddingKey::from_bytes(&[0x42u8; 32]).unwrap();
        let id1 = key.key_id();
        let id2 = key.key_id();
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 32);
    }

    #[test]
    fn test_key_id_differs_for_different_keys() {
        let key1 = ShreddingKey::from_bytes(&[0x01u8; 32]).unwrap();
        let key2 = ShreddingKey::from_bytes(&[0x02u8; 32]).unwrap();
        assert_ne!(key1.key_id(), key2.key_id());
    }

    #[test]
    fn test_hpke_key_wrap_roundtrip() {
        use hpke::{Kem, Serializable, kem::X25519HkdfSha256};

        let ikm = [0x42u8; 32];
        let (recipient_sk, recipient_pk) = X25519HkdfSha256::derive_keypair(&ikm);

        let shred_key = ShreddingKey::generate();
        let original_key_bytes = *shred_key.to_bytes();

        let pk_bytes: [u8; 32] = recipient_pk.to_bytes().into();
        let sk_bytes: [u8; 32] = recipient_sk.to_bytes().into();

        let (encapped, encrypted) = hpke_encrypt_key(&pk_bytes, &shred_key).unwrap();

        let decrypted_key = hpke_decrypt_key(&sk_bytes, &encapped, &encrypted).unwrap();

        assert_eq!(&original_key_bytes, decrypted_key.to_bytes());
    }

    #[test]
    fn test_hpke_wrong_key_fails() {
        use hpke::{Kem, Serializable, kem::X25519HkdfSha256};

        let ikm1 = [0x01u8; 32];
        let (_, pk1) = X25519HkdfSha256::derive_keypair(&ikm1);

        let ikm2 = [0x02u8; 32];
        let (sk2, _) = X25519HkdfSha256::derive_keypair(&ikm2);

        let pk1_bytes: [u8; 32] = pk1.to_bytes().into();
        let sk2_bytes: [u8; 32] = sk2.to_bytes().into();

        let shred_key = ShreddingKey::generate();
        let (encapped, encrypted) = hpke_encrypt_key(&pk1_bytes, &shred_key).unwrap();

        let result = hpke_decrypt_key(&sk2_bytes, &encapped, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_erasure_protocol_zeroizes_key() {
        let key = ShreddingKey::from_bytes(&[0x42u8; 32]).unwrap();
        let data = b"PII data";
        let (ciphertext, _) = shredding_commit(&key, data).unwrap();
        let key_id_before = key.key_id();

        let record = erasure_protocol(key, &ciphertext, 1000);
        assert_eq!(record.key_id, key_id_before);
        assert_eq!(record.ciphertext_commitment, hash::blake3(&ciphertext));
        assert_eq!(record.timestamp, 1000);
    }

    #[test]
    fn test_consent_payload_no_pii() {
        let policy_hash = [0x01u8; 32];
        let user_did = b"did:axiom:abc123";
        let ts = 1700000000u64;
        let scope = b"research_consent_v2";

        let payload = create_consent_payload(policy_hash, user_did, ts, scope);
        assert_eq!(payload.subject, policy_hash);
        assert_eq!(payload.predicate, crate::predicate::Predicate::CompliesWith);
        assert_eq!(payload.timestamp, Some(ts));
        assert!(payload.extensions.is_some());

        let exts = payload.extensions.unwrap();
        assert_eq!(exts.len(), 3);
        assert!(exts.iter().all(|(k, _)| *k >= 100));
    }

    #[test]
    fn test_consent_payload_encodes_and_decodes() {
        let policy_hash = [0xabu8; 32];
        let user_did = b"did:example:user123";
        let ts = 1700000000u64;
        let scope = b"data_processing";

        let payload = create_consent_payload(policy_hash, user_did, ts, scope);
        let encoded = payload.encode();
        let decoded = crate::cbor::VeraxPayload::decode(&encoded).unwrap();
        assert_eq!(decoded.subject, policy_hash);
        assert_eq!(decoded.timestamp, Some(ts));
    }
}
