//! # HSM Abstraction Layer
//!
//! Provides a hardware security module (HSM) abstraction for key custody in the
//! Verax protocol. The [`SecureKeyStore`] trait defines the interface; private
//! key material never leaves the trait implementation — protocol logic interacts
//! only through opaque [`KeyReference`] handles.
//!
//! ## Implementations
//!
//! - **`software`** (feature `software-hsm`): In-memory key store for testing.
//!   WARNING: private keys are resident in host memory; not for production.
//! - **`pkcs11`** (feature `pkcs11-hsm`): PKCS#11-backed store (placeholder).
//! - **`tpm`** (feature `tpm-hsm`): TPM-backed store (placeholder).
//! - [`NullKeyStore`]: No-op store that returns errors on all operations.

use alloc::vec::Vec;

use zeroize::Zeroize;

use crate::error::{Error, Result};

/// Algorithm tag for the COSE protected header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// Ed25519 (algorithm ID -8).
    Ed25519,
    /// ML-DSA-65 (algorithm ID -38).
    MlDsa65,
    /// Composite Ed25519 + ML-DSA-65 (algorithm ID -39).
    Composite,
}

impl Algorithm {
    /// Return the COSE algorithm ID for this algorithm.
    ///
    /// - Ed25519 → -8
    /// - ML-DSA-65 → -38
    /// - Composite → -39
    pub fn cose_alg_id(&self) -> i64 {
        match self {
            Algorithm::Ed25519 => -8,
            Algorithm::MlDsa65 => -38,
            Algorithm::Composite => -39,
        }
    }

    /// Parse an algorithm from a COSE algorithm ID.
    ///
    /// Returns `None` for unrecognised IDs.
    pub fn from_cose_alg_id(id: i64) -> Option<Self> {
        match id {
            -8 => Some(Algorithm::Ed25519),
            -38 => Some(Algorithm::MlDsa65),
            -39 => Some(Algorithm::Composite),
            _ => None,
        }
    }
}

/// Attributes describing a key stored in a secure enclave.
#[derive(Debug, Clone)]
pub struct KeyAttributes {
    /// Cryptographic algorithm this key is used with.
    pub algorithm: Algorithm,
    /// Whether the key material may be exported from the secure enclave.
    pub exportable: bool,
    /// Whether the key material may be extracted in plaintext form.
    pub extractable: bool,
}

impl Default for KeyAttributes {
    fn default() -> Self {
        Self {
            algorithm: Algorithm::Ed25519,
            exportable: false,
            extractable: false,
        }
    }
}

/// Opaque reference to a key inside a secure keystore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyReference {
    /// Key identifier — a 32-byte unique handle for the key in the keystore.
    pub kid: [u8; 32],
    /// Cryptographic algorithm this reference is associated with.
    pub algorithm: Algorithm,
}

impl Zeroize for KeyReference {
    /// Zeroize the KID bytes on explicit request.
    fn zeroize(&mut self) {
        self.kid.zeroize();
    }
}

impl KeyReference {
    /// Create an Ed25519 key reference from a 32-byte KID.
    pub fn new_ed25519(kid: [u8; 32]) -> Self {
        Self {
            kid,
            algorithm: Algorithm::Ed25519,
        }
    }

    /// Create an ML-DSA-65 key reference from a 32-byte KID.
    pub fn new_mldsa65(kid: [u8; 32]) -> Self {
        Self {
            kid,
            algorithm: Algorithm::MlDsa65,
        }
    }

    /// Create a composite key reference from a 32-byte KID.
    pub fn new_composite(kid: [u8; 32]) -> Self {
        Self {
            kid,
            algorithm: Algorithm::Composite,
        }
    }
}

/// Secure key store: the central abstraction for HSM-backed key custody.
///
/// Key material NEVER leaves the trait implementation. The protocol logic
/// interacts only through opaque `KeyReference` handles. This satisfies the
/// HSM verification criterion: private keys are isolated from protocol logic.
pub trait SecureKeyStore {
    /// Generate a new key inside the secure store.
    fn generate(&mut self, algorithm: Algorithm, attrs: KeyAttributes) -> Result<KeyReference>;

    /// Sign a message using a key referenced by `key_ref`.
    fn sign(&self, key_ref: &KeyReference, msg: &[u8]) -> Result<Vec<u8>>;

    /// Export the public key bytes for the given key reference.
    fn public_key(&self, key_ref: &KeyReference) -> Result<Vec<u8>>;

    /// Check whether a given key reference is still valid.
    fn is_valid(&self, key_ref: &KeyReference) -> bool;

    /// Delete a key from the secure store.
    fn delete(&mut self, key_ref: &KeyReference) -> Result<()>;

    /// List all key references currently in the store.
    fn list_keys(&self) -> Vec<KeyReference>;
}

/// Software-backed implementation of `SecureKeyStore`.
///
/// WARNING: Private key material IS resident in host memory. Suitable for
/// testing and development only. Production deployments MUST use an HSM,
/// TPM, or KMS-backed implementation instead.
#[cfg(feature = "software-hsm")]
pub mod software {
    use alloc::collections::BTreeMap;
    use alloc::string::ToString;
    use ed25519_dalek::ed25519::signature::Signer as EdSigner;
    use ml_dsa::KeyExport;
    use ml_dsa::Keypair;
    use ml_dsa::SignatureEncoding;
    use sha2::Digest as _;

    use super::*;

    const CONTEXT_STRING: &[u8] = b"Verax-Provenance-v1";

    enum KeyMaterial {
        Ed25519(ed25519_dalek::SigningKey),
        MlDsa65(ml_dsa::SigningKey<ml_dsa::MlDsa65>),
        Composite {
            ed: ed25519_dalek::SigningKey,
            ml: ml_dsa::SigningKey<ml_dsa::MlDsa65>,
        },
    }

    impl KeyMaterial {
        fn algorithm(&self) -> Algorithm {
            match self {
                KeyMaterial::Ed25519(_) => Algorithm::Ed25519,
                KeyMaterial::MlDsa65(_) => Algorithm::MlDsa65,
                KeyMaterial::Composite { .. } => Algorithm::Composite,
            }
        }
    }

    impl Drop for KeyMaterial {
        fn drop(&mut self) {
            match self {
                KeyMaterial::Ed25519(sk) => {
                    let mut bytes = sk.to_bytes();
                    bytes.zeroize();
                }
                KeyMaterial::MlDsa65(_) => {}
                KeyMaterial::Composite { ed, .. } => {
                    let mut bytes = ed.to_bytes();
                    bytes.zeroize();
                }
            }
        }
    }

    pub struct SoftwareKeyStore {
        keys: BTreeMap<[u8; 32], (KeyMaterial, KeyAttributes)>,
    }

    impl SoftwareKeyStore {
        /// Create an empty software key store.
        pub fn new() -> Self {
            Self {
                keys: BTreeMap::new(),
            }
        }
    }

    fn generate_ed25519() -> ed25519_dalek::SigningKey {
        use rand_core::RngCore;
        let mut seed = [0u8; 32];
        let mut os_rng = rand_core::OsRng;
        os_rng.fill_bytes(&mut seed);
        ed25519_dalek::SigningKey::from_bytes(&seed)
    }

    fn generate_mldsa65() -> ml_dsa::SigningKey<ml_dsa::MlDsa65> {
        use rand_core::RngCore;
        let mut seed_data = [0u8; 32];
        let mut os_rng = rand_core::OsRng;
        os_rng.fill_bytes(&mut seed_data);
        let ml_seed = ml_dsa::Seed::try_from(&seed_data[..]).unwrap();
        ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&ml_seed)
    }

    impl SecureKeyStore for SoftwareKeyStore {
        fn generate(&mut self, algorithm: Algorithm, attrs: KeyAttributes) -> Result<KeyReference> {
            let material = match algorithm {
                Algorithm::Ed25519 => KeyMaterial::Ed25519(generate_ed25519()),
                Algorithm::MlDsa65 => KeyMaterial::MlDsa65(generate_mldsa65()),
                Algorithm::Composite => KeyMaterial::Composite {
                    ed: generate_ed25519(),
                    ml: generate_mldsa65(),
                },
            };

            let pubkey_bytes = match &material {
                KeyMaterial::Ed25519(sk) => sk.verifying_key().to_bytes().to_vec(),
                KeyMaterial::MlDsa65(sk) => sk.verifying_key().to_bytes().to_vec(),
                KeyMaterial::Composite { ed, ml } => {
                    let mut pk = ml.verifying_key().to_bytes().to_vec();
                    pk.extend_from_slice(&ed.verifying_key().to_bytes());
                    pk
                }
            };

            let kid = crate::hash::blake3(&pubkey_bytes);
            let algorithm_for_ref = material.algorithm();
            let key_ref = KeyReference {
                kid,
                algorithm: algorithm_for_ref,
            };

            if self.keys.contains_key(&kid) {
                return Err(Error::Crypto("key collision".into()));
            }

            self.keys.insert(kid, (material, attrs));
            Ok(key_ref)
        }

        fn sign(&self, key_ref: &KeyReference, msg: &[u8]) -> Result<Vec<u8>> {
            let (material, _) = self
                .keys
                .get(&key_ref.kid)
                .ok_or_else(|| Error::Crypto("key not found".into()))?;

            match material {
                KeyMaterial::Ed25519(sk) => {
                    let sig: ed25519_dalek::Signature = EdSigner::sign(sk, msg);
                    Ok(sig.to_bytes().to_vec())
                }
                KeyMaterial::MlDsa65(sk) => {
                    let sig = ml_dsa::Signer::try_sign(sk, msg)
                        .map_err(|e| Error::Crypto(e.to_string()))?;
                    Ok(sig.to_bytes().to_vec())
                }
                KeyMaterial::Composite { ed, ml } => {
                    let ed_hasher = sha2::Sha512::new()
                        .chain_update(CONTEXT_STRING)
                        .chain_update(msg);
                    let ed_sig: ed25519_dalek::Signature = ed
                        .sign_prehashed(ed_hasher, Some(CONTEXT_STRING))
                        .map_err(|e| Error::Crypto(e.to_string()))?;
                    let ml_sig = ml_dsa::Signer::try_sign(ml, msg)
                        .map_err(|e| Error::Crypto(e.to_string()))?;
                    let mut combined = ml_sig.to_bytes().to_vec();
                    combined.extend_from_slice(&ed_sig.to_bytes());
                    Ok(combined)
                }
            }
        }

        fn public_key(&self, key_ref: &KeyReference) -> Result<Vec<u8>> {
            let (material, _) = self
                .keys
                .get(&key_ref.kid)
                .ok_or_else(|| Error::Crypto("key not found".into()))?;

            match material {
                KeyMaterial::Ed25519(sk) => Ok(sk.verifying_key().to_bytes().to_vec()),
                KeyMaterial::MlDsa65(sk) => Ok(sk.verifying_key().to_bytes().to_vec()),
                KeyMaterial::Composite { ed, ml } => {
                    let mut pk = ed.verifying_key().to_bytes().to_vec();
                    pk.extend_from_slice(&ml.verifying_key().to_bytes());
                    Ok(pk)
                }
            }
        }

        fn is_valid(&self, key_ref: &KeyReference) -> bool {
            self.keys.contains_key(&key_ref.kid)
        }

        fn delete(&mut self, key_ref: &KeyReference) -> Result<()> {
            self.keys
                .remove(&key_ref.kid)
                .ok_or_else(|| Error::Crypto("key not found".into()))?;
            Ok(())
        }

        fn list_keys(&self) -> Vec<KeyReference> {
            self.keys
                .iter()
                .map(|(kid, (material, _))| KeyReference {
                    kid: *kid,
                    algorithm: material.algorithm(),
                })
                .collect()
        }
    }
}

/// PKCS#11-backed key store (requires `pkcs11-hsm` feature and a PKCS#11
/// module such as SoftHSM or an actual hardware token).
#[cfg(feature = "pkcs11-hsm")]
pub mod pkcs11 {
    use super::*;

    pub struct Pkcs11KeyStore;

    impl Pkcs11KeyStore {
        pub fn new(_module_path: &str, _slot_id: usize, _pin: &str) -> Result<Self> {
            Err(Error::Io("PKCS#11 not yet implemented".into()))
        }
    }

    impl SecureKeyStore for Pkcs11KeyStore {
        fn generate(&mut self, _alg: Algorithm, _attrs: KeyAttributes) -> Result<KeyReference> {
            Err(Error::Io("PKCS#11 not yet implemented".into()))
        }
        fn sign(&self, _key_ref: &KeyReference, _msg: &[u8]) -> Result<Vec<u8>> {
            Err(Error::Io("PKCS#11 not yet implemented".into()))
        }
        fn public_key(&self, _key_ref: &KeyReference) -> Result<Vec<u8>> {
            Err(Error::Io("PKCS#11 not yet implemented".into()))
        }
        fn is_valid(&self, _key_ref: &KeyReference) -> bool {
            false
        }
        fn delete(&mut self, _key_ref: &KeyReference) -> Result<()> {
            Err(Error::Io("PKCS#11 not yet implemented".into()))
        }
        fn list_keys(&self) -> Vec<KeyReference> {
            Vec::new()
        }
    }
}

/// TPM-backed key store (requires `tpm-hsm` feature).
#[cfg(feature = "tpm-hsm")]
pub mod tpm {
    use super::*;

    pub struct TpmKeyStore;

    impl TpmKeyStore {
        pub fn new() -> Result<Self> {
            Err(Error::Io("TPM not yet implemented".into()))
        }
    }

    impl SecureKeyStore for TpmKeyStore {
        fn generate(&mut self, _alg: Algorithm, _attrs: KeyAttributes) -> Result<KeyReference> {
            Err(Error::Io("TPM not yet implemented".into()))
        }
        fn sign(&self, _key_ref: &KeyReference, _msg: &[u8]) -> Result<Vec<u8>> {
            Err(Error::Io("TPM not yet implemented".into()))
        }
        fn public_key(&self, _key_ref: &KeyReference) -> Result<Vec<u8>> {
            Err(Error::Io("TPM not yet implemented".into()))
        }
        fn is_valid(&self, _key_ref: &KeyReference) -> bool {
            false
        }
        fn delete(&mut self, _key_ref: &KeyReference) -> Result<()> {
            Err(Error::Io("TPM not yet implemented".into()))
        }
        fn list_keys(&self) -> Vec<KeyReference> {
            Vec::new()
        }
    }
}

/// Null/no-op key store for use when no HSM is available.
///
/// All operations return `Err(Error::Crypto("no secure keystore available".into()))`.
pub struct NullKeyStore;

impl SecureKeyStore for NullKeyStore {
    fn generate(&mut self, _alg: Algorithm, _attrs: KeyAttributes) -> Result<KeyReference> {
        Err(Error::Crypto("no secure keystore available".into()))
    }
    fn sign(&self, _key_ref: &KeyReference, _msg: &[u8]) -> Result<Vec<u8>> {
        Err(Error::Crypto("no secure keystore available".into()))
    }
    fn public_key(&self, _key_ref: &KeyReference) -> Result<Vec<u8>> {
        Err(Error::Crypto("no secure keystore available".into()))
    }
    fn is_valid(&self, _key_ref: &KeyReference) -> bool {
        false
    }
    fn delete(&mut self, _key_ref: &KeyReference) -> Result<()> {
        Err(Error::Crypto("no secure keystore available".into()))
    }
    fn list_keys(&self) -> Vec<KeyReference> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "software-hsm")]
    #[test]
    fn test_software_hsm_generate_ed25519() {
        let mut store = software::SoftwareKeyStore::new();
        let ref1 = store
            .generate(Algorithm::Ed25519, KeyAttributes::default())
            .unwrap();
        let ref2 = store
            .generate(Algorithm::Ed25519, KeyAttributes::default())
            .unwrap();
        assert_ne!(ref1.kid, ref2.kid, "two generated keys differ");
        assert!(store.is_valid(&ref1));
        assert_eq!(store.list_keys().len(), 2);
    }

    #[cfg(feature = "software-hsm")]
    #[test]
    fn test_software_hsm_sign_verify_ed25519() {
        use ed25519_dalek::Verifier;

        let mut store = software::SoftwareKeyStore::new();
        let key_ref = store
            .generate(Algorithm::Ed25519, KeyAttributes::default())
            .unwrap();
        let msg = b"hello hsm";
        let sig_bytes = store.sign(&key_ref, msg).unwrap();
        assert_eq!(sig_bytes.len(), 64);

        let pk_bytes = store.public_key(&key_ref).unwrap();
        let pk = ed25519_dalek::VerifyingKey::from_bytes(&{
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&pk_bytes);
            arr
        })
        .unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&{
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&sig_bytes);
            arr
        });
        pk.verify(msg, &sig).unwrap();
    }

    #[cfg(feature = "software-hsm")]
    #[test]
    fn test_software_hsm_delete_key() {
        let mut store = software::SoftwareKeyStore::new();
        let key_ref = store
            .generate(Algorithm::Ed25519, KeyAttributes::default())
            .unwrap();
        assert!(store.is_valid(&key_ref));
        store.delete(&key_ref).unwrap();
        assert!(!store.is_valid(&key_ref));
    }

    #[test]
    fn test_null_keystore_returns_error() {
        let mut store = NullKeyStore;
        assert!(
            store
                .generate(Algorithm::Ed25519, KeyAttributes::default())
                .is_err()
        );
    }

    #[test]
    fn test_algorithm_cose_roundtrip() {
        for alg in [Algorithm::Ed25519, Algorithm::MlDsa65, Algorithm::Composite] {
            let id = alg.cose_alg_id();
            assert_eq!(Algorithm::from_cose_alg_id(id), Some(alg));
        }
        assert_eq!(Algorithm::from_cose_alg_id(0), None);
    }
}
