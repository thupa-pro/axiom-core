use ml_dsa::Keypair;
use sha2::Digest as _;
use verax_core::{
    Artifact, CompositePublicKey, Error, Predicate, ShreddingKey, Statement, TrustStore,
    VeraxPayload, blake3,
    ct::{LogInclusionProof, SignedTreeHead, TemporalAnchor},
    decrypt_pii, encrypt_pii, hash_ciphertext, shredding_commit, verify_statement,
    verify_statement_ed25519,
};

/// An append‑only mock transparency log that builds real Merkle trees.
///
/// All leaves are stored and never removed.  The Merkle tree is a perfect
/// binary tree (padded to the next power of two with zero hashes), making it
/// compatible with [`LogInclusionProof::verify`] which expects a sibling at
/// every level.
struct MockLog {
    sk: ed25519_dalek::SigningKey,
    leaves: Vec<[u8; 32]>,
    /// Cached root hash of the current tree.
    root: [u8; 32],
    /// Cached tree — each level is a slice of the flattened level vector.
    /// `levels[0]` is the leaf‑hash level, `levels[last]` is the root.
    levels: Vec<Vec<[u8; 32]>>,
}

impl MockLog {
    fn new(sk: ed25519_dalek::SigningKey) -> Self {
        Self {
            sk,
            leaves: Vec::new(),
            root: [0u8; 32],
            levels: Vec::new(),
        }
    }

    fn log_pubkey(&self) -> [u8; 32] {
        self.sk.verifying_key().to_bytes()
    }

    fn log_id(&self) -> [u8; 32] {
        blake3(&self.log_pubkey())
    }

    /// Append a leaf (BLAKE3 hash of the payload) and rebuild the tree.
    fn append(&mut self, leaf: [u8; 32]) {
        self.leaves.push(leaf);
        self.rebuild();
    }

    /// Build the Merkle tree from scratch.  Pads to the next power of two
    /// so that [`LogInclusionProof::verify`] works correctly.
    fn rebuild(&mut self) {
        if self.leaves.is_empty() {
            self.levels.clear();
            self.root = [0u8; 32];
            return;
        }
        let n = self.leaves.len().next_power_of_two();
        let mut level: Vec<[u8; 32]> = (0..n)
            .map(|i| {
                if i < self.leaves.len() {
                    sha256_leaf_node(&self.leaves[i])
                } else {
                    [0u8; 32]
                }
            })
            .collect();
        self.levels.clear();
        while level.len() > 1 {
            self.levels.push(level.clone());
            level = level
                .chunks_exact(2)
                .map(|chunk| sha256_node(&chunk[0], &chunk[1]))
                .collect();
        }
        self.root = level[0];
        self.levels.push(vec![self.root]);
    }

    /// Number of leaves in the log.
    fn tree_size(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// Current root hash of the Merkle tree.
    fn root_hash(&self) -> [u8; 32] {
        self.root
    }

    /// Generate a signed tree head for the current state.
    fn sth(&self, timestamp: u64) -> SignedTreeHead {
        use ed25519_dalek::ed25519::signature::Signer;
        let mut data = Vec::new();
        data.extend_from_slice(&timestamp.to_be_bytes());
        data.extend_from_slice(&self.tree_size().to_be_bytes());
        data.extend_from_slice(&self.root);
        let sig: ed25519_dalek::Signature = self.sk.sign(&data);
        SignedTreeHead::new(
            timestamp,
            self.tree_size(),
            self.root,
            sig.to_bytes().to_vec(),
            self.log_pubkey().to_vec(),
        )
    }

    /// Return the inclusion proof for leaf at `leaf_index`.
    fn proof(&self, leaf_index: u64) -> LogInclusionProof {
        let mut siblings = Vec::new();
        let n_padded = self.leaves.len().next_power_of_two();
        if n_padded == 0 {
            return LogInclusionProof {
                leaf_index,
                siblings,
            };
        }
        // Build the full padded leaf level
        let mut layer: Vec<[u8; 32]> = (0..n_padded)
            .map(|i| {
                if (i as usize) < self.leaves.len() {
                    sha256_leaf_node(&self.leaves[i])
                } else {
                    [0u8; 32]
                }
            })
            .collect();
        let mut idx = leaf_index as usize;
        while layer.len() > 1 {
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            if sibling_idx < layer.len() {
                siblings.push(layer[sibling_idx]);
            }
            // Build next layer
            layer = layer
                .chunks_exact(2)
                .map(|chunk| sha256_node(&chunk[0], &chunk[1]))
                .collect();
            idx /= 2;
        }
        LogInclusionProof {
            leaf_index: leaf_index as u64,
            siblings,
        }
    }

    /// Create an anchor for the given payload hash, returning the anchor.
    fn anchor(&self, payload_hash: &[u8; 32]) -> Option<TemporalAnchor> {
        let pos = self.leaves.iter().position(|h| h == payload_hash)?;
        let proof = self.proof(pos as u64);
        let sth = self.sth(1700000000);
        Some(TemporalAnchor {
            inclusion_proof: proof,
            signed_tree_head: sth,
        })
    }
}

fn sha256_leaf_node(data: &[u8; 32]) -> [u8; 32] {
    sha2::Sha256::new()
        .chain_update([0x00u8])
        .chain_update(data)
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

struct TestTrust {
    key: ed25519_dalek::VerifyingKey,
    log_key: [u8; 32],
    chain: std::collections::HashMap<[u8; 32], Vec<u8>>,
}

impl TestTrust {
    fn new(sk: &ed25519_dalek::SigningKey, log_sk: &ed25519_dalek::SigningKey) -> Self {
        Self {
            key: sk.verifying_key(),
            log_key: log_sk.verifying_key().to_bytes(),
            chain: std::collections::HashMap::new(),
        }
    }
}

impl TrustStore for TestTrust {
    fn resolve_key(&self, _kid: &[u8]) -> Option<ed25519_dalek::VerifyingKey> {
        Some(self.key)
    }
    fn resolve_composite_key(&self, _kid: &[u8]) -> Option<CompositePublicKey> {
        None
    }
    fn fetch_statement(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        self.chain.get(hash).cloned()
    }
    fn is_revoked_in_log(&self, _stmt_hash: &[u8; 32], _after: u64) -> Option<bool> {
        Some(false)
    }
    fn resolve_log_pubkey(&self, log_id: &[u8; 32], candidate_key: &[u8; 32]) -> Option<[u8; 32]> {
        let computed = verax_core::blake3(&self.log_key);
        if &computed == log_id && &self.log_key == candidate_key {
            Some(self.log_key)
        } else {
            None
        }
    }
}

fn sign_sk(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

fn sign_and_anchor(
    payload: &VeraxPayload,
    sk: &ed25519_dalek::SigningKey,
    log_sk: &ed25519_dalek::SigningKey,
) -> Statement {
    let mut log = MockLog::new(log_sk.clone());
    let payload_hash = blake3(&payload.encode());
    log.append(payload_hash);
    let anchor = log.anchor(&payload_hash).unwrap();
    Statement::sign_ed25519_and_anchor(payload, sk, &anchor).unwrap()
}

// ─── Use Case 1: Digital Fingerprints ───────────────────────────────────────
// Verax identifies files by their BLAKE3 hash (digital fingerprint),
// not by location. A single changed byte produces a completely different
// fingerprint, making tampering detectable.

#[test]
fn use_case_1_digital_fingerprints() {
    let data = b"Verax Protocol - Digital Notary";

    let artifact = Artifact::new(data);
    assert_eq!(
        artifact.hash().len(),
        32,
        "fingerprint is 32 bytes (BLAKE3)"
    );

    let same = Artifact::new(data);
    assert_eq!(
        artifact.hash(),
        same.hash(),
        "identical content → identical fingerprint"
    );

    let different = Artifact::new(b"different content");
    assert_ne!(
        artifact.hash(),
        different.hash(),
        "different content → completely different fingerprint"
    );

    assert!(
        artifact.verify(data),
        "content verified against its fingerprint"
    );

    assert!(
        !artifact.verify(b"tampered"),
        "tampered content fails fingerprint check"
    );

    let large: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
    let large_artifact = Artifact::new(&large);
    assert!(
        large_artifact.verify(&large),
        "BLAKE3 tree-hash handles large files"
    );
}

// ─── Use Case 2: Family Tree of Files (Lineage / DAG) ──────────────────────
// Verax never erases history. Each statement points to its predecessor via
// the "lineage" field, forming an immutable family tree (DAG).

#[test]
fn use_case_2_family_tree() {
    let alice = sign_sk(0x01);
    let log_sk = sign_sk(0x99);
    let store = TestTrust::new(&alice, &log_sk);

    let doc_v1 = VeraxPayload::new(blake3(b"contract_v1"), Predicate::Authors);
    let stmt_v1 = sign_and_anchor(&doc_v1, &alice, &log_sk);
    let h1 = blake3(stmt_v1.to_bytes());
    {
        let mut store = TestTrust::new(&alice, &log_sk);
        store.chain.insert(h1, stmt_v1.to_bytes().to_vec());
        assert!(
            verify_statement(stmt_v1.to_bytes(), &store).is_ok(),
            "v1: Alice authored contract_v1"
        );
    }

    let mut doc_v2 = VeraxPayload::new(blake3(b"contract_v2"), Predicate::DerivedFrom);
    doc_v2.object = Some(blake3(b"contract_v1"));
    doc_v2.lineage = Some(h1);
    let stmt_v2 = sign_and_anchor(&doc_v2, &alice, &log_sk);
    let h2 = blake3(stmt_v2.to_bytes());
    {
        let mut store = TestTrust::new(&alice, &log_sk);
        store.chain.insert(h1, stmt_v1.to_bytes().to_vec());
        store.chain.insert(h2, stmt_v2.to_bytes().to_vec());
        assert!(
            verify_statement(stmt_v2.to_bytes(), &store).is_ok(),
            "v2: Alice derived contract_v2 from v1"
        );
    }

    let mut doc_v3 = VeraxPayload::new(blake3(b"contract_v3"), Predicate::Supersedes);
    doc_v3.lineage = Some(h2);
    doc_v3.object = Some(h1);
    let stmt_v3 = sign_and_anchor(&doc_v3, &alice, &log_sk);
    {
        let mut store = TestTrust::new(&alice, &log_sk);
        store.chain.insert(h1, stmt_v1.to_bytes().to_vec());
        store.chain.insert(h2, stmt_v2.to_bytes().to_vec());
        store
            .chain
            .insert(blake3(stmt_v3.to_bytes()), stmt_v3.to_bytes().to_vec());
        assert!(
            verify_statement(stmt_v3.to_bytes(), &store).is_ok(),
            "v3: chain of 3 statements verified"
        );
    }

    let mut doc_broken = VeraxPayload::new(blake3(b"orphan"), Predicate::Authors);
    doc_broken.lineage = Some([0xba; 32]);
    let stmt_broken = sign_and_anchor(&doc_broken, &alice, &log_sk);
    let res = verify_statement(stmt_broken.to_bytes(), &store);
    assert_eq!(
        res,
        Err(Error::BrokenLineage("previous statement not found".into()))
    );
}

// ─── Use Case 3: Public Logbook (CT Temporal Anchoring) ────────────────────
// Instead of a blockchain, Verax anchors statements in an RFC 9162
// Transparency Log. This provides a mathematical proof of time without
// tokens, miners, or gas fees.

#[test]
fn use_case_3_public_logbook() {
    let issuer = sign_sk(0x42);
    let log_op = sign_sk(0x99);

    let payload = VeraxPayload::new(blake3(b"important_document"), Predicate::Attests);
    let stmt = sign_and_anchor(&payload, &issuer, &log_op);

    let store = TestTrust::new(&issuer, &log_op);
    assert!(
        verify_statement(stmt.to_bytes(), &store).is_ok(),
        "CT-anchored statement verifies"
    );

    let wrong_log_op = sign_sk(0x88);
    let bad_store = TestTrust::new(&issuer, &wrong_log_op);
    assert!(
        verify_statement(stmt.to_bytes(), &bad_store).is_err(),
        "wrong log key fails STH sig check"
    );
}

// ─── Use Case 4: The 8 Basic Verbs (Predicates) ────────────────────────────
// Verax's core only understands 8 predicates. Domain-specific metadata
// (HIPAA, FDA, etc.) goes in the extensions map (sticky notes).

#[test]
fn use_case_4_all_predicates() {
    let issuer = sign_sk(0x10);
    let log_sk = sign_sk(0x99);
    let subject = blake3(b"some_content");
    let object = blake3(b"other_content");
    let store = TestTrust::new(&issuer, &log_sk);

    for (pred, name) in [
        (Predicate::Attests, "ATTESTS"),
        (Predicate::Authors, "AUTHORS"),
        (Predicate::DerivedFrom, "DERIVED_FROM"),
        (Predicate::Supersedes, "SUPERSEDES"),
        (Predicate::Revokes, "REVOKES"),
        (Predicate::Endorses, "ENDORSES"),
        (Predicate::Appends, "APPENDS"),
        (Predicate::CompliesWith, "COMPLIES_WITH"),
    ] {
        let mut p = VeraxPayload::new(subject, pred);
        p.object = Some(object);
        let stmt = sign_and_anchor(&p, &issuer, &log_sk);
        let decoded = verify_statement(stmt.to_bytes(), &store)
            .expect(&format!("predicate {} must verify", name))
            .decode_payload()
            .unwrap();
        assert_eq!(decoded.predicate, pred);
        assert_eq!(decoded.subject, subject);
        assert_eq!(decoded.object, Some(object));
    }

    let mut p = VeraxPayload::new(blake3(b"extension_test"), Predicate::Attests);
    p.extensions = Some(vec![
        (100, verax_core::VeraxPayloadValue::Uint(42)),
        (101, verax_core::VeraxPayloadValue::Bstr(vec![1, 2, 3])),
    ]);
    let stmt = sign_and_anchor(&p, &issuer, &log_sk);
    let decoded = verify_statement(stmt.to_bytes(), &store)
        .expect("statement with extensions must verify")
        .decode_payload()
        .unwrap();
    assert!(
        decoded.extensions.is_some(),
        "extensions preserved through round-trip"
    );
    assert_eq!(decoded.extensions.as_ref().unwrap().len(), 2);

    let stream_id = blake3(b"live_stream_123");
    let chunk0 = VeraxPayload::new(stream_id, Predicate::Appends);
    let stmt0 = sign_and_anchor(&chunk0, &issuer, &log_sk);
    let h0 = blake3(stmt0.to_bytes());

    let mut chunk1 = VeraxPayload::new(stream_id, Predicate::Appends);
    chunk1.lineage = Some(h0);
    chunk1.object = Some(h0);
    let stmt1 = sign_and_anchor(&chunk1, &issuer, &log_sk);

    let mut chain_store = TestTrust::new(&issuer, &log_sk);
    chain_store.chain.insert(h0, stmt0.to_bytes().to_vec());
    assert!(
        verify_statement(stmt1.to_bytes(), &chain_store).is_ok(),
        "APPENDS chain with matching subject passes"
    );
}

// ─── Use Case 5: Right to be Forgotten (Cryptographic Shredding) ────────────
// Instead of erasing immutable history, Verax encrypts PII with a dedicated
// key and stores only the ciphertext. When the key is destroyed (zeroized),
// the data is mathematically unrecoverable — the "safe" remains but the key
// is gone.

#[test]
fn use_case_5_right_to_be_forgotten() {
    let patient_data = b"Patient: John Doe, Diagnosis: X, SSN: 123-45-6789";

    let shred_key = ShreddingKey::generate();

    let (ciphertext, commitment) = shredding_commit(&shred_key, patient_data).unwrap();
    assert_ne!(ciphertext, patient_data, "data is encrypted (ciphered)");
    assert_eq!(
        commitment,
        hash_ciphertext(&ciphertext),
        "commitment = hash of ciphertext"
    );

    let decrypted = decrypt_pii(&shred_key, &ciphertext).unwrap();
    assert_eq!(decrypted, patient_data, "decrypted data matches original");

    let wrong_key = ShreddingKey::generate();
    assert!(
        decrypt_pii(&wrong_key, &ciphertext).is_err(),
        "wrong key cannot decrypt"
    );

    assert!(
        decrypt_pii(&ShreddingKey::generate(), &ciphertext).is_err(),
        "fresh key also cannot decrypt"
    );

    let encrypted_twice = encrypt_pii(&shred_key, patient_data).unwrap();
    assert_ne!(
        encrypted_twice, ciphertext,
        "same data encrypts differently each time (unique nonce)"
    );

    let comm2 = hash_ciphertext(&ciphertext);
    assert_eq!(
        comm2, commitment,
        "hash is deterministic — ciphertext can be committed on-ledger"
    );
}

// ─── Offline verification ───────────────────────────────────────────────────
// A border agent or auditor can verify a statement with zero internet
// connectivity. No blockchain queries, no API calls — just pure math.

#[test]
fn use_case_offline_verification() {
    let issuer = sign_sk(0xaa);
    let payload = VeraxPayload::new(blake3(b"offline_doc"), Predicate::Authors);
    let stmt = Statement::sign_ed25519(&payload, &issuer).unwrap();
    let vk = issuer.verifying_key();

    let decoded = verify_statement_ed25519(stmt.to_bytes(), &vk)
        .expect("offline verification: pure math, no network, no TrustStore")
        .decode_payload()
        .unwrap();
    assert_eq!(decoded.subject, blake3(b"offline_doc"));
    assert_eq!(decoded.predicate, Predicate::Authors);
}

// ─── Multi-leaf CT log ──────────────────────────────────────────────────────
// Verifies that MockLog correctly builds Merkle trees with multiple leaves
// and produces inclusion proofs that pass verification.

#[test]
fn use_case_multi_leaf_ct_log() {
    let issuer = sign_sk(0x10);
    let log_sk = sign_sk(0x99);
    let vk = issuer.verifying_key();
    let log_key_bytes = log_sk.verifying_key().to_bytes();

    // Append 3 statements to the same log
    let mut log = MockLog::new(log_sk.clone());

    let p0 = VeraxPayload::new(blake3(b"leaf0"), Predicate::Attests);
    let p1 = VeraxPayload::new(blake3(b"leaf1"), Predicate::Authors);
    let p2 = VeraxPayload::new(blake3(b"leaf2"), Predicate::Endorses);

    let h0 = blake3(&p0.encode());
    let h1 = blake3(&p1.encode());
    let h2 = blake3(&p2.encode());

    log.append(h0);
    assert_eq!(log.tree_size(), 1, "1 leaf");
    let a0 = log.anchor(&h0).unwrap();
    assert_eq!(a0.signed_tree_head.tree_size, 1);
    // tree has 1 leaf → padded to next_power_of_two(1)=1 → root must match
    let expected_root0 = sha256_leaf_node(&h0);
    assert_eq!(a0.signed_tree_head.root_hash, expected_root0);

    log.append(h1);
    assert_eq!(log.tree_size(), 2, "2 leaves");
    let a1 = log.anchor(&h1).unwrap();
    assert_eq!(a1.signed_tree_head.tree_size, 2);
    // leaves = [h0, h1] → no padding needed since 2 is a power of 2
    let expected_root1 = sha256_node(&sha256_leaf_node(&h0), &sha256_leaf_node(&h1));
    assert_eq!(a1.signed_tree_head.root_hash, expected_root1);
    // Inclusion proof must verify
    assert!(a1.inclusion_proof.verify(&h1, &expected_root1));
    // Non-leaf (h2 not yet added) must NOT be findable
    assert!(log.anchor(&h2).is_none(), "h2 not yet in log");

    log.append(h2);
    assert_eq!(log.tree_size(), 3, "3 leaves");
    let a2 = log.anchor(&h2).unwrap();
    assert_eq!(a2.signed_tree_head.tree_size, 3);
    // 3 leaves → padded to next_power_of_two(3)=4 with zero hashes
    let leaf_nodes: Vec<[u8; 32]> = (0..4)
        .map(|i| match i {
            0 => sha256_leaf_node(&h0),
            1 => sha256_leaf_node(&h1),
            2 => sha256_leaf_node(&h2),
            _ => [0u8; 32],
        })
        .collect();
    let l1_0 = sha256_node(&leaf_nodes[0], &leaf_nodes[1]);
    let l1_1 = sha256_node(&leaf_nodes[2], &leaf_nodes[3]);
    let expected_root2 = sha256_node(&l1_0, &l1_1);
    assert_eq!(a2.signed_tree_head.root_hash, expected_root2);
    // Inclusion proof must verify for all 3 leaves
    assert!(a2.inclusion_proof.verify(&h2, &expected_root2));

    // Verify that leaf[0] also gets a correct proof from the 3-leaf tree
    // (regression: ensure mock doesn't only support the last leaf)
    let a0_v2 = log.anchor(&h0).unwrap();
    assert!(a0_v2.inclusion_proof.verify(&h0, &expected_root2));

    // Full verification via verify_statement
    let stmt0 = Statement::sign_ed25519_and_anchor(&p0, &issuer, &a0_v2).unwrap();

    struct MultiLeafStore {
        vk: ed25519_dalek::VerifyingKey,
        log_key: [u8; 32],
    }
    impl TrustStore for MultiLeafStore {
        fn resolve_key(&self, _: &[u8]) -> Option<ed25519_dalek::VerifyingKey> {
            Some(self.vk)
        }
        fn resolve_composite_key(&self, _: &[u8]) -> Option<CompositePublicKey> {
            None
        }
        fn fetch_statement(&self, _: &[u8; 32]) -> Option<Vec<u8>> {
            None
        }
        fn is_revoked_in_log(&self, _: &[u8; 32], _: u64) -> Option<bool> {
            Some(false)
        }
        fn resolve_log_pubkey(&self, log_id: &[u8; 32], candidate_key: &[u8; 32]) -> Option<[u8; 32]> {
            let computed = blake3(&self.log_key);
            if &computed == log_id && &self.log_key == candidate_key {
                Some(self.log_key)
            } else {
                None
            }
        }
    }
    let store = MultiLeafStore { vk, log_key: log_key_bytes };
    let result = verify_statement(stmt0.to_bytes(), &store);
    assert!(result.is_ok(), "leaf from multi-leaf CT log verifies");
}

// ─── Quantum-ready composite signatures ────────────────────────────────────
// Two locks on every statement: Ed25519 (today) + ML-DSA-65 (quantum-safe).

#[test]
fn use_case_quantum_ready_composite() {
    let ed_seed = [0x42u8; 32];
    let ed_sk = ed25519_dalek::SigningKey::from_bytes(&ed_seed);

    let mut ml_seed_bytes = [0u8; 32];
    for (i, b) in ml_seed_bytes.iter_mut().enumerate() {
        *b = i as u8;
    }
    let ml_seed = ml_dsa::Seed::try_from(&ml_seed_bytes[..]).unwrap();
    let ml_sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&ml_seed);

    let payload = VeraxPayload::new(blake3(b"quantum_document"), Predicate::Authors);
    let stmt = Statement::sign_composite(&payload, &ed_sk, &ml_sk).unwrap();

    let ml_vk = ml_sk.verifying_key();
    let pubkey = verax_core::composite_pubkey(&ed_sk.verifying_key(), &ml_vk);

    let log_sk = sign_sk(0x99);
    let store = TestTrust::new(&ed_sk, &log_sk);
    let result = verify_statement(stmt.to_bytes(), &store);
    assert!(
        result.is_err(),
        "Ed25519 key alone cannot verify a composite signature"
    );

    struct CompositeTrust {
        key: CompositePublicKey,
        log_key: [u8; 32],
    }
    impl TrustStore for CompositeTrust {
        fn resolve_key(&self, _: &[u8]) -> Option<ed25519_dalek::VerifyingKey> {
            None
        }
        fn resolve_composite_key(&self, _: &[u8]) -> Option<CompositePublicKey> {
            Some(self.key.clone())
        }
        fn fetch_statement(&self, _: &[u8; 32]) -> Option<Vec<u8>> {
            None
        }
        fn is_revoked_in_log(&self, _: &[u8; 32], _: u64) -> Option<bool> {
            Some(false)
        }
        fn resolve_log_pubkey(
            &self,
            log_id: &[u8; 32],
            candidate_key: &[u8; 32],
        ) -> Option<[u8; 32]> {
            let computed = verax_core::blake3(&self.log_key);
            if &computed == log_id && &self.log_key == candidate_key {
                Some(self.log_key)
            } else {
                None
            }
        }
    }
    let comp_store = CompositeTrust {
        key: pubkey,
        log_key: log_sk.verifying_key().to_bytes(),
    };
    assert!(
        verify_statement(stmt.to_bytes(), &comp_store).is_ok(),
        "composite key verifies the statement"
    );
}

// ─── CT-anchored composite signature ────────────────────────────────────────
// Composite signing + CT temporal anchoring combined. This exercises both
// the quantum-resistant signing path and the RFC 9162 inclusion proof path.

#[test]
fn use_case_ct_anchored_composite() {
    let ed_seed = [0x42u8; 32];
    let ed_sk = ed25519_dalek::SigningKey::from_bytes(&ed_seed);

    let mut ml_seed_bytes = [0u8; 32];
    for (i, b) in ml_seed_bytes.iter_mut().enumerate() {
        *b = i as u8;
    }
    let ml_seed = ml_dsa::Seed::try_from(&ml_seed_bytes[..]).unwrap();
    let ml_sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&ml_seed);

    let log_sk = sign_sk(0x99);
    let log_key_bytes = log_sk.verifying_key().to_bytes();

    // Build anchor first, then sign composite with anchor embedded
    let mut payload = VeraxPayload::new(blake3(b"ct_composite_doc"), Predicate::DerivedFrom);
    payload.object = Some(blake3(b"original_source"));
    let mut log = MockLog::new(log_sk.clone());
    let payload_hash = blake3(&payload.encode());
    log.append(payload_hash);
    let anchor = log.anchor(&payload_hash).unwrap();
    let stmt = Statement::sign_composite_and_anchor(&payload, &ed_sk, &ml_sk, &anchor).unwrap();

    let ml_vk = ml_sk.verifying_key();
    let pubkey = verax_core::composite_pubkey(&ed_sk.verifying_key(), &ml_vk);

    struct CompAnchorStore {
        key: CompositePublicKey,
        log_key: [u8; 32],
    }
    impl TrustStore for CompAnchorStore {
        fn resolve_key(&self, _: &[u8]) -> Option<ed25519_dalek::VerifyingKey> {
            None
        }
        fn resolve_composite_key(&self, _: &[u8]) -> Option<CompositePublicKey> {
            Some(self.key.clone())
        }
        fn fetch_statement(&self, _: &[u8; 32]) -> Option<Vec<u8>> {
            None
        }
        fn is_revoked_in_log(&self, _: &[u8; 32], _: u64) -> Option<bool> {
            Some(false)
        }
        fn resolve_log_pubkey(
            &self,
            log_id: &[u8; 32],
            candidate_key: &[u8; 32],
        ) -> Option<[u8; 32]> {
            let computed = verax_core::blake3(&self.log_key);
            if &computed == log_id && &self.log_key == candidate_key {
                Some(self.log_key)
            } else {
                None
            }
        }
    }
    let store = CompAnchorStore {
        key: pubkey.clone(),
        log_key: log_key_bytes,
    };
    assert!(
        verify_statement(stmt.to_bytes(), &store).is_ok(),
        "CT-anchored composite statement verifies"
    );

    // Wrong log key should fail STH signature check
    let wrong_log = sign_sk(0x88);
    let bad_store = CompAnchorStore {
        key: pubkey,
        log_key: wrong_log.verifying_key().to_bytes(),
    };
    assert!(
        verify_statement(stmt.to_bytes(), &bad_store).is_err(),
        "wrong log key fails verification"
    );
}
