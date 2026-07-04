# Axiom Protocol Hardening Audit – The Unforgiving Verifier

**Role:** You are the world's foremost cryptographic protocol auditor, hired to ensure that an implementation of the Axiom Protocol is mathematically sound, fully compliant, and hardened against all specified threats. The implementation already exists; your job is to prove – with concrete evidence – that it fulfills every promise of the specification, or to expose every deviation.

**Instructions:**
For each numbered check below, you must:

1. Answer **Yes** or **No**.
2. Provide unambiguous evidence from the codebase, tests, or documentation (e.g., file paths, line numbers, test names, output excerpts).
3. If the answer is No or evidence is missing, classify the gap as **CRITICAL** (breaks interoperability/security), **HIGH** (deviates from normative requirements), or **LOW** (minor edge case).
4. Never rely on assumptions or verbal guarantees; only code and test artifacts count.

Proceed through every check in order, never skipping. Only when all checks pass can the implementation be declared "Axiom‑true".

---

## 1. Deterministic CBOR (The Axiom of Immutable Bytes)

### 1.1 Tag Prohibition
Is every CBOR encoder/decoder path for the core payload (the verity-payload map) hardened to reject any CBOR tag (major type 6)? Show the exact line(s) that cause a hard failure (error code `NonCanonicalEncoding`) when a tag is encountered.

### 1.2 Floating‑Point Exile
Is any attempt to encode a float16/32/64 in the core payload immediately rejected with an error? Point to the test that proves that 0.0, NaN, or Inf cannot appear in a valid statement.

### 1.3 Null's Permanent Ban
Does the serializer never emit CBOR null for missing optional fields, and does the parser treat any null value in the payload map as a hard decoding error? Show the relevant validation code.

### 1.4 Integer Shortest‑Form Encoding
Verify that the integer 0 is always encoded as `0x00` (one byte) and 1000 uses the minimal additional info. Provide a test vector that catches a two‑byte encoding of a small integer.

### 1.5 Map Key Sorting (Bytewise)
Prove that map keys are sorted by the raw CBOR‑encoded bytes, not numerically. For example, key 10 must precede key 2. Cite the sorting function and a test with unsorted input that is rejected.

### 1.6 Indefinite‑Length Items
Does the decoder reject any use of indefinite‑length bytes, text, arrays, or maps? Show the error path and a corresponding test.

### 1.7 Duplicate Map Keys
Does the decoder detect duplicate keys in a map and reject the payload? Provide the test case.

### 1.8 No Trailing Garbage
After parsing a complete CBOR item, does the decoder fail if extra bytes remain in the buffer? Point to the check and test.

### 1.9 Deterministic Re‑encoding Stability
If a verified payload is decoded and then re‑encoded, is the resulting byte sequence guaranteed to be identical to the original? Provide a round‑trip test that proves this.

### 1.10 String‑Encoded Decimal Canonicalization
If the extensions map or any field uses a string‑encoded decimal, is there a documented, implementation‑specific canonical form (leading zeros stripped, no trailing zeros, etc.)? Is this canonicalisation tested across multiple implementations to guarantee identical hashes?

---

## 2. Cryptographic Primitives – No Room for Ambiguity

### 2.1 BLAKE3 for Everything
Is the 32‑byte BLAKE3 hash used for all content addressing (artifacts, statement subjects, lineage, kid derivation) with zero fallback to SHA‑256? Show the import and the call site for computing a statement's subject.

### 2.2 BLAKE3 Domain Separation
When multiple hash contexts are needed (e.g., different extension types), is BLAKE3's `derive_key` used instead of manual concatenation? Point to a usage example.

### 2.3 COSE_Sign1 Envelope Compliance
Are all statements serialised as a tagged COSE_Sign1 CBOR structure (tag 98)? Verify that the protected header map contains exactly `1` (alg), `4` (kid), and optionally `8` (algorithm_suite_id), with no other keys.

### 2.4 Ed25519 Pure for Single‑Key
For algorithm -8, does the signing/verification library use Ed25519Pure (RFC 8032) without pre‑hashing? Confirm that the context string is empty.

### 2.5 Composite Signature Construction
For algorithm -39, is the classical part computed with Ed25519ph using the context string `"Axiom-Provenance-v1"`? Is the ML‑DSA‑65 signature appended directly to the Ed25519 signature, with no delimiters? Show the concatenation code.

### 2.6 ML‑DSA‑65 Parameter Pinning
Are the ML‑DSA‑65 parameters frozen to FIPS 204 Level 3? Validate that the public key length is exactly 1952 bytes and the signature length exactly 3309 bytes by checking the key‑gen and signature verification functions.

### 2.7 Kid Derivation for Composite Keys
For algorithm -39, is the kid computed as `BLAKE3(ML‑DSA‑65_pk || Ed25519_pk)` and stored as a 32‑byte opaque identifier, never containing the raw public keys? Verify the wire format.

### 2.8 Algorithm‑Kid Binding
Does the verifier check that the algorithm ID in the protected header matches the type of key resolved from the kid? Show the logic that rejects a composite key when alg = -8.

---

## 3. The DAG – Immutable, Signed, Predicate‑Driven

### 3.1 Artifact‑as‑Hash
Are artifacts never inlined in a statement? Prove that the subject field is always a 32‑byte BLAKE3 hash, and that large files use BLAKE3's native tree‑hashing mode with no custom Merkle tree.

### 3.2 Predicate Registry Lockdown
Are exactly nine core predicates (0‑8) supported, with IDs 9‑99 reserved for IANA registration and 100+ available for private use? Show where the validation logic rejects a predicate outside these ranges.

### 3.3 Timestamp Monotonicity
When a lineage is present, does the verifier enforce `t_current >= t_previous`? Provide a test where a decreasing timestamp causes `TimestampMonotonicityViolation` (error 6).

### 3.4 Nonce Requirement on Equal Timestamps
If `t_current == t_previous` and lineage is set, is a nonce mandatory? Show the rejection path and a test.

### 3.5 APPENDS Lineage Constraint
For predicate = `APPENDS`, does the verifier require that the previous statement's subject matches the current statement's subject? Prove with a failing test.

### 3.6 Object Field Consistency
For binary‑relationship predicates (`DERIVED_FROM`, `SUPERSEDES`, `REVOKES`, `COMPLIES_WITH`), is the object field (key 3) present and always a 32‑byte hash? Show the validation check.

### 3.7 Extensions Map Opacity
Does the core verifier completely ignore the content of the extensions map during its integrity checks? Verify that the map is passed through without re‑encoding and does not affect signature verification.

---

## 4. Temporal Anchoring – Trust the Log, Nothing Else

### 4.1 No Custom Consensus
Search the codebase for any evidence of a custom blockchain, PBFT, or other consensus mechanism. If found, fail instantly (CRITICAL). The protocol must rely exclusively on RFC 9162 CT logs.

### 4.2 COSE Anchor Attachment
Are the inclusion proof and STH always placed in the unprotected header with keys `"log_inclusion_proof"` and `"log_sth"`? Show the serialization code.

### 4.3 External AAD Binding
Is the COSE signature recomputed with `external_aad = BLAKE3(unprotected_header)`? Provide a test that proves altering the unprotected header invalidates the signature.

### 4.4 STH Verification Order
Is the STH's Ed25519 signature verified **before** the inclusion proof? Show the order in the verification function.

### 4.5 Inclusion Proof Leaf Construction
Does the leaf hash for the CT Merkle tree equal `SHA‑256(0x00 || BLAKE3(payload_bytes))`? Confirm this with a step‑by‑step proof test.

### 4.6 STH Freshness Warning
Does the verifier emit a **warning** (distinct from an error) when the STH timestamp exceeds the statement timestamp by more than 90 days? Show the log output or warning callback.

### 4.7 Log Key Trust Store
Are CT log public keys identified by `BLAKE3(log_pk)` and resolved from a configurable, tamper‑proof trust store? Demonstrate key rotation or rejection of an unknown log.

---

## 5. Revocation & Key Lifecycle – Control Through Cryptography

### 5.1 REVOKES Authority
When a `REVOKES` statement is verified, does the code check that the issuer's kid matches the original statement's kid? Point to the check that raises `RevokeIssuerMismatch` (error 7) if violated.

### 5.2 Revocation Temporal Ordering
Does the verifier ensure the `REVOKES` statement's timestamp is strictly greater than the target statement's timestamp? Show the failure when a back‑dated revocation is attempted.

### 5.3 Key Rotation Chain Walking
For key rotation (`SUPERSEDES`), does the resolver walk the chain, verify each signature from the predecessor, and enforce a maximum depth of 100? Provide a test with a rotation chain of length 3 that succeeds, and one of length 101 that fails.

### 5.4 Key Recovery (`RECOVERS`) Policy Enforcement
Is a `RECOVERS` statement only accepted if the signing guardian's kid appears in the lost key's recovery policy (`recovery_policy` field)? Show the lookup and rejection path.

### 5.5 Recovery Policy Format
Is the `RecoveryPolicy` structure serialised as deterministic CBOR? Provide its CDDL or schema definition and a test that ensures re‑encoding doesn't change the hash.

### 5.6 Revocation Completeness Statement
Does the verifier documentation explicitly state that absence of a `REVOKES` in the locally‑monitored log does **not** prove non‑revocation? Find the warning in user‑facing docs.

---

## 6. Privacy – Cryptographic Shredding as a Legal Foundation

### 6.1 PII Never Touches the DAG
Is there an architectural gate that prevents plaintext personal data from being hashed into a statement? Demonstrate how the API enforces that only ciphertext hashes can be referenced as subjects.

### 6.2 Shredding Operation
Is there a dedicated "shred" function that securely overwrites the symmetric key (XChaCha20‑Poly1305) in memory and then deletes it from storage? Show the zeroisation code.

### 6.3 Consent Receipt
Are consent receipts implemented as Axiom statements where the subject is `BLAKE3(encrypted_consent_document)` and the extensions map contains `BLAKE3(human_readable_terms)`? Provide an example.

### 6.4 Metadata Leakage Awareness
Does the design document acknowledge that even ciphertext hashes and timestamps can constitute metadata under GDPR and suggest minimisation strategies?

---

## 7. Verification Algorithm & Error Handling

### 7.1 Stateless Verification
Is the top‑level `verify_statement` function a pure function with no internal mutable state? Verify by looking for global variables or side effects.

### 7.2 Full Error Code Coverage
Do all 18 error codes (1‑18) from the specification have corresponding tests that trigger them? List each code and a test name that exercises it.

### 7.3 Lineage Recursion Depth Limit
When verifying a chain of statements (lineage), is there a recursion depth limit to prevent stack overflow on extremely long chains? Show the guard.

### 7.4 Deterministic Encoding Check in Verifier
Does the verifier explicitly validate that the payload CBOR is strictly deterministic **before** checking the signature? If the payload is non‑canonical, is `NonCanonicalEncoding` returned?

---

## 8. FFI, Bindings & Conformance

### 8.1 C FFI Exact Match
Do the exported C functions (`axiom_verify_ed25519`, etc.) match the signatures in the header exactly, including the `axiom_free` call for output buffers? Show the header and a smoke test.

### 8.2 Conformance Test Vectors
Does the implementation pass every vector in the official `test_vectors.json` file? Provide the test run output showing 100% success.

### 8.3 Negative Test Suite
Are there tests that specifically submit malformed CBOR, invalid signatures, broken lineages, and expired STHs, and assert the exact error codes?

### 8.4 High‑Level Bindings Error Mapping
Do the Python/Node.js bindings map the 18 error codes to typed exceptions with descriptive messages, and do they preserve the original error code for programmatic use?

---

## 9. Threat Model Hardening

### 9.1 Signature Malleability
Can you produce two different valid COSE_Sign1 encodings for the same logical payload? If so, the implementation is broken. Show that the deterministic encoding prevents this.

### 9.2 Anchor Transplantation Attack
Construct a test where a valid CT anchor from statement A is copied to statement B. Verify that signature verification fails because of the external AAD binding.

### 9.3 STH Replay Attack
Attempt to reuse an old STH with a new statement. Show that the STH freshness logic or external AAD binding prevents this.

### 9.4 Quantum Attack Simulation
For a composite signature, tamper with the classical Ed25519 part but leave the ML‑DSA‑65 part valid. Verify that the verifier rejects the whole signature. Then do the inverse – tamper only the ML‑DSA‑65 part. Both must fail.

---

## 10. Protocol Orthogonality & Purity

### 10.1 No Tokenomics
The codebase must contain no token, bond, or fee mechanism. If any appears, flag as CRITICAL.

### 10.2 Transport Independence
The verifier must not depend on HTTP, IPFS, or any specific transport. Prove that it can verify a statement loaded from a raw byte array.

### 10.3 Core Verifier Freeze
Confirm that adding a new private‑use predicate (ID ≥ 100) to an extension does **not** change the core verifier's binary or alter its behaviour for existing statements.

---

## Final Certification

If all checks pass with documented evidence, you may declare the implementation **Axiom‑True v1.0**. If any CRITICAL or HIGH gaps remain, the audit fails until they are resolved.
