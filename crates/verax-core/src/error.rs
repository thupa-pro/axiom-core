//! Error types for the Verax Protocol core crate.
//!
//! All fallible operations return [`Result<T>`] (aliasing
//! `core::result::Result<T, Error>`). The [`Error`] enum has 19 variants
//! covering CBOR encoding/decoding, signature verification, lineage
//! traversal, certificate transparency, revocation, I/O, and cryptography:
//!
//! | #  | Variant                     | Description                              |
//! |----|-----------------------------|------------------------------------------|
//! | 1  | `MalformedCose`             | Invalid COSE_Sign1 envelope structure    |
//! | 2  | `NonCanonicalEncoding`      | Non-deterministic CBOR encoding          |
//! | 3  | `InvalidSignature`          | Ed25519 or composite signature failure   |
//! | 4  | `BrokenLineage`             | Lineage chain validation error           |
//! | 5  | `LineageSubjectMismatch`    | Parent/child subject hash mismatch       |
//! | 6  | `TimestampMonotonicityViolation` | Child timestamp precedes parent      |
//! | 7  | `RevokeIssuerMismatch`      | REVOKES issuer ≠ revoked statement key   |
//! | 8  | `InvalidLogProof`           | CT log inclusion proof is invalid        |
//! | 9  | `Revoked`                   | Statement has been revoked               |
//! | 10 | `InvalidField`              | A required field has an invalid value    |
//! | 11 | `Crypto`                    | Cryptographic operation failure          |
//! | 12 | `Decode`                    | CBOR decode failure (structure)          |
//! | 13 | `HashLength`                | Expected/actual hash length mismatch     |
//! | 14 | `Io`                        | I/O operation failure                    |
//! | 15 | `Payload`                   | Payload field validation error           |
//! | 16 | `RecoveryPolicyViolation`   | Recovery policy check failed             |
//! | 17 | `AnchorHashMismatch`        | CT anchor hash verification failure      |
//! | 18 | `LineageDepthExceeded`      | Lineage traversal exceeded max depth     |
//! | 19 | `Encode`                    | CBOR encoding failure                    |
use alloc::string::String;
use alloc::string::ToString;
use core::fmt;

/// Convenience alias for `core::result::Result<T, Error>`.
pub type Result<T> = core::result::Result<T, Error>;

/// Protocol-level error type covering all verification, encoding, and
/// I/O failures in verax-core.
///
/// Each variant carries contextual information where appropriate. The
/// [`Display`](core::fmt::Display) implementation produces human-readable
/// messages suitable for CLI and logging output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Error code 1: invalid COSE_Sign1 envelope structure or payload.
    MalformedCose(String),
    /// Error code 2: CBOR encoding violates determinism rules
    /// (non-shortest-form ints, unsorted map keys, tags, floats,
    /// null/undefined, or indefinite-length items).
    NonCanonicalEncoding,
    /// Error code 3: Ed25519 or composite (Ed25519 + ML-DSA-65) signature
    /// verification failed.
    InvalidSignature,
    /// Error code 4: lineage chain validation failed (e.g. parent hash
    /// does not match claimed parent, or lineage records disagree).
    BrokenLineage(String),
    /// Error code 5: the subject hash of a child statement does not match
    /// the subject hash of its claimed parent.
    LineageSubjectMismatch,
    /// Error code 6: a child statement's timestamp is older than its
    /// parent's timestamp.
    TimestampMonotonicityViolation,
    /// Error code 7: the issuer key of a REVOKES statement does not match
    /// the key that signed the revoked statement.
    RevokeIssuerMismatch,
    /// Error code 8: a Certificate Transparency log inclusion proof
    /// is structurally invalid or does not verify against the signed
    /// tree head.
    InvalidLogProof(String),
    /// Error code 9: the statement has been explicitly revoked.
    Revoked,
    /// Error code 10: a required field has an invalid value (e.g. out of
    /// range, wrong length).
    InvalidField(&'static str),
    /// Error code 11: cryptographic primitive failure (e.g. key
    /// deserialisation, signature generation).
    Crypto(String),
    /// Error code 12: CBOR structural decode error (unexpected end of
    /// input, wrong major type, reserved additional info).
    Decode(String),
    /// Error code 13: hash length mismatch between expected and actual
    /// byte count.
    HashLength {
        /// Expected hash length in bytes.
        expected: usize,
        /// Actual hash length in bytes that was provided.
        actual: usize,
    },
    /// Error code 14: I/O operation failure (file read/write, network).
    Io(String),
    /// Error code 15: payload field validation failure (missing required
    /// field, wrong byte length for `subject`/`object`, invalid predicate).
    Payload(String),
    /// Error code 16: recovery policy validation failure (e.g. insufficient
    /// guardian approvals, invalid recovery proof).
    RecoveryPolicyViolation(String),
    /// Error code 17: the `anchor_hash` in the payload does not match the
    /// hash derived from the CT anchor proof.
    AnchorHashMismatch,
    /// Error code 18: lineage traversal exceeded the maximum depth limit
    /// (1024), preventing infinite loops in deeply nested chains.
    LineageDepthExceeded,
    /// Error code 19: CBOR encoding failure (FFI error code 16).
    Encode(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::MalformedCose(msg) => write!(f, "malformed COSE: {msg}"),
            Error::NonCanonicalEncoding => write!(f, "non-canonical CBOR encoding"),
            Error::InvalidSignature => write!(f, "invalid signature"),
            Error::BrokenLineage(msg) => write!(f, "broken lineage: {msg}"),
            Error::LineageSubjectMismatch => write!(f, "lineage subject mismatch"),
            Error::TimestampMonotonicityViolation => write!(f, "timestamp monotonicity violation"),
            Error::RevokeIssuerMismatch => {
                write!(f, "REVOKES issuer does not match revoked statement issuer")
            }
            Error::InvalidLogProof(msg) => write!(f, "invalid log proof: {msg}"),
            Error::Revoked => write!(f, "statement has been revoked"),
            Error::InvalidField(name) => write!(f, "invalid field: {name}"),
            Error::Crypto(msg) => write!(f, "crypto error: {msg}"),
            Error::Decode(msg) => write!(f, "decode error: {msg}"),
            Error::HashLength { expected, actual } => {
                write!(f, "hash length: expected {expected}, got {actual}")
            }
            Error::Io(msg) => write!(f, "I/O error: {msg}"),
            Error::Payload(msg) => write!(f, "payload error: {msg}"),
            Error::RecoveryPolicyViolation(msg) => write!(f, "recovery policy violation: {msg}"),
            Error::AnchorHashMismatch => write!(f, "anchor hash mismatch"),
            Error::LineageDepthExceeded => write!(f, "lineage traversal depth exceeded"),
            Error::Encode(msg) => write!(f, "encode error: {msg}"),
        }
    }
}

impl From<ed25519_dalek::ed25519::Error> for Error {
    fn from(e: ed25519_dalek::ed25519::Error) -> Self {
        Error::Crypto(e.to_string())
    }
}


