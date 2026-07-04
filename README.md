# Axiom Protocol

[![CI](https://github.com/thupa-pro/axiom-core/actions/workflows/ci.yml/badge.svg)](https://github.com/thupa-pro/axiom-core/actions/workflows/ci.yml)
[![Axiom-True](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/thupa-pro/axiom-core/main/.github/badges/axiom-true-status.json&color=2ea44f)](https://github.com/thupa-pro/axiom-core/actions/workflows/axiom-compliance.yml)
[![cargo-deny](https://img.shields.io/badge/cargo--deny-passed-brightgreen)](https://github.com/thupa-pro/axiom-core/actions/workflows/axiom-compliance.yml)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Rust](https://img.shields.io/badge/rust-1.85%2B-orange)
![Rust Edition](https://img.shields.io/badge/edition-2024-blue)

Axiom is a minimal, tamper-evident provenance protocol using **deterministic CBOR**, **Ed25519 + ML-DSA-65 hybrid signatures** (FIPS 204), **Certificate Transparency anchoring** (RFC 9162), and **PII shredding** — with an IETF forensic audit passed, 101 tests, and Axiom-True v1.0 verification compliance. Bindings for Rust, C, Python, Node.js, and Go.

---

## Quick Start

```bash
# Install the CLI
cargo install --path crates/axiom-cli

# Create a project
axiom init

# Sign an artifact
echo "Hello, Axiom!" > hello.txt
axiom sign hello.txt

# Verify
axiom verify hello.axm
```

## Overview

Axiom is a protocol for **verifiable provenance** — cryptographic statements that link an artifact to a predicate (attests, authors, derived_from, etc.) in a tamper-evident DAG. Every statement is signed, optionally anchored to a Certificate Transparency log, and verifiable offline.

### Key Features

- **Deterministic CBOR** — Canonical encoding prevents malleability attacks (T5 fix)
- **Ed25519 + ML-DSA-65 hybrid** — Post-quantum composite signatures (FIPS 204)
- **CT anchoring** — Bind statements to public transparency logs (T1 fix)
- **Revocation** — Log-based revocation with local cache support
- **PII shredding** — Encrypt-then-commit for right-to-be-forgotten compliance
- **Formal proofs** — TLA+, Coq, Lean 4, and Kani proof harnesses
- **Full protocol verification** — Lineage, key rotation, timestamps, and revocation all checked
- **Multiple bindings** — Rust, C FFI, Python, Node.js, Go

## Crates

| Crate | Description |
|-------|-------------|
| [`axiom-core`](crates/axiom-core) | Core protocol library — payload, COSE signing, verification, CT, shredding |
| [`axiom-cli`](crates/axiom-cli) | Command-line tool — init, sign, verify, inspect, lint, graph |
| [`axiom-core-ffi`](crates/axiom-core-ffi) | C FFI bindings for Go and other languages |
| [`axiom-core-python`](crates/axiom-core-python) | Python bindings (PyO3) |
| [`axiom-core-node`](crates/axiom-core-node) | Node.js bindings (napi-rs) |

## Documentation

- [Getting Started](docs/getting-started.md) — Step-by-step walkthrough
- [Architecture](docs/architecture.md) — High-level design and data flow
- [Protocol Specification](docs/protocol-spec.md) — CBOR payload format, COSE envelopes, CT anchoring
- [Composite Signatures](docs/composite-signatures.md) — Ed25519 + ML-DSA-65 hybrid
- [PII Shredding](docs/shredding.md) — Encryption and commitment for right-to-be-forgotten
- [Key Rotation](docs/key-rotation.md) — Key rotation protocol and chain resolution
- [Security Audit](docs/security_audit.md) — Third-party security analysis
- [Formal Proofs](FORMAL_PROOFS.md) — Map of formal verification and proof harnesses
- [Shredding](crates/axiom-core/src/shred.rs) — PII shredding module with formal theorem (module-level docs)

## Security

See [SECURITY.md](SECURITY.md) for our disclosure policy and [docs/security_audit.md](docs/security_audit.md) for the full audit report.

## Development

- [Contributing Guide](CONTRIBUTING.md)
- [Agent Constitution](AGENTS.md) — Hard constraints for AI coding agents
- [Pre-commit hooks](.pre-commit-config.yaml) — Auto-enforce code quality
- [`cargo-deny`](deny.toml) — Dependency license and advisory checking

## License

MIT — see [LICENSE](LICENSE).
