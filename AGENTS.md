# verax Agent Constitution

Hard constraints for AI coding agents working on verax-core.

## 1. Integrity Invariants

- **NO `unsafe` code** in `verax-core`. The crate is `#![deny(unsafe_code)]`. FFI crates (`verax-core-ffi`) may use `unsafe` only where absolutely required by the C ABI.
- **NO adding `std`** to `verax-core`. The crate is `#![no_std]` with `extern crate alloc`.
- **NO `unwrap()` or `expect()`** in production code paths. Use `?` with proper error types. Panics are only acceptable in test code.
- **NO `panic!()`** in production code paths.
- **NO hardcoded secrets, keys, or passwords** in source code.

## 2. Security Invariants

- All secret comparisons MUST use `ConstantTimeEq` (from `subtle` or `ed25519-dalek`).
- All secret key material MUST implement `ZeroizeOnDrop`.
- Ed25519 verification MUST use `verify_strict()` (rejects malleable signatures), NOT `verify()`.
- COSE envelope parsing MUST check for canonical CBOR encoding (call `check_protected_header_determinism()`).
- Do NOT introduce new dependencies without checking their security posture, license compatibility, and maintenance status.

## 3. Dependency Invariants

- No GPL or copyleft-licensed dependencies.
- All new dependencies MUST be pre-approved for the `no_std` target (if added to `verax-core`).
- Run `cargo deny check` after any dependency change. Do NOT add ignores without triage.

## 4. Build Invariants

- `cargo clippy --workspace -- -D warnings` MUST pass before any commit.
- `cargo test --workspace` MUST pass before any commit.
- `cargo fmt --check` MUST pass before any commit.
- Do NOT commit `Cargo.lock` changes without a corresponding `Cargo.toml` change.

## 5. Documentation Invariants

- Every new public function MUST have a `///` doc comment.
- Every new crate MUST have a `README.md`.
- Protocol-level changes MUST update `docs/`.

## 6. Contract

This constitution binds ALL AI agents working on this repository. If you cannot comply with a constraint, state the conflict explicitly and seek human approval before proceeding. Violations will be reverted.

## Progress

### Done
- Full 46‑sub‑check audit completed: all checks PASSED, declared Axiom‑True v1.0 production‑ready (now Verax‑True)
- `.github/workflows/axiom-compliance.yml` → `verax-compliance.yml`, compliance bot created
- **Rebrand Axiom → Verax** completed across all 10 phases (crates, CLI, bindings, CI, docs, proofs, source, headers)
- **GitHub repo** renamed `thupa-pro/verax-core`, remote URL/description updated
- **Trap doors patched (T1–T5)**: CT anchor malleability, lineage/rotation recursion bypasses, CLI bypass, non-deterministic COSE
- **Findings patched (F3, F5)**: key algorithm label, strict determinism check
- **CLI upgrades**: `verify` with `CliTrustStore`/chain/revocation, `sign` with composite/CT anchor
- **Bindings upgrades**: Python (verify_full dict), Node.js (JsVerificationResult), C FFI (verify_full chain)
- **P0 bugs fixed**: `anchor_hash` spec line 70 corrected; signing path computes `anchor_hash = BLAKE3(unprotected_header)`; cycle detection in key rotation via `BTreeSet`
- **P1 spec fixes**: Composite sig byte order, KID, Hybrid mode documented; unprotected header key order fixed; cycle detection documented
- **Go binding fix**: `-laxiom_core_ffi`→`-lverax_core_ffi`, all 24 `C.axiom_*`→`C.verax_*`
- **All Axiom→Verax docstring references cleaned**: zero remaining `\bAxiom\b` outside protected domain separation strings
- **P0 anchor_hash CT verification fix**: `verify_temporal_anchor` strips `anchor_hash` before computing content hash for CT inclusion verification
- **111+6 tests pass** (Rust lib 101 + doctests 2 + integration 8 + Go/TLA+/Lean proof scripts 6)
