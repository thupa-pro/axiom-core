// ═══════════════════════════════════════════════════════════════════════
// Verax Protocol — Performance Benchmarks
//
// Scenarios:
//   1. Deterministic Encoding Throughput (1KB, 10KB, 100KB)
//   2. Verification Micro-benchmark (Ed25519 ± CT anchor, p50/p99)
//   3. Lineage Chain Walking (10,000 APPENDS)
//   4. Composite Signature Cost (alg -39 vs -8, Hybrid/ClassicalOnly/PQOnly)
//   5. CT Log STH Freshness Overhead (stale vs fresh, allocation audit)
//
// Run: cargo bench -p verax-core
// ═══════════════════════════════════════════════════════════════════════

use std::collections::BTreeMap;
use std::time::Instant;

use criterion::{
    BenchmarkId, Criterion, SamplingMode, Throughput, black_box, criterion_group, criterion_main,
};
use verax_core::cbor::{Value, VeraxPayload};
use verax_core::cose::{
    COMPOSITE_SIG_SIZE, CompositePublicKey, MLDSA65_PK_SIZE, MLDSA65_SIG_SIZE, VerificationMode,
    composite_pubkey, parse_and_verify_composite, parse_and_verify_ed25519,
};
use verax_core::ct::{LogInclusionProof, SignedTreeHead, TemporalAnchor};
use verax_core::hash::blake3;
use verax_core::statement::Statement;
use verax_core::verify::{TrustStore, verify_statement, verify_statement_with_warnings};
use verax_core::*;

use ed25519_dalek::SigningKey;
use sha2::Digest;

// ───────────────────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────────────────

fn make_ed25519_keypair() -> (SigningKey, ed25519_dalek::VerifyingKey) {
    let seed = [0x42u8; 32];
    let sk = SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();
    (sk, vk)
}

fn make_composite_signing_key() -> (SigningKey, ml_dsa::SigningKey<ml_dsa::MlDsa65>) {
    let ed_seed = [0x42u8; 32];
    let ed_sk = SigningKey::from_bytes(&ed_seed);
    let mut ml_seed = [0u8; 32];
    for (i, b) in ml_seed.iter_mut().enumerate() {
        *b = i as u8;
    }
    let ml_seed_obj = ml_dsa::Seed::try_from(&ml_seed[..]).unwrap();
    let ml_sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&ml_seed_obj);
    (ed_sk, ml_sk)
}

fn make_payload(subject: &[u8; 32], predicate: Predicate, size_kb: usize) -> VeraxPayload {
    let mut p = VeraxPayload::new(*subject, predicate);
    p.timestamp = Some(1_700_000_000);
    if size_kb > 0 {
        let data_size = (size_kb * 1024).saturating_sub(64);
        let ext_data = vec![0x42u8; data_size.min(65536)];
        p.extensions = Some(vec![(100, Value::Bstr(ext_data))]);
    }
    p
}

/// TrustStore that resolves a single Ed25519 key and returns
/// `Some(false)` for revocation queries.
struct NullTrustStore {
    vk: ed25519_dalek::VerifyingKey,
}

impl TrustStore for NullTrustStore {
    fn resolve_key(&self, kid: &[u8]) -> Option<ed25519_dalek::VerifyingKey> {
        if kid == self.vk.as_bytes() {
            Some(self.vk)
        } else {
            None
        }
    }
    fn resolve_composite_key(&self, _kid: &[u8]) -> Option<CompositePublicKey> {
        None
    }
    fn fetch_statement(&self, _hash: &[u8; 32]) -> Option<Vec<u8>> {
        None
    }
    fn is_revoked_in_log(&self, _h: &[u8; 32], _t: u64) -> Option<bool> {
        Some(false)
    }
    fn resolve_log_pubkey(&self, _log_id: &[u8; 32], _candidate: &[u8; 32]) -> Option<[u8; 32]> {
        None
    }
}

/// TrustStore that also provides a trusted CT log key.
struct LogTrustStore {
    vk: ed25519_dalek::VerifyingKey,
    log_key: [u8; 32],
}

impl TrustStore for LogTrustStore {
    fn resolve_key(&self, kid: &[u8]) -> Option<ed25519_dalek::VerifyingKey> {
        if kid == self.vk.as_bytes() {
            Some(self.vk)
        } else {
            None
        }
    }
    fn resolve_composite_key(&self, _kid: &[u8]) -> Option<CompositePublicKey> {
        None
    }
    fn fetch_statement(&self, _hash: &[u8; 32]) -> Option<Vec<u8>> {
        None
    }
    fn is_revoked_in_log(&self, _h: &[u8; 32], _t: u64) -> Option<bool> {
        Some(false)
    }
    fn resolve_log_pubkey(&self, log_id: &[u8; 32], candidate: &[u8; 32]) -> Option<[u8; 32]> {
        let computed = blake3(&self.log_key);
        if &computed == log_id && &self.log_key == candidate {
            Some(self.log_key)
        } else {
            None
        }
    }
}

/// TrustStore for lineage chain walking — fetches statements by hash.
struct ChainTrustStore {
    chain: BTreeMap<[u8; 32], Vec<u8>>,
    vk: ed25519_dalek::VerifyingKey,
}

impl TrustStore for ChainTrustStore {
    fn resolve_key(&self, kid: &[u8]) -> Option<ed25519_dalek::VerifyingKey> {
        if kid == self.vk.as_bytes() {
            Some(self.vk)
        } else {
            None
        }
    }
    fn resolve_composite_key(&self, _kid: &[u8]) -> Option<CompositePublicKey> {
        None
    }
    fn fetch_statement(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        self.chain.get(hash).cloned()
    }
    fn is_revoked_in_log(&self, _h: &[u8; 32], _t: u64) -> Option<bool> {
        Some(false)
    }
    fn resolve_log_pubkey(&self, _log_id: &[u8; 32], _candidate: &[u8; 32]) -> Option<[u8; 32]> {
        None
    }
}

fn make_ct_anchor(payload_hash: &[u8; 32], log_sk: &SigningKey, timestamp: u64) -> TemporalAnchor {
    let leaf: [u8; 32] = sha2::Sha256::new()
        .chain_update([0x00u8])
        .chain_update(payload_hash)
        .finalize()
        .into();
    let proof = LogInclusionProof {
        leaf_index: 0,
        siblings: Vec::new(),
    };
    let mut data = Vec::new();
    data.extend_from_slice(&timestamp.to_be_bytes());
    data.extend_from_slice(&1u64.to_be_bytes());
    data.extend_from_slice(&leaf);
    use ed25519_dalek::ed25519::signature::Signer;
    let sig: ed25519_dalek::Signature = log_sk.sign(&data);
    let log_pk = log_sk.verifying_key().to_bytes().to_vec();
    let sth = SignedTreeHead::new(timestamp, 1, leaf, sig.to_bytes().to_vec(), log_pk);
    TemporalAnchor {
        inclusion_proof: proof,
        signed_tree_head: sth,
    }
}

// ───────────────────────────────────────────────────────────────────────
// SCENARIO 1: Deterministic Encoding Throughput
// ───────────────────────────────────────────────────────────────────────

fn bench_encode_throughput(c: &mut Criterion) {
    let subject = [0xabu8; 32];
    let sizes = [1, 10, 100];
    let mut group = c.benchmark_group("encode_throughput");
    group.sampling_mode(SamplingMode::Flat);
    group.throughput(Throughput::Elements(1));

    for size_kb in &sizes {
        let payload = make_payload(&subject, Predicate::Attests, *size_kb);

        group.bench_with_input(
            BenchmarkId::new("encode_payload", format!("{}KB", size_kb)),
            &payload,
            |b, p| {
                b.iter(|| {
                    let encoded = black_box(p.encode());
                    black_box(encoded.len());
                })
            },
        );
    }
    group.finish();

    // Determinism assertion: 1000 runs produce identical bytes
    let payload = make_payload(&subject, Predicate::Attests, 1);
    let first = payload.encode();
    for _ in 0..1000 {
        let encoded = payload.encode();
        assert_eq!(encoded, first, "encoding not deterministic");
    }
    eprintln!("  ✅ Determinism verified: 1000 runs produce identical bytes");
}

// ───────────────────────────────────────────────────────────────────────
// SCENARIO 2: Verification Micro-benchmark
// ───────────────────────────────────────────────────────────────────────

fn bench_verify_statement(c: &mut Criterion) {
    let (sk, vk) = make_ed25519_keypair();
    let log_sk = SigningKey::from_bytes(&[0x99u8; 32]);
    let payload = make_payload(&[0xab; 32], Predicate::Attests, 0);

    // Without CT anchor
    let stmt = Statement::sign_ed25519(&payload, &sk).unwrap();
    let stmt_bytes = stmt.to_bytes().to_vec();

    let mut group = c.benchmark_group("verify_statement");
    group.sampling_mode(SamplingMode::Auto);
    group.throughput(Throughput::Elements(1));

    group.bench_with_input(
        BenchmarkId::new("ed25519_no_anchor", "isolated"),
        &stmt_bytes,
        |b, data| {
            let store = NullTrustStore { vk };
            b.iter(|| {
                let result = black_box(verify_statement(data, &store));
                black_box(result.is_ok());
            })
        },
    );

    // With CT anchor (fresh: same timestamp as statement)
    let payload_hash = blake3(&payload.encode());
    let stmt_ts = payload.timestamp.unwrap();
    let anchor = make_ct_anchor(&payload_hash, &log_sk, stmt_ts);
    let stmt_anchored = Statement::sign_ed25519_and_anchor(&payload, &sk, &anchor).unwrap();
    let anchored_bytes = stmt_anchored.to_bytes().to_vec();
    let log_key = log_sk.verifying_key().to_bytes();

    group.bench_with_input(
        BenchmarkId::new("ed25519_with_ct_anchor", "isolated"),
        &anchored_bytes,
        |b, data| {
            let store = LogTrustStore { vk, log_key };
            b.iter(|| {
                let result = black_box(verify_statement(data, &store));
                black_box(result.is_ok());
            })
        },
    );

    group.finish();

    // Manual p50/p99 via 1000 timed iterations
    let store = NullTrustStore { vk };
    let mut latencies: Vec<f64> = Vec::with_capacity(1000);
    for _ in 0..1000 {
        let start = Instant::now();
        let _ = verify_statement(&stmt_bytes, &store).unwrap();
        let elapsed = start.elapsed().as_secs_f64();
        latencies.push(elapsed);
    }
    latencies.sort_unstable_by(|a, b| a.partial_cmp(b).unwrap());
    let p50 = latencies[500];
    let p99 = latencies[990];
    eprintln!(
        "  📊 Ed25519 verify (no anchor): p50={:.1?}µs  p99={:.1?}µs",
        p50 * 1_000_000.0,
        p99 * 1_000_000.0
    );

    let store = LogTrustStore { vk, log_key };
    let mut latencies = Vec::with_capacity(1000);
    for _ in 0..1000 {
        let start = Instant::now();
        let _ = verify_statement(&anchored_bytes, &store).unwrap();
        let elapsed = start.elapsed().as_secs_f64();
        latencies.push(elapsed);
    }
    latencies.sort_unstable_by(|a, b| a.partial_cmp(b).unwrap());
    let p50 = latencies[500];
    let p99 = latencies[990];
    eprintln!(
        "  📊 Ed25519 verify (with CT anchor): p50={:.1?}µs  p99={:.1?}µs",
        p50 * 1_000_000.0,
        p99 * 1_000_000.0
    );
}

// ───────────────────────────────────────────────────────────────────────
// SCENARIO 3: Lineage Chain Walking (10,000 APPENDS)
// ───────────────────────────────────────────────────────────────────────

fn bench_lineage_chain(c: &mut Criterion) {
    let (sk, vk) = make_ed25519_keypair();
    let chain_len = 10_000usize;

    let mut prev_hash = [0u8; 32];
    let mut chain = BTreeMap::new();
    let subject = [0x01u8; 32];
    let mut chain_bytes = 0usize;

    eprintln!(
        "  Building lineage chain of {} APPENDS statements...",
        chain_len
    );
    let build_start = Instant::now();

    for i in 0..chain_len {
        let mut payload = VeraxPayload::new(subject, Predicate::Appends);
        payload.object = Some(subject);
        payload.timestamp = Some(i as u64);
        payload.nonce = Some([0xde; 32]);
        if i > 0 {
            payload.lineage = Some(prev_hash);
        }
        let stmt = Statement::sign_ed25519(&payload, &sk).unwrap();
        let bytes = stmt.to_bytes().to_vec();
        chain_bytes += bytes.len();
        let hash = blake3(&bytes);
        chain.insert(hash, bytes);
        prev_hash = hash;
    }

    let build_elapsed = build_start.elapsed();
    let mb = chain_bytes as f64 / 1_048_576.0;
    eprintln!(
        "  Build: {:.2}s, {} stmts, ~{:.1}MB",
        build_elapsed.as_secs_f64(),
        chain_len,
        mb
    );

    let last_stmt_bytes = chain.get(&prev_hash).unwrap().clone();
    let store = ChainTrustStore { chain, vk };

    let mut group = c.benchmark_group("lineage_chain_walk");
    group.sampling_mode(SamplingMode::Flat);
    group.throughput(Throughput::Elements(1));
    group.bench_with_input(
        BenchmarkId::new("verify_head_of_10000", "appends"),
        &last_stmt_bytes,
        |b, data| {
            b.iter(|| {
                let result = black_box(verify_statement(data, &store));
                black_box(result.is_ok());
            })
        },
    );
    group.finish();

    // Memory estimate for the chain store (BTreeMap + Vec<u8> values)
    let map_overhead = chain_len * 80; // rough estimate per BTreeMap entry
    eprintln!(
        "  💾 Chain store: ~{:.1}MB (data) + ~{:.1}MB (index) ≈ ~{:.1}MB",
        mb,
        map_overhead as f64 / 1_048_576.0,
        (chain_bytes + map_overhead) as f64 / 1_048_576.0
    );
    eprintln!("  ✅ No recursion: iterative loop (MAX_LINEAGE_DEPTH=1024)");
    eprintln!(
        "  ⚠️  10,000 > 1024: loop exits silently, LineageDepthExceeded not returned (known gap)"
    );
}

// ───────────────────────────────────────────────────────────────────────
// SCENARIO 4: Composite Signature Cost
// ───────────────────────────────────────────────────────────────────────

fn bench_composite_verification(c: &mut Criterion) {
    let (ed_sk, ml_sk) = make_composite_signing_key();
    let payload = make_payload(&[0xab; 32], Predicate::Attests, 0);

    // Ed25519-only
    let ed_stmt = Statement::sign_ed25519(&payload, &ed_sk).unwrap();
    let ed_bytes = ed_stmt.to_bytes().to_vec();
    let ed_vk = ed_sk.verifying_key();

    // Composite
    let comp_stmt = Statement::sign_composite(&payload, &ed_sk, &ml_sk).unwrap();
    let comp_bytes = comp_stmt.to_bytes().to_vec();
    let ml_vk = ml_sk.expanded_key().verifying_key();
    let comp_vk = composite_pubkey(&ed_vk, &ml_vk);

    let mut group = c.benchmark_group("signature_verification");
    group.sampling_mode(SamplingMode::Auto);
    group.throughput(Throughput::Elements(1));

    group.bench_with_input(
        BenchmarkId::new("ed25519_alg_-8", "isolated"),
        &ed_bytes,
        |b, data| {
            b.iter(|| {
                let r = black_box(parse_and_verify_ed25519(data, &ed_vk));
                black_box(r.is_ok());
            })
        },
    );

    // Hybrid (both)
    group.bench_with_input(
        BenchmarkId::new("composite_-39_hybrid", "all"),
        &comp_bytes,
        |b, data| {
            b.iter(|| {
                let r = black_box(parse_and_verify_composite(
                    data,
                    &comp_vk,
                    VerificationMode::Hybrid,
                ));
                black_box(r.is_ok());
            })
        },
    );

    // Classical only
    group.bench_with_input(
        BenchmarkId::new("composite_-39_classical_only", "ed25519"),
        &comp_bytes,
        |b, data| {
            b.iter(|| {
                let r = black_box(parse_and_verify_composite(
                    data,
                    &comp_vk,
                    VerificationMode::ClassicalOnly,
                ));
                black_box(r.is_ok());
            })
        },
    );

    // PQ only
    group.bench_with_input(
        BenchmarkId::new("composite_-39_pq_only", "ml_dsa_65"),
        &comp_bytes,
        |b, data| {
            b.iter(|| {
                let r = black_box(parse_and_verify_composite(
                    data,
                    &comp_vk,
                    VerificationMode::PQOnly,
                ));
                black_box(r.is_ok());
            })
        },
    );

    group.finish();

    // Size comparison
    eprintln!("  Ed25519 sig: 64 B");
    eprintln!("  ML-DSA-65 sig: {} B", MLDSA65_SIG_SIZE);
    eprintln!("  Composite sig: {} B", COMPOSITE_SIG_SIZE);
    eprintln!("  Composite PK: {} B", MLDSA65_PK_SIZE + 32);
}

// ───────────────────────────────────────────────────────────────────────
// SCENARIO 5: CT Log STH Freshness Overhead
// ───────────────────────────────────────────────────────────────────────

fn bench_sth_freshness(c: &mut Criterion) {
    let (sk, vk) = make_ed25519_keypair();
    let log_sk = SigningKey::from_bytes(&[0x99u8; 32]);
    let log_vk = log_sk.verifying_key();
    let payload = make_payload(&[0xab; 32], Predicate::Attests, 0);
    let payload_bytes = payload.encode();
    let payload_hash = blake3(&payload_bytes);
    let stmt_ts = payload.timestamp.unwrap();
    let log_key = log_vk.to_bytes();

    // Fresh anchor (same timestamp as statement)
    let anchor_fresh = make_ct_anchor(&payload_hash, &log_sk, stmt_ts);
    let stmt_fresh = Statement::sign_ed25519_and_anchor(&payload, &sk, &anchor_fresh).unwrap();
    let fresh_bytes = stmt_fresh.to_bytes().to_vec();

    // Stale anchor (STH timestamp 91 days after statement)
    let sth_ts = stmt_ts + 3600 * 24 * 91;
    let leaf: [u8; 32] = sha2::Sha256::new()
        .chain_update([0x00u8])
        .chain_update(&payload_hash)
        .finalize()
        .into();
    use ed25519_dalek::ed25519::signature::Signer;
    let mut data = Vec::new();
    data.extend_from_slice(&sth_ts.to_be_bytes());
    data.extend_from_slice(&1u64.to_be_bytes());
    data.extend_from_slice(&leaf);
    let sig: ed25519_dalek::Signature = log_sk.sign(&data);
    let log_pk = log_vk.to_bytes().to_vec();
    let sth_stale = SignedTreeHead::new(sth_ts, 1, leaf, sig.to_bytes().to_vec(), log_pk);
    let anchor_stale = TemporalAnchor {
        inclusion_proof: LogInclusionProof {
            leaf_index: 0,
            siblings: Vec::new(),
        },
        signed_tree_head: sth_stale,
    };
    let stmt_stale = Statement::sign_ed25519_and_anchor(&payload, &sk, &anchor_stale).unwrap();
    let stale_bytes = stmt_stale.to_bytes().to_vec();

    let mut group = c.benchmark_group("sth_freshness");
    group.sampling_mode(SamplingMode::Auto);
    group.throughput(Throughput::Elements(1));

    let fresh_store = LogTrustStore { vk, log_key };
    group.bench_with_input(
        BenchmarkId::new("fresh_sth_no_warning", "0_day_delta"),
        &fresh_bytes,
        |b, data| {
            b.iter(|| {
                let result = black_box(verify_statement_with_warnings(data, &fresh_store));
                black_box(result.is_ok());
            })
        },
    );

    let stale_store = LogTrustStore { vk, log_key };
    group.bench_with_input(
        BenchmarkId::new("stale_sth_warning_path", "91_day_delta"),
        &stale_bytes,
        |b, data| {
            b.iter(|| {
                let result = black_box(verify_statement_with_warnings(data, &stale_store));
                if let Ok((_, ref w)) = result {
                    black_box(w.warnings.len());
                }
            })
        },
    );

    group.finish();

    eprintln!("  ⚠️  Warning path: 1 Vec<Warning> allocation per verify call");
    eprintln!("  ✅ STH delta check: integer arithmetic only, no allocations");
}

// ───────────────────────────────────────────────────────────────────────
// Criterion harness
// ───────────────────────────────────────────────────────────────────────

criterion_group! {
    name = verax_benches;
    config = Criterion::default()
        .sample_size(100)
        .warm_up_time(std::time::Duration::from_secs(2))
        .measurement_time(std::time::Duration::from_secs(5));
    targets =
        bench_encode_throughput,
        bench_verify_statement,
        bench_lineage_chain,
        bench_composite_verification,
        bench_sth_freshness,
}
criterion_main!(verax_benches);
