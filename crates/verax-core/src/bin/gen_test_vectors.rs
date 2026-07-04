use ml_dsa::{KeyExport, Keypair};
use verax_core::{Predicate, Statement, VeraxPayload, VeraxPayloadValue, cose::sign_ed25519};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn payload_to_json(payload: &VeraxPayload) -> String {
    let mut fields = Vec::new();
    fields.push(format!(r#""subject_hex": "{}""#, hex(&payload.subject)));
    fields.push(format!(r#""predicate": "{}""#, payload.predicate.name()));
    if let Some(obj) = &payload.object {
        fields.push(format!(r#""object_hex": "{}""#, hex(obj)));
    }
    if let Some(ts) = payload.timestamp {
        fields.push(format!(r#""timestamp": {ts}"#));
    }
    if let Some(lin) = &payload.lineage {
        fields.push(format!(r#""lineage_hex": "{}""#, hex(lin)));
    }
    if let Some(nonce) = &payload.nonce {
        fields.push(format!(r#""nonce_hex": "{}""#, hex(nonce)));
    }
    if let Some(exts) = &payload.extensions {
        let mut ext_parts = Vec::new();
        for (k, v) in exts {
            let vs = match v {
                VeraxPayloadValue::Uint(u) => format!(r#"{{"type": "uint", "value": {u}}}"#),
                VeraxPayloadValue::Bstr(b) => {
                    format!(r#"{{"type": "bstr", "hex": "{}"}}"#, hex(b))
                }
                VeraxPayloadValue::Map(m) => {
                    let inner: Vec<String> = m
                        .iter()
                        .map(|(ik, iv)| format!(r#""{ik}": "{:?}""#, iv))
                        .collect();
                    format!(r#"{{"type": "map", "entries": [{}]}}"#, inner.join(","))
                }
                VeraxPayloadValue::Array(_) => r#"{"type": "array"}"#.to_string(),
            };
            ext_parts.push(format!(r#""{k}": {vs}"#));
        }
        fields.push(format!(r#""extensions": {{{}}}"#, ext_parts.join(",")));
    }
    format!("{{{}}}", fields.join(","))
}

#[allow(clippy::too_many_arguments)]
fn make_vector(
    name: &str,
    predicate: Predicate,
    subject: [u8; 32],
    object: Option<[u8; 32]>,
    timestamp: Option<u64>,
    lineage: Option<[u8; 32]>,
    nonce: Option<[u8; 32]>,
    extensions: Option<Vec<(u64, VeraxPayloadValue)>>,
    sk: &ed25519_dalek::SigningKey,
) -> String {
    let mut payload = VeraxPayload::new(subject, predicate);
    payload.object = object;
    payload.timestamp = timestamp;
    payload.lineage = lineage;
    payload.nonce = nonce;
    payload.extensions = extensions;

    let payload_bytes = payload.encode();
    let payload_hex = hex(&payload_bytes);

    let cose_result = sign_ed25519(&payload_bytes, sk);
    let (cose_hex, is_valid) = match cose_result {
        Ok(cose) => (hex(&cose), true),
        Err(_) => (String::new(), false),
    };

    let payload_json = payload_to_json(&payload);

    format!(
        r#"  {{
    "name": "{name}",
    "is_valid": {is_valid},
    "payload_cbor_hex": "{payload_hex}",
    "cose_hex": "{cose_hex}",
    "payload": {payload_json}
  }}"#
    )
}

#[allow(clippy::too_many_arguments)]
fn make_composite_vector(
    name: &str,
    predicate: Predicate,
    subject: [u8; 32],
    object: Option<[u8; 32]>,
    timestamp: Option<u64>,
    lineage: Option<[u8; 32]>,
    nonce: Option<[u8; 32]>,
    extensions: Option<Vec<(u64, VeraxPayloadValue)>>,
    ed_sk: &ed25519_dalek::SigningKey,
    ml_seed: &ml_dsa::Seed,
) -> String {
    let mut payload = VeraxPayload::new(subject, predicate);
    payload.object = object;
    payload.timestamp = timestamp;
    payload.lineage = lineage;
    payload.nonce = nonce;
    payload.extensions = extensions;

    let payload_bytes = payload.encode();
    let payload_hex = hex(&payload_bytes);

    let ml_sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(ml_seed);
    let ml_vk = ml_sk.verifying_key();

    let stmt = Statement::sign_composite(&payload, ed_sk, &ml_sk).unwrap();
    let stmt_bytes = stmt.to_bytes();
    let stmt_hex = hex(stmt_bytes);

    let comp_pk = verax_core::composite_pubkey(&ed_sk.verifying_key(), &ml_vk);
    let mut pk_bytes_vec = Vec::with_capacity(32 + ml_vk.to_bytes().len());
    pk_bytes_vec.extend_from_slice(&comp_pk.ed25519);
    pk_bytes_vec.extend_from_slice(&comp_pk.mldsa65);
    let pk_hex = hex(&pk_bytes_vec);

    let payload_json = payload_to_json(&payload);

    format!(
        r#"  {{
    "name": "{name}",
    "is_valid": true,
    "signature_alg": "composite(-8, -39)",
    "payload_cbor_hex": "{payload_hex}",
    "composite_cose_hex": "{stmt_hex}",
    "composite_pk_hex": "{pk_hex}",
    "payload": {payload_json}
  }}"#
    )
}

#[allow(clippy::vec_init_then_push)]
fn main() {
    let seed = [0x42u8; 32];
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();
    let kid = hex(&vk.to_bytes());

    let subj01 = [0x01u8; 32];
    let subj02 = [0x02u8; 32];
    let subjab = [0xabu8; 32];

    let mut vectors = Vec::new();

    // 1. Minimal ATTESTS
    vectors.push(make_vector(
        "attests_minimal",
        Predicate::Attests,
        subjab,
        None,
        None,
        None,
        None,
        None,
        &sk,
    ));

    // 2. ATTESTS with timestamp
    vectors.push(make_vector(
        "attests_with_timestamp",
        Predicate::Attests,
        subjab,
        None,
        Some(1700000000),
        None,
        None,
        None,
        &sk,
    ));

    // 3. AUTHORS
    vectors.push(make_vector(
        "authors_minimal",
        Predicate::Authors,
        subj01,
        None,
        None,
        None,
        None,
        None,
        &sk,
    ));

    // 4. DERIVED_FROM (subject, object, timestamp)
    vectors.push(make_vector(
        "derived_from_full",
        Predicate::DerivedFrom,
        subj02,
        Some(subj01),
        Some(1700000001),
        None,
        None,
        None,
        &sk,
    ));

    // 5. SUPERSEDES (subject, object, timestamp, lineage)
    vectors.push(make_vector(
        "supersedes_full",
        Predicate::Supersedes,
        subjab,
        Some(subj01),
        Some(1700000002),
        Some(subj02),
        None,
        None,
        &sk,
    ));

    // 6. REVOKES (subject = object)
    vectors.push(make_vector(
        "revokes_same_issuer",
        Predicate::Revokes,
        subj01,
        Some(subj01),
        Some(1700000003),
        None,
        None,
        None,
        &sk,
    ));

    // 7. APPENDS with matching subject (lineage points to prev)
    vectors.push(make_vector(
        "appends_chunk",
        Predicate::Appends,
        subj02,
        Some(subj01),
        Some(1700000004),
        Some(subj01),
        None,
        None,
        &sk,
    ));

    // 8. COMPLIES_WITH with extensions
    vectors.push(make_vector(
        "complies_with_extensions",
        Predicate::CompliesWith,
        subj01,
        Some(subj02),
        Some(1700000005),
        None,
        None,
        Some(vec![
            (100, VeraxPayloadValue::Uint(42)),
            (101, VeraxPayloadValue::Bstr(vec![1, 2, 3])),
        ]),
        &sk,
    ));

    // 9. With nonce
    vectors.push(make_vector(
        "attests_with_nonce",
        Predicate::Attests,
        subjab,
        None,
        Some(1700000006),
        None,
        Some([0xde; 32]),
        None,
        &sk,
    ));

    // 10. ENDORSES
    vectors.push(make_vector(
        "endorses_minimal",
        Predicate::Endorses,
        subj01,
        Some(subj02),
        None,
        None,
        None,
        None,
        &sk,
    ));

    // 11. Full with everything
    vectors.push(make_vector(
        "full_all_fields",
        Predicate::DerivedFrom,
        subj01,
        Some(subj02),
        Some(1700000007),
        Some(subjab),
        Some([0xca; 32]),
        Some(vec![
            (200, VeraxPayloadValue::Uint(99)),
            (201, VeraxPayloadValue::Bstr(b"hello".to_vec())),
        ]),
        &sk,
    ));

    // 12. Long timestamp (uint32 boundary)
    vectors.push(make_vector(
        "attests_large_timestamp",
        Predicate::Attests,
        subjab,
        None,
        Some(4_000_000_000),
        None,
        None,
        None,
        &sk,
    ));

    // 13. Zero timestamp
    vectors.push(make_vector(
        "attests_zero_timestamp",
        Predicate::Attests,
        subjab,
        None,
        Some(0),
        None,
        None,
        None,
        &sk,
    ));

    // ─── Composite-signed vectors ────────────────────────────────────────

    let ml_seed_bytes = {
        let mut b = [0u8; 32];
        for (i, byte) in b.iter_mut().enumerate() {
            *byte = i as u8;
        }
        b
    };
    let ml_seed = ml_dsa::Seed::try_from(&ml_seed_bytes[..]).unwrap();

    // 14. Composite: minimal ATTESTS
    vectors.push(make_composite_vector(
        "composite_attests_minimal",
        Predicate::Attests,
        subjab,
        None,
        None,
        None,
        None,
        None,
        &sk,
        &ml_seed,
    ));

    // 15. Composite: DERIVED_FROM with timestamp and object
    vectors.push(make_composite_vector(
        "composite_derived_from_full",
        Predicate::DerivedFrom,
        subj02,
        Some(subj01),
        Some(1700000001),
        None,
        None,
        None,
        &sk,
        &ml_seed,
    ));

    // 16. Composite: with extensions
    vectors.push(make_composite_vector(
        "composite_complies_with_extensions",
        Predicate::CompliesWith,
        subj01,
        None,
        Some(1700000005),
        None,
        None,
        Some(vec![
            (100, VeraxPayloadValue::Uint(42)),
            (101, VeraxPayloadValue::Bstr(vec![1, 2, 3])),
        ]),
        &sk,
        &ml_seed,
    ));

    // Output JSON
    println!("{{");
    println!(r#"  "version": "1.0.0","#);
    println!(r#"  "description": "Verax Protocol canonical test vectors","#);
    println!(r#"  "signing_key_seed_hex": "{}","#, hex(&seed));
    println!(r#"  "signing_key_pubkey_hex": "{kid}","#);
    println!(r#"  "ml_dsa_seed_hex": "{}","#, hex(&ml_seed_bytes));
    let ml_vk_hex = {
        let ml_sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&ml_seed);
        hex(&ml_sk.verifying_key().to_bytes())
    };
    println!(r#"  "ml_dsa_pubkey_hex": "{ml_vk_hex}","#);
    println!(r#"  "vectors": ["#);
    for (i, vec) in vectors.iter().enumerate() {
        if i > 0 {
            println!(",");
        }
        print!("{vec}");
    }
    println!();
    println!("  ]");
    println!("}}");
}
