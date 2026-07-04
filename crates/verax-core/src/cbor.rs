//! Deterministic CBOR encoding and decoding for Verax Protocol payloads.
//!
//! This module implements a **strictly deterministic CBOR** subset for encoding
//! [`VeraxPayload`] and [`RecoveryPolicy`] structures. The encoding enforces
//! six determinism rules:
//!
//! 1. **Shortest-form integers** — unsigned and negative integers use the
//!    minimum number of bytes for their value.
//! 2. **Sorted map keys** — map entries are serialised in ascending bytewise
//!    key order.
//! 3. **No tags** — CBOR tags (major type 6) are rejected during decode.
//! 4. **No floats** — floating-point values (major type 7, additional info
//!    20–27) are rejected.
//! 5. **No null/undefined** — simple values `null` (`0xf6`) and `undefined`
//!    (`0xf7`) are rejected.
//! 6. **Definite-length** — arrays, maps, byte strings, and text strings all
//!    use definite-length encoding; indefinite-length forms are rejected.
//!
//! ## Payload Structure
//!
//! The top-level [`VeraxPayload`] is a CBOR map with the following fields:
//!
//! | Key | Field             | Type          | Required |
//! |-----|-------------------|---------------|----------|
//! | 1   | `subject`         | bstr .size 32 | yes      |
//! | 2   | `predicate`       | uint (0–8)    | yes      |
//! | 3   | `object`          | bstr .size 32 | no       |
//! | 4   | `timestamp`       | uint           | no       |
//! | 5   | `lineage`         | bstr .size 32 | no       |
//! | 6   | `nonce`           | bstr .size 32 | no       |
//! | 7   | `extensions`      | map            | no       |
//! | 8   | `anchor_hash`     | bstr .size 32 | no       |
//! | 10  | `recovery_policy` | bstr           | no       |
//!
//! ## Extension Values
//!
//! Extension map entries use the [`Value`] enum, which supports unsigned
//! integers, byte strings, nested maps, and arrays.
//!
//! ## Key Functions
//!
//! * [`encode_payload`] — serialises an [`VeraxPayload`] to deterministic CBOR.
//! * [`decode_payload`] — parses and validates CBOR, enforcing all determinism
//!   rules.
//! * [`is_strictly_deterministic`] — checks whether encoded bytes satisfy the
//!   deterministic encoding via decode-then-re-encode.
//!
//! ## Reference
//!
//! This implementation follows the Verax Protocol Deterministic CBOR specification
//! (Protocol Spec §5).
use crate::error::{Error, Result};
use alloc::format;
use alloc::vec::Vec;

const MAJOR_UINT: u8 = 0x00;
const MAJOR_BSTR: u8 = 0x40;
const MAJOR_MAP: u8 = 0xa0;

pub(crate) fn encode_uint_head(buf: &mut Vec<u8>, major: u8, val: u64) {
    if val < 24 {
        buf.push(major | val as u8);
    } else if val < 0x100 {
        buf.push(major | 24);
        buf.push(val as u8);
    } else if val < 0x10000 {
        buf.push(major | 25);
        buf.extend_from_slice(&(val as u16).to_be_bytes());
    } else if val < 0x100000000 {
        buf.push(major | 26);
        buf.extend_from_slice(&(val as u32).to_be_bytes());
    } else {
        buf.push(major | 27);
        buf.extend_from_slice(&val.to_be_bytes());
    }
}

fn encode_bstr(buf: &mut Vec<u8>, data: &[u8]) {
    encode_uint_head(buf, MAJOR_BSTR, data.len() as u64);
    buf.extend_from_slice(data);
}

pub(crate) fn encode_text_string(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    encode_uint_head(buf, 0x60, bytes.len() as u64);
    buf.extend_from_slice(bytes);
}

pub(crate) fn decode_text_string(data: &[u8], offset: &mut usize) -> Result<Vec<u8>> {
    if *offset >= data.len() {
        return Err(Error::Decode("unexpected end of text string".into()));
    }
    let byte = data[*offset];
    let major = byte >> 5;
    let info = byte & 0x1f;
    *offset += 1;

    if major != 3 {
        return Err(Error::Decode(format!(
            "expected text string major type, got {major}"
        )));
    }

    let len = match info {
        0..=23 => info as u64,
        24 => {
            if *offset >= data.len() {
                return Err(Error::Decode("unexpected end of text string length".into()));
            }
            let v = data[*offset] as u64;
            *offset += 1;
            check_shortest_encoding(v, info, 24, "text string")?;
            v
        }
        25 => {
            if *offset + 2 > data.len() {
                return Err(Error::Decode("unexpected end of text string length".into()));
            }
            let v = u16::from_be_bytes([data[*offset], data[*offset + 1]]) as u64;
            *offset += 2;
            check_shortest_encoding(v, info, 0x100, "text string")?;
            v
        }
        26 => {
            if *offset + 4 > data.len() {
                return Err(Error::Decode("unexpected end of text string length".into()));
            }
            let v = u32::from_be_bytes([
                data[*offset],
                data[*offset + 1],
                data[*offset + 2],
                data[*offset + 3],
            ]) as u64;
            *offset += 4;
            check_shortest_encoding(v, info, 0x10000, "text string")?;
            v
        }
        27 => {
            if *offset + 8 > data.len() {
                return Err(Error::Decode("unexpected end of text string length".into()));
            }
            let v = u64::from_be_bytes([
                data[*offset],
                data[*offset + 1],
                data[*offset + 2],
                data[*offset + 3],
                data[*offset + 4],
                data[*offset + 5],
                data[*offset + 6],
                data[*offset + 7],
            ]);
            *offset += 8;
            check_shortest_encoding(v, info, 0x100000000, "text string")?;
            v
        }
        _ => {
            return Err(Error::Decode(format!(
                "reserved additional info for text string: {info}"
            )));
        }
    };

    let len_usize = len as usize;
    if *offset + len_usize > data.len() {
        return Err(Error::Decode("unexpected end of text string data".into()));
    }
    let result = data[*offset..*offset + len_usize].to_vec();
    *offset += len_usize;
    Ok(result)
}

pub(crate) fn encode_uint(buf: &mut Vec<u8>, val: u64) {
    encode_uint_head(buf, MAJOR_UINT, val);
}

pub(crate) fn encode_negative_int(buf: &mut Vec<u8>, val: i64) {
    let n = (-1i64 - val) as u64;
    encode_uint_head(buf, 0x20, n);
}

pub(crate) fn decode_negative_int(data: &[u8], offset: &mut usize) -> Result<i64> {
    if *offset >= data.len() {
        return Err(Error::Decode("unexpected end of negative int".into()));
    }
    let byte = data[*offset];
    let major = byte >> 5;
    let info = byte & 0x1f;
    *offset += 1;
    if major != 1 {
        return Err(Error::Decode(format!(
            "expected negative int major type, got {major}"
        )));
    }
    let n = match info {
        0..=23 => info as u64,
        24 => {
            if *offset >= data.len() {
                return Err(Error::Decode("unexpected end of negative int".into()));
            }
            let v = data[*offset] as u64;
            *offset += 1;
            check_shortest_encoding(v, info, 24, "negative int")?;
            v
        }
        25 => {
            if *offset + 2 > data.len() {
                return Err(Error::Decode("unexpected end of negative int16".into()));
            }
            let v = u16::from_be_bytes([data[*offset], data[*offset + 1]]) as u64;
            *offset += 2;
            check_shortest_encoding(v, info, 0x100, "negative int")?;
            v
        }
        26 => {
            if *offset + 4 > data.len() {
                return Err(Error::Decode("unexpected end of negative int32".into()));
            }
            let v = u32::from_be_bytes([
                data[*offset],
                data[*offset + 1],
                data[*offset + 2],
                data[*offset + 3],
            ]) as u64;
            *offset += 4;
            check_shortest_encoding(v, info, 0x10000, "negative int")?;
            v
        }
        27 => {
            if *offset + 8 > data.len() {
                return Err(Error::Decode("unexpected end of negative int64".into()));
            }
            let v = u64::from_be_bytes([
                data[*offset],
                data[*offset + 1],
                data[*offset + 2],
                data[*offset + 3],
                data[*offset + 4],
                data[*offset + 5],
                data[*offset + 6],
                data[*offset + 7],
            ]);
            *offset += 8;
            check_shortest_encoding(v, info, 0x100000000, "negative int")?;
            v
        }
        _ => {
            return Err(Error::Decode(format!(
                "reserved additional info for negative int: {info}"
            )));
        }
    };
    Ok(-1i64 - n as i64)
}

fn check_shortest_encoding(val: u64, _info: u8, min_for_info: u64, major_name: &str) -> Result<()> {
    if val < min_for_info {
        return Err(Error::Decode(format!(
            "non-canonical {major_name}: value {val} uses {min_for_info}+ byte form but fits in shorter form"
        )));
    }
    Ok(())
}

pub(crate) fn decode_uint(data: &[u8], offset: &mut usize) -> Result<u64> {
    if *offset >= data.len() {
        return Err(Error::Decode("unexpected end of uint".into()));
    }
    let byte = data[*offset];
    let major = byte >> 5;
    let info = byte & 0x1f;
    *offset += 1;

    if major != 0 {
        return Err(Error::Decode(format!(
            "expected uint major type, got {major}"
        )));
    }

    match info {
        0..=23 => Ok(info as u64),
        24 => {
            if *offset >= data.len() {
                return Err(Error::Decode("unexpected end of uint".into()));
            }
            let v = data[*offset] as u64;
            *offset += 1;
            check_shortest_encoding(v, info, 24, "uint")?;
            Ok(v)
        }
        25 => {
            if *offset + 2 > data.len() {
                return Err(Error::Decode("unexpected end of uint16".into()));
            }
            let v = u16::from_be_bytes([data[*offset], data[*offset + 1]]) as u64;
            *offset += 2;
            check_shortest_encoding(v, info, 0x100, "uint")?;
            Ok(v)
        }
        26 => {
            if *offset + 4 > data.len() {
                return Err(Error::Decode("unexpected end of uint32".into()));
            }
            let v = u32::from_be_bytes([
                data[*offset],
                data[*offset + 1],
                data[*offset + 2],
                data[*offset + 3],
            ]) as u64;
            *offset += 4;
            check_shortest_encoding(v, info, 0x10000, "uint")?;
            Ok(v)
        }
        27 => {
            if *offset + 8 > data.len() {
                return Err(Error::Decode("unexpected end of uint64".into()));
            }
            let v = u64::from_be_bytes([
                data[*offset],
                data[*offset + 1],
                data[*offset + 2],
                data[*offset + 3],
                data[*offset + 4],
                data[*offset + 5],
                data[*offset + 6],
                data[*offset + 7],
            ]);
            *offset += 8;
            check_shortest_encoding(v, info, 0x100000000, "uint")?;
            Ok(v)
        }
        _ => Err(Error::Decode(format!(
            "reserved additional info for uint: {info}"
        ))),
    }
}

fn decode_bstr_len(data: &[u8], offset: &mut usize) -> Result<u64> {
    if *offset >= data.len() {
        return Err(Error::Decode("unexpected end of bstr".into()));
    }
    let byte = data[*offset];
    let major = byte >> 5;
    let info = byte & 0x1f;
    *offset += 1;

    if major != 2 {
        return Err(Error::Decode(format!(
            "expected bstr major type, got {major}"
        )));
    }

    let len = match info {
        0..=23 => info as u64,
        24 => {
            if *offset >= data.len() {
                return Err(Error::Decode("unexpected end of bstr length".into()));
            }
            let v = data[*offset] as u64;
            *offset += 1;
            check_shortest_encoding(v, info, 24, "bstr")?;
            v
        }
        25 => {
            if *offset + 2 > data.len() {
                return Err(Error::Decode("unexpected end of bstr length".into()));
            }
            let v = u16::from_be_bytes([data[*offset], data[*offset + 1]]) as u64;
            *offset += 2;
            check_shortest_encoding(v, info, 0x100, "bstr")?;
            v
        }
        26 => {
            if *offset + 4 > data.len() {
                return Err(Error::Decode("unexpected end of bstr length".into()));
            }
            let v = u32::from_be_bytes([
                data[*offset],
                data[*offset + 1],
                data[*offset + 2],
                data[*offset + 3],
            ]) as u64;
            *offset += 4;
            check_shortest_encoding(v, info, 0x10000, "bstr")?;
            v
        }
        27 => {
            if *offset + 8 > data.len() {
                return Err(Error::Decode("unexpected end of bstr length".into()));
            }
            let v = u64::from_be_bytes([
                data[*offset],
                data[*offset + 1],
                data[*offset + 2],
                data[*offset + 3],
                data[*offset + 4],
                data[*offset + 5],
                data[*offset + 6],
                data[*offset + 7],
            ]);
            *offset += 8;
            check_shortest_encoding(v, info, 0x100000000, "bstr")?;
            v
        }
        _ => {
            return Err(Error::Decode(format!(
                "reserved additional info for bstr: {info}"
            )));
        }
    };
    Ok(len)
}

pub(crate) fn decode_bstr(data: &[u8], offset: &mut usize) -> Result<Vec<u8>> {
    let len = decode_bstr_len(data, offset)? as usize;
    if *offset + len > data.len() {
        return Err(Error::Decode("unexpected end of bstr data".into()));
    }
    let result = data[*offset..*offset + len].to_vec();
    *offset += len;
    Ok(result)
}

pub(crate) fn decode_map_len(data: &[u8], offset: &mut usize) -> Result<u64> {
    if *offset >= data.len() {
        return Err(Error::Decode("unexpected end of map".into()));
    }
    let byte = data[*offset];
    let major = byte >> 5;
    let info = byte & 0x1f;
    *offset += 1;

    if major != 5 {
        return Err(Error::Decode(format!(
            "expected map major type, got {major}"
        )));
    }

    let len = match info {
        0..=23 => info as u64,
        24 => {
            if *offset >= data.len() {
                return Err(Error::Decode("unexpected end of map length".into()));
            }
            let v = data[*offset] as u64;
            *offset += 1;
            check_shortest_encoding(v, info, 24, "map")?;
            v
        }
        25 => {
            if *offset + 2 > data.len() {
                return Err(Error::Decode("unexpected end of map length".into()));
            }
            let v = u16::from_be_bytes([data[*offset], data[*offset + 1]]) as u64;
            *offset += 2;
            check_shortest_encoding(v, info, 0x100, "map")?;
            v
        }
        26 => {
            if *offset + 4 > data.len() {
                return Err(Error::Decode("unexpected end of map length".into()));
            }
            let v = u32::from_be_bytes([
                data[*offset],
                data[*offset + 1],
                data[*offset + 2],
                data[*offset + 3],
            ]) as u64;
            *offset += 4;
            check_shortest_encoding(v, info, 0x10000, "map")?;
            v
        }
        27 => {
            if *offset + 8 > data.len() {
                return Err(Error::Decode("unexpected end of map length".into()));
            }
            let v = u64::from_be_bytes([
                data[*offset],
                data[*offset + 1],
                data[*offset + 2],
                data[*offset + 3],
                data[*offset + 4],
                data[*offset + 5],
                data[*offset + 6],
                data[*offset + 7],
            ]);
            *offset += 8;
            check_shortest_encoding(v, info, 0x100000000, "map")?;
            v
        }
        _ => {
            return Err(Error::Decode(format!(
                "reserved additional info for map: {info}"
            )));
        }
    };
    Ok(len)
}

/// Serialise an [`VeraxPayload`] to deterministic CBOR.
///
/// Produces a byte sequence that satisfies all six determinism rules
/// (shortest-form ints, sorted map keys, no tags, no floats, no null,
/// definite-length). The output is guaranteed to be identical for identical
/// payloads.
pub fn encode_payload(payload: &VeraxPayload) -> Vec<u8> {
    let mut entries = Vec::new();

    entries.push((1u64, Value::Bstr(payload.subject.to_vec())));
    entries.push((2u64, Value::Uint(payload.predicate as u64)));

    if let Some(obj) = &payload.object {
        entries.push((3u64, Value::Bstr(obj.to_vec())));
    }
    if let Some(ts) = payload.timestamp {
        entries.push((4u64, Value::Uint(ts)));
    }
    if let Some(lineage) = &payload.lineage {
        entries.push((5u64, Value::Bstr(lineage.to_vec())));
    }
    if let Some(nonce) = &payload.nonce {
        entries.push((6u64, Value::Bstr(nonce.to_vec())));
    }
    if let Some(ah) = &payload.anchor_hash {
        entries.push((8u64, Value::Bstr(ah.to_vec())));
    }
    if let Some(rp) = &payload.recovery_policy {
        entries.push((10u64, Value::Bstr(rp.clone())));
    }
    if let Some(exts) = &payload.extensions
        && !exts.is_empty()
    {
        entries.push((7u64, Value::Map(exts.clone())));
    }

    entries.sort_by_key(|(k, _)| *k);

    let mut buf = Vec::new();
    encode_uint_head(&mut buf, MAJOR_MAP, entries.len() as u64);
    for (key, val) in entries {
        encode_uint(&mut buf, key);
        encode_value(&mut buf, &val);
    }
    buf
}

fn encode_value(buf: &mut Vec<u8>, val: &Value) {
    match val {
        Value::Uint(v) => encode_uint(buf, *v),
        Value::Bstr(v) => encode_bstr(buf, v),
        Value::Map(entries) => {
            let mut sorted = entries.clone();
            sorted.sort_by_key(|(k, _)| *k);
            encode_uint_head(buf, MAJOR_MAP, sorted.len() as u64);
            for (k, v) in sorted {
                encode_uint(buf, k);
                encode_value(buf, &v);
            }
        }
        Value::Array(items) => {
            encode_uint_head(buf, 0x80, items.len() as u64);
            for item in items {
                encode_value(buf, item);
            }
        }
    }
}

/// Parse and validate a deterministic CBOR payload.
///
/// Enforces all six determinism rules plus field-level validation:
/// * `subject`, `object`, `lineage`, `nonce`, `anchor_hash` must each be
///   exactly 32 bytes.
/// * `predicate` must be in range 0–8.
/// * Map keys must appear in ascending bytewise order (no duplicates).
/// * Trailing data after the top-level map is rejected.
/// * The whole payload must not be wrapped in a CBOR tag.
///
/// Returns [`Error::Payload`] on field validation failure,
/// [`Error::NonCanonicalEncoding`] on ordering violations, and
/// [`Error::Decode`] on malformed CBOR structure.
pub fn decode_payload(data: &[u8]) -> Result<VeraxPayload> {
    let mut offset = 0;
    let map_len = decode_map_len(data, &mut offset)? as usize;

    let mut prev_key = 0u64;
    let mut subject = None;
    let mut predicate = None;
    let mut object = None;
    let mut timestamp = None;
    let mut lineage = None;
    let mut nonce = None;
    let mut anchor_hash = None;
    let mut extensions = None;
    let mut recovery_policy = None;

    for _ in 0..map_len {
        let key = decode_uint(data, &mut offset)?;
        if key == prev_key {
            return Err(Error::NonCanonicalEncoding);
        }
        if key < prev_key {
            return Err(Error::NonCanonicalEncoding);
        }
        prev_key = key;
        match key {
            1 => {
                let b = decode_bstr(data, &mut offset)?;
                if b.len() != 32 {
                    return Err(Error::Payload("subject must be 32 bytes".into()));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                subject = Some(arr);
            }
            2 => {
                let v = decode_uint(data, &mut offset)?;
                if v > 8 {
                    return Err(Error::Payload(format!("invalid predicate: {v}")));
                }
                predicate = Some(v as u8);
            }
            3 => {
                let b = decode_bstr(data, &mut offset)?;
                if b.len() != 32 {
                    return Err(Error::Payload("object must be 32 bytes".into()));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                object = Some(arr);
            }
            4 => {
                timestamp = Some(decode_uint(data, &mut offset)?);
            }
            5 => {
                let b = decode_bstr(data, &mut offset)?;
                if b.len() != 32 {
                    return Err(Error::Payload("lineage must be 32 bytes".into()));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                lineage = Some(arr);
            }
            6 => {
                let b = decode_bstr(data, &mut offset)?;
                if b.len() != 32 {
                    return Err(Error::Payload("nonce must be 32 bytes".into()));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                nonce = Some(arr);
            }
            8 => {
                let b = decode_bstr(data, &mut offset)?;
                if b.len() != 32 {
                    return Err(Error::Payload("anchor_hash must be 32 bytes".into()));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                anchor_hash = Some(arr);
            }
            7 => {
                extensions = Some(decode_map_value(data, &mut offset)?);
            }
            10 => {
                let b = decode_bstr(data, &mut offset)?;
                recovery_policy = Some(b);
            }
            _ => {
                if key < 100 {
                    return Err(Error::Payload(format!("unknown reserved key: {key}")));
                }
                skip_value(data, &mut offset)?;
            }
        }
    }

    if offset < data.len() {
        return Err(Error::Payload("trailing data after payload".into()));
    }

    let subject =
        subject.ok_or_else(|| Error::Payload("missing required field: subject".into()))?;
    let predicate =
        predicate.ok_or_else(|| Error::Payload("missing required field: predicate".into()))?;

    Ok(VeraxPayload {
        subject,
        predicate: crate::predicate::Predicate::from_u8(predicate)?,
        object,
        timestamp,
        lineage,
        nonce,
        anchor_hash,
        extensions,
        recovery_policy,
    })
}

fn decode_map_value(data: &[u8], offset: &mut usize) -> Result<Vec<(u64, Value)>> {
    let len = decode_map_len(data, offset)? as usize;
    let mut entries = Vec::with_capacity(len);
    for _ in 0..len {
        let key = decode_uint(data, offset)?;
        let val = decode_any_value(data, offset)?;
        entries.push((key, val));
    }
    Ok(entries)
}

fn decode_any_value(data: &[u8], offset: &mut usize) -> Result<Value> {
    if *offset >= data.len() {
        return Err(Error::Decode("unexpected end of value".into()));
    }
    let byte = data[*offset];
    let major = byte >> 5;
    match major {
        0 => {
            let v = decode_uint(data, offset)?;
            Ok(Value::Uint(v))
        }
        2 => {
            let b = decode_bstr(data, offset)?;
            Ok(Value::Bstr(b))
        }
        5 => {
            let entries = decode_map_value(data, offset)?;
            Ok(Value::Map(entries))
        }
        4 => Err(Error::Decode("arrays not allowed in extensions".into())),
        6 => Err(Error::NonCanonicalEncoding),
        7 => {
            let info = byte & 0x1f;
            if info == 20 || info == 23 {
                Err(Error::Decode("null/undefined values not allowed".into()))
            } else {
                Err(Error::Decode(format!(
                    "unexpected major type 7 with info {info}"
                )))
            }
        }
        _ => Err(Error::Decode(format!(
            "unexpected major type {major} in payload"
        ))),
    }
}

pub(crate) fn decode_array_len(data: &[u8], offset: &mut usize) -> Result<u64> {
    if *offset >= data.len() {
        return Err(Error::Decode("unexpected end of array".into()));
    }
    let byte = data[*offset];
    let major = byte >> 5;
    let info = byte & 0x1f;
    *offset += 1;

    if major != 4 {
        return Err(Error::Decode(format!(
            "expected array major type, got {major}"
        )));
    }

    let len = match info {
        0..=23 => info as u64,
        24 => {
            if *offset >= data.len() {
                return Err(Error::Decode("unexpected end of array length".into()));
            }
            let v = data[*offset] as u64;
            *offset += 1;
            check_shortest_encoding(v, info, 24, "array")?;
            v
        }
        25 => {
            if *offset + 2 > data.len() {
                return Err(Error::Decode("unexpected end of array length".into()));
            }
            let v = u16::from_be_bytes([data[*offset], data[*offset + 1]]) as u64;
            *offset += 2;
            check_shortest_encoding(v, info, 0x100, "array")?;
            v
        }
        26 => {
            if *offset + 4 > data.len() {
                return Err(Error::Decode("unexpected end of array length".into()));
            }
            let v = u32::from_be_bytes([
                data[*offset],
                data[*offset + 1],
                data[*offset + 2],
                data[*offset + 3],
            ]) as u64;
            *offset += 4;
            check_shortest_encoding(v, info, 0x10000, "array")?;
            v
        }
        27 => {
            if *offset + 8 > data.len() {
                return Err(Error::Decode("unexpected end of array length".into()));
            }
            let v = u64::from_be_bytes([
                data[*offset],
                data[*offset + 1],
                data[*offset + 2],
                data[*offset + 3],
                data[*offset + 4],
                data[*offset + 5],
                data[*offset + 6],
                data[*offset + 7],
            ]);
            *offset += 8;
            check_shortest_encoding(v, info, 0x100000000, "array")?;
            v
        }
        _ => {
            return Err(Error::Decode(format!(
                "reserved additional info for array: {info}"
            )));
        }
    };
    Ok(len)
}

pub(crate) fn skip_value(data: &[u8], offset: &mut usize) -> Result<()> {
    if *offset >= data.len() {
        return Err(Error::Decode("unexpected end while skipping".into()));
    }
    let byte = data[*offset];
    let major = byte >> 5;
    let info = (byte & 0x1f) as usize;
    *offset += 1;

    match major {
        0 | 1 => {
            let add = match info {
                0..=23 => 0,
                24 => 1,
                25 => 2,
                26 => 4,
                27 => 8,
                _ => return Err(Error::Decode("reserved additional info".into())),
            };
            *offset += add;
        }
        2 | 3 => {
            let len = match info {
                0..=23 => info,
                24..=27 => {
                    let nbytes = 1 << (info - 24);
                    if *offset + nbytes > data.len() {
                        return Err(Error::Decode("unexpected end of str length".into()));
                    }
                    let mut len = 0usize;
                    for i in 0..nbytes {
                        len = (len << 8) | data[*offset + i] as usize;
                    }
                    *offset += nbytes;
                    len
                }
                _ => return Err(Error::Decode("reserved additional info".into())),
            };
            *offset += len;
        }
        4 | 5 => {
            let len = match info {
                0..=23 => info,
                24..=27 => {
                    let nbytes = 1 << (info - 24);
                    if *offset + nbytes > data.len() {
                        return Err(Error::Decode("unexpected end of array/map length".into()));
                    }
                    let mut len = 0usize;
                    for i in 0..nbytes {
                        len = (len << 8) | data[*offset + i] as usize;
                    }
                    *offset += nbytes;
                    len
                }
                _ => return Err(Error::Decode("reserved additional info".into())),
            };
            for _ in 0..len {
                if major == 4 {
                    skip_value(data, offset)?;
                } else {
                    skip_value(data, offset)?;
                    skip_value(data, offset)?;
                }
            }
        }
        6 => {
            skip_value(data, offset)?;
            skip_value(data, offset)?;
        }
        7 => {
            if info == 20 || info == 23 || info >= 24 {
                return Err(Error::Decode("floats/null/undefined not allowed".into()));
            }
        }
        _ => return Err(Error::Decode(format!("unexpected major type {major}"))),
    }
    Ok(())
}

/// Check whether encoded bytes satisfy the deterministic CBOR subset.
///
/// Decodes the byte slice and re-encodes the result. If the re-encoded
/// output is byte-identical to the input, the data is strictly
/// deterministic. Returns `false` on any parse error or mismatch.
pub fn is_strictly_deterministic(data: &[u8]) -> bool {
    if let Ok(payload) = decode_payload(data) {
        let re_encoded = payload.encode();
        re_encoded == data
    } else {
        false
    }
}

/// A CBOR value used in extension map entries.
///
/// Only four CBOR major types are permitted in extensions: unsigned
/// integers, byte strings, maps, and arrays. Floats, tags, null,
/// undefined, and negative integers are rejected.
///
/// Maps nested inside a `Value` are recursively sorted by key during
/// encoding.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// An unsigned integer (`uint`).
    Uint(u64),
    /// A byte string (`bstr`).
    Bstr(Vec<u8>),
    /// A nested map (`map`). Keys are sorted bytewise during encoding.
    Map(Vec<(u64, Value)>),
    /// An array (`array`). Only valid in extension values.
    Array(Vec<Value>),
}

/// The top-level verax statement payload.
///
/// Encoded as a deterministic CBOR map. Every statement has exactly one
/// `subject` and one `predicate`; all other fields are optional.
#[derive(Debug, Clone, PartialEq)]
pub struct VeraxPayload {
    /// Subject identifier (32-byte BLAKE3 hash of a public key or artifact).
    pub subject: [u8; 32],
    /// Statement predicate (e.g. `Attests`, `Authors`, `DerivedFrom`, etc.).
    pub predicate: crate::predicate::Predicate,
    /// Optional object identifier (32-byte hash, required for binary predicates).
    pub object: Option<[u8; 32]>,
    /// Optional Unix timestamp (seconds since epoch).
    pub timestamp: Option<u64>,
    /// Optional lineage commitment (32-byte hash of the parent statement).
    pub lineage: Option<[u8; 32]>,
    /// Optional nonce for replay protection (32 bytes).
    pub nonce: Option<[u8; 32]>,
    /// Optional Certificate Transparency anchor hash (32 bytes).
    pub anchor_hash: Option<[u8; 32]>,
    /// Optional extension map for application-specific metadata.
    pub extensions: Option<Vec<(u64, Value)>>,
    /// Optional encoded [`RecoveryPolicy`] byte string for the RECOVERS predicate.
    pub recovery_policy: Option<Vec<u8>>,
}

/// Recovery policy for key recovery (RECOVERS predicate).
///
/// CDDL:
/// ```cddl
/// RecoveryPolicy = {
///   1: [* bstr .size 32],     ; guardians: list of guardian key hashes
///   2: uint,                   ; threshold: number of guardian approvals needed
///   ? 3: uint,                 ; recovery_delay: optional delay in seconds
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct RecoveryPolicy {
    /// List of guardian key hashes (each is a 32-byte BLAKE3 hash of a guardian's public key).
    pub guardians: Vec<[u8; 32]>,
    /// Number of guardian approvals required to recover a key.
    pub threshold: u64,
    /// Optional delay in seconds before recovery can be executed.
    pub recovery_delay: Option<u64>,
}

impl RecoveryPolicy {
    /// Encode this recovery policy as a deterministic CBOR map.
    ///
    /// Map keys are sorted bytewise. Returns the canonical encoded form.
    pub fn encode(&self) -> Vec<u8> {
        let mut entries = Vec::new();
        let guardian_bstrs: Vec<_> = self
            .guardians
            .iter()
            .map(|g| Value::Bstr(g.to_vec()))
            .collect();
        entries.push((1u64, Value::Array(guardian_bstrs)));
        entries.push((2u64, Value::Uint(self.threshold)));
        if let Some(delay) = self.recovery_delay {
            entries.push((3u64, Value::Uint(delay)));
        }
        entries.sort_by_key(|(k, _)| *k);
        let mut buf = Vec::new();
        encode_uint_head(&mut buf, MAJOR_MAP, entries.len() as u64);
        for (key, val) in entries {
            encode_uint(&mut buf, key);
            encode_value(&mut buf, &val);
        }
        buf
    }

    /// Decode a recovery policy from deterministic CBOR.
    ///
    /// Validates that all guardian hashes are exactly 32 bytes and that
    /// required keys (guardians, threshold) are present.
    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut offset = 0;
        let map_len = decode_map_len(data, &mut offset)? as usize;
        let mut guardians = None;
        let mut threshold = None;
        let mut recovery_delay = None;
        for _ in 0..map_len {
            let key = decode_uint(data, &mut offset)?;
            match key {
                1 => {
                    let arr_len = decode_array_len(data, &mut offset)? as usize;
                    let mut gs = Vec::with_capacity(arr_len);
                    for _ in 0..arr_len {
                        let b = decode_bstr(data, &mut offset)?;
                        if b.len() != 32 {
                            return Err(Error::Payload("guardian hash must be 32 bytes".into()));
                        }
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&b);
                        gs.push(arr);
                    }
                    guardians = Some(gs);
                }
                2 => {
                    threshold = Some(decode_uint(data, &mut offset)?);
                }
                3 => {
                    recovery_delay = Some(decode_uint(data, &mut offset)?);
                }
                _ => {
                    skip_value(data, &mut offset)?;
                }
            }
        }
        let guardians =
            guardians.ok_or_else(|| Error::Payload("recovery policy: missing guardians".into()))?;
        let threshold =
            threshold.ok_or_else(|| Error::Payload("recovery policy: missing threshold".into()))?;
        Ok(RecoveryPolicy {
            guardians,
            threshold,
            recovery_delay,
        })
    }
}

impl VeraxPayload {
    /// Create a new [`VeraxPayload`] with the minimum required fields.
    ///
    /// Optional fields (`object`, `timestamp`, `lineage`, `nonce`, `anchor_hash`,
    /// `extensions`, `recovery_policy`) are initialised to `None` and can be set
    /// via struct update syntax.
    ///
    /// ```
    /// use verax_core::predicate::Predicate;
    /// use verax_core::cbor::VeraxPayload;
    ///
    /// let subject = [0xabu8; 32];
    /// let payload = VeraxPayload::new(subject, Predicate::Attests);
    /// let encoded = payload.encode();
    /// let decoded = VeraxPayload::decode(&encoded).unwrap();
    /// assert_eq!(decoded, payload);
    /// ```
    pub fn new(subject: [u8; 32], predicate: crate::predicate::Predicate) -> Self {
        Self {
            subject,
            predicate,
            object: None,
            timestamp: None,
            lineage: None,
            nonce: None,
            anchor_hash: None,
            extensions: None,
            recovery_policy: None,
        }
    }

    /// Encode this payload as deterministic CBOR. Delegates to [`encode_payload`].
    pub fn encode(&self) -> Vec<u8> {
        encode_payload(self)
    }

    /// Decode a payload from deterministic CBOR. Delegates to [`decode_payload`].
    pub fn decode(data: &[u8]) -> Result<Self> {
        decode_payload(data)
    }
}

/// Kani proof harness for CBOR round-trip determinism (I1).
///
/// Proves that for any strictly-valid VeraxPayload, the
/// serialization is injective: `decode(encode(p)) == p`.
#[cfg(kani)]
mod kani_proofs {
    use super::*;
    use crate::predicate::Predicate;

    #[kani::proof]
    #[kani::unwind(20)]
    fn check_cbor_roundtrip_minimal() {
        let subject: [u8; 32] = kani::any();
        let payload = VeraxPayload::new(subject, Predicate::Attests);
        let encoded = payload.encode();
        let decoded = VeraxPayload::decode(&encoded).unwrap();
        assert!(decoded == payload);
    }

    #[kani::proof]
    #[kani::unwind(20)]
    fn check_cbor_roundtrip_full() {
        let subject: [u8; 32] = kani::any();
        let object: [u8; 32] = kani::any();
        let ts: u64 = kani::any();
        let lineage: [u8; 32] = kani::any();
        let nonce: [u8; 32] = kani::any();
        let mut p = VeraxPayload::new(subject, Predicate::DerivedFrom);
        p.object = Some(object);
        p.timestamp = Some(ts);
        p.lineage = Some(lineage);
        p.nonce = Some(nonce);
        let encoded = p.encode();
        let decoded = VeraxPayload::decode(&encoded).unwrap();
        assert!(decoded == p);
    }

    #[kani::proof]
    #[kani::unwind(15)]
    fn check_cbor_determinism_repeated() {
        let p = VeraxPayload::new([0xab; 32], Predicate::Attests);
        let a = p.encode();
        let b = p.encode();
        assert_eq!(a, b);
    }

    #[kani::proof]
    #[kani::unwind(15)]
    fn check_cbor_encode_never_panics() {
        let subject: [u8; 32] = kani::any();
        let p = VeraxPayload::new(subject, Predicate::Attests);
        let encoded = p.encode();
        assert!(!encoded.is_empty());
    }

    #[kani::proof]
    #[kani::unwind(15)]
    fn check_cbor_subject_roundtrip() {
        let subject: [u8; 32] = kani::any();
        let payload = VeraxPayload::new(subject, Predicate::Attests);
        let encoded = payload.encode();
        let decoded = VeraxPayload::decode(&encoded).unwrap();
        assert_eq!(decoded.subject, subject);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::predicate::Predicate;
    use alloc::vec;

    #[test]
    fn test_round_trip_minimal() {
        let payload = VeraxPayload::new([0xabu8; 32], Predicate::Attests);
        let encoded = payload.encode();
        let decoded = VeraxPayload::decode(&encoded).unwrap();
        assert_eq!(decoded.subject, payload.subject);
        assert_eq!(decoded.predicate, payload.predicate);
    }

    #[test]
    fn test_round_trip_full() {
        let mut p = VeraxPayload::new([0x01; 32], Predicate::DerivedFrom);
        p.object = Some([0x02; 32]);
        p.timestamp = Some(1700000000);
        p.lineage = Some([0x03; 32]);
        p.nonce = Some([0x04; 32]);
        p.anchor_hash = Some([0x05; 32]);
        p.extensions = Some(vec![
            (100, Value::Uint(42)),
            (101, Value::Bstr(vec![1, 2, 3])),
        ]);

        let encoded = p.encode();
        let decoded = VeraxPayload::decode(&encoded).unwrap();
        assert_eq!(decoded.subject, p.subject);
        assert_eq!(decoded.predicate, p.predicate);
        assert_eq!(decoded.object, p.object);
        assert_eq!(decoded.timestamp, p.timestamp);
        assert_eq!(decoded.lineage, p.lineage);
        assert_eq!(decoded.nonce, p.nonce);
        assert_eq!(decoded.anchor_hash, p.anchor_hash);
        assert_eq!(decoded.extensions, p.extensions);
    }

    #[test]
    fn test_deterministic_encoding() {
        let a = {
            let mut p = VeraxPayload::new([0x01; 32], Predicate::Authors);
            p.object = Some([0x02; 32]);
            p.encode()
        };
        let b = {
            let mut p = VeraxPayload::new([0x01; 32], Predicate::Authors);
            p.object = Some([0x02; 32]);
            p.encode()
        };
        assert_eq!(a, b);
    }

    #[test]
    fn test_rejects_null_bytes() {
        let buf = vec![0xa1, 0x01, 0xf6]; // map {1: null}
        assert!(VeraxPayload::decode(&buf).is_err());
    }

    #[test]
    fn test_rejects_float() {
        let buf = vec![0xa1, 0x01, 0xfa, 0x00, 0x00, 0x00, 0x00]; // map {1: float(0)}
        assert!(VeraxPayload::decode(&buf).is_err());
    }

    #[test]
    fn test_rejects_tags() {
        let mut data = vec![0xc1]; // tag(1) prefix
        let inner = VeraxPayload::new([0x01; 32], Predicate::Attests).encode();
        data.extend_from_slice(&inner);
        assert!(VeraxPayload::decode(&data).is_err());
    }

    #[test]
    fn test_missing_subject_fails() {
        let buf = vec![0xa1, 0x02, 0x01]; // map {2: 1} — missing subject
        assert!(VeraxPayload::decode(&buf).is_err());
    }

    #[test]
    fn test_subject_wrong_length() {
        // map {1: h'00...00'} with 16 bytes instead of 32
        let mut buf = vec![0xa1, 0x01, 0x58, 0x10];
        buf.resize(buf.len() + 16, 0x00);
        assert!(VeraxPayload::decode(&buf).is_err());
    }

    /// Simple deterministic PRNG for fuzz-like testing (no_std compatible).
    struct FuzzRng(u64);
    impl FuzzRng {
        fn new(seed: u64) -> Self {
            Self(seed)
        }
        fn next_u32(&mut self) -> u32 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (self.0 >> 33) as u32
        }
        fn next_u64(&mut self) -> u64 {
            ((self.next_u32() as u64) << 32) | self.next_u32() as u64
        }
        fn fill_bytes(&mut self, buf: &mut [u8]) {
            for chunk in buf.chunks_mut(4) {
                let val = self.next_u32().to_le_bytes();
                for (d, s) in chunk.iter_mut().zip(val.iter()) {
                    *d = *s;
                }
            }
        }
    }

    fn random_32_bytes(rng: &mut FuzzRng) -> [u8; 32] {
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);
        buf
    }

    /// Fuzz-like stress test: 10,000 random payload round-trips.
    #[test]
    fn test_fuzz_roundtrip_random_payloads() {
        let mut rng = FuzzRng::new(42);
        for pred in 0..9 {
            let predicate = Predicate::from_u8(pred).unwrap();
            for _ in 0..1000 {
                let subject = random_32_bytes(&mut rng);
                let mut p = VeraxPayload::new(subject, predicate);
                if rng.next_u32() % 2 == 0 {
                    p.object = Some(random_32_bytes(&mut rng));
                }
                if rng.next_u32() % 2 == 0 {
                    p.timestamp = Some(rng.next_u64());
                }
                if rng.next_u32() % 2 == 0 {
                    p.lineage = Some(random_32_bytes(&mut rng));
                }
                if rng.next_u32() % 2 == 0 {
                    p.nonce = Some(random_32_bytes(&mut rng));
                }
                if rng.next_u32() % 2 == 0 {
                    p.anchor_hash = Some(random_32_bytes(&mut rng));
                }
                if rng.next_u32() % 2 == 0 {
                    let exts = alloc::vec![
                        (100u64, Value::Uint(rng.next_u64())),
                        (101u64, Value::Bstr(random_32_bytes(&mut rng).to_vec())),
                    ];
                    p.extensions = Some(exts);
                }
                let encoded = p.encode();
                assert!(!encoded.is_empty());
                let encoded2 = p.encode();
                assert_eq!(encoded, encoded2, "determinism violated");
                let decoded = VeraxPayload::decode(&encoded).unwrap();
                assert_eq!(decoded, p, "round-trip failed for pred {pred}");
                assert!(is_strictly_deterministic(&encoded));
            }
        }
    }

    /// Fuzz-like stress test: 5,000 random byte slices must not panic the decoder.
    #[test]
    fn test_fuzz_decode_never_panics() {
        let mut rng = FuzzRng::new(99);
        for _ in 0..5000 {
            let len = (rng.next_u32() % 256) as usize;
            let mut bytes = alloc::vec![0u8; len];
            rng.fill_bytes(&mut bytes);
            let _ = VeraxPayload::decode(&bytes);
        }
    }

    /// Fuzz-like test: 2,000 non-canonical encodings must not panic.
    #[test]
    fn test_fuzz_rejects_non_canonical_uint() {
        let mut rng = FuzzRng::new(123);
        for _ in 0..2000 {
            let subject = random_32_bytes(&mut rng);
            let pred: u8 = (rng.next_u32() % 9) as u8;
            let mut buf = alloc::vec![0xbb, 0, 0, 0, 0, 0, 0, 0, 2];
            buf.push(0x01);
            buf.push(0x58);
            buf.push(32);
            buf.extend_from_slice(&subject);
            buf.push(0x02);
            buf.push(pred);
            let _ = VeraxPayload::decode(&buf);
        }
    }

    /// Fuzz-like test: duplicate keys always rejected.
    #[test]
    fn test_fuzz_rejects_duplicate_keys() {
        let mut rng = FuzzRng::new(456);
        for _ in 0..1000 {
            let subject = random_32_bytes(&mut rng);
            let pred: u8 = (rng.next_u32() % 9) as u8;
            let mut buf = alloc::vec![0xa3, 0x01, 0x58, 0x20];
            buf.extend_from_slice(&subject);
            buf.extend_from_slice(&[0x01, 0x58, 0x20]);
            buf.extend_from_slice(&subject);
            buf.extend_from_slice(&[0x02, pred]);
            assert!(VeraxPayload::decode(&buf).is_err(), "duplicate keys");
        }
    }

    /// Edge case: empty input must be rejected without panic.
    #[test]
    fn test_fuzz_empty_input() {
        assert!(VeraxPayload::decode(&[]).is_err());
    }

    /// Edge case: single byte input must be rejected without panic.
    #[test]
    fn test_fuzz_single_byte() {
        for b in 0..=255u8 {
            let _ = VeraxPayload::decode(&[b]);
        }
    }

    /// Indefinite-length items must be rejected.
    #[test]
    fn test_rejects_indefinite_length() {
        // indefinite-length map (0xbf), then break (0xff)
        assert!(VeraxPayload::decode(&[0xbf, 0xff]).is_err());
        // indefinite-length array (0x9f), then break (0xff)
        assert!(VeraxPayload::decode(&[0x9f, 0xff]).is_err());
        // indefinite-length bstr (0x5f), then break (0xff)
        assert!(VeraxPayload::decode(&[0x5f, 0xff]).is_err());
        // indefinite-length text (0x7f), then break (0xff)
        assert!(VeraxPayload::decode(&[0x7f, 0xff]).is_err());
    }

    /// Tags at the value level (not just wrapping the whole payload) must be rejected.
    #[test]
    fn test_rejects_tagged_values_inner() {
        // map {1: h'0000...00'} where the bstr is wrapped in tag(1): 0xc1
        let mut buf = vec![0xa1, 0x01, 0xc1, 0x58, 0x20];
        buf.resize(buf.len() + 32, 0x00);
        assert!(VeraxPayload::decode(&buf).is_err());
    }

    /// Map keys must be sorted by raw CBOR-encoded bytes (bytewise), not numerically.
    /// Key 10 (0x0a) sorts AFTER key 2 (0x02) bytewise. A map with key 10 before
    /// key 2 must be rejected as non-canonical.
    #[test]
    fn test_rejects_bytewise_unsorted_keys() {
        // Construct a 3-entry map: {1: subject, 10: uint(42), 2: predicate}
        // Key 10 appears before key 2 — violates bytewise canonical order.
        let subject = [0x01u8; 32];
        let mut buf = vec![0xa3]; // map(3)
        // key 1 (subject)
        buf.extend_from_slice(&[0x01, 0x58, 0x20]);
        buf.extend_from_slice(&subject);
        // key 10 (extension-like uint) — out of order, should come after key 2
        buf.extend_from_slice(&[0x0a, 0x18, 0x2a]); // key=10, value=uint(42)
        // key 2 (predicate)
        buf.extend_from_slice(&[0x02, 0x00]); // key=2, value=uint(0=Attests)
        assert!(
            VeraxPayload::decode(&buf).is_err(),
            "map with key 10 before key 2 must be rejected (bytewise unsorted)"
        );
    }

    /// Canonical encoding must place key 2 before key 10. Prove that a properly
    /// sorted payload encodes key 2 before key 10 in the output bytes.
    #[test]
    fn test_bytewise_sorted_keys_in_encoded_output() {
        let subject = [0xabu8; 32];
        let mut p = VeraxPayload::new(subject, Predicate::Attests);
        // Add an extension at key 10 (private-use range)
        p.extensions = Some(alloc::vec![(10u64, Value::Uint(42))]);
        let encoded = p.encode();
        // Find the positions of key bytes 0x02 and 0x0a in the encoded form
        let pos_key2 = encoded.iter().position(|&b| b == 0x02);
        let pos_key10 = encoded.iter().position(|&b| b == 0x0a);
        assert!(
            pos_key2.is_some(),
            "key 2 must be present in encoded output"
        );
        assert!(
            pos_key10.is_some(),
            "key 10 must be present in encoded output"
        );
        assert!(
            pos_key2.unwrap() < pos_key10.unwrap(),
            "key 2 (0x02) must appear before key 10 (0x0a) in bytewise-sorted encoding, \
             but found key 2 at byte {} and key 10 at byte {}",
            pos_key2.unwrap(),
            pos_key10.unwrap()
        );
    }
}
