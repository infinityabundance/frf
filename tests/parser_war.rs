//! The PARSER WAR — the differential canonical-JSON battle.
//!
//! Layer 1 (this suite, in-engine): pathological documents generated
//! deterministically must canonicalize without panicking, be idempotent
//! (canonical(canonical(x)) == canonical(x)), round-trip strictly
//! (parse_strict(encode(v)) == v; encode(parse_strict(canonical)) == the
//! canonical bytes), and never split one semantic document into two
//! identities.
//!
//! Layer 2 (the conformance corpus, `conformance/valid/07-pathological-
//! strings.json`): the SAME pathological values are pinned as canonical
//! bytes + digests and consumed by ALL THREE implementations — the engine
//! (`cargo test --test conformance`), the independent Rust verifier
//! (`cargo xtask verify corpus conformance`), and the Go verifier
//! (`frf-verifier-go verify corpus`). If any two implementations ever
//! produce different JCS bytes for the same document, or accept/reject
//! differently, the triangle breaks.

use frf::canon::{encode, parse_strict};
use frf::host::sha256_bytes;
use serde_json::{json, Value};

/// The pathological string corpus: UTF-16 sorting boundaries, supplementary
/// Unicode, escaped/unescaped equivalents, embedded controls, identifier
/// boundaries, and long mixed-plane UTF-8.
fn pathological_strings() -> Vec<String> {
    let long = "ΩΣφλδε·😀🚀💥\u{00fc}\u{4e2d}\u{6587}".repeat(120);
    vec![
        // UTF-16 sorting boundary: U+10000 (surrogate pair) vs U+E000 vs
        // U+D7FF — the JCS encoder must sort code points, not UTF-16 units.
        "\u{10000}".to_string(),
        "\u{e000}".to_string(),
        "\u{d7ff}".to_string(),
        "boundary-\u{10000}-\u{e000}-\u{d7ff}".to_string(),
        // Escaped/unescaped equivalents: "\u0041" == "A" — the canonical
        // form must be the shortest escape / literal consistently.
        "\u{0041}".to_string(),
        "A".to_string(),
        "\u{0000}".to_string(),
        // Supplementary + combining + RTL.
        "\u{1f600}\u{0301}\u{200f}\u{0627}".to_string(),
        // Embedded controls.
        "\u{0009}\u{000d}\u{001f}\u{007f}".to_string(),
        // Identifier boundaries: 63/64/65-byte runs.
        format!("{}{}{}", "a".repeat(63), ".".repeat(64), "b".repeat(65)),
        // Long mixed-plane UTF-8 (a multibyte char straddling any byte
        // boundary the encoder might truncate at).
        long,
        // Empty + single-char + astral-only.
        String::new(),
        "\u{1f600}".to_string(),
    ]
}

/// The pathological VALUE corpus: deep nesting, huge arrays, empty
/// containers. Numbers are deliberately ABSENT — they belong to the refusal
/// case (the evidence value domain is strings/arrays/booleans/null only),
/// asserted separately below.
fn pathological_values() -> Vec<Value> {
    let mut deep = json!(null);
    for _ in 0..100 {
        deep = json!({ "k": deep });
    }
    vec![
        deep,
        json!((0..10_000).map(|i| i.to_string()).collect::<Vec<_>>()),
        json!([]),
        json!({}),
    ]
}

#[test]
fn pathological_documents_canonicalize_stably_and_round_trip() {
    let strings = pathological_strings();
    let values = pathological_values();
    let mut docs: Vec<Value> = Vec::new();
    // Single-string docs + mixed docs (the field names also stress sorting).
    for (i, s) in strings.iter().enumerate() {
        docs.push(json!({ "z": s, "a": i.to_string(), "m": { "n": s, "b": "x" } }));
    }
    for v in &values {
        docs.push(json!({ "payload": v, "id": "doc" }));
    }
    // A document with every pathological string at once.
    docs.push(json!({
        "list": strings,
        "values": values,
        "nested": json!({"deep": {"deeper": strings[0]}}),
    }));

    // The RFC 8785 NUMBER serialization is deliberately out of scope for the
    // evidence value domain (strings/arrays/booleans/null only): a number in
    // an evidence document is a documented REFUSAL, never a silently
    // reinterpreted value.
    for (i, n) in [1e308, -1e308, 0.0, -0.0, 1.0, -1.0, 9223372036854775807.0]
        .into_iter()
        .enumerate()
    {
        let v = serde_json::Number::from_f64(n).map(Value::Number);
        let doc = json!({ "n": v });
        let err = encode(&doc).expect_err(&format!("numeric value {i} must be refused"));
        assert!(
            err.message().contains("number") || err.message().contains("out of scope"),
            "numeric refusal must name the domain: {err}"
        );
    }

    let mut seen: std::collections::BTreeMap<String, String> = Default::default();
    for (i, doc) in docs.iter().enumerate() {
        // 1. No panic; the canonical form is produced.
        let canonical = encode(doc).unwrap_or_else(|e| panic!("doc {i}: {e}"));
        // 2. Idempotent: re-encoding the canonical bytes yields the same
        //    bytes.
        let reparsed: Value = parse_strict(canonical.as_bytes())
            .unwrap_or_else(|e| panic!("doc {i}: cannot re-parse canonical: {e}"));
        let recanon = encode(&reparsed).unwrap();
        assert_eq!(canonical, recanon, "doc {i}: canonical must be idempotent");
        // 3. Strict round-trip: parse_strict(encode(v)) == v.
        assert_eq!(reparsed, *doc, "doc {i}: encode -> parse must be identity");
        // 4. One semantic document, one identity: the canonical bytes hash
        //    deterministically.
        let digest = sha256_bytes(canonical.as_bytes());
        if let Some(prev) = seen.insert(digest.clone(), format!("doc-{i}")) {
            panic!("doc {i}: identity collision with {prev}");
        }
    }
    // The corpus pin for the pathological fixture must match the engine's
    // own canonicalizer — the cross-implementation agreement is the corpus
    // test's job, but the ENGINE must not drift from its own pin either.
    let corpus = std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("conformance/valid/07-pathological-strings.json"),
    )
    .unwrap();
    let parsed: Value = parse_strict(&corpus).unwrap();
    let canonical = encode(&parsed).unwrap();
    let pinned = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("conformance/canonical/07-pathological-strings.json"),
    )
    .unwrap();
    assert_eq!(
        canonical, pinned,
        "the engine's canonicalizer drifted from the pinned pathological corpus"
    );
}

use std::path::PathBuf;

#[test]
fn strict_parse_refuses_duplicate_properties_in_pathological_documents() {
    // RFC 8785 I-JSON: a document with a repeated property name is refused,
    // never collapsed — the duplicate cannot deserialize away before the
    // identity is checked.
    for (name, text) in [
        ("top-level", r#"{"a": 1, "a": 2}"#.to_string()),
        ("nested", r#"{"a": {"b": 1, "b": 2}}"#.to_string()),
        (
            "deep-nested",
            r#"{"a": {"b": {"c": 1, "c": 2}}}"#.to_string(),
        ),
    ] {
        let err = parse_strict(text.as_bytes()).expect_err(&format!("{name}: must refuse"));
        assert!(
            err.message().contains("duplicate") || err.message().contains("strict"),
            "{name}: {err}"
        );
    }
}
