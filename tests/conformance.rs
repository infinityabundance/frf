//! OpenReceipt conformance suite — the executable form of the protocol.
//!
//! Walks the `conformance/` corpus and proves, for every valid fixture:
//! the document parses, deserializes into the [`Receipt`] schema, and
//! canonicalizes (RFC 8785) to EXACTLY the pinned bytes in `canonical/`,
//! whose SHA-256 is EXACTLY the pinned value in `hashes/`. Invalid
//! fixtures must fail to parse or deserialize.
//!
//! The corpus is for every implementation, not just this one: a Go or
//! Python implementation that passes the same corpus speaks the same
//! protocol (see `spec/openreceipt.md`).
//!
//! The schema (`spec/openreceipt.schema.json`) is validated here with a
//! fail-closed subset validator instead of the `jsonschema` crate: every
//! released jsonschema resolves `url` to 2.5.x, which unconditionally
//! enables idna's `compiled_data` feature and pulls ICU (idna_adapter 1.2.2
//! and icu_* 2.3.0 need rustc 1.86/1.88), breaking the 1.85 MSRV. The
//! schema deliberately uses only the core keywords the validator audits;
//! any keyword outside that set is a test failure, never a silent skip.
//!
//! Generator mode (used to refresh the pins after a schema change):
//!   FRF_CONFORM_PRINT=1 cargo test --test conformance -- --nocapture
//! prints `name<TAB>canonical<TAB>sha256` per valid fixture.

use frf::canon;
use frf::host;
use frf::model::{DetachedObjects, Receipt, KIND_SCHEMAS};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

/// The detached-objects declaration fixtures share the corpus layout but are
/// a different document family: they deserialize as [`DetachedObjects`], not
/// [`Receipt`]. Named `detached-*.json`.
fn is_detached_fixture(name: &str) -> bool {
    name.starts_with("detached-")
}

fn dir(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn schema() -> Value {
    serde_json::from_str(
        &fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("spec/openreceipt.schema.json"),
        )
        .expect("spec/openreceipt.schema.json must exist"),
    )
    .expect("the schema must be valid JSON")
}

/// The keyword subset `spec/openreceipt.schema.json` is allowed to use.
/// Everything else is a harness failure — validation must never be skipped.
const SUPPORTED_KEYWORDS: &[&str] = &[
    "type",
    "required",
    "properties",
    "additionalProperties",
    "items",
    "enum",
    "const",
    "pattern",
    "$ref",
    // Metadata the corpus ignores.
    "$schema",
    "$id",
    "title",
    "description",
    "definitions",
];

fn audit(schema: &Value, where_: &str) {
    if let Some(obj) = schema.as_object() {
        for key in obj.keys() {
            assert!(
                SUPPORTED_KEYWORDS.contains(&key.as_str()),
                "{where_}: unsupported keyword {key:?} — the conformance harness must not skip it"
            );
        }
    }
    if let Some(p) = schema.get("properties") {
        for (k, sub) in p.as_object().expect("properties must be an object") {
            audit(sub, &format!("{where_}.properties.{k}"));
        }
    }
    if let Some(items) = schema.get("items") {
        audit(items, &format!("{where_}.items"));
    }
    if let Some(defs) = schema.get("definitions") {
        for (k, sub) in defs.as_object().expect("definitions must be an object") {
            audit(sub, &format!("{where_}.definitions.{k}"));
        }
    }
    if let Some(p) = schema.get("pattern") {
        // The corpus only uses these two patterns. Any future pattern must be
        // implemented here before it may appear in the schema.
        let p = p.as_str().expect("pattern must be a string");
        assert!(
            matches!(p, "^[0-9a-f]{64}$" | "^[a-z][a-z0-9._-]*$"),
            "{where_}: unsupported pattern — implement it before using it"
        );
    }
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The protocol identifier grammar: lowercase letter first, then lowercase
/// letters, digits, `.`, `_`, `-`; 1..=64 characters.
fn is_ident(s: &str) -> bool {
    if s.is_empty() || s.len() > 64 {
        return false;
    }
    let mut chars = s.chars();
    if !chars.next().is_some_and(|c| c.is_ascii_lowercase()) {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
}

fn validate(schema: &Value, defs: &Value, instance: &Value) -> Result<(), String> {
    if let Some(r#ref) = schema.get("$ref") {
        let r = r#ref.as_str().expect("$ref must be a string");
        let name = r
            .strip_prefix("#/definitions/")
            .unwrap_or_else(|| panic!("unsupported $ref {r:?}: only #/definitions/NAME is used"));
        let target = defs
            .get(name)
            .unwrap_or_else(|| panic!("$ref {r:?} has no matching definition"));
        return validate(target, defs, instance);
    }
    if let Some(t) = schema.get("type") {
        match t {
            Value::String(single) => {
                let ok = match single.as_str() {
                    "object" => instance.is_object(),
                    "array" => instance.is_array(),
                    "string" => instance.is_string(),
                    other => panic!("unsupported type keyword {other:?}"),
                };
                if !ok {
                    return Err(format!("expected {single}, got {}", type_name(instance)));
                }
            }
            Value::Array(types) => {
                let ok = types.iter().any(|t| match t.as_str() {
                    Some("object") => instance.is_object(),
                    Some("array") => instance.is_array(),
                    Some("string") => instance.is_string(),
                    Some("null") => instance.is_null(),
                    Some(other) => panic!("unsupported type keyword {other:?}"),
                    None => panic!("type array entries must be strings"),
                });
                if !ok {
                    return Err(format!(
                        "expected one of {types:?}, got {}",
                        type_name(instance)
                    ));
                }
            }
            _ => panic!("type must be a string or an array of strings"),
        }
    }
    if instance.is_object() {
        let obj = instance.as_object().unwrap();
        if let Some(req) = schema.get("required") {
            for k in req.as_array().expect("required must be an array") {
                let k = k.as_str().expect("required entries must be strings");
                if !obj.contains_key(k) {
                    return Err(format!("missing required property {k:?}"));
                }
            }
        }
        if let Some(props) = schema.get("properties") {
            for (k, sub) in props.as_object().expect("properties must be an object") {
                if let Some(v) = obj.get(k) {
                    validate(sub, defs, v).map_err(|e| format!("{k}: {e}"))?;
                }
            }
        }
        if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
            let props = schema.get("properties").expect(
                "additionalProperties: false without properties — the harness cannot check it",
            );
            let props = props.as_object().expect("properties must be an object");
            for k in obj.keys() {
                if !props.contains_key(k) {
                    return Err(format!("additional property {k:?}"));
                }
            }
        }
    }
    if instance.is_array() {
        if let Some(items) = schema.get("items") {
            for (i, v) in instance.as_array().unwrap().iter().enumerate() {
                validate(items, defs, v).map_err(|e| format!("[{i}]: {e}"))?;
            }
        }
    }
    if let Some(e) = schema.get("enum") {
        let e = e.as_array().expect("enum must be an array");
        if !e.iter().any(|candidate| candidate == instance) {
            return Err(format!("value is not one of {e:?}"));
        }
    }
    if let Some(c) = schema.get("const") {
        if c != instance {
            return Err(format!("value does not equal const {c}"));
        }
    }
    if schema.get("pattern").is_some() {
        // `audit` has already proven the only reachable patterns are the hex
        // digest and the protocol identifier; both are implemented below.
        let p = schema["pattern"]
            .as_str()
            .expect("pattern must be a string");
        if let Some(s) = instance.as_str() {
            let ok = match p {
                "^[0-9a-f]{64}$" => hex64(s),
                "^[a-z][a-z0-9._-]*$" => is_ident(s),
                other => panic!("unsupported pattern {other:?}"),
            };
            if !ok {
                return Err(format!("{s:?} does not match {p}"));
            }
        }
    }
    Ok(())
}

/// Compile-and-validate: audits the schema once, then validates the instance.
fn schema_valid(instance: &Value) -> Result<(), String> {
    let doc = schema();
    let defs = doc
        .get("definitions")
        .expect("the schema must carry definitions");
    audit(&doc, "openreceipt.schema.json");
    validate(&doc, defs, instance)
}

#[test]
fn valid_fixtures_parse_canonicalize_and_hash_to_the_pinned_values() {
    let mut count = 0;
    let print = std::env::var("FRF_CONFORM_PRINT").is_ok();
    for entry in fs::read_dir(dir("conformance/valid")).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let source = fs::read_to_string(&path).unwrap();

        // Must parse as STRICT JSON (RFC 8785 §2 I-JSON: duplicate property
        // names refused — serde_json::Value would silently collapse them) and
        // deserialize into its schema (unknown properties refused by
        // deny_unknown_fields): an OpenReceipt, or the detached-objects
        // declaration for the `detached-*` family.
        let value: Value = canon::parse_strict(source.as_bytes())
            .unwrap_or_else(|e| panic!("{name}: not strict JSON: {e}"));
        let detached_family = is_detached_fixture(&name);
        if detached_family {
            let declaration: DetachedObjects = serde_json::from_value(value.clone())
                .unwrap_or_else(|e| {
                    panic!("{name}: does not deserialize as a detached-objects declaration: {e}")
                });
            declaration.validate_semantics().unwrap_or_else(|e| {
                panic!("{name}: fails detached-objects semantic conformance: {e}")
            });
        } else {
            let _receipt: Receipt = serde_json::from_value(value.clone())
                .unwrap_or_else(|e| panic!("{name}: does not deserialize as an OpenReceipt: {e}"));
        }

        let canonical =
            canon::canonical(&value).unwrap_or_else(|e| panic!("{name}: cannot canonicalize: {e}"));
        let hash = host::sha256_bytes(canonical.as_bytes());

        if print {
            println!("{name}\t{canonical}\t{hash}");
            continue;
        }

        // The canonical bytes are pinned byte-for-byte.
        let expected = fs::read_to_string(dir("conformance/canonical").join(&name))
            .unwrap_or_else(|_| panic!("{name}: missing canonical/{name} — run the generator"));
        assert_eq!(
            canonical, expected,
            "{name}: canonical bytes drifted from the pinned corpus"
        );
        // The hash is pinned.
        let expected_hash =
            fs::read_to_string(dir("conformance/hashes").join(format!("{name}.sha256")))
                .unwrap_or_else(|_| {
                    panic!("{name}: missing hashes/{name}.sha256 — run the generator")
                });
        assert_eq!(hash, expected_hash.trim(), "{name}: digest drifted");
        // The schema validates the canonical form too (OpenReceipt family
        // only — the detached family validated above).
        if !detached_family {
            let canonical_value: Value =
                serde_json::from_str(&canonical).expect("canonical bytes must be JSON");
            schema_valid(&canonical_value)
                .unwrap_or_else(|e| panic!("{name}: fails the OpenReceipt schema: {e}"));
        }
        count += 1;
    }
    assert!(!print, "generator mode: wrote pins above");
    assert!(
        count >= 4,
        "the corpus must carry at least four valid fixtures"
    );
}

#[test]
fn invalid_fixtures_must_be_refused() {
    let mut count = 0;
    for entry in fs::read_dir(dir("conformance/invalid")).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let source = fs::read_to_string(&path).unwrap();
        // Either the JSON is not strict (duplicate property names — RFC 8785
        // §2 I-JSON), or it does not deserialize as an OpenReceipt (schema
        // version enforced, fields required, enums closed, unknown properties
        // refused). Both are refusals.
        let refused = canon::parse_strict(source.as_bytes())
            .ok()
            .and_then(|v| serde_json::from_value::<Receipt>(v).ok())
            .is_none();
        assert!(refused, "{name}: must be refused");
        count += 1;
    }
    assert!(
        count >= 4,
        "the corpus must carry at least four invalid fixtures"
    );
}

#[test]
fn semantic_invalid_fixtures_must_be_refused() {
    // The second conformance level (spec/openreceipt.md): documents that are
    // STRUCTURALLY valid — they parse as JSON and deserialize into the
    // Receipt schema — but violate the cross-field, cross-object SEMANTIC
    // invariants (disposition cross-field rules, rederivable identities,
    // verdict consistency, replay target, token rederivation, interpreter
    // consistency, …). The corpus is for every implementation: any
    // independent verifier that accepts a document in here is not
    // OpenReceipt-conformant.
    let mut count = 0;
    for entry in fs::read_dir(dir("conformance/invalid-semantic")).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let source = fs::read_to_string(&path).unwrap();
        // Structurally valid: must parse as STRICT JSON (no duplicate
        // property names) and deserialize. The `detached-*` family
        // deserializes as the detached-objects declaration and must fail
        // ITS semantic validator instead.
        let value: Value = canon::parse_strict(source.as_bytes())
            .unwrap_or_else(|e| panic!("{name}: not strict JSON: {e}"));
        if is_detached_fixture(&name) {
            let declaration: DetachedObjects = serde_json::from_value(value).unwrap_or_else(|e| {
                panic!("{name}: must deserialize as a detached-objects declaration (structural conformance): {e}")
            });
            assert!(
                declaration.validate_semantics().is_err(),
                "{name}: must fail detached-objects semantic conformance"
            );
            count += 1;
            continue;
        }
        let receipt: Receipt = serde_json::from_value(value).unwrap_or_else(|e| {
            panic!("{name}: must deserialize as an OpenReceipt (structural conformance): {e}")
        });
        // Semantically invalid: must fail the document-level validator.
        assert!(
            receipt.validate_semantics().is_err(),
            "{name}: must fail OpenReceipt semantic conformance"
        );
        count += 1;
    }
    assert!(
        count >= 8,
        "the semantic corpus must carry at least eight fixtures"
    );
}

#[test]
fn the_kind_records_are_pinned_and_their_identities_rederive() {
    // The residual-kind vocabulary (FRF/KIND/v1) is a protocol object: every
    // registered kind record in `conformance/kinds/` must canonicalize to the
    // pinned bytes, hash to the pinned digest, and carry an `identity` that
    // rederives from the record's own semantic fields.
    let mut count = 0;
    for entry in fs::read_dir(dir("conformance/kinds")).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let source = fs::read_to_string(&path).unwrap();
        let value: Value = canon::parse_strict(source.as_bytes())
            .unwrap_or_else(|e| panic!("{name}: not strict JSON: {e}"));
        let canonical =
            canon::canonical(&value).unwrap_or_else(|e| panic!("{name}: cannot canonicalize: {e}"));
        let expected = fs::read_to_string(dir("conformance/canonical/kinds").join(&name))
            .unwrap_or_else(|_| panic!("{name}: missing canonical/kinds/{name}"));
        assert_eq!(
            canonical, expected,
            "{name}: canonical bytes drifted from the pinned corpus"
        );
        let digest = host::sha256_bytes(canonical.as_bytes());
        let stem = name.strip_suffix(".json").unwrap_or(&name);
        let pinned =
            fs::read_to_string(dir("conformance/hashes").join(format!("{stem}.kind.sha256")))
                .unwrap_or_else(|_| panic!("{name}: missing hashes/{stem}.kind.sha256"));
        assert_eq!(digest, pinned.trim(), "{name}: digest drifted");
        // The identity rederives from the record's own fields.
        assert_eq!(
            frf::semantics::kind_identity_parts(
                value["id"].as_str().unwrap_or_default(),
                value["meaning"].as_str().unwrap_or_default(),
                value["surface_grammar"].as_str().unwrap_or_default(),
                value["comparator_family"].as_str().unwrap_or_default(),
            )
            .unwrap(),
            value["identity"].as_str().unwrap_or_default(),
            "{name}: the identity does not rederive from its own fields"
        );
        // And the engine's own registry table declares exactly this record.
        let id = value["id"].as_str().unwrap_or_default();
        let engine = KIND_SCHEMAS
            .iter()
            .find(|s| s.id == id)
            .unwrap_or_else(|| panic!("{name}: kind not in the engine's KIND_SCHEMAS"));
        assert_eq!(
            engine.id,
            value["id"].as_str().unwrap_or_default(),
            "{name}"
        );
        assert_eq!(
            engine.meaning,
            value["meaning"].as_str().unwrap_or_default(),
            "{name}: the pinned record drifts from the engine's registered vocabulary"
        );
        assert_eq!(
            engine.surface_grammar,
            value["surface_grammar"].as_str().unwrap_or_default(),
            "{name}: the pinned record drifts from the engine's registered vocabulary"
        );
        assert_eq!(
            engine.comparator_family,
            value["comparator_family"].as_str().unwrap_or_default(),
            "{name}: the pinned record drifts from the engine's registered vocabulary"
        );
        count += 1;
    }
    assert!(count >= 4, "the kind corpus must carry the full vocabulary");
}

#[test]
fn every_kind_used_in_valid_fixtures_is_registered() {
    // The vocabulary rule, end to end: a valid fixture's residuals and its
    // comparators' classifiers must name REGISTERED kinds (the reference
    // engine's KIND_SCHEMAS — the protocol vocabulary the corpus pins).
    for entry in fs::read_dir(dir("conformance/valid")).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let source = fs::read_to_string(&path).unwrap();
        let value: Value = canon::parse_strict(source.as_bytes())
            .unwrap_or_else(|e| panic!("{name}: not strict JSON: {e}"));
        for c in value["comparator_semantics"]
            .as_array()
            .cloned()
            .unwrap_or_default()
        {
            let classifier = c["residual_classifier"].as_str().unwrap_or_default();
            assert!(
                frf::model::KIND_SCHEMAS.iter().any(|s| s.id == classifier),
                "{name}: comparator classifier {classifier:?} is not a registered kind"
            );
        }
        for r in value["residuals"].as_array().cloned().unwrap_or_default() {
            let kind = r["kind"].as_str().unwrap_or_default();
            assert!(
                frf::model::KIND_SCHEMAS.iter().any(|s| s.id == kind),
                "{name}: residual kind {kind:?} is not a registered kind"
            );
        }
    }
}

#[test]
fn the_schema_rejects_forbidden_states() {
    // Negative controls for the schema itself: a receipt that structurally
    // deserializes (the corpus validator tolerates nothing) is one thing;
    // the schema must also refuse out-of-domain values.
    let base: Value = serde_json::from_str(
        &fs::read_to_string(dir("conformance/valid/04-minimal.json")).unwrap(),
    )
    .unwrap();
    let mut bad = base.clone();
    bad["run"] = serde_json::json!(42);
    assert!(schema_valid(&bad).is_err(), "number in string slot");
    let mut bad = base.clone();
    bad["residuals"] = serde_json::json!([{"id": "x", "disposition": "closed"}]);
    assert!(schema_valid(&bad).is_err(), "unknown disposition");
    let mut bad = base.clone();
    bad["schema_version"] = serde_json::json!("frf-receipt-v5");
    assert!(schema_valid(&bad).is_err(), "wrong schema version");
    // And the unmutated base must still validate.
    assert!(
        schema_valid(&base).is_ok(),
        "the base fixture must validate"
    );
}
