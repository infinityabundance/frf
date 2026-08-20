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
//! Generator mode (used to refresh the pins after a schema change):
//!   FRF_CONFORM_PRINT=1 cargo test --test conformance -- --nocapture
//! prints `name<TAB>canonical<TAB>sha256` per valid fixture.

use frf::canon;
use frf::host;
use frf::model::Receipt;
use std::fs;
use std::path::PathBuf;

fn dir(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn schema() -> serde_json::Value {
    serde_json::from_str(
        &fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("spec/openreceipt.schema.json"),
        )
        .expect("spec/openreceipt.schema.json must exist"),
    )
    .expect("the schema must be valid JSON")
}

#[test]
fn valid_fixtures_parse_canonicalize_and_hash_to_the_pinned_values() {
    let compiled = jsonschema::validator_for(&schema()).expect("schema must compile");
    let mut count = 0;
    let print = std::env::var("FRF_CONFORM_PRINT").is_ok();
    for entry in fs::read_dir(dir("conformance/valid")).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let source = fs::read_to_string(&path).unwrap();

        // Must parse as JSON and deserialize into the schema.
        let value: serde_json::Value =
            serde_json::from_str(&source).unwrap_or_else(|e| panic!("{name}: not valid JSON: {e}"));
        let _receipt: Receipt = serde_json::from_value(value.clone())
            .unwrap_or_else(|e| panic!("{name}: does not deserialize as an OpenReceipt: {e}"));

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
        // The schema validates the canonical form too.
        if let Err(e) =
            compiled.validate(&serde_json::from_str::<serde_json::Value>(&canonical).unwrap())
        {
            panic!("{name}: fails the OpenReceipt schema: {e}");
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
        // Either the JSON is malformed, or it does not deserialize as an
        // OpenReceipt (schema version enforced, fields required, enums
        // closed). Both are refusals.
        let refused = serde_json::from_str::<serde_json::Value>(&source)
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
fn the_schema_rejects_forbidden_states() {
    // Negative controls for the schema itself: a receipt that structurally
    // deserializes (the corpus validator tolerates nothing) is one thing;
    // the schema must also refuse out-of-domain values.
    let compiled = jsonschema::validator_for(&schema()).unwrap();
    let base: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(dir("conformance/valid/04-minimal.json")).unwrap(),
    )
    .unwrap();
    let mut bad = base.clone();
    bad["run"] = serde_json::json!(42);
    assert!(!compiled.is_valid(&bad), "number in string slot");
    let mut bad = base.clone();
    bad["residuals"] = serde_json::json!([{"id": "x", "disposition": "closed"}]);
    assert!(!compiled.is_valid(&bad), "unknown disposition");
    let mut bad = base.clone();
    bad["schema_version"] = serde_json::json!("frf-receipt-v5");
    assert!(!compiled.is_valid(&bad), "wrong schema version");
}
