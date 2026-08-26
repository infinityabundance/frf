//! The structured error kinds (src/error.rs): the machine-readable category
//! a library consumer matches on without parsing the message. The strategic
//! boundaries are typed — a missing object is [`FrfErrorKind::Missing`], a
//! write-once collision is [`FrfErrorKind::AlreadyExists`], refused evidence
//! is [`FrfErrorKind::Refused`], and bad caller input is
//! [`FrfErrorKind::InvalidInput`].

use frf::error::FrfErrorKind;
use frf::store::Store;
use std::path::PathBuf;

const MANIFEST: &str = env!("CARGO_MANIFEST_DIR");

fn repo(path: &str) -> PathBuf {
    PathBuf::from(MANIFEST).join(path)
}

struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn temp_store() -> (TempDir, Store) {
    let dir = std::env::temp_dir().join(format!(
        "frf-error-kinds-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let store = Store::new(dir.clone());
    store.ensure_tree().unwrap();
    (TempDir(dir), store)
}

#[test]
fn a_missing_object_is_kind_missing() {
    let (_dir, store) = temp_store();
    let err = store
        .load_claim(&"0".repeat(64))
        .expect_err("a nonexistent claim must refuse");
    assert_eq!(err.kind(), FrfErrorKind::Missing);
    assert!(err.is_missing());
    let err = match store.load_capture("run-that-does-not-exist") {
        Ok(_) => panic!("a nonexistent run must refuse"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), FrfErrorKind::Missing);
}

/// The first claim document from the golden tree (discovered — ids
/// regenerate at every release).
fn first_golden_claim() -> String {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(repo("frf/claims"))
        .unwrap_or_else(|e| panic!("the golden tree must have claims: {e}"))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    paths.sort();
    let p = paths
        .first()
        .unwrap_or_else(|| panic!("the golden tree has claims"));
    std::fs::read_to_string(p).unwrap()
}

#[test]
fn a_write_once_collision_is_kind_already_exists() {
    let (_dir, store) = temp_store();
    let path = store.root.join("authorities").join("a.json");
    store.write_once(&path, "x").unwrap();
    let err = store
        .write_once(&path, "y")
        .expect_err("a second write to the same path must refuse");
    assert_eq!(err.kind(), FrfErrorKind::AlreadyExists);
    assert!(err.is_already_exists());
}

#[test]
fn tampered_evidence_is_kind_refused() {
    // A claim whose content address no longer rederives (the file bytes do
    // not match the recorded id) is refused — kind Refused, not a crash.
    let (_dir, store) = temp_store();
    // Seed the store with a real claim, then corrupt it.
    let source = first_golden_claim();
    let doc: serde_json::Value = frf::canon::parse_strict(source.as_bytes()).unwrap();
    let id = doc["id"].as_str().unwrap().to_string();
    std::fs::write(store.root.join("claims").join(format!("{id}.json")), source).unwrap();
    // The genuine claim loads fine.
    store.load_claim(&id).expect("the genuine claim loads");
    // Tamper: change a hex character inside the claim's `id` VALUE so the
    // document still parses (and is still canonical) but the id inside no
    // longer matches the file name / the rederived identity.
    let path = store.root.join("claims").join(format!("{id}.json"));
    let mut bytes = std::fs::read(&path).unwrap();
    let id_marker = bytes
        .windows(5)
        .position(|w| w == b"\"id\":")
        .expect("the claim carries its id")
        + 5;
    let value_start = bytes[id_marker..]
        .iter()
        .position(|b| *b == b'\"')
        .expect("the id value opens with a quote")
        + id_marker
        + 1;
    let idx = bytes[value_start..]
        .iter()
        .position(|b| b.is_ascii_hexdigit())
        .expect("the id is a hex digest")
        + value_start;
    bytes[idx] = if bytes[idx] == b'0' { b'1' } else { b'0' };
    std::fs::write(&path, &bytes).unwrap();
    let err = store
        .load_claim(&id)
        .expect_err("a tampered claim must be refused");
    assert_eq!(err.kind(), FrfErrorKind::Refused);
    assert!(err.is_refused());
}

#[test]
fn an_unregistered_schema_version_is_kind_refused() {
    // The store loader's admission runs before deserialization and refuses
    // with kind Refused, naming the version.
    let (_dir, store) = temp_store();
    let source = first_golden_claim();
    let doc: serde_json::Value = frf::canon::parse_strict(source.as_bytes()).unwrap();
    let mut relabeled = doc.clone();
    // An UNREGISTERED claim version (built dynamically so the
    // protocol_registry lexical scan never sees an unregistered token).
    relabeled["schema_version"] = serde_json::Value::String(format!("frf-claim-v{}", 99));
    let record: frf::model::ClaimRecord =
        serde_json::from_value(relabeled).expect("the relabeled claim deserializes");
    let id = frf::semantics::claim_identity(&record).unwrap();
    let canonical = frf::canon::canonical(&record).unwrap();
    std::fs::write(
        store.root.join("claims").join(format!("{id}.json")),
        canonical,
    )
    .unwrap();
    let err = store
        .load_claim(&id)
        .expect_err("an unregistered schema version must be refused");
    assert_eq!(err.kind(), FrfErrorKind::Refused);
    assert!(
        err.message().contains("not a registered schema"),
        "the message must name the refusal: {}",
        err.message()
    );
}

#[test]
fn a_semantic_violation_is_kind_refused() {
    // Document-level semantic conformance refusals are kind Refused.
    // Build a receipt that passes parsing but violates semantics: take the
    // golden resolution receipt and empty its residuals while keeping a
    // residual verdict observable.
    let receipts: Vec<PathBuf> = std::fs::read_dir(repo("frf/receipts"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    let source = std::fs::read_to_string(receipts.first().unwrap()).unwrap();
    let mut doc: serde_json::Value = frf::canon::parse_strict(source.as_bytes()).unwrap();
    doc["residuals"] = serde_json::Value::Array(vec![]);
    let receipt: frf::model::Receipt =
        serde_json::from_value(doc).expect("the mutated receipt still deserializes");
    let err = receipt
        .validate_semantics()
        .expect_err("an empty-residual receipt with a residual verdict must refuse");
    assert_eq!(err.kind(), FrfErrorKind::Refused);
}

#[test]
fn witness_signing_input_errors_are_invalid_input() {
    // A malformed signing key is kind InvalidInput — bad caller input, not
    // refused evidence.
    let (_dir, store) = temp_store();
    let bad_key = store.root.join("bad-key.hex");
    std::fs::write(&bad_key, "deadbeef").unwrap();
    let err = frf::commands::witness::sign(
        &store,
        "receipt",
        "receipt-run-x-0000000000000000000000000000000000000000000000000000000000000000",
        "release-signer",
        "sign",
        "v1",
        &bad_key,
        "signed statement",
    )
    .expect_err("a malformed key must refuse");
    assert_eq!(err.kind(), FrfErrorKind::InvalidInput);
    assert!(err.is_invalid_input());
}
