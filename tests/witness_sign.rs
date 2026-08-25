//! Signatures (spec/witness.md §7): external-key Ed25519 signing of
//! receipts and claims, recorded as signed witness statements and verified
//! by the engine — `frf witness sign` + `frf witness verify`.
//!
//! The signature binds the subject document's EXACT canonical bytes; the
//! statement id commits the public key (via `FRF/ED25519-KEY/v1`), so a
//! signature cannot be re-attributed to a different key or document without
//! changing the statement's content address.

use base64::Engine as _;
use frf::commands::witness;
use frf::store::Store;
use std::path::{Path, PathBuf};

const MANIFEST: &str = env!("CARGO_MANIFEST_DIR");

fn repo(path: &str) -> PathBuf {
    PathBuf::from(MANIFEST).join(path)
}

/// A fixed, deterministic Ed25519 seed (the 32-byte seed as 64 hex
/// characters) for the tests. NOT a secret: it is a test fixture key.
const TEST_KEY_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
/// A second, distinct test key.
const OTHER_KEY_HEX: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap().flatten() {
        let src = entry.path();
        let dst = to.join(entry.file_name());
        if src.is_dir() {
            copy_tree(&src, &dst);
        } else {
            std::fs::copy(&src, &dst).unwrap();
        }
    }
}

/// A temp store seeded with the ENTIRE golden evidence tree (small), so the
/// verified receipt/claim loaders' closures resolve. Dropped at test end.
struct Seeded(PathBuf);

impl Drop for Seeded {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn seeded_store() -> (Seeded, Store, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "frf-witness-sign-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    copy_tree(&repo("frf"), &dir);
    let store = Store::new(dir.clone());
    store.ensure_tree().unwrap();
    (Seeded(dir.clone()), store, dir)
}

fn first_receipt_id() -> String {
    let mut ids: Vec<String> = std::fs::read_dir(repo("frf/receipts"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".json"))
        .collect();
    ids.sort();
    ids.first().unwrap().trim_end_matches(".json").to_string()
}

fn first_claim_id() -> String {
    let mut ids: Vec<String> = std::fs::read_dir(repo("frf/claims"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".json"))
        .collect();
    ids.sort();
    ids.first().unwrap().trim_end_matches(".json").to_string()
}

fn write_key(dir: &Path, hex: &str) -> PathBuf {
    let path = dir.join("signing-key.hex");
    std::fs::write(&path, hex).unwrap();
    path
}

#[test]
fn a_receipt_signs_and_verifies() {
    let (_seeded, store, dir) = seeded_store();
    let receipt = first_receipt_id();
    let key = write_key(&dir, TEST_KEY_HEX);
    let id = witness::sign(
        &store,
        "receipt",
        &receipt,
        "release-signer",
        "sign",
        "v1",
        &key,
        "the release receipt is signed by the release key holder",
    )
    .expect("signing a verified receipt must succeed");
    assert_eq!(id.len(), 64);

    let verdict = witness::verify(&store, &id).expect("the signed statement must verify");
    assert!(
        verdict.contains("signature verified") && verdict.contains("receipt"),
        "the verdict must confirm the signature: {verdict}"
    );
    // The statement exists as canonical evidence with its preserved
    // request/response documents.
    let stmt_path = store.root.join("witnesses").join(format!("{id}.json"));
    assert!(stmt_path.is_file(), "the statement must be recorded");
    for f in ["request.json", "response.json"] {
        assert!(
            store.root.join("witnesses").join(&id).join(f).is_file(),
            "the preserved {f} must be recorded"
        );
    }
    // The request carries the subject's exact canonical bytes (base64).
    let request: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(store.root.join("witnesses").join(&id).join("request.json"))
            .unwrap(),
    )
    .unwrap();
    let canonical = request["subject_canonical"]
        .as_str()
        .expect("the signing request carries the subject's canonical bytes");
    assert!(!canonical.is_empty());
}

#[test]
fn a_claim_signs_and_verifies() {
    let (_seeded, store, dir) = seeded_store();
    let claim = first_claim_id();
    let key = write_key(&dir, TEST_KEY_HEX);
    let id = witness::sign(
        &store,
        "claim",
        &claim,
        "release-signer",
        "sign",
        "v1",
        &key,
        "the claim is signed by the release key holder",
    )
    .expect("signing a verified claim must succeed");

    let verdict = witness::verify(&store, &id).expect("the signed claim statement must verify");
    assert!(
        verdict.contains("signature verified") && verdict.contains("claim"),
        "the verdict must confirm the claim signature: {verdict}"
    );
}

#[test]
fn a_tampered_signature_is_refused() {
    let (_seeded, store, dir) = seeded_store();
    let receipt = first_receipt_id();
    let key = write_key(&dir, TEST_KEY_HEX);
    let id = witness::sign(
        &store,
        "receipt",
        &receipt,
        "release-signer",
        "sign",
        "v1",
        &key,
        "signed statement",
    )
    .unwrap();
    // Flip one byte of the recorded signature VALUE: the statement id no
    // longer rederives (the signature is part of the content address), so
    // the store loader refuses it before any cryptographic check.
    let path = store.root.join("witnesses").join(format!("{id}.json"));
    let mut doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let value = doc["signature"]["value"].as_str().unwrap().to_string();
    let mut bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &value)
        .expect("the recorded value is base64");
    bytes[0] ^= 0x01;
    doc["signature"]["value"] =
        serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(&bytes));
    std::fs::write(&path, frf::canon::canonical(&doc).unwrap()).unwrap();
    let err = witness::verify(&store, &id)
        .expect_err("a tampered signature must be refused at the store loader");
    assert!(
        err.to_string().contains("not content-addressed")
            || err.to_string().contains("does not rederive"),
        "the refusal must name the broken content address: {err}"
    );
}

#[test]
fn a_signature_over_a_different_subject_is_refused() {
    // Sign receipt A, then rewrite the statement to claim subject = a
    // DIFFERENT receipt B (with the statement id recomputed so the document
    // is self-consistent): the subject rebinds to B, and the signature —
    // made over A's exact canonical bytes — fails to verify over B's bytes.
    let (_seeded, store, dir) = seeded_store();
    let mut receipts: Vec<String> = std::fs::read_dir(repo("frf/receipts"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".json"))
        .collect();
    receipts.sort();
    let receipt_a = receipts
        .first()
        .unwrap()
        .trim_end_matches(".json")
        .to_string();
    let receipt_b = receipts
        .get(1)
        .unwrap()
        .trim_end_matches(".json")
        .to_string();
    assert_ne!(receipt_a, receipt_b);

    let key = write_key(&dir, TEST_KEY_HEX);
    let id = witness::sign(
        &store,
        "receipt",
        &receipt_a,
        "release-signer",
        "sign",
        "v1",
        &key,
        "signed statement",
    )
    .unwrap();

    // Rewrite the statement with subject -> receipt B (same key, same
    // signature, same request/response cids) and a recomputed id.
    let path = store.root.join("witnesses").join(format!("{id}.json"));
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let mut rewritten: frf::model::WitnessStatement = serde_json::from_value(doc).unwrap();
    let digest_b = receipt_b
        .strip_prefix("receipt-")
        .and_then(|r| r.rsplit_once('-'))
        .map(|(_, d)| d.to_string())
        .unwrap();
    rewritten.subject = frf::model::WitnessSubject {
        kind: "receipt".to_string(),
        id: receipt_b.clone(),
        cid: digest_b,
    };
    let new_id =
        frf::semantics::witness_statement_identity(&frf::semantics::WitnessStatementContent {
            subject: &rewritten.subject,
            witness_semantic: &rewritten.witness_semantic,
            witness_implementation: &rewritten.witness_implementation,
            witness_identity: &rewritten.witness_identity,
            authority: &rewritten.authority,
            statement: &rewritten.statement,
            attestation: &rewritten.attestation,
            signature: &rewritten.signature,
            request_cid: &rewritten.request_cid,
            response_cid: &rewritten.response_cid,
        })
        .unwrap();
    rewritten.id = new_id.clone();
    let canonical = frf::canon::canonical(&rewritten).unwrap();
    let dir = store.root.join("witnesses");
    std::fs::write(dir.join(format!("{new_id}.json")), &canonical).unwrap();
    // The preserved documents are shared with the original statement
    // (content-addressed: same bytes -> same cids).
    let src_dir = store.root.join("witnesses").join(&id);
    let dst_dir = store.root.join("witnesses").join(&new_id);
    std::fs::create_dir_all(&dst_dir).unwrap();
    for f in ["request.json", "response.json"] {
        std::fs::copy(src_dir.join(f), dst_dir.join(f)).unwrap();
    }

    let err = witness::verify(&store, &new_id)
        .expect_err("a signature over a different subject must be refused");
    // The binding is enforced at two layers: the store loader refuses because
    // the preserved SIGNING REQUEST's subject block no longer matches the
    // statement (the request is the evidence of what was signed), and the
    // cryptographic check would refuse because the signature does not verify
    // over the rebound subject's bytes. Either refusal is the boundary.
    assert!(
        err.to_string().contains("does NOT verify")
            || err.to_string().contains("subject block does not equal"),
        "the refusal must name the failed binding: {err}"
    );
}

#[test]
fn a_misbound_key_identity_is_refused() {
    // Rewrite the statement so its implementation hash commits a DIFFERENT
    // key than the one that signed: the key-identity binding refuses.
    let (_seeded, store, dir) = seeded_store();
    let receipt = first_receipt_id();
    let key = write_key(&dir, TEST_KEY_HEX);
    let id = witness::sign(
        &store,
        "receipt",
        &receipt,
        "release-signer",
        "sign",
        "v1",
        &key,
        "signed statement",
    )
    .unwrap();

    let path = store.root.join("witnesses").join(format!("{id}.json"));
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let mut rewritten: frf::model::WitnessStatement = serde_json::from_value(doc).unwrap();
    // The OTHER key's identity, bound to a statement the OTHER key did not
    // sign.
    let other_pub = {
        let mut seed = [0u8; 32];
        for i in 0..32 {
            seed[i] = u8::from_str_radix(&OTHER_KEY_HEX[i * 2..i * 2 + 2], 16).unwrap();
        }
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().as_bytes())
    };
    let other_key_id = frf::semantics::ed25519_key_identity("ed25519", &other_pub).unwrap();
    rewritten.witness_implementation.implementation_hash = other_key_id;
    let new_id =
        frf::semantics::witness_statement_identity(&frf::semantics::WitnessStatementContent {
            subject: &rewritten.subject,
            witness_semantic: &rewritten.witness_semantic,
            witness_implementation: &rewritten.witness_implementation,
            witness_identity: &rewritten.witness_identity,
            authority: &rewritten.authority,
            statement: &rewritten.statement,
            attestation: &rewritten.attestation,
            signature: &rewritten.signature,
            request_cid: &rewritten.request_cid,
            response_cid: &rewritten.response_cid,
        })
        .unwrap();
    rewritten.id = new_id.clone();
    let canonical = frf::canon::canonical(&rewritten).unwrap();
    let dir = store.root.join("witnesses");
    std::fs::write(dir.join(format!("{new_id}.json")), &canonical).unwrap();
    let src_dir = store.root.join("witnesses").join(&id);
    let dst_dir = store.root.join("witnesses").join(&new_id);
    std::fs::create_dir_all(&dst_dir).unwrap();
    for f in ["request.json", "response.json"] {
        std::fs::copy(src_dir.join(f), dst_dir.join(f)).unwrap();
    }

    let err = witness::verify(&store, &new_id).expect_err(
        "a statement whose key identity does not commit the signing key must be refused",
    );
    assert!(
        err.to_string().contains("does not commit"),
        "the refusal must name the key-identity binding: {err}"
    );
}

#[test]
fn key_file_format_errors_are_refused() {
    let (_seeded, store, dir) = seeded_store();
    let receipt = first_receipt_id();
    // Missing file.
    let err = witness::sign(
        &store,
        "receipt",
        &receipt,
        "release-signer",
        "sign",
        "v1",
        &dir.join("no-such-key.hex"),
        "signed statement",
    )
    .expect_err("a missing key file must refuse");
    assert!(err.to_string().contains("cannot read the signing key"));
    // Wrong length.
    let bad = dir.join("bad-length.hex");
    std::fs::write(&bad, "deadbeef").unwrap();
    let err = witness::sign(
        &store,
        "receipt",
        &receipt,
        "release-signer",
        "sign",
        "v1",
        &bad,
        "signed statement",
    )
    .expect_err("a wrong-length key must refuse");
    assert!(err.to_string().contains("64 hex characters"));
    // Non-hex characters.
    let bad = dir.join("bad-hex.hex");
    std::fs::write(&bad, "zz".repeat(32)).unwrap();
    let err = witness::sign(
        &store,
        "receipt",
        &receipt,
        "release-signer",
        "sign",
        "v1",
        &bad,
        "signed statement",
    )
    .expect_err("a non-hex key must refuse");
    assert!(err.to_string().contains("64 hex characters"));
    // An unsupported subject kind refuses before the key is read.
    let key = write_key(&dir, TEST_KEY_HEX);
    let err = witness::sign(
        &store,
        "run",
        &receipt,
        "release-signer",
        "sign",
        "v1",
        &key,
        "signed statement",
    )
    .expect_err("run is not a signable document");
    assert!(err.to_string().contains("receipt or claim"));
}

#[test]
fn a_plain_attestation_statement_verifies_without_a_signature() {
    // The golden tree's attestation statements (produced by the demo's
    // witness program) must verify through the same command — an attestation
    // carries no signature, and the verdict says so.
    let (_seeded, store, _dir) = seeded_store();
    let witnesses: Vec<String> = std::fs::read_dir(store.root.join("witnesses"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".json"))
        .collect();
    assert!(!witnesses.is_empty(), "the golden tree has attestations");
    let mut verified_any = false;
    for w in witnesses {
        let id = w.trim_end_matches(".json").to_string();
        if let Ok(verdict) = witness::verify(&store, &id) {
            assert!(
                verdict.contains("verified"),
                "the verdict must say verified: {verdict}"
            );
            verified_any = true;
        }
    }
    assert!(verified_any, "at least one golden attestation must verify");
}
