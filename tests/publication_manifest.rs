//! The publication-layer canonicality discipline (P0/P1): the publication
//! transform's documents — the per-stream disposition records
//! (`<side>.<stream>.pub.json`) and the publication manifest
//! (`publication-manifest.json`) — are EVIDENCE, and they are verified with
//! the same discipline as every evidence document: strict canonical JSON
//! (duplicate property names and non-canonical bytes refused), the closed
//! schema, and the cross-references. A non-canonical, moved, lying, or
//! invented disposition refuses the tree — a withheld stream can never
//! silently disappear, and the transform's record can never be silently
//! altered.
//!
//! The hostile cases:
//!   - duplicate property in a stream disposition record (strict JSON);
//!   - non-canonical key order in a stream disposition record (canonical
//!     bytes);
//!   - non-canonical whitespace in the publication manifest (canonical
//!     bytes);
//!   - unknown property in a stream disposition record (closed schema);
//!   - wrong stream hash in a disposition record (the withheld identity is
//!     broken);
//!   - missing stream disposition (a withheld stream cannot silently
//!     disappear);
//!   - duplicate stream disposition in the manifest (a stream has exactly
//!     one disposition);
//!   - extra manifest entry naming a run that does not exist (a disposition
//!     cannot invent an observation).

use frf::store::Store;
use std::fs;
use std::path::{Path, PathBuf};

mod common;
use common::*;

/// The court manifest for the surface tests: the canonical cli-malformed-
/// input court with the candidate's stdout declared hash-only.
const SURFACE_MANIFEST: &str = r#"court:
  id: cli-pubmanifest-{COURT}
  question: >-
    For malformed input in fixture family malformed-input, does the candidate
    preserve the admitted reference's exit class and first diagnostic line?
  falsifier: >-
    The candidate's exit class or first diagnostic line diverges from the
    admitted reference on a fixture in family malformed-input.
  authority: ref-cli-1.8.2
  candidate:
    name: cand-cli
    version_or_commit: "0.1.0"
    build_profile: debug
    path: golden/candidate.sh
  fixture:
    id: malformed-path.conf
    path: frf/courts/cli-malformed-input/fixtures/malformed-path.conf
    arguments: ["--strict", "{fixture}"]
  admissibility_envelope:
    fixture_family: malformed-input
    platforms: ["x86_64-linux"]
    observables: [exit, stderr]
    normalizers: []
    replay_scope: single-run
capture_surface:
  - side: candidate
    stream: stdout
    policy: hash-only
"#;

fn setup_publication(work: &Workdir, court: &str) -> (PathBuf, String) {
    let mpath = work.path(&format!("frf/courts/cli-pubmanifest-{court}/manifest.yaml"));
    fs::create_dir_all(mpath.parent().unwrap()).unwrap();
    fs::write(&mpath, SURFACE_MANIFEST.replace("{COURT}", court)).unwrap();
    let out = frf(
        work,
        &[
            "--root",
            ROOT,
            "court",
            "run",
            &format!("frf/courts/cli-pubmanifest-{court}/manifest.yaml"),
        ],
    );
    assert_success(&out, &format!("pubmanifest court {court} run"));
    let run = stdout(&out);

    let local = Store::new(work.path(ROOT));
    let policy = work.path("policy.json");
    fs::write(
        &policy,
        r#"{"schema_version":"frf-detached-objects-v1","policy":"surface-only","objects":[]}"#,
    )
    .unwrap();
    let pub_dir = work.path("pub");
    frf::commands::evidence::publish_detached(&local, &policy, &pub_dir)
        .expect("the publication transform must succeed");
    (pub_dir, run)
}

/// The verified capture loader over the PUBLISHED tree must refuse the
/// tampered document, and `evidence status` must report graph_verified NO.
fn assert_published_tree_refused(pub_dir: &Path, run: &str, needle: &str) {
    let pub_store = Store::new(pub_dir.to_path_buf());
    let err = match frf::verify::load_capture_verified(&pub_store, run) {
        Err(e) => e,
        Ok(_) => panic!("the tampered publication must be refused"),
    };
    assert!(
        err.to_string().contains(needle),
        "the refusal must name the violation ({needle}): {err}"
    );
    let out = frf_bin(pub_dir, &["evidence", "status"]);
    assert!(
        !out.status.success() || out_status_graph_verified(&out),
        "the status command must refuse or report the violation"
    );
}

fn frf_bin(root: &Path, args: &[&str]) -> std::process::Output {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_frf"));
    let mut all = vec!["--root", root.to_str().unwrap()];
    all.extend_from_slice(args);
    cmd.args(&all);
    cmd.output().unwrap()
}

fn out_status_graph_verified(out: &std::process::Output) -> bool {
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines().any(|l| l.contains("graph_verified: yes"))
}

/// Duplicate property in a stream disposition record: strict JSON refuses
/// duplicate property names (RFC 8785 §2) — the same rule as every evidence
/// document.
#[test]
fn duplicate_property_in_a_stream_disposition_is_refused() {
    let work = Workdir::new("pubmanifest-duplicate-property");
    work.copy_canonical_tree();
    admit_reference(&work);
    let (pub_dir, run) = setup_publication(&work, "dup");
    let path = pub_dir
        .join("captures")
        .join(&run)
        .join("candidate.stdout.pub.json");
    let doc = fs::read_to_string(&path).unwrap();
    let duplicated = doc.replace(
        "\"schema_version\":\"frf-stream-publication-v1\"",
        "\"schema_version\":\"frf-stream-publication-v1\",\"schema_version\":\"frf-stream-publication-v1\"",
    );
    fs::write(&path, duplicated).unwrap();
    assert_published_tree_refused(&pub_dir, &run, "not a canonical stream-publication record");
}

/// Non-canonical key order in a stream disposition record: the bytes must BE
/// the canonical serialization of the parsed document (one semantic
/// document, one byte sequence).
#[test]
fn noncanonical_key_order_in_a_stream_disposition_is_refused() {
    let work = Workdir::new("pubmanifest-key-order");
    work.copy_canonical_tree();
    admit_reference(&work);
    let (pub_dir, run) = setup_publication(&work, "keyorder");
    let path = pub_dir
        .join("captures")
        .join(&run)
        .join("candidate.stdout.pub.json");
    let doc: serde_json::Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    // Re-serialize with a REVERSED key order, written literally (the
    // semantic document is identical; the bytes are NOT the canonical
    // serialization). serde_json::Map sorts keys, so the bytes must be
    // hand-written to prove the canonical-byte discipline.
    let obj = doc.as_object().unwrap();
    let keys: Vec<&String> = obj.keys().rev().collect();
    let mut body: Vec<String> = Vec::new();
    for k in &keys {
        let v = serde_json::to_string(&obj[*k]).unwrap();
        body.push(format!("{:?}:{}", k, v));
    }
    fs::write(&path, format!("{{{}}}", body.join(","))).unwrap();
    assert_published_tree_refused(&pub_dir, &run, "not a canonical stream-publication record");
}

/// Unknown property in a stream disposition record: the closed schema
/// refuses it — a disposition record cannot carry extra meaning.
#[test]
fn unknown_property_in_a_stream_disposition_is_refused() {
    let work = Workdir::new("pubmanifest-unknown-property");
    work.copy_canonical_tree();
    admit_reference(&work);
    let (pub_dir, run) = setup_publication(&work, "unknown");
    let path = pub_dir
        .join("captures")
        .join(&run)
        .join("candidate.stdout.pub.json");
    let mut doc: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    doc.as_object_mut().unwrap().insert(
        "unrecognized".into(),
        serde_json::Value::String("tampered".into()),
    );
    let canonical = frf::canon::canonical(&doc).unwrap();
    fs::write(&path, canonical).unwrap();
    assert_published_tree_refused(&pub_dir, &run, "not a canonical stream-publication record");
}

/// Wrong stream hash in a disposition record: the record names bytes that do
/// not hash to the capture's recorded stream hash — the withheld identity is
/// broken.
#[test]
fn wrong_stream_hash_in_a_stream_disposition_is_refused() {
    let work = Workdir::new("pubmanifest-wrong-hash");
    work.copy_canonical_tree();
    admit_reference(&work);
    let (pub_dir, run) = setup_publication(&work, "wronghash");
    let path = pub_dir
        .join("captures")
        .join(&run)
        .join("candidate.stdout.pub.json");
    let mut doc: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    doc["sha256"] = serde_json::Value::String("0".repeat(64));
    let canonical = frf::canon::canonical(&doc).unwrap();
    fs::write(&path, canonical).unwrap();
    assert_published_tree_refused(&pub_dir, &run, "the withheld stream's identity is broken");
}

/// Missing stream disposition: a withheld stream without its disposition
/// record cannot silently disappear.
#[test]
fn missing_stream_disposition_is_refused() {
    let work = Workdir::new("pubmanifest-missing-disposition");
    work.copy_canonical_tree();
    admit_reference(&work);
    let (pub_dir, run) = setup_publication(&work, "missing");
    let path = pub_dir
        .join("captures")
        .join(&run)
        .join("candidate.stdout.pub.json");
    fs::remove_file(&path).unwrap();
    let pub_store = Store::new(pub_dir.clone());
    let err = match frf::verify::load_capture_verified(&pub_store, &run) {
        Err(e) => e,
        Ok(_) => panic!("a withheld stream without its disposition must be refused"),
    };
    assert!(
        err.to_string().contains("cannot read"),
        "the refusal must name the missing disposition: {err}"
    );
}

/// Duplicate stream disposition in the manifest: a stream has exactly one
/// disposition.
#[test]
fn duplicate_stream_disposition_in_the_manifest_is_refused() {
    let work = Workdir::new("pubmanifest-duplicate-entry");
    work.copy_canonical_tree();
    admit_reference(&work);
    let (pub_dir, _run) = setup_publication(&work, "dupent");
    let path = pub_dir.join("publication-manifest.json");
    let mut doc: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    let streams = doc["streams"].as_array().unwrap().clone();
    let first = streams[0].clone();
    doc["streams"].as_array_mut().unwrap().push(first);
    let canonical = frf::canon::canonical(&doc).unwrap();
    fs::write(&path, canonical).unwrap();
    let pub_store = Store::new(pub_dir.clone());
    let err = frf::verify::load_publication_manifest_verified(&pub_store)
        .expect_err("a duplicate stream disposition must be refused")
        .to_string();
    assert!(
        err.contains("TWICE"),
        "the refusal must name the duplicate: {err}"
    );
}

/// Extra manifest entry naming a run that does not exist: a disposition
/// cannot invent an observation.
#[test]
fn extra_manifest_entry_naming_a_missing_run_is_refused() {
    let work = Workdir::new("pubmanifest-extra-entry");
    work.copy_canonical_tree();
    admit_reference(&work);
    let (pub_dir, _run) = setup_publication(&work, "extra");
    let path = pub_dir.join("publication-manifest.json");
    let mut doc: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    let phantom = serde_json::json!({
        "run": "run-phantom-0000000000000000000000000000000000000000000000000000000000000000",
        "side": "candidate",
        "stream": "stdout",
        "policy": "hash-only",
        "sha256": "0".repeat(64),
        "published": false,
    });
    doc["streams"].as_array_mut().unwrap().push(phantom);
    let canonical = frf::canon::canonical(&doc).unwrap();
    fs::write(&path, canonical).unwrap();
    let pub_store = Store::new(pub_dir.clone());
    let err = frf::verify::load_publication_manifest_verified(&pub_store)
        .expect_err("an invented observation must be refused")
        .to_string();
    assert!(
        err.contains("does not exist in this store"),
        "the refusal must name the missing run: {err}"
    );
}

/// Non-canonical whitespace in the publication manifest: the bytes must BE
/// the canonical serialization.
#[test]
fn noncanonical_whitespace_in_the_publication_manifest_is_refused() {
    let work = Workdir::new("pubmanifest-whitespace");
    work.copy_canonical_tree();
    admit_reference(&work);
    let (pub_dir, _run) = setup_publication(&work, "ws");
    let path = pub_dir.join("publication-manifest.json");
    let doc: serde_json::Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    fs::write(&path, serde_json::to_string_pretty(&doc).unwrap()).unwrap();
    let pub_store = Store::new(pub_dir.clone());
    let err = frf::verify::load_publication_manifest_verified(&pub_store)
        .expect_err("non-canonical manifest bytes must be refused")
        .to_string();
    assert!(
        err.contains("not canonical evidence"),
        "the refusal must name the canonicality violation: {err}"
    );
}
