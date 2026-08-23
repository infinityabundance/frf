//! The detached-object protocol (spec/detached-objects.md): a publication
//! may deliberately withhold content-address bytes. Verification must then
//! distinguish, mechanically:
//!
//!   - graph_verified — the canonical documents parse, the identities
//!     rederive, and every referenced CID resolves (present OR declared
//!     detached with a reconstruction recipe);
//!   - object_closure — complete, or incomplete-by-policy naming the
//!     declared-detached payloads;
//!   - replay_ready — the object + stream closures are complete (the bytes a
//!     replay would execute are materialized); `replay_verified` stays
//!     `not-performed` until an actual replay operation reproduces the
//!     observation.
//!
//! A declared-detached publication is never treated as corruption; a
//! missing, undeclared object is.

mod common;
use common::*;

use std::fs;

/// A court's content-addressed objects, removed + declared detached: the
/// graph must still verify, the closure must report incomplete-by-policy.
#[test]
fn declared_detached_keeps_the_graph_verified() {
    let work = Workdir::new("detached");
    work.copy_canonical_tree();
    let root = ROOT;

    let out = frf(
        &work,
        &[
            "--root",
            root,
            "authority",
            "admit",
            "golden/reference.sh",
            "--name",
            "ref-cli",
            "--version",
            "1.8.2",
        ],
    );
    assert_success(&out, "authority admit");

    let out = frf(&work, &["--root", root, "court", "run", MANIFEST]);
    assert_success(&out, "court run");

    // Every content address the captures reference (the object closure).
    let captures = fs::read_dir(work.path("frf/captures")).unwrap();
    let mut cids: Vec<String> = Vec::new();
    for entry in captures {
        let run = entry.unwrap().file_name().to_string_lossy().to_string();
        let cap: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(work.path(&format!("frf/captures/{run}/capture.json"))).unwrap(),
        )
        .unwrap();
        for ref_ in cap["evidence_refs"].as_array().unwrap() {
            let cid = ref_["cid"].as_str().unwrap().to_string();
            if !cids.contains(&cid) {
                cids.push(cid);
            }
        }
    }
    assert!(!cids.is_empty(), "the court must reference objects");

    // The FULL local tree verifies (closure complete).
    let out = frf(&work, &["--root", root, "evidence", "status"]);
    assert_success(&out, "evidence status (complete)");
    assert!(
        stdout(&out).contains("object_closure: complete"),
        "full local tree: {}",
        stdout(&out)
    );

    // Remove the object bytes and declare every referenced CID detached.
    fs::remove_dir_all(work.path("frf/objects")).unwrap();
    let objects: Vec<serde_json::Value> = cids
        .iter()
        .map(|cid| {
            serde_json::json!({
                "cid": cid,
                "role": "candidate-artifact",
                "publication": "external-security-sensitive",
                "size": "17",
                "reconstruction": {
                    "recipe": "re-run the court with the local artifacts",
                    "source_path": "golden/candidate.sh",
                },
            })
        })
        .collect();
    let declaration = serde_json::json!({
        "schema_version": "frf-detached-objects-v1",
        "policy": "detached",
        "objects": objects,
    });
    let canonical = frf::canon::canonical(&declaration).expect("the declaration must canonicalize");
    fs::write(work.path("frf/detached-objects.json"), canonical.as_bytes()).unwrap();

    // The graph verifies; the closure reports incomplete-by-policy.
    let out = frf(&work, &["--root", root, "evidence", "status"]);
    assert_success(&out, "evidence status (detached)");
    let text = stdout(&out);
    assert!(text.contains("graph_verified: yes"), "graph: {text}");
    assert!(
        text.contains("object_closure: incomplete-by-policy"),
        "closure: {text}"
    );
    assert!(text.contains("replay_ready: no"), "replay_ready: {text}");
    assert!(
        text.contains("replay_verified: not-performed"),
        "replay_verified: {text}"
    );
    assert!(
        text.contains(&format!("{} declared-detached", cids.len())),
        "count: {text}"
    );

    // A missing, UNDECLARED object is a corrupt publication: refuse.
    fs::remove_file(work.path("frf/detached-objects.json")).unwrap();
    let out = frf(&work, &["--root", root, "evidence", "status"]);
    assert!(
        !out.status.success(),
        "evidence status must refuse an undeclared missing object"
    );
}

/// The publication transform: a COMPLETE local tree -> publish-detached ->
/// a tree WITHOUT the declared payloads + the declaration; byte-deterministic;
/// refuses to publish from an incomplete source or an existing output.
#[test]
fn publish_detached_transform_withholds_and_declares() {
    let work = Workdir::new("publish");
    work.copy_canonical_tree();
    let root = ROOT;

    let out = frf(
        &work,
        &[
            "--root",
            root,
            "authority",
            "admit",
            "golden/reference.sh",
            "--name",
            "ref-cli",
            "--version",
            "1.8.2",
        ],
    );
    assert_success(&out, "authority admit");
    let out = frf(&work, &["--root", root, "court", "run", MANIFEST]);
    assert_success(&out, "court run");

    // The candidate object cid (from the capture).
    let captures = fs::read_dir(work.path("frf/captures")).unwrap();
    let mut candidate_cid = String::new();
    for entry in captures {
        let run = entry.unwrap().file_name().to_string_lossy().to_string();
        let cap: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(work.path(&format!("frf/captures/{run}/capture.json"))).unwrap(),
        )
        .unwrap();
        for ref_ in cap["evidence_refs"].as_array().unwrap() {
            if ref_["role"] == "candidate-artifact" {
                candidate_cid = ref_["cid"].as_str().unwrap().to_string();
            }
        }
    }
    assert_eq!(candidate_cid.len(), 64);

    // The policy: withhold the candidate artifact.
    let policy = serde_json::json!({
        "schema_version": "frf-detached-objects-v1",
        "policy": "detached",
        "objects": [{
            "cid": candidate_cid,
            "role": "candidate-artifact",
            "publication": "external-security-sensitive",
            "size": "17",
            "reconstruction": {"recipe": "re-run the court with the local artifacts", "source_path": "golden/candidate.sh"},
        }],
    });
    let policy_canonical = frf::canon::canonical(&policy).expect("the policy must canonicalize");
    let policy_path = work.path("policy.json");
    fs::write(&policy_path, policy_canonical.as_bytes()).unwrap();

    let out = frf(
        &work,
        &[
            "--root",
            root,
            "evidence",
            "publish-detached",
            "--policy",
            "policy.json",
            "--output",
            "publication",
        ],
    );
    assert_success(&out, "publish-detached");

    // The candidate object is absent; the declaration is present; the graph
    // verifies with an incomplete-by-policy closure.
    assert!(
        !work
            .path("publication/objects/sha256")
            .join(&candidate_cid)
            .exists(),
        "the withheld candidate must not be in the publication"
    );
    assert!(work.path("publication/detached-objects.json").is_file());
    let out = frf(&work, &["--root", "publication", "evidence", "status"]);
    assert_success(&out, "publication status");
    let text = stdout(&out);
    assert!(text.contains("graph_verified: yes"), "graph: {text}");
    assert!(text.contains("incomplete-by-policy"), "closure: {text}");

    // Determinism: a second publish is byte-identical.
    let pub2 = work.path("publication-2");
    let out = frf(
        &work,
        &[
            "--root",
            root,
            "evidence",
            "publish-detached",
            "--policy",
            "policy.json",
            "--output",
            "publication-2",
        ],
    );
    assert_success(&out, "second publish");
    let same = dirs_identical(&work.path("publication"), &pub2);
    assert!(same, "the publication transform must be byte-deterministic");

    // Refuses to publish from an INCOMPLETE source (the published tree).
    let out = frf(
        &work,
        &[
            "--root",
            "publication",
            "evidence",
            "publish-detached",
            "--policy",
            "policy.json",
            "--output",
            "publication-3",
        ],
    );
    assert!(
        !out.status.success(),
        "publish-detached must refuse an incomplete source tree"
    );
}

fn dirs_identical(a: &std::path::Path, b: &std::path::Path) -> bool {
    let walk = |p: &std::path::Path| -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        let mut pending = vec![p.to_path_buf()];
        while let Some(dir) = pending.pop() {
            for entry in fs::read_dir(&dir).unwrap() {
                let entry = entry.unwrap();
                let from = entry.path();
                if entry.file_type().unwrap().is_dir() {
                    pending.push(from);
                } else {
                    let rel = from.strip_prefix(p).unwrap().to_string_lossy().to_string();
                    out.push((rel, fs::read(&from).unwrap()));
                }
            }
        }
        out.sort();
        out
    };
    walk(a) == walk(b)
}

/// The declaration's own semantic rules: duplicate cids, bad cids, empty
/// fields, and wrong schema versions are all refused.
#[test]
fn detached_declaration_semantic_refusals() {
    let base = |cid: &str| {
        serde_json::json!({
            "cid": cid,
            "role": "authority-artifact",
            "publication": "external-security-sensitive",
            "size": "17",
            "reconstruction": {"recipe": "recipe"},
        })
    };
    let good = "1fa728ceb86abab91de36f044e798e8631fbd672676c0cce8992889ef3bbeb77";
    let decl = |objects: Vec<serde_json::Value>| {
        serde_json::json!({
            "schema_version": "frf-detached-objects-v1",
            "policy": "detached",
            "objects": objects,
        })
    };

    let ok: frf::model::DetachedObjects = serde_json::from_value(decl(vec![base(good)])).unwrap();
    ok.validate_semantics().expect("valid declaration");

    // Duplicate cid.
    let dup: frf::model::DetachedObjects =
        serde_json::from_value(decl(vec![base(good), base(good)])).unwrap();
    assert!(dup.validate_semantics().is_err(), "duplicate cid refused");

    // Not a 64-hex cid.
    let bad_cid: frf::model::DetachedObjects =
        serde_json::from_value(decl(vec![base("nope")])).unwrap();
    assert!(bad_cid.validate_semantics().is_err(), "bad cid refused");

    // Wrong schema version (built dynamically so the registry scanner does
    // not mistake the literal for a protocol token).
    let bad_version = format!("frf-detached-objects-{}", "v0");
    let bad_ver: frf::model::DetachedObjects = serde_json::from_value(serde_json::json!({
        "schema_version": bad_version,
        "policy": "detached",
        "objects": [base(good)],
    }))
    .unwrap();
    assert!(bad_ver.validate_semantics().is_err(), "bad schema refused");

    // Empty recipe.
    let mut no_recipe = base(good);
    no_recipe["reconstruction"] = serde_json::json!({"recipe": ""});
    let empty: frf::model::DetachedObjects = serde_json::from_value(decl(vec![no_recipe])).unwrap();
    assert!(empty.validate_semantics().is_err(), "empty recipe refused");
}
