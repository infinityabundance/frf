//! The SYSTEMATIC EVIDENCE-GRAPH MUTATION sweep: for every content-addressed
//! object in a real bundle, apply each structurally plausible mutation and
//! assert the verifier REFUSES before semantic consumption — even when the
//! attacker FIXES the manifest (recomputing the mutated file's hash), so the
//! identity/derivation checks — not the manifest inventory — must catch it.
//!
//! Canonical evidence has essentially NO irrelevant representation change:
//! every mutation below must be refused, with the manifest hash check
//! removed as the hiding place.

use frf::host::sha256_bytes;
use std::fs;
use std::path::Path;

mod common;
use common::*;

fn golden_to_claimable(work: &Workdir) -> String {
    admit_reference(work);
    let _run = run_court(work);
    let resolution_run = run_resolution_court(work);
    let out = frf(
        work,
        &[
            "--root",
            ROOT,
            "residual",
            "dispose",
            "cli-exit-0001",
            "--disposition",
            "fixed",
            "--resolution-run",
            &resolution_run,
            "--reason",
            "candidate patched to preserve reference exit class",
        ],
    );
    assert_success(&out, "dispose exit fixed");
    for (id, reason) in [
        ("cli-text-0001", "documented divergence"),
        ("cli-text-0002", "documented divergence"),
    ] {
        let out = frf(
            work,
            &[
                "--root",
                ROOT,
                "residual",
                "dispose",
                id,
                "--disposition",
                "intentional",
                "--reason",
                reason,
            ],
        );
        assert_success(&out, &format!("dispose {id}"));
    }
    let out = frf(work, &["--root", ROOT, "receipt", "emit", &resolution_run]);
    assert_success(&out, "receipt emit");
    let receipt = stdout(&out);
    let out = frf(work, &["--root", ROOT, "claim", "compile", &receipt]);
    assert_success(&out, "claim compile");
    receipt
}

/// Rewrite the bundle manifest with a NEW hash for one entry — the hostile
/// attacker fixing the inventory so the mutation is not caught by the
/// manifest check.
fn remanifest(bundle: &Path, rel: &str) {
    let manifest_path = bundle.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    let bytes = fs::read(bundle.join(rel)).unwrap();
    let new_hash = sha256_bytes(&bytes);
    let mut updated = false;
    for item in manifest["inventory"].as_array_mut().unwrap() {
        if item["path"] == rel {
            item["sha256"] = serde_json::json!(new_hash);
            updated = true;
        }
    }
    assert!(updated, "manifest must cover {rel}");
    let canonical = frf::canon::encode(&manifest).unwrap();
    fs::write(&manifest_path, canonical).unwrap();
}

/// Mutate one bundle file and assert `frf bundle verify` REFUSES — with the
/// manifest re-hashed, so the refusal comes from the evidence itself.
fn assert_mutation_refused(work: &Workdir, rel: &str, mutate: impl Fn(&Path)) {
    // A fresh copy of the bundle per mutation.
    let scratch = work.path("mut-scratch");
    let _ = fs::remove_dir_all(&scratch);
    fs::create_dir_all(&scratch).unwrap();
    copy_tree(&work.path("mut-base"), &scratch);
    let target = scratch.join(rel);
    assert!(
        target.is_file(),
        "mutation target {rel} must exist in the bundle"
    );
    // Sealed bundle files are 0444 — chmod first (the hostile actor would).
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
    mutate(&target);
    remanifest(&scratch, rel);
    let out = frf(work, &["bundle", "verify", "mut-scratch"]);
    assert!(
        !out.status.success(),
        "mutation of {rel} MUST be refused (stderr: {})",
        stderr(&out)
    );
}

fn copy_tree(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if from.is_dir() {
            copy_tree(&from, &to);
        } else {
            fs::copy(&from, &to).unwrap();
        }
    }
}

/// The bundle's evidence files (every content-addressed object class).
fn evidence_files(bundle: &Path) -> Vec<String> {
    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(bundle.join("manifest.json")).unwrap()).unwrap();
    manifest["inventory"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["path"].as_str().unwrap().to_string())
        .filter(|rel| {
            !rel.ends_with("manifest.json")
                && !rel.contains("/produced/")
                && !rel.ends_with("capture.json")
        })
        .collect()
}

#[test]
fn every_mutation_is_refused_with_the_manifest_fixed() {
    let work = Workdir::new("graph-mutation");
    work.copy_canonical_tree();
    let receipt = golden_to_claimable(&work);
    let out = frf(
        &work,
        &[
            "--root", ROOT, "bundle", "export", &receipt, "--output", "mut-base",
        ],
    );
    assert_success(&out, "bundle export");
    let bundle = work.path("mut-base");

    // 1. Byte flips at projection-AFFECTING offsets in every evidence file
    //    (byte 0 of everything; the middle byte for files whose projection
    //    is hash-bound — stdout/stderr/JSON — but NOT the whitespace-trimmed
    //    text projections (exit/first-line), where a trailing-newline flip
    //    is the one legitimate accepted-with-identical-semantics case).
    let trim_projection = |rel: &str| {
        rel.ends_with(".exit.txt")
            || rel.ends_with("_first_line.txt")
            || rel.ends_with("first_line.txt")
    };
    for rel in evidence_files(&bundle) {
        for offset in [0usize, 1] {
            if offset == 1 && trim_projection(&rel) {
                continue;
            }
            assert_mutation_refused(&work, &rel, move |p| {
                let mut bytes = fs::read(p).unwrap();
                let idx = if offset == 0 { 0 } else { bytes.len() / 2 };
                let idx = idx.min(bytes.len().saturating_sub(1));
                bytes[idx] ^= 0x01;
                fs::write(p, &bytes).unwrap();
            });
        }
    }

    // 2. Truncation of every evidence file (except the whitespace-trimmed
    //    text projections, where dropping the trailing newline is identical
    //    semantics — the projection is unchanged).
    for rel in evidence_files(&bundle) {
        if trim_projection(&rel) {
            continue;
        }
        assert_mutation_refused(&work, &rel, |p| {
            let bytes = fs::read(p).unwrap();
            let cut = bytes.len().saturating_sub(1).max(1);
            fs::write(p, &bytes[..cut]).unwrap();
        });
    }

    // 3. Non-canonical re-encode (whitespace) of every JSON evidence file.
    for rel in evidence_files(&bundle) {
        if !rel.ends_with(".json") {
            continue;
        }
        assert_mutation_refused(&work, &rel, |p| {
            let value: serde_json::Value = serde_json::from_slice(&fs::read(p).unwrap()).unwrap();
            fs::write(p, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        });
    }

    // 4. Duplicate-key injection into a receipt (RFC 8785 I-JSON: a document
    //    with a repeated property name is refused).
    let receipt_rel = {
        let mut found = String::new();
        for rel in evidence_files(&bundle) {
            if rel.starts_with("receipts/") {
                found = rel;
            }
        }
        found
    };
    assert!(!receipt_rel.is_empty(), "the bundle must carry a receipt");
    assert_mutation_refused(&work, &receipt_rel, |p| {
        let bytes = fs::read(p).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        // Duplicate the "run" key at the start of the object.
        let dup = format!("{{\"run\":\"x\",{}}}", &text[1..]);
        fs::write(p, dup).unwrap();
    });
}

/// A DELETED object the closure references (with the manifest fixed) is
/// refused: the bundle is incomplete — the closure walk demands the file.
#[test]
fn deleting_referenced_evidence_is_refused() {
    let work = Workdir::new("graph-deletion");
    work.copy_canonical_tree();
    let receipt = golden_to_claimable(&work);
    let out = frf(
        &work,
        &[
            "--root", ROOT, "bundle", "export", &receipt, "--output", "mut-base",
        ],
    );
    assert_success(&out, "bundle export");

    // Delete one residual record the receipt references.
    let scratch = work.path("del-scratch");
    let _ = fs::remove_dir_all(&scratch);
    fs::create_dir_all(&scratch).unwrap();
    copy_tree(&work.path("mut-base"), &scratch);
    let mut deleted = String::new();
    for entry in fs::read_dir(scratch.join("residuals")).unwrap() {
        let p = entry.unwrap().path();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        if name.starts_with("cli-") && name.ends_with(".json") {
            deleted = p.file_name().unwrap().to_string_lossy().into_owned();
            fs::remove_file(&p).unwrap();
            break;
        }
    }
    assert!(!deleted.is_empty(), "a residual must be deleted");
    // Fix the manifest: drop the entry so the inventory itself is consistent.
    let manifest_path = scratch.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    let rel = format!("residuals/{deleted}");
    manifest["inventory"]
        .as_array_mut()
        .unwrap()
        .retain(|i| i["path"] != rel);
    fs::write(&manifest_path, frf::canon::encode(&manifest).unwrap()).unwrap();

    let out = frf(&work, &["bundle", "verify", "del-scratch"]);
    assert!(
        !out.status.success(),
        "a bundle missing referenced evidence MUST be refused"
    );
}
