//! The refusal-root CONFORMANCE TRIANGLE: a bundle carrying a refused
//! execution attempt (the refusal-root — a failed observation attempt made
//! first-class evidence) must verify identically through all three
//! implementations:
//!
//!   1. the Rust reference engine  (`frf bundle verify`),
//!   2. the independent Rust verifier (xtask `verify bundle`),
//!   3. the Go verifier           (`frf-verifier-go verify bundle`).
//!
//! If all three accept the same attempt-bearing bundle and refuse the same
//! tampered one, the `FRF/EXECUTION-ATTEMPT/v1` identity is a protocol, not
//! a Rust file format.

mod common;
use common::*;

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn refusal_root_bundle_passes_the_full_conformance_triangle() {
    let work = Workdir::new("attempt-triangle");
    work.copy_canonical_tree();
    work.write_candidate("#!/bin/sh\nsleep 5\n");
    admit_reference(&work);

    // A refusal first (the sleeping candidate times out): the attempt record
    // + its harness event are written to the store.
    let out = frf_env(
        &work,
        &["--root", ROOT, "court", "run", MANIFEST],
        &[("FRF_EXEC_TIMEOUT_MS", "200")],
    );
    assert!(!out.status.success());
    let attempts = fs::read_dir(work.path("frf/attempts")).unwrap().count();
    assert_eq!(attempts, 1, "the refusal-root must exist");

    // Then a success in the SAME court + store, and a receipt to root the
    // bundle.
    work.write_candidate("#!/bin/sh\nexit 2\n");
    let run = run_court(&work);
    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &run]);
    assert_success(&out, "receipt emit");
    let receipt = stdout(&out);

    let bundle = work.path("bundle");
    let out = frf(
        &work,
        &[
            "--root", ROOT, "bundle", "export", &receipt, "--output", "bundle",
        ],
    );
    assert!(out.status.success(), "export: {}", stderr(&out));
    assert!(
        bundle.join("attempts").is_dir(),
        "the bundle must carry the refusal history"
    );

    // 1. The Rust reference engine verifies the bundle with its refusal
    //    history.
    let out = frf(&work, &["--root", ROOT, "bundle", "verify", "bundle"]);
    assert!(
        out.status.success(),
        "the reference engine must verify the attempt-bearing bundle: {}",
        stderr(&out)
    );

    // 2. The independent Rust verifier agrees.
    let out = Command::new("cargo")
        .args(["run", "--quiet", "--manifest-path"])
        .arg(repo_root().join("xtask/Cargo.toml"))
        .args(["--", "verify", "bundle"])
        .arg(&bundle)
        .output()
        .unwrap_or_else(|e| panic!("cannot run the xtask verifier: {e}"));
    assert!(
        out.status.success(),
        "the xtask verifier must agree: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // 3. The Go verifier agrees.
    let out = Command::new("go")
        .args(["run", ".", "verify", "bundle"])
        .arg(&bundle)
        .current_dir(repo_root().join("verifier-go"))
        .output()
        .unwrap_or_else(|e| panic!("cannot run the Go verifier: {e}"));
    assert!(
        out.status.success(),
        "the Go verifier must agree: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The triangle refuses the same tamper: flip the attempt's kind (a
    // completed attempt IS a run — no such record exists), and all three
    // verifiers must REFUSE the bundle.
    use std::os::unix::fs::PermissionsExt;
    let attempt_file = fs::read_dir(bundle.join("attempts"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    let path = attempt_file.path();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    let bytes = fs::read(&path).unwrap();
    let flipped = String::from_utf8(bytes)
        .unwrap()
        .replace("\"kind\":\"refused\"", "\"kind\":\"completed\"");
    fs::write(&path, flipped).unwrap();

    let out = frf(&work, &["--root", ROOT, "bundle", "verify", "bundle"]);
    assert!(
        !out.status.success(),
        "the engine must refuse the tampered bundle"
    );
    let out = Command::new("cargo")
        .args(["run", "--quiet", "--manifest-path"])
        .arg(repo_root().join("xtask/Cargo.toml"))
        .args(["--", "verify", "bundle"])
        .arg(&bundle)
        .output()
        .unwrap_or_else(|e| panic!("cannot run the xtask verifier: {e}"));
    assert!(
        !out.status.success(),
        "the xtask verifier must refuse the tampered bundle"
    );
    let out = Command::new("go")
        .args(["run", ".", "verify", "bundle"])
        .arg(&bundle)
        .current_dir(repo_root().join("verifier-go"))
        .output()
        .unwrap_or_else(|e| panic!("cannot run the Go verifier: {e}"));
    assert!(
        !out.status.success(),
        "the Go verifier must refuse the tampered bundle"
    );
}
