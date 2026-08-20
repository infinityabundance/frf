//! Independent verifier tests: the protocol-separation milestone.
//!
//! `verifier/frf_verify.py` is a deliberately small SECOND implementation of
//! the FRF protocol — Python, no execution. If the Rust reference engine and
//! this verifier agree on the same bundle and the same conformance corpus,
//! FRF is a protocol, not a Rust file format.
//!
//! These tests assert that the verifier:
//!   1. verifies a freshly exported golden bundle (exit 0, admissible IR);
//!   2. passes the structural + semantic corpus that the Rust engine also
//!      passes (same oracle, two implementations);
//!   3. refuses a tampered bundle (nonzero exit, names the corruption).
//!
//! The verifier needs `python3` with PyYAML. CI installs PyYAML so these
//! tests always run there; on a machine without either, they print a clear
//! note and skip rather than fail a local `cargo test`.

mod common;
use common::*;

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

const VERIFIER: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/verifier/frf_verify.py");
const CONFORMANCE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/conformance");

/// The interpreter that can run the verifier: `FRF_VERIFIER_PY` wins, then
/// `python3`, then `python`. A lazy runtime probe, deliberately not a `cfg`.
fn verifier_python() -> Option<String> {
    if let Ok(py) = std::env::var("FRF_VERIFIER_PY") {
        return Some(py);
    }
    for candidate in ["python3", "python"] {
        let probe = Command::new(candidate).arg("--version").output();
        if matches!(probe, Ok(o) if o.status.success()) {
            return Some(candidate.to_string());
        }
    }
    None
}

/// True when the verifier's single third-party dependency (PyYAML) imports.
fn verifier_ready() -> bool {
    match verifier_python() {
        Some(py) => {
            let probe = Command::new(&py).args(["-c", "import yaml"]).output();
            matches!(probe, Ok(o) if o.status.success())
        }
        None => false,
    }
}

fn run_verifier(cwd: &Path, args: &[&str]) -> Output {
    let py = verifier_python().expect("verifier_python() was probed");
    let mut cmd = Command::new(py);
    cmd.arg(VERIFIER).args(args).current_dir(cwd);
    cmd.output().unwrap()
}

fn copy_dir(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if from.is_dir() {
            copy_dir(&from, &to);
        } else {
            fs::copy(&from, &to).unwrap();
        }
    }
}

/// Run the golden path to a claimable state and return (resolution run,
/// final receipt id). Mirrors tests/bundle.rs.
fn golden_to_claim(work: &Workdir) -> (String, String) {
    admit_reference(work);
    let run = run_court(work);
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
        (
            "cli-text-0001",
            "clearer diagnostic wording; documented divergence",
        ),
        (
            "cli-text-0002",
            "clearer diagnostic wording; documented divergence (re-observed)",
        ),
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
        assert_success(&out, &format!("dispose {id} intentional"));
    }
    let out = frf(work, &["--root", ROOT, "receipt", "emit", &resolution_run]);
    assert_success(&out, "receipt emit (final)");
    let receipt_final = stdout(&out);
    let out = frf(work, &["--root", ROOT, "claim", "compile", &receipt_final]);
    assert_success(&out, "claim compile");
    let _ = run; // the original run stays a failure record; the bundle uses the resolution run
    (resolution_run, receipt_final)
}

fn export_bundle(work: &Workdir, receipt_final: &str, name: &str) {
    let out = frf(
        work,
        &[
            "--root",
            ROOT,
            "bundle",
            "export",
            receipt_final,
            "--output",
            name,
        ],
    );
    assert_success(&out, "bundle export");
}

#[test]
fn verifier_verifies_the_golden_bundle_and_derives_the_same_claim_ir() {
    if !verifier_ready() {
        eprintln!(
            "skipping: no python3 with PyYAML (install pyyaml to run the independent verifier)"
        );
        return;
    }
    let work = Workdir::new("independent-bundle");
    work.copy_canonical_tree();
    let (resolution_run, receipt_final) = golden_to_claim(&work);
    export_bundle(&work, &receipt_final, "portable.frf");

    // The verifier must accept the bundle — from its own directory, with the
    // evidence tree present (the bundle is the artifact under test).
    let out = run_verifier(&work.dir, &["bundle", "portable.frf"]);
    assert!(
        out.status.success(),
        "verifier refused the golden bundle:\nstdout: {}\nstderr: {}",
        stdout(&out),
        stderr(&out)
    );
    let out_text = format!("{}{}", stdout(&out), stderr(&out));
    assert!(out_text.contains("verified: bundle="), "{out_text}");
    assert!(
        out_text.contains(&receipt_final),
        "names the receipt: {out_text}"
    );
    assert!(
        out_text.contains(&resolution_run),
        "names the run: {out_text}"
    );
    // The Claim IR must agree with the Rust claim compiler: exit parity is
    // admissible (the stderr intentional residual excludes only its axis).
    assert!(
        out_text.contains("admissible=true"),
        "claim-ir must agree with the Rust compiler: {out_text}"
    );
    assert!(
        out_text.contains("observable_scope=[\"exit\"]"),
        "observable scope must be exactly the clean axis: {out_text}"
    );
}

#[test]
fn verifier_passes_the_structural_and_semantic_corpus() {
    if !verifier_ready() {
        eprintln!(
            "skipping: no python3 with PyYAML (install pyyaml to run the independent verifier)"
        );
        return;
    }
    // The same corpus the Rust engine passes (`cargo test --test conformance`)
    // must pass an independent implementation byte-for-byte: canonical bytes,
    // pinned hashes, structural refusals, semantic refusals.
    let out = run_verifier(
        Path::new(env!("CARGO_MANIFEST_DIR")),
        &["corpus", CONFORMANCE],
    );
    assert!(
        out.status.success(),
        "the independent verifier failed the corpus:\nstdout: {}\nstderr: {}",
        stdout(&out),
        stderr(&out)
    );
    let out_text = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        out_text.contains("fixture(s) passed"),
        "corpus summary missing: {out_text}"
    );
}

#[test]
fn verifier_refuses_a_tampered_bundle() {
    if !verifier_ready() {
        eprintln!(
            "skipping: no python3 with PyYAML (install pyyaml to run the independent verifier)"
        );
        return;
    }
    let work = Workdir::new("independent-tamper");
    work.copy_canonical_tree();
    let (resolution_run, receipt_final) = golden_to_claim(&work);
    export_bundle(&work, &receipt_final, "portable.frf");

    // A foreign directory with ONLY a copy of the bundle: no evidence tree,
    // no frf binary. An attacker can chmod the sealed files — the manifest
    // hash must catch the content change regardless.
    let foreign = Workdir::new("independent-foreign");
    copy_dir(&work.path("portable.frf"), &foreign.path("portable.frf"));
    let side = foreign.path(&format!(
        "portable.frf/captures/{resolution_run}/reference.stdout"
    ));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&side, fs::Permissions::from_mode(0o644)).unwrap();
    }
    fs::write(&side, b"tampered").unwrap();

    let out = run_verifier(&foreign.dir, &["bundle", "portable.frf"]);
    assert!(
        !out.status.success(),
        "the independent verifier accepted a tampered bundle"
    );
    assert!(
        stderr(&out).contains("corrupt"),
        "tamper refusal must name the corruption: {}",
        stderr(&out)
    );
}

/// Sanity: the probes themselves resolve (guards every other test's skip).
#[test]
fn verifier_runner_is_discoverable() {
    let Some(py) = verifier_python() else {
        eprintln!(
            "skipping: no python3 (install PyYAML + python3 to run the independent verifier)"
        );
        return;
    };
    let out = Command::new(py).args([VERIFIER]).output().unwrap();
    // With no mode argument the verifier prints its usage to stderr and
    // exits 2 — proving the script itself is importable/runnable.
    assert_eq!(
        out.status.code(),
        Some(2),
        "usage exit code: {:?}",
        out.status.code()
    );
}
