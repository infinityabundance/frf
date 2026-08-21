//! Independent verifier tests: the protocol-separation milestone.
//!
//! `cargo xtask verify` (xtask/) is a deliberately small SECOND
//! implementation of the FRF protocol — Rust, no execution, no dependency on
//! the `frf` reference engine. If the Rust reference engine and this
//! verifier agree on the same bundle and the same conformance corpus, FRF is
//! a protocol, not a Rust file format.
//!
//! These tests assert that the verifier:
//!   1. verifies a freshly exported golden bundle (exit 0, admissible IR);
//!   2. passes the structural + semantic corpus that the Rust engine also
//!      passes (same oracle, two implementations);
//!   3. refuses a tampered bundle (nonzero exit, names the corruption).

mod common;
use common::*;

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

const XTASK_MANIFEST: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/xtask/Cargo.toml");
const CONFORMANCE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/conformance");

/// Run the xtask verifier. The xtask crate is independent of the frf
/// library; `env!("CARGO")` is the cargo that built this test, and the
/// manifest path pins the xtask crate.
fn run_xtask(cwd: &Path, args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO"));
    cmd.args(["run", "--quiet", "--manifest-path", XTASK_MANIFEST, "--"])
        .args(args)
        .current_dir(cwd);
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
    let work = Workdir::new("independent-bundle");
    work.copy_canonical_tree();
    let (resolution_run, receipt_final) = golden_to_claim(&work);
    export_bundle(&work, &receipt_final, "portable.frf");

    // The independent verifier must accept the bundle and derive the SAME
    // Claim IR as the Rust claim compiler: exit parity is admissible (the
    // stderr intentional residual excludes only its axis), no blockers.
    let out = run_xtask(&work.dir, &["verify", "bundle", "portable.frf"]);
    assert!(
        out.status.success(),
        "the independent verifier refused the golden bundle:\nstdout: {}\nstderr: {}",
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
    // The same corpus the Rust engine passes (`cargo test --test conformance`)
    // must pass an independent implementation byte-for-byte: canonical bytes,
    // pinned hashes, structural refusals (including unknown properties and
    // duplicate property names — RFC 8785 I-JSON), semantic refusals.
    let out = run_xtask(
        Path::new(env!("CARGO_MANIFEST_DIR")),
        &["verify", "corpus", CONFORMANCE],
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

    let out = run_xtask(&foreign.dir, &["verify", "bundle", "portable.frf"]);
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

/// Sanity: the xtask builds and reports its usage (exit 2) with no mode.
#[test]
fn xtask_builds_and_reports_usage() {
    let out = run_xtask(Path::new(env!("CARGO_MANIFEST_DIR")), &[]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "usage exit code: {:?}",
        out.status.code()
    );
}
