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

/// Run the Go verifier (the third triangle point; shares no parsing library
/// with either Rust implementation). The verifier lives in the repo's
/// `verifier-go/`; the bundle path is passed absolutely so the verifier runs
/// from its own directory.
fn go_verifier(args: &[&str]) -> Output {
    let go_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("verifier-go");
    let mut cmd = Command::new("go");
    cmd.args(["run", "."]).args(args).current_dir(go_dir);
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
    // Residual ids are content addresses: resolve them from the evidence.
    let exit_id = residual_id(work, &run, "exit");
    let text_id = residual_id(work, &run, "stderr");
    let res_text_id = residual_id(work, &resolution_run, "stderr");
    let out = frf(
        work,
        &[
            "--root",
            ROOT,
            "residual",
            "dispose",
            &exit_id,
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
            text_id.clone(),
            "clearer diagnostic wording; documented divergence",
        ),
        (
            res_text_id.clone(),
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
                &id,
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

/// The second premise manifest: the SAME authority and the SAME candidate
/// artifact (candidate-fixed.sh) observed on a surface the resolution court
/// never covered — a stdout-only court whose axis passes for the fixed
/// candidate.
const STDOUT_ONLY_MANIFEST: &str = r#"
court:
  id: cli-stdout-only
  question: >-
    For malformed input in fixture family malformed-input, does the candidate
    preserve the admitted reference's stdout?
  falsifier: >-
    The candidate's stdout diverges from the admitted reference on a fixture
    in family malformed-input.
  authority: ref-cli-1.8.2
  candidate:
    name: cand-cli
    version_or_commit: "0.1.0-fixed"
    build_profile: debug
    path: golden/work/candidate-fixed.sh
  fixture:
    id: malformed-path.conf
    path: frf/courts/cli-malformed-input/fixtures/malformed-path.conf
    arguments: ["--strict", "{fixture}"]
  admissibility_envelope:
    fixture_family: malformed-input
    platforms: ["x86_64-linux"]
    observables: [stdout]
    normalizers: []
    replay_scope: single-run
"#;

/// The multi-premise case of the conformance triangle: a claim compiled from
/// TWO premise receipts (the resolution receipt + a stdout-only receipt of
/// the SAME candidate), exported as a bundle, must verify in the independent
/// xtask verifier AND the Go verifier, with the per-premise capability
/// binding re-derived from the bundle alone.
#[test]
fn both_verifiers_agree_on_a_multi_premise_claim_bundle() {
    let work = Workdir::new("independent-multi");
    work.copy_canonical_tree();
    let (_resolution_run, receipt_final) = golden_to_claim(&work);

    // The second premise: stdout-only, same authority, same candidate bytes.
    let manifest = "frf/courts/cli-malformed-input/manifest-stdout-only.yaml";
    fs::write(work.path(manifest), STDOUT_ONLY_MANIFEST).unwrap();
    let out = frf(&work, &["--root", ROOT, "court", "run", manifest]);
    assert_success(&out, "stdout-only court run");
    let run2 = stdout(&out);
    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &run2]);
    assert_success(&out, "stdout-only receipt emit");
    let receipt2 = stdout(&out);

    // Sensitivity coverage is PER PREMISE: challenge each premise's court on
    // its claimed axis, then compile the multi-premise claim under the
    // sensitivity-backed tier (the capability entries bind the premise).
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "court",
            "challenge",
            MANIFEST,
            "--operators",
            "exit-class",
        ],
    );
    assert_success(&out, "court challenge (exit-class)");
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "court",
            "challenge",
            manifest,
            "--operators",
            "stdout-first-line",
        ],
    );
    assert_success(&out, "court challenge (stdout-first-line)");
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "claim",
            "compile",
            &receipt_final,
            &receipt2,
            "--policy",
            "sensitivity-backed",
        ],
    );
    assert_success(&out, "multi-premise claim compile");

    // The receipt now has TWO compiled claims (the baseline from
    // `golden_to_claim` and this one — a different policy is a different
    // claim, and they coexist); resolve the multi-premise one through the
    // index. The claim names BOTH premises.
    let claims = claim_json_all(&work, &receipt_final);
    let claim = claims
        .iter()
        .find(|c| {
            c["requires"]
                .as_array()
                .map(|r| r.len() == 2)
                .unwrap_or(false)
        })
        .expect("the multi-premise claim");
    assert_eq!(claim["schema_version"], "frf-claim-v10");
    assert_eq!(
        claim["requires"],
        serde_json::json!([receipt_final, receipt2])
    );
    assert_eq!(
        claim["observable_scope"],
        serde_json::json!(["exit", "stdout"])
    );

    // Export: the closure must carry BOTH premise receipts and BOTH premise
    // runs (the second premise is not the bundle root).
    export_bundle(&work, &receipt_final, "portable-multi.frf");
    let bundle = work.path("portable-multi.frf");
    assert!(
        bundle.join(format!("receipts/{receipt2}.json")).is_file(),
        "the bundle must carry the second premise receipt"
    );
    assert!(
        bundle.join(format!("captures/{run2}")).is_dir(),
        "the bundle must carry the second premise's run"
    );

    // The independent verifiers re-derive the policy admission from the
    // bundle alone (per-premise capability binding included).
    let out = run_xtask(&work.dir, &["verify", "bundle", "portable-multi.frf"]);
    assert!(
        out.status.success(),
        "xtask refused the multi-premise bundle:\nstdout: {}\nstderr: {}",
        stdout(&out),
        stderr(&out)
    );
    let bundle_abs = work.path("portable-multi.frf");
    let out = go_verifier(&["verify", "bundle", bundle_abs.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "the Go verifier refused the multi-premise bundle:\nstdout: {}\nstderr: {}",
        stdout(&out),
        stderr(&out)
    );
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
