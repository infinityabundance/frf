//! Golden-path acceptance test (Section 12 of the paper, run through the real
//! binary). Two tiny CLI programs — a reference and a candidate — that agree
//! on everything except exit code (2 vs 1) and first stderr line wording on a
//! malformed-input fixture. The full pipeline against them must:
//!
//! 1. admit the authority and run the court → two `open` residuals
//!    (`cli-exit-*`, `cli-text-*`), raw captures, endoduction tokens;
//! 2. refuse a positive claim while the residuals are open;
//! 3. accept `fixed` (exit) and `intentional` (text) dispositions — and refuse
//!    a disposition without a reason;
//! 4. emit the final receipt and compile the bounded claim, with the
//!    Section 12 non-claim printed next to it.

mod common;
use common::*;

use std::fs;
use std::path::PathBuf;

#[test]
fn golden_path_end_to_end() {
    let work = Workdir::new("path");
    work.copy_canonical_tree();
    let root = ROOT;

    // -- 1. admit ------------------------------------------------------------

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
    assert_eq!(stdout(&out), "ref-cli-1.8.2");

    let authority: serde_yaml::Value = serde_yaml::from_str(
        &fs::read_to_string(work.path("frf/authorities/ref-cli-1.8.2.yaml")).unwrap(),
    )
    .unwrap();
    assert_eq!(authority["kind"], "executable_reference");
    assert_eq!(authority["version"], "1.8.2");
    let sha = authority["executable_sha256"].as_str().unwrap();
    assert_eq!(sha.len(), 64);
    assert!(sha.chars().all(|c| c.is_ascii_hexdigit()));

    // Admission is once: re-admitting the same id must fail.
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
    assert!(!out.status.success());
    assert!(stderr(&out).contains("already admitted"));

    // -- 2. run the court ------------------------------------------------------

    let run = run_court(&work);
    assert!(
        fs::read_to_string(work.path(&format!("{root}/captures/{run}/reference.exit.txt")))
            .unwrap()
            .starts_with('2')
    );
    assert!(
        fs::read_to_string(work.path(&format!("{root}/captures/{run}/candidate.exit.txt")))
            .unwrap()
            .starts_with('1')
    );

    // Two residuals, both open, with endoduction tokens.
    let exit_residual: serde_yaml::Value = serde_yaml::from_str(
        &fs::read_to_string(work.path("frf/residuals/cli-exit-0001.yaml")).unwrap(),
    )
    .unwrap();
    assert_eq!(exit_residual["kind"], "exit");
    assert_eq!(exit_residual["raw_reference"], "2");
    assert_eq!(exit_residual["raw_candidate"], "1");
    assert_eq!(exit_residual["disposition"], "open");

    let text_residual: serde_yaml::Value = serde_yaml::from_str(
        &fs::read_to_string(work.path("frf/residuals/cli-text-0001.yaml")).unwrap(),
    )
    .unwrap();
    assert_eq!(text_residual["kind"], "text");
    assert_eq!(text_residual["surface"], "first-diagnostic-line");
    assert_eq!(text_residual["disposition"], "open");
    let ref_line = text_residual["raw_reference"].as_str().unwrap();
    assert!(
        ref_line.contains("malformed-path.conf:4: unknown directive 'servre'"),
        "reference stderr line: {ref_line}"
    );
    let cand_line = text_residual["raw_candidate"].as_str().unwrap();
    assert_eq!(cand_line, "error: unknown directive servre at line 4");

    let exit_token: serde_yaml::Value = serde_yaml::from_str(
        &fs::read_to_string(work.path("frf/residuals/cli-exit-0001.token.yaml")).unwrap(),
    )
    .unwrap();
    assert_eq!(exit_token["token"], "exit/exit-class/class-change/open");
    assert_eq!(exit_token["next_court"], "cli-exit-minimize");

    let text_token: serde_yaml::Value = serde_yaml::from_str(
        &fs::read_to_string(work.path("frf/residuals/cli-text-0001.token.yaml")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        text_token["token"],
        "text/diagnostic-routing/first-line-token-change/open"
    );
    assert_eq!(text_token["next_court"], "cli-diagnostic-minimize");

    // -- 3. refuse the claim while residuals are open ---------------------------

    let out = frf(&work, &["--root", root, "receipt", "emit", &run]);
    assert_success(&out, "receipt emit (open)");
    let receipt_open = stdout(&out);
    assert!(receipt_open.starts_with("receipt-run-cli-malformed-input-"));

    let out = frf(&work, &["--root", root, "claim", "compile", &receipt_open]);
    assert!(
        !out.status.success(),
        "claim must be refused while residuals are open"
    );
    let err = stderr(&out);
    assert!(
        err.contains("cannot claim compatibility for fixture family malformed-input because residual cli-exit-0001 (exit) is open"),
        "refusal line: {err}"
    );
    assert!(err.contains("residual cli-text-0001 (text) is open"));
    assert!(err.contains("does not establish byte-identical stderr"));

    // -- 4. dispositions ----------------------------------------------------------

    // The misuse-resistance gate: no disposition without a reason.
    let out = frf(
        &work,
        &[
            "--root",
            root,
            "residual",
            "dispose",
            "cli-exit-0001",
            "--disposition",
            "fixed",
        ],
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("reason"));

    // `open` is not settable.
    let out = frf(
        &work,
        &[
            "--root",
            root,
            "residual",
            "dispose",
            "cli-exit-0001",
            "--disposition",
            "open",
            "--reason",
            "nope",
        ],
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("invalid value"));

    // Unknown residual id.
    let out = frf(
        &work,
        &[
            "--root",
            root,
            "residual",
            "dispose",
            "cli-exit-9999",
            "--disposition",
            "fixed",
            "--reason",
            "x",
        ],
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("no such residual"));

    // Dispositions with reasons.
    let out = frf(
        &work,
        &[
            "--root",
            root,
            "residual",
            "dispose",
            "cli-exit-0001",
            "--disposition",
            "fixed",
            "--reason",
            "candidate patched to preserve reference exit class",
        ],
    );
    assert_success(&out, "dispose exit");
    let out = frf(
        &work,
        &[
            "--root",
            root,
            "residual",
            "dispose",
            "cli-text-0001",
            "--disposition",
            "intentional",
            "--reason",
            "clearer diagnostic wording; documented divergence",
        ],
    );
    assert_success(&out, "dispose text");

    let exit_residual: serde_yaml::Value = serde_yaml::from_str(
        &fs::read_to_string(work.path("frf/residuals/cli-exit-0001.yaml")).unwrap(),
    )
    .unwrap();
    assert_eq!(exit_residual["disposition"], "fixed");
    assert!(exit_residual["reason"]
        .as_str()
        .unwrap()
        .contains("patched"));
    // The token file follows the disposition.
    let exit_token: serde_yaml::Value = serde_yaml::from_str(
        &fs::read_to_string(work.path("frf/residuals/cli-exit-0001.token.yaml")).unwrap(),
    )
    .unwrap();
    assert_eq!(exit_token["token"], "exit/exit-class/class-change/fixed");

    // -- 5. final receipt + bounded claim ------------------------------------------

    let out = frf(&work, &["--root", root, "receipt", "emit", &run]);
    assert_success(&out, "receipt emit (final)");
    let receipt_final = stdout(&out);
    assert_ne!(
        receipt_final, receipt_open,
        "re-emitting after a disposition change must produce a new receipt"
    );

    let receipt_yaml: serde_yaml::Value = serde_yaml::from_str(
        &fs::read_to_string(work.path(&format!("{root}/receipts/{receipt_final}.yaml"))).unwrap(),
    )
    .unwrap();
    assert_eq!(
        receipt_yaml["authority"]["identity_hash"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    assert!(receipt_yaml["claims"]["blocked_by_open_residuals"]
        .as_sequence()
        .unwrap()
        .is_empty());

    let out = frf(&work, &["--root", root, "claim", "compile", &receipt_final]);
    assert_success(&out, "claim compile (final)");
    let out_text = stdout(&out);
    assert!(
        out_text.contains(
            "For reference ref-cli-1.8.2, fixture family malformed-input, and environment x86_64-linux ("
        ),
        "bounded claim sentence: {out_text}"
    );
    assert!(
        out_text.contains("the candidate preserves malformed-input exit class for the malformed-input cases in court cli-malformed-input."),
        "claim scope: {out_text}"
    );
    assert!(
        out_text.contains("This receipt does not establish byte-identical stderr, full CLI compatibility, or a drop-in replacement claim."),
        "non-claim printed: {out_text}"
    );
    assert!(
        out_text.contains("In particular, it does not establish a drop-in replacement for all malformed-input behavior."),
        "non-claim scope: {out_text}"
    );

    let claim_path = work.path(&format!("{root}/claims/{receipt_final}.yaml"));
    let claim_yaml: serde_yaml::Value =
        serde_yaml::from_str(&fs::read_to_string(&claim_path).unwrap()).unwrap();
    assert_eq!(claim_yaml["receipt"], receipt_final);
    let positive = claim_yaml["positive"].as_sequence().unwrap();
    assert_eq!(positive.len(), 1, "exactly one conservative sentence");

    // -- 6. authority drift refuses to run -------------------------------------------

    // Tamper with the admitted reference; the court must refuse, not silently
    // compare against a drifted oracle.
    let ref_path = work.path("golden/reference.sh");
    fs::write(
        &ref_path,
        format!("# tampered\n{}", fs::read_to_string(&ref_path).unwrap()),
    )
    .unwrap();
    let out = frf(&work, &["--root", root, "court", "run", MANIFEST]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("changed since admission"));
}

#[test]
fn raw_captures_are_immutable() {
    let work = Workdir::new("immutable");
    work.copy_canonical_tree();
    let root = ROOT;

    admit_reference(&work);
    let run = run_court(&work);

    // Re-running the identical court must refuse (content-addressed captures).
    let out = frf(&work, &["--root", root, "court", "run", MANIFEST]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("already exists"),
        "stderr: {}",
        stderr(&out)
    );

    // The raw stderr file must be byte-identical to what the reference wrote.
    let raw = fs::read(work.path(&format!("{root}/captures/{run}/reference.stderr"))).unwrap();
    assert_eq!(
        String::from_utf8_lossy(&raw),
        "tool: frf/courts/cli-malformed-input/fixtures/malformed-path.conf:4: unknown directive 'servre'\n"
    );
}

#[test]
fn refusal_writes_no_claim_file() {
    // Same pipeline as the golden path, but assert the *open* receipt's claim
    // compile behavior precisely: exit code 1, no prose on stdout, nothing
    // written to claims/.
    let work = Workdir::new("refusal");
    work.copy_canonical_tree();
    let root = ROOT;

    admit_reference(&work);
    let run = run_court(&work);
    let out = frf(&work, &["--root", root, "receipt", "emit", &run]);
    assert_success(&out, "receipt emit");
    let receipt = stdout(&out);

    let out = frf(&work, &["--root", root, "claim", "compile", &receipt]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stdout(&out).is_empty(),
        "no claim prose on stdout when refused"
    );
    let claims_dir = work.path(&format!("{root}/claims"));
    assert!(
        fs::read_dir(&claims_dir).unwrap().next().is_none(),
        "refused compile must not write a claim file"
    );
}

#[test]
fn tree_imports_resolve() {
    // Guard: the canonical manifest and fixture files exist in the repo, so
    // every other test's copy_canonical_tree works.
    let src_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for rel in CANONICAL_FILES {
        assert!(src_root.join(rel).is_file(), "missing canonical file {rel}");
    }
}
