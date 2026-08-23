//! Golden-path acceptance test (Section 12 of the paper, run through the real
//! binary). Two tiny CLI programs — a reference and a candidate — that agree
//! on everything except exit code (2 vs 1) and first stderr line wording on a
//! malformed-input fixture. The full pipeline against them must:
//!
//! 1. admit the authority and run the court → two `open` residuals
//!    (`cli-exit-*`, `cli-text-*`), raw captures, endoduction tokens;
//! 2. refuse a positive claim while the residuals are open;
//! 3. refuse `fixed` without a resolution run; accept `fixed` only when
//!    backed by a NEW court run that reran the same question under a
//!    compatible envelope and shows the residual no longer reproduces;
//!    accept `intentional` for the documented wording divergence;
//! 4. preserve the original receipt as what it was — it can never yield a
//!    parity claim, however its residuals are disposed — and compile the
//!    bounded claim from the RESOLUTION run's receipt, attributed to the
//!    exact candidate artifact (0.1.0-fixed) that actually passed, with the
//!    Section 12 non-claim printed next to it.

mod common;
use common::*;

use std::fs;

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

    let authority: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path("frf/authorities/ref-cli-1.8.2.json")).unwrap(),
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

    // The capture manifest binds the exact candidate artifact.
    let capture: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("{root}/captures/{run}/capture.json"))).unwrap(),
    )
    .unwrap();
    let candidate_hash = capture["candidate_artifact"]["sha256"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(candidate_hash.len(), 64);

    // Two residuals, both open, with endoduction tokens; the observation
    // records carry NO disposition (dispositions are events). The residual
    // ids are content addresses — resolve them from the capture's evidence.
    let exit_id = residual_id(&work, &run, "exit");
    let text_id = residual_id(&work, &run, "stderr");
    let exit_residual: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("{root}/residuals/{exit_id}.json"))).unwrap(),
    )
    .unwrap();
    assert_eq!(exit_residual["kind"], "exit");
    assert_eq!(exit_residual["raw_reference"], "2");
    assert_eq!(exit_residual["raw_candidate"], "1");
    assert!(
        exit_residual.get("disposition").is_none(),
        "observations must not carry dispositions"
    );
    assert_eq!(
        exit_residual["candidate_sha256"].as_str().unwrap(),
        candidate_hash
    );
    // The content address rederives from the record's own fields.
    assert_eq!(
        exit_residual["id"].as_str().unwrap(),
        exit_id,
        "the residual id is the FRF/RESIDUAL/v1 content address"
    );

    let text_residual: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("{root}/residuals/{text_id}.json"))).unwrap(),
    )
    .unwrap();
    assert_eq!(text_residual["kind"], "text");
    assert_eq!(text_residual["surface"], "first-diagnostic-line");
    let ref_line = text_residual["raw_reference"].as_str().unwrap();
    assert!(
        ref_line.contains(":4: unknown directive 'servre'"),
        "reference stderr line: {ref_line}"
    );
    assert!(
        ref_line.contains("objects/sha256/"),
        "the side reads the content-addressed fixture snapshot: {ref_line}"
    );
    let cand_line = text_residual["raw_candidate"].as_str().unwrap();
    assert_eq!(cand_line, "error: unknown directive servre at line 4");

    let exit_token: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("{root}/residuals/{exit_id}.token.json"))).unwrap(),
    )
    .unwrap();
    assert_eq!(exit_token["token"], "exit/exit-class/class-change/open");
    assert_eq!(exit_token["next_court"], "cli-exit-minimize");

    let text_token: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("{root}/residuals/{text_id}.token.json"))).unwrap(),
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
        err.contains(&format!("because residual {exit_id} (exit) is open")),
        "refusal line: {err}"
    );
    assert!(err.contains(&format!("residual {text_id} (text) is open")));
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
            &exit_id,
            "--disposition",
            "fixed",
        ],
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("reason"));

    // The evidence gate: `fixed` without a resolution run is refused — a
    // disposition is not evidence.
    let out = frf(
        &work,
        &[
            "--root",
            root,
            "residual",
            "dispose",
            &exit_id,
            "--disposition",
            "fixed",
            "--reason",
            "patched",
        ],
    );
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("--resolution-run"),
        "stderr: {}",
        stderr(&out)
    );

    // The resolution run must be a NEW run, not the one that observed the
    // residual.
    let out = frf(
        &work,
        &[
            "--root",
            root,
            "residual",
            "dispose",
            &exit_id,
            "--disposition",
            "fixed",
            "--resolution-run",
            &run,
            "--reason",
            "patched",
        ],
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("new court run"));

    // And it must exist.
    let out = frf(
        &work,
        &[
            "--root",
            root,
            "residual",
            "dispose",
            &exit_id,
            "--disposition",
            "fixed",
            "--resolution-run",
            "run-nope",
            "--reason",
            "patched",
        ],
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("no such run 'run-nope'"));

    // `open` is not settable.
    let out = frf(
        &work,
        &[
            "--root",
            root,
            "residual",
            "dispose",
            &exit_id,
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
            "--resolution-run",
            "run-x",
        ],
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("no such residual"));

    // Patch the candidate, re-run the court under the same question/envelope,
    // and only then dispose `fixed` with the run that closes the residual.
    let resolution_run = run_resolution_court(&work);
    let res_text_id = residual_id(&work, &resolution_run, "stderr");
    let out = frf(
        &work,
        &[
            "--root",
            root,
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
    assert_success(&out, "dispose exit (fixed, with closure evidence)");

    let out = frf(
        &work,
        &[
            "--root",
            root,
            "residual",
            "dispose",
            &text_id,
            "--disposition",
            "intentional",
            "--reason",
            "clearer diagnostic wording; documented divergence",
        ],
    );
    assert_success(&out, "dispose text 0001");
    let out = frf(
        &work,
        &[
            "--root",
            root,
            "residual",
            "dispose",
            &res_text_id,
            "--disposition",
            "intentional",
            "--reason",
            "clearer diagnostic wording; documented divergence (re-observed)",
        ],
    );
    assert_success(&out, "dispose text 0002");

    // The observation record is untouched; the disposition is an appended
    // event carrying the resolution edge and the verified predicate.
    let exit_residual: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("{root}/residuals/{exit_id}.json"))).unwrap(),
    )
    .unwrap();
    assert!(
        exit_residual.get("disposition").is_none(),
        "observation must remain immutable"
    );
    let event: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("{root}/residuals/{exit_id}.events/0001.json")))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(event["disposition"], "fixed");
    assert!(event["reason"].as_str().unwrap().contains("patched"));
    assert_eq!(event["resolution_run_id"].as_str().unwrap(), resolution_run);
    assert!(event["closure_predicate"]
        .as_str()
        .unwrap()
        .contains("fix-court"));
    // The token file follows the projected disposition.
    let exit_token: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("{root}/residuals/{exit_id}.token.json"))).unwrap(),
    )
    .unwrap();
    assert_eq!(exit_token["token"], "exit/exit-class/class-change/fixed");

    // -- 5. the old receipt stays what it was; the claim comes from the
    //       resolution run ---------------------------------------------------------

    let out = frf(&work, &["--root", root, "receipt", "emit", &run]);
    assert_success(&out, "receipt emit (original run, after dispositions)");
    let receipt_old = stdout(&out);
    assert_ne!(
        receipt_old, receipt_open,
        "re-emitting after a disposition change must produce a new receipt"
    );

    let receipt_yaml: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("{root}/receipts/{receipt_old}.json"))).unwrap(),
    )
    .unwrap();
    let exit_entry = receipt_yaml["residuals"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == exit_id)
        .expect("exit residual in receipt");
    assert_eq!(
        exit_entry["resolution_run_id"].as_str().unwrap(),
        resolution_run,
        "the receipt must bind the resolution edge"
    );
    assert!(exit_entry["closure_predicate"]
        .as_str()
        .unwrap()
        .contains("fix-court"));

    // The original (failing) run's receipt can never yield a parity claim,
    // however its residuals are disposed.
    let out = frf(&work, &["--root", root, "claim", "compile", &receipt_old]);
    assert!(
        !out.status.success(),
        "the failing run's receipt must never become parity"
    );
    assert!(
        stderr(&out).contains("compile the claim from the resolution run"),
        "stderr: {}",
        stderr(&out)
    );
    assert!(stderr(&out).contains(&resolution_run));

    // The positive claim is compiled from the resolution run's receipt: the
    // run that actually observed the passing candidate.
    let out = frf(&work, &["--root", root, "receipt", "emit", &resolution_run]);
    assert_success(&out, "receipt emit (resolution run)");
    let receipt_final = stdout(&out);
    assert_ne!(receipt_final, receipt_old);

    let out = frf(&work, &["--root", root, "claim", "compile", &receipt_final]);
    assert_success(&out, "claim compile (resolution run)");
    let out_text = stdout(&out);
    assert!(
        out_text.contains(
            "For reference ref-cli-1.8.2, fixture family malformed-input, and environment x86_64-linux ("
        ),
        "bounded claim sentence: {out_text}"
    );
    // Attributed to the exact candidate artifact that actually passed — the
    // resolution run's candidate (H1), not the original failing one (H0).
    let res_capture: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("{root}/captures/{resolution_run}/capture.json")))
            .unwrap(),
    )
    .unwrap();
    let h1_hash = res_capture["candidate_artifact"]["sha256"]
        .as_str()
        .unwrap();
    assert_ne!(h1_hash, candidate_hash, "H1 must differ from H0");
    let cand_short = &h1_hash[..8];
    assert!(
        out_text.contains(&format!(
            "candidate cand-cli 0.1.0-fixed ({cand_short}) preserves malformed-input exit class for the malformed-input cases in court cli-malformed-input."
        )),
        "claim attribution: {out_text}"
    );
    assert!(
        out_text.contains("This receipt does not establish byte-identical stderr, full CLI compatibility, or a drop-in replacement claim."),
        "non-claim printed: {out_text}"
    );
    assert!(
        out_text.contains("In particular, it does not establish a drop-in replacement for all malformed-input behavior."),
        "non-claim scope: {out_text}"
    );

    let claim_path = claim_path(&work, &receipt_final);
    let claim_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&claim_path).unwrap()).unwrap();
    assert_eq!(claim_json["receipt"], receipt_final);
    assert_eq!(claim_json["candidate"]["name"], "cand-cli");
    assert_eq!(claim_json["candidate"]["version_or_commit"], "0.1.0-fixed");
    assert_eq!(
        claim_json["candidate"]["identity_hash"].as_str().unwrap(),
        h1_hash,
        "the claim names the candidate artifact that actually passed"
    );

    // The prose is NOT stored in the Claim IR — it is DERIVED by the
    // renderer from the verified premises (a hand-written claim file can
    // never make a renderer restate a sentence the evidence does not
    // deterministically produce).
    assert!(
        claim_json.get("positive").is_none(),
        "prose is a renderer output, never stored Claim IR"
    );
    let rendered = frf(
        &work,
        &[
            "--root",
            root,
            "claim",
            "render",
            &receipt_final,
            "--format",
            "prose",
        ],
    );
    assert_success(&rendered, "claim render prose");
    let rendered_out = stdout(&rendered);
    let rendered_lines: Vec<&str> = rendered_out.lines().collect();
    assert_eq!(
        rendered_lines.len(),
        3,
        "one conservative sentence + the two non-claims"
    );

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

    admit_reference(&work);
    let run = run_court(&work);

    // Re-running the identical court must refuse (content-addressed captures).
    let out = frf(&work, &["--root", ROOT, "court", "run", MANIFEST]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("already exists"),
        "stderr: {}",
        stderr(&out)
    );

    // The raw stderr file must be byte-identical to what the reference wrote:
    // the side reports the content-addressed fixture snapshot path it opened.
    let raw = fs::read(work.path(&format!("{ROOT}/captures/{run}/reference.stderr"))).unwrap();
    let text = String::from_utf8_lossy(&raw);
    assert!(
        text.starts_with("tool: frf/objects/sha256/")
            && text.contains(":4: unknown directive 'servre'\n"),
        "reference stderr: {text}"
    );
}

#[test]
fn refusal_writes_no_claim_file() {
    // Same pipeline as the golden path, but assert the *open* receipt's claim
    // compile behavior precisely: exit code 1, no prose on stdout, nothing
    // written to claims/.
    let work = Workdir::new("refusal");
    work.copy_canonical_tree();

    admit_reference(&work);
    let run = run_court(&work);
    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &run]);
    assert_success(&out, "receipt emit");
    let receipt = stdout(&out);

    let out = frf(&work, &["--root", ROOT, "claim", "compile", &receipt]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stdout(&out).is_empty(),
        "no claim prose on stdout when refused"
    );
    let claims_dir = work.path(&format!("{ROOT}/claims"));
    assert!(
        fs::read_dir(&claims_dir).unwrap().next().is_none(),
        "refused compile must not write a claim file"
    );
}

#[test]
fn tree_imports_resolve() {
    // Guard: the canonical manifest and fixture files exist in the repo, so
    // every other test's copy_canonical_tree works.
    let src_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for rel in CANONICAL_FILES {
        assert!(src_root.join(rel).is_file(), "missing canonical file {rel}");
    }
}
