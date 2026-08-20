//! Regression suite — the invariant bank.
//!
//! Where the golden-path test proves the happy chain, this suite locks down
//! every rejection path and behavioral edge: admission validation, court
//! declaration validation, the disposition reason gate, re-disposition,
//! claim-blocking semantics for every closure kind, the id/path-safety
//! boundary, execution timeout kill, and the zero-residual positive control.

mod common;
use common::*;

use std::fs;

fn raw_residual(work: &Workdir, id: &str) -> serde_yaml::Value {
    serde_yaml::from_str(
        &fs::read_to_string(work.path(&format!("frf/residuals/{id}.yaml"))).unwrap(),
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// Admission validation
// ---------------------------------------------------------------------------

#[test]
fn admission_rejects_bad_kind_name_version_and_file() {
    let work = Workdir::new("admit-rejects");
    work.copy_canonical_tree();

    // Only executable_reference is admitted in v0.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "authority",
            "admit",
            "golden/reference.sh",
            "--name",
            "ref-cli",
            "--version",
            "1.8.2",
            "--kind",
            "specification",
        ],
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("only 'executable_reference' is supported"));

    // Names and versions must be safe path components (they become the id).
    for (flag, value) in [
        ("--name", "a b"),
        ("--version", "1.0/rc1"),
        ("--name", "../x"),
    ] {
        let mut args = vec!["--root", ROOT, "authority", "admit", "golden/reference.sh"];
        if flag == "--name" {
            args.extend_from_slice(&["--name", value, "--version", "1.8.2"]);
        } else {
            args.extend_from_slice(&["--name", "ref-cli", "--version", value]);
        }
        let out = frf(&work, &args);
        assert!(!out.status.success(), "{flag}={value} must be rejected");
        assert!(
            stderr(&out).contains("invalid authority"),
            "stderr: {}",
            stderr(&out)
        );
    }

    // Missing file.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "authority",
            "admit",
            "golden/nope.sh",
            "--name",
            "ref-cli",
            "--version",
            "1.8.2",
        ],
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("not a file"));

    // Non-executable file.
    let plain = work.path("golden/plain.txt");
    fs::write(&plain, "not a program\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&plain, fs::Permissions::from_mode(0o644)).unwrap();
    }
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "authority",
            "admit",
            "golden/plain.txt",
            "--name",
            "plain",
            "--version",
            "1.0",
        ],
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("not executable"));
}

// ---------------------------------------------------------------------------
// Court declaration validation
// ---------------------------------------------------------------------------

/// A manifest copy with one declared line replaced. `old_line` and `new_line`
/// are matched by trimmed content; the matched line's indentation is kept.
fn manifest_variant(work: &Workdir, old_line: &str, new_line: &str) -> String {
    let path = work.path("frf/courts/cli-malformed-input/manifest.yaml");
    let text = fs::read_to_string(&path).unwrap();
    let mut replaced = false;
    let out: String = text
        .lines()
        .map(|line| {
            if line.trim() == old_line {
                replaced = true;
                let indent: String = line.chars().take_while(|c| *c == ' ').collect();
                format!("{indent}{new_line}")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(replaced, "line {old_line:?} not found in manifest");
    let variant = work.path("frf/courts/variant.yaml");
    fs::write(&variant, out).unwrap();
    "frf/courts/variant.yaml".to_string()
}

#[test]
fn court_rejects_bad_declarations() {
    let work = Workdir::new("court-rejects");
    work.copy_canonical_tree();
    admit_reference(&work);

    // Unsupported observable axis (v0: exit and stderr only).
    let m = manifest_variant(
        &work,
        "observables: [exit, stderr]",
        "observables: [stdout]",
    );
    let out = frf(&work, &["--root", ROOT, "court", "run", &m]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("unsupported observable axis 'stdout'"));

    // Unknown authority id.
    let m = manifest_variant(&work, "authority: ref-cli-1.8.2", "authority: nope-1.0");
    let out = frf(&work, &["--root", ROOT, "court", "run", &m]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("not admitted"));

    // Missing candidate.
    let m = manifest_variant(&work, "path: golden/candidate.sh", "path: golden/nope.sh");
    let out = frf(&work, &["--root", ROOT, "court", "run", &m]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("candidate golden/nope.sh not found"));

    // Missing fixture.
    let m = manifest_variant(
        &work,
        "path: frf/courts/cli-malformed-input/fixtures/malformed-path.conf",
        "path: frf/courts/cli-malformed-input/fixtures/nope.conf",
    );
    let out = frf(&work, &["--root", ROOT, "court", "run", &m]);
    assert!(!out.status.success());
    assert!(stderr(&out)
        .contains("fixture frf/courts/cli-malformed-input/fixtures/nope.conf not found"));

    // Missing manifest file itself.
    let out = frf(
        &work,
        &["--root", ROOT, "court", "run", "frf/courts/nope.yaml"],
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("cannot read"));
}

#[test]
fn court_rejects_ids_that_could_escape_the_root() {
    let work = Workdir::new("court-ids");
    work.copy_canonical_tree();
    admit_reference(&work);

    // Court id becomes a run-dir component; a traversal must be refused.
    let m = manifest_variant(&work, "id: cli-malformed-input", "id: ../../evil");
    let out = frf(&work, &["--root", ROOT, "court", "run", &m]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("invalid court id '../../evil'"));

    // Authority id in the manifest is validated at load time.
    let m = manifest_variant(&work, "authority: ref-cli-1.8.2", "authority: ../../x");
    let out = frf(&work, &["--root", ROOT, "court", "run", &m]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("invalid authority id '../../x'"));

    // Nothing was created outside the root.
    assert!(!work.path("evil").exists());
    assert!(!work.path("x.yaml").exists());
}

#[test]
fn fixture_not_referenced_warns_but_runs() {
    let work = Workdir::new("fixture-warn");
    work.copy_canonical_tree();
    admit_reference(&work);

    // No {fixture} placeholder: the fixture is not exercised; a warning must
    // name that observability gap.
    let m = manifest_variant(
        &work,
        "arguments: [\"--strict\", \"{fixture}\"]",
        "arguments: []",
    );
    let out = frf(&work, &["--root", ROOT, "court", "run", &m]);
    assert_success(&out, "court run without fixture reference");
    assert!(stderr(&out).contains("does not exercise it"));
    // Without a file argument both sides hit their no-input path: same exit
    // class (2), different wording → exactly one text residual.
    assert!(work.path("frf/residuals/cli-text-0001.yaml").is_file());
    assert!(!work.path("frf/residuals/cli-exit-0001.yaml").exists());
}

// ---------------------------------------------------------------------------
// Dispositions
// ---------------------------------------------------------------------------

#[test]
fn all_six_dispositions_and_re_disposition() {
    let work = Workdir::new("dispose-six");
    work.copy_canonical_tree();
    admit_reference(&work);
    let run = run_court(&work);

    // Every closure kind round-trips through the file, in sequence, on the
    // same residual (re-disposition is allowed; `open` is not).
    for (kind, expect_block) in [
        ("environmental", false),
        ("oracle_version", false),
        ("harness", true),
        ("unknown", true),
        ("fixed", false),
        ("intentional", true), // intentional on a parity axis ⇒ unclaimable
    ] {
        let out = frf(
            &work,
            &[
                "--root",
                ROOT,
                "residual",
                "dispose",
                "cli-exit-0001",
                "--disposition",
                kind,
                "--reason",
                &format!("regression: {kind}"),
            ],
        );
        assert_success(&out, &format!("dispose {kind}"));
        let rec = raw_residual(&work, "cli-exit-0001");
        assert_eq!(rec["disposition"], kind);
        assert_eq!(rec["reason"], format!("regression: {kind}"));
        // The token follows.
        let tok: serde_yaml::Value = serde_yaml::from_str(
            &fs::read_to_string(work.path("frf/residuals/cli-exit-0001.token.yaml")).unwrap(),
        )
        .unwrap();
        assert_eq!(tok["token"], format!("exit/exit-class/class-change/{kind}"));

        // Claim semantics per closure kind (text residual still open):
        let out = frf(&work, &["--root", ROOT, "receipt", "emit", &run]);
        assert_success(&out, "receipt emit");
        let receipt = stdout(&out);
        let out = frf(&work, &["--root", ROOT, "claim", "compile", &receipt]);
        if expect_block {
            assert!(!out.status.success(), "disposition {kind} must block");
        } else {
            // Blocked anyway by the still-open text residual.
            assert!(!out.status.success(), "text residual still open must block");
            assert!(stderr(&out).contains("cli-text-0001 (text) is open"));
        }
    }

    // Close the text residual; `unknown` on it still blocks.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "residual",
            "dispose",
            "cli-text-0001",
            "--disposition",
            "intentional",
            "--reason",
            "clearer wording",
        ],
    );
    assert_success(&out, "dispose text");
    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &run]);
    assert_success(&out, "receipt emit");
    let receipt = stdout(&out);
    let out = frf(&work, &["--root", ROOT, "claim", "compile", &receipt]);
    // exit is intentional at this point ⇒ no claimable axis.
    assert!(!out.status.success());
    assert!(stderr(&out).contains("no declared observable axis"));

    // Re-dispose exit to fixed ⇒ claim compiles.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "residual",
            "dispose",
            "cli-exit-0001",
            "--disposition",
            "fixed",
            "--reason",
            "candidate patched",
        ],
    );
    assert_success(&out, "dispose exit fixed");
    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &run]);
    assert_success(&out, "receipt emit");
    let receipt = stdout(&out);
    let out = frf(&work, &["--root", ROOT, "claim", "compile", &receipt]);
    assert_success(&out, "claim compile after fix");
}

#[test]
fn disposition_reason_gate() {
    let work = Workdir::new("reason-gate");
    work.copy_canonical_tree();
    admit_reference(&work);
    run_court(&work);

    // Missing --reason: clap refuses at parse time.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "residual",
            "dispose",
            "cli-exit-0001",
            "--disposition",
            "fixed",
        ],
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("reason"));

    // Empty or whitespace-only reason.
    for reason in ["", "   "] {
        let out = frf(
            &work,
            &[
                "--root",
                ROOT,
                "residual",
                "dispose",
                "cli-exit-0001",
                "--disposition",
                "fixed",
                "--reason",
                reason,
            ],
        );
        assert!(!out.status.success());
        assert!(stderr(&out).contains("non-empty one-line reason"));
    }

    // Multi-line reason.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "residual",
            "dispose",
            "cli-exit-0001",
            "--disposition",
            "fixed",
            "--reason",
            "line one\nline two",
        ],
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("single line"));

    // The residual is still open after all refusals.
    assert_eq!(raw_residual(&work, "cli-exit-0001")["disposition"], "open");
}

#[test]
fn ids_cannot_escape_the_root_from_commands() {
    let work = Workdir::new("id-escape");
    work.copy_canonical_tree();
    admit_reference(&work);
    run_court(&work);

    for (verb_args, needle) in [
        (
            vec![
                "residual",
                "dispose",
                "../../evil",
                "--disposition",
                "fixed",
                "--reason",
                "x",
            ],
            "invalid residual id '../../evil'",
        ),
        (
            vec!["receipt", "emit", "../../evil"],
            "invalid run id '../../evil'",
        ),
        (
            vec!["claim", "compile", "../../evil"],
            "invalid receipt id '../../evil'",
        ),
    ] {
        let mut args = vec!["--root", ROOT];
        args.extend(verb_args);
        let out = frf(&work, &args);
        assert!(!out.status.success());
        assert!(stderr(&out).contains(needle), "stderr: {}", stderr(&out));
    }

    // `..` and `.` specifically.
    for id in ["..", "."] {
        let out = frf(
            &work,
            &[
                "--root",
                ROOT,
                "residual",
                "dispose",
                id,
                "--disposition",
                "fixed",
                "--reason",
                "x",
            ],
        );
        assert!(!out.status.success());
        assert!(stderr(&out).contains("invalid residual id"));
    }

    // Nothing escaped: no stray files in the workdir root or above the root.
    assert!(!work.path("evil.yaml").exists());
    assert!(!work.path("evil").exists());
    assert!(!work.dir.parent().unwrap().join("evil.yaml").exists());
}

// ---------------------------------------------------------------------------
// Behavioral edges
// ---------------------------------------------------------------------------

#[test]
fn clean_pair_yields_no_residuals_and_two_axis_claim() {
    // Positive control: a candidate identical in behavior to the reference
    // produces no residuals on either axis, and the claim covers both.
    let work = Workdir::new("clean");
    work.copy_canonical_tree();
    let ref_content = fs::read_to_string(work.path("golden/reference.sh")).unwrap();
    work.write_candidate(&ref_content);
    admit_reference(&work);
    let run = run_court(&work);

    let residuals = fs::read_dir(work.path("frf/residuals")).unwrap().count();
    assert_eq!(residuals, 0, "identical behavior must leave zero residuals");

    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &run]);
    assert_success(&out, "receipt emit");
    let receipt = stdout(&out);
    let out = frf(&work, &["--root", ROOT, "claim", "compile", &receipt]);
    assert_success(&out, "claim compile");
    let text = stdout(&out);
    assert!(
        text.contains("malformed-input exit class and malformed-input first diagnostic line"),
        "claim: {text}"
    );
}

#[test]
fn execution_timeout_kills_and_writes_nothing() {
    let work = Workdir::new("timeout");
    work.copy_canonical_tree();
    work.write_candidate("#!/bin/sh\nsleep 5\n");
    admit_reference(&work);

    let out = frf_env(
        &work,
        &["--root", ROOT, "court", "run", MANIFEST],
        &[("FRF_EXEC_TIMEOUT_MS", "200")],
    );
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("execution timeout"),
        "stderr: {}",
        stderr(&out)
    );

    // A timed-out court writes no evidence at all.
    let captures = fs::read_dir(work.path("frf/captures")).unwrap().count();
    assert_eq!(captures, 0, "no run dir may exist after a timeout");
    let residuals = fs::read_dir(work.path("frf/residuals")).unwrap().count();
    assert_eq!(residuals, 0, "no residuals may exist after a timeout");
}

#[test]
fn receipt_emit_is_idempotent_per_state() {
    let work = Workdir::new("receipt-idem");
    work.copy_canonical_tree();
    admit_reference(&work);
    let run = run_court(&work);

    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &run]);
    assert_success(&out, "receipt emit");
    let first = stdout(&out);
    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &run]);
    assert_success(&out, "receipt emit again");
    let second = stdout(&out);
    assert_eq!(first, second, "same state must yield the same receipt id");
    assert!(stderr(&out).contains("already exists"));

    // Unknown run.
    let out = frf(&work, &["--root", ROOT, "receipt", "emit", "run-nope"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("no such run 'run-nope'"));
}

#[test]
fn claim_compile_rejects_unknown_receipt() {
    let work = Workdir::new("claim-unknown");
    work.copy_canonical_tree();
    let out = frf(&work, &["--root", ROOT, "claim", "compile", "receipt-nope"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("no such receipt 'receipt-nope'"));
}
