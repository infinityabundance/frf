//! Claim renderers — presentation, never new epistemic meaning (spec/claim.md
//! §4): the compiled Claim IR renders as prose, canonical JSON, SARIF 2.1.0,
//! a CI status document, or a badge. The renderers are pure functions of the
//! compiled claim; there is no format in which a claim says more than its
//! evidence licensed.

mod common;
use common::*;

/// Drive the golden path to a compiled claim (resolution receipt → claim).
fn compiled_claim(work: &Workdir) -> String {
    admit_reference(work);
    let _run = run_court(work);
    let resolution_run = run_resolution_court(work);
    for (id, args) in [
        (
            "cli-exit-0001",
            vec![
                "--disposition",
                "fixed",
                "--resolution-run",
                &resolution_run,
                "--reason",
                "candidate patched to preserve reference exit class",
            ],
        ),
        (
            "cli-text-0001",
            vec![
                "--disposition",
                "intentional",
                "--reason",
                "clearer diagnostic wording",
            ],
        ),
        (
            "cli-text-0002",
            vec![
                "--disposition",
                "intentional",
                "--reason",
                "clearer diagnostic wording (re-observed)",
            ],
        ),
    ] {
        let mut cmd: Vec<&str> = vec!["--root", ROOT, "residual", "dispose", id];
        cmd.extend_from_slice(&args);
        let out = frf(work, &cmd);
        assert_success(&out, "dispose");
    }
    let out = frf(work, &["--root", ROOT, "receipt", "emit", &resolution_run]);
    assert_success(&out, "receipt emit");
    let receipt = stdout(&out);
    let out = frf(work, &["--root", ROOT, "claim", "compile", &receipt]);
    assert_success(&out, "claim compile");
    receipt
}

#[test]
fn the_claim_renders_into_every_presentation_without_new_meaning() {
    let work = Workdir::new("render-all");
    work.copy_canonical_tree();
    let receipt = compiled_claim(&work);

    // prose: the compiled sentences (the human renderer).
    let out = frf(
        &work,
        &[
            "--root", ROOT, "claim", "render", &receipt, "--format", "prose",
        ],
    );
    assert_success(&out, "render prose");
    let prose = stdout(&out);
    assert!(prose.contains("malformed-input exit class"));
    assert!(prose.contains("does not establish byte-identical stderr"));

    // json: the IR itself, canonically.
    let out = frf(
        &work,
        &[
            "--root", ROOT, "claim", "render", &receipt, "--format", "json",
        ],
    );
    assert_success(&out, "render json");
    let ir: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(ir["schema_version"], "frf-claim-v7");
    assert_eq!(ir["receipt"], receipt);

    // sarif: a 2.1.0 document — the claim as a none-level result, the
    // excluded residual as a note.
    let out = frf(
        &work,
        &[
            "--root", ROOT, "claim", "render", &receipt, "--format", "sarif",
        ],
    );
    assert_success(&out, "render sarif");
    let sarif: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(sarif["version"], "2.1.0");
    assert_eq!(sarif["runs"][0]["tool"]["driver"]["name"], "frf");
    let results = sarif["runs"][0]["results"].as_array().unwrap();
    assert!(
        results
            .iter()
            .any(|r| r["ruleId"] == "frf/claim" && r["level"] == "none"),
        "the admissible claim renders as a none-level result"
    );
    assert!(
        results
            .iter()
            .any(|r| r["ruleId"] == "frf/residual" && r["level"] == "note"),
        "the excluded residual renders as a note"
    );

    // ci: the gate document — pass, scope, premises.
    let out = frf(
        &work,
        &[
            "--root", ROOT, "claim", "render", &receipt, "--format", "ci",
        ],
    );
    assert_success(&out, "render ci");
    let ci: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(ci["schema_version"], "frf-ci-status-v1");
    assert_eq!(ci["status"], "pass");
    assert_eq!(ci["claim"], receipt);
    assert!(ci["observable_scope"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("exit")));

    // badge: a deterministic SVG carrying the scope.
    let out = frf(
        &work,
        &[
            "--root", ROOT, "claim", "render", &receipt, "--format", "badge",
        ],
    );
    assert_success(&out, "render badge");
    let badge = stdout(&out);
    assert!(badge.starts_with("<svg "));
    assert!(badge.contains("admissible"));
    assert!(badge.contains("exit"));
    let out2 = frf(
        &work,
        &[
            "--root", ROOT, "claim", "render", &receipt, "--format", "badge",
        ],
    );
    assert_eq!(badge, stdout(&out2), "the badge is deterministic");

    // An unknown format is refused.
    let out = frf(
        &work,
        &[
            "--root", ROOT, "claim", "render", &receipt, "--format", "html",
        ],
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("unknown render format"));

    // Rendering a receipt with NO compiled claim is refused: the renderers
    // present the compiled IR, they do not invent it.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "claim",
            "render",
            "receipt-run-nonexistent-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--format",
            "badge",
        ],
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("no compiled claim"));
}

#[test]
fn the_sarif_document_is_deterministic() {
    // Rendering the SAME compiled claim twice is byte-identical: the render
    // is a pure function of the IR (prose is one renderer; the presentation
    // never changes between runs).
    let work = Workdir::new("render-sarif");
    work.copy_canonical_tree();
    let receipt = compiled_claim(&work);
    let a = frf(
        &work,
        &[
            "--root", ROOT, "claim", "render", &receipt, "--format", "sarif",
        ],
    );
    assert_success(&a, "render a");
    let b = frf(
        &work,
        &[
            "--root", ROOT, "claim", "render", &receipt, "--format", "sarif",
        ],
    );
    assert_success(&b, "render b");
    assert_eq!(stdout(&a), stdout(&b), "SARIF is deterministic");
}
