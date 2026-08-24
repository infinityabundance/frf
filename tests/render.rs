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
    let run = run_court(work);
    let resolution_run = run_resolution_court(work);
    // Residual ids are CONTENT ADDRESSES (FRF/RESIDUAL/v1 over the run +
    // divergence): resolve them from the runs instead of assuming storage
    // labels.
    let exit_id = residual_id(work, &run, "exit");
    let text_id = residual_id(work, &run, "stderr");
    let reobserved_text_id = residual_id(work, &resolution_run, "stderr");
    for (id, args) in [
        (
            exit_id.as_str(),
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
            text_id.as_str(),
            vec![
                "--disposition",
                "intentional",
                "--reason",
                "clearer diagnostic wording",
            ],
        ),
        (
            reobserved_text_id.as_str(),
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
    assert_eq!(ir["schema_version"], "frf-claim-v12");
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

/// The P0 semantic-non-bypass regression: a SELF-CONSISTENT forged claim
/// (a canonical document whose id rederives, placed at `claims/<id>.json`
/// with its by-receipt index marker) must be REFUSED by every renderer —
/// the renderers present VERIFIED evidence, never a hand-written file, so
/// "I claim whatever I want" cannot enter SARIF/CI/badge/prose output
/// without going through claim compilation.
#[test]
fn a_self_consistent_forged_claim_is_refused_by_every_renderer() {
    let work = Workdir::new("render-forgery");
    work.copy_canonical_tree();
    let receipt = compiled_claim(&work);

    // The genuine claim document.
    let genuine: serde_json::Value = claim_json(&work, &receipt);

    // Forge: tamper the proposition (say whatever we want), keep everything
    // else, and recompute a VALID content address for the tampered document
    // (FRF/CLAIM/v1 over the canonical document minus the id). The forged
    // claim is cryptographically self-consistent — the id rederives.
    let mut forged = genuine.clone();
    forged["proposition"] = serde_json::json!("parity(cells=[]): I claim whatever I want");
    let mut doc = forged.clone();
    doc.as_object_mut().unwrap().remove("id");
    let canonical = frf::canon::canonical(&doc).unwrap();
    let forged_id = frf::host::sha256_bytes(format!("FRF/CLAIM/v1\n{canonical}").as_bytes());
    forged["id"] = serde_json::json!(forged_id);
    let forged_bytes = frf::canon::canonical(&forged).unwrap();
    std::fs::write(
        work.path(&format!("{ROOT}/claims/{forged_id}.json")),
        &forged_bytes,
    )
    .unwrap();
    std::fs::create_dir_all(work.path(&format!("{ROOT}/claims/by-receipt/{receipt}"))).unwrap();
    std::fs::write(
        work.path(&format!("{ROOT}/claims/by-receipt/{receipt}/{forged_id}")),
        &receipt,
    )
    .unwrap();

    // The forged claim's id rederives from its own bytes (it is canonical
    // and content-addressed), yet every renderer REFUSES it: the claim's
    // proposition does not rederive from its verified scope.
    for format in ["prose", "json", "sarif", "ci", "badge"] {
        let out = frf(
            &work,
            &[
                "--root", ROOT, "claim", "render", &forged_id, "--format", format,
            ],
        );
        assert!(
            !out.status.success(),
            "render {format} accepted the forged claim"
        );
        assert!(
            stderr(&out).contains("proposition does not rederive")
                || stderr(&out).contains("does not rederive"),
            "render {format} refused for the wrong reason: {}",
            stderr(&out)
        );
    }

    // The genuine claim still renders by its own id (the forged one never
    // displaced it). Rendering by the RECEIPT is now correctly ambiguous —
    // two claims are bound to it — and the command names the ambiguity.
    let genuine_id = genuine["id"].as_str().unwrap();
    let out = frf(
        &work,
        &[
            "--root", ROOT, "claim", "render", genuine_id, "--format", "ci",
        ],
    );
    assert_success(&out, "the genuine claim still renders");
    let out = frf(
        &work,
        &[
            "--root", ROOT, "claim", "render", &receipt, "--format", "ci",
        ],
    );
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("has 2 compiled claims"),
        "the ambiguity is named: {}",
        stderr(&out)
    );
}

/// A receipt compiled under two admission policies is TWO claims — a
/// content-addressed claim is a projection of (receipt, universe, policy),
/// not a slot on the receipt — and both coexist forever.
#[test]
fn a_receipt_compiled_under_two_policies_yields_two_coexisting_claims() {
    let work = Workdir::new("render-two-claims");
    work.copy_canonical_tree();
    let receipt = compiled_claim(&work);

    // Compile again under a different policy.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "claim",
            "compile",
            &receipt,
            "--policy",
            "high-assurance",
        ],
    );
    assert!(
        !out.status.success(),
        "high-assurance without its evidence refuses"
    );

    // Render by RECEIPT is now ambiguous (two claims would exist after the
    // second compile) — the command names the ambiguity instead of picking
    // one arbitrarily.
    let claims = claim_json_all(&work, &receipt);
    assert_eq!(claims.len(), 1, "only the baseline claim compiled");
    let out = frf(
        &work,
        &[
            "--root", ROOT, "claim", "render", &receipt, "--format", "prose",
        ],
    );
    assert_success(&out, "a single claim renders by receipt");
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
