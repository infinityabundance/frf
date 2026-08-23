//! The WHOLE-STORE status (P0): `evidence status`'s `graph_verified` now
//! enumerates EVERY protocol-object namespace and passes each object through
//! its verified loader — authorities, captures, residuals + disposition
//! events, receipts, reductions + minimizer evidence, series, trajectories,
//! challenges + mutation evidence, witnesses, independence, attempts, harness
//! events, claims — not just the receipt/capture roots. An orphaned,
//! malformed, or tampered protocol object ANYWHERE in the tree fails the
//! graph; `replay_verified` stays `not-performed` because the status command
//! never re-executes anything.

mod common;
use common::*;

use std::fs;

/// The golden path to a compiled claim: the failing court run + the
/// resolution run + the disposals that close the residual surfaces, then the
/// final receipt and its compiled claim. Returns the final receipt id.
fn golden_to_claim(work: &Workdir) -> String {
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
    receipt_final
}

/// A tampered CLAIM document — downstream of the receipt roots the old
/// receipts/captures-only status walked — must refuse the whole-store status:
/// the claim namespace is verified, not assumed, and the graph cannot report
/// `graph_verified: yes` while any committed protocol object is corrupt.
#[test]
fn a_tampered_claim_refuses_the_whole_store_status() {
    let work = Workdir::new("whole-store-claim");
    work.copy_canonical_tree();
    admit_reference(&work);
    let receipt_final = golden_to_claim(&work);

    // The whole store verifies, the claims namespace was walked, and the
    // status command itself never re-executes.
    let out = frf(&work, &["--root", ROOT, "evidence", "status"]);
    assert_success(&out, "whole store verifies");
    let text = stdout(&out);
    assert!(text.contains("graph_verified: yes"), "graph: {text}");
    assert!(
        text.contains("claims=1"),
        "the claims namespace was walked: {text}"
    );
    assert!(
        text.contains("replay_verified: not-performed"),
        "status never re-executes: {text}"
    );

    // Tamper the claim: flip one byte of the canonical document.
    let claim = claim_path(&work, &receipt_final);
    let bytes = fs::read(&claim).unwrap();
    let mut tampered = bytes.clone();
    tampered[bytes.len() - 2] ^= 0x01;
    fs::write(&claim, &tampered).unwrap();

    let out = frf(&work, &["--root", ROOT, "evidence", "status"]);
    assert!(
        !out.status.success(),
        "a tampered claim must refuse the whole-store status"
    );
    let text = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        text.contains("claim "),
        "the refusal names the claim: {text}"
    );
}

/// An ORPHANED residual — a record no capture references — must refuse the
/// whole-store status: the residuals/ namespace is enumerated independently
/// of the capture walk, and a record whose parent run does not verify is
/// corruption, not a harmless stray file.
#[test]
fn an_orphaned_residual_refuses_the_whole_store_status() {
    let work = Workdir::new("whole-store-residual");
    work.copy_canonical_tree();
    admit_reference(&work);
    let run = run_court(&work);

    // A real residual record's bytes, planted under an id no run references
    // (and whose content address does not rederive from its fields).
    let exit_id = residual_id(&work, &run, "exit");
    let real = fs::read(work.path(&format!("{ROOT}/residuals/{exit_id}.json"))).unwrap();
    fs::write(
        work.path(&format!("{ROOT}/residuals/cli-exit-9999.json")),
        &real,
    )
    .unwrap();

    let out = frf(&work, &["--root", ROOT, "evidence", "status"]);
    assert!(
        !out.status.success(),
        "an orphaned residual must refuse the whole-store status"
    );
    let text = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        text.contains("residual cli-exit-9999"),
        "the refusal names the orphan: {text}"
    );
}
