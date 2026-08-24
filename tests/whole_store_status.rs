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
    let run = run_court(work);
    let resolution_run = run_resolution_court(work);
    let exit_id = residual_id(work, &run, "exit");
    let text_id = residual_id(work, &run, "stderr");
    let reobserved_text_id = residual_id(work, &resolution_run, "stderr");
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
            text_id.as_str(),
            "clearer diagnostic wording; documented divergence",
        ),
        (
            reobserved_text_id.as_str(),
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

/// An ORPHANED residual — a residual whose parent run does not verify — must
/// refuse the whole-store status: the residuals/ namespace is enumerated
/// independently of the capture walk, and a residual whose parent run is
/// missing is corruption, not a harmless stray file.
#[test]
fn an_orphaned_residual_refuses_the_whole_store_status() {
    let work = Workdir::new("whole-store-residual");
    work.copy_canonical_tree();
    admit_reference(&work);
    let run = run_court(&work);

    // Plant a genuine orphan: take the real exit residual, point it at a
    // PHANTOM run, recompute its content address from its own fields (so the
    // identity rederives), and write BOTH the leaf (inside the phantom run's
    // residuals dir) and the derived index copy. The whole-store walk must
    // refuse: the parent run does not exist and does not verify.
    let exit_id = residual_id(&work, &run, "exit");
    let copy_path = work.path(&format!("{ROOT}/residuals/{exit_id}.json"));
    let mut record: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&copy_path).unwrap()).unwrap();
    record["run"] = serde_json::Value::String(format!("run-orphan-{}", "0".repeat(60)));
    let record: frf::model::ResidualRecord =
        serde_json::from_value(record).expect("the rewritten record still deserializes");
    let orphan_id = frf::semantics::residual_record_identity(&record).unwrap();
    let orphan_canonical = frf::canon::canonical(&record).unwrap();
    // The orphan's leaf inside its phantom run + the derived index copy.
    let phantom_run = record.run.clone();
    let leaf = work.path(&format!(
        "{ROOT}/captures/{phantom_run}/residuals/{orphan_id}.json"
    ));
    fs::create_dir_all(leaf.parent().unwrap()).unwrap();
    fs::write(&leaf, &orphan_canonical).unwrap();
    fs::write(
        work.path(&format!("{ROOT}/residuals/{orphan_id}.json")),
        &orphan_canonical,
    )
    .unwrap();

    let out = frf(&work, &["--root", ROOT, "evidence", "status"]);
    assert!(
        !out.status.success(),
        "an orphaned residual must refuse the whole-store status"
    );
    let text = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        text.contains(&format!("residual {orphan_id}")),
        "the refusal names the orphan: {text}"
    );
    assert!(
        text.contains("no leaf") || text.contains("does not verify") || text.contains("incomplete"),
        "the refusal names the missing parent run: {text}"
    );
}
