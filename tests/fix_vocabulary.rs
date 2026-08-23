//! The fixed-vs-non-reproduction vocabulary (frf-disposition-v3): a later
//! pass on the SAME candidate artifact is real evidence of nondeterminism,
//! never remediation evidence.
//!
//!   fixed        — the resolution run executed a CHANGED candidate artifact
//!                  and the residual no longer reproduces (unblocks claims);
//!   nonreproduced — ONE later pass on the SAME candidate (still blocks);
//!   stabilized   — REPEATED later passes on the SAME candidate, backed by a
//!                  verified trajectory (still blocks).
//!
//! The gates are enforced at dispose time AND re-verified when a receipt is
//! loaded: a same-candidate pass can never become `fixed`, and a changed
//! candidate can never be recorded as `nonreproduced`.

mod common;
use common::*;

use std::fs;

/// The flaky candidate: exits 2 (the reference's class — a PASS) when the
/// marker exists, otherwise exits 1 (a DIVERGENCE) and CREATES the marker.
/// The candidate BYTES are identical across every run — the artifact identity
/// never changes — so the same-candidate rules are exercised deterministically.
fn write_flaky_candidate(work: &Workdir) {
    let marker = work.dir.join(".frf-flake-marker");
    let marker = marker.display().to_string();
    work.write_candidate(&format!(
        "#!/bin/sh\nif [ -e {marker} ]; then exit 2; else touch {marker}; exit 1; fi\n"
    ));
}

#[test]
fn fixed_requires_a_changed_candidate_artifact() {
    let work = Workdir::new("fix-vocab-same-candidate");
    work.copy_canonical_tree();
    admit_reference(&work);
    write_flaky_candidate(&work);

    // Run 1 (marker absent): the flaky candidate diverges -> exit residual.
    let run1 = run_court(&work);
    let exit_id = residual_id(&work, &run1, "exit");
    // Run 2 (marker present): the SAME candidate passes the exit axis.
    let run2 = run_court(&work);
    assert_ne!(
        run1, run2,
        "the divergence and the pass are different observations"
    );

    // A pass on the SAME candidate is not a fix: `fixed` must be refused and
    // must name the same-candidate rule, not fail for an unrelated reason.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "residual",
            "dispose",
            &exit_id,
            "--disposition",
            "fixed",
            "--resolution-run",
            &run2,
            "--reason",
            "candidate patched",
        ],
    );
    assert!(
        !out.status.success(),
        "same-candidate fixed must be refused"
    );
    let err = stderr(&out);
    assert!(
        err.contains("SAME candidate"),
        "the refusal must name the same-candidate rule: {err}"
    );

    // The honest label: `nonreproduced` with the observation run is accepted.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "residual",
            "dispose",
            &exit_id,
            "--disposition",
            "nonreproduced",
            "--observation-run",
            &run2,
            "--reason",
            "flaky under load; passed once on the same candidate",
        ],
    );
    assert_success(&out, "nonreproduced dispose");

    // The projected disposition is `nonreproduced` (the event recorded it).
    let store = frf::store::Store::new(work.path(ROOT));
    let projected = store
        .current_disposition(&exit_id)
        .expect("disposition loads");
    assert_eq!(projected.as_str(), "nonreproduced");
    assert!(
        projected.is_blocking(),
        "a non-reproduction is not remediation evidence: it must still block claims"
    );
}

#[test]
fn nonreproduced_requires_the_same_candidate() {
    let work = Workdir::new("fix-vocab-changed-candidate");
    work.copy_canonical_tree();
    admit_reference(&work);

    let run1 = run_court(&work);
    let exit_id = residual_id(&work, &run1, "exit");
    // The resolution court runs the PATCHED candidate (different bytes).
    let resolution_run = run_resolution_court(&work);

    // A candidate change is a FIX, not a non-reproduction: `nonreproduced`
    // must be refused and must name the changed-candidate rule.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "residual",
            "dispose",
            &exit_id,
            "--disposition",
            "nonreproduced",
            "--observation-run",
            &resolution_run,
            "--reason",
            "passed once",
        ],
    );
    assert!(
        !out.status.success(),
        "changed-candidate nonreproduced must be refused"
    );
    let err = stderr(&out);
    assert!(
        err.contains("DIFFERENT candidate"),
        "the refusal must name the changed-candidate rule: {err}"
    );
}

#[test]
fn stabilized_refuses_unverified_or_subfloor_evidence() {
    let work = Workdir::new("fix-vocab-stabilized-gates");
    work.copy_canonical_tree();
    admit_reference(&work);

    let run1 = run_court(&work);
    let exit_id = residual_id(&work, &run1, "exit");

    // A trajectory id that is not a document key is refused structurally.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "residual",
            "dispose",
            &exit_id,
            "--disposition",
            "stabilized",
            "--trajectory",
            "zzz",
            "--consecutive-passes",
            "2",
            "--reason",
            "settled",
        ],
    );
    assert!(!out.status.success(), "bogus trajectory must be refused");

    // One pass is `nonreproduced`, never `stabilized` — the floor is 2.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "residual",
            "dispose",
            &exit_id,
            "--disposition",
            "stabilized",
            "--trajectory",
            "a.repeat_index.b",
            "--consecutive-passes",
            "1",
            "--reason",
            "settled",
        ],
    );
    assert!(
        !out.status.success(),
        "sub-floor stabilized must be refused"
    );
    let err = stderr(&out);
    assert!(
        err.contains("protocol floor"),
        "the refusal must name the floor rule: {err}"
    );

    // A real trajectory of a DIFFERENT lineage is refused (the subject must
    // be this residual's lineage).
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "residual",
            "dispose",
            &exit_id,
            "--disposition",
            "stabilized",
            "--trajectory",
            &format!("{}.repeat_index.{}", "1".repeat(64), "2".repeat(64)),
            "--consecutive-passes",
            "2",
            "--reason",
            "settled",
        ],
    );
    assert!(
        !out.status.success(),
        "wrong-lineage trajectory must be refused"
    );
}

#[test]
fn stabilized_accepts_a_verified_trajectory_tail() {
    let work = Workdir::new("fix-vocab-stabilized");
    work.copy_canonical_tree();
    admit_reference(&work);
    write_flaky_candidate(&work);

    // One series of three repetitions: point 1 diverges (marker absent),
    // points 2-3 pass (marker present). The exit lineage is observed at
    // point 1 only -> its trajectory tail is two consecutive
    // non-reproductions under the SAME candidate.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "court",
            "run",
            "frf/courts/cli-malformed-input/manifest.yaml",
            "--repeat",
            "3",
        ],
    );
    assert_success(&out, "court run --repeat 3");

    // The exit residual of the FIRST repetition (the run id is the first
    // point's run). Resolve it through the trajectory's subject lineage:
    // read the exit trajectory, take its first point's residual.
    let traj_dir = work.path("frf/trajectories");
    let mut exit_traj = None;
    for entry in fs::read_dir(&traj_dir).unwrap() {
        let path = entry.unwrap().path();
        let doc: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        if doc["axis"] == "exit" {
            exit_traj = Some((path, doc));
            break;
        }
    }
    let (traj_path, traj) = exit_traj.expect("the exit lineage's trajectory exists");
    let observations = traj["observations"].as_array().unwrap();
    assert_eq!(observations.len(), 3, "one observation per repetition");
    let tail: Vec<bool> = observations
        .iter()
        .skip(1)
        .map(|o| o["observed"].as_bool().unwrap())
        .collect();
    assert_eq!(
        tail,
        vec![false, false],
        "the exit divergence does not reproduce in the tail"
    );
    let first_residual = observations[0]["residual"].as_str().unwrap().to_string();
    let run1 = observations[0]["run"].as_str().unwrap().to_string();
    assert_eq!(run1, traj["observations"][0]["run"].as_str().unwrap());

    // The trajectory id is the document key {lineage}.{coordinate}.{series}.
    let traj_id = traj_path
        .file_name()
        .unwrap()
        .to_string_lossy()
        .trim_end_matches(".json")
        .to_string();
    assert!(
        traj_id.contains(".repeat_index."),
        "trajectory id shape: {traj_id}"
    );

    // The same-candidate gate holds: the residual's original run must carry
    // the SAME candidate as the passing points. The flaky candidate is
    // byte-identical everywhere, so the stabilized disposition is accepted.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "residual",
            "dispose",
            &first_residual,
            "--disposition",
            "stabilized",
            "--trajectory",
            &traj_id,
            "--consecutive-passes",
            "2",
            "--reason",
            "two consecutive non-reproductions on the same candidate",
        ],
    );
    assert_success(&out, "stabilized dispose (verified trajectory tail)");
}

#[test]
fn nonreproduced_still_blocks_positive_claims() {
    let work = Workdir::new("fix-vocab-blocks");
    work.copy_canonical_tree();
    admit_reference(&work);
    write_flaky_candidate(&work);

    // run1 diverges; run2 (same candidate) passes the exit axis.
    let run1 = run_court(&work);
    let run2 = run_court(&work);
    let exit_id = residual_id(&work, &run1, "exit");
    let run1_text = residual_id(&work, &run1, "stderr");
    let run2_text = residual_id(&work, &run2, "stderr");

    // Close everything that is legitimately closable; the exit residual is
    // recorded `nonreproduced` — real evidence of nondeterminism, NOT
    // remediation evidence.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "residual",
            "dispose",
            &exit_id,
            "--disposition",
            "nonreproduced",
            "--observation-run",
            &run2,
            "--reason",
            "flaky; passed once on the same candidate",
        ],
    );
    assert_success(&out, "nonreproduced dispose");
    for (id, reason) in [
        (&run1_text, "clearer diagnostic wording"),
        (&run2_text, "clearer diagnostic wording (re-observed)"),
    ] {
        let out = frf(
            &work,
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
        assert_success(&out, "intentional dispose");
    }

    // The claim compiled from the passing run's receipt is STILL refused: the
    // nonreproduced divergence on the same surface blocks it.
    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &run2]);
    assert_success(&out, "receipt emit");
    let receipt = stdout(&out);
    let out = frf(&work, &["--root", ROOT, "claim", "compile", &receipt]);
    assert!(
        !out.status.success(),
        "a nonreproduced residual must block the claim"
    );
    let err = stderr(&out);
    assert!(
        err.contains("nonreproduced"),
        "the refusal must name the nonreproduced residual: {err}"
    );
}
