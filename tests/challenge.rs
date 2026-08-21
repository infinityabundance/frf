//! Court-challenge acceptance: the negative controls.
//!
//! A court run that yields a pass proves nothing unless the court has
//! demonstrated it can SEE the defect classes it declares. For each built-in
//! mutation operator whose targeted axis the court declares, the challenge
//! runs the court against a MUTANT candidate — a deterministic wrapper of the
//! admitted reference that alters exactly one observable dimension — and
//! requires a divergence on the targeted axis and ONLY on it.
//!
//! 1. the golden court sees both declared defect classes (exit, stderr) with
//!    clean specificity;
//! 2. the mutant runs are ordinary content-addressed runs whose residuals
//!    live on the targeted axis only, and replay reproduces them;
//! 3. the challenge records are content-addressed and their verdicts rederive
//!    (a hand-edited record is refused);
//! 4. unknown operators, operators targeting undeclared axes, and courts
//!    with no built-in mutation surface are refused.

mod common;
use common::*;

use std::fs;

fn challenge(work: &Workdir) -> Vec<String> {
    let out = frf(work, &["--root", ROOT, "court", "challenge", MANIFEST]);
    assert_success(&out, "court challenge");
    let ids: Vec<String> = stdout(&out)
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    assert!(!ids.is_empty(), "the challenge must produce records");
    ids
}

fn challenge_record(work: &Workdir, id: &str) -> serde_json::Value {
    serde_json::from_str(
        &fs::read_to_string(work.path(&format!("frf/challenges/{id}.json"))).unwrap(),
    )
    .unwrap()
}

#[test]
fn the_golden_court_sees_its_declared_defects() {
    let work = Workdir::new("challenge-sees");
    work.copy_canonical_tree();
    admit_reference(&work);

    let ids = challenge(&work);
    assert_eq!(ids.len(), 2, "exit-class + stderr-first-line");

    for id in &ids {
        let rec = challenge_record(&work, id);
        assert_eq!(rec["schema_version"].as_str().unwrap(), "frf-challenge-v1");
        assert_eq!(rec["id"].as_str().unwrap(), id);
        assert_eq!(rec["court"].as_str().unwrap(), "cli-malformed-input");
        let saw = rec["saw_defect"].as_bool().unwrap();
        assert!(saw, "{id} must see its seeded defect");
        let specific = rec["specificity_clean"].as_bool().unwrap();
        assert!(
            specific,
            "{id} must not conflate the mutant with other axes"
        );
        let target = rec["target_axis"].as_str().unwrap();
        let unaffected: Vec<String> = rec["unaffected_axes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            unaffected,
            if target == "exit" {
                vec!["stderr".to_string()]
            } else {
                vec!["exit".to_string()]
            },
            "the unaffected axes are the declared observables minus the target"
        );
        // The mutant artifact is rederivable: the deterministic wrapper of
        // the reference for this operator.
        let op = frf::mutation::MutationOperator::parse(rec["operator"].as_str().unwrap()).unwrap();
        assert_eq!(op.target_axis(), target);
        let wrapper = op.wrapper(rec["reference_sha256"].as_str().unwrap());
        assert_eq!(
            frf::host::sha256_bytes(wrapper.as_bytes()),
            rec["mutant_candidate_sha256"].as_str().unwrap(),
            "{id}: the mutant must be the deterministic wrapper"
        );
        // The observed residual lives on the targeted axis — and only it.
        let run = rec["run"].as_str().unwrap();
        let capture: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(work.path(&format!("frf/captures/{run}/capture.json"))).unwrap(),
        )
        .unwrap();
        assert_eq!(
            capture["residuals"].as_array().unwrap().len(),
            1,
            "{id}: the mutant must diverge on exactly one axis"
        );
        let residual_id = capture["residuals"][0].as_str().unwrap();
        let residual: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(work.path(&format!("frf/residuals/{residual_id}.json"))).unwrap(),
        )
        .unwrap();
        assert_eq!(
            residual["axis"].as_str().unwrap(),
            target,
            "{id}: the observed residual must be on the targeted axis"
        );
    }
}

#[test]
fn the_mutant_runs_are_ordinary_runs_and_replay_reproduces_them() {
    let work = Workdir::new("challenge-replay");
    work.copy_canonical_tree();
    admit_reference(&work);

    let ids = challenge(&work);
    for id in &ids {
        let rec = challenge_record(&work, id);
        let run = rec["run"].as_str().unwrap().to_string();
        // The mutant run is a normal content-addressed run.
        let out = frf(
            &work,
            &["--root", ROOT, "replay", &run, "--policy", "exact"],
        );
        assert_success(&out, &format!("replay of the mutant run {run}"));
        let out_text = format!("{}{}", stdout(&out), stderr(&out));
        assert!(
            out_text.contains("reproduced"),
            "the mutant run must replay: {out_text}"
        );
    }
}

#[test]
fn challenge_records_are_content_addressed_and_refuse_tampering() {
    let work = Workdir::new("challenge-tamper");
    work.copy_canonical_tree();
    admit_reference(&work);
    let ids = challenge(&work);
    let id = &ids[0];

    // Hand-edit a DECLARED field (part of the content address): the verified
    // loader must refuse the mismatch — the name is a claim until recomputed.
    // (The derived verdicts — saw_defect, specificity_clean, the residual
    // list — are recomputed from the run by verification, so a tampered
    // verdict is caught there: tests/verify_tree.rs asserts exactly that.)
    let path = work.path(&format!("frf/challenges/{id}.json"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    }
    let mut rec: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    rec["target_axis"] = serde_json::Value::String("stderr".to_string());
    // Write the tampered record as CANONICAL JSON: the canonical-bytes gate
    // passes, and the content-address check must refuse the edited field.
    fs::write(&path, frf::canon::canonical(&rec).unwrap()).unwrap();

    // The verified loader refuses the tampered record: the verdicts rederive
    // from the run's residuals, and the content address covers the declared
    // fields — a mismatch is a lie, not an edit.
    let store = frf::store::Store::new(work.path(ROOT));
    let err = store.load_challenge(id).unwrap_err();
    assert!(
        err.0.contains("is not content-addressed") || err.0.contains("id mismatch"),
        "the tampered record must be refused: {}",
        err.0
    );

    // The untouched record (the other operator) still verifies.
    let other = ids.iter().find(|i| *i != id).unwrap();
    assert!(store.load_challenge(other).is_ok());
}

#[test]
fn unknown_and_inapplicable_operators_are_refused() {
    let work = Workdir::new("challenge-refuse");
    work.copy_canonical_tree();
    admit_reference(&work);

    // Unknown operator id.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "court",
            "challenge",
            MANIFEST,
            "--operators",
            "bogus",
        ],
    );
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("unknown mutation operator"),
        "{}",
        stderr(&out)
    );

    // An operator whose targeted axis the court does not declare: the seeded
    // defect would be unobservable.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "court",
            "challenge",
            MANIFEST,
            "--operators",
            "stdout-first-line",
        ],
    );
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("does not declare"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_court_without_a_builtin_mutation_surface_cannot_be_challenged() {
    let work = Workdir::new("challenge-blind-court");
    work.copy_canonical_tree();
    admit_reference(&work);

    // A court that declares no observables has no defect class to challenge.
    let no_axes = "frf/courts/cli-malformed-input/no-observables.yaml";
    let manifest: serde_yaml::Value = serde_yaml::from_str(
        &fs::read_to_string(work.path("frf/courts/cli-malformed-input/manifest.yaml")).unwrap(),
    )
    .unwrap();
    let mut decl = manifest.clone();
    decl["court"]["admissibility_envelope"]["observables"] = serde_yaml::Value::Sequence(vec![]);
    fs::write(work.path(no_axes), serde_yaml::to_string(&decl).unwrap()).unwrap();
    let out = frf(&work, &["--root", ROOT, "court", "challenge", no_axes]);
    assert!(
        !out.status.success(),
        "an unchallengeable court must be refused"
    );
    assert!(
        stderr(&out).contains("cannot prove it can see"),
        "{}",
        stderr(&out)
    );
}
