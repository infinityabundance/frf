//! Trajectory protocol tests: repeated-run courts (`--repeat N`) write
//! residual trajectories over the `repeat_index` axis, receipts derive their
//! `sign` from them, and the verified loaders re-derive both.
//!
//! A single-run court keeps the honest `not-observed` sign: one run cannot
//! observe drift or slew. A repeated-run court can — and the trajectory is
//! the executable evidence for it.

mod common;
use common::*;

use std::fs;

#[test]
fn repeated_court_writes_a_persistent_trajectory_and_the_receipt_derives_its_sign() {
    let work = Workdir::new("trajectory-persistent");
    work.copy_canonical_tree();
    admit_reference(&work);

    // The golden candidate diverges DETERMINISTICALLY on exit + stderr: all
    // repetitions re-observed the identical evidence (one content-addressed
    // run, reused) and the trajectory must classify it persistent/stable.
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
    let run = stdout(&out);
    assert!(run.starts_with("run-cli-malformed-input-"), "run id: {run}");

    // Two divergence lineages (exit + stderr), both persistent/stable.
    let mut trajectories: Vec<serde_yaml::Value> = fs::read_dir(work.path("frf/trajectories"))
        .unwrap()
        .map(|e| {
            let path = e.unwrap().path();
            serde_yaml::from_str::<serde_yaml::Value>(&fs::read_to_string(&path).unwrap()).unwrap()
        })
        .collect();
    assert_eq!(trajectories.len(), 2, "exit + stderr lineages");
    trajectories.sort_by_key(|t| t["subject"].as_str().unwrap().to_string());
    let mut series_id = String::new();
    for t in &trajectories {
        assert_eq!(t["schema_version"], "frf-trajectory-v2");
        assert_eq!(t["coordinate_system"], "repeat_index");
        assert_eq!(t["derivation"]["drift"], "persistent");
        assert_eq!(t["derivation"]["slew"], "stable");
        assert_eq!(t["derivation"]["localization"], "none");
        assert_eq!(t["derivation"]["bands"], 1);
        let obs = t["observations"].as_sequence().unwrap();
        assert_eq!(obs.len(), 3, "one observation per repetition");
        for (i, o) in obs.iter().enumerate() {
            assert_eq!(o["point_index"], (i + 1) as u64);
            assert_eq!(o["coordinate"], (i + 1).to_string());
            assert_eq!(o["run"], run, "identical evidence is the same run");
            assert_eq!(o["observed"], true);
            assert!(o["residual"].as_str().unwrap().starts_with("cli-"));
            assert!(
                o["fingerprint"].as_str().unwrap().len() == 64,
                "observed entry carries the exact fingerprint"
            );
        }
        series_id = t["series"].as_str().unwrap().to_string();
    }
    assert_eq!(series_id.len(), 64, "series content address");

    // The ExecutionSeries record: one series, three dense points, all
    // referencing the single content-addressed run.
    let series_dir = work.path("frf/series");
    let series_files: Vec<_> = fs::read_dir(&series_dir).unwrap().collect();
    assert_eq!(series_files.len(), 1, "one repeat_index series");
    let series: serde_yaml::Value = serde_yaml::from_str(
        &fs::read_to_string(work.path(&format!("frf/series/{series_id}.yaml"))).unwrap(),
    )
    .unwrap();
    assert_eq!(series["schema_version"], "frf-series-v1");
    assert_eq!(series["id"], series_id);
    assert_eq!(series["coordinate_system"], "repeat_index");
    let points = series["points"].as_sequence().unwrap();
    assert_eq!(points.len(), 3);
    for (i, p) in points.iter().enumerate() {
        assert_eq!(p["point_index"], (i + 1) as u64);
        assert_eq!(p["run"], run);
    }

    // The receipt derived from this repeated run carries the trajectory's
    // classification in its sign block.
    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &run]);
    assert_success(&out, "receipt emit (repeated run)");
    let receipt = stdout(&out);
    let rec: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("frf/receipts/{receipt}.json"))).unwrap(),
    )
    .unwrap();
    assert_eq!(rec["residuals"].as_array().unwrap().len(), 2);
    for res in rec["residuals"].as_array().unwrap() {
        assert_eq!(res["sign"]["norm"], "repeated-run");
        assert_eq!(res["sign"]["drift"], "persistent");
        assert_eq!(res["sign"]["slew"], "stable");
        assert_eq!(
            res["sign"]["series"], series_id,
            "the receipt pins the series snapshot its sign was derived from"
        );
    }

    // The verified path agrees: export the bundle and verify it (this runs
    // load_receipt_verified, which rederives the sign from the trajectory).
    let out = frf(
        &work,
        &[
            "--root", ROOT, "bundle", "export", &receipt, "--output", "traj.frf",
        ],
    );
    assert_success(&out, "bundle export (repeated run)");
    let out = frf(&work, &["bundle", "verify", "traj.frf"]);
    assert_success(&out, "bundle verify (repeated run)");
    assert!(
        fs::read_dir(work.path("traj.frf/trajectories"))
            .unwrap()
            .count()
            >= 2,
        "the bundle closure must carry the trajectories"
    );
    assert!(
        fs::read_dir(work.path("traj.frf/series")).unwrap().count() >= 1,
        "the bundle closure must carry the series record"
    );
}

#[test]
fn repeated_court_with_a_nondeterministic_candidate_writes_a_valid_trajectory() {
    let work = Workdir::new("trajectory-transient");
    work.copy_canonical_tree();
    admit_reference(&work);
    // A candidate that matches the reference's behavior about half the time:
    // the divergence pattern across repetitions is nondeterministic, which is
    // exactly what the repeat axis is FOR.
    work.write_candidate(
        "#!/bin/bash\nfile=\"\"\nfor arg in \"$@\"; do\n  case \"$arg\" in\n    --strict) ;;\n    *) file=\"$arg\" ;;\n  esac\ndone\nif [ $((RANDOM % 2)) -eq 0 ]; then\n  echo \"tool: $file:4: unknown directive 'servre'\" >&2\n  exit 2\nelse\n  echo \"error: unknown directive servre at line 4\" >&2\n  exit 1\nfi\n",
    );
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "court",
            "run",
            "frf/courts/cli-malformed-input/manifest.yaml",
            "--repeat",
            "5",
        ],
    );
    assert_success(&out, "court run --repeat 5 (nondeterministic)");
    let run = stdout(&out);

    // Robust against the (small) chance that every repetition matched: if any
    // divergence was observed, the trajectory must exist and be consistent.
    let dir = work.path("frf/trajectories");
    let files: Vec<_> = fs::read_dir(&dir)
        .map(|d| d.map(|e| e.unwrap().path()).collect())
        .unwrap_or_default();
    if files.is_empty() {
        // Every repetition matched; the run has no residuals and no
        // trajectory exists. The series record still documents the
        // experiment.
        assert!(
            fs::read_dir(work.path("frf/series")).unwrap().count() >= 1,
            "the repeat experiment must leave a series record"
        );
        return;
    }
    assert!(files.len() <= 2, "exit + stderr lineages at most");
    for path in &files {
        let t: serde_yaml::Value =
            serde_yaml::from_str(&fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(t["schema_version"], "frf-trajectory-v2");
        assert_eq!(t["coordinate_system"], "repeat_index");
        let obs = t["observations"].as_sequence().unwrap();
        assert_eq!(obs.len(), 5);
        // The derivation must be the deterministic classification of the
        // observed pattern.
        let observed: Vec<bool> = obs
            .iter()
            .map(|o| o["observed"].as_bool().unwrap())
            .collect();
        let has_true = observed.iter().any(|o| *o);
        assert!(
            has_true,
            "a trajectory only exists for an observed divergence"
        );
        let n = observed.len();
        let tset: Vec<usize> = observed
            .iter()
            .enumerate()
            .filter(|(_, o)| **o)
            .map(|(i, _)| i)
            .collect();
        let expected_drift = if tset.len() == n {
            "persistent"
        } else if tset.first() == Some(&0) && tset.last() == Some(&(n - 1)) {
            "recurrent"
        } else {
            "transient"
        };
        let expected_slew = if tset.len() == n {
            "stable"
        } else if tset.last().unwrap() - tset.first().unwrap() + 1 == tset.len() {
            if tset.first() == Some(&0) || tset.last() == Some(&(n - 1)) {
                "abrupt"
            } else {
                "burst"
            }
        } else {
            "recurrent"
        };
        assert_eq!(t["derivation"]["drift"], expected_drift);
        assert_eq!(t["derivation"]["slew"], expected_slew);
        // The derivation's localization/bands are the deterministic
        // companions (re-derived by frf::trajectory::classify).
        let d = frf::trajectory::classify(&observed).unwrap();
        assert_eq!(t["derivation"]["localization"], d.localization.as_str());
        assert_eq!(t["derivation"]["bands"], d.bands);
        // Observed entries reference a real residual whose fingerprint is the
        // observation fingerprint, recorded against a real run.
        for o in obs {
            let repetition_run = o["run"].as_str().unwrap().to_string();
            assert!(
                fs::read_to_string(
                    work.path(&format!("frf/captures/{repetition_run}/capture.yaml"))
                )
                .is_ok(),
                "observation run must exist"
            );
            if o["observed"].as_bool().unwrap() {
                let id = o["residual"].as_str().unwrap();
                let record: serde_yaml::Value = serde_yaml::from_str(
                    &fs::read_to_string(work.path(&format!("frf/residuals/{id}.yaml"))).unwrap(),
                )
                .unwrap();
                assert_eq!(record["run"].as_str().unwrap(), repetition_run);
            }
        }
    }

    // The receipt from the first repetition emits and verifies (its sign
    // derives from the trajectory when that run observed residuals).
    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &run]);
    assert_success(&out, "receipt emit (nondeterministic run)");
    let receipt = stdout(&out);
    let out = frf(
        &work,
        &[
            "--root", ROOT, "bundle", "export", &receipt, "--output", "nd.frf",
        ],
    );
    assert_success(&out, "bundle export (nondeterministic)");
    let out = frf(&work, &["bundle", "verify", "nd.frf"]);
    assert_success(&out, "bundle verify (nondeterministic)");
}

#[test]
fn single_run_courts_keep_the_honest_not_observed_sign_and_write_no_trajectories() {
    let work = Workdir::new("trajectory-single");
    work.copy_canonical_tree();
    admit_reference(&work);
    let run = run_court(&work);

    // No repeated court: no trajectory RECORDS are written (the empty
    // trajectories/ dir is part of the evidence-tree layout).
    assert_eq!(
        fs::read_dir(work.path("frf/trajectories")).unwrap().count(),
        0,
        "single-run courts write no trajectories"
    );

    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &run]);
    assert_success(&out, "receipt emit (single run)");
    let receipt = stdout(&out);
    let rec: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("frf/receipts/{receipt}.json"))).unwrap(),
    )
    .unwrap();
    for res in rec["residuals"].as_array().unwrap() {
        assert_eq!(res["sign"]["norm"], "single-run");
        assert_eq!(res["sign"]["drift"], "not-observed");
        assert_eq!(res["sign"]["slew"], "not-observed");
    }
}
