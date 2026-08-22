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
fn environment_axis_records_every_observation_event() {
    // Each environment COORDINATE is a DECLARED environment (the manifest's
    // `environment_points` — a label is not evidence unless the environment
    // it names is declared), and the declared env is part of the
    // observation identity. Distinct coordinates are therefore DISTINCT
    // observations — distinct content-addressed runs, each with its own
    // declared environment recorded in the capture — and every observation
    // event is still a point: no persistence information is lost.
    let work = Workdir::new("trajectory-env-accumulate");
    work.copy_canonical_tree();
    admit_reference(&work);
    let mut runs: Vec<String> = Vec::new();
    for coord in ["machine-a", "machine-b", "machine-c"] {
        let out = frf(
            &work,
            &[
                "--root",
                ROOT,
                "court",
                "run",
                MANIFEST,
                "--environment-point",
                coord,
            ],
        );
        assert_success(&out, &format!("environment point {coord}"));
        runs.push(stdout(&out));
    }
    let run = runs.last().unwrap().clone();

    // Distinct coordinates: distinct declared environments, distinct runs.
    assert_ne!(
        runs[0], runs[1],
        "different env coordinates are different observations"
    );
    assert_ne!(runs[1], runs[2]);
    // Each capture records the DECLARED environment it ran under.
    for (coord, run) in ["machine-a", "machine-b", "machine-c"].iter().zip(&runs) {
        let cap: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(work.path(&format!("frf/captures/{run}/capture.json"))).unwrap(),
        )
        .unwrap();
        assert_eq!(
            cap["environment"]["environment"]["HOSTNAME"], *coord,
            "the capture records the declared environment of the coordinate"
        );
    }

    // The experiment's history: three parent-linked snapshots, the newest
    // carrying three points — one per observation event.
    let store = frf::store::Store::new(work.path("frf"));
    let heads = store
        .experiment_heads("cli-malformed-input-environment")
        .unwrap();
    assert_eq!(heads.len(), 1, "one unique head");
    let head = &heads[0];
    assert_eq!(head.coordinate_system, "environment");
    assert_eq!(head.points.len(), 3, "every observation event is a point");
    let coords: Vec<&str> = head.points.iter().map(|p| p.coordinate.as_str()).collect();
    assert_eq!(coords, vec!["machine-a", "machine-b", "machine-c"]);
    let point_runs: Vec<&str> = head.points.iter().map(|p| p.run.as_str()).collect();
    assert_eq!(
        point_runs,
        runs.iter().map(|s| s.as_str()).collect::<Vec<_>>()
    );
    // The chain: walking parents reaches the first snapshot, whose parent is
    // None, and every snapshot's points are a prefix of the next's.
    let mut depth = 0u32;
    let mut current = head.id.clone();
    let mut previous_points: Vec<frf::model::SeriesPoint> = Vec::new();
    loop {
        let series = store.load_series(&current).unwrap();
        // Walking the chain NEWEST -> OLDEST: each ancestor's points are a
        // prefix of its descendant's (an append only extends).
        assert!(
            previous_points.is_empty() || series.points.len() <= previous_points.len(),
            "an append only extends the experiment"
        );
        previous_points = series.points.clone();
        match series.parent_series_id {
            Some(parent) => {
                current = parent;
                depth += 1;
            }
            None => break,
        }
    }
    assert_eq!(depth, 2, "S1 -> S2 -> S3");

    // The receipt from the run carries the trajectory evidence per coordinate
    // system (the environment entry pins the newest snapshot).
    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &run]);
    assert_success(&out, "receipt emit (environment series run)");
    let receipt = stdout(&out);
    let rec: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("frf/receipts/{receipt}.json"))).unwrap(),
    )
    .unwrap();
    for res in rec["residuals"].as_array().unwrap() {
        let evidence = res["sign"]["trajectory_evidence"].as_array().unwrap();
        assert_eq!(evidence.len(), 1, "one entry per coordinate system");
        assert_eq!(evidence[0]["coordinate_system"], "environment");
        assert_eq!(evidence[0]["series"], head.id);
    }
}

#[test]
fn a_branched_experiment_exposes_two_heads_and_implicit_appends_are_refused() {
    // The experiment's history is a parent-linked chain; a BRANCH (two heads)
    // is visible, and an implicit append has no unambiguous target — the
    // court refuses and names the heads; --series-parent chooses the branch.
    let work = Workdir::new("trajectory-env-branch");
    work.copy_canonical_tree();
    admit_reference(&work);
    let mut run = String::new();
    for coord in ["machine-a", "machine-b"] {
        let out = frf(
            &work,
            &[
                "--root",
                ROOT,
                "court",
                "run",
                MANIFEST,
                "--environment-point",
                coord,
            ],
        );
        assert_success(&out, &format!("environment point {coord}"));
        run = stdout(&out);
    }
    let store = frf::store::Store::new(work.path("frf"));
    let head = store
        .experiment_heads("cli-malformed-input-environment")
        .unwrap()
        .into_iter()
        .next()
        .unwrap();

    // Fabricate a SECOND head: a sibling of the current head with the same
    // parent but a different final point (an alternative branch).
    let mut branch_points = head.points.clone();
    branch_points[1].coordinate = "machine-b-prime".to_string();
    let experiment_id = head.experiment_id.clone();
    let branch_id = frf::semantics::series_identity(
        &experiment_id,
        head.parent_series_id.as_deref(),
        &head.court,
        &head.coordinate_system,
        &branch_points,
    )
    .unwrap();
    let branch = frf::model::ExecutionSeries {
        schema_version: frf::model::SCHEMA_SERIES.to_string(),
        id: branch_id,
        experiment_id: experiment_id.clone(),
        parent_series_id: head.parent_series_id.clone(),
        court: head.court.clone(),
        coordinate_system: head.coordinate_system.clone(),
        points: branch_points,
    };
    store.write_series(&branch).unwrap();
    let heads = store.experiment_heads(&experiment_id).unwrap();
    assert_eq!(heads.len(), 2, "the branch is visible as two heads");

    // An implicit append is now ambiguous: refused, naming both heads.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "court",
            "run",
            MANIFEST,
            "--environment-point",
            "machine-d",
        ],
    );
    assert!(
        !out.status.success(),
        "a branched experiment must refuse an implicit append"
    );
    assert!(
        stderr(&out).contains("branched") && stderr(&out).contains("--series-parent"),
        "the refusal must name the branch choice: {}",
        stderr(&out)
    );

    // --series-parent picks the branch: appending to the fabricated head
    // extends THAT chain.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "court",
            "run",
            MANIFEST,
            "--environment-point",
            "machine-d",
            "--series-parent",
            &branch.id,
        ],
    );
    assert_success(&out, "append to the chosen branch");
    let _ = run;
    let heads = store.experiment_heads(&experiment_id).unwrap();
    assert_eq!(heads.len(), 2, "both branches remain visible");
    let chosen = heads
        .iter()
        .find(|h| h.parent_series_id.as_deref() == Some(branch.id.as_str()));
    assert!(chosen.is_some(), "the chosen branch was extended");
}

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
    let mut trajectories: Vec<serde_json::Value> = fs::read_dir(work.path("frf/trajectories"))
        .unwrap()
        .map(|e| {
            let path = e.unwrap().path();
            serde_json::from_str::<serde_json::Value>(&fs::read_to_string(&path).unwrap()).unwrap()
        })
        .collect();
    assert_eq!(trajectories.len(), 2, "exit + stderr lineages");
    trajectories.sort_by_key(|t| t["subject"].as_str().unwrap().to_string());
    let mut series_id = String::new();
    for t in &trajectories {
        assert_eq!(t["schema_version"], "frf-trajectory-v4");
        assert_eq!(t["coordinate_system"], "repeat_index");
        assert_eq!(t["derivation"]["drift"], "persistent");
        assert_eq!(t["derivation"]["slew"], "stable");
        assert_eq!(t["derivation"]["localization"], "none");
        assert_eq!(t["derivation"]["bands"], "1");
        let obs = t["observations"].as_array().unwrap();
        assert_eq!(obs.len(), 3, "one observation per repetition");
        for (i, o) in obs.iter().enumerate() {
            assert_eq!(o["point_index"], (i + 1).to_string());
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
    let series: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("frf/series/{series_id}.json"))).unwrap(),
    )
    .unwrap();
    assert_eq!(series["schema_version"], "frf-series-v3");
    assert_eq!(series["id"], series_id);
    assert_eq!(series["coordinate_system"], "repeat_index");
    assert_eq!(series["experiment_id"], "cli-malformed-input-repeat_index");
    assert!(
        series["parent_series_id"].is_null(),
        "first snapshot has no parent"
    );
    let points = series["points"].as_array().unwrap();
    assert_eq!(points.len(), 3);
    for (i, p) in points.iter().enumerate() {
        assert_eq!(p["point_index"], (i + 1).to_string());
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
        let evidence = res["sign"]["trajectory_evidence"].as_array().unwrap();
        assert_eq!(evidence.len(), 1, "one entry per coordinate system");
        assert_eq!(evidence[0]["coordinate_system"], "repeat_index");
        assert_eq!(evidence[0]["drift"], "persistent");
        assert_eq!(evidence[0]["slew"], "stable");
        assert_eq!(
            evidence[0]["series"], series_id,
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
        let t: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(t["schema_version"], "frf-trajectory-v4");
        assert_eq!(t["coordinate_system"], "repeat_index");
        let obs = t["observations"].as_array().unwrap();
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
        } else if tset.last().unwrap() - tset.first().unwrap() + 1 == tset.len()
            && (tset.first() == Some(&0) || tset.last() == Some(&(n - 1)))
        {
            // A single contiguous band touching exactly one bound.
            "boundary-localized"
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
        // The derivation's localization/bands/trend/magnitude_kind are the
        // deterministic companions (re-derived by frf::trajectory::classify
        // over the coordinate system with the rederived magnitudes).
        let magnitudes: Vec<Option<String>> = obs
            .iter()
            .map(|o| {
                o["residual"].as_str().and_then(|rid| {
                    let record: serde_json::Value = serde_json::from_str(
                        &fs::read_to_string(work.path(&format!("frf/residuals/{rid}.json")))
                            .unwrap(),
                    )
                    .unwrap();
                    frf::comparators::divergence_magnitude(
                        record["axis"].as_str().unwrap(),
                        record["raw_reference"].as_str().unwrap(),
                        record["raw_candidate"].as_str().unwrap(),
                    )
                })
            })
            .collect();
        let kind = frf::comparators::magnitude_kind(t["axis"].as_str().unwrap());
        let d = frf::trajectory::classify(
            &observed,
            t["coordinate_system"].as_str().unwrap(),
            &magnitudes,
            &kind,
        )
        .unwrap();
        assert_eq!(t["derivation"]["localization"], d.localization.as_str());
        assert_eq!(t["derivation"]["bands"], d.bands);
        assert_eq!(t["derivation"]["trend"], d.trend.as_str());
        assert_eq!(t["derivation"]["magnitude_kind"], d.magnitude_kind);
        // Observed entries reference a real residual whose fingerprint is the
        // observation fingerprint, recorded against a real run.
        for o in obs {
            let repetition_run = o["run"].as_str().unwrap().to_string();
            assert!(
                fs::read_to_string(
                    work.path(&format!("frf/captures/{repetition_run}/capture.json"))
                )
                .is_ok(),
                "observation run must exist"
            );
            if o["observed"].as_bool().unwrap() {
                let id = o["residual"].as_str().unwrap();
                let record: serde_json::Value = serde_json::from_str(
                    &fs::read_to_string(work.path(&format!("frf/residuals/{id}.json"))).unwrap(),
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
        assert_eq!(
            res["sign"]["trajectory_evidence"],
            serde_json::json!([]),
            "a single-run receipt honestly carries no trajectory evidence (drift/slew are not-observed)"
        );
    }
}
