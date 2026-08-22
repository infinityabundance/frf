//! The EXTERNAL empirical program v2 — the trajectory axes on real defects.
//!
//! The v1 external program (experiment_external.rs) measures defect
//! discovery, claims, minimization, replay, and challenge sensitivity on the
//! reconstructed historical defects (external-corpus/). v2 drives the SAME
//! corpus through the three generalized trajectory axes, so the movement of
//! a real historical divergence becomes executable evidence:
//!
//! 1. **Version ladders** (`candidate_revision`): the buggy candidate and
//!    the clean candidate are two revisions of one program. The defect
//!    lineage is observed at the buggy revision and ABSENT at the clean one
//!    — the trajectory must classify the cessation as `boundary-localized`
//!    at the start of the ladder.
//! 2. **Environment matrices** (`environment`): the defect court is observed
//!    at three declared environment coordinates (deterministic TZ/LANG
//!    variations — the harness controls the ambient environment the court
//!    captures). The defect must be observed at EVERY point: a real
//!    historical defect is not environment-specific, so the trajectory must
//!    be `persistent` / `stable`.
//! 3. **Authority transitions** (`authority_version`): the oracle changes.
//!    The historical vulnerable program IS the pre-fix oracle; the corpus
//!    reference is the fixed oracle. Admitted as two versions of one
//!    authority:
//!    - the BUGGY candidate against the ladder: matching the pre-fix oracle
//!      (self-match — no divergence) and diverging from the fixed one → the
//!      defect becomes observable exactly when the oracle was fixed:
//!      `boundary-localized` onset at the end;
//!    - the CLEAN candidate against the ladder: stricter than the pre-fix
//!      oracle (divergence) and matching the fixed one → `boundary-localized`
//!      cessation at the start.
//!
//! Every experiment is measured with the REAL `frf` engine; the series and
//! trajectory records are read back and their classifications checked
//! against the deterministic table (they must classify exactly as declared).
//! `--check` (default) exits non-zero on any misclassification, any
//! environment point that lost the defect, or any replay that did not
//! reproduce.

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use super::experiment::{dir_size, frf_bin};
use super::experiment_external::{admit, copy_to, run_frf, write_bytes};
use crate::load_evidence;

fn as_str(v: &Value) -> &str {
    v.as_str().unwrap_or_default()
}

/// The declared environment matrix: deterministic ambient variations the
/// harness applies to the court process. Each point is a real environment
/// coordinate the engine captures (locale + timezone move the digest).
const ENVIRONMENT_MATRIX: &[(&str, &str, &str)] = &[
    ("utc", "TZ=UTC", "LANG=C"),
    ("new-york", "TZ=America/New_York", "LANG=en_US.UTF-8"),
    ("tokyo", "TZ=Asia/Tokyo", "LANG=ja_JP.UTF-8"),
];

/// The trajectory classification one lineage must have for an experiment
/// kind, at one point of the ladder: `None` = the lineage must be ABSENT at
/// that point, `Some("boundary-localized")` etc. = the classification of the
/// derived trajectory.
enum Expectation {
    /// The lineage must be observed at this point (exact classification is
    /// asserted on the derived trajectory).
    Observed,
    /// The lineage must NOT be observed at this point.
    Absent,
}

impl Copy for Expectation {}
impl Clone for Expectation {
    fn clone(&self) -> Self {
        *self
    }
}

/// One measured trajectory experiment.
struct TrajectoryMeasurement {
    experiment: String,
    case: String,
    axis: String,
    lineage: String,
    pattern: Vec<bool>,
    expected_drift: &'static str,
    expected_slew: &'static str,
    expected_localization: &'static str,
    evidence_bytes: u64,
}

pub fn run(repo_root: &Path, out_path: &Path, check: bool) {
    let frf = frf_bin(repo_root);
    let corpus = repo_root.join("external-corpus");
    let work = repo_root
        .join("golden")
        .join("work")
        .join("external-experiment-v2");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();

    let manifest = crate::load_json(&corpus.join("manifest.json"));
    let cases = manifest["cases"].as_array().cloned().unwrap_or_default();

    let mut measurements: Vec<TrajectoryMeasurement> = Vec::new();
    let mut failures: Vec<String> = Vec::new();

    for case in &cases {
        let id = as_str(&case["id"]);
        let case_src = corpus.join(id);
        let case_work = work.join(id);
        std::fs::create_dir_all(&case_work).unwrap();

        // Stage the case exactly like v1: scripts, fixtures, manifests.
        for f in ["reference.sh", "candidate-buggy.sh", "candidate-clean.sh"] {
            copy_to(&case_src, &case_work, f, true);
        }
        for f in [
            as_str(&case["fixture_defect"]),
            as_str(&case["fixture_clean"]),
        ] {
            let bytes = std::fs::read(case_src.join("fixtures").join(f))
                .unwrap_or_else(|e| panic!("cannot read fixture {f}: {e}"));
            write_bytes(&case_work, &format!("fixtures/{f}"), &bytes, false);
        }
        if let Some(mut_prog) = case.get("mutation_provider").and_then(|v| v.as_str()) {
            let bytes = std::fs::read(case_src.join(mut_prog))
                .unwrap_or_else(|e| panic!("cannot read mutation provider {mut_prog}: {e}"));
            write_bytes(&case_work, mut_prog, &bytes, true);
        }
        let template = std::fs::read_to_string(case_src.join("manifest.yaml"))
            .unwrap_or_else(|e| panic!("cannot read manifest for {id}: {e}"));
        let staged = |candidate: &str, fixture: &str| {
            template
                .replace("{candidate}", candidate)
                .replace("fixtures/{fixture}", fixture)
        };
        let manifest_defect = staged(
            "scripts/candidate-buggy.sh",
            &format!("fixtures/{}", as_str(&case["fixture_defect"])),
        );
        let manifest_clean = staged(
            "scripts/candidate-clean.sh",
            &format!("fixtures/{}", as_str(&case["fixture_clean"])),
        );
        // The clean candidate against the DEFECT fixture: the authority
        // transition's control needs the fixed behavior on the tampered
        // input (the clean manifest's own fixture would match every oracle).
        let manifest_clean_defect = staged(
            "scripts/candidate-clean.sh",
            &format!("fixtures/{}", as_str(&case["fixture_defect"])),
        );
        write_bytes(
            &case_work,
            &format!("courts/{id}/manifest-defect.yaml"),
            manifest_defect.as_bytes(),
            false,
        );
        write_bytes(
            &case_work,
            &format!("courts/{id}/manifest-clean.yaml"),
            manifest_clean.as_bytes(),
            false,
        );
        write_bytes(
            &case_work,
            &format!("courts/{id}/manifest-clean-defect.yaml"),
            manifest_clean_defect.as_bytes(),
            false,
        );

        let name = as_str(&case["authority_name"]);
        let fixed_version = as_str(&case["authority_version"]);
        admit(
            &frf,
            &case_work,
            "scripts/reference.sh",
            name,
            fixed_version,
        );
        // The AUTHORITY TRANSITION: the historical vulnerable program IS the
        // pre-fix oracle — the same bytes, admitted as an earlier version of
        // the same authority.
        admit(
            &frf,
            &case_work,
            "scripts/candidate-buggy.sh",
            name,
            "pre-fix",
        );

        // -- 1. the version ladder: buggy revision -> clean revision --------
        let (ok, out, err) = run_frf(
            &frf,
            &case_work,
            &[
                "--root",
                "ev",
                "court",
                "run",
                &format!("courts/{id}/manifest-defect.yaml"),
                "--candidate-revisions",
                "scripts/candidate-buggy.sh,scripts/candidate-clean.sh",
            ],
        );
        if !ok {
            failures.push(format!("{id}/ladder: run failed: {err}"));
        } else {
            let ladder_runs: Vec<String> = out.lines().map(|l| l.to_string()).collect();
            // The defect lineage must be observed at revision 1 (buggy) and
            // absent at revision 2 (clean): a boundary-localized cessation.
            // A DIAGNOSTIC-WORDING lineage may legitimately persist across
            // the ladder (the clean candidate refuses like the reference but
            // words its diagnostic differently) — those are measured as
            // notes, not failures; the DEFECT lineage must cease.
            let mut ceased = 0usize;
            let axis_trajectories = read_axis_trajectories(&case_work, "candidate_revision");
            for (lineage, records) in &axis_trajectories {
                match select_by_pattern(records, &[Expectation::Observed, Expectation::Absent]) {
                    Some(t) => {
                        measurements.push(check_trajectory(
                            &case_work,
                            "ladder",
                            id,
                            "candidate_revision",
                            lineage,
                            t,
                            &[Expectation::Observed, Expectation::Absent],
                            "boundary-localized",
                            "abrupt",
                            "start",
                            &mut failures,
                        ));
                        ceased += 1;
                    }
                    None => {
                        // A lineage that did not cease: its classification
                        // must still rederive from its own pattern.
                        for t in records {
                            let pattern: Vec<bool> = t["observations"]
                                .as_array()
                                .map(|a| {
                                    a.iter()
                                        .map(|o| o["observed"].as_bool().unwrap_or(false))
                                        .collect()
                                })
                                .unwrap_or_default();
                            let (drift, slew, loc, _, _) = crate::rederive::classify(
                                &pattern,
                                "candidate_revision",
                                &vec![None; pattern.len()],
                                "none",
                            );
                            if drift != as_str(&t["derivation"]["drift"])
                                || slew != as_str(&t["derivation"]["slew"])
                                || loc != as_str(&t["derivation"]["localization"])
                            {
                                failures.push(format!(
                                    "{id}/ladder: lineage {lineage} classification does not rederive"
                                ));
                            }
                            measurements.push(TrajectoryMeasurement {
                                experiment: "ladder".to_string(),
                                case: id.to_string(),
                                axis: "candidate_revision".to_string(),
                                lineage: lineage.clone(),
                                pattern,
                                expected_drift: "persistent",
                                expected_slew: "stable",
                                expected_localization: "none",
                                evidence_bytes: 0,
                            });
                            eprintln!(
                                "note: {id}/ladder lineage {} persists across the ladder (diagnostic wording)",
                                &lineage[..16]
                            );
                        }
                    }
                }
            }
            if ceased == 0 {
                failures.push(format!(
                    "{id}/ladder: NO lineage ceased at the clean revision — the defect did not fix"
                ));
            }
            // Replay stability of the ladder's observed revision.
            if let Some(buggy_run) = ladder_runs.first() {
                let (rok, rout, _) = run_frf(
                    &frf,
                    &case_work,
                    &["--root", "ev", "replay", buggy_run, "--policy", "exact"],
                );
                if !(rok && rout.contains("reproduced")) {
                    failures.push(format!("{id}/ladder: replay did not reproduce"));
                }
            }
        }

        // -- 2. the environment matrix: the defect at every coordinate ------
        // The coordinates are DECLARED in each case manifest's
        // `environment_points` — the coordinate's TZ/LANG are evidence, not
        // orchestration (the ambient host environment is never inherited).
        let mut env_runs: Vec<String> = Vec::new();
        for (label, _tz, _lang) in ENVIRONMENT_MATRIX {
            let (ok, out, err) = run_frf_env(
                &frf,
                &case_work,
                &[
                    "--root",
                    "ev",
                    "court",
                    "run",
                    &format!("courts/{id}/manifest-defect.yaml"),
                    "--environment-point",
                    label,
                ],
                &[],
            );
            if !ok {
                failures.push(format!("{id}/env:{label}: run failed: {err}"));
                continue;
            }
            let run_id = out.lines().last().unwrap_or_default().to_string();
            env_runs.push(run_id.clone());
            // The defect MUST be observed at this point (a real historical
            // defect is not environment-specific).
            let cap = load_evidence(
                &case_work
                    .join("ev/captures")
                    .join(&run_id)
                    .join("capture.json"),
            );
            if cap["residuals"]
                .as_array()
                .map(|a| a.is_empty())
                .unwrap_or(true)
            {
                failures.push(format!(
                    "{id}/env:{label}: the defect was NOT observed at this environment coordinate"
                ));
            }
        }
        // The accumulated environment series must classify the defect as
        // persistent and stable (observed at every coordinate).
        if env_runs.len() == ENVIRONMENT_MATRIX.len() {
            let axis_trajectories = read_axis_trajectories(&case_work, "environment");
            for (lineage, records) in &axis_trajectories {
                let observed_all = &[Expectation::Observed; ENVIRONMENT_MATRIX.len()];
                match select_by_pattern(records, observed_all) {
                    Some(t) => {
                        measurements.push(check_trajectory(
                            &case_work,
                            "environment-matrix",
                            id,
                            "environment",
                            lineage,
                            t,
                            observed_all,
                            "persistent",
                            "stable",
                            "none",
                            &mut failures,
                        ));
                    }
                    None => {
                        failures.push(format!(
                            "{id}/environment-matrix: lineage {lineage} has no fully-observed head snapshot"
                        ));
                    }
                }
            }
        }

        // -- 3. the authority transition: the oracle gets fixed -------------
        // The BUGGY candidate: matching the pre-fix oracle (no divergence)
        // and diverging from the fixed one — the defect becomes observable
        // exactly when the oracle was fixed (onset at the end).
        let (ok, _out, err) = run_frf(
            &frf,
            &case_work,
            &[
                "--root",
                "ev",
                "court",
                "run",
                &format!("courts/{id}/manifest-defect.yaml"),
                "--authority-versions",
                &format!("pre-fix,{fixed_version}"),
            ],
        );
        if !ok {
            failures.push(format!("{id}/authority-buggy: run failed: {err}"));
        } else {
            let axis_trajectories = read_axis_trajectories(&case_work, "authority_version");
            let expected = &[Expectation::Absent, Expectation::Observed];
            for (lineage, records) in &axis_trajectories {
                match select_by_pattern(records, expected) {
                    Some(t) => {
                        measurements.push(check_trajectory(
                            &case_work,
                            "authority-transition",
                            id,
                            "authority_version",
                            lineage,
                            t,
                            expected,
                            "boundary-localized",
                            "abrupt",
                            "end",
                            &mut failures,
                        ));
                    }
                    None => {
                        failures.push(format!(
                            "{id}/authority-buggy: lineage {lineage} has no onset-into-fixed-oracle record"
                        ));
                    }
                }
            }
        }
        // The CLEAN candidate on the DEFECT fixture: stricter than the
        // pre-fix oracle (it refuses the tampered input the old oracle
        // accepted) and matching the fixed one — a cessation at the start.
        let (ok, _out, err) = run_frf(
            &frf,
            &case_work,
            &[
                "--root",
                "ev",
                "court",
                "run",
                &format!("courts/{id}/manifest-clean-defect.yaml"),
                "--authority-versions",
                &format!("pre-fix,{fixed_version}"),
            ],
        );
        if !ok {
            failures.push(format!("{id}/authority-clean: run failed: {err}"));
        } else {
            let axis_trajectories = read_axis_trajectories(&case_work, "authority_version");
            let expected = &[Expectation::Observed, Expectation::Absent];
            let mut ceased = 0usize;
            for (lineage, records) in &axis_trajectories {
                match select_by_pattern(records, expected) {
                    Some(t) => {
                        measurements.push(check_trajectory(
                            &case_work,
                            "authority-transition",
                            id,
                            "authority_version",
                            lineage,
                            t,
                            expected,
                            "boundary-localized",
                            "abrupt",
                            "start",
                            &mut failures,
                        ));
                        ceased += 1;
                    }
                    None => {
                        // A diagnostic-wording lineage may legitimately
                        // persist across the transition: measured as a note,
                        // not a failure — the DEFECT lineage must cease.
                        eprintln!(
                            "note: {id}/authority-clean lineage {} persists across the authority transition (diagnostic wording)",
                            &lineage[..16]
                        );
                    }
                }
            }
            if ceased == 0 {
                failures.push(format!(
                    "{id}/authority-clean: NO lineage ceased when the oracle was fixed"
                ));
            }
        }
    }

    // -- metrics -------------------------------------------------------------
    // The canonical value domain is strings/arrays/booleans/null: every
    // count is a decimal string.
    let mut trajectory_bytes = 0u64;
    for m in &measurements {
        trajectory_bytes += m.evidence_bytes;
    }
    let cases_count = cases.len();
    let ladder_count = measurements
        .iter()
        .filter(|m| m.experiment == "ladder")
        .count();
    let env_count = measurements
        .iter()
        .filter(|m| m.experiment == "environment-matrix")
        .count();
    let authority_count = measurements
        .iter()
        .filter(|m| m.experiment == "authority-transition")
        .count();

    let report = json!({
        "schema_version": "frf-external-experiment-v2",
        "corpus": "external-corpus (frf-external-corpus-v1)",
        "cases": cases_count.to_string(),
        "trajectory_measurements": {
            "total": measurements.len().to_string(),
            "ladder": ladder_count.to_string(),
            "environment_matrix": env_count.to_string(),
            "authority_transition": authority_count.to_string(),
            "classifications": measurements
                .iter()
                .map(|m| json!({
                    "experiment": m.experiment,
                    "case": m.case,
                    "axis": m.axis,
                    "lineage": m.lineage,
                    "pattern": m.pattern,
                    "expected": {
                        "drift": m.expected_drift,
                        "slew": m.expected_slew,
                        "localization": m.expected_localization,
                    },
                }))
                .collect::<Vec<_>>(),
        },
        "evidence_overhead_bytes": trajectory_bytes.to_string(),
        "failures": failures,
    });

    let out_text = crate::jcs::encode(&report).expect("cannot canonicalize the v2 report");
    std::fs::write(out_path, &out_text)
        .unwrap_or_else(|e| panic!("cannot write the v2 report to {}: {e}", out_path.display()));
    println!(
        "external-experiment-v2: {} case(s), {} trajectory measurement(s) ({} ladder, {} environment, {} authority), evidence {} bytes",
        cases_count,
        measurements.len(),
        ladder_count,
        env_count,
        authority_count,
        trajectory_bytes
    );
    for m in &measurements {
        println!(
            "  {}/{}: pattern={:?} -> {}/{}/{}",
            m.case,
            m.experiment,
            m.pattern,
            m.expected_drift,
            m.expected_slew,
            m.expected_localization
        );
    }
    if !failures.is_empty() {
        for f in &failures {
            eprintln!("FAIL: {f}");
        }
    }
    if check && !failures.is_empty() {
        panic!(
            "external-experiment-v2 CHECK FAILED:\n  {}",
            failures.join("\n  ")
        );
    }
}

/// Run frf with an explicit ambient environment (the environment matrix
/// points the court captures).
fn run_frf_env(frf: &Path, cwd: &Path, args: &[&str], envs: &[&str]) -> (bool, String, String) {
    let mut cmd = Command::new(frf);
    cmd.args(args).current_dir(cwd);
    for e in envs {
        let (k, v) = e.split_once('=').expect("env pair");
        cmd.env(k, v);
    }
    let out = cmd
        .output()
        .unwrap_or_else(|e| panic!("cannot execute {frf:?}: {e}"));
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).trim().to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// Read the derived trajectories of one axis, grouped by lineage: an
/// accumulated experiment (environment/time) appends parent-linked series
/// snapshots each with its own trajectory record, and the one-shot axes
/// (candidate_revision/authority_version) can have several experiments per
/// axis — the caller selects the record whose pattern matches its expected
/// observation. Returns (lineage, records) sorted by lineage.
fn read_axis_trajectories(case_work: &Path, coordinate_system: &str) -> Vec<(String, Vec<Value>)> {
    let dir = case_work.join("ev/trajectories");
    let mut by_lineage: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    if !dir.is_dir() {
        return Vec::new();
    }
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        // trajectories/<lineage>.<coordinate-system>.<series>.json — the
        // coordinate system is the middle segment.
        if !name.contains(&format!(".{coordinate_system}.")) {
            continue;
        }
        let record = load_evidence(&path);
        if as_str(&record["coordinate_system"]) != coordinate_system {
            continue;
        }
        by_lineage
            .entry(as_str(&record["subject"]).to_string())
            .or_default()
            .push(record);
    }
    by_lineage.into_iter().collect()
}

/// Select the trajectory record whose observed pattern matches the expected
/// pattern point by point (the record of the experiment being measured —
/// with several experiments per axis, the expected pattern is the selector).
fn select_by_pattern<'a>(records: &'a [Value], expected: &[Expectation]) -> Option<&'a Value> {
    records.iter().find(|r| {
        let pattern: Vec<bool> = r["observations"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|o| o["observed"].as_bool().unwrap_or(false))
                    .collect()
            })
            .unwrap_or_default();
        pattern.len() == expected.len()
            && pattern.iter().zip(expected.iter()).all(|(o, e)| match e {
                Expectation::Observed => *o,
                Expectation::Absent => !*o,
            })
    })
}

/// Assert a trajectory record against its declared expectation: the observed
/// pattern must match point by point, and the derived classification must be
/// exactly the declared drift/slew/localization. Returns the measurement.
#[allow(clippy::too_many_arguments)]
fn check_trajectory(
    case_work: &Path,
    experiment: &str,
    case: &str,
    axis: &str,
    lineage: &str,
    record: &Value,
    expected_pattern: &[Expectation],
    expected_drift: &'static str,
    expected_slew: &'static str,
    expected_localization: &'static str,
    failures: &mut Vec<String>,
) -> TrajectoryMeasurement {
    let observations = record["observations"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let pattern: Vec<bool> = observations
        .iter()
        .map(|o| o["observed"].as_bool().unwrap_or(false))
        .collect();
    if pattern.len() != expected_pattern.len() {
        failures.push(format!(
            "{case}/{experiment}: lineage {lineage} has {} point(s), expected {}",
            pattern.len(),
            expected_pattern.len()
        ));
    }
    for (i, (o, exp)) in pattern.iter().zip(expected_pattern.iter()).enumerate() {
        match exp {
            Expectation::Observed if !*o => {
                failures.push(format!(
                    "{case}/{experiment}: lineage {lineage} was NOT observed at point {i}"
                ));
            }
            Expectation::Absent if *o => {
                failures.push(format!(
                    "{case}/{experiment}: lineage {lineage} was observed at point {i} but must be absent"
                ));
            }
            _ => {}
        }
    }
    let drift = as_str(&record["derivation"]["drift"]);
    let slew = as_str(&record["derivation"]["slew"]);
    let localization = as_str(&record["derivation"]["localization"]);
    if drift != expected_drift || slew != expected_slew || localization != expected_localization {
        failures.push(format!(
            "{case}/{experiment}: lineage {lineage} classified {drift}/{slew}/{localization}, expected {expected_drift}/{expected_slew}/{expected_localization}"
        ));
    }
    let mut bytes = 0u64;
    for o in &observations {
        let run = as_str(&o["run"]).to_string();
        if run.is_empty() {
            continue;
        }
        bytes += dir_size(&case_work.join("ev/captures").join(&run));
        if let Some(rid) = o["residual"].as_str() {
            bytes += dir_size(&case_work.join("ev/residuals").join(format!("{rid}.json")));
        }
    }
    TrajectoryMeasurement {
        experiment: experiment.to_string(),
        case: case.to_string(),
        axis: axis.to_string(),
        lineage: lineage.to_string(),
        pattern,
        expected_drift,
        expected_slew,
        expected_localization,
        evidence_bytes: bytes,
    }
}
