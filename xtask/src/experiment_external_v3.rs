//! The EXTERNAL empirical program v3 — the trajectory axes on ACTUAL
//! upstream vulnerable and fixed releases.
//!
//! The v1/v2 programs measured reconstructed minimal reproducers. v3 drives
//! the same trajectory axes against the REAL historical software: the
//! vulnerable release and the fixed release of bash (CVE-2014-6271),
//! OpenSSL (CVE-2014-0160), and Log4j (CVE-2021-44228), built from the
//! pinned upstream sources by the hermetic recipes in external-corpus/v3/
//! (containerized native builds on fedora:41; Maven Central jars pinned by
//! SHA-256). The committed builds/ artifacts ARE the sides; the fixtures
//! are real interactions with the vulnerable code paths:
//!
//!   shellshock  the side is the real bash binary; the fixture is a script;
//!               the trigger is the malicious function-import environment
//!               variable (the exact CVE-2014-6271 condition).
//!   heartbleed  the side is a probe statically linked against the real
//!               libssl; it performs the exact historical exploit message
//!               sequence (ClientHello with the heartbeat extension, then
//!               the malformed heartbeat after ServerHelloDone).
//!   log4shell   the side is a launcher running the probe on the real log4j
//!               jars; the fixture logs a message containing the JNDI lookup.
//!
//! Each case exercises the same four experiments as v2 — the version
//! ladder, the environment matrix, and both authority transitions — plus a
//! NEW CLEAN CONTROL: the vulnerable side against the clean fixture must
//! produce NO residual (the divergence is specific to the trigger, not a
//! spurious difference between the two real builds). The historical fix
//! boundary must classify exactly as declared:
//!
//!   ladder (buggy -> fixed):          [observed, absent]      boundary-localized/abrupt/start
//!   environment matrix:               [observed x3]           persistent/stable/none
//!   authority transition (buggy):     [absent, observed]      boundary-localized/abrupt/end
//!   authority transition (fixed):     [observed, absent]      boundary-localized/abrupt/start
//!
//! `--check` (default) exits non-zero on any misclassification, any lost
//! defect, any replay that did not reproduce, or any clean control that
//! diverged.

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use super::experiment::{dir_size, frf_bin};
use super::experiment_external::{admit, write_bytes};
use crate::load_evidence;

fn as_str(v: &Value) -> &str {
    v.as_str().unwrap_or_default()
}

const ENVIRONMENT_MATRIX: [(&str, &str, &str); 3] = [
    ("utc", "TZ=UTC", "LANG=C"),
    ("new-york", "TZ=America/New_York", "LANG=en_US.UTF-8"),
    ("tokyo", "TZ=Asia/Tokyo", "LANG=ja_JP.UTF-8"),
];

/// The Shellshock trigger: a function import whose trailing code executes
/// on the vulnerable release. The env var is part of the OBSERVATION (the
/// court's ambient environment), exactly as in the historical exploit.
const SHELLSHOCK_TRIGGER: &str = "x=() { :;}; echo PWNED";

enum Expectation {
    Observed,
    Absent,
}

impl Copy for Expectation {}

impl Clone for Expectation {
    fn clone(&self) -> Self {
        *self
    }
}

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

struct CleanControl {
    case: String,
    residual_count: usize,
}

/// Run frf with an explicit ambient environment (the environment matrix
/// points the court captures; the Shellshock trigger rides the same path).
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

/// Recursively copy the case's builds/ and fixtures/ into the staged work
/// directory.
fn copy_tree(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if from.is_dir() {
            std::fs::create_dir_all(&to).unwrap();
            copy_tree(&from, &to);
        } else {
            let bytes = std::fs::read(&from)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", from.display()));
            std::fs::write(&to, bytes)
                .unwrap_or_else(|e| panic!("cannot write {}: {e}", to.display()));
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&from)
                    .map(|m| m.permissions().mode())
                    .unwrap_or(0o644);
                std::fs::set_permissions(&to, std::fs::Permissions::from_mode(mode)).unwrap();
            }
        }
    }
}

/// Read the derived trajectories of one axis, grouped by lineage (same
/// selector as v2: with several experiments per axis, the caller picks the
/// record whose observed pattern matches its expectation).
fn read_axis_trajectories(case_work: &Path, coordinate_system: &str) -> Vec<(String, Vec<Value>)> {
    let dir = case_work.join("ev/trajectories");
    let mut by_lineage: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    if !dir.is_dir() {
        return Vec::new();
    }
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
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
/// pattern point by point.
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

/// Assert a trajectory record against its declared expectation.
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

/// The per-case trigger environment (empty for cases without an ambient
/// trigger, the Shellshock import variable otherwise).
fn trigger_env(case: &Value) -> Vec<&str> {
    if as_str(&case["trigger"]) == "env" {
        vec![SHELLSHOCK_TRIGGER]
    } else {
        Vec::new()
    }
}

pub fn run(repo_root: &Path, out_path: &Path, check: bool) {
    let frf = frf_bin(repo_root);
    let corpus = repo_root.join("external-corpus").join("v3");
    let work = repo_root
        .join("golden")
        .join("work")
        .join("external-experiment-v3");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();

    let manifest = crate::load_json(&corpus.join("manifest.json"));
    let cases = manifest["cases"].as_array().cloned().unwrap_or_default();

    let mut measurements: Vec<TrajectoryMeasurement> = Vec::new();
    let mut clean_controls: Vec<CleanControl> = Vec::new();
    let mut failures: Vec<String> = Vec::new();

    for case in &cases {
        let id = as_str(&case["id"]);
        let case_src = corpus.join(id);
        let case_work = work.join(id);
        std::fs::create_dir_all(&case_work).unwrap();
        // The per-case metadata (authority identity, sides, fixtures).
        let meta = crate::load_json(&case_src.join("case.json"));
        let name = as_str(&meta["authority_name"]);
        let fixed_version = as_str(&meta["authority_fixed_version"]);
        let side_vuln = as_str(&meta["sides"]["vulnerable"]);
        let side_fixed = as_str(&meta["sides"]["fixed"]);
        let fixture_defect = as_str(&meta["fixtures"]["defect"]);
        let fixture_clean = as_str(&meta["fixtures"]["clean"]);
        let trigger = trigger_env(&meta);

        // Stage the corpus: builds/ + fixtures/ are copied verbatim; the
        // three manifests are rendered from the template.
        copy_tree(&case_src.join("builds"), &case_work.join("builds"));
        copy_tree(&case_src.join("fixtures"), &case_work.join("fixtures"));
        let template = std::fs::read_to_string(case_src.join("manifest.yaml"))
            .unwrap_or_else(|e| panic!("cannot read the manifest for {id}: {e}"));
        let staged = |candidate: &str, fixture: &str| {
            template
                .replace("{candidate}", candidate)
                .replace("fixtures/{fixture}", &format!("fixtures/{fixture}"))
        };
        write_bytes(
            &case_work,
            &format!("courts/{id}/manifest-defect.yaml"),
            staged(side_vuln, fixture_defect).as_bytes(),
            false,
        );
        write_bytes(
            &case_work,
            &format!("courts/{id}/manifest-clean.yaml"),
            staged(side_vuln, fixture_clean).as_bytes(),
            false,
        );
        write_bytes(
            &case_work,
            &format!("courts/{id}/manifest-clean-defect.yaml"),
            staged(side_fixed, fixture_defect).as_bytes(),
            false,
        );

        // Admit the FIXED release as the reference authority, and the
        // VULNERABLE release as its pre-fix version (the historical oracle
        // transition).
        admit(&frf, &case_work, side_fixed, name, fixed_version);
        admit(&frf, &case_work, side_vuln, name, "pre-fix");

        // -- 1. the version ladder: buggy release -> fixed release ----------
        let (ok, out, err) = run_frf_env(
            &frf,
            &case_work,
            &[
                "--root",
                "ev",
                "court",
                "run",
                &format!("courts/{id}/manifest-defect.yaml"),
                "--candidate-revisions",
                &format!("{side_vuln},{side_fixed}"),
            ],
            &trigger,
        );
        if !ok {
            failures.push(format!("{id}/ladder: run failed: {err}"));
        } else {
            let ladder_runs: Vec<String> = out.lines().map(|l| l.to_string()).collect();
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
                            eprintln!(
                                "note: {id}/ladder lineage {} persists across the ladder",
                                &lineage[..16]
                            );
                        }
                    }
                }
            }
            if ceased == 0 {
                failures.push(format!(
                    "{id}/ladder: NO lineage ceased at the fixed release — the historical defect did not fix"
                ));
            }
            // Replay stability of the ladder's observed buggy run (under
            // the same trigger environment).
            if let Some(buggy_run) = ladder_runs.first() {
                let (rok, rout, _) = run_frf_env(
                    &frf,
                    &case_work,
                    &["--root", "ev", "replay", buggy_run, "--policy", "exact"],
                    &trigger,
                );
                if !(rok && rout.contains("reproduced")) {
                    failures.push(format!("{id}/ladder: replay did not reproduce"));
                }
            }
        }

        // -- 2. the environment matrix: the defect at every coordinate ------
        let mut env_runs: Vec<String> = Vec::new();
        for (label, tz, lang) in ENVIRONMENT_MATRIX {
            let mut envs: Vec<&str> = trigger.clone();
            envs.push(tz);
            envs.push(lang);
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
                &envs,
            );
            if !ok {
                failures.push(format!("{id}/env:{label}: run failed: {err}"));
                continue;
            }
            let run_id = out.lines().last().unwrap_or_default().to_string();
            env_runs.push(run_id.clone());
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
        let (ok, _out, err) = run_frf_env(
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
            &trigger,
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
        // The FIXED candidate on the DEFECT fixture: stricter than the
        // pre-fix oracle (it refuses the tampered input the old oracle
        // accepted) and matching the fixed one — a cessation at the start.
        let (ok, _out, err) = run_frf_env(
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
            &trigger,
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
                        eprintln!(
                            "note: {id}/authority-clean lineage {} persists across the authority transition",
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

        // -- 4. the CLEAN CONTROL (v3): the vulnerable side without the
        //    trigger must not diverge from the fixed authority ---------------
        // The divergence is the historical defect, not a spurious difference
        // between two real builds: without the trigger, EVERY declared axis
        // must pass.
        let (ok, out, err) = run_frf_env(
            &frf,
            &case_work,
            &[
                "--root",
                "ev",
                "court",
                "run",
                &format!("courts/{id}/manifest-clean.yaml"),
            ],
            &[],
        );
        if !ok {
            failures.push(format!("{id}/clean-control: run failed: {err}"));
        } else {
            let run_id = out.lines().last().unwrap_or_default().to_string();
            let cap = load_evidence(
                &case_work
                    .join("ev/captures")
                    .join(&run_id)
                    .join("capture.json"),
            );
            let residuals = cap["residuals"].as_array().cloned().unwrap_or_default();
            if !residuals.is_empty() {
                failures.push(format!(
                    "{id}/clean-control: the vulnerable side diverged WITHOUT the trigger ({} residual(s): {})",
                    residuals.len(),
                    residuals
                        .iter()
                        .map(|r| as_str(&r["id"]).to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            clean_controls.push(CleanControl {
                case: id.to_string(),
                residual_count: residuals.len(),
            });
        }
    }

    // -- metrics -------------------------------------------------------------
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
        "schema_version": "frf-external-experiment-v3",
        "corpus": "external-corpus/v3 (frf-external-corpus-v3: ACTUAL upstream vulnerable + fixed releases)",
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
        "clean_controls": clean_controls
            .iter()
            .map(|c| json!({
                "case": c.case,
                "residuals": c.residual_count.to_string(),
            }))
            .collect::<Vec<_>>(),
        "evidence_overhead_bytes": trajectory_bytes.to_string(),
        "failures": failures,
    });

    let out_text = crate::jcs::encode(&report).expect("cannot canonicalize the v3 report");
    std::fs::write(out_path, &out_text)
        .unwrap_or_else(|e| panic!("cannot write the v3 report to {}: {e}", out_path.display()));
    println!(
        "external-experiment-v3: {} case(s), {} trajectory measurement(s) ({} ladder, {} environment, {} authority), {} clean control(s), evidence {} bytes",
        cases_count,
        measurements.len(),
        ladder_count,
        env_count,
        authority_count,
        clean_controls.len(),
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
    for c in &clean_controls {
        println!(
            "  {}/clean-control: {} residual(s) (the vulnerable side without the trigger)",
            c.case, c.residual_count
        );
    }
    if !failures.is_empty() {
        for f in &failures {
            eprintln!("FAIL: {f}");
        }
    }
    if check && !failures.is_empty() {
        panic!(
            "external-experiment-v3 CHECK FAILED:\n  {}",
            failures.join("\n  ")
        );
    }
}
