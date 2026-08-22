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
//! The per-case staging and the four experiments are SHARED with the v4
//! measurement study (`experiment_external_v4`): v4 runs the same staged
//! corpus through the same gates and attaches its own measurements
//! (repeat-probe determinism, challenge sensitivity, minimization, claims,
//! conventional baselines, storage/runtime/localization overhead). There is
//! ONE implementation of the four experiments.
//!
//! `--check` (default) exits non-zero on any misclassification, any lost
//! defect, any replay that did not reproduce, or any clean control that
//! diverged.

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::experiment::{dir_size, frf_bin};
use super::experiment_external::{admit, write_bytes};
use crate::load_evidence;

pub(crate) fn as_str(v: &Value) -> &str {
    v.as_str().unwrap_or_default()
}

const ENVIRONMENT_MATRIX: [(&str, &str, &str); 3] = [
    ("utc", "TZ=UTC", "LANG=C"),
    ("new-york", "TZ=America/New_York", "LANG=en_US.UTF-8"),
    ("tokyo", "TZ=Asia/Tokyo", "LANG=ja_JP.UTF-8"),
];

pub(crate) enum Expectation {
    Observed,
    Absent,
}

impl Copy for Expectation {}

impl Clone for Expectation {
    fn clone(&self) -> Self {
        *self
    }
}

pub(crate) struct TrajectoryMeasurement {
    pub experiment: String,
    pub case: String,
    pub axis: String,
    pub lineage: String,
    pub pattern: Vec<bool>,
    pub expected_drift: &'static str,
    pub expected_slew: &'static str,
    pub expected_localization: &'static str,
    pub evidence_bytes: u64,
}

pub(crate) struct CleanControl {
    pub case: String,
    pub residual_count: usize,
}

/// The per-case environment coordinates are DECLARED in each case manifest's
/// `environment_points`; the Shellshock trigger is a DECLARED environment
/// variable in the shellshock manifest (evidence, not orchestration) — a new
/// execution engine reproduces the observation from the evidence alone.
pub(crate) fn run_frf_env(
    frf: &Path,
    cwd: &Path,
    args: &[&str],
    envs: &[&str],
) -> (bool, String, String) {
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
pub(crate) fn read_axis_trajectories(
    case_work: &Path,
    coordinate_system: &str,
) -> Vec<(String, Vec<Value>)> {
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
pub(crate) fn select_by_pattern<'a>(
    records: &'a [Value],
    expected: &[Expectation],
) -> Option<&'a Value> {
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

/// The staged evidence of one case: the work tree with builds/, fixtures/,
/// the three rendered manifests, and the admitted authority versions.
pub(crate) struct StagedCase {
    pub id: String,
    pub case_work: PathBuf,
    /// The case metadata (`case.json`): sides, fixtures, authority name.
    pub meta: Value,
    pub manifest_defect: String,
    pub manifest_clean: String,
    pub manifest_clean_defect: String,
}

/// The run ids the four shared experiments produced — the handles the v4
/// measurement study needs to attach replays, claims, and reductions.
pub(crate) struct CaseEvidence {
    /// The ladder's observed run ids (the buggy revision first).
    pub ladder_runs: Vec<String>,
    /// The environment matrix's run ids, in coordinate order.
    pub env_runs: Vec<String>,
    /// The clean control's run id.
    pub clean_run: Option<String>,
}

/// Stage one case: copy the corpus builds/ + fixtures/ into the work tree,
/// render the three manifests from the template, and admit the two authority
/// versions (the fixed release, and the vulnerable release as `pre-fix`).
pub(crate) fn stage_case(frf: &Path, corpus: &Path, work: &Path, case: &Value) -> StagedCase {
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

    // Stage the corpus: builds/ + fixtures/ are copied verbatim; the
    // three manifests are rendered from the template. An ambient-trigger
    // case (Shellshock) declares the malicious function-import variable in
    // its manifest via the `x: "{trigger}"` placeholder: the defect
    // manifests receive the real trigger (declared environment = evidence),
    // and the CLEAN CONTROL manifest has the line REMOVED (the vulnerable
    // side without the trigger must produce zero residuals).
    copy_tree(&case_src.join("builds"), &case_work.join("builds"));
    copy_tree(&case_src.join("fixtures"), &case_work.join("fixtures"));
    let template = std::fs::read_to_string(case_src.join("manifest.yaml"))
        .unwrap_or_else(|e| panic!("cannot read the manifest for {id}: {e}"));
    let trigger_line = "  x: \"{trigger}\"";
    let trigger_value = "() { :;}; echo PWNED";
    let staged = |candidate: &str, fixture: &str, trigger: bool| {
        let t = template
            .replace("{candidate}", candidate)
            .replace("fixtures/{fixture}", &format!("fixtures/{fixture}"));
        if t.contains(trigger_line) {
            if trigger {
                t.replace(trigger_line, &format!("  x: \"{trigger_value}\""))
            } else {
                // The clean control runs WITHOUT the trigger: the line is
                // removed (an empty YAML line is inert).
                t.replace(trigger_line, "")
            }
        } else {
            t
        }
    };
    let ambient_trigger = as_str(&meta["trigger"]) == "env";
    write_bytes(
        &case_work,
        &format!("courts/{id}/manifest-defect.yaml"),
        staged(side_vuln, fixture_defect, ambient_trigger).as_bytes(),
        false,
    );
    write_bytes(
        &case_work,
        &format!("courts/{id}/manifest-clean.yaml"),
        staged(side_vuln, fixture_clean, false).as_bytes(),
        false,
    );
    write_bytes(
        &case_work,
        &format!("courts/{id}/manifest-clean-defect.yaml"),
        staged(side_fixed, fixture_defect, ambient_trigger).as_bytes(),
        false,
    );

    // Admit the FIXED release as the reference authority, and the
    // VULNERABLE release as its pre-fix version (the historical oracle
    // transition).
    admit(frf, &case_work, side_fixed, name, fixed_version);
    admit(frf, &case_work, side_vuln, name, "pre-fix");

    StagedCase {
        id: id.to_string(),
        case_work,
        meta,
        manifest_defect: format!("courts/{id}/manifest-defect.yaml"),
        manifest_clean: format!("courts/{id}/manifest-clean.yaml"),
        manifest_clean_defect: format!("courts/{id}/manifest-clean-defect.yaml"),
    }
}

/// Drive the four shared experiments over one staged case — the version
/// ladder, the environment matrix, both authority transitions, and the clean
/// control — pushing every measurement and failure, and returning the run
/// ids the later measurements need. This is the ONE implementation of the
/// four experiments; v3's runner and the v4 measurement study both use it.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_case_experiments(
    frf: &Path,
    staged: &StagedCase,
    measurements: &mut Vec<TrajectoryMeasurement>,
    clean_controls: &mut Vec<CleanControl>,
    failures: &mut Vec<String>,
) -> CaseEvidence {
    let id = &staged.id;
    let case_work = &staged.case_work;
    let meta = &staged.meta;
    let fixed_version = as_str(&meta["authority_fixed_version"]);
    let side_vuln = as_str(&meta["sides"]["vulnerable"]);
    let side_fixed = as_str(&meta["sides"]["fixed"]);

    // -- 1. the version ladder: buggy release -> fixed release ----------
    // An ambient-trigger case (Shellshock) has the trigger DECLARED in the
    // defect manifest's environment (evidence, not orchestration); the
    // ladder, authority transitions, and clean control all run plain.
    let revisions = format!("{side_vuln},{side_fixed}");
    let ladder_args: Vec<&str> = vec![
        "--root",
        "ev",
        "court",
        "run",
        &staged.manifest_defect,
        "--candidate-revisions",
        &revisions,
    ];
    let (ok, out, err) = run_frf_env(frf, case_work, &ladder_args, &[]);
    let mut ladder_runs: Vec<String> = Vec::new();
    if !ok {
        failures.push(format!("{id}/ladder: run failed: {err}"));
    } else {
        ladder_runs = out.lines().map(|l| l.to_string()).collect();
        let mut ceased = 0usize;
        let axis_trajectories = read_axis_trajectories(case_work, "candidate_revision");
        for (lineage, records) in &axis_trajectories {
            match select_by_pattern(records, &[Expectation::Observed, Expectation::Absent]) {
                Some(t) => {
                    measurements.push(check_trajectory(
                        case_work,
                        "ladder",
                        id,
                        "candidate_revision",
                        lineage,
                        t,
                        &[Expectation::Observed, Expectation::Absent],
                        "boundary-localized",
                        "abrupt",
                        "start",
                        failures,
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
                frf,
                case_work,
                &["--root", "ev", "replay", buggy_run, "--policy", "exact"],
                &[],
            );
            if !(rok && rout.contains("reproduced")) {
                failures.push(format!("{id}/ladder: replay did not reproduce"));
            }
        }
    }

    // -- 2. the environment matrix: the defect at every coordinate ------
    // The coordinates are DECLARED in each case manifest's
    // `environment_points` (TZ/LANG are evidence, not orchestration), and the
    // Shellshock trigger rides the manifest's declared `environment` — a new
    // execution engine reproduces the observation from the evidence alone.
    let mut env_runs: Vec<String> = Vec::new();
    for (label, _tz, _lang) in ENVIRONMENT_MATRIX {
        let (ok, out, err) = run_frf_env(
            frf,
            case_work,
            &[
                "--root",
                "ev",
                "court",
                "run",
                &staged.manifest_defect,
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
        let axis_trajectories = read_axis_trajectories(case_work, "environment");
        for (lineage, records) in &axis_trajectories {
            let observed_all = &[Expectation::Observed; ENVIRONMENT_MATRIX.len()];
            match select_by_pattern(records, observed_all) {
                Some(t) => {
                    measurements.push(check_trajectory(
                        case_work,
                        "environment-matrix",
                        id,
                        "environment",
                        lineage,
                        t,
                        observed_all,
                        "persistent",
                        "stable",
                        "none",
                        failures,
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
    // exactly when the oracle was fixed (onset at the end). The defect
    // manifest carries the declared trigger for an ambient-trigger case.
    let versions = format!("pre-fix,{fixed_version}");
    let auth_args: Vec<&str> = vec![
        "--root",
        "ev",
        "court",
        "run",
        &staged.manifest_defect,
        "--authority-versions",
        &versions,
    ];
    let (ok, _out, err) = run_frf_env(frf, case_work, &auth_args, &[]);
    if !ok {
        failures.push(format!("{id}/authority-buggy: run failed: {err}"));
    } else {
        let axis_trajectories = read_axis_trajectories(case_work, "authority_version");
        let expected = &[Expectation::Absent, Expectation::Observed];
        for (lineage, records) in &axis_trajectories {
            match select_by_pattern(records, expected) {
                Some(t) => {
                    measurements.push(check_trajectory(
                        case_work,
                        "authority-transition",
                        id,
                        "authority_version",
                        lineage,
                        t,
                        expected,
                        "boundary-localized",
                        "abrupt",
                        "end",
                        failures,
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
    // accepted) and matching the fixed one — a cessation at the start. The
    // defect manifest carries the declared trigger for an ambient-trigger
    // case.
    let versions_clean = format!("pre-fix,{fixed_version}");
    let auth_clean_args: Vec<&str> = vec![
        "--root",
        "ev",
        "court",
        "run",
        &staged.manifest_clean_defect,
        "--authority-versions",
        &versions_clean,
    ];
    let (ok, _out, err) = run_frf_env(frf, case_work, &auth_clean_args, &[]);
    if !ok {
        failures.push(format!("{id}/authority-clean: run failed: {err}"));
    } else {
        let axis_trajectories = read_axis_trajectories(case_work, "authority_version");
        let expected = &[Expectation::Observed, Expectation::Absent];
        let mut ceased = 0usize;
        for (lineage, records) in &axis_trajectories {
            match select_by_pattern(records, expected) {
                Some(t) => {
                    measurements.push(check_trajectory(
                        case_work,
                        "authority-transition",
                        id,
                        "authority_version",
                        lineage,
                        t,
                        expected,
                        "boundary-localized",
                        "abrupt",
                        "start",
                        failures,
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
    let mut clean_run: Option<String> = None;
    let (ok, out, err) = run_frf_env(
        frf,
        case_work,
        &["--root", "ev", "court", "run", &staged.manifest_clean],
        &[],
    );
    if !ok {
        failures.push(format!("{id}/clean-control: run failed: {err}"));
    } else {
        let run_id = out.lines().last().unwrap_or_default().to_string();
        clean_run = Some(run_id.clone());
        let cap = load_evidence(
            &case_work
                .join("ev/captures")
                .join(&run_id)
                .join("capture.json"),
        );
        let residuals = cap["residuals"].as_array().cloned().unwrap_or_default();
        if !residuals.is_empty() {
            // The capture's `residuals` are residual RECORD ids (strings);
            // load each record so the failure names the exact axis, kind,
            // and raw projections that diverged without the trigger — a
            // timing-sensitive probe and a genuine defect divergence look
            // very different in this detail.
            let detail: Vec<String> = residuals
                .iter()
                .filter_map(|r| r.as_str())
                .map(|rid| {
                    let rec =
                        load_evidence(&case_work.join("ev/residuals").join(format!("{rid}.json")));
                    format!(
                        "{rid} axis={} kind={} ref={:?} cand={:?}",
                        as_str(&rec["axis"]),
                        as_str(&rec["kind"]),
                        as_str(&rec["raw_reference"]),
                        as_str(&rec["raw_candidate"]),
                    )
                })
                .collect();
            failures.push(format!(
                "{id}/clean-control: the vulnerable side diverged WITHOUT the trigger ({} residual(s): {})",
                residuals.len(),
                detail.join(" | ")
            ));
        }
        clean_controls.push(CleanControl {
            case: id.to_string(),
            residual_count: residuals.len(),
        });
    }

    CaseEvidence {
        ladder_runs,
        env_runs,
        clean_run,
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

    // The Log4j case needs a JVM (the launcher execs `java`); without one it
    // is recorded as skipped and the gates apply to the executed cases only
    // (the report says exactly what ran).
    let java = Command::new("java")
        .arg("-version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    let mut measurements: Vec<TrajectoryMeasurement> = Vec::new();
    let mut clean_controls: Vec<CleanControl> = Vec::new();
    let mut failures: Vec<String> = Vec::new();
    let mut skipped_cases: Vec<String> = Vec::new();

    for case in &cases {
        let id = as_str(&case["id"]);
        if id == "log4shell" && !java {
            skipped_cases.push(id.to_string());
            continue;
        }
        let staged = stage_case(&frf, &corpus, &work, case);
        let _evidence = run_case_experiments(
            &frf,
            &staged,
            &mut measurements,
            &mut clean_controls,
            &mut failures,
        );
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

    let skipped_count = skipped_cases.len();
    let report = json!({
        "schema_version": "frf-external-experiment-v3",
        "corpus": "external-corpus/v3 (frf-external-corpus-v3: ACTUAL upstream vulnerable + fixed releases)",
        "cases": cases_count.to_string(),
        "cases_executed": (cases_count - skipped_cases.len()).to_string(),
        "skipped_cases": skipped_cases,
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
        "external-experiment-v3: {} case(s), {} skipped, {} trajectory measurement(s) ({} ladder, {} environment, {} authority), {} clean control(s), evidence {} bytes",
        cases_count,
        skipped_count,
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
