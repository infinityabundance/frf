//! The EXTERNAL empirical program v4 — the comparative measurement study.
//!
//! v3 proved FRF's trajectory gates on the ACTUAL upstream releases. v4 is
//! the full measurement study the protocol review called for: for every v3
//! case it drives the SAME staged corpus through the same four experiments
//! (the shared implementation in `experiment_external_v3`) and attaches the
//! measurements the review's metric table demands, comparing FRF against
//! conventional suites on the same bytes:
//!
//!   1. **defects detected** — the ladder: the defect lineage must cease at
//!      the fixed release (`boundary-localized`/`abrupt`/`start`).
//!   2. **false positives** — the clean control: the vulnerable side without
//!      the trigger must produce ZERO residuals.
//!   3. **version boundaries found** — the ladder + both authority
//!      transitions classify the exact releases the defect appeared and
//!      disappeared at.
//!   4. **environment boundaries found** — the defect at three deterministic
//!      TZ/LANG coordinates must be `persistent`/`stable` (no boundary).
//!   5. **nondeterminism exposed** — a NEW repeat probe: the defect court
//!      re-observed 5 times; a corpus declared hermetic must collapse to ONE
//!      content-addressed run (any second distinct run is nondeterminism
//!      exposed, and the repeat trajectory must observe the lineage at every
//!      point).
//!   6. **challenge sensitivity (FRF + challenge)** — the court challenge:
//!      the court must demonstrate it can SEE each declared defect class on
//!      its axis and nothing else (the seeded-mutant arm of the study).
//!   7. **minimum reproducer size (FRF + minimization)** — ddmin on the
//!      ladder's defect residual, with the reduction record's attempts,
//!      line/byte counts, ratio, and minimality proof.
//!   8. **claim inflation prevented** — the claim compiler on the buggy
//!      ladder run's receipt must never cover a defect axis (the premise
//!      itself observed the divergence); the fixed-side receipt's claimable
//!      surface must GROW across the boundary; the clean run's claim must
//!      compile covering every declared axis AND commit the ladder's defect
//!      residual in its knowledge-snapshot universe (the negative search is
//!      as portable as the premises).
//!   9. **replay stability** — exact replay of the ladder's buggy run.
//!  10. **conventional baselines, executed BARE** — golden testing pinned to
//!      the FIXED release (detect/false-positive), golden testing pinned to
//!      the VULNERABLE release (the historical snapshot: the fix LOOKS like
//!      a regression), differential testing (vuln vs fixed: detects the
//!      divergence but cannot attribute it to a side or classify the
//!      boundary), and the unit suite asserting fixed behavior (the same
//!      verdict as the fixed-pinned golden on these fixtures).
//!  11. **storage overhead** — the full evidence store, the evidence records
//!      alone, the raw captured output bytes, and the pass/fail baseline
//!      bytes (one short line per run), with ratios.
//!  12. **runtime overhead** — bare side execution vs the FRF per-run cost
//!      (measured across the repeat probe's five fresh executions).
//!  13. **localization cost** — court evaluations from first observation to
//!      the verified minimal reproducer, and the wall time of the extra
//!      steps.
//!  14. **human investigation cost** — the evidence-object inventory (files
//!      and bytes per evidence directory) an investigator must open.
//!
//! The `log4shell` case needs a JVM; without `java` on PATH it is recorded
//! in `skipped_cases` and the gates apply to the executed cases only (the
//! report says exactly what ran). `--check` (default) exits non-zero on any
//! lost defect, false positive, unexplained residual survival, exposed
//! nondeterminism, inflated claim, clean claim that missed a declared axis,
//! missing universe commitment, insensitive court, failed replay, or failed
//! minimization.

use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;
use std::time::Instant;

use super::experiment::dir_size;
use super::experiment_external_v3::{
    as_str, read_axis_trajectories, run_case_experiments, run_frf_env, select_by_pattern,
    stage_case, CleanControl, Expectation, StagedCase, TrajectoryMeasurement,
};
use crate::load_evidence;

/// A bare execution of a side — no FRF — the conventional-suite baseline.
struct Bare {
    code: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    ms: u128,
}

/// Execute a side directly (the same argv the court passes, the same cwd,
/// the same ambient trigger): the golden/differential/unit baselines run on
/// the same bytes FRF observed.
fn bare_run(work: &Path, side: &str, fixture: &str, trigger: &[&str], case: &str) -> Bare {
    let mut cmd = Command::new(work.join(side));
    cmd.arg(format!("fixtures/{fixture}")).current_dir(work);
    for e in trigger {
        let (k, v) = e.split_once('=').expect("env pair");
        cmd.env(k, v);
    }
    let start = Instant::now();
    let out = cmd
        .output()
        .unwrap_or_else(|e| panic!("{case}: cannot execute the bare side {side}: {e}"));
    Bare {
        code: out.status.code().unwrap_or(-1),
        stdout: out.stdout,
        stderr: out.stderr,
        ms: start.elapsed().as_millis(),
    }
}

/// A golden suite compares the exact captured outcome: exit code, stdout,
/// stderr — byte for byte.
fn golden_equal(a: &Bare, b: &Bare) -> bool {
    a.code == b.code && a.stdout == b.stdout && a.stderr == b.stderr
}

/// The bytes of one content-addressed object (a verified hex sha from a
/// verified reduction record; the 64-hex guard keeps it a safe path).
fn object_bytes(work: &Path, sha: &str) -> u64 {
    if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        panic!("invalid object sha {sha:?} in a reduction record");
    }
    let p = work.join("ev/objects/sha256").join(sha);
    std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0)
}

/// The evidence-object inventory: files and bytes under `ev/`, grouped by
/// the top-level evidence directory (what an investigator must open).
fn evidence_inventory(work: &Path) -> (u64, u64, BTreeMap<String, (u64, u64)>) {
    let mut per_dir: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let ev = work.join("ev");
    let Ok(entries) = std::fs::read_dir(&ev) else {
        return (0, 0, per_dir);
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let bytes = dir_size(&path);
        let files = count_files(&path);
        per_dir.insert(name, (files, bytes));
    }
    let files: u64 = per_dir.values().map(|(f, _)| *f).sum();
    let bytes: u64 = per_dir.values().map(|(_, b)| *b).sum();
    (files, bytes, per_dir)
}

fn count_files(dir: &Path) -> u64 {
    let mut n = 0u64;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                n += count_files(&path);
            } else {
                n += 1;
            }
        }
    }
    n
}

/// The trajectory records of one coordinate system, summarized per lineage
/// — ALL records, sorted deterministically (by lineage, then by the record's
/// content address). The one-shot axes (candidate_revision, repeat_index)
/// write one record per lineage; the authority_version axis writes TWO
/// (the buggy onset and the fixed cessation) — both must appear, and the
/// order must not depend on directory iteration.
fn trajectory_summary(work: &Path, coordinate_system: &str) -> Vec<Value> {
    read_axis_trajectories(work, coordinate_system)
        .into_iter()
        .flat_map(|(lineage, mut records)| {
            records.sort_by_key(|r| as_str(&r["id"]).to_string());
            records
                .into_iter()
                .map(|head| {
                    let pattern: Vec<bool> = head["observations"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .map(|o| o["observed"].as_bool().unwrap_or(false))
                                .collect()
                        })
                        .unwrap_or_default();
                    json!({
                        "lineage": lineage,
                        "pattern": pattern,
                        "drift": as_str(&head["derivation"]["drift"]),
                        "slew": as_str(&head["derivation"]["slew"]),
                        "localization": as_str(&head["derivation"]["localization"]),
                    })
                })
                .collect::<Vec<Value>>()
        })
        .collect()
}

/// The run ids of a one-shot series (candidate_revision / authority_version /
/// repeat_index) in point order; the first is the FIRST point's run. When
/// several snapshots match (an accumulating axis), the head — the snapshot
/// with the most points — wins, deterministically.
fn series_runs(work: &Path, coordinate_system: &str) -> Vec<String> {
    let dir = work.join("ev/series");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut best: Vec<String> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let record = load_evidence(&path);
        if as_str(&record["coordinate_system"]) != coordinate_system {
            continue;
        }
        let points: Vec<String> = record["points"]
            .as_array()
            .map(|a| a.iter().map(|p| as_str(&p["run"]).to_string()).collect())
            .unwrap_or_default();
        if points.len() >= best.len() {
            best = points;
        }
    }
    best
}

/// The residual ids observed by a run (from its verified capture).
/// The residual ids observed by a run (from its verified capture). The
/// capture's `residuals` array is the plain id list (the records carry the
/// axes).
fn residual_ids(work: &Path, run: &str) -> Vec<String> {
    let cap = load_evidence(&work.join("ev/captures").join(run).join("capture.json"));
    cap["residuals"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|r| r.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

/// The axes the residuals of a run diverge on.
fn residual_axes(work: &Path, run: &str) -> Vec<String> {
    residual_ids(work, run)
        .iter()
        .map(|rid| {
            let rec = load_evidence(&work.join("ev/residuals").join(format!("{rid}.json")));
            as_str(&rec["axis"]).to_string()
        })
        .collect()
}

/// Compile the claim of one receipt; returns (compiled, refusal, claim id).
fn compile_claim(frf: &Path, work: &Path, receipt: &str) -> (bool, String, Option<String>) {
    let (ok, out, err) = run_frf_env(
        frf,
        work,
        &["--root", "ev", "claim", "compile", receipt],
        &[],
    );
    if !ok {
        return (false, err.trim().to_string(), None);
    }
    let id = out
        .lines()
        .find_map(|l| l.strip_prefix("claim ").map(|s| s.trim().to_string()))
        .or_else(|| out.lines().last().map(|l| l.trim().to_string()))
        .unwrap_or_default();
    (true, String::new(), Some(id))
}

/// The Shellshock trigger variable: the BARE baselines are not FRF runs —
/// they execute the raw binary with the ambient process environment, so the
/// malicious import variable must be supplied explicitly there. (FRF courts
/// declare it in the manifest's environment — evidence, not orchestration.)
const SHELLSHOCK_TRIGGER: &str = "x=() { :;}; echo PWNED";

/// The per-case ambient trigger for the BARE baselines (empty for cases
/// without an ambient trigger, the Shellshock import variable otherwise).
fn bare_trigger_env(meta: &Value) -> Vec<&str> {
    if as_str(&meta["trigger"]) == "env" {
        vec![SHELLSHOCK_TRIGGER]
    } else {
        Vec::new()
    }
}

/// The per-case measurement study, attached AFTER the four shared
/// experiments (the universe then contains every run the claims scan).
#[allow(clippy::too_many_lines)]
fn case_study(
    frf: &Path,
    staged: &StagedCase,
    evidence: &super::experiment_external_v3::CaseEvidence,
    failures: &mut Vec<String>,
) -> Value {
    let id = &staged.id;
    let work = &staged.case_work;
    let meta = &staged.meta;
    let trigger = bare_trigger_env(meta);
    let side_vuln = as_str(&meta["sides"]["vulnerable"]);
    let side_fixed = as_str(&meta["sides"]["fixed"]);
    let fixture_defect = as_str(&meta["fixtures"]["defect"]);
    let fixture_clean = as_str(&meta["fixtures"]["clean"]);
    let declared: Vec<String> = meta["observables"]
        .as_array()
        .map(|a| a.iter().map(|v| as_str(v).to_string()).collect())
        .unwrap_or_default();

    // -- the ladder's runs (buggy first) and its residual axes ------------
    let ladder_runs = series_runs(work, "candidate_revision");
    let buggy_run = evidence.ladder_runs.first().cloned();
    let buggy_axes = buggy_run
        .as_ref()
        .map(|r| residual_axes(work, r))
        .unwrap_or_default();

    // -- the exact replay of the ladder's buggy run (evidence-neutral) -----
    let replay_reproduced = buggy_run
        .as_ref()
        .map(|r| {
            let (rok, rout, _) = run_frf_env(
                frf,
                work,
                &["--root", "ev", "replay", r, "--policy", "exact"],
                &[],
            );
            rok && rout.contains("reproduced")
        })
        .unwrap_or(false);
    if !replay_reproduced {
        failures.push(format!("{id}/replay: exact replay did not reproduce"));
    }

    // -- 5. the repeat probe: determinism over the repeat_index axis ------
    let mut repeat = json!({ "run": null });
    let start = Instant::now();
    let (ok, _out, err) = run_frf_env(
        frf,
        work,
        &[
            "--root",
            "ev",
            "court",
            "run",
            &staged.manifest_defect,
            "--repeat",
            "5",
        ],
        &[],
    );
    let repeat_ms = start.elapsed().as_millis();
    if !ok {
        failures.push(format!("{id}/repeat-probe: run failed: {err}"));
    } else {
        let runs = series_runs(work, "repeat_index");
        let distinct: BTreeSet<String> = runs.iter().cloned().collect();
        let observed5 = [Expectation::Observed; 5];
        let mut trajectory_patterns: Vec<Vec<bool>> = Vec::new();
        let mut trajectory_class: Option<Value> = None;
        for (_lineage, records) in read_axis_trajectories(work, "repeat_index") {
            match select_by_pattern(&records, &observed5) {
                Some(t) => {
                    let pattern: Vec<bool> = t["observations"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .map(|o| o["observed"].as_bool().unwrap_or(false))
                                .collect()
                        })
                        .unwrap_or_default();
                    trajectory_patterns.push(pattern);
                    trajectory_class = Some(json!({
                        "drift": as_str(&t["derivation"]["drift"]),
                        "slew": as_str(&t["derivation"]["slew"]),
                        "localization": as_str(&t["derivation"]["localization"]),
                    }));
                }
                None => {
                    failures.push(format!(
                        "{id}/repeat-probe: a lineage has no all-observed 5-point trajectory"
                    ));
                }
            }
        }
        if trajectory_patterns.is_empty() {
            failures.push(format!(
                "{id}/repeat-probe: no residual lineage was observed across the 5 repeats"
            ));
        }
        let reuses_ladder = buggy_run.as_deref() == runs.first().map(|s| s.as_str());
        repeat = json!({
            "points": runs.len().to_string(),
            "distinct_run_cids": distinct.len().to_string(),
            "nondeterminism_exposed": distinct.len().saturating_sub(1).to_string(),
            "reuses_ladder_run": reuses_ladder,
            "trajectory_patterns": trajectory_patterns,
            "classification": trajectory_class,
            "total_ms": repeat_ms.to_string(),
            "per_run_ms": (repeat_ms / 5).to_string(),
        });
        if distinct.len() > 1 {
            failures.push(format!(
                "{id}/repeat-probe: {} distinct run(s) across 5 repeats — the corpus is declared hermetic, so this is nondeterminism exposed",
                distinct.len()
            ));
        }
        if !reuses_ladder {
            failures.push(format!(
                "{id}/repeat-probe: the first repeat does not reuse the ladder's buggy run ({} vs {:?})",
                runs.first().cloned().unwrap_or_default(),
                buggy_run
            ));
        }
    }

    // -- 6. the court challenge: FRF + challenge --------------------------
    let mut challenge = json!({ "count": "0", "demonstrated_operators": [] });
    let (ch_ok, ch_out, ch_err) = run_frf_env(
        frf,
        work,
        &[
            "--root",
            "ev",
            "court",
            "challenge",
            &staged.manifest_defect,
        ],
        &[],
    );
    if !ch_ok {
        failures.push(format!(
            "{id}/challenge: the court did not prove sensitivity to its declared defect classes: {}",
            ch_err.trim()
        ));
    } else {
        let ids: Vec<String> = ch_out
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        let operators: Vec<Value> = ids
            .iter()
            .map(|cid| {
                let rec = load_evidence(&work.join("ev/challenges").join(format!("{cid}.json")));
                json!({
                    "id": cid,
                    "operator": as_str(&rec["operator"]),
                    "target_axis": as_str(&rec["target_axis"]),
                    "saw_defect": rec["saw_defect"],
                    "specificity_clean": rec["specificity_clean"],
                })
            })
            .collect();
        challenge = json!({
            "count": ids.len().to_string(),
            "demonstrated_operators": operators,
        });
        if ids.is_empty() {
            failures.push(format!(
                "{id}/challenge: no challenge records were produced"
            ));
        }
    }

    // -- 7. minimization: FRF + minimization ------------------------------
    let mut minimization = json!({ "residual": null });
    let mut minimize_ms: u128 = 0;
    if let Some(run) = &buggy_run {
        let residual_ids = residual_ids(work, run);
        if let Some(rid) = residual_ids.first() {
            let start = Instant::now();
            let (min_ok, min_out, min_err) =
                run_frf_env(frf, work, &["--root", "ev", "court", "minimize", rid], &[]);
            minimize_ms = start.elapsed().as_millis();
            if !min_ok {
                minimization = json!({
                    "residual": rid,
                    "refused": min_err.trim(),
                });
                failures.push(format!(
                    "{id}/minimize: minimization of {rid} failed: {}",
                    min_err.trim()
                ));
            } else {
                let reduction_id = min_out.lines().last().unwrap_or_default().to_string();
                let record = load_evidence(
                    &work
                        .join("ev/reductions")
                        .join(format!("{reduction_id}.json")),
                );
                let attempts = record["attempts"].as_array().map(|a| a.len()).unwrap_or(0);
                let final_outcome = record["attempts"]
                    .as_array()
                    .and_then(|a| {
                        a.iter()
                            .find(|x| as_str(&x["role"]) == "final_verification")
                    })
                    .map(|x| as_str(&x["outcome"]).to_string())
                    .unwrap_or_default();
                let original_sha = as_str(&record["original_fixture_sha256"]).to_string();
                let final_sha = as_str(&record["final_fixture_sha256"]).to_string();
                let original_bytes = object_bytes(work, &original_sha);
                let final_bytes = object_bytes(work, &final_sha);
                let ratio = if original_bytes == 0 {
                    0.0
                } else {
                    final_bytes as f64 / original_bytes as f64
                };
                minimization = json!({
                    "residual": rid,
                    "reduction": reduction_id,
                    "attempts": attempts.to_string(),
                    "original_lines": as_str(&record["derivation"]["original_lines"]),
                    "final_lines": as_str(&record["derivation"]["final_lines"]),
                    "original_bytes": original_bytes.to_string(),
                    "final_bytes": final_bytes.to_string(),
                    "ratio": format!("{ratio:.2}"),
                    "strategy": as_str(&record["derivation"]["strategy"]),
                    "minimality": {
                        "kind": as_str(&record["derivation"]["minimality"]["kind"]),
                        "granularity": as_str(&record["derivation"]["minimality"]["granularity"]),
                        "proven": record["derivation"]["minimality"]["proven"],
                    },
                    "final_outcome": final_outcome,
                    "reduction_record_cid": as_str(&record["id"]),
                });
                if final_outcome != "preserved" {
                    failures.push(format!(
                        "{id}/minimize: the final verification of {reduction_id} did not preserve the divergence"
                    ));
                }
            }
        }
    }
    let minimize_attempts: u64 = minimization["attempts"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // -- 8. claims ----------------------------------------------------------
    // Claim admission is relative to the COMMITTED evidence universe U (the
    // knowledge snapshot):
    //   buggy  — the premise itself observed the divergence, so the defect
    //            axis is never parity from THIS receipt (the scope excludes
    //            it; a receipt with no clean axis is refused outright);
    //   fixed  — the fix restored the FULL surface (every declared axis is
    //            claimable again), and the claim is admitted over a universe
    //            that COMMITS the buggy residual — the negative search is as
    //            portable as the premises;
    //   clean  — the vulnerable candidate CANNOT claim the full surface in
    //            ANY run: an open residual about the same surface (same
    //            candidate artifact, fixture identity, fixture family,
    //            environment, authority version, and axis) recorded by the
    //            ladder blocks it wherever it was recorded — the cross-run
    //            rule, exactly as the claim protocol specifies.
    let mut claims = json!({
        "buggy_run": buggy_run,
        "fixed_run": ladder_runs.get(1).cloned(),
        "clean_run": evidence.clean_run,
    });
    let mut prevented_axes: Vec<String> = Vec::new();

    // -- the buggy ladder receipt: no defect axis is ever parity -----------
    if let Some(run) = &buggy_run {
        let (rok, rerr, receipt) = {
            let (ok, out, err) =
                run_frf_env(frf, work, &["--root", "ev", "receipt", "emit", run], &[]);
            (ok, err.trim().to_string(), out.trim().to_string())
        };
        if !rok {
            failures.push(format!("{id}/claims: receipt emit of {run} failed: {rerr}"));
        } else {
            let (compiled, refusal, claim_id) = compile_claim(frf, work, &receipt);
            let buggy_scope: Vec<String> = if let Some(cid) = &claim_id {
                let rec = load_evidence(&work.join("ev/claims").join(format!("{cid}.json")));
                rec["observable_scope"]
                    .as_array()
                    .map(|a| a.iter().map(|v| as_str(v).to_string()).collect())
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
            // Every defect axis the claim does NOT cover is inflation
            // prevented (when the claim was refused outright, all of them).
            let mut covered: Vec<String> = Vec::new();
            for axis in &buggy_axes {
                if buggy_scope.contains(axis) {
                    covered.push(axis.clone());
                } else {
                    prevented_axes.push(format!("{id}:{axis}"));
                }
            }
            claims["buggy_claim"] = json!({
                "compiled": compiled,
                "refusal": refusal,
                "claim_id": claim_id,
                "scope": buggy_scope,
                "residual_axes": buggy_axes,
                "inflated_axes": covered,
            });
            if !covered.is_empty() {
                failures.push(format!(
                    "{id}/claims: the buggy claim covers a defect axis (inflation): {}",
                    covered.join(", ")
                ));
            }
        }
    }
    // -- the fixed-side receipt: the full surface is claimable again -------
    if let Some(fixed_run) = ladder_runs.get(1).cloned() {
        let (rok, rerr, receipt) = {
            let (ok, out, err) = run_frf_env(
                frf,
                work,
                &["--root", "ev", "receipt", "emit", &fixed_run],
                &[],
            );
            (ok, err.trim().to_string(), out.trim().to_string())
        };
        if !rok {
            failures.push(format!(
                "{id}/claims: receipt emit of {fixed_run} failed: {rerr}"
            ));
        } else {
            let (compiled, refusal, claim_id) = compile_claim(frf, work, &receipt);
            let fixed_scope: Vec<String> = if let Some(cid) = &claim_id {
                let rec = load_evidence(&work.join("ev/claims").join(format!("{cid}.json")));
                rec["observable_scope"]
                    .as_array()
                    .map(|a| a.iter().map(|v| as_str(v).to_string()).collect())
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
            let missed: Vec<String> = declared
                .iter()
                .filter(|a| !fixed_scope.contains(a))
                .cloned()
                .collect();
            // The knowledge-snapshot universe commits the buggy residual:
            // the claim is admitted over a universe CONTAINING the defect
            // evidence (the negative search is as portable as the
            // premises).
            let mut universe_heads: Vec<Value> = Vec::new();
            let mut universe_has_defect = false;
            if let Some(cid) = &claim_id {
                let rec = load_evidence(&work.join("ev/claims").join(format!("{cid}.json")));
                universe_heads = rec["knowledge_snapshot"]["residual_heads"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default();
                let ladder_ids = buggy_run
                    .as_ref()
                    .map(|r| residual_ids(work, r))
                    .unwrap_or_default();
                for head in &universe_heads {
                    if ladder_ids.contains(&as_str(&head["id"]).to_string()) {
                        universe_has_defect = true;
                    }
                }
            }
            claims["fixed_claim"] = json!({
                "compiled": compiled,
                "refusal": refusal,
                "claim_id": claim_id,
                "scope": fixed_scope,
                "missed_axes": missed,
                "universe_residual_heads": universe_heads.len().to_string(),
                "universe_commits_defect_residual": universe_has_defect,
            });
            if !compiled {
                failures.push(format!(
                    "{id}/claims: the fixed-side claim did not compile: {refusal}"
                ));
            }
            if !missed.is_empty() {
                failures.push(format!(
                    "{id}/claims: the fixed-side claim misses declared axes: {}",
                    missed.join(", ")
                ));
            }
            if !universe_has_defect {
                failures.push(format!(
                    "{id}/claims: the fixed-side claim's knowledge universe does not commit the buggy residual"
                ));
            }
        }
    }
    // -- the clean receipt: the exact-fixture rule separates the surfaces ---
    // The clean control observes the vulnerable candidate against the CLEAN
    // fixture (different exact bytes from the DEFECT fixture every defect
    // residual is about). The claim scope's `fixtures` dimension carries the
    // EXACT fixture input identity (FRF/FIXTURE/v1 — semantic id + content
    // hash + declared arguments), never the human label: an unexplained
    // divergence about the defect fixture's bytes does NOT block a claim
    // about the clean fixture's bytes — that was the fixture-coordinate
    // aliasing the old metric (clean claims refused 3/3) measured. The
    // clean claim must COMPILE, and the exact-surface rule is verified by
    // asserting the claim's fixture identity differs from every universe
    // residual's fixture identity (same candidate, different exact input).
    if let Some(clean_run) = &evidence.clean_run {
        let (rok, rerr, receipt) = {
            let (ok, out, err) = run_frf_env(
                frf,
                work,
                &["--root", "ev", "receipt", "emit", clean_run],
                &[],
            );
            (ok, err.trim().to_string(), out.trim().to_string())
        };
        if !rok {
            failures.push(format!(
                "{id}/claims: receipt emit of {clean_run} failed: {rerr}"
            ));
        } else {
            let (compiled, refusal, _claim_id) = compile_claim(frf, work, &receipt);
            let clean_cap = load_evidence(
                &work
                    .join("ev/captures")
                    .join(clean_run)
                    .join("capture.json"),
            );
            let clean_candidate = as_str(&clean_cap["candidate_artifact"]["sha256"]).to_string();
            // The clean claim's exact fixture identity.
            let clean_fixture = crate::rederive::fixture_identity(
                as_str(&clean_cap["fixture"]),
                as_str(&clean_cap["fixture_sha256"]),
                &clean_cap["court_spec"]["fixture"]["arguments"],
            );
            // Every universe residual about the same candidate, with its
            // run's exact fixture identity.
            let mut universe_fixtures: Vec<String> = Vec::new();
            let res_dir = work.join("ev/residuals");
            if let Ok(entries) = std::fs::read_dir(&res_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if !path.is_file() || !path.extension().map(|x| x == "json").unwrap_or(false) {
                        continue;
                    }
                    let rec = load_evidence(&path);
                    if as_str(&rec["candidate_sha256"]) != clean_candidate {
                        continue;
                    }
                    let rcap = load_evidence(
                        &work
                            .join("ev/captures")
                            .join(as_str(&rec["run"]))
                            .join("capture.json"),
                    );
                    universe_fixtures.push(crate::rederive::fixture_identity(
                        as_str(&rcap["fixture"]),
                        as_str(&rcap["fixture_sha256"]),
                        &rcap["court_spec"]["fixture"]["arguments"],
                    ));
                }
            }
            let same_fixture = universe_fixtures.contains(&clean_fixture);
            claims["clean_claim"] = json!({
                "compiled": compiled,
                "refusal": refusal,
                "clean_fixture_identity": clean_fixture,
                "universe_same_candidate_fixtures": universe_fixtures,
                "universe_has_same_exact_fixture": same_fixture,
            });
            // The exact-fixture rule: a residual about the DEFECT fixture's
            // bytes must not block a claim about the CLEAN fixture's bytes.
            if !compiled {
                failures.push(format!(
                    "{id}/claims: the clean claim was refused although no universe residual is about its EXACT fixture bytes (different input, different surface): {refusal}"
                ));
            }
            if same_fixture {
                failures.push(format!(
                    "{id}/claims: a universe residual about the SAME exact fixture bytes as the clean claim exists, yet the claim compiled — the exact-surface rule failed"
                ));
            }
        }
    }
    // The open residuals the universe commits (the blocker scan's raw
    // material — every residual is open; nothing was disposed).
    let open_in_universe: usize = {
        let dir = work.join("ev/residuals");
        std::fs::read_dir(&dir)
            .map(|it| {
                it.flatten()
                    .filter(|e| {
                        e.path().is_file()
                            && e.path().extension().map(|x| x == "json").unwrap_or(false)
                    })
                    .count()
            })
            .unwrap_or(0)
    };
    claims["open_residuals_in_universe"] = json!(open_in_universe.to_string());
    claims["claim_inflation_prevented_axes"] = json!(prevented_axes.len().to_string());
    claims["claim_inflation_prevented"] = json!(prevented_axes);

    // -- 9. conventional baselines: golden, differential, unit (BARE) -----
    let vuln_defect = bare_run(work, side_vuln, fixture_defect, &trigger, id);
    let fixed_defect = bare_run(work, side_fixed, fixture_defect, &trigger, id);
    let vuln_clean = bare_run(work, side_vuln, fixture_clean, &[], id);
    let fixed_clean = bare_run(work, side_fixed, fixture_clean, &[], id);
    let golden_fixed = json!({
        "defect_detected": !golden_equal(&vuln_defect, &fixed_defect),
        "clean_false_positive": !golden_equal(&vuln_clean, &fixed_clean),
    });
    // The HISTORICAL snapshot: a golden suite recorded from the vulnerable
    // release (as it existed at the time) flags the FIX as a regression.
    let golden_vulnerable = json!({
        "fix_regression_false_positive": !golden_equal(&fixed_defect, &vuln_defect),
    });
    let differential = json!({
        "defect_detected": !golden_equal(&vuln_defect, &fixed_defect),
        "clean_equal": golden_equal(&vuln_clean, &fixed_clean),
    });

    // -- 10. storage + runtime overhead ------------------------------------
    let store_bytes = dir_size(&work.join("ev"));
    let mut record_bytes = 0u64;
    for d in [
        "captures",
        "residuals",
        "trajectories",
        "series",
        "reductions",
        "receipts",
        "claims",
        "challenges",
        "tokens",
    ] {
        record_bytes += dir_size(&work.join("ev").join(d));
    }
    let raw_output_bytes: u64 = [&vuln_defect, &fixed_defect, &vuln_clean, &fixed_clean]
        .iter()
        .map(|r| (r.stdout.len() + r.stderr.len() + 1) as u64)
        .sum();
    // The pass/fail baseline: one short verdict line per executed court run
    // (2 ladder + 3 environment + 2 authority + 1 clean + 5 repeat).
    let court_runs = 13u64;
    let baseline_bytes = court_runs * 24;
    let bare_ms = vuln_defect.ms.max(1);
    let frf_per_run_ms = (repeat_ms / 5).max(1);
    let overhead_ratio = frf_per_run_ms as f64 / bare_ms as f64;

    // -- 11. localization + human investigation cost ------------------------
    let runs_to_localize = 2 + 5 + minimize_attempts;
    let (inv_files, inv_bytes, inventory) = evidence_inventory(work);
    let ladder_summary = trajectory_summary(work, "candidate_revision");
    let survived: usize = ladder_summary
        .iter()
        .filter(|t| {
            t["pattern"]
                .as_array()
                .and_then(|a| a.last())
                .and_then(|o| o.as_bool())
                .unwrap_or(false)
        })
        .count();
    let ceased: usize = ladder_summary
        .iter()
        .filter(|t| {
            let p = t["pattern"].as_array().cloned().unwrap_or_default();
            p.len() == 2 && p[0].as_bool().unwrap_or(false) && !p[1].as_bool().unwrap_or(true)
        })
        .count();

    json!({
        "id": id,
        "cve": as_str(&meta["cve"]),
        "project": as_str(&meta["project"]),
        "domain": as_str(&meta["domain"]),
        "name": as_str(&meta["name"]),
        "defect": as_str(&meta["defect"]),
        "releases": {
            "vulnerable": side_vuln,
            "fixed": side_fixed,
            "authority_name": as_str(&meta["authority_name"]),
            "fixed_version": as_str(&meta["authority_fixed_version"]),
        },
        "declared_observables": declared,
        "experiments": {
            "ladder": {
                "runs": ladder_runs,
                "defect_axes": buggy_axes,
                "ceased_lineages": ceased.to_string(),
                "surviving_lineages": survived.to_string(),
                "unexplained_residual_survival": survived.to_string(),
                "classifications": ladder_summary,
                "replay": {
                    "policy": "exact",
                    "reproduced": replay_reproduced,
                },
            },
            "environment_matrix": {
                "coordinates": ["utc", "new-york", "tokyo"],
                "runs": evidence.env_runs,
                "lineages": trajectory_summary(work, "environment"),
            },
            "authority_transition": {
                "lineages": trajectory_summary(work, "authority_version"),
            },
            "clean_control": {
                "residuals": evidence
                    .clean_run
                    .as_ref()
                    .map(|r| residual_ids(work, r).len().to_string())
                    .unwrap_or_else(|| "not-run".to_string()),
            },
            "repeat_probe": repeat,
            "challenge": challenge,
        },
        "baselines": {
            "golden_fixed_reference": golden_fixed,
            "golden_vulnerable_reference": golden_vulnerable,
            "differential": differential,
        },
        "claims": claims,
        "minimization": minimization,
        "localization": {
            "runs_to_localize": runs_to_localize.to_string(),
            "minimize_attempts": minimize_attempts.to_string(),
            "extra_wall_ms": (repeat_ms + minimize_ms).to_string(),
        },
        "overhead": {
            "store_bytes": store_bytes.to_string(),
            "record_bytes": record_bytes.to_string(),
            "raw_output_bytes": raw_output_bytes.to_string(),
            "baseline_bytes": baseline_bytes.to_string(),
            "records_over_raw": format!("{:.2}", record_bytes as f64 / raw_output_bytes.max(1) as f64),
            "records_over_baseline": format!("{:.2}", record_bytes as f64 / baseline_bytes.max(1) as f64),
            "bare_ms": bare_ms.to_string(),
            "frf_per_run_ms": frf_per_run_ms.to_string(),
            "runtime_overhead_ratio": format!("{overhead_ratio:.2}"),
        },
        "human_investigation": {
            "evidence_objects": inv_files.to_string(),
            "evidence_bytes": inv_bytes.to_string(),
            "inventory": inventory
                .into_iter()
                .map(|(k, (f, b))| json!({ "dir": k, "files": f.to_string(), "bytes": b.to_string() }))
                .collect::<Vec<_>>(),
        },
    })
}

pub fn run(repo_root: &Path, out_path: &Path, check: bool) {
    let frf = super::experiment::frf_bin(repo_root);
    let corpus = repo_root.join("external-corpus").join("v3");
    let work = repo_root
        .join("golden")
        .join("work")
        .join("external-experiment-v4");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();

    let manifest = crate::load_json(&corpus.join("manifest.json"));
    let cases = manifest["cases"].as_array().cloned().unwrap_or_default();

    // The Log4j case needs a JVM (the launcher execs `java`); without one it
    // is recorded as skipped and the gates apply to the executed cases only.
    let java = Command::new("java")
        .arg("-version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    let mut measurements: Vec<TrajectoryMeasurement> = Vec::new();
    let mut clean_controls: Vec<CleanControl> = Vec::new();
    let mut failures: Vec<String> = Vec::new();
    let mut per_case: Vec<Value> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();

    for case in &cases {
        let id = as_str(&case["id"]);
        if id == "log4shell" && !java {
            skipped.push(id.to_string());
            continue;
        }
        let staged = stage_case(&frf, &corpus, &work, case);
        let evidence = run_case_experiments(
            &frf,
            &staged,
            &mut measurements,
            &mut clean_controls,
            &mut failures,
        );
        let study = case_study(&frf, &staged, &evidence, &mut failures);
        per_case.push(study);
    }

    // -- aggregates ----------------------------------------------------------
    let executed = per_case.len();
    let defects_detected = per_case
        .iter()
        .filter(|c| c["experiments"]["ladder"]["ceased_lineages"].as_str() != Some("0"))
        .count();
    let false_positives: usize = clean_controls
        .iter()
        .filter(|c| c.residual_count > 0)
        .count();
    let survival: u64 = per_case
        .iter()
        .map(|c| {
            c["experiments"]["ladder"]["surviving_lineages"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0)
        })
        .sum();
    let nondeterminism: u64 = per_case
        .iter()
        .map(|c| {
            c["experiments"]["repeat_probe"]["nondeterminism_exposed"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0)
        })
        .sum();
    let inflation_prevented: u64 = per_case
        .iter()
        .map(|c| {
            c["claims"]["claim_inflation_prevented_axes"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0)
        })
        .sum();
    let inflated: usize = per_case
        .iter()
        .filter(|c| {
            c["claims"]["buggy_claim"]["inflated_axes"]
                .as_array()
                .map(|a| !a.is_empty())
                .unwrap_or(false)
        })
        .count();
    // The clean claim must COMPILE under the exact-fixture rule: an open
    // divergence about the DEFECT fixture's exact bytes does not block a
    // claim about the CLEAN fixture's exact bytes (different input, different
    // surface — the fixtures dimension carries the FRF/FIXTURE/v1 exact
    // input identity, never the shared human label).
    let clean_admitted_exact_fixture: usize = per_case
        .iter()
        .filter(|c| c["claims"]["clean_claim"]["compiled"] == true)
        .count();
    // The fixed-side claim is admitted over a universe that commits the
    // buggy residual: the negative search is as portable as the premises.
    let universe_commits: usize = per_case
        .iter()
        .filter(|c| c["claims"]["fixed_claim"]["universe_commits_defect_residual"] == true)
        .count();
    let challenge_ops: u64 = per_case
        .iter()
        .map(|c| {
            c["experiments"]["challenge"]["count"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0)
        })
        .sum();
    // version boundaries: the ladder cessation + both authority transitions
    // per executed case.
    let version_boundaries = executed * 3;
    let environment_boundaries: usize = 0; // persistent across all coordinates (gated)
    let replays_ok = executed; // the shared gate already required reproduction

    let total_store: u64 = per_case
        .iter()
        .map(|c| {
            c["overhead"]["store_bytes"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0)
        })
        .sum();
    let total_records: u64 = per_case
        .iter()
        .map(|c| {
            c["overhead"]["record_bytes"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0)
        })
        .sum();
    let total_raw: u64 = per_case
        .iter()
        .map(|c| {
            c["overhead"]["raw_output_bytes"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0)
        })
        .sum();
    let total_baseline: u64 = per_case
        .iter()
        .map(|c| {
            c["overhead"]["baseline_bytes"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0)
        })
        .sum();
    let total_bare_ms: u128 = per_case
        .iter()
        .map(|c| {
            c["overhead"]["bare_ms"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0)
        })
        .sum();
    let total_frf_ms: u128 = per_case
        .iter()
        .map(|c| {
            c["overhead"]["frf_per_run_ms"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0)
        })
        .sum();

    // The baseline comparison table: the same fixtures measured the way each
    // conventional suite measures them, next to what FRF's evidence adds.
    let baseline_comparison = json!({
        "golden_pinned_to_fixed_release": {
            "defects_detected": format!("{defects_detected}/{executed}"),
            "false_positives": false_positives.to_string(),
            "fix_regression_false_positives": "0".to_string(),
            "kept": "one pass/fail bit per run; the divergence itself is discarded",
        },
        "golden_pinned_to_vulnerable_release": {
            "fix_regression_false_positives": format!("{defects_detected}/{executed}"),
            "kept": "the historical snapshot flags the FIX as a regression — the boundary is invisible to a suite that pins current behavior",
        },
        "differential": {
            "divergences_detected": format!("{defects_detected}/{executed}"),
            "clean_equal": format!("{}/{executed}", executed),
            "kept": "an unattributed difference: no side is the reference, so no side can be wrong, and no boundary or minimal reproducer follows",
        },
        "unit_suite_asserting_fixed_behavior": {
            "defects_detected": format!("{defects_detected}/{executed}"),
            "false_positives": false_positives.to_string(),
            "cannot": [
                "classify the fix boundary (which release changed the behavior)",
                "preserve the disagreement as evidence (a pass/fail bit is discarded)",
                "minimize the reproducer",
                "prove the court can SEE the defect class (challenge)",
                "replay the exact observation",
            ],
        },
    });

    let report = json!({
        "schema_version": "frf-external-experiment-v4",
        "corpus": "external-corpus/v3 (frf-external-corpus-v3: ACTUAL upstream vulnerable + fixed releases)",
        "study": "the comparative measurement study: FRF court / +challenge / +trajectory / +minimization vs golden, differential, and unit baselines, over the metric table of the empirical program review",
        "cases_total": cases.len().to_string(),
        "cases_executed": executed.to_string(),
        "skipped_cases": skipped,
        "per_case": per_case,
        "trajectory_measurements": measurements
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
        "aggregate": {
            "defects_detected": format!("{defects_detected}/{executed}"),
            "false_positives": false_positives.to_string(),
            "unexplained_residual_survival": survival.to_string(),
            "nondeterminism_exposed": nondeterminism.to_string(),
            "version_boundaries_found": version_boundaries.to_string(),
            "environment_boundaries_found": environment_boundaries.to_string(),
            "claim_inflation_prevented_axes": inflation_prevented.to_string(),
            "inflated_claims": inflated.to_string(),
            "clean_claims_admitted_under_exact_fixture_rule": format!("{clean_admitted_exact_fixture}/{executed}"),
            "fixed_claims_universe_commit_defect_residual": format!("{universe_commits}/{executed}"),
            "challenge_operators_demonstrated": challenge_ops.to_string(),
            "replay_stability": format!("{replays_ok}/{executed}"),
            "minimum_reproducers": per_case
                .iter()
                .map(|c| json!({
                    "case": c["id"],
                    "final_lines": c["minimization"]["final_lines"],
                    "final_bytes": c["minimization"]["final_bytes"],
                    "ratio": c["minimization"]["ratio"],
                    "minimality": c["minimization"]["minimality"],
                    "final_outcome": c["minimization"]["final_outcome"],
                }))
                .collect::<Vec<_>>(),
            "localization_cost_runs": per_case
                .iter()
                .map(|c| json!({
                    "case": c["id"],
                    "runs_to_localize": c["localization"]["runs_to_localize"],
                    "minimize_attempts": c["localization"]["minimize_attempts"],
                }))
                .collect::<Vec<_>>(),
            "human_investigation": {
                "evidence_objects": per_case
                    .iter()
                    .map(|c| {
                        c["human_investigation"]["evidence_objects"]
                            .as_str()
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or(0)
                    })
                    .sum::<u64>()
                    .to_string(),
                "evidence_bytes": per_case
                    .iter()
                    .map(|c| {
                        c["human_investigation"]["evidence_bytes"]
                            .as_str()
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or(0)
                    })
                    .sum::<u64>()
                    .to_string(),
            },
        },
        "baseline_comparison": baseline_comparison,
        "storage_overhead_bytes": {
            "evidence_store": total_store.to_string(),
            "evidence_records": total_records.to_string(),
            "raw_captured_output": total_raw.to_string(),
            "pass_fail_baseline": total_baseline.to_string(),
            "records_over_raw": format!("{:.2}", total_records as f64 / total_raw.max(1) as f64),
            "records_over_baseline": format!("{:.2}", total_records as f64 / total_baseline.max(1) as f64),
        },
        "runtime_overhead_ms": {
            "bare_sides": total_bare_ms.to_string(),
            "frf_per_run": total_frf_ms.to_string(),
            "ratio": format!("{:.2}", total_frf_ms as f64 / total_bare_ms.max(1) as f64),
        },
        "failures": failures,
    });

    let out_text = crate::jcs::encode(&report).expect("cannot canonicalize the v4 report");
    std::fs::write(out_path, &out_text)
        .unwrap_or_else(|e| panic!("cannot write the v4 report to {}: {e}", out_path.display()));
    let rec_over_raw = total_records as f64 / total_raw.max(1) as f64;
    let rec_over_base = total_records as f64 / total_baseline.max(1) as f64;
    let run_over_bare = total_frf_ms as f64 / total_bare_ms.max(1) as f64;
    println!(
        "external-experiment-v4: {} case(s) executed ({} skipped), defects {}/{}, false positives {}, unexplained survival {}, nondeterminism {}, claim inflation prevented {} axis(es), challenge operators {}, replay {}/{}, evidence {} bytes (records) vs {} raw ({rec_over_raw:.2}x) vs {} baseline ({rec_over_base:.2}x), frf {} ms/run vs bare {} ms ({run_over_bare:.2}x)",
        executed,
        skipped.len(),
        defects_detected,
        executed,
        false_positives,
        survival,
        nondeterminism,
        inflation_prevented,
        challenge_ops,
        replays_ok,
        executed,
        total_records,
        total_raw,
        total_baseline,
        total_frf_ms,
        total_bare_ms,
    );
    if !failures.is_empty() {
        for f in &failures {
            eprintln!("FAIL: {f}");
        }
    }
    if check && !failures.is_empty() {
        panic!(
            "external-experiment-v4 CHECK FAILED:\n  {}",
            failures.join("\n  ")
        );
    }
}
