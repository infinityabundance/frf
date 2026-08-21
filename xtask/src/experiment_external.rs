//! The EXTERNAL empirical program — Phase 10.
//!
//! Real historical defects, reconstructed as minimal deterministic
//! reproducers (external-corpus/), measured with the REAL `frf` reference
//! engine across the domains those defects actually occurred in: CLI
//! (Apple's "goto fail", bash's "Shellshock"), wire (OpenSSL's
//! "Heartbleed"), and structured state (Log4j's "Log4Shell", the Mars
//! Climate Orbiter unit mismatch, the two-digit-year Y2K bug).
//!
//! For every case the harness measures:
//!
//! 1. **defect discovery** — the buggy candidate must produce a residual on
//!    its targeted axis under the FIXED reference;
//! 2. **false positives** — a distinct clean candidate must produce zero
//!    residuals under the fixed reference;
//! 3. **claim behavior** — on a defective run the claim compiler is either
//!    refused or scoped to the clean axes only (never the defect axis); on a
//!    clean run the bounded claim must compile covering every declared axis;
//! 4. **minimization cost** — deterministic ddmin where a text reducer
//!    exists (CLI cases), and the honest refusal where a surface has none;
//! 5. **replay stability** — exact replays of the defect run, byte-identical;
//! 6. **challenge sensitivity** — the court must demonstrate it can SEE the
//!    defect class: built-in operators for CLI axes, an EXTERNAL MUTATION
//!    PROVIDER (spec/mutation.md) that reintroduces the historical defect
//!    for the wire/state domains;
//! 7. **evidence overhead** — FRF bytes per observation vs a conventional
//!    pass/fail baseline.
//!
//! The conventional-suite comparison is stated plainly: a unit or golden
//! suite that tests only the cases its fixtures happen to cover misses the
//! bugs its fixtures do not exercise. FRF's differentiators are measured —
//! residual preservation, challenge-proven sensitivity, minimization,
//! replay — not assumed.
//!
//! `--check` (default) exits non-zero when any measurement violates the
//! standards: an undetected historical defect, a false positive, claim
//! inflation, an insensitive court, or a replay that did not reproduce.

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use super::experiment::{dir_size, frf_bin};
use crate::load_evidence;

fn as_str(v: &Value) -> &str {
    v.as_str().unwrap_or_default()
}

pub(crate) fn run_frf(frf: &Path, cwd: &Path, args: &[&str]) -> (bool, String, String) {
    let out = Command::new(frf)
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap_or_else(|e| panic!("cannot execute {frf:?}: {e}"));
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).trim().to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

pub(crate) fn copy_to(src_root: &Path, dst_root: &Path, rel: &str, executable: bool) {
    let src = src_root.join(rel);
    let bytes =
        std::fs::read(&src).unwrap_or_else(|e| panic!("cannot read {}: {e}", src.display()));
    write_bytes(dst_root, &format!("scripts/{rel}"), &bytes, executable);
}

pub(crate) fn write_bytes(root: &Path, rel: &str, bytes: &[u8], executable: bool) {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).unwrap();
        }
    }
    std::fs::write(&path, bytes).unwrap_or_else(|e| panic!("cannot write {}: {e}", path.display()));
    if executable {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
}

pub(crate) fn admit(frf: &Path, cwd: &Path, path: &str, name: &str, version: &str) {
    let (ok, out, err) = run_frf(
        frf,
        cwd,
        &[
            "--root",
            "ev",
            "authority",
            "admit",
            path,
            "--name",
            name,
            "--version",
            version,
        ],
    );
    assert!(ok, "authority admit failed: {out} {err}");
}

/// One measured case result.
struct Observed {
    id: String,
    domain: String,
    name: String,
    defect_run: String,
    residual_axes: Vec<String>,
    residual_surfaces: Vec<String>,
    clean_run_residuals: usize,
    claim_on_defect: Option<(bool, Vec<String>)>, // (compiled, scope)
    claim_on_clean: Option<(bool, Vec<String>)>,
    replays_ok: u32,
    challenge_ok: bool,
    challenge_axes: Vec<String>,
    minimization: Option<Value>,
    evidence_bytes: u64,
}

pub fn run(repo_root: &Path, out_path: &Path, check: bool) {
    let frf = frf_bin(repo_root);
    let corpus = repo_root.join("external-corpus");
    let work = repo_root
        .join("golden")
        .join("work")
        .join("external-experiment");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();

    let manifest = crate::load_json(&corpus.join("manifest.json"));
    assert_eq!(
        as_str(&manifest["schema_version"]),
        "frf-external-corpus-v1"
    );
    let cases = manifest["cases"].as_array().cloned().unwrap_or_default();

    let mut observed: Vec<Observed> = Vec::new();
    for case in &cases {
        let id = as_str(&case["id"]);
        let case_src = corpus.join(id);
        let case_work = work.join(id);
        std::fs::create_dir_all(&case_work).unwrap();

        // Stage the case: scripts under scripts/, fixtures and the mutation
        // provider at the case root (the manifest's paths are cwd-relative).
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

        // The per-run manifests: concrete candidate + concrete fixture (the
        // {fixture} in ARGUMENTS resolves at run time; the fixture PATH is
        // concrete).
        let staged_defect = template
            .replace("{candidate}", "scripts/candidate-buggy.sh")
            .replace(
                "fixtures/{fixture}",
                &format!("fixtures/{}", as_str(&case["fixture_defect"])),
            );
        let staged_clean = template
            .replace("{candidate}", "scripts/candidate-clean.sh")
            .replace(
                "fixtures/{fixture}",
                &format!("fixtures/{}", as_str(&case["fixture_clean"])),
            );
        write_bytes(
            &case_work,
            &format!("courts/{id}/manifest-defect.yaml"),
            staged_defect.as_bytes(),
            false,
        );
        write_bytes(
            &case_work,
            &format!("courts/{id}/manifest-clean.yaml"),
            staged_clean.as_bytes(),
            false,
        );

        // -- the fixed reference, admitted -----------------------------------
        let name = as_str(&case["authority_name"]);
        let version = as_str(&case["authority_version"]);
        admit(&frf, &case_work, "scripts/reference.sh", name, version);

        // -- defect run: buggy candidate on the defect fixture --------------
        let (ok, out, err) = run_frf(
            &frf,
            &case_work,
            &[
                "--root",
                "ev",
                "court",
                "run",
                &format!("courts/{id}/manifest-defect.yaml"),
            ],
        );
        assert!(ok, "defect run {id} failed:\nstdout: {out}\nstderr: {err}");
        let defect_run = out.lines().last().unwrap_or_default().to_string();
        let capture = load_evidence(
            &case_work
                .join("ev/captures")
                .join(&defect_run)
                .join("capture.json"),
        );
        let mut residual_axes = Vec::new();
        let mut residual_surfaces = Vec::new();
        let mut first_residual: Option<String> = None;
        for rid in capture["residuals"].as_array().cloned().unwrap_or_default() {
            let rid = as_str(&rid).to_string();
            let record = load_evidence(&case_work.join("ev/residuals").join(format!("{rid}.json")));
            residual_axes.push(as_str(&record["axis"]).to_string());
            residual_surfaces.push(as_str(&record["surface"]).to_string());
            if first_residual.is_none() {
                first_residual = Some(rid);
            }
        }

        // -- clean run: clean candidate on the clean fixture -----------------
        let (ok, out, err) = run_frf(
            &frf,
            &case_work,
            &[
                "--root",
                "ev",
                "court",
                "run",
                &format!("courts/{id}/manifest-clean.yaml"),
            ],
        );
        assert!(ok, "clean run {id} failed:\nstdout: {out}\nstderr: {err}");
        let clean_run = out.lines().last().unwrap_or_default().to_string();
        let clean_capture = load_evidence(
            &case_work
                .join("ev/captures")
                .join(&clean_run)
                .join("capture.json"),
        );
        let clean_residuals = clean_capture["residuals"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0);

        // -- claims ----------------------------------------------------------
        let claim_outcome = |run: &str| -> (bool, Vec<String>) {
            let (ok, receipt, _) =
                run_frf(&frf, &case_work, &["--root", "ev", "receipt", "emit", run]);
            assert!(ok, "receipt emit failed for {id}/{run}");
            let receipt = receipt.trim().to_string();
            let (claim_ok, _, _) = run_frf(
                &frf,
                &case_work,
                &["--root", "ev", "claim", "compile", &receipt],
            );
            let mut scope = Vec::new();
            if claim_ok {
                // Claim v8: content-addressed claim files with a by-receipt
                // index; the experiment compiles once per receipt (baseline),
                // so exactly one claim must resolve.
                let index = case_work.join("ev/claims/by-receipt").join(&receipt);
                let mut ids: Vec<String> = std::fs::read_dir(&index)
                    .unwrap_or_else(|e| panic!("claim index for {receipt} is missing: {e}"))
                    .flatten()
                    .filter(|e| e.path().is_file())
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect();
                ids.sort();
                assert_eq!(
                    ids.len(),
                    1,
                    "receipt {receipt} has {} compiled claim(s); the experiment compiles once per receipt",
                    ids.len()
                );
                let claim =
                    load_evidence(&case_work.join("ev/claims").join(format!("{}.json", ids[0])));
                for o in claim["observable_scope"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                {
                    scope.push(as_str(&o).to_string());
                }
            }
            (claim_ok, scope)
        };
        let claim_on_defect = Some(claim_outcome(&defect_run));
        let claim_on_clean = Some(claim_outcome(&clean_run));

        // -- replay stability: three exact replays of the defect run ---------
        let mut replays_ok = 0u32;
        for _ in 0..3 {
            let (ok, out_text, _) = run_frf(
                &frf,
                &case_work,
                &["--root", "ev", "replay", &defect_run, "--policy", "exact"],
            );
            if ok && out_text.contains("reproduced") {
                replays_ok += 1;
            }
        }

        // -- the court must prove it can SEE the defect class ----------------
        // CLI domains use the built-in operators; wire/state domains use the
        // declared EXTERNAL MUTATION PROVIDER, which proposes a mutant that
        // reintroduces the historical defect — the court decides the
        // verdicts from the run.
        let (challenge_ok, _challenge_out, challenge_err) =
            match case.get("challenge").and_then(|v| v.as_str()) {
                Some("builtin") => run_frf(
                    &frf,
                    &case_work,
                    &[
                        "--root",
                        "ev",
                        "court",
                        "challenge",
                        &format!("courts/{id}/manifest-defect.yaml"),
                    ],
                ),
                Some("mutation") => {
                    let op = as_str(&case["mutation_operator"]);
                    run_frf(
                        &frf,
                        &case_work,
                        &[
                            "--root",
                            "ev",
                            "court",
                            "challenge",
                            &format!("courts/{id}/manifest-defect.yaml"),
                            "--operators",
                            op,
                        ],
                    )
                }
                _ => panic!("case {id}: unknown challenge mode"),
            };
        let challenge_axes: Vec<String> = case["observables"]
            .as_array()
            .map(|a| a.iter().map(|v| as_str(v).to_string()).collect())
            .unwrap_or_default();

        // -- minimization (text reducers only) -------------------------------
        let mut minimization: Option<Value> = None;
        if case.get("minimizable").and_then(|v| v.as_bool()) == Some(true) {
            if let Some(rid) = first_residual {
                let (ok, out, err) = run_frf(
                    &frf,
                    &case_work,
                    &["--root", "ev", "court", "minimize", &rid],
                );
                if !ok {
                    minimization = Some(json!({
                        "residual": rid,
                        "refused": err.trim(),
                    }));
                } else {
                    let reduction_id = out.lines().last().unwrap_or_default().to_string();
                    let record = load_evidence(
                        &case_work
                            .join("ev/reductions")
                            .join(format!("{reduction_id}.json")),
                    );
                    minimization = Some(json!({
                        "residual": rid,
                        "reduction": reduction_id,
                        "attempts": record["attempts"].as_array().map(|a| a.len()).unwrap_or(0),
                        "original_lines": record["derivation"]["original_lines"],
                        "final_lines": record["derivation"]["final_lines"],
                        "minimality": {
                            "kind": record["derivation"]["minimality"]["kind"],
                            "granularity": record["derivation"]["minimality"]["granularity"],
                            "proven": record["derivation"]["minimality"]["proven"],
                        },
                    }));
                }
            }
        }

        // -- evidence overhead ------------------------------------------------
        let mut evidence_bytes = dir_size(&case_work.join("ev/captures").join(&defect_run));
        for rid in capture["residuals"].as_array().cloned().unwrap_or_default() {
            let rid = as_str(&rid).to_string();
            evidence_bytes += dir_size(&case_work.join("ev/residuals").join(format!("{rid}.json")));
            evidence_bytes += dir_size(
                &case_work
                    .join("ev/residuals")
                    .join(format!("{rid}.token.json")),
            );
        }

        observed.push(Observed {
            id: id.to_string(),
            domain: as_str(&case["domain"]).to_string(),
            name: as_str(&case["name"]).to_string(),
            defect_run,
            residual_axes,
            residual_surfaces,
            clean_run_residuals: clean_residuals,
            claim_on_defect,
            claim_on_clean,
            replays_ok,
            challenge_ok,
            challenge_axes,
            minimization,
            evidence_bytes,
        });

        // The challenge's stderr is narration; the verdict is recorded in
        // the challenge records and the exit status (a blind or conflating
        // court refuses).
        if !challenge_ok {
            eprintln!("challenge {id}: {}", challenge_err.trim());
        }
    }

    // -- metrics -------------------------------------------------------------
    let total = observed.len();
    let detected: Vec<&Observed> = observed
        .iter()
        .filter(|o| !o.residual_axes.is_empty())
        .collect();
    let undetected: Vec<&Observed> = observed
        .iter()
        .filter(|o| o.residual_axes.is_empty())
        .collect();
    let false_positives: Vec<&Observed> = observed
        .iter()
        .filter(|o| o.clean_run_residuals > 0)
        .collect();

    // Claim inflation: on a defect run, a compiled claim must never cover the
    // defect's axis. The defect axis = the observed residual axes.
    let mut inflated: Vec<String> = Vec::new();
    let mut defect_claims: Vec<String> = Vec::new();
    for o in &observed {
        if let Some((compiled, scope)) = &o.claim_on_defect {
            if *compiled {
                defect_claims.push(o.id.clone());
                if scope.iter().any(|a| o.residual_axes.contains(a)) {
                    inflated.push(o.id.clone());
                }
            }
        }
    }
    let clean_claims: Vec<&Observed> = observed
        .iter()
        .filter(|o| o.claim_on_clean.as_ref().map(|(c, _)| *c).unwrap_or(false))
        .collect();
    let scope_misses: Vec<String> = observed
        .iter()
        .filter(|o| {
            let Some((compiled, scope)) = &o.claim_on_clean else {
                return false;
            };
            !*compiled || o.challenge_axes.iter().any(|a| !scope.contains(a))
        })
        .map(|o| format!("{} lacks full clean-axis claim coverage", o.id))
        .collect();

    let replays_total = total as u32 * 3;
    let replays_ok: u32 = observed.iter().map(|o| o.replays_ok).sum();
    let insensitive: Vec<String> = observed
        .iter()
        .filter(|o| !o.challenge_ok)
        .map(|o| o.id.clone())
        .collect();

    let frf_bytes: u64 = observed.iter().map(|o| o.evidence_bytes).sum();
    let baseline_bytes = (total * 2) as u64 * 24; // defect + clean pass/fail lines
    let per_case_bytes: BTreeMap<String, u64> = observed
        .iter()
        .map(|o| (o.id.clone(), o.evidence_bytes))
        .collect();

    let cases_report: Vec<Value> = observed
        .iter()
        .map(|o| {
            json!({
                "id": o.id,
                "name": o.name,
                "domain": o.domain,
                "defect_run": o.defect_run,
                "residual_axes": o.residual_axes,
                "residual_surfaces": o.residual_surfaces,
                "clean_run_residuals": o.clean_run_residuals,
                "claim_on_defect": o.claim_on_defect,
                "claim_on_clean": o.claim_on_clean,
                "challenge_passed": o.challenge_ok,
                "replays_ok": o.replays_ok,
                "minimization": o.minimization,
                "evidence_bytes": o.evidence_bytes,
            })
        })
        .collect();

    let report = json!({
        "schema_version": "frf-external-experiment-v1",
        "corpus": {
            "cases": total,
            "domains": ["cli", "wire", "state"],
        },
        "defect_discovery": {
            "historical_defects": total,
            "detected": detected.len(),
            "rate": if total == 0 { 0.0 } else { detected.len() as f64 / total as f64 },
            "undetected": undetected.iter().map(|o| o.id.clone()).collect::<Vec<_>>(),
        },
        "specificity": {
            "clean_runs": total,
            "false_positives": false_positives.len(),
            "rate": if total == 0 { 0.0 } else { (total - false_positives.len()) as f64 / total as f64 },
            "false_positive_cases": false_positives.iter().map(|o| o.id.clone()).collect::<Vec<_>>(),
        },
        "claims": {
            "defect_runs": total,
            "claims_compiled_scoped_to_clean_axes": defect_claims.len(),
            "inflated": inflated.len(),
            "inflated_cases": inflated,
            "clean_runs": total,
            "compiled_on_clean": clean_claims.len(),
            "scope_coverage_misses": scope_misses,
        },
        "challenge": {
            "courts_challenged": total,
            "sensitivity_proven": total - insensitive.len(),
            "insensitive": insensitive,
        },
        "minimization": observed
            .iter()
            .filter_map(|o| {
                o.minimization.as_ref().map(|m| {
                    let mut entry = m.as_object().cloned().unwrap_or_default();
                    entry.insert("case".to_string(), Value::String(o.id.clone()));
                    Value::Object(entry)
                })
            })
            .collect::<Vec<_>>(),
        "replay": {
            "attempts": replays_total,
            "reproduced": replays_ok,
            "stability": if replays_total == 0 { 0.0 } else { replays_ok as f64 / replays_total as f64 },
        },
        "evidence_overhead": {
            "frf_bytes": frf_bytes,
            "baseline_bytes": baseline_bytes,
            "ratio": if baseline_bytes == 0 { 0.0 } else { frf_bytes as f64 / baseline_bytes as f64 },
            "per_case_bytes": per_case_bytes,
        },
        "cases": cases_report,
    });

    std::fs::write(out_path, serde_json::to_string_pretty(&report).unwrap()).unwrap();

    // -- the printed summary -------------------------------------------------
    println!("FRF external empirical program — real historical defects");
    println!(
        "  corpus: {} historical defect(s) across cli/wire/state",
        total
    );
    for o in &observed {
        println!(
            "  {} ({}): {} — detected via [{}] on {}, clean control {} residual(s), replay {}/3, challenge {}",
            o.id,
            o.domain,
            o.name,
            o.residual_axes.join(", "),
            o.defect_run,
            o.clean_run_residuals,
            o.replays_ok,
            if o.challenge_ok { "sensitivity proven" } else { "INSENSITIVE" },
        );
        if let Some(m) = &o.minimization {
            if let Some(refused) = m.get("refused") {
                println!("      minimization: refused ({refused})");
            } else {
                println!(
                    "      minimization: {} attempt(s), {} -> {} lines (minimality {}/{}, proven {})",
                    m["attempts"], m["original_lines"], m["final_lines"],
                    m["minimality"]["kind"], m["minimality"]["granularity"], m["minimality"]["proven"]
                );
            }
        }
    }
    println!(
        "  defect discovery: {}/{} detected ({:.0}%)",
        detected.len(),
        total,
        detected.len() as f64 / total as f64 * 100.0
    );
    println!(
        "  specificity: {} clean control(s), {} false positive(s)",
        total,
        false_positives.len()
    );
    println!(
        "  claims: {} compiled on defect run(s) (never covering the defect axis), {} inflated; {} compiled on clean run(s)",
        defect_claims.len(),
        inflated.len(),
        clean_claims.len()
    );
    println!(
        "  challenge: {}/{} courts demonstrated sensitivity to their defect class",
        total - insensitive.len(),
        total
    );
    println!(
        "  replay stability: {}/{} reproduced ({:.0}%)",
        replays_ok,
        replays_total,
        replays_ok as f64 / replays_total as f64 * 100.0
    );
    println!(
        "  evidence overhead: {} FRF bytes vs {} baseline bytes (ratio {:.1}x)",
        frf_bytes,
        baseline_bytes,
        frf_bytes as f64 / baseline_bytes as f64
    );
    println!("report: {}", out_path.display());

    if check {
        let mut failures: Vec<String> = Vec::new();
        if !undetected.is_empty() {
            failures.push(format!(
                "undetected historical defects: {}",
                undetected
                    .iter()
                    .map(|o| o.id.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if !false_positives.is_empty() {
            failures.push(format!(
                "false positives: {}",
                false_positives
                    .iter()
                    .map(|o| o.id.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if !inflated.is_empty() {
            failures.push(format!(
                "claim inflation (a claim covered a defect axis): {}",
                inflated.join(", ")
            ));
        }
        if clean_claims.len() != total {
            failures.push(format!(
                "clean claims compiled: {}/{}",
                clean_claims.len(),
                total
            ));
        }
        if !scope_misses.is_empty() {
            failures.push(format!("claim scope misses: {}", scope_misses.join(", ")));
        }
        if !insensitive.is_empty() {
            failures.push(format!(
                "courts that did not demonstrate sensitivity: {}",
                insensitive.join(", ")
            ));
        }
        if replays_ok != replays_total {
            failures.push(format!("replay stability: {replays_ok}/{replays_total}"));
        }
        if !failures.is_empty() {
            panic!(
                "external experiment CHECK FAILED:\n  {}",
                failures.join("\n  ")
            );
        }
    }
}
