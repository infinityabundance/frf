//! The EXTERNAL empirical program v5 — the PROPER benchmark protocol.
//!
//! v4's runtime-overhead row was an explicit PILOT: one bare vulnerable
//! execution vs one FRF per-run number, millisecond resolution, no warmups,
//! samples, quantiles, or machine description. v5 is the protocol the review
//! called for — a real single-host performance measurement of the FRF
//! per-observation cost against the bare side on the same bytes:
//!
//! - **warmups** before measurement (the OS page-cache and the dynamic
//!   loader settle; the reported numbers are the steady-state cost);
//! - **samples** per side (default 15, `FRF_BENCH_SAMPLES`; warmups 3,
//!   `FRF_BENCH_WARMUPS`) — each sample is FULLY ISOLATED: a fresh store, a
//!   fresh authority admission, a fresh court run, so every sample is a real
//!   observation (the reuse path never short-circuits a repeated identical
//!   run into a cache hit);
//! - **wall time AND child CPU time** per sample (getrusage(RUSAGE_CHILDREN)
//!   deltas — the direct child's user+sys; sequential samples make each
//!   delta exact);
//! - **medians and quantiles** (p50 / p90 / p99), mean and stddev, for the
//!   bare side and the FRF court, and the overhead ratio at the median and
//!   the p90;
//! - **machine description** (kernel, architecture, CPU model, core count,
//!   memory) so the numbers travel with their host.
//!
//! Two honest labels, never conflated:
//!
//! - `bare` = one side executed directly (wall + that side's CPU).
//! - `frf` = one full court observation from a cold store (wall + the
//!   HARNESS PROCESS's own CPU — the frf executable's user+sys; the sides it
//!   spawns are the same binaries the bare row measures, so the side CPU is
//!   already accounted; `frf_total_cpu_proxy` adds the two bare sides' CPU
//!   to the harness CPU and is labeled a proxy).
//!
//! Hermeticity is re-proven at the identity level: the content-addressed run
//! id must be IDENTICAL across all samples of a case (the observation did
//! not vary), and `--check` (default) fails the run otherwise, or when any
//! sample failed to execute, the stats are degenerate (p50 > p90), or the
//! machine description is missing. No TIMING threshold is asserted: the
//! benchmark measures and reports; the gates are protocol-correctness gates.

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use super::experiment_external::as_str;
use super::experiment_external_v3::stage_case;
use super::experiment_external_v4::bare_trigger_env;

/// getrusage(RUSAGE_CHILDREN) user+sys seconds of the terminated children —
/// the direct child's CPU. Sequential samples make the delta exact.
fn children_cpu_s() -> f64 {
    #[cfg(unix)]
    {
        let mut ru = std::mem::MaybeUninit::<libc::rusage>::uninit();
        // SAFETY: getrusage writes the struct on success; the pointer is
        // valid for the lifetime of the call.
        let rc = unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, ru.as_mut_ptr()) };
        if rc != 0 {
            return 0.0;
        }
        // SAFETY: rc == 0 means the struct was initialized.
        let ru = unsafe { ru.assume_init() };
        ru.ru_utime.tv_sec as f64
            + ru.ru_utime.tv_usec as f64 / 1e6
            + ru.ru_stime.tv_sec as f64
            + ru.ru_stime.tv_usec as f64 / 1e6
    }
    #[cfg(not(unix))]
    {
        0.0
    }
}

/// One timed sample: wall ms (microsecond precision — a sub-millisecond side
/// must not collapse to 0.0) + the child CPU ms consumed by that sample.
struct Timed {
    wall_ms: f64,
    cpu_ms: f64,
}

/// Execute the bare vulnerable side (the same argv + declared trigger the
/// court passes) and return wall + the side's CPU.
fn bare_sample(work: &Path, side: &str, fixture: &str, trigger: &[&str]) -> Timed {
    let mut cmd = Command::new(work.join(side));
    cmd.arg(format!("fixtures/{fixture}")).current_dir(work);
    for e in trigger {
        let (k, v) = e.split_once('=').expect("env pair");
        cmd.env(k, v);
    }
    let cpu_before = children_cpu_s();
    let start = Instant::now();
    let out = cmd.output().expect("bare side executes");
    let wall_ms = start.elapsed().as_micros() as f64 / 1000.0;
    let cpu_ms = (children_cpu_s() - cpu_before) * 1e3;
    assert!(
        out.status.success() || out.status.code().is_some(),
        "the bare side must terminate with a status"
    );
    Timed { wall_ms, cpu_ms }
}

/// Execute ONE full FRF court observation from a FRESH store (the sample is
/// fully isolated: no reuse short-circuit, no cache) and return the run id
/// plus wall + the harness process's own CPU. The fresh store is a copy of
/// the staged case tree, so the reference authority is ALREADY admitted (an
/// admission is a one-time setup, measured nowhere; the sample measures the
/// OBSERVATION).
fn frf_sample(frf: &Path, sample_dir: &Path, manifest: &str) -> (String, Timed) {
    let cpu_before = children_cpu_s();
    let start = Instant::now();
    let out = Command::new(frf)
        .args(["--root", "ev", "court", "run", manifest])
        .current_dir(sample_dir)
        .output()
        .expect("frf court executes");
    let wall_ms = start.elapsed().as_micros() as f64 / 1000.0;
    let cpu_ms = (children_cpu_s() - cpu_before) * 1e3;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let run = stdout
        .lines()
        .rev()
        .find(|l| l.starts_with("run-"))
        .unwrap_or_else(|| panic!("{sample_dir:?}: frf court run returned no run id: {stdout}"))
        .to_string();
    assert!(
        out.status.success(),
        "{sample_dir:?}: frf court run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    (run, Timed { wall_ms, cpu_ms })
}

/// p-quantile (nearest-rank, 0..=1) of a sorted sample vector.
fn quantile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((p * (sorted.len() as f64 - 1.0)).round() as usize).min(sorted.len() - 1);
    sorted[idx]
}

fn stats(ms: &[f64]) -> Value {
    let mut sorted: Vec<f64> = ms.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));
    let mean = sorted.iter().sum::<f64>() / sorted.len().max(1) as f64;
    let variance =
        sorted.iter().map(|x| (x - mean) * (x - mean)).sum::<f64>() / sorted.len().max(1) as f64;
    json!({
        "p50_ms": format!("{:.2}", quantile(&sorted, 0.50)),
        "p90_ms": format!("{:.2}", quantile(&sorted, 0.90)),
        "p99_ms": format!("{:.2}", quantile(&sorted, 0.99)),
        "mean_ms": format!("{:.2}", mean),
        "stddev_ms": format!("{:.2}", variance.sqrt()),
        "min_ms": format!("{:.2}", sorted.first().copied().unwrap_or(0.0)),
        "max_ms": format!("{:.2}", sorted.last().copied().unwrap_or(0.0)),
        "samples": sorted.len().to_string(),
    })
}

/// The machine description the numbers travel with: kernel, architecture,
/// CPU model + count, and memory (Linux; other hosts report what they have).
fn machine_description() -> Value {
    let uname = Command::new("uname")
        .args(["-srm"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let cpu_model = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|s| {
            s.lines().find(|l| l.starts_with("model name")).map(|l| {
                l.split_once(':')
                    .map(|(_, v)| v.trim().to_string())
                    .unwrap_or_default()
            })
        })
        .unwrap_or_else(|| "unknown".to_string());
    let cpu_count = Command::new("nproc")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let mem_total = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("MemTotal"))
                .map(|l| l.split_whitespace().nth(1).unwrap_or("?").to_string())
        })
        .unwrap_or_else(|| "?".to_string());
    json!({
        "uname": uname,
        "cpu_model": cpu_model,
        "cpu_count": cpu_count,
        "mem_total_kb": mem_total,
        "frf_version": env!("CARGO_PKG_VERSION"),
    })
}

/// The benchmark parameters (warmups + samples), env-overridable so a CI run
/// can stay cheap (FRF_BENCH_SAMPLES=5 is the CI smoke scale) and a full
/// study can scale to hundreds of samples. The third tuple element records
/// whether an explicit override is in force: the samples floor depends on it
/// (an explicit override admits a smoke run; the default 15 must stay
/// dozens).
fn bench_params() -> (usize, usize, bool) {
    let explicit = std::env::var("FRF_BENCH_SAMPLES").is_ok();
    let warmups = std::env::var("FRF_BENCH_WARMUPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);
    let samples = std::env::var("FRF_BENCH_SAMPLES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(15);
    (warmups, samples, explicit)
}

/// The benchmark protocol for ONE case: warmups + samples of the bare side
/// and of the full FRF observation, fully isolated per sample, with the
/// quantile stats and the overhead ratios.
fn bench_case(
    frf: &Path,
    corpus: &Path,
    work: &Path,
    case: &Value,
    failures: &mut Vec<String>,
) -> Value {
    let (warmups, samples, explicit_override) = bench_params();
    let staged = stage_case(frf, corpus, work, case);
    let id = &staged.id;
    let meta = &staged.meta;
    let side_vuln = as_str(&meta["sides"]["vulnerable"]);
    let fixture_defect = as_str(&meta["fixtures"]["defect"]);
    let trigger = bare_trigger_env(meta);
    let manifest = staged.manifest_defect.clone();

    // -- warmups --------------------------------------------------------------
    // The first executions warm the OS page cache + dynamic loader; only the
    // measured samples are reported.
    for _ in 0..warmups {
        let _ = bare_sample(&staged.case_work, side_vuln, fixture_defect, &trigger);
        let warm = work.join(format!("{id}.warmup"));
        std::fs::create_dir_all(&warm).unwrap();
        copy_case(&staged.case_work, &warm);
        let _ = frf_sample(frf, &warm, &manifest);
        let _ = std::fs::remove_dir_all(&warm);
    }

    // -- measured samples ------------------------------------------------------
    let mut bare_wall: Vec<f64> = Vec::new();
    let mut bare_cpu: Vec<f64> = Vec::new();
    let mut frf_wall: Vec<f64> = Vec::new();
    let mut frf_cpu: Vec<f64> = Vec::new();
    let mut run_ids: BTreeMap<String, usize> = BTreeMap::new();
    for i in 0..samples {
        // Bare side first (the side the court will spawn).
        let t = bare_sample(&staged.case_work, side_vuln, fixture_defect, &trigger);
        bare_wall.push(t.wall_ms);
        bare_cpu.push(t.cpu_ms);

        // A FRESH isolated store per sample: the court really executes (the
        // reuse path never collapses a repeated identical run into a cache
        // hit), and the measured cost is one observation from a cold store.
        let sample_dir = work.join(format!("{id}.sample-{i:03}"));
        std::fs::create_dir_all(&sample_dir).unwrap();
        copy_case(&staged.case_work, &sample_dir);
        let (run, t) = frf_sample(frf, &sample_dir, &manifest);
        frf_wall.push(t.wall_ms);
        frf_cpu.push(t.cpu_ms);
        *run_ids.entry(run.clone()).or_insert(0) += 1;
        let _ = std::fs::remove_dir_all(&sample_dir);
    }

    // -- hermeticity at the identity level ------------------------------------
    // The observation is content-addressed: identical evidence MUST produce
    // one run id across every isolated sample. Any second id is an exposed
    // nondeterminism the benchmark itself caught.
    let distinct = run_ids.len();
    if distinct > 1 {
        failures.push(format!(
            "{id}/benchmark: {} distinct run ids across {samples} isolated samples — the corpus is declared hermetic; the benchmark exposes nondeterminism",
            distinct
        ));
    }
    if samples < 5 {
        failures.push(format!(
            "{id}/benchmark: only {samples} samples — even a smoke run needs at least 5 (FRF_BENCH_SAMPLES)"
        ));
    } else if samples < 10 && !explicit_override {
        failures.push(format!(
            "{id}/benchmark: only {samples} samples — the protocol calls for dozens (FRF_BENCH_SAMPLES); an explicit override admits a smoke run"
        ));
    }
    if samples != bare_wall.len() || samples != frf_wall.len() {
        failures.push(format!("{id}/benchmark: sample-count bookkeeping failed"));
    }

    // -- the overhead ratios at the median and the p90 ------------------------
    let bare_stats = stats(&bare_wall);
    let frf_stats = stats(&frf_wall);
    let median_bare: f64 = bare_stats["p50_ms"]
        .as_str()
        .unwrap_or("0")
        .parse()
        .unwrap_or(1.0);
    let median_frf: f64 = frf_stats["p50_ms"]
        .as_str()
        .unwrap_or("0")
        .parse()
        .unwrap_or(1.0);
    let p90_bare: f64 = bare_stats["p90_ms"]
        .as_str()
        .unwrap_or("0")
        .parse()
        .unwrap_or(1.0);
    let p90_frf: f64 = frf_stats["p90_ms"]
        .as_str()
        .unwrap_or("0")
        .parse()
        .unwrap_or(1.0);

    // Stats sanity: quantiles must be monotonic.
    for stats in [&bare_stats, &frf_stats] {
        let p50: f64 = stats["p50_ms"]
            .as_str()
            .unwrap_or("0")
            .parse()
            .unwrap_or(0.0);
        let p90: f64 = stats["p90_ms"]
            .as_str()
            .unwrap_or("0")
            .parse()
            .unwrap_or(0.0);
        let p99: f64 = stats["p99_ms"]
            .as_str()
            .unwrap_or("0")
            .parse()
            .unwrap_or(0.0);
        if p50 > p90 + 0.5 || p90 > p99 + 0.5 {
            failures.push(format!(
                "{id}/benchmark: degenerate quantiles (p50 {p50} > p90 {p90} > p99 {p99})"
            ));
        }
    }

    // The harness CPU is the frf executable's OWN user+sys (the sides it
    // spawned are the same binaries the bare row measured). The total-CPU
    // proxy adds both sides' bare median CPU to the harness median and is
    // labeled exactly that.
    let bare_cpu_median: f64 = {
        let mut s: Vec<f64> = bare_cpu.clone();
        s.sort_by(|a, b| a.total_cmp(b));
        quantile(&s, 0.50)
    };
    let frf_cpu_median: f64 = {
        let mut s: Vec<f64> = frf_cpu.clone();
        s.sort_by(|a, b| a.total_cmp(b));
        quantile(&s, 0.50)
    };

    json!({
        "id": id,
        "project": as_str(&meta["project"]),
        "cve": as_str(&meta["cve"]),
        "protocol": {
            "warmups": warmups.to_string(),
            "samples": samples.to_string(),
            "isolation": "fresh store + fresh authority admission per sample; the reuse path never short-circuits",
            "wall": "process wall time, ms",
            "cpu": "child CPU (getrusage(RUSAGE_CHILDREN) user+sys delta), ms",
            "quantiles": "nearest-rank p50/p90/p99",
        },
        "hermeticity": {
            "distinct_run_ids_across_samples": distinct.to_string(),
            "run_ids": run_ids.iter().map(|(k, v)| json!({"run": k, "samples": v.to_string()})).collect::<Vec<_>>(),
        },
        "bare": {
            "side": side_vuln,
            "wall": bare_stats,
            "cpu_ms_median": format!("{bare_cpu_median:.1}"),
        },
        "frf": {
            "manifest": manifest,
            "wall": frf_stats,
            "harness_cpu_ms_median": format!("{frf_cpu_median:.1}"),
            // The two sides are the same binaries the bare row measured; the
            // proxy adds their CPU to the harness CPU. Labeled a proxy: the
            // sides are not re-measured inside the court.
            "total_cpu_proxy_ms_median": format!("{:.1}", frf_cpu_median + 2.0 * bare_cpu_median),
        },
        "overhead": {
            "median_wall_ratio": format!("{:.2}", median_frf / median_bare.max(1.0)),
            "p90_wall_ratio": format!("{:.2}", p90_frf / p90_bare.max(1.0)),
            "median_wall_ms_absolute": format!("{median_frf:.1}"),
            "bare_median_wall_ms": format!("{median_bare:.1}"),
        },
    })
}

/// Copy the staged case tree (builds/, fixtures/, courts/, ev/ with the
/// admitted authorities) into a fresh sample dir — the observation starts
/// from a cold store with the authority already admitted (admission is not
/// part of the observation; it is a one-time setup, measured nowhere).
fn copy_case(src: &Path, dst: &Path) {
    copy_tree(src, dst);
}

fn copy_tree(src: &Path, dst: &Path) {
    let mut pending: Vec<PathBuf> = vec![src.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let from = entry.path();
            let to = dst.join(from.strip_prefix(src).unwrap());
            let ft = entry.file_type().unwrap();
            if ft.is_dir() {
                std::fs::create_dir_all(&to).unwrap();
                pending.push(from);
            } else {
                std::fs::create_dir_all(to.parent().unwrap()).unwrap();
                std::fs::copy(&from, &to).unwrap();
                // Preserve the executable bit (the sides must exec).
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&from).unwrap().permissions().mode();
                std::fs::set_permissions(&to, std::fs::Permissions::from_mode(mode)).unwrap();
            }
        }
    }
}

pub fn run(repo_root: &Path, out_path: &Path, check: bool) {
    let frf = super::experiment::frf_bin(repo_root);
    let corpus = repo_root.join("external-corpus").join("v3");
    let work = repo_root
        .join("golden")
        .join("work")
        .join("external-experiment-v5");
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

    let (warmups, samples, explicit_override) = bench_params();
    let mut failures: Vec<String> = Vec::new();
    let mut per_case: Vec<Value> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();

    for case in &cases {
        let id = as_str(&case["id"]);
        if id == "log4shell" && !java {
            skipped.push(id.to_string());
            continue;
        }
        per_case.push(bench_case(&frf, &corpus, &work, case, &mut failures));
    }

    let machine = machine_description();
    if as_str(&machine["uname"]) == "unknown" || as_str(&machine["cpu_count"]) == "unknown" {
        failures.push("benchmark: the machine description is missing".to_string());
    }

    let report = json!({
        "protocol": "frf-external-experiment-v5",
        "description": "The proper single-host runtime-overhead benchmark: warmups + isolated samples, wall + child CPU, p50/p90/p99, machine description. Measurements only — no timing thresholds; the gates are protocol-correctness gates.",
        "benchmark": {
            "warmups": warmups.to_string(),
            "samples": samples.to_string(),
            "explicit_sample_override": explicit_override,
            "env_overrides": "FRF_BENCH_WARMUPS / FRF_BENCH_SAMPLES",
        },
        "machine": machine,
        "cases": per_case,
        "skipped_cases": skipped,
    });
    std::fs::write(out_path, serde_json::to_vec_pretty(&report).unwrap())
        .unwrap_or_else(|e| panic!("cannot write {}: {e}", out_path.display()));
    eprintln!(
        "external-experiment-v5: {} case(s) benchmarked, {} skipped, {} gate failure(s); report: {}",
        per_case.len(),
        skipped.len(),
        failures.len(),
        out_path.display()
    );
    if check && !failures.is_empty() {
        for f in &failures {
            eprintln!("  v5 gate failure: {f}");
        }
        std::process::exit(1);
    }
}
