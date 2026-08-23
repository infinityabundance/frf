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
//! - **samples** per case (default 30, `FRF_BENCH_SAMPLES`; warmups 3,
//!   `FRF_BENCH_WARMUPS`);
//! - **three measurements per sample, apples-to-apples** (0.1.63):
//!   - `bare_candidate` — one execution of the vulnerable side (the defect
//!     observation the court must reproduce);
//!   - `bare_pair` — the reference side + the candidate side executed
//!     sequentially (what the court's two sides cost bare);
//!   - `frf_court` — one full court observation from a PREPARED fresh store
//!     (the authority is pre-admitted; admission is a one-time setup,
//!     deliberately excluded from the observation timing — the definition
//!     says exactly that);
//!   - the sample ORDER is COUNTERBALANCED deterministically (a cyclic
//!     rotation of the three measurements per sample index) so no
//!     measurement always runs first or last;
//! - **wall time AND CPU, separated** (0.1.63): the FRF process itself
//!   reports its OWN CPU (RUSAGE_SELF, `FRF_PRINT_SELF_CPU=1` — the harness
//!   executable's user+sys, excluding the sides it spawned); the sides' CPU
//!   is accounted independently from the bare measurements; the aggregate
//!   court CPU is reported separately and labeled a proxy;
//! - **quantiles** (p50 / p90 / p99), mean and stddev, for all three
//!   measurements, plus the PAIRED framework-overhead distribution
//!   (frf_court − bare_pair on the same sample);
//! - **the overhead decomposition**: user-visible amplification
//!   (frf / bare_candidate — "what does using FRF cost vs just running the
//!   program?") is reported SEPARATELY from the framework overhead
//!   (frf − bare_pair — "how much is evidence construction, hashing,
//!   sealing, capture, comparison, storage, beyond the two executions?") and
//!   the framework ratio (frf / bare_pair);
//! - **machine description** (kernel, architecture, CPU model, core count,
//!   memory) so the numbers travel with their host.
//!
//! Hermeticity is re-proven at the identity level and REPORTED AT BOTH
//! LAYERS (0.1.63): `distinct_observation_identities` (behavioral
//! determinism — what was observed) and `distinct_execution_identities`
//! (machinery/provenance stability — under exactly what contract it was
//! observed) are counted separately, alongside the run ids. `--check`
//! (default) fails the run when any sample failed to execute, the identity
//! counts are not both 1, the stats are degenerate (p50 > p90), or the
//! machine description is missing. No TIMING threshold is asserted: the
//! benchmark measures and reports; the gates are protocol-correctness gates.
//!
//! Quantile convention (documented, not assumed): nearest-index empirical
//! quantile `round(p · (n−1))` over the sorted sample — at n=15, p99 is
//! effectively the maximum, which is why the default is 30 samples.

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use super::experiment_external::as_str;
use super::experiment_external_v3::stage_case;
use super::experiment_external_v4::bare_trigger_env;

/// getrusage(RUSAGE_CHILDREN) user+sys seconds of the terminated children.
/// Used ONLY for the bare measurements, where the only waited-for children
/// ARE the side(s) themselves, so the delta is exactly the side(s)' CPU.
/// It is deliberately NOT used around the frf court child: that delta would
/// also contain the court sides' CPU (the frf process waits for them) and
/// double-count them against the bare rows. The court row's harness CPU
/// comes from the frf process's own RUSAGE_SELF report instead.
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
/// must not collapse to 0.0) + the CPU ms attributable to that measurement.
/// For the bare rows that is the side(s)' CPU (RUSAGE_CHILDREN delta — the
/// only waited-for children are the sides); for the court row it is the
/// harness process's OWN CPU (the frf process's RUSAGE_SELF report), NOT the
/// caller's RUSAGE_CHILDREN (which would include the court sides and
/// double-count them against the bare rows).
struct Timed {
    wall_ms: f64,
    cpu_ms: f64,
}

/// A bare side invocation: the same argv + declared trigger the court passes.
fn bare_cmd(work: &Path, side: &str, fixture: &str, trigger: &[&str]) -> Command {
    let mut cmd = Command::new(work.join(side));
    cmd.arg(format!("fixtures/{fixture}")).current_dir(work);
    for e in trigger {
        let (k, v) = e.split_once('=').expect("env pair");
        cmd.env(k, v);
    }
    cmd
}

/// Execute the bare vulnerable side alone (the defect observation the court
/// must reproduce) and return wall + the side's own CPU.
fn bare_sample(work: &Path, side: &str, fixture: &str, trigger: &[&str]) -> Timed {
    let cpu_before = children_cpu_s();
    let start = Instant::now();
    let out = bare_cmd(work, side, fixture, trigger)
        .output()
        .expect("bare side executes");
    let wall_ms = start.elapsed().as_micros() as f64 / 1000.0;
    let cpu_ms = (children_cpu_s() - cpu_before) * 1e3;
    assert!(
        out.status.success() || out.status.code().is_some(),
        "the bare side must terminate with a status"
    );
    Timed { wall_ms, cpu_ms }
}

/// Execute the reference side + the candidate side SEQUENTIALLY, both bare —
/// the two executions the court itself performs — and return wall + the two
/// sides' combined CPU. This is the honest denominator for the framework
/// overhead: the court's cost above and beyond "you asked for two
/// executions".
fn bare_pair_sample(
    work: &Path,
    reference: &str,
    candidate: &str,
    fixture: &str,
    trigger: &[&str],
) -> Timed {
    let cpu_before = children_cpu_s();
    let start = Instant::now();
    let first = bare_cmd(work, reference, fixture, trigger)
        .output()
        .expect("bare reference side executes");
    let second = bare_cmd(work, candidate, fixture, trigger)
        .output()
        .expect("bare candidate side executes");
    let wall_ms = start.elapsed().as_micros() as f64 / 1000.0;
    let cpu_ms = (children_cpu_s() - cpu_before) * 1e3;
    assert!(
        first.status.success() || first.status.code().is_some(),
        "the bare reference side must terminate with a status"
    );
    assert!(
        second.status.success() || second.status.code().is_some(),
        "the bare candidate side must terminate with a status"
    );
    Timed { wall_ms, cpu_ms }
}

/// One full FRF court observation from a FRESH PREPARED store (a copy of the
/// staged case tree — the reference authority is ALREADY admitted; admission
/// is a one-time setup, deliberately excluded from the observation timing)
/// plus the three identities the observation committed (run, observation,
/// execution) and wall + the HARNESS process's OWN CPU.
///
/// Harness CPU is the frf process's RUSAGE_SELF (user+sys of the frf
/// executable itself, excluding the sides it spawned), printed by the frf
/// process under FRF_PRINT_SELF_CPU=1 and parsed here — NOT the caller's
/// RUSAGE_CHILDREN delta, which would also contain the court sides' CPU and
/// double-count them.
struct CourtSample {
    run: String,
    observation_identity: String,
    execution_identity: String,
    wall_ms: f64,
    harness_cpu_ms: f64,
}

fn frf_sample(frf: &Path, sample_dir: &Path, manifest: &str) -> CourtSample {
    let start = Instant::now();
    let out = Command::new(frf)
        .args(["--root", "ev", "court", "run", manifest])
        .current_dir(sample_dir)
        .env("FRF_PRINT_SELF_CPU", "1")
        .output()
        .expect("frf court executes");
    assert!(
        out.status.success(),
        "{sample_dir:?}: frf court run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let wall_ms = start.elapsed().as_micros() as f64 / 1000.0;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let run = stdout
        .lines()
        .rev()
        .find(|l| l.starts_with("run-"))
        .unwrap_or_else(|| panic!("{sample_dir:?}: frf court run returned no run id: {stdout}"))
        .to_string();
    let harness_cpu_ms = stdout
        .lines()
        .rev()
        .find(|l| l.starts_with("frf-self-cpu-ms:"))
        .and_then(|l| {
            l.split_once(':')
                .and_then(|(_, v)| v.trim().parse::<f64>().ok())
        })
        .unwrap_or_else(|| {
            panic!(
                "{sample_dir:?}: frf court run did not report its own CPU (frf-self-cpu-ms) — \
                 the benchmark requires FRF_PRINT_SELF_CPU=1 support in the frf binary: {stdout}"
            )
        });
    // The observation committed both identity layers; the benchmark reads them
    // back and reports behavioral determinism and machinery/provenance
    // stability SEPARATELY instead of collapsing both into one run-id count.
    let capture = crate::load_json(
        &sample_dir
            .join("ev/captures")
            .join(&run)
            .join("capture.json"),
    );
    CourtSample {
        run,
        observation_identity: as_str(&capture["observation_identity"]).to_string(),
        execution_identity: as_str(&capture["execution_identity"]).to_string(),
        wall_ms,
        harness_cpu_ms,
    }
}

/// p-quantile of a SORTED sample vector, 0..=1. Convention: nearest-index
/// empirical quantile `round(p · (n−1))` (NOT nearest-rank) — documented, not
/// assumed. At n=15, p99 is effectively the maximum; the protocol calls for
/// samples in the dozens.
fn quantile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((p * (sorted.len() as f64 - 1.0)).round() as usize).min(sorted.len() - 1);
    sorted[idx]
}

/// p-quantile of an unsorted sample vector (sorts a copy).
fn quantile_of(ms: &[f64], p: f64) -> f64 {
    let mut sorted: Vec<f64> = ms.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));
    quantile(&sorted, p)
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
/// (an explicit override admits a smoke run; the default 30 is what numbers
/// meant for serious comparison call for — at n=15, p99 is just the max).
fn bench_params() -> (usize, usize, bool) {
    let explicit = std::env::var("FRF_BENCH_SAMPLES").is_ok();
    let warmups = std::env::var("FRF_BENCH_WARMUPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);
    let samples = std::env::var("FRF_BENCH_SAMPLES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);
    (warmups, samples, explicit)
}

/// The three measurements of one sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Measure {
    /// The vulnerable side alone (the defect observation the court reproduces).
    BareCandidate,
    /// The reference side + the candidate side, both bare, sequentially — the
    /// two executions the court itself performs.
    BarePair,
    /// One full court observation from a prepared fresh store.
    FrfCourt,
}

/// Deterministic counterbalance: a cyclic rotation of the three measurements
/// per sample index, so no measurement always runs first or last. Warmups do
/// not remove ordered-pair bias — page cache, filesystem metadata, CPU
/// frequency state, loader state and other machine effects are systematically
/// asymmetric between first and later positions.
fn sample_order(i: usize) -> [Measure; 3] {
    match i % 3 {
        0 => [Measure::BareCandidate, Measure::BarePair, Measure::FrfCourt],
        1 => [Measure::BarePair, Measure::FrfCourt, Measure::BareCandidate],
        _ => [Measure::FrfCourt, Measure::BareCandidate, Measure::BarePair],
    }
}

/// The benchmark protocol for ONE case: warmups + samples of the three
/// measurements (bare_candidate, bare_pair, frf_court), fully isolated per
/// sample, counterbalanced, with the quantile stats, the paired framework
/// overhead, and the overhead decomposition.
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
    let side_fixed = as_str(&meta["sides"]["fixed"]);
    let fixture_defect = as_str(&meta["fixtures"]["defect"]);
    let trigger = bare_trigger_env(meta);
    let manifest = staged.manifest_defect.clone();

    // -- warmups --------------------------------------------------------------
    // The first executions warm the OS page cache + dynamic loader; only the
    // measured samples are reported. ALL THREE measurements are warmed, so no
    // measurement carries a first-touch cost into the samples.
    for _ in 0..warmups {
        let _ = bare_sample(&staged.case_work, side_vuln, fixture_defect, &trigger);
        let _ = bare_pair_sample(
            &staged.case_work,
            side_fixed,
            side_vuln,
            fixture_defect,
            &trigger,
        );
        let warm = work.join(format!("{id}.warmup"));
        std::fs::create_dir_all(&warm).unwrap();
        copy_case(&staged.case_work, &warm);
        let _ = frf_sample(frf, &warm, &manifest);
        let _ = std::fs::remove_dir_all(&warm);
    }

    // -- measured samples ------------------------------------------------------
    // Per sample: a FRESH PREPARED store (a copy of the staged tree — the
    // authority is pre-admitted; admission is a one-time setup, excluded from
    // the observation timing) and the three measurements in a cyclically
    // rotated (counterbalanced) order. Each measurement type gets exactly one
    // entry per sample, so the rows are PAIRED by sample index.
    let mut bare_cand_wall: Vec<f64> = Vec::new();
    let mut bare_cand_cpu: Vec<f64> = Vec::new();
    let mut bare_pair_wall: Vec<f64> = Vec::new();
    let mut bare_pair_cpu: Vec<f64> = Vec::new();
    let mut frf_wall: Vec<f64> = Vec::new();
    let mut frf_harness_cpu: Vec<f64> = Vec::new();
    let mut run_ids: BTreeMap<String, usize> = BTreeMap::new();
    let mut observation_ids: BTreeMap<String, usize> = BTreeMap::new();
    let mut execution_ids: BTreeMap<String, usize> = BTreeMap::new();
    let mut orders: Vec<String> = Vec::new();
    for i in 0..samples {
        let sample_dir = work.join(format!("{id}.sample-{i:03}"));
        std::fs::create_dir_all(&sample_dir).unwrap();
        copy_case(&staged.case_work, &sample_dir);
        let order = sample_order(i);
        orders.push(format!("{:?} + {:?} + {:?}", order[0], order[1], order[2]));
        for m in order {
            match m {
                Measure::BareCandidate => {
                    let t = bare_sample(&staged.case_work, side_vuln, fixture_defect, &trigger);
                    bare_cand_wall.push(t.wall_ms);
                    bare_cand_cpu.push(t.cpu_ms);
                }
                Measure::BarePair => {
                    let t = bare_pair_sample(
                        &staged.case_work,
                        side_fixed,
                        side_vuln,
                        fixture_defect,
                        &trigger,
                    );
                    bare_pair_wall.push(t.wall_ms);
                    bare_pair_cpu.push(t.cpu_ms);
                }
                Measure::FrfCourt => {
                    let s = frf_sample(frf, &sample_dir, &manifest);
                    frf_wall.push(s.wall_ms);
                    frf_harness_cpu.push(s.harness_cpu_ms);
                    *run_ids.entry(s.run).or_insert(0) += 1;
                    *observation_ids.entry(s.observation_identity).or_insert(0) += 1;
                    *execution_ids.entry(s.execution_identity).or_insert(0) += 1;
                }
            }
        }
        let _ = std::fs::remove_dir_all(&sample_dir);
    }

    // -- hermeticity at BOTH identity layers -----------------------------------
    // The observation is content-addressed and the execution contract is
    // committed: identical evidence MUST produce one observation identity
    // (behavioral determinism), one execution identity (machinery/provenance
    // stability), and therefore one run identity across every isolated
    // sample. Any second id at any layer is nondeterminism the benchmark
    // itself caught — reported separately instead of being collapsed into one
    // run-id count.
    let distinct_runs = run_ids.len();
    let distinct_obs = observation_ids.len();
    let distinct_exec = execution_ids.len();
    if distinct_runs > 1 || distinct_obs > 1 || distinct_exec > 1 {
        failures.push(format!(
            "{id}/benchmark: hermeticity violated across {samples} isolated samples — \
             {} distinct run ids, {} distinct observation identities, {} distinct \
             execution identities; the corpus is declared hermetic and the \
             benchmark exposes nondeterminism",
            distinct_runs, distinct_obs, distinct_exec
        ));
    }
    if samples < 5 {
        failures.push(format!(
            "{id}/benchmark: only {samples} samples — even a smoke run needs at least 5 (FRF_BENCH_SAMPLES)"
        ));
    } else if samples < 10 && !explicit_override {
        failures.push(format!(
            "{id}/benchmark: only {samples} samples — the protocol calls for dozens (default 30; FRF_BENCH_SAMPLES); an explicit override admits a smoke run"
        ));
    }
    if samples != bare_cand_wall.len()
        || samples != bare_pair_wall.len()
        || samples != frf_wall.len()
    {
        failures.push(format!("{id}/benchmark: sample-count bookkeeping failed"));
    }

    // -- stats + the PAIRED framework-overhead distribution -------------------
    let bare_cand_stats = stats(&bare_cand_wall);
    let bare_pair_stats = stats(&bare_pair_wall);
    let frf_stats = stats(&frf_wall);
    // Paired by sample index (each sample ran all three measurements): the
    // framework overhead is frf_court − bare_pair on the SAME sample, so
    // machine drift between samples does not inflate the distribution.
    let paired_overhead: Vec<f64> = frf_wall
        .iter()
        .zip(bare_pair_wall.iter())
        .map(|(f, b)| f - b)
        .collect();
    let paired_stats = stats(&paired_overhead);

    // Stats sanity: quantiles must be monotonic.
    for stats in [
        &bare_cand_stats,
        &bare_pair_stats,
        &frf_stats,
        &paired_stats,
    ] {
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

    // -- the overhead decomposition -------------------------------------------
    // user_visible_amplification = frf_court / bare_candidate — "what does
    // using FRF cost vs just running the program?"; framework_overhead =
    // frf_court − bare_pair (paired) — "how much is evidence construction,
    // hashing, sealing, capture, comparison, storage beyond the two
    // executions?"; framework_ratio = frf_court / bare_pair. Reported at the
    // median AND the p90; the paired difference gets its own distribution.
    let med_bare_cand = quantile_of(&bare_cand_wall, 0.50);
    let med_bare_pair = quantile_of(&bare_pair_wall, 0.50);
    let med_frf = quantile_of(&frf_wall, 0.50);
    let p90_bare_cand = quantile_of(&bare_cand_wall, 0.90);
    let p90_bare_pair = quantile_of(&bare_pair_wall, 0.90);
    let p90_frf = quantile_of(&frf_wall, 0.90);
    let med_harness_cpu = quantile_of(&frf_harness_cpu, 0.50);
    let med_bare_cand_cpu = quantile_of(&bare_cand_cpu, 0.50);
    let med_bare_pair_cpu = quantile_of(&bare_pair_cpu, 0.50);

    json!({
        "id": id,
        "project": as_str(&meta["project"]),
        "cve": as_str(&meta["cve"]),
        "protocol": {
            "warmups": warmups.to_string(),
            "samples": samples.to_string(),
            "isolation": "a fresh PREPARED store per frf_court sample (a copy of the staged tree); the authority is pre-admitted — admission is a one-time setup, deliberately excluded from the observation timing; the reuse path never short-circuits",
            "counterbalance": "the three measurements are cyclically rotated per sample index; no measurement always runs first or last",
            "wall": "process wall time, ms (microsecond precision)",
            "cpu": {
                "harness": "the frf process itself reports getrusage(RUSAGE_SELF) user+sys (FRF_PRINT_SELF_CPU=1) — the harness executable's own CPU, excluding the sides it spawned",
                "sides": "the bare measurements report getrusage(RUSAGE_CHILDREN) deltas — the side(s)' own CPU (the only waited-for children); the court sides are the same binaries the bare rows measured",
                "aggregate": "proxy: harness RUSAGE_SELF median + bare_pair side-CPU median — the sides are not re-measured inside the court; labeled a proxy",
            },
            "quantiles": "nearest-index empirical quantile round(p·(n−1)) over the sorted samples",
            "overhead_decomposition": {
                "user_visible_amplification": "frf_court / bare_candidate — what using FRF costs vs just running the program",
                "framework_overhead": "frf_court − bare_pair (paired per sample) — evidence construction, hashing, sealing, capture, comparison, storage beyond the two executions",
                "framework_ratio": "frf_court / bare_pair",
                "ratio_denominator_floor": "0.001 ms (1 µs) — below measurement resolution; prevents division by a measured zero when a side is sub-microsecond",
            },
        },
        "hermeticity": {
            "distinct_observation_identities": distinct_obs.to_string(),
            "distinct_execution_identities": distinct_exec.to_string(),
            "distinct_run_ids_across_samples": distinct_runs.to_string(),
            "observation_identities": observation_ids.iter().map(|(k, v)| json!({"observation_identity": k, "samples": v.to_string()})).collect::<Vec<_>>(),
            "execution_identities": execution_ids.iter().map(|(k, v)| json!({"execution_identity": k, "samples": v.to_string()})).collect::<Vec<_>>(),
            "run_ids": run_ids.iter().map(|(k, v)| json!({"run": k, "samples": v.to_string()})).collect::<Vec<_>>(),
            "sample_orders": orders,
        },
        "measurements": {
            "bare_candidate": {
                "side": side_vuln,
                "wall": bare_cand_stats,
                "cpu_ms_median": format!("{med_bare_cand_cpu:.1}"),
            },
            "bare_pair": {
                "reference_side": side_fixed,
                "candidate_side": side_vuln,
                "wall": bare_pair_stats,
                "cpu_ms_median": format!("{med_bare_pair_cpu:.1}"),
            },
            "frf_court": {
                "manifest": manifest,
                "wall": frf_stats,
                "harness_cpu_ms_median": format!("{med_harness_cpu:.1}"),
            },
        },
        "overhead": {
            "user_visible_amplification": {
                "p50": format!("{:.2}", med_frf / med_bare_cand.max(0.001)),
                "p90": format!("{:.2}", p90_frf / p90_bare_cand.max(0.001)),
            },
            "framework_overhead_ms": paired_stats,
            "framework_ratio": {
                "p50": format!("{:.2}", med_frf / med_bare_pair.max(0.001)),
                "p90": format!("{:.2}", p90_frf / p90_bare_pair.max(0.001)),
            },
            "aggregate_court_cpu_proxy_ms_median": format!("{:.1}", med_harness_cpu + med_bare_pair_cpu),
            "harness_cpu_ms_median": format!("{med_harness_cpu:.1}"),
        },
    })
}

/// Copy the staged case tree (builds/, fixtures/, courts/, ev/ with the
/// PRE-ADMITTED authorities) into a fresh sample dir — the observation starts
/// from a prepared fresh store with the authority already admitted (admission
/// is not part of the observation; it is a one-time setup, measured nowhere).
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
        "description": "The proper single-host runtime-overhead benchmark: three measurements per sample (bare_candidate, bare_pair, frf_court), deterministically counterbalanced; warmups + isolated samples; wall + separately-attributed CPU (the frf process reports its own RUSAGE_SELF for harness CPU; the sides' CPU comes from the bare measurements); p50/p90/p99; the PAIRED framework-overhead distribution (frf_court − bare_pair); machine description. Measurements only — no timing thresholds; the gates are protocol-correctness gates (execution, hermeticity at both identity layers, monotonic quantiles, machine description).",
        "benchmark": {
            "warmups": warmups.to_string(),
            "samples": samples.to_string(),
            "explicit_sample_override": explicit_override,
            "env_overrides": "FRF_BENCH_WARMUPS / FRF_BENCH_SAMPLES",
            "measurements": ["bare_candidate", "bare_pair", "frf_court"],
            "counterbalance": "deterministic cyclic rotation of the three measurements per sample index; no measurement always runs first or last",
            "prepared_store": "the reference authority is pre-admitted; admission is a one-time setup, deliberately excluded from the observation timing",
            "quantile_convention": "nearest-index empirical quantile round(p·(n−1))",
            "harness_cpu_source": "the frf process reports getrusage(RUSAGE_SELF) under FRF_PRINT_SELF_CPU=1",
            "aggregate_court_cpu": "proxy: harness RUSAGE_SELF + bare_pair side CPU (the sides are not re-measured inside the court)",
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
