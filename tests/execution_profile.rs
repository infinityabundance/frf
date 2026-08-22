//! Phase-5 acceptance: execution profiles and the exact/semantic replay
//! distinction.
//!
//! 1. the receipt carries the execution profile and the exact capture
//!    bounds that applied — copied from the capture, never reconstructed;
//! 2. exact replay requires the same execution provenance (profile, bounds,
//!    environment, interpreter chains) and REFUSES on any drift;
//! 3. semantic replay admits and REPORTS the same drift, then requires the
//!    bounded observation to reproduce anyway;
//! 4. a side that exceeds the profile's per-stream capture cap refuses the
//!    whole run — truncated output is never evidence.

mod common;
use common::*;

use std::fs;

/// The capture bound values the reference profile applies by default.
const DEFAULT_BOUNDS: &[(&str, &str)] = &[
    ("timeout_ms", "60000"),
    ("max_stream_bytes", "16777216"),
    ("rlimit_as_mb", "2048"),
    ("rlimit_cpu_s", "30"),
    ("rlimit_nofile", "1024"),
];

fn receipt_json(work: &Workdir, receipt: &str) -> serde_json::Value {
    serde_json::from_str(
        &fs::read_to_string(work.path(&format!("frf/receipts/{receipt}.json"))).unwrap(),
    )
    .unwrap()
}

fn receipt_emit(work: &Workdir, run: &str) -> String {
    let out = frf(work, &["--root", ROOT, "receipt", "emit", run]);
    assert_success(&out, "receipt emit");
    let receipt = stdout(&out);
    assert!(receipt.starts_with("receipt-run-"), "receipt id: {receipt}");
    receipt
}

#[test]
fn the_receipt_carries_the_profile_and_the_bounds_that_applied() {
    let work = Workdir::new("profile");
    work.copy_canonical_tree();
    admit_reference(&work);
    let run = run_court(&work);

    // The capture records the harness contract at observation time.
    let capture: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("frf/captures/{run}/capture.json"))).unwrap(),
    )
    .unwrap();
    assert_eq!(capture["execution_profile"], "frf-exec-linux-v1");
    for (k, v) in DEFAULT_BOUNDS {
        assert_eq!(
            capture["capture_bounds"][k], *v,
            "capture bound {k} must be recorded as applied"
        );
    }

    // The receipt copies them verbatim — it never guesses the contract.
    let receipt = receipt_emit(&work, &run);
    let body = receipt_json(&work, &receipt);
    assert_eq!(body["execution_profile"], "frf-exec-linux-v1");
    let capture_bounds: serde_json::Value =
        serde_json::to_value(&capture["capture_bounds"]).unwrap();
    assert_eq!(body["capture_bounds"], capture_bounds);
    assert_eq!(body["schema_version"], "frf-receipt-v18");

    // Replay consumes the receipt through the same verified loader, which
    // enforces that the receipt's profile/bounds equal the capture's.
    let out = frf(
        &work,
        &["--root", ROOT, "replay", &receipt, "--policy", "exact"],
    );
    assert_success(&out, "exact replay from the receipt id");
}

#[test]
fn exact_replay_refuses_on_provenance_drift() {
    let work = Workdir::new("drift");
    work.copy_canonical_tree();
    admit_reference(&work);
    let run = run_court(&work);

    // No drift: exact replay reproduces byte-for-byte.
    let out = frf(
        &work,
        &["--root", ROOT, "replay", &run, "--policy", "exact"],
    );
    assert_success(&out, "exact replay without drift");
    assert!(stdout(&out).contains("replay (exact)"));
    assert!(stdout(&out).contains("reproduced"));

    // A declared provenance difference (a different capture cap in force)
    // must refuse exact replay, naming the drifted dimension.
    let out = frf_env(
        &work,
        &["--root", ROOT, "replay", &run, "--policy", "exact"],
        &[("FRF_EXEC_MAX_BYTES", "2048")],
    );
    assert!(!out.status.success(), "exact replay must refuse on drift");
    let err = stderr(&out);
    assert!(err.contains("replay (exact)"), "stderr: {err}");
    assert!(
        err.contains("refused: the execution provenance changed"),
        "stderr: {err}"
    );
    assert!(
        err.contains("capture bound max_stream_bytes changed: 16777216 -> 2048"),
        "the drift report must name the dimension: {err}"
    );
}

#[test]
fn semantic_replay_reports_the_drift_and_reproduces_anyway() {
    let work = Workdir::new("semantic");
    work.copy_canonical_tree();
    admit_reference(&work);
    let run = run_court(&work);

    // The same drift semantic replay admits: each difference is REPORTED to
    // stderr, the final line counts it, and the observation reproduces.
    let out = frf_env(
        &work,
        &["--root", ROOT, "replay", &run, "--policy", "semantic"],
        &[("FRF_EXEC_MAX_BYTES", "2048")],
    );
    assert_success(&out, "semantic replay must reproduce under admitted drift");
    let err = stderr(&out);
    assert!(
        err.contains(
            "replay (semantic): declared provenance difference: capture bound max_stream_bytes"
        ),
        "the drift must be reported, never silent: {err}"
    );
    let out_str = stdout(&out);
    assert!(out_str.contains("replay (semantic)"), "stdout: {out_str}");
    assert!(out_str.contains("reproduced"), "stdout: {out_str}");
    assert!(
        out_str.contains("1 declared provenance difference(s)"),
        "the reproduction must count the admitted differences: {out_str}"
    );

    // An unknown policy is refused loudly.
    let out = frf(
        &work,
        &["--root", ROOT, "replay", &run, "--policy", "loose"],
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("unknown replay policy 'loose'"));
}

/// A copy of the canonical manifest declaring the cgroup v2 execution
/// profile (`frf-exec-linux-v2`).
fn v2_manifest(work: &Workdir) -> String {
    let src = fs::read_to_string(work.path(MANIFEST)).unwrap();
    let v2 = src.replace(
        "  admissibility_envelope:",
        "  execution_profile: frf-exec-linux-v2\n  admissibility_envelope:",
    );
    let path = work.path("frf/courts/cli-malformed-input/manifest-v2.yaml");
    fs::write(&path, v2).unwrap();
    "frf/courts/cli-malformed-input/manifest-v2.yaml".to_string()
}

/// A fake cgroup v2 root for the regression suite (delegation is a machine
/// property, not a test one).
fn fake_cgroup_root(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "frf-it-cgroup-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("cgroup.controllers"),
        "cpuset cpu io memory pids\n",
    )
    .unwrap();
    dir
}

/// The v2 profile is a REAL second execution profile: a court that declares
/// it runs its sides under the per-side cgroup v2 aggregate envelope, and
/// the capture + receipt record the profile AND the cgroup bounds that
/// actually applied.
#[test]
fn the_v2_profile_records_its_cgroup_envelope_in_capture_and_receipt() {
    let work = Workdir::new("profile-v2");
    work.copy_canonical_tree();
    admit_reference(&work);
    let manifest = v2_manifest(&work);
    let root = fake_cgroup_root("v2");

    let out = frf_env(
        &work,
        &["--root", ROOT, "court", "run", &manifest],
        &[("FRF_CGROUP2_ROOT", root.to_str().unwrap())],
    );
    assert_success(&out, "court run under frf-exec-linux-v2");
    let run = stdout(&out);
    assert!(run.starts_with("run-cli-malformed-input-"), "run id: {run}");

    // The capture records the declared profile and the cgroup envelope that
    // applied (pids.max / memory.max / cpu.max over the side's whole tree).
    let capture: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("frf/captures/{run}/capture.json"))).unwrap(),
    )
    .unwrap();
    assert_eq!(capture["execution_profile"], "frf-exec-linux-v2");
    assert_eq!(capture["capture_bounds"]["cgroup_pids_max"], "1024");
    assert_eq!(capture["capture_bounds"]["cgroup_memory_max"], "2147483648");
    assert_eq!(capture["capture_bounds"]["cgroup_cpu_max"], "100000 100000");
    // The setrlimit layer remains in force underneath the envelope.
    assert_eq!(capture["capture_bounds"]["rlimit_nproc"], "4096");

    // The receipt copies the contract verbatim (v16 records the envelope).
    let receipt = receipt_emit(&work, &run);
    let body = receipt_json(&work, &receipt);
    assert_eq!(body["execution_profile"], "frf-exec-linux-v2");
    assert_eq!(
        body["capture_bounds"],
        serde_json::to_value(&capture["capture_bounds"]).unwrap()
    );
    assert_eq!(body["schema_version"], "frf-receipt-v18");

    // Exact replay re-executes under the SAME recorded profile and envelope
    // (the fake root stands in for the delegated subtree).
    let out = frf_env(
        &work,
        &["--root", ROOT, "replay", &run, "--policy", "exact"],
        &[("FRF_CGROUP2_ROOT", root.to_str().unwrap())],
    );
    assert_success(
        &out,
        "exact replay of a v2 observation under the same envelope",
    );

    // The v2 group was removed after the runs: nothing lingers in the root.
    let leftover = fs::read_dir(root.join("frf"))
        .map(|it| it.flatten().count())
        .unwrap_or(0);
    assert_eq!(
        leftover, 0,
        "the per-side cgroups must be removed after the runs"
    );
    let _ = fs::remove_dir_all(&root);
}

/// A declared profile is ENFORCED, never approximated: `frf-exec-linux-v2`
/// without a writable cgroup v2 subtree REFUSES the run, even though the
/// setrlimit layer alone could have run it. A silent downgrade would record
/// a contract the harness did not enforce.
#[test]
fn the_v2_profile_refuses_without_a_writable_cgroup_root() {
    let work = Workdir::new("profile-v2-refuse");
    work.copy_canonical_tree();
    admit_reference(&work);
    let manifest = v2_manifest(&work);

    // `none` forces the no-writable-root path deterministically on any host
    // (this test environment has no delegated cgroup subtree anyway).
    let out = frf_env(
        &work,
        &["--root", ROOT, "court", "run", &manifest],
        &[("FRF_CGROUP2_ROOT", "none")],
    );
    assert!(
        !out.status.success(),
        "a v2 run without a cgroup root must refuse"
    );
    let err = stderr(&out);
    assert!(
        err.contains("no writable cgroup v2 subtree"),
        "the refusal must name the missing delegation: {err}"
    );
    assert!(
        err.contains("frf-exec-linux-v2"),
        "the refusal must name the profile: {err}"
    );
}

#[test]
fn a_side_exceeding_the_stream_cap_refuses_the_run() {
    let work = Workdir::new("overflow");
    work.copy_canonical_tree();
    admit_reference(&work);

    // The candidate emits far beyond the tiny cap in force: the run must be
    // REFUSED, never recorded truncated. (The reference side stays small.)
    let big = "#!/bin/sh\nawk 'BEGIN{for(i=0;i<1000;i++) print \"0123456789abcdefghijklmnopqrstuvwxyz\"}'\n";
    work.write_candidate(big);

    let out = frf_env(
        &work,
        &["--root", ROOT, "court", "run", MANIFEST],
        &[("FRF_EXEC_MAX_BYTES", "1024")],
    );
    assert!(
        !out.status.success(),
        "a side over the stream cap must refuse the court"
    );
    let err = stderr(&out);
    assert!(
        err.contains("exceeded the execution profile's 1024 byte per-stream capture cap"),
        "the refusal must name the cap: {err}"
    );
    assert!(
        err.contains("refusing to record truncated output"),
        "truncated output must never become evidence: {err}"
    );
    assert!(
        !stdout(&out).starts_with("run-cli-malformed-input-"),
        "no run id may be returned for a refused run: {}",
        stdout(&out)
    );

    // And the court legitimately runs again once the side is within bounds.
    let out = frf_env(
        &work,
        &["--root", ROOT, "court", "run", MANIFEST],
        &[("FRF_EXEC_MAX_BYTES", "65536")],
    );
    assert_success(&out, "court run within bounds");
    assert!(stdout(&out).starts_with("run-cli-malformed-input-"));
}
