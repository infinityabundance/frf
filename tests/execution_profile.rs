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
    assert_eq!(body["schema_version"], "frf-receipt-v14");

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
