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
use std::path::Path;

/// The capture bound values the reference profile applies by default.
const DEFAULT_BOUNDS: &[(&str, &str)] = &[
    ("timeout_ms", "60000"),
    ("max_stream_bytes", "16777216"),
    ("produced_max_files", "4096"),
    ("produced_max_bytes", "268435456"),
    ("produced_max_file_bytes", "16777216"),
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
    assert_eq!(body["schema_version"], "frf-receipt-v19");

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
    assert_eq!(body["schema_version"], "frf-receipt-v19");

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

    // The evidentiary overflow (v19): the refusal is itself evidence — a
    // content-addressed harness event under harness/<id>.json records that
    // the declared 1024-byte stream cap was ENFORCED, with the side, the
    // target, and the observed size. Its id rederives from its own fields.
    let harness_dir = work.path(&format!("{ROOT}/harness"));
    let mut event_ids: Vec<String> = std::fs::read_dir(&harness_dir)
        .expect("the refused run must write harness events")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".json"))
        .collect();
    event_ids.sort();
    assert!(
        !event_ids.is_empty(),
        "a stream overflow must write a harness event"
    );
    let event: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(harness_dir.join(&event_ids[0])).unwrap())
            .unwrap();
    assert_eq!(event["schema_version"], "frf-harness-event-v1");
    assert_eq!(event["event_kind"], "stream-overflow");
    assert_eq!(
        event["side"], "candidate",
        "the overflowing side is recorded"
    );
    assert_eq!(event["target"], "stdout");
    assert_eq!(event["cap"], "1024", "the cap as enforced");
    assert!(
        event["observed"].as_str().unwrap().parse::<u64>().unwrap() > 1024,
        "the observed size must exceed the cap"
    );
    assert_eq!(event["court"], "cli-malformed-input");
    assert_eq!(event["execution_profile"], "frf-exec-linux-v1");
    assert_eq!(event["id"].as_str().unwrap().len(), 64);
    // The record is immutable + content-addressed: it lives at its content
    // address under harness/<id>.json.
    let event_id = event["id"].as_str().unwrap().to_string();
    assert!(work
        .path(&format!("{ROOT}/harness/{event_id}.json"))
        .is_file());
    assert!(work
        .path(&format!("{ROOT}/harness/{event_id}.json"))
        .is_file());

    // And the court legitimately runs again once the side is within bounds.
    let out = frf_env(
        &work,
        &["--root", ROOT, "court", "run", MANIFEST],
        &[("FRF_EXEC_MAX_BYTES", "65536")],
    );
    assert_success(&out, "court run within bounds");
    assert!(stdout(&out).starts_with("run-cli-malformed-input-"));
}

/// v19 — a produced tree that exceeds a cap is refused exactly like a stream
/// overflow (never truncated, never partially recorded), and the refusal
/// writes the content-addressed produced-overflow harness event.
#[test]
fn a_produced_tree_over_the_cap_refuses_the_run_and_records_the_event() {
    let work = Workdir::new("produced-overflow");
    work.copy_canonical_tree();
    admit_reference(&work);
    // The candidate writes far more produced files than the tiny cap allows.
    // Like the treegen tools, it parses `--out` and creates the output
    // directory itself (the harness clears the produce path between sides).
    let flood = "#!/bin/sh\nspec=\"\"; out=\"\"\nwhile [ $# -gt 0 ]; do\n  case \"$1\" in\n    --spec) spec=\"$2\"; shift 2 ;;\n    --out) out=\"$2\"; shift 2 ;;\n    *) shift ;;\n  esac\ndone\nmkdir -p \"$out\"\nfor i in $(seq 1 200); do echo x > \"$out/out-$i.txt\"; done\nexit 0\n";
    // The fs-tree-build court's candidate is treegen-cand.sh, not the CLI
    // candidate.
    let cand = work.path("golden/treegen-cand.sh");
    fs::write(&cand, flood).unwrap();
    set_exec(&cand);
    // The fs-tree-build court declares produce (the sides write to {output});
    // copy its manifest + fixture into the workdir.
    let src_manifest =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("frf/courts/fs-tree-build/manifest.yaml");
    let src_fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("frf/courts/fs-tree-build/fixtures/tree-spec.conf");
    let dst_manifest = work.path("frf/courts/fs-tree-build/manifest.yaml");
    fs::create_dir_all(dst_manifest.parent().unwrap()).unwrap();
    fs::copy(&src_manifest, &dst_manifest).unwrap();
    let dst_fixture = work.path("frf/courts/fs-tree-build/fixtures/tree-spec.conf");
    fs::create_dir_all(dst_fixture.parent().unwrap()).unwrap();
    fs::copy(&src_fixture, &dst_fixture).unwrap();
    // The tree-build court's authority: the treegen reference.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "authority",
            "admit",
            "golden/treegen-ref.sh",
            "--name",
            "treegen-ref",
            "--version",
            "1.0",
        ],
    );
    assert_success(&out, "treegen authority admit");

    let out = frf_env(
        &work,
        &[
            "--root",
            ROOT,
            "court",
            "run",
            "frf/courts/fs-tree-build/manifest.yaml",
        ],
        // The treegen reference produces ~5 files; the flood candidate
        // produces 200. A 50-file cap refuses the candidate's tree.
        &[("FRF_EXEC_PRODUCED_MAX_FILES", "50")],
    );
    assert!(
        !out.status.success(),
        "a produced tree over the cap must refuse the court"
    );
    let err = stderr(&out);
    assert!(
        err.contains("file cap"),
        "the refusal must name the produced-file cap: {err}"
    );
    // The produced-overflow harness event was written.
    let harness_dir = work.path(&format!("{ROOT}/harness"));
    let mut event_ids: Vec<String> = std::fs::read_dir(&harness_dir)
        .expect("the refused run must write harness events")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".json"))
        .collect();
    event_ids.sort();
    let event: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(harness_dir.join(&event_ids[0])).unwrap())
            .unwrap();
    assert_eq!(event["event_kind"], "produced-overflow");
    assert_eq!(event["target"], "produced-files");
    assert_eq!(event["cap"], "50");
    assert!(
        event["observed"].as_str().unwrap().parse::<u64>().unwrap() > 50,
        "the observed file count must exceed the cap"
    );
    assert_eq!(event["side"], "candidate");
}

/// v19 — the RESOURCE-LIMIT path is the design's key nuance: a side that
/// dies by a declared bound's signal (the CPU limit's SIGXCPU) is a COMPLETE
/// observation, not a refusal. The run continues, and the harness event is
/// recorded ALONGSIDE — and bound into the capture's `harness_events` (v15),
/// so the run's bundle carries the bound-firing evidence.
#[test]
fn a_cpu_limit_signal_records_the_event_without_refusing_the_run() {
    let work = Workdir::new("rlimit-event");
    work.copy_canonical_tree();
    admit_reference(&work);
    // The candidate burns CPU; with a 1-second CPU bound it dies by the
    // profile's deterministic signal outcome before the wall-clock timeout.
    work.write_candidate("#!/bin/sh\nwhile :; do :; done\n");

    let out = frf_env(
        &work,
        &["--root", ROOT, "court", "run", MANIFEST],
        &[("FRF_EXEC_RLIMIT_CPU_S", "1")],
    );
    assert_success(&out, "a resource-limit signal must not refuse the run");
    let run = stdout(&out);
    assert!(
        run.starts_with("run-cli-malformed-input-"),
        "the run completes with an id: {run}"
    );

    // The capture binds the harness event (v15) — the run's evidence graph
    // points at the record that explains the side's signal exit.
    let capture: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("{ROOT}/captures/{run}/capture.json"))).unwrap(),
    )
    .unwrap();
    assert_eq!(capture["schema_version"], "frf-capture-v15");
    let cited: Vec<String> = capture["harness_events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(cited.len(), 1, "exactly one bound fired: {cited:?}");
    let exit = capture["candidate"]["exit"].as_str().unwrap().to_string();
    assert!(
        exit.starts_with("signal("),
        "the candidate must have died by the CPU limit's signal, got {exit}"
    );

    // The event itself: content-addressed (lives at its id), canonical,
    // and its id rederives from its own fields (the store refuses anything
    // else).
    let event_path = work.path(&format!("{ROOT}/harness/{}.json", cited[0]));
    assert!(
        event_path.is_file(),
        "the event lives at its content address"
    );
    let event: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&event_path).unwrap()).unwrap();
    assert_eq!(event["schema_version"], "frf-harness-event-v1");
    assert_eq!(event["event_kind"], "rlimit");
    assert_eq!(event["target"], "cpu");
    assert_eq!(event["side"], "candidate");
    assert_eq!(event["court"], "cli-malformed-input");
    assert_eq!(event["execution_profile"], "frf-exec-linux-v1");
    assert_eq!(event["cap"], "1");
    assert_eq!(event["observed"], exit);
    assert!(event["runner"].as_str().unwrap().len() == 64);
    assert_eq!(event["id"].as_str().unwrap(), cited[0]);

    // The receipt over the run carries the capture, which cites the event:
    // the bound-firing evidence is portable with the observation. Export the
    // receipt's closure to a directory bundle and prove the event travels.
    let receipt = receipt_emit(&work, &run);
    let out = frf(
        &work,
        &[
            "--root", ROOT, "bundle", "export", &receipt, "--output", "b/",
        ],
    );
    assert_success(&out, "bundle export with the harness event");
    assert!(
        work.path(&format!("b/harness/{}.json", cited[0])).is_file(),
        "the bundle must carry the harness event"
    );
    let out = frf(&work, &["--root", ROOT, "bundle", "verify", "b/"]);
    assert_success(&out, "bundle verify with the harness event");
}

/// 0.1.62 — the OCI execution profile (`frf-exec-oci`): each side runs
/// INSIDE a container from a digest-pinned OCI image — the complete root
/// filesystem is the execution machinery, bound by digest in the execution
/// identity. The profile is ENFORCED, never approximated: no declared image,
/// an image declared without the profile, or an image the runtime does not
/// have all REFUSE the run.
#[test]
fn the_oci_profile_is_enforced_never_approximated() {
    let work = Workdir::new("oci-refusals");
    work.copy_canonical_tree();
    admit_reference(&work);

    let base = |extra: &str| -> String {
        format!(
            "court:\n  id: oci-test\n  question: q\n  falsifier: f\n  authority: ref-cli-1.8.2\n  candidate:\n    name: cand\n    version_or_commit: \"0.1.0\"\n    build_profile: debug\n    path: golden/candidate.sh\n  fixture:\n    id: malformed-path.conf\n    path: frf/courts/cli-malformed-input/fixtures/malformed-path.conf\n    arguments: [\"--strict\", \"{{fixture}}\"]\n  admissibility_envelope:\n    fixture_family: malformed-input\n    platforms: [\"x86_64-linux\"]\n    observables: [exit, stderr]\n    normalizers: []\n    replay_scope: single-run\n{extra}"
        )
    };
    let manifest = work.path("oci-court.yaml");

    // (1) The OCI profile without a declared image: refused — the image is
    // part of the declared machinery, never invented.
    fs::write(&manifest, base("  execution_profile: frf-exec-oci\n")).unwrap();
    let out = frf(&work, &["--root", ROOT, "court", "run", "oci-court.yaml"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("execution_image"),
        "the refusal must name the missing image: {}",
        stderr(&out)
    );

    // (2) A declared image under the reference profile: refused — the image
    // is only meaningful under the OCI profile.
    fs::write(
        &manifest,
        base("  execution_image: docker.io/library/busybox@sha256:aaaa\n"),
    )
    .unwrap();
    let out = frf(&work, &["--root", ROOT, "court", "run", "oci-court.yaml"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("execution_image"),
        "the refusal must name the misdeclared image: {}",
        stderr(&out)
    );

    // (3) A mutable tag (no digest) under the OCI profile: refused — the
    // image is content-addressed machinery, never a mutable tag.
    fs::write(
        &manifest,
        base("  execution_profile: frf-exec-oci\n  execution_image: docker.io/library/busybox:latest\n"),
    )
    .unwrap();
    let out = frf(&work, &["--root", ROOT, "court", "run", "oci-court.yaml"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("digest"),
        "the refusal must demand a digest: {}",
        stderr(&out)
    );

    // (4) An image the runtime does not have: refused (when a runtime is
    // present; without one the profile refuses earlier with the same
    // enforcement message).
    fs::write(
        &manifest,
        base("  execution_profile: frf-exec-oci\n  execution_image: docker.io/library/nonexistent-frf-image@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"),
    )
    .unwrap();
    let out = frf(&work, &["--root", ROOT, "court", "run", "oci-court.yaml"]);
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(
        err.contains("image") || err.contains("runtime"),
        "the refusal must name the image or the runtime: {err}"
    );
}

/// 0.1.62 — the OCI happy path, env-gated (`FRF_TEST_OCI=1`, set by the CI
/// demo job): the side runs INSIDE the digest-pinned busybox image, the
/// capture records the profile + image identity, the execution identity
/// binds the image (a different image is a different execution), and exact
/// replay reproduces.
#[test]
fn oci_profile_runs_the_side_inside_the_declared_image() {
    if std::env::var("FRF_TEST_OCI")
        .map(|v| v != "1")
        .unwrap_or(true)
    {
        eprintln!("skipping: set FRF_TEST_OCI=1 to run the OCI container test");
        return;
    }
    // A container runtime must be present (the profile is enforced).
    let runtime_ok = ["podman", "docker"].iter().any(|bin| {
        std::process::Command::new(bin)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    });
    if !runtime_ok {
        eprintln!("skipping: no container runtime (podman/docker)");
        return;
    }
    // The digest-pinned busybox image the court declares. Pulling by digest
    // is deterministic and content-addressed; the runtime must have it.
    const IMAGE: &str = "docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662";
    let pulled = std::process::Command::new("podman")
        .args(["image", "inspect", IMAGE])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !pulled {
        eprintln!(
            "skipping: the pinned busybox image is not present; load it (podman pull {IMAGE})"
        );
        return;
    }

    let work = Workdir::new("oci-run");
    work.copy_canonical_tree();
    admit_reference(&work);
    let manifest = work.path("oci-court.yaml");
    fs::write(
        &manifest,
        format!(
            "court:\n  id: oci-test\n  question: q\n  falsifier: f\n  authority: ref-cli-1.8.2\n  candidate:\n    name: cand\n    version_or_commit: \"0.1.0\"\n    build_profile: debug\n    path: golden/candidate.sh\n  fixture:\n    id: malformed-path.conf\n    path: frf/courts/cli-malformed-input/fixtures/malformed-path.conf\n    arguments: [\"--strict\", \"{{fixture}}\"]\n  execution_profile: frf-exec-oci\n  execution_image: {IMAGE}\n  admissibility_envelope:\n    fixture_family: malformed-input\n    platforms: [\"x86_64-linux\"]\n    observables: [exit, stderr]\n    normalizers: []\n    replay_scope: single-run\n"
        ),
    )
    .unwrap();

    let out = frf(&work, &["--root", ROOT, "court", "run", "oci-court.yaml"]);
    assert_success(&out, "the OCI court runs the sides inside the image");
    let run = stdout(&out);
    assert!(run.starts_with("run-oci-test-"));

    // The capture records the profile and the image identity (digest +
    // runtime), and the residual divergences are the same ones the host
    // court observes (the exit class + the first stderr line).
    let capture: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("frf/captures/{run}/capture.json"))).unwrap(),
    )
    .unwrap();
    assert_eq!(capture["execution_profile"], "frf-exec-oci");
    assert_eq!(
        capture["container_image"]["digest"],
        "sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"
    );
    assert!(capture["container_image"]["runtime"]
        .as_str()
        .unwrap()
        .contains("podman"));
    assert_eq!(capture["reference"]["exit"], "2");
    assert_eq!(capture["candidate"]["exit"], "1");
    assert!(!capture["residuals"].as_array().unwrap().is_empty());

    // The execution identity binds the image: the OCI observation is NOT the
    // same execution as the reference-profile observation of the same sides.
    // (Both runs exist in the same store; the OCI run id differs.)
    let host_run = run_court(&work);
    assert_ne!(
        run, host_run,
        "the OCI execution is a different execution identity than the host execution"
    );
    let host_capture: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("frf/captures/{host_run}/capture.json"))).unwrap(),
    )
    .unwrap();
    assert_eq!(host_capture["execution_profile"], "frf-exec-linux-v1");
    assert_ne!(
        capture["execution_identity"], host_capture["execution_identity"],
        "the container image is execution machinery and must change the execution identity"
    );

    // The receipt carries the profile; exact replay re-runs the sides inside
    // the same image and reproduces.
    let receipt = receipt_emit(&work, &run);
    let body = receipt_json(&work, &receipt);
    assert_eq!(body["execution_profile"], "frf-exec-oci");
    let out = frf(
        &work,
        &["--root", ROOT, "replay", &receipt, "--policy", "exact"],
    );
    assert_success(&out, "exact replay of the OCI observation");
    assert!(stdout(&out).contains("reproduced"));
}
