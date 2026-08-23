//! 0.1.65: the I/O-CLOSED execution profile (`frf-exec-linux-v3`).
//!
//! The side's world is closed before it runs a single instruction:
//!
//! - the FILESYSTEM closure (Landlock): read/execute only the content-
//!   addressed objects directory, the execution machinery (the interpreter
//!   chain + its native closure, the declared execution-context artifacts),
//!   and the declared randomness channel; the produced-output staging
//!   directory is the ONLY writable surface;
//! - the AMBIENT-CHANNEL closure (seccomp): no network, no Unix sockets, no
//!   shared memory, no ptrace, no cross-process memory.
//!
//! A side that violates a closure does not crash the harness: the access is
//! denied (EACCES/EPERM) and the court OBSERVES the denial like any other
//! output divergence. A host without Landlock refuses the profile cleanly
//! (a declared profile is enforced, never approximated).

mod common;
use common::*;

use std::fs;

/// A v3 court manifest: the I/O-closed profile + a produced tree + the
/// filesystem.tree observable (the produced tree is the write surface).
fn write_v3_manifest(work: &Workdir) -> String {
    let manifest = "v3-manifest.yaml";
    fs::write(
        work.path(manifest),
        r#"court:
  id: cli-io-closed
  question: >-
    Under the I/O-closed profile, does the candidate preserve the reference's
    exit class and first diagnostic line on fixture family malformed-input?
  falsifier: >-
    The candidate's exit class or first diagnostic line diverges from the
    admitted reference on a fixture in family malformed-input.
  authority: ref-cli-1.8.2
  candidate:
    name: cand-cli
    version_or_commit: "0.1.0"
    build_profile: debug
    path: golden/candidate.sh
  fixture:
    id: malformed-path.conf
    path: frf/courts/cli-malformed-input/fixtures/malformed-path.conf
    arguments: ["--strict", "{fixture}"]
  execution_profile: frf-exec-linux-v3
  produce:
    path: produced-out
  environment_points: {}
  admissibility_envelope:
    fixture_family: malformed-input
    platforms: ["x86_64-linux"]
    observables: [exit, stderr, filesystem.tree]
    normalizers: []
    replay_scope: single-run
"#,
    )
    .unwrap();
    manifest.to_string()
}

fn v3_capture(work: &Workdir, run: &str) -> serde_json::Value {
    serde_json::from_str(
        &fs::read_to_string(work.path(&format!("frf/captures/{run}/capture.json"))).unwrap(),
    )
    .unwrap()
}

fn store_residual_axis(work: &Workdir, rid: &serde_json::Value) -> String {
    let rid = rid.as_str().expect("residual id is a string");
    let record: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("frf/residuals/{rid}.json"))).unwrap(),
    )
    .unwrap();
    record["axis"].as_str().unwrap_or_default().to_string()
}

/// The side that matches the reference (exit 2, `tool:` first stderr line)
/// AND writes its produced tree: under the closure it must be able to read
/// its fixture and write its produced directory, and the run must be a clean
/// pass with the produced tree captured.
#[test]
fn io_closed_side_reads_its_world_and_writes_its_produced_tree() {
    let work = Workdir::new("v3-positive");
    work.copy_canonical_tree();
    work.write_candidate(
        "#!/bin/sh\n\
         set -u\n\
         printf 'artifact\\n' > produced-out/artifact.txt\n\
         file=\"\"\n\
         for arg in \"$@\"; do\n\
           case \"$arg\" in\n\
             --strict) ;;\n\
             *) file=\"$arg\" ;;\n\
           esac\n\
         done\n\
         line=0\n\
         while IFS= read -r entry || [ -n \"$entry\" ]; do\n\
           line=$((line + 1))\n\
           case \"$entry\" in\n\
             '' | \\#*) continue ;;\n\
             server\\ * | listen\\ * | log\\ *) echo \"ok: $entry\" ;;\n\
             *)\n\
               word=${entry%% *}\n\
               echo \"tool: $file:$line: unknown directive '$word'\" >&2\n\
               exit 2 ;;\n\
           esac\n\
         done <\"$file\"\n\
         exit 0\n",
    );
    admit_reference(&work);
    let manifest = write_v3_manifest(&work);

    let out = frf(&work, &["--root", ROOT, "court", "run", &manifest]);
    assert_success(&out, "v3 court run (positive)");
    let run = stdout(&out);
    let cap = v3_capture(&work, &run);
    assert_eq!(cap["execution_profile"], "frf-exec-linux-v3");
    // The produced tree was written under the closure and captured.
    let produced = cap["candidate"]["produced"]["files"].as_array().unwrap();
    assert_eq!(produced.len(), 1, "the produced artifact must be captured");
    assert_eq!(produced[0]["path"], "artifact.txt");
    // The exit/stderr axes are a clean pass (the candidate matched the
    // reference's exit class and first diagnostic line); the ONLY residual is
    // the legitimate filesystem.tree divergence — the reference produced
    // nothing, the candidate wrote its artifact (which is exactly what the
    // closure was supposed to allow).
    let residuals = cap["residuals"].as_array().unwrap();
    assert_eq!(
        residuals.len(),
        1,
        "only the produced-tree divergence may remain"
    );
    let first_residual = store_residual_axis(&work, &residuals[0]);
    assert_eq!(
        first_residual, "filesystem.tree",
        "the only residual must be the produced-tree divergence"
    );
}

/// A side that reaches outside its declared world (reading /etc/passwd) is
/// DENIED by the filesystem closure — and the court OBSERVES the denial:
/// the run records the failed side instead of pretending the access
/// happened.
#[test]
fn io_closed_denies_undeclared_file_reads_and_observes_the_denial() {
    let work = Workdir::new("v3-read-deny");
    work.copy_canonical_tree();
    // The candidate reads /etc/passwd: outside the closure (only the objects
    // dir, the machinery, the produced dir, and the runtime channels are
    // readable) -> EACCES -> the side fails visibly.
    work.write_candidate("#!/bin/sh\ncat /etc/passwd\nexit 0\n");
    admit_reference(&work);
    let manifest = write_v3_manifest(&work);

    let out = frf(&work, &["--root", ROOT, "court", "run", &manifest]);
    assert_success(
        &out,
        "the court OBSERVES the denial (the run itself succeeds)",
    );
    let run = stdout(&out);
    let cap = v3_capture(&work, &run);
    let cand_err = cap["candidate"]["stderr_first_line"].as_str().unwrap_or("");
    assert!(
        cand_err.contains("Permission denied") || cand_err.contains("cannot open"),
        "the side must be denied, got: {cand_err}"
    );
    // The denial is a DIVERGENCE (the reference read its fixture fine): the
    // run records residuals instead of a false pass.
    assert!(
        !cap["residuals"].as_array().unwrap().is_empty(),
        "the observed denial must be recorded as residual evidence"
    );
}

/// A side that opens an ambient channel (a TCP socket via bash's /dev/tcp)
/// is DENIED by the seccomp closure — the channel never exists, and the
/// court observes the EPERM.
#[test]
fn io_closed_denies_ambient_channels_and_observes_the_denial() {
    let work = Workdir::new("v3-socket-deny");
    work.copy_canonical_tree();
    // bash's /dev/tcp performs real socket()/connect() syscalls: seccomp
    // denies them with EPERM. The bash interpreter + its native closure are
    // inside the machinery allow-set, so the side RUNS and the channel
    // itself is what fails.
    work.write_candidate("#!/bin/bash\necho x > /dev/tcp/127.0.0.1/1\n");
    admit_reference(&work);
    let manifest = write_v3_manifest(&work);

    let out = frf(&work, &["--root", ROOT, "court", "run", &manifest]);
    assert_success(
        &out,
        "the court OBSERVES the denial (the run itself succeeds)",
    );
    let run = stdout(&out);
    let cap = v3_capture(&work, &run);
    let cand_err = cap["candidate"]["stderr_first_line"].as_str().unwrap_or("");
    assert!(
        cand_err.contains("Operation not permitted") || cand_err.contains("Permission denied"),
        "the ambient channel must be denied, got: {cand_err}"
    );
    assert!(
        !cap["residuals"].as_array().unwrap().is_empty(),
        "the observed denial must be recorded as residual evidence"
    );
}

/// A host without Landlock cannot run the profile: the court REFUSES with a
/// clear message (a declared profile is enforced, never approximated).
/// On hosts WITH Landlock the same refusal is a test-failure guard (the
/// profile must have run instead).
#[test]
fn io_closed_profile_refuses_cleanly_without_landlock() {
    let work = Workdir::new("v3-enforceability");
    work.copy_canonical_tree();
    work.write_candidate("#!/bin/sh\nexit 0\n");
    admit_reference(&work);
    let manifest = write_v3_manifest(&work);

    let out = frf(&work, &["--root", ROOT, "court", "run", &manifest]);
    let abi = frf::sandbox::landlock_abi();
    if abi.is_none() {
        assert!(
            !out.status.success(),
            "without Landlock the profile must refuse"
        );
        assert!(
            stderr(&out).contains("Landlock"),
            "the refusal must name the missing mechanism: {}",
            stderr(&out)
        );
    } else {
        assert_success(&out, "with Landlock the profile must run");
    }
}

/// REPLAY reproduces the I/O-closed contract: the closure is rebuilt from
/// the capture's recorded machinery (not from the host), and the replay
/// re-observes the same bounded world — a v3 observation is replayed under
/// the SAME closure, never unclosed.
#[test]
fn io_closed_replay_reproduces_the_closure_contract() {
    let work = Workdir::new("v3-replay");
    work.copy_canonical_tree();
    work.write_candidate("#!/bin/sh\ncat /etc/passwd\nexit 0\n");
    admit_reference(&work);
    let manifest = write_v3_manifest(&work);

    let out = frf(&work, &["--root", ROOT, "court", "run", &manifest]);
    assert_success(&out, "v3 court run");
    let run = stdout(&out);
    let first = v3_capture(&work, &run);
    let first_denial = first["candidate"]["stderr_first_line"]
        .as_str()
        .unwrap_or_default()
        .to_string();

    // Exact replay re-executes the sides under the rebuilt closure: the
    // same denied access is re-observed (the closure held), and the replay
    // reports success.
    let out = frf(
        &work,
        &["--root", ROOT, "replay", &run, "--policy", "exact"],
    );
    assert_success(&out, "v3 replay under the rebuilt closure");
    let replay_capture = v3_capture(&work, &run);
    assert_eq!(
        replay_capture["candidate"]["stderr_first_line"]
            .as_str()
            .unwrap_or_default(),
        first_denial,
        "the replay must re-observe the same denial"
    );
}
