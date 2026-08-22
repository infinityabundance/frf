//! Priority 4 — the DECLARED execution-context closure (v18). A court author
//! declares the child executables / runtime libraries / data dependencies the
//! side's behavior depends on beyond its own bytes; the engine snapshots each
//! declared path at observation time, content-addresses the bytes, and binds
//! the closure (FRF/EXECUTION-CONTEXT/v1) in the capture and the receipt.
//!
//! 1. a court run with a declared closure records it in the capture (sorted
//!    artifacts, protocol roles, rederiving cid, content-addressed objects)
//!    and the receipt copies it verbatim and verifies;
//! 2. exact replay reproduces the observation (the closure is re-snapshotted
//!    from the same declared paths);
//! 3. the bundle closure carries the snapshotted objects (the evidence-refs
//!    graph traversal — no closure-walker special case);
//! 4. a tampered capture closure (wrong cid) refuses verification;
//! 5. an undeclared role refuses the court at observation time;
//! 6. a missing declared artifact refuses the court at observation time.

mod common;
use common::*;

use std::fs;

/// The execution-context court manifest. `candidate` and `fixture` are
/// interpolated; the declared execution-context artifacts are fixed paths
/// under the workdir (relative = resolved against the working directory).
fn context_manifest(work: &Workdir, candidate: &str, fixture: &str, closure_yaml: &str) -> String {
    let manifest = format!(
        "court:\n  id: context-cli\n  question: >-\n    For input in fixture family context, does the candidate preserve the\n    admitted reference's output?\n  falsifier: >-\n    The candidate's output diverges from the admitted reference's on a fixture\n    in family context.\n  authority: ref-context-1.0\n  candidate:\n    name: cand-context\n    version_or_commit: \"0.1.0\"\n    build_profile: debug\n    path: {candidate}\n  fixture:\n    id: context-input.conf\n    path: {fixture}\n    arguments: [\"{{fixture}}\"]\n  admissibility_envelope:\n    fixture_family: context\n    platforms: [\"x86_64-linux\"]\n    observables: [exit, stdout]\n    normalizers: []\n    replay_scope: single-run\n  execution_context:\n    artifacts:\n{closure_yaml}\n"
    );
    let path = work.path("frf/courts/context-cli/manifest.yaml");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, &manifest).unwrap();
    "frf/courts/context-cli/manifest.yaml".to_string()
}

/// The three declared closure artifacts: a child executable the sides spawn,
/// a data file they read, and a runtime library they load. The closure is
/// SEMANTICALLY real: the sides' output derives from these files.
fn write_context_artifacts(work: &Workdir) {
    let helper = work.path("golden/context-helper.sh");
    fs::write(&helper, "#!/bin/sh\necho helper-ok\n").unwrap();
    set_exec(&helper);
    fs::write(
        work.path("golden/context-data.txt"),
        "data-line-from-context\n",
    )
    .unwrap();
    fs::write(
        work.path("golden/context-lib.txt"),
        "lib-line-from-context\n",
    )
    .unwrap();
}

/// The sides: reference and candidate both spawn the helper and print the
/// declared data + library — identical output, so the court PASSES and the
/// observation is a clean pass under the declared closure.
fn write_context_sides(work: &Workdir) {
    let reference = work.path("golden/context-reference.sh");
    fs::write(
        &reference,
        "#!/bin/sh\n./golden/context-helper.sh\ncat golden/context-data.txt\ncat golden/context-lib.txt\n",
    )
    .unwrap();
    set_exec(&reference);
    let candidate = work.path("golden/context-candidate.sh");
    fs::write(
        &candidate,
        "#!/bin/sh\n./golden/context-helper.sh\ncat golden/context-data.txt\ncat golden/context-lib.txt\n",
    )
    .unwrap();
    set_exec(&candidate);
}

/// The empty fixture the sides receive as `{fixture}`.
fn context_fixture(work: &Workdir) -> String {
    let path = work.path("frf/courts/context-cli/fixtures/context-input.conf");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, "# context input\n").unwrap();
    "frf/courts/context-cli/fixtures/context-input.conf".to_string()
}

#[test]
fn a_court_run_binds_the_declared_execution_context_in_capture_and_receipt() {
    let work = Workdir::new("execution-context");
    work.copy_canonical_tree();
    write_context_artifacts(&work);
    write_context_sides(&work);
    let fixture = context_fixture(&work);
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "authority",
            "admit",
            "golden/context-reference.sh",
            "--name",
            "ref-context",
            "--version",
            "1.0",
        ],
    );
    assert_success(&out, "context authority admit");

    let closure_yaml = concat!(
        "      - path: golden/context-helper.sh\n",
        "        role: child-executable\n",
        "      - path: golden/context-data.txt\n",
        "        role: data\n",
        "      - path: golden/context-lib.txt\n",
        "        role: runtime-library\n"
    );
    let manifest = context_manifest(&work, "golden/context-candidate.sh", &fixture, closure_yaml);
    let out = frf(&work, &["--root", ROOT, "court", "run", &manifest]);
    assert_success(&out, "context court run");
    let run = stdout(&out);
    assert!(run.starts_with("run-context-cli-"), "run id: {run}");

    // The capture binds the closure: protocol schema, a 64-hex cid, the
    // declared artifacts sorted by path with protocol roles, and content-
    // addressed object hashes.
    let capture: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("frf/captures/{run}/capture.json"))).unwrap(),
    )
    .unwrap();
    let closure = &capture["execution_context"];
    assert_eq!(closure["schema_version"], "frf-execution-context-v1");
    let cid = closure["cid"].as_str().unwrap().to_string();
    assert_eq!(
        cid.len(),
        64,
        "closure cid must be a 64-hex content address"
    );
    let artifacts = closure["artifacts"].as_array().unwrap();
    let declared: Vec<(String, &str)> = artifacts
        .iter()
        .map(|a| {
            (
                a["path"].as_str().unwrap().to_string(),
                a["role"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        declared,
        vec![
            ("golden/context-data.txt".to_string(), "data"),
            ("golden/context-helper.sh".to_string(), "child-executable"),
            ("golden/context-lib.txt".to_string(), "runtime-library"),
        ],
        "artifacts must be sorted by path with the declared roles"
    );
    for a in artifacts {
        let h = a["sha256"].as_str().unwrap();
        assert_eq!(h.len(), 64, "artifact {} hash", a["path"]);
        let obj = work.path(&format!("{ROOT}/objects/sha256/{h}"));
        assert!(
            obj.is_file(),
            "artifact {} must be a content-addressed object",
            a["path"]
        );
    }
    // The receipt copies the closure verbatim and VERIFIES (the verified
    // loader rederives the cid and checks the roles/order).
    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &run]);
    assert_success(&out, "receipt emit");
    let receipt = stdout(&out);
    assert!(receipt.starts_with("receipt-run-"), "receipt id: {receipt}");
    let body: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("{ROOT}/receipts/{receipt}.json"))).unwrap(),
    )
    .unwrap();
    assert_eq!(body["schema_version"], "frf-receipt-v18");
    assert_eq!(
        body["execution_context"], *closure,
        "the receipt must copy the capture's closure"
    );

    // The closure's evidence refs rode the generic graph: bundle export from
    // the receipt must carry the snapshotted objects without a closure-walker
    // special case.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "bundle",
            "export",
            &receipt,
            "--output",
            "golden/work/context.frf",
        ],
    );
    assert_success(&out, "bundle export");
    for a in artifacts {
        let rel = format!("objects/sha256/{}", a["sha256"].as_str().unwrap());
        let p = work.path(&format!("golden/work/context.frf/{rel}"));
        assert!(
            p.is_file(),
            "the bundle must carry the execution-context object {rel}"
        );
    }

    // Exact replay re-executes the court: the declared paths re-snapshot to
    // the same bytes, the run reproduces, and the verified loader accepts.
    let out = frf(
        &work,
        &["--root", ROOT, "replay", &receipt, "--policy", "exact"],
    );
    assert_success(&out, "exact replay from the receipt id");
}

#[test]
fn a_tampered_capture_closure_refuses_verification() {
    let work = Workdir::new("execution-context-tamper");
    work.copy_canonical_tree();
    write_context_artifacts(&work);
    write_context_sides(&work);
    let fixture = context_fixture(&work);
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "authority",
            "admit",
            "golden/context-reference.sh",
            "--name",
            "ref-context",
            "--version",
            "1.0",
        ],
    );
    assert_success(&out, "context authority admit");
    let closure_yaml = "      - path: golden/context-data.txt\n        role: data\n";
    let manifest = context_manifest(&work, "golden/context-candidate.sh", &fixture, closure_yaml);
    let out = frf(&work, &["--root", ROOT, "court", "run", &manifest]);
    assert_success(&out, "context court run");
    let run = stdout(&out);

    // Tamper the capture's closure cid (a different well-formed value). The
    // capture is canonical JSON, so the document still parses — the verified
    // loader must refuse the rederivation, never consume a closure whose
    // identity it cannot reproduce.
    let cap_path = work.path(&format!("{ROOT}/captures/{run}/capture.json"));
    let mut capture: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&cap_path).unwrap()).unwrap();
    capture["execution_context"]["cid"] = serde_json::json!("0".repeat(64));
    let tampered = crate_canonical(&capture);
    fs::write(&cap_path, tampered).unwrap();

    let out = frf(
        &work,
        &["--root", ROOT, "replay", &run, "--policy", "exact"],
    );
    assert!(
        !out.status.success(),
        "a capture whose closure cid does not rederive must refuse verification"
    );
    let err = stderr(&out);
    assert!(
        err.contains("execution-context closure cid does not rederive"),
        "refusal must name the closure identity: {err}"
    );
}

#[test]
fn an_undeclared_closure_role_refuses_the_court() {
    let work = Workdir::new("execution-context-role");
    work.copy_canonical_tree();
    write_context_artifacts(&work);
    write_context_sides(&work);
    let fixture = context_fixture(&work);
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "authority",
            "admit",
            "golden/context-reference.sh",
            "--name",
            "ref-context",
            "--version",
            "1.0",
        ],
    );
    assert_success(&out, "context authority admit");
    let closure_yaml = "      - path: golden/context-data.txt\n        role: config\n";
    let manifest = context_manifest(&work, "golden/context-candidate.sh", &fixture, closure_yaml);
    let out = frf(&work, &["--root", ROOT, "court", "run", &manifest]);
    assert!(
        !out.status.success(),
        "an undeclared closure role must refuse the court at observation time"
    );
    let err = stderr(&out);
    assert!(
        err.contains("admits child-executable, runtime-library, or data"),
        "refusal must name the protocol roles: {err}"
    );
}

#[test]
fn a_missing_declared_artifact_refuses_the_court() {
    let work = Workdir::new("execution-context-missing");
    work.copy_canonical_tree();
    write_context_sides(&work);
    let fixture = context_fixture(&work);
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "authority",
            "admit",
            "golden/context-reference.sh",
            "--name",
            "ref-context",
            "--version",
            "1.0",
        ],
    );
    assert_success(&out, "context authority admit");
    // Declared but NEVER WRITTEN: the data file does not exist.
    let closure_yaml = "      - path: golden/context-data.txt\n        role: data\n";
    let manifest = context_manifest(&work, "golden/context-candidate.sh", &fixture, closure_yaml);
    let out = frf(&work, &["--root", ROOT, "court", "run", &manifest]);
    assert!(
        !out.status.success(),
        "a declared artifact that cannot be read must refuse the court"
    );
    let err = stderr(&out);
    assert!(
        err.contains("cannot be read"),
        "refusal must name the unreadable artifact: {err}"
    );
}

/// Canonicalize a JSON value the way the engine writes evidence documents
/// (keys sorted, no whitespace) — the tampered capture must remain a valid
/// canonical document so the refusal comes from identity rederivation, not
/// from a formatting check.
fn crate_canonical(value: &serde_json::Value) -> String {
    // RFC 8785 key sorting + compact serialization: sort keys recursively.
    fn sort_keys(v: &serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::Object(m) => {
                let mut sorted = serde_json::Map::new();
                let mut keys: Vec<&String> = m.keys().collect();
                keys.sort();
                for k in keys {
                    sorted.insert(k.clone(), sort_keys(&m[k]));
                }
                serde_json::Value::Object(sorted)
            }
            serde_json::Value::Array(a) => {
                serde_json::Value::Array(a.iter().map(sort_keys).collect())
            }
            other => other.clone(),
        }
    }
    serde_json::to_string(&sort_keys(value)).unwrap()
}
