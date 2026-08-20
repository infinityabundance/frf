//! Comparator extension protocol tests (spec/comparator.md): an external
//! program can serve an observable axis through a canonical stdin/stdout
//! protocol, with its own implementation identity — while the QUESTION it
//! asks is whatever its declared specification says it is.
//!
//! The protocol's defining properties, tested here:
//!
//! - An external comparator implementing the SAME specification as an
//!   in-binary comparator produces the SAME residual fingerprint (the same
//!   question, a different implementation).
//! - The capture records the comparator's implementation identity (its
//!   program bytes), not the frf executable's, while the runner hash still
//!   names the harness.
//! - A different extractor is a different question (different specification
//!   hash, different semantic identity).
//! - A failing, indeterminate, or undeclared comparator refuses the court
//!   (fail closed: no evidence is recorded from a malfunctioning instrument).

mod common;
use common::*;

use std::fs;

/// A court manifest for the malformed-input court with a `comparators`
/// section (the trailing YAML is injected verbatim; `{}` in the format
/// string is escaped as `{{}}`).
fn write_manifest(work: &Workdir, name: &str, comparators: &str) {
    let manifest = format!(
        "court:\n  id: cli-malformed-input\n  question: >-\n    For malformed input in fixture family malformed-input, does the candidate\n    preserve the admitted reference's exit class and first diagnostic line?\n  falsifier: >-\n    The candidate's exit class or first diagnostic line diverges from the\n    admitted reference on a fixture in family malformed-input.\n  authority: ref-cli-1.8.2\n  candidate:\n    name: cand-cli\n    version_or_commit: \"0.1.0\"\n    build_profile: debug\n    path: golden/candidate.sh\n  fixture:\n    id: malformed-path.conf\n    path: frf/courts/cli-malformed-input/fixtures/malformed-path.conf\n    arguments: [\"--strict\", \"{{fixture}}\"]\n  admissibility_envelope:\n    fixture_family: malformed-input\n    platforms: [\"x86_64-linux\"]\n    observables: [exit, stderr]\n    normalizers: []\n    replay_scope: single-run\n{comparators}\n"
    );
    fs::write(
        work.path(&format!("frf/courts/cli-malformed-input/{name}")),
        manifest,
    )
    .unwrap();
}

fn capture(work: &Workdir, run: &str) -> serde_yaml::Value {
    serde_yaml::from_str(
        &fs::read_to_string(work.path(&format!("frf/captures/{run}/capture.yaml"))).unwrap(),
    )
    .unwrap()
}

fn residual_fingerprint(work: &Workdir, id: &str) -> String {
    let record: frf::model::ResidualRecord = serde_yaml::from_str(
        &fs::read_to_string(work.path(&format!("frf/residuals/{id}.yaml"))).unwrap(),
    )
    .unwrap();
    frf::semantics::residual_fingerprint(&record).unwrap()
}

const PY_COMPARATOR: &str = "comparators:\n  - axis: stderr\n    relation: eq\n    extractor: stderr-first-line\n    relation_version: \"v1\"\n    program: golden/comparators/stderr-first-line.py\n";

#[test]
fn an_external_comparator_serves_the_same_question_with_its_own_identity() {
    // The built-in court (in-binary stderr comparator), in its own store.
    let work_builtin = Workdir::new("cmp-builtin");
    work_builtin.copy_canonical_tree();
    admit_reference(&work_builtin);
    run_court(&work_builtin);

    // The same court with the stderr axis served by a PYTHON comparator, in
    // a separate store (identical evidence would collide on run ids — the
    // content-addressed run does not depend on the comparator implementation,
    // which is exactly the point).
    let work_ext = Workdir::new("cmp-ext");
    work_ext.copy_canonical_tree();
    admit_reference(&work_ext);
    write_manifest(&work_ext, "manifest-py.yaml", PY_COMPARATOR);
    let out = frf(
        &work_ext,
        &[
            "--root",
            ROOT,
            "court",
            "run",
            "frf/courts/cli-malformed-input/manifest-py.yaml",
        ],
    );
    assert_success(&out, "court run (external comparator)");
    let run_ext = stdout(&out);

    // Same question, different implementation: the external comparator
    // produced the SAME residual fingerprint for the stderr divergence.
    let fp_builtin = residual_fingerprint(&work_builtin, "cli-text-0001");
    let fp_ext = residual_fingerprint(&work_ext, "cli-text-0001");
    assert_eq!(
        fp_builtin, fp_ext,
        "the external comparator must produce the same residual fingerprint"
    );

    // The comparator SEMANTIC identity is the built-in registry's: the
    // declaration has the same relation/extractor/version, so the question
    // is the same.
    let cap = capture(&work_ext, &run_ext);
    let stderr_sem = cap["comparator_semantics"]
        .as_sequence()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "stderr")
        .unwrap();
    assert_eq!(
        stderr_sem["specification_hash"].as_str().unwrap(),
        frf::comparators::semantic("stderr")
            .unwrap()
            .specification_hash,
        "the external comparator must serve the SAME specification"
    );

    // The IMPLEMENTATION identity is the program's bytes — not the frf
    // executable's — while the runner hash still names the harness.
    let program_hash = frf::host::sha256_bytes(
        &fs::read(work_ext.path("golden/comparators/stderr-first-line.py")).unwrap(),
    );
    let runner_hash = cap["provenance"]["runner"]["frf_executable_hash"]
        .as_str()
        .unwrap()
        .to_string();
    let stderr_impl = cap["provenance"]["comparator_implementations"]
        .as_sequence()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "stderr")
        .unwrap();
    assert_eq!(
        stderr_impl["implementation_hash"].as_str().unwrap(),
        program_hash,
        "the comparator implementation identity must be its program bytes"
    );
    assert_eq!(
        stderr_impl["runner_hash"].as_str().unwrap(),
        runner_hash,
        "the runner hash must name the harness that orchestrated it"
    );
    assert_ne!(
        stderr_impl["implementation_hash"].as_str().unwrap(),
        runner_hash,
        "the implementation must NOT be the frf executable for an external comparator"
    );
    // The exit axis stayed in-binary.
    let exit_impl = cap["provenance"]["comparator_implementations"]
        .as_sequence()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "exit")
        .unwrap();
    assert_eq!(
        exit_impl["implementation_hash"].as_str().unwrap(),
        runner_hash
    );
}

#[test]
fn a_new_extractor_is_a_new_question() {
    let work = Workdir::new("cmp-bytes");
    work.copy_canonical_tree();
    admit_reference(&work);
    // A byte-parity comparator: a DIFFERENT extractor, therefore a different
    // specification and a different question.
    fs::write(
        work.path("golden/comparators/stderr-bytes.py"),
        "#!/usr/bin/env python3\nimport base64, json, sys\nreq = json.load(sys.stdin)\nref = base64.b64decode(req[\"reference\"][\"stderr_base64\"])\ncand = base64.b64decode(req[\"candidate\"][\"stderr_base64\"])\nif ref == cand:\n    print(json.dumps({\"schema_version\": \"frf-comparator-response-v1\", \"equivalent\": True, \"residuals\": [], \"indeterminate\": False, \"failure\": None}, separators=(\",\", \":\")))\nelse:\n    print(json.dumps({\"schema_version\": \"frf-comparator-response-v1\", \"equivalent\": False, \"residuals\": [{\"surface\": \"stderr-bytes\", \"raw_reference\": ref.decode(\"utf-8\", \"replace\"), \"raw_candidate\": cand.decode(\"utf-8\", \"replace\")}], \"indeterminate\": False, \"failure\": None}, separators=(\",\", \":\")))\n",
    )
    .unwrap();
    write_manifest(
        &work,
        "manifest-bytes.yaml",
        "comparators:\n  - axis: stderr\n    relation: eq\n    extractor: stderr-bytes\n    relation_version: \"v1\"\n    program: golden/comparators/stderr-bytes.py\n",
    );
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "court",
            "run",
            "frf/courts/cli-malformed-input/manifest-bytes.yaml",
        ],
    );
    assert_success(&out, "court run (byte-parity comparator)");
    let run = stdout(&out);

    // Different specification hash -> different question.
    let cap = capture(&work, &run);
    let stderr_sem = cap["comparator_semantics"]
        .as_sequence()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "stderr")
        .unwrap();
    assert_ne!(
        stderr_sem["specification_hash"].as_str().unwrap(),
        frf::comparators::semantic("stderr")
            .unwrap()
            .specification_hash,
        "a different extractor must be a different specification"
    );
    // The residual follows the comparator's extractor: the surface it
    // declared, and a fingerprint different from the first-line comparator's.
    let rec: serde_yaml::Value = serde_yaml::from_str(
        &fs::read_to_string(work.path("frf/residuals/cli-text-0001.yaml")).unwrap(),
    )
    .unwrap();
    assert_eq!(rec["surface"], "stderr-bytes");
    assert!(rec["raw_reference"]
        .as_str()
        .unwrap()
        .contains("unknown directive"));
}

#[test]
fn a_failing_comparator_refuses_the_court() {
    let work = Workdir::new("cmp-fail");
    work.copy_canonical_tree();
    admit_reference(&work);
    fs::write(
        work.path("golden/comparators/failing.py"),
        "#!/usr/bin/env python3\nimport sys\nsys.exit(3)\n",
    )
    .unwrap();
    write_manifest(
        &work,
        "manifest-fail.yaml",
        "comparators:\n  - axis: stderr\n    relation: eq\n    extractor: stderr-first-line\n    relation_version: \"v1\"\n    program: golden/comparators/failing.py\n",
    );
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "court",
            "run",
            "frf/courts/cli-malformed-input/manifest-fail.yaml",
        ],
    );
    assert!(
        !out.status.success(),
        "a failing comparator must refuse the court"
    );
    assert!(
        stderr(&out).contains("comparator"),
        "the refusal must name the comparator: {}",
        stderr(&out)
    );
    assert!(!work
        .path("frf/captures")
        .join("..")
        .join("..")
        .join("x")
        .exists());
}

#[test]
fn an_indeterminate_comparator_refuses_the_court() {
    let work = Workdir::new("cmp-indet");
    work.copy_canonical_tree();
    admit_reference(&work);
    fs::write(
        work.path("golden/comparators/indeterminate.py"),
        "#!/usr/bin/env python3\nimport json\nprint(json.dumps({\"schema_version\": \"frf-comparator-response-v1\", \"equivalent\": False, \"residuals\": [], \"indeterminate\": True, \"failure\": None}, separators=(\",\", \":\")))\n",
    )
    .unwrap();
    write_manifest(
        &work,
        "manifest-indet.yaml",
        "comparators:\n  - axis: stderr\n    relation: eq\n    extractor: stderr-first-line\n    relation_version: \"v1\"\n    program: golden/comparators/indeterminate.py\n",
    );
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "court",
            "run",
            "frf/courts/cli-malformed-input/manifest-indet.yaml",
        ],
    );
    assert!(
        !out.status.success(),
        "an indeterminate comparator must refuse the court"
    );
    assert!(
        stderr(&out).contains("indeterminate"),
        "the refusal must name the inconclusive state: {}",
        stderr(&out)
    );
}

#[test]
fn a_comparator_for_an_undeclared_axis_refuses_the_court() {
    let work = Workdir::new("cmp-undeclared");
    work.copy_canonical_tree();
    admit_reference(&work);
    // stdout is not in the envelope's observables (exit, stderr).
    write_manifest(
        &work,
        "manifest-bad.yaml",
        "comparators:\n  - axis: stdout\n    relation: eq\n    extractor: stdout-first-line\n    relation_version: \"v1\"\n    program: golden/comparators/stderr-first-line.py\n",
    );
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "court",
            "run",
            "frf/courts/cli-malformed-input/manifest-bad.yaml",
        ],
    );
    assert!(
        !out.status.success(),
        "a comparator for an undeclared axis must refuse the court"
    );
    assert!(
        stderr(&out).contains("not in the envelope"),
        "the refusal must name the undeclared axis: {}",
        stderr(&out)
    );
}
