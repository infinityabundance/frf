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
//! - Observable axes are PROTOCOL IDENTIFIERS: a court can declare a wholly
//!   new axis (`wire`) served only by an external comparator, producing
//!   residuals of the comparator's declared kind.
//! - The response must cryptographically name the request it answers
//!   (`request_id`); a response that does not is refused.
//! - The capture records the comparator's implementation identity (its
//!   program bytes) and its ARTIFACT identity; the invocation + result
//!   evidence is preserved under the run and verifies.
//! - A different extractor is a different question (different specification
//!   hash, different semantic identity).
//! - A failing, indeterminate, or undeclared comparator refuses the court
//!   (fail closed: no evidence is recorded from a malfunctioning instrument).
//! - REPLAY re-invokes the exact snapshotted comparator implementation, and
//!   requires the request to rederive and the outcome to reproduce.

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

const PY_COMPARATOR: &str = "comparators:\n  - axis: stderr\n    relation: eq\n    extractor: stderr-first-line\n    residual_classifier: text\n    relation_version: \"v2\"\n    program: golden/comparators/stderr-first-line.py\n";

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
    // declaration has the same relation/extractor/classifier/version, so the
    // question is the same.
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
    // The artifact identity is recorded (snapshot path + interpreter), so
    // replay can re-invoke the exact instrument.
    assert!(
        stderr_impl["artifact"]["sha256"].as_str().unwrap() == program_hash,
        "the comparator artifact must be the snapshotted program bytes"
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
    assert!(
        exit_impl.get("artifact").is_none(),
        "an in-binary comparator must not carry an artifact"
    );

    // The invocation evidence is preserved under the run and verifies
    // (identity rederives, request/response documents hash, the response
    // names its request, the result binds the residuals).
    let evidence_dir = work_ext.path(&format!("frf/captures/{run_ext}/comparator/stderr"));
    for f in [
        "request.json",
        "response.json",
        "invocation.json",
        "result.json",
    ] {
        assert!(
            evidence_dir.join(f).is_file(),
            "missing comparator evidence {f}"
        );
    }
    let invocation: frf::model::ComparatorInvocation =
        serde_json::from_str(&fs::read_to_string(evidence_dir.join("invocation.json")).unwrap())
            .unwrap();
    assert_eq!(invocation.axis.as_str(), "stderr");
    let rederived = frf::semantics::comparator_invocation_identity(
        &frf::semantics::ComparatorInvocationContent {
            axis: &invocation.axis,
            request_cid: &invocation.request_cid,
            comparator_semantic_cid: &invocation.comparator_semantic_cid,
            comparator_implementation_artifact: &invocation.comparator_implementation_artifact,
            execution_provenance: &invocation.execution_provenance,
        },
    )
    .unwrap();
    assert_eq!(rederived, invocation.invocation_id);
    let result: frf::model::ComparatorResult =
        serde_json::from_str(&fs::read_to_string(evidence_dir.join("result.json")).unwrap())
            .unwrap();
    assert_eq!(result.outcome, "divergent");
    assert_eq!(
        result.residual_observation_ids,
        vec!["cli-text-0001".to_string()]
    );
    assert_eq!(result.request_cid, invocation.request_cid);
    // The preserved response names the exact request it answers.
    let response: frf::model::ComparatorResponse =
        serde_json::from_str(&fs::read_to_string(evidence_dir.join("response.json")).unwrap())
            .unwrap();
    assert_eq!(response.request_id, invocation.request_cid);

    // REPLAY re-invokes the exact snapshotted comparator and requires the
    // outcome to reproduce.
    let out = frf(&work_ext, &["--root", ROOT, "replay", &run_ext]);
    assert_success(&out, "replay (external comparator)");
    assert!(stdout(&out).contains("reproduced"), "{}", stdout(&out));
}

#[test]
fn a_new_axis_is_a_protocol_identifier() {
    // Observable-pluggability: a court may declare a wholly NEW axis
    // (`wire`), served ONLY by an external comparator, producing residuals
    // of the comparator's declared kind. The core never learns what "wire"
    // means.
    let work = Workdir::new("cmp-wire");
    work.copy_canonical_tree();
    admit_reference(&work);
    // A wire comparator: compares the stderr BYTES of the two sides.
    fs::write(
        work.path("golden/comparators/wire.py"),
        "#!/usr/bin/env python3\nimport base64, hashlib, json, sys\nraw = sys.stdin.buffer.read()\nreq = json.loads(raw.decode(\"utf-8\"))\nrequest_id = hashlib.sha256(raw).hexdigest()\nref = base64.b64decode(req[\"reference\"][\"stderr_base64\"])\ncand = base64.b64decode(req[\"candidate\"][\"stderr_base64\"])\nbase = {\"schema_version\": \"frf-comparator-response-v2\", \"request_id\": request_id, \"indeterminate\": False, \"failure\": None}\nif ref == cand:\n    print(json.dumps({**base, \"equivalent\": True, \"residuals\": []}, separators=(\",\", \":\")))\nelse:\n    print(json.dumps({**base, \"equivalent\": False, \"residuals\": [{\"surface\": \"stderr-bytes\", \"raw_reference\": ref.decode(\"utf-8\", \"replace\"), \"raw_candidate\": cand.decode(\"utf-8\", \"replace\")}]}, separators=(\",\", \":\")))\n",
    )
    .unwrap();
    let manifest = "court:\n  id: cli-wire-court\n  question: >-\n    For malformed input in fixture family malformed-input, does the candidate\n    preserve the admitted reference's wire stream?\n  falsifier: >-\n    The candidate's wire stream diverges from the admitted reference.\n  authority: ref-cli-1.8.2\n  candidate:\n    name: cand-cli\n    version_or_commit: \"0.1.0\"\n    build_profile: debug\n    path: golden/candidate.sh\n  fixture:\n    id: malformed-path.conf\n    path: frf/courts/cli-malformed-input/fixtures/malformed-path.conf\n    arguments: [\"--strict\", \"{fixture}\"]\n  admissibility_envelope:\n    fixture_family: malformed-input\n    platforms: [\"x86_64-linux\"]\n    observables: [wire]\n    normalizers: []\n    replay_scope: single-run\ncomparators:\n  - axis: wire\n    relation: eq\n    extractor: stderr-bytes\n    residual_classifier: wire\n    relation_version: \"v1\"\n    program: golden/comparators/wire.py\n"
    .to_string();
    fs::write(
        work.path("frf/courts/cli-malformed-input/manifest-wire.yaml"),
        manifest,
    )
    .unwrap();
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "court",
            "run",
            "frf/courts/cli-malformed-input/manifest-wire.yaml",
        ],
    );
    assert_success(&out, "court run (wire axis)");
    let run = stdout(&out);

    // The residual: kind `wire`, id `cli-wire-0001`, surface from the
    // comparator's extractor, and the honest generic κ row (no fabricated
    // minimizer target).
    let rec: serde_yaml::Value = serde_yaml::from_str(
        &fs::read_to_string(work.path("frf/residuals/cli-wire-0001.yaml")).unwrap(),
    )
    .unwrap();
    assert_eq!(rec["axis"], "wire");
    assert_eq!(rec["kind"], "wire");
    assert_eq!(rec["surface"], "stderr-bytes");
    let token: serde_yaml::Value = serde_yaml::from_str(
        &fs::read_to_string(work.path("frf/residuals/cli-wire-0001.token.yaml")).unwrap(),
    )
    .unwrap();
    assert_eq!(token["token"], "wire/wire-divergence/observed/open");
    assert_eq!(token["next_court"], "none");
    assert_eq!(
        token["blocks_claims"][0], "malformed-input wire parity",
        "the token must block exactly the wire-axis claim phrase"
    );

    // The claim compiler refuses (the open residual blocks the wire axis),
    // naming the axis.
    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &run]);
    assert_success(&out, "receipt emit (wire axis)");
    let receipt = stdout(&out);
    let out = frf(&work, &["--root", ROOT, "claim", "compile", &receipt]);
    assert!(
        !out.status.success(),
        "an open wire residual must block the claim"
    );
    assert!(
        stderr(&out).contains("wire"),
        "the refusal must name the wire axis: {}",
        stderr(&out)
    );

    // Replay re-invokes the wire comparator and reproduces.
    let out = frf(&work, &["--root", ROOT, "replay", &run]);
    assert_success(&out, "replay (wire axis)");
}

#[test]
fn a_response_that_does_not_name_its_request_is_refused() {
    let work = Workdir::new("cmp-noreq");
    work.copy_canonical_tree();
    admit_reference(&work);
    // A comparator that answers WITHOUT echoing the request_id it received:
    // the court must refuse — the response does not cryptographically say
    // which request it answers.
    fs::write(
        work.path("golden/comparators/no-request-id.py"),
        "#!/usr/bin/env python3\nimport json, sys\nsys.stdin.buffer.read()\nprint(json.dumps({\"schema_version\": \"frf-comparator-response-v2\", \"request_id\": \"0\" * 64, \"equivalent\": True, \"residuals\": [], \"indeterminate\": False, \"failure\": None}, separators=(\",\", \":\")))\n",
    )
    .unwrap();
    write_manifest(
        &work,
        "manifest-noreq.yaml",
        "comparators:\n  - axis: stderr\n    relation: eq\n    extractor: stderr-first-line\n    residual_classifier: text\n    relation_version: \"v2\"\n    program: golden/comparators/no-request-id.py\n",
    );
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "court",
            "run",
            "frf/courts/cli-malformed-input/manifest-noreq.yaml",
        ],
    );
    assert!(
        !out.status.success(),
        "a response that does not name its request must refuse the court"
    );
    assert!(
        stderr(&out).contains("names request"),
        "the refusal must name the binding: {}",
        stderr(&out)
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
        "#!/usr/bin/env python3\nimport base64, hashlib, json, sys\nraw = sys.stdin.buffer.read()\nreq = json.loads(raw.decode(\"utf-8\"))\nrequest_id = hashlib.sha256(raw).hexdigest()\nref = base64.b64decode(req[\"reference\"][\"stderr_base64\"])\ncand = base64.b64decode(req[\"candidate\"][\"stderr_base64\"])\nbase = {\"schema_version\": \"frf-comparator-response-v2\", \"request_id\": request_id, \"indeterminate\": False, \"failure\": None}\nif ref == cand:\n    print(json.dumps({**base, \"equivalent\": True, \"residuals\": []}, separators=(\",\", \":\")))\nelse:\n    print(json.dumps({**base, \"equivalent\": False, \"residuals\": [{\"surface\": \"stderr-bytes\", \"raw_reference\": ref.decode(\"utf-8\", \"replace\"), \"raw_candidate\": cand.decode(\"utf-8\", \"replace\")}]}, separators=(\",\", \":\")))\n",
    )
    .unwrap();
    write_manifest(
        &work,
        "manifest-bytes.yaml",
        "comparators:\n  - axis: stderr\n    relation: eq\n    extractor: stderr-bytes\n    residual_classifier: text\n    relation_version: \"v1\"\n    program: golden/comparators/stderr-bytes.py\n",
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
        "comparators:\n  - axis: stderr\n    relation: eq\n    extractor: stderr-first-line\n    residual_classifier: text\n    relation_version: \"v2\"\n    program: golden/comparators/failing.py\n",
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
}

#[test]
fn an_indeterminate_comparator_refuses_the_court() {
    let work = Workdir::new("cmp-indet");
    work.copy_canonical_tree();
    admit_reference(&work);
    fs::write(
        work.path("golden/comparators/indeterminate.py"),
        "#!/usr/bin/env python3\nimport hashlib, json, sys\nraw = sys.stdin.buffer.read()\nprint(json.dumps({\"schema_version\": \"frf-comparator-response-v2\", \"request_id\": hashlib.sha256(raw).hexdigest(), \"equivalent\": False, \"residuals\": [], \"indeterminate\": True, \"failure\": None}, separators=(\",\", \":\")))\n",
    )
    .unwrap();
    write_manifest(
        &work,
        "manifest-indet.yaml",
        "comparators:\n  - axis: stderr\n    relation: eq\n    extractor: stderr-first-line\n    residual_classifier: text\n    relation_version: \"v2\"\n    program: golden/comparators/indeterminate.py\n",
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
        "comparators:\n  - axis: stdout\n    relation: eq\n    extractor: stdout-first-line\n    residual_classifier: text\n    relation_version: \"v2\"\n    program: golden/comparators/stderr-first-line.py\n",
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

#[test]
fn a_declared_axis_with_no_comparator_refuses_the_court() {
    let work = Workdir::new("cmp-unserved");
    work.copy_canonical_tree();
    admit_reference(&work);
    // `wire` is declared in the envelope but served by no comparator (and is
    // not a built-in): the court must refuse — an observable with no
    // comparator cannot be compared.
    let manifest = "court:\n  id: cli-malformed-input\n  question: q\n  falsifier: f\n  authority: ref-cli-1.8.2\n  candidate:\n    name: cand-cli\n    version_or_commit: \"0.1.0\"\n    build_profile: debug\n    path: golden/candidate.sh\n  fixture:\n    id: malformed-path.conf\n    path: frf/courts/cli-malformed-input/fixtures/malformed-path.conf\n    arguments: [\"--strict\", \"{fixture}\"]\n  admissibility_envelope:\n    fixture_family: malformed-input\n    platforms: [\"x86_64-linux\"]\n    observables: [exit, wire]\n    normalizers: []\n    replay_scope: single-run\n"
    .to_string();
    fs::write(
        work.path("frf/courts/cli-malformed-input/manifest-unserved.yaml"),
        manifest,
    )
    .unwrap();
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "court",
            "run",
            "frf/courts/cli-malformed-input/manifest-unserved.yaml",
        ],
    );
    assert!(
        !out.status.success(),
        "an observable with no comparator must refuse the court"
    );
    assert!(
        stderr(&out).contains("no comparator serves observable axis"),
        "the refusal must name the unserved axis: {}",
        stderr(&out)
    );
}
