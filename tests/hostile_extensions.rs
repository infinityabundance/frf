//! The HOSTILE EXTENSION bank: deliberately malicious comparator programs
//! that violate the extension protocol in every structurally plausible way.
//! For each, the court must REFUSE (fail-closed — no conclusive evidence may
//! exist from a hostile instrument), and the refusal must be a refusal —
//! never a pass, never a silent substitution.
//!
//! The hard property under test: no hostile extension can cause conclusive
//! evidence to exist unless its invocation AND conclusion satisfy the
//! extension protocol.

use std::fs;

mod common;
use common::*;

/// A court manifest with the stderr axis served by a hostile program.
fn write_manifest(work: &Workdir, name: &str, program: &str, extra: &str) -> String {
    let manifest = format!(
        "court:\n  id: cli-malformed-input\n  question: >-\n    For malformed input in fixture family malformed-input, does the candidate\n    preserve the admitted reference's first diagnostic line?\n  falsifier: >-\n    The candidate's first diagnostic line diverges from the admitted reference.\n  authority: ref-cli-1.8.2\n  candidate:\n    name: cand-cli\n    version_or_commit: \"0.1.0\"\n    build_profile: debug\n    path: golden/candidate.sh\n  fixture:\n    id: malformed-path.conf\n    path: frf/courts/cli-malformed-input/fixtures/malformed-path.conf\n    arguments: [\"--strict\", \"{{fixture}}\"]\n  admissibility_envelope:\n    fixture_family: malformed-input\n    platforms: [\"x86_64-linux\"]\n    observables: [exit, stderr]\n    normalizers: []\n    replay_scope: single-run\ncomparators:\n  - axis: stderr\n    relation: eq\n    extractor: stderr-first-line\n    residual_classifier: text\n    relation_version: \"v2\"\n    program: {program}\n{extra}\n"
    );
    let rel = format!("frf/courts/cli-malformed-input/{name}");
    fs::write(work.path(&rel), manifest).unwrap();
    rel
}

fn write_program(work: &Workdir, rel: &str, contents: &str) {
    let path = work.path(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, contents).unwrap();
    set_exec(&path);
}

/// The hostile comparator reads the canonical request and emits a response
/// under its own control. The request_id is the SHA-256 of the exact request
/// bytes (the protocol rule); the responses are emitted canonical unless the
/// violation IS the non-canonicity.
const BAD_REQUEST_ID: &str = "#!/usr/bin/env python3\nimport sys, json, hashlib\nraw = sys.stdin.buffer.read()\nreq = json.loads(raw)\njson.dump({\"schema_version\": \"frf-comparator-response-v2\", \"request_id\": \"0\" * 64, \"equivalent\": True}, sys.stdout, sort_keys=True, separators=(\",\", \":\"))\n";

const NONCANONICAL: &str = "#!/usr/bin/env python3\nimport sys, json, hashlib\nraw = sys.stdin.buffer.read()\nreq = json.loads(raw)\nrequest_id = hashlib.sha256(raw).hexdigest()\nresp = {\"schema_version\": \"frf-comparator-response-v2\", \"request_id\": request_id, \"equivalent\": True}\nprint(json.dumps(resp, indent=2))\n";

const DUPLICATE_KEYS: &str = "#!/usr/bin/env python3\nimport sys\n# A response with a duplicated property name (RFC 8785 I-JSON forbids it).\nprint('{\"schema_version\": \"frf-comparator-response-v2\", \"schema_version\": \"frf-comparator-response-v2\", \"request_id\": \"x\"}')\n";

const INDETERMINATE: &str = "#!/usr/bin/env python3\nimport sys, json, hashlib\nraw = sys.stdin.buffer.read()\nreq = json.loads(raw)\nrequest_id = hashlib.sha256(raw).hexdigest()\njson.dump({\"schema_version\": \"frf-comparator-response-v2\", \"request_id\": request_id, \"indeterminate\": True}, sys.stdout, sort_keys=True, separators=(\",\", \":\"))\n";

const FAILURE: &str = "#!/usr/bin/env python3\nimport sys, json, hashlib\nraw = sys.stdin.buffer.read()\nreq = json.loads(raw)\nrequest_id = hashlib.sha256(raw).hexdigest()\njson.dump({\"schema_version\": \"frf-comparator-response-v2\", \"request_id\": request_id, \"failure\": \"my lens is broken\"}, sys.stdout, sort_keys=True, separators=(\",\", \":\"))\n";

const EQUIVALENT_WITH_RESIDUALS: &str = "#!/usr/bin/env python3\nimport sys, json, hashlib\nraw = sys.stdin.buffer.read()\nreq = json.loads(raw)\nrequest_id = hashlib.sha256(raw).hexdigest()\njson.dump({\"schema_version\": \"frf-comparator-response-v2\", \"request_id\": request_id, \"equivalent\": True, \"residuals\": [{\"surface\": \"stderr\", \"raw_reference\": \"a\", \"raw_candidate\": \"b\"}]}, sys.stdout, sort_keys=True, separators=(\",\", \":\"))\n";

const DIVERGENT_NO_RESIDUAL: &str = "#!/usr/bin/env python3\nimport sys, json, hashlib\nraw = sys.stdin.buffer.read()\nreq = json.loads(raw)\nrequest_id = hashlib.sha256(raw).hexdigest()\njson.dump({\"schema_version\": \"frf-comparator-response-v2\", \"request_id\": request_id, \"equivalent\": False}, sys.stdout, sort_keys=True, separators=(\",\", \":\"))\n";

const EQUAL_RAW_DIVERGENT: &str = "#!/usr/bin/env python3\nimport sys, json, hashlib\nraw = sys.stdin.buffer.read()\nreq = json.loads(raw)\nrequest_id = hashlib.sha256(raw).hexdigest()\njson.dump({\"schema_version\": \"frf-comparator-response-v2\", \"request_id\": request_id, \"equivalent\": False, \"residuals\": [{\"surface\": \"stderr\", \"raw_reference\": \"identical\", \"raw_candidate\": \"identical\"}]}, sys.stdout, sort_keys=True, separators=(\",\", \":\"))\n";

const CRASH: &str = "#!/usr/bin/env python3\nimport sys\nexit(7)\n";

const HANG: &str = "#!/usr/bin/env python3\nimport time\ntime.sleep(30)\n";

const FLOOD: &str = "#!/usr/bin/env python3\nimport sys\nsys.stdout.write('x' * 500000)\n";

const SIGSTOP: &str =
    "#!/usr/bin/env python3\nimport os, signal\nos.kill(os.getpid(), signal.SIGSTOP)\n";

fn setup(work: &Workdir, program_rel: &str, contents: &str, extra: &str) -> String {
    work.copy_canonical_tree();
    write_program(work, program_rel, contents);
    admit_reference(work);
    write_manifest(work, "manifest-hostile.yaml", program_rel, extra)
}

fn run_court_refused(work: &Workdir, manifest: &str) -> String {
    let out = frf(work, &["--root", ROOT, "court", "run", manifest]);
    assert!(
        !out.status.success(),
        "a hostile comparator MUST refuse the court: {}",
        stderr(&out)
    );
    stderr(&out)
}

#[test]
fn a_comparator_answering_another_request_is_refused() {
    let work = Workdir::new("hostile-wrong-request");
    let m = setup(&work, "golden/comparators/hostile.py", BAD_REQUEST_ID, "");
    let err = run_court_refused(&work, &m);
    assert!(
        err.contains("request"),
        "must name the request binding: {err}"
    );
}

#[test]
fn a_noncanonical_comparator_response_is_refused() {
    let work = Workdir::new("hostile-noncanonical");
    let m = setup(&work, "golden/comparators/hostile.py", NONCANONICAL, "");
    let err = run_court_refused(&work, &m);
    assert!(
        err.contains("canonical"),
        "must name the canonical-JSON rule: {err}"
    );
}

#[test]
fn a_duplicate_key_comparator_response_is_refused() {
    let work = Workdir::new("hostile-duplicate-key");
    let m = setup(&work, "golden/comparators/hostile.py", DUPLICATE_KEYS, "");
    let err = run_court_refused(&work, &m);
    assert!(
        err.contains("strict") || err.contains("duplicate"),
        "must refuse: {err}"
    );
}

#[test]
fn an_indeterminate_comparator_is_refused() {
    let work = Workdir::new("hostile-indeterminate");
    let m = setup(&work, "golden/comparators/hostile.py", INDETERMINATE, "");
    let err = run_court_refused(&work, &m);
    assert!(
        err.contains("indeterminate")
            || err.contains("inconclusive")
            || err.contains("cannot parse"),
        "must refuse the inconclusive verdict: {err}"
    );
}

#[test]
fn a_failing_comparator_is_refused() {
    let work = Workdir::new("hostile-failure");
    let m = setup(&work, "golden/comparators/hostile.py", FAILURE, "");
    let err = run_court_refused(&work, &m);
    assert!(
        err.contains("failure") || err.contains("cannot parse"),
        "must surface the failure: {err}"
    );
}

#[test]
fn a_self_contradictory_comparator_is_refused() {
    // Equivalent-with-residuals: the response claims both states.
    let work = Workdir::new("hostile-equiv-residual");
    let m = setup(
        &work,
        "golden/comparators/hostile.py",
        EQUIVALENT_WITH_RESIDUALS,
        "",
    );
    let err = run_court_refused(&work, &m);
    assert!(
        err.contains("contradicts"),
        "must name the contradiction: {err}"
    );

    // Divergent-without-a-residual: claims divergence but names nothing.
    let work2 = Workdir::new("hostile-divergent-nil");
    let m2 = setup(
        &work2,
        "golden/comparators/hostile.py",
        DIVERGENT_NO_RESIDUAL,
        "",
    );
    let err2 = run_court_refused(&work2, &m2);
    assert!(
        err2.contains("contradicts"),
        "must name the contradiction: {err2}"
    );

    // Divergent on EQUAL raw values: the residual is not a divergence.
    let work3 = Workdir::new("hostile-equal-raw");
    let m3 = setup(
        &work3,
        "golden/comparators/hostile.py",
        EQUAL_RAW_DIVERGENT,
        "",
    );
    let err3 = run_court_refused(&work3, &m3);
    assert!(
        err3.contains("contradicts"),
        "must name the contradiction: {err3}"
    );
}

#[test]
fn a_crashing_comparator_is_refused() {
    let work = Workdir::new("hostile-crash");
    let m = setup(&work, "golden/comparators/hostile.py", CRASH, "");
    let err = run_court_refused(&work, &m);
    assert!(
        err.contains("failed comparator"),
        "a crashing comparator must refuse: {err}"
    );
}

#[test]
fn a_hanging_comparator_is_refused_by_the_invocation_timeout() {
    let work = Workdir::new("hostile-hang");
    let m = setup(&work, "golden/comparators/hostile.py", HANG, "");
    // The extension invocation runs under the side profile's bounds; a short
    // timeout makes the hang fail fast.
    let out = frf_env(
        &work,
        &["--root", ROOT, "court", "run", &m],
        &[("FRF_EXEC_TIMEOUT_MS", "1000")],
    );
    assert!(
        !out.status.success(),
        "a hanging comparator MUST be refused: {}",
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("timeout") || stderr(&out).contains("timed out"),
        "the refusal must name the timeout: {}",
        stderr(&out)
    );
}

#[test]
fn a_stream_flooding_comparator_is_refused_by_the_stream_cap() {
    let work = Workdir::new("hostile-flood");
    let m = setup(&work, "golden/comparators/hostile.py", FLOOD, "");
    let out = frf_env(
        &work,
        &["--root", ROOT, "court", "run", &m],
        &[("FRF_EXEC_MAX_BYTES", "1024")],
    );
    assert!(
        !out.status.success(),
        "a flooding comparator MUST be refused: {}",
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("overflow") || stderr(&out).contains("cap"),
        "the refusal must name the overflow: {}",
        stderr(&out)
    );
}

#[test]
fn a_sigstopping_comparator_is_refused_by_the_timeout() {
    let work = Workdir::new("hostile-sigstop");
    let m = setup(&work, "golden/comparators/hostile.py", SIGSTOP, "");
    let out = frf_env(
        &work,
        &["--root", ROOT, "court", "run", &m],
        &[("FRF_EXEC_TIMEOUT_MS", "1000")],
    );
    assert!(
        !out.status.success(),
        "a SIGSTOPped comparator MUST be refused: {}",
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("timeout") || stderr(&out).contains("timed out"),
        "the refusal must name the timeout: {}",
        stderr(&out)
    );
}
