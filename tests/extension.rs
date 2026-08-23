//! The extension protocols (Phase 10): normalizers, capture adapters,
//! external minimizers, and witnesses are PROTOCOL PARTICIPANTS, not Rust
//! code — any program that speaks the canonical stdin/stdout JSON protocol
//! can build the comparison surface, capture a domain observation, reduce a
//! fixture, or attest a subject. The core runs observables without knowing
//! what stdout, packets, or filesystem trees are.
//!
//! Every protocol is fail-closed: wrong schema version, unparseable JSON,
//! non-zero exit, a response that does not name its request, indeterminate,
//! or an explicit failure is a refusal — never a silent default. And every
//! participant's program bytes are sealed BEFORE it runs (the same
//! ArtifactIdentity discipline as the artifacts), so the exact instrument
//! that observed is part of the evidence graph, re-invoked by replay, and
//! carried by the bundle closure.

use frf::model::*;
use frf::store::Store;
use std::fs;
use std::path::PathBuf;

mod common;

use common::*;

fn copy_into(work: &Workdir, rel: &str) {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    let dst = work.path(rel);
    fs::create_dir_all(dst.parent().unwrap()).unwrap();
    fs::copy(&src, &dst).unwrap();
}

/// Write a protocol program into the workdir (creating parents) and seal it
/// executable.
fn write_program(work: &Workdir, rel: &str, contents: &str) {
    let path = work.path(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, contents).unwrap();
    set_exec(&path);
}

/// The capture YAML of a run, as a value.
fn capture(work: &Workdir, run: &str) -> serde_json::Value {
    serde_json::from_str(
        &fs::read_to_string(work.path(&format!("frf/captures/{run}/capture.json"))).unwrap(),
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// The normalizer extension protocol
// ---------------------------------------------------------------------------

#[test]
fn a_normalizer_builds_the_comparison_surface() {
    // The reference's diagnostic carries trailing whitespace; the candidate's
    // is identical except for it. The RAW first lines diverge; the NORMALIZED
    // surface (trailing whitespace trimmed by the declared normalizer) is
    // equivalent — the court passes ONLY because the normalizer applies, and
    // the raw streams survive as the normalizer request evidence.
    let work = Workdir::new("ext-norm");
    work.copy_canonical_tree();
    copy_into(&work, "golden/ref-ws.sh");
    copy_into(&work, "golden/cand-ws.sh");
    copy_into(&work, "golden/normalizers/trim-trailing-ws.py");
    copy_into(&work, "frf/courts/cli-normalized/manifest.yaml");
    // Admit the whitespace-carrying reference.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "authority",
            "admit",
            "golden/ref-ws.sh",
            "--name",
            "ref-ws",
            "--version",
            "1.0",
        ],
    );
    assert_success(&out, "ref-ws authority admit");

    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "court",
            "run",
            "frf/courts/cli-normalized/manifest.yaml",
        ],
    );
    assert_success(&out, "normalized court run");
    let run = stdout(&out);
    assert!(run.starts_with("run-cli-normalized-"), "run id: {run}");

    // The capture binds the normalizer SEMANTIC + IMPLEMENTATION, and the
    // run observed NO residual (the normalized surface is equivalent).
    let cap = capture(&work, &run);
    assert_eq!(
        cap["normalizer_semantics"][0]["id"], "trim-trailing-ws",
        "the capture binds the normalizer semantic"
    );
    assert_eq!(cap["normalizer_semantics"][0]["applies_to"], "stderr");
    assert_eq!(
        cap["provenance"]["normalizer_implementations"][0]["id"],
        "trim-trailing-ws"
    );
    assert!(
        cap["provenance"]["normalizer_implementations"][0]["artifact"]["sha256"].is_string(),
        "the normalizer's program bytes are the implementation identity"
    );
    assert_eq!(
        cap["residuals"].as_array().unwrap().len(),
        0,
        "the normalized surface is equivalent: no residual"
    );

    // The normalizer evidence is preserved under the run: the canonical
    // request (the RAW streams, base64), the response (the NORMALIZED
    // streams), and the content-addressed invocation + result records.
    let ev = work.path(&format!(
        "frf/captures/{run}/normalizer/trim-trailing-ws/reference"
    ));
    for f in [
        "request.json",
        "response.json",
        "invocation.json",
        "result.json",
    ] {
        assert!(ev.join(f).is_file(), "missing normalizer evidence {f}");
    }
    let request: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(ev.join("request.json")).unwrap()).unwrap();
    assert_eq!(request["schema_version"], "frf-normalizer-request-v1");
    // The RAW stderr carried the trailing whitespace...
    let raw_stderr = frf::ext::unb64(request["stderr_base64"].as_str().unwrap(), "test").unwrap();
    assert!(
        raw_stderr.windows(3).any(|w| w == b"   "),
        "the raw stderr carries trailing whitespace"
    );
    let response: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(ev.join("response.json")).unwrap()).unwrap();
    // The response cryptographically names the exact request it answers: its
    // `request_id` is the SHA-256 of the preserved request document.
    let request_bytes = fs::read(ev.join("request.json")).unwrap();
    assert_eq!(
        response["request_id"].as_str().unwrap(),
        frf::host::sha256_bytes(&request_bytes)
    );
    // ...and the normalized stderr does not.
    let norm_stderr = frf::ext::unb64(response["stderr_base64"].as_str().unwrap(), "test").unwrap();
    assert!(
        !norm_stderr.windows(3).any(|w| w == b"   "),
        "the normalized stderr has the trailing whitespace trimmed"
    );
    // The captured COMPARED streams are the normalized ones: the side file
    // must not carry the whitespace.
    let side_stderr = fs::read(work.path(&format!("frf/captures/{run}/reference.stderr"))).unwrap();
    assert!(
        !side_stderr.windows(3).any(|w| w == b"   "),
        "the compared side file is the normalized stream"
    );

    // The verified loader rehashes the normalizer chain end to end: the
    // capture's compared hashes derive from the recorded evidence.
    let store = Store::new(work.path(ROOT));
    let verified = frf::verify::load_capture_verified(&store, &run).unwrap();
    assert_eq!(verified.capture.normalizer_semantics.len(), 1);

    // Replay re-invokes the EXACT snapshotted normalizer; the request must
    // rederive to the recorded request_cid (exact replay).
    let out = frf(
        &work,
        &["--root", ROOT, "replay", &run, "--policy", "exact"],
    );
    assert_success(&out, "normalized replay");
    assert!(stdout(&out).contains("reproduced"), "{}", stdout(&out));
}

#[test]
fn a_normalizer_that_moves_what_it_is_not_declared_to_move_is_refused() {
    // A normalizer declared `applies_to: stderr` that changes stdout moves
    // what it was not declared to move: the court refuses — the evidence
    // would be a lie about the comparison surface.
    let work = Workdir::new("ext-norm-lie");
    work.copy_canonical_tree();
    admit_reference(&work);
    // The side's stdout and stderr DIFFER (the parser echoes ok lines to
    // stdout); the lying normalizer rewrites stdout despite the declaration.
    write_program(
        &work,
        "golden/normalizers/liar.py",
        "#!/usr/bin/env python3\n\
import base64, hashlib, json, sys\n\
raw = sys.stdin.buffer.read()\n\
req = json.loads(raw.decode(\"utf-8\"))\n\
request_id = hashlib.sha256(raw).hexdigest()\n\
stdout = base64.b64decode(req[\"stdout_base64\"])\n\
stderr = base64.b64decode(req[\"stderr_base64\"])\n\
response = {\n\
    \"schema_version\": \"frf-normalizer-response-v1\",\n\
    \"request_id\": request_id,\n\
    \"stdout_base64\": base64.b64encode(b\"TAMPERED\\n\").decode(\"ascii\"),\n\
    \"stderr_base64\": base64.b64encode(stderr).decode(\"ascii\"),\n\
    \"indeterminate\": False,\n\
    \"failure\": None,\n\
}\n\
json.dump(response, sys.stdout, sort_keys=True, separators=(\",\", \":\"))\n\n",
    );
    let manifest = fs::read_to_string(work.path(MANIFEST)).unwrap();
    let variant = format!(
        "{manifest}\nnormalizers:\n  - id: liar\n    relation: rewrite-stdout\n    applies_to: stderr\n    relation_version: \"v1\"\n    program: golden/normalizers/liar.py\n"
    );
    // The envelope must APPLY the liar.
    let variant = variant.replace("normalizers: []", "normalizers: [liar]");
    let m = work.path("frf/courts/variant.yaml");
    fs::write(&m, variant).unwrap();

    let out = frf(
        &work,
        &["--root", ROOT, "court", "run", "frf/courts/variant.yaml"],
    );
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("declared to normalize stderr but changed stdout"),
        "stderr: {}",
        stderr(&out)
    );
}

// ---------------------------------------------------------------------------
// The capture-adapter extension protocol
// ---------------------------------------------------------------------------

/// A reference emitting a deterministic 4-byte DNS-ish packet on stdout.
const WIRE_REF: &str = "#!/bin/sh\nprintf '\\001\\002\\003\\004'\n";
/// A candidate emitting a DIFFERENT packet (one byte differs).
const WIRE_CAND: &str = "#!/bin/sh\nprintf '\\001\\002\\003\\377'\n";

const WIRE_ADAPTER: &str = "#!/usr/bin/env python3\n\
import base64, hashlib, json, sys\n\
raw = sys.stdin.buffer.read()\n\
req = json.loads(raw.decode(\"utf-8\"))\n\
request_id = hashlib.sha256(raw).hexdigest()\n\
payload = base64.b64decode(req[\"outcome\"][\"stdout_base64\"])\n\
observation = {\n\
    \"format\": \"dns-wire\",\n\
    \"payload_base64\": base64.b64encode(payload).decode(\"ascii\"),\n\
    \"content_sha256\": hashlib.sha256(payload).hexdigest(),\n\
}\n\
response = {\n\
    \"schema_version\": \"frf-capture-response-v1\",\n\
    \"request_id\": request_id,\n\
    \"observation\": observation,\n\
    \"indeterminate\": False,\n\
    \"failure\": None,\n\
}\n\
json.dump(response, sys.stdout, sort_keys=True, separators=(\",\", \":\"))\n\n";

const WIRE_COMPARATOR: &str = "#!/usr/bin/env python3\nimport hashlib, json, sys\nraw = sys.stdin.buffer.read()\nreq = json.loads(raw.decode(\"utf-8\"))\nassert req[\"schema_version\"] == \"frf-comparator-request-v4\", req\nrequest_id = hashlib.sha256(raw).hexdigest()\nref = req[\"reference\"][\"adapted\"][\"payload_base64\"]\ncand = req[\"candidate\"][\"adapted\"][\"payload_base64\"]\nbase = {\"schema_version\": \"frf-comparator-response-v2\", \"request_id\": request_id, \"indeterminate\": False, \"failure\": None}\nif ref == cand:\n    sys.stdout.write(json.dumps({**base, \"equivalent\": True, \"residuals\": []}, sort_keys=True, separators=(\",\", \":\")))\nelse:\n    sys.stdout.write(json.dumps({**base, \"equivalent\": False, \"residuals\": [{\"surface\": \"dns-wire-bytes\", \"raw_reference\": ref, \"raw_candidate\": cand}]}, sort_keys=True, separators=(\",\", \":\")))\n";

#[test]
fn a_capture_adapter_serves_a_domain_axis() {
    // The core has NO built-in capture for a wire axis: the adapter captures
    // the observation (the side's stdout, as a base64 payload), and the
    // external comparator compares the ADAPTED payloads. The core never
    // learns what a packet is.
    let work = Workdir::new("ext-adapter");
    work.copy_canonical_tree();
    write_program(&work, "golden/wire-ref.sh", WIRE_REF);
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "authority",
            "admit",
            "golden/wire-ref.sh",
            "--name",
            "wire-ref",
            "--version",
            "1.0",
        ],
    );
    assert_success(&out, "wire authority admit");
    write_program(&work, "golden/wire-cand.sh", WIRE_CAND);
    write_program(&work, "golden/adapters/wire-dump.py", WIRE_ADAPTER);
    write_program(&work, "golden/comparators/wire-compare.py", WIRE_COMPARATOR);
    fs::create_dir_all(work.path("frf/courts/wire-adapter/fixtures")).unwrap();
    fs::write(
        work.path("frf/courts/wire-adapter/fixtures/packet.conf"),
        b"packet: 4\n",
    )
    .unwrap();
    let manifest = "court:\n  id: wire-adapter\n  question: >-\n    Does the candidate emit the same wire packet as the reference?\n  falsifier: >-\n    The candidate's packet diverges.\n  authority: wire-ref-1.0\n  candidate:\n    name: wire-cand\n    version_or_commit: \"0.1.0\"\n    build_profile: debug\n    path: golden/wire-cand.sh\n  fixture:\n    id: packet.conf\n    path: frf/courts/wire-adapter/fixtures/packet.conf\n    arguments: [\"{fixture}\"]\n  admissibility_envelope:\n    fixture_family: wire-encode\n    platforms: [\"x86_64-linux\"]\n    observables: [dns.wire]\n    normalizers: []\n    replay_scope: single-run\ncomparators:\n  - axis: dns.wire\n    relation: eq\n    extractor: dns-wire-payload\n    residual_classifier: wire\n    relation_version: \"v1\"\n    program: golden/comparators/wire-compare.py\ncapture_adapters:\n  - axis: dns.wire\n    relation: dns-wire-dump\n    relation_version: \"v1\"\n    program: golden/adapters/wire-dump.py\n";
    fs::create_dir_all(work.path("frf/courts/wire-adapter")).unwrap();
    fs::write(work.path("frf/courts/wire-adapter/manifest.yaml"), manifest).unwrap();

    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "court",
            "run",
            "frf/courts/wire-adapter/manifest.yaml",
        ],
    );
    assert_success(&out, "adapted court run");
    let run = stdout(&out);
    assert!(run.starts_with("run-wire-adapter-"), "run id: {run}");

    // The capture carries the adapted observations and the residual on the
    // dns.wire axis.
    let cap = capture(&work, &run);
    assert_eq!(cap["adapter_semantics"][0]["id"], "dns.wire");
    assert_eq!(
        cap["reference"]["adapted"]["format"], "dns-wire",
        "the side capture carries the adapted observation"
    );
    assert_eq!(
        cap["reference"]["adapted"]["payload_base64"],
        frf::ext::b64(b"\x01\x02\x03\x04")
    );
    assert_eq!(
        cap["candidate"]["adapted"]["payload_base64"],
        frf::ext::b64(b"\x01\x02\x03\xff")
    );
    assert_eq!(cap["residuals"].as_array().unwrap().len(), 1);
    let rid = cap["residuals"][0].as_str().unwrap().to_string();
    // The residual id is a content address (64 hex), not a storage label.
    assert_eq!(rid.len(), 64, "residual id: {rid}");
    assert!(rid.chars().all(|c| c.is_ascii_hexdigit()));

    // The adapter + comparator evidence are preserved under the run and the
    // verified loader rehashes the chain (adapter request carried the raw
    // outcome; the adapted payload decodes to its content hash).
    let ev = work.path(&format!(
        "frf/captures/{run}/capture-adapter/dns.wire/reference"
    ));
    for f in [
        "request.json",
        "response.json",
        "invocation.json",
        "result.json",
    ] {
        assert!(ev.join(f).is_file(), "missing adapter evidence {f}");
    }
    let store = Store::new(work.path(ROOT));
    let verified = frf::verify::load_capture_verified(&store, &run).unwrap();
    assert_eq!(verified.capture.adapter_semantics.len(), 1);

    // Replay re-invokes the adapter AND the comparator; the reproduced
    // observation includes the adapted payloads.
    let out = frf(
        &work,
        &["--root", ROOT, "replay", &run, "--policy", "exact"],
    );
    assert_success(&out, "adapted replay");
    assert!(stdout(&out).contains("reproduced"), "{}", stdout(&out));

    // The receipt binds the external axis and compiles after the residual is
    // disposed.
    let rec = frf(&work, &["--root", ROOT, "receipt", "emit", &run]);
    assert_success(&rec, "adapted receipt");
    let receipt = stdout(&rec);
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "residual",
            "dispose",
            &rid,
            "--disposition",
            "intentional",
            "--reason",
            "documented wire divergence",
        ],
    );
    assert_success(&out, "dispose adapted residual");
    let claim = frf(&work, &["--root", ROOT, "claim", "compile", &receipt]);
    assert!(!claim.status.success(), "an open/unknown claim must refuse");
    // A second receipt after disposal carries the closed disposition.
    let rec2 = frf(&work, &["--root", ROOT, "receipt", "emit", &run]);
    assert_success(&rec2, "re-emit after dispose");
}

// ---------------------------------------------------------------------------
// The external minimizer extension protocol
// ---------------------------------------------------------------------------

#[test]
fn an_external_minimizer_is_court_verified() {
    // The court declares an external minimizer for the exit residual's κ
    // route. `court minimize` consults the residual's capture, re-invokes the
    // exact snapshotted program, and COURT-VERIFIES its proposal with the
    // one comparison operation. The reduction record binds the minimizer's
    // semantic + implementation identities and the content-addressed
    // invocation evidence.
    let work = Workdir::new("ext-minimize");
    work.copy_canonical_tree();
    admit_reference(&work);
    copy_into(&work, "golden/minimizers/ddmin-lines.py");
    copy_into(&work, "frf/courts/cli-external-minimizer/manifest.yaml");
    copy_into(
        &work,
        "frf/courts/cli-external-minimizer/fixtures/malformed-verbose.conf",
    );

    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "court",
            "run",
            "frf/courts/cli-external-minimizer/manifest.yaml",
        ],
    );
    assert_success(&out, "external-minimizer court run");
    let run = stdout(&out);
    let cap = capture(&work, &run);
    assert_eq!(cap["minimizer_semantics"][0]["id"], "cli-exit-minimize");
    let rid = cap["residuals"][0].as_str().unwrap().to_string();

    let out = frf(&work, &["--root", ROOT, "court", "minimize", &rid]);
    assert_success(&out, "external minimize");
    let reduction_id = stdout(&out);
    assert_eq!(reduction_id.len(), 64, "content-addressed reduction id");

    let rec: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("frf/reductions/{reduction_id}.json"))).unwrap(),
    )
    .unwrap();
    assert_eq!(rec["schema_version"], "frf-reduction-v4");
    assert_eq!(rec["minimizer_semantic_id"], "cli-exit-minimize");
    assert!(rec["minimizer_semantic_hash"].as_str().unwrap().len() == 64);
    assert!(rec["minimizer_implementation_hash"].as_str().unwrap().len() == 64);
    assert_eq!(
        rec["derivation"]["strategy"],
        "external:drop-comment-blank-lines"
    );
    // The core's executable attempts: baseline + the court-verified proposal.
    let attempts = rec["attempts"].as_array().unwrap();
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0]["role"], "baseline");
    assert_eq!(attempts[0]["outcome"], "preserved");
    assert_eq!(attempts[1]["role"], "final_verification");
    assert_eq!(attempts[1]["outcome"], "preserved");
    assert_eq!(attempts[1]["accepted"], true);
    // The accepted reproducer is strictly smaller and its final verification
    // is the proposal's.
    assert_eq!(rec["final_fixture_sha256"], attempts[1]["fixture_sha256"]);
    assert!(
        rec["derivation"]["final_lines"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap()
            < rec["derivation"]["original_lines"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap(),
        "the reproducer must be strictly smaller"
    );

    // The minimizer's canonical request/response + invocation + result are
    // preserved under the reduction and cross-verify.
    let mdir = work.path(&format!("frf/reductions/{reduction_id}/minimizer"));
    for f in [
        "request.json",
        "response.json",
        "invocation.json",
        "result.json",
    ] {
        assert!(mdir.join(f).is_file(), "missing minimizer evidence {f}");
    }
    let invocation: frf::model::MinimizerInvocation =
        serde_json::from_str(&fs::read_to_string(mdir.join("invocation.json")).unwrap()).unwrap();
    let rederived = frf::semantics::minimizer_invocation_identity(
        &frf::semantics::MinimizerInvocationContent {
            minimizer_id: &invocation.minimizer_id,
            residual_id: &invocation.residual_id,
            request_cid: &invocation.request_cid,
            minimizer_semantic_cid: &invocation.minimizer_semantic_cid,
            minimizer_implementation_artifact: &invocation.minimizer_implementation_artifact,
            execution_provenance: &invocation.execution_provenance,
        },
    )
    .unwrap();
    assert_eq!(rederived, invocation.invocation_id);
    assert_eq!(invocation.minimizer_id, "cli-exit-minimize");
    let result: frf::model::MinimizerResult =
        serde_json::from_str(&fs::read_to_string(mdir.join("result.json")).unwrap()).unwrap();
    assert!(result.court_verified);
    assert_eq!(result.outcome, "accepted");
    // The record binds the same invocation/result ids.
    assert_eq!(rec["minimizer_invocation_id"], result.invocation_id);
    assert_eq!(rec["minimizer_result_id"], result.result_id);

    // The reduction record's content address rederives (the minimizer binding
    // is part of the preimage).
    let store = Store::new(work.path(ROOT));
    let loaded = store.load_reduction(&reduction_id).unwrap();
    assert_eq!(loaded.id, reduction_id);
}

#[test]
fn an_uncourt_verifiable_minimizer_proposal_is_recorded_but_not_accepted() {
    // A minimizer that proposes an EMPTY fixture: the proposal cannot carry
    // the divergence, so court verification fails. The proposal is RECORDED
    // (the refusal is itself evidence, content-addressed under the residual)
    // but NEVER accepted — no reduction record appears.
    let work = Workdir::new("ext-minimize-lie");
    work.copy_canonical_tree();
    admit_reference(&work);
    copy_into(&work, "frf/courts/cli-external-minimizer/manifest.yaml");
    copy_into(
        &work,
        "frf/courts/cli-external-minimizer/fixtures/malformed-verbose.conf",
    );
    write_program(
        &work,
        "golden/minimizers/empty.py",
        "#!/usr/bin/env python3\n\
import base64, hashlib, json, sys\n\
raw = sys.stdin.buffer.read()\n\
req = json.loads(raw.decode(\"utf-8\"))\n\
request_id = hashlib.sha256(raw).hexdigest()\n\
empty = b\"\"\n\
response = {\n\
    \"schema_version\": \"frf-minimizer-response-v1\",\n\
    \"request_id\": request_id,\n\
    \"fixture_sha256\": hashlib.sha256(empty).hexdigest(),\n\
    \"fixture_base64\": base64.b64encode(empty).decode(\"ascii\"),\n\
    \"minimal\": True,\n\
    \"attempts\": [],\n\
    \"indeterminate\": False,\n\
    \"failure\": None,\n\
}\n\
json.dump(response, sys.stdout, sort_keys=True, separators=(\",\", \":\"))\n\n",
    );
    // Point the manifest at the lying minimizer.
    let manifest_path = work.path("frf/courts/cli-external-minimizer/manifest.yaml");
    let manifest = fs::read_to_string(&manifest_path).unwrap();
    fs::write(
        &manifest_path,
        manifest.replace(
            "golden/minimizers/ddmin-lines.py",
            "golden/minimizers/empty.py",
        ),
    )
    .unwrap();

    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "court",
            "run",
            "frf/courts/cli-external-minimizer/manifest.yaml",
        ],
    );
    assert_success(&out, "lying-minimizer court run");
    let run = stdout(&out);
    let cap = capture(&work, &run);
    let rid = cap["residuals"][0].as_str().unwrap().to_string();

    let out = frf(&work, &["--root", ROOT, "court", "minimize", &rid]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("recorded but NOT accepted"),
        "stderr: {}",
        stderr(&out)
    );

    // The refusal is evidence: a content-addressed minimizer evidence dir
    // under the residual (keyed by the request cid).
    let refusal_root = work.path(&format!("frf/residuals/{rid}.minimizer"));
    assert!(
        refusal_root.is_dir(),
        "the refusal evidence must be preserved"
    );
    let mut cids: Vec<String> = fs::read_dir(&refusal_root)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    assert_eq!(cids.len(), 1);
    let cid = cids.pop().unwrap();
    for f in [
        "request.json",
        "response.json",
        "invocation.json",
        "result.json",
    ] {
        assert!(
            refusal_root.join(&cid).join(f).is_file(),
            "missing refusal evidence {f}"
        );
    }
    let result: frf::model::MinimizerResult = serde_json::from_str(
        &fs::read_to_string(refusal_root.join(&cid).join("result.json")).unwrap(),
    )
    .unwrap();
    assert!(!result.court_verified);
    assert_eq!(result.outcome, "rejected");

    // No reduction record was written.
    let reductions = fs::read_dir(work.path("frf/reductions")).unwrap().count();
    assert_eq!(
        reductions, 0,
        "an unaccepted proposal produces no reduction"
    );
}

// ---------------------------------------------------------------------------
// The witness extension protocol
// ---------------------------------------------------------------------------

const WITNESS_PY: &str = "#!/usr/bin/env python3\n\
import hashlib, json, sys\n\
raw = sys.stdin.buffer.read()\n\
req = json.loads(raw.decode(\"utf-8\"))\n\
assert req[\"schema_version\"] == \"frf-witness-request-v1\", req\n\
request_id = hashlib.sha256(raw).hexdigest()\n\
response = {\n\
    \"schema_version\": \"frf-witness-response-v3\",\n\
    \"request_id\": request_id,\n\
    \"indeterminate\": False,\n\
    \"failure\": None,\n\
    \"attestation\": {\n\
        \"statement\": req[\"statement\"],\n\
        \"outcome\": \"affirm\",\n\
        \"detail\": \"independent confirmation\",\n\
    },\n\
}\n\
json.dump(response, sys.stdout, sort_keys=True, separators=(\",\", \":\"))\n\n";

#[test]
fn a_witness_attests_a_content_addressed_subject() {
    let work = Workdir::new("ext-witness");
    work.copy_canonical_tree();
    admit_reference(&work);
    let run = run_court(&work);
    write_program(&work, "golden/witnesses/attest.py", WITNESS_PY);

    let statement = "the candidate diverges on the malformed fixture (witnessed)";
    let exit_id = residual_id(&work, &run, "exit");
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "witness",
            "attest",
            "residual",
            &exit_id,
            "--id",
            "manual-review",
            "--relation",
            "independent-confirmation",
            "--program",
            "golden/witnesses/attest.py",
            "--statement",
            statement,
        ],
    );
    assert_success(&out, "witness attest");
    let id = stdout(&out);
    assert_eq!(id.len(), 64, "content-addressed witness statement");

    // The statement is content-addressed canonical JSON, re-verified on read
    // (identity rederives; request/response hash; the response names its
    // request; the attestation names exactly the statement).
    let store = Store::new(work.path(ROOT));
    let stmt = store.load_witness_statement(&id).unwrap();
    assert_eq!(stmt.subject.kind, "residual");
    assert_eq!(stmt.subject.id, exit_id);
    // The subject content address is the residual's fingerprint — rederived
    // by the command, never read from the caller.
    let record = frf::verify::load_residual_verified(&store, &exit_id)
        .unwrap()
        .record()
        .clone();
    assert_eq!(
        stmt.subject.cid,
        frf::semantics::residual_fingerprint(&record).unwrap()
    );
    assert_eq!(stmt.statement, statement);
    assert_eq!(stmt.attestation.statement, statement);
    assert_eq!(stmt.attestation.outcome, "affirm");
    // The preserved request names the subject + statement; the preserved
    // response cryptographically names the request.
    let request: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("frf/witnesses/{id}/request.json"))).unwrap(),
    )
    .unwrap();
    assert_eq!(request["statement"], statement);
    assert_eq!(request["subject"]["cid"], stmt.subject.cid);

    // The same witness can attest a RUN: the content address is the run's
    // identity digest, recomputed by the verified loader.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "witness",
            "attest",
            "run",
            &run,
            "--id",
            "manual-review",
            "--relation",
            "independent-confirmation",
            "--program",
            "golden/witnesses/attest.py",
            "--statement",
            "the run reproduced",
        ],
    );
    assert_success(&out, "witness attest run");
    let id2 = stdout(&out);
    let stmt2 = store.load_witness_statement(&id2).unwrap();
    let residuals: Vec<ResidualRecord> = {
        let verified = frf::verify::load_capture_verified(&store, &run).unwrap();
        verified
            .capture
            .residuals
            .iter()
            .map(|rid| {
                frf::verify::load_residual_verified(&store, rid)
                    .unwrap()
                    .record()
                    .clone()
            })
            .collect()
    };
    let verified = frf::verify::load_capture_verified(&store, &run).unwrap();
    assert_eq!(stmt2.subject.cid, verified.digest(&residuals).unwrap());
}

#[test]
fn a_witness_that_declines_is_refused() {
    // A witness program that returns NO attestation: the only admissible
    // outcome is an attestation; a decline is a refusal, never a silent
    // "not verified" record.
    let work = Workdir::new("ext-witness-decline");
    work.copy_canonical_tree();
    admit_reference(&work);
    let run = run_court(&work);
    let exit_id = residual_id(&work, &run, "exit");
    write_program(
        &work,
        "golden/witnesses/decline.py",
        "#!/usr/bin/env python3\n\
import hashlib, json, sys\n\
raw = sys.stdin.buffer.read()\n\
request_id = hashlib.sha256(raw).hexdigest()\n\
response = {\n\
    \"schema_version\": \"frf-witness-response-v3\",\n\
    \"request_id\": request_id,\n\
    \"indeterminate\": False,\n\
    \"failure\": None,\n\
    \"attestation\": None,\n\
}\n\
json.dump(response, sys.stdout, sort_keys=True, separators=(\",\", \":\"))\n\n",
    );
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "witness",
            "attest",
            "residual",
            &exit_id,
            "--id",
            "manual-review",
            "--relation",
            "independent-confirmation",
            "--program",
            "golden/witnesses/decline.py",
            "--statement",
            "anything",
        ],
    );
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("declined to attest"),
        "stderr: {}",
        stderr(&out)
    );
    // No statement was recorded.
    assert!(
        !work
            .path("frf/witnesses")
            .join("manual-review.json")
            .exists(),
        "no statement for a declined attestation"
    );
}

#[test]
fn the_independence_relation_is_declared_evidence_not_derived() {
    // spec/witness.md §6: independence is a DECLARED relation. The statement
    // carries the witness IDENTITY (the stable WHO); the operator declares
    // the independence claim with its basis; FRF verifies the evidence
    // structure — never the social truth of independence.
    let work = Workdir::new("ext-independence");
    work.copy_canonical_tree();
    admit_reference(&work);
    let run = run_court(&work);
    let exit_id = residual_id(&work, &run, "exit");
    write_program(&work, "golden/witnesses/attest.py", WITNESS_PY);
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "witness",
            "attest",
            "residual",
            &exit_id,
            "--id",
            "manual-review",
            "--relation",
            "independent-confirmation",
            "--program",
            "golden/witnesses/attest.py",
            "--statement",
            "the candidate diverges on the malformed fixture (witnessed)",
        ],
    );
    assert_success(&out, "witness attest");
    let wid = stdout(&out);
    let store = Store::new(work.path(ROOT));
    let stmt = store.load_witness_statement(&wid).unwrap();
    // The witness identity (the stable WHO) rederives from the relation's
    // specification and the program's bytes + interpreter chain.
    assert_eq!(
        frf::semantics::witness_identity(&stmt.witness_semantic, &stmt.witness_implementation)
            .unwrap(),
        stmt.witness_identity
    );

    // An unknown relation is refused.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "witness",
            "independence",
            &wid,
            "--relation",
            "totally-independent",
            "--basis",
            "nope",
        ],
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("unknown independence relation"));

    // A missing basis is refused.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "witness",
            "independence",
            &wid,
            "--relation",
            "separate-party",
            "--basis",
            "   ",
        ],
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("needs a basis"));

    // The declared relation: content-addressed, bound to the statement.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "witness",
            "independence",
            &wid,
            "--relation",
            "separate-party",
            "--basis",
            "the attestation was made by an unaffiliated reviewer",
            "--detail",
            "reviewed the exported bundle",
        ],
    );
    assert_success(&out, "witness independence");
    let iid = stdout(&out);
    assert_eq!(iid.len(), 64);
    let rec = store.load_independence(&iid).unwrap();
    assert_eq!(rec.witness_statement, wid);
    assert_eq!(rec.witness_identity, stmt.witness_identity);
    assert_eq!(rec.subject, stmt.subject);
    assert_eq!(rec.relation, "separate-party");
    assert_eq!(
        rec.specification_hash,
        frf::semantics::independence_specification_hash("separate-party", "v1").unwrap()
    );
    // The typed evidence refs bind the statement + the program object.
    assert!(rec
        .evidence_refs
        .iter()
        .any(|r| r.role == "witness-statement" && r.cid == wid));
    assert!(rec
        .evidence_refs
        .iter()
        .any(|r| r.role == "witness-implementation"
            && r.cid == stmt.witness_implementation.implementation_hash));
    // The record is idempotent: writing it again verifies the existing one.
    store.write_independence(&rec).unwrap();
    // A record bound to a statement that does not exist is refused on load.
    let forged = frf::model::IndependenceEvidence {
        schema_version: frf::model::SCHEMA_INDEPENDENCE.to_string(),
        id: String::new(),
        subject: rec.subject.clone(),
        witness_statement: "f".repeat(64),
        witness_identity: rec.witness_identity.clone(),
        relation: rec.relation.clone(),
        relation_version: rec.relation_version.clone(),
        specification_hash: rec.specification_hash.clone(),
        basis: rec.basis.clone(),
        detail: rec.detail.clone(),
        evidence_refs: rec.evidence_refs.clone(),
        created_by: rec.created_by.clone(),
    };
    let forged_id = frf::semantics::independence_identity(&frf::semantics::IndependenceContent {
        subject: &forged.subject,
        witness_statement: &forged.witness_statement,
        witness_identity: &forged.witness_identity,
        relation: &forged.relation,
        relation_version: &forged.relation_version,
        specification_hash: &forged.specification_hash,
        basis: &forged.basis,
        detail: &forged.detail,
        evidence_refs: &forged.evidence_refs,
    })
    .unwrap();
    let path = store.independence_path(&forged_id).unwrap();
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, frf::canon::canonical(&forged).unwrap()).unwrap();
    assert!(
        store.load_independence(&forged_id).is_err(),
        "an independence record bound to a missing statement must refuse"
    );
}

#[test]
fn a_declared_authority_is_recorded_verbatim_and_kind_is_closed() {
    let work = Workdir::new("ext-witness-authority");
    work.copy_canonical_tree();
    admit_reference(&work);
    let run = run_court(&work);
    let exit_id = residual_id(&work, &run, "exit");
    write_program(
        &work,
        "golden/witnesses/authority.py",
        "#!/usr/bin/env python3\n\
import hashlib, json, sys\n\
raw = sys.stdin.buffer.read()\n\
request_id = hashlib.sha256(raw).hexdigest()\n\
response = {\n\
    \"schema_version\": \"frf-witness-response-v3\",\n\
    \"request_id\": request_id,\n\
    \"indeterminate\": False,\n\
    \"failure\": None,\n\
    \"authority\": {\"id\": \"independent-review-board\", \"kind\": \"organization\", \"detail\": \"chartered reviewer pool\"},\n\
    \"attestation\": {\n\
        \"statement\": \"the candidate diverges (witnessed)\",\n\
        \"outcome\": \"affirm\",\n\
        \"detail\": \"board review\",\n\
    },\n\
}\n\
json.dump(response, sys.stdout, sort_keys=True, separators=(\",\", \":\"))\n\n",
    );
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "witness",
            "attest",
            "residual",
            &exit_id,
            "--id",
            "board-review",
            "--relation",
            "independent-confirmation",
            "--program",
            "golden/witnesses/authority.py",
            "--statement",
            "the candidate diverges (witnessed)",
        ],
    );
    assert_success(&out, "witness attest with authority");
    let wid = stdout(&out);
    let store = Store::new(work.path(ROOT));
    let stmt = store.load_witness_statement(&wid).unwrap();
    let authority = stmt
        .authority
        .clone()
        .expect("the declared authority is recorded");
    assert_eq!(authority.id, "independent-review-board");
    assert_eq!(authority.kind, "organization");
    // The authority is part of the statement's identity (a different
    // declaration is a different statement).
    let mut without = stmt.clone();
    without.authority = None;
    assert_ne!(
        frf::semantics::witness_statement_identity(&frf::semantics::WitnessStatementContent {
            subject: &without.subject,
            witness_semantic: &without.witness_semantic,
            witness_implementation: &without.witness_implementation,
            witness_identity: &without.witness_identity,
            authority: &without.authority,
            statement: &without.statement,
            attestation: &without.attestation,
            request_cid: &without.request_cid,
            response_cid: &without.response_cid,
        })
        .unwrap(),
        wid
    );

    // A witness declaring an unknown authority kind is refused.
    write_program(
        &work,
        "golden/witnesses/bad-authority.py",
        "#!/usr/bin/env python3\n\
import hashlib, json, sys\n\
raw = sys.stdin.buffer.read()\n\
request_id = hashlib.sha256(raw).hexdigest()\n\
response = {\n\
    \"schema_version\": \"frf-witness-response-v3\",\n\
    \"request_id\": request_id,\n\
    \"indeterminate\": False,\n\
    \"failure\": None,\n\
    \"authority\": {\"id\": \"x\", \"kind\": \"royal-society\"},\n\
    \"attestation\": {\n\
        \"statement\": \"anything\",\n\
        \"outcome\": \"affirm\",\n\
        \"detail\": \"x\",\n\
    },\n\
}\n\
json.dump(response, sys.stdout, sort_keys=True, separators=(\",\", \":\"))\n\n",
    );
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "witness",
            "attest",
            "residual",
            &exit_id,
            "--id",
            "bad-board",
            "--relation",
            "independent-confirmation",
            "--program",
            "golden/witnesses/bad-authority.py",
            "--statement",
            "anything",
        ],
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("declared authority kind"));
}

/// 0.1.59 — verified-on-read is closed under ALL evidence transforms: a
/// receipt cannot be minted from a tampered capture, and a disposition
/// cannot be appended to a tampered residual. The raw store loaders parse
/// ONLY (`Unverified<T>`); every semantic consumer goes through the verified
/// loaders, so a hand-edited observation cannot bind a claim or gain a
/// closure.
#[test]
fn receipt_emit_and_dispose_refuse_tampered_evidence() {
    let work = Workdir::new("ext-verified-gates");
    work.copy_canonical_tree();
    admit_reference(&work);
    let run = run_court(&work);
    let capture_path = work.path(&format!("{ROOT}/captures/{run}/capture.json"));

    // Tamper with the captured candidate exit: a hand-edited observation is
    // not evidence. `receipt emit` must REFUSE (the run identity no longer
    // rederives), never mint a receipt that binds the forged bytes.
    let mut capture: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&capture_path).unwrap()).unwrap();
    capture["candidate"]["exit"] = serde_json::Value::String("0".into());
    let json = frf::canon::canonical(&capture).unwrap();
    fs::write(&capture_path, json).unwrap();
    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &run]);
    assert!(
        !out.status.success(),
        "a tampered capture must not mint a receipt: {}",
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("does not rederive") || stderr(&out).contains("refusing"),
        "the refusal must name the verification failure: {}",
        stderr(&out)
    );

    // Tamper with a residual record: `dispose` must refuse (identity +
    // derivation from the parent run are established before a disposition
    // may be appended).
    let exit_id = residual_id(&work, &run, "exit");
    let residual_path = work.path(&format!("{ROOT}/residuals/{exit_id}.json"));
    let mut residual: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&residual_path).unwrap()).unwrap();
    residual["raw_reference"] = serde_json::Value::String("9".into());
    let json = frf::canon::canonical(&residual).unwrap();
    fs::write(&residual_path, json).unwrap();
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "residual",
            "dispose",
            &exit_id,
            "--disposition",
            "intentional",
            "--reason",
            "x",
        ],
    );
    assert!(
        !out.status.success(),
        "a tampered residual must not be disposable: {}",
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("does not rederive")
            || stderr(&out).contains("does not derive")
            || stderr(&out).contains("refusing"),
        "the refusal must name the verification failure: {}",
        stderr(&out)
    );
}
