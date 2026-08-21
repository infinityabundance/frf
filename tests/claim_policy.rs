//! Claim admission policies (the assurance grades): beyond `baseline`
//! (observation evidence only), a claim must be backed by DEMONSTRATED
//! capability evidence that the compiled claim carries —
//!
//! - `sensitivity-backed`: every claimed observable axis must have challenge
//!   coverage (the court demonstrated it can SEE the surface's defect class:
//!   same court semantic identity, same reference artifact, a mutation on
//!   exactly that axis observed and nothing else — verdicts recomputed from
//!   the mutant run, never trusted from the record);
//! - `independently-witnessed`: sensitivity coverage PLUS a verified witness
//!   attestation of the receipt (`outcome: affirm`);
//! - `high-assurance`: independently witnessed PLUS the observation was made
//!   under the reference execution profile and the reference capture bounds.
//!
//! The compiled claim carries the capability evidence (challenge ids,
//! witness ids, the replay contract), and the bundle export carries that
//! evidence, so the policy admission re-derives from a bundle alone — in the
//! independent verifiers too.
//!
//! Run: `cargo test --test claim_policy`.

use frf::store::Store;
use std::fs;

mod common;
use common::*;

/// Drive the golden path to the resolution receipt (the run that observed the
/// passing candidate and licenses the exit-axis claim): admit, run the court,
/// dispose the original residuals, run the patched candidate, dispose `fixed`
/// with the resolution edge, and emit the resolution receipt.
fn resolution_receipt(work: &Workdir) -> (String, String) {
    admit_reference(work);
    let run = run_court(work);

    let dispose = |id: &str, disposition: &str, reason: &str, extra: &[&str]| {
        let mut args: Vec<&str> = vec![
            "--root",
            ROOT,
            "residual",
            "dispose",
            id,
            "--disposition",
            disposition,
            "--reason",
            reason,
        ];
        args.extend_from_slice(extra);
        let out = frf(work, &args);
        assert_success(&out, "dispose");
    };

    // The resolution run: the patched candidate under the same question.
    let resolution_run = run_resolution_court(work);
    dispose(
        "cli-exit-0001",
        "fixed",
        "candidate patched to preserve reference exit class",
        &["--resolution-run", &resolution_run],
    );
    dispose(
        "cli-text-0001",
        "intentional",
        "clearer diagnostic wording; documented divergence",
        &[],
    );
    dispose(
        "cli-text-0002",
        "intentional",
        "clearer diagnostic wording; documented divergence (re-observed)",
        &[],
    );

    let out = frf(work, &["--root", ROOT, "receipt", "emit", &resolution_run]);
    assert_success(&out, "receipt emit (resolution run)");
    let receipt = stdout(&out);
    (run, receipt)
}

#[test]
fn sensitivity_backed_requires_challenge_coverage_per_claimed_axis() {
    let work = Workdir::new("policy-sensitivity");
    work.copy_canonical_tree();
    let (_run, receipt) = resolution_receipt(&work);

    // Baseline compiles (observation evidence only).
    let out = frf(
        &work,
        &[
            "--root", ROOT, "claim", "compile", &receipt, "--policy", "baseline",
        ],
    );
    assert_success(&out, "baseline claim");

    // Sensitivity-backed BEFORE the challenge: refused — the court has never
    // demonstrated it can see the claimed exit surface.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "claim",
            "compile",
            &receipt,
            "--policy",
            "sensitivity-backed",
        ],
    );
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("has NOT demonstrated it can see the exit defect class"),
        "stderr: {}",
        stderr(&out)
    );

    // Run the negative control: the court must observe the exit-class mutant
    // and only it.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "court",
            "challenge",
            MANIFEST,
            "--operators",
            "exit-class",
        ],
    );
    assert_success(&out, "court challenge (exit-class)");

    // Now the sensitivity-backed claim compiles, and it carries the exact
    // content-addressed challenge evidence for the claimed axis.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "claim",
            "compile",
            &receipt,
            "--policy",
            "sensitivity-backed",
        ],
    );
    assert_success(&out, "sensitivity-backed claim");
    let claim: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("{ROOT}/claims/{receipt}.json"))).unwrap(),
    )
    .unwrap();
    assert_eq!(claim["schema_version"], "frf-claim-v7");
    assert_eq!(claim["policy"], "sensitivity-backed");
    assert_eq!(claim["observable_scope"], serde_json::json!(["exit"]));
    let capability = claim["capability"].as_array().unwrap();
    assert_eq!(capability.len(), 1, "one capability entry per claimed axis");
    assert_eq!(capability[0]["axis"], "exit");
    assert_eq!(
        capability[0]["receipt"], receipt,
        "the capability entry binds the premise receipt it covers"
    );
    let challenge_ids: Vec<String> = capability[0]["challenge_ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(!challenge_ids.is_empty());
    // The challenge records are content-addressed and verifiable.
    let store = Store::new(work.path(ROOT));
    for cid in &challenge_ids {
        store.load_challenge(cid).unwrap();
    }
    // The mutant run answers the same question and wraps the same reference.
    let receipt_doc: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("{ROOT}/receipts/{receipt}.json"))).unwrap(),
    )
    .unwrap();
    for cid in &challenge_ids {
        let ch = store.load_challenge(cid).unwrap();
        assert_eq!(ch.court, "cli-malformed-input");
        assert_eq!(ch.target_axis, "exit");
        assert_eq!(
            ch.reference_sha256,
            receipt_doc["authority"]["identity_hash"].as_str().unwrap()
        );
        let cap = store.load_capture(&ch.run).unwrap();
        assert_eq!(
            cap.court_semantic_identity,
            receipt_doc["court"]["semantic_identity"].as_str().unwrap()
        );
        assert!(ch.saw_defect && ch.specificity_clean);
    }
}

#[test]
fn independently_witnessed_requires_a_verified_attestation_of_the_receipt() {
    let work = Workdir::new("policy-witness");
    work.copy_canonical_tree();
    let (_run, receipt) = resolution_receipt(&work);

    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "court",
            "challenge",
            MANIFEST,
            "--operators",
            "exit-class",
        ],
    );
    assert_success(&out, "court challenge");

    // Independently-witnessed before the attestation: refused.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "claim",
            "compile",
            &receipt,
            "--policy",
            "independently-witnessed",
        ],
    );
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("no verified witness statement attests premise receipt"),
        "stderr: {}",
        stderr(&out)
    );

    // Attest the RECEIPT (the witness program affirms).
    let program = work.path("golden/witnesses/attest.py");
    fs::create_dir_all(program.parent().unwrap()).unwrap();
    fs::write(
        &program,
        "#!/usr/bin/env python3\n\
import hashlib, json, sys\n\
raw = sys.stdin.buffer.read()\n\
request_id = hashlib.sha256(raw).hexdigest()\n\
req = json.loads(raw.decode(\"utf-8\"))\n\
response = {\n\
    \"schema_version\": \"frf-witness-response-v3\",\n\
    \"request_id\": request_id,\n\
    \"indeterminate\": False,\n\
    \"failure\": None,\n\
    \"attestation\": {\n\
        \"statement\": req[\"statement\"],\n\
        \"outcome\": \"affirm\",\n\
        \"detail\": \"independent confirmation of the receipt\",\n\
    },\n\
}\n\
json.dump(response, sys.stdout, sort_keys=True, separators=(\",\", \":\"))\n",
    )
    .unwrap();
    set_exec(&program);
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "witness",
            "attest",
            "receipt",
            &receipt,
            "--id",
            "manual-review",
            "--relation",
            "independent-confirmation",
            "--program",
            "golden/witnesses/attest.py",
            "--statement",
            "the receipt binds a verified observation of the passing candidate",
        ],
    );
    assert_success(&out, "witness attest receipt");
    let wid = stdout(&out);
    assert_eq!(wid.len(), 64);

    // Now the tier compiles and carries the witness id.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "claim",
            "compile",
            &receipt,
            "--policy",
            "independently-witnessed",
        ],
    );
    assert_success(&out, "independently-witnessed claim");
    let claim: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("{ROOT}/claims/{receipt}.json"))).unwrap(),
    )
    .unwrap();
    assert_eq!(claim["policy"], "independently-witnessed");
    assert_eq!(
        claim["witness_statements"],
        serde_json::json!([wid]),
        "the claim names the exact verified attestation"
    );
}

/// The second premise manifest used by the multi-premise tests: the SAME
/// authority and the SAME candidate artifact (candidate-fixed.sh, byte-
/// identical) observed on a surface the resolution court never covered — a
/// stdout-only court whose axis passes for the fixed candidate.
const STDOUT_ONLY_MANIFEST: &str = r#"
court:
  id: cli-stdout-only
  question: >-
    For malformed input in fixture family malformed-input, does the candidate
    preserve the admitted reference's stdout?
  falsifier: >-
    The candidate's stdout diverges from the admitted reference on a fixture
    in family malformed-input.
  authority: ref-cli-1.8.2
  candidate:
    name: cand-cli
    version_or_commit: "0.1.0-fixed"
    build_profile: debug
    path: golden/work/candidate-fixed.sh
  fixture:
    id: malformed-path.conf
    path: frf/courts/cli-malformed-input/fixtures/malformed-path.conf
    arguments: ["--strict", "{fixture}"]
  admissibility_envelope:
    fixture_family: malformed-input
    platforms: ["x86_64-linux"]
    observables: [stdout]
    normalizers: []
    replay_scope: single-run
"#;

/// Run the stdout-only court (the second premise) and emit its receipt.
fn stdout_only_receipt(work: &Workdir) -> String {
    let manifest = "frf/courts/cli-malformed-input/manifest-stdout-only.yaml";
    fs::write(work.path(manifest), STDOUT_ONLY_MANIFEST).unwrap();
    let out = frf(work, &["--root", ROOT, "court", "run", manifest]);
    assert_success(&out, "stdout-only court run");
    let run2 = stdout(&out);
    let out = frf(work, &["--root", ROOT, "receipt", "emit", &run2]);
    assert_success(&out, "stdout-only receipt emit");
    stdout(&out)
}

#[test]
fn multi_premise_claim_compiles_under_the_region_algebra() {
    let work = Workdir::new("multi-premise");
    work.copy_canonical_tree();
    let (_run, receipt) = resolution_receipt(&work);
    let receipt2 = stdout_only_receipt(&work);

    // K = {exit} ∪ {stdout}; P = {exit,stderr} ∪ {stdout}. The multi-premise
    // claim covers BOTH axes and names BOTH premises; the region cells are
    // the per-premise clean surfaces, never a merged product.
    let out = frf(
        &work,
        &["--root", ROOT, "claim", "compile", &receipt, &receipt2],
    );
    assert_success(&out, "multi-premise claim");
    let claim: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("{ROOT}/claims/{receipt}.json"))).unwrap(),
    )
    .unwrap();
    assert_eq!(claim["schema_version"], "frf-claim-v7");
    assert_eq!(
        claim["requires"],
        serde_json::json!([receipt, receipt2]),
        "the claim names every premise receipt"
    );
    assert_eq!(claim["receipt"], receipt);
    assert_eq!(
        claim["observable_scope"],
        serde_json::json!(["exit", "stdout"])
    );
    // The scope is a REGION: one cell per premise's clean surface.
    let cells = claim["scope"]["cells"].as_array().unwrap();
    assert_eq!(cells.len(), 2, "one cell per premise: {cells:?}");
    let cell_axes: Vec<Vec<String>> = cells
        .iter()
        .map(|c| {
            c["observables"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect()
        })
        .collect();
    assert!(
        cell_axes.contains(&vec!["exit".to_string()]),
        "the resolution premise's cell: {cell_axes:?}"
    );
    assert!(
        cell_axes.contains(&vec!["stdout".to_string()]),
        "the stdout premise's cell: {cell_axes:?}"
    );
    // One conservative sentence per premise cell.
    assert_eq!(claim["positive"].as_array().unwrap().len(), 2);
    let prop = claim["proposition"].as_str().unwrap();
    assert!(prop.starts_with("parity(cells="), "proposition: {prop}");
    assert!(
        prop.contains("exit"),
        "proposition names the exit cell: {prop}"
    );
    assert!(
        prop.contains("stdout"),
        "proposition names the stdout cell: {prop}"
    );

    // Subject coherence: a receipt binding a DIFFERENT candidate artifact
    // cannot join the premises — a claim asserts parity of ONE candidate.
    // (The original candidate's run already exists, so a genuinely different
    // artifact is needed: overwrite the candidate with new bytes.)
    work.write_candidate(
        "#!/bin/sh\n# a third candidate: different artifact, different exit class\nexit 3\n",
    );
    let out = frf(&work, &["--root", ROOT, "court", "run", MANIFEST]);
    assert_success(&out, "third-candidate court run");
    let run_orig = stdout(&out);
    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &run_orig]);
    assert_success(&out, "original-candidate receipt emit");
    let receipt_orig = stdout(&out);
    let out = frf(
        &work,
        &["--root", ROOT, "claim", "compile", &receipt, &receipt_orig],
    );
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("different candidate artifacts"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn multi_premise_capability_binds_each_premise_receipt() {
    let work = Workdir::new("multi-premise-capability");
    work.copy_canonical_tree();
    let (_run, receipt) = resolution_receipt(&work);
    let receipt2 = stdout_only_receipt(&work);

    // Sensitivity coverage is PER PREMISE: the exit axis needs a challenge of
    // the resolution court, the stdout axis a challenge of the stdout court
    // — and the compiled capability entries bind the premise they cover.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "court",
            "challenge",
            MANIFEST,
            "--operators",
            "exit-class",
        ],
    );
    assert_success(&out, "court challenge (exit-class)");
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "court",
            "challenge",
            "frf/courts/cli-malformed-input/manifest-stdout-only.yaml",
            "--operators",
            "stdout-first-line",
        ],
    );
    assert_success(&out, "court challenge (stdout-first-line)");

    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "claim",
            "compile",
            &receipt,
            &receipt2,
            "--policy",
            "sensitivity-backed",
        ],
    );
    assert_success(&out, "multi-premise sensitivity-backed claim");
    let claim: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("{ROOT}/claims/{receipt}.json"))).unwrap(),
    )
    .unwrap();
    let capability = claim["capability"].as_array().unwrap();
    assert_eq!(capability.len(), 2, "one capability entry per claimed axis");
    let exit_cap = capability
        .iter()
        .find(|c| c["axis"] == "exit")
        .expect("exit capability");
    assert_eq!(exit_cap["receipt"], receipt);
    assert!(!exit_cap["challenge_ids"].as_array().unwrap().is_empty());
    let stdout_cap = capability
        .iter()
        .find(|c| c["axis"] == "stdout")
        .expect("stdout capability");
    assert_eq!(stdout_cap["receipt"], receipt2);
    assert!(!stdout_cap["challenge_ids"].as_array().unwrap().is_empty());
    // The challenge records are content-addressed and bound to the RIGHT
    // court: the exit challenge answers the resolution court's question, the
    // stdout challenge the stdout-only court's question.
    let store = Store::new(work.path(ROOT));
    for cid in exit_cap["challenge_ids"].as_array().unwrap() {
        let ch = store.load_challenge(cid.as_str().unwrap()).unwrap();
        assert_eq!(ch.court, "cli-malformed-input");
    }
    for cid in stdout_cap["challenge_ids"].as_array().unwrap() {
        let ch = store.load_challenge(cid.as_str().unwrap()).unwrap();
        assert_eq!(ch.court, "cli-stdout-only");
    }
}

#[test]
fn high_assurance_requires_the_reference_execution_contract() {
    let work = Workdir::new("policy-high");
    work.copy_canonical_tree();
    let (_run, receipt) = resolution_receipt(&work);

    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "court",
            "challenge",
            MANIFEST,
            "--operators",
            "exit-class",
        ],
    );
    assert_success(&out, "court challenge");

    // The golden path runs under the reference profile with the reference
    // bounds, so the challenge + witness path compiles at the top tier too.
    // (The witness is created inside the resolution receipt's store.)
    let program = work.path("golden/witnesses/attest.py");
    fs::create_dir_all(program.parent().unwrap()).unwrap();
    fs::write(
        &program,
        "#!/usr/bin/env python3\n\
import hashlib, json, sys\n\
raw = sys.stdin.buffer.read()\n\
request_id = hashlib.sha256(raw).hexdigest()\n\
req = json.loads(raw.decode(\"utf-8\"))\n\
response = {\n\
    \"schema_version\": \"frf-witness-response-v3\",\n\
    \"request_id\": request_id,\n\
    \"indeterminate\": False,\n\
    \"failure\": None,\n\
    \"attestation\": {\n\
        \"statement\": req[\"statement\"],\n\
        \"outcome\": \"affirm\",\n\
        \"detail\": \"independent confirmation of the receipt\",\n\
    },\n\
}\n\
json.dump(response, sys.stdout, sort_keys=True, separators=(\",\", \":\"))\n",
    )
    .unwrap();
    set_exec(&program);
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "witness",
            "attest",
            "receipt",
            &receipt,
            "--id",
            "manual-review",
            "--relation",
            "independent-confirmation",
            "--program",
            "golden/witnesses/attest.py",
            "--statement",
            "the receipt binds a verified observation of the passing candidate",
        ],
    );
    assert_success(&out, "witness attest receipt");

    // The DECLARED independence relation (spec/witness.md §6): an operator
    // records which independence claim the attestation rests on and why.
    let wid = stdout(&out);
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
            "the attestation was made by an unaffiliated reviewer against the exported bundle",
        ],
    );
    assert_success(&out, "witness independence");
    let iid = stdout(&out);

    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "claim",
            "compile",
            &receipt,
            "--policy",
            "high-assurance",
        ],
    );
    assert_success(&out, "high-assurance claim");
    let claim: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("{ROOT}/claims/{receipt}.json"))).unwrap(),
    )
    .unwrap();
    assert_eq!(claim["policy"], "high-assurance");
    assert_eq!(claim["replay_profile"], "frf-exec-linux-v1");
    assert_eq!(claim["witness_statements"].as_array().unwrap().len(), 1);
    assert_eq!(claim["capability"].as_array().unwrap().len(), 1);
    assert_eq!(
        claim["independence_evidence"],
        serde_json::json!([iid]),
        "the claim carries the declared independence evidence"
    );
    // The record is verified on read: identity rederives, the bound
    // statement verifies.
    let store = Store::new(work.path(ROOT));
    store.load_independence(&iid).unwrap();
}

#[test]
fn the_bundle_carries_the_independence_evidence_and_verifies() {
    let work = Workdir::new("policy-independence-bundle");
    work.copy_canonical_tree();
    let (_run, receipt) = resolution_receipt(&work);

    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "court",
            "challenge",
            MANIFEST,
            "--operators",
            "exit-class",
        ],
    );
    assert_success(&out, "court challenge");

    let program = work.path("golden/witnesses/attest.py");
    fs::create_dir_all(program.parent().unwrap()).unwrap();
    fs::write(
        &program,
        "#!/usr/bin/env python3\n\
import hashlib, json, sys\n\
raw = sys.stdin.buffer.read()\n\
request_id = hashlib.sha256(raw).hexdigest()\n\
req = json.loads(raw.decode(\"utf-8\"))\n\
response = {\n\
    \"schema_version\": \"frf-witness-response-v3\",\n\
    \"request_id\": request_id,\n\
    \"indeterminate\": False,\n\
    \"failure\": None,\n\
    \"attestation\": {\n\
        \"statement\": req[\"statement\"],\n\
        \"outcome\": \"affirm\",\n\
        \"detail\": \"independent confirmation of the receipt\",\n\
    },\n\
}\n\
json.dump(response, sys.stdout, sort_keys=True, separators=(\",\", \":\"))\n",
    )
    .unwrap();
    set_exec(&program);
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "witness",
            "attest",
            "receipt",
            &receipt,
            "--id",
            "manual-review",
            "--relation",
            "independent-confirmation",
            "--program",
            "golden/witnesses/attest.py",
            "--statement",
            "the receipt binds a verified observation of the passing candidate",
        ],
    );
    assert_success(&out, "witness attest receipt");
    let wid = stdout(&out);
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "witness",
            "independence",
            &wid,
            "--relation",
            "unaffiliated-channel",
            "--basis",
            "the reviewer examined only the exported bundle, never the producing installation",
        ],
    );
    assert_success(&out, "witness independence");
    let iid = stdout(&out);

    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "claim",
            "compile",
            &receipt,
            "--policy",
            "high-assurance",
        ],
    );
    assert_success(&out, "high-assurance claim");

    // Export: the closure carries the independence record AND the witness
    // program object the claim's evidence refs point at.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "bundle",
            "export",
            &receipt,
            "--output",
            "portable-independence.frf",
        ],
    );
    assert_success(&out, "bundle export (independence)");
    let bundle = work.path("portable-independence.frf");
    assert!(
        bundle.join(format!("independence/{iid}.json")).is_file(),
        "the bundle must carry the independence record"
    );
    assert!(
        fs::read_dir(bundle.join("witnesses")).unwrap().count() >= 1,
        "the bundle must carry the witness statement"
    );
    let stmt = {
        let store = Store::new(work.path(ROOT));
        store.load_witness_statement(&wid).unwrap()
    };
    if let Some(artifact) = &stmt.witness_implementation.artifact {
        assert!(
            bundle
                .join(format!("objects/sha256/{}", artifact.sha256))
                .is_file(),
            "the bundle must carry the witness program object"
        );
    }
    // The independent verifiers agree from the bundle alone (identity
    // rederives, the independence record binds a carried witness statement).
    let out = frf(&work, &["bundle", "verify", "portable-independence.frf"]);
    assert_success(&out, "bundle verify (independence)");
}

#[test]
fn the_bundle_carries_the_capability_evidence_and_verifies() {
    let work = Workdir::new("policy-bundle");
    work.copy_canonical_tree();
    let (_run, receipt) = resolution_receipt(&work);

    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "court",
            "challenge",
            MANIFEST,
            "--operators",
            "exit-class",
        ],
    );
    assert_success(&out, "court challenge");

    let program = work.path("golden/witnesses/attest.py");
    fs::create_dir_all(program.parent().unwrap()).unwrap();
    fs::write(
        &program,
        "#!/usr/bin/env python3\n\
import hashlib, json, sys\n\
raw = sys.stdin.buffer.read()\n\
request_id = hashlib.sha256(raw).hexdigest()\n\
req = json.loads(raw.decode(\"utf-8\"))\n\
response = {\n\
    \"schema_version\": \"frf-witness-response-v3\",\n\
    \"request_id\": request_id,\n\
    \"indeterminate\": False,\n\
    \"failure\": None,\n\
    \"attestation\": {\n\
        \"statement\": req[\"statement\"],\n\
        \"outcome\": \"affirm\",\n\
        \"detail\": \"independent confirmation of the receipt\",\n\
    },\n\
}\n\
json.dump(response, sys.stdout, sort_keys=True, separators=(\",\", \":\"))\n",
    )
    .unwrap();
    set_exec(&program);
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "witness",
            "attest",
            "receipt",
            &receipt,
            "--id",
            "manual-review",
            "--relation",
            "independent-confirmation",
            "--program",
            "golden/witnesses/attest.py",
            "--statement",
            "the receipt binds a verified observation of the passing candidate",
        ],
    );
    assert_success(&out, "witness attest receipt");

    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "claim",
            "compile",
            &receipt,
            "--policy",
            "high-assurance",
        ],
    );
    assert_success(&out, "high-assurance claim");

    // Export the bundle: the closure must carry the challenge record + its
    // mutant run, and the witness statement + its preserved documents.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "bundle",
            "export",
            &receipt,
            "--output",
            "portable-policy.frf",
        ],
    );
    assert_success(&out, "bundle export");
    let bundle = work.path("portable-policy.frf");
    assert!(bundle.is_dir());
    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(bundle.join("manifest.json")).unwrap()).unwrap();
    let inventory: Vec<serde_json::Value> = manifest["inventory"].as_array().unwrap().clone();
    let paths: Vec<&str> = inventory
        .iter()
        .map(|e| e["path"].as_str().unwrap())
        .collect();
    assert!(
        paths.iter().any(|p| p.starts_with("challenges/")),
        "the bundle must carry the challenge evidence: {paths:?}"
    );
    assert!(
        paths.iter().any(|p| p.starts_with("witnesses/")),
        "the bundle must carry the witness evidence: {paths:?}"
    );

    // The independent verifiers re-derive the policy admission from the
    // bundle alone (the engine-side `bundle export` already verified the
    // closure against the source tree).
    let store = Store::new(work.path(ROOT));
    store.ensure_tree().unwrap();
}
