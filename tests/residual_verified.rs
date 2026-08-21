//! Verified-on-read residuals (spec/evaluation.md, the verified evidence
//! layer): a residual is evidence only after it is proven to derive from a
//! verified parent run — same run/court/authority/candidate, declared axis,
//! comparator-generated divergence, and rederived projections. Parsing a
//! residual-shaped file is not the same thing.
//!
//! The library entry point is `frf::verify::load_residual_verified`; the
//! witness command is the CLI consumer that accepts only `ResidualVerified`.
//!
//! Run: `cargo test --test residual_verified`.

use frf::canon;
use frf::host;
use frf::model::*;
use frf::semantics;
use frf::store::Store;
use frf::verify::load_residual_verified;
use std::fs;
use std::path::PathBuf;

mod common;
use common::*;

fn store(work: &Workdir) -> Store {
    Store::new(work.path(ROOT))
}

/// The refusal message of a failed verification (or a panic if it verified).
fn refusal(store: &Store, id: &str) -> String {
    match load_residual_verified(store, id) {
        Ok(_) => panic!("residual {id} must NOT verify"),
        Err(e) => e.to_string(),
    }
}

/// The canonical golden-path court produces exactly these residuals.
fn golden_residuals(work: &Workdir) -> Vec<String> {
    let out = frf(work, &["--root", ROOT, "court", "run", MANIFEST]);
    assert_success(&out, "court run");
    let run = stdout(&out);
    assert!(run.starts_with("run-cli-malformed-input-"), "run id: {run}");
    let mut ids = Vec::new();
    for entry in fs::read_dir(work.path(&format!("{ROOT}/residuals"))).unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().to_string();
        if name.ends_with(".json") && !name.ends_with(".token.json") {
            ids.push(name.trim_end_matches(".json").to_string());
        }
    }
    ids.sort();
    assert!(!ids.is_empty(), "the golden court must produce residuals");
    ids
}

/// Load the canonical JSON of a residual record, mutate one field, and write
/// it back STILL canonical (so the refusal comes from the derivation checks,
/// not from the canonical-bytes loader).
fn rewrite_canonical_residual(
    work: &Workdir,
    id: &str,
    mutate: impl FnOnce(&mut serde_json::Value),
) {
    let path = work.path(&format!("{ROOT}/residuals/{id}.json"));
    let value = canon::parse_strict(&fs::read(&path).unwrap()).unwrap();
    let mut value = serde_json::to_value(value).unwrap();
    mutate(&mut value);
    let canonical = canon::canonical(&value).unwrap();
    fs::write(&path, canonical.into_bytes()).unwrap();
}

#[test]
fn every_residual_verifies_against_its_parent_run() {
    let work = Workdir::new("rv-all");
    work.copy_canonical_tree();
    admit_reference(&work);
    for id in golden_residuals(&work) {
        let verified = load_residual_verified(&store(&work), &id)
            .unwrap_or_else(|e| panic!("residual {id} must verify: {e}"));
        assert_eq!(verified.id(), id);
        assert_eq!(verified.record().id, id);
        assert_eq!(verified.record().run, verified.capture().run);
        assert_eq!(verified.record().court, verified.capture().capture.court);
        assert_eq!(
            verified.record().authority,
            verified.capture().capture.authority
        );
        assert_eq!(
            verified.record().candidate_sha256,
            verified.capture().capture.candidate_artifact.sha256
        );
        // The capture lists the residual back.
        assert!(verified
            .capture()
            .capture
            .residuals
            .iter()
            .any(|rid| rid == &id));
        // The axis is declared.
        assert!(verified
            .capture()
            .capture
            .comparator_semantics
            .iter()
            .any(|s| s.id == verified.record().axis.as_str()));
        // The fingerprint rederives from the verified record.
        let fp = semantics::residual_fingerprint(verified.record()).unwrap();
        assert_eq!(fp.len(), 64);
    }
}

#[test]
fn a_hand_edited_residual_is_refused() {
    let work = Workdir::new("rv-tamper");
    work.copy_canonical_tree();
    admit_reference(&work);
    let ids = golden_residuals(&work);
    assert!(ids.contains(&"cli-exit-0001".to_string()));

    // A divergence that does not rederive from the verified sides: the
    // recorded raw projections no longer equal what the comparator derived.
    rewrite_canonical_residual(&work, "cli-exit-0001", |v| {
        v["raw_candidate"] = serde_json::Value::String("999".to_string());
    });
    let err = refusal(&store(&work), "cli-exit-0001");
    let msg = err;
    assert!(
        msg.contains("does not rederive") || msg.contains("hash to"),
        "unexpected refusal: {msg}"
    );
}

#[test]
fn an_undeclared_axis_is_refused() {
    let work = Workdir::new("rv-axis");
    work.copy_canonical_tree();
    admit_reference(&work);
    let ids = golden_residuals(&work);
    assert!(ids.contains(&"cli-exit-0001".to_string()));

    // Point the residual at an axis the court never declared.
    rewrite_canonical_residual(&work, "cli-exit-0001", |v| {
        v["axis"] = serde_json::Value::String("dns.wire".to_string());
    });
    let err = refusal(&store(&work), "cli-exit-0001");
    assert!(
        err.contains("was not declared"),
        "unexpected refusal: {err}"
    );
}

#[test]
fn a_corrupted_parent_capture_refuses_every_residual() {
    let work = Workdir::new("rv-capture");
    work.copy_canonical_tree();
    admit_reference(&work);
    let ids = golden_residuals(&work);

    // Corrupt the capture: change the recorded exit of the reference side
    // (canonically, so the capture loader parses it and the RUN IDENTITY
    // fails to rederive — the name is a claim until recomputed).
    let run = {
        let first = ids.first().unwrap().clone();
        let record: ResidualRecord = {
            let path = work.path(&format!("{ROOT}/residuals/{first}.json"));
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap()
        };
        record.run
    };
    let cap_path = work.path(&format!("{ROOT}/captures/{run}/capture.json"));
    let value = canon::parse_strict(&fs::read(&cap_path).unwrap()).unwrap();
    let mut value = serde_json::to_value(value).unwrap();
    value["reference"]["exit"] = serde_json::Value::String("7".to_string());
    let canonical = canon::canonical(&value).unwrap();
    fs::write(&cap_path, canonical.into_bytes()).unwrap();

    for id in &ids {
        let err = refusal(&store(&work), id);
        assert!(
            err.contains("do not hash to the run identity") || err.contains("not self"),
            "residual {id}: unexpected refusal: {err}"
        );
    }
}

#[test]
fn a_residual_witness_binds_the_verified_fingerprint() {
    let work = Workdir::new("rv-witness");
    work.copy_canonical_tree();
    admit_reference(&work);
    let ids = golden_residuals(&work);
    let subject = ids.first().unwrap().clone();

    // The witness program echoes the request and affirms the statement.
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
    \"schema_version\": \"frf-witness-response-v2\",\n\
    \"request_id\": request_id,\n\
    \"indeterminate\": False,\n\
    \"failure\": None,\n\
    \"attestation\": {\n\
        \"statement\": req[\"statement\"],\n\
        \"outcome\": \"affirm\",\n\
        \"detail\": \"verified from the recorded observation\",\n\
    },\n\
}\n\
json.dump(response, sys.stdout, sort_keys=True, separators=(\",\", \":\"))\n",
    )
    .unwrap();
    set_exec(&program);

    let statement = "this exact residual divergence is a real observation";
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "witness",
            "attest",
            "residual",
            &subject,
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
    assert_success(&out, "witness attest residual");
    let stmt_id = stdout(&out);
    assert_eq!(stmt_id.len(), 64);

    // The bound subject content address is the REDERIVED fingerprint of the
    // VERIFIED record — never a caller-supplied address.
    let store = store(&work);
    let verified = load_residual_verified(&store, &subject).unwrap();
    let fp = semantics::residual_fingerprint(verified.record()).unwrap();
    let stmt = store.load_witness_statement(&stmt_id).unwrap();
    assert_eq!(stmt.subject.kind, "residual");
    assert_eq!(stmt.subject.id, subject);
    assert_eq!(stmt.subject.cid, fp);

    // The preserved request names the same subject content address.
    let request_path: PathBuf = work.path(&format!("{ROOT}/witnesses/{stmt_id}/request.json"));
    let request = canon::parse_strict(&fs::read(&request_path).unwrap()).unwrap();
    assert_eq!(request["subject"]["cid"], serde_json::Value::String(fp));
    assert_eq!(
        request["subject"]["id"],
        serde_json::Value::String(subject.clone())
    );

    // A hand-edited residual can no longer be witnessed: the derivation
    // proof fails before any statement is produced.
    rewrite_canonical_residual(&work, &subject, |v| {
        v["raw_reference"] = serde_json::Value::String("forged".to_string());
    });
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "witness",
            "attest",
            "residual",
            &subject,
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
    assert!(
        !out.status.success(),
        "a forged residual must not be witnessed"
    );
    assert!(
        !out.status.success(),
        "a forged residual must not be witnessed"
    );
    // The forged raw projection breaks the run identity commitment (the
    // residual's raw projections are part of FRF/RUN/v1), so the refusal
    // names the run — fail-closed either way.
    let stderr = stderr(&out);
    assert!(
        stderr.contains("does not rederive")
            || stderr.contains("hash to")
            || stderr.contains("not self"),
        "unexpected refusal: {stderr}"
    );

    // The reference side file is rehashed against the recorded hash by
    // load_capture_verified: the same raw bytes produce the same hash.
    let run = verified.record().run.clone();
    let side = fs::read(work.path(&format!("{ROOT}/captures/{run}/reference.stdout"))).unwrap();
    assert_eq!(
        host::sha256_bytes(&side),
        verified.capture().capture.reference.stdout_sha256
    );
}
