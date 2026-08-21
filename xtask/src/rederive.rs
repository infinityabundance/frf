//! Rederivations — the same identity functions the reference engine uses,
//! recomputed here from the document alone. If these disagree with the
//! reference engine on the same bundle, FRF is a Rust file format; if they
//! agree, it is a protocol.

use serde_json::{json, Value};

fn sha256_bytes(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

fn preimage(kind: &str, doc: &Value) -> String {
    use crate::jcs::encode;
    let canonical = encode(doc).unwrap_or_else(|e| panic!("preimage {kind}: {e}"));
    sha256_bytes(format!("{kind}\n{canonical}").as_bytes())
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap_or_default()
}

/// Environment digest: sha256("os={os}\narch={arch}\nkernel={kernel}").
pub fn env_digest(os: &str, arch: &str, kernel: &str) -> String {
    sha256_bytes(format!("os={os}\narch={arch}\nkernel={kernel}").as_bytes())
}

pub fn interpreter_hash(artifact: &Value) -> Option<String> {
    artifact
        .get("interpreter")
        .and_then(|i| i.get("downstream_interpreter"))
        .and_then(|d| d.get("sha256"))
        .map(s)
        .map(str::to_string)
}

/// FRF/COURT/v1 over the receipt's own document (declared arguments,
/// authority artifact hash, fixture, envelope, comparator semantics).
pub fn court_semantic_identity_from_receipt(rec: &Value) -> String {
    let court = &rec["court"];
    let env = &court["admissibility_envelope"];
    let fixture = &rec["fixtures"][0];
    let doc = json!({
        "question": s(&court["question"]),
        "falsifier": s(&court["falsifier"]),
        "authority_artifact_identity": s(&rec["authority"]["identity_hash"]),
        "fixture": {
            "id": s(&fixture["id"]),
            "sha256": s(&fixture["hash"]),
            "arguments": fixture["declared_arguments"],
        },
        "envelope": {
            "fixture_family": s(&env["fixture_family"]),
            "platforms": env["platforms"],
            "observables": env["observables"],
            "normalizers": env["normalizers"],
            "replay_scope": s(&env["replay_scope"]),
        },
        "comparators": rec["comparator_semantics"]
            .as_array()
            .map(|cs| {
                cs.iter()
                    .map(|c| {
                        json!({
                            "id": s(&c["id"]),
                            "relation_id": s(&c["relation_id"]),
                            "relation_version": s(&c["relation_version"]),
                            "specification_hash": s(&c["specification_hash"]),
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
    });
    preimage("FRF/COURT/v1", &doc)
}

/// FRF/RESIDUAL-FINGERPRINT/v1 over the immutable observation record.
pub fn residual_fingerprint(record: &Value) -> String {
    let doc = json!({
        "kind": s(&record["kind"]),
        "axis": s(&record["axis"]),
        "surface": record.get("surface").cloned().unwrap_or(Value::Null),
        "reference_sha256": sha256_bytes(s(&record["raw_reference"]).as_bytes()),
        "candidate_sha256": sha256_bytes(s(&record["raw_candidate"]).as_bytes()),
    });
    preimage("FRF/RESIDUAL-FINGERPRINT/v1", &doc)
}

fn side(doc: &Value) -> Value {
    json!({
        "exit": s(&doc["exit"]),
        "stdout_sha256": s(&doc["stdout_sha256"]),
        "stderr_sha256": s(&doc["stderr_sha256"]),
        "stdout_first_line": s(&doc["stdout_first_line"]),
        "stderr_first_line": s(&doc["stderr_first_line"]),
    })
}

/// FRF/RUN/v1 over the capture's recorded fields — the name is a claim until
/// recomputed.
pub fn run_identity(cap: &Value, residuals: &[Value]) -> String {
    let doc = json!({
        "court": s(&cap["court"]),
        "authority": s(&cap["authority"]),
        "authority_interpreter": interpreter_hash(&cap["authority_artifact"]),
        "candidate_sha256": s(&cap["candidate_artifact"]["sha256"]),
        "candidate_interpreter": interpreter_hash(&cap["candidate_artifact"]),
        "fixture_sha256": s(&cap["fixture_sha256"]),
        "arguments": cap["arguments"],
        "environment_digest": s(&cap["environment"]["digest"]),
        "runner_hash": s(&cap["provenance"]["runner"]["frf_executable_hash"]),
        "court_semantic_identity": s(&cap["court_semantic_identity"]),
        "reference": side(&cap["reference"]),
        "candidate": side(&cap["candidate"]),
        "residuals": residuals
            .iter()
            .map(|r| {
                json!({
                    "kind": s(&r["kind"]),
                    "raw_reference": s(&r["raw_reference"]),
                    "raw_candidate": s(&r["raw_candidate"]),
                })
            })
            .collect::<Vec<_>>(),
    });
    preimage("FRF/RUN/v1", &doc)
}

/// FRF/DISPOSITION-EVENT/v1 over the event's own fields.
pub fn disposition_event_identity(event: &Value) -> String {
    let disposition = if s(&event["disposition"]) == "fixed" {
        json!({
            "kind": "fixed",
            "reason": s(&event["reason"]),
            "resolution_run_id": s(&event["resolution_run_id"]),
            "closure_predicate": s(&event["closure_predicate"]),
        })
    } else {
        json!({
            "kind": s(&event["disposition"]),
            "reason": s(&event["reason"]),
        })
    };
    let doc = json!({
        "residual_id": s(&event["residual_id"]),
        "parent_event_id": event.get("parent_event_id").cloned().unwrap_or(Value::Null),
        "disposition": disposition,
        "evidence_refs": event.get("evidence_refs").cloned().unwrap_or_else(|| json!([])),
    });
    preimage("FRF/DISPOSITION-EVENT/v1", &doc)
}

/// The κ routing table (Section 12): axis → (surface, magnitude, next_court).
pub fn kappa_next(residual: &Value) -> &'static str {
    match s(&residual["axis"]) {
        "exit" => "cli-exit-minimize",
        "stderr" => "cli-diagnostic-minimize",
        _ => "cli-stdout-minimize",
    }
}

pub fn expected_token(residual: &Value) -> String {
    let (surface, magnitude) = match s(&residual["axis"]) {
        "exit" => ("exit-class", "class-change"),
        "stderr" => ("diagnostic-routing", "first-line-token-change"),
        _ => ("stdout-routing", "first-line-token-change"),
    };
    format!(
        "{}/{surface}/{magnitude}/{}",
        s(&residual["kind"]),
        s(&residual["disposition"])
    )
}

pub fn expected_blocks(residual: &Value, family: &str) -> String {
    match s(&residual["axis"]) {
        "exit" => format!("{family} exit parity"),
        "stderr" => "byte-identical diagnostics".to_string(),
        _ => "byte-identical stdout".to_string(),
    }
}

/// The deterministic repeat-axis classification (the paper's restraint: a
/// single-run court cannot observe drift/slew).
pub fn classify_repeat(observed: &[bool]) -> (String, String) {
    let n = observed.len();
    let t: Vec<usize> = observed
        .iter()
        .enumerate()
        .filter(|(_, o)| **o)
        .map(|(i, _)| i)
        .collect();
    if t.is_empty() {
        panic!("no observations in the repeat series");
    }
    if t.len() == n {
        return ("persistent".to_string(), "stable".to_string());
    }
    if t.last().unwrap() - t[0] + 1 == t.len() {
        if t[0] == 0 || t.last() == Some(&(n - 1)) {
            return ("transient".to_string(), "abrupt".to_string());
        }
        return ("transient".to_string(), "burst".to_string());
    }
    if t[0] == 0 && t.last() == Some(&(n - 1)) {
        return ("recurrent".to_string(), "recurrent".to_string());
    }
    ("transient".to_string(), "recurrent".to_string())
}
