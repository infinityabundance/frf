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

/// The protocol identifier grammar: lowercase letter first, then lowercase
/// letters, digits, `.`, `_`, `-`; 1..=64 characters. Mirrors the reference
/// engine's ObservableId/ResidualKind validation.
pub fn is_valid_identifier(s: &str) -> bool {
    if s.is_empty() || s.len() > 64 {
        return false;
    }
    let mut chars = s.chars();
    if !chars.next().is_some_and(|c| c.is_ascii_lowercase()) {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
}

/// FRF/COMPARATOR-SPEC/v1 over the specification document
/// (id + relation + extractor + residual_classifier) — the comparator's
/// semantic identity, rederivable from a recorded ComparatorSemantic's own
/// fields.
pub fn comparator_spec_hash(id: &str, relation: &str, extractor: &str, classifier: &str) -> String {
    preimage(
        "FRF/COMPARATOR-SPEC/v1",
        &json!({
            "id": id,
            "relation": relation,
            "extractor": extractor,
            "residual_classifier": classifier,
        }),
    )
}

/// Environment digest: sha256("os={os}\narch={arch}\nkernel={kernel}\n
/// locale={locale}\ntimezone={timezone}\numask={umask}").
pub fn env_digest(
    os: &str,
    arch: &str,
    kernel: &str,
    locale: &str,
    timezone: &str,
    umask: &str,
) -> String {
    sha256_bytes(
        format!(
            "os={os}\narch={arch}\nkernel={kernel}\nlocale={locale}\ntimezone={timezone}\numask={umask}"
        )
        .as_bytes(),
    )
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
        "produced": doc.get("produced").map(|p| json!({
            "schema_version": s(&p["schema_version"]),
            "manifest_sha256": s(&p["manifest_sha256"]),
            "files": p["files"].as_array().map(|fs| fs.iter().map(|f| json!({
                "path": s(&f["path"]),
                "sha256": s(&f["sha256"]),
                "executable": f["executable"].as_bool().unwrap_or(false),
            })).collect::<Vec<_>>()).unwrap_or_default(),
        })),
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

/// The κ routing table (Section 12): axis → next_court. Built-in rows as in
/// the reference engine; any other axis has no routed minimizer (`none`).
pub fn kappa_next(residual: &Value) -> String {
    match s(&residual["axis"]) {
        "exit" => "cli-exit-minimize".to_string(),
        "stderr" => "cli-diagnostic-minimize".to_string(),
        "stdout" => "cli-stdout-minimize".to_string(),
        _ => "none".to_string(),
    }
}

pub fn expected_token(residual: &Value) -> String {
    let (surface, magnitude) = match s(&residual["axis"]) {
        "exit" => ("exit-class".to_string(), "class-change".to_string()),
        "stderr" => (
            "diagnostic-routing".to_string(),
            "first-line-token-change".to_string(),
        ),
        "stdout" => (
            "stdout-routing".to_string(),
            "first-line-token-change".to_string(),
        ),
        other => (format!("{other}-divergence"), "observed".to_string()),
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
        "stdout" => "byte-identical stdout".to_string(),
        other => format!("{family} {other} parity"),
    }
}

/// The residual LINEAGE identity: the stable comparison question/surface/
/// feature (kind, axis, surface, fixture, fixture family, authority NAME) —
/// deliberately not the exact observed bytes, so trajectories can record the
/// MOVEMENT of a divergence across candidate revisions, authority versions,
/// environments, and time.
pub fn residual_lineage(
    kind: &str,
    axis: &str,
    surface: Option<&str>,
    fixture_family: &str,
    authority_name: &str,
    fixture: &str,
) -> String {
    let doc = json!({
        "kind": kind,
        "axis": axis,
        "surface": surface,
        "fixture_family": fixture_family,
        "authority_name": authority_name,
        "fixture": fixture,
    });
    preimage("FRF/RESIDUAL-LINEAGE/v1", &doc)
}

/// The ExecutionSeries identity: content-addressed over the experiment
/// (experiment key, parent snapshot, court, coordinate system, ordered
/// points; the point index enters as its string form — the canonical value
/// domain has no numbers). v2: parent-linked — an append is a NEW immutable
/// node of the experiment's history.
pub fn series_identity(
    experiment_id: &str,
    parent_series_id: Option<&str>,
    court: &str,
    coordinate_system: &str,
    points: &Value,
) -> String {
    let doc = json!({
        "experiment_id": experiment_id,
        "parent_series_id": parent_series_id,
        "court": court,
        "coordinate_system": coordinate_system,
        "points": points.as_array().map(|ps| {
            ps.iter()
                .map(|p| {
                    json!({
                        "point_index": s(&p["point_index"]).to_string(),
                        "coordinate": s(&p["coordinate"]),
                        "run": s(&p["run"]),
                    })
                })
                .collect::<Vec<_>>()
        }).unwrap_or_default(),
    });
    preimage("FRF/SERIES/v2", &doc)
}

/// FRF/REDUCTION/v2 over the minimization record's own fields — every bound
/// identity (candidate artifact, authority artifact, environment,
/// comparator semantic + implementation) plus the attempts, the derivation,
/// and the transform declaration.
#[allow(clippy::too_many_arguments)]
pub fn reduction_identity(
    residual_id: &str,
    source_run: &str,
    axis: &str,
    kind: &str,
    court_semantic_identity: &str,
    authority_artifact_sha256: &str,
    candidate_artifact_sha256: &str,
    environment_digest: &str,
    comparator_semantic_id: &str,
    comparator_semantic_hash: &str,
    comparator_implementation_hash: &str,
    argv_template: &Value,
    original_fixture_sha256: &str,
    final_fixture_sha256: &str,
    attempts: &Value,
    derivation: &Value,
    transform: &Value,
) -> String {
    let doc = json!({
        "residual_id": residual_id,
        "source_run": source_run,
        "axis": axis,
        "kind": kind,
        "court_semantic_identity": court_semantic_identity,
        "authority_artifact_sha256": authority_artifact_sha256,
        "candidate_artifact_sha256": candidate_artifact_sha256,
        "environment_digest": environment_digest,
        "comparator_semantic_id": comparator_semantic_id,
        "comparator_semantic_hash": comparator_semantic_hash,
        "comparator_implementation_hash": comparator_implementation_hash,
        "argv_template": argv_template,
        "original_fixture_sha256": original_fixture_sha256,
        "final_fixture_sha256": final_fixture_sha256,
        "attempts": attempts.as_array().map(|as_| {
            as_.iter()
                .map(|a| json!({
                    "attempt": s(&a["attempt"]),
                    "role": s(&a["role"]),
                    "fixture_sha256": s(&a["fixture_sha256"]),
                    "outcome": s(&a["outcome"]),
                    "accepted": a["accepted"].as_bool().unwrap_or(false),
                }))
                .collect::<Vec<_>>()
        }).unwrap_or_default(),
        "derivation": {
            "strategy": s(&derivation["strategy"]),
            "original_lines": s(&derivation["original_lines"]),
            "final_lines": s(&derivation["final_lines"]),
            "minimality": {
                "kind": s(&derivation["minimality"]["kind"]),
                "granularity": s(&derivation["minimality"]["granularity"]),
                "proven": derivation["minimality"]["proven"].as_bool().unwrap_or(false),
            },
        },
        "transform": transform,
    });
    preimage("FRF/REDUCTION/v2", &doc)
}

/// FRF/KNOWLEDGE/v1 over the claim's committed evidence universe: the
/// residual heads (with their dispositions + events), receipts, runs,
/// authorities, series snapshots, and reductions present at compile time.
/// Sorted lists — the same universe hashes identically in every
/// implementation.
pub fn knowledge_snapshot_identity(snapshot: &Value) -> String {
    let doc = json!({
        "residual_heads": snapshot["residual_heads"].as_array().map(|hs| {
            hs.iter()
                .map(|h| json!({
                    "id": s(&h["id"]),
                    "disposition": s(&h["disposition"]),
                    "disposition_event_id": h.get("disposition_event_id").cloned().unwrap_or(Value::Null),
                }))
                .collect::<Vec<_>>()
        }).unwrap_or_default(),
        "receipts": snapshot["receipts"],
        "runs": snapshot["runs"],
        "authorities": snapshot["authorities"],
        "series": snapshot["series"],
        "reductions": snapshot["reductions"],
    });
    preimage("FRF/KNOWLEDGE/v1", &doc)
}

/// The deterministic ordered-axis classification: drift, slew, localization,
/// and bands. Mirrors the reference engine's trajectory::classify.
pub fn classify(observed: &[bool]) -> (String, String, String, u32) {
    let n = observed.len();
    let t: Vec<usize> = observed
        .iter()
        .enumerate()
        .filter(|(_, o)| **o)
        .map(|(i, _)| i)
        .collect();
    if t.is_empty() {
        panic!("no observations in the series");
    }
    let first = *t.first().unwrap();
    let last = *t.last().unwrap();
    let mut bands = 1u32;
    for w in t.windows(2) {
        if w[1] != w[0] + 1 {
            bands += 1;
        }
    }
    let contiguous = last - first + 1 == t.len();
    if t.len() == n {
        ("persistent".into(), "stable".into(), "none".into(), bands)
    } else if contiguous {
        if first == 0 {
            ("transient".into(), "abrupt".into(), "start".into(), bands)
        } else if last == n - 1 {
            ("transient".into(), "abrupt".into(), "end".into(), bands)
        } else {
            ("transient".into(), "burst".into(), "interior".into(), bands)
        }
    } else if first == 0 && last == n - 1 {
        ("recurrent".into(), "recurrent".into(), "both".into(), bands)
    } else {
        let localization = if first == 0 {
            "start"
        } else if last == n - 1 {
            "end"
        } else {
            "interior"
        };
        (
            "transient".into(),
            "recurrent".into(),
            localization.into(),
            bands,
        )
    }
}
