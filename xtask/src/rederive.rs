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

/// The minimizer document a reduction's identity binds: built from the
/// record's OWN `minimizer_*` fields (the record carries no top-level
/// `minimizer` key) — mirroring the reference engine's
/// `store::minimizer_binding`. `Null` for a built-in ddmin reduction (the
/// identity's `minimizer` member is optional).
pub fn minimizer_doc(reduction: &Value) -> Value {
    if !reduction["minimizer_semantic_id"].is_string() {
        return Value::Null;
    }
    let mut map = serde_json::Map::new();
    for key in [
        "semantic_id",
        "semantic_hash",
        "implementation_hash",
        "implementation_artifact",
        "invocation_id",
        "result_id",
    ] {
        map.insert(
            key.to_string(),
            reduction[&format!("minimizer_{key}")].clone(),
        );
    }
    Value::Object(map)
}

/// The identity of a harness-enforcement evidence record: `FRF/HARNESS-EVENT/v1`
/// over the event's own fields (the id is never in the preimage). Mirrors the
/// reference engine's `semantics::harness_event_identity`.
pub fn harness_event_identity(event: &Value) -> String {
    preimage(
        "FRF/HARNESS-EVENT/v1",
        &json!({
            "event_kind": s(&event["event_kind"]),
            "side": s(&event["side"]),
            "court": s(&event["court"]),
            "execution_profile": s(&event["execution_profile"]),
            "cap": s(&event["cap"]),
            "observed": s(&event["observed"]),
            "target": s(&event["target"]),
            "detail": s(&event["detail"]),
            "runner": s(&event["runner"]),
        }),
    )
}

/// The identity of a refused execution-attempt record: `FRF/EXECUTION-ATTEMPT/v1`
/// over the record's own fields minus the id (the cited harness events sorted,
/// so the identity is a deterministic function of the cited SET). Mirrors the
/// reference engine's `semantics::execution_attempt_identity`.
pub fn execution_attempt_identity(attempt: &Value) -> String {
    let mut events: Vec<&Value> = attempt["harness_events"]
        .as_array()
        .map(|es| es.iter().collect())
        .unwrap_or_default();
    events.sort_by(|a, b| s(a).cmp(s(b)));
    preimage(
        "FRF/EXECUTION-ATTEMPT/v1",
        &json!({
            "court": s(&attempt["court"]),
            "court_semantic_identity": s(&attempt["court_semantic_identity"]),
            "authority_sha256": s(&attempt["authority_sha256"]),
            "candidate_sha256": s(&attempt["candidate_sha256"]),
            "fixture_sha256": s(&attempt["fixture_sha256"]),
            "arguments": attempt["arguments"],
            "environment_digest": s(&attempt["environment_digest"]),
            "execution_profile": s(&attempt["execution_profile"]),
            "capture_bounds": attempt["capture_bounds"],
            "side": s(&attempt["side"]),
            "harness_events": events,
            "refusal_reason": attempt["refusal_reason"],
        }),
    )
}

/// The identity of a native runtime closure: `FRF/RUNTIME-CLOSURE/v1` over
/// the canonical document minus the `cid`, with the components sorted by
/// path — the closure is a deterministic function of the resolved SET.
pub fn runtime_closure_identity(closure: &Value) -> String {
    let mut components: Vec<&Value> = closure["components"]
        .as_array()
        .map(|cs| cs.iter().collect())
        .unwrap_or_default();
    #[allow(clippy::needless_borrow)]
    // auto-deref of &&Value makes the suggested form a type error
    components.sort_by(|a, b| s(&a["path"]).cmp(&s(&b["path"])));
    let doc = json!({
        "schema_version": s(&closure["schema_version"]),
        "interp": {
            "path": s(&closure["interp"]["path"]),
            "sha256": s(&closure["interp"]["sha256"]),
        },
        "components": components.iter().map(|c| json!({
            "path": s(&c["path"]),
            "sha256": s(&c["sha256"]),
        })).collect::<Vec<_>>(),
    });
    preimage("FRF/RUNTIME-CLOSURE/v1", &doc)
}

/// The identity of a DECLARED execution-context closure:
/// `FRF/EXECUTION-CONTEXT/v1` over the canonical document minus the `cid`,
/// with the artifacts sorted by path — the closure is a deterministic
/// function of the declared SET (two observations that snapshot the same
/// declared paths to the same bytes share one identity).
pub fn execution_context_identity(closure: &Value) -> String {
    let mut artifacts: Vec<&Value> = closure["artifacts"]
        .as_array()
        .map(|as_| as_.iter().collect())
        .unwrap_or_default();
    #[allow(clippy::needless_borrow)]
    artifacts.sort_by(|a, b| s(&a["path"]).cmp(&s(&b["path"])));
    let doc = json!({
        "schema_version": s(&closure["schema_version"]),
        "artifacts": artifacts.iter().map(|a| json!({
            "path": s(&a["path"]),
            "role": s(&a["role"]),
            "sha256": s(&a["sha256"]),
        })).collect::<Vec<_>>(),
    });
    preimage("FRF/EXECUTION-CONTEXT/v1", &doc)
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

/// FRF/COMPARATOR-SPEC/v2 over the specification document
/// (id + relation + extractor + residual_classifier + relation_version) — the
/// comparator's semantic identity, rederivable from a recorded
/// ComparatorSemantic's own fields. v2: the version enters the preimage
/// itself, so two relations with the same fields under different versions are
/// two relations.
pub fn comparator_spec_hash(
    id: &str,
    relation: &str,
    extractor: &str,
    classifier: &str,
    relation_version: &str,
) -> String {
    preimage(
        "FRF/COMPARATOR-SPEC/v2",
        &json!({
            "id": id,
            "relation": relation,
            "extractor": extractor,
            "residual_classifier": classifier,
            "relation_version": relation_version,
        }),
    )
}

/// FRF/WITNESS-IDENTITY/v1 over {specification_hash, implementation_hash,
/// interpreter} — the stable WHO behind an attestation.
pub fn witness_identity(semantic: &Value, implementation: &Value) -> String {
    let interpreter = implementation["artifact"]
        .get("interpreter")
        .cloned()
        .filter(|v| !v.is_null());
    preimage(
        "FRF/WITNESS-IDENTITY/v1",
        &json!({
            "specification_hash": s(&semantic["specification_hash"]),
            "implementation_hash": s(&implementation["implementation_hash"]),
            "interpreter": interpreter,
        }),
    )
}

/// FRF/WITNESS-STATEMENT/v1 over the statement's own fields (v3: the witness
/// identity and the declared authority enter the preimage).
pub fn witness_statement_identity(stmt: &Value) -> String {
    preimage(
        "FRF/WITNESS-STATEMENT/v1",
        &json!({
            "subject": stmt["subject"],
            "witness_semantic": stmt["witness_semantic"],
            "witness_implementation": stmt["witness_implementation"],
            "witness_identity": s(&stmt["witness_identity"]),
            "authority": stmt["authority"],
            "statement": s(&stmt["statement"]),
            "attestation": stmt["attestation"],
            "request_cid": s(&stmt["request_cid"]),
            "response_cid": s(&stmt["response_cid"]),
        }),
    )
}

/// FRF/INDEPENDENCE-SPEC/v1 over {relation, relation_version} — the semantic
/// identity of a declared independence relation.
pub fn independence_spec_hash(relation: &str, relation_version: &str) -> String {
    preimage(
        "FRF/INDEPENDENCE-SPEC/v1",
        &json!({ "relation": relation, "relation_version": relation_version }),
    )
}

/// FRF/INDEPENDENCE/v1 over the record's own fields — the content address of
/// a declared independence claim.
pub fn independence_identity(record: &Value) -> String {
    preimage(
        "FRF/INDEPENDENCE/v1",
        &json!({
            "subject": record["subject"],
            "witness_statement": s(&record["witness_statement"]),
            "witness_identity": s(&record["witness_identity"]),
            "relation": s(&record["relation"]),
            "relation_version": s(&record["relation_version"]),
            "specification_hash": s(&record["specification_hash"]),
            "basis": s(&record["basis"]),
            "detail": record["detail"],
            "evidence_refs": record["evidence_refs"],
        }),
    )
}

/// FRF/NORMALIZER-SPEC/v2 over {id, relation, applies_to, relation_version}.
pub fn normalizer_spec_hash(
    id: &str,
    relation: &str,
    applies_to: &str,
    relation_version: &str,
) -> String {
    preimage(
        "FRF/NORMALIZER-SPEC/v2",
        &json!({
            "id": id,
            "relation": relation,
            "applies_to": applies_to,
            "relation_version": relation_version,
        }),
    )
}

/// FRF/CAPTURE-ADAPTER-SPEC/v2 over {id, relation, relation_version}.
pub fn capture_adapter_spec_hash(id: &str, relation: &str, relation_version: &str) -> String {
    preimage(
        "FRF/CAPTURE-ADAPTER-SPEC/v2",
        &json!({
            "id": id,
            "relation": relation,
            "relation_version": relation_version,
        }),
    )
}

/// The exact fixture input identity: `FRF/FIXTURE/v1` over the canonical
/// document of the fixture's semantic id, content SHA-256, and declared
/// arguments — claim scopes and residual surfaces carry this identity in
/// their `fixtures` dimension, so two different files that share a fixture
/// id are different exact inputs.
pub fn fixture_identity(
    semantic_id: &str,
    content_sha256: &str,
    declared_arguments: &Value,
) -> String {
    let doc = json!({
        "semantic_id": semantic_id,
        "content_sha256": content_sha256,
        "declared_arguments": declared_arguments.clone(),
    });
    preimage("FRF/FIXTURE/v1", &doc)
}

/// Environment digest: FRF/ENVIRONMENT/v2 over the canonical-JSON document
/// of the host strata (os/arch/kernel/locale/timezone/umask) AND the
/// declared execution environment map — a declared variable is
/// content-addressed input. The one formula, shared with the reference
/// engine.
pub fn env_digest(
    os: &str,
    arch: &str,
    kernel: &str,
    locale: &str,
    timezone: &str,
    umask: &str,
    environment: &Value,
) -> String {
    let doc = json!({
        "os": os,
        "architecture": arch,
        "kernel_release": kernel,
        "locale": locale,
        "timezone": timezone,
        "umask": umask,
        "environment": environment.clone(),
    });
    preimage("FRF/ENVIRONMENT/v2", &doc)
}

pub fn interpreter_hash(artifact: &Value) -> Option<String> {
    artifact
        .get("interpreter")
        .and_then(|i| i.get("downstream_interpreter"))
        .and_then(|d| d.get("sha256"))
        .map(s)
        .map(str::to_string)
}

/// FRF/COURT/v2 over the receipt's own document (declared arguments,
/// authority artifact hash, fixture, envelope, comparator semantics, the
/// normalizer semantics in application order, and the capture-adapter
/// semantics sorted by axis — the full observation-defining semantics).
pub fn court_semantic_identity_from_receipt(rec: &Value) -> String {
    let court = &rec["court"];
    let env = &court["admissibility_envelope"];
    let fixture = &rec["fixtures"][0];
    let mut adapters = rec["adapter_semantics"]
        .as_array()
        .map(|as_| as_.to_vec())
        .unwrap_or_default();
    adapters.sort_by(|a, b| s(&a["id"]).cmp(s(&b["id"])));
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
        "normalizers": rec["normalizer_semantics"]
            .as_array()
            .map(|ns| {
                ns.iter()
                    .map(|n| {
                        json!({
                            "id": s(&n["id"]),
                            "relation_id": s(&n["relation_id"]),
                            "applies_to": s(&n["applies_to"]),
                            "relation_version": s(&n["relation_version"]),
                            "specification_hash": s(&n["specification_hash"]),
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
        "capture_adapters": adapters
            .iter()
            .map(|a| {
                json!({
                    "id": s(&a["id"]),
                    "relation_id": s(&a["relation_id"]),
                    "relation_version": s(&a["relation_version"]),
                    "specification_hash": s(&a["specification_hash"]),
                })
            })
            .collect::<Vec<_>>(),
    });
    preimage("FRF/COURT/v2", &doc)
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
        "adapted": doc.get("adapted").map(|a| json!({
            "format": s(&a["format"]),
            "payload_base64": s(&a["payload_base64"]),
            "content_sha256": s(&a["content_sha256"]),
        })),
    })
}

/// The residual projection shared by the observation and run identities.
fn residual_projection(r: &Value) -> Value {
    json!({
        "kind": s(&r["kind"]),
        "raw_reference": s(&r["raw_reference"]),
        "raw_candidate": s(&r["raw_candidate"]),
    })
}

/// The implementation projection shared by the execution identity: the exact
/// program that served one axis/route, bound by its implementation hash.
fn implementation_projection(doc: &Value) -> Value {
    json!({
        "id": s(&doc["id"]),
        "implementation_hash": s(&doc["implementation_hash"]),
    })
}

/// FRF/OBSERVATION/v1 over the capture's recorded fields: what was observed
/// — the question, the inputs, the effective environment, and the answer.
pub fn observation_identity(cap: &Value, residuals: &[Value]) -> String {
    let mut doc = json!({
        "court": s(&cap["court"]),
        "court_semantic_identity": s(&cap["court_semantic_identity"]),
        "authority": s(&cap["authority"]),
        "candidate_sha256": s(&cap["candidate_artifact"]["sha256"]),
        "fixture_sha256": s(&cap["fixture_sha256"]),
        "arguments": cap["arguments"],
        "environment_digest": s(&cap["environment"]["digest"]),
        "reference": side(&cap["reference"]),
        "candidate": side(&cap["candidate"]),
        "residuals": residuals.iter().map(residual_projection).collect::<Vec<_>>(),
    });
    // The capture surface is part of the observation contract; entered only
    // when the capture declares one (absent == the pre-surface shape).
    if let Some(surface) = cap.get("publication_surface") {
        if surface.as_array().map(|a| !a.is_empty()).unwrap_or(false) {
            doc["publication_surface"] = surface.clone();
        }
    }
    preimage("FRF/OBSERVATION/v1", &doc)
}

/// FRF/EXECUTION/v1 over the capture's recorded fields: under exactly what
/// machinery and contract the observation was made — the execution profile,
/// the effective capture bounds (including FRF_EXEC_* overrides), the runner
/// executable, the side interpreter chains, and every comparator/normalizer/
/// adapter/minimizer implementation.
pub fn execution_identity(cap: &Value) -> String {
    let bounds = &cap["capture_bounds"];
    let opt = |k: &str| bounds.get(k).cloned().unwrap_or(Value::Null);
    let prov = &cap["provenance"];
    let impls = |k: &str| {
        prov.get(k)
            .and_then(|v| v.as_array())
            .map(|a| a.iter().map(implementation_projection).collect::<Vec<_>>())
            .unwrap_or_default()
    };
    let doc = json!({
        "execution_profile": s(&cap["execution_profile"]),
        "capture_bounds": {
            "timeout_ms": s(&bounds["timeout_ms"]),
            "max_stream_bytes": s(&bounds["max_stream_bytes"]),
            "produced_max_files": s(&bounds["produced_max_files"]),
            "produced_max_bytes": s(&bounds["produced_max_bytes"]),
            "produced_max_file_bytes": s(&bounds["produced_max_file_bytes"]),
            "rlimit_as_mb": s(&bounds["rlimit_as_mb"]),
            "rlimit_cpu_s": s(&bounds["rlimit_cpu_s"]),
            "rlimit_nofile": s(&bounds["rlimit_nofile"]),
            "rlimit_nproc": s(&bounds["rlimit_nproc"]),
            "cgroup_pids_max": opt("cgroup_pids_max"),
            "cgroup_memory_max": opt("cgroup_memory_max"),
            "cgroup_cpu_max": opt("cgroup_cpu_max"),
        },
        "runner_hash": s(&prov["runner"]["frf_executable_hash"]),
        "authority_interpreter": interpreter_hash(&cap["authority_artifact"]),
        "candidate_interpreter": interpreter_hash(&cap["candidate_artifact"]),
        "comparator_implementations": impls("comparator_implementations"),
        "normalizer_implementations": impls("normalizer_implementations"),
        "adapter_implementations": impls("adapter_implementations"),
        "minimizer_implementations": impls("minimizer_implementations"),
        // 0.1.62: the OCI image the observation ran inside (null when the
        // court did not declare frf-exec-oci) — the complete root filesystem
        // is execution machinery, bound by digest.
        "container_image": cap.get("container_image").cloned().unwrap_or(Value::Null),
    });
    preimage("FRF/EXECUTION/v1", &doc)
}

/// FRF/RUN/v2 over the capture's recorded fields — the composition of the
/// observation identity and the execution identity; the name is a claim until
/// recomputed.
pub fn run_identity(cap: &Value, residuals: &[Value]) -> String {
    let doc = json!({
        "observation_identity": observation_identity(cap, residuals),
        "execution_identity": execution_identity(cap),
    });
    preimage("FRF/RUN/v2", &doc)
}

/// FRF/DISPOSITION-EVENT/v1 over the event's own fields.
pub fn disposition_event_identity(event: &Value) -> String {
    let disposition = match s(&event["disposition"]) {
        "fixed" => json!({
            "kind": "fixed",
            "reason": s(&event["reason"]),
            "resolution_run_id": s(&event["resolution_run_id"]),
            "closure_predicate": s(&event["closure_predicate"]),
        }),
        "nonreproduced" => json!({
            "kind": "nonreproduced",
            "reason": s(&event["reason"]),
            "observation_run_id": s(&event["observation_run_id"]),
        }),
        "stabilized" => json!({
            "kind": "stabilized",
            "reason": s(&event["reason"]),
            "trajectory_id": s(&event["trajectory_id"]),
            "consecutive_passes": s(&event["consecutive_passes"]),
            "stabilization_bound": s(&event["stabilization_bound"]),
        }),
        other => json!({
            "kind": other,
            "reason": s(&event["reason"]),
        }),
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
/// node of the experiment's history. v3: each point commits its COORDINATE
/// IDENTITY (`FRF/COORDINATE/v1`) — the series is content-addressed over the
/// exact coordinates, not the labels.
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
                        "coordinate_identity": s(&p["coordinate_identity"]),
                        "run": s(&p["run"]),
                    })
                })
                .collect::<Vec<_>>()
        }).unwrap_or_default(),
    });
    preimage("FRF/SERIES/v3", &doc)
}

/// FRF/REDUCTION/v3 over the minimization record's own fields — every bound
/// identity (candidate artifact, authority artifact, environment,
/// comparator semantic + implementation) plus the attempts, the derivation,
/// the transform declaration, and the external-minimizer binding when an
/// external minimizer performed the reduction.
/// The content address of a REDUCTION record computed from its document
/// (the `reduction_identity` wrapper the regen uses to re-pin fixtures after
/// a schema change): every field the identity commits is read from the
/// document's own recorded values, and the minimizer binding is the store's
/// `minimizer_binding` mirror ([`minimizer_doc`]).
pub fn reduction_identity_from_doc(doc: &Value) -> String {
    use crate::as_str;
    let s = |key: &str| as_str(&doc[key]);
    reduction_identity(
        s("residual_id"),
        s("source_run"),
        s("axis"),
        s("kind"),
        s("court_semantic_identity"),
        s("authority_artifact_sha256"),
        s("candidate_artifact_sha256"),
        s("environment_digest"),
        s("comparator_semantic_id"),
        s("comparator_semantic_hash"),
        s("comparator_implementation_hash"),
        &doc["argv_template"],
        s("original_fixture_sha256"),
        s("final_fixture_sha256"),
        &doc["attempts"],
        &doc["derivation"],
        &doc["transform"],
        &minimizer_doc(doc),
    )
}

/// The content address of a REDUCTION record computed from its document
/// (the `reduction_identity` wrapper the regen uses to re-pin fixtures after
/// a schema change): every field the identity commits is read from the
/// document's own recorded values, and the minimizer binding is the store's
/// `minimizer_binding` mirror.
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
    minimizer: &Value,
) -> String {
    let mut minimality = json!({
        "kind": s(&derivation["minimality"]["kind"]),
        "proven": derivation["minimality"]["proven"]
            .as_bool()
            .unwrap_or(false),
    });
    // The domain-aware predicate fields enter the identity ONLY when the
    // record carries them, exactly as they serialize (absent == the record
    // shape written before the generalization; an explicit coordinate is a
    // different preimage). v5 types the domain: the nested `reduction_domain`
    // (kind + semantic) and the two-point `boundary` (predecessor + value,
    // each with its observed preservation) replace the flat coordinates.
    if let Some(v) = derivation["minimality"].get("granularity") {
        minimality["granularity"] = v.clone();
    }
    if let Some(v) = derivation["minimality"].get("reduction_domain") {
        minimality["reduction_domain"] = v.clone();
    }
    if let Some(v) = derivation["minimality"].get("boundary") {
        minimality["boundary"] = v.clone();
    }
    // The minimizer's claim enters the identity ONLY when the record carries
    // one (absent == None == the record shape written before the field
    // existed; an explicit claim is a different preimage).
    if let Some(v) = derivation["minimality"].get("proposal_minimality_claimed") {
        minimality["proposal_minimality_claimed"] = v.clone();
    }
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
            "minimality": minimality,
        },
        "transform": transform,
        "minimizer": minimizer.as_object().map(|m| json!({
            "semantic_id": s(&m["semantic_id"]),
            "semantic_hash": s(&m["semantic_hash"]),
            "implementation_hash": s(&m["implementation_hash"]),
            "implementation_artifact": &m["implementation_artifact"],
            "invocation_id": s(&m["invocation_id"]),
            "result_id": s(&m["result_id"]),
        })),
    });
    preimage("FRF/REDUCTION/v3", &doc)
}

/// FRF/KNOWLEDGE/v2 over the claim's committed evidence universe: every
/// residual head enters as (id, record content address, fingerprint,
/// disposition, event) — the universe commits the exact immutable
/// observations the blocker scan reads, not labels — and every other member
/// enters as (kind, id, cid) in the objects list. Sorted lists — the same
/// universe hashes identically in every implementation.
pub fn knowledge_snapshot_identity(snapshot: &Value) -> String {
    let doc = json!({
        "residual_heads": snapshot["residual_heads"].as_array().map(|hs| {
            hs.iter()
                .map(|h| json!({
                    "id": s(&h["id"]),
                    "record_cid": s(&h["record_cid"]),
                    "fingerprint": s(&h["fingerprint"]),
                    "disposition": s(&h["disposition"]),
                    "disposition_event_id": h.get("disposition_event_id").cloned().unwrap_or(Value::Null),
                }))
                .collect::<Vec<_>>()
        }).unwrap_or_default(),
        "objects": snapshot["objects"].as_array().map(|os| {
            os.iter()
                .map(|o| json!({
                    "kind": s(&o["kind"]),
                    "id": s(&o["id"]),
                    "cid": s(&o["cid"]),
                }))
                .collect::<Vec<_>>()
        }).unwrap_or_default(),
    });
    preimage("FRF/KNOWLEDGE/v2", &doc)
}

/// The deterministic ordered-axis classification: drift, slew, localization,
/// bands, trend, and magnitude kind. Mirrors the reference engine's
/// trajectory::classify (frf-trajectory-v4): the stratified axes get
/// `version-stratified` for 2+ bands, boundary-touching single bands get
/// `boundary-localized`, and a monotonic magnitude trend licenses `gradual`.
pub fn classify(
    observed: &[bool],
    coordinate_system: &str,
    magnitudes: &[Option<String>],
    magnitude_kind: &str,
) -> (String, String, String, u32, String) {
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
    let stratified = matches!(
        coordinate_system,
        "authority_version" | "candidate_revision"
    );
    let (drift, slew, localization) = if t.len() == n {
        ("persistent", "stable", "none")
    } else if contiguous {
        if first == 0 {
            ("boundary-localized", "abrupt", "start")
        } else if last == n - 1 {
            ("boundary-localized", "abrupt", "end")
        } else {
            ("transient", "burst", "interior")
        }
    } else if bands >= 2 && stratified {
        let localization = if first == 0 && last == n - 1 {
            "both"
        } else if first == 0 {
            "start"
        } else if last == n - 1 {
            "end"
        } else {
            "interior"
        };
        ("version-stratified", "recurrent", localization)
    } else if first == 0 && last == n - 1 {
        ("recurrent", "recurrent", "both")
    } else {
        let localization = if first == 0 {
            "start"
        } else if last == n - 1 {
            "end"
        } else {
            "interior"
        };
        ("transient", "recurrent", localization)
    };
    let trend = magnitude_trend(observed, magnitudes, magnitude_kind);
    let slew = if matches!(trend.as_str(), "increasing" | "decreasing") {
        "gradual"
    } else {
        slew
    };
    (
        drift.to_string(),
        slew.to_string(),
        localization.to_string(),
        bands,
        trend,
    )
}

/// The magnitude trend over the observed points (mirrors the reference
/// engine): `unknown` when no measure is declared or fewer than three
/// observed magnitudes; else `flat` / `increasing` / `decreasing` /
/// `non-monotonic`. Only OBSERVED points carry a magnitude.
pub fn magnitude_trend(
    observed: &[bool],
    magnitudes: &[Option<String>],
    magnitude_kind: &str,
) -> String {
    if magnitude_kind == "none" {
        return "unknown".to_string();
    }
    let values: Vec<i64> = observed
        .iter()
        .zip(magnitudes.iter())
        .filter(|(o, _)| **o)
        .filter_map(|(_, m)| m.as_deref().and_then(|v| v.parse::<i64>().ok()))
        .collect();
    // A trend needs at least THREE observed magnitudes.
    if values.len() < 3 {
        return "unknown".to_string();
    }
    let mut increasing = false;
    let mut decreasing = false;
    for w in values.windows(2) {
        if w[1] > w[0] {
            increasing = true;
        } else if w[1] < w[0] {
            decreasing = true;
        }
    }
    if !increasing && !decreasing {
        "flat".to_string()
    } else if increasing && !decreasing {
        "increasing".to_string()
    } else if !increasing && decreasing {
        "decreasing".to_string()
    } else {
        "non-monotonic".to_string()
    }
}

/// The deterministic divergence degree between a residual observation's
/// compared projections on `axis` (mirrors the reference engine's
/// comparators::divergence_magnitude, bound included): a decimal string, or
/// `None` when the axis declares no measure.
pub fn divergence_magnitude(
    axis: &str,
    raw_reference: &str,
    raw_candidate: &str,
) -> Option<String> {
    const MAGNITUDE_BOUND: usize = 2048;
    match axis {
        "exit" => {
            let a = raw_reference.trim().parse::<i64>().ok()?;
            let b = raw_candidate.trim().parse::<i64>().ok()?;
            Some((a - b).abs().to_string())
        }
        "stderr" | "stdout" | "structured.state" => Some(
            edit_distance_bytes(
                &raw_reference.as_bytes()[..raw_reference.len().min(MAGNITUDE_BOUND)],
                &raw_candidate.as_bytes()[..raw_candidate.len().min(MAGNITUDE_BOUND)],
            )
            .to_string(),
        ),
        _ => None,
    }
}

pub fn magnitude_kind(axis: &str) -> String {
    match axis {
        "exit" => "exit-code-distance".to_string(),
        "stderr" | "stdout" => "line-edit-distance".to_string(),
        "structured.state" => "value-edit-distance".to_string(),
        _ => "none".to_string(),
    }
}

/// The Levenshtein (byte edit) distance — the declared line/value distance
/// measure of the text-family comparators. 0.1.63: consumes BOUNDED BYTES
/// (the same fix as the reference engine — a multibyte character straddling
/// the 2048-byte bound is counted by the bytes present; no UTF-8 boundary
/// question, no panic, identical semantics to the engine and the Go
/// verifier).
pub fn edit_distance_bytes(a: &[u8], b: &[u8]) -> usize {
    if a == b {
        return 0;
    }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut curr: Vec<usize> = vec![0; b.len() + 1];
    for i in 1..=a.len() {
        curr[0] = i;
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b.len()]
}
