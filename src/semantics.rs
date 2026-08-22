//! Identity discipline — every evidence identity in FRF.
//!
//! One rule for all identities: the preimage is a fixed domain tag followed
//! by canonical JSON (RFC 8785), and the identity is its SHA-256. No
//! delimiter-assembled strings (`|`, newlines) anywhere: a JSON document
//! cannot be ambiguous about field boundaries the way a concatenation can.
//!
//!   FRF/RUN/v2                 run (capture) identity = composition of
//!   FRF/OBSERVATION/v1         observation identity (what was observed)
//!   FRF/EXECUTION/v1           execution identity (under what contract)
//!   FRF/COURT/v2               court semantic identity (the question)
//!   FRF/COMPARATOR-SPEC/v2     comparator relation specification
//!   FRF/RESIDUAL-FINGERPRINT/v1  residual fingerprint
//!   FRF/KIND/v1                residual-kind protocol record
//!   FRF/FIXTURE/v1             exact fixture input identity
//!
//! The court semantic identity answers ONLY "what question was asked?":
//! question, falsifier, authority ARTIFACT identity, fixture identity,
//! arguments, the full envelope, the comparator SEMANTIC identities, the
//! normalizer SEMANTIC identities in application order, and the
//! capture-adapter SEMANTIC identities axis-keyed (v2 — everything that
//! defines the observation is part of the question). Implementation
//! provenance (which runner, which comparator implementations) is bound
//! separately in the capture — the question never depends on the
//! implementation, so two independent FRF implementations can ask the same
//! court question without pretending to be the same implementation. In
//! every extension protocol, the relation's VERSION enters the
//! specification document itself (all spec domains are v2) — one rule, so
//! a relation's version is part of its semantic identity everywhere.

use crate::canon;
use crate::error::{FrfError, Result};
use crate::host;
use crate::model::*;
use crate::store::Store;
use serde_json::{json, Value};

/// The one identity primitive: SHA-256 of `FRF/<kind>` + newline + the
/// canonical JSON of `doc`.
pub fn hash_preimage(kind: &str, doc: &Value) -> Result<String> {
    let json = canon::canonical(doc)?;
    Ok(host::sha256_bytes(format!("{kind}\n{json}").as_bytes()))
}

/// The exact fixture input identity: `FRF/FIXTURE/v1` over the canonical
/// document of the fixture's SEMANTIC id (the human role label), its
/// content SHA-256 (the exact bytes), and its DECLARED arguments (the
/// declared input contract). Two different files that share a fixture id are
/// DIFFERENT exact inputs; renaming an input (changing only its semantic
/// id) must not make an unexplained residual about the exact bytes
/// disappear from the claim surface. Claim scopes and residual surfaces
/// carry this identity in their `fixtures` dimension.
pub fn fixture_identity(
    semantic_id: &str,
    content_sha256: &str,
    declared_arguments: &[String],
) -> Result<String> {
    let doc = json!({
        "semantic_id": semantic_id,
        "content_sha256": content_sha256,
        "declared_arguments": declared_arguments,
    });
    hash_preimage("FRF/FIXTURE/v1", &doc)
}

/// The execution-context closure identity: `FRF/EXECUTION-CONTEXT/v1` over
/// the canonical document minus the cid (the artifacts SORTED BY PATH, so
/// the closure is a deterministic function of the declared SET).
pub fn execution_context_identity(closure: &ExecutionContextClosure) -> Result<String> {
    let mut sorted: Vec<&ExecutionContextArtifact> = closure.artifacts.iter().collect();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));
    let mut value = serde_json::to_value(closure)
        .map_err(|e| FrfError::new(format!("cannot serialize the closure: {e}")))?;
    if let Some(obj) = value.as_object_mut() {
        obj.remove("cid");
        if let Some(arts) = obj
            .get_mut("artifacts")
            .and_then(serde_json::Value::as_array_mut)
        {
            *arts = sorted
                .into_iter()
                .map(|a| {
                    serde_json::to_value(a)
                        .map_err(|e| FrfError::new(format!("cannot serialize an artifact: {e}")))
                })
                .collect::<Result<Vec<_>>>()?;
        }
    }
    hash_preimage("FRF/EXECUTION-CONTEXT/v1", &value)
}

/// The content address of a native runtime closure: `FRF/RUNTIME-CLOSURE/v1`
/// over the canonical document minus the `cid` (the components are SORTED BY
/// NAME inside the identity, so the closure is a deterministic function of
/// the resolved SET — two loaders that resolve the same closure agree on one
/// identity, whatever order they collected it in).
pub fn runtime_closure_identity(closure: &NativeRuntimeClosure) -> Result<String> {
    let mut sorted: Vec<&NativeRuntimeComponent> = closure.components.iter().collect();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));
    let mut value = serde_json::to_value(closure)
        .map_err(|e| FrfError::new(format!("cannot serialize the closure: {e}")))?;
    if let Some(obj) = value.as_object_mut() {
        obj.remove("cid");
        if let Some(comps) = obj
            .get_mut("components")
            .and_then(serde_json::Value::as_array_mut)
        {
            *comps = sorted
                .into_iter()
                .map(|c| {
                    serde_json::to_value(c)
                        .map_err(|e| FrfError::new(format!("cannot serialize a component: {e}")))
                })
                .collect::<Result<Vec<_>>>()?;
        }
    }
    hash_preimage("FRF/RUNTIME-CLOSURE/v1", &value)
}

/// The identity of a residual-kind protocol record: `FRF/KIND/v1` over the
/// record's own fields. The kind vocabulary is a protocol object like every
/// other — the canonical identity is deterministic, the records are pinned in
/// the conformance corpus (`conformance/kinds/`), and the reference engine's
/// [`KIND_SCHEMAS`] table is the registry the corpus pins. A residual's kind
/// id is validated against the registered vocabulary by every verifier
/// (fail closed: an unregistered kind is a protocol the engine does not
/// know).
pub fn kind_identity(schema: &KindSchema) -> Result<String> {
    kind_identity_parts(
        schema.id,
        schema.meaning,
        schema.surface_grammar,
        schema.comparator_family,
    )
}

/// The `FRF/KIND/v1` preimage over the four semantic fields — the same
/// formula for any caller holding the fields (the corpus record's derived
/// `identity` field must equal this).
pub fn kind_identity_parts(
    id: &str,
    meaning: &str,
    surface_grammar: &str,
    comparator_family: &str,
) -> Result<String> {
    let doc = json!({
        "id": id,
        "meaning": meaning,
        "surface_grammar": surface_grammar,
        "comparator_family": comparator_family,
    });
    hash_preimage("FRF/KIND/v1", &doc)
}

// ---------------------------------------------------------------------------
// Extension-protocol specification hashes. One formula everywhere: a
// domain-separated canonical JSON document whose SHA-256 is the semantic
// identity of the relation — what the relation IS, never which implementation
// ran it. v2: `relation_version` enters the preimage itself (the one rule:
// a relation's version is part of its semantic identity, in every protocol),
// so two relations with the same id/relation but different versions are
// different relations.
// ---------------------------------------------------------------------------

/// `FRF/NORMALIZER-SPEC/v2` over {id, relation, applies_to, relation_version}.
pub fn normalizer_specification_hash(
    id: &str,
    relation: &str,
    applies_to: &str,
    relation_version: &str,
) -> Result<String> {
    hash_preimage(
        "FRF/NORMALIZER-SPEC/v2",
        &json!({"id": id, "relation": relation, "applies_to": applies_to, "relation_version": relation_version}),
    )
}

/// `FRF/MINIMIZER-SPEC/v2` over {id, relation, relation_version}.
pub fn minimizer_specification_hash(
    id: &str,
    relation: &str,
    relation_version: &str,
) -> Result<String> {
    hash_preimage(
        "FRF/MINIMIZER-SPEC/v2",
        &json!({"id": id, "relation": relation, "relation_version": relation_version}),
    )
}

/// `FRF/CAPTURE-ADAPTER-SPEC/v2` over {id, relation, relation_version}.
pub fn capture_adapter_specification_hash(
    id: &str,
    relation: &str,
    relation_version: &str,
) -> Result<String> {
    hash_preimage(
        "FRF/CAPTURE-ADAPTER-SPEC/v2",
        &json!({"id": id, "relation": relation, "relation_version": relation_version}),
    )
}

/// `FRF/WITNESS-SPEC/v2` over {id, relation, relation_version}.
pub fn witness_specification_hash(
    id: &str,
    relation: &str,
    relation_version: &str,
) -> Result<String> {
    hash_preimage(
        "FRF/WITNESS-SPEC/v2",
        &json!({"id": id, "relation": relation, "relation_version": relation_version}),
    )
}

/// The court semantic identity — the resolution-comparability key. Contents
/// (FRF/COURT/v2):
///
/// - question, falsifier
/// - the admitted authority ARTIFACT hash (bytes, not the id label)
/// - fixture id + bytes + declared arguments
/// - the full admissibility envelope
/// - comparator SEMANTIC identities (relation + version + specification hash)
/// - normalizer SEMANTIC identities, in APPLICATION ORDER (a normalizer
///   changes the comparison surface; its relation and the streams it moves
///   are part of the question — two courts applying different normalizers
///   under the same id ask different questions)
/// - capture-adapter SEMANTIC identities, axis-keyed and sorted (an adapter
///   defines the observation delivered to an externally served axis — a
///   different extraction scheme is a different evidentiary surface)
///
/// Deliberately absent: the court id (a label), the candidate (the one
/// thing a fix court may change), the environment (checked separately by
/// the resolution predicate), and all implementation identity.
pub fn court_semantic_identity(
    spec: &CourtSpec,
    authority_sha256: &str,
    fixture_sha256: &str,
    comparator_semantics: &[ComparatorSemantic],
    normalizer_semantics: &[NormalizerSemantic],
    adapter_semantics: &[CaptureAdapterSemantic],
) -> Result<String> {
    court_semantic_doc(
        &spec.question,
        &spec.falsifier,
        authority_sha256,
        &spec.fixture.id,
        fixture_sha256,
        &spec.fixture.arguments,
        &spec.admissibility_envelope,
        comparator_semantics,
        normalizer_semantics,
        adapter_semantics,
    )
    .and_then(|doc| hash_preimage("FRF/COURT/v2", &doc))
}

/// The court-semantic-identity preimage document, built from the fields that
/// define the evidentiary question. Shared by the capture-time computation
/// and the receipt-side rederivation ([`court_semantic_identity_from_receipt`]),
/// so a receipt's `semantic_identity` can be proven to re-derive — in any
/// implementation, from the receipt document alone.
#[allow(clippy::too_many_arguments)] // one argument per question dimension; the doc is the protocol shape
fn court_semantic_doc(
    question: &str,
    falsifier: &str,
    authority_sha256: &str,
    fixture_id: &str,
    fixture_sha256: &str,
    fixture_arguments: &[String],
    envelope: &AdmissibilityEnvelope,
    comparator_semantics: &[ComparatorSemantic],
    normalizer_semantics: &[NormalizerSemantic],
    adapter_semantics: &[CaptureAdapterSemantic],
) -> Result<Value> {
    // Normalizers compose in APPLICATION ORDER: the order is semantic. The
    // adapters serve distinct axes; their array is sorted by axis so two
    // manifests declaring them in different orders ask the same question.
    let mut adapters: Vec<&CaptureAdapterSemantic> = adapter_semantics.iter().collect();
    adapters.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(json!({
        "question": question,
        "falsifier": falsifier,
        "authority_artifact_identity": authority_sha256,
        "fixture": {
            "id": fixture_id,
            "sha256": fixture_sha256,
            "arguments": fixture_arguments,
        },
        "envelope": {
            "fixture_family": envelope.fixture_family,
            "platforms": envelope.platforms,
            "observables": envelope.observables,
            "normalizers": envelope.normalizers,
            "replay_scope": envelope.replay_scope,
        },
        "comparators": comparator_semantics
            .iter()
            .map(|c| json!({
                "id": c.id,
                "relation_id": c.relation_id,
                "relation_version": c.relation_version,
                "specification_hash": c.specification_hash,
            }))
            .collect::<Vec<_>>(),
        "normalizers": normalizer_semantics
            .iter()
            .map(|n| json!({
                "id": n.id,
                "relation_id": n.relation_id,
                "applies_to": n.applies_to,
                "relation_version": n.relation_version,
                "specification_hash": n.specification_hash,
            }))
            .collect::<Vec<_>>(),
        "capture_adapters": adapters
            .iter()
            .map(|a| json!({
                "id": a.id,
                "relation_id": a.relation_id,
                "relation_version": a.relation_version,
                "specification_hash": a.specification_hash,
            }))
            .collect::<Vec<_>>(),
    }))
}

/// Rederive the court semantic identity from an OpenReceipt document alone.
/// The receipt carries everything the question is made of: question,
/// falsifier, authority artifact hash, fixture id/hash/arguments, the
/// envelope, the comparator semantics, the normalizer semantics (application
/// order), and the capture-adapter semantics. The validator requires exactly
/// one fixture (v0 courts have one), so `fixtures[0]` is the fixture.
pub fn court_semantic_identity_from_receipt(rec: &Receipt) -> Result<String> {
    let envelope = AdmissibilityEnvelope {
        fixture_family: rec.court.admissibility_envelope.fixture_family.clone(),
        platforms: rec.court.admissibility_envelope.platforms.clone(),
        observables: rec.court.admissibility_envelope.observables.clone(),
        normalizers: rec.court.admissibility_envelope.normalizers.clone(),
        replay_scope: rec.court.admissibility_envelope.replay_scope.clone(),
    };
    let fixture = rec.fixtures.first().ok_or_else(|| {
        FrfError::new("receipt carries no fixture; cannot rederive the semantic identity")
    })?;
    court_semantic_doc(
        &rec.court.question,
        &rec.court.falsifier,
        &rec.authority.identity_hash,
        &fixture.id,
        &fixture.hash,
        &fixture.declared_arguments,
        &envelope,
        &rec.comparator_semantics,
        &rec.normalizer_semantics,
        &rec.adapter_semantics,
    )
    .and_then(|doc| hash_preimage("FRF/COURT/v2", &doc))
}

/// Every input that defines one court run's identity. The identity is the
/// pair of the run's OBSERVATION identity (what was observed — the question
/// and the answer) and its EXECUTION identity (under exactly what machinery
/// and contract it was observed), composed into a domain-separated canonical
/// JSON document (`FRF/RUN/v2`); the digest is its SHA-256. Built at court
/// time by the runner and REDERIVED by replay, receipt verification, and the
/// verification suite from the capture's own recorded fields — the name is a
/// claim until it is recomputed.
///
/// The split is deliberate: a repeated execution can legitimately share an
/// observation identity (same program, same input, same environment, same
/// output) while the execution identity remains separately addressable — the
/// same program observed under `frf-exec-linux-v1` with a 60s timeout is
/// NOT the same bounded observation as under `frf-exec-linux-v2` with a
/// cgroup envelope, even if the outputs coincide, and an `FRF_EXEC_*`
/// override changes the observation's contract even when the process
/// happened to terminate well within both bounds.
pub struct RunPreimage<'a> {
    pub court: &'a str,
    pub authority: &'a str,
    pub authority_interpreter: Option<&'a str>,
    pub candidate_sha256: &'a str,
    pub candidate_interpreter: Option<&'a str>,
    pub fixture_sha256: &'a str,
    pub arguments: &'a [String],
    pub environment_digest: &'a str,
    pub runner_hash: &'a str,
    pub court_semantic_identity: &'a str,
    pub reference: &'a SideCapture,
    pub candidate: &'a SideCapture,
    pub residuals: &'a [ResidualRecord],
    /// The harness contract the observation was made under: the execution
    /// profile id and the EFFECTIVE capture bounds (the profile's defaults
    /// or the overrides in force) — the run identity commits the contract,
    /// not merely the outputs.
    pub execution_profile: &'a str,
    pub capture_bounds: &'a CaptureBounds,
    /// The exact implementations that produced the observation: the
    /// comparator, normalizer, capture-adapter, and minimizer programs that
    /// served each axis (in-binary implementations hash to the runner
    /// executable; external ones carry their own implementation hash).
    pub comparator_implementations: &'a [ComparatorImplementation],
    pub normalizer_implementations: &'a [NormalizerImplementation],
    pub adapter_implementations: &'a [CaptureAdapterImplementation],
    pub minimizer_implementations: &'a [MinimizerImplementation],
}

/// The side projection shared by the observation and run identities: the
/// OBSERVED surface (exit class, stream hashes + first lines, produced
/// artifact tree, adapted payload) — never raw bytes.
fn side_projection(s: &SideCapture) -> serde_json::Value {
    json!({
        "exit": s.exit,
        "stdout_sha256": s.stdout_sha256,
        "stderr_sha256": s.stderr_sha256,
        "stdout_first_line": s.stdout_first_line,
        "stderr_first_line": s.stderr_first_line,
        "produced": s.produced.as_ref().map(|p| json!({
            "schema_version": p.schema_version,
            "manifest_sha256": p.manifest_sha256,
            "files": p.files.iter().map(|f| json!({
                "path": f.path,
                "sha256": f.sha256,
                "executable": f.executable,
            })).collect::<Vec<_>>(),
        })),
        "adapted": s.adapted.as_ref().map(|a| json!({
            "format": a.format,
            "payload_base64": a.payload_base64,
            "content_sha256": a.content_sha256,
        })),
    })
}

/// The residual projection shared by the observation and run identities: the
/// recorded disagreements (kind + raw projections), not the residual ids — a
/// residual's identity as evidence is its divergence, not its storage label.
fn residual_projection(r: &ResidualRecord) -> serde_json::Value {
    json!({
        "kind": r.kind.as_str(),
        "raw_reference": r.raw_reference,
        "raw_candidate": r.raw_candidate,
    })
}

/// The observation identity: WHAT was observed — the semantic question and
/// the answer. `FRF/OBSERVATION/v1` over the domain-separated canonical
/// document; the digest is its SHA-256. Two observations with the same
/// question, inputs, effective environment, and outputs share this identity
/// regardless of which harness observed them.
pub fn observation_identity(p: &RunPreimage) -> Result<String> {
    let doc = json!({
        "court": p.court,
        "court_semantic_identity": p.court_semantic_identity,
        "authority": p.authority,
        "candidate_sha256": p.candidate_sha256,
        "fixture_sha256": p.fixture_sha256,
        "arguments": p.arguments,
        "environment_digest": p.environment_digest,
        "reference": side_projection(p.reference),
        "candidate": side_projection(p.candidate),
        "residuals": p.residuals.iter().map(residual_projection).collect::<Vec<_>>(),
    });
    hash_preimage("FRF/OBSERVATION/v1", &doc)
}

/// The implementation projection shared by the execution identity: the
/// exact program that served one axis/route, bound by its implementation
/// hash (in-binary implementations hash to the runner executable; external
/// ones carry their own).
fn implementation_projection(id: &str, implementation_hash: &str) -> serde_json::Value {
    json!({
        "id": id,
        "implementation_hash": implementation_hash,
    })
}

/// The execution identity: under EXACTLY what machinery and contract the
/// observation was made. `FRF/EXECUTION/v1` over the domain-separated
/// canonical document; the digest is its SHA-256. The execution profile, the
/// effective capture bounds (including `FRF_EXEC_*` overrides), the runner
/// executable, the interpreter chain of each side, and every comparator /
/// normalizer / adapter / minimizer implementation are all part of it — an
/// observation is made under a declared harness contract, and its identity
/// commits that contract.
pub fn execution_identity(p: &RunPreimage) -> Result<String> {
    let b = p.capture_bounds;
    let doc = json!({
        "execution_profile": p.execution_profile,
        "capture_bounds": {
            "timeout_ms": b.timeout_ms,
            "max_stream_bytes": b.max_stream_bytes,
            "rlimit_as_mb": b.rlimit_as_mb,
            "rlimit_cpu_s": b.rlimit_cpu_s,
            "rlimit_nofile": b.rlimit_nofile,
            "rlimit_nproc": b.rlimit_nproc,
            "cgroup_pids_max": b.cgroup_pids_max,
            "cgroup_memory_max": b.cgroup_memory_max,
            "cgroup_cpu_max": b.cgroup_cpu_max,
        },
        "runner_hash": p.runner_hash,
        "authority_interpreter": p.authority_interpreter,
        "candidate_interpreter": p.candidate_interpreter,
        "comparator_implementations": p
            .comparator_implementations
            .iter()
            .map(|i| implementation_projection(&i.id, &i.implementation_hash))
            .collect::<Vec<_>>(),
        "normalizer_implementations": p
            .normalizer_implementations
            .iter()
            .map(|i| implementation_projection(&i.id, &i.implementation_hash))
            .collect::<Vec<_>>(),
        "adapter_implementations": p
            .adapter_implementations
            .iter()
            .map(|i| implementation_projection(&i.id, &i.implementation_hash))
            .collect::<Vec<_>>(),
        "minimizer_implementations": p
            .minimizer_implementations
            .iter()
            .map(|i| implementation_projection(&i.id, &i.implementation_hash))
            .collect::<Vec<_>>(),
    });
    hash_preimage("FRF/EXECUTION/v1", &doc)
}

/// The one run-identity function, shared by `court run`, replay, receipt
/// verification, and the verification suite. No duplicate implementation:
/// a capture whose recorded fields hash to a different id is refused.
///
/// `FRF/RUN/v2` composes the observation identity and the execution identity
/// (each separately rederivable and separately addressable): the capture is
/// the complete content-addressed evidence object, and its identity commits
/// BOTH what was observed and under exactly what machinery/contract it was
/// observed.
pub fn run_identity(p: &RunPreimage) -> Result<String> {
    let observation = observation_identity(p)?;
    let execution = execution_identity(p)?;
    let doc = json!({
        "observation_identity": observation,
        "execution_identity": execution,
    });
    hash_preimage("FRF/RUN/v2", &doc)
}

/// The residual fingerprint: stable across repeated executions and (with the
/// same raw projections) across stores, because it is built from the
/// residual's hashed projections, not the raw values.
pub fn residual_fingerprint(r: &ResidualRecord) -> Result<String> {
    fingerprint_from_projections(
        &r.kind,
        &r.axis,
        r.surface.as_deref(),
        &r.raw_reference,
        &r.raw_candidate,
    )
}

/// The fingerprint of a divergence, computed directly from raw projections
/// (used by replay to re-derive what a fresh execution must reproduce).
pub fn fingerprint_from_projections(
    kind: &ResidualKind,
    axis: &ObservableId,
    surface: Option<&str>,
    raw_reference: &str,
    raw_candidate: &str,
) -> Result<String> {
    let doc = json!({
        "kind": kind.as_str(),
        "axis": axis.as_str(),
        "surface": surface,
        "reference_sha256": host::sha256_bytes(raw_reference.as_bytes()),
        "candidate_sha256": host::sha256_bytes(raw_candidate.as_bytes()),
    });
    hash_preimage("FRF/RESIDUAL-FINGERPRINT/v1", &doc)
}

/// The residual LINEAGE identity: the stable comparison question, surface,
/// and feature — deliberately NOT the exact observed bytes. The lineage
/// spans candidate revisions, authority versions, environments, and time
/// (candidate hash, raw projections, environment, and version are all
/// absent), so a trajectory over those axes records the MOVEMENT of a
/// divergence: the same lineage at commit 1, commit 2, and commit 3 has
/// different fingerprints but one trajectory.
///
/// Contents: kind, axis, surface, fixture, fixture family, authority NAME.
/// (The authority name, not the versioned id — the lineage must span
/// authority versions; the fixture is part of the comparison question, and
/// minimization will introduce its own preservation predicate rather than
/// silently changing the lineage.)
pub fn residual_lineage(
    kind: &ResidualKind,
    axis: &ObservableId,
    surface: Option<&str>,
    fixture_family: &str,
    authority_name: &str,
    fixture: &str,
) -> Result<String> {
    let doc = json!({
        "kind": kind.as_str(),
        "axis": axis.as_str(),
        "surface": surface,
        "fixture_family": fixture_family,
        "authority_name": authority_name,
        "fixture": fixture,
    });
    hash_preimage("FRF/RESIDUAL-LINEAGE/v1", &doc)
}

/// The lineage of a stored residual record (loads the authority name from
/// the record's authority id via the store's authority record).
pub fn residual_lineage_of_record(store: &Store, record: &ResidualRecord) -> Result<String> {
    let authority = store.load_authority(&record.authority)?;
    residual_lineage(
        &record.kind,
        &record.axis,
        record.surface.as_deref(),
        &record.scope,
        &authority.name,
        &store.load_capture(&record.run)?.fixture,
    )
}

/// The ExecutionSeries identity: content-addressed over the experiment
/// (court, coordinate system, the parent snapshot, and the ordered points).
/// Every append produces a NEW series record — the growth of a series is an
/// immutable, parent-linked history; trajectories reference the series
/// snapshot they derive from. The point index enters the preimage as its
/// string form (the canonical value domain is strings/arrays/booleans/null
/// — numbers are refused).
pub fn series_identity(
    experiment_id: &str,
    parent_series_id: Option<&str>,
    court: &str,
    coordinate_system: &str,
    points: &[SeriesPoint],
) -> Result<String> {
    let doc = json!({
        "experiment_id": experiment_id,
        "parent_series_id": parent_series_id,
        "court": court,
        "coordinate_system": coordinate_system,
        "points": points
            .iter()
            .map(|p| json!({
                "point_index": p.point_index,
                "coordinate": p.coordinate,
                "run": p.run,
            }))
            .collect::<Vec<_>>(),
    });
    hash_preimage("FRF/SERIES/v2", &doc)
}

/// The reduction identity: content-addressed over the minimization
/// experiment (residual, every bound identity, fixtures, the attempts, the
/// derivation, and the transform declaration).
#[allow(clippy::too_many_arguments)] // one argument per record dimension; the doc is the protocol shape
pub fn reduction_identity(
    residual_id: &str,
    source_run: &str,
    axis: &str,
    kind: ResidualKind,
    court_semantic_identity: &str,
    authority_artifact_sha256: &str,
    candidate_artifact_sha256: &str,
    environment_digest: &str,
    comparator_semantic_id: &str,
    comparator_semantic_hash: &str,
    comparator_implementation_hash: &str,
    argv_template: &[String],
    original_fixture_sha256: &str,
    final_fixture_sha256: &str,
    attempts: &[ReductionAttempt],
    derivation: &ReductionDerivation,
    transform: &EvidenceTransform,
    minimizer: Option<(&str, &str, &str, &ArtifactIdentity, &str, &str)>,
) -> Result<String> {
    let minimizer_doc = match minimizer {
        Some((id, hash, impl_hash, artifact, invocation_id, result_id)) => Some(json!({
            "semantic_id": id,
            "semantic_hash": hash,
            "implementation_hash": impl_hash,
            "implementation_artifact": serde_json::to_value(artifact).map_err(|e| {
                FrfError::new(format!("cannot serialize the minimizer artifact: {e}"))
            })?,
            "invocation_id": invocation_id,
            "result_id": result_id,
        })),
        None => None,
    };
    let doc = json!({
        "residual_id": residual_id,
        "source_run": source_run,
        "axis": axis,
        "kind": kind.as_str(),
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
        "attempts": attempts
            .iter()
            .map(|a| json!({
                "attempt": a.attempt,
                "role": a.role.as_str(),
                "fixture_sha256": a.fixture_sha256,
                "outcome": a.outcome.as_str(),
                "accepted": a.accepted,
            }))
            .collect::<Vec<_>>(),
        "derivation": {
            "strategy": derivation.strategy,
            "original_lines": derivation.original_lines,
            "final_lines": derivation.final_lines,
            "minimality": {
                "kind": derivation.minimality.kind,
                "granularity": derivation.minimality.granularity,
                "proven": derivation.minimality.proven,
            },
        },
        "transform": serde_json::to_value(transform)
            .map_err(|e| FrfError::new(format!("cannot serialize the transform: {e}")))?,
        "minimizer": minimizer_doc,
    });
    hash_preimage("FRF/REDUCTION/v3", &doc)
}

/// The knowledge-snapshot identity: SHA-256 of `FRF/KNOWLEDGE/v2` over the
/// canonical document of the snapshot's fields. Every residual head enters as
/// (id, record content address, fingerprint, disposition, event) — the
/// universe commits the exact immutable observations the blocker scan reads,
/// not the labels — and the objects list commits every other member by
/// (kind, id, cid). Every list is sorted, so the same universe hashes
/// identically in every implementation.
pub fn knowledge_snapshot_identity(snapshot: &KnowledgeSnapshot) -> Result<String> {
    let doc = json!({
        "residual_heads": snapshot
            .residual_heads
            .iter()
            .map(|h| json!({
                "id": h.id,
                "record_cid": h.record_cid,
                "fingerprint": h.fingerprint,
                "disposition": h.disposition,
                "disposition_event_id": h.disposition_event_id,
            }))
            .collect::<Vec<_>>(),
        "objects": snapshot
            .objects
            .iter()
            .map(|o| json!({
                "kind": o.kind,
                "id": o.id,
                "cid": o.cid,
            }))
            .collect::<Vec<_>>(),
    });
    hash_preimage("FRF/KNOWLEDGE/v2", &doc)
}

/// The content address of a COMPILED CLAIM: `FRF/CLAIM/v1` over the
/// canonical document minus the `id` field. The claim is an immutable
/// protocol object — the same receipt compiled under a different evidence
/// universe, admission policy, or scope is a DIFFERENT claim with a
/// different id, and they coexist forever. The identity cryptographically
/// binds the proposition and the whole evidence graph it rests on.
pub fn claim_identity(claim: &ClaimRecord) -> Result<String> {
    let mut value = serde_json::to_value(claim)
        .map_err(|e| FrfError::new(format!("cannot serialize the claim: {e}")))?;
    if let Some(obj) = value.as_object_mut() {
        obj.remove("id");
    }
    let json = crate::canon::canonical(&value)?;
    Ok(host::sha256_bytes(
        format!("FRF/CLAIM/v1\n{json}").as_bytes(),
    ))
}

/// The CONTENT ADDRESS of an evidence record (a residual record or an
/// authority record): SHA-256 of the canonical serialization of the record's
/// own fields. Records are stored as canonical JSON evidence documents, and
/// their content identity is the canonical JSON of their fields — the same
/// document any independent implementation rederives from its own parsing.
/// This is what the knowledge universe commits for a record whose id is a
/// label, not a content address.
pub fn record_content_identity<T: serde::Serialize>(record: &T) -> Result<String> {
    let value = serde_json::to_value(record)
        .map_err(|e| FrfError::new(format!("cannot serialize the record: {e}")))?;
    let json = crate::canon::canonical(&value)?;
    Ok(host::sha256_bytes(json.as_bytes()))
}

/// The court-challenge identity: `FRF/CHALLENGE/v1` over the DECLARED
/// evidence — the court, the mutation operator, the targeted axis, the
/// admitted reference artifact, the mutant candidate artifact, and the
/// mutant run. The verdicts (`saw_defect`, `specificity_clean`, the
/// observed residual ids) are deliberately NOT in the identity: they are
/// DERIVED from the run's residuals and recomputed by verification, so a
/// hand-edited verdict breaks the derived check rather than the address.
#[allow(clippy::too_many_arguments)] // one argument per declared-evidence dimension
pub fn challenge_identity(
    court: &str,
    operator: &str,
    target_axis: &str,
    reference_sha256: &str,
    mutant_candidate_sha256: &str,
    run: &str,
) -> Result<String> {
    let doc = json!({
        "schema_version": SCHEMA_CHALLENGE,
        "court": court,
        "operator": operator,
        "target_axis": target_axis,
        "reference_sha256": reference_sha256,
        "mutant_candidate_sha256": mutant_candidate_sha256,
        "run": run,
    });
    hash_preimage("FRF/CHALLENGE/v1", &doc)
}

/// The content-addressable inputs of one disposition event: everything the
/// event's identity is computed over (the event_id itself is excluded — an
/// object cannot contain its own address). The parent link makes the event
/// chain a hash chain.
pub struct DispositionEventContent<'a> {
    pub residual_id: &'a str,
    pub parent_event_id: Option<&'a str>,
    pub disposition: &'a Disposition,
    pub evidence_refs: &'a [String],
}

/// The identity of a disposition event: SHA-256 of `FRF/DISPOSITION-EVENT/v1`
/// over the event's content. The disposition is a nested document (kind +
/// its fields), so the identity cannot be confused with a flattened YAML
/// shape. Rederivable from the event's own recorded fields — a name is a
/// claim until recomputed.
pub fn disposition_event_identity(c: &DispositionEventContent) -> Result<String> {
    let disposition = match c.disposition {
        Disposition::Open => json!({ "kind": "open" }),
        Disposition::Closed { kind, reason } => {
            json!({ "kind": kind.as_str(), "reason": reason })
        }
        Disposition::Fixed {
            reason,
            resolution_run_id,
            closure_predicate,
        } => json!({
            "kind": "fixed",
            "reason": reason,
            "resolution_run_id": resolution_run_id,
            "closure_predicate": closure_predicate,
        }),
    };
    let doc = json!({
        "residual_id": c.residual_id,
        "parent_event_id": c.parent_event_id,
        "disposition": disposition,
        "evidence_refs": c.evidence_refs,
    });
    hash_preimage("FRF/DISPOSITION-EVENT/v1", &doc)
}

/// Does a recorded comparator SEMANTIC rederive its own specification hash?
/// The semantic record carries the full specification (id, relation,
/// extractor, residual classifier) next to its hash, so the receipt-side
/// validator can prove a receipt's comparator semantics are what they claim
/// to be.
pub fn comparator_spec_hash_rederives(c: &ComparatorSemantic) -> Result<bool> {
    Ok(crate::comparators::specification_hash(
        &c.id,
        &c.relation_id,
        &c.extractor,
        &c.residual_classifier,
        &c.relation_version,
    )? == c.specification_hash)
}

/// Does a recorded NORMALIZER semantic rederive its own specification hash?
/// Same discipline as [`comparator_spec_hash_rederives`]: the semantic record
/// carries the full specification (id, relation, applies_to, version) next to
/// its hash, so a receipt cannot claim a normalizer specification its own
/// fields do not hash to.
pub fn normalizer_spec_hash_rederives(n: &NormalizerSemantic) -> Result<bool> {
    Ok(
        normalizer_specification_hash(&n.id, &n.relation_id, &n.applies_to, &n.relation_version)?
            == n.specification_hash,
    )
}

/// Does a recorded CAPTURE-ADAPTER semantic rederive its own specification
/// hash? Same discipline: the adapter's spec document is {id, relation,
/// relation_version}, so the recorded hash must rederive from those fields.
pub fn capture_adapter_spec_hash_rederives(a: &CaptureAdapterSemantic) -> Result<bool> {
    Ok(
        capture_adapter_specification_hash(&a.id, &a.relation_id, &a.relation_version)?
            == a.specification_hash,
    )
}

/// The content-addressable inputs of one comparator INVOCATION record: the
/// record's identity is computed over these (the `invocation_id` itself is
/// excluded — an object cannot contain its own address).
pub struct ComparatorInvocationContent<'a> {
    pub axis: &'a ObservableId,
    pub request_cid: &'a str,
    pub comparator_semantic_cid: &'a str,
    pub comparator_implementation_artifact: &'a ArtifactIdentity,
    pub execution_provenance: &'a RunnerIdentity,
}

/// The identity of a comparator invocation record: SHA-256 of
/// `FRF/COMPARATOR-INVOCATION/v1` over its content. Rederivable from the
/// record's own recorded fields — a name is a claim until recomputed.
pub fn comparator_invocation_identity(c: &ComparatorInvocationContent) -> Result<String> {
    let doc = json!({
        "axis": c.axis.as_str(),
        "request_cid": c.request_cid,
        "comparator_semantic_cid": c.comparator_semantic_cid,
        "comparator_implementation_artifact":
            serde_json::to_value(c.comparator_implementation_artifact)
                .map_err(|e| FrfError::new(format!("cannot serialize the comparator implementation artifact: {e}")))?,
        "execution_provenance":
            serde_json::to_value(c.execution_provenance)
                .map_err(|e| FrfError::new(format!("cannot serialize the execution provenance: {e}")))?,
    });
    hash_preimage("FRF/COMPARATOR-INVOCATION/v1", &doc)
}

/// The content-addressable inputs of one comparator RESULT record.
pub struct ComparatorResultContent<'a> {
    pub request_cid: &'a str,
    pub response_cid: &'a str,
    pub outcome: &'a str,
    pub residual_observation_ids: &'a [String],
}

/// The identity of a comparator result record: SHA-256 of
/// `FRF/COMPARATOR-RESULT/v1` over its content.
pub fn comparator_result_identity(c: &ComparatorResultContent) -> Result<String> {
    let doc = json!({
        "request_cid": c.request_cid,
        "response_cid": c.response_cid,
        "outcome": c.outcome,
        "residual_observation_ids": c.residual_observation_ids,
    });
    hash_preimage("FRF/COMPARATOR-RESULT/v1", &doc)
}

/// The specification hash of a mutation relation: SHA-256 of
/// `FRF/MUTATION-SPEC/v1` over (id, relation, relation_version). What kind of
/// mutant is being asked for — not which program proposes it.
pub fn mutation_specification_hash(
    id: &str,
    relation: &str,
    relation_version: &str,
) -> Result<String> {
    hash_preimage(
        "FRF/MUTATION-SPEC/v1",
        &json!({"id": id, "relation": relation, "relation_version": relation_version}),
    )
}

/// The content-addressable inputs of one mutation INVOCATION record.
pub struct MutationInvocationContent<'a> {
    pub operator: &'a str,
    pub target_axis: &'a str,
    pub request_cid: &'a str,
    pub mutation_semantic_cid: &'a str,
    pub mutation_implementation_artifact: &'a ArtifactIdentity,
    pub execution_provenance: &'a RunnerIdentity,
}

/// The identity of a mutation invocation record: SHA-256 of
/// `FRF/MUTATION-INVOCATION/v1` over its content.
pub fn mutation_invocation_identity(c: &MutationInvocationContent) -> Result<String> {
    let doc = json!({
        "operator": c.operator,
        "target_axis": c.target_axis,
        "request_cid": c.request_cid,
        "mutation_semantic_cid": c.mutation_semantic_cid,
        "mutation_implementation_artifact":
            serde_json::to_value(c.mutation_implementation_artifact)
                .map_err(|e| FrfError::new(format!("cannot serialize the mutation implementation artifact: {e}")))?,
        "execution_provenance":
            serde_json::to_value(c.execution_provenance)
                .map_err(|e| FrfError::new(format!("cannot serialize the execution provenance: {e}")))?,
    });
    hash_preimage("FRF/MUTATION-INVOCATION/v1", &doc)
}

/// The content-addressable inputs of one mutation RESULT record.
pub struct MutationResultContent<'a> {
    pub request_cid: &'a str,
    pub response_cid: &'a str,
    pub outcome: &'a str,
    pub mutant_sha256: &'a str,
    pub expected_affected_surfaces: &'a [String],
}

/// The identity of a mutation result record: SHA-256 of
/// `FRF/MUTATION-RESULT/v1` over its content.
pub fn mutation_result_identity(c: &MutationResultContent) -> Result<String> {
    let doc = json!({
        "request_cid": c.request_cid,
        "response_cid": c.response_cid,
        "outcome": c.outcome,
        "mutant_sha256": c.mutant_sha256,
        "expected_affected_surfaces": c.expected_affected_surfaces,
    });
    hash_preimage("FRF/MUTATION-RESULT/v1", &doc)
}

/// The content-addressable inputs of one normalizer INVOCATION record.
pub struct NormalizerInvocationContent<'a> {
    pub normalizer_id: &'a str,
    pub side: &'a str,
    pub request_cid: &'a str,
    pub normalizer_semantic_cid: &'a str,
    pub normalizer_implementation_artifact: &'a ArtifactIdentity,
    pub execution_provenance: &'a RunnerIdentity,
}

/// The identity of a normalizer invocation record: SHA-256 of
/// `FRF/NORMALIZER-INVOCATION/v1` over its content.
pub fn normalizer_invocation_identity(c: &NormalizerInvocationContent) -> Result<String> {
    let doc = json!({
        "normalizer_id": c.normalizer_id,
        "side": c.side,
        "request_cid": c.request_cid,
        "normalizer_semantic_cid": c.normalizer_semantic_cid,
        "normalizer_implementation_artifact":
            serde_json::to_value(c.normalizer_implementation_artifact)
                .map_err(|e| FrfError::new(format!("cannot serialize the normalizer implementation artifact: {e}")))?,
        "execution_provenance":
            serde_json::to_value(c.execution_provenance)
                .map_err(|e| FrfError::new(format!("cannot serialize the execution provenance: {e}")))?,
    });
    hash_preimage("FRF/NORMALIZER-INVOCATION/v1", &doc)
}

/// The content-addressable inputs of one normalizer RESULT record.
pub struct NormalizerResultContent<'a> {
    pub request_cid: &'a str,
    pub response_cid: &'a str,
    pub stdout_sha256: &'a str,
    pub stderr_sha256: &'a str,
}

/// The identity of a normalizer result record.
pub fn normalizer_result_identity(c: &NormalizerResultContent) -> Result<String> {
    let doc = json!({
        "request_cid": c.request_cid,
        "response_cid": c.response_cid,
        "stdout_sha256": c.stdout_sha256,
        "stderr_sha256": c.stderr_sha256,
    });
    hash_preimage("FRF/NORMALIZER-RESULT/v1", &doc)
}

/// The content-addressable inputs of one minimizer INVOCATION record.
pub struct MinimizerInvocationContent<'a> {
    pub minimizer_id: &'a str,
    pub residual_id: &'a str,
    pub request_cid: &'a str,
    pub minimizer_semantic_cid: &'a str,
    pub minimizer_implementation_artifact: &'a ArtifactIdentity,
    pub execution_provenance: &'a RunnerIdentity,
}

/// The identity of a minimizer invocation record.
pub fn minimizer_invocation_identity(c: &MinimizerInvocationContent) -> Result<String> {
    let doc = json!({
        "minimizer_id": c.minimizer_id,
        "residual_id": c.residual_id,
        "request_cid": c.request_cid,
        "minimizer_semantic_cid": c.minimizer_semantic_cid,
        "minimizer_implementation_artifact":
            serde_json::to_value(c.minimizer_implementation_artifact)
                .map_err(|e| FrfError::new(format!("cannot serialize the minimizer implementation artifact: {e}")))?,
        "execution_provenance":
            serde_json::to_value(c.execution_provenance)
                .map_err(|e| FrfError::new(format!("cannot serialize the execution provenance: {e}")))?,
    });
    hash_preimage("FRF/MINIMIZER-INVOCATION/v1", &doc)
}

/// The content-addressable inputs of one minimizer RESULT record.
pub struct MinimizerResultContent<'a> {
    pub request_cid: &'a str,
    pub response_cid: &'a str,
    pub proposed_fixture_sha256: &'a str,
    pub court_verified: bool,
}

/// The identity of a minimizer result record.
pub fn minimizer_result_identity(c: &MinimizerResultContent) -> Result<String> {
    let doc = json!({
        "request_cid": c.request_cid,
        "response_cid": c.response_cid,
        "proposed_fixture_sha256": c.proposed_fixture_sha256,
        "court_verified": c.court_verified,
    });
    hash_preimage("FRF/MINIMIZER-RESULT/v1", &doc)
}

/// The content-addressable inputs of one capture-adapter INVOCATION record.
pub struct CaptureAdapterInvocationContent<'a> {
    pub axis: &'a str,
    pub side: &'a str,
    pub request_cid: &'a str,
    pub adapter_semantic_cid: &'a str,
    pub adapter_implementation_artifact: &'a ArtifactIdentity,
    pub execution_provenance: &'a RunnerIdentity,
}

/// The identity of a capture-adapter invocation record.
pub fn capture_adapter_invocation_identity(c: &CaptureAdapterInvocationContent) -> Result<String> {
    let doc = json!({
        "axis": c.axis,
        "side": c.side,
        "request_cid": c.request_cid,
        "adapter_semantic_cid": c.adapter_semantic_cid,
        "adapter_implementation_artifact":
            serde_json::to_value(c.adapter_implementation_artifact)
                .map_err(|e| FrfError::new(format!("cannot serialize the adapter implementation artifact: {e}")))?,
        "execution_provenance":
            serde_json::to_value(c.execution_provenance)
                .map_err(|e| FrfError::new(format!("cannot serialize the execution provenance: {e}")))?,
    });
    hash_preimage("FRF/CAPTURE-ADAPTER-INVOCATION/v1", &doc)
}

/// The content-addressable inputs of one capture-adapter RESULT record.
pub struct CaptureAdapterResultContent<'a> {
    pub request_cid: &'a str,
    pub response_cid: &'a str,
    pub observation_sha256: &'a str,
}

/// The identity of a capture-adapter result record.
pub fn capture_adapter_result_identity(c: &CaptureAdapterResultContent) -> Result<String> {
    let doc = json!({
        "request_cid": c.request_cid,
        "response_cid": c.response_cid,
        "observation_sha256": c.observation_sha256,
    });
    hash_preimage("FRF/CAPTURE-ADAPTER-RESULT/v1", &doc)
}

/// The content-addressable inputs of one witness statement record.
pub struct WitnessStatementContent<'a> {
    pub subject: &'a WitnessSubject,
    pub witness_semantic: &'a WitnessSemantic,
    pub witness_implementation: &'a WitnessImplementation,
    pub witness_identity: &'a str,
    pub authority: &'a Option<WitnessAuthority>,
    pub statement: &'a str,
    pub attestation: &'a WitnessAttestation,
    pub request_cid: &'a str,
    pub response_cid: &'a str,
}

/// The WITNESS IDENTITY — the stable WHO behind an attestation: SHA-256 of
/// `FRF/WITNESS-IDENTITY/v1` over the relation's specification and the
/// program's exact bytes + interpreter chain. Two attestations with the same
/// identity were made by the same instrument; a different identity is a
/// different instrument, and nothing more.
pub fn witness_identity(
    semantic: &WitnessSemantic,
    implementation: &WitnessImplementation,
) -> Result<String> {
    let doc = json!({
        "specification_hash": semantic.specification_hash,
        "implementation_hash": implementation.implementation_hash,
        "interpreter": implementation
            .artifact
            .as_ref()
            .and_then(|a| a.interpreter.as_ref())
            .map(serde_json::to_value)
            .transpose()
            .map_err(|e| FrfError::new(format!("cannot serialize the interpreter identity: {e}")))?,
    });
    hash_preimage("FRF/WITNESS-IDENTITY/v1", &doc)
}

/// The identity of a witness statement record: SHA-256 of
/// `FRF/WITNESS-STATEMENT/v1` over its content. Rederivable from the record's
/// own fields. v3: the witness identity and the declared authority enter the
/// preimage.
pub fn witness_statement_identity(c: &WitnessStatementContent) -> Result<String> {
    let doc = json!({
        "subject": serde_json::to_value(c.subject)
            .map_err(|e| FrfError::new(format!("cannot serialize the subject: {e}")))?,
        "witness_semantic": serde_json::to_value(c.witness_semantic)
            .map_err(|e| FrfError::new(format!("cannot serialize the witness semantic: {e}")))?,
        "witness_implementation": serde_json::to_value(c.witness_implementation)
            .map_err(|e| FrfError::new(format!("cannot serialize the witness implementation: {e}")))?,
        "witness_identity": c.witness_identity,
        "authority": c.authority,
        "statement": c.statement,
        "attestation": serde_json::to_value(c.attestation)
            .map_err(|e| FrfError::new(format!("cannot serialize the attestation: {e}")))?,
        "request_cid": c.request_cid,
        "response_cid": c.response_cid,
    });
    hash_preimage("FRF/WITNESS-STATEMENT/v1", &doc)
}

/// The specification hash of an INDEPENDENCE relation: SHA-256 of
/// `FRF/INDEPENDENCE-SPEC/v1` over `{relation, relation_version}`.
pub fn independence_specification_hash(relation: &str, relation_version: &str) -> Result<String> {
    hash_preimage(
        "FRF/INDEPENDENCE-SPEC/v1",
        &json!({ "relation": relation, "relation_version": relation_version }),
    )
}

/// The content-addressable inputs of one independence evidence record.
pub struct IndependenceContent<'a> {
    pub subject: &'a WitnessSubject,
    pub witness_statement: &'a str,
    pub witness_identity: &'a str,
    pub relation: &'a str,
    pub relation_version: &'a str,
    pub specification_hash: &'a str,
    pub basis: &'a str,
    pub detail: &'a Option<String>,
    pub evidence_refs: &'a [EvidenceRef],
}

/// The identity of an independence evidence record: SHA-256 of
/// `FRF/INDEPENDENCE/v1` over its content. Rederivable from the record's own
/// fields.
pub fn independence_identity(c: &IndependenceContent) -> Result<String> {
    let doc = json!({
        "subject": serde_json::to_value(c.subject)
            .map_err(|e| FrfError::new(format!("cannot serialize the subject: {e}")))?,
        "witness_statement": c.witness_statement,
        "witness_identity": c.witness_identity,
        "relation": c.relation,
        "relation_version": c.relation_version,
        "specification_hash": c.specification_hash,
        "basis": c.basis,
        "detail": c.detail,
        "evidence_refs": serde_json::to_value(c.evidence_refs)
            .map_err(|e| FrfError::new(format!("cannot serialize the evidence refs: {e}")))?,
    });
    hash_preimage("FRF/INDEPENDENCE/v1", &doc)
}

/// The first semantic dimension on which two captures differ, phrased for an
/// error message ("fixture id differs (a != b)"). Only used for diagnostics:
/// the PREDICATE is the semantic identity hash, this walk just names the
/// mismatch, aligned to exactly the fields that ARE in the identity.
pub fn semantic_diff(a: &CaptureManifest, b: &CaptureManifest) -> Option<String> {
    let a_env = &a.court_spec.admissibility_envelope;
    let b_env = &b.court_spec.admissibility_envelope;
    let a_sem = &a.comparator_semantics;
    let b_sem = &b.comparator_semantics;
    let checks: Vec<(&str, String, String)> = vec![
        (
            "question",
            a.court_spec.question.clone(),
            b.court_spec.question.clone(),
        ),
        (
            "falsifier",
            a.court_spec.falsifier.clone(),
            b.court_spec.falsifier.clone(),
        ),
        (
            "authority artifact (sha256)",
            a.authority_artifact.sha256.clone(),
            b.authority_artifact.sha256.clone(),
        ),
        ("fixture id", a.fixture.clone(), b.fixture.clone()),
        (
            "fixture bytes (sha256)",
            a.fixture_sha256.clone(),
            b.fixture_sha256.clone(),
        ),
        (
            "fixture arguments",
            format!("{:?}", a.court_spec.fixture.arguments),
            format!("{:?}", b.court_spec.fixture.arguments),
        ),
        (
            "fixture family",
            a_env.fixture_family.clone(),
            b_env.fixture_family.clone(),
        ),
        (
            "platforms",
            a_env.platforms.join(","),
            b_env.platforms.join(","),
        ),
        (
            "observables",
            a_env.observables.join(","),
            b_env.observables.join(","),
        ),
        (
            "normalizers",
            a_env.normalizers.join(","),
            b_env.normalizers.join(","),
        ),
        (
            "replay scope",
            a_env.replay_scope.clone(),
            b_env.replay_scope.clone(),
        ),
        (
            "comparator semantics",
            format!("{:?}", a_sem),
            format!("{:?}", b_sem),
        ),
    ];
    checks
        .into_iter()
        .find(|(_, x, y)| x != y)
        .map(|(what, x, y)| format!("{what} differs ({x:?} != {y:?})"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(question: &str) -> CourtSpec {
        CourtSpec {
            id: "cli-malformed-input".into(),
            question: question.into(),
            falsifier: "f".into(),
            authority: "ref-cli-1.8.2".into(),
            candidate: CandidateSpec {
                name: "cand-cli".into(),
                version_or_commit: "0.1.0".into(),
                build_profile: "debug".into(),
                path: "golden/candidate.sh".into(),
            },
            fixture: FixtureSpec {
                id: "malformed-path.conf".into(),
                path: "f.conf".into(),
                arguments: vec!["--strict".into(), "{fixture}".into()],
            },
            admissibility_envelope: AdmissibilityEnvelope {
                fixture_family: "malformed-input".into(),
                platforms: vec!["x86_64-linux".into()],
                observables: vec!["exit".into(), "stderr".into()],
                normalizers: vec![],
                replay_scope: "single-run".into(),
            },
            produce: None,
            execution_profile: None,
            environment: None,
            environment_points: None,
            execution_context: None,
        }
    }

    fn semantics() -> Vec<ComparatorSemantic> {
        vec![crate::comparators::semantic("exit").unwrap()]
    }

    #[test]
    fn identity_is_deterministic_and_sensitive_to_the_question() {
        let a = court_semantic_identity(
            &spec("q"),
            &"1".repeat(64),
            &"2".repeat(64),
            &semantics(),
            &[],
            &[],
        )
        .unwrap();
        assert_eq!(
            a,
            court_semantic_identity(
                &spec("q"),
                &"1".repeat(64),
                &"2".repeat(64),
                &semantics(),
                &[],
                &[],
            )
            .unwrap()
        );
        // The candidate is NOT part of the question.
        let mut s2 = spec("q");
        s2.candidate.name = "something-else".into();
        assert_eq!(
            a,
            court_semantic_identity(
                &s2,
                &"1".repeat(64),
                &"2".repeat(64),
                &semantics(),
                &[],
                &[],
            )
            .unwrap()
        );
        // The court id is a label, not part of the question.
        let mut s3 = spec("q");
        s3.id = "renamed-court".into();
        assert_eq!(
            a,
            court_semantic_identity(
                &s3,
                &"1".repeat(64),
                &"2".repeat(64),
                &semantics(),
                &[],
                &[],
            )
            .unwrap()
        );
        // The question, the authority ARTIFACT bytes, the fixture bytes, and
        // the comparator semantics all move it.
        assert_ne!(
            a,
            court_semantic_identity(
                &spec("different"),
                &"1".repeat(64),
                &"2".repeat(64),
                &semantics(),
                &[],
                &[],
            )
            .unwrap()
        );
        assert_ne!(
            a,
            court_semantic_identity(
                &spec("q"),
                &"9".repeat(64),
                &"2".repeat(64),
                &semantics(),
                &[],
                &[],
            )
            .unwrap()
        );
        assert_ne!(
            a,
            court_semantic_identity(
                &spec("q"),
                &"1".repeat(64),
                &"9".repeat(64),
                &semantics(),
                &[],
                &[],
            )
            .unwrap()
        );
        assert_ne!(
            a,
            court_semantic_identity(&spec("q"), &"1".repeat(64), &"2".repeat(64), &[], &[], &[])
                .unwrap()
        );
    }

    #[test]
    fn fixture_identity_binds_the_exact_bytes_not_the_label() {
        // The claim-scope aliasing fix: two different files that share a
        // fixture id are DIFFERENT exact inputs, and renaming an input
        // changes the semantic id (the named role stays a separate,
        // family-level dimension).
        let args = vec!["--strict".to_string(), "{fixture}".to_string()];
        let a = fixture_identity("import.trigger", &"1".repeat(64), &args).unwrap();
        let b = fixture_identity("import.trigger", &"2".repeat(64), &args).unwrap();
        assert_ne!(
            a, b,
            "different bytes under the same id are different exact inputs"
        );
        let renamed = fixture_identity("renamed", &"1".repeat(64), &args).unwrap();
        assert_ne!(a, renamed, "renaming an input is a different semantic id");
        let diff_args =
            fixture_identity("import.trigger", &"1".repeat(64), &["--lax".to_string()]).unwrap();
        assert_ne!(
            a, diff_args,
            "a different declared input contract is a different identity"
        );
        // Deterministic: the same exact input is one identity.
        assert_eq!(
            a,
            fixture_identity("import.trigger", &"1".repeat(64), &args).unwrap()
        );
    }

    #[test]
    fn preimages_are_domain_separated() {
        let a = hash_preimage("FRF/X/v1", &json!({"v": "1"})).unwrap();
        // Same doc under a different domain must not collide.
        assert_ne!(a, hash_preimage("FRF/Y/v1", &json!({"v": "1"})).unwrap());
        // The domain tag is not part of the JSON: a doc that embeds the tag
        // as data cannot be confused with a tagged doc.
        let b = hash_preimage("FRF/X/v1", &json!({"v": "FRF/X/v1"})).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn fingerprint_is_structured_and_stable() {
        let r = |surface: Option<String>, raw_ref: &str, raw_cand: &str| ResidualRecord {
            schema_version: SCHEMA_RESIDUAL.into(),
            id: "cli-text-0001".into(),
            court: "c".into(),
            run: "r".into(),
            axis: ObservableId::stderr(),
            kind: ResidualKind::text(),
            surface,
            authority: "a".into(),
            scope: "s".into(),
            candidate_sha256: "0".repeat(64),
            raw_reference: raw_ref.into(),
            raw_candidate: raw_cand.into(),
            raw_reference_sha256: host::sha256_bytes(raw_ref.as_bytes()),
            raw_candidate_sha256: host::sha256_bytes(raw_cand.as_bytes()),
        };
        // Values containing the old separator characters cannot be confused:
        // the preimage is JSON, not concatenation.
        let a = residual_fingerprint(&r(Some("a|b".into()), "c", "d")).unwrap();
        let b = residual_fingerprint(&r(Some("a".into()), "b|c", "d")).unwrap();
        assert_ne!(a, b);
        assert_eq!(
            a,
            residual_fingerprint(&r(Some("a|b".into()), "c", "d")).unwrap()
        );
    }

    #[test]
    fn run_identity_commits_the_execution_contract_but_observation_is_separate() {
        // The core property of the FRF/RUN/v2 split: two executions that
        // coincide on outputs under DIFFERENT harness contracts are
        // different bounded observations (different run identities) yet
        // share the same observation identity; and two executions that
        // differ on OUTPUTS under the same contract share the execution
        // identity.
        let empty = SideCapture {
            exit: "0".into(),
            exit_sha256: "0".repeat(64),
            stderr_first_line: String::new(),
            stderr_first_line_sha256: "0".repeat(64),
            stdout_first_line: String::new(),
            stdout_first_line_sha256: "0".repeat(64),
            stdout_sha256: "0".repeat(64),
            stderr_sha256: "0".repeat(64),
            produced: None,
            adapted: None,
            stdout_bytes: vec![],
        };
        let bounds = |timeout: &str, cgroup: Option<&str>| CaptureBounds {
            timeout_ms: timeout.into(),
            max_stream_bytes: "16777216".into(),
            rlimit_as_mb: "2048".into(),
            rlimit_cpu_s: "30".into(),
            rlimit_nofile: "1024".into(),
            rlimit_nproc: "512".into(),
            cgroup_pids_max: cgroup.map(str::to_string),
            cgroup_memory_max: None,
            cgroup_cpu_max: None,
        };
        let candidate_sha = "1".repeat(64);
        let fixture_sha = "2".repeat(64);
        let env_digest = "3".repeat(64);
        let runner_hash = "4".repeat(64);
        let court_sem = "5".repeat(64);
        // The three identities of one run, computed from a preimage built
        // and consumed inside the closure (no borrow escapes).
        let ids = |profile: &str,
                   timeout: &str,
                   cgroup: Option<&str>,
                   side: &SideCapture|
         -> (String, String, String) {
            let b = bounds(timeout, cgroup);
            let pre = RunPreimage {
                court: "c",
                authority: "a",
                authority_interpreter: None,
                candidate_sha256: &candidate_sha,
                candidate_interpreter: None,
                fixture_sha256: &fixture_sha,
                arguments: &[],
                environment_digest: &env_digest,
                runner_hash: &runner_hash,
                court_semantic_identity: &court_sem,
                reference: side,
                candidate: side,
                residuals: &[],
                execution_profile: profile,
                capture_bounds: &b,
                comparator_implementations: &[],
                normalizer_implementations: &[],
                adapter_implementations: &[],
                minimizer_implementations: &[],
            };
            (
                observation_identity(&pre).unwrap(),
                execution_identity(&pre).unwrap(),
                run_identity(&pre).unwrap(),
            )
        };
        let (obs, exec, run) = ids("frf-exec-linux-v1", "60000", None, &empty);
        let (obs5, exec5, run5) = ids("frf-exec-linux-v1", "5000", None, &empty);
        // Same outputs under a different TIMEOUT: the same bounded
        // observation contract must not silently collide.
        assert_eq!(
            obs, obs5,
            "identical outputs + inputs under different bounds share the OBSERVATION identity"
        );
        assert_ne!(
            exec, exec5,
            "a different timeout is a different EXECUTION identity"
        );
        assert_ne!(
            run, run5,
            "a different contract is a different RUN identity even with identical outputs"
        );

        // Same outputs under a different PROFILE (v1 per-process limits vs
        // v2 cgroup envelope): different execution + run identity.
        let (obs_v2, _, run_v2) = ids("frf-exec-linux-v2", "60000", Some("64"), &empty);
        assert_eq!(obs, obs_v2);
        assert_ne!(run, run_v2);

        // A different observed OUTPUT under the same contract: the same
        // execution identity, a different observation + run identity.
        let mut out1 = empty.clone();
        out1.exit = "1".into();
        let (obs_out, exec_out, run_out) = ids("frf-exec-linux-v1", "60000", None, &out1);
        assert_eq!(exec, exec_out);
        assert_ne!(obs, obs_out);
        assert_ne!(run, run_out);

        // The run identity is the deterministic composition of the two.
        let (_, _, run_re) = ids("frf-exec-linux-v1", "60000", None, &empty);
        assert_eq!(run, run_re);
    }

    #[test]
    fn diff_names_the_first_differing_dimension() {
        let capture = |spec: CourtSpec, auth_sha: &str| CaptureManifest {
            schema_version: SCHEMA_CAPTURE.into(),
            run: "run-x".into(),
            court: spec.id.clone(),
            authority: spec.authority.clone(),
            manifest: "m.yaml".into(),
            fixture: spec.fixture.id.clone(),
            fixture_sha256: "2".repeat(64),
            arguments: vec![],
            environment: EnvironmentIdentity {
                schema_version: SCHEMA_ENVIRONMENT.into(),
                os: "linux".into(),
                architecture: "x86_64".into(),
                kernel_release: "6".into(),
                locale: "C".into(),
                timezone: "Etc/UTC".into(),
                umask: "0022".into(),
                cwd: "frf".into(),
                environment: Default::default(),
                digest: "0".repeat(64),
            },
            court_spec: spec,
            comparator_semantics: vec![],
            normalizer_semantics: vec![],
            adapter_semantics: vec![],
            minimizer_semantics: vec![],
            provenance: ObservationProvenance {
                schema_version: SCHEMA_PROVENANCE.into(),
                runner: RunnerIdentity {
                    schema_version: SCHEMA_RUNNER.into(),
                    frf_version: "0".into(),
                    frf_executable_hash: "0".repeat(64),
                },
                comparator_implementations: vec![],
                normalizer_implementations: vec![],
                adapter_implementations: vec![],
                minimizer_implementations: vec![],
            },
            authority_artifact: ArtifactIdentity {
                path: "p".into(),
                sha256: auth_sha.into(),
                interpreter: None,
                native_runtime: None,
            },
            candidate_artifact: ArtifactIdentity {
                path: "p".into(),
                sha256: "0".repeat(64),
                interpreter: None,
                native_runtime: None,
            },
            court_semantic_identity: "0".repeat(64),
            execution_profile: crate::model::EXECUTION_PROFILE_LINUX.into(),
            capture_bounds: CaptureBounds {
                timeout_ms: "60000".into(),
                max_stream_bytes: "16777216".into(),
                rlimit_as_mb: "2048".into(),
                rlimit_cpu_s: "30".into(),
                rlimit_nofile: "1024".into(),
                rlimit_nproc: "512".into(),
                cgroup_pids_max: None,
                cgroup_memory_max: None,
                cgroup_cpu_max: None,
            },
            observation_identity: "0".repeat(64),
            execution_identity: "0".repeat(64),
            reference: SideCapture {
                exit: "0".into(),
                exit_sha256: "0".repeat(64),
                stderr_first_line: String::new(),
                stderr_first_line_sha256: "0".repeat(64),
                stdout_first_line: String::new(),
                stdout_first_line_sha256: "0".repeat(64),
                stdout_sha256: "0".repeat(64),
                stderr_sha256: "0".repeat(64),
                produced: None,
                adapted: None,
                stdout_bytes: vec![],
            },
            candidate: SideCapture {
                exit: "0".into(),
                exit_sha256: "0".repeat(64),
                stderr_first_line: String::new(),
                stderr_first_line_sha256: "0".repeat(64),
                stdout_first_line: String::new(),
                stdout_first_line_sha256: "0".repeat(64),
                stdout_sha256: "0".repeat(64),
                stderr_sha256: "0".repeat(64),
                produced: None,
                adapted: None,
                stdout_bytes: vec![],
            },
            residuals: vec![],
            evidence_refs: vec![],
            execution_context: None,
        };

        let a = capture(spec("q"), &"1".repeat(64));
        assert_eq!(
            semantic_diff(&a, &capture(spec("q"), &"1".repeat(64))),
            None
        );
        let mut b = capture(spec("q"), &"1".repeat(64));
        b.fixture = "other.conf".into();
        assert_eq!(
            semantic_diff(&a, &b).unwrap(),
            "fixture id differs (\"malformed-path.conf\" != \"other.conf\")"
        );
        let mut c = capture(spec("q"), &"1".repeat(64));
        c.authority_artifact.sha256 = "9".repeat(64);
        assert_eq!(
            semantic_diff(&a, &c).unwrap(),
            format!(
                "authority artifact (sha256) differs ({:?} != {:?})",
                "1".repeat(64),
                "9".repeat(64)
            )
        );
    }
}
