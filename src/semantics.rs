//! Identity discipline — every evidence identity in FRF.
//!
//! One rule for all identities: the preimage is a fixed domain tag followed
//! by canonical JSON (RFC 8785), and the identity is its SHA-256. No
//! delimiter-assembled strings (`|`, newlines) anywhere: a JSON document
//! cannot be ambiguous about field boundaries the way a concatenation can.
//!
//!   FRF/RUN/v1                 run identity (per court run)
//!   FRF/COURT/v2               court semantic identity (the question)
//!   FRF/COMPARATOR-SPEC/v2     comparator relation specification
//!   FRF/RESIDUAL-FINGERPRINT/v1  residual fingerprint
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

/// Every input that defines one court run's identity. The preimage is a
/// domain-separated canonical JSON document (`FRF/RUN/v1`); the identity is
/// its SHA-256. Built at court time by the runner and REDERIVED by replay,
/// receipt verification, and the verification suite from the capture's own
/// recorded fields — the name is a claim until it is recomputed.
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
}

/// The one run-identity function, shared by `court run`, replay, receipt
/// verification, and the verification suite. No duplicate implementation:
/// a capture whose recorded fields hash to a different id is refused.
pub fn run_identity(p: &RunPreimage) -> Result<String> {
    let side = |s: &SideCapture| {
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
    };
    let doc = json!({
        "court": p.court,
        "authority": p.authority,
        "authority_interpreter": p.authority_interpreter,
        "candidate_sha256": p.candidate_sha256,
        "candidate_interpreter": p.candidate_interpreter,
        "fixture_sha256": p.fixture_sha256,
        "arguments": p.arguments,
        "environment_digest": p.environment_digest,
        "runner_hash": p.runner_hash,
        "court_semantic_identity": p.court_semantic_identity,
        "reference": side(p.reference),
        "candidate": side(p.candidate),
        "residuals": p
            .residuals
            .iter()
            .map(|r| json!({
                "kind": r.kind.as_str(),
                "raw_reference": r.raw_reference,
                "raw_candidate": r.raw_candidate,
            }))
            .collect::<Vec<_>>(),
    });
    hash_preimage("FRF/RUN/v1", &doc)
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
                "point_index": p.point_index.to_string(),
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
                "attempt": a.attempt.to_string(),
                "role": a.role.as_str(),
                "fixture_sha256": a.fixture_sha256,
                "outcome": a.outcome.as_str(),
                "accepted": a.accepted,
            }))
            .collect::<Vec<_>>(),
        "derivation": {
            "strategy": derivation.strategy,
            "original_lines": derivation.original_lines.to_string(),
            "final_lines": derivation.final_lines.to_string(),
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

/// The CONTENT ADDRESS of an evidence record (a residual record or an
/// authority record): SHA-256 of the canonical serialization of the record's
/// own fields. Records are stored as YAML by the reference engine, but their
/// content identity is the canonical JSON document of their fields — the
/// same document any independent implementation rederives from its own
/// parsing. This is what the knowledge universe commits for a record whose
/// id is a label, not a content address.
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
    pub statement: &'a str,
    pub attestation: &'a WitnessAttestation,
    pub request_cid: &'a str,
    pub response_cid: &'a str,
}

/// The identity of a witness statement record: SHA-256 of
/// `FRF/WITNESS-STATEMENT/v1` over its content. Rederivable from the record's
/// own fields.
pub fn witness_statement_identity(c: &WitnessStatementContent) -> Result<String> {
    let doc = json!({
        "subject": serde_json::to_value(c.subject)
            .map_err(|e| FrfError::new(format!("cannot serialize the subject: {e}")))?,
        "witness_semantic": serde_json::to_value(c.witness_semantic)
            .map_err(|e| FrfError::new(format!("cannot serialize the witness semantic: {e}")))?,
        "witness_implementation": serde_json::to_value(c.witness_implementation)
            .map_err(|e| FrfError::new(format!("cannot serialize the witness implementation: {e}")))?,
        "statement": c.statement,
        "attestation": serde_json::to_value(c.attestation)
            .map_err(|e| FrfError::new(format!("cannot serialize the attestation: {e}")))?,
        "request_cid": c.request_cid,
        "response_cid": c.response_cid,
    });
    hash_preimage("FRF/WITNESS-STATEMENT/v1", &doc)
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
            },
            candidate_artifact: ArtifactIdentity {
                path: "p".into(),
                sha256: "0".repeat(64),
                interpreter: None,
            },
            court_semantic_identity: "0".repeat(64),
            execution_profile: crate::model::EXECUTION_PROFILE_LINUX.into(),
            capture_bounds: CaptureBounds {
                timeout_ms: "60000".into(),
                max_stream_bytes: "16777216".into(),
                rlimit_as_mb: "2048".into(),
                rlimit_cpu_s: "30".into(),
                rlimit_nofile: "1024".into(),
            },
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
