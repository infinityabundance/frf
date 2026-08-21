//! Comparator registry + extension protocol host — the observable/plugin
//! architecture.
//!
//! Each observable axis is served by a comparator RELATION. What a relation
//! *is* is captured as a canonical specification document — id, relation
//! family, extractor, and residual classifier — and its SHA-256 becomes the
//! comparator's `specification_hash`. That hash is what enters the court's
//! semantic identity: two independent FRF implementations that implement the
//! same specification ask the same question, even though their executable
//! bytes differ.
//!
//! The observable id is a PROTOCOL IDENTIFIER ([`ObservableId`]), not a
//! closed Rust enum: the reference engine ships three in-binary comparators
//! (`exit`, `stderr`, `stdout`), but ANY valid id (`dns.wire`,
//! `filesystem.tree`, `tzif.bytes`, …) can be declared and served by an
//! external comparator through the extension protocol (spec/comparator.md).
//! The core runs observables without knowing what stdout, packets, or
//! filesystem trees are; the built-ins are strongly typed helpers here.
//!
//! What *implemented* the relation (this executable, or an external
//! comparator program) is a separate fact, recorded in the capture's
//! observation provenance — and an external comparator's invocation is
//! itself evidence (the canonical request, the canonical response, the
//! invocation record, the result record) that replay re-runs and the bundle
//! carries. The question never depends on the implementation; the
//! provenance always records it.

use crate::error::{FrfError, Result};
use crate::host;
use crate::host::ProcessOutcome;
use crate::model::{
    ArtifactIdentity, ComparatorDeclaration, ComparatorResponse, ComparatorSemantic, ObservableId,
    RunnerIdentity, SideCapture, COMPARATOR_VERSION,
};
use crate::store::Store;
use serde_json::json;
use std::path::Path;

/// The canonical specification of a comparator relation: everything that
/// defines WHAT the relation is (the residual classifier included — it is
/// part of the question, because it fixes the kind every divergence on the
/// axis is recorded as).
pub struct ComparatorSpec {
    /// Observable axis id.
    pub id: &'static str,
    /// Relation family (Section 10, Δ_a).
    pub relation: &'static str,
    /// What the comparator extracts and compares.
    pub extractor: &'static str,
    /// The residual kind divergences on this axis are classified as.
    pub residual_classifier: &'static str,
}

pub const SPECS: &[ComparatorSpec] = &[
    ComparatorSpec {
        id: "exit",
        relation: "eq",
        extractor: "exit-code",
        residual_classifier: "exit",
    },
    ComparatorSpec {
        id: "stderr",
        relation: "eq",
        extractor: "stderr-first-line",
        residual_classifier: "text",
    },
    ComparatorSpec {
        id: "stdout",
        relation: "eq",
        extractor: "stdout-first-line",
        residual_classifier: "text",
    },
];

/// The registry row serving `id`, if the axis is a built-in.
pub fn spec_for(id: &str) -> Option<&'static ComparatorSpec> {
    SPECS.iter().find(|s| s.id == id)
}

/// The specification hash: SHA-256 of `FRF/COMPARATOR-SPEC/v1` over the
/// canonical specification document. One formula shared by the in-binary
/// registry and external declarations — and by the receipt-side semantic
/// validator, so a recorded `specification_hash` REDERIVES from its own
/// fields.
pub fn specification_hash(
    id: &str,
    relation: &str,
    extractor: &str,
    residual_classifier: &str,
) -> Result<String> {
    let doc = json!({
        "id": id,
        "relation": relation,
        "extractor": extractor,
        "residual_classifier": residual_classifier,
    });
    crate::semantics::hash_preimage("FRF/COMPARATOR-SPEC/v1", &doc)
}

/// The comparator semantic from a registry row.
pub fn semantic(id: &str) -> Result<ComparatorSemantic> {
    let spec = spec_for(id).ok_or_else(|| {
        FrfError::new(format!(
            "no built-in comparator registered for axis '{id}' (declare an external comparator for it, see spec/comparator.md)"
        ))
    })?;
    let specification_hash = specification_hash(
        spec.id,
        spec.relation,
        spec.extractor,
        spec.residual_classifier,
    )?;
    Ok(ComparatorSemantic {
        id: spec.id.to_string(),
        relation_id: spec.relation.to_string(),
        extractor: spec.extractor.to_string(),
        residual_classifier: spec.residual_classifier.to_string(),
        relation_version: COMPARATOR_VERSION.to_string(),
        specification_hash,
    })
}

/// The semantic identity of an EXTERNAL comparator declared in a court
/// manifest. Same formula as [`semantic`]: a declaration with the same
/// relation/extractor/classifier/version as a built-in produces the SAME
/// specification hash — the external program serves the same question; only
/// the implementation differs (recorded in the capture's provenance).
pub fn declared_semantic(decl: &ComparatorDeclaration) -> Result<ComparatorSemantic> {
    let specification_hash = specification_hash(
        &decl.axis,
        &decl.relation,
        &decl.extractor,
        &decl.residual_classifier,
    )?;
    Ok(ComparatorSemantic {
        id: decl.axis.clone(),
        relation_id: decl.relation.clone(),
        extractor: decl.extractor.clone(),
        residual_classifier: decl.residual_classifier.clone(),
        relation_version: decl.relation_version.clone(),
        specification_hash,
    })
}

/// The comparator implementations that observed a run, for the capture's
/// provenance block. In-binary comparators are implemented by the frf
/// executable itself, so both hashes are the runner's executable hash.
pub fn implementations(
    axes: &[String],
    runner_hash: &str,
) -> Vec<crate::model::ComparatorImplementation> {
    axes.iter()
        .map(|id| crate::model::ComparatorImplementation {
            id: id.clone(),
            implementation_hash: runner_hash.to_string(),
            runner_hash: runner_hash.to_string(),
            artifact: None,
        })
        .collect()
}

/// What a comparator concluded about one axis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComparatorOutcome {
    /// The axes' projections agree; no residual on this axis.
    Equivalent,
    /// The divergences, as `(surface, raw_reference, raw_candidate)` triples
    /// the court preserves verbatim.
    Divergent(Vec<(Option<String>, String, String)>),
}

/// Interpret a comparator's canonical response. Fail-closed: every
/// contradiction or inconclusive state is a refusal, never a silent default.
///
/// - wrong schema version, unparseable JSON, non-zero exit, timeout → the
///   CALLER refuses (the response never made it here);
/// - `request_id` not equal to the request the court sent → refusal (the
///   response must cryptographically name the request it answers);
/// - `indeterminate` → refusal (inconclusive evidence must not be recorded);
/// - `failure` → refusal;
/// - `equivalent` with residuals, or `divergent` without residuals → refusal
///   (the response contradicts itself);
/// - a divergent response whose raw values are equal → refusal (a divergence
///   must diverge).
pub fn interpret(
    response: &ComparatorResponse,
    expected_request_id: &str,
) -> Result<ComparatorOutcome> {
    if response.schema_version != crate::model::SCHEMA_COMPARATOR_RESPONSE {
        return Err(FrfError::new(format!(
            "comparator response has unsupported schema version {:?} (expected {})",
            response.schema_version,
            crate::model::SCHEMA_COMPARATOR_RESPONSE
        )));
    }
    if response.request_id != expected_request_id {
        return Err(FrfError::new(format!(
            "comparator response names request {} but it answers request {}; a response must cryptographically name the exact request it answers",
            &response.request_id[..16.min(response.request_id.len())],
            &expected_request_id[..16]
        )));
    }
    if response.indeterminate {
        return Err(FrfError::new(
            "comparator returned indeterminate: the axis cannot be evaluated; refusing to record inconclusive evidence as conclusive",
        ));
    }
    if let Some(f) = &response.failure {
        return Err(FrfError::new(format!("comparator reported failure: {f}")));
    }
    if response.equivalent {
        if !response.residuals.is_empty() {
            return Err(FrfError::new(
                "comparator response contradicts itself: equivalent with residuals",
            ));
        }
        return Ok(ComparatorOutcome::Equivalent);
    }
    if response.residuals.is_empty() {
        return Err(FrfError::new(
            "comparator response contradicts itself: divergent without naming a residual",
        ));
    }
    let mut out = Vec::with_capacity(response.residuals.len());
    for r in &response.residuals {
        if r.raw_reference == r.raw_candidate {
            return Err(FrfError::new(
                "comparator response contradicts itself: a divergent residual whose raw values are equal",
            ));
        }
        out.push((
            r.surface.clone(),
            r.raw_reference.clone(),
            r.raw_candidate.clone(),
        ));
    }
    Ok(ComparatorOutcome::Divergent(out))
}

// ---------------------------------------------------------------------------
// The built-in extractors (strongly typed helpers for the three built-ins)
// ---------------------------------------------------------------------------

/// The three in-binary comparator implementations, as strongly typed helpers.
/// The evidence core never matches on these directly — the registry keys the
/// comparison on the observable id — but the built-in extractors live here,
/// next to their registry rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuiltinKind {
    Exit,
    Stderr,
    Stdout,
}

impl BuiltinKind {
    /// The built-in implementation serving `id`, if any.
    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "exit" => Some(BuiltinKind::Exit),
            "stderr" => Some(BuiltinKind::Stderr),
            "stdout" => Some(BuiltinKind::Stdout),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            BuiltinKind::Exit => "exit",
            BuiltinKind::Stderr => "stderr",
            BuiltinKind::Stdout => "stdout",
        }
    }

    /// The residual surface this built-in names its divergence with.
    pub fn surface(self) -> Option<&'static str> {
        match self {
            BuiltinKind::Exit => None,
            BuiltinKind::Stderr => Some("first-diagnostic-line"),
            BuiltinKind::Stdout => Some("first-stdout-line"),
        }
    }

    /// The raw projection this built-in extracts from one side.
    pub fn project(self, side: &SideCapture) -> String {
        match self {
            BuiltinKind::Exit => side.exit.clone(),
            BuiltinKind::Stderr => side.stderr_first_line.clone(),
            BuiltinKind::Stdout => side.stdout_first_line.clone(),
        }
    }

    /// Compare two sides: `(surface, raw_reference, raw_candidate)`.
    pub fn compare(
        self,
        reference: &SideCapture,
        candidate: &SideCapture,
    ) -> (Option<&'static str>, String, String) {
        (
            self.surface(),
            self.project(reference),
            self.project(candidate),
        )
    }
}

// ---------------------------------------------------------------------------
// The external comparator protocol host
// ---------------------------------------------------------------------------

/// Build the canonical comparator REQUEST for one axis (the extension
/// protocol, spec/comparator.md). ONE builder, shared by the court, replay,
/// minimization, and (via recorded evidence) the verifier — a request is a
/// derived object, and its identity (`request_cid`) is its canonical bytes'
/// SHA-256, so rebuilding it must reproduce the same cid or the evidence is
/// refused.
#[allow(clippy::too_many_arguments)] // one argument per request dimension; the doc is the protocol shape
pub fn build_request<'a>(
    axis: &'a str,
    semantic: &'a ComparatorSemantic,
    reference: &'a ProcessOutcome,
    candidate: &'a ProcessOutcome,
    fixture_sha256: &'a str,
    arguments: &'a [String],
    environment_digest: &'a str,
) -> crate::model::ComparatorRequest<'a> {
    crate::model::ComparatorRequest {
        schema_version: crate::model::SCHEMA_COMPARATOR_REQUEST,
        comparator: semantic,
        axis,
        reference: crate::model::ComparatorObservation {
            exit: &reference.exit,
            stdout_base64: b64(&reference.stdout),
            stderr_base64: b64(&reference.stderr),
        },
        candidate: crate::model::ComparatorObservation {
            exit: &candidate.exit,
            stdout_base64: b64(&candidate.stdout),
            stderr_base64: b64(&candidate.stderr),
        },
        context: crate::model::ComparatorContext {
            fixture_sha256,
            arguments,
            environment_digest,
        },
    }
}

/// The canonical bytes of a request plus their content address. The request
/// document carries its `schema_version` (the domain tag is inside the
/// document), so its identity is simply the SHA-256 of its exact canonical
/// bytes — the same bytes the comparator receives and must echo.
pub fn canonical_request(request: &crate::model::ComparatorRequest) -> Result<(Vec<u8>, String)> {
    let json = crate::canon::canonical(request)?;
    let bytes = json.into_bytes();
    let cid = host::sha256_bytes(&bytes);
    Ok((bytes, cid))
}

/// Execute an external comparator against a request and interpret its
/// response, fail-closed. The comparator must already be a verified,
/// materialized snapshot (the caller hashes + seals before execution); this
/// function refuses a non-zero exit, an unparseable response, a response
/// that does not name the request it answers, and every contradictory or
/// inconclusive response ([`interpret`]).
pub fn run_external(
    snapshot: &Path,
    axis: &ObservableId,
    request_bytes: &[u8],
    request_cid: &str,
) -> Result<(ComparatorOutcome, Vec<u8>)> {
    let out = host::run_process_with_stdin(snapshot, &[], request_bytes)?;
    if out.exit != "0" {
        return Err(FrfError::new(format!(
            "comparator for axis {} exited {}; refusing to record evidence from a failed comparator",
            axis.as_str(),
            out.exit
        )));
    }
    let response: ComparatorResponse = serde_json::from_slice(&out.stdout).map_err(|e| {
        FrfError::new(format!(
            "comparator for axis {} produced an unparseable response: {e}",
            axis.as_str()
        ))
    })?;
    let outcome = interpret(&response, request_cid)
        .map_err(|e| FrfError::new(format!("comparator for axis {}: {e}", axis.as_str())))?;
    Ok((outcome, out.stdout))
}

/// The invocation evidence for one externally served axis: written at court
/// time under `captures/<run>/comparator/<axis>/`, and re-verified on every
/// read (see [`Store::load_comparator_invocation`] /
/// [`Store::load_comparator_result`]).
pub fn evidence_file_names() -> [&'static str; 4] {
    [
        "request.json",
        "response.json",
        "invocation.json",
        "result.json",
    ]
}

/// `Store` binding: materialize + verify a comparator implementation artifact
/// (the exact bytes the court snapshotted) for re-execution.
pub fn materialize_implementation(
    store: &Store,
    artifact: &ArtifactIdentity,
) -> Result<std::path::PathBuf> {
    let bytes = store.verified_object_bytes(&artifact.sha256)?;
    store.materialize_object(&bytes, true)
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// The runner identity of the invoking process, shared by all comparator
/// evidence records written by this court.
pub fn runner_identity() -> Result<RunnerIdentity> {
    Ok(RunnerIdentity {
        schema_version: crate::model::SCHEMA_RUNNER.to_string(),
        frf_version: env!("CARGO_PKG_VERSION").to_string(),
        frf_executable_hash: host::current_exe_hash()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ComparatorDeclaration, ComparatorResidual};

    #[test]
    fn semantics_are_stable_and_distinct() {
        let a = semantic("exit").unwrap();
        assert_eq!(a, semantic("exit").unwrap());
        assert_ne!(a, semantic("stderr").unwrap());
        assert_eq!(a.relation_id, "eq");
        assert_eq!(a.relation_version, COMPARATOR_VERSION);
        assert_eq!(a.specification_hash.len(), 64);
        // The semantic identity is implementation-independent by
        // construction: it is a hash of the specification doc, not of code.
        let expected = specification_hash("exit", "eq", "exit-code", "exit").unwrap();
        assert_eq!(a.specification_hash, expected);
    }

    #[test]
    fn unknown_axis_has_no_builtin_comparator() {
        assert!(semantic("wire").is_err());
        assert!(BuiltinKind::from_id("wire").is_none());
    }

    #[test]
    fn a_declaration_with_the_builtin_spec_asks_the_same_question() {
        let decl = ComparatorDeclaration {
            axis: "stderr".into(),
            relation: "eq".into(),
            extractor: "stderr-first-line".into(),
            residual_classifier: "text".into(),
            relation_version: COMPARATOR_VERSION.into(),
            program: "golden/comparators/stderr-first-line.py".into(),
        };
        // Same relation/extractor/classifier/version as the built-in registry
        // row: the external program serves the SAME question.
        assert_eq!(
            declared_semantic(&decl).unwrap(),
            semantic("stderr").unwrap()
        );
        // A different extractor is a different question.
        let mut other = decl.clone();
        other.extractor = "stderr-bytes".into();
        assert_ne!(
            declared_semantic(&decl).unwrap(),
            declared_semantic(&other).unwrap()
        );
        // A different residual classifier is a different question too (it is
        // part of the specification document).
        let mut other_kind = decl.clone();
        other_kind.residual_classifier = "diagnostic".into();
        assert_ne!(
            declared_semantic(&decl).unwrap(),
            declared_semantic(&other_kind).unwrap()
        );
    }

    fn response(
        equivalent: bool,
        residuals: Vec<ComparatorResidual>,
        indeterminate: bool,
        failure: Option<&str>,
    ) -> ComparatorResponse {
        ComparatorResponse {
            schema_version: crate::model::SCHEMA_COMPARATOR_RESPONSE.into(),
            request_id: "r".repeat(64),
            equivalent,
            residuals,
            indeterminate,
            failure: failure.map(str::to_string),
        }
    }

    #[test]
    fn interpret_accepts_equivalent_and_divergent() {
        let rid = "r".repeat(64);
        assert_eq!(
            interpret(&response(true, vec![], false, None), &rid).unwrap(),
            ComparatorOutcome::Equivalent
        );
        let out = interpret(
            &response(
                false,
                vec![ComparatorResidual {
                    surface: Some("first-diagnostic-line".into()),
                    raw_reference: "a".into(),
                    raw_candidate: "b".into(),
                }],
                false,
                None,
            ),
            &rid,
        )
        .unwrap();
        assert_eq!(
            out,
            ComparatorOutcome::Divergent(vec![(
                Some("first-diagnostic-line".into()),
                "a".into(),
                "b".into()
            )])
        );
    }

    #[test]
    fn interpret_refuses_every_contradiction_and_inconclusive_state() {
        let rid = "r".repeat(64);
        let divergent = || ComparatorResidual {
            surface: None,
            raw_reference: "a".into(),
            raw_candidate: "b".into(),
        };
        // indeterminate
        assert!(interpret(&response(false, vec![divergent()], true, None), &rid).is_err());
        // failure
        assert!(interpret(
            &response(false, vec![divergent()], false, Some("boom")),
            &rid
        )
        .is_err());
        // equivalent with residuals
        assert!(interpret(&response(true, vec![divergent()], false, None), &rid).is_err());
        // divergent without residuals
        assert!(interpret(&response(false, vec![], false, None), &rid).is_err());
        // divergent residual whose raw values are equal
        assert!(interpret(
            &response(
                false,
                vec![ComparatorResidual {
                    surface: None,
                    raw_reference: "same".into(),
                    raw_candidate: "same".into(),
                }],
                false,
                None
            ),
            &rid
        )
        .is_err());
        // wrong schema version
        let mut bad = response(true, vec![], false, None);
        bad.schema_version = "frf-comparator-response-v9".into();
        assert!(interpret(&bad, &rid).is_err());
        // the response must name the request it answers
        let mut wrong = response(true, vec![], false, None);
        wrong.request_id = "0".repeat(64);
        let err = interpret(&wrong, &rid).unwrap_err();
        assert!(err.0.contains("names request"), "{err:?}");
    }

    #[test]
    fn builtin_projections_follow_the_registry_extractors() {
        let reference = SideCapture {
            exit: "2".into(),
            exit_sha256: "a".repeat(64),
            stderr_first_line: "ref diag".into(),
            stderr_first_line_sha256: "b".repeat(64),
            stdout_first_line: "ref out".into(),
            stdout_first_line_sha256: "c".repeat(64),
            stdout_sha256: "d".repeat(64),
            stderr_sha256: "e".repeat(64),
        };
        let candidate = SideCapture {
            exit: "1".into(),
            exit_sha256: "f".repeat(64),
            stderr_first_line: "cand diag".into(),
            stderr_first_line_sha256: "g".repeat(64),
            stdout_first_line: "ref out".into(),
            stdout_first_line_sha256: "c".repeat(64),
            stdout_sha256: "h".repeat(64),
            stderr_sha256: "i".repeat(64),
        };
        let (surface, raw_ref, raw_cand) = BuiltinKind::Exit.compare(&reference, &candidate);
        assert_eq!(surface, None);
        assert_eq!((raw_ref.as_str(), raw_cand.as_str()), ("2", "1"));
        let (surface, raw_ref, raw_cand) = BuiltinKind::Stderr.compare(&reference, &candidate);
        assert_eq!(surface, Some("first-diagnostic-line"));
        assert_eq!(
            (raw_ref.as_str(), raw_cand.as_str()),
            ("ref diag", "cand diag")
        );
        let (surface, raw_ref, raw_cand) = BuiltinKind::Stdout.compare(&reference, &candidate);
        assert_eq!(surface, Some("first-stdout-line"));
        assert_eq!(
            (raw_ref.as_str(), raw_cand.as_str()),
            ("ref out", "ref out")
        );
    }
}
