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
    ArtifactIdentity, CaptureManifest, ComparatorDeclaration, ComparatorImplementation,
    ComparatorResponse, ComparatorSemantic, ObservableId, ProducedSide, RunnerIdentity,
    SideCapture, COMPARATOR_VERSION,
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
    ComparatorSpec {
        id: "filesystem.tree",
        relation: "eq",
        extractor: "produced-tree",
        residual_classifier: "text",
    },
    ComparatorSpec {
        id: "bytes.wire",
        relation: "eq",
        extractor: "stdout-bytes",
        residual_classifier: "text",
    },
    ComparatorSpec {
        id: "structured.state",
        relation: "eq",
        extractor: "json-fields",
        residual_classifier: "text",
    },
];

/// The registry row serving `id`, if the axis is a built-in.
pub fn spec_for(id: &str) -> Option<&'static ComparatorSpec> {
    SPECS.iter().find(|s| s.id == id)
}

// ---------------------------------------------------------------------------
// Trajectory magnitude measures (v0.1.37, frf-trajectory-v4)
// ---------------------------------------------------------------------------
//
// The trajectory vocabulary's `gradual` needs a MAGNITUDE dimension: presence
// is binary, so how FAR apart the compared projections are at each point must
// be a separate, deterministic measure. The measure is declared PER COMPARATOR
// here, in the registry that already defines each built-in's extractor — the
// trajectory derivation code stays surface-agnostic. Only built-ins whose
// residual projections admit a distance get a measure:
//
//   exit            -> exit-code-distance    |ref_exit - cand_exit|
//   stderr/stdout   -> line-edit-distance    Levenshtein on the compared
//                                            first-line projections
//   structured.state-> value-edit-distance   Levenshtein on the compared
//                                            field values
//   filesystem.tree, bytes.wire, external -> none (the projections are
//                                            content hashes / hashes — an
//                                            identity, not a degree; an
//                                            external surface is unknowable)
//
// The measures are bounded and deterministic: the edit distance is computed
// over the first MAGNITUDE_BOUND bytes of each projection (a declared
// constant), so a hostile or enormous stream cannot make the derivation
// unbounded, and the truncation is part of the measure's declaration. The
// computed degree is a decimal STRING (the canonical JSON value domain has no
// numbers).

/// The declared truncation bound of the edit-distance measures (bytes).
pub const MAGNITUDE_BOUND: usize = 2048;

/// The declared magnitude measure for a built-in axis, or `none`.
pub fn magnitude_kind(axis: &str) -> String {
    match axis {
        "exit" => "exit-code-distance".to_string(),
        "stderr" | "stdout" => "line-edit-distance".to_string(),
        "structured.state" => "value-edit-distance".to_string(),
        _ => "none".to_string(),
    }
}

/// The deterministic divergence degree between a residual observation's
/// compared projections on `axis` — a decimal string, or `None` when the
/// axis declares no measure or the measure is not computable on this
/// observation. Computed from the projections THE COMPARATOR COMPARED (the
/// residual record's raw values), never from any derived claim.
pub fn divergence_magnitude(
    axis: &str,
    raw_reference: &str,
    raw_candidate: &str,
) -> Option<String> {
    match axis {
        "exit" => {
            let a = raw_reference.trim().parse::<i64>().ok()?;
            let b = raw_candidate.trim().parse::<i64>().ok()?;
            Some((a - b).abs().to_string())
        }
        "stderr" | "stdout" | "structured.state" => Some(
            edit_distance(
                &truncate(raw_reference, MAGNITUDE_BOUND),
                &truncate(raw_candidate, MAGNITUDE_BOUND),
            )
            .to_string(),
        ),
        _ => None,
    }
}

fn truncate(s: &str, bound: usize) -> String {
    if s.len() <= bound {
        s.to_string()
    } else {
        s[..bound].to_string()
    }
}

/// The Levenshtein (byte edit) distance between two strings — deterministic,
/// declared as the line/value distance measure of the text-family
/// comparators. The inputs are already bounded by the caller.
pub fn edit_distance(a: &str, b: &str) -> usize {
    if a == b {
        return 0;
    }
    let a: Vec<u8> = a.as_bytes().to_vec();
    let b: Vec<u8> = b.as_bytes().to_vec();
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

/// The specification hash: SHA-256 of `FRF/COMPARATOR-SPEC/v2` over the
/// The comparator specification hash — the SEMANTIC identity of a relation.
/// v2: `relation_version` enters the specification document itself (the one
/// rule: a relation's version is part of its semantic identity, in every
/// protocol), so the same id/relation/extractor/classifier under two
/// versions are two relations. One formula shared by the in-binary registry
/// and external declarations — and by the receipt-side semantic validator,
/// so a recorded `specification_hash` REDERIVES from its own fields.
pub fn specification_hash(
    id: &str,
    relation: &str,
    extractor: &str,
    residual_classifier: &str,
    relation_version: &str,
) -> Result<String> {
    let doc = json!({
        "id": id,
        "relation": relation,
        "extractor": extractor,
        "residual_classifier": residual_classifier,
        "relation_version": relation_version,
    });
    crate::semantics::hash_preimage("FRF/COMPARATOR-SPEC/v2", &doc)
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
        COMPARATOR_VERSION,
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
        &decl.relation_version,
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

/// What a comparator concluded about one axis. The SAME outcome type serves
/// the built-ins and the external protocol: the one evaluation relation is
/// true all the way down, not only at the dispatcher layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComparatorOutcome {
    /// The axes' projections agree; no residual on this axis.
    Equivalent,
    /// The divergences, as `(surface, raw_reference, raw_candidate)` triples
    /// the court preserves verbatim.
    Divergent(Vec<(Option<String>, String, String)>),
    /// The comparison cannot be decided on the evidence (e.g. a relation
    /// whose extractor requires structured input received unparsable input
    /// on BOTH sides). Inconclusive evidence is refused, never recorded as
    /// conclusive.
    Indeterminate,
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

/// The in-binary comparator implementations, as strongly typed helpers.
/// The evidence core never matches on these directly — the registry keys the
/// comparison on the observable id — but the built-in extractors live here,
/// next to their registry rows. Six built-ins: the three Section-12 CLI
/// surfaces (exit, stderr, stdout) and three domain-general surfaces
/// (filesystem.tree over PRODUCED ARTIFACTS, bytes.wire over the raw stdout
/// stream, structured.state over stdout JSON).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuiltinKind {
    Exit,
    Stderr,
    Stdout,
    /// The filesystem-tree surface: compares the sides' PRODUCED ARTIFACT
    /// trees (the `produce` clause) file by file. A court declaring this
    /// axis MUST declare `produce`.
    Tree,
    /// The byte/wire surface: compares the sides' raw stdout streams
    /// byte-exactly (base64 projections — lossy text decoding would miss a
    /// divergence between two byte sequences that decode to the same text).
    Bytes,
    /// The structured-state surface: parses both sides' stdout as JSON and
    /// compares field by field (residual per differing field, surfaced by
    /// its JSON pointer).
    Json,
}

impl BuiltinKind {
    /// The built-in implementation serving `id`, if any.
    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "exit" => Some(BuiltinKind::Exit),
            "stderr" => Some(BuiltinKind::Stderr),
            "stdout" => Some(BuiltinKind::Stdout),
            "filesystem.tree" => Some(BuiltinKind::Tree),
            "bytes.wire" => Some(BuiltinKind::Bytes),
            "structured.state" => Some(BuiltinKind::Json),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            BuiltinKind::Exit => "exit",
            BuiltinKind::Stderr => "stderr",
            BuiltinKind::Stdout => "stdout",
            BuiltinKind::Tree => "filesystem.tree",
            BuiltinKind::Bytes => "bytes.wire",
            BuiltinKind::Json => "structured.state",
        }
    }

    /// The residual surface this built-in names its divergence with.
    pub fn surface(self) -> Option<&'static str> {
        match self {
            BuiltinKind::Exit => None,
            BuiltinKind::Stderr => Some("first-diagnostic-line"),
            BuiltinKind::Stdout => Some("first-stdout-line"),
            BuiltinKind::Tree | BuiltinKind::Bytes | BuiltinKind::Json => None,
        }
    }

    /// The raw projection this built-in extracts from one side (the
    /// single-surface built-ins only; the domain comparators dispatch in
    /// [`BuiltinKind::compare`]).
    pub fn project(self, side: &SideCapture) -> String {
        match self {
            BuiltinKind::Exit => side.exit.clone(),
            BuiltinKind::Stderr => side.stderr_first_line.clone(),
            BuiltinKind::Stdout => side.stdout_first_line.clone(),
            BuiltinKind::Bytes | BuiltinKind::Json | BuiltinKind::Tree => {
                unreachable!("domain comparators dispatch in compare()")
            }
        }
    }

    /// Compare two sides, returning the SAME outcome type the external
    /// protocol uses. The single-surface built-ins (exit, stderr, stdout,
    /// bytes) yield at most one divergence; the domain comparators
    /// (filesystem.tree, structured.state) yield one per differing file or
    /// field. An `Err` is a refusal (the comparison cannot be evaluated);
    /// `Indeterminate` is an honest "cannot decide on this evidence".
    pub fn compare(
        self,
        reference: &SideCapture,
        candidate: &SideCapture,
    ) -> Result<ComparatorOutcome> {
        let divergences = match self {
            BuiltinKind::Tree => {
                // One residual per differing produced FILE: the surface is
                // the relative path, the raw projections are the content
                // hashes (or `<absent>` when the file exists on one side
                // only). A file present on both sides with identical content
                // but a different EXECUTABLE FLAG is a mode divergence with
                // its own surface (`path:<path>#executable`) — an artifact
                // that is not executable is operationally different even when
                // its bytes match. No produced observation on either side is
                // an empty tree: both produced nothing, and nothing diverges.
                let ref_files = reference
                    .produced
                    .as_ref()
                    .map(|p| p.files.as_slice())
                    .unwrap_or(&[]);
                let cand_files = candidate
                    .produced
                    .as_ref()
                    .map(|p| p.files.as_slice())
                    .unwrap_or(&[]);
                let mut out = Vec::new();
                let mut i = 0;
                let mut j = 0;
                while i < ref_files.len() || j < cand_files.len() {
                    let ref_f = ref_files.get(i);
                    let cand_f = cand_files.get(j);
                    let (path, ref_sha, cand_sha, ref_exec, cand_exec) = match (ref_f, cand_f) {
                        (Some(r), Some(c)) if r.path == c.path => {
                            i += 1;
                            j += 1;
                            (
                                r.path.clone(),
                                r.sha256.clone(),
                                c.sha256.clone(),
                                r.executable,
                                c.executable,
                            )
                        }
                        (Some(r), Some(c)) if r.path < c.path => {
                            i += 1;
                            (
                                r.path.clone(),
                                r.sha256.clone(),
                                "<absent>".to_string(),
                                r.executable,
                                false,
                            )
                        }
                        (Some(r), _) => {
                            i += 1;
                            (
                                r.path.clone(),
                                r.sha256.clone(),
                                "<absent>".to_string(),
                                r.executable,
                                false,
                            )
                        }
                        (_, Some(c)) => {
                            j += 1;
                            (
                                c.path.clone(),
                                "<absent>".to_string(),
                                c.sha256.clone(),
                                false,
                                c.executable,
                            )
                        }
                        (None, None) => break,
                    };
                    if ref_sha != cand_sha {
                        out.push((
                            Some(format!("path:{path}")),
                            ref_sha.clone(),
                            cand_sha.clone(),
                        ));
                    }
                    if ref_exec != cand_exec {
                        // A mode divergence: its own surface, raw values the
                        // flags themselves. EMITTED EVEN when the bytes also
                        // differ — a file with different contents AND a
                        // different executable state is two observable facts,
                        // and two residuals. Trajectories must be able to
                        // watch a content divergence vanish while a mode
                        // divergence persists.
                        out.push((
                            Some(format!("path:{path}#executable")),
                            ref_exec.to_string(),
                            cand_exec.to_string(),
                        ));
                    }
                }
                out
            }
            BuiltinKind::Json => {
                // Parse both sides' stdout as JSON; one residual per
                // differing field (surface = the JSON pointer), or a single
                // parse residual when ONE side is not valid JSON (a side that
                // fails the extractor is a divergence on the structured
                // surface). When BOTH sides fail parsing, the relation
                // cannot decide — the two invalid documents are not evidence
                // of equivalence, and recording them as equal would license a
                // false pass — so the outcome is INDETERMINATE (refused).
                let ref_text = String::from_utf8_lossy(reference.stdout()).into_owned();
                let cand_text = String::from_utf8_lossy(candidate.stdout()).into_owned();
                let ref_val = serde_json::from_str::<serde_json::Value>(&ref_text);
                let cand_val = serde_json::from_str::<serde_json::Value>(&cand_text);
                match (ref_val, cand_val) {
                    (Ok(r), Ok(c)) if r == c => vec![],
                    (Ok(r), Ok(c)) => {
                        let mut out = Vec::new();
                        diff_json(&mut out, "$", &r, &c);
                        out
                    }
                    (Err(_), Err(_)) => {
                        return Ok(ComparatorOutcome::Indeterminate);
                    }
                    (Err(_), Ok(_)) => {
                        vec![(Some("json-parse".to_string()), ref_text, cand_text)]
                    }
                    (Ok(_), Err(_)) => {
                        vec![(Some("json-parse".to_string()), ref_text, cand_text)]
                    }
                }
            }
            // The byte/wire surface: the raw stdout stream, compared by
            // content identity (the stream hash IS the byte-identity — no
            // lossy decoding can miss a divergence).
            BuiltinKind::Bytes => {
                let raw_ref = reference.stdout_sha256.clone();
                let raw_cand = candidate.stdout_sha256.clone();
                if raw_ref != raw_cand {
                    vec![(None, raw_ref, raw_cand)]
                } else {
                    vec![]
                }
            }
            other => {
                let raw_ref = other.project(reference);
                let raw_cand = other.project(candidate);
                if raw_ref != raw_cand {
                    vec![(other.surface().map(str::to_string), raw_ref, raw_cand)]
                } else {
                    vec![]
                }
            }
        };
        Ok(if divergences.is_empty() {
            ComparatorOutcome::Equivalent
        } else {
            ComparatorOutcome::Divergent(divergences)
        })
    }
}

/// Field-level JSON diff: one `(surface, raw_ref, raw_cand)` per differing
/// leaf, surfaced by JSON pointer (`$.a.b[2]`).
fn diff_json(
    out: &mut Vec<(Option<String>, String, String)>,
    pointer: &str,
    reference: &serde_json::Value,
    candidate: &serde_json::Value,
) {
    match (reference, candidate) {
        (serde_json::Value::Object(r), serde_json::Value::Object(c)) => {
            let mut keys: Vec<&String> = r.keys().chain(c.keys()).collect();
            keys.sort();
            keys.dedup();
            for k in keys {
                let sub = format!("{pointer}.{k}");
                match (r.get(k), c.get(k)) {
                    (Some(rv), Some(cv)) => diff_json(out, &sub, rv, cv),
                    (Some(rv), None) => out.push((
                        Some(sub.clone()),
                        serde_json::to_string(rv).unwrap_or_default(),
                        "<absent>".to_string(),
                    )),
                    (None, Some(cv)) => out.push((
                        Some(sub.clone()),
                        "<absent>".to_string(),
                        serde_json::to_string(cv).unwrap_or_default(),
                    )),
                    (None, None) => {}
                }
            }
        }
        (serde_json::Value::Array(r), serde_json::Value::Array(c)) => {
            let n = r.len().max(c.len());
            for i in 0..n {
                let sub = format!("{pointer}[{i}]");
                match (r.get(i), c.get(i)) {
                    (Some(rv), Some(cv)) => diff_json(out, &sub, rv, cv),
                    (Some(rv), None) => out.push((
                        Some(sub.clone()),
                        serde_json::to_string(rv).unwrap_or_default(),
                        "<absent>".to_string(),
                    )),
                    (None, Some(cv)) => out.push((
                        Some(sub.clone()),
                        "<absent>".to_string(),
                        serde_json::to_string(cv).unwrap_or_default(),
                    )),
                    (None, None) => {}
                }
            }
        }
        (r, c) if r == c => {}
        (r, c) => out.push((
            Some(pointer.to_string()),
            serde_json::to_string(r).unwrap_or_default(),
            serde_json::to_string(c).unwrap_or_default(),
        )),
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
///
/// `reference`/`candidate` are the streams the request carries. For a
/// non-adapted external axis these are the COMPARED streams (normalized, when
/// normalizers applied); for an adapted axis the comparison is over the
/// adapted payloads and the streams are the truly raw ones (the adapter's
/// input evidence). The adapted observations (when an adapter serves the
/// axis) travel alongside.
#[allow(clippy::too_many_arguments)] // one argument per request dimension; the doc is the protocol shape
pub fn build_request<'a>(
    axis: &'a str,
    semantic: &'a ComparatorSemantic,
    reference: &'a ProcessOutcome,
    candidate: &'a ProcessOutcome,
    reference_adapted: Option<&'a crate::model::AdaptedObservation>,
    candidate_adapted: Option<&'a crate::model::AdaptedObservation>,
    fixture_sha256: &'a str,
    arguments: &'a [String],
    environment_digest: &'a str,
    produced: Option<(
        &'a crate::model::ProducedSide,
        &'a crate::model::ProducedSide,
    )>,
) -> crate::model::ComparatorRequest<'a> {
    crate::model::ComparatorRequest {
        schema_version: crate::model::SCHEMA_COMPARATOR_REQUEST,
        comparator: semantic,
        axis,
        reference: crate::model::ComparatorObservation {
            exit: &reference.exit,
            stdout_base64: b64(&reference.stdout),
            stderr_base64: b64(&reference.stderr),
            adapted: reference_adapted,
        },
        candidate: crate::model::ComparatorObservation {
            exit: &candidate.exit,
            stdout_base64: b64(&candidate.stdout),
            stderr_base64: b64(&candidate.stderr),
            adapted: candidate_adapted,
        },
        context: crate::model::ComparatorContext {
            fixture_sha256,
            arguments,
            environment_digest,
            produced: produced.map(|(r, c)| crate::model::ProducedContext {
                reference: crate::model::ProducedSideContext {
                    manifest_sha256: &r.manifest_sha256,
                    files: &r.files,
                },
                candidate: crate::model::ProducedSideContext {
                    manifest_sha256: &c.manifest_sha256,
                    files: &c.files,
                },
            }),
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
    image: &host::ExecImage,
    axis: &ObservableId,
    request_bytes: &[u8],
    request_cid: &str,
    cwd: &Path,
    profile: host::ExecProfile,
) -> Result<(ComparatorOutcome, Vec<u8>)> {
    let out = host::run_process_with_stdin_in(image, &[], request_bytes, cwd, profile)?;
    if out.exit != "0" {
        return Err(FrfError::new(format!(
            "comparator for axis {} exited {}; refusing to record evidence from a failed comparator",
            axis.as_str(),
            out.exit
        )));
    }
    // The protocol says canonical JSON: the response must BE its own
    // canonical serialization (one semantic response, one evidence identity).
    crate::ext::require_canonical_response(&out.stdout, "comparator response")?;
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
/// Materialize an extension implementation artifact and SEAL it into an
/// executable image: the exact verified bytes (verify→execute race closed)
/// with the materialized object path as argv[0].
pub fn materialize_implementation(
    store: &Store,
    artifact: &ArtifactIdentity,
) -> Result<host::ExecImage> {
    let bytes = store.verified_object_bytes(&artifact.sha256)?;
    let path = store.materialize_object(&bytes, true)?;
    host::ExecImage::seal(&bytes, &artifact.sha256, &path)
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

// ---------------------------------------------------------------------------
// The ONE evaluation operation
// ---------------------------------------------------------------------------

/// The full specification of how one observable axis is evaluated: the
/// SEMANTIC identity (what the relation is) plus the IMPLEMENTATION identity
/// (who runs it). Every evidence operation that decides parity — court run,
/// replay, resolution, minimization — derives its plan from the SAME
/// capture-bound fields and evaluates through [`evaluate`]. Nothing outside
/// [`evaluate`] may decide whether an axis differs.
#[derive(Debug, Clone)]
pub struct EvaluationPlan {
    pub axis: ObservableId,
    pub semantic: ComparatorSemantic,
    pub implementation: ComparatorImplementation,
}

impl EvaluationPlan {
    /// The plan that observed a run, for one declared axis: derived from the
    /// capture's bound comparator semantics + implementations — the same
    /// fields court, replay, resolution, and minimization all consume.
    pub fn from_capture(capture: &CaptureManifest, axis: &ObservableId) -> Result<EvaluationPlan> {
        let semantic = capture
            .comparator_semantics
            .iter()
            .find(|s| s.id == axis.as_str())
            .cloned()
            .ok_or_else(|| {
                FrfError::new(format!(
                    "the capture carries no comparator semantic for axis {}",
                    axis.as_str()
                ))
            })?;
        let implementation = capture
            .provenance
            .comparator_implementations
            .iter()
            .find(|i| i.id == axis.as_str())
            .cloned()
            .ok_or_else(|| {
                FrfError::new(format!(
                    "the capture carries no comparator implementation for axis {}",
                    axis.as_str()
                ))
            })?;
        Ok(EvaluationPlan {
            axis: axis.clone(),
            semantic,
            implementation,
        })
    }
}

/// The observation context a comparison is made under: everything outside
/// the two sides' observations that the comparison may need.
#[derive(Debug, Clone)]
pub struct EvaluationContext<'a> {
    pub fixture_sha256: &'a str,
    pub arguments: &'a [String],
    pub environment_digest: &'a str,
    /// The sides' produced trees (the filesystem.tree surface), when the
    /// court declares `produce`.
    pub produced: Option<(&'a ProducedSide, &'a ProducedSide)>,
    /// The working directory external programs run from.
    pub cwd: &'a Path,
    /// The truly RAW streams (before normalization), for externally evaluated
    /// axes: present when the caller holds the ProcessOutcomes (court run,
    /// replay, minimization). For an ADAPTED axis the external request
    /// carries these raw bytes (the adapter's input evidence) plus the
    /// adapted payloads.
    pub raw: Option<(&'a ProcessOutcome, &'a ProcessOutcome)>,
    /// The COMPARED streams (after the declared normalizers applied), for
    /// externally evaluated NON-adapted axes: the comparison surface. Falls
    /// back to `raw` when absent (a court with no normalizers compares the
    /// raw streams).
    pub compared: Option<(&'a ProcessOutcome, &'a ProcessOutcome)>,
    /// The execution profile the comparison runs under: an externally served
    /// axis's instrument runs under the SAME declared harness contract as
    /// the sides (the per-side cgroup v2 envelope for `frf-exec-linux-v2`).
    pub profile: crate::host::ExecProfile,
}

/// The verdict of evaluating one axis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvaluationResult {
    /// No divergence on this axis.
    Pass,
    /// Every divergence, as `(surface, raw_reference, raw_candidate)` — an
    /// external comparator may name several.
    Divergent(Vec<(Option<String>, String, String)>),
}

/// The instrument evidence of one evaluation: present when the axis was
/// evaluated by an EXTERNAL program — the canonical request the instrument
/// received and the canonical response it returned, both content-addressed
/// and preserved under the run (an invocation is itself evidence).
#[derive(Debug, Clone)]
pub struct EvaluationEvidence {
    pub request_bytes: Vec<u8>,
    pub request_cid: String,
    pub response_bytes: Vec<u8>,
    pub response_cid: String,
}

/// One evaluation: the verdict plus the instrument evidence (when the axis
/// was externally served).
#[derive(Debug, Clone)]
pub struct Evaluation {
    pub result: EvaluationResult,
    pub evidence: Option<EvaluationEvidence>,
}

/// THE one comparison operation. Everything that decides "does this axis
/// differ?" — court run, replay, resolution, minimization — goes through
/// this function; nothing outside it may decide parity.
///
/// - a BUILT-IN implementation (the capture's implementation identity is the
///   runner's own hash, no artifact) is evaluated in-process: the registry
///   row's extractor projection, or the domain comparator's per-file /
///   per-field divergences;
/// - an EXTERNAL implementation (the capture binds its artifact identity) is
///   RE-INVOKED through the extension protocol: the request is built from
///   the raw streams, the snapshotted program is re-hashed and re-sealed
///   before use, and its response is interpreted fail-closed (it must name
///   the request it answers).
///
/// Callers that hold ProcessOutcomes pass them in `context.raw` so an
/// externally served axis receives the identical request bytes (and
/// therefore the identical request_cid) it received at observation time.
pub fn evaluate(
    store: &Store,
    plan: &EvaluationPlan,
    reference: &SideCapture,
    candidate: &SideCapture,
    context: &EvaluationContext,
) -> Result<Evaluation> {
    match &plan.implementation.artifact {
        None => {
            // The in-binary implementation of this spec — the SAME outcome
            // type the external protocol uses: the one evaluation relation is
            // true all the way down.
            let builtin = BuiltinKind::from_id(plan.axis.as_str()).ok_or_else(|| {
                FrfError::new(format!(
                    "the {} axis was served by no known in-binary comparator",
                    plan.axis.as_str()
                ))
            })?;
            let outcome = builtin.compare(reference, candidate)?;
            Ok(Evaluation {
                result: match outcome {
                    ComparatorOutcome::Equivalent => EvaluationResult::Pass,
                    ComparatorOutcome::Divergent(v) => EvaluationResult::Divergent(v),
                    ComparatorOutcome::Indeterminate => {
                        return Err(FrfError::new(format!(
                            "the {} axis is indeterminate: the comparison cannot be decided on this evidence; refusing to record inconclusive evidence as conclusive",
                            plan.axis.as_str()
                        )));
                    }
                },
                evidence: None,
            })
        }
        Some(artifact) => {
            // Re-invoke the exact snapshotted implementation. The streams the
            // request carries must be available: an adapted axis carries the
            // truly raw streams (the adapter's input evidence) plus the
            // adapted payloads; a non-adapted axis carries the COMPARED
            // streams (normalized, when normalizers applied) — the surface
            // the comparator is the meaning of.
            let (reference_out, candidate_out) = if reference.adapted.is_some() {
                context.raw
            } else {
                context.compared.or(context.raw)
            }
            .ok_or_else(|| {
                FrfError::new(format!(
                    "the {} axis is externally served; evaluating it requires the side streams (context.raw/compared) — a recorded result is only valid for verification without execution",
                    plan.axis.as_str()
                ))
            })?;
            let snapshot = materialize_implementation(store, artifact)?;
            let request = build_request(
                plan.axis.as_str(),
                &plan.semantic,
                reference_out,
                candidate_out,
                reference.adapted.as_ref(),
                candidate.adapted.as_ref(),
                context.fixture_sha256,
                context.arguments,
                context.environment_digest,
                context.produced,
            );
            let (request_bytes, request_cid) = canonical_request(&request)?;
            let (outcome, response_bytes) = run_external(
                &snapshot,
                &plan.axis,
                &request_bytes,
                &request_cid,
                context.cwd,
                context.profile,
            )?;
            let response_cid = host::sha256_bytes(&response_bytes);
            let result = match outcome {
                ComparatorOutcome::Equivalent => EvaluationResult::Pass,
                ComparatorOutcome::Divergent(v) => EvaluationResult::Divergent(v),
                // `interpret` refuses indeterminate responses, so this arm is
                // unreachable for an external comparator — kept for the
                // exhaustive match.
                ComparatorOutcome::Indeterminate => {
                    return Err(FrfError::new(format!(
                        "the {} axis is indeterminate: the comparison cannot be decided on this evidence; refusing to record inconclusive evidence as conclusive",
                        plan.axis.as_str()
                    )));
                }
            };
            Ok(Evaluation {
                result,
                evidence: Some(EvaluationEvidence {
                    request_bytes,
                    request_cid,
                    response_bytes,
                    response_cid,
                }),
            })
        }
    }
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
    use crate::model::{ComparatorDeclaration, ComparatorResidual, ProducedFile};

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
        let expected =
            specification_hash("exit", "eq", "exit-code", "exit", COMPARATOR_VERSION).unwrap();
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
            produced: None,
            adapted: None,
            stdout_bytes: vec![],
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
            produced: None,
            adapted: None,
            stdout_bytes: vec![],
        };
        let divergences = BuiltinKind::Exit.compare(&reference, &candidate).unwrap();
        assert_eq!(
            divergences,
            ComparatorOutcome::Divergent(vec![(None, "2".to_string(), "1".to_string())])
        );
        let divergences = BuiltinKind::Stderr.compare(&reference, &candidate).unwrap();
        assert_eq!(
            divergences,
            ComparatorOutcome::Divergent(vec![(
                Some("first-diagnostic-line".to_string()),
                "ref diag".to_string(),
                "cand diag".to_string()
            )])
        );
        let divergences = BuiltinKind::Stdout.compare(&reference, &candidate).unwrap();
        assert_eq!(divergences, ComparatorOutcome::Equivalent);
    }

    /// The filesystem.tree false-pass fix: a file present on both sides with
    /// identical bytes but a different EXECUTABLE FLAG is a mode divergence
    /// with its own surface — an artifact that is not executable is
    /// operationally different even when its content hashes match.
    #[test]
    fn tree_diverges_on_the_executable_flag_alone() {
        let side = |executable: bool| SideCapture {
            exit: "0".into(),
            exit_sha256: "a".repeat(64),
            stderr_first_line: String::new(),
            stderr_first_line_sha256: "b".repeat(64),
            stdout_first_line: String::new(),
            stdout_first_line_sha256: "c".repeat(64),
            stdout_sha256: "d".repeat(64),
            stderr_sha256: "e".repeat(64),
            produced: Some(ProducedSide {
                schema_version: crate::model::SCHEMA_PRODUCED.into(),
                manifest_sha256: "f".repeat(64),
                files: vec![ProducedFile {
                    path: "bin/tool".into(),
                    sha256: "abc".repeat(21) + "def", // 64 hex, identical on both sides
                    executable,
                }],
            }),
            adapted: None,
            stdout_bytes: vec![],
        };
        let reference = side(true);
        let candidate = side(false);
        let outcome = BuiltinKind::Tree.compare(&reference, &candidate).unwrap();
        assert_eq!(
            outcome,
            ComparatorOutcome::Divergent(vec![(
                Some("path:bin/tool#executable".to_string()),
                "true".to_string(),
                "false".to_string()
            )])
        );
        // Identical bytes AND identical flags: still equivalent.
        let both = side(true);
        assert_eq!(
            BuiltinKind::Tree.compare(&both, &both).unwrap(),
            ComparatorOutcome::Equivalent
        );
    }

    /// The structured.state false-pass fix: two unparsable documents are NOT
    /// evidence of equivalence. Both sides failing the extractor is
    /// INDETERMINATE (refused — inconclusive evidence must never record as
    /// conclusive); one side failing is a parse divergence on the structured
    /// surface.
    #[test]
    fn json_comparator_is_fail_closed_on_unparsable_input() {
        let side = |stdout: &str| SideCapture {
            exit: "0".into(),
            exit_sha256: "a".repeat(64),
            stderr_first_line: String::new(),
            stderr_first_line_sha256: "b".repeat(64),
            stdout_first_line: stdout.to_string(),
            stdout_first_line_sha256: "c".repeat(64),
            stdout_sha256: "d".repeat(64),
            stderr_sha256: "e".repeat(64),
            produced: None,
            adapted: None,
            stdout_bytes: stdout.as_bytes().to_vec(),
        };
        // Both sides invalid: indeterminate — the two broken documents do
        // not license equivalence.
        assert_eq!(
            BuiltinKind::Json
                .compare(
                    &side("{ this is broken A"),
                    &side("THIS IS DIFFERENT BROKEN")
                )
                .unwrap(),
            ComparatorOutcome::Indeterminate
        );
        // One side invalid: a parse divergence on the structured surface.
        let outcome = BuiltinKind::Json
            .compare(&side("{\"a\":1}"), &side("not json at all"))
            .unwrap();
        assert!(matches!(
            outcome,
            ComparatorOutcome::Divergent(ref v) if v.len() == 1
        ));
        // Both valid but differing: a field-pointer divergence.
        let outcome = BuiltinKind::Json
            .compare(
                &side("{\"config\":{\"timeout\":5},\"status\":\"ok\"}"),
                &side("{\"config\":{\"timeout\":9},\"status\":\"ok\"}"),
            )
            .unwrap();
        match outcome {
            ComparatorOutcome::Divergent(ref v) => {
                assert_eq!(v[0].0.as_deref(), Some("$.config.timeout"));
            }
            _ => panic!("expected a field divergence"),
        }
    }
}
