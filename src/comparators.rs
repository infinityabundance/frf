//! Comparator registry — the seed of the observable/plugin architecture.
//!
//! Each observable axis is served by a comparator RELATION. What a relation
//! *is* is captured as a canonical specification document — id, relation
//! family, and extractor — and its SHA-256 becomes the comparator's
//! `specification_hash`. That hash is what enters the court's semantic
//! identity: two independent FRF implementations that implement the same
//! specification ask the same question, even though their executable bytes
//! differ.
//!
//! What *implemented* the relation (this executable, or later an external
//! comparator program) is a separate fact, recorded in the capture's
//! observation provenance. The reviewer's distinction, implemented: the
//! question never depends on the implementation; the provenance always
//! records it.
//!
//! Adding an axis = adding a row here (plus the extractor + classifier the
//! court command applies). The semantic identity then changes only if the
//! SPEC changes — which is exactly when it should.

use crate::error::Result;
use crate::model::{
    ComparatorDeclaration, ComparatorResponse, ComparatorSemantic, COMPARATOR_VERSION,
};
use serde_json::json;

/// The canonical specification of a comparator relation.
pub struct ComparatorSpec {
    /// Observable axis id (matches `Axis::as_str`).
    pub id: &'static str,
    /// Relation family (Section 10, Δ_a).
    pub relation: &'static str,
    /// What the comparator extracts and compares.
    pub extractor: &'static str,
}

pub const SPECS: &[ComparatorSpec] = &[
    ComparatorSpec {
        id: "exit",
        relation: "eq",
        extractor: "exit-code",
    },
    ComparatorSpec {
        id: "stderr",
        relation: "eq",
        extractor: "stderr-first-line",
    },
    ComparatorSpec {
        id: "stdout",
        relation: "eq",
        extractor: "stdout-first-line",
    },
];

/// The semantic identity of the comparator serving `id`, or `None` when the
/// axis has no registered comparator (the court refuses earlier).
pub fn semantic(id: &str) -> Result<ComparatorSemantic> {
    let spec = SPECS.iter().find(|s| s.id == id).ok_or_else(|| {
        crate::error::FrfError::new(format!("no comparator registered for axis '{id}'"))
    })?;
    let doc = json!({
        "id": spec.id,
        "relation": spec.relation,
        "extractor": spec.extractor,
    });
    let specification_hash = crate::semantics::hash_preimage("FRF/COMPARATOR-SPEC/v1", &doc)?;
    Ok(ComparatorSemantic {
        id: spec.id.to_string(),
        relation_id: spec.relation.to_string(),
        relation_version: COMPARATOR_VERSION.to_string(),
        specification_hash,
    })
}

/// The semantic identity of an EXTERNAL comparator declared in a court
/// manifest. Same formula as [`semantic`]: a declaration with the same
/// relation/extractor/version as a built-in produces the SAME specification
/// hash — the external program serves the same question; only the
/// implementation differs (recorded in the capture's provenance).
pub fn declared_semantic(decl: &ComparatorDeclaration) -> Result<ComparatorSemantic> {
    let doc = json!({
        "id": decl.axis,
        "relation": decl.relation,
        "extractor": decl.extractor,
    });
    let specification_hash = crate::semantics::hash_preimage("FRF/COMPARATOR-SPEC/v1", &doc)?;
    Ok(ComparatorSemantic {
        id: decl.axis.clone(),
        relation_id: decl.relation.clone(),
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
/// - `indeterminate` → refusal (inconclusive evidence must not be recorded);
/// - `failure` → refusal;
/// - `equivalent` with residuals, or `divergent` without residuals → refusal
///   (the response contradicts itself);
/// - a divergent response whose raw values are equal → refusal (a divergence
///   must diverge).
pub fn interpret(response: &ComparatorResponse) -> Result<ComparatorOutcome> {
    if response.schema_version != crate::model::SCHEMA_COMPARATOR_RESPONSE {
        return Err(crate::error::FrfError::new(format!(
            "comparator response has unsupported schema version {:?} (expected {})",
            response.schema_version,
            crate::model::SCHEMA_COMPARATOR_RESPONSE
        )));
    }
    if response.indeterminate {
        return Err(crate::error::FrfError::new(
            "comparator returned indeterminate: the axis cannot be evaluated; refusing to record inconclusive evidence as conclusive",
        ));
    }
    if let Some(f) = &response.failure {
        return Err(crate::error::FrfError::new(format!(
            "comparator reported failure: {f}"
        )));
    }
    if response.equivalent {
        if !response.residuals.is_empty() {
            return Err(crate::error::FrfError::new(
                "comparator response contradicts itself: equivalent with residuals",
            ));
        }
        return Ok(ComparatorOutcome::Equivalent);
    }
    if response.residuals.is_empty() {
        return Err(crate::error::FrfError::new(
            "comparator response contradicts itself: divergent without naming a residual",
        ));
    }
    let mut out = Vec::with_capacity(response.residuals.len());
    for r in &response.residuals {
        if r.raw_reference == r.raw_candidate {
            return Err(crate::error::FrfError::new(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ComparatorResidual;

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
        let doc = json!({"id": "exit", "relation": "eq", "extractor": "exit-code"});
        let expected = crate::semantics::hash_preimage("FRF/COMPARATOR-SPEC/v1", &doc).unwrap();
        assert_eq!(a.specification_hash, expected);
    }

    #[test]
    fn unknown_axis_has_no_comparator() {
        assert!(semantic("wire").is_err());
    }

    #[test]
    fn a_declaration_with_the_builtin_spec_asks_the_same_question() {
        let decl = ComparatorDeclaration {
            axis: "stderr".into(),
            relation: "eq".into(),
            extractor: "stderr-first-line".into(),
            relation_version: COMPARATOR_VERSION.into(),
            program: "golden/comparators/stderr-first-line.py".into(),
        };
        // Same relation/extractor/version as the built-in registry row: the
        // external program serves the SAME question.
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
    }

    fn response(
        equivalent: bool,
        residuals: Vec<ComparatorResidual>,
        indeterminate: bool,
        failure: Option<&str>,
    ) -> ComparatorResponse {
        ComparatorResponse {
            schema_version: crate::model::SCHEMA_COMPARATOR_RESPONSE.into(),
            equivalent,
            residuals,
            indeterminate,
            failure: failure.map(str::to_string),
        }
    }

    #[test]
    fn interpret_accepts_equivalent_and_divergent() {
        assert_eq!(
            interpret(&response(true, vec![], false, None)).unwrap(),
            ComparatorOutcome::Equivalent
        );
        let out = interpret(&response(
            false,
            vec![ComparatorResidual {
                surface: Some("first-diagnostic-line".into()),
                raw_reference: "a".into(),
                raw_candidate: "b".into(),
            }],
            false,
            None,
        ))
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
        let divergent = || ComparatorResidual {
            surface: None,
            raw_reference: "a".into(),
            raw_candidate: "b".into(),
        };
        // indeterminate
        assert!(interpret(&response(false, vec![divergent()], true, None)).is_err());
        // failure
        assert!(interpret(&response(false, vec![divergent()], false, Some("boom"))).is_err());
        // equivalent with residuals
        assert!(interpret(&response(true, vec![divergent()], false, None)).is_err());
        // divergent without residuals
        assert!(interpret(&response(false, vec![], false, None)).is_err());
        // divergent residual whose raw values are equal
        assert!(interpret(&response(
            false,
            vec![ComparatorResidual {
                surface: None,
                raw_reference: "same".into(),
                raw_candidate: "same".into(),
            }],
            false,
            None
        ))
        .is_err());
        // wrong schema version
        let mut bad = response(true, vec![], false, None);
        bad.schema_version = "frf-comparator-response-v9".into();
        assert!(interpret(&bad).is_err());
    }
}
