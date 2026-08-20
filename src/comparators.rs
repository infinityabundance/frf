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
use crate::model::{ComparatorSemantic, COMPARATOR_VERSION};
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
