//! Claim RENDERERS — pure presentations of the verified Claim IR.
//!
//! Prose is one renderer of the IR; `--json` emits the IR itself. These
//! renderers add SARIF 2.1.0 (static-analysis interchange), a CI status
//! document, and a badge — presentation only, never new epistemic meaning:
//! a claim is what it is because of its evidence; the renderer only says it
//! in another voice.
//!
//! The renderers accept ONLY a [`RenderView`] built from a [`ClaimVerified`]
//! (`frf claim render` resolves + verifies the claim first) — a hand-written
//! canonical file at `claims/<id>.json` is REFUSED, never rendered. The
//! prose (`positive`, `non_claims`) is NOT stored in the claim IR; the view
//! DERIVES it from the verified premise receipts, so a renderer can never
//! restate a sentence that the verified IR does not deterministically
//! produce.
//!
//! - SARIF: one `result` per positive sentence (level `none` — the claim is
//!   admissible by construction) and one per carried residual (level
//!   `error` for a blocker, `note` for excluded evidence), with the
//!   structured scope in `properties`.
//! - CI status: a compact machine-readable document a pipeline can gate on
//!   (`status: pass` means the claim compiled — the admission held under
//!   the declared policy and the committed knowledge universe).
//! - Badge: a deterministic shields-style SVG.

use crate::error::{FrfError, Result};
use crate::model::ClaimRecord;

/// The renderer's input: the verified claim plus the prose DERIVED from its
/// verified premises. Built by [`RenderView::from_verified`]; the renderers
/// are pure functions of it (no store access — the view is precomputed by
/// the verified loader's caller).
pub struct RenderView<'a> {
    pub claim: &'a ClaimRecord,
    /// The positive sentences, derived from the verified premise receipts
    /// (never read from the claim document).
    pub positive: Vec<String>,
    /// The non-claim sentences, derived from the premise fixture family.
    pub non_claims: Vec<String>,
}

impl<'a> RenderView<'a> {
    /// Derive the render view from a VERIFIED claim: prose is a deterministic
    /// function of the verified premises, not of anything stored in the
    /// claim document.
    pub fn from_verified(verified: &'a crate::verify::ClaimVerified) -> Result<RenderView<'a>> {
        let claim = verified.claim();
        let premises = verified.premises();
        let positive: Vec<String> = premises
            .iter()
            .filter_map(|p| crate::sentences::positive_claim(p.body()))
            .chain(crate::sentences::movement_claims(
                &claim.trajectory_premises,
                premises[0].body(),
            ))
            .collect();
        if positive.is_empty() {
            return Err(FrfError::new(format!(
                "claim {}: the verified premises derive no positive sentence — nothing to render",
                verified.id()
            )));
        }
        let family = &premises[0]
            .body()
            .court
            .admissibility_envelope
            .fixture_family;
        Ok(RenderView {
            claim,
            positive,
            non_claims: crate::sentences::non_claims(family),
        })
    }
}

/// The SARIF 2.1.0 document for a compiled claim.
pub fn sarif(view: &RenderView, driver_version: &str) -> Result<String> {
    let claim = view.claim;
    let mut results: Vec<serde_json::Value> = Vec::new();
    for sentence in &view.positive {
        results.push(serde_json::json!({
            "ruleId": "frf/claim",
            "level": "none",
            "message": { "text": sentence },
            "properties": {
                "proposition": claim.proposition,
                "policy": claim.policy,
                "observable_scope": claim.observable_scope,
                "fixture_family": claim.fixture_family,
                "authority": claim.authority,
                "candidate": claim.candidate.identity_hash,
                "requires": claim.requires,
                "replay_profile": claim.replay_profile,
                "witness_statements": claim.witness_statements,
                "independence_evidence": claim.independence_evidence,
            }
        }));
    }
    // The carried residuals: a blocker is an error (an unexplained
    // divergence on the claimed surface — the claim would not have compiled
    // with one, but the field is rendered honestly if present); excluded
    // evidence is a note (an observed divergence outside the claimed cells).
    for rid in &claim.blockers {
        results.push(serde_json::json!({
            "ruleId": "frf/residual",
            "level": "error",
            "message": { "text": format!("blocking residual {rid}") },
            "properties": { "residual_id": rid, "kind": "blocker" }
        }));
    }
    for rid in &claim.excluded_evidence {
        results.push(serde_json::json!({
            "ruleId": "frf/residual",
            "level": "note",
            "message": { "text": format!("excluded residual {rid}") },
            "properties": { "residual_id": rid, "kind": "excluded" }
        }));
    }
    let doc = serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "frf",
                    "version": driver_version,
                    "informationUri": "https://github.com/infinityabundance/frf",
                    "rules": [
                        {
                            "id": "frf/claim",
                            "name": "claim",
                            "shortDescription": {
                                "text": "A compiled FRF claim: parity of one candidate against one reference over a verified surface"
                            }
                        },
                        {
                            "id": "frf/residual",
                            "name": "residual",
                            "shortDescription": {
                                "text": "A preserved divergence observation the claim excludes or is blocked by"
                            }
                        }
                    ]
                }
            },
            "results": results,
            "columnKind": "unicodeCodePoints"
        }]
    });
    crate::canon::canonical(&doc)
}

/// The CI status document: the compact gate a pipeline can consume.
pub fn ci_status(view: &RenderView) -> Result<String> {
    let claim = view.claim;
    let doc = serde_json::json!({
        "schema_version": "frf-ci-status-v1",
        "status": if claim.blockers.is_empty() { "pass" } else { "fail" },
        "claim": claim.receipt,
        "policy": claim.policy,
        "proposition": claim.proposition,
        "observable_scope": claim.observable_scope,
        "requires": claim.requires,
        "positive": view.positive,
        "excluded_evidence": claim.excluded_evidence,
        "blockers": claim.blockers,
        "non_claims": view.non_claims,
    });
    crate::canon::canonical(&doc)
}

/// The badge: a deterministic shields-style SVG. `admissible` is green; a
/// blocked claim would be red; the message is the scope (short).
pub fn badge(view: &RenderView) -> Result<String> {
    let claim = view.claim;
    let scope = claim.observable_scope.join(",");
    let (status, color) = if claim.blockers.is_empty() {
        (format!("admissible · {scope}"), "#4c1")
    } else {
        (format!("blocked · {scope}"), "#e05d44")
    };
    let label = "frf claim";
    // Fixed, deterministic geometry (shields-style): label + value segments.
    let label_w = label.len() as u32 * 7 + 12;
    let value_w = status.len() as u32 * 7 + 12;
    let width = label_w + value_w;
    let svg = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{width}\" height=\"20\" role=\"img\" aria-label=\"frf claim: {status}\">\n\
  <rect width=\"{width}\" height=\"20\" fill=\"#555\"/>\n\
  <rect x=\"{label_w}\" width=\"{value_w}\" height=\"20\" fill=\"{color}\"/>\n\
  <g fill=\"#fff\" text-anchor=\"middle\" font-family=\"Verdana,Geneva,DejaVu Sans,sans-serif\" font-size=\"11\">\n\
    <text x=\"{}\" y=\"14\">{label}</text>\n\
    <text x=\"{}\" y=\"14\">{status}</text>\n\
  </g>\n\
</svg>\n",
        label_w / 2,
        label_w + value_w / 2,
    );
    Ok(svg)
}

/// Render a verified claim into the requested format. `prose` re-states the
/// derived sentences, `json` emits the IR canonically, `sarif` / `ci` /
/// `badge` are the presentations above.
pub fn render(view: &RenderView, format: &str, driver_version: &str) -> Result<String> {
    let claim = view.claim;
    match format {
        "prose" => {
            let mut out = view.positive.join("\n");
            if !view.non_claims.is_empty() {
                out.push('\n');
                out.push_str(&view.non_claims.join("\n"));
            }
            Ok(out)
        }
        "json" => crate::canon::canonical(claim),
        "sarif" => sarif(view, driver_version),
        "ci" => ci_status(view),
        "badge" => badge(view),
        other => Err(FrfError::new(format!(
            "unknown render format {other:?}: the claim renderer admits prose, json, sarif, ci, or badge"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;

    fn claim() -> ClaimRecord {
        let empty_region = EvidenceRegion::empty();
        ClaimRecord {
            id: "a".repeat(64),
            schema_version: SCHEMA_CLAIM.to_string(),
            receipt: "receipt-run-x-abc".to_string(),
            authority: "ref-cli-1.8.2".to_string(),
            candidate: ClaimCandidate {
                name: "cand-cli".to_string(),
                version_or_commit: "0.1.0".to_string(),
                identity_hash: "b".repeat(64),
            },
            court: "cli-malformed-input".to_string(),
            fixture_family: "malformed-input".to_string(),
            environment: "x86_64-linux (deadbeef)".to_string(),
            relation: "eq(exit-code)".to_string(),
            proposition: "parity(cells=[...])".to_string(),
            scope: empty_region,
            observable_scope: vec!["exit".to_string()],
            blockers: Vec::new(),
            excluded_evidence: vec!["cli-text-0001".to_string()],
            requires: vec!["receipt-run-x-abc".to_string()],
            trajectory_premises: Vec::new(),
            transform: EvidenceTransform::claim("receipt-run-x-abc", "parity"),
            knowledge_snapshot: KnowledgeSnapshot {
                schema_version: SCHEMA_CLAIM.to_string(),
                cid: "f".repeat(64),
                residual_heads: Vec::new(),
                objects: Vec::new(),
            },
            policy: "baseline".to_string(),
            mutation_profile: Vec::new(),
            capability: Vec::new(),
            witness_statements: Vec::new(),
            independence_evidence: Vec::new(),
            replay_profile: "frf-exec-linux-v1".to_string(),
            required_capabilities: Vec::new(),
        }
    }

    /// The render view: the claim plus the prose a verified loader would
    /// have derived from its premises (the renderers never read prose from
    /// the claim document).
    fn view(c: &ClaimRecord) -> RenderView<'_> {
        RenderView {
            claim: c,
            positive: vec!["For reference ref-cli-1.8.2, fixture family malformed-input, candidate cand 0.1.0 preserves exit class.".to_string()],
            non_claims: vec!["This receipt does not establish byte-identical stderr.".to_string()],
        }
    }

    #[test]
    fn sarif_is_a_well_formed_2_1_0_document() {
        let c = claim();
        let v = view(&c);
        let doc: serde_json::Value = serde_json::from_str(&sarif(&v, "0.1.39").unwrap()).unwrap();
        assert_eq!(doc["version"], "2.1.0");
        assert_eq!(doc["runs"][0]["tool"]["driver"]["name"], "frf");
        let results = doc["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2, "one claim result + one excluded residual");
        assert_eq!(results[0]["ruleId"], "frf/claim");
        assert_eq!(results[0]["level"], "none");
        assert_eq!(results[1]["ruleId"], "frf/residual");
        assert_eq!(results[1]["level"], "note");
        assert_eq!(
            results[0]["properties"]["observable_scope"],
            serde_json::json!(["exit"])
        );
        // Deterministic: a second render is byte-identical.
        assert_eq!(sarif(&v, "0.1.39").unwrap(), sarif(&v, "0.1.39").unwrap());
    }

    #[test]
    fn a_blocker_renders_as_an_error() {
        let mut c = claim();
        c.blockers.push("cli-exit-0001".to_string());
        let v = view(&c);
        let doc: serde_json::Value = serde_json::from_str(&sarif(&v, "0.1.39").unwrap()).unwrap();
        let results = doc["runs"][0]["results"].as_array().unwrap();
        let blocker = results
            .iter()
            .find(|r| r["ruleId"] == "frf/residual" && r["properties"]["kind"] == "blocker")
            .expect("blocker result");
        assert_eq!(blocker["level"], "error");
    }

    #[test]
    fn ci_status_gates_on_blockers() {
        let c = claim();
        let v = view(&c);
        let doc: serde_json::Value = serde_json::from_str(&ci_status(&v).unwrap()).unwrap();
        assert_eq!(doc["status"], "pass");
        assert_eq!(doc["schema_version"], "frf-ci-status-v1");
        assert_eq!(doc["observable_scope"], serde_json::json!(["exit"]));
        let mut blocked = claim();
        blocked.blockers.push("cli-exit-0001".to_string());
        let vb = view(&blocked);
        let doc: serde_json::Value = serde_json::from_str(&ci_status(&vb).unwrap()).unwrap();
        assert_eq!(doc["status"], "fail");
    }

    #[test]
    fn badge_is_deterministic_svg() {
        let c = claim();
        let v = view(&c);
        let svg = badge(&v).unwrap();
        assert!(svg.starts_with("<svg "));
        assert!(svg.contains("admissible"));
        assert!(svg.contains("#4c1"));
        assert_eq!(badge(&v).unwrap(), svg, "badge is deterministic");
        let mut blocked = claim();
        blocked.blockers.push("x".to_string());
        let vb = view(&blocked);
        assert!(badge(&vb).unwrap().contains("blocked"));
    }

    #[test]
    fn unknown_formats_are_refused() {
        let c = claim();
        let v = view(&c);
        assert!(render(&v, "html", "0.1.39").is_err());
    }
}
