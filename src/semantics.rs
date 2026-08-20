//! Identity discipline — every evidence identity in FRF.
//!
//! One rule for all identities: the preimage is a fixed domain tag followed
//! by canonical JSON (RFC 8785), and the identity is its SHA-256. No
//! delimiter-assembled strings (`|`, newlines) anywhere: a JSON document
//! cannot be ambiguous about field boundaries the way a concatenation can.
//!
//!   FRF/RUN/v1                 run identity (per court run)
//!   FRF/COURT/v1               court semantic identity (the question)
//!   FRF/COMPARATOR-SPEC/v1     comparator relation specification
//!   FRF/RESIDUAL-FINGERPRINT/v1  residual fingerprint
//!
//! The court semantic identity answers ONLY "what question was asked?":
//! question, falsifier, authority ARTIFACT identity, fixture identity,
//! arguments, the full envelope, and the comparator SEMANTIC identities
//! (specification hashes). Implementation provenance (which runner, which
//! comparator implementations) is bound separately in the capture — the
//! question never depends on the implementation, so two independent FRF
//! implementations can ask the same court question without pretending to be
//! the same implementation.

use crate::canon;
use crate::error::{FrfError, Result};
use crate::host;
use crate::model::*;
use serde_json::{json, Value};

/// The one identity primitive: SHA-256 of `FRF/<kind>` + newline + the
/// canonical JSON of `doc`.
pub fn hash_preimage(kind: &str, doc: &Value) -> Result<String> {
    let json = canon::canonical(doc)?;
    Ok(host::sha256_bytes(format!("{kind}\n{json}").as_bytes()))
}

/// The court semantic identity — the resolution-comparability key. Contents:
///
/// - question, falsifier
/// - the admitted authority ARTIFACT hash (bytes, not the id label)
/// - fixture id + bytes + declared arguments
/// - the full admissibility envelope
/// - comparator SEMANTIC identities (relation + specification hash)
///
/// Deliberately absent: the court id (a label), the candidate (the one
/// thing a fix court may change), the environment (checked separately by
/// the resolution predicate), and all implementation identity.
pub fn court_semantic_identity(
    spec: &CourtSpec,
    authority_sha256: &str,
    fixture_sha256: &str,
    comparator_semantics: &[ComparatorSemantic],
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
    )
    .and_then(|doc| hash_preimage("FRF/COURT/v1", &doc))
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
) -> Result<Value> {
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
    }))
}

/// Rederive the court semantic identity from an OpenReceipt document alone.
/// The receipt carries everything the question is made of: question,
/// falsifier, authority artifact hash, fixture id/hash/arguments, the
/// envelope, and the comparator semantics. The validator requires exactly one
/// fixture (v0 courts have one), so `fixtures[0]` is the fixture.
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
    )
    .and_then(|doc| hash_preimage("FRF/COURT/v1", &doc))
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
        r.kind,
        r.axis,
        r.surface.as_deref(),
        &r.raw_reference,
        &r.raw_candidate,
    )
}

/// The fingerprint of a divergence, computed directly from raw projections
/// (used by replay to re-derive what a fresh execution must reproduce).
pub fn fingerprint_from_projections(
    kind: ResidualKind,
    axis: Axis,
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
        }
    }

    fn semantics() -> Vec<ComparatorSemantic> {
        vec![crate::comparators::semantic("exit").unwrap()]
    }

    #[test]
    fn identity_is_deterministic_and_sensitive_to_the_question() {
        let a = court_semantic_identity(&spec("q"), &"1".repeat(64), &"2".repeat(64), &semantics())
            .unwrap();
        assert_eq!(
            a,
            court_semantic_identity(&spec("q"), &"1".repeat(64), &"2".repeat(64), &semantics())
                .unwrap()
        );
        // The candidate is NOT part of the question.
        let mut s2 = spec("q");
        s2.candidate.name = "something-else".into();
        assert_eq!(
            a,
            court_semantic_identity(&s2, &"1".repeat(64), &"2".repeat(64), &semantics()).unwrap()
        );
        // The court id is a label, not part of the question.
        let mut s3 = spec("q");
        s3.id = "renamed-court".into();
        assert_eq!(
            a,
            court_semantic_identity(&s3, &"1".repeat(64), &"2".repeat(64), &semantics()).unwrap()
        );
        // The question, the authority ARTIFACT bytes, the fixture bytes, and
        // the comparator semantics all move it.
        assert_ne!(
            a,
            court_semantic_identity(
                &spec("different"),
                &"1".repeat(64),
                &"2".repeat(64),
                &semantics()
            )
            .unwrap()
        );
        assert_ne!(
            a,
            court_semantic_identity(&spec("q"), &"9".repeat(64), &"2".repeat(64), &semantics())
                .unwrap()
        );
        assert_ne!(
            a,
            court_semantic_identity(&spec("q"), &"1".repeat(64), &"9".repeat(64), &semantics())
                .unwrap()
        );
        assert_ne!(
            a,
            court_semantic_identity(&spec("q"), &"1".repeat(64), &"2".repeat(64), &[]).unwrap()
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
            axis: Axis::Stderr,
            kind: ResidualKind::Text,
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
                digest: "0".repeat(64),
            },
            court_spec: spec,
            comparator_semantics: vec![],
            provenance: ObservationProvenance {
                schema_version: SCHEMA_PROVENANCE.into(),
                runner: RunnerIdentity {
                    schema_version: SCHEMA_RUNNER.into(),
                    frf_version: "0".into(),
                    frf_executable_hash: "0".repeat(64),
                },
                comparator_implementations: vec![],
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
            reference: SideCapture {
                exit: "0".into(),
                exit_sha256: "0".repeat(64),
                stderr_first_line: String::new(),
                stderr_first_line_sha256: "0".repeat(64),
                stdout_first_line: String::new(),
                stdout_first_line_sha256: "0".repeat(64),
                stdout_sha256: "0".repeat(64),
                stderr_sha256: "0".repeat(64),
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
            },
            residuals: vec![],
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
