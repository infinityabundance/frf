//! Court semantic identity — the resolution-comparability key.
//!
//! `resolution_compatibility` used to enumerate fields by hand ("same court
//! string, same authority, same fixture…"), which is brittle: every new
//! dimension of the question had to be remembered. Instead, the court's
//! semantic identity is a canonical hash of EVERYTHING that defines the
//! evidentiary question, computed once at court time and stored in the
//! capture:
//!
//! - court id, question, falsifier
//! - admitted authority id
//! - fixture id + bytes (sha256) + declared arguments
//! - the full admissibility envelope (fixture family, platforms,
//!   observables, normalizers, replay scope)
//! - the comparator identities applied (id + version + implementation hash)
//!
//! The candidate is deliberately absent: a fix court changes the candidate
//! while holding the question stable. The environment is deliberately
//! absent: the resolution predicate checks it as a separate dimension.
//!
//! This is one instance of the general FRF idea of *evidence-transform
//! predicates*: a transformation (fix, minimization, environment
//! refinement, authority split) declares which dimensions may change and
//! which must stay invariant. The fix-court predicate here is: same
//! semantic identity, same environment, candidate MAY differ, target axis
//! closes.

use crate::canon;
use crate::error::Result;
use crate::host;
use crate::model::*;
use serde_json::json;

/// The canonical hash of the evidentiary question. Deterministic: the same
/// court declaration, fixture bytes, and comparators always yield the same
/// identity, in any implementation that serializes with RFC 8785.
pub fn court_semantic_identity(
    spec: &CourtSpec,
    fixture_sha256: &str,
    comparators: &[ComparatorIdentity],
) -> Result<String> {
    let envelope = &spec.admissibility_envelope;
    let doc = json!({
        "court": spec.id,
        "question": spec.question,
        "falsifier": spec.falsifier,
        "authority": spec.authority,
        "fixture": {
            "id": spec.fixture.id,
            "sha256": fixture_sha256,
            "arguments": spec.fixture.arguments,
        },
        "envelope": {
            "fixture_family": envelope.fixture_family,
            "platforms": envelope.platforms,
            "observables": envelope.observables,
            "normalizers": envelope.normalizers,
            "replay_scope": envelope.replay_scope,
        },
        "comparators": comparators
            .iter()
            .map(|c| json!({"id": c.id, "version": c.version, "implementation_hash": c.implementation_hash}))
            .collect::<Vec<_>>(),
    });
    let json = canon::canonical(&doc)?;
    Ok(host::sha256_bytes(json.as_bytes()))
}

/// The first semantic dimension on which two captures differ, phrased for an
/// error message ("fixture id differs (a != b)"). Only used for diagnostics:
/// the PREDICATE is the semantic identity hash, this walk just names the
/// mismatch.
pub fn semantic_diff(a: &CaptureManifest, b: &CaptureManifest) -> Option<String> {
    let a_env = &a.court_spec.admissibility_envelope;
    let b_env = &b.court_spec.admissibility_envelope;
    let checks: Vec<(&str, String, String)> = vec![
        ("court", a.court.clone(), b.court.clone()),
        ("authority", a.authority.clone(), b.authority.clone()),
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
            "comparators",
            format!("{:?}", a.comparators),
            format!("{:?}", b.comparators),
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

    fn spec(id: &str, authority: &str) -> CourtSpec {
        CourtSpec {
            id: id.into(),
            question: "q".into(),
            falsifier: "f".into(),
            authority: authority.into(),
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

    fn comparators() -> Vec<ComparatorIdentity> {
        vec![ComparatorIdentity {
            id: "exit".into(),
            version: "v1".into(),
            implementation_hash: "0".repeat(64),
        }]
    }

    #[test]
    fn identity_is_deterministic_and_sensitive_to_the_question() {
        let a = court_semantic_identity(&spec("c", "a"), &"1".repeat(64), &comparators()).unwrap();
        assert_eq!(
            a,
            court_semantic_identity(&spec("c", "a"), &"1".repeat(64), &comparators()).unwrap()
        );
        // The candidate is NOT part of the question.
        let mut s2 = spec("c", "a");
        s2.candidate.name = "something-else".into();
        assert_eq!(
            a,
            court_semantic_identity(&s2, &"1".repeat(64), &comparators()).unwrap()
        );
        // Everything that defines the question is.
        let mut s3 = spec("c", "a");
        s3.admissibility_envelope.replay_scope = "repeated(3)".into();
        assert_ne!(
            a,
            court_semantic_identity(&s3, &"1".repeat(64), &comparators()).unwrap()
        );
        assert_ne!(
            a,
            court_semantic_identity(&spec("c", "a"), &"2".repeat(64), &comparators()).unwrap()
        );
        assert_ne!(
            a,
            court_semantic_identity(&spec("c", "a"), &"1".repeat(64), &[]).unwrap()
        );
    }

    #[test]
    fn diff_names_the_first_differing_dimension() {
        let capture = |spec: CourtSpec| CaptureManifest {
            schema_version: SCHEMA_CAPTURE.into(),
            run: "run-x".into(),
            court: spec.id.clone(),
            authority: spec.authority.clone(),
            manifest: "m.yaml".into(),
            fixture: spec.fixture.id.clone(),
            fixture_sha256: "1".repeat(64),
            arguments: vec![],
            environment_digest: "0".repeat(64),
            court_spec: spec,
            runner: RunnerIdentity {
                schema_version: SCHEMA_RUNNER.into(),
                frf_version: "0".into(),
                frf_executable_hash: "0".repeat(64),
            },
            comparators: vec![],
            authority_artifact: ArtifactIdentity {
                path: "p".into(),
                sha256: "0".repeat(64),
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

        let a = capture(spec("c", "a"));
        let mut b = capture(spec("c", "a"));
        assert_eq!(semantic_diff(&a, &b), None);
        b.fixture = "other.conf".into();
        assert_eq!(
            semantic_diff(&a, &b).unwrap(),
            "fixture id differs (\"malformed-path.conf\" != \"other.conf\")"
        );
        let mut c = capture(spec("c", "a"));
        c.authority = "other-1.0".into();
        assert_eq!(
            semantic_diff(&a, &c).unwrap(),
            "authority differs (\"a\" != \"other-1.0\")"
        );
    }
}
