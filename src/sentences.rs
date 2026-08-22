//! Claim sentence assembly — the only module in the crate allowed to produce
//! claim prose, and the only caller is `commands/claim.rs`. No positive claim
//! string can be hand-authored anywhere: every sentence is assembled here
//! from receipt fields, and nothing else writes into `claims/`.
//!
//! Claim dependency algebra (the paper's rule, implemented): a residual
//! blocks ONLY the claims whose observable scope intersects it.
//!
//! - `harness` invalidates the EVIDENCE of the run: no claim from the
//!   receipt, on any axis (harness is run-level, not axis-level).
//! - `open` and `unknown` block claims on their axis only: an unexplained
//!   stdout difference blocks stdout parity, never knowledge about exit.
//! - a residual on an axis, whatever its disposition, means THIS run
//!   observed divergence on that axis — the axis is never claimable as
//!   parity from this receipt (a disposition links history; it never
//!   rewrites an observation). Compile from the resolution run instead.
//! - `fixed`, `intentional`, `environmental`, `oracle_version` exclude only
//!   their axis and never license parity on it.
//!
//! The compiled sentence is scoped to the executed court, the admitted
//! authority id, the EXACT candidate artifact, the fixture family, and the
//! environment digest — never beyond the receipt's surface.

use crate::model::*;

/// Short environment label used inside sentences: `x86_64-linux (ab12cd34)`
/// (the paper's arch-os platform convention).
fn environment_label(env: &EnvironmentIdentity) -> String {
    let digest = &env.digest;
    let short = if digest.len() >= 8 {
        &digest[..8]
    } else {
        digest
    };
    format!("{}-{} ({short})", env.architecture, env.os)
}

/// The single conservative positive sentence, or `None` when no positive
/// claim is licensed: harness residuals invalidate the whole run's evidence,
/// and an axis is claimable only when THIS receipt's run observed it passing
/// (no residual on the axis) — whatever a residual's disposition, an axis
/// this run observed diverging is never parity from this receipt. Open and
/// unknown residuals block only their own axis (they fall out of the scope
/// like any residual); harness blocks everything.
pub fn positive_claim(r: &Receipt) -> Option<String> {
    // Harness invalidates the evidence of the run, on every axis.
    if r.residuals.iter().any(|res| res.disposition == "harness") {
        return None;
    }
    let family = &r.court.admissibility_envelope.fixture_family;
    let mut clauses: Vec<String> = Vec::new();
    for obs in &r.observables {
        // The run observed a residual on this axis → the axis cannot be
        // claimed as parity from this receipt, whatever the disposition.
        if r.residuals.iter().any(|res| res.axis == obs.axis) {
            continue;
        }
        let clause = match obs.axis.as_str() {
            "exit" => format!("{family} exit class"),
            "stderr" => format!("{family} first diagnostic line"),
            "stdout" => format!("{family} first stdout line"),
            other => format!("{other} behavior"),
        };
        clauses.push(clause);
    }
    if clauses.is_empty() {
        return None;
    }
    let authority = format!("{}-{}", r.authority.name, r.authority.version);
    let env = environment_label(&r.environment);
    let court = &r.court.id;
    // Attribute to the exact candidate artifact: name/version are labels, the
    // identity hash is the executed bytes.
    let digest = &r.candidate.identity_hash;
    let short = if digest.len() >= 8 {
        &digest[..8]
    } else {
        digest
    };
    Some(format!(
        "For reference {authority}, fixture family {family}, and environment {env}, \
         candidate {} {} ({short}) preserves {} for the {family} cases in court {court}.",
        r.candidate.name,
        r.candidate.version_or_commit,
        clauses.join(" and ")
    ))
}

/// The non-claim boundary, always stated next to any positive claim. The first
/// sentence carries the refusal phrasing from Section 12 verbatim; the second
/// binds the scope to the fixture family.
pub fn non_claims(fixture_family: &str) -> Vec<String> {
    vec![
        "This receipt does not establish byte-identical stderr, full CLI compatibility, or a drop-in replacement claim.".to_string(),
        format!("In particular, it does not establish a drop-in replacement for all {fixture_family} behavior."),
    ]
}

/// Refusal lines, split by level:
///
/// - [`harness_refusal_lines`]: run-level — harness invalidates the evidence
///   of the run, blocking every claim from the receipt.
/// - [`open_refusal_lines`]: axis-level — open/unknown residuals block only
///   claims whose observable scope intersects their axis.
///
/// Each line uses the prompt's exact shape "cannot claim X because residual
/// Y is open". [`refusal_lines_from_residuals`] is the union, used for the
/// receipt's embedded claim state at emit time.
pub fn harness_refusal_lines(residuals: &[ReceiptResidual], fixture_family: &str) -> Vec<String> {
    refusal_lines_matching(residuals, fixture_family, |d| d == "harness")
}

pub fn open_refusal_lines(residuals: &[ReceiptResidual], fixture_family: &str) -> Vec<String> {
    refusal_lines_matching(residuals, fixture_family, |d| {
        matches!(d, "open" | "unknown")
    })
}

/// Union of all refusal lines (harness + open + unknown).
pub fn refusal_lines_from_residuals(
    residuals: &[ReceiptResidual],
    fixture_family: &str,
) -> Vec<String> {
    refusal_lines_matching(residuals, fixture_family, |d| {
        matches!(d, "open" | "unknown" | "harness")
    })
}

fn refusal_lines_matching(
    residuals: &[ReceiptResidual],
    fixture_family: &str,
    matches: impl Fn(&str) -> bool,
) -> Vec<String> {
    residuals
        .iter()
        .filter(|res| matches(res.disposition.as_str()))
        .map(|res| {
            format!(
                "cannot claim compatibility for fixture family {fixture_family} because residual {} ({}) is {}",
                res.id,
                res.kind.as_str(),
                res.disposition
            )
        })
        .collect()
}

/// Refusal lines for a whole receipt (convenience wrapper, union form).
pub fn refusal_lines(r: &Receipt) -> Vec<String> {
    let family = &r.court.admissibility_envelope.fixture_family;
    refusal_lines_from_residuals(&r.residuals, family)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> EnvironmentIdentity {
        EnvironmentIdentity {
            schema_version: SCHEMA_ENVIRONMENT.into(),
            os: "linux".into(),
            architecture: "x86_64".into(),
            kernel_release: "6.1".into(),
            locale: "C".into(),
            timezone: "Etc/UTC".into(),
            umask: "0022".into(),
            cwd: "frf".into(),
            digest: "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899".into(),
        }
    }

    fn provenance() -> ObservationProvenance {
        ObservationProvenance {
            schema_version: SCHEMA_PROVENANCE.into(),
            runner: RunnerIdentity {
                schema_version: SCHEMA_RUNNER.into(),
                frf_version: env!("CARGO_PKG_VERSION").into(),
                frf_executable_hash: "0".repeat(64),
            },
            comparator_implementations: vec![],
            normalizer_implementations: vec![],
            adapter_implementations: vec![],
            minimizer_implementations: vec![],
        }
    }

    fn receipt_base() -> Receipt {
        Receipt {
            schema_version: SCHEMA_RECEIPT.into(),
            run: "run-cli-malformed-input-ab12cd34".into(),
            court: ReceiptCourt {
                id: "cli-malformed-input".into(),
                question: "q".into(),
                falsifier: "f".into(),
                admissibility_envelope: ReceiptEnvelope {
                    authority_versions: vec!["1.8.2".into()],
                    fixture_family: "malformed-input".into(),
                    platforms: vec!["x86_64-linux".into()],
                    observables: vec!["exit".into(), "stderr".into()],
                    normalizers: vec![],
                    replay_scope: "single-run".into(),
                },
                semantic_identity: "1".repeat(64),
            },
            provenance: provenance(),
            comparator_semantics: vec![],
            normalizer_semantics: vec![],
            adapter_semantics: vec![],
            execution_profile: EXECUTION_PROFILE_LINUX.into(),
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
            authority: ReceiptAuthority {
                name: "ref-cli".into(),
                kind: "executable_reference".into(),
                version: "1.8.2".into(),
                identity_hash: "0".repeat(64),
                provenance: "file:golden/reference.sh".into(),
                interpreter: None,
                native_runtime: None,
            },
            candidate: ReceiptCandidate {
                name: "cand-cli".into(),
                version_or_commit: "0.1.0".into(),
                build_profile: "debug".into(),
                identity_hash: "c".repeat(64),
                interpreter: None,
                native_runtime: None,
            },
            environment: env(),
            fixtures: vec![ReceiptFixture {
                id: "malformed-path.conf".into(),
                hash: "1".repeat(64),
                arguments: vec!["--strict".into(), "obj".into()],
                declared_arguments: vec!["--strict".into(), "{fixture}".into()],
            }],
            observables: vec![
                ReceiptObservable {
                    axis: "exit".into(),
                    raw_reference_hash: "2".repeat(64),
                    raw_candidate_hash: "1".repeat(64),
                    comparator: "eq(exit-code)".into(),
                    normalization_rules: vec![],
                    verdict: ObservableVerdict::Residual,
                    comparator_request: None,
                    comparator_result: None,
                },
                ReceiptObservable {
                    axis: "stderr".into(),
                    raw_reference_hash: "3".repeat(64),
                    raw_candidate_hash: "4".repeat(64),
                    comparator: "eq(stderr-first-line)".into(),
                    normalization_rules: vec![],
                    verdict: ObservableVerdict::Residual,
                    comparator_request: None,
                    comparator_result: None,
                },
            ],
            residuals: vec![],
            endoduction: ReceiptEndoduction {
                schema_version: TOKEN_SCHEMA_VERSION.into(),
                tokens: vec![],
            },
            claims: ReceiptClaims {
                positive: vec![],
                non_claims: non_claims("malformed-input"),
                blocked_by_open_residuals: vec![],
            },
            replay: ReceiptReplay {
                program: "frf".into(),
                evidence_root: "frf".into(),
                argv: vec!["--root".into(), "frf".into(), "court".into(), "run".into()],
                expected_run_identity: "run-cli-malformed-input-ab12cd34".into(),
            },
        }
    }

    fn res(id: &str, axis: &str, disposition: &str) -> ReceiptResidual {
        ReceiptResidual {
            id: id.into(),
            axis: axis.into(),
            kind: if axis == "exit" {
                ResidualKind::exit()
            } else {
                ResidualKind::text()
            },
            sign: ResidualSign {
                trajectory_evidence: vec![],
            },
            grammar_state: "violation".into(),
            raw_reference_hash: "e".repeat(64),
            raw_candidate_hash: "1".repeat(64),
            disposition: disposition.into(),
            disposition_event_id: None,
            reason: None,
            resolution_run_id: None,
            closure_predicate: None,
            reproducer: "replay".into(),
            invariant: String::new(),
            residual_fingerprint: "0".repeat(64),
        }
    }

    /// A `fixed` receipt residual carrying its resolution run and predicate.
    fn res_fixed(id: &str, axis: &str, run: &str) -> ReceiptResidual {
        let mut r = res(id, axis, "fixed");
        r.reason = Some("candidate patched".into());
        r.resolution_run_id = Some(run.into());
        r.closure_predicate = Some(CLOSURE_PREDICATE_FIX_COURT.into());
        r
    }

    #[test]
    fn claim_comes_from_the_run_that_observed_the_pass() {
        // The positive claim is compiled from the RESOLUTION run's receipt:
        // exit clean (no residual — the run observed the pass), stderr
        // intentional. The sentence is attributed to the exact candidate
        // artifact that ran.
        let mut r = receipt_base();
        r.candidate.version_or_commit = "0.1.0-fixed".into();
        r.residuals
            .push(res("cli-text-0001", "stderr", "intentional"));
        let sentence = positive_claim(&r).unwrap();
        assert!(
            sentence.starts_with("For reference ref-cli-1.8.2, fixture family malformed-input, and environment x86_64-linux (aabbccdd), candidate cand-cli 0.1.0-fixed (cccccccc) preserves malformed-input exit class for the malformed-input cases in court cli-malformed-input."),
            "got: {sentence}"
        );
        assert!(!sentence.contains("stderr"));
        assert!(!sentence.contains("drop-in"));
    }

    #[test]
    fn receipt_that_observed_divergence_never_yields_parity() {
        // Whatever the disposition — open, fixed with its resolution run,
        // intentional, environmental — a residual on the axis means THIS
        // receipt's run observed divergence, so the axis is not claimable
        // from this receipt. A disposition links history; it never rewrites
        // the observation.
        for disposition in [
            "open",
            "fixed",
            "intentional",
            "environmental",
            "oracle_version",
        ] {
            let mut r = receipt_base();
            let res_entry = if disposition == "fixed" {
                res_fixed("cli-exit-0001", "exit", "run-verify")
            } else {
                res("cli-exit-0001", "exit", disposition)
            };
            r.residuals.push(res_entry);
            r.residuals
                .push(res("cli-text-0001", "stderr", "intentional"));
            assert_eq!(
                positive_claim(&r),
                None,
                "disposition '{disposition}' on an observed axis must not license parity from this receipt"
            );
        }
    }

    #[test]
    fn open_residual_blocks_only_its_axis() {
        // exit open, stderr clean: the exit claim is blocked (its axis was
        // observed diverging), but stderr remains claimable — an open
        // residual never throws away unrelated positive knowledge.
        let mut r = receipt_base();
        r.residuals.push(res("cli-exit-0001", "exit", "open"));
        let sentence = positive_claim(&r).unwrap();
        assert!(
            sentence.contains("malformed-input first diagnostic line"),
            "got: {sentence}"
        );
        assert!(!sentence.contains("exit class"));
        assert_eq!(
            open_refusal_lines(&r.residuals, "malformed-input"),
            vec!["cannot claim compatibility for fixture family malformed-input because residual cli-exit-0001 (exit) is open"]
        );
    }

    #[test]
    fn harness_invalidates_the_whole_run() {
        // harness is run-level: no claim on ANY axis, even clean ones.
        let mut r = receipt_base();
        r.residuals.push(res("cli-text-0001", "stderr", "harness"));
        assert_eq!(positive_claim(&r), None);
        assert_eq!(
            harness_refusal_lines(&r.residuals, "malformed-input"),
            vec!["cannot claim compatibility for fixture family malformed-input because residual cli-text-0001 (text) is harness"]
        );
    }

    #[test]
    fn unknown_blocks_only_its_axis() {
        let mut r = receipt_base();
        r.residuals.push(res("cli-exit-0001", "exit", "unknown"));
        let sentence = positive_claim(&r).unwrap();
        assert!(sentence.contains("malformed-input first diagnostic line"));
        assert!(!sentence.contains("exit class"));
    }

    #[test]
    fn intentional_stderr_excludes_only_stderr() {
        // Only stderr diverges (intentionally); exit was observed passing, so
        // the claim covers exit class alone.
        let mut r = receipt_base();
        r.residuals
            .push(res("cli-text-0001", "stderr", "intentional"));
        let sentence = positive_claim(&r).unwrap();
        assert!(sentence.contains("malformed-input exit class"));
        assert!(!sentence.contains("first diagnostic line"));
    }

    #[test]
    fn clean_axes_are_claimable() {
        let r = receipt_base();
        let sentence = positive_claim(&r).unwrap();
        assert!(sentence
            .contains("malformed-input exit class and malformed-input first diagnostic line"));
    }

    #[test]
    fn non_claim_language_is_verbatim() {
        let ncs = non_claims("malformed-input");
        assert_eq!(ncs[0], "This receipt does not establish byte-identical stderr, full CLI compatibility, or a drop-in replacement claim.");
        assert_eq!(ncs[1], "In particular, it does not establish a drop-in replacement for all malformed-input behavior.");
    }
}
