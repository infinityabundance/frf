//! Claim sentence assembly — the only module in the crate allowed to produce
//! claim prose, and the only caller is `commands/claim.rs`. No positive claim
//! string can be hand-authored anywhere: every sentence is assembled here
//! from receipt fields, and nothing else writes into `claims/`.
//!
//! Positive-claim rule (Section 12 + the semantic non-bypass rule):
//! - A positive parity claim is compiled ONLY from a receipt whose run
//!   actually observed the axis passing — an axis is claimable iff this
//!   receipt has no residual on it. A receipt that observed divergence can
//!   never become a parity receipt, however its residuals are disposed: a
//!   disposition links historical evidence (e.g. `fixed` with its resolution
//!   run) but never rewrites what an old run demonstrated. Compile the
//!   positive claim from the resolution run's receipt instead.
//! - `open`, `unknown`, and `harness` block the entire claim; other closures
//!   exclude only their own axis.
//! - The compiled sentence is scoped to the executed court, the admitted
//!   authority id, the EXACT candidate artifact, the fixture family, and the
//!   environment digest — never beyond the receipt's surface.

use crate::model::*;

/// Short environment label used inside sentences: `x86_64-linux (ab12cd34)`
/// (the paper's arch-os platform convention).
fn environment_label(env: &ReceiptEnvironment) -> String {
    let digest = &env.environment_digest;
    let short = if digest.len() >= 8 {
        &digest[..8]
    } else {
        digest
    };
    format!("{}-{} ({short})", env.architecture, env.os)
}

/// The single conservative positive sentence, or `None` when a positive claim
/// is not licensed: any blocking residual (open/unknown/harness) refuses the
/// whole claim, and an axis is claimable only when THIS receipt's run observed
/// it passing (no residual on the axis). A disposed residual — `fixed`
/// included — links history; it never makes the old failing observation into
/// parity. The claim is attributed to the exact candidate artifact the run
/// executed.
pub fn positive_claim(r: &Receipt) -> Option<String> {
    let family = &r.court.admissibility_envelope.fixture_family;
    // Blocking dispositions refuse the entire claim, not just their axis.
    if r.residuals
        .iter()
        .any(|res| matches!(res.disposition.as_str(), "open" | "unknown" | "harness"))
    {
        return None;
    }
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

/// Refusal lines for residuals that block a positive claim: one line per
/// blocking residual, in the prompt's exact shape
/// "cannot claim X because residual Y is open". Blocking dispositions are
/// `open`, `unknown`, and `harness`.
pub fn refusal_lines_from_residuals(
    residuals: &[ReceiptResidual],
    fixture_family: &str,
) -> Vec<String> {
    residuals
        .iter()
        .filter(|res| {
            matches!(
                res.disposition.as_str(),
                "open" | "unknown" | "harness"
            )
        })
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

/// Refusal lines for a whole receipt (convenience wrapper).
pub fn refusal_lines(r: &Receipt) -> Vec<String> {
    let family = &r.court.admissibility_envelope.fixture_family;
    refusal_lines_from_residuals(&r.residuals, family)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> ReceiptEnvironment {
        ReceiptEnvironment {
            os: "linux".into(),
            architecture: "x86_64".into(),
            environment_digest: "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
                .into(),
        }
    }

    fn runner() -> RunnerIdentity {
        RunnerIdentity {
            schema_version: SCHEMA_RUNNER.into(),
            frf_version: env!("CARGO_PKG_VERSION").into(),
            frf_executable_hash: "0".repeat(64),
        }
    }

    fn receipt_base() -> Receipt {
        Receipt {
            schema_version: SCHEMA_RECEIPT.into(),
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
            runner: runner(),
            comparators: vec![],
            authority: ReceiptAuthority {
                name: "ref-cli".into(),
                kind: "executable_reference".into(),
                version: "1.8.2".into(),
                identity_hash: "0".repeat(64),
                provenance: "file:golden/reference.sh".into(),
                interpreter: None,
            },
            candidate: ReceiptCandidate {
                name: "cand-cli".into(),
                version_or_commit: "0.1.0".into(),
                build_profile: "debug".into(),
                identity_hash: "c".repeat(64),
                interpreter: None,
            },
            environment: env(),
            fixtures: vec![ReceiptFixture {
                id: "malformed-path.conf".into(),
                hash: "1".repeat(64),
                arguments: vec!["--strict".into(), "{fixture}".into()],
            }],
            observables: vec![
                ReceiptObservable {
                    axis: "exit".into(),
                    raw_reference_hash: "2".repeat(64),
                    raw_candidate_hash: "1".repeat(64),
                    comparator: "eq(exit-code)".into(),
                    normalization_rules: vec![],
                    verdict: ObservableVerdict::Residual,
                },
                ReceiptObservable {
                    axis: "stderr".into(),
                    raw_reference_hash: "3".repeat(64),
                    raw_candidate_hash: "4".repeat(64),
                    comparator: "eq(stderr-first-line)".into(),
                    normalization_rules: vec![],
                    verdict: ObservableVerdict::Residual,
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
                command: "frf --root frf court run frf/courts/cli-malformed-input/manifest.yaml"
                    .into(),
            },
        }
    }

    fn res(id: &str, axis: &str, disposition: &str) -> ReceiptResidual {
        ReceiptResidual {
            id: id.into(),
            axis: axis.into(),
            kind: if axis == "exit" {
                ResidualKind::Exit
            } else {
                ResidualKind::Text
            },
            sign: ResidualSign {
                norm: "single-run".into(),
                drift: "not-observed".into(),
                slew: "not-observed".into(),
            },
            grammar_state: "violation".into(),
            raw_reference_hash: "0".repeat(64),
            raw_candidate_hash: "1".repeat(64),
            disposition: disposition.into(),
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
    fn open_residual_blocks_the_whole_sentence() {
        let mut r = receipt_base();
        r.residuals.push(res("cli-exit-0001", "exit", "open"));
        // Even though stderr is clean, one open residual refuses everything.
        assert_eq!(positive_claim(&r), None);
        assert_eq!(
            refusal_lines(&r),
            vec!["cannot claim compatibility for fixture family malformed-input because residual cli-exit-0001 (exit) is open"]
        );
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
