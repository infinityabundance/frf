//! Claim sentence assembly — the only module in the crate allowed to produce
//! claim prose, and the only caller is `commands/claim.rs`. No positive claim
//! string can be hand-authored anywhere: every sentence is assembled here
//! from receipt fields, and nothing else writes into `claims/`.
//!
//! Positive-claim rule (Section 12 + the semantic non-bypass rule):
//! - A declared axis is *claimable* when it has no residual, or when every
//!   residual on it is `fixed` with a `resolution_run_id` — the court run
//!   whose captures show the residual no longer reproduces. A disposition is
//!   never evidence; the run is. `fixed` without that edge is not claimable.
//! - No other closure licenses parity: `intentional` is a documented
//!   divergence, `environmental` and `oracle_version` weaken the envelope
//!   rather than claim it, and `harness`/`unknown`/`open` block entirely.
//! - The compiled sentence is scoped to the executed court, the admitted
//!   authority id, the fixture family, and the environment digest — never
//!   beyond the receipt's surface.

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
/// whole claim, and an axis is only claimable when it matched or was closed
/// as `fixed` **with a resolution run**. `intentional` axes are documented
/// divergences, `environmental`/`oracle_version` weaken the envelope — none
/// of them licenses parity.
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
        // An axis is claimable only when every residual on it is fixed and
        // points at its resolution run. The run itself is verified by the
        // caller (claim compile / verify); here the edge must exist.
        let claimable = r
            .residuals
            .iter()
            .filter(|res| res.axis == obs.axis)
            .all(|res| res.disposition == "fixed" && res.resolution_run_id.is_some());
        if !claimable {
            continue;
        }
        let clause = match obs.axis.as_str() {
            "exit" => format!("{family} exit class"),
            "stderr" => format!("{family} first diagnostic line"),
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
    Some(format!(
        "For reference {authority}, fixture family {family}, and environment {env}, \
         the candidate preserves {} for the {family} cases in court {court}.",
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
            toolchain: "frf/0.1.0".into(),
            environment_digest: "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
                .into(),
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
            },
            authority: ReceiptAuthority {
                name: "ref-cli".into(),
                kind: "executable_reference".into(),
                version: "1.8.2".into(),
                identity_hash: "0".repeat(64),
                provenance: "file:golden/reference.sh".into(),
            },
            candidate: ReceiptCandidate {
                name: "cand-cli".into(),
                version_or_commit: "0.1.0".into(),
                build_profile: "debug".into(),
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
            reproducer: "replay".into(),
            invariant: String::new(),
            residual_fingerprint: "0".repeat(64),
        }
    }

    /// A `fixed` receipt residual carrying its resolution run.
    fn res_fixed(id: &str, axis: &str, run: &str) -> ReceiptResidual {
        let mut r = res(id, axis, "fixed");
        r.reason = Some("candidate patched".into());
        r.resolution_run_id = Some(run.into());
        r
    }

    #[test]
    fn golden_claim_sentence_shape() {
        // exit fixed (with its resolution run), stderr intentional → the
        // claim covers exit only.
        let mut r = receipt_base();
        r.residuals.push(res_fixed(
            "cli-exit-0001",
            "exit",
            "run-cli-malformed-input-verify",
        ));
        r.residuals
            .push(res("cli-text-0001", "stderr", "intentional"));
        let sentence = positive_claim(&r).unwrap();
        assert!(
            sentence.starts_with("For reference ref-cli-1.8.2, fixture family malformed-input, and environment x86_64-linux (aabbccdd), the candidate preserves malformed-input exit class for the malformed-input cases in court cli-malformed-input."),
            "got: {sentence}"
        );
        assert!(!sentence.contains("stderr"));
        assert!(!sentence.contains("drop-in"));
    }

    #[test]
    fn fixed_without_a_resolution_run_is_not_claimable() {
        // The hole this tool closes: a bare `fixed` label licenses nothing.
        let mut r = receipt_base();
        r.residuals.push(res("cli-exit-0001", "exit", "fixed"));
        r.residuals
            .push(res("cli-text-0001", "stderr", "intentional"));
        assert_eq!(positive_claim(&r), None);
    }

    #[test]
    fn environmental_and_oracle_version_weaken_the_envelope_not_parity() {
        for disposition in ["environmental", "oracle_version"] {
            let mut r = receipt_base();
            r.residuals.push(res("cli-exit-0001", "exit", disposition));
            r.residuals
                .push(res("cli-text-0001", "stderr", "intentional"));
            assert_eq!(
                positive_claim(&r),
                None,
                "{disposition} must not license parity"
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
        // Only stderr diverges (intentionally); exit matched, so the claim
        // covers exit class alone.
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
