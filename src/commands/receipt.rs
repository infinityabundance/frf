//! `frf receipt emit`: bind court + authority + candidate + fixture +
//! captures + residuals + dispositions into an OpenReceipt (Appendix A,
//! trimmed: `verdict_case_file`, `taste_gates`, and `invariants` are
//! deliberately dropped in v0 — see README Known Limitations).
//!
//! The receipt body is serialized as canonical JSON (RFC 8785) and its id is
//! `receipt-{run}-{full SHA-256 of the canonical bytes}` — the full digest,
//! not a display prefix, is the identity (a short prefix is UI sugar, never
//! the address). Re-emitting the same state yields the same id and is a
//! no-op; emitting after a disposition change yields a new receipt. Receipts
//! are never rewritten.

use crate::error::Result;
use crate::host;
use crate::kappa;
use crate::model::*;
use crate::store::Store;

pub fn run(store: &Store, run: &str) -> Result<String> {
    let capture = store.load_capture(run)?;
    let authority = store.load_authority(&capture.authority)?;
    let spec = &capture.court_spec;

    // Load the residuals this run observed, with their current dispositions.
    let mut residuals: Vec<ResidualRecord> = Vec::new();
    for id in &capture.residuals {
        residuals.push(store.load_residual(id)?);
    }

    let family = &spec.admissibility_envelope.fixture_family;

    let observables: Vec<ReceiptObservable> = spec
        .admissibility_envelope
        .observables
        .iter()
        .map(|o| {
            let axis = Axis::parse(o).expect("validated at court run");
            let (raw_reference_hash, raw_candidate_hash) = match axis {
                Axis::Exit => (
                    capture.reference.exit_sha256.clone(),
                    capture.candidate.exit_sha256.clone(),
                ),
                Axis::Stderr => (
                    capture.reference.stderr_first_line_sha256.clone(),
                    capture.candidate.stderr_first_line_sha256.clone(),
                ),
                Axis::Stdout => (
                    capture.reference.stdout_first_line_sha256.clone(),
                    capture.candidate.stdout_first_line_sha256.clone(),
                ),
            };
            let has_residual = residuals.iter().any(|r| r.axis == axis);
            ReceiptObservable {
                axis: axis.as_str().to_string(),
                raw_reference_hash,
                raw_candidate_hash,
                comparator: axis.comparator().to_string(),
                normalization_rules: vec![],
                verdict: if has_residual {
                    ObservableVerdict::Residual
                } else {
                    ObservableVerdict::Pass
                },
            }
        })
        .collect();

    let receipt_residuals: Vec<ReceiptResidual> = residuals
        .iter()
        .map(|r| {
            // The disposition is the projection of the residual's append-only
            // event history at emit time; the observation itself is immutable.
            let disposition = store.current_disposition(&r.id)?;
            let fingerprint = crate::semantics::residual_fingerprint(r)?;
            Ok(ReceiptResidual {
                id: r.id.clone(),
                axis: r.axis.as_str().to_string(),
                kind: r.kind,
                sign: ResidualSign {
                    norm: "single-run".to_string(),
                    drift: "not-observed".to_string(),
                    slew: "not-observed".to_string(),
                },
                grammar_state: kappa::grammar_state(&disposition).to_string(),
                raw_reference_hash: r.raw_reference_sha256.clone(),
                raw_candidate_hash: r.raw_candidate_sha256.clone(),
                disposition: disposition.as_str().to_string(),
                reason: disposition.reason().map(|s| s.to_string()),
                resolution_run_id: disposition.resolution_run_id().map(|s| s.to_string()),
                closure_predicate: match &disposition {
                    Disposition::Fixed {
                        closure_predicate, ..
                    } => Some(closure_predicate.clone()),
                    _ => None,
                },
                // A residual reproduces by replaying the run that observed it.
                reproducer: run.to_string(),
                invariant: String::new(),
                residual_fingerprint: fingerprint,
            })
        })
        .collect::<Result<_>>()?;

    // Draft the receipt body; the id is a hash of this body.
    let blocked = crate::sentences::refusal_lines_from_residuals(&receipt_residuals, family);
    let body = Receipt {
        schema_version: SCHEMA_RECEIPT.to_string(),
        run: run.to_string(),
        court: ReceiptCourt {
            id: spec.id.clone(),
            question: spec.question.clone(),
            falsifier: spec.falsifier.clone(),
            admissibility_envelope: ReceiptEnvelope {
                authority_versions: vec![authority.version.clone()],
                fixture_family: family.clone(),
                platforms: spec.admissibility_envelope.platforms.clone(),
                observables: spec.admissibility_envelope.observables.clone(),
                normalizers: spec.admissibility_envelope.normalizers.clone(),
                replay_scope: spec.admissibility_envelope.replay_scope.clone(),
            },
            // The semantic identity was bound at observation time; the
            // receipt copies it, never recomputes it.
            semantic_identity: capture.court_semantic_identity.clone(),
        },
        // Runner, comparator semantics, and environment are copied from the
        // capture: they describe the executable, relations, and host that
        // OBSERVED the run, not the one that happens to emit the receipt
        // later. Semantic identity and implementation provenance are kept
        // separate: the question asked vs. who asked it.
        provenance: capture.provenance.clone(),
        comparator_semantics: capture.comparator_semantics.clone(),
        authority: ReceiptAuthority {
            name: authority.name.clone(),
            kind: authority.kind.clone(),
            version: authority.version.clone(),
            identity_hash: authority.executable_sha256.clone(),
            provenance: format!("file:{}", authority.path),
            interpreter: capture.authority_artifact.interpreter.clone(),
        },
        candidate: ReceiptCandidate {
            name: spec.candidate.name.clone(),
            version_or_commit: spec.candidate.version_or_commit.clone(),
            build_profile: spec.candidate.build_profile.clone(),
            identity_hash: capture.candidate_artifact.sha256.clone(),
            interpreter: capture.candidate_artifact.interpreter.clone(),
        },
        environment: capture.environment.clone(),
        fixtures: vec![ReceiptFixture {
            id: capture.fixture.clone(),
            hash: capture.fixture_sha256.clone(),
            arguments: capture.arguments.clone(),
            // The semantic identity is computed over the DECLARED arguments;
            // the receipt must carry them to rederive the question.
            declared_arguments: spec.fixture.arguments.clone(),
        }],
        observables,
        residuals: receipt_residuals,
        endoduction: ReceiptEndoduction {
            schema_version: TOKEN_SCHEMA_VERSION.to_string(),
            tokens: residuals
                .iter()
                .map(|r| {
                    let disposition = store
                        .current_disposition(&r.id)
                        .unwrap_or(Disposition::Open);
                    let token = kappa::kappa(r, &disposition);
                    ReceiptToken {
                        residual_id: r.id.clone(),
                        token: token.token,
                        next_court: token.next_court,
                        blocks_claims: token.blocks_claims,
                    }
                })
                .collect(),
        },
        claims: ReceiptClaims {
            positive: vec![],
            non_claims: crate::sentences::non_claims(family),
            blocked_by_open_residuals: blocked,
        },
        replay: ReceiptReplay {
            program: "frf".to_string(),
            evidence_root: store.root.to_string_lossy().into_owned(),
            argv: crate::commands::replay::replay_argv(&store.root, &capture.manifest),
            expected_run_identity: run.to_string(),
        },
    };

    let json = crate::canon::canonical(&body)?;
    let id = format!("receipt-{run}-{}", host::sha256_bytes(json.as_bytes()));
    let path = store.receipt_path(&id)?;
    if path.exists() {
        // Content-addressed: identical body means identical id, so this is
        // the same receipt; nothing to rewrite.
        eprintln!("receipt {id} already exists (identical evidence state); nothing rewritten");
        return Ok(id);
    }
    store.write_once(&path, &json)?;
    let blocking_count = body
        .residuals
        .iter()
        .filter(|r| matches!(r.disposition.as_str(), "open" | "unknown" | "harness"))
        .count();
    eprintln!(
        "receipt {id}: {} observable(s), {} residual(s) ({} blocking), tokens bound",
        body.observables.len(),
        body.residuals.len(),
        blocking_count
    );
    Ok(id)
}
