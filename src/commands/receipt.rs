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

use crate::error::{FrfError, Result};
use crate::host;
use crate::kappa;
use crate::model::*;
use crate::store::Store;
use std::fs;
use std::path::Path;

fn read(path: &Path, what: &str) -> Result<Vec<u8>> {
    fs::read(path).map_err(|e| FrfError::new(format!("cannot read {what} {}: {e}", path.display())))
}

pub fn run(store: &Store, run: &str) -> Result<String> {
    // 0.1.59: a receipt may only be emitted from VERIFIED evidence. The run
    // identity rederives, the recorded identities recompute, the side files
    // rehash, and every residual is a verified observation of the run —
    // minting a receipt from a hand-crafted capture directory would let a
    // forged observation bind a claim.
    let cv = crate::verify::load_capture_verified(store, run)?;
    let capture = cv.capture;
    let authority = store.load_authority(&capture.authority)?;
    let spec = &capture.court_spec;

    // Load the residuals this run observed, with their current dispositions.
    let mut residuals: Vec<ResidualRecord> = Vec::new();
    for id in &capture.residuals {
        residuals.push(
            crate::verify::load_residual_verified(store, id)?
                .record()
                .clone(),
        );
    }

    let family = &spec.admissibility_envelope.fixture_family;

    let observables: Vec<ReceiptObservable> = spec
        .admissibility_envelope
        .observables
        .iter()
        .map(|o| {
            let axis = ObservableId::parse(o).expect("validated at court run");
            let semantic = capture
                .comparator_semantics
                .iter()
                .find(|s| s.id == axis.as_str())
                .expect("validated at court run");
            let implementation = capture
                .provenance
                .comparator_implementations
                .iter()
                .find(|i| i.id == axis.as_str())
                .expect("validated at court run");
            let has_residual = residuals.iter().any(|r| r.axis == axis);
            // For an in-binary axis the raw hashes are the captured
            // projections; for an externally served axis they are the
            // canonical `reference`/`candidate` subtrees of the preserved
            // comparator request, and the observable binds the exact
            // invocation + result records that produced its verdict.
            let (raw_reference_hash, raw_candidate_hash, comparator_request, comparator_result) =
                match &implementation.artifact {
                    None => {
                        let builtin = crate::comparators::BuiltinKind::from_id(axis.as_str())
                            .expect("validated at court run");
                        let (ref_h, cand_h) = match builtin {
                            crate::comparators::BuiltinKind::Exit => (
                                capture.reference.exit_sha256.clone(),
                                capture.candidate.exit_sha256.clone(),
                            ),
                            crate::comparators::BuiltinKind::Stderr => (
                                capture.reference.stderr_first_line_sha256.clone(),
                                capture.candidate.stderr_first_line_sha256.clone(),
                            ),
                            crate::comparators::BuiltinKind::Stdout => (
                                capture.reference.stdout_first_line_sha256.clone(),
                                capture.candidate.stdout_first_line_sha256.clone(),
                            ),
                            // The domain surfaces' raw observation: the
                            // produced tree's manifest hash, or the raw stdout
                            // stream's hash.
                            crate::comparators::BuiltinKind::Tree => (
                                capture
                                    .reference
                                    .produced
                                    .as_ref()
                                    .map(|p| p.manifest_sha256.clone())
                                    .unwrap_or_default(),
                                capture
                                    .candidate
                                    .produced
                                    .as_ref()
                                    .map(|p| p.manifest_sha256.clone())
                                    .unwrap_or_default(),
                            ),
                            crate::comparators::BuiltinKind::Bytes
                            | crate::comparators::BuiltinKind::Json => (
                                capture.reference.stdout_sha256.clone(),
                                capture.candidate.stdout_sha256.clone(),
                            ),
                        };
                        (ref_h, cand_h, None, None)
                    }
                    Some(_) => {
                        let evidence = store.load_comparator_evidence(run, axis.as_str())?;
                        let dir = store.comparator_dir(run, axis.as_str())?;
                        let request_value = crate::canon::parse_strict(&read(
                            &dir.join("request.json"),
                            "request",
                        )?)?;
                        let ref_h = host::sha256_bytes(
                            crate::canon::encode(&request_value["reference"])?.as_bytes(),
                        );
                        let cand_h = host::sha256_bytes(
                            crate::canon::encode(&request_value["candidate"])?.as_bytes(),
                        );
                        (
                            ref_h,
                            cand_h,
                            Some(evidence.invocation.request_cid.clone()),
                            Some(evidence.result.result_id.clone()),
                        )
                    }
                };
            Ok(ReceiptObservable {
                axis: axis.as_str().to_string(),
                raw_reference_hash,
                raw_candidate_hash,
                comparator: semantic.relation_label(),
                normalization_rules: vec![],
                verdict: if has_residual {
                    ObservableVerdict::Residual
                } else {
                    ObservableVerdict::Pass
                },
                comparator_request,
                comparator_result,
            })
        })
        .collect::<Result<_>>()?;

    let receipt_residuals: Vec<ReceiptResidual> = residuals
        .iter()
        .map(|r| {
            // The disposition is the projection of the residual's append-only
            // event history at emit time; the observation itself is immutable.
            // The receipt binds the EXACT event that supplied the state
            // (`disposition_event_id`), so it points at an immutable node in
            // the hash chain, not merely a copied disposition.
            let events = store.disposition_events(&r.id)?;
            let head = events.last();
            let disposition = head
                .map(|e| e.disposition.clone())
                .unwrap_or(Disposition::Open);
            let fingerprint = crate::semantics::residual_fingerprint(r)?;
            // The sign: a single-run court honestly records that drift/slew
            // were not observed; a repeated-run court derives them from the
            // residual's trajectory (fail closed if it is missing — the
            // repeated court wrote it before a receipt could be emitted).
            let sign = crate::verify::sign_for(store, &capture, r).map_err(|e| {
                FrfError::new(format!(
                    "receipt of run {run}: cannot derive the sign of residual {}: {e}",
                    r.id
                ))
            })?;
            Ok(ReceiptResidual {
                id: r.id.clone(),
                axis: r.axis.as_str().to_string(),
                kind: r.kind.clone(),
                sign,
                grammar_state: kappa::grammar_state(&disposition).to_string(),
                raw_reference_hash: r.raw_reference_sha256.clone(),
                raw_candidate_hash: r.raw_candidate_sha256.clone(),
                disposition: disposition.as_str().to_string(),
                disposition_event_id: head.map(|e| e.event_id.clone()),
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
        normalizer_semantics: capture.normalizer_semantics.clone(),
        adapter_semantics: capture.adapter_semantics.clone(),
        // The execution profile + applied capture bounds are copied from the
        // capture: an observation is read against the harness contract it
        // was actually made under, never what the emitting binary guesses.
        execution_profile: capture.execution_profile.clone(),
        capture_bounds: capture.capture_bounds.clone(),
        authority: ReceiptAuthority {
            name: authority.name.clone(),
            kind: authority.kind.clone(),
            version: authority.version.clone(),
            identity_hash: authority.executable_sha256.clone(),
            provenance: format!("file:{}", authority.path),
            interpreter: capture.authority_artifact.interpreter.clone(),
            native_runtime: capture.authority_artifact.native_runtime.clone(),
        },
        candidate: ReceiptCandidate {
            name: spec.candidate.name.clone(),
            version_or_commit: spec.candidate.version_or_commit.clone(),
            build_profile: spec.candidate.build_profile.clone(),
            identity_hash: capture.candidate_artifact.sha256.clone(),
            interpreter: capture.candidate_artifact.interpreter.clone(),
            native_runtime: capture.candidate_artifact.native_runtime.clone(),
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
        // The snapshotted execution-context closure (when the court declared
        // one), copied from the capture — a receipt never reconstructs the
        // runtime context from whatever happens to be installed.
        execution_context: capture.execution_context.clone(),
    };

    let json = crate::canon::canonical(&body)?;
    let id = format!("receipt-{run}-{}", host::sha256_bytes(json.as_bytes()));
    let path = store.receipt_path(&id)?;
    if path.exists() {
        // Idempotent write, content-addressed discipline: a receipt's id IS
        // the SHA-256 of its canonical bytes, so the existing file must
        // hash to that id — a corrupt or hand-edited document at this
        // address is refused, never silently "reused".
        let existing = read(&path, "receipt")?;
        let digest = id
            .strip_prefix("receipt-")
            .and_then(|rest| rest.rsplit_once('-'))
            .map(|(_, d)| d.to_string())
            .ok_or_else(|| FrfError::new("internal error: malformed receipt id"))?;
        if host::sha256_bytes(&existing) != digest {
            return Err(FrfError::new(format!(
                "receipt {id} already exists but does not hash to its id ({} != {}); refusing to reuse a corrupt receipt",
                &host::sha256_bytes(&existing)[..16],
                &digest[..16]
            )));
        }
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
