//! `frf replay <RUN_ID | RECEIPT_ID>`: a first-class evidence operation.
//!
//! Replay re-executes a captured observation — the exact snapshotted
//! artifacts (verified and re-sealed on every use), the exact captured argv,
//! under a checked admissibility environment — and requires the observation
//! to reproduce byte-for-byte: identical sides, identical residual
//! fingerprints, no new residuals, no missing residuals.
//!
//! Replay is not a re-observation: it writes nothing. If it succeeds, the
//! run's evidence is reproducible; if it fails, the failure names the
//! dimension that drifted (corrupt object, changed environment, changed
//! output). Original repository paths are provenance, not replay
//! dependencies — everything a replay needs lives under `objects/`.

use crate::error::{FrfError, Result};
use crate::host;
use crate::model::*;
use crate::store::Store;
use std::collections::BTreeSet;
use std::path::Path;

pub fn run(store: &Store, id: &str) -> Result<()> {
    // The name is a claim until recomputed: a run id must rederive its run
    // identity, and a receipt id must verify (content-addressed, semantically
    // conformant, derived from its capture) BEFORE it may be replayed.
    let (run, capture) = match store.load_capture(id) {
        Ok(_) => {
            let cv = crate::verify::load_capture_verified(store, id)?;
            (cv.run, cv.capture)
        }
        Err(_) => {
            let verified =
                crate::verify::load_receipt_verified(store, id).map_err(|e| {
                    match store.receipt_path(id) {
                        Err(validation) => validation,
                        Ok(p) if p.is_file() => e,
                        Ok(_) => FrfError::new(format!("no such run or receipt '{id}'")),
                    }
                })?;
            let body = verified.body();
            // `expected_run_identity` is enforced by the receipt verifier;
            // replay the exact run the receipt binds.
            let run = body.run.clone();
            let cv = crate::verify::load_capture_verified(store, &run)?;
            (cv.run, cv.capture)
        }
    };

    // -- checked admissibility environment ----------------------------------
    let current_platform = format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS);
    let envelope = &capture.court_spec.admissibility_envelope;
    if !envelope.platforms.iter().any(|p| p == &current_platform) {
        return Err(FrfError::new(format!(
            "replay refused: current platform {current_platform} is outside the run's declared envelope {:?}",
            envelope.platforms
        )));
    }
    let env = host::environment_identity();
    if env.digest != capture.environment.digest {
        return Err(FrfError::new(format!(
            "replay refused: the environment changed since observation ({} != {}); the run is not reproducible under the current environment",
            &env.digest[..8],
            &capture.environment.digest[..8]
        )));
    }

    // -- artifacts must reproduce exactly: verified, re-sealed snapshots ----
    let authority_snapshot = store.materialize_object(
        &store.verified_object_bytes(&capture.authority_artifact.sha256)?,
        true,
    )?;
    let candidate_snapshot = store.materialize_object(
        &store.verified_object_bytes(&capture.candidate_artifact.sha256)?,
        true,
    )?;
    // The fixture object is referenced by the captured argv; verify it too.
    store.verified_object_bytes(&capture.fixture_sha256)?;

    // -- execute the exact captured argv ------------------------------------
    let reference_out = host::run_process(&authority_snapshot, &capture.arguments)?;
    let candidate_out = host::run_process(&candidate_snapshot, &capture.arguments)?;
    let reference = SideCapture::from_outcome(&reference_out);
    let candidate = SideCapture::from_outcome(&candidate_out);

    // -- the observation must reproduce byte-for-byte ------------------------
    if reference != capture.reference || candidate != capture.candidate {
        return Err(FrfError::new(format!(
            "replay of {run} FAILED: the executed sides differ from the captured observation (outputs did not reproduce)"
        )));
    }

    // -- residuals must reproduce: same divergences, same fingerprints ------
    // Each declared axis is re-observed with the SAME comparator that
    // observed it: a built-in axis rederives its projection equality; an
    // externally served axis RE-INVOKES the exact snapshotted comparator
    // implementation against the reproduced sides (the request must rederive
    // to the recorded request_cid, and the outcome must match the recorded
    // result). The fresh fingerprints must then equal the recorded ones as
    // SETS — no new residuals, no missing residuals.
    for axis_str in &capture.court_spec.admissibility_envelope.observables {
        let axis = ObservableId::parse(axis_str)?;
        let semantic = capture
            .comparator_semantics
            .iter()
            .find(|s| s.id == axis.as_str())
            .ok_or_else(|| {
                FrfError::new(format!(
                    "replay of {run}: the capture carries no comparator semantic for axis {}",
                    axis.as_str()
                ))
            })?;
        let classifier = ResidualKind::parse(&semantic.residual_classifier)?;
        let implementation = capture
            .provenance
            .comparator_implementations
            .iter()
            .find(|i| i.id == axis.as_str())
            .ok_or_else(|| {
                FrfError::new(format!(
                    "replay of {run}: the capture carries no comparator implementation for axis {}",
                    axis.as_str()
                ))
            })?;
        let outcome = match &implementation.artifact {
            None => {
                let builtin = crate::comparators::BuiltinKind::from_id(axis.as_str()).ok_or_else(
                    || {
                        FrfError::new(format!(
                            "replay of {run}: the {} axis was served by no known in-binary comparator",
                            axis.as_str()
                        ))
                    },
                )?;
                let (surface, raw_ref, raw_cand) = builtin.compare(&reference, &candidate);
                if raw_ref == raw_cand {
                    crate::comparators::ComparatorOutcome::Equivalent
                } else {
                    crate::comparators::ComparatorOutcome::Divergent(vec![(
                        surface.map(str::to_string),
                        raw_ref,
                        raw_cand,
                    )])
                }
            }
            Some(artifact) => {
                // Re-invoke the exact snapshotted comparator on the
                // reproduced sides: replay is a re-observation with the same
                // instrument, not a re-derivation using the built-in logic.
                let request = crate::comparators::build_request(
                    axis.as_str(),
                    semantic,
                    &reference_out,
                    &candidate_out,
                    &capture.fixture_sha256,
                    &capture.arguments,
                    &capture.environment.digest,
                );
                let (request_bytes, request_cid) = crate::comparators::canonical_request(&request)?;
                let evidence = store.load_comparator_evidence(&run, axis.as_str())?;
                if request_cid != evidence.invocation.request_cid {
                    return Err(FrfError::new(format!(
                        "replay of {run} FAILED: the comparator request for the {} axis no longer rederives to the recorded request_cid — the reproduced sides differ from what the instrument saw",
                        axis.as_str()
                    )));
                }
                let snapshot = crate::comparators::materialize_implementation(store, artifact)?;
                let (outcome, _) = crate::comparators::run_external(
                    &snapshot,
                    &axis,
                    &request_bytes,
                    &request_cid,
                )?;
                let outcome_str = match &outcome {
                    crate::comparators::ComparatorOutcome::Equivalent => "equivalent",
                    crate::comparators::ComparatorOutcome::Divergent(_) => "divergent",
                };
                if outcome_str != evidence.result.outcome {
                    return Err(FrfError::new(format!(
                        "replay of {run} FAILED: the comparator for the {} axis no longer reproduces its recorded outcome ({} now vs {} recorded)",
                        axis.as_str(),
                        outcome_str,
                        evidence.result.outcome
                    )));
                }
                outcome
            }
        };
        let fresh: Vec<(Option<String>, String, String)> = match outcome {
            crate::comparators::ComparatorOutcome::Equivalent => vec![],
            crate::comparators::ComparatorOutcome::Divergent(v) => v,
        };
        let fresh_fps: BTreeSet<String> = fresh
            .iter()
            .map(|(surface, raw_ref, raw_cand)| {
                crate::semantics::fingerprint_from_projections(
                    &classifier,
                    &axis,
                    surface.as_deref(),
                    raw_ref,
                    raw_cand,
                )
            })
            .collect::<Result<_>>()?;
        let recorded: Vec<ResidualRecord> = capture
            .residuals
            .iter()
            .filter_map(|rid| store.load_residual(rid).ok())
            .filter(|r| r.axis == axis)
            .collect();
        let recorded_fps: BTreeSet<String> = recorded
            .iter()
            .map(crate::semantics::residual_fingerprint)
            .collect::<Result<_>>()?;
        if fresh_fps != recorded_fps {
            let new: Vec<&String> = fresh_fps.difference(&recorded_fps).collect();
            let gone: Vec<&String> = recorded_fps.difference(&fresh_fps).collect();
            if !new.is_empty() {
                return Err(FrfError::new(format!(
                    "replay of {run} FAILED: {} new divergence(s) appeared on the {} axis that were not in the captured observation",
                    new.len(),
                    axis.as_str()
                )));
            }
            return Err(FrfError::new(format!(
                "replay of {run} FAILED: {} recorded residual(s) on the {} axis no longer reproduce (fingerprint mismatch)",
                gone.len(),
                axis.as_str()
            )));
        }
    }

    println!(
        "replay {run}: reproduced — sides byte-identical, {} residual(s) with matching fingerprints",
        capture.residuals.len()
    );
    Ok(())
}

/// The replay argv recorded in receipts, for documentation parity.
pub fn replay_argv(root: &Path, manifest: &str) -> Vec<String> {
    vec![
        "--root".to_string(),
        root.to_string_lossy().into_owned(),
        "court".to_string(),
        "run".to_string(),
        manifest.to_string(),
    ]
}
