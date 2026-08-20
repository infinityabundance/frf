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

    // -- residuals must reproduce: same divergences, same fingerprints -------
    for axis in &capture.court_spec.admissibility_envelope.observables {
        let axis = Axis::parse(axis).map_err(FrfError::new)?;
        let kind = ResidualKind::from_axis(axis);
        let surface = match axis {
            Axis::Exit => None,
            Axis::Stderr => Some("first-diagnostic-line"),
            Axis::Stdout => Some("first-stdout-line"),
        };
        let (raw_ref, raw_cand) = match axis {
            Axis::Exit => (reference.exit.clone(), candidate.exit.clone()),
            Axis::Stderr => (
                reference.stderr_first_line.clone(),
                candidate.stderr_first_line.clone(),
            ),
            Axis::Stdout => (
                reference.stdout_first_line.clone(),
                candidate.stdout_first_line.clone(),
            ),
        };
        let diverges = raw_ref != raw_cand;
        let recorded = capture
            .residuals
            .iter()
            .filter_map(|rid| store.load_residual(rid).ok())
            .find(|r| r.axis == axis);
        match (diverges, recorded) {
            (true, Some(rec)) => {
                let replay_fp = crate::semantics::fingerprint_from_projections(
                    kind, axis, surface, &raw_ref, &raw_cand,
                )?;
                let recorded_fp = crate::semantics::residual_fingerprint(&rec)?;
                if replay_fp != recorded_fp {
                    return Err(FrfError::new(format!(
                        "replay of {run} FAILED: residual {} no longer reproduces (fingerprint mismatch)",
                        rec.id
                    )));
                }
            }
            (true, None) => {
                return Err(FrfError::new(format!(
                    "replay of {run} FAILED: a new residual appeared on the {} axis that was not in the captured observation",
                    axis.as_str()
                )));
            }
            (false, Some(rec)) => {
                return Err(FrfError::new(format!(
                    "replay of {run} FAILED: recorded residual {} no longer reproduces (the {} axis now agrees)",
                    rec.id,
                    axis.as_str()
                )));
            }
            (false, None) => {}
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
