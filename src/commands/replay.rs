//! `frf replay <RUN_ID | RECEIPT_ID> [--policy exact|semantic]`: a first-class
//! evidence operation.
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
//!
//! Two reproduction policies, never conflated:
//!
//! - **exact** (default): essentially the same execution must reproduce. The
//!   execution profile and applied capture bounds must be identical, the
//!   environment (digest + working directory) must be identical, and every
//!   artifact's interpreter chain — the kernel-invoked executable, the env
//!   resolver, the downstream interpreter, the PATH digest — must re-resolve
//!   to the recorded identities. Any provenance drift REFUSES the replay.
//! - **semantic**: the same bounded observation must reproduce under
//!   admissibly different machinery. Same court question, same
//!   authority/candidate artifacts, same observation bytes — while
//!   provenance differences (environment, interpreter chains, profile,
//!   bounds) are admitted but always REPORTED, so a reproduction under
//!   changed machinery is never silently called "the same execution".

use crate::error::{FrfError, Result};
use crate::host;
use crate::model::*;
use crate::store::Store;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The reproduction policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayPolicy {
    /// Same execution provenance (profile, bounds, environment, interpreter
    /// chains) + same observations. Any drift refuses.
    Exact,
    /// Same court question + same artifacts + same observations; provenance
    /// drift is admitted and reported.
    Semantic,
}

impl ReplayPolicy {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "exact" => Ok(ReplayPolicy::Exact),
            "semantic" => Ok(ReplayPolicy::Semantic),
            other => Err(FrfError::new(format!(
                "unknown replay policy '{other}': use 'exact' (same execution provenance) or 'semantic' (same bounded observation, provenance drift reported)"
            ))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ReplayPolicy::Exact => "exact",
            ReplayPolicy::Semantic => "semantic",
        }
    }
}

fn short(h: &str) -> &str {
    if h.len() >= 8 {
        &h[..8]
    } else {
        h
    }
}

/// The first differing dimension of two interpreter chains, phrased for a
/// drift report.
fn interpreter_drift(
    who: &str,
    recorded: &InterpreterIdentity,
    now: &InterpreterIdentity,
) -> Option<String> {
    if recorded.kernel_interpreter != now.kernel_interpreter {
        Some(format!(
            "{who} kernel interpreter changed: {} {} -> {} {}",
            recorded.kernel_interpreter.path,
            short(&recorded.kernel_interpreter.sha256),
            now.kernel_interpreter.path,
            short(&now.kernel_interpreter.sha256)
        ))
    } else if recorded.downstream_interpreter != now.downstream_interpreter {
        Some(format!(
            "{who} downstream interpreter changed: {} {} -> {} {}",
            recorded.downstream_interpreter.path,
            short(&recorded.downstream_interpreter.sha256),
            now.downstream_interpreter.path,
            short(&now.downstream_interpreter.sha256)
        ))
    } else if recorded.shebang_argument_bytes != now.shebang_argument_bytes {
        Some(format!(
            "{who} shebang arguments changed: {:?} -> {:?}",
            recorded.shebang_argument_bytes, now.shebang_argument_bytes
        ))
    } else if recorded.resolver != now.resolver {
        Some(format!(
            "{who} env resolver changed (recorded {:?}, now {:?})",
            recorded.resolver, now.resolver
        ))
    } else {
        None
    }
}

/// The execution-provenance drift between the captured observation and the
/// current host, as human-actionable lines. Exact replay refuses on any;
/// semantic replay reports them and reproduces the observation anyway.
fn provenance_drift(store: &Store, capture: &CaptureManifest) -> Result<Vec<String>> {
    let mut drift: Vec<String> = Vec::new();

    // The execution profile and the capture bounds that applied.
    if capture.execution_profile != crate::model::EXECUTION_PROFILE_LINUX {
        drift.push(format!(
            "execution profile changed: recorded {}, current engine is {}",
            capture.execution_profile,
            crate::model::EXECUTION_PROFILE_LINUX
        ));
    }
    let bounds_now = host::capture_bounds();
    let bounds_recorded = &capture.capture_bounds;
    for (what, recorded, now) in [
        (
            "timeout_ms",
            &bounds_recorded.timeout_ms,
            &bounds_now.timeout_ms,
        ),
        (
            "max_stream_bytes",
            &bounds_recorded.max_stream_bytes,
            &bounds_now.max_stream_bytes,
        ),
        (
            "rlimit_as_mb",
            &bounds_recorded.rlimit_as_mb,
            &bounds_now.rlimit_as_mb,
        ),
        (
            "rlimit_cpu_s",
            &bounds_recorded.rlimit_cpu_s,
            &bounds_now.rlimit_cpu_s,
        ),
        (
            "rlimit_nofile",
            &bounds_recorded.rlimit_nofile,
            &bounds_now.rlimit_nofile,
        ),
    ] {
        if recorded != now {
            drift.push(format!("capture bound {what} changed: {recorded} -> {now}"));
        }
    }

    // The environment: digest over the output-moving strata, and the working
    // directory the sides ran under.
    let env_now = host::environment_identity();
    if env_now.digest != capture.environment.digest {
        drift.push(format!(
            "environment digest changed: {} -> {} (os/arch/kernel/locale/timezone/umask)",
            short(&capture.environment.digest),
            short(&env_now.digest)
        ));
    }
    if env_now.cwd != capture.environment.cwd {
        drift.push(format!(
            "working directory changed: {:?} -> {:?}",
            capture.environment.cwd, env_now.cwd
        ));
    }

    // Interpreter chains: the artifacts' kernels/resolvers/downstream
    // interpreters re-resolve against the CURRENT host — a changed /usr/bin/
    // bash with an unchanged kernel is a provenance change exact replay must
    // see.
    for (who, artifact) in [
        ("authority", &capture.authority_artifact),
        ("candidate", &capture.candidate_artifact),
    ] {
        let bytes = store.verified_object_bytes(&artifact.sha256)?;
        let now = host::interpreter_identity(&bytes)?;
        match (&artifact.interpreter, now) {
            (Some(recorded), Some(now)) => {
                if let Some(line) = interpreter_drift(who, recorded, &now) {
                    drift.push(line);
                }
            }
            (None, None) => {}
            _ => drift.push(format!("{who} interpreter presence changed")),
        }
    }
    // The comparator instruments' interpreters too: replay re-invokes the
    // exact snapshotted comparator programs.
    for impl_ in &capture.provenance.comparator_implementations {
        let Some(artifact) = &impl_.artifact else {
            continue;
        };
        let bytes = store.verified_object_bytes(&artifact.sha256)?;
        let now = host::interpreter_identity(&bytes)?;
        match (&artifact.interpreter, now) {
            (Some(recorded), Some(now)) => {
                if let Some(line) =
                    interpreter_drift(&format!("comparator {}", impl_.id), recorded, &now)
                {
                    drift.push(line);
                }
            }
            (None, None) => {}
            _ => drift.push(format!(
                "comparator {} interpreter presence changed",
                impl_.id
            )),
        }
    }
    // The normalizer, capture-adapter, and minimizer instruments' interpreters
    // too: replay re-invokes the exact snapshotted normalizers and adapters
    // (the minimizer runs only under `court minimize`, whose reduction record
    // binds the artifact it ran under).
    for implementation in &capture.provenance.normalizer_implementations {
        let Some(artifact) = &implementation.artifact else {
            continue;
        };
        let bytes = store.verified_object_bytes(&artifact.sha256)?;
        let now = host::interpreter_identity(&bytes)?;
        match (&artifact.interpreter, now) {
            (Some(recorded), Some(now)) => {
                if let Some(line) =
                    interpreter_drift(&format!("normalizer {}", implementation.id), recorded, &now)
                {
                    drift.push(line);
                }
            }
            (None, None) => {}
            _ => drift.push(format!(
                "normalizer {} interpreter presence changed",
                implementation.id
            )),
        }
    }
    for implementation in &capture.provenance.adapter_implementations {
        let Some(artifact) = &implementation.artifact else {
            continue;
        };
        let bytes = store.verified_object_bytes(&artifact.sha256)?;
        let now = host::interpreter_identity(&bytes)?;
        match (&artifact.interpreter, now) {
            (Some(recorded), Some(now)) => {
                if let Some(line) = interpreter_drift(
                    &format!("capture adapter {}", implementation.id),
                    recorded,
                    &now,
                ) {
                    drift.push(line);
                }
            }
            (None, None) => {}
            _ => drift.push(format!(
                "capture adapter {} interpreter presence changed",
                implementation.id
            )),
        }
    }

    Ok(drift)
}

/// Replay a run or receipt id from the store. `side_cwd` is the working
/// directory the sides execute under: tree replay passes the invocation cwd
/// (the recorded argv paths resolve against the tree), while bundle replay
/// passes the reconstructed invocation root, so recorded root-relative argv
/// paths resolve to the bundle's own objects — the sides never silently read
/// the surrounding tree.
pub fn run(store: &Store, id: &str, policy_str: &str, side_cwd: &Path) -> Result<()> {
    let policy = ReplayPolicy::parse(policy_str)?;
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
    // The envelope's platforms are part of the court QUESTION (they are in
    // the semantic identity): running out-of-envelope is out-of-question, so
    // this gate applies under BOTH policies.
    let current_platform = format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS);
    let envelope = &capture.court_spec.admissibility_envelope;
    if !envelope.platforms.iter().any(|p| p == &current_platform) {
        return Err(FrfError::new(format!(
            "replay refused: current platform {current_platform} is outside the run's declared envelope {:?}",
            envelope.platforms
        )));
    }

    // -- execution-provenance drift (the exact/semantic distinction) --------
    // Exact replay refuses on any drift; semantic replay reports it and
    // requires the observation to reproduce anyway. The drift is computed
    // BEFORE execution so the reproduction itself is never skipped.
    let drift = provenance_drift(store, &capture)?;
    match policy {
        ReplayPolicy::Exact => {
            if !drift.is_empty() {
                let lines = drift.join("\n  ");
                return Err(FrfError::new(format!(
                    "replay (exact) of {run} refused: the execution provenance changed — the observation is not reproducible under the current host:\n  {lines}"
                )));
            }
        }
        ReplayPolicy::Semantic => {
            for line in &drift {
                eprintln!("replay (semantic): declared provenance difference: {line}");
            }
        }
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
    // The sides run from `side_cwd`: bundle replay reconstructs the
    // invocation root there, so the recorded root-relative argv paths
    // resolve to the bundle's own verified objects. With a produce clause
    // the sides re-write their output trees to the declared (transient)
    // path; the harness re-captures them exactly as the court did.
    let staging = crate::produced::ProducedStaging::new("replay")?;
    let clear_produce = |path: &Path| -> Result<()> {
        if path.exists() {
            if path.is_dir() {
                std::fs::remove_dir_all(path)
                    .map_err(|e| FrfError::new(format!("cannot clear {}: {e}", path.display())))?;
            } else {
                std::fs::remove_file(path)
                    .map_err(|e| FrfError::new(format!("cannot clear {}: {e}", path.display())))?;
            }
        }
        Ok(())
    };
    // The produce path is relative to the sides' working directory.
    let produce_path: Option<PathBuf> = capture
        .court_spec
        .produce
        .as_ref()
        .map(|p| side_cwd.join(&p.path));
    if let Some(prod) = &produce_path {
        clear_produce(prod)?;
    }
    let raw_reference_out =
        host::run_process_in(&authority_snapshot, &capture.arguments, side_cwd)?;
    let reference_produced = if let Some(prod) = &produce_path {
        let files = crate::produced::capture_produced_tree(prod, &staging.dir.join("reference"))?;
        clear_produce(prod)?;
        Some(crate::produced::produced_side(files)?)
    } else {
        None
    };
    let raw_candidate_out =
        host::run_process_in(&candidate_snapshot, &capture.arguments, side_cwd)?;
    let candidate_produced = if let Some(prod) = &produce_path {
        let files = crate::produced::capture_produced_tree(prod, &staging.dir.join("candidate"))?;
        clear_produce(prod)?;
        Some(crate::produced::produced_side(files)?)
    } else {
        None
    };

    // -- the comparison surface: re-apply the declared normalizers -----------
    // A normalizer maps one side's raw streams to the streams the court
    // COMPARED. Replay re-invokes the EXACT snapshotted implementations (the
    // artifact identities the capture bound at observation time), in
    // application order. Under exact replay each rebuilt request must
    // rederive to the recorded request_cid — the raw streams the instrument
    // saw reproduced byte-for-byte; under semantic replay raw-stream drift
    // the normalizer absorbs is admitted, and the normalized surface must
    // still reproduce.
    let normalize_side = |side: &str,
                          raw_outcome: &host::ProcessOutcome|
     -> Result<host::ProcessOutcome> {
        let recorded: Option<Vec<String>> = if policy == ReplayPolicy::Exact {
            let mut cids = Vec::new();
            for semantic in &capture.normalizer_semantics {
                let (invocation, _) = store.load_normalizer_evidence(&run, &semantic.id, side)?;
                cids.push(invocation.request_cid);
            }
            Some(cids)
        } else {
            None
        };
        crate::normalizers::apply_capture_normalizers(
            store,
            &capture,
            side,
            raw_outcome,
            recorded.as_deref(),
            side_cwd,
        )
    };
    let reference_compared = normalize_side("reference", &raw_reference_out)?;
    let candidate_compared = normalize_side("candidate", &raw_candidate_out)?;
    let mut reference = SideCapture::from_outcome(&reference_compared);
    reference.produced = reference_produced;
    let mut candidate = SideCapture::from_outcome(&candidate_compared);
    candidate.produced = candidate_produced;

    // -- the adapted observations: re-invoke the capture adapters ------------
    // An adapter captured one side's ADAPTED observation for its axis from
    // the RAW outcome. Replay re-invokes the exact snapshotted adapter; the
    // adapted payload is attached to the compared side capture, so the
    // observation equality below covers it, and the axis's external
    // comparator request carries it (the raw streams travel alongside as the
    // request evidence).
    for semantic in &capture.adapter_semantics {
        let implementation = capture
            .provenance
            .adapter_implementations
            .iter()
            .find(|i| i.id == semantic.id)
            .ok_or_else(|| {
                FrfError::new(format!(
                    "replay of {run}: the capture carries no implementation for capture adapter {}",
                    semantic.id
                ))
            })?;
        let artifact = implementation.artifact.as_ref().ok_or_else(|| {
            FrfError::new(format!(
                "replay of {run}: capture adapter {} has no snapshotted implementation artifact",
                semantic.id
            ))
        })?;
        let snapshot = crate::comparators::materialize_implementation(store, artifact)?;
        for (side, raw_outcome, compared_side) in [
            ("reference", &raw_reference_out, &mut reference),
            ("candidate", &raw_candidate_out, &mut candidate),
        ] {
            let request = crate::model::CaptureAdapterRequest {
                schema_version: crate::model::SCHEMA_CAPTURE_ADAPTER_REQUEST,
                adapter: semantic,
                side,
                outcome: crate::model::CaptureAdapterOutcome {
                    exit: &raw_outcome.exit,
                    stdout_base64: crate::ext::b64(&raw_outcome.stdout),
                    stderr_base64: crate::ext::b64(&raw_outcome.stderr),
                    produced: None,
                },
                context: crate::model::NormalizerContext {
                    fixture_sha256: &capture.fixture_sha256,
                    arguments: &capture.arguments,
                    environment_digest: &capture.environment.digest,
                },
            };
            let request_bytes = crate::canon::canonical(&request)?.into_bytes();
            let request_cid = crate::ext::request_cid(&request_bytes);
            let (recorded_invocation, _recorded_result) =
                store.load_adapter_evidence(&run, &semantic.id, side)?;
            if policy == ReplayPolicy::Exact && request_cid != recorded_invocation.request_cid {
                return Err(FrfError::new(format!(
                    "replay of {run} FAILED: the capture adapter {} request for the {side} side no longer rederives to the recorded request_cid — the raw outcome differs from what the instrument saw",
                    semantic.id
                )));
            }
            let response_bytes = crate::ext::run_program(&snapshot, &request_bytes, side_cwd)?;
            let response: crate::model::CaptureAdapterResponse =
                serde_json::from_slice(&response_bytes).map_err(|e| {
                    FrfError::new(format!(
                        "capture adapter for axis {} produced an unparseable response: {e}",
                        semantic.id
                    ))
                })?;
            if response.schema_version != crate::model::SCHEMA_CAPTURE_ADAPTER_RESPONSE {
                return Err(FrfError::new(format!(
                    "capture adapter response has unsupported schema version {:?}",
                    response.schema_version
                )));
            }
            if response.request_id != request_cid {
                return Err(FrfError::new(format!(
                    "capture adapter for axis {} does not name the request it answers",
                    semantic.id
                )));
            }
            if response.indeterminate {
                return Err(FrfError::new(format!(
                    "capture adapter for axis {} returned indeterminate; refusing to record inconclusive evidence",
                    semantic.id
                )));
            }
            if let Some(f) = &response.failure {
                return Err(FrfError::new(format!(
                    "capture adapter for axis {} reported failure: {f}",
                    semantic.id
                )));
            }
            compared_side.adapted = response.observation;
        }
    }

    // -- the observation must reproduce byte-for-byte ------------------------
    if reference != capture.reference || candidate != capture.candidate {
        return Err(FrfError::new(format!(
            "replay ({}) of {run} FAILED: the executed sides differ from the captured observation (outputs did not reproduce{})",
            policy.as_str(),
            if drift.is_empty() { String::new() } else { " under declared provenance differences".to_string() }
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
                let divergences = builtin.compare(&reference, &candidate);
                if divergences.is_empty() {
                    crate::comparators::ComparatorOutcome::Equivalent
                } else {
                    crate::comparators::ComparatorOutcome::Divergent(divergences)
                }
            }
            Some(artifact) => {
                // Re-invoke the exact snapshotted comparator on the
                // reproduced sides: replay is a re-observation with the same
                // instrument, not a re-derivation using the built-in logic.
                // The request is built from the same streams the instrument
                // saw — the COMPARED (normalized) streams for a non-adapted
                // axis, the truly raw streams (plus the adapted payloads)
                // for an adapted axis — so its identity must rederive to the
                // recorded request_cid (exact; semantic admits raw-stream
                // drift the normalizer/adapter absorbs and reproduces the
                // surface anyway).
                let (request_ref, request_cand) = if reference.adapted.is_some() {
                    (&raw_reference_out, &raw_candidate_out)
                } else {
                    (&reference_compared, &candidate_compared)
                };
                let request = crate::comparators::build_request(
                    axis.as_str(),
                    semantic,
                    request_ref,
                    request_cand,
                    reference.adapted.as_ref(),
                    candidate.adapted.as_ref(),
                    &capture.fixture_sha256,
                    &capture.arguments,
                    &capture.environment.digest,
                    reference.produced.as_ref().zip(candidate.produced.as_ref()),
                );
                let (request_bytes, request_cid) = crate::comparators::canonical_request(&request)?;
                let evidence = store.load_comparator_evidence(&run, axis.as_str())?;
                if (policy == ReplayPolicy::Exact || reference.adapted.is_none())
                    && request_cid != evidence.invocation.request_cid
                {
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
                    side_cwd,
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

    match policy {
        ReplayPolicy::Exact => println!(
            "replay (exact) {run}: reproduced — sides byte-identical, {} residual(s) with matching fingerprints",
            capture.residuals.len()
        ),
        ReplayPolicy::Semantic => println!(
            "replay (semantic) {run}: reproduced — sides byte-identical, {} residual(s) with matching fingerprints, {} declared provenance difference(s)",
            capture.residuals.len(),
            drift.len()
        ),
    }
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
