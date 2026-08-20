//! `frf court run`: execute authority and candidate against the fixture,
//! capture raw observations immutably, and preserve every declared-axis
//! disagreement as an `open` residual plus its endoduction token.
//!
//! Invariants enforced here:
//! - The admitted authority's file is re-hashed before execution; a drifted
//!   oracle refuses to run (silent oracle drift is prevented, not warned).
//! - Raw captures are written with `create_new` under a content-addressed run
//!   id: identical evidence cannot be re-captured, and nothing is overwritten.
//! - Residuals are written with disposition `open` and no interpretation:
//!   no explanation, no repair, no "who is right".
//! - `{fixture}` substitution is literal; arguments never pass through a shell.

use crate::error::{FrfError, Result};
use crate::host;
use crate::model::*;
use crate::store::Store;
use base64::Engine as _;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

/// Base64 for the comparator extension protocol's raw side streams.
fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// `frf court run [--repeat N] MANIFEST.yaml`.
///
/// One court run executes authority and candidate against the fixture and
/// captures the observation immutably. `--repeat N` re-executes the same
/// court N times (fresh processes each time — nondeterminism is the point),
/// and after the series writes a residual TRAJECTORY per observed divergence
/// fingerprint (`trajectories/<fingerprint>.yaml`): the ordered
/// observations over the `repeat_index` axis plus the deterministic
/// drift/slew classification. Identical repetitions produce identical
/// content-addressed runs and are reused, never re-captured; the returned
/// run id is the first repetition's.
pub fn run(store: &Store, manifest_path: &Path, repeat: u32) -> Result<String> {
    if repeat == 0 {
        return Err(FrfError::new("--repeat must be at least 1"));
    }
    if repeat == 1 {
        return run_once(store, manifest_path, None, None);
    }

    let mut rep_runs: Vec<String> = Vec::with_capacity(repeat as usize);
    // fingerprint -> (axis, per-repetition residual id that observed it)
    let mut seen: BTreeMap<String, (String, Vec<Option<String>>)> = BTreeMap::new();
    for k in 1..=repeat {
        let run = run_once(store, manifest_path, Some(k), Some(repeat))?;
        rep_runs.push(run.clone());
        let capture = store.load_capture(&run)?;
        for id in &capture.residuals {
            let record = store.load_residual(id)?;
            let fp = crate::semantics::residual_fingerprint(&record)?;
            let entry = seen.entry(fp).or_insert_with(|| {
                (
                    record.axis.as_str().to_string(),
                    vec![None; repeat as usize],
                )
            });
            entry.1[k as usize - 1] = Some(id.clone());
        }
    }

    // Trajectories are immutable evidence: identical content is a no-op,
    // different content for the same subject is refused.
    let mut written = 0usize;
    for (fp, (axis, per_rep)) in &seen {
        let observed: Vec<bool> = per_rep.iter().map(|o| o.is_some()).collect();
        let derivation = crate::trajectory::classify_repeat(&observed)?;
        let record = TrajectoryRecord {
            schema_version: SCHEMA_TRAJECTORY.to_string(),
            subject: fp.clone(),
            axis: axis.clone(),
            coordinate_system: "repeat_index".to_string(),
            repeat_count: repeat,
            observations: per_rep
                .iter()
                .enumerate()
                .map(|(i, o)| TrajectoryObservation {
                    repetition: (i + 1) as u32,
                    run: rep_runs[i].clone(),
                    observed: o.is_some(),
                    residual: o.clone(),
                })
                .collect(),
            derivation,
        };
        let path = store.trajectory_path(fp)?;
        let yaml = store.to_yaml(&record)?;
        if path.exists() {
            let existing: TrajectoryRecord = store.parse_yaml(&path)?;
            if existing != record {
                return Err(FrfError::new(format!(
                    "trajectory {} already exists with different content; refusing to rewrite immutable evidence (a trajectory is a snapshot of one repeated court)",
                    &fp[..16]
                )));
            }
        } else {
            store.write_once(&path, &yaml)?;
        }
        written += 1;
        eprintln!(
            "trajectory {} (axis {}, repeat x{repeat}): drift={}, slew={}",
            &fp[..16],
            record.axis,
            record.derivation.drift.as_str(),
            record.derivation.slew.as_str()
        );
    }
    eprintln!(
        "repeated court: {repeat} repetition(s), {} distinct run(s), {written} trajectory(ies)",
        rep_runs
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
    );
    Ok(rep_runs[0].clone())
}

/// One court execution: validate the declaration, snapshot + hash every
/// artifact BEFORE executing, execute authority and candidate against the
/// fixture, capture the raw observation immutably, preserve residuals + κ
/// tokens, and write the capture manifest. `repeat_index`/`repeat_count`
/// record the repetition context when part of a repeated court.
pub fn run_once(
    store: &Store,
    manifest_path: &Path,
    repeat_index: Option<u32>,
    repeat_count: Option<u32>,
) -> Result<String> {
    let manifest: CourtManifest = store.parse_yaml(manifest_path)?;
    let spec = &manifest.court;

    // -- validate the declaration ------------------------------------------

    // The court id becomes a directory-name component (run-{court}-{hash});
    // it must not be able to escape the captures root.
    crate::store::validate_id("court", &spec.id)?;

    let observables: Vec<Axis> = spec
        .admissibility_envelope
        .observables
        .iter()
        .map(|o| Axis::parse(o).map_err(FrfError::new))
        .collect::<Result<_>>()?;

    // External comparator declarations (the extension protocol): each must
    // serve a declared observable axis — a comparator the court did not
    // declare must not run.
    for c in &manifest.comparators {
        if !spec
            .admissibility_envelope
            .observables
            .iter()
            .any(|o| o == &c.axis)
        {
            return Err(FrfError::new(format!(
                "comparator declaration serves axis '{}' which is not in the envelope's observables; refusing to run a comparator the court did not declare",
                c.axis
            )));
        }
        Axis::parse(&c.axis).map_err(FrfError::new)?;
    }

    let authority = store.load_authority(&spec.authority)?;

    // -- fail closed on the admissibility envelope --------------------------
    // Declaration must never masquerade as enforcement: anything the executor
    // does not actually enforce is refused up front.
    let envelope = &spec.admissibility_envelope;
    if !envelope.normalizers.is_empty() {
        return Err(FrfError::new(format!(
            "normalizers are not supported in this version (declared: {:?}); a declared normalizer that is not applied would falsify the evidence — remove the declaration",
            envelope.normalizers
        )));
    }
    if envelope.replay_scope != "single-run" {
        return Err(FrfError::new(format!(
            "replay_scope '{:?}' is not supported: only 'single-run' execution exists, and a declared scope that is not executed would falsify the evidence",
            envelope.replay_scope
        )));
    }
    let current_platform = format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS);
    if !envelope.platforms.iter().any(|p| p == &current_platform) {
        return Err(FrfError::new(format!(
            "current platform {current_platform} is outside the declared envelope {:?}; refusing to run out-of-envelope",
            envelope.platforms
        )));
    }
    if authority.platform != current_platform {
        return Err(FrfError::new(format!(
            "authority {} was admitted for platform {} but this court is running on {current_platform}; refusing to run an out-of-envelope oracle (re-admit on this platform)",
            authority.id, authority.platform
        )));
    }

    // -- read + hash BEFORE any execution -----------------------------------
    //
    // Every artifact is hashed first and executed ONLY through an immutable
    // content-addressed snapshot (`objects/sha256/<H>`, verified on every
    // use, sealed read-only). There is no window in which a path can change
    // between being hashed and being executed: the bytes that ran are the
    // bytes that were hashed, exactly.
    let authority_bytes = host::read_file(Path::new(&authority.path))?;
    let authority_sha256 = host::sha256_bytes(&authority_bytes);
    if authority_sha256 != authority.executable_sha256 {
        return Err(FrfError::new(format!(
            "authority file {} changed since admission ({} != {}); refusing to run against a drifted oracle — admit the new file as a new version",
            authority.path,
            &authority_sha256[..16],
            &authority.executable_sha256[..16]
        )));
    }

    let candidate_path = Path::new(&spec.candidate.path);
    let candidate_bytes = host::read_file(candidate_path)?;
    let candidate_sha256 = host::sha256_bytes(&candidate_bytes);

    let fixture_path = Path::new(&spec.fixture.path);
    let fixture_bytes = host::read_file(fixture_path)?;
    let fixture_sha256 = host::sha256_bytes(&fixture_bytes);

    // -- content-addressed execution snapshots -------------------------------
    // Executed artifacts are sealed 0555; data (fixture) 0444.

    let authority_snapshot = store.materialize_object(&authority_bytes, true)?;
    let candidate_snapshot = store.materialize_object(&candidate_bytes, true)?;
    let fixture_snapshot = store.materialize_object(&fixture_bytes, false)?;

    // Scripts execute under an interpreter; bind it for the exact-artifact
    // claim (binaries yield None).
    let authority_interpreter = host::interpreter_identity(&authority_bytes)?;
    let candidate_interpreter = host::interpreter_identity(&candidate_bytes)?;

    // -- identities, bound NOW (observation time) ----------------------------
    // Two questions, answered separately: WHAT question was asked (semantic
    // identity from comparator SEMANTICS + artifact hashes) and WHO asked it
    // (provenance: runner + comparator implementations). A receipt emitted
    // later copies both; it never reconstructs them from whatever binary or
    // host happens to be installed.
    let environment = host::environment_identity();
    // The comparator SEMANTIC identities: the declared (external) spec for a
    // declared axis, the in-binary registry otherwise. The semantic identity
    // of the QUESTION is built from these — an external program implementing
    // the same spec asks the same question.
    let comparator_semantics: Vec<ComparatorSemantic> = observables
        .iter()
        .map(|axis| {
            match manifest
                .comparators
                .iter()
                .find(|c| c.axis == axis.as_str())
            {
                Some(c) => crate::comparators::declared_semantic(c),
                None => crate::comparators::semantic(axis.as_str()),
            }
        })
        .collect::<Result<_>>()?;
    let runner = RunnerIdentity {
        schema_version: SCHEMA_RUNNER.to_string(),
        frf_version: env!("CARGO_PKG_VERSION").to_string(),
        frf_executable_hash: host::current_exe_hash()?,
    };
    // Comparator IMPLEMENTATION identities + execution hosts. External
    // comparator programs are read + hashed BEFORE any execution and executed
    // through content-addressed snapshots (the same discipline as the
    // artifacts): the bytes that ran are the bytes that were hashed, and the
    // program's digest — not the frf binary's — is its implementation
    // identity. In-binary comparators are implemented by the frf executable.
    let mut external_hosts: Vec<Option<(std::path::PathBuf, ComparatorSemantic)>> = Vec::new();
    let comparator_implementations: Vec<ComparatorImplementation> = observables
        .iter()
        .map(|axis| {
            match manifest
                .comparators
                .iter()
                .find(|c| c.axis == axis.as_str())
            {
                Some(c) => {
                    let bytes = host::read_file(Path::new(&c.program))?;
                    let impl_hash = host::sha256_bytes(&bytes);
                    let snapshot = store.materialize_object(&bytes, true)?;
                    external_hosts
                        .push(Some((snapshot, crate::comparators::declared_semantic(c)?)));
                    Ok(ComparatorImplementation {
                        id: axis.as_str().to_string(),
                        implementation_hash: impl_hash,
                        runner_hash: runner.frf_executable_hash.clone(),
                    })
                }
                None => {
                    external_hosts.push(None);
                    Ok(ComparatorImplementation {
                        id: axis.as_str().to_string(),
                        implementation_hash: runner.frf_executable_hash.clone(),
                        runner_hash: runner.frf_executable_hash.clone(),
                    })
                }
            }
        })
        .collect::<Result<_>>()?;
    let provenance = ObservationProvenance {
        schema_version: SCHEMA_PROVENANCE.to_string(),
        runner: runner.clone(),
        comparator_implementations,
    };
    let court_semantic_identity = crate::semantics::court_semantic_identity(
        spec,
        &authority_sha256,
        &fixture_sha256,
        &comparator_semantics,
    )?;

    // The fixture argument resolves to the SNAPSHOT path: the side reads
    // exactly the hashed bytes, and the recorded arguments are replayable
    // without the original tree.
    let fixture_arg = fixture_snapshot.to_string_lossy().into_owned();
    let arguments: Vec<String> = spec
        .fixture
        .arguments
        .iter()
        .map(|a| {
            if a == "{fixture}" {
                fixture_arg.clone()
            } else {
                a.clone()
            }
        })
        .collect();
    if !arguments.contains(&fixture_arg) {
        eprintln!(
            "frf: warning: fixture {} is not referenced by the declared arguments; this execution does not exercise it",
            spec.fixture.path
        );
    }

    // -- observe both sides ---------------------------------------------------

    let reference_out = host::run_process(&authority_snapshot, &arguments)?;
    let candidate_out = host::run_process(&candidate_snapshot, &arguments)?;

    let reference = SideCapture::from_outcome(&reference_out);
    let candidate = SideCapture::from_outcome(&candidate_out);

    // -- diff the declared axes (Section 12 comparators) -----------------------

    let mut residuals: Vec<ResidualRecord> = Vec::new();
    // Ids are assigned before anything is written, so a run with two
    // text-family residuals (stderr + stdout) must not re-read the disk and
    // hand out the same sequence number twice: track ids already handed out
    // in this run and keep bumping past them.
    let mut pending_seq: std::collections::HashMap<ResidualKind, u32> =
        std::collections::HashMap::new();
    for (idx, axis) in observables.iter().enumerate() {
        // An externally served axis speaks the comparator extension protocol:
        // the raw sides go to the comparator program on stdin (canonical JSON,
        // base64 streams), and its canonical response is interpreted
        // fail-closed. A built-in axis is compared in-process (the reference
        // implementation of the same protocol).
        let projections: Vec<(Option<String>, String, String)> = match &external_hosts[idx] {
            Some((snapshot, semantic)) => {
                let request = ComparatorRequest {
                    schema_version: SCHEMA_COMPARATOR_REQUEST,
                    comparator: semantic,
                    axis: axis.as_str(),
                    reference: ComparatorObservation {
                        exit: &reference.exit,
                        stdout_base64: b64(&reference_out.stdout),
                        stderr_base64: b64(&reference_out.stderr),
                    },
                    candidate: ComparatorObservation {
                        exit: &candidate.exit,
                        stdout_base64: b64(&candidate_out.stdout),
                        stderr_base64: b64(&candidate_out.stderr),
                    },
                    context: ComparatorContext {
                        fixture_sha256: &fixture_sha256,
                        arguments: &arguments,
                        environment_digest: &environment.digest,
                    },
                };
                let request_json = crate::canon::canonical(&request)?;
                let out = host::run_process_with_stdin(snapshot, &[], request_json.as_bytes())?;
                if out.exit != "0" {
                    return Err(FrfError::new(format!(
                            "comparator for axis {} exited {}; refusing to record evidence from a failed comparator",
                            axis.as_str(),
                            out.exit
                        )));
                }
                let response: ComparatorResponse =
                    serde_json::from_slice(&out.stdout).map_err(|e| {
                        FrfError::new(format!(
                            "comparator for axis {} produced an unparseable response: {e}",
                            axis.as_str()
                        ))
                    })?;
                match crate::comparators::interpret(&response).map_err(|e| {
                    FrfError::new(format!("comparator for axis {}: {e}", axis.as_str()))
                })? {
                    crate::comparators::ComparatorOutcome::Equivalent => vec![],
                    crate::comparators::ComparatorOutcome::Divergent(v) => v,
                }
            }
            None => {
                let (raw_ref, raw_cand, surface) = match axis {
                    Axis::Exit => (reference.exit.clone(), candidate.exit.clone(), None),
                    Axis::Stderr => (
                        reference.stderr_first_line.clone(),
                        candidate.stderr_first_line.clone(),
                        Some("first-diagnostic-line".to_string()),
                    ),
                    Axis::Stdout => (
                        reference.stdout_first_line.clone(),
                        candidate.stdout_first_line.clone(),
                        Some("first-stdout-line".to_string()),
                    ),
                };
                if raw_ref != raw_cand {
                    vec![(surface, raw_ref, raw_cand)]
                } else {
                    vec![]
                }
            }
        };
        for (surface, raw_ref, raw_cand) in projections {
            let kind = ResidualKind::from_axis(*axis);
            let seq = match pending_seq.get(&kind) {
                Some(s) => s + 1,
                None => store.next_residual_seq(kind)?,
            };
            pending_seq.insert(kind, seq);
            residuals.push(ResidualRecord {
                schema_version: SCHEMA_RESIDUAL.to_string(),
                id: format!("{}-{}-{:04}", kind.domain_prefix(), kind.as_str(), seq),
                court: spec.id.clone(),
                run: String::new(), // filled once the run id is known
                axis: *axis,
                kind,
                surface,
                authority: authority.id.clone(),
                scope: spec.admissibility_envelope.fixture_family.clone(),
                candidate_sha256: candidate_sha256.clone(),
                raw_reference: raw_ref,
                raw_candidate: raw_cand,
                raw_reference_sha256: String::new(),
                raw_candidate_sha256: String::new(),
            });
        }
    }

    // -- content-address the run ----------------------------------------------
    // Identity discipline: ONE run-identity function, shared with replay,
    // receipt verification, and the verification suite. The preimage is a
    // domain-separated canonical JSON document (FRF/RUN/v1), never a
    // delimiter-assembled string; a name is a claim until it is recomputed.
    let pre = crate::semantics::RunPreimage {
        court: &spec.id,
        authority: &authority.id,
        authority_interpreter: authority_interpreter
            .as_ref()
            .map(|i| i.downstream_interpreter.sha256.as_str()),
        // The candidate NAME is a label and deliberately absent: the
        // candidate_sha256 is the identity. (It is still recorded in the
        // capture's court_spec as metadata.)
        candidate_sha256: &candidate_sha256,
        candidate_interpreter: candidate_interpreter
            .as_ref()
            .map(|i| i.downstream_interpreter.sha256.as_str()),
        fixture_sha256: &fixture_sha256,
        arguments: &arguments,
        environment_digest: &environment.digest,
        runner_hash: &runner.frf_executable_hash,
        court_semantic_identity: &court_semantic_identity,
        reference: &reference,
        candidate: &candidate,
        residuals: &residuals,
    };
    let run_hash = crate::semantics::run_identity(&pre)?;
    let run = format!("run-{}-{}", spec.id, run_hash);
    let run_dir = store.run_dir(&run)?;
    if run_dir.exists() {
        if repeat_count.is_some() {
            // A repeated court re-observed identical evidence: the
            // content-addressed run IS the same run. Reuse it — raw captures
            // are immutable, and identical evidence is captured once however
            // often it is asked for.
            eprintln!(
                "repetition {}: identical evidence already captured as {run}; reusing",
                repeat_index.unwrap_or(1)
            );
            return Ok(run);
        }
        return Err(FrfError::new(format!(
            "run '{run}' already exists (identical evidence was already captured); raw captures are immutable — refusing to re-capture"
        )));
    }

    // -- write raw captures (immutable) ----------------------------------------

    std::fs::create_dir(&run_dir)
        .map_err(|e| FrfError::new(format!("cannot create {}: {e}", run_dir.display())))?;
    write_side_files(&run_dir, "reference", &reference_out, &reference)?;
    write_side_files(&run_dir, "candidate", &candidate_out, &candidate)?;

    // Fill in run id + axis hashes, then persist the immutable observation
    // records and their (open) endoduction tokens.
    for r in &mut residuals {
        r.run = run.clone();
        r.raw_reference_sha256 = host::sha256_bytes(r.raw_reference.as_bytes());
        r.raw_candidate_sha256 = host::sha256_bytes(r.raw_candidate.as_bytes());
        let yaml = store.to_yaml(r)?;
        store.write_once(&store.residual_path(&r.id)?, &yaml)?;
        store.write_token(r, &Disposition::Open)?;
        let token = crate::kappa::kappa(r, &Disposition::Open);
        eprintln!(
            "residual {} ({}) open: reference={} candidate={} -> token {} -> {}",
            r.id,
            r.kind.as_str(),
            r.raw_reference,
            r.raw_candidate,
            token.token,
            token.next_court
        );
    }

    let rel_to_root = |p: &Path| {
        p.strip_prefix(&store.root)
            .map(|r| r.to_string_lossy().into_owned())
            .unwrap_or_else(|_| p.to_string_lossy().into_owned())
    };

    // -- capture manifest --------------------------------------------------------

    let capture = CaptureManifest {
        schema_version: SCHEMA_CAPTURE.to_string(),
        run: run.clone(),
        court: spec.id.clone(),
        authority: authority.id.clone(),
        manifest: manifest_path.to_string_lossy().into_owned(),
        fixture: spec.fixture.id.clone(),
        fixture_sha256,
        arguments,
        environment,
        court_spec: spec.clone(),
        comparator_semantics,
        provenance,
        // Artifact paths are ROOT-relative pointers (stable across machines);
        // the capture's `arguments` are the verbatim argv the side received.
        authority_artifact: ArtifactIdentity {
            path: rel_to_root(&authority_snapshot),
            sha256: authority_sha256,
            interpreter: authority_interpreter,
        },
        candidate_artifact: ArtifactIdentity {
            path: rel_to_root(&candidate_snapshot),
            sha256: candidate_sha256,
            interpreter: candidate_interpreter,
        },
        court_semantic_identity,
        reference,
        candidate,
        residuals: residuals.iter().map(|r| r.id.clone()).collect(),
        repeat_index,
        repeat_count,
    };
    let yaml = store.to_yaml(&capture)?;
    store.write_once(&run_dir.join("capture.yaml"), &yaml)?;

    eprintln!(
        "court {} run: captures, residuals, and tokens written under {}",
        spec.id,
        run_dir.display()
    );
    Ok(run)
}

impl SideCapture {
    pub(crate) fn from_outcome(outcome: &host::ProcessOutcome) -> SideCapture {
        let first_line = |bytes: &[u8]| -> String {
            String::from_utf8_lossy(bytes)
                .split('\n')
                .next()
                .unwrap_or("")
                .to_string()
        };
        let stderr_first_line = first_line(&outcome.stderr);
        let stdout_first_line = first_line(&outcome.stdout);
        SideCapture {
            exit: outcome.exit.clone(),
            exit_sha256: host::sha256_bytes(outcome.exit.as_bytes()),
            stderr_first_line: stderr_first_line.clone(),
            stderr_first_line_sha256: host::sha256_bytes(stderr_first_line.as_bytes()),
            stdout_first_line: stdout_first_line.clone(),
            stdout_first_line_sha256: host::sha256_bytes(stdout_first_line.as_bytes()),
            stdout_sha256: host::sha256_bytes(&outcome.stdout),
            stderr_sha256: host::sha256_bytes(&outcome.stderr),
        }
    }
}

/// Raw bytes of stdout/stderr and the compared projections (exit code, first
/// stderr line) as plain text. All files are created with `create_new`.
fn write_side_files(
    run_dir: &Path,
    side: &str,
    outcome: &host::ProcessOutcome,
    capture: &SideCapture,
) -> Result<()> {
    for (name, bytes) in [("stdout", &outcome.stdout), ("stderr", &outcome.stderr)] {
        write_once(run_dir.join(format!("{side}.{name}")), bytes)?;
    }
    for (name, text) in [
        ("exit", &capture.exit),
        ("stderr_first_line", &capture.stderr_first_line),
        ("stdout_first_line", &capture.stdout_first_line),
    ] {
        write_once(
            run_dir.join(format!("{side}.{name}.txt")),
            format!("{text}\n").as_bytes(),
        )?;
    }
    Ok(())
}

fn write_once(path: std::path::PathBuf, bytes: &[u8]) -> Result<()> {
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(mut f) => f
            .write_all(bytes)
            .and_then(|_| f.flush())
            .map_err(|e| FrfError::new(format!("cannot write {}: {e}", path.display()))),
        Err(e) => Err(FrfError::new(format!(
            "cannot create {}: {e}",
            path.display()
        ))),
    }
}
