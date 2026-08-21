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

/// The series options of `frf court run`. Exactly one may be set; absent,
/// the court is single-run.
#[derive(Debug, Clone, Default)]
pub struct SeriesOptions {
    /// `--repeat N` (N >= 2): the `repeat_index` axis.
    pub repeat: Option<u32>,
    /// `--candidate-revisions P1,P2,...` (>= 2): the `candidate_revision`
    /// axis — one run per candidate artifact.
    pub candidate_revisions: Option<Vec<String>>,
    /// `--authority-versions V1,V2,...` (>= 2): the `authority_version`
    /// axis — one run per admitted authority version.
    pub authority_versions: Option<Vec<String>>,
    /// `--environment-point LABEL`: the `environment` axis — this run is one
    /// point of the environment experiment at the given coordinate.
    pub environment_point: Option<String>,
    /// `--time-point LABEL`: the `time` axis — this run is one point of the
    /// time experiment at the given coordinate.
    pub time_point: Option<String>,
}

impl SeriesOptions {
    /// The coordinate system, or `None` for a single run.
    fn coordinate_system(&self) -> Option<&'static str> {
        if self.repeat.is_some() {
            Some("repeat_index")
        } else if self.candidate_revisions.is_some() {
            Some("candidate_revision")
        } else if self.authority_versions.is_some() {
            Some("authority_version")
        } else if self.environment_point.is_some() {
            Some("environment")
        } else if self.time_point.is_some() {
            Some("time")
        } else {
            None
        }
    }
}

/// `frf court run MANIFEST.yaml [--repeat N] [--candidate-revisions …]
/// [--authority-versions …] [--environment-point LABEL] [--time-point LABEL]`.
///
/// A single run executes authority and candidate against the fixture and
/// captures the observation immutably. A SERIES court re-executes the same
/// experiment over a declared coordinate system (`repeat_index`,
/// `candidate_revision`, `authority_version`, `environment`, `time`), writes
/// an [`ExecutionSeries`] record (`series/`, content-addressed — every append
/// is a new snapshot), and DERIVES one residual TRAJECTORY per observed
/// lineage (`trajectories/<lineage>.<coord>.<series>.yaml`): the ordered
/// observations plus the deterministic drift/slew/localization/bands
/// classification. Runs never know which experiment references them; the
/// series references the runs.
pub fn run(store: &Store, manifest_path: &Path, opts: &SeriesOptions) -> Result<String> {
    let mut set = 0;
    if opts.repeat.is_some() {
        set += 1;
    }
    if opts.candidate_revisions.is_some() {
        set += 1;
    }
    if opts.authority_versions.is_some() {
        set += 1;
    }
    if opts.environment_point.is_some() {
        set += 1;
    }
    if opts.time_point.is_some() {
        set += 1;
    }
    if set > 1 {
        return Err(FrfError::new(
            "at most one series axis may be declared (--repeat, --candidate-revisions, --authority-versions, --environment-point, --time-point are mutually exclusive)",
        ));
    }

    // The single run: no series.
    let Some(coordinate_system) = opts.coordinate_system() else {
        return run_once(store, manifest_path, None, None, false);
    };

    // A single repetition is a single run: one point cannot observe drift or
    // slew, and the paper's restraint is kept (receipts say not-observed).
    if opts.repeat == Some(1) {
        return run_once(store, manifest_path, None, None, false);
    }

    let manifest: CourtManifest = store.parse_yaml(manifest_path)?;
    let court_id = manifest.court.id.clone();

    // -- build the ordered points -------------------------------------------
    let mut points: Vec<SeriesPoint> = Vec::new();
    let mut first_run: Option<String> = None;
    match coordinate_system {
        "repeat_index" => {
            let n = opts.repeat.unwrap();
            for k in 1..=n {
                let run = run_once(store, manifest_path, None, None, true)?;
                first_run.get_or_insert_with(|| run.clone());
                points.push(SeriesPoint {
                    point_index: k,
                    coordinate: k.to_string(),
                    run,
                });
            }
        }
        "candidate_revision" => {
            let revisions = opts.candidate_revisions.as_ref().unwrap();
            if revisions.len() < 2 {
                return Err(FrfError::new(
                    "--candidate-revisions needs at least two revisions (one point cannot observe drift or slew)",
                ));
            }
            for (i, path) in revisions.iter().enumerate() {
                let run = run_once(store, manifest_path, Some(path), None, true)?;
                first_run.get_or_insert_with(|| run.clone());
                points.push(SeriesPoint {
                    point_index: (i + 1) as u32,
                    coordinate: path.clone(),
                    run,
                });
            }
        }
        "authority_version" => {
            let versions = opts.authority_versions.as_ref().unwrap();
            if versions.len() < 2 {
                return Err(FrfError::new(
                    "--authority-versions needs at least two versions (one point cannot observe drift or slew)",
                ));
            }
            // The authority NAME comes from the manifest's admitted authority;
            // each point runs {name}-{version}. Every version must already be
            // admitted — fail fast before executing any point.
            let authority = store.load_authority(&manifest.court.authority)?;
            for version in versions {
                store.load_authority(&format!("{}-{}", authority.name, version))?;
            }
            for (i, version) in versions.iter().enumerate() {
                let run = run_once(store, manifest_path, None, Some(version), true)?;
                first_run.get_or_insert_with(|| run.clone());
                points.push(SeriesPoint {
                    point_index: (i + 1) as u32,
                    coordinate: version.clone(),
                    run,
                });
            }
        }
        "environment" | "time" => {
            let label = if coordinate_system == "environment" {
                opts.environment_point.as_ref().unwrap().clone()
            } else {
                opts.time_point.as_ref().unwrap().clone()
            };
            let run = run_once(store, manifest_path, None, None, true)?;
            first_run = Some(run.clone());
            // Accumulate: the previous series snapshot for this experiment
            // (court, coordinate system), if any, then append this point.
            let mut prior: Vec<SeriesPoint> = Vec::new();
            let mut max_index = 0u32;
            let dir = store.root.join("series");
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if !name.ends_with(".yaml") {
                        continue;
                    }
                    let series = store.load_series(name.trim_end_matches(".yaml"))?;
                    if series.court != court_id || series.coordinate_system != coordinate_system {
                        continue;
                    }
                    // The latest snapshot: the one with the most points.
                    if series.points.len() > prior.len() {
                        prior = series.points.clone();
                        max_index = series
                            .points
                            .iter()
                            .map(|p| p.point_index)
                            .max()
                            .unwrap_or(0);
                    }
                }
            }
            let index = max_index + 1;
            // The same run must not be appended twice (identical evidence).
            if prior.iter().all(|p| p.run != run) {
                prior.push(SeriesPoint {
                    point_index: index,
                    coordinate: label.clone(),
                    run: run.clone(),
                });
            }
            points = prior;
        }
        _ => unreachable!("coordinate system validated by the CLI"),
    }

    if points.is_empty() {
        return Err(FrfError::new("series court produced no points"));
    }

    // -- the series record (content-addressed; an append is a NEW snapshot) --
    let id = crate::semantics::series_identity(&court_id, coordinate_system, &points)?;
    let series = ExecutionSeries {
        schema_version: SCHEMA_SERIES.to_string(),
        id,
        court: court_id.clone(),
        coordinate_system: coordinate_system.to_string(),
        points: points.clone(),
    };
    store.write_series(&series)?;

    // -- derive one trajectory per observed lineage --------------------------
    let written = derive_trajectories(store, &series)?;
    eprintln!(
        "series {}: {} point(s), {} distinct run(s), {written} trajectory(ies)",
        coordinate_system,
        points.len(),
        points
            .iter()
            .map(|p| p.run.clone())
            .collect::<std::collections::HashSet<_>>()
            .len()
    );
    Ok(first_run.unwrap())
}

/// Derive one trajectory per lineage observed in the series. Trajectories
/// are DERIVED projections of the series (regenerable from the immutable
/// runs), so re-derivation overwrites — the runs never change.
fn derive_trajectories(store: &Store, series: &ExecutionSeries) -> Result<usize> {
    /// Per-point observation of one lineage: (residual id, fingerprint).
    type Observed = Vec<Option<(String, String)>>;
    // lineage -> (axis, per-point observation)
    let mut seen: BTreeMap<String, (String, Observed)> = BTreeMap::new();
    for (i, point) in series.points.iter().enumerate() {
        let capture = store.load_capture(&point.run)?;
        for id in &capture.residuals {
            let record = store.load_residual(id)?;
            let fp = crate::semantics::residual_fingerprint(&record)?;
            let lineage = crate::semantics::residual_lineage_of_record(store, &record)?;
            let entry = seen.entry(lineage).or_insert_with(|| {
                (
                    record.axis.as_str().to_string(),
                    vec![None; series.points.len()],
                )
            });
            entry.1[i] = Some((id.clone(), fp));
        }
    }

    let mut written = 0usize;
    for (lineage, (axis, per_point)) in &seen {
        let observed: Vec<bool> = per_point.iter().map(|o| o.is_some()).collect();
        let derivation = crate::trajectory::classify(&observed)?;
        let record = TrajectoryRecord {
            schema_version: SCHEMA_TRAJECTORY.to_string(),
            subject: lineage.clone(),
            axis: axis.clone(),
            coordinate_system: series.coordinate_system.clone(),
            series: series.id.clone(),
            observations: per_point
                .iter()
                .enumerate()
                .map(|(i, o)| TrajectoryObservation {
                    point_index: series.points[i].point_index,
                    coordinate: series.points[i].coordinate.clone(),
                    run: series.points[i].run.clone(),
                    observed: o.is_some(),
                    residual: o.as_ref().map(|(r, _)| r.clone()),
                    fingerprint: o.as_ref().map(|(_, f)| f.clone()),
                })
                .collect(),
            derivation,
        };
        let path = store.trajectory_path(lineage, &series.coordinate_system, &series.id)?;
        store.write_derived(&path, &store.to_yaml(&record)?)?;
        written += 1;
        eprintln!(
            "trajectory {} (axis {}, {} x{}): drift={}, slew={}, localization={}, bands={}",
            &lineage[..16],
            record.axis,
            record.coordinate_system,
            record.observations.len(),
            record.derivation.drift.as_str(),
            record.derivation.slew.as_str(),
            record.derivation.localization.as_str(),
            record.derivation.bands
        );
    }
    Ok(written)
}

/// One court execution: validate the declaration, snapshot + hash every
/// artifact BEFORE executing, execute authority and candidate against the
/// fixture, capture the raw observation immutably, preserve residuals + κ
/// tokens, and write the capture manifest. `candidate_override` replaces the
/// manifest's candidate path (a `candidate_revision` series point);
/// `authority_version_override` replaces the authority version (an
/// `authority_version` series point — the authority must be admitted under
/// the manifest's authority NAME). A run never knows the series that
/// references it.
pub fn run_once(
    store: &Store,
    manifest_path: &Path,
    candidate_override: Option<&str>,
    authority_version_override: Option<&str>,
    reuse: bool,
) -> Result<String> {
    let mut manifest: CourtManifest = store.parse_yaml(manifest_path)?;
    if let Some(path) = candidate_override {
        manifest.court.candidate.path = path.to_string();
    }
    if let Some(version) = authority_version_override {
        let authority = store.load_authority(&manifest.court.authority)?;
        manifest.court.authority = format!("{}-{}", authority.name, version);
    }
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
        if reuse {
            // A series court re-observed identical evidence: the
            // content-addressed run IS the same run. Reuse it — raw captures
            // are immutable, and identical evidence is captured once however
            // often it is asked for; the series point references the run.
            eprintln!("identical evidence already captured as {run}; reusing");
            return Ok(run);
        }
        return Err(FrfError::new(format!(
            "run '{run}' already exists (identical evidence was already captured); raw captures are immutable — refusing to re-capture (use a series axis to re-observe deliberately)"
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
