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
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

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
    /// `--series-parent SERIES_ID`: explicitly choose the branch to extend
    /// when appending to an environment/time experiment (required when the
    /// experiment has branched into multiple heads).
    pub series_parent: Option<String>,
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
        return run_once(store, manifest_path, None, None, false, None);
    };

    // A single repetition is a single run: one point cannot observe drift or
    // slew, and the paper's restraint is kept (receipts say not-observed).
    if opts.repeat == Some(1) {
        return run_once(store, manifest_path, None, None, false, None);
    }

    let manifest: CourtManifest = store.parse_yaml(manifest_path)?;
    let court_id = manifest.court.id.clone();

    // The declared environment coordinate for an `--environment-point` run:
    // the label must name a declared coordinate (a label is not evidence
    // unless the environment it names is), and the point's effective
    // environment is the court's declared environment with the coordinate's
    // vars applied.
    let point_environment: Option<std::collections::BTreeMap<String, String>> = opts
        .environment_point
        .as_ref()
        .map(|label| {
            let points = manifest.court.environment_points.clone().unwrap_or_default();
            points.get(label).cloned().ok_or_else(|| {
                FrfError::new(format!(
                    "--environment-point {label:?} is not declared in the manifest's environment_points — a coordinate label is not evidence unless the environment it names is declared"
                ))
            })
        })
        .transpose()?;

    // -- build the ordered points -------------------------------------------
    let mut points: Vec<SeriesPoint> = Vec::new();
    let mut first_run: Option<String> = None;
    // The parent snapshot of the new series record (environment/time
    // experiments accumulate; the one-shot axes write a fresh snapshot).
    let mut parent_series_id: Option<String> = None;
    match coordinate_system {
        "repeat_index" => {
            let n = opts.repeat.unwrap();
            for k in 1..=n {
                let run = run_once(store, manifest_path, None, None, true, None)?;
                first_run.get_or_insert_with(|| run.clone());
                points.push(SeriesPoint {
                    point_index: k.to_string(),
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
                let run = run_once(store, manifest_path, Some(path), None, true, None)?;
                first_run.get_or_insert_with(|| run.clone());
                points.push(SeriesPoint {
                    point_index: (i + 1).to_string(),
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
                let run = run_once(store, manifest_path, None, Some(version), true, None)?;
                first_run.get_or_insert_with(|| run.clone());
                points.push(SeriesPoint {
                    point_index: (i + 1).to_string(),
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
            let run = run_once(
                store,
                manifest_path,
                None,
                None,
                true,
                point_environment.as_ref(),
            )?;
            first_run = Some(run.clone());
            // Accumulate: the experiment's history is a parent-linked chain
            // of immutable series snapshots. The append target is the unique
            // HEAD of the experiment; a branched experiment (two heads) has
            // no unambiguous append target and an implicit append is
            // refused — the caller must choose the branch with
            // `--series-parent`.
            let experiment_id = format!("{court_id}-{coordinate_system}");
            let heads = store.experiment_heads(&experiment_id)?;
            let parent: Option<String> = match (heads.as_slice(), opts.series_parent.as_deref()) {
                ([], None) => None,
                ([head], None) => Some(head.id.clone()),
                (heads, None) => {
                    return Err(FrfError::new(format!(
                        "the experiment {experiment_id} has branched: {} head(s) ({}) — an implicit append has no unambiguous target; pass --series-parent <series-id> to choose the branch",
                        heads.len(),
                        heads
                            .iter()
                            .map(|h| &h.id[..16])
                            .collect::<Vec<_>>()
                            .join(", ")
                    )));
                }
                (_, Some(chosen)) => {
                    let series = store.load_series(chosen)?;
                    if series.experiment_id != experiment_id {
                        return Err(FrfError::new(format!(
                            "--series-parent {chosen} belongs to experiment {} not {experiment_id}; refusing to append across experiments",
                            series.experiment_id
                        )));
                    }
                    Some(chosen.to_string())
                }
            };
            let prior: Vec<SeriesPoint> = match &parent {
                Some(p) => store.load_series(p)?.points.clone(),
                None => Vec::new(),
            };
            let index = prior
                .iter()
                .filter_map(|p| p.point_index.parse::<u32>().ok())
                .max()
                .unwrap_or(0)
                + 1;
            let index = index.to_string();
            // Every observation event is a point: multiple coordinates may
            // reference the SAME content-addressed run (identical evidence
            // shares the run, but each coordinate at which an observation
            // occurred is recorded — deduplicating would destroy the
            // persistence information precisely when the system is stable).
            points = prior;
            points.push(SeriesPoint {
                point_index: index,
                coordinate: label.clone(),
                run: run.clone(),
            });
            parent_series_id = parent;
        }
        _ => unreachable!("coordinate system validated by the CLI"),
    }

    if points.is_empty() {
        return Err(FrfError::new("series court produced no points"));
    }

    // -- the series record (content-addressed; an append is a NEW snapshot
    //    parent-linked into the experiment's immutable history) --------------
    let experiment_id = format!("{court_id}-{coordinate_system}");
    let id = crate::semantics::series_identity(
        &experiment_id,
        parent_series_id.as_deref(),
        &court_id,
        coordinate_system,
        &points,
    )?;
    let series = ExecutionSeries {
        schema_version: SCHEMA_SERIES.to_string(),
        id,
        experiment_id: experiment_id.clone(),
        parent_series_id: parent_series_id.clone(),
        court: court_id.clone(),
        coordinate_system: coordinate_system.to_string(),
        points: points.clone(),
    };
    store.write_series(&series)?;

    // -- derive one trajectory per observed lineage --------------------------
    let written = derive_trajectories(store, &series)?;
    eprintln!(
        "series {}: {} point(s), {} distinct run(s), parent {}, {written} trajectory(ies)",
        coordinate_system,
        points.len(),
        points
            .iter()
            .map(|p| p.run.clone())
            .collect::<std::collections::HashSet<_>>()
            .len(),
        parent_series_id
            .as_deref()
            .map(|p| &p[..16])
            .unwrap_or("none")
    );
    Ok(first_run.unwrap())
}

/// Derive one trajectory per lineage observed in the series. Trajectories
/// are DERIVED projections of the series (regenerable from the immutable
/// runs), so re-derivation overwrites — the runs never change. Every
/// observation consumed here is VERIFIED first: a series point's run is a
/// verified capture (identity rederives), and each residual is a verified
/// observation of that run (derivation re-proven) before its fingerprint,
/// lineage, or magnitude may drive the classification.
fn derive_trajectories(store: &Store, series: &ExecutionSeries) -> Result<usize> {
    /// Per-point observation of one lineage: (residual id, fingerprint,
    /// magnitude).
    type Observed = Vec<Option<(String, String, Option<String>)>>;
    // lineage -> (axis, per-point observation)
    let mut seen: BTreeMap<String, (String, Observed)> = BTreeMap::new();
    for (i, point) in series.points.iter().enumerate() {
        let capture = crate::verify::load_capture_verified(store, &point.run)?;
        for id in &capture.capture.residuals {
            let record = crate::verify::load_residual_verified(store, id)?;
            let record = record.record();
            let fp = crate::semantics::residual_fingerprint(record)?;
            let lineage = crate::semantics::residual_lineage_of_record(store, record)?;
            // The divergence DEGREE at this point (v4): the axis's declared
            // magnitude measure applied to the compared projections — the
            // deterministic input to the `gradual` vocabulary.
            let magnitude = crate::comparators::divergence_magnitude(
                record.axis.as_str(),
                &record.raw_reference,
                &record.raw_candidate,
            );
            let entry = seen.entry(lineage).or_insert_with(|| {
                (
                    record.axis.as_str().to_string(),
                    vec![None; series.points.len()],
                )
            });
            entry.1[i] = Some((id.clone(), fp, magnitude));
        }
    }

    let mut written = 0usize;
    for (lineage, (axis, per_point)) in &seen {
        let observed: Vec<bool> = per_point.iter().map(|o| o.is_some()).collect();
        let magnitudes: Vec<Option<String>> = per_point
            .iter()
            .map(|o| o.as_ref().and_then(|(_, _, m)| m.clone()))
            .collect();
        let kind = crate::comparators::magnitude_kind(axis);
        let derivation =
            crate::trajectory::classify(&observed, &series.coordinate_system, &magnitudes, &kind)?;
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
                    point_index: series.points[i].point_index.clone(),
                    coordinate: series.points[i].coordinate.clone(),
                    run: series.points[i].run.clone(),
                    observed: o.is_some(),
                    residual: o.as_ref().map(|(r, _, _)| r.clone()),
                    fingerprint: o.as_ref().map(|(_, f, _)| f.clone()),
                    magnitude: o.as_ref().and_then(|(_, _, m)| m.clone()),
                })
                .collect(),
            derivation,
        };
        let path = store.trajectory_path(lineage, &series.coordinate_system, &series.id)?;
        store.write_derived(&path, &store.to_evidence(&record)?)?;
        written += 1;
        eprintln!(
            "trajectory {} (axis {}, {} x{}): drift={}, slew={}, localization={}, bands={}, trend={}",
            &lineage[..16],
            record.axis,
            record.coordinate_system,
            record.observations.len(),
            record.derivation.drift.as_str(),
            record.derivation.slew.as_str(),
            record.derivation.localization.as_str(),
            record.derivation.bands,
            record.derivation.trend.as_str()
        );
    }
    Ok(written)
}

/// The attempt budget for one minimization: ddmin is O(n log n) executions;
/// a bounded budget keeps a hostile or enormous fixture from hanging the
/// tool, and the derivation honestly records whether minimality was proven.
const MINIMIZE_MAX_ATTEMPTS: usize = 256;

/// `frf court minimize RESIDUAL_ID` — the routed minimizer. The residual's κ
/// token routes `cli-exit-minimize`/`cli-diagnostic-minimize`; this version
/// implements ONE deterministic reducer (ddmin over fixture lines) that both
/// routes share. The transform is declared, not assumed: only the FIXTURE
/// may change; the candidate artifact, authority artifact, environment, and
/// the comparator SEMANTIC + IMPLEMENTATION that observed the residual are
/// each bound by identity in the record, and preservation is decided by THE
/// ONE evaluation operation — the same comparator that generated the
/// original evidence (the built-in implementation in-process, the exact
/// snapshotted external program re-invoked). Every executable attempt is
/// recorded in a content-addressed [`ReductionRecord`] (`reductions/`) with
/// its role, outcome, and acceptance; the attempt budget is a HARD gate
/// around every execution; the final reproducer is court-verified.
pub fn minimize(store: &Store, residual_id: &str) -> Result<String> {
    // The residual is VERIFIED before anything may consume it: identity +
    // derivation from its verified parent run. The reduction's transform
    // declaration is read from verified evidence, never from raw records.
    let verified = crate::verify::load_residual_verified(store, residual_id)?;
    let record = verified.record();
    let capture = &verified.capture().capture;

    // The fixture being reduced: the exact bytes the residual's run used.
    let fixture_bytes = store.verified_object_bytes(&capture.fixture_sha256)?;
    let fixture_text = String::from_utf8(fixture_bytes.clone()).map_err(|_| {
        FrfError::new(format!(
            "residual {residual_id}: the fixture is not UTF-8 text; this version's reducer is ddmin over text lines (binary reducers are future domain reducers)"
        ))
    })?;
    let original_lines = fixture_text.lines().count().to_string();
    if original_lines == "0" {
        return Err(FrfError::new(format!(
            "residual {residual_id}: the fixture is empty; there is nothing to reduce"
        )));
    }

    // The execution recipe: snapshotted authority + candidate (the exact
    // artifacts the run executed), the resolved argv with the fixture slot.
    // The executed images are the SEALED verified bytes (verify→execute race
    // closed): the snapshot paths remain argv[0] and the evidence paths.
    let authority_program = store.root.join(&capture.authority_artifact.path);
    let candidate_program = store.root.join(&capture.candidate_artifact.path);
    let authority_bytes = store.verified_object_bytes(&capture.authority_artifact.sha256)?;
    let candidate_bytes = store.verified_object_bytes(&capture.candidate_artifact.sha256)?;
    let authority_image = host::ExecImage::seal(
        &authority_bytes,
        &capture.authority_artifact.sha256,
        &authority_program,
    )?;
    let candidate_image = host::ExecImage::seal(
        &candidate_bytes,
        &capture.candidate_artifact.sha256,
        &candidate_program,
    )?;
    let original_fixture_arg = store
        .root
        .join("objects")
        .join("sha256")
        .join(&capture.fixture_sha256)
        .to_string_lossy()
        .into_owned();

    // The evaluation plan of the residual's axis — the SAME plan the court
    // bound at observation time (semantic + implementation). Preservation is
    // decided by [`crate::comparators::evaluate`], nothing else.
    let plan = crate::comparators::EvaluationPlan::from_capture(capture, &record.axis)?;
    let environment_digest = capture.environment.digest.clone();
    // The harness contract the residual was observed under: a reduction
    // re-executes both sides under the SAME declared profile (a v2
    // observation cannot be reduced under an approximated envelope).
    let profile = host::ExecProfile::parse(&capture.execution_profile)?;

    // The routed minimizer (the extension protocol, spec/minimizer.md): the
    // residual's κ route names the reducer that may serve it. A declared
    // minimizer for that route is an EXTERNAL program the court bound at
    // observation time; the core COURT-VERIFIES its proposal with the one
    // comparison operation. No declaration = the built-in ddmin reducer.
    let route = crate::kappa::token_shape(&record.axis).next_court;
    if let Some(semantic) = capture.minimizer_semantics.iter().find(|m| m.id == route) {
        return minimize_external(
            store,
            capture,
            record,
            semantic,
            &fixture_bytes,
            original_lines,
            &plan,
            &authority_image,
            &candidate_image,
            &original_fixture_arg,
            &environment_digest,
            profile,
        );
    }

    let mut attempts: Vec<ReductionAttempt> = Vec::new();

    // The initial check: the ORIGINAL fixture must reproduce the lineage
    // under the minimizer's own comparison (if it does not, the reduction
    // cannot even start — fail closed). A baseline is never an accepted
    // reduction (nothing shrank).
    let baseline = run_attempt(
        store,
        capture,
        &plan,
        &authority_image,
        &candidate_image,
        &original_fixture_arg,
        &environment_digest,
        &fixture_bytes,
        ReductionAttemptRole::Baseline,
        false,
        &mut attempts,
        residual_id,
        profile,
    )?
    .ok_or_else(|| {
        FrfError::new(format!(
            "minimization of {residual_id}: the attempt budget was exhausted by the baseline check"
        ))
    })?;
    if baseline != ReductionAttemptOutcome::Preserved {
        return Err(FrfError::new(format!(
            "residual {residual_id}: the original fixture does not reproduce the {} divergence under this comparator; refusing to minimize",
            record.axis.as_str()
        )));
    }

    // Deterministic ddmin over lines (Zeller). Elements are lines WITH their
    // trailing newline, so joining them reproduces the file byte-for-byte.
    let mut elements: Vec<Vec<u8>> = split_keep_newlines(&fixture_text);
    let mut minimal_proven = true;
    let mut n = 2usize;
    'outer: while elements.len() >= 2 && attempts.len() < MINIMIZE_MAX_ATTEMPTS {
        let chunk_size = (elements.len() / n).max(1);
        let mut reduced_any = false;
        let mut start = 0usize;
        while start < elements.len() && attempts.len() < MINIMIZE_MAX_ATTEMPTS {
            let end = (start + chunk_size).min(elements.len());
            let mut candidate: Vec<Vec<u8>> = elements[..start].to_vec();
            candidate.extend_from_slice(&elements[end..]);
            let candidate_bytes: Vec<u8> = candidate.concat();
            let outcome = run_attempt(
                store,
                capture,
                &plan,
                &authority_image,
                &candidate_image,
                &original_fixture_arg,
                &environment_digest,
                &candidate_bytes,
                ReductionAttemptRole::Candidate,
                false,
                &mut attempts,
                residual_id,
                profile,
            )?;
            let Some(outcome) = outcome else {
                break 'outer; // budget exhausted — the gate sits around the execution
            };
            let shrank = !candidate_bytes.is_empty() && candidate.len() < elements.len();
            if outcome == ReductionAttemptOutcome::Preserved && shrank {
                // The reduction was KEPT: preserved AND the fixture shrank.
                elements = candidate;
                if let Some(last) = attempts.last_mut() {
                    last.accepted = true;
                }
                reduced_any = true;
                n = n.saturating_sub(1).max(2);
                break;
            }
            start += chunk_size;
        }
        if !reduced_any {
            if n >= elements.len() {
                break;
            }
            n = (n * 2).min(elements.len());
        }
    }
    if attempts.len() >= MINIMIZE_MAX_ATTEMPTS && elements.len() >= 2 {
        minimal_proven = false;
    }

    let final_bytes: Vec<u8> = elements.concat();
    let final_sha = host::sha256_bytes(&final_bytes);
    let final_lines = elements.len().to_string();

    // The final reproducer is court-verified (the last attempt that kept it
    // ran it); a final explicit confirmation keeps the record honest even
    // when the budget cut the search short. The budget gates this execution
    // too: if it is exhausted the record cannot claim a verified reproducer.
    let outcome = run_attempt(
        store,
        capture,
        &plan,
        &authority_image,
        &candidate_image,
        &original_fixture_arg,
        &environment_digest,
        &final_bytes,
        ReductionAttemptRole::FinalVerification,
        false,
        &mut attempts,
        residual_id,
        profile,
    )?
    .ok_or_else(|| {
        FrfError::new(format!(
            "minimization of {residual_id}: the attempt budget was exhausted before the final reproducer could be court-verified; re-run with a larger budget"
        ))
    })?;
    if outcome != ReductionAttemptOutcome::Preserved {
        return Err(FrfError::new(format!(
            "residual {residual_id}: internal error — the final reproducer does not reproduce the lineage"
        )));
    }
    if let Some(last) = attempts.last_mut() {
        last.accepted = true;
    }

    let derivation = ReductionDerivation {
        strategy: "ddmin-lines".to_string(),
        original_lines,
        final_lines,
        minimality: ReductionMinimality {
            kind: "one-minimal".to_string(),
            granularity: "line".to_string(),
            proven: minimal_proven,
        },
    };
    let transform = EvidenceTransform::reduction(residual_id, &plan.semantic.relation_label());
    let id = crate::semantics::reduction_identity(
        residual_id,
        &record.run,
        record.axis.as_str(),
        record.kind.clone(),
        &capture.court_semantic_identity,
        &capture.authority_artifact.sha256,
        &capture.candidate_artifact.sha256,
        &capture.environment.digest,
        &plan.semantic.id,
        &plan.semantic.specification_hash,
        &plan.implementation.implementation_hash,
        &capture.arguments,
        &capture.fixture_sha256,
        &final_sha,
        &attempts,
        &derivation,
        &transform,
        None, // the built-in ddmin reducer binds no external minimizer
    )?;
    let reduction = ReductionRecord {
        schema_version: SCHEMA_REDUCTION.to_string(),
        id: id.clone(),
        residual_id: residual_id.to_string(),
        source_run: record.run.clone(),
        axis: record.axis.as_str().to_string(),
        kind: record.kind.clone(),
        court_semantic_identity: capture.court_semantic_identity.clone(),
        authority_artifact_sha256: capture.authority_artifact.sha256.clone(),
        candidate_artifact_sha256: capture.candidate_artifact.sha256.clone(),
        environment_digest,
        comparator_semantic_id: plan.semantic.id.clone(),
        comparator_semantic_hash: plan.semantic.specification_hash.clone(),
        comparator_implementation_hash: plan.implementation.implementation_hash.clone(),
        argv_template: capture.arguments.clone(),
        original_fixture_sha256: capture.fixture_sha256.clone(),
        final_fixture_sha256: final_sha.clone(),
        attempts,
        derivation: derivation.clone(),
        transform: transform.clone(),
        minimizer_semantic_id: None,
        minimizer_semantic_hash: None,
        minimizer_implementation_hash: None,
        minimizer_implementation_artifact: None,
        minimizer_invocation_id: None,
        minimizer_result_id: None,
    };
    store.write_reduction(&reduction)?;

    eprintln!(
        "reduction {}: {} -> {} line(s) (ddmin, {} attempt(s), minimality {}/{} proven={}); reproducer object {}",
        &id[..16],
        derivation.original_lines,
        derivation.final_lines,
        reduction.attempts.len(),
        derivation.minimality.kind,
        derivation.minimality.granularity,
        derivation.minimality.proven,
        &final_sha[..16]
    );
    Ok(id)
}

/// Run one executable fixture attempt during a minimization: materialize the
/// fixture, execute both sides, re-apply the declared normalizers (the
/// COMPARISON SURFACE — the same surface the court compared), evaluate the
/// residual's axis through THE ONE comparison operation, and record the
/// attempt with its role/outcome/acceptance. The budget is a HARD gate
/// around EVERY executable attempt; a harness failure aborts the
/// minimization, never silently skipped. Returns `None` when the budget is
/// exhausted.
#[allow(clippy::too_many_arguments)] // one argument per evidence dimension; the doc is the protocol shape
fn run_attempt(
    store: &Store,
    capture: &CaptureManifest,
    plan: &crate::comparators::EvaluationPlan,
    authority_image: &host::ExecImage,
    candidate_image: &host::ExecImage,
    original_fixture_arg: &str,
    environment_digest: &str,
    bytes: &[u8],
    role: ReductionAttemptRole,
    accepted: bool,
    attempts: &mut Vec<ReductionAttempt>,
    what: &str,
    profile: host::ExecProfile,
) -> Result<Option<ReductionAttemptOutcome>> {
    if attempts.len() >= MINIMIZE_MAX_ATTEMPTS {
        return Ok(None);
    }
    let sha = host::sha256_bytes(bytes);
    let fixture_snapshot = store.materialize_object(bytes, false)?;
    let fixture_arg = fixture_snapshot.to_string_lossy().into_owned();
    let arguments: Vec<String> = capture
        .arguments
        .iter()
        .map(|a| {
            if a == original_fixture_arg {
                fixture_arg.clone()
            } else {
                a.clone()
            }
        })
        .collect();
    let raw_reference_out = host::run_process(
        authority_image,
        &arguments,
        profile,
        &capture.environment.environment,
    )?;
    let raw_candidate_out = host::run_process(
        candidate_image,
        &arguments,
        profile,
        &capture.environment.environment,
    )?;
    // The comparison surface is the NORMALIZED streams: re-apply the exact
    // snapshotted normalizers the court bound (a fresh attempt is a NEW
    // observation — its requests are not checked against the run's evidence).
    let reference_out = crate::normalizers::apply_capture_normalizers(
        store,
        capture,
        "reference",
        &raw_reference_out,
        None,
        std::path::Path::new("."),
        profile,
        &capture.environment.environment,
    )?;
    let candidate_out = crate::normalizers::apply_capture_normalizers(
        store,
        capture,
        "candidate",
        &raw_candidate_out,
        None,
        std::path::Path::new("."),
        profile,
        &capture.environment.environment,
    )?;
    let reference = SideCapture::from_outcome(&reference_out);
    let candidate = SideCapture::from_outcome(&candidate_out);
    let context = crate::comparators::EvaluationContext {
        fixture_sha256: &sha,
        arguments: &arguments,
        environment_digest,
        produced: None,
        cwd: std::path::Path::new("."),
        raw: Some((&raw_reference_out, &raw_candidate_out)),
        compared: Some((&reference_out, &candidate_out)),
        profile,
        env: &capture.environment.environment,
    };
    let evaluation = crate::comparators::evaluate(store, plan, &reference, &candidate, &context);
    let (outcome, recordable) = match evaluation {
        Ok(e) => (
            if matches!(e.result, crate::comparators::EvaluationResult::Divergent(_)) {
                ReductionAttemptOutcome::Preserved
            } else {
                ReductionAttemptOutcome::Lost
            },
            true,
        ),
        Err(e) => {
            attempts.push(ReductionAttempt {
                attempt: (attempts.len() + 1).to_string(),
                role,
                fixture_sha256: sha,
                outcome: ReductionAttemptOutcome::HarnessFailure,
                accepted: false,
            });
            return Err(FrfError::new(format!(
                "minimization of {what} aborted: an executable attempt could not be evaluated: {e}"
            )));
        }
    };
    if recordable {
        attempts.push(ReductionAttempt {
            attempt: (attempts.len() + 1).to_string(),
            role,
            fixture_sha256: sha,
            outcome,
            accepted,
        });
    }
    Ok(Some(outcome))
}

/// The EXTERNAL minimizer path (the extension protocol, spec/minimizer.md):
/// the residual's κ route is served by a declared minimizer whose program the
/// court bound at observation time. The minimizer proposes a reduced fixture;
/// the core COURT-VERIFIES it with the one comparison operation — a proposal
/// that does not preserve the lineage is recorded-but-not-accepted (the
/// refusal is itself evidence, content-addressed under the residual), and a
/// proposal that cannot be evaluated aborts as a harness failure. The
/// accepted reduction binds the minimizer's semantic + implementation
/// identities and the content-addressed invocation + result records.
#[allow(clippy::too_many_arguments)] // one argument per evidence dimension; the doc is the protocol shape
fn minimize_external(
    store: &Store,
    capture: &CaptureManifest,
    record: &ResidualRecord,
    semantic: &MinimizerSemantic,
    fixture_bytes: &[u8],
    original_lines: String,
    plan: &crate::comparators::EvaluationPlan,
    authority_image: &host::ExecImage,
    candidate_image: &host::ExecImage,
    original_fixture_arg: &str,
    environment_digest: &str,
    profile: host::ExecProfile,
) -> Result<String> {
    let residual_id = record.id.clone();
    let implementation = capture
        .provenance
        .minimizer_implementations
        .iter()
        .find(|i| i.id == semantic.id)
        .ok_or_else(|| {
            FrfError::new(format!(
                "residual {residual_id}: the capture carries no implementation for minimizer {}",
                semantic.id
            ))
        })?;
    let artifact = implementation.artifact.as_ref().ok_or_else(|| {
        FrfError::new(format!(
            "residual {residual_id}: minimizer {} has no snapshotted implementation artifact",
            semantic.id
        ))
    })?;
    let snapshot = crate::comparators::materialize_implementation(store, artifact)?;

    // The canonical minimizer request: the residual + the original fixture
    // (base64) + the proposal budget the core will honor. The response must
    // cryptographically name the request it answers.
    let request = MinimizerRequest {
        schema_version: crate::model::SCHEMA_MINIMIZER_REQUEST,
        minimizer: semantic,
        residual: MinimizerResidual {
            id: &record.id,
            axis: record.axis.as_str(),
            kind: record.kind.as_str(),
            authority: &record.authority,
            candidate_sha256: &record.candidate_sha256,
        },
        fixture: MinimizerFixture {
            sha256: &capture.fixture_sha256,
            raw_base64: crate::ext::b64(fixture_bytes),
        },
        budget: MINIMIZE_MAX_ATTEMPTS.to_string(),
        context: MinimizerContext {
            court_semantic_identity: &capture.court_semantic_identity,
            environment_digest,
        },
    };
    let request_bytes = crate::canon::canonical(&request)?.into_bytes();
    let request_cid = crate::ext::request_cid(&request_bytes);
    let response_bytes = crate::ext::run_program(
        &snapshot,
        &request_bytes,
        std::path::Path::new("."),
        profile,
        &capture.environment.environment,
    )?;
    // The protocol says canonical JSON: the response must BE its own
    // canonical serialization.
    let response: MinimizerResponse =
        crate::ext::parse_canonical_response(&response_bytes, "minimizer response")
            .map_err(|e| FrfError::new(format!("minimizer {}: {e}", semantic.id)))?;
    if response.schema_version != crate::model::SCHEMA_MINIMIZER_RESPONSE {
        return Err(FrfError::new(format!(
            "minimizer response has unsupported schema version {:?}",
            response.schema_version
        )));
    }
    if response.request_id != request_cid {
        return Err(FrfError::new(format!(
            "minimizer {} does not name the request it answers",
            semantic.id
        )));
    }
    if response.indeterminate {
        return Err(FrfError::new(format!(
            "minimizer {} returned indeterminate; refusing to record inconclusive evidence",
            semantic.id
        )));
    }
    if let Some(f) = &response.failure {
        return Err(FrfError::new(format!(
            "minimizer {} reported failure: {f}",
            semantic.id
        )));
    }
    let proposal_bytes = crate::ext::unb64(&response.fixture_base64, "proposed fixture")?;
    let proposal_sha = host::sha256_bytes(&proposal_bytes);
    if proposal_sha != response.fixture_sha256 {
        return Err(FrfError::new(format!(
            "minimizer {} proposed a fixture that does not hash to its declared sha256; refusing to court-verify a self-contradictory proposal",
            semantic.id
        )));
    }
    if proposal_bytes == fixture_bytes {
        return Err(FrfError::new(format!(
            "minimizer {} proposed the original fixture; nothing was reduced",
            semantic.id
        )));
    }

    let mut attempts: Vec<ReductionAttempt> = Vec::new();
    // The baseline: the ORIGINAL fixture must reproduce the lineage (as in
    // the built-in reducer) before any proposal is even considered.
    let baseline = run_attempt(
        store,
        capture,
        plan,
        authority_image,
        candidate_image,
        original_fixture_arg,
        environment_digest,
        fixture_bytes,
        ReductionAttemptRole::Baseline,
        false,
        &mut attempts,
        &residual_id,
        profile,
    )?
    .ok_or_else(|| {
        FrfError::new(format!(
            "minimization of {residual_id}: the attempt budget was exhausted by the baseline check"
        ))
    })?;
    if baseline != ReductionAttemptOutcome::Preserved {
        return Err(FrfError::new(format!(
            "residual {residual_id}: the original fixture does not reproduce the {} divergence under this comparator; refusing to minimize",
            record.axis.as_str()
        )));
    }

    // Court-verify the proposal: THE comparison operation decides, never the
    // minimizer's claim. This is the only other executable attempt.
    let outcome = run_attempt(
        store,
        capture,
        plan,
        authority_image,
        candidate_image,
        original_fixture_arg,
        environment_digest,
        &proposal_bytes,
        ReductionAttemptRole::FinalVerification,
        false,
        &mut attempts,
        &residual_id,
        profile,
    )?
    .ok_or_else(|| {
        FrfError::new(format!(
            "minimization of {residual_id}: the attempt budget was exhausted before the proposed fixture could be court-verified"
        ))
    })?;

    let response_cid = crate::host::sha256_bytes(&response_bytes);
    let invocation = MinimizerInvocation {
        schema_version: crate::model::SCHEMA_MINIMIZER_INVOCATION.to_string(),
        invocation_id: crate::semantics::minimizer_invocation_identity(
            &crate::semantics::MinimizerInvocationContent {
                minimizer_id: &semantic.id,
                residual_id: &record.id,
                request_cid: &request_cid,
                minimizer_semantic_cid: &semantic.specification_hash,
                minimizer_implementation_artifact: artifact,
                execution_provenance: &capture.provenance.runner,
            },
        )?,
        minimizer_id: semantic.id.clone(),
        residual_id: record.id.clone(),
        request_cid: request_cid.clone(),
        minimizer_semantic_cid: semantic.specification_hash.clone(),
        minimizer_implementation_artifact: artifact.clone(),
        execution_provenance: capture.provenance.runner.clone(),
    };
    let court_verified = outcome == ReductionAttemptOutcome::Preserved;
    let result = MinimizerResult {
        schema_version: crate::model::SCHEMA_MINIMIZER_RESULT.to_string(),
        result_id: crate::semantics::minimizer_result_identity(
            &crate::semantics::MinimizerResultContent {
                request_cid: &request_cid,
                response_cid: &response_cid,
                proposed_fixture_sha256: &proposal_sha,
                court_verified,
            },
        )?,
        invocation_id: invocation.invocation_id.clone(),
        request_cid,
        response_cid,
        proposed_fixture_sha256: proposal_sha.clone(),
        court_verified,
        outcome: if court_verified {
            "accepted".to_string()
        } else {
            "rejected".to_string()
        },
    };

    if !court_verified {
        // Recorded-but-not-accepted: the proposal failed court verification.
        // The refusal is itself evidence — the canonical request/response +
        // invocation + result are preserved, content-addressed by the request,
        // under the residual.
        let dir = store
            .residual_path(&record.id)?
            .parent()
            .expect("residual path has a parent")
            .join(format!("{}.minimizer", record.id))
            .join(&result.request_cid);
        crate::ext::write_evidence(
            store,
            &dir,
            &request_bytes,
            &response_bytes,
            &serde_json::to_value(&invocation).map_err(|e| {
                FrfError::new(format!("cannot serialize the minimizer invocation: {e}"))
            })?,
            &serde_json::to_value(&result).map_err(|e| {
                FrfError::new(format!("cannot serialize the minimizer result: {e}"))
            })?,
        )?;
        return Err(FrfError::new(format!(
            "minimizer {} proposed fixture {} which does not preserve the {} lineage under court verification; the proposal was recorded but NOT accepted — no reduction produced",
            semantic.id,
            &proposal_sha[..16],
            record.axis.as_str()
        )));
    }

    // Accepted: the proposal is the court-verified minimal reproducer.
    if let Some(last) = attempts.last_mut() {
        last.accepted = true;
    }
    let final_sha = proposal_sha;
    let final_text = String::from_utf8(proposal_bytes.clone()).map_err(|_| {
        FrfError::new(format!(
            "minimizer {} proposed a non-UTF-8 fixture; this version's derivation records line counts (text reducers only)",
            semantic.id
        ))
    })?;
    let final_lines = final_text.lines().count().to_string();

    let derivation = ReductionDerivation {
        strategy: format!("external:{}", semantic.relation_id),
        original_lines,
        final_lines,
        minimality: ReductionMinimality {
            kind: "one-minimal".to_string(),
            granularity: "line".to_string(),
            // The minimizer's own claim, recorded as claimed; the final
            // proposal's survival is independently court-verified above.
            proven: response.minimal,
        },
    };
    let transform = EvidenceTransform::reduction(&record.id, &plan.semantic.relation_label());
    let id = crate::semantics::reduction_identity(
        &record.id,
        &record.run,
        record.axis.as_str(),
        record.kind.clone(),
        &capture.court_semantic_identity,
        &capture.authority_artifact.sha256,
        &capture.candidate_artifact.sha256,
        environment_digest,
        &plan.semantic.id,
        &plan.semantic.specification_hash,
        &plan.implementation.implementation_hash,
        &capture.arguments,
        &capture.fixture_sha256,
        &final_sha,
        &attempts,
        &derivation,
        &transform,
        Some((
            &semantic.id,
            &semantic.specification_hash,
            &implementation.implementation_hash,
            artifact,
            &invocation.invocation_id,
            &result.result_id,
        )),
    )?;
    let reduction = ReductionRecord {
        schema_version: SCHEMA_REDUCTION.to_string(),
        id: id.clone(),
        residual_id: record.id.clone(),
        source_run: record.run.clone(),
        axis: record.axis.as_str().to_string(),
        kind: record.kind.clone(),
        court_semantic_identity: capture.court_semantic_identity.clone(),
        authority_artifact_sha256: capture.authority_artifact.sha256.clone(),
        candidate_artifact_sha256: capture.candidate_artifact.sha256.clone(),
        environment_digest: environment_digest.to_string(),
        comparator_semantic_id: plan.semantic.id.clone(),
        comparator_semantic_hash: plan.semantic.specification_hash.clone(),
        comparator_implementation_hash: plan.implementation.implementation_hash.clone(),
        argv_template: capture.arguments.clone(),
        original_fixture_sha256: capture.fixture_sha256.clone(),
        final_fixture_sha256: final_sha.clone(),
        attempts,
        derivation: derivation.clone(),
        transform: transform.clone(),
        minimizer_semantic_id: Some(semantic.id.clone()),
        minimizer_semantic_hash: Some(semantic.specification_hash.clone()),
        minimizer_implementation_hash: Some(implementation.implementation_hash.clone()),
        minimizer_implementation_artifact: Some(artifact.clone()),
        minimizer_invocation_id: Some(invocation.invocation_id.clone()),
        minimizer_result_id: Some(result.result_id.clone()),
    };
    // The minimizer's invocation evidence lives under the reduction, bound by
    // the record; then the record itself (content-addressed, write-once).
    crate::ext::write_evidence(
        store,
        &store.minimizer_dir(&id)?,
        &request_bytes,
        &response_bytes,
        &serde_json::to_value(&invocation).map_err(|e| {
            FrfError::new(format!("cannot serialize the minimizer invocation: {e}"))
        })?,
        &serde_json::to_value(&result)
            .map_err(|e| FrfError::new(format!("cannot serialize the minimizer result: {e}")))?,
    )?;
    store.write_reduction(&reduction)?;

    eprintln!(
        "reduction {}: {} -> {} line(s) (external minimizer {}, {} attempt(s), minimality proven={}, court-verified); reproducer object {}",
        &id[..16],
        derivation.original_lines,
        derivation.final_lines,
        semantic.id,
        reduction.attempts.len(),
        derivation.minimality.proven,
        &final_sha[..16]
    );
    Ok(id)
}

/// Split text into lines KEEPING the trailing newline, so concatenation
/// reproduces the file byte-for-byte.
fn split_keep_newlines(text: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(idx) = rest.find('\n') {
        out.push(rest.as_bytes()[..=idx].to_vec());
        rest = &rest[idx + 1..];
    }
    if !rest.is_empty() {
        out.push(rest.as_bytes().to_vec());
    }
    out
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
    point_environment: Option<&std::collections::BTreeMap<String, String>>,
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

    // The DECLARED EXECUTION ENVIRONMENT: the exact environment every
    // program this court executes runs under (the sides AND every extension
    // program), built from scratch — the ambient host environment is never
    // inherited. An environment point's vars override the base declaration.
    let mut declared_environment: std::collections::BTreeMap<String, String> =
        spec.environment.clone().unwrap_or_default();
    if let Some(point) = point_environment {
        for (k, v) in point {
            declared_environment.insert(k.clone(), v.clone());
        }
    }

    // -- validate the declaration ------------------------------------------

    // The court id becomes a directory-name component (run-{court}-{hash});
    // it must not be able to escape the captures root.
    crate::store::validate_id("court", &spec.id)?;

    // Observable axes are PROTOCOL IDENTIFIERS, not a closed enum: any valid
    // id may be declared (dns.wire, filesystem.tree, …), but every declared
    // observable must be SERVED by a comparator — a built-in registry row or
    // an external declaration — and duplicates are refused (observing the
    // same axis twice would manufacture two records for one comparison).
    let observables: Vec<ObservableId> = spec
        .admissibility_envelope
        .observables
        .iter()
        .map(|o| ObservableId::parse(o))
        .collect::<Result<_>>()?;
    let mut seen_obs: Vec<&str> = Vec::new();
    for o in &observables {
        if seen_obs.contains(&o.as_str()) {
            return Err(FrfError::new(format!(
                "duplicate observable axis '{}' in the envelope; an axis may be observed once per run",
                o.as_str()
            )));
        }
        seen_obs.push(o.as_str());
    }

    // External comparator declarations (the extension protocol): each must
    // serve a declared observable axis — a comparator the court did not
    // declare must not run — and every externally served axis must carry a
    // valid residual classifier.
    for c in &manifest.comparators {
        if !observables.iter().any(|o| o.as_str() == c.axis) {
            return Err(FrfError::new(format!(
                "comparator declaration serves axis '{}' which is not in the envelope's observables; refusing to run a comparator the court did not declare",
                c.axis
            )));
        }
        ResidualKind::parse(&c.residual_classifier)?;
    }
    // Every declared observable must be SERVED: by a declaration, or by the
    // in-binary registry. An observable with no comparator cannot be
    // compared — refuse rather than silently skip it.
    for o in &observables {
        let declared = manifest.comparators.iter().any(|c| c.axis == o.as_str());
        if !declared && crate::comparators::spec_for(o.as_str()).is_none() {
            return Err(FrfError::new(format!(
                "no comparator serves observable axis '{}': it is not a built-in (exit, stderr, stdout) and no external comparator is declared for it (see spec/comparator.md)",
                o.as_str()
            )));
        }
    }

    // The DECLARED execution profile (spec/execution-profile.md): the
    // harness contract the sides and every extension program run under.
    // Absent = the reference profile. The profile is ENFORCED, never
    // approximated — `frf-exec-linux-v2` requires a writable cgroup v2
    // subtree and refuses without one.
    let profile = host::ExecProfile::parse(
        spec.execution_profile
            .as_deref()
            .unwrap_or(crate::model::EXECUTION_PROFILE_LINUX),
    )?;

    let authority = store.load_authority(&spec.authority)?;

    // -- fail closed on the admissibility envelope --------------------------
    // Declaration must never masquerade as enforcement: anything the executor
    // does not actually enforce is refused up front.
    let envelope = &spec.admissibility_envelope;

    // -- the normalizer extension protocol (spec/normalizer.md) --------------
    // The envelope's `normalizers` list names exactly the declared normalizer
    // ids that are APPLIED, in application order. Fail closed both ways: an
    // applied normalizer that is not declared would run unverifiable code; a
    // declared normalizer that is not applied would make the declaration a
    // lie. The set must match exactly; the order is the envelope's.
    for id in &envelope.normalizers {
        crate::store::validate_id("normalizer", id)?;
        if !manifest.normalizers.iter().any(|n| &n.id == id) {
            return Err(FrfError::new(format!(
                "the envelope applies normalizer {id:?} but no normalizer with that id is declared in the manifest; refusing to run unverifiable normalization"
            )));
        }
    }
    let mut seen_normalizer: Vec<&str> = Vec::new();
    for n in &manifest.normalizers {
        crate::store::validate_id("normalizer", &n.id)?;
        if seen_normalizer.contains(&n.id.as_str()) {
            return Err(FrfError::new(format!(
                "duplicate normalizer id '{}' in the manifest; a normalizer is applied at most once per side",
                n.id
            )));
        }
        seen_normalizer.push(&n.id);
        if !matches!(n.applies_to.as_str(), "stdout" | "stderr" | "both") {
            return Err(FrfError::new(format!(
                "normalizer {} declares applies_to {:?}; the protocol admits stdout, stderr, or both",
                n.id, n.applies_to
            )));
        }
        if !envelope.normalizers.iter().any(|id| id == &n.id) {
            return Err(FrfError::new(format!(
                "normalizer {} is declared but the envelope does not apply it; a declared normalizer that is not applied would falsify the evidence — apply it or remove the declaration",
                n.id
            )));
        }
    }

    // -- the capture-adapter extension protocol (spec/capture-adapter.md) ----
    // An adapter serves ONE externally served observable axis: it captures
    // the observation (dns.wire, sql.schema, …) the external comparator
    // consumes. An adapted axis MUST be served by an external comparator (the
    // adapter defines the observation format; no built-in knows it), and an
    // axis may have at most one adapter.
    let mut seen_adapter: Vec<&str> = Vec::new();
    for a in &manifest.capture_adapters {
        crate::store::validate_id("capture-adapter", &a.axis)?;
        if !observables.iter().any(|o| o.as_str() == a.axis) {
            return Err(FrfError::new(format!(
                "capture adapter serves axis '{}' which is not in the envelope's observables; refusing to capture an axis the court did not declare",
                a.axis
            )));
        }
        if seen_adapter.contains(&a.axis.as_str()) {
            return Err(FrfError::new(format!(
                "duplicate capture adapter for axis '{}'; an axis has at most one capture",
                a.axis
            )));
        }
        seen_adapter.push(&a.axis);
        let externally_served = manifest.comparators.iter().any(|c| c.axis == a.axis);
        if !externally_served {
            return Err(FrfError::new(format!(
                "capture adapter serves axis '{}' but no external comparator is declared for it; an adapted observation has a format only its comparator knows — declare the comparator",
                a.axis
            )));
        }
    }

    // -- the minimizer extension protocol (spec/minimizer.md) ----------------
    // Declared minimizers serve κ routes; each id must be a valid identifier
    // and unique. Resolution happens at `frf court minimize` time against
    // this run's capture.
    let mut seen_minimizer: Vec<&str> = Vec::new();
    for m in &manifest.minimizers {
        crate::store::validate_id("minimizer", &m.id)?;
        if seen_minimizer.contains(&m.id.as_str()) {
            return Err(FrfError::new(format!(
                "duplicate minimizer id '{}' in the manifest; one minimizer per κ route",
                m.id
            )));
        }
        seen_minimizer.push(&m.id);
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

    // -- the produced-artifact clause (the filesystem-tree surface) -----------
    // When the court declares `produce`, the sides write their OUTPUT to the
    // declared path (transient: cleared between sides, captured immutably
    // into the run). The path must be a contained relative path.
    let produce_path: Option<PathBuf> = match &spec.produce {
        Some(p) => {
            let path = Path::new(&p.path);
            if path.is_absolute()
                || path
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                return Err(FrfError::new(format!(
                    "produce path {:?} must be a contained relative path (no absolute path, no '..')",
                    p.path
                )));
            }
            Some(path.to_path_buf())
        }
        None => None,
    };
    // The built-in filesystem.tree axis observes PRODUCED artifacts; a court
    // declaring it without a produce clause would compare two empty trees.
    for axis in &observables {
        if axis.as_str() == "filesystem.tree" && produce_path.is_none() {
            return Err(FrfError::new(
                "the filesystem.tree axis observes produced artifacts; the court must declare `produce` (the output directory each side writes)",
            ));
        }
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

    // The executed images are the SEALED verified bytes, not the snapshot
    // paths: the same-OS-user verify→execute race is closed — the bytes that
    // were hashed are the bytes that exec (a memfd sealed read-only, executed
    // via /proc/self/fd/<n>). The snapshot path remains argv[0] and the
    // evidence path; only the executed IMAGE is the sealed object.
    let authority_image =
        host::ExecImage::seal(&authority_bytes, &authority_sha256, &authority_snapshot)?;
    let candidate_image =
        host::ExecImage::seal(&candidate_bytes, &candidate_sha256, &candidate_snapshot)?;

    // Scripts execute under an interpreter; bind it for the exact-artifact
    // claim (binaries yield None). A NATIVE (ELF) artifact binds its runtime
    // closure instead: the dynamic loader + the resolved dependency closure,
    // hashed at observation time (executable hash is not executable
    // semantics — spec/execution-profile.md). The closure is resolved for
    // the SNAPSHOT path the side actually executes. The native runtime
    // closure resolves against the SEALED EXEC PATH (the loader sees
    // `/proc/self/fd/<n>` at exec time), never the materialized snapshot
    // path: `$ORIGIN`-relative dependencies resolve exactly as the loader
    // resolves them when the side runs — a dependency the sealed mechanism
    // cannot find is a REFUSAL (the artifact cannot load under the profile's
    // sealed execution).
    let authority_interpreter = host::interpreter_identity(&authority_bytes)?;
    let authority_native =
        crate::native::runtime_closure(authority_image.path(), &authority_bytes)?;
    let candidate_interpreter = host::interpreter_identity(&candidate_bytes)?;
    let candidate_native =
        crate::native::runtime_closure(candidate_image.path(), &candidate_bytes)?;

    // -- the DECLARED execution-context closure -----------------------------
    // The court declares the child executables / runtime libraries / data
    // dependencies the side's execution depends on beyond its own bytes.
    // Each declared artifact is snapshotted and content-addressed at
    // observation time (relative paths resolve against the working
    // directory, absolute paths against the host), and the closure is
    // recorded in the capture — a declared dependency is bound to the exact
    // bytes, never assumed. The closure is a DECLARED context, never a
    // measured file-access trace (spec/execution-profile.md).
    let mut execution_context_refs: Vec<EvidenceRef> = Vec::new();
    let execution_context: Option<ExecutionContextClosure> = if let Some(decl) =
        &spec.execution_context
    {
        let mut artifacts: Vec<ExecutionContextArtifact> = Vec::new();
        for a in &decl.artifacts {
            let executable = match a.role.as_str() {
                "child-executable" => true,
                "runtime-library" | "data" => false,
                other => {
                    return Err(FrfError::new(format!(
                            "execution-context artifact {} declares role {other:?}; the protocol admits child-executable, runtime-library, or data",
                            a.path
                        )));
                }
            };
            let path = Path::new(&a.path);
            let resolved = if path.is_absolute() {
                path.to_path_buf()
            } else {
                std::env::current_dir()
                    .map_err(|e| {
                        FrfError::new(format!("cannot resolve the working directory: {e}"))
                    })?
                    .join(path)
            };
            let bytes = host::read_file(&resolved).map_err(|e| {
                FrfError::new(format!(
                    "execution-context artifact {} cannot be read (resolved {}): {e}",
                    a.path,
                    resolved.display()
                ))
            })?;
            let sha = host::sha256_bytes(&bytes);
            store.materialize_object(&bytes, executable)?;
            artifacts.push(ExecutionContextArtifact {
                path: a.path.clone(),
                role: a.role.clone(),
                sha256: sha.clone(),
            });
            execution_context_refs.push(EvidenceRef {
                role: "execution-context".into(),
                object_kind: "object".into(),
                cid: sha,
            });
        }
        artifacts.sort_by(|a, b| a.path.cmp(&b.path));
        let mut closure = ExecutionContextClosure {
            schema_version: SCHEMA_EXECUTION_CONTEXT.to_string(),
            cid: String::new(),
            artifacts,
        };
        closure.cid = crate::semantics::execution_context_identity(&closure)?;
        Some(closure)
    } else {
        None
    };

    // -- identities, bound NOW (observation time) ----------------------------
    // Two questions, answered separately: WHAT question was asked (semantic
    // identity from comparator SEMANTICS + artifact hashes) and WHO asked it
    // (provenance: runner + comparator implementations). A receipt emitted
    // later copies both; it never reconstructs them from whatever binary or
    // host happens to be installed.
    let environment = host::environment_identity(&declared_environment);
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
    // identity. An external comparator also records its ARTIFACT identity
    // (snapshot path + interpreter chain), so replay can re-invoke the exact
    // instrument and the bundle closure can carry it. In-binary comparators
    // are implemented by the frf executable.
    let rel_to_root = |p: &Path| {
        p.strip_prefix(&store.root)
            .map(|r| r.to_string_lossy().into_owned())
            .unwrap_or_else(|_| p.to_string_lossy().into_owned())
    };
    #[derive(Clone)]
    struct ExternalHost {
        artifact: ArtifactIdentity,
    }
    let mut external_hosts: Vec<Option<ExternalHost>> = Vec::new();
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
                    // Snapshot + seal BEFORE execution; the evaluation
                    // operation re-hashes the sealed snapshot on every use.
                    let snapshot = store.materialize_object(&bytes, true)?;
                    let interpreter = host::interpreter_identity(&bytes)?;
                    // The comparator's native runtime closure resolves
                    // against its SEALED EXEC PATH (it runs via the sealed
                    // memfd like every other program): `$ORIGIN`-relative
                    // dependencies must resolve as the loader resolves them
                    // when the comparator actually runs.
                    let comparator_image = host::ExecImage::seal(&bytes, &impl_hash, &snapshot)?;
                    let artifact = ArtifactIdentity {
                        path: rel_to_root(&snapshot),
                        sha256: impl_hash.clone(),
                        interpreter,
                        native_runtime: crate::native::runtime_closure(
                            comparator_image.path(),
                            &bytes,
                        )?,
                    };
                    external_hosts.push(Some(ExternalHost {
                        artifact: artifact.clone(),
                    }));
                    Ok(ComparatorImplementation {
                        id: axis.as_str().to_string(),
                        implementation_hash: impl_hash,
                        runner_hash: runner.frf_executable_hash.clone(),
                        artifact: Some(artifact),
                    })
                }
                None => {
                    external_hosts.push(None);
                    Ok(ComparatorImplementation {
                        id: axis.as_str().to_string(),
                        implementation_hash: runner.frf_executable_hash.clone(),
                        runner_hash: runner.frf_executable_hash.clone(),
                        artifact: None,
                    })
                }
            }
        })
        .collect::<Result<_>>()?;
    // Normalizer implementations: read + hash + seal BEFORE any execution;
    // the snapshots are what run against the sides' raw streams.
    let normalizer_hosts: Vec<(NormalizerDeclaration, crate::ext::ProgramSnapshot)> = envelope
        .normalizers
        .iter()
        .map(|id| {
            let decl = manifest
                .normalizers
                .iter()
                .find(|n| &n.id == id)
                .expect("validated: every applied normalizer is declared");
            let snapshot = crate::ext::snapshot_program(store, Path::new(&decl.program))?;
            Ok((decl.clone(), snapshot))
        })
        .collect::<Result<_>>()?;
    let normalizer_implementations: Vec<NormalizerImplementation> = normalizer_hosts
        .iter()
        .map(|(decl, snap)| NormalizerImplementation {
            id: decl.id.clone(),
            implementation_hash: snap.impl_hash.clone(),
            runner_hash: runner.frf_executable_hash.clone(),
            artifact: Some(snap.artifact.clone()),
        })
        .collect();
    // Capture-adapter implementations: one per adapted axis.
    let adapter_hosts: Vec<(CaptureAdapterDeclaration, crate::ext::ProgramSnapshot)> = manifest
        .capture_adapters
        .iter()
        .map(|a| {
            let snapshot = crate::ext::snapshot_program(store, Path::new(&a.program))?;
            Ok((a.clone(), snapshot))
        })
        .collect::<Result<_>>()?;
    let adapter_implementations: Vec<CaptureAdapterImplementation> = adapter_hosts
        .iter()
        .map(|(decl, snap)| CaptureAdapterImplementation {
            id: decl.axis.clone(),
            implementation_hash: snap.impl_hash.clone(),
            runner_hash: runner.frf_executable_hash.clone(),
            artifact: Some(snap.artifact.clone()),
        })
        .collect();
    // Minimizer implementations: read + hash + seal BEFORE anything could
    // execute them. A minimizer runs only at `frf court minimize` time, but
    // the EXACT reducer the court binds for a κ route is snapshotted at
    // OBSERVATION time — so minimize works without the original manifest and
    // the bundle closure carries the reducer that actually reduced.
    let minimizer_hosts: Vec<(MinimizerDeclaration, crate::ext::ProgramSnapshot)> = manifest
        .minimizers
        .iter()
        .map(|m| {
            let snapshot = crate::ext::snapshot_program(store, Path::new(&m.program))?;
            Ok((m.clone(), snapshot))
        })
        .collect::<Result<_>>()?;
    let minimizer_implementations: Vec<MinimizerImplementation> = minimizer_hosts
        .iter()
        .map(|(decl, snap)| MinimizerImplementation {
            id: decl.id.clone(),
            implementation_hash: snap.impl_hash.clone(),
            runner_hash: runner.frf_executable_hash.clone(),
            artifact: Some(snap.artifact.clone()),
        })
        .collect();
    let provenance = ObservationProvenance {
        schema_version: SCHEMA_PROVENANCE.to_string(),
        runner: runner.clone(),
        comparator_implementations,
        normalizer_implementations,
        adapter_implementations,
        minimizer_implementations,
    };

    // The normalizer SEMANTIC identities, in application (envelope) order,
    // and the minimizer semantics the court binds for `court minimize`.
    let normalizer_semantics: Vec<NormalizerSemantic> = normalizer_hosts
        .iter()
        .map(|(decl, _)| crate::normalizers::declared_semantic(decl))
        .collect::<Result<_>>()?;
    // The minimizer semantics the court binds for `court minimize`.
    let minimizer_semantics: Vec<MinimizerSemantic> = manifest
        .minimizers
        .iter()
        .map(|m| {
            let specification_hash = crate::semantics::minimizer_specification_hash(
                &m.id,
                &m.relation,
                &m.relation_version,
            )?;
            Ok(MinimizerSemantic {
                id: m.id.clone(),
                relation_id: m.relation.clone(),
                relation_version: m.relation_version.clone(),
                specification_hash,
            })
        })
        .collect::<Result<_>>()?;
    let adapter_semantics: Vec<CaptureAdapterSemantic> = manifest
        .capture_adapters
        .iter()
        .map(|a| {
            let specification_hash = crate::semantics::capture_adapter_specification_hash(
                &a.axis,
                &a.relation,
                &a.relation_version,
            )?;
            Ok(CaptureAdapterSemantic {
                id: a.axis.clone(),
                relation_id: a.relation.clone(),
                relation_version: a.relation_version.clone(),
                specification_hash,
            })
        })
        .collect::<Result<_>>()?;
    let court_semantic_identity = crate::semantics::court_semantic_identity(
        spec,
        &authority_sha256,
        &fixture_sha256,
        &comparator_semantics,
        &normalizer_semantics,
        &adapter_semantics,
    )?;

    // The fixture argument resolves to the SNAPSHOT path: the side reads
    // exactly the hashed bytes, and the recorded arguments are replayable
    // without the original tree. `{output}` (with a produce clause) resolves
    // to the declared output path — the side writes its produced tree there.
    let fixture_arg = fixture_snapshot.to_string_lossy().into_owned();
    let arguments: Vec<String> = spec
        .fixture
        .arguments
        .iter()
        .map(|a| {
            if a == "{fixture}" {
                Ok(fixture_arg.clone())
            } else if a == "{output}" {
                produce_path
                    .as_ref()
                    .map(|p| p.to_string_lossy().into_owned())
                    .ok_or_else(|| {
                        FrfError::new(
                            "the fixture arguments reference '{output}' but the court declares no produce clause",
                        )
                    })
            } else {
                Ok(a.clone())
            }
        })
        .collect::<Result<_>>()?;
    if !arguments.contains(&fixture_arg) {
        eprintln!(
            "frf: warning: fixture {} is not referenced by the declared arguments; this execution does not exercise it",
            spec.fixture.path
        );
    }

    // -- observe both sides ---------------------------------------------------

    // With a produce clause, each side writes its output tree to the
    // (transient) produce path: the harness clears it before each side,
    // walks it after, stages the bytes, and captures the tree immutably.
    let staging = crate::produced::ProducedStaging::new("court")?;
    let clear_produce = |path: &Path| -> Result<()> {
        if path.exists() {
            if path.is_dir() {
                fs::remove_dir_all(path)
                    .map_err(|e| FrfError::new(format!("cannot clear {}: {e}", path.display())))?;
            } else {
                fs::remove_file(path)
                    .map_err(|e| FrfError::new(format!("cannot clear {}: {e}", path.display())))?;
            }
        }
        Ok(())
    };

    if let Some(prod) = &produce_path {
        clear_produce(prod)?;
    }
    let reference_out =
        host::run_process(&authority_image, &arguments, profile, &declared_environment)?;
    let mut reference = SideCapture::from_outcome(&reference_out);
    if let Some(prod) = &produce_path {
        let files = crate::produced::capture_produced_tree(prod, &staging.dir.join("reference"))?;
        reference.produced = Some(crate::produced::produced_side(files)?);
        clear_produce(prod)?;
    }

    let candidate_out =
        host::run_process(&candidate_image, &arguments, profile, &declared_environment)?;
    let mut candidate = SideCapture::from_outcome(&candidate_out);
    if let Some(prod) = &produce_path {
        let files = crate::produced::capture_produced_tree(prod, &staging.dir.join("candidate"))?;
        candidate.produced = Some(crate::produced::produced_side(files)?);
        // The transient output directory is never evidence; the run-dir
        // copies below are.
        clear_produce(prod)?;
    }

    // -- apply the declared normalizers (spec/normalizer.md) ------------------
    // A normalizer maps one side's raw streams to the streams the court
    // COMPARES. Normalizers compose in envelope order; the raw streams survive
    // as each invocation's request evidence, so an observation is never
    // rewritten — the comparison surface is. The compared streams are what
    // the capture records, what the residuals derive from, and what the
    // external comparator requests carry.
    struct PendingNormalizer {
        id: String,
        side: String,
        request_bytes: Vec<u8>,
        response_bytes: Vec<u8>,
        invocation: NormalizerInvocation,
        result: NormalizerResult,
    }
    let mut pending_normalizers: Vec<PendingNormalizer> = Vec::new();
    // The produced trees (the normalizers do not touch them; the compared
    // side captures carry them).
    let raw_reference_produced = reference.produced.clone();
    let raw_candidate_produced = candidate.produced.clone();
    let mut normalize_side = |side: &str,
                              outcome: &host::ProcessOutcome|
     -> Result<host::ProcessOutcome> {
        let mut stdout = outcome.stdout.clone();
        let mut stderr = outcome.stderr.clone();
        for (decl, snap) in &normalizer_hosts {
            let semantic = crate::normalizers::declared_semantic(decl)?;
            let request = crate::normalizers::build_request(
                &semantic,
                side,
                &stdout,
                &stderr,
                &fixture_sha256,
                &arguments,
                &environment.digest,
            );
            let (request_bytes, _request_cid) = crate::normalizers::canonical_request(&request)?;
            let (new_stdout, new_stderr, response_bytes) = crate::normalizers::run_side(
                &snap.image,
                &request_bytes,
                &semantic,
                &stdout,
                &stderr,
                std::path::Path::new("."),
                profile,
                &declared_environment,
            )?;
            // The invocation + result records are written once the run id
            // exists (the evidence lives under captures/<run>/).
            let (invocation, result) = crate::normalizers::record_evidence(
                &decl.id,
                side,
                &semantic,
                &snap.artifact,
                &runner,
                &request_bytes,
                &response_bytes,
                &new_stdout,
                &new_stderr,
            )?;
            pending_normalizers.push(PendingNormalizer {
                id: decl.id.clone(),
                side: side.to_string(),
                request_bytes,
                response_bytes,
                invocation,
                result,
            });
            stdout = new_stdout;
            stderr = new_stderr;
        }
        Ok(host::ProcessOutcome {
            stdout,
            stderr,
            exit: outcome.exit.clone(),
        })
    };
    let reference_compared = normalize_side("reference", &reference_out)?;
    let candidate_compared = normalize_side("candidate", &candidate_out)?;

    // The COMPARED observation: the normalized streams (the raw streams live
    // in the normalizer request evidence), the produced trees, and — below —
    // the adapted observations.
    let mut reference = SideCapture::from_outcome(&reference_compared);
    reference.produced = raw_reference_produced;
    let mut candidate = SideCapture::from_outcome(&candidate_compared);
    candidate.produced = raw_candidate_produced;

    // -- capture adapters (spec/capture-adapter.md) ---------------------------
    // An adapter captures the observation for one externally served axis: the
    // side's raw outcome in (the request evidence), the ADAPTED observation
    // out, attached to the compared side capture — what the axis's external
    // comparator receives.
    struct PendingAdapter {
        axis: String,
        side: String,
        request_bytes: Vec<u8>,
        response_bytes: Vec<u8>,
        invocation: CaptureAdapterInvocation,
        result: CaptureAdapterResult,
    }
    let mut pending_adapters: Vec<PendingAdapter> = Vec::new();
    for (decl, snap) in &adapter_hosts {
        let semantic = adapter_semantics
            .iter()
            .find(|s| s.id == decl.axis)
            .expect("validated: adapter semantics match declarations")
            .clone();
        for (side, raw_outcome, compared_side) in [
            ("reference", &reference_out, &mut reference),
            ("candidate", &candidate_out, &mut candidate),
        ] {
            let request = crate::model::CaptureAdapterRequest {
                schema_version: crate::model::SCHEMA_CAPTURE_ADAPTER_REQUEST,
                adapter: &semantic,
                side,
                outcome: crate::model::CaptureAdapterOutcome {
                    exit: &raw_outcome.exit,
                    stdout_base64: crate::ext::b64(&raw_outcome.stdout),
                    stderr_base64: crate::ext::b64(&raw_outcome.stderr),
                    produced: None,
                },
                context: crate::model::NormalizerContext {
                    fixture_sha256: &fixture_sha256,
                    arguments: &arguments,
                    environment_digest: &environment.digest,
                },
            };
            let json = crate::canon::canonical(&request)?;
            let request_bytes = json.into_bytes();
            let response_bytes = crate::ext::run_program(
                &snap.image,
                &request_bytes,
                std::path::Path::new("."),
                profile,
                &declared_environment,
            )?;
            // The protocol says canonical JSON: the response must BE its own
            // canonical serialization.
            let response: crate::model::CaptureAdapterResponse =
                crate::ext::parse_canonical_response(&response_bytes, "capture-adapter response")
                    .map_err(|e| {
                    FrfError::new(format!("capture adapter for axis {}: {e}", decl.axis))
                })?;
            if response.schema_version != crate::model::SCHEMA_CAPTURE_ADAPTER_RESPONSE {
                return Err(FrfError::new(format!(
                    "capture adapter response has unsupported schema version {:?}",
                    response.schema_version
                )));
            }
            if response.request_id != crate::ext::request_cid(&request_bytes) {
                return Err(FrfError::new(format!(
                    "capture adapter for axis {} names request {} but it answers request {}; a response must cryptographically name the exact request it answers",
                    decl.axis,
                    &response.request_id[..16.min(response.request_id.len())],
                    &crate::ext::request_cid(&request_bytes)[..16]
                )));
            }
            if response.indeterminate {
                return Err(FrfError::new(format!(
                    "capture adapter for axis {} returned indeterminate; refusing to record inconclusive evidence",
                    decl.axis
                )));
            }
            if let Some(f) = &response.failure {
                return Err(FrfError::new(format!(
                    "capture adapter for axis {} reported failure: {f}",
                    decl.axis
                )));
            }
            let observation_sha256 = response
                .observation
                .as_ref()
                .map(|o| o.content_sha256.clone())
                .unwrap_or_default();
            compared_side.adapted = response.observation.clone();
            let response_cid = crate::host::sha256_bytes(&response_bytes);
            let request_cid = crate::ext::request_cid(&request_bytes);
            let invocation_id = crate::semantics::capture_adapter_invocation_identity(
                &crate::semantics::CaptureAdapterInvocationContent {
                    axis: &decl.axis,
                    side,
                    request_cid: &request_cid,
                    adapter_semantic_cid: &semantic.specification_hash,
                    adapter_implementation_artifact: &snap.artifact,
                    execution_provenance: &runner,
                },
            )?;
            let result_id = crate::semantics::capture_adapter_result_identity(
                &crate::semantics::CaptureAdapterResultContent {
                    request_cid: &request_cid,
                    response_cid: &response_cid,
                    observation_sha256: &observation_sha256,
                },
            )?;
            pending_adapters.push(PendingAdapter {
                axis: decl.axis.clone(),
                side: side.to_string(),
                request_bytes,
                response_bytes,
                invocation: CaptureAdapterInvocation {
                    schema_version: crate::model::SCHEMA_CAPTURE_ADAPTER_INVOCATION.to_string(),
                    invocation_id: invocation_id.clone(),
                    axis: decl.axis.clone(),
                    side: side.to_string(),
                    request_cid: request_cid.clone(),
                    adapter_semantic_cid: semantic.specification_hash.clone(),
                    adapter_implementation_artifact: snap.artifact.clone(),
                    execution_provenance: runner.clone(),
                },
                result: CaptureAdapterResult {
                    schema_version: crate::model::SCHEMA_CAPTURE_ADAPTER_RESULT.to_string(),
                    result_id,
                    invocation_id,
                    request_cid,
                    response_cid,
                    observation_sha256,
                    outcome: "captured".to_string(),
                },
            });
        }
    }

    // -- diff the declared axes (Section 12 comparators) -----------------------

    // The comparator serving each axis fixes the relation AND the residual
    // classifier (a divergence's kind is part of the question).
    let mut residuals: Vec<ResidualRecord> = Vec::new();
    // Ids are assigned before anything is written, so a run with two
    // text-family residuals (stderr + stdout) must not re-read the disk and
    // hand out the same sequence number twice: track ids already handed out
    // in this run and keep bumping past them.
    let mut pending_seq: std::collections::HashMap<ResidualKind, u32> =
        std::collections::HashMap::new();
    // The externally served axes' invocation evidence, written once the
    // residuals (and therefore their ids) exist.
    struct PendingInvocation {
        invocation: ComparatorInvocation,
        response_cid: String,
        request_bytes: Vec<u8>,
        response_bytes: Vec<u8>,
        residual_ids: Vec<String>,
    }
    let mut pending_invocations: Vec<Option<PendingInvocation>> =
        (0..observables.len()).map(|_| None).collect();
    for (idx, axis) in observables.iter().enumerate() {
        // The comparator serving this axis: a declaration (external) or a
        // registry row (built-in). Its SEMANTIC fixes the relation, the
        // extractor, and the residual classifier. EVERY axis is evaluated
        // through the ONE evaluation operation — the in-binary implementation
        // for a registry row, the re-invoked external program for a
        // declaration; nothing else may decide parity.
        let semantic = comparator_semantics[idx].clone();
        let classifier = ResidualKind::parse(&semantic.residual_classifier)?;
        let plan = crate::comparators::EvaluationPlan {
            axis: axis.clone(),
            semantic: semantic.clone(),
            implementation: provenance.comparator_implementations[idx].clone(),
        };
        let context = crate::comparators::EvaluationContext {
            fixture_sha256: &fixture_sha256,
            arguments: &arguments,
            environment_digest: &environment.digest,
            produced: reference.produced.as_ref().zip(candidate.produced.as_ref()),
            cwd: std::path::Path::new("."),
            raw: Some((&reference_out, &candidate_out)),
            compared: Some((&reference_compared, &candidate_compared)),
            profile,
            env: &declared_environment,
        };
        let evaluation =
            crate::comparators::evaluate(store, &plan, &reference, &candidate, &context)?;
        let projections: Vec<(Option<String>, String, String)> = match evaluation.result {
            crate::comparators::EvaluationResult::Pass => vec![],
            crate::comparators::EvaluationResult::Divergent(v) => v,
        };
        if let Some(ev) = &evaluation.evidence {
            // An externally served axis: the request + response + invocation
            // + result are themselves evidence (the exact instrument that
            // observed), written once the residuals (and therefore their
            // ids) exist.
            let invocation = ComparatorInvocation {
                schema_version: SCHEMA_COMPARATOR_INVOCATION.to_string(),
                invocation_id: String::new(), // filled below
                axis: axis.clone(),
                request_cid: ev.request_cid.clone(),
                comparator_semantic_cid: semantic.specification_hash.clone(),
                comparator_implementation_artifact: external_hosts[idx]
                    .as_ref()
                    .expect("externally evaluated axis has an external host")
                    .artifact
                    .clone(),
                execution_provenance: runner.clone(),
            };
            pending_invocations[idx] = Some(PendingInvocation {
                invocation,
                response_cid: ev.response_cid.clone(),
                request_bytes: ev.request_bytes.clone(),
                response_bytes: ev.response_bytes.clone(),
                residual_ids: vec![],
            });
        }
        for (surface, raw_ref, raw_cand) in projections {
            let seq = match pending_seq.get(&classifier) {
                Some(s) => s + 1,
                None => store.next_residual_seq(classifier.clone())?,
            };
            pending_seq.insert(classifier.clone(), seq);
            residuals.push(ResidualRecord {
                schema_version: SCHEMA_RESIDUAL.to_string(),
                id: format!(
                    "{}-{}-{:04}",
                    classifier.domain_prefix(),
                    classifier.as_str(),
                    seq
                ),
                court: spec.id.clone(),
                run: String::new(), // filled once the run id is known
                axis: axis.clone(),
                kind: classifier.clone(),
                surface,
                authority: authority.id.clone(),
                scope: spec.admissibility_envelope.fixture_family.clone(),
                candidate_sha256: candidate_sha256.clone(),
                raw_reference: raw_ref,
                raw_candidate: raw_cand,
                raw_reference_sha256: String::new(),
                raw_candidate_sha256: String::new(),
            });
            if let Some(p) = &mut pending_invocations[idx] {
                p.residual_ids
                    .push(residuals.last().expect("just pushed").id.clone());
            }
        }
    }

    // -- content-address the run ----------------------------------------------
    // Identity discipline: ONE run-identity function, shared with replay,
    // receipt verification, and the verification suite. The identity
    // (FRF/RUN/v2) composes the OBSERVATION identity (FRF/OBSERVATION/v1 —
    // what was observed) and the EXECUTION identity (FRF/EXECUTION/v1 —
    // under exactly what machinery/contract it was observed: profile,
    // effective bounds, runner, interpreters, and every comparator/
    // normalizer/adapter/minimizer implementation). The preimages are
    // domain-separated canonical JSON documents, never delimiter-assembled
    // strings; a name is a claim until it is recomputed.
    let capture_bounds = host::capture_bounds(profile);
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
        execution_profile: profile.as_str(),
        capture_bounds: &capture_bounds,
        comparator_implementations: &provenance.comparator_implementations,
        normalizer_implementations: &provenance.normalizer_implementations,
        adapter_implementations: &provenance.adapter_implementations,
        minimizer_implementations: &provenance.minimizer_implementations,
    };
    let observation_identity = crate::semantics::observation_identity(&pre)?;
    let execution_identity = crate::semantics::execution_identity(&pre)?;
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
    write_side_files(&run_dir, "reference", &reference_compared, &reference)?;
    write_side_files(&run_dir, "candidate", &candidate_compared, &candidate)?;
    // The produced trees: the staged bytes are copied under the run (the
    // transient produce path is already cleared), immutable and rehashed by
    // verification.
    if let Some(prod) = &reference.produced {
        crate::produced::write_produced_dir(
            &run_dir,
            "reference",
            &staging.dir.join("reference"),
            &prod.files,
        )?;
    }
    if let Some(prod) = &candidate.produced {
        crate::produced::write_produced_dir(
            &run_dir,
            "candidate",
            &staging.dir.join("candidate"),
            &prod.files,
        )?;
    }

    // Fill in run id + axis hashes, then persist the immutable observation
    // records and their (open) endoduction tokens.
    for r in &mut residuals {
        r.run = run.clone();
        r.raw_reference_sha256 = host::sha256_bytes(r.raw_reference.as_bytes());
        r.raw_candidate_sha256 = host::sha256_bytes(r.raw_candidate.as_bytes());
        let json = store.to_evidence(r)?;
        store.write_once(&store.residual_path(&r.id)?, &json)?;
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

    // -- comparator invocation evidence (externally served axes) ----------------
    // The canonical request the comparator received, its canonical response,
    // and the content-addressed invocation + result records that bind them to
    // this run's residuals. Written once, immutable, canonical JSON — the
    // instrument is part of the evidence.
    for (idx, axis) in observables.iter().enumerate() {
        let Some(pending) = &mut pending_invocations[idx] else {
            continue;
        };
        let invocation_id = crate::semantics::comparator_invocation_identity(
            &crate::semantics::ComparatorInvocationContent {
                axis,
                request_cid: &pending.invocation.request_cid,
                comparator_semantic_cid: &pending.invocation.comparator_semantic_cid,
                comparator_implementation_artifact: &pending
                    .invocation
                    .comparator_implementation_artifact,
                execution_provenance: &pending.invocation.execution_provenance,
            },
        )?;
        pending.invocation.invocation_id = invocation_id;
        let result_id = crate::semantics::comparator_result_identity(
            &crate::semantics::ComparatorResultContent {
                request_cid: &pending.invocation.request_cid,
                response_cid: &pending.response_cid,
                outcome: if pending.residual_ids.is_empty() {
                    "equivalent"
                } else {
                    "divergent"
                },
                residual_observation_ids: &pending.residual_ids,
            },
        )?;
        let result = ComparatorResult {
            schema_version: SCHEMA_COMPARATOR_RESULT.to_string(),
            result_id,
            request_cid: pending.invocation.request_cid.clone(),
            response_cid: pending.response_cid.clone(),
            outcome: if pending.residual_ids.is_empty() {
                "equivalent".to_string()
            } else {
                "divergent".to_string()
            },
            residual_observation_ids: pending.residual_ids.clone(),
        };
        let dir = store.comparator_dir(&run, axis.as_str())?;
        std::fs::create_dir_all(&dir)
            .map_err(|e| FrfError::new(format!("cannot create {}: {e}", dir.display())))?;
        store.write_once(
            &dir.join("request.json"),
            &String::from_utf8(pending.request_bytes.clone())
                .map_err(|_| FrfError::new("internal error: comparator request is not UTF-8"))?,
        )?;
        store.write_once(
            &dir.join("response.json"),
            &String::from_utf8(pending.response_bytes.clone())
                .map_err(|_| FrfError::new("internal error: comparator response is not UTF-8"))?,
        )?;
        store.write_once(
            &dir.join("invocation.json"),
            &crate::canon::canonical(&pending.invocation)?,
        )?;
        store.write_once(&dir.join("result.json"), &crate::canon::canonical(&result)?)?;
        eprintln!(
            "comparator {} invocation {} -> {}",
            axis.as_str(),
            &pending.invocation.invocation_id[..16],
            result.outcome
        );
    }

    // -- normalizer + capture-adapter invocation evidence -------------------
    // The exact instruments that built the COMPARISON SURFACE: each
    // normalizer's canonical request (one side's raw streams at that point of
    // the application chain), its canonical response, and the content-
    // addressed invocation + result records — written once, immutable,
    // under `captures/<run>/normalizer/<id>/<side>/`. The capture adapters
    // that produced the ADAPTED observations are the same shape, under
    // `captures/<run>/capture-adapter/<axis>/<side>/`. Verification rehashes
    // every file and rederives every identity without executing anything.
    for pending in &pending_normalizers {
        crate::ext::write_evidence(
            store,
            &run_dir
                .join("normalizer")
                .join(&pending.id)
                .join(&pending.side),
            &pending.request_bytes,
            &pending.response_bytes,
            &serde_json::to_value(&pending.invocation).map_err(|e| {
                FrfError::new(format!("cannot serialize the normalizer invocation: {e}"))
            })?,
            &serde_json::to_value(&pending.result).map_err(|e| {
                FrfError::new(format!("cannot serialize the normalizer result: {e}"))
            })?,
        )?;
    }
    for pending in &pending_adapters {
        crate::ext::write_evidence(
            store,
            &run_dir
                .join("capture-adapter")
                .join(&pending.axis)
                .join(&pending.side),
            &pending.request_bytes,
            &pending.response_bytes,
            &serde_json::to_value(&pending.invocation).map_err(|e| {
                FrfError::new(format!(
                    "cannot serialize the capture-adapter invocation: {e}"
                ))
            })?,
            &serde_json::to_value(&pending.result).map_err(|e| {
                FrfError::new(format!("cannot serialize the capture-adapter result: {e}"))
            })?,
        )?;
    }

    // -- capture manifest --------------------------------------------------------

    // The run's outgoing evidence references: the executed artifacts and the
    // comparator instrumentation, as typed edges the bundle closure walks.
    let mut evidence_refs = vec![
        EvidenceRef {
            role: "authority-artifact".into(),
            object_kind: "object".into(),
            cid: authority_sha256.clone(),
        },
        EvidenceRef {
            role: "candidate-artifact".into(),
            object_kind: "object".into(),
            cid: candidate_sha256.clone(),
        },
        EvidenceRef {
            role: "fixture-object".into(),
            object_kind: "object".into(),
            cid: fixture_sha256.clone(),
        },
    ];
    for host in external_hosts.iter().flatten() {
        evidence_refs.push(EvidenceRef {
            role: "comparator-implementation".into(),
            object_kind: "object".into(),
            cid: host.artifact.sha256.clone(),
        });
    }
    for (_, snap) in &normalizer_hosts {
        evidence_refs.push(EvidenceRef {
            role: "normalizer-implementation".into(),
            object_kind: "object".into(),
            cid: snap.impl_hash.clone(),
        });
    }
    for (_, snap) in &adapter_hosts {
        evidence_refs.push(EvidenceRef {
            role: "capture-adapter-implementation".into(),
            object_kind: "object".into(),
            cid: snap.impl_hash.clone(),
        });
    }
    for (_, snap) in &minimizer_hosts {
        evidence_refs.push(EvidenceRef {
            role: "minimizer-implementation".into(),
            object_kind: "object".into(),
            cid: snap.impl_hash.clone(),
        });
    }
    evidence_refs.extend(execution_context_refs);

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
        normalizer_semantics,
        adapter_semantics,
        minimizer_semantics,
        provenance,
        // Artifact paths are ROOT-relative pointers (stable across machines);
        // the capture's `arguments` are the verbatim argv the side received.
        authority_artifact: ArtifactIdentity {
            path: rel_to_root(&authority_snapshot),
            sha256: authority_sha256,
            interpreter: authority_interpreter,
            native_runtime: authority_native,
        },
        candidate_artifact: ArtifactIdentity {
            path: rel_to_root(&candidate_snapshot),
            sha256: candidate_sha256,
            interpreter: candidate_interpreter,
            native_runtime: candidate_native,
        },
        court_semantic_identity,
        execution_profile: profile.as_str().to_string(),
        capture_bounds,
        observation_identity,
        execution_identity,
        reference,
        candidate,
        residuals: residuals.iter().map(|r| r.id.clone()).collect(),
        evidence_refs,
        execution_context,
    };
    let json = store.to_evidence(&capture)?;
    store.write_once(&run_dir.join("capture.json"), &json)?;

    eprintln!(
        "court {} run: captures, residuals, and tokens written under {}",
        spec.id,
        run_dir.display()
    );
    Ok(run)
}

/// `frf court challenge MANIFEST [--operators ...]`: the negative controls.
/// A court that yields a pass proves nothing unless it has demonstrated it
/// can SEE the defect classes it declares. For every applicable mutation
/// operator (each built-in operator whose targeted axis the court declares;
/// by default all of them), the challenge:
///
/// 1. generates the deterministic MUTANT candidate — a wrapper of the
///    admitted reference artifact that alters exactly the targeted observable
///    dimension and preserves every other byte-for-byte (`src/mutation.rs`);
/// 2. runs the court against the mutant (a normal, content-addressed run —
///    same question, same envelope, same fixture, mutant candidate);
/// 3. records a content-addressed `CourtChallenge` (`challenges/<id>.yaml`)
///    with the DERIVED verdicts: `saw_defect` (a divergence appeared on the
///    targeted axis — the court can see the seeded defect) and
///    `specificity_clean` (no divergence appeared on the unaffected axes —
///    the mutant moved only the targeted dimension and the court did not
///    conflate it with others).
///
/// A court that is BLIND to a declared defect class (no residual on the
/// targeted axis) or conflates axes (residuals on unaffected axes) is
/// refused: the challenge records remain as evidence, but the command exits
/// non-zero.
pub fn challenge(
    store: &Store,
    manifest_path: &Path,
    operators_arg: Option<&str>,
) -> Result<Vec<String>> {
    let manifest: CourtManifest = store.parse_yaml(manifest_path)?;
    let spec = &manifest.court;
    crate::store::validate_id("court", &spec.id)?;
    // The declared execution profile: the mutant run and the mutation
    // provider execute under the same harness contract as the court's sides.
    let profile = host::ExecProfile::parse(
        spec.execution_profile
            .as_deref()
            .unwrap_or(crate::model::EXECUTION_PROFILE_LINUX),
    )?;

    // The declared observables must be served comparators (the run itself
    // re-validates); the challenge needs them to scope the operators and the
    // unaffected axes.
    let observables: Vec<String> = spec
        .admissibility_envelope
        .observables
        .iter()
        .map(|o| ObservableId::parse(o).map(|id| id.as_str().to_string()))
        .collect::<Result<_>>()?;
    if observables.is_empty() {
        return Err(FrfError::new(
            "the court declares no observables; there is no defect class to challenge — a court that cannot be challenged cannot prove it can see",
        ));
    }

    // The declared mutation providers (the extension protocol): each
    // declares the axes it seeds defects on, all of which must be declared
    // observables. Ids must be unique and must not collide with the built-in
    // operators.
    let mut seen_mutation: Vec<&str> = Vec::new();
    for m in &manifest.mutations {
        crate::store::validate_id("mutation provider", &m.id)?;
        if seen_mutation.contains(&m.id.as_str()) {
            return Err(FrfError::new(format!(
                "duplicate mutation provider id '{}' in the manifest",
                m.id
            )));
        }
        seen_mutation.push(&m.id);
        if crate::mutation::MutationOperator::parse(&m.id).is_ok() {
            return Err(FrfError::new(format!(
                "mutation provider id '{}' collides with a built-in operator; rename the provider",
                m.id
            )));
        }
        if m.target_axes.is_empty() {
            return Err(FrfError::new(format!(
                "mutation provider {} declares no target axes; a provider must declare the axes it seeds defects on",
                m.id
            )));
        }
        for a in &m.target_axes {
            if !observables.iter().any(|o| o == a) {
                return Err(FrfError::new(format!(
                    "mutation provider {} targets axis '{a}' which the court does not declare; the seeded defect would be unobservable",
                    m.id
                )));
            }
        }
    }

    // One requested challenge: a built-in operator (the deterministic
    // wrapper) or an external mutation provider for one specific target axis
    // (the provider PROPOSES the mutant; the court decides the verdicts).
    enum ChallengeOperator<'a> {
        Builtin(crate::mutation::MutationOperator),
        External(&'a MutationDeclaration, String),
    }
    impl ChallengeOperator<'_> {
        fn label(&self) -> String {
            match self {
                ChallengeOperator::Builtin(op) => op.as_str().to_string(),
                ChallengeOperator::External(decl, _) => decl.id.clone(),
            }
        }
        fn target_axis(&self) -> &str {
            match self {
                ChallengeOperator::Builtin(op) => op.target_axis(),
                ChallengeOperator::External(_, axis) => axis,
            }
        }
    }
    let provider_for = |id: &str| manifest.mutations.iter().find(|m| m.id == id);

    let operators: Vec<ChallengeOperator> = match operators_arg {
        Some(list) => {
            let mut ops = Vec::new();
            for raw in list.split(',') {
                let raw = raw.trim();
                if raw.is_empty() {
                    continue;
                }
                match crate::mutation::MutationOperator::parse(raw) {
                    Ok(op) => {
                        if !observables.iter().any(|o| o == op.target_axis()) {
                            return Err(FrfError::new(format!(
                                "operator {} targets axis '{}' which the court does not declare; the seeded defect would be unobservable",
                                op.as_str(),
                                op.target_axis()
                            )));
                        }
                        ops.push(ChallengeOperator::Builtin(op));
                    }
                    Err(_) => {
                        // A declared external mutation provider: one challenge
                        // per declared target axis.
                        let decl = provider_for(raw).ok_or_else(|| {
                            FrfError::new(format!(
                                "unknown mutation operator {raw:?}: built-ins are exit-class, stderr-first-line, stdout-first-line, and the declared mutation providers are {}",
                                manifest
                                    .mutations
                                    .iter()
                                    .map(|m| m.id.as_str())
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            ))
                        })?;
                        for a in &decl.target_axes {
                            ops.push(ChallengeOperator::External(decl, a.clone()));
                        }
                    }
                }
            }
            if ops.is_empty() {
                return Err(FrfError::new(
                    "no mutation operators requested; pass --operators exit-class,stderr-first-line,... or a declared mutation provider id",
                ));
            }
            ops
        }
        None => {
            let mut ops = Vec::new();
            let mut skipped: Vec<String> = Vec::new();
            for o in &observables {
                match crate::mutation::MutationOperator::from_axis(o) {
                    Some(op) => ops.push(ChallengeOperator::Builtin(op)),
                    None => match provider_for(o).or_else(|| {
                        manifest
                            .mutations
                            .iter()
                            .find(|m| m.target_axes.iter().any(|a| a == o))
                    }) {
                        Some(decl) => ops.push(ChallengeOperator::External(decl, o.clone())),
                        None => skipped.push(o.clone()),
                    },
                }
            }
            if ops.is_empty() {
                return Err(FrfError::new(format!(
                    "no mutation operator applies to this court's observables {:?}; declare an external mutation provider for {}",
                    observables,
                    skipped.join(", ")
                )));
            }
            if !skipped.is_empty() {
                eprintln!(
                    "court challenge: skipping axes with no mutation surface (no built-in operator, no declared provider): {}",
                    skipped.join(", ")
                );
            }
            ops
        }
    };

    // The reference the mutants wrap: the admitted authority artifact. The
    // wrapper resolves it relative to itself (both live in the same
    // objects/sha256/ directory), so the built-in mutant bytes depend only on
    // the operator and the reference hash — root-independent and rederivable.
    let authority = store.load_authority(&spec.authority)?;
    let reference_sha256 = authority.executable_sha256.clone();
    let created_by = RunnerIdentity {
        schema_version: SCHEMA_RUNNER.to_string(),
        frf_version: env!("CARGO_PKG_VERSION").to_string(),
        frf_executable_hash: host::current_exe_hash()?,
    };

    // Transient mutant wrappers live under the store's challenges/ dir.
    fs::create_dir_all(store.root.join("challenges")).map_err(|e| {
        FrfError::new(format!(
            "cannot create {}: {e}",
            store.root.join("challenges").display()
        ))
    })?;

    let mut ids: Vec<String> = Vec::new();
    let mut failures: Vec<String> = Vec::new();
    for op in &operators {
        let label = op.label();
        let target_axis = op.target_axis().to_string();

        // The mutant artifact: generated (built-in) or PROPOSED (external
        // provider). For an external proposal, the request + response +
        // invocation + result are preserved as evidence under the challenge
        // (the exact instrument that proposed the mutant).
        let (mutant_sha256, mutant_bytes, mutation_evidence) = match op {
            ChallengeOperator::Builtin(operator) => {
                let wrapper = operator.wrapper(&reference_sha256);
                (
                    host::sha256_bytes(wrapper.as_bytes()),
                    wrapper.into_bytes(),
                    None,
                )
            }
            ChallengeOperator::External(decl, _) => {
                // The provider is snapshotted + sealed BEFORE it runs; its
                // semantic identity fixes WHAT kind of mutant is asked for.
                let snap = crate::ext::snapshot_program(store, Path::new(&decl.program))?;
                let semantic = MutationSemantic {
                    id: decl.id.clone(),
                    relation_id: decl.relation.clone(),
                    relation_version: decl.relation_version.clone(),
                    specification_hash: crate::semantics::mutation_specification_hash(
                        &decl.id,
                        &decl.relation,
                        &decl.relation_version,
                    )?,
                };
                let fixture_sha256 = {
                    // The fixture the court runs the mutant against: read from
                    // the manifest (the court resolves {fixture} at run time;
                    // the request carries the exact bytes the provider mutates
                    // against).
                    let f = spec
                        .fixture
                        .path
                        .replace("{root}", &store.root.to_string_lossy());
                    let bytes = host::read_file(Path::new(&f))?;
                    let sha = host::sha256_bytes(&bytes);
                    // Ensure the object is materialized so the provider and
                    // the court see the same content-addressed bytes.
                    store.materialize_object(&bytes, false)?;
                    (sha, bytes)
                };
                let reference_bytes = {
                    // The authority artifact bytes: admitted at authority
                    // admit time (the OBJECT is materialized at court run
                    // time, so the challenge materializes it first — the
                    // provider receives the same content-addressed bytes the
                    // court will execute).
                    let bytes = host::read_file(Path::new(&authority.path))?;
                    store.materialize_object(&bytes, true)?;
                    store.verified_object_bytes(&reference_sha256)?
                };
                let request = MutationRequest {
                    schema_version: SCHEMA_MUTATION_REQUEST,
                    mutation: &semantic,
                    court: MutationCourt {
                        id: &spec.id,
                        question: &spec.question,
                        falsifier: &spec.falsifier,
                        observables: &observables,
                        fixture_family: &spec.admissibility_envelope.fixture_family,
                    },
                    target_axis: &target_axis,
                    reference_artifact: MutationArtifact {
                        sha256: &reference_sha256,
                        contents_base64: &crate::ext::b64(&reference_bytes),
                    },
                    fixture: MutationArtifact {
                        sha256: &fixture_sha256.0,
                        contents_base64: &crate::ext::b64(&fixture_sha256.1),
                    },
                };
                let request_bytes = crate::canon::canonical(&request)?.into_bytes();
                let request_cid = crate::ext::request_cid(&request_bytes);
                let response_bytes = crate::ext::run_program(
                    &snap.image,
                    &request_bytes,
                    Path::new("."),
                    profile,
                    &spec.environment.clone().unwrap_or_default(),
                )?;
                let response_cid = host::sha256_bytes(&response_bytes);
                // The protocol says canonical JSON: the response must BE its
                // own canonical serialization.
                let response: MutationResponse =
                    crate::ext::parse_canonical_response(&response_bytes, "mutation response")
                        .map_err(|e| {
                            FrfError::new(format!("mutation provider {id}: {e}", id = decl.id))
                        })?;
                if response.schema_version != SCHEMA_MUTATION_RESPONSE {
                    failures.push(format!(
                        "mutation provider {}: response has unsupported schema version {:?}",
                        decl.id, response.schema_version
                    ));
                    continue;
                }
                if response.request_id != request_cid {
                    failures.push(format!(
                        "mutation provider {}: the response does not name the request it answers; a response must cryptographically name the exact request it answers",
                        decl.id
                    ));
                    continue;
                }
                if let Some(f) = &response.failure {
                    failures.push(format!(
                        "mutation provider {} reported failure: {f}",
                        decl.id
                    ));
                    continue;
                }
                let Some(b64) = &response.mutant_base64 else {
                    failures.push(format!(
                        "mutation provider {} declined to propose a mutant; a proposal is the only admissible outcome",
                        decl.id
                    ));
                    continue;
                };
                let mutant = crate::ext::unb64(b64, "mutation response mutant")
                    .map_err(|e| FrfError::new(format!("mutation provider {}: {e}", decl.id)))?;
                if mutant.is_empty() {
                    failures.push(format!(
                        "mutation provider {} proposed an EMPTY mutant; a mutant must alter the targeted surface",
                        decl.id
                    ));
                    continue;
                }
                let mutant_sha256 = host::sha256_bytes(&mutant);
                let invocation_id = crate::semantics::mutation_invocation_identity(
                    &crate::semantics::MutationInvocationContent {
                        operator: &decl.id,
                        target_axis: &target_axis,
                        request_cid: &request_cid,
                        mutation_semantic_cid: &semantic.specification_hash,
                        mutation_implementation_artifact: &snap.artifact,
                        execution_provenance: &created_by,
                    },
                )?;
                let result_id = crate::semantics::mutation_result_identity(
                    &crate::semantics::MutationResultContent {
                        request_cid: &request_cid,
                        response_cid: &response_cid,
                        outcome: "proposed",
                        mutant_sha256: &mutant_sha256,
                        expected_affected_surfaces: &response.expected_affected_surfaces,
                    },
                )?;
                (
                    mutant_sha256,
                    mutant,
                    Some((
                        request_bytes,
                        response_bytes,
                        invocation_id,
                        result_id,
                        semantic,
                        snap,
                        request_cid,
                        response.expected_affected_surfaces,
                    )),
                )
            }
        };

        // Write the mutant to a deterministic transient path, run the court
        // with it as the candidate override, then remove it: the EVIDENCE is
        // the content-addressed mutant object + the run, not the transient
        // file. The built-in path is derived from the operator + reference
        // hash (root-independent and rederivable); the external mutant path
        // carries the provider id so re-runs overwrite deterministically.
        let mutant_rel = format!(
            "{}/challenges/.mutant-{}-{}.sh",
            store.root.display(),
            label,
            &reference_sha256[..16]
        );
        let mutant_path = Path::new(&mutant_rel);
        fs::write(mutant_path, &mutant_bytes)
            .map_err(|e| FrfError::new(format!("cannot write {}: {e}", mutant_path.display())))?;

        let run_result = run_once(store, manifest_path, Some(&mutant_rel), None, false, None);
        let _ = fs::remove_file(mutant_path);
        let run = match run_result {
            Ok(run) => run,
            Err(e) => {
                failures.push(format!("operator {label}: the mutant run failed: {}", e.0));
                continue;
            }
        };

        // The derived verdicts, from the run's own residuals.
        let capture = store.load_capture(&run)?;
        let mut observed: Vec<String> = Vec::new();
        let mut on_target = false;
        let mut on_unaffected: Vec<String> = Vec::new();
        for rid in &capture.residuals {
            let record = store.load_residual(rid)?;
            if record.axis.as_str() == target_axis {
                on_target = true;
            } else {
                on_unaffected.push(record.axis.as_str().to_string());
            }
            observed.push(rid.clone());
        }
        let unaffected_axes: Vec<String> = observables
            .iter()
            .filter(|o| *o != &target_axis)
            .cloned()
            .collect();
        let saw_defect = on_target;
        let specificity_clean = on_unaffected.is_empty();

        let id = crate::semantics::challenge_identity(
            &spec.id,
            &label,
            &target_axis,
            &reference_sha256,
            &mutant_sha256,
            &run,
        )?;
        // The external proposal's evidence, under `challenges/<id>/mutation/`
        // (request/response/invocation/result, all content-addressed and
        // cross-verified on read).
        let (mutation_invocation_id, mutation_result_id) = match &mutation_evidence {
            Some((
                request_bytes,
                response_bytes,
                invocation_id,
                result_id,
                semantic,
                snap,
                request_cid,
                expected_affected_surfaces,
            )) => {
                let dir = store.challenge_mutation_dir(&id)?;
                fs::create_dir_all(&dir)
                    .map_err(|e| FrfError::new(format!("cannot create {}: {e}", dir.display())))?;
                store.write_once(
                    &dir.join("request.json"),
                    &String::from_utf8(request_bytes.clone()).map_err(|_| {
                        FrfError::new("internal error: mutation request is not UTF-8")
                    })?,
                )?;
                store.write_once(
                    &dir.join("response.json"),
                    &String::from_utf8(response_bytes.clone()).map_err(|_| {
                        FrfError::new("internal error: mutation response is not UTF-8")
                    })?,
                )?;
                let invocation = MutationInvocation {
                    schema_version: SCHEMA_MUTATION_INVOCATION.to_string(),
                    invocation_id: invocation_id.clone(),
                    operator: label.clone(),
                    target_axis: target_axis.clone(),
                    request_cid: request_cid.clone(),
                    mutation_semantic_cid: semantic.specification_hash.clone(),
                    mutation_implementation_artifact: snap.artifact.clone(),
                    execution_provenance: created_by.clone(),
                };
                let result = MutationResult {
                    schema_version: SCHEMA_MUTATION_RESULT.to_string(),
                    result_id: result_id.clone(),
                    request_cid: request_cid.clone(),
                    response_cid: host::sha256_bytes(response_bytes),
                    outcome: "proposed".to_string(),
                    mutant_sha256: mutant_sha256.clone(),
                    expected_affected_surfaces: expected_affected_surfaces.clone(),
                };
                store.write_once(
                    &dir.join("invocation.json"),
                    &store.to_evidence(&invocation)?,
                )?;
                store.write_once(&dir.join("result.json"), &store.to_evidence(&result)?)?;
                (Some(invocation_id.clone()), Some(result_id.clone()))
            }
            None => (None, None),
        };
        store.write_challenge(&CourtChallenge {
            schema_version: SCHEMA_CHALLENGE.to_string(),
            id: id.clone(),
            court: spec.id.clone(),
            operator: label.clone(),
            target_axis: target_axis.clone(),
            reference_sha256: reference_sha256.clone(),
            mutant_candidate_sha256: mutant_sha256,
            run: run.clone(),
            observed_residuals: observed,
            unaffected_axes,
            saw_defect,
            specificity_clean,
            mutation_invocation_id,
            mutation_result_id,
            created_by: created_by.clone(),
        })?;
        ids.push(id.clone());

        if saw_defect && specificity_clean {
            eprintln!(
                "court challenge {id}: operator {label} saw the seeded defect on {target_axis} and nothing else — the court can see this defect class"
            );
        } else {
            let mut why = format!("operator {label}");
            if !saw_defect {
                why.push_str(" — the court observed NO divergence on the targeted axis (blind to the seeded defect)");
            }
            if !specificity_clean {
                why.push_str(&format!(
                    " — the court also observed divergences on unaffected axes: {}",
                    on_unaffected.join(", ")
                ));
            }
            failures.push(why);
        }
    }

    if !failures.is_empty() {
        return Err(FrfError::new(format!(
            "court challenge of {} FAILED: the court did not prove it can see every defect class it declares (the challenge records remain as evidence):\n  {}",
            spec.id,
            failures.join("\n  ")
        )));
    }
    Ok(ids)
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
            produced: None,
            adapted: None,
            stdout_bytes: outcome.stdout.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_keep_newlines_round_trips_byte_for_byte() {
        let text = "# comment\nserver 1.2.3.4\nservre x\n";
        let parts = split_keep_newlines(text);
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], b"# comment\n");
        assert_eq!(parts[2], b"servre x\n");
        assert_eq!(parts.concat(), text.as_bytes());

        // A trailing line without a newline survives.
        let parts = split_keep_newlines("a\nb");
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[1], b"b");
        assert_eq!(parts.concat(), b"a\nb");

        // Empty input yields no elements.
        assert!(split_keep_newlines("").is_empty());
    }
}
