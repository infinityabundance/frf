//! `frf residual dispose`: append a disposition event to a residual.
//!
//! Dispositions are append-only events under `residuals/<id>.events/`; the
//! observation record itself is never rewritten, so a residual's trajectory
//! survives re-disposition and a receipt never changes epistemic meaning.
//!
//! The refusal to dispose without a reason is the misuse-resistance gate from
//! the Taste Codex layer. `open` is not settable (it is the projection of no
//! events).
//!
//! The evidence-bearing dispositions each require their evidence edge, and
//! each edge is VERIFIED before it is recorded — a disposition is metadata,
//! never evidence:
//!
//! - `fixed` requires `--resolution-run <RUN_ID>` naming a court run that
//!   reran the SAME evidentiary question under a compatible envelope (same
//!   court, authority, fixture, arguments, observables, normalizers,
//!   environment) whose captures show the axis now agreeing, AND a CHANGED
//!   candidate artifact. A later pass on the same candidate is a
//!   non-reproduction, not a fix — the command refuses and points at the
//!   honest label.
//! - `nonreproduced` requires `--observation-run <RUN_ID>` naming a court
//!   run of the same question whose captures show the residual did not
//!   reproduce while the candidate stayed IDENTICAL. A single pass on the
//!   same candidate is real evidence of nondeterminism, never remediation
//!   evidence: it still blocks positive claims.
//! - `stabilized` requires `--trajectory <TRAJECTORY_ID>` +
//!   `--consecutive-passes N`: a VERIFIED trajectory whose tail shows N
//!   consecutive non-reproductions (N ≥ the protocol floor of 2), all under
//!   the SAME candidate. The trajectory is RE-DERIVED from its series and
//!   byte-compared before the disposition is recorded.
//!
//! The append itself is a COMPARE-AND-SWAP against the chain's last event:
//! the caller re-reads the chain, and a concurrent writer that appended first
//! is a conflict, not a silent overwrite. `Store::append_disposition_event_cas`
//! retries a bounded number of times; the event CONTENT never depends on the
//! chain (the parent link is filled by the append), so a retry rebuilds
//! nothing.

use crate::cli::ClosureArg;
use crate::error::{FrfError, Result};
use crate::model::*;
use crate::store::Store;

// One argument per disposition dimension; the closure is the command's whole
// surface.
#[allow(clippy::too_many_arguments)]
pub fn run(
    store: &Store,
    id: &str,
    disposition: ClosureArg,
    reason: &str,
    resolution_run: Option<String>,
    observation_run: Option<String>,
    trajectory: Option<String>,
    consecutive_passes: Option<u32>,
) -> Result<()> {
    // 0.1.59: a disposition may only be appended to a VERIFIED residual —
    // identity + derivation from its parent run are established before the
    // record's run/axis may drive the closure predicate (a forged residual
    // must not be closable, and a `fixed` disposition must not be granted
    // against an unverified resolution comparison).
    let verified = crate::verify::load_residual_verified(store, id)?;
    let record = verified.record();
    let before = store.current_disposition(id)?;

    let event = match (
        disposition,
        resolution_run,
        observation_run,
        trajectory,
        consecutive_passes,
    ) {
        (ClosureArg::Fixed, None, _, _, _) => {
            return Err(FrfError::new(
                "disposition 'fixed' requires --resolution-run <RUN_ID>: \
                 the court run whose captures show this residual no longer \
                 reproduces under a CHANGED candidate (a disposition is not \
                 evidence)",
            ));
        }
        (ClosureArg::Fixed, Some(run), _, _, _) => {
            // The resolution run must rerun the same question under a
            // compatible envelope; everything but the candidate is held
            // stable. The candidate is exactly what a fix is allowed to
            // change — and MUST change: a later pass on the same candidate
            // is a non-reproduction, not a fix. Both runs record their
            // artifact hashes.
            store.resolution_compatibility(&record.run, &run, &record.axis)?;
            store.require_fix_candidate_change(&record.run, &run)?;
            DispositionEvent::fixed(
                id,
                reason.to_string(),
                run,
                CLOSURE_PREDICATE_FIX_COURT.to_string(),
            )?
        }
        (ClosureArg::Nonreproduced, Some(_), _, _, _) => {
            return Err(FrfError::new(
                "disposition 'nonreproduced' takes --observation-run, not --resolution-run: \
                 a non-reproduction is a pass on the SAME candidate; a changed candidate is a fix",
            ));
        }
        (ClosureArg::Nonreproduced, None, None, _, _) => {
            return Err(FrfError::new(
                "disposition 'nonreproduced' requires --observation-run <RUN_ID>: \
                 the court run whose captures show this residual did not \
                 reproduce while the candidate stayed IDENTICAL (a \
                 disposition is not evidence)",
            ));
        }
        (ClosureArg::Nonreproduced, None, Some(run), _, _) => {
            // Same question + envelope, axis closes, and the candidate is
            // IDENTICAL — the observation run's pass is a non-reproduction,
            // and the record says so honestly instead of borrowing `fixed`'s
            // remediation vocabulary.
            store.resolution_compatibility(&record.run, &run, &record.axis)?;
            store.require_same_candidate(&record.run, &run)?;
            DispositionEvent::nonreproduced(id, reason.to_string(), run)?
        }
        (ClosureArg::Stabilized, Some(_), _, _, _) => {
            return Err(FrfError::new(
                "disposition 'stabilized' takes --trajectory + --consecutive-passes, not --resolution-run",
            ));
        }
        (ClosureArg::Stabilized, None, Some(_), _, _) => {
            return Err(FrfError::new(
                "disposition 'stabilized' takes --trajectory + --consecutive-passes, not --observation-run",
            ));
        }
        (ClosureArg::Stabilized, None, None, None, _) => {
            return Err(FrfError::new(
                "disposition 'stabilized' requires --trajectory <TRAJECTORY_ID> and --consecutive-passes N: \
                 the verified trajectory whose tail establishes persistent disappearance (a disposition is not evidence)",
            ));
        }
        (ClosureArg::Stabilized, None, None, Some(_), None) => {
            return Err(FrfError::new(
                "disposition 'stabilized' requires --consecutive-passes N: \
                 the consecutive non-reproductions the trajectory tail established",
            ));
        }
        (ClosureArg::Stabilized, None, None, Some(traj), Some(passes)) => {
            if passes < STABILIZATION_MIN_CONSECUTIVE_PASSES {
                return Err(FrfError::new(format!(
                    "consecutive_passes {passes} is below the protocol floor of {STABILIZATION_MIN_CONSECUTIVE_PASSES} — a single pass is 'nonreproduced', not 'stabilized'"
                )));
            }
            store.require_stabilization_trajectory(record, &traj, &passes.to_string())?;
            DispositionEvent::stabilized(
                id,
                reason.to_string(),
                traj,
                passes.to_string(),
                STABILIZATION_MIN_CONSECUTIVE_PASSES.to_string(),
            )?
        }
        (_other, Some(_), _, _, _)
        | (_other, None, Some(_), _, _)
        | (_other, None, None, Some(_), _)
        | (_other, None, None, None, Some(_)) => {
            return Err(FrfError::new(
                "--resolution-run/--observation-run/--trajectory/--consecutive-passes are only meaningful with --disposition fixed/nonreproduced/stabilized",
            ));
        }
        (other, None, None, None, None) => DispositionEvent::closed(
            id,
            other
                .closure_kind()
                .expect("non-evidence ClosureArg maps to a ClosureKind"),
            reason.to_string(),
        )?,
    };

    // The append is a compare-and-swap against the chain's last event (the
    // multi-writer-safe append): a concurrent dispose that won first is a
    // conflict, and the bounded retry re-reads the chain. The event's CONTENT
    // never depends on the chain, so nothing is rebuilt.
    let event = store.append_disposition_event_cas(id, &event)?;
    // The derived token follows the projected disposition.
    store.write_token(record, &event.disposition)?;

    match &event.disposition {
        Disposition::Fixed {
            resolution_run_id, ..
        } => {
            eprintln!(
                "residual {id}: {} -> fixed ({}) [closure observed in run {resolution_run_id} under a changed candidate] [event {}]",
                before.as_str(),
                reason.trim(),
                &event.event_id[..16]
            );
        }
        Disposition::Nonreproduced {
            observation_run_id, ..
        } => {
            eprintln!(
                "residual {id}: {} -> nonreproduced ({}) [did not reproduce in run {observation_run_id} under the SAME candidate — still blocks claims] [event {}]",
                before.as_str(),
                reason.trim(),
                &event.event_id[..16]
            );
        }
        Disposition::Stabilized {
            trajectory_id,
            consecutive_passes,
            ..
        } => {
            eprintln!(
                "residual {id}: {} -> stabilized ({}) [trajectory {trajectory_id}: {consecutive_passes} consecutive non-reproductions under the SAME candidate — still blocks claims] [event {}]",
                before.as_str(),
                reason.trim(),
                &event.event_id[..16]
            );
        }
        _ => {
            eprintln!(
                "residual {id}: {} -> {} ({}) [event {}]",
                before.as_str(),
                event.disposition.as_str(),
                reason.trim(),
                &event.event_id[..16]
            );
        }
    }
    Ok(())
}
