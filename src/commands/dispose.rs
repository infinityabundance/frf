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
//! The refusal to mark a residual `fixed` without a resolution run is the
//! stronger gate: a disposition is metadata, never evidence. `fixed` requires
//! `--resolution-run <RUN_ID>` naming a court run that reran the SAME
//! evidentiary question under a compatible envelope (same court, authority,
//! fixture, arguments, observables, normalizers, environment) with the
//! candidate free to differ, and whose captures show the axis now agreeing.
//! The verified predicate is recorded on the event.

use crate::cli::ClosureArg;
use crate::error::{FrfError, Result};
use crate::model::*;
use crate::store::Store;

pub fn run(
    store: &Store,
    id: &str,
    disposition: ClosureArg,
    reason: &str,
    resolution_run: Option<String>,
) -> Result<()> {
    let record = store.load_residual(id)?;
    let before = store.current_disposition(id)?;

    let event = match (disposition, resolution_run) {
        (ClosureArg::Fixed, None) => {
            return Err(FrfError::new(
                "disposition 'fixed' requires --resolution-run <RUN_ID>: \
                 the court run whose captures show this residual no longer \
                 reproduces (a disposition is not evidence)",
            ));
        }
        (ClosureArg::Fixed, Some(run)) => {
            // The resolution run must rerun the same question under a
            // compatible envelope; everything but the candidate is held
            // stable. The candidate is exactly what a fix is allowed to
            // change, and both runs record their artifact hashes.
            store.resolution_compatibility(&record.run, &run, record.axis)?;
            DispositionEvent::fixed(
                id,
                reason.to_string(),
                run,
                CLOSURE_PREDICATE_FIX_COURT.to_string(),
            )?
        }
        (_other, Some(_)) => {
            return Err(FrfError::new(
                "--resolution-run is only meaningful with --disposition fixed",
            ));
        }
        (other, None) => DispositionEvent::closed(
            id,
            other
                .closure_kind()
                .expect("non-fixed ClosureArg maps to a ClosureKind"),
            reason.to_string(),
        )?,
    };

    store.append_disposition_event(&event)?;
    // The derived token follows the projected disposition.
    store.write_token(&record, &event.disposition)?;

    match &event.disposition {
        Disposition::Fixed {
            resolution_run_id, ..
        } => {
            eprintln!(
                "residual {id}: {} -> fixed ({}) [closure observed in run {resolution_run_id}]",
                before.as_str(),
                reason.trim()
            );
        }
        _ => {
            eprintln!(
                "residual {id}: {} -> {} ({})",
                before.as_str(),
                event.disposition.as_str(),
                reason.trim()
            );
        }
    }
    Ok(())
}
