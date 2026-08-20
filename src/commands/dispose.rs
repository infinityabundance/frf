//! `frf residual dispose`: record a residual's disposition.
//!
//! The refusal to dispose without a reason is the misuse-resistance gate from
//! the Taste Codex layer, implemented as a hard error rather than a default.
//! `open` is not settable.
//!
//! The refusal to mark a residual `fixed` without a resolution run is the
//! stronger gate: a disposition is metadata, never evidence. `fixed` requires
//! `--resolution-run <RUN_ID>` naming a court run — for the same court, not
//! the run that produced the residual — whose captures show authority and
//! candidate now agreeing on the residual's axis. That run is the closure
//! evidence; the label only records it.

use crate::cli::ClosureArg;
use crate::error::{FrfError, Result};
use crate::model::ResidualRecord;
use crate::store::Store;

pub fn run(
    store: &Store,
    id: &str,
    disposition: ClosureArg,
    reason: &str,
    resolution_run: Option<String>,
) -> Result<()> {
    let mut record = store.load_residual(id)?;
    let before = record.disposition.as_str();

    match (disposition, resolution_run) {
        (ClosureArg::Fixed, None) => {
            return Err(FrfError::new(
                "disposition 'fixed' requires --resolution-run <RUN_ID>: \
                 the court run whose captures show this residual no longer \
                 reproduces (a disposition is not evidence)",
            ));
        }
        (ClosureArg::Fixed, Some(run)) => {
            validate_resolution_run(store, &record, &run)?;
            record.dispose_fixed(reason.to_string(), run)?;
        }
        (_other, Some(_)) => {
            return Err(FrfError::new(
                "--resolution-run is only meaningful with --disposition fixed",
            ));
        }
        (other, None) => {
            record.dispose(
                other
                    .closure_kind()
                    .expect("non-fixed ClosureArg maps to a ClosureKind"),
                reason.to_string(),
            )?;
        }
    }

    store.write_residual(&record)?;
    match &record.disposition {
        crate::model::Disposition::Fixed {
            resolution_run_id, ..
        } => {
            eprintln!(
                "residual {id}: {before} -> fixed ({}) [closure observed in run {resolution_run_id}]",
                reason.trim()
            );
        }
        _ => {
            eprintln!(
                "residual {id}: {before} -> {} ({})",
                record.disposition.as_str(),
                reason.trim()
            );
        }
    }
    Ok(())
}

/// The closure predicate: the run must exist, be a *new* run for the same
/// court, and show authority and candidate agreeing on the residual's axis.
fn validate_resolution_run(store: &Store, record: &ResidualRecord, run: &str) -> Result<()> {
    if run == record.run {
        return Err(FrfError::new(format!(
            "resolution run must be a new court run, not '{}' — the run that produced residual {}",
            record.run, record.id
        )));
    }
    if !store.run_closes_axis(run, &record.court, record.axis)? {
        return Err(FrfError::new(format!(
            "run '{run}' does not close residual {}: the {} axis still diverges in its captures (a fixed disposition must be backed by a run where the residual no longer reproduces)",
            record.id,
            record.axis.as_str()
        )));
    }
    Ok(())
}
