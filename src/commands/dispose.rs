//! `frf residual dispose`: record a residual's disposition with a mandatory
//! one-line reason. The refusal to dispose without a reason is the
//! misuse-resistance gate from the Taste Codex layer, implemented as a hard
//! error rather than a default. `open` is not settable.

use crate::error::Result;
use crate::model::ClosureKind;
use crate::store::Store;

pub fn run(store: &Store, id: &str, kind: ClosureKind, reason: &str) -> Result<()> {
    let mut record = store.load_residual(id)?;
    let before = record.disposition.as_str();
    record.dispose(kind, reason.to_string())?;
    store.write_residual(&record)?;
    eprintln!(
        "residual {id}: {before} -> {} ({})",
        kind.as_str(),
        reason.trim()
    );
    Ok(())
}
