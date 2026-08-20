//! `frf claim compile`: the semantic non-bypass rule, implemented literally.
//!
//! This is the ONLY code path that can produce a positive claim sentence.
//! There is no flag, no verb, no file a human can author that emits claim
//! prose: `claims/` is written solely here, from receipt fields alone.
//!
//! Claim dependency algebra (the paper's rule, implemented): a residual
//! blocks ONLY the claims whose observable scope intersects it.
//!
//! - `harness` invalidates the evidence of the run: every claim from the
//!   receipt is refused, whatever the axes. The refusal names the harness
//!   residuals and exits non-zero.
//! - `open` / `unknown` block claims on their axis only. A receipt with a
//!   clean axis still compiles its scoped claim; the refusal lines for the
//!   blocked axes are printed next to it as explicit non-claim boundaries.
//! - an axis this receipt's run observed diverging is never parity from this
//!   receipt, whatever its disposition — a disposition links history, it
//!   never rewrites an observation. If every declared axis has a residual,
//!   no positive claim is licensed; the refusal names the resolution run to
//!   compile from instead.
//! - Otherwise the compiler emits exactly one conservative sentence, scoped
//!   to the receipt's authority, fixture family, environment, executed
//!   court, and exact candidate artifact — never more — and states the
//!   non-claim next to it.

use crate::error::{FrfError, Result};
use crate::model::*;
use crate::sentences;
use crate::store::Store;

pub fn run(store: &Store, receipt_id: &str) -> Result<()> {
    let receipt = store.load_receipt(receipt_id)?;
    let family = receipt.court.admissibility_envelope.fixture_family.clone();

    // 1. Run-level invalidation: harness blocks every claim from this run.
    let harness_lines = sentences::harness_refusal_lines(&receipt.residuals, &family);
    if !harness_lines.is_empty() {
        for line in &harness_lines {
            eprintln!("{line}");
        }
        for nc in sentences::non_claims(&family) {
            eprintln!("{nc}");
        }
        return Err(FrfError::new(format!(
            "claim refused: {} harness residual(s) invalidate the evidence of this run — no positive claim emitted",
            harness_lines.len()
        )));
    }

    // 2. Axis-level blocking: an open/unknown residual excludes its axis;
    //    clean axes remain claimable. The sentence covers only axes THIS run
    //    observed passing.
    let Some(sentence) = sentences::positive_claim(&receipt) else {
        // No clean axis: print the axis blockers (the non-claim boundaries)
        // plus the non-claim sentences, and refuse.
        for line in sentences::open_refusal_lines(&receipt.residuals, &family) {
            eprintln!("{line}");
        }
        for nc in sentences::non_claims(&family) {
            eprintln!("{nc}");
        }
        // A receipt that observed divergence cannot become a parity receipt;
        // if it carries resolution edges, point at the run that observed the
        // passing candidate.
        let hint = receipt
            .residuals
            .iter()
            .find_map(|res| {
                (res.disposition == "fixed")
                    .then_some(res.resolution_run_id.as_deref())
                    .flatten()
            })
            .map(|run| format!(" — compile the claim from the resolution run '{run}' instead (this receipt's run observed the divergence; a disposition never rewrites an observation)"))
            .unwrap_or_default();
        return Err(FrfError::new(format!(
            "claim refused: no declared observable axis for fixture family {family} is established as parity by this receipt's run{hint}"
        )));
    };

    // 3. A claim IS licensed (scoped to the clean axes). Print the axis
    //    blockers as explicit non-claim boundaries, then the claim.
    for line in sentences::open_refusal_lines(&receipt.residuals, &family) {
        eprintln!("{line}");
    }

    let environment = format!(
        "{}-{} ({})",
        receipt.environment.architecture,
        receipt.environment.os,
        &receipt.environment.digest[..8]
    );
    let claim = ClaimRecord {
        schema_version: SCHEMA_CLAIM.to_string(),
        receipt: receipt_id.to_string(),
        authority: format!("{}-{}", receipt.authority.name, receipt.authority.version),
        candidate: ClaimCandidate {
            name: receipt.candidate.name.clone(),
            version_or_commit: receipt.candidate.version_or_commit.clone(),
            identity_hash: receipt.candidate.identity_hash.clone(),
        },
        court: receipt.court.id.clone(),
        fixture_family: family.clone(),
        environment,
        // Claim IR: the observable scope this claim covers, and the
        // residuals excluded from it (observed divergences on other axes).
        observable_scope: receipt
            .observables
            .iter()
            .filter(|obs| !receipt.residuals.iter().any(|r| r.axis == obs.axis))
            .map(|obs| obs.axis.clone())
            .collect(),
        excluded_residuals: receipt.residuals.iter().map(|r| r.id.clone()).collect(),
        positive: vec![sentence.clone()],
        non_claims: sentences::non_claims(&family),
    };

    let yaml = store.to_yaml(&claim)?;
    let path = store.claim_path(receipt_id)?;
    store.write_derived(&path, &yaml)?;

    println!("{sentence}");
    for nc in &claim.non_claims {
        println!("{nc}");
    }
    eprintln!("claim written to {}", path.display());
    Ok(())
}
