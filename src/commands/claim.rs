//! `frf claim compile`: the semantic non-bypass rule, implemented literally.
//!
//! This is the ONLY code path that can produce a positive claim sentence.
//! There is no flag, no verb, no file a human can author that emits claim
//! prose: `claims/` is written solely here, from receipt fields alone.
//!
//! Rules:
//! - Any residual with disposition `open`, `unknown`, or `harness` blocks the
//!   claim. The compile prints the explicit non-claim boundary (one line per
//!   blocking residual) plus the non-claim sentences, and exits non-zero.
//! - Otherwise the compiler emits exactly one conservative sentence, scoped
//!   to the receipt's authority, fixture family, environment, and executed
//!   court — never more — and states the non-claim next to it.

use crate::error::{FrfError, Result};
use crate::model::*;
use crate::sentences;
use crate::store::Store;

pub fn run(store: &Store, receipt_id: &str) -> Result<()> {
    let receipt = store.load_receipt(receipt_id)?;
    let family = receipt.court.admissibility_envelope.fixture_family.clone();

    // 1. Refuse while anything blocks.
    let blockers = sentences::refusal_lines(&receipt);
    if !blockers.is_empty() {
        for line in &blockers {
            eprintln!("{line}");
        }
        let non_claims = sentences::non_claims(&family);
        for nc in &non_claims {
            eprintln!("{nc}");
        }
        return Err(FrfError::new(format!(
            "claim refused: {} blocking residual(s) — no positive claim emitted",
            blockers.len()
        )));
    }

    // 2. Compose the single bounded sentence.
    let Some(sentence) = sentences::positive_claim(&receipt) else {
        let non_claims = sentences::non_claims(&family);
        for nc in &non_claims {
            eprintln!("{nc}");
        }
        return Err(FrfError::new(format!(
            "claim refused: no declared observable axis for fixture family {family} is established as parity (every axis is a documented divergence or unmeasured)"
        )));
    };

    let environment = format!(
        "{}-{} ({})",
        receipt.environment.architecture,
        receipt.environment.os,
        &receipt.environment.environment_digest[..8]
    );
    let claim = ClaimRecord {
        schema_version: SCHEMA_CLAIM.to_string(),
        receipt: receipt_id.to_string(),
        authority: format!("{}-{}", receipt.authority.name, receipt.authority.version),
        court: receipt.court.id.clone(),
        fixture_family: family.clone(),
        environment,
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
