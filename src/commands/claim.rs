//! `frf claim compile`: the semantic non-bypass rule, implemented literally.
//!
//! This is the ONLY code path that can produce a positive claim sentence.
//! There is no flag, no verb, no file a human can author that emits claim
//! prose: `claims/` is written solely here, from verified evidence.
//!
//! Claim dependency algebra (Section 10 of the paper, implemented): admission
//! is set containment — `Scope(K) ⊆ Scope(P₁ ∪ … ∪ Pₙ)` — and a blocking
//! residual blocks EXACTLY the claims whose scope intersects its surface.
//!
//! - `harness` invalidates the evidence of a premise run: no claim whose
//!   `requires` includes a harness run, whatever the axes.
//! - `open` / `unknown` residuals block claims whose scope intersects their
//!   surface (same authority, same candidate artifact, same fixture, same
//!   family, same environment, same version, same axis) — WHEREVER the
//!   divergence was recorded, not merely in this receipt: the compiler scans
//!   the whole store, so an unexplained divergence about the claimed surface
//!   blocks the claim even when a later run passed. A residual about a
//!   different candidate, axis, fixture, or environment does not block (a
//!   disposition, or a later run, never rewrites an older observation).
//! - an axis this receipt's run observed diverging is never parity from this
//!   receipt, whatever its disposition. If every declared axis has a
//!   residual, no positive claim is licensed; the refusal names the
//!   resolution run to compile from instead.
//! - Otherwise the compiler emits exactly one conservative sentence, scoped
//!   to the receipt's authority, fixture family, environment, executed
//!   court, and exact candidate artifact — never more — and states the
//!   non-claim next to it. The claim file carries the full Claim IR; prose
//!   is one renderer (`--json` emits the same IR canonically).

use crate::error::{FrfError, Result};
use crate::model::*;
use crate::scope;
use crate::sentences;
use crate::store::Store;

/// Blocking residuals: `open`/`unknown` (unexplained divergences). `harness`
/// is run-level and handled separately.
fn is_scope_blocking(disposition: &str) -> bool {
    matches!(disposition, "open" | "unknown")
}

/// Scan the EVIDENCE UNIVERSE (the committed [`KnowledgeSnapshot`] the claim
/// is being compiled against — not a live directory) for residuals whose
/// surface intersects the claim's scope K and whose head disposition in that
/// universe is blocking. Returns the residual ids.
///
/// This is the cross-run part of the algebra: a claim compiled from receipt
/// R is blocked by an open divergence recorded by ANY run in the universe
/// about the same surface (same authority, candidate artifact, fixture,
/// family, environment, version, and axis). A divergence about a different
/// surface — most importantly, a different candidate artifact — never
/// blocks: that is the paper's rule that no observation may be rewritten,
/// generalized to scopes.
///
/// The universe is EXPLICIT: the claim is admissible relative to U — no
/// unresolved residual IN U intersects K — and the compiled claim carries U,
/// so the same scan reproduces in any implementation from the claim alone.
/// A residual disposed after compile time does not rewrite the claim; a
/// residual created after compile time is outside U and does not rewrite it
/// either (the claim documents the state of knowledge it was admissible
/// under).
///
/// Shared with `verify_tree` so a compiled claim and its re-derivation run
/// the SAME scan (one source of truth).
pub fn store_blockers(
    store: &Store,
    k: &ClaimScope,
    universe: &KnowledgeSnapshot,
) -> Result<Vec<(String, ResidualKind, String)>> {
    let mut blockers = Vec::new();
    for head in &universe.residual_heads {
        if !is_scope_blocking(&head.disposition) {
            continue;
        }
        let record = store.load_residual(&head.id)?;
        // The universe commits the exact observation: the record loaded now
        // must BE the record the universe named (canonical record content
        // address + fingerprint). A store that no longer matches the
        // committed universe cannot be scanned against it — the claim would
        // be compiled against evidence it does not name.
        let record_cid = crate::semantics::record_content_identity(&record)?;
        if record_cid != head.record_cid {
            return Err(FrfError::new(format!(
                "residual {} no longer matches the committed knowledge universe (its record content address changed); re-compile against a fresh universe",
                head.id
            )));
        }
        let fingerprint = crate::semantics::residual_fingerprint(&record)?;
        if fingerprint != head.fingerprint {
            return Err(FrfError::new(format!(
                "residual {} no longer matches the committed knowledge universe (its fingerprint changed); re-compile against a fresh universe",
                head.id
            )));
        }
        let capture = store.load_capture(&record.run)?;
        let authority = store.load_authority(&record.authority)?;
        let surface = scope::residual_scope(&record, &capture, &authority.version);
        if surface.intersects(k) {
            blockers.push((record.id.clone(), record.kind, head.disposition.clone()));
        }
    }
    blockers.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(blockers)
}

pub fn run(store: &Store, receipt_id: &str, json: bool) -> Result<()> {
    // The semantic non-bypass rule, enforced structurally: claim compilation
    // accepts ONLY a ReceiptVerified — a receipt whose identity AND derivation
    // have been verified (content-addressed, semantically conformant, derived
    // from its verified capture, dispositions evidenced by the event history,
    // fixed closures re-verified). Parsing data cannot turn it into evidence.
    let verified = crate::verify::load_receipt_verified(store, receipt_id).map_err(|e| {
        // An invalid id keeps its validation refusal; a valid id naming no
        // receipt gets the friendly refusal; anything that exists but fails
        // verification keeps the specific violation.
        match store.receipt_path(receipt_id) {
            Err(validation) => validation,
            Ok(p) if p.is_file() => e,
            Ok(_) => FrfError::new(format!("no such receipt '{receipt_id}'")),
        }
    })?;
    let receipt = verified.body();
    let family = receipt.court.admissibility_envelope.fixture_family.clone();

    // 1. Run-level invalidation: harness on a premise blocks every claim from
    //    that run.
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
    let Some(sentence) = sentences::positive_claim(receipt) else {
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

    // 3. The claim IR. Scope K is the executed surface restricted to the
    //    clean axes; admission is the containment rule
    //    Scope(K) ⊆ Scope(P₁ ∪ … ∪ Pₙ) — checked literally against the
    //    premise surface (it holds by construction for a single receipt; the
    //    check is the guard that keeps it true when premises grow).
    let k_scope = scope::claim_scope(receipt);
    let premise = scope::premise_scope(receipt);
    if !premise.contains(&k_scope) {
        return Err(FrfError::new(
            "claim refused: Scope(K) ⊄ Scope(P) — the claim's scope exceeds the receipt's executed surface".to_string(),
        ));
    }

    // 4. Store-wide blocking: any open/unknown residual about the claimed
    //    surface blocks, wherever it was recorded. The universe is committed
    //    BEFORE the scan: the claim is admissible relative to U, and the
    //    compiled claim carries U (a later store mutation cannot silently
    //    change what the claim means — the negative search is as portable as
    //    the premises).
    let knowledge_snapshot = store.knowledge_snapshot()?;
    let blockers = store_blockers(store, &k_scope, &knowledge_snapshot)?;
    if !blockers.is_empty() {
        for (id, kind, disposition) in &blockers {
            eprintln!(
                "cannot claim compatibility for fixture family {family} because residual {id} ({}) is {disposition} — it was observed on the claimed surface and remains unexplained",
                kind.as_str()
            );
        }
        for nc in sentences::non_claims(&family) {
            eprintln!("{nc}");
        }
        return Err(FrfError::new(format!(
            "claim refused: {} blocking residual(s) intersect this claim's scope — no positive claim emitted while an unexplained divergence on the claimed surface exists",
            blockers.len()
        )));
    }

    // 5. A claim IS licensed (scoped to the clean axes). Print the axis
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
    let relation = receipt
        .observables
        .iter()
        .filter(|obs| !receipt.residuals.iter().any(|r| r.axis == obs.axis))
        .map(|obs| obs.comparator.clone())
        .collect::<Vec<_>>()
        .join(", ");
    let proposition = format!(
        "parity(observables=[{}]; fixtures=[{}]; family={}; authority=[{}]; candidate=[{}]; environments=[{}]; versions=[{}])",
        k_scope.observables.join(", "),
        k_scope.fixtures.join(", "),
        k_scope.fixture_family,
        k_scope.authority.join(", "),
        k_scope.candidate.join(", "),
        k_scope.environments.join(", "),
        k_scope.versions.join(", "),
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
        relation,
        proposition,
        scope: k_scope.clone(),
        observable_scope: k_scope.observables.clone(),
        blockers: blockers.iter().map(|(id, _, _)| id.clone()).collect(),
        excluded_evidence: receipt.residuals.iter().map(|r| r.id.clone()).collect(),
        requires: vec![receipt_id.to_string()],
        knowledge_snapshot,
        positive: vec![sentence.clone()],
        non_claims: sentences::non_claims(&family),
    };

    if json {
        let canonical = crate::canon::canonical(&claim)?;
        println!("{canonical}");
        return Ok(());
    }

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
