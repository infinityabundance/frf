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
use crate::host;
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

/// The challenge records in the store (ids of `challenges/*.json`).
fn challenge_ids(store: &Store) -> Result<Vec<String>> {
    let dir = store.root.join("challenges");
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut ids: Vec<String> = std::fs::read_dir(&dir)
        .map_err(|e| FrfError::new(format!("cannot read challenges directory: {e}")))?
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
        .map(|e| {
            e.file_name()
                .to_string_lossy()
                .trim_end_matches(".json")
                .to_string()
        })
        .collect();
    ids.sort();
    Ok(ids)
}

/// The witness statements in the store (ids of `witnesses/*.json`).
fn witness_ids(store: &Store) -> Result<Vec<String>> {
    let dir = store.root.join("witnesses");
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut ids: Vec<String> = std::fs::read_dir(&dir)
        .map_err(|e| FrfError::new(format!("cannot read witnesses directory: {e}")))?
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
        .map(|e| {
            e.file_name()
                .to_string_lossy()
                .trim_end_matches(".json")
                .to_string()
        })
        .collect();
    ids.sort();
    Ok(ids)
}

/// The per-axis capability coverage a sensitivity-backed claim requires:
/// every claimed (clean) observable axis must have a challenge record that
/// demonstrated sensitivity on EXACTLY that axis — same court semantic
/// identity (the mutant ran the same question), same reference artifact,
/// the recomputed verdicts `saw_defect` AND `specificity_clean`. The claim
/// carries the content-addressed challenge ids; this function refuses the
/// claim, naming the axis and what would satisfy the tier, when coverage is
/// missing.
fn capability_coverage(
    store: &Store,
    receipt: &Receipt,
    k: &ClaimScope,
) -> Result<Vec<ClaimCapability>> {
    let mut out = Vec::new();
    let ids = challenge_ids(store)?;
    // Each challenge's mutant run is verified ONCE (identity + derivation);
    // the verdicts and the court-semantic-identity binding are recomputed
    // from that verified run.
    let mut challenges: Vec<(CourtChallenge, crate::verify::CaptureVerified)> = Vec::new();
    for id in &ids {
        let ch = store.load_challenge(id)?; // verified: content-addressed
        challenges.push((
            ch.clone(),
            crate::verify::load_capture_verified(store, &ch.run)?,
        ));
    }
    for axis in &k.observables {
        let mut challenge_ids: Vec<String> = Vec::new();
        for (ch, cv) in &challenges {
            if ch.court != receipt.court.id {
                continue;
            }
            if ch.target_axis != *axis {
                continue;
            }
            // The mutant must wrap the SAME reference artifact the receipt
            // binds.
            if ch.reference_sha256 != receipt.authority.identity_hash {
                continue;
            }
            // The mutant run must have answered the SAME question.
            if cv.capture.court_semantic_identity != receipt.court.semantic_identity {
                continue;
            }
            // The verdicts RECOMPUTE from the mutant run's residuals (derived
            // facts are never trusted from the record file).
            let mut on_target = false;
            let mut on_unaffected = false;
            for rid in &cv.capture.residuals {
                let record = store.load_residual(rid)?;
                if record.axis.as_str() == ch.target_axis {
                    on_target = true;
                } else {
                    on_unaffected = true;
                }
            }
            if on_target && !on_unaffected {
                challenge_ids.push(ch.id.clone());
            }
        }
        if challenge_ids.is_empty() {
            return Err(FrfError::new(format!(
                "claim refused under policy sensitivity-backed: the court has NOT demonstrated it can see the {axis} defect class — no challenge record (same court semantic identity, same reference artifact, targeted axis, saw_defect and specificity_clean recomputed from the mutant run) covers the claimed axis; run `frf court challenge` before compiling"
            )));
        }
        challenge_ids.sort();
        out.push(ClaimCapability {
            axis: axis.clone(),
            challenge_ids,
        });
    }
    Ok(out)
}

/// The verified witness statements attesting this receipt (`outcome:
/// affirm`) that an independently-witnessed claim requires. The statement
/// loader verifies the identity rederives, the preserved request/response
/// hash to their cids, and the response names its request — an attestation
/// bound to the exact receipt content address, never a label.
fn witness_coverage(store: &Store, receipt_id: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for id in witness_ids(store)? {
        let stmt = store.load_witness_statement(&id)?;
        if stmt.subject.kind == "receipt"
            && stmt.subject.id == receipt_id
            && stmt.attestation.outcome == "affirm"
        {
            out.push(id);
        }
    }
    if out.is_empty() {
        return Err(FrfError::new(format!(
            "claim refused under policy independently-witnessed: no verified witness statement attests this receipt (subject kind=receipt, id={receipt_id}, outcome=affirm); attest the receipt before compiling"
        )));
    }
    Ok(out)
}

pub fn run(store: &Store, receipt_id: &str, json: bool, policy: &str) -> Result<()> {
    // The admission policy is one of the declared tiers (baseline through
    // high-assurance); a tier the engine does not know is refused, never
    // silently downgraded.
    if !CLAIM_POLICIES.contains(&policy) {
        return Err(FrfError::new(format!(
            "unknown claim policy {policy:?}: the protocol admits {}",
            CLAIM_POLICIES.join(", ")
        )));
    }
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

    // 4b. The admission policy (the assurance grade). Each tier above
    //     `baseline` requires DEMONSTRATED capability evidence, and the
    //     compiled claim carries the evidence that satisfied it — a
    //     sensitivity-backed claim is not "challenge passed" as a boolean, it
    //     names the exact content-addressed challenges that proved the court
    //     can SEE each claimed surface.
    let sensitivity_required = matches!(
        policy,
        CLAIM_POLICY_SENSITIVITY_BACKED
            | CLAIM_POLICY_INDEPENDENTLY_WITNESSED
            | CLAIM_POLICY_HIGH_ASSURANCE
    );
    let capability = if sensitivity_required {
        capability_coverage(store, receipt, &k_scope)?
    } else {
        Vec::new()
    };
    let witness_required = matches!(
        policy,
        CLAIM_POLICY_INDEPENDENTLY_WITNESSED | CLAIM_POLICY_HIGH_ASSURANCE
    );
    let witness_statements = if witness_required {
        witness_coverage(store, receipt_id)?
    } else {
        Vec::new()
    };
    let replay_profile = if policy == CLAIM_POLICY_HIGH_ASSURANCE {
        // High assurance requires the exact-replay contract: the observation
        // was made under the reference profile with the reference capture
        // bounds (no permissive overrides). The claim records the contract.
        if receipt.execution_profile != EXECUTION_PROFILE_LINUX {
            return Err(FrfError::new(format!(
                "claim refused under policy {policy:?}: this receipt's run was observed under execution profile {}; high-assurance requires the reference profile {EXECUTION_PROFILE_LINUX}",
                receipt.execution_profile
            )));
        }
        if receipt.capture_bounds != host::capture_bounds() {
            return Err(FrfError::new(format!(
                "claim refused under policy {policy:?}: this receipt's run was observed under non-reference capture bounds; high-assurance requires the reference harness contract (the exact-replay profile)",
            )));
        }
        EXECUTION_PROFILE_LINUX.to_string()
    } else {
        receipt.execution_profile.clone()
    };

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
        policy: policy.to_string(),
        capability,
        witness_statements,
        replay_profile,
        positive: vec![sentence.clone()],
        non_claims: sentences::non_claims(&family),
    };

    if json {
        let canonical = crate::canon::canonical(&claim)?;
        println!("{canonical}");
        return Ok(());
    }

    let json = store.to_evidence(&claim)?;
    let path = store.claim_path(receipt_id)?;
    store.write_derived(&path, &json)?;

    println!("{sentence}");
    for nc in &claim.non_claims {
        println!("{nc}");
    }
    eprintln!("claim written to {}", path.display());
    Ok(())
}
