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
//! Since v6 the compiler is MULTI-PREMISE: `frf claim compile R1 R2 …` takes
//! any number of verified premise receipts. K is a REGION of cells (one per
//! premise's clean surface, in disjunctive normal form — a union of Cartesian
//! products is never the product of dimension-wise unions, so no surface a
//! premise did not observe is ever invented). The premise union P is the cell
//! list of the premises' FULL surfaces, and admission is checked literally:
//! every point of every K cell must lie in SOME premise cell.
//!
//! All premises must bind the SAME authority and the SAME candidate artifact:
//! a claim asserts parity of one candidate against one reference, over a
//! surface the premises jointly observed. Different fixtures, axes,
//! environments, and courts are the point of multiple premises.
//!
//! - `harness` invalidates the evidence of a premise run: no claim whose
//!   `requires` includes a harness run, whatever the axes.
//! - `open` / `unknown` residuals block claims whose scope intersects their
//!   surface (same authority, same candidate artifact, same fixture, same
//!   family, same environment, same version, same axis) — WHEREVER the
//!   divergence was recorded, not merely in a premise receipt: the compiler
//!   scans the whole committed universe, so an unexplained divergence about
//!   any claimed cell's surface blocks the claim even when a later run
//!   passed. A residual about a different candidate, axis, fixture, or
//!   environment does not block (a disposition, or a later run, never
//!   rewrites an older observation).
//! - an axis a premise's run observed diverging is never parity from THAT
//!   premise, whatever its disposition — but it remains claimable from
//!   another premise that observed it passing, unless an unexplained
//!   divergence on that surface blocks (the cross-run rule).
//! - Otherwise the compiler emits one conservative sentence per premise
//!   cell, scoped to the authority, fixture family, environment, executed
//!   court, and exact candidate artifact — never more — and states the
//!   non-claim next to them. The claim file carries the full Claim IR; prose
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
/// surface intersects the claim's scope region K and whose head disposition
/// in that universe is blocking. Returns the residual ids.
///
/// This is the cross-run part of the algebra: a claim is blocked by an open
/// divergence recorded by ANY run in the universe about the same surface
/// (same authority, candidate artifact, fixture, family, environment,
/// version, and axis) as ANY of the claim's cells. A divergence about a
/// different surface — most importantly, a different candidate artifact —
/// never blocks: that is the paper's rule that no observation may be
/// rewritten, generalized to scopes.
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
    k: &EvidenceRegion,
    universe: &KnowledgeSnapshot,
) -> Result<Vec<(String, ResidualKind, String)>> {
    let mut blockers = Vec::new();
    for head in &universe.residual_heads {
        if !is_scope_blocking(&head.disposition) {
            continue;
        }
        // The residual is VERIFIED before its scope may be read: identity +
        // derivation from its verified parent run (the same doctrine the
        // blocker scan's scope depends on — an unverified record cannot
        // decide whether a claim is blocked).
        let verified = crate::verify::load_residual_verified(store, &head.id)?;
        let record = verified.record();
        // The universe commits the exact observation: the record loaded now
        // must BE the record the universe named (canonical record content
        // address + fingerprint). A store that no longer matches the
        // committed universe cannot be scanned against it — the claim would
        // be compiled against evidence it does not name.
        let record_cid = crate::semantics::record_content_identity(record)?;
        if record_cid != head.record_cid {
            return Err(FrfError::new(format!(
                "residual {} no longer matches the committed knowledge universe (its record content address changed); re-compile against a fresh universe",
                head.id
            )));
        }
        let fingerprint = crate::semantics::residual_fingerprint(record)?;
        if fingerprint != head.fingerprint {
            return Err(FrfError::new(format!(
                "residual {} no longer matches the committed knowledge universe (its fingerprint changed); re-compile against a fresh universe",
                head.id
            )));
        }
        let authority = store.load_authority(&record.authority)?;
        let surface =
            scope::residual_scope(record, &verified.capture().capture, &authority.version);
        if k.intersects(&surface) {
            blockers.push((
                record.id.clone(),
                record.kind.clone(),
                head.disposition.clone(),
            ));
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

/// The per-axis capability coverage ONE premise's claim cell requires: every
/// claimed (clean) observable axis of that premise must have a challenge
/// record that demonstrated sensitivity on EXACTLY that axis — same court
/// semantic identity (the mutant ran the same question), same reference
/// artifact, the recomputed verdicts `saw_defect` AND `specificity_clean`.
/// The claim carries the content-addressed challenge ids BOUND TO THE
/// PREMISE RECEIPT; this function refuses the claim, naming the axis and
/// what would satisfy the tier, when coverage is missing.
///
/// v9: the returned entry also carries the DEMONSTRATED MUTATION PROFILE —
/// the distinct operators of the covering challenges — and `required` (the
/// `AXIS:FAMILY` pairs the claim was compiled under) constrains the
/// coverage: a required family on a claimed axis must be among the
/// demonstrated operators, and a required pair for an axis the claim does
/// not cover is refused (a claim cannot require sensitivity on a surface it
/// does not claim — the profile stays bounded, never a correctness claim).
fn capability_coverage(
    store: &Store,
    receipt_id: &str,
    receipt: &Receipt,
    k: &ClaimScope,
    required: &[String],
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
    // The required AXIS:FAMILY pairs, validated: an axis the claim does not
    // claim is refused (bounded — never a requirement on an unclaimed
    // surface).
    let required_pairs: Vec<(String, String)> = required
        .iter()
        .map(|entry| {
            let (axis, family) = entry.split_once(':').ok_or_else(|| {
                FrfError::new(format!(
                    "claim refused under policy sensitivity-backed: the required mutation profile entry {entry:?} is not AXIS:FAMILY"
                ))
            })?;
            if !k.observables.contains(&axis.to_string()) {
                return Err(FrfError::new(format!(
                    "claim refused under policy sensitivity-backed: the required mutation profile names axis {axis}, which the claim does not cover — a claim cannot require sensitivity on a surface it does not assert"
                )));
            }
            Ok((axis.to_string(), family.to_string()))
        })
        .collect::<Result<Vec<_>>>()?;
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
            // facts are never trusted from the record file, and each residual
            // is itself VERIFIED — identity + derivation from its parent run
            // — before its axis is read).
            let mut on_target = false;
            let mut on_unaffected = false;
            for rid in &cv.capture.residuals {
                let record = crate::verify::load_residual_verified(store, rid)?;
                if record.record().axis.as_str() == ch.target_axis {
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
                "claim refused under policy sensitivity-backed: the court has NOT demonstrated it can see the {axis} defect class — no challenge record (same court semantic identity, same reference artifact, targeted axis, saw_defect and specificity_clean recomputed from the mutant run) covers the claimed axis of premise {receipt_id}; run `frf court challenge` before compiling"
            )));
        }
        // The DEMONSTRATED mutation profile: the distinct operators of the
        // covering challenges (sorted, so the profile is a deterministic set
        // identity and a verifier can re-derive it from the named records).
        let mut mutation_profile: Vec<String> = challenges
            .iter()
            .filter(|(ch, _)| challenge_ids.contains(&ch.id))
            .map(|(ch, _)| ch.operator.clone())
            .collect();
        mutation_profile.sort();
        mutation_profile.dedup();
        // The REQUIRED families on THIS axis must be demonstrated.
        for (req_axis, family) in &required_pairs {
            if req_axis == axis && !mutation_profile.contains(family) {
                return Err(FrfError::new(format!(
                    "claim refused under policy sensitivity-backed: the court has NOT demonstrated the {family} mutation family on the claimed {axis} axis — the required profile {family} (on {req_axis}) is not among the demonstrated operators {}; run `frf court challenge --operators {family}` before compiling",
                    mutation_profile.join(", ")
                )));
            }
        }
        challenge_ids.sort();
        out.push(ClaimCapability {
            receipt: receipt_id.to_string(),
            axis: axis.clone(),
            mutation_profile,
            challenge_ids,
        });
    }
    Ok(out)
}

/// Resolve a claim render target: a claim content address directly, or a
/// receipt via the `claims/by-receipt/<receipt>/` index. A receipt compiled
/// more than once (a different committed universe or admission policy is a
/// DIFFERENT claim) names several claims — the caller must render by claim
/// id; the index keeps the ambiguity visible instead of picking one
/// arbitrarily.
pub fn resolve_claim(store: &Store, target: &str) -> Result<String> {
    if let Ok(p) = store.claim_path(target) {
        if p.is_file() {
            return Ok(target.to_string());
        }
    }
    let ids = store.claim_ids_for_receipt(target)?;
    match ids.len() {
        0 => Err(FrfError::new(format!(
            "no compiled claim for '{target}': run `frf claim compile {target}` first — the renderers present the verified IR"
        ))),
        1 => Ok(ids[0].clone()),
        _ => Err(FrfError::new(format!(
            "receipt '{target}' has {} compiled claims (a different universe or policy is a different claim): render one by its claim id: {}",
            ids.len(),
            ids.join(", ")
        ))),
    }
}

/// The verified witness statements attesting one premise receipt
/// (`outcome: affirm`) that an independently-witnessed claim requires. The
/// verified loader establishes the identity rederives, the preserved
/// request/response hash to their cids, the response names its request, AND
/// the subject is REBOUND to the actual evidence object (the statement's
/// subject cid must rederive from the verified premise receipt itself) — an
/// attestation bound to the exact receipt content address, never a label,
/// and never a self-consistent but misbound statement.
fn witness_coverage(store: &Store, receipt_id: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for id in witness_ids(store)? {
        let stmt = crate::verify::load_witness_statement_verified(store, &id)?;
        if stmt.subject().kind == "receipt"
            && stmt.subject().id == receipt_id
            && stmt.statement().attestation.outcome == "affirm"
        {
            out.push(id);
        }
    }
    if out.is_empty() {
        return Err(FrfError::new(format!(
            "claim refused under policy independently-witnessed: no verified witness statement attests premise receipt {receipt_id} (subject kind=receipt, outcome=affirm); attest every premise before compiling"
        )));
    }
    Ok(out)
}

/// The machine-readable proposition of one scope cell — a pure function of
/// the cell, shared by the claim compiler and the verified loader (the
/// claim's stored proposition must rederive).
pub fn cell_proposition(cell: &ClaimScope) -> String {
    format!(
        "{{observables=[{}]; fixtures=[{}]; family={}; authority=[{}]; candidate=[{}]; environments=[{}]; versions=[{}]}}",
        cell.observables.join(", "),
        cell.fixtures.join(", "),
        cell.fixture_family,
        cell.authority.join(", "),
        cell.candidate.join(", "),
        cell.environments.join(", "),
        cell.versions.join(", "),
    )
}

/// The resolution-run hint for a premise that observed only divergences.
fn resolution_hint(receipt: &Receipt) -> String {
    receipt
        .residuals
        .iter()
        .find_map(|res| {
            (res.disposition == "fixed")
                .then_some(res.resolution_run_id.as_deref())
                .flatten()
        })
        .map(|run| format!(" — compile the claim from the resolution run '{run}' instead (that premise's run observed the divergence; a disposition never rewrites an observation)"))
        .unwrap_or_default()
}

pub fn run(
    store: &Store,
    receipt_ids: &[String],
    json: bool,
    policy: &str,
    mutation_profile: &str,
) -> Result<()> {
    // The admission policy is one of the declared tiers (baseline through
    // high-assurance); a tier the engine does not know is refused, never
    // silently downgraded.
    if !CLAIM_POLICIES.contains(&policy) {
        return Err(FrfError::new(format!(
            "unknown claim policy {policy:?}: the protocol admits {}",
            CLAIM_POLICIES.join(", ")
        )));
    }
    if receipt_ids.is_empty() {
        return Err(FrfError::new(
            "claim compile needs at least one premise receipt: frf claim compile R1 [R2 …]",
        ));
    }

    // The semantic non-bypass rule, enforced structurally: claim compilation
    // accepts ONLY ReceiptVerified values — receipts whose identity AND
    // derivation have been verified (content-addressed, semantically
    // conformant, derived from their verified captures, dispositions
    // evidenced by the event history, fixed closures re-verified). Parsing
    // data cannot turn it into evidence.
    let mut verified: Vec<crate::verify::ReceiptVerified> = Vec::new();
    for id in receipt_ids {
        let v = crate::verify::load_receipt_verified(store, id).map_err(|e| {
            // An invalid id keeps its validation refusal; a valid id naming
            // no receipt gets the friendly refusal; anything that exists but
            // fails verification keeps the specific violation.
            match store.receipt_path(id) {
                Err(validation) => validation,
                Ok(p) if p.is_file() => e,
                Ok(_) => FrfError::new(format!("no such receipt '{id}'")),
            }
        })?;
        verified.push(v);
    }
    let receipts: Vec<&Receipt> = verified.iter().map(|v| v.body()).collect();
    let first = receipts[0];
    let family = &first.court.admissibility_envelope.fixture_family;

    // Subject coherence: all premises must bind the SAME authority and the
    // SAME candidate artifact — a claim asserts parity of one candidate
    // against one reference, over the surface the premises jointly observed.
    for r in &receipts[1..] {
        if r.authority.name != first.authority.name
            || r.authority.version != first.authority.version
            || r.authority.identity_hash != first.authority.identity_hash
        {
            return Err(FrfError::new(format!(
                "claim refused: the premises bind different authorities ({} and {}) — a claim asserts parity against ONE reference; compile separate claims instead",
                format_args!("{}-{}", first.authority.name, first.authority.version),
                format_args!("{}-{}", r.authority.name, r.authority.version),
            )));
        }
        if r.candidate.identity_hash != first.candidate.identity_hash {
            return Err(FrfError::new(format!(
                "claim refused: the premises bind different candidate artifacts ({} and {}) — a claim asserts parity of ONE candidate; compile separate claims instead",
                &first.candidate.identity_hash[..16],
                &r.candidate.identity_hash[..16],
            )));
        }
    }

    // 1. Run-level invalidation: harness on ANY premise blocks every claim
    //    from that premise.
    for (i, r) in receipts.iter().enumerate() {
        let fam = &r.court.admissibility_envelope.fixture_family;
        let harness_lines = sentences::harness_refusal_lines(&r.residuals, fam);
        if !harness_lines.is_empty() {
            for line in &harness_lines {
                eprintln!("{line}");
            }
            for nc in sentences::non_claims(fam) {
                eprintln!("{nc}");
            }
            return Err(FrfError::new(format!(
                "claim refused: premise {} carries {} harness residual(s) which invalidate the evidence of this run — no positive claim emitted",
                receipt_ids[i],
                harness_lines.len()
            )));
        }
    }

    // 2. Every premise must contribute at least one claimable (clean) axis;
    //    a premise that observed only divergences cannot support the claim.
    for (i, r) in receipts.iter().enumerate() {
        if sentences::positive_claim(r).is_none() {
            for line in sentences::open_refusal_lines(
                &r.residuals,
                &r.court.admissibility_envelope.fixture_family,
            ) {
                eprintln!("{line}");
            }
            for nc in sentences::non_claims(&r.court.admissibility_envelope.fixture_family) {
                eprintln!("{nc}");
            }
            let hint = resolution_hint(r);
            return Err(FrfError::new(format!(
                "claim refused: premise {} establishes no declared observable axis as parity{}",
                receipt_ids[i], hint
            )));
        }
    }

    // 3. The claim IR. K is the region of per-premise clean surfaces; the
    //    premise union P is the region of the premises' FULL surfaces.
    //    Admission is the containment rule Scope(K) ⊆ Scope(P₁ ∪ … ∪ Pₙ),
    //    checked literally over the cells — every point of every K cell must
    //    lie in SOME premise cell (the guard that keeps the union honest as
    //    premises grow: no dimension-wise merging, so no invented surface).
    let k_region = scope::claim_region(&receipts);
    let p_region = scope::premise_region(&receipts);
    for cell in &k_region.cells {
        if !p_region.contains(cell) {
            return Err(FrfError::new(format!(
                "claim refused: Scope(K) ⊄ Scope(P₁ ∪ … ∪ Pₙ) — the cell {} exceeds the premises' observed surface",
                cell_proposition(cell)
            )));
        }
    }

    // 4. Store-wide blocking: any open/unknown residual about ANY claimed
    //    cell's surface blocks, wherever it was recorded. The universe is
    //    committed BEFORE the scan: the claim is admissible relative to U,
    //    and the compiled claim carries U (a later store mutation cannot
    //    silently change what the claim means — the negative search is as
    //    portable as the premises).
    let knowledge_snapshot = store.knowledge_snapshot()?;
    let blockers = store_blockers(store, &k_region, &knowledge_snapshot)?;
    if !blockers.is_empty() {
        for (id, kind, disposition) in &blockers {
            eprintln!(
                "cannot claim compatibility for fixture family {family} because residual {id} ({}) is {disposition} — it was observed on the claimed surface and remains unexplained",
                kind.as_str()
            );
        }
        for nc in sentences::non_claims(family) {
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
    //     names the exact content-addressed challenges that proved each
    //     premise's court can SEE each claimed surface.
    //
    //     v9: the REQUIRED SENSITIVITY MUTATION PROFILE (--mutation-profile,
    //     `AXIS:FAMILY,…`) constrains WHICH families must be demonstrated on
    //     each claimed axis; the claim records the required profile AND each
    //     axis's demonstrated profile.
    let sensitivity_required = matches!(
        policy,
        CLAIM_POLICY_SENSITIVITY_BACKED
            | CLAIM_POLICY_INDEPENDENTLY_WITNESSED
            | CLAIM_POLICY_HIGH_ASSURANCE
    );
    let required_profile: Vec<String> = if mutation_profile.trim().is_empty() {
        Vec::new()
    } else {
        mutation_profile
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    };
    if !required_profile.is_empty() && !sensitivity_required {
        return Err(FrfError::new(format!(
            "claim refused: --mutation-profile requires a sensitivity-bearing policy tier (sensitivity-backed, independently-witnessed, or high-assurance), not {policy:?}"
        )));
    }
    let capability = if sensitivity_required {
        let mut cap = Vec::new();
        for (i, r) in receipts.iter().enumerate() {
            let cell = scope::claim_scope(r);
            cap.extend(capability_coverage(
                store,
                &receipt_ids[i],
                r,
                &cell,
                &required_profile,
            )?);
        }
        cap
    } else {
        Vec::new()
    };
    let witness_required = matches!(
        policy,
        CLAIM_POLICY_INDEPENDENTLY_WITNESSED | CLAIM_POLICY_HIGH_ASSURANCE
    );
    let witness_statements = if witness_required {
        let mut all = Vec::new();
        for rid in receipt_ids {
            all.extend(witness_coverage(store, rid)?);
        }
        all.sort();
        all.dedup();
        all
    } else {
        Vec::new()
    };
    // The declared INDEPENDENCE evidence bound to those attestations (v7):
    // every verified IndependenceEvidence record whose witness statement the
    // claim carries. The claim documents WHICH independence relations were
    // declared for its witnesses — a different executable hash is never by
    // itself independence, and the carried records are the declared claims
    // with their bases (verified on load: identity rederives, the bound
    // statement verifies).
    let independence_evidence = if witness_required {
        let mut all = Vec::new();
        for id in store.independence_ids()? {
            let rec = store.load_independence(&id)?;
            if witness_statements.contains(&rec.witness_statement) {
                all.push(id);
            }
        }
        all.sort();
        all.dedup();
        // The tier is NAMED independently-witnessed: every premise receipt
        // must carry at least one admissible independence relation bound to
        // an attestation of THAT premise. A producer-controlled affirm with
        // zero declared independence is witnessed, not independently
        // witnessed — the tier must not mean less than its name.
        for rid in receipt_ids {
            let attested: Vec<String> = witness_coverage(store, rid)?;
            let covered = all.iter().any(|id| {
                store
                    .load_independence(id)
                    .map(|rec| attested.contains(&rec.witness_statement))
                    .unwrap_or(false)
            });
            if !covered {
                return Err(FrfError::new(format!(
                    "claim refused under policy {policy:?}: premise receipt {rid} has no admissible independence relation — an attestation alone is witnessed, not independently witnessed; declare one with `frf witness independence`"
                )));
            }
        }
        all
    } else {
        Vec::new()
    };
    let replay_profile = if policy == CLAIM_POLICY_HIGH_ASSURANCE {
        // High assurance REQUIRES A CAPABILITY SET, not a profile name: the
        // reference contract — exact capture semantics, the sealed
        // executable image, and the bound native runtime closure. Every
        // admitted profile provides it (v1 exactly, v2/v3/OCI as supersets),
        // so an observation made under a stronger harness qualifies exactly
        // like the reference one — assurance is orthogonal capabilities,
        // not a "v1 < v2 < v3 < OCI" ladder. The capture-bounds check is the
        // exact_capture_contract capability's enforcement: an FRF_EXEC_*
        // override can never redefine the reference bounds.
        for r in &receipts {
            let caps = crate::model::profile_capabilities(&r.execution_profile).ok_or_else(|| {
                FrfError::new(format!(
                    "claim refused under policy {policy:?}: a premise's run was observed under unknown execution profile {:?}",
                    r.execution_profile
                ))
            })?;
            for required in crate::model::HIGH_ASSURANCE_CAPABILITIES {
                if !caps.contains(required) {
                    return Err(FrfError::new(format!(
                        "claim refused under policy {policy:?}: a premise's run was observed under execution profile {} which does NOT provide the required capability {required} (the reference contract); high-assurance requires {:?}",
                        r.execution_profile,
                        crate::model::HIGH_ASSURANCE_CAPABILITIES
                    )));
                }
            }
            if r.capture_bounds != host::reference_capture_bounds() {
                return Err(FrfError::new(format!(
                    "claim refused under policy {policy:?}: a premise's run was observed under non-reference capture bounds; high-assurance requires the exact capture contract (the reference harness bounds) — an FRF_EXEC_* override can never redefine the reference bounds",
                )));
            }
            // Native artifacts must bind their runtime closure: for native
            // software, executable hash is not executable semantics — a
            // high-assurance premise must name what its artifacts actually
            // loaded (the dynamic loader + the resolved dependency closure).
            for (who, artifact) in [
                (
                    "authority",
                    (&r.authority.interpreter, &r.authority.native_runtime),
                ),
                (
                    "candidate",
                    (&r.candidate.interpreter, &r.candidate.native_runtime),
                ),
            ] {
                if artifact.0.is_none() && artifact.1.is_none() {
                    return Err(FrfError::new(format!(
                        "claim refused under policy {policy:?}: the premise {} is a NATIVE artifact whose runtime closure is not bound — high-assurance native evidence must name the dynamic loader and the resolved dependency closure (re-run the court to bind it)",
                        who
                    )));
                }
            }
            // The premise's DECLARED execution-context closure (when
            // declared) is stated, never implied: a high-assurance claim
            // names the runtime context it was compiled under, and names it
            // as DECLARED — the child executables / runtime libraries / data
            // dependencies the court author declared, snapshotted and
            // content-addressed at observation time. It is NOT a measured
            // file-access trace: "the declared context is bound" never means
            // "every file the side read was captured" (a launcher's
            // classpath is bound because the court declared it, and the
            // native/script artifact's own closure is its startup-link
            // closure, not a runtime trace).
            if let Some(ec) = &r.execution_context {
                eprintln!(
                    "high-assurance premise {}: declared execution-context closure {} ({} artifact(s): {})",
                    r.run,
                    &ec.cid[..16],
                    ec.artifacts.len(),
                    ec.artifacts
                        .iter()
                        .map(|a| format!("{}={}", a.role, a.path))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        }
        EXECUTION_PROFILE_LINUX.to_string()
    } else {
        first.execution_profile.clone()
    };

    // 5. A claim IS licensed. Print each premise's axis blockers as explicit
    //    non-claim boundaries, then the claim sentences (one per premise
    //    cell).
    for r in &receipts {
        let fam = &r.court.admissibility_envelope.fixture_family;
        for line in sentences::open_refusal_lines(&r.residuals, fam) {
            eprintln!("{line}");
        }
    }

    let environment = format!(
        "{}-{} ({})",
        first.environment.architecture,
        first.environment.os,
        &first.environment.digest[..8]
    );
    let mut relation: Vec<String> = Vec::new();
    for r in &receipts {
        for obs in &r.observables {
            if !r.residuals.iter().any(|res| res.axis == obs.axis)
                && !relation.contains(&obs.comparator)
            {
                relation.push(obs.comparator.clone());
            }
        }
    }
    let proposition = format!(
        "parity(cells=[{}])",
        k_region
            .cells
            .iter()
            .map(cell_proposition)
            .collect::<Vec<_>>()
            .join(",")
    );
    let observable_scope = scope::region_observables(&k_region);
    let excluded_evidence = scope::region_excluded_evidence(&receipts, &k_region);
    let positive: Vec<String> = receipts
        .iter()
        .filter_map(|r| sentences::positive_claim(r))
        .collect();
    assert!(
        !positive.is_empty(),
        "validated: every premise has a clean axis"
    );

    // The required capability set: what the admission policy demanded. The
    // claim records it, so the requirement re-derives from the claim alone.
    let required_capabilities: Vec<String> = if policy == CLAIM_POLICY_HIGH_ASSURANCE {
        crate::model::HIGH_ASSURANCE_CAPABILITIES
            .iter()
            .map(|c| c.to_string())
            .collect()
    } else {
        Vec::new()
    };

    // The ClaimRecord WITHOUT the id first: the content address is
    // FRF/CLAIM/v1 over the canonical document minus the id — a claim is an
    // immutable protocol object, and the same receipt compiled under a
    // different universe or policy is a DIFFERENT claim id.
    let mut claim = ClaimRecord {
        id: String::new(),
        schema_version: SCHEMA_CLAIM.to_string(),
        receipt: receipt_ids[0].clone(),
        authority: format!("{}-{}", first.authority.name, first.authority.version),
        candidate: ClaimCandidate {
            name: first.candidate.name.clone(),
            version_or_commit: first.candidate.version_or_commit.clone(),
            identity_hash: first.candidate.identity_hash.clone(),
        },
        court: first.court.id.clone(),
        fixture_family: family.clone(),
        environment,
        relation: relation.join(", "),
        proposition,
        scope: k_region,
        observable_scope,
        blockers: blockers.iter().map(|(id, _, _)| id.clone()).collect(),
        excluded_evidence,
        requires: receipt_ids.to_vec(),
        knowledge_snapshot,
        policy: policy.to_string(),
        mutation_profile: required_profile,
        capability,
        witness_statements,
        independence_evidence,
        replay_profile,
        required_capabilities,
    };
    claim.id = crate::semantics::claim_identity(&claim)?;

    if json {
        let canonical = crate::canon::canonical(&claim)?;
        println!("{canonical}");
        return Ok(());
    }

    store.write_claim(&claim)?;

    for sentence in &positive {
        println!("{sentence}");
    }
    for nc in sentences::non_claims(family) {
        println!("{nc}");
    }
    eprintln!(
        "claim written to {}",
        store.claim_path(&claim.id)?.display()
    );
    println!("claim {}", claim.id);
    Ok(())
}
