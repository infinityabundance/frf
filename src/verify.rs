//! The verified-on-read evidence layer.
//!
//! Rule: a content-addressed evidence object is never consumed semantically
//! until BOTH its identity and its derivation are verified. Parsing data
//! cannot turn it into evidence.
//!
//! - [`load_capture_verified`] rederives the run identity from the capture's
//!   own recorded fields (`semantics::run_identity` — the same function the
//!   court uses, never a duplicate), rehashes the raw side files the capture
//!   derives from, verifies the content-addressed snapshots, and checks that
//!   every listed residual exists and belongs to the run.
//! - [`load_receipt_verified`] first proves the receipt is content-addressed
//!   (id == SHA-256 of its canonical bytes), then runs the document-level
//!   OpenReceipt SEMANTIC conformance rules ([`Receipt::validate_semantics`]),
//!   then proves the receipt derives from the verified capture: same court,
//!   artifacts, environment, comparator semantics/provenance, observables,
//!   and exactly the run's residuals — with fingerprints and κ tokens
//!   rederived, dispositions checked against the append-only event history,
//!   and `fixed` closures re-verified against their resolution run.
//!
//! The type distinction is structural: [`ReceiptVerified`] has private fields
//! and is constructible only here, so `claim compile` — which accepts only a
//! `ReceiptVerified` — cannot be reached by a hand-edited or forged receipt.
//! The same discipline is applied to [`CaptureVerified`].
//!
//! Two conformance levels, deliberately separate (see `spec/openreceipt.md`):
//!
//! - *Structural* conformance: JSON Schema + RFC 8785 + hash rules (the
//!   `conformance/{valid,invalid,canonical,hashes}/` corpus).
//! - *Semantic* conformance: [`Receipt::validate_semantics`], a pure
//!   document-level algorithm any independent implementation can run
//!   (`conformance/invalid-semantic/` corpus).

use crate::error::{FrfError, Result};
use crate::host;
use crate::kappa;
use crate::model::*;
use crate::semantics::RunPreimage;
use crate::store::Store;
use std::fs;
use std::path::Path;

// ---------------------------------------------------------------------------
// Verified captures
// ---------------------------------------------------------------------------

/// A capture whose identity and derivation have been verified. Produced only
/// by [`load_capture_verified`].
pub struct CaptureVerified {
    pub run: String,
    pub capture: CaptureManifest,
}

fn read_bytes(path: &Path, what: &str) -> Result<Vec<u8>> {
    fs::read(path).map_err(|e| FrfError::new(format!("cannot read {what} {}: {e}", path.display())))
}

fn first_line(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .split('\n')
        .next()
        .unwrap_or("")
        .to_string()
}

/// Verify a capture before anything may consume it:
///
/// 1. the run field inside `capture.yaml` equals the directory name (the name
///    is a claim until recomputed);
/// 2. every listed residual exists, is immutable, and belongs to this run;
/// 3. the run identity REDERIVES: `semantics::run_identity` over the
///    capture's own recorded fields hashes to the run id;
/// 4. the raw side files under the run dir rehash to the recorded hashes and
///    their first lines rederive;
/// 5. the authority/candidate/fixture snapshots exist and are
///    content-addressed (`verified_object_bytes` refuses corrupt objects).
pub fn load_capture_verified(store: &Store, run: &str) -> Result<CaptureVerified> {
    let capture = store.load_capture(run)?;
    if capture.run != run {
        return Err(FrfError::new(format!(
            "capture {run}: the run field inside capture.yaml is {capture:?} — the name is a claim; refusing to consume"
        )));
    }

    let mut residuals = Vec::with_capacity(capture.residuals.len());
    for id in &capture.residuals {
        let record = store.load_residual(id).map_err(|e| {
            FrfError::new(format!(
                "capture {run}: listed residual {id} is missing: {e}"
            ))
        })?;
        if record.run != run {
            return Err(FrfError::new(format!(
                "capture {run}: residual {id} belongs to run {}; the capture is not self-consistent",
                record.run
            )));
        }
        residuals.push(record);
    }

    // 3. The run identity rederives from the capture's recorded fields.
    let pre = RunPreimage {
        court: &capture.court,
        authority: &capture.authority,
        authority_interpreter: capture
            .authority_artifact
            .interpreter
            .as_ref()
            .map(|i| i.downstream_interpreter.sha256.as_str()),
        candidate_sha256: &capture.candidate_artifact.sha256,
        candidate_interpreter: capture
            .candidate_artifact
            .interpreter
            .as_ref()
            .map(|i| i.downstream_interpreter.sha256.as_str()),
        fixture_sha256: &capture.fixture_sha256,
        arguments: &capture.arguments,
        environment_digest: &capture.environment.digest,
        runner_hash: &capture.provenance.runner.frf_executable_hash,
        court_semantic_identity: &capture.court_semantic_identity,
        reference: &capture.reference,
        candidate: &capture.candidate,
        residuals: &residuals,
    };
    let rederived = crate::semantics::run_identity(&pre)?;
    // The run id is `run-{court}-{hash}`; the rederived hash must be its
    // digest component — the name is a claim until recomputed.
    let expected = format!("run-{}-{}", capture.court, rederived);
    if expected != capture.run {
        return Err(FrfError::new(format!(
            "capture {run}: the recorded fields do not hash to the run identity ({} != {}) — the capture is not self-authenticating",
            &rederived[..16],
            &capture.run[..16]
        )));
    }

    // 4. The raw side files derive the recorded hashes.
    let dir = store.run_dir(run)?;
    for (side, s) in [
        ("reference", &capture.reference),
        ("candidate", &capture.candidate),
    ] {
        let stdout = read_bytes(&dir.join(format!("{side}.stdout")), "side file")?;
        let stderr = read_bytes(&dir.join(format!("{side}.stderr")), "side file")?;
        if host::sha256_bytes(&stdout) != s.stdout_sha256 {
            return Err(FrfError::new(format!(
                "capture {run}: {side}.stdout does not hash to the recorded value"
            )));
        }
        if host::sha256_bytes(&stderr) != s.stderr_sha256 {
            return Err(FrfError::new(format!(
                "capture {run}: {side}.stderr does not hash to the recorded value"
            )));
        }
        if first_line(&stdout) != s.stdout_first_line {
            return Err(FrfError::new(format!(
                "capture {run}: {side}.stdout first line does not derive to the recorded projection"
            )));
        }
        if first_line(&stderr) != s.stderr_first_line {
            return Err(FrfError::new(format!(
                "capture {run}: {side}.stderr first line does not derive to the recorded projection"
            )));
        }
        let exit = read_bytes(&dir.join(format!("{side}.exit.txt")), "side file")?;
        if exit.trim_ascii() != s.exit.as_bytes()
            || host::sha256_bytes(s.exit.as_bytes()) != s.exit_sha256
        {
            return Err(FrfError::new(format!(
                "capture {run}: {side}.exit.txt does not derive to the recorded exit projection"
            )));
        }
        for (file, recorded, hash) in [
            (
                format!("{side}.stderr_first_line.txt"),
                s.stderr_first_line.as_str(),
                &s.stderr_first_line_sha256,
            ),
            (
                format!("{side}.stdout_first_line.txt"),
                s.stdout_first_line.as_str(),
                &s.stdout_first_line_sha256,
            ),
        ] {
            let text = read_bytes(&dir.join(&file), "side file")?;
            if text.trim_ascii() != recorded.as_bytes() {
                return Err(FrfError::new(format!(
                    "capture {run}: {file} does not derive to the recorded first-line projection"
                )));
            }
            if host::sha256_bytes(recorded.as_bytes()) != *hash {
                return Err(FrfError::new(format!(
                    "capture {run}: first-line hash for {file} does not rederive"
                )));
            }
        }
    }

    // 5. The content-addressed snapshots exist and are intact.
    store.verified_object_bytes(&capture.authority_artifact.sha256)?;
    store.verified_object_bytes(&capture.candidate_artifact.sha256)?;
    store.verified_object_bytes(&capture.fixture_sha256)?;

    // 6. External comparator evidence: every externally served axis must have
    //    a verified invocation + result record bound to this run (identity
    //    rederives, request/response documents hash to their cids, the
    //    response names its request, the referenced residuals belong to the
    //    run), and the exact instrument bytes must be intact under objects/.
    for impl_ in &capture.provenance.comparator_implementations {
        if let Some(artifact) = &impl_.artifact {
            store.verified_object_bytes(&artifact.sha256)?;
            let evidence = store.load_comparator_evidence(run, &impl_.id)?;
            if evidence.invocation.axis.as_str() != impl_.id
                || evidence.invocation.comparator_semantic_cid
                    != capture
                        .comparator_semantics
                        .iter()
                        .find(|s| s.id == impl_.id)
                        .map(|s| s.specification_hash.clone())
                        .ok_or_else(|| {
                            FrfError::new(format!(
                                "capture {run}: externally served axis {} has no comparator semantic in the capture",
                                impl_.id
                            ))
                        })?
            {
                return Err(FrfError::new(format!(
                    "capture {run}: comparator invocation for axis {} does not bind the recorded semantic identity",
                    impl_.id
                )));
            }
        }
    }

    Ok(CaptureVerified {
        run: run.to_string(),
        capture,
    })
}

// ---------------------------------------------------------------------------
// Verified receipts
// ---------------------------------------------------------------------------

/// A receipt whose identity AND derivation have been verified against the
/// evidence tree. Private fields: the only constructor is
/// [`load_receipt_verified`], so a `ReceiptVerified` cannot be fabricated —
/// `claim compile` accepts only this type.
pub struct ReceiptVerified {
    id: String,
    body: Receipt,
}

impl ReceiptVerified {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn body(&self) -> &Receipt {
        &self.body
    }
}

/// Push one semantic-conformance violation (accepts literals and formatted
/// Strings alike).
fn fail(violations: &mut Vec<String>, msg: impl Into<String>) {
    violations.push(msg.into());
}

/// The sign a receipt entry MUST carry for a residual record: single-run
/// courts honestly record `not-observed` drift/slew (one run cannot observe
/// drift or slew); a residual whose run belongs to an [`ExecutionSeries`]
/// derives its sign from the series' trajectory for the residual's LINEAGE
/// and PINs the series snapshot it derived from. One function, shared by
/// receipt emission and the verification suite; the receipt verifier uses
/// [`verify_sign`], which replays the pinned series.
pub fn sign_for(
    store: &Store,
    _capture: &CaptureManifest,
    record: &ResidualRecord,
) -> Result<ResidualSign> {
    let series = store.series_containing_run(&record.run)?;
    let lineage = crate::semantics::residual_lineage_of_record(store, record)?;
    for s in &series {
        // Deterministic: series sorted by id. The trajectory exists iff the
        // lineage was observed in the series.
        let path = store.trajectory_path(&lineage, &s.coordinate_system, &s.id)?;
        if !path.is_file() {
            continue;
        }
        let t: TrajectoryRecord = store.parse_yaml(&path)?;
        return Ok(ResidualSign {
            norm: "repeated-run".to_string(),
            drift: t.derivation.drift.as_str().to_string(),
            slew: t.derivation.slew.as_str().to_string(),
            series: Some(s.id.clone()),
        });
    }
    Ok(ResidualSign {
        norm: "single-run".to_string(),
        drift: "not-observed".to_string(),
        slew: "not-observed".to_string(),
        series: None,
    })
}

/// Verify a receipt entry's sign against the evidence it PINNED. The sign's
/// `series` names the exact ExecutionSeries snapshot the drift/slew were
/// derived from; the verifier replays THAT series (it must exist, contain
/// the run, and its trajectory for the residual's lineage must yield the
/// recorded drift/slew). A `single-run` sign pins nothing: the absence of a
/// series at emit time is not reconstructible, so the snapshot is accepted
/// as-is — a later experiment referencing the same run does not rewrite an
/// emitted receipt.
pub fn verify_sign(store: &Store, record: &ResidualRecord, sign: &ResidualSign) -> Result<()> {
    let lineage = crate::semantics::residual_lineage_of_record(store, record)?;
    match sign.norm.as_str() {
        "single-run" => {
            if sign.drift != "not-observed" || sign.slew != "not-observed" {
                return Err(FrfError::new(format!(
                    "residual {}: single-run sign must carry not-observed drift/slew",
                    record.id
                )));
            }
            if sign.series.is_some() {
                return Err(FrfError::new(format!(
                    "residual {}: single-run sign carries a series pin",
                    record.id
                )));
            }
        }
        "repeated-run" => {
            let sid = sign.series.as_deref().ok_or_else(|| {
                FrfError::new(format!(
                    "residual {}: repeated-run sign without a pinned series",
                    record.id
                ))
            })?;
            let series = store.load_series(sid)?;
            if !series.points.iter().any(|p| p.run == record.run) {
                return Err(FrfError::new(format!(
                    "residual {}: the pinned series {sid} does not contain run {}",
                    record.id, record.run
                )));
            }
            let t = store.load_trajectory(&lineage, &series.coordinate_system, sid)?;
            if sign.drift != t.derivation.drift.as_str() || sign.slew != t.derivation.slew.as_str()
            {
                return Err(FrfError::new(format!(
                    "residual {}: drift/slew do not match the pinned series' trajectory",
                    record.id
                )));
            }
        }
        other => {
            return Err(FrfError::new(format!(
                "residual {}: invalid sign norm {other:?}",
                record.id
            )));
        }
    }
    Ok(())
}

/// The disposition a receipt entry claims, rebuilt from its fields after the
/// cross-field rules have validated them.
fn disposition_of(res: &ReceiptResidual) -> Option<Disposition> {
    match res.disposition.as_str() {
        "open" => Some(Disposition::Open),
        "fixed" => Some(Disposition::Fixed {
            reason: res.reason.clone()?,
            resolution_run_id: res.resolution_run_id.clone()?,
            closure_predicate: res.closure_predicate.clone()?,
        }),
        other => Some(Disposition::Closed {
            kind: ClosureKind::parse(other)?,
            reason: res.reason.clone()?,
        }),
    }
}

/// Verify a receipt before anything may consume it:
///
/// 1. content addressing: `id == receipt-{run}-{SHA-256(canonical body)}`;
/// 2. document-level semantic conformance ([`Receipt::validate_semantics`]);
/// 3. derivation from the verified capture: same court, artifacts,
///    environment, comparator semantics + provenance, observables, and
///    EXACTLY the run's residuals;
/// 4. per-residual derivation: the record file, the fingerprint, the κ token,
///    and dispositions evidenced by the append-only event history;
/// 5. `fixed` closures re-verified as evidence: the resolution run reran the
///    same question under a compatible envelope and the axis now closes.
pub fn load_receipt_verified(store: &Store, id: &str) -> Result<ReceiptVerified> {
    let path = store.receipt_path(id)?;
    let text = read_bytes(&path, "receipt")?;

    // 1. Content addressing begins with the DOCUMENT, never the typed
    //    projection. Strict parse refuses duplicate property names (RFC 8785
    //    §2 I-JSON — serde_json::Value would silently collapse them), then
    //    the canonical bytes are computed from the raw value, so an unknown
    //    property either survives into the digest or the receipt is refused
    //    — it can never be deserialized away before the identity is checked.
    let value = crate::canon::parse_strict(&text)?;
    let canonical = crate::canon::encode(&value)?;
    let actual = host::sha256_bytes(canonical.as_bytes());

    let rest = id
        .strip_prefix("receipt-")
        .ok_or_else(|| FrfError::new(format!("{id} is not a receipt id")))?;
    let (run, digest) = rest
        .rsplit_once('-')
        .ok_or_else(|| FrfError::new(format!("receipt id {id} must end in the digest")))?;
    if actual != digest {
        return Err(FrfError::new(format!(
            "receipt {id} is not content-addressed: its canonical body hashes to {} but its id claims {digest}; refusing to consume hand-edited or forged evidence",
            &actual[..16]
        )));
    }

    // 2. Strict structural deserialization: every OpenReceipt type carries
    //    deny_unknown_fields, so a document cannot shed bytes the content
    //    address covered (an unknown property is refused, not dropped). The
    //    schema version and the closed enums are enforced here too.
    let body: Receipt = serde_json::from_value(value)
        .map_err(|e| FrfError::new(format!("cannot deserialize {}: {e}", path.display())))?;
    if body.run != run {
        return Err(FrfError::new(format!(
            "receipt {id}: the run field inside the body is {body:?} — the name is a claim",
            body = body.run
        )));
    }

    // 3. Document-level semantic conformance.
    body.validate_semantics()
        .map_err(|e| FrfError::new(format!("receipt {id}: {e}")))?;

    // 4. The receipt derives from the verified capture of its own run.
    let cv = load_capture_verified(store, run)?;
    let cap = &cv.capture;
    if body.court.id != cap.court
        || body.court.question != cap.court_spec.question
        || body.court.falsifier != cap.court_spec.falsifier
    {
        return Err(FrfError::new(format!(
            "receipt {id}: the court block does not match the captured court"
        )));
    }
    if body.court.semantic_identity != cap.court_semantic_identity {
        return Err(FrfError::new(format!(
            "receipt {id}: the court semantic identity does not match the capture"
        )));
    }
    let env = &cap.court_spec.admissibility_envelope;
    let rec_env = &body.court.admissibility_envelope;
    if rec_env.fixture_family != env.fixture_family
        || rec_env.platforms != env.platforms
        || rec_env.observables != env.observables
        || rec_env.normalizers != env.normalizers
        || rec_env.replay_scope != env.replay_scope
    {
        return Err(FrfError::new(format!(
            "receipt {id}: the admissibility envelope does not match the capture"
        )));
    }
    if body.authority.identity_hash != cap.authority_artifact.sha256
        || body.authority.interpreter != cap.authority_artifact.interpreter
    {
        return Err(FrfError::new(format!(
            "receipt {id}: the authority artifact does not match the capture"
        )));
    }
    if body.candidate.identity_hash != cap.candidate_artifact.sha256
        || body.candidate.interpreter != cap.candidate_artifact.interpreter
    {
        return Err(FrfError::new(format!(
            "receipt {id}: the candidate artifact does not match the capture"
        )));
    }
    if body.fixtures.len() != 1 {
        return Err(FrfError::new(format!(
            "receipt {id}: v0 receipts carry exactly one fixture"
        )));
    }
    let f = &body.fixtures[0];
    if f.id != cap.fixture || f.hash != cap.fixture_sha256 || f.arguments != cap.arguments {
        return Err(FrfError::new(format!(
            "receipt {id}: the fixture block does not match the capture"
        )));
    }
    if body.environment != cap.environment {
        return Err(FrfError::new(format!(
            "receipt {id}: the environment block does not match the capture (the receipt must never ask its own host what environment an old court ran under)"
        )));
    }
    if body.provenance != cap.provenance || body.comparator_semantics != cap.comparator_semantics {
        return Err(FrfError::new(format!(
            "receipt {id}: provenance or comparator semantics do not match the capture (both are bound at observation time, never reconstructed)"
        )));
    }
    for obs in &body.observables {
        ObservableId::parse(&obs.axis)?;
        // The comparator that served this axis decides what the raw hashes
        // are: an in-binary axis rederives its captured projections; an
        // externally served axis binds the exact invocation + result records
        // and its raw hashes are the canonical reference/candidate subtrees
        // of the preserved request.
        let implementation = cap
            .provenance
            .comparator_implementations
            .iter()
            .find(|i| i.id == obs.axis)
            .ok_or_else(|| {
                FrfError::new(format!(
                    "receipt {id}: observable {} has no comparator implementation in the capture",
                    obs.axis
                ))
            })?;
        match &implementation.artifact {
            None => {
                let builtin =
                    crate::comparators::BuiltinKind::from_id(&obs.axis).ok_or_else(|| {
                        FrfError::new(format!(
                        "receipt {id}: observable {} was served by no known in-binary comparator",
                        obs.axis
                    ))
                    })?;
                let (ref_h, cand_h) = match builtin {
                    crate::comparators::BuiltinKind::Exit => {
                        (&cap.reference.exit_sha256, &cap.candidate.exit_sha256)
                    }
                    crate::comparators::BuiltinKind::Stderr => (
                        &cap.reference.stderr_first_line_sha256,
                        &cap.candidate.stderr_first_line_sha256,
                    ),
                    crate::comparators::BuiltinKind::Stdout => (
                        &cap.reference.stdout_first_line_sha256,
                        &cap.candidate.stdout_first_line_sha256,
                    ),
                };
                if obs.raw_reference_hash != *ref_h || obs.raw_candidate_hash != *cand_h {
                    return Err(FrfError::new(format!(
                        "receipt {id}: observable {} raw hashes do not match the capture",
                        obs.axis
                    )));
                }
                if obs.comparator_request.is_some() || obs.comparator_result.is_some() {
                    return Err(FrfError::new(format!(
                        "receipt {id}: in-binary observable {} must not bind comparator request/result records",
                        obs.axis
                    )));
                }
            }
            Some(_) => {
                let evidence = store.load_comparator_evidence(run, &obs.axis)?;
                if obs.comparator_request.as_deref()
                    != Some(evidence.invocation.request_cid.as_str())
                    || obs.comparator_result.as_deref() != Some(evidence.result.result_id.as_str())
                {
                    return Err(FrfError::new(format!(
                        "receipt {id}: observable {} does not bind the recorded comparator request/result records",
                        obs.axis
                    )));
                }
                let dir = store.comparator_dir(run, &obs.axis)?;
                let request_bytes = read_bytes(&dir.join("request.json"), "comparator request")?;
                let request_value = crate::canon::parse_strict(&request_bytes)?;
                let ref_h = host::sha256_bytes(
                    crate::canon::encode(&request_value["reference"])?.as_bytes(),
                );
                let cand_h = host::sha256_bytes(
                    crate::canon::encode(&request_value["candidate"])?.as_bytes(),
                );
                if obs.raw_reference_hash != ref_h || obs.raw_candidate_hash != cand_h {
                    return Err(FrfError::new(format!(
                        "receipt {id}: observable {} raw hashes do not match the canonical request subtrees",
                        obs.axis
                    )));
                }
            }
        }
    }

    // 4. Residuals: EXACTLY the run's residuals (same ids, same order — the
    //    emitter preserves capture order, so order is part of the protocol).
    let receipt_ids: Vec<&str> = body.residuals.iter().map(|r| r.id.as_str()).collect();
    let capture_ids: Vec<&str> = cap.residuals.iter().map(|s| s.as_str()).collect();
    if receipt_ids != capture_ids {
        return Err(FrfError::new(format!(
            "receipt {id}: the residual set does not match the run's captured residuals"
        )));
    }
    for res in &body.residuals {
        let record = store.load_residual(&res.id)?;
        if record.run != run {
            return Err(FrfError::new(format!(
                "receipt {id}: residual {} belongs to run {}",
                res.id, record.run
            )));
        }
        if res.axis != record.axis.as_str()
            || res.kind != record.kind
            || res.raw_reference_hash != record.raw_reference_sha256
            || res.raw_candidate_hash != record.raw_candidate_sha256
        {
            return Err(FrfError::new(format!(
                "receipt {id}: residual {} does not derive from its record file",
                res.id
            )));
        }
        let fp = crate::semantics::residual_fingerprint(&record)?;
        if res.residual_fingerprint != fp {
            return Err(FrfError::new(format!(
                "receipt {id}: residual fingerprint of {} does not rederive",
                res.id
            )));
        }
        // The sign verifies against the evidence it PINNED: a repeated-run
        // sign names the exact ExecutionSeries snapshot it was derived from
        // and the verifier replays it (the series must exist, contain the
        // run, and its trajectory for the lineage must yield the recorded
        // drift/slew); a single-run sign is a snapshot of emit time and is
        // accepted as such — a later experiment referencing the same
        // content-addressed run does not rewrite an emitted receipt.
        verify_sign(store, &record, &res.sign)?;
        // Dispositions must be bound to the EXACT immutable event that
        // supplied them. `open` is the projection of no events — a receipt
        // snapshot may predate later events, so it needs no event, and it
        // must not claim one. Any other disposition must name an event in the
        // chain whose fields EXACTLY match the receipt's: the receipt points
        // at a node in the hash chain, it does not merely copy state.
        match res.disposition.as_str() {
            "open" => {
                if res.disposition_event_id.is_some() {
                    return Err(FrfError::new(format!(
                        "receipt {id}: open residual {} claims a disposition_event_id — open is the projection of no events",
                        res.id
                    )));
                }
            }
            _ => {
                let Some(eid) = &res.disposition_event_id else {
                    return Err(FrfError::new(format!(
                        "receipt {id}: residual {} disposition {:?} has no bound disposition_event_id — a disposition must be an event, not a copy",
                        res.id,
                        res.disposition
                    )));
                };
                let events = store.disposition_events(&res.id)?;
                let Some(event) = events.iter().find(|e| &e.event_id == eid) else {
                    return Err(FrfError::new(format!(
                        "receipt {id}: residual {} binds disposition_event_id {eid} but no such event exists in its hash chain",
                        res.id
                    )));
                };
                let closure_ok = match (&event.disposition, &res.closure_predicate) {
                    (
                        Disposition::Fixed {
                            closure_predicate, ..
                        },
                        Some(cp),
                    ) => closure_predicate == cp,
                    (Disposition::Fixed { .. }, None) => false,
                    (_, None) => true,
                    (_, Some(_)) => false,
                };
                if event.disposition.as_str() != res.disposition
                    || event.disposition.reason().map(str::to_string) != res.reason
                    || event.disposition.resolution_run_id().map(str::to_string)
                        != res.resolution_run_id
                    || !closure_ok
                {
                    return Err(FrfError::new(format!(
                        "receipt {id}: residual {} disposition {:?} does not match the bound event {eid} — the receipt must not drift from the event it points at",
                        res.id,
                        res.disposition
                    )));
                }
            }
        }
        // The endoduction token rederives from the record under the receipt's
        // disposition (a snapshot, since receipts bind the state at emit time).
        let disposition = disposition_of(res).ok_or_else(|| {
            FrfError::new(format!(
                "receipt {id}: cannot rebuild the disposition of {}",
                res.id
            ))
        })?;
        let token = kappa::kappa(&record, &disposition);
        let recorded = body
            .endoduction
            .tokens
            .iter()
            .find(|t| t.residual_id == res.id)
            .ok_or_else(|| FrfError::new(format!("receipt {id}: no token bound for {}", res.id)))?;
        if token.token != recorded.token
            || token.next_court != recorded.next_court
            || token.blocks_claims != recorded.blocks_claims
        {
            return Err(FrfError::new(format!(
                "receipt {id}: the endoduction token of {} does not rederive",
                res.id
            )));
        }
    }

    // 5. Fixed closures must be backed by verifiable resolution evidence.
    for res in &body.residuals {
        if let (Some(resolution_run_id), Ok(axis)) =
            (&res.resolution_run_id, ObservableId::parse(&res.axis))
        {
            if resolution_run_id == run {
                return Err(FrfError::new(format!(
                    "receipt {id}: residual {} claims to be fixed by the run that observed it — a disposition must not substitute for new evidence",
                    res.id
                )));
            }
            store
                .resolution_compatibility(run, resolution_run_id, &axis)
                .map_err(|e| {
                    FrfError::new(format!(
                        "receipt {id}: the fixed closure of {} is not backed by verifiable resolution evidence: {e}",
                        res.id
                    ))
                })?;
        }
    }

    Ok(ReceiptVerified {
        id: id.to_string(),
        body,
    })
}

// ---------------------------------------------------------------------------
// OpenReceipt SEMANTIC conformance (document-level)
// ---------------------------------------------------------------------------

impl Receipt {
    /// OpenReceipt SEMANTIC conformance: the cross-field, cross-object
    /// invariants of `frf-receipt-v10`, checked on the document ALONE so any
    /// independent implementation can run the same algorithm (normative
    /// description in `spec/openreceipt.md`, corpus in
    /// `conformance/invalid-semantic/`). This is deliberately separate from
    /// structural conformance (JSON Schema + RFC 8785 + hash rules): the
    /// schema says what *shapes* are legal; this says what *documents* are.
    ///
    /// All violations are collected, so a human or an implementation sees
    /// every rule a document breaks, not just the first.
    pub fn validate_semantics(&self) -> Result<()> {
        let mut violations: Vec<String> = Vec::new();

        if self.schema_version != SCHEMA_RECEIPT {
            fail(
                &mut violations,
                format!(
                    "schema_version is {:?}, expected {SCHEMA_RECEIPT}",
                    self.schema_version
                ),
            );
        }

        // One fixture per court (v0).
        if self.fixtures.len() != 1 {
            fail(
                &mut violations,
                format!(
                    "exactly one fixture is required (found {})",
                    self.fixtures.len()
                ),
            );
        }

        // The resolved argv and the declared arguments must correspond: v0
        // courts resolve `{fixture}` to the snapshot path and pass everything
        // else verbatim, so every resolved argument is either the declared
        // argument or a `{fixture}` substitution.
        if let Some(f) = self.fixtures.first() {
            if f.arguments.len() != f.declared_arguments.len() {
                fail(
                    &mut violations,
                    "the resolved argv and the declared arguments must have the same length",
                );
            }
            for (i, (resolved, declared)) in f
                .arguments
                .iter()
                .zip(f.declared_arguments.iter())
                .enumerate()
            {
                if resolved != declared && declared != "{fixture}" {
                    fail(&mut violations, format!(
                        "argv[{i}] {resolved:?} is neither the declared argument nor a {{fixture}} substitution (declared {declared:?})"
                    ));
                }
            }
        }

        // Fail-closed envelope: a declared scope that is not executed would
        // falsify the evidence.
        let envelope = &self.court.admissibility_envelope;
        if envelope.replay_scope != "single-run" {
            fail(&mut violations, format!(
                "replay_scope {:?} is not executable in v0; a declared scope that is not executed would falsify the evidence",
                envelope.replay_scope
            ));
        }

        // Declared observable axes: valid protocol identifiers, and unique.
        let mut declared: Vec<&str> = Vec::new();
        for axis in &envelope.observables {
            if ObservableId::parse(axis).is_err() {
                fail(
                    &mut violations,
                    format!("invalid observable axis identifier {axis:?}"),
                );
            }
            if declared.contains(&axis.as_str()) {
                fail(
                    &mut violations,
                    format!("duplicate declared observable axis {axis:?}"),
                );
            } else {
                declared.push(axis);
            }
        }

        // The observables block: valid identifiers, unique, declared.
        let mut obs_axes: Vec<&str> = Vec::new();
        for obs in &self.observables {
            if ObservableId::parse(&obs.axis).is_err() {
                fail(
                    &mut violations,
                    format!("observable with invalid axis identifier {:?}", obs.axis),
                );
            }
            if !declared.contains(&obs.axis.as_str()) {
                fail(
                    &mut violations,
                    format!("observable {} is not declared in the envelope", obs.axis),
                );
            }
            if obs_axes.contains(&obs.axis.as_str()) {
                fail(
                    &mut violations,
                    format!("duplicate observable block for axis {}", obs.axis),
                );
            } else {
                obs_axes.push(&obs.axis);
            }
            // An observable's comparator binding is all-or-nothing: an
            // external verdict names BOTH the exact request and the exact
            // result record that produced it; an in-binary verdict names
            // neither.
            match (&obs.comparator_request, &obs.comparator_result) {
                (None, None) => {}
                (Some(_), Some(_)) => {
                    for (what, v) in [
                        ("comparator_request", obs.comparator_request.as_deref().unwrap_or("")),
                        ("comparator_result", obs.comparator_result.as_deref().unwrap_or("")),
                    ] {
                        if v.len() != 64 || !v.bytes().all(|b| b.is_ascii_hexdigit()) {
                            fail(
                                &mut violations,
                                format!("observable {} {what} must be a 64-hex content address", obs.axis),
                            );
                        }
                    }
                }
                _ => fail(&mut violations, format!(
                    "observable {} binds only one of comparator_request/comparator_result — an external verdict binds both, an in-binary verdict binds neither",
                    obs.axis
                )),
            }
        }

        // Comparator semantics: exactly one per observable axis, no orphans,
        // unique ids, and every specification hash REDERIVES from the
        // record's own fields (the record carries the full specification,
        // so a receipt cannot claim a specification its semantics do not
        // hash to).
        let mut sem_ids: Vec<&str> = Vec::new();
        for c in &self.comparator_semantics {
            if sem_ids.contains(&c.id.as_str()) {
                fail(
                    &mut violations,
                    format!("duplicate comparator semantic id {}", c.id),
                );
            } else {
                sem_ids.push(&c.id);
            }
            if !obs_axes.contains(&c.id.as_str()) {
                fail(
                    &mut violations,
                    format!("comparator semantic {} serves no observable", c.id),
                );
            }
            if c.relation_id.is_empty()
                || c.extractor.is_empty()
                || c.residual_classifier.is_empty()
            {
                fail(
                    &mut violations,
                    format!(
                        "comparator semantic {} must carry a relation, an extractor, and a residual classifier",
                        c.id
                    ),
                );
            }
            match crate::semantics::comparator_spec_hash_rederives(c) {
                Ok(true) => {}
                Ok(false) => fail(
                    &mut violations,
                    format!(
                        "comparator semantic {}: the specification_hash does not rederive from its own fields",
                        c.id
                    ),
                ),
                Err(e) => fail(
                    &mut violations,
                    format!("comparator semantic {}: {e}", c.id),
                ),
            }
        }
        for obs in &self.observables {
            let n = self
                .comparator_semantics
                .iter()
                .filter(|c| c.id == obs.axis)
                .count();
            if n != 1 {
                fail(
                    &mut violations,
                    format!(
                        "observable {} must have exactly one comparator semantic (found {n})",
                        obs.axis
                    ),
                );
            }
        }

        // Provenance: every comparator semantic has a recorded implementation.
        if self.provenance.comparator_implementations.len() != self.comparator_semantics.len() {
            fail(
                &mut violations,
                "comparator_implementations must mirror comparator_semantics one-to-one",
            );
        }
        for c in &self.comparator_semantics {
            if !self
                .provenance
                .comparator_implementations
                .iter()
                .any(|i| i.id == c.id)
            {
                fail(
                    &mut violations,
                    format!(
                        "comparator semantic {} has no implementation provenance",
                        c.id
                    ),
                );
            }
        }

        // Residuals: unique ids, declared + valid axes, kind/classifier
        // consistency, disposition cross-field rules, derived grammar_state,
        // v0 sign fields, and the reproducer binding.
        let family = &envelope.fixture_family;
        let mut residual_ids: Vec<&str> = Vec::new();
        for r in &self.residuals {
            if residual_ids.contains(&r.id.as_str()) {
                fail(&mut violations, format!("duplicate residual id {}", r.id));
            } else {
                residual_ids.push(&r.id);
            }
            if ObservableId::parse(&r.axis).is_err() {
                fail(
                    &mut violations,
                    format!("residual {} has invalid axis identifier {:?}", r.id, r.axis),
                );
                continue;
            }
            if !declared.contains(&r.axis.as_str()) {
                fail(
                    &mut violations,
                    format!(
                        "residual {} axis {} is not a declared observable",
                        r.id, r.axis
                    ),
                );
            }
            if ResidualKind::parse(r.kind.as_str()).is_err() {
                fail(
                    &mut violations,
                    format!("residual {} has invalid kind {:?}", r.id, r.kind.as_str()),
                );
            }
            // The residual kind is the axis's comparator's residual
            // classifier — the classifier is part of the question, so a
            // residual whose kind disagrees with its comparator is
            // inconsistent evidence.
            let classifier = self
                .comparator_semantics
                .iter()
                .find(|c| c.id == r.axis)
                .map(|c| c.residual_classifier.as_str());
            if classifier != Some(r.kind.as_str()) {
                fail(
                    &mut violations,
                    format!(
                        "residual {} kind {:?} is inconsistent with the {} axis's residual classifier {:?}",
                        r.id,
                        r.kind.as_str(),
                        r.axis,
                        classifier.unwrap_or("<none>")
                    ),
                );
            }
            match r.disposition.as_str() {
                "open" => {
                    if r.reason.is_some() {
                        fail(
                            &mut violations,
                            format!("open residual {} carries a reason", r.id),
                        );
                    }
                    if r.resolution_run_id.is_some() {
                        fail(
                            &mut violations,
                            format!("open residual {} carries a resolution_run_id", r.id),
                        );
                    }
                    if r.closure_predicate.is_some() {
                        fail(
                            &mut violations,
                            format!("open residual {} carries a closure_predicate", r.id),
                        );
                    }
                    if r.disposition_event_id.is_some() {
                        fail(
                            &mut violations,
                            format!(
                                "open residual {} carries a disposition_event_id (open is the projection of no events)",
                                r.id
                            ),
                        );
                    }
                }
                "fixed" => {
                    if r.reason.is_none() {
                        fail(
                            &mut violations,
                            format!("fixed residual {} without a reason", r.id),
                        );
                    }
                    if r.resolution_run_id.is_none() {
                        fail(&mut violations, format!(
                            "fixed residual {} without a resolution_run_id — a disposition must not substitute for new evidence",
                            r.id
                        ));
                    }
                    if r.closure_predicate.as_deref() != Some(CLOSURE_PREDICATE_FIX_COURT) {
                        fail(
                            &mut violations,
                            format!(
                                "fixed residual {} must carry the fix-court closure predicate",
                                r.id
                            ),
                        );
                    }
                    if r.disposition_event_id.is_none() {
                        fail(
                            &mut violations,
                            format!(
                                "fixed residual {} without a disposition_event_id — a receipt must point at the exact event that supplied the disposition",
                                r.id
                            ),
                        );
                    }
                }
                other => {
                    if ClosureKind::parse(other).is_none() {
                        fail(
                            &mut violations,
                            format!("residual {} has unknown disposition {other:?}", r.id),
                        );
                    }
                    if r.reason.is_none() {
                        fail(
                            &mut violations,
                            format!("{other} residual {} requires a reason", r.id),
                        );
                    }
                    if r.resolution_run_id.is_some() {
                        fail(
                            &mut violations,
                            format!("{other} residual {} carries a resolution_run_id", r.id),
                        );
                    }
                    if r.closure_predicate.is_some() {
                        fail(
                            &mut violations,
                            format!("{other} residual {} carries a closure_predicate", r.id),
                        );
                    }
                    if r.disposition_event_id.is_none() {
                        fail(
                            &mut violations,
                            format!(
                                "{other} residual {} without a disposition_event_id — a receipt must point at the exact event that supplied the disposition",
                                r.id
                            ),
                        );
                    }
                }
            }
            if let Some(d) = disposition_of(r) {
                let expected = kappa::grammar_state(&d);
                if r.grammar_state != expected {
                    fail(
                        &mut violations,
                        format!(
                            "grammar_state of {} is {:?}, expected {:?}",
                            r.id, r.grammar_state, expected
                        ),
                    );
                }
            }
            // The sign: a single-run court honestly records that drift/slew
            // were not observed; a repeated-run court derives them from the
            // residual's trajectory.
            match r.sign.norm.as_str() {
                "single-run" => {
                    if r.sign.drift != "not-observed" || r.sign.slew != "not-observed" {
                        fail(&mut violations, format!(
                            "single-run residual {} must carry drift/slew not-observed — one run cannot observe them",
                            r.id
                        ));
                    }
                }
                "repeated-run" => {
                    if TrajectoryDrift::parse(&r.sign.drift).is_none() {
                        fail(
                            &mut violations,
                            format!(
                                "repeated-run residual {} has invalid drift {:?}",
                                r.id, r.sign.drift
                            ),
                        );
                    }
                    if TrajectorySlew::parse(&r.sign.slew).is_none() {
                        fail(
                            &mut violations,
                            format!(
                                "repeated-run residual {} has invalid slew {:?}",
                                r.id, r.sign.slew
                            ),
                        );
                    }
                }
                other => fail(
                    &mut violations,
                    format!("residual {} has invalid sign norm {other:?}", r.id),
                ),
            }
            if r.reproducer != self.run {
                fail(
                    &mut violations,
                    format!(
                        "residual {} reproducer must be the receipt's run ({:?}, got {:?})",
                        r.id, self.run, r.reproducer
                    ),
                );
            }
        }

        // Verdicts: a residual verdict requires residual evidence on the axis;
        // a pass verdict excludes it.
        for obs in &self.observables {
            let has = self.residuals.iter().any(|r| r.axis == obs.axis);
            match obs.verdict {
                ObservableVerdict::Pass => {
                    if has {
                        fail(
                            &mut violations,
                            format!(
                                "pass verdict on {} while a residual exists on the axis",
                                obs.axis
                            ),
                        );
                    }
                }
                ObservableVerdict::Residual => {
                    if !has {
                        fail(
                            &mut violations,
                            format!(
                                "residual verdict on {} without any residual on the axis",
                                obs.axis
                            ),
                        );
                    }
                }
            }
        }

        // The environment digest rederives from the environment fields.
        let env_expected = host::environment_digest(
            &self.environment.os,
            &self.environment.architecture,
            &self.environment.kernel_release,
        );
        if env_expected != self.environment.digest {
            fail(
                &mut violations,
                "the environment digest does not rederive from os/architecture/kernel_release",
            );
        }

        // The court semantic identity rederives from the document.
        match crate::semantics::court_semantic_identity_from_receipt(self) {
            Ok(h) if h != self.court.semantic_identity => {
                fail(
                    &mut violations,
                    "the court semantic identity does not rederive from the document",
                );
            }
            Err(e) => fail(
                &mut violations,
                format!("the court semantic identity cannot be rederived: {e}"),
            ),
            _ => {}
        }

        // The replay block is a real court-run invocation of THIS run.
        if self.replay.program != "frf" {
            fail(
                &mut violations,
                format!(
                    "replay.program must be \"frf\", got {:?}",
                    self.replay.program
                ),
            );
        }
        if self.replay.expected_run_identity != self.run {
            fail(
                &mut violations,
                "replay.expected_run_identity must equal the receipt's run",
            );
        }
        if self.replay.argv.len() < 5
            || self.replay.argv[0] != "--root"
            || self.replay.argv[2] != "court"
            || self.replay.argv[3] != "run"
        {
            fail(
                &mut violations,
                "replay.argv must be a court-run invocation: [--root, ROOT, court, run, MANIFEST]",
            );
        }

        // Endoduction tokens: same residual set, same order, each rederivable
        // from kind/axis/disposition via the κ table.
        if self.endoduction.tokens.len() != self.residuals.len() {
            fail(
                &mut violations,
                "endoduction tokens must mirror residuals one-to-one",
            );
        }
        for (r, t) in self.residuals.iter().zip(&self.endoduction.tokens) {
            if t.residual_id != r.id {
                fail(
                    &mut violations,
                    format!(
                        "token bound to {} but the residual is {}",
                        t.residual_id, r.id
                    ),
                );
                continue;
            }
            let axis = match ObservableId::parse(&r.axis) {
                Ok(a) => a,
                Err(_) => continue,
            };
            let shape = kappa::token_shape(&axis);
            let expected_token = format!(
                "{}/{}/{}/{}",
                r.kind.as_str(),
                shape.surface,
                shape.magnitude,
                r.disposition
            );
            if t.token != expected_token {
                fail(
                    &mut violations,
                    format!(
                        "token of {} is {:?}, expected {:?}",
                        r.id, t.token, expected_token
                    ),
                );
            }
            if t.next_court != shape.next_court {
                fail(
                    &mut violations,
                    format!(
                        "next_court of {} is {:?}, expected {:?}",
                        r.id, t.next_court, shape.next_court
                    ),
                );
            }
            let expected_blocks = kappa::blocks_claims(&axis, family);
            if t.blocks_claims != expected_blocks {
                fail(
                    &mut violations,
                    format!("blocks_claims of {} does not rederive", r.id),
                );
            }
        }

        // Interpreter chains are internally consistent: an env resolver must
        // BE the kernel interpreter it resolved through; without a resolver
        // the kernel must BE the downstream interpreter.
        for (who, interp) in [
            ("authority", &self.authority.interpreter),
            ("candidate", &self.candidate.interpreter),
        ] {
            if let Some(i) = interp {
                match &i.resolver {
                    Some(r) => {
                        if r.kind != "env" {
                            fail(
                                &mut violations,
                                format!(
                                    "{who} interpreter resolver kind must be \"env\", got {:?}",
                                    r.kind
                                ),
                            );
                        }
                        if r.path != i.kernel_interpreter.path {
                            fail(&mut violations, format!(
                                "{who} interpreter resolver path must be the kernel interpreter path"
                            ));
                        }
                    }
                    None => {
                        if i.kernel_interpreter != i.downstream_interpreter {
                            fail(&mut violations, format!(
                                "{who} interpreter: without a resolver the kernel must BE the downstream interpreter"
                            ));
                        }
                    }
                }
            }
        }

        // Claims: v0 receipts never carry positive claims — the claim
        // compiler writes claims/ files from a verified receipt.
        if !self.claims.positive.is_empty() {
            fail(
                &mut violations,
                "v0 receipts carry no positive claims; the claim compiler writes claims/",
            );
        }

        if violations.is_empty() {
            Ok(())
        } else {
            Err(FrfError::new(format!(
                "OpenReceipt semantic conformance: {}",
                violations.join("; ")
            )))
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal but semantically VALID receipt document, hand-built so every
    /// invariant can be violated one at a time. All hashes are real
    /// derivatives except where a test mutates them.
    fn valid_receipt() -> Receipt {
        let os = std::env::consts::OS;
        let arch = std::env::consts::ARCH;
        let kernel = host::kernel_release();
        let env_digest = host::environment_digest(os, arch, &kernel);
        let authority_hash = "a".repeat(64);
        let fixture_hash = "b".repeat(64);
        let candidate_hash = "c".repeat(64);
        // The semantic identity must rederive from the fixture fields, so
        // build it from a real court declaration.
        let spec = CourtSpec {
            id: "cli-malformed-input".into(),
            question: "q".into(),
            falsifier: "f".into(),
            authority: "ref-cli-1.8.2".into(),
            candidate: CandidateSpec {
                name: "cand-cli".into(),
                version_or_commit: "0.1.0".into(),
                build_profile: "debug".into(),
                path: "cand.sh".into(),
            },
            fixture: FixtureSpec {
                id: "malformed-path.conf".into(),
                path: "f.conf".into(),
                arguments: vec!["--strict".into(), "{fixture}".into()],
            },
            admissibility_envelope: AdmissibilityEnvelope {
                fixture_family: "malformed-input".into(),
                platforms: vec![format!("{arch}-{os}")],
                observables: vec!["exit".into()],
                normalizers: vec![],
                replay_scope: "single-run".into(),
            },
        };
        let semantic = crate::semantics::court_semantic_identity(
            &spec,
            &authority_hash,
            &fixture_hash,
            &[crate::comparators::semantic("exit").unwrap()],
        )
        .unwrap();

        let env = EnvironmentIdentity {
            schema_version: SCHEMA_ENVIRONMENT.into(),
            os: os.into(),
            architecture: arch.into(),
            kernel_release: kernel,
            digest: env_digest,
        };
        let comparator = crate::comparators::semantic("exit").unwrap();
        let runner = RunnerIdentity {
            schema_version: SCHEMA_RUNNER.into(),
            frf_version: env!("CARGO_PKG_VERSION").into(),
            frf_executable_hash: "d".repeat(64),
        };
        let body = Receipt {
            schema_version: SCHEMA_RECEIPT.into(),
            run: "run-cli-malformed-input-1234".into(),
            court: ReceiptCourt {
                id: spec.id,
                question: spec.question,
                falsifier: spec.falsifier,
                admissibility_envelope: ReceiptEnvelope {
                    authority_versions: vec!["1.8.2".into()],
                    fixture_family: "malformed-input".into(),
                    platforms: vec![format!("{arch}-{os}")],
                    observables: vec!["exit".into()],
                    normalizers: vec![],
                    replay_scope: "single-run".into(),
                },
                semantic_identity: semantic,
            },
            provenance: ObservationProvenance {
                schema_version: SCHEMA_PROVENANCE.into(),
                runner,
                comparator_implementations: vec![crate::comparators::implementations(
                    &["exit".into()],
                    &"d".repeat(64),
                )
                .remove(0)],
            },
            comparator_semantics: vec![comparator],
            authority: ReceiptAuthority {
                name: "ref-cli".into(),
                kind: "executable_reference".into(),
                version: "1.8.2".into(),
                identity_hash: authority_hash,
                provenance: "file:golden/reference.sh".into(),
                interpreter: None,
            },
            candidate: ReceiptCandidate {
                name: "cand-cli".into(),
                version_or_commit: "0.1.0".into(),
                build_profile: "debug".into(),
                identity_hash: candidate_hash,
                interpreter: None,
            },
            environment: env,
            fixtures: vec![ReceiptFixture {
                id: "malformed-path.conf".into(),
                hash: fixture_hash,
                arguments: vec!["--strict".into(), "obj".into()],
                declared_arguments: vec!["--strict".into(), "{fixture}".into()],
            }],
            observables: vec![ReceiptObservable {
                axis: "exit".into(),
                raw_reference_hash: "e".repeat(64),
                raw_candidate_hash: "f".repeat(64),
                comparator: "eq(exit-code)".into(),
                normalization_rules: vec![],
                verdict: ObservableVerdict::Residual,
                comparator_request: None,
                comparator_result: None,
            }],
            residuals: vec![ReceiptResidual {
                id: "cli-exit-0001".into(),
                axis: "exit".into(),
                kind: ResidualKind::exit(),
                sign: ResidualSign {
                    norm: "single-run".into(),
                    drift: "not-observed".into(),
                    slew: "not-observed".into(),
                    series: None,
                },
                grammar_state: "violation".into(),
                raw_reference_hash: "e".repeat(64),
                raw_candidate_hash: "f".repeat(64),
                disposition: "open".into(),
                disposition_event_id: None,
                reason: None,
                resolution_run_id: None,
                closure_predicate: None,
                reproducer: "run-cli-malformed-input-1234".into(),
                invariant: String::new(),
                residual_fingerprint: "0".repeat(64),
            }],
            endoduction: ReceiptEndoduction {
                schema_version: TOKEN_SCHEMA_VERSION.into(),
                tokens: vec![ReceiptToken {
                    residual_id: "cli-exit-0001".into(),
                    token: "exit/exit-class/class-change/open".into(),
                    next_court: "cli-exit-minimize".into(),
                    blocks_claims: vec!["malformed-input exit parity".into()],
                }],
            },
            claims: ReceiptClaims {
                positive: vec![],
                non_claims: vec![
                    "This receipt does not establish byte-identical stderr, full CLI compatibility, or a drop-in replacement claim.".into(),
                ],
                blocked_by_open_residuals: vec![
                    "malformed-input exit parity is not established: cli-exit-0001 is open".into(),
                ],
            },
            replay: ReceiptReplay {
                program: "frf".into(),
                evidence_root: "frf".into(),
                argv: vec![
                    "--root".into(),
                    "frf".into(),
                    "court".into(),
                    "run".into(),
                    "frf/courts/cli-malformed-input/manifest.yaml".into(),
                ],
                expected_run_identity: "run-cli-malformed-input-1234".into(),
            },
        };
        body.validate_semantics()
            .expect("the base receipt must be semantically valid");
        body
    }

    fn violates(mut body: Receipt, mutate: impl FnOnce(&mut Receipt)) -> String {
        mutate(&mut body);
        body.validate_semantics()
            .expect_err("the mutated receipt must violate semantic conformance")
            .to_string()
    }

    #[test]
    fn base_receipt_is_semantically_valid() {
        valid_receipt();
    }

    #[test]
    fn open_cannot_carry_a_reason() {
        let msg = violates(valid_receipt(), |b| {
            b.residuals[0].reason = Some("why".into());
        });
        assert!(msg.contains("open residual"), "{msg}");
    }

    #[test]
    fn fixed_requires_the_closure_evidence_fields() {
        let msg = violates(valid_receipt(), |b| {
            b.residuals[0].disposition = "fixed".into();
            b.residuals[0].reason = Some("patched".into());
            b.residuals[0].grammar_state = "recovery".into();
            // no resolution_run_id / closure_predicate
        });
        assert!(msg.contains("resolution_run_id"), "{msg}");
    }

    #[test]
    fn non_fixed_closure_cannot_carry_a_resolution_run() {
        let msg = violates(valid_receipt(), |b| {
            b.residuals[0].disposition = "intentional".into();
            b.residuals[0].reason = Some("clearer wording".into());
            b.residuals[0].grammar_state = "intentional_divergence".into();
            b.residuals[0].resolution_run_id = Some("run-x".into());
            b.endoduction.tokens[0].token = "exit/exit-class/class-change/intentional".into();
        });
        assert!(msg.contains("resolution_run_id"), "{msg}");
    }

    #[test]
    fn duplicate_declared_axes_are_refused() {
        let msg = violates(valid_receipt(), |b| {
            b.court
                .admissibility_envelope
                .observables
                .push("exit".into());
        });
        assert!(msg.contains("duplicate declared"), "{msg}");
    }

    #[test]
    fn residual_axis_must_be_declared() {
        let msg = violates(valid_receipt(), |b| {
            b.residuals[0].axis = "stdout".into();
            b.residuals[0].kind = ResidualKind::text();
        });
        assert!(msg.contains("not a declared observable"), "{msg}");
    }

    #[test]
    fn pass_verdict_cannot_coexist_with_a_residual() {
        let msg = violates(valid_receipt(), |b| {
            b.observables[0].verdict = ObservableVerdict::Pass;
        });
        assert!(msg.contains("pass verdict"), "{msg}");
    }

    #[test]
    fn replay_must_target_the_receipts_run() {
        let msg = violates(valid_receipt(), |b| {
            b.replay.expected_run_identity = "run-other".into();
        });
        assert!(msg.contains("expected_run_identity"), "{msg}");
    }

    #[test]
    fn tokens_must_rederive() {
        let msg = violates(valid_receipt(), |b| {
            b.endoduction.tokens[0].token = "exit/exit-class/class-change/fixed".into();
        });
        assert!(msg.contains("token"), "{msg}");
    }

    #[test]
    fn environment_digest_must_rederive() {
        let msg = violates(valid_receipt(), |b| {
            b.environment.digest = "0".repeat(64);
        });
        assert!(msg.contains("environment digest"), "{msg}");
    }

    #[test]
    fn semantic_identity_must_rederive() {
        let msg = violates(valid_receipt(), |b| {
            b.court.semantic_identity = "0".repeat(64);
        });
        assert!(msg.contains("semantic identity"), "{msg}");
    }

    #[test]
    fn grammar_state_must_derive_from_the_disposition() {
        let msg = violates(valid_receipt(), |b| {
            b.residuals[0].grammar_state = "recovery".into();
        });
        assert!(msg.contains("grammar_state"), "{msg}");
    }

    #[test]
    fn open_cannot_carry_a_disposition_event_id() {
        let msg = violates(valid_receipt(), |b| {
            b.residuals[0].disposition_event_id = Some("0".repeat(64));
        });
        assert!(msg.contains("disposition_event_id"), "{msg}");
    }

    #[test]
    fn a_closed_disposition_must_bind_the_exact_event() {
        let msg = violates(valid_receipt(), |b| {
            b.residuals[0].disposition = "intentional".into();
            b.residuals[0].reason = Some("clearer wording".into());
            b.residuals[0].grammar_state = "intentional_divergence".into();
            b.endoduction.tokens[0].token = "exit/exit-class/class-change/intentional".into();
            // disposition_event_id left None: the receipt must point at the
            // exact event that supplied the disposition.
        });
        assert!(msg.contains("disposition_event_id"), "{msg}");
    }
}
