//! `frf witness attest <KIND> <SUBJECT_ID> --program … --statement …`: the
//! witness extension protocol (spec/witness.md).
//!
//! A witness is a protocol participant, not Rust code: any program that
//! speaks the canonical stdin/stdout protocol can attest to a
//! content-addressed evidence subject (a run, a receipt, or a residual) by
//! echoing its `request_id` and returning an attestation of the exact
//! statement it was asked. The statement is recorded as a content-addressed
//! [`WitnessStatement`] (`witnesses/<id>.json`, canonical JSON) with the
//! canonical request and response preserved as evidence — so an attestation
//! is bound to the exact subject content address (rederived here, never read
//! from the caller) and the exact statement, and no one can attach an
//! attestation to a different object after the fact.
//!
//! Fail-closed rules, mirroring the other extension protocols: wrong schema
//! version, unparseable JSON, non-zero exit, timeout, a response that does
//! not name its request, `indeterminate`, or an explicit `failure` are all
//! refusals. A witness that declines (returns no attestation) is also a
//! refusal — an attestation is the only admissible outcome.

use crate::error::{FrfError, Result};
use crate::host;
use crate::model::*;
use crate::store::Store;
use std::path::Path;

/// Attest a content-addressed subject with a declared witness program.
#[allow(clippy::too_many_arguments)] // one argument per declaration dimension; the doc is the protocol shape
pub fn attest(
    store: &Store,
    subject_kind: &str,
    subject_id: &str,
    id: &str,
    relation: &str,
    relation_version: &str,
    program: &str,
    statement: &str,
) -> Result<String> {
    crate::store::validate_id("witness", id)?;
    if statement.trim().is_empty() {
        return Err(FrfError::new(
            "the witness statement must not be empty; an attestation attests exactly one statement",
        ));
    }

    // -- the subject: kind + id + content address, all REDERIVED -------------
    // The content address is never read from the caller: a run's identity
    // digest, a receipt's digest, or a residual's fingerprint is recomputed
    // from the verified evidence object itself. A witness therefore cannot be
    // pointed at a forged address.
    let subject = match subject_kind {
        "run" => {
            let verified = crate::verify::load_capture_verified(store, subject_id)?;
            let residuals: Vec<ResidualRecord> = verified
                .capture
                .residuals
                .iter()
                .map(|rid| store.load_residual(rid))
                .collect::<Result<_>>()?;
            let cid = verified.digest(&residuals)?;
            WitnessSubject {
                kind: "run".to_string(),
                id: subject_id.to_string(),
                cid,
            }
        }
        "receipt" => {
            // The receipt's identity + derivation are verified on read; the
            // digest is the id's own suffix (a receipt is content-addressed).
            crate::verify::load_receipt_verified(store, subject_id)?;
            let digest = subject_id
                .strip_prefix("receipt-")
                .and_then(|rest| rest.rsplit_once('-'))
                .map(|(_, d)| d.to_string())
                .ok_or_else(|| {
                    FrfError::new("invalid receipt id: expected receipt-{run}-{digest}")
                })?;
            WitnessSubject {
                kind: "receipt".to_string(),
                id: subject_id.to_string(),
                cid: digest,
            }
        }
        "residual" => {
            // The residual is verified on read: it must derive from a
            // verified parent run (same run/court/authority/candidate,
            // declared axis, comparator-generated divergence, rederived
            // projections), and its fingerprint is computed from the verified
            // record — a witness cannot be pointed at a residual that is not
            // an actual observation.
            let verified = crate::verify::load_residual_verified(store, subject_id)?;
            let cid = crate::semantics::residual_fingerprint(verified.record())?;
            WitnessSubject {
                kind: "residual".to_string(),
                id: subject_id.to_string(),
                cid,
            }
        }
        other => {
            return Err(FrfError::new(format!(
            "unknown witness subject kind {other:?}: the protocol admits run, receipt, or residual"
        )))
        }
    };

    // -- the semantic + implementation identities ----------------------------
    // WHAT the attestation is (id + relation + version, hashed into the
    // semantic identity) vs. WHO attests (the program's bytes + interpreter,
    // sealed BEFORE it runs — the same ArtifactIdentity discipline as every
    // other extension participant). A different executable hash is NOT
    // evidence of independent observation; independence is a future explicit
    // relation (WitnessIdentity / WitnessAuthority / IndependenceEvidence).
    let specification_hash =
        crate::semantics::witness_specification_hash(id, relation, relation_version)?;
    let semantic = WitnessSemantic {
        id: id.to_string(),
        relation_id: relation.to_string(),
        relation_version: relation_version.to_string(),
        specification_hash,
    };
    let snapshot = crate::ext::snapshot_program(store, Path::new(program))?;
    let runner = RunnerIdentity {
        schema_version: SCHEMA_RUNNER.to_string(),
        frf_version: env!("CARGO_PKG_VERSION").to_string(),
        frf_executable_hash: host::current_exe_hash()?,
    };
    let implementation = WitnessImplementation {
        id: id.to_string(),
        implementation_hash: snapshot.impl_hash.clone(),
        runner_hash: runner.frf_executable_hash.clone(),
        artifact: Some(snapshot.artifact.clone()),
    };

    // -- the canonical request + response ------------------------------------
    let request = WitnessRequest {
        schema_version: SCHEMA_WITNESS_REQUEST,
        witness: &semantic,
        subject: &subject,
        statement,
        context: WitnessContext {
            evidence_root: &store.root.to_string_lossy(),
        },
    };
    let request_bytes = crate::canon::canonical(&request)?.into_bytes();
    let request_cid = crate::ext::request_cid(&request_bytes);
    let response_bytes =
        crate::ext::run_program(&snapshot.snapshot, &request_bytes, Path::new("."))?;
    let response_cid = host::sha256_bytes(&response_bytes);
    // The protocol says canonical JSON: the response must BE its own
    // canonical serialization.
    crate::ext::require_canonical_response(&response_bytes, "witness response")?;
    let response: WitnessResponse = serde_json::from_slice(&response_bytes).map_err(|e| {
        FrfError::new(format!(
            "witness {id} produced an unparseable response: {e}"
        ))
    })?;
    if response.schema_version != SCHEMA_WITNESS_RESPONSE {
        return Err(FrfError::new(format!(
            "witness response has unsupported schema version {:?}",
            response.schema_version
        )));
    }
    if response.request_id != request_cid {
        return Err(FrfError::new(format!(
            "witness {id} does not name the request it answers; a response must cryptographically name the exact request it answers"
        )));
    }
    if response.indeterminate {
        return Err(FrfError::new(format!(
            "witness {id} returned indeterminate; refusing to record inconclusive evidence"
        )));
    }
    if let Some(f) = &response.failure {
        return Err(FrfError::new(format!("witness {id} reported failure: {f}")));
    }
    let attestation = response.attestation.ok_or_else(|| {
        FrfError::new(format!(
            "witness {id} declined to attest (no attestation in the response); an attestation is the only admissible outcome"
        ))
    })?;
    if attestation.statement != statement {
        return Err(FrfError::new(format!(
            "witness {id} attested a different statement than the request; refusing to record a mismatched attestation"
        )));
    }
    // The witness's own assertion is one of the closed outcomes. It is the
    // WITNESS's claim about the world; FRF's verification — that the
    // statement is bound to the correct subject, request, and statement — is
    // the content-address, and the two predicates are never conflated.
    if !matches!(
        attestation.outcome.as_str(),
        "affirm" | "deny" | "indeterminate"
    ) {
        return Err(FrfError::new(format!(
            "witness {id} returned attestation outcome {:?}; the protocol admits affirm, deny, or indeterminate",
            attestation.outcome
        )));
    }

    // -- the content-addressed statement record ------------------------------
    let stmt = WitnessStatement {
        schema_version: SCHEMA_WITNESS_STATEMENT.to_string(),
        id: String::new(), // filled below
        subject: subject.clone(),
        witness_semantic: semantic,
        witness_implementation: implementation,
        statement: statement.to_string(),
        attestation,
        request_cid: request_cid.clone(),
        response_cid: response_cid.clone(),
        created_by: runner,
    };
    let statement_id =
        crate::semantics::witness_statement_identity(&crate::semantics::WitnessStatementContent {
            subject: &stmt.subject,
            witness_semantic: &stmt.witness_semantic,
            witness_implementation: &stmt.witness_implementation,
            statement: &stmt.statement,
            attestation: &stmt.attestation,
            request_cid: &stmt.request_cid,
            response_cid: &stmt.response_cid,
        })?;
    let mut stmt = stmt;
    stmt.id = statement_id;
    store.write_witness_statement(&stmt)?;
    // The preserved request + response documents, under `witnesses/<id>/`.
    // Both are content-addressed (the cids are the byte hashes): when they
    // already exist, verify the existing bytes hash to the recorded cids —
    // a corrupt or mismatched document at this address is refused, never
    // silently "reused".
    let dir = store.witness_dir(&stmt.id)?;
    std::fs::create_dir_all(&dir)
        .map_err(|e| FrfError::new(format!("cannot create {}: {e}", dir.display())))?;
    let request_doc = String::from_utf8(request_bytes)
        .map_err(|_| FrfError::new("internal error: witness request is not UTF-8"))?;
    let response_doc = String::from_utf8(response_bytes)
        .map_err(|_| FrfError::new("internal error: witness response is not UTF-8"))?;
    for (file, cid, doc) in [
        ("request.json", &stmt.request_cid, &request_doc),
        ("response.json", &stmt.response_cid, &response_doc),
    ] {
        let target = dir.join(file);
        if target.exists() {
            let existing = std::fs::read(&target)
                .map_err(|e| FrfError::new(format!("cannot read {}: {e}", target.display())))?;
            if crate::host::sha256_bytes(&existing) != *cid {
                return Err(FrfError::new(format!(
                    "{} already exists but does not hash to the recorded {} cid; refusing to reuse corrupt witness evidence",
                    target.display(),
                    file
                )));
            }
        } else {
            store.write_once(&target, doc)?;
        }
    }

    eprintln!(
        "witness statement {}: {} {} -> outcome={} ({})",
        &stmt.id[..16],
        subject.kind,
        subject.id,
        stmt.attestation.outcome,
        stmt.attestation.detail
    );
    Ok(stmt.id)
}
