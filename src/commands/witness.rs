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
                .map(|rid| {
                    // The run digest consumes the residual projections; each
                    // is a verified observation of the run.
                    crate::verify::load_residual_verified(store, rid).map(|v| v.record().clone())
                })
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
    let snapshot =
        crate::ext::snapshot_program(store, Path::new(program), crate::host::ExecProfile::LinuxV1)?;
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
        subject_canonical: None,
        context: WitnessContext {
            evidence_root: &store.root.to_string_lossy(),
        },
    };
    let request_bytes = crate::canon::canonical(&request)?.into_bytes();
    let request_cid = crate::ext::request_cid(&request_bytes);
    // The witness PROGRAM runs under the reference profile (a standalone
    // attestation records no profile of its own; the reference contract is
    // the declared default) and the minimal execution environment (a
    // standalone attestation has no court declaration; the ambient host
    // environment is never inherited — it is not evidence).
    let response_bytes = crate::ext::run_program(
        &snapshot.image,
        &request_bytes,
        std::path::Path::new("."),
        crate::host::ExecProfile::LinuxV1,
        &crate::host::minimal_execution_environment(),
    )?;
    let response_cid = host::sha256_bytes(&response_bytes);
    // The protocol says canonical JSON: the response must BE its own
    // canonical serialization.
    let response: WitnessResponse =
        crate::ext::parse_canonical_response(&response_bytes, "witness response")
            .map_err(|e| FrfError::new(format!("witness {id}: {e}")))?;
    if let Err(e) = crate::schema::admit("witness-response", &response.schema_version) {
        return Err(FrfError::new(format!(
            "witness response has unsupported schema version: {e}"
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
    // The declared authority (v3): a closed kind, recorded verbatim — the
    // witness's own declaration, never FRF's interpretation.
    if let Some(authority) = &response.authority {
        if !WitnessAuthority::KINDS.contains(&authority.kind.as_str()) {
            return Err(FrfError::new(format!(
                "witness {id} declared authority kind {:?}; the protocol admits {}",
                authority.kind,
                WitnessAuthority::KINDS.join(", ")
            )));
        }
        if authority.id.trim().is_empty() {
            return Err(FrfError::new(format!(
                "witness {id} declared an authority without an id"
            )));
        }
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
    // The witness IDENTITY (the stable WHO): content-addressed over the
    // relation's specification and the program's exact bytes + interpreter
    // chain. A different identity is a different instrument — never, by
    // itself, evidence of independent observation (independence is the
    // DECLARED relation of §6).
    let witness_identity = crate::semantics::witness_identity(&semantic, &implementation)?;
    let stmt = WitnessStatement {
        schema_version: SCHEMA_WITNESS_STATEMENT.to_string(),
        id: String::new(), // filled below
        subject: subject.clone(),
        witness_semantic: semantic,
        witness_implementation: implementation,
        witness_identity,
        authority: response.authority,
        statement: statement.to_string(),
        attestation,
        signature: None,
        request_cid: request_cid.clone(),
        response_cid: response_cid.clone(),
        created_by: runner,
    };
    let statement_id =
        crate::semantics::witness_statement_identity(&crate::semantics::WitnessStatementContent {
            subject: &stmt.subject,
            witness_semantic: &stmt.witness_semantic,
            witness_implementation: &stmt.witness_implementation,
            witness_identity: &stmt.witness_identity,
            authority: &stmt.authority,
            statement: &stmt.statement,
            attestation: &stmt.attestation,
            signature: &stmt.signature,
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

/// The exact canonical document bytes of a signable witness subject (a
/// receipt or a claim): read from the store and required to BE canonical —
/// the signature binds these exact bytes, never a typed projection.
fn signable_subject_document(store: &Store, subject: &WitnessSubject) -> Result<Vec<u8>> {
    let path = match subject.kind.as_str() {
        "receipt" => store.receipt_path(&subject.id)?,
        "claim" => store.claim_path(&subject.id)?,
        other => {
            return Err(FrfError::refused(format!(
                "subject kind {other:?} is not a signable document: the signing protocol admits receipt or claim"
            )))
        }
    };
    let bytes = std::fs::read(&path)
        .map_err(|e| FrfError::new(format!("cannot read {}: {e}", path.display())))?;
    crate::canon::require_canonical_bytes(&bytes, &format!("{}", path.display()))?;
    Ok(bytes)
}

/// Resolve a signable witness subject (receipt | claim): the verified load
/// (identity + derivation proven on read) and its content address, plus the
/// subject's exact canonical document bytes.
fn resolve_signable_subject(
    store: &Store,
    subject_kind: &str,
    subject_id: &str,
) -> Result<(WitnessSubject, Vec<u8>)> {
    let subject = match subject_kind {
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
        "claim" => {
            // The claim is content-addressed (the store loader rederives the
            // id from the canonical document minus the id) — the cid IS the
            // claim id.
            let claim = store.load_claim(subject_id)?;
            let _ = claim;
            WitnessSubject {
                kind: "claim".to_string(),
                id: subject_id.to_string(),
                cid: subject_id.to_string(),
            }
        }
        other => {
            return Err(FrfError::refused(format!(
            "unknown signable subject kind {other:?}: the signing protocol admits receipt or claim"
        )))
        }
    };
    let canonical_bytes = signable_subject_document(store, &subject)?;
    Ok((subject, canonical_bytes))
}

/// `frf witness sign <SUBJECT_KIND> <SUBJECT_ID> --key <KEYFILE> --statement
/// <TEXT>`: an EXTERNAL KEY signs a content-addressed evidence document (a
/// receipt or a claim). The signature binds the document's EXACT canonical
/// bytes (recomputed here, never read from the caller), and the statement is
/// recorded exactly like an attestation (`witnesses/<id>.json`) with the
/// signature, the public key, and the signing request/response preserved as
/// evidence (spec/witness.md §7).
///
/// The key file is the 32-byte Ed25519 SEED as 64 lowercase hex characters.
/// FRF computes the signature with the provided key and records it; the key
/// itself is never stored in the tree, and verification recomputes the
/// subject's canonical bytes and checks the signature against the recorded
/// public key. The statement id commits the public key via the key identity
/// (`FRF/ED25519-KEY/v1`), so a signature cannot be re-attributed to a
/// different key without changing the statement's content address.
#[allow(clippy::too_many_arguments)] // one argument per declaration dimension; the doc is the protocol shape
pub fn sign(
    store: &Store,
    subject_kind: &str,
    subject_id: &str,
    id: &str,
    relation: &str,
    relation_version: &str,
    key_path: &Path,
    statement: &str,
) -> Result<String> {
    crate::store::validate_id("witness", id)?;
    if statement.trim().is_empty() {
        return Err(FrfError::invalid_input(
            "the signed statement must not be empty; a signature signs exactly one statement",
        ));
    }

    // -- the external key (Ed25519 seed: 64 hex characters) ------------------
    // Validated BEFORE the subject is resolved: a malformed key is bad
    // caller input, and failing fast on it needs no evidence tree.
    let key_text = std::fs::read_to_string(key_path).map_err(|e| {
        FrfError::invalid_input(format!(
            "cannot read the signing key {}: {e}",
            key_path.display()
        ))
    })?;
    let key_text = key_text.trim();
    if key_text.len() != 64 || !key_text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(FrfError::invalid_input(format!(
            "the signing key {} must be the 32-byte Ed25519 seed as 64 hex characters",
            key_path.display()
        )));
    }
    let seed: Vec<u8> = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&key_text[i..i + 2], 16))
        .collect::<std::result::Result<Vec<u8>, std::num::ParseIntError>>()
        .map_err(|e| FrfError::invalid_input(format!("malformed Ed25519 seed: {e}")))?;
    let seed: [u8; 32] = seed.try_into().map_err(|_| {
        FrfError::invalid_input("the Ed25519 seed must be exactly 32 bytes (64 hex characters)")
    })?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    use base64::Engine as _;
    let algorithm = "ed25519";
    let public_key = base64::engine::general_purpose::STANDARD.encode(verifying_key.as_bytes());

    // -- the semantic + implementation identities ----------------------------
    // WHAT the signature is (id + relation + version, hashed into the
    // semantic identity) vs. WHICH KEY signs (the key identity commits the
    // public key; a key-based signer has no program artifact).
    let specification_hash =
        crate::semantics::witness_specification_hash(id, relation, relation_version)?;
    let semantic = WitnessSemantic {
        id: id.to_string(),
        relation_id: relation.to_string(),
        relation_version: relation_version.to_string(),
        specification_hash,
    };
    let implementation_hash = crate::semantics::ed25519_key_identity(algorithm, &public_key)?;
    let runner = RunnerIdentity {
        schema_version: SCHEMA_RUNNER.to_string(),
        frf_version: env!("CARGO_PKG_VERSION").to_string(),
        frf_executable_hash: host::current_exe_hash()?,
    };
    let implementation = WitnessImplementation {
        id: id.to_string(),
        implementation_hash,
        runner_hash: runner.frf_executable_hash.clone(),
        artifact: None,
    };

    // -- the subject: kind + id + content address + EXACT canonical bytes ---
    // Resolved after the key is validated: the content address and the
    // canonical bytes are REDERIVED here, never read from the caller — the
    // signature binds the exact document.
    let (subject, canonical_bytes) = resolve_signable_subject(store, subject_kind, subject_id)?;

    // -- the canonical signing request + response ----------------------------
    // The request carries the subject's EXACT canonical bytes (base64) so
    // the signature provably binds the document, and the response carries
    // the signature. Both are preserved under `witnesses/<id>/`.
    let request = WitnessRequest {
        schema_version: SCHEMA_WITNESS_REQUEST,
        witness: &semantic,
        subject: &subject,
        statement,
        subject_canonical: Some(base64::engine::general_purpose::STANDARD.encode(&canonical_bytes)),
        context: WitnessContext {
            evidence_root: &store.root.to_string_lossy(),
        },
    };
    let request_bytes = crate::canon::canonical(&request)?.into_bytes();
    let request_cid = crate::ext::request_cid(&request_bytes);

    use ed25519_dalek::Signer as _;
    let signature_bytes = signing_key.sign(&canonical_bytes).to_bytes();
    let witness_signature = WitnessSignature {
        algorithm: algorithm.to_string(),
        public_key: public_key.clone(),
        value: base64::engine::general_purpose::STANDARD.encode(signature_bytes),
    };
    let attestation = WitnessAttestation {
        statement: statement.to_string(),
        outcome: "affirm".to_string(),
        detail: "the key holder signed the subject document's exact canonical bytes".to_string(),
    };
    let response = WitnessResponse {
        schema_version: SCHEMA_WITNESS_RESPONSE.to_string(),
        request_id: request_cid.clone(),
        attestation: Some(attestation.clone()),
        indeterminate: false,
        failure: None,
        authority: None,
        signature: Some(witness_signature.clone()),
    };
    let response_bytes = crate::canon::canonical(&response)?.into_bytes();
    let response_cid = host::sha256_bytes(&response_bytes);

    // -- the content-addressed statement record ------------------------------
    let witness_identity = crate::semantics::witness_identity(&semantic, &implementation)?;
    let stmt = WitnessStatement {
        schema_version: SCHEMA_WITNESS_STATEMENT.to_string(),
        id: String::new(), // filled below
        subject: subject.clone(),
        witness_semantic: semantic,
        witness_implementation: implementation,
        witness_identity,
        authority: None,
        statement: statement.to_string(),
        attestation,
        signature: Some(witness_signature),
        request_cid: request_cid.clone(),
        response_cid: response_cid.clone(),
        created_by: runner,
    };
    let statement_id =
        crate::semantics::witness_statement_identity(&crate::semantics::WitnessStatementContent {
            subject: &stmt.subject,
            witness_semantic: &stmt.witness_semantic,
            witness_implementation: &stmt.witness_implementation,
            witness_identity: &stmt.witness_identity,
            authority: &stmt.authority,
            statement: &stmt.statement,
            attestation: &stmt.attestation,
            signature: &stmt.signature,
            request_cid: &stmt.request_cid,
            response_cid: &stmt.response_cid,
        })?;
    let mut stmt = stmt;
    stmt.id = statement_id;
    store.write_witness_statement(&stmt)?;
    // The preserved request + response documents, under `witnesses/<id>/`.
    // Both are content-addressed (the cids are the byte hashes): when they
    // already exist, verify the existing bytes hash to the recorded cids — a
    // corrupt or mismatched document at this address is refused, never
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
        "witness statement {}: {} {} signed with ed25519 key {}",
        &stmt.id[..16],
        subject.kind,
        subject.id,
        &stmt.signature.as_ref().unwrap().public_key[..16]
    );
    Ok(stmt.id)
}

/// `frf witness verify <STATEMENT_ID>`: verify a witness statement — the
/// statement id rederives and the subject rebinds to the actual verified
/// evidence object (the established witness verification), AND, for a
/// SIGNED statement, the Ed25519 signature verifies over the subject's
/// recomputed exact canonical bytes and the recorded implementation hash
/// commits the signature's public key (the key identity binding). A plain
/// attestation statement verifies with no signature check.
pub fn verify(store: &Store, id: &str) -> Result<String> {
    let verified = crate::verify::load_witness_statement_verified(store, id)?;
    let stmt = verified.statement();
    let mut lines = vec![format!(
        "witness statement {} verified: {} {} — the statement id rederives and the subject rebinds to the verified evidence object",
        &id[..16],
        stmt.subject.kind,
        stmt.subject.id
    )];
    let Some(signature) = &stmt.signature else {
        lines.push(
            "attestation statement: no signature to verify (the attestation is bound by the subject content address)"
                .to_string(),
        );
        return Ok(lines.join("\n"));
    };

    if signature.algorithm != "ed25519" {
        return Err(FrfError::new(format!(
            "witness statement {id}: signature algorithm {:?} is not admitted (the protocol admits ed25519)",
            signature.algorithm
        )));
    }
    use base64::Engine as _;
    let public_key = base64::engine::general_purpose::STANDARD
        .decode(&signature.public_key)
        .map_err(|e| {
            FrfError::new(format!(
                "witness statement {id}: the recorded public key is not valid base64: {e}"
            ))
        })?;
    let signature_value = base64::engine::general_purpose::STANDARD
        .decode(&signature.value)
        .map_err(|e| {
            FrfError::new(format!(
                "witness statement {id}: the recorded signature value is not valid base64: {e}"
            ))
        })?;
    let public_key: [u8; 32] = public_key.try_into().map_err(|_| {
        FrfError::new(format!(
            "witness statement {id}: an ed25519 public key is exactly 32 bytes"
        ))
    })?;
    let signature_value: [u8; 64] = signature_value.try_into().map_err(|_| {
        FrfError::new(format!(
            "witness statement {id}: an ed25519 signature is exactly 64 bytes"
        ))
    })?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key).map_err(|e| {
        FrfError::new(format!(
            "witness statement {id}: the recorded public key is not a valid ed25519 key: {e}"
        ))
    })?;
    let sig = ed25519_dalek::Signature::from_bytes(&signature_value);

    // Recompute the subject's EXACT canonical bytes from the evidence tree
    // and verify the signature over them — a signature over anything else is
    // a refusal, never an interpretation.
    let canonical = signable_subject_document(store, &stmt.subject)?;
    verifying_key.verify_strict(&canonical, &sig).map_err(|e| {
        FrfError::new(format!(
            "witness statement {id}: the ed25519 signature does NOT verify over the {} {}'s exact canonical bytes: {e}",
            stmt.subject.kind, stmt.subject.id
        ))
    })?;

    // The key-identity binding: the implementation hash commits the public
    // key, so the signature cannot be re-attributed to a different key
    // without changing the statement's content address.
    let expected_key_id =
        crate::semantics::ed25519_key_identity(&signature.algorithm, &signature.public_key)?;
    if stmt.witness_implementation.implementation_hash != expected_key_id {
        return Err(FrfError::new(format!(
            "witness statement {id}: the recorded implementation hash does not commit the signature's public key — the signature cannot be re-attributed to this statement"
        )));
    }

    lines.push(format!(
        "signature verified: ed25519 key {} signs the exact canonical bytes of the {} {}",
        &signature.public_key[..16],
        stmt.subject.kind,
        stmt.subject.id
    ));
    Ok(lines.join("\n"))
}

/// `frf witness independence STATEMENT_ID --relation REL --basis TEXT`: the
/// DECLARED independence relation (spec/witness.md §6). An operator records
/// an independence CLAIM about a verified witness statement — which
/// independence relation is claimed and the basis it rests on. FRF verifies
/// the evidence structure (the statement verifies, the witness identity
/// rederives, the relation is closed, the typed evidence refs rederive); it
/// never verifies the social truth of independence, and a different
/// executable hash is never by itself evidence of independent observation —
/// the declaration is the evidence, recorded as a content-addressed
/// [`IndependenceEvidence`] record (`independence/<id>.json`).
pub fn declare_independence(
    store: &Store,
    statement_id: &str,
    relation: &str,
    relation_version: &str,
    basis: &str,
    detail: Option<&str>,
) -> Result<String> {
    if !INDEPENDENCE_RELATIONS.contains(&relation) {
        return Err(FrfError::new(format!(
            "unknown independence relation {relation:?}: the protocol admits {}",
            INDEPENDENCE_RELATIONS.join(", ")
        )));
    }
    if basis.trim().is_empty() {
        return Err(FrfError::new(
            "an independence claim needs a basis: WHY the relation is claimed (the evidence it rests on)",
        ));
    }
    // The statement verifies on read (identity rederives, the preserved
    // documents bind it); an independence claim can only bind real evidence.
    let stmt = store.load_witness_statement(statement_id)?;

    let specification_hash =
        crate::semantics::independence_specification_hash(relation, relation_version)?;
    let runner = RunnerIdentity {
        schema_version: SCHEMA_RUNNER.to_string(),
        frf_version: env!("CARGO_PKG_VERSION").to_string(),
        frf_executable_hash: host::current_exe_hash()?,
    };
    // The typed evidence refs: the statement record and the witness program
    // artifact the independence claim rests on (both rederived, never read
    // from the caller).
    let mut evidence_refs: Vec<EvidenceRef> = Vec::new();
    evidence_refs.push(EvidenceRef {
        role: "witness-statement".to_string(),
        object_kind: "witness".to_string(),
        cid: stmt.id.clone(),
    });
    if let Some(artifact) = &stmt.witness_implementation.artifact {
        evidence_refs.push(EvidenceRef {
            role: "witness-implementation".to_string(),
            object_kind: "object".to_string(),
            cid: artifact.sha256.clone(),
        });
    }
    let detail_owned = detail.map(|d| d.to_string());
    let record = IndependenceEvidence {
        schema_version: SCHEMA_INDEPENDENCE.to_string(),
        id: String::new(), // filled below
        subject: stmt.subject.clone(),
        witness_statement: stmt.id.clone(),
        witness_identity: stmt.witness_identity.clone(),
        relation: relation.to_string(),
        relation_version: relation_version.to_string(),
        specification_hash,
        basis: basis.to_string(),
        detail: detail_owned,
        evidence_refs,
        created_by: runner,
    };
    let identity =
        crate::semantics::independence_identity(&crate::semantics::IndependenceContent {
            subject: &record.subject,
            witness_statement: &record.witness_statement,
            witness_identity: &record.witness_identity,
            relation: &record.relation,
            relation_version: &record.relation_version,
            specification_hash: &record.specification_hash,
            basis: &record.basis,
            detail: &record.detail,
            evidence_refs: &record.evidence_refs,
        })?;
    let mut record = record;
    record.id = identity;
    store.write_independence(&record)?;
    eprintln!(
        "independence {}: witness statement {} -> relation={} ({})",
        &record.id[..16],
        &record.witness_statement[..16],
        record.relation,
        record.basis
    );
    Ok(record.id)
}
