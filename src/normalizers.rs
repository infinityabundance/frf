//! The normalizer extension protocol host (spec/normalizer.md).
//!
//! A normalizer is a protocol participant, not Rust code: any program that
//! speaks the canonical stdin/stdout protocol can map a side's raw streams to
//! the normalized streams the court COMPARES. The raw streams survive as the
//! request evidence — an observation is never rewritten, the comparison
//! surface is.
//!
//! Fail-closed rules, mirroring the comparator protocol:
//!
//! - wrong schema version, unparseable JSON, non-zero exit, timeout → refusal;
//! - `request_id` must equal the canonical request the court sent;
//! - `indeterminate` / `failure` → refusal;
//! - a normalizer declared `applies_to: stdout` that changes stderr (or vice
//!   versa) → refusal — it moved what it was not declared to move.

use crate::error::{FrfError, Result};
use crate::ext;
use crate::host;
use crate::model::{
    CaptureManifest, NormalizerContext, NormalizerDeclaration, NormalizerInvocation,
    NormalizerRequest, NormalizerResponse, NormalizerResult, NormalizerSemantic,
    SCHEMA_NORMALIZER_REQUEST, SCHEMA_NORMALIZER_RESPONSE,
};
use crate::semantics;
use crate::store::Store;
use std::path::Path;

/// The semantic identity of a declared normalizer. Same formula as the
/// comparator registry: `FRF/NORMALIZER-SPEC/v2` over the specification
/// document (id + relation + applies_to).
pub fn declared_semantic(decl: &NormalizerDeclaration) -> Result<NormalizerSemantic> {
    let specification_hash = semantics::normalizer_specification_hash(
        &decl.id,
        &decl.relation,
        &decl.applies_to,
        &decl.relation_version,
    )?;
    Ok(NormalizerSemantic {
        id: decl.id.clone(),
        relation_id: decl.relation.clone(),
        applies_to: decl.applies_to.clone(),
        relation_version: decl.relation_version.clone(),
        specification_hash,
    })
}

/// Build the canonical normalizer REQUEST for one side: the raw streams,
/// base64. ONE builder shared by the court and replay — the request is a
/// derived object, and its identity (`request_cid`) is its canonical bytes'
/// SHA-256.
pub fn build_request<'a>(
    semantic: &'a NormalizerSemantic,
    side: &'a str,
    stdout: &'a [u8],
    stderr: &'a [u8],
    fixture_sha256: &'a str,
    arguments: &'a [String],
    environment_digest: &'a str,
) -> NormalizerRequest<'a> {
    NormalizerRequest {
        schema_version: SCHEMA_NORMALIZER_REQUEST,
        normalizer: semantic,
        side,
        stdout_base64: ext::b64(stdout),
        stderr_base64: ext::b64(stderr),
        context: NormalizerContext {
            fixture_sha256,
            arguments,
            environment_digest,
        },
    }
}

/// The canonical bytes of a request plus their content address.
pub fn canonical_request(request: &NormalizerRequest) -> Result<(Vec<u8>, String)> {
    let json = crate::canon::canonical(request)?;
    let bytes = json.into_bytes();
    let cid = crate::host::sha256_bytes(&bytes);
    Ok((bytes, cid))
}

/// Interpret a normalizer's canonical response, fail-closed. On success
/// returns the normalized stdout/stderr bytes.
pub fn interpret(
    response: &NormalizerResponse,
    expected_request_id: &str,
    applies_to: &str,
    raw_stdout: &[u8],
    raw_stderr: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    if response.schema_version != SCHEMA_NORMALIZER_RESPONSE {
        return Err(FrfError::new(format!(
            "normalizer response has unsupported schema version {:?} (expected {SCHEMA_NORMALIZER_RESPONSE})",
            response.schema_version
        )));
    }
    if response.request_id != expected_request_id {
        return Err(FrfError::new(format!(
            "normalizer response names request {} but it answers request {}; a response must cryptographically name the exact request it answers",
            &response.request_id[..16.min(response.request_id.len())],
            &expected_request_id[..16]
        )));
    }
    if response.indeterminate {
        return Err(FrfError::new(
            "normalizer returned indeterminate: the streams cannot be normalized; refusing to compare un-normalized output as normalized",
        ));
    }
    if let Some(f) = &response.failure {
        return Err(FrfError::new(format!("normalizer reported failure: {f}")));
    }
    let stdout = ext::unb64(&response.stdout_base64, "normalized stdout")?;
    let stderr = ext::unb64(&response.stderr_base64, "normalized stderr")?;
    // A normalizer may only move what it is declared to move.
    match applies_to {
        "stdout" => {
            if stderr != raw_stderr {
                return Err(FrfError::new(
                    "normalizer is declared to normalize stdout but changed stderr; refusing to record evidence from a normalizer that moves what it is not declared to move",
                ));
            }
        }
        "stderr" => {
            if stdout != raw_stdout {
                return Err(FrfError::new(
                    "normalizer is declared to normalize stderr but changed stdout; refusing to record evidence from a normalizer that moves what it is not declared to move",
                ));
            }
        }
        "both" => {}
        other => {
            return Err(FrfError::new(format!(
                "normalizer declares applies_to {other:?}; the protocol admits stdout, stderr, or both"
            )));
        }
    }
    Ok((stdout, stderr))
}

/// Run a snapshotted normalizer against one side's raw streams and interpret
/// its response, under the declared execution profile. Returns the
/// normalized streams and the raw response bytes.
pub fn run_side(
    image: &host::ExecImage,
    request_bytes: &[u8],
    semantic: &NormalizerSemantic,
    raw_stdout: &[u8],
    raw_stderr: &[u8],
    cwd: &Path,
    profile: host::ExecProfile,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let response_bytes = ext::run_program(image, request_bytes, cwd, profile)?;
    // The protocol says canonical JSON: the response must BE its own
    // canonical serialization (one semantic response, one evidence identity).
    ext::require_canonical_response(&response_bytes, "normalizer response")?;
    let response: NormalizerResponse = serde_json::from_slice(&response_bytes).map_err(|e| {
        FrfError::new(format!(
            "normalizer for id {} produced an unparseable response: {e}",
            semantic.id
        ))
    })?;
    let request_cid = ext::request_cid(request_bytes);
    let (stdout, stderr) = interpret(
        &response,
        &request_cid,
        &semantic.applies_to,
        raw_stdout,
        raw_stderr,
    )
    .map_err(|e| FrfError::new(format!("normalizer {}: {e}", semantic.id)))?;
    Ok((stdout, stderr, response_bytes))
}

/// The invocation evidence records for one normalized side. The four
/// evidence files are written by the court once the run id exists (under
/// `captures/<run>/normalizer/<id>/<side>/` via [`ext::write_evidence`]);
/// replay builds the records only, to re-verify the request rederives.
#[allow(clippy::too_many_arguments)] // one argument per evidence dimension; the doc is the protocol shape
pub fn record_evidence(
    normalizer_id: &str,
    side: &str,
    semantic: &NormalizerSemantic,
    implementation_artifact: &crate::model::ArtifactIdentity,
    runner: &crate::model::RunnerIdentity,
    request_bytes: &[u8],
    response_bytes: &[u8],
    normalized_stdout: &[u8],
    normalized_stderr: &[u8],
) -> Result<(NormalizerInvocation, NormalizerResult)> {
    let request_cid = ext::request_cid(request_bytes);
    let response_cid = crate::host::sha256_bytes(response_bytes);
    let invocation_id =
        semantics::normalizer_invocation_identity(&semantics::NormalizerInvocationContent {
            normalizer_id,
            side,
            request_cid: &request_cid,
            normalizer_semantic_cid: &semantic.specification_hash,
            normalizer_implementation_artifact: implementation_artifact,
            execution_provenance: runner,
        })?;
    let invocation = NormalizerInvocation {
        schema_version: crate::model::SCHEMA_NORMALIZER_INVOCATION.to_string(),
        invocation_id: invocation_id.clone(),
        normalizer_id: normalizer_id.to_string(),
        side: side.to_string(),
        request_cid: request_cid.clone(),
        normalizer_semantic_cid: semantic.specification_hash.clone(),
        normalizer_implementation_artifact: implementation_artifact.clone(),
        execution_provenance: runner.clone(),
    };
    let stdout_sha256 = crate::host::sha256_bytes(normalized_stdout);
    let stderr_sha256 = crate::host::sha256_bytes(normalized_stderr);
    let result_id = semantics::normalizer_result_identity(&semantics::NormalizerResultContent {
        request_cid: &request_cid,
        response_cid: &response_cid,
        stdout_sha256: &stdout_sha256,
        stderr_sha256: &stderr_sha256,
    })?;
    let result = NormalizerResult {
        schema_version: crate::model::SCHEMA_NORMALIZER_RESULT.to_string(),
        result_id: result_id.clone(),
        invocation_id: invocation.invocation_id.clone(),
        request_cid,
        response_cid,
        stdout_sha256,
        stderr_sha256,
        outcome: "applied".to_string(),
    };
    Ok((invocation, result))
}

/// Apply the capture's declared normalizers (in application order) to one
/// side's raw outcome, using the EXACT snapshotted implementations bound at
/// observation time — the same instrument evidence the court recorded. Used
/// by replay and minimization, which must reproduce the comparison surface
/// without the original manifest. `verify_request_cids` (when `Some`) is the
/// recorded evidence's `request_cid` per normalizer, in application order,
/// which the rebuilt requests must rederive to under exact replay; `None`
/// skips the check (semantic replay, or a fresh minimization attempt whose
/// requests are NEW observations).
pub fn apply_capture_normalizers(
    store: &Store,
    capture: &CaptureManifest,
    side: &str,
    raw_outcome: &host::ProcessOutcome,
    verify_request_cids: Option<&[String]>,
    cwd: &Path,
    profile: host::ExecProfile,
) -> Result<host::ProcessOutcome> {
    let mut stdout = raw_outcome.stdout.clone();
    let mut stderr = raw_outcome.stderr.clone();
    for (idx, semantic) in capture.normalizer_semantics.iter().enumerate() {
        let implementation = capture
            .provenance
            .normalizer_implementations
            .iter()
            .find(|i| i.id == semantic.id)
            .ok_or_else(|| {
                FrfError::new(format!(
                    "the capture carries no implementation for normalizer {}",
                    semantic.id
                ))
            })?;
        let artifact = implementation.artifact.as_ref().ok_or_else(|| {
            FrfError::new(format!(
                "normalizer {} has no snapshotted implementation artifact",
                semantic.id
            ))
        })?;
        let snapshot = crate::comparators::materialize_implementation(store, artifact)?;
        let request = build_request(
            semantic,
            side,
            &stdout,
            &stderr,
            &capture.fixture_sha256,
            &capture.arguments,
            &capture.environment.digest,
        );
        let (request_bytes, request_cid) = canonical_request(&request)?;
        if let Some(recorded) = verify_request_cids.and_then(|cids| cids.get(idx)) {
            if request_cid != *recorded {
                return Err(FrfError::new(format!(
                    "the normalizer {} request for the {side} side no longer rederives to the recorded request_cid — the raw streams differ from what the instrument saw",
                    semantic.id
                )));
            }
        }
        let (new_stdout, new_stderr, _response_bytes) = run_side(
            &snapshot,
            &request_bytes,
            semantic,
            &stdout,
            &stderr,
            cwd,
            profile,
        )?;
        stdout = new_stdout;
        stderr = new_stderr;
    }
    Ok(host::ProcessOutcome {
        stdout,
        stderr,
        exit: raw_outcome.exit.clone(),
    })
}
