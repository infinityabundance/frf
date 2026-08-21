//! The shared external-program host for the extension protocols.
//!
//! Every extension protocol participant — a normalizer, a minimizer, a
//! capture adapter, a witness, an external comparator — is a PROGRAM that
//! speaks a canonical stdin/stdout JSON protocol, not Rust code. This module
//! is the one place the four protocol hosts share:
//!
//! - **snapshotting**: a program is read and hashed BEFORE any execution,
//!   executed through a content-addressed immutable snapshot, and re-hashed
//!   on every use — the same `ArtifactIdentity` discipline as the artifacts
//!   it helps observe (no TOCTOU window between hashing and executing);
//! - **running fail-closed**: a non-zero exit, a timeout, or an unparseable
//!   response is a refusal, never a silent default;
//! - **evidence writing**: the canonical request, the canonical response,
//!   the invocation record, and the result record — the exact instrument
//!   that observed — written once and re-verified on every read.
//!
//! The comparator protocol (spec/comparator.md) has its own host in
//! `comparators.rs` with a pinned evidence layout; the four NEW protocols
//! (spec/normalizer.md, spec/minimizer.md, spec/capture-adapter.md,
//! spec/witness.md) all use this one.

use crate::error::{FrfError, Result};
use crate::host;
use crate::model::{ArtifactIdentity, InterpreterIdentity};
use crate::store::Store;
use std::path::{Path, PathBuf};

/// A snapshotted extension program: the exact bytes that will run.
pub struct ProgramSnapshot {
    /// SHA-256 of the program bytes.
    pub impl_hash: String,
    /// The immutable, sealed snapshot under `objects/sha256/` (the evidence
    /// path + argv[0]).
    pub snapshot: PathBuf,
    /// The SEALED executable image: the exact verified bytes, executed via a
    /// memfd sealed read-only (verify→execute race closed).
    pub image: host::ExecImage,
    /// The artifact identity (root-relative snapshot path + interpreter
    /// chain) recorded in provenance and carried by the bundle closure.
    pub artifact: ArtifactIdentity,
}

/// Read + hash + seal a program BEFORE anything executes it, and record its
/// interpreter chain. The program is a content-addressed object like any
/// artifact; the executed image is the sealed verified bytes.
pub fn snapshot_program(store: &Store, path: &Path) -> Result<ProgramSnapshot> {
    let bytes = host::read_file(path)?;
    let impl_hash = host::sha256_bytes(&bytes);
    let snapshot = store.materialize_object(&bytes, true)?;
    let image = host::ExecImage::seal(&bytes, &impl_hash, &snapshot)?;
    let interpreter = host::interpreter_identity(&bytes)?;
    let artifact = ArtifactIdentity {
        path: store
            .root
            .join("objects")
            .join("sha256")
            .join(&impl_hash)
            .strip_prefix(&store.root)
            .map(|r| r.to_string_lossy().into_owned())
            .unwrap_or_else(|_| impl_hash.clone()),
        sha256: impl_hash.clone(),
        interpreter,
    };
    Ok(ProgramSnapshot {
        impl_hash,
        snapshot,
        image,
        artifact,
    })
}

/// Execute a snapshotted protocol program with the canonical request on
/// stdin. Fail-closed: a non-zero exit or an execution error (timeout,
/// overflow, missing program) is a refusal. Returns the raw stdout bytes —
/// the caller parses and interprets them against the protocol.
pub fn run_program(image: &host::ExecImage, request_bytes: &[u8], cwd: &Path) -> Result<Vec<u8>> {
    let out = host::run_process_with_stdin_in(image, &[], request_bytes, cwd)?;
    if out.exit != "0" {
        return Err(FrfError::new(format!(
            "extension program {} exited {}; refusing to record evidence from a failed participant",
            image.argv0().display(),
            out.exit
        )));
    }
    Ok(out.stdout)
}

/// The content address of a canonical request document: SHA-256 of its exact
/// canonical bytes — the same bytes the program received and must echo back
/// as its `request_id`.
pub fn request_cid(request_bytes: &[u8]) -> String {
    host::sha256_bytes(request_bytes)
}

/// A protocol response must BE its own canonical serialization: strict-JSON
/// parse the bytes, JCS-encode the parsed value, and refuse anything that is
/// not byte-identical. The protocols say canonical JSON on both sides of the
/// wire; requests are canonicalized by construction, and a response must
/// not be able to split one semantic document into many evidence identities
/// (two byte sequences for the same response would otherwise hash
/// differently and preserve differently).
pub fn require_canonical_response(response_bytes: &[u8], what: &str) -> Result<()> {
    crate::canon::require_canonical_bytes(response_bytes, what)
}

/// Write the four invocation-evidence files under `dir` (created): the
/// canonical request, the canonical response, the invocation record, and the
/// result record. All are written with `create_new`: evidence is never
/// overwritten.
pub fn write_evidence(
    store: &Store,
    dir: &Path,
    request_bytes: &[u8],
    response_bytes: &[u8],
    invocation: &serde_json::Value,
    result: &serde_json::Value,
) -> Result<()> {
    std::fs::create_dir_all(dir)
        .map_err(|e| FrfError::new(format!("cannot create {}: {e}", dir.display())))?;
    let req = String::from_utf8(request_bytes.to_vec())
        .map_err(|_| FrfError::new("internal error: extension request is not UTF-8"))?;
    let res = String::from_utf8(response_bytes.to_vec())
        .map_err(|_| FrfError::new("internal error: extension response is not UTF-8"))?;
    store.write_once(&dir.join("request.json"), &req)?;
    store.write_once(&dir.join("response.json"), &res)?;
    store.write_once(
        &dir.join("invocation.json"),
        &crate::canon::canonical(invocation)?,
    )?;
    store.write_once(&dir.join("result.json"), &crate::canon::canonical(result)?)?;
    Ok(())
}

/// Base64-encode bytes.
pub fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Base64-decode bytes, fail-closed.
pub fn unb64(b64: &str, what: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| FrfError::new(format!("cannot decode {what}: {e}")))
}

/// Convenience: the interpreter identity of the frf executable itself —
/// `None` (a native binary).
#[allow(dead_code)]
pub fn native_interpreter() -> Option<InterpreterIdentity> {
    None
}
