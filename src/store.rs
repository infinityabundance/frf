//! Root-relative evidence store with immutability guards.
//!
//! Layout (Section 19.3 of the paper):
//!
//! ```text
//! <root>/
//!   authorities/   admitted once, never rewritten
//!   courts/        hand-authored declarations (never created by the tool)
//!   captures/      raw observations, written once (create_new); the run
//!                  directory is the TRANSACTIONAL ROOT — it carries the
//!                  residual LEAVES (captures/<run>/residuals/<id>.json),
//!                  published by ONE atomic rename
//!   objects/       content-addressed execution snapshots (sha256/<H>)
//!   residuals/     the DERIVED INDEX (byte-identical copies of the leaves)
//!                  + derived token files + <id>.events/ event chains
//!   receipts/      bindings, written once (content-addressed ids)
//!   claims/        compiled claim artifacts, written only by `frf claim compile`
//! ```
//!
//! Invariants enforced here:
//! - Every id → path construction validates the id first ([`is_valid_id`]); an
//!   id can never escape the root, no matter where it came from (manifests,
//!   CLI arguments, or fuzzed input).
//! - [`Store::write_once`] fails if the target already exists (raw captures,
//!   authorities, receipts).
//! - [`Store::write_derived`] may overwrite, and is used only for artifacts
//!   that are pure functions of immutable inputs (tokens, claims, the derived
//!   residual index).
//! - The residual record is IMMUTABLE evidence: its LEAF is written once
//!   inside the run (the transactional root) and never rewritten; the derived
//!   top-level artifacts that follow it — the index copy and the κ token —
//!   are pure functions of the record + its disposition chain, rewritten by
//!   [`Store::write_residual_index`] / [`Store::write_token`].

use crate::error::{FrfError, Result};
use crate::model::*;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// The availability of one content address for GRAPH verification: present
/// (bytes verified), declared-detached (bytes withheld by the publication
/// policy — the graph still verifies, the closure is incomplete-by-policy),
/// or missing (neither — an incomplete or corrupt publication).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectAvailability {
    Present,
    DeclaredDetached,
    Missing,
}

/// Safe id charset: letters, digits, `.`, `_`, `-`, and never `.` or `..`.
/// This is the *only* vocabulary ids may use, because ids become path
/// components (authority/residual/receipt/claim filenames and run dir names).
pub fn is_valid_id(id: &str) -> bool {
    !id.is_empty()
        && id != "."
        && id != ".."
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Validate an id, producing a user-facing error naming the offending value.
pub fn validate_id(what: &str, id: &str) -> Result<()> {
    if is_valid_id(id) {
        Ok(())
    } else {
        Err(FrfError::new(format!(
            "invalid {what} id '{id}': ids may contain letters, digits, '.', '_', '-' only (and may not be '.' or '..')"
        )))
    }
}

/// The reduction record's external-minimizer binding, when an external
/// minimizer performed the reduction: (semantic id, semantic hash,
/// implementation hash, implementation artifact, invocation id, result id).
/// `None` for a built-in ddmin reduction.
pub fn minimizer_binding(
    record: &ReductionRecord,
) -> Option<(
    &String,
    &String,
    &String,
    &ArtifactIdentity,
    &String,
    &String,
)> {
    match (
        &record.minimizer_semantic_id,
        &record.minimizer_semantic_hash,
        &record.minimizer_implementation_hash,
        &record.minimizer_implementation_artifact,
        &record.minimizer_invocation_id,
        &record.minimizer_result_id,
    ) {
        (Some(a), Some(b), Some(c), Some(d), Some(e), Some(f)) => Some((a, b, c, d, e, f)),
        _ => None,
    }
}

pub struct Store {
    pub root: PathBuf,
}

impl Store {
    pub fn new(root: PathBuf) -> Self {
        Store { root }
    }

    /// Create the generated evidence directories under the root.
    /// `courts/` is intentionally not created: court declarations are source,
    /// not tool output.
    pub fn ensure_tree(&self) -> Result<()> {
        for dir in [
            "authorities",
            "captures",
            "objects",
            "residuals",
            "series",
            "trajectories",
            "reductions",
            "receipts",
            "claims",
            "witnesses",
            "independence",
            "harness",
        ] {
            fs::create_dir_all(self.root.join(dir)).map_err(|e| {
                FrfError::new(format!(
                    "cannot create {}: {e}",
                    self.root.join(dir).display()
                ))
            })?;
        }
        Ok(())
    }

    // -- paths --------------------------------------------------------------

    /// Every path builder validates its id; a bad id is an error, never a
    /// silent escape from the root.
    pub fn authority_path(&self, id: &str) -> Result<PathBuf> {
        validate_id("authority", id)?;
        Ok(self.root.join("authorities").join(format!("{id}.json")))
    }

    pub fn run_dir(&self, run: &str) -> Result<PathBuf> {
        validate_id("run", run)?;
        Ok(self.root.join("captures").join(run))
    }

    /// `captures/<run>/comparator/<axis>/` — the invocation evidence
    /// directory for one externally served axis (request.json, response.json,
    /// invocation.json, result.json). The axis is validated again for
    /// defense in depth: it becomes a path component.
    pub fn comparator_dir(&self, run: &str, axis: &str) -> Result<PathBuf> {
        crate::model::ObservableId::parse(axis)?;
        Ok(self.run_dir(run)?.join("comparator").join(axis))
    }

    /// Load + verify a comparator INVOCATION record: its identity rederives
    /// from its own fields, and the preserved request document hashes to the
    /// recorded `request_cid`. A hand-edited or corrupt record is refused,
    /// never silently consumed.
    pub fn load_comparator_invocation(
        &self,
        run: &str,
        axis: &str,
    ) -> Result<crate::model::ComparatorInvocation> {
        let dir = self.comparator_dir(run, axis)?;
        let path = dir.join("invocation.json");
        if !path.is_file() {
            return Err(FrfError::new(format!(
                "run {run}: no comparator invocation evidence for axis {axis} (missing {})",
                path.display()
            )));
        }
        let inv: crate::model::ComparatorInvocation = self.parse_evidence(&path)?;
        let rederived = crate::semantics::comparator_invocation_identity(
            &crate::semantics::ComparatorInvocationContent {
                axis: &inv.axis,
                request_cid: &inv.request_cid,
                comparator_semantic_cid: &inv.comparator_semantic_cid,
                comparator_implementation_artifact: &inv.comparator_implementation_artifact,
                execution_provenance: &inv.execution_provenance,
            },
        )?;
        if rederived != inv.invocation_id {
            return Err(FrfError::new(format!(
                "run {run}: comparator invocation for axis {axis} is not content-addressed (its recorded fields hash to {}) — refusing to consume a hand-edited invocation",
                &rederived[..16]
            )));
        }
        let request_path = dir.join("request.json");
        if !request_path.is_file() {
            return Err(FrfError::new(format!(
                "run {run}: comparator request for axis {axis} is missing ({})",
                request_path.display()
            )));
        }
        let request_bytes = fs::read(&request_path)
            .map_err(|e| FrfError::new(format!("cannot read {}: {e}", request_path.display())))?;
        if crate::host::sha256_bytes(&request_bytes) != inv.request_cid {
            return Err(FrfError::new(format!(
                "run {run}: the preserved request for axis {axis} does not hash to its recorded request_cid"
            )));
        }
        Ok(inv)
    }

    /// Load + verify a comparator RESULT record: its identity rederives from
    /// its own fields, and the preserved response document hashes to the
    /// recorded `response_cid`.
    pub fn load_comparator_result(
        &self,
        run: &str,
        axis: &str,
    ) -> Result<crate::model::ComparatorResult> {
        let dir = self.comparator_dir(run, axis)?;
        let path = dir.join("result.json");
        if !path.is_file() {
            return Err(FrfError::new(format!(
                "run {run}: no comparator result evidence for axis {axis} (missing {})",
                path.display()
            )));
        }
        let res: crate::model::ComparatorResult = self.parse_evidence(&path)?;
        let rederived = crate::semantics::comparator_result_identity(
            &crate::semantics::ComparatorResultContent {
                request_cid: &res.request_cid,
                response_cid: &res.response_cid,
                outcome: &res.outcome,
                residual_observation_ids: &res.residual_observation_ids,
            },
        )?;
        if rederived != res.result_id {
            return Err(FrfError::new(format!(
                "run {run}: comparator result for axis {axis} is not content-addressed (its recorded fields hash to {}) — refusing to consume a hand-edited result",
                &rederived[..16]
            )));
        }
        let response_path = dir.join("response.json");
        if !response_path.is_file() {
            return Err(FrfError::new(format!(
                "run {run}: comparator response for axis {axis} is missing ({})",
                response_path.display()
            )));
        }
        let response_bytes = fs::read(&response_path)
            .map_err(|e| FrfError::new(format!("cannot read {}: {e}", response_path.display())))?;
        if crate::host::sha256_bytes(&response_bytes) != res.response_cid {
            return Err(FrfError::new(format!(
                "run {run}: the preserved response for axis {axis} does not hash to its recorded response_cid"
            )));
        }
        Ok(res)
    }

    /// Load + cross-verify a comparator's invocation AND result evidence, and
    /// the response's binding to its request: the result must answer the
    /// invocation's exact request (same `request_cid`), and the response must
    /// cryptographically name that request (`request_id`).
    pub fn load_comparator_evidence(
        &self,
        run: &str,
        axis: &str,
    ) -> Result<crate::model::ComparatorEvidence> {
        let invocation = self.load_comparator_invocation(run, axis)?;
        let result = self.load_comparator_result(run, axis)?;
        if result.request_cid != invocation.request_cid {
            return Err(FrfError::new(format!(
                "run {run}: comparator result for axis {axis} answers a different request than its invocation"
            )));
        }
        let dir = self.comparator_dir(run, axis)?;
        let response: crate::model::ComparatorResponse =
            self.parse_evidence(&dir.join("response.json"))?;
        if response.request_id != invocation.request_cid {
            return Err(FrfError::new(format!(
                "run {run}: comparator response for axis {axis} does not name the request it answers"
            )));
        }
        for rid in &result.residual_observation_ids {
            // The comparator result claims these residuals; the check is on
            // the run binding (the caller that produced the result already
            // verified the run).
            let record = self.load_residual(rid)?.into_inner();
            if record.run != run {
                return Err(FrfError::new(format!(
                    "run {run}: comparator result for axis {axis} references residual {rid} which belongs to run {}",
                    record.run
                )));
            }
        }
        Ok(crate::model::ComparatorEvidence { invocation, result })
    }

    /// `challenges/<id>/mutation/` — the preserved request + response +
    /// invocation + result evidence of an external mutation proposal.
    pub fn challenge_mutation_dir(&self, id: &str) -> Result<PathBuf> {
        validate_id("challenge", id)?;
        Ok(self.root.join("challenges").join(id).join("mutation"))
    }

    /// Load + verify a mutation INVOCATION record: its identity rederives
    /// from its own fields, and the preserved request document hashes to the
    /// recorded `request_cid`.
    pub fn load_mutation_invocation(&self, id: &str) -> Result<crate::model::MutationInvocation> {
        let dir = self.challenge_mutation_dir(id)?;
        let path = dir.join("invocation.json");
        let inv: crate::model::MutationInvocation = self.parse_evidence(&path)?;
        let rederived = crate::semantics::mutation_invocation_identity(
            &crate::semantics::MutationInvocationContent {
                operator: &inv.operator,
                target_axis: &inv.target_axis,
                request_cid: &inv.request_cid,
                mutation_semantic_cid: &inv.mutation_semantic_cid,
                mutation_implementation_artifact: &inv.mutation_implementation_artifact,
                execution_provenance: &inv.execution_provenance,
            },
        )?;
        if rederived != inv.invocation_id {
            return Err(FrfError::new(format!(
                "mutation invocation {id} is not content-addressed (its recorded fields hash to {}); refusing to consume a hand-edited record",
                &rederived[..16]
            )));
        }
        let request_bytes = match fs::read(dir.join("request.json")) {
            Ok(bytes) => bytes,
            Err(_) => {
                // The request document (which carries the reference artifact
                // bytes) may be DECLARED DETACHED by the publication policy:
                // the graph verifies (the invocation's own fields rederive,
                // the CID is declared in detached-objects.json), the object
                // closure is incomplete-by-policy. An undeclared missing
                // request is a corrupt publication and is refused.
                if self.detached_entry(&inv.request_cid)?.is_some() {
                    return Ok(inv);
                }
                return Err(FrfError::new(format!(
                    "cannot read {}: the request is missing and not declared detached",
                    dir.join("request.json").display()
                )));
            }
        };
        if crate::host::sha256_bytes(&request_bytes) != inv.request_cid {
            return Err(FrfError::new(format!(
                "mutation invocation {id}: the preserved request does not hash to the recorded request_cid"
            )));
        }
        Ok(inv)
    }

    /// Load + verify a mutation RESULT record: its identity rederives, and
    /// the preserved response document hashes to the recorded `response_cid`.
    pub fn load_mutation_result(&self, id: &str) -> Result<crate::model::MutationResult> {
        let dir = self.challenge_mutation_dir(id)?;
        let path = dir.join("result.json");
        let res: crate::model::MutationResult = self.parse_evidence(&path)?;
        let rederived =
            crate::semantics::mutation_result_identity(&crate::semantics::MutationResultContent {
                request_cid: &res.request_cid,
                response_cid: &res.response_cid,
                outcome: &res.outcome,
                mutant_sha256: &res.mutant_sha256,
                expected_affected_surfaces: &res.expected_affected_surfaces,
            })?;
        if rederived != res.result_id {
            return Err(FrfError::new(format!(
                "mutation result {id} is not content-addressed (its recorded fields hash to {}); refusing to consume a hand-edited record",
                &rederived[..16]
            )));
        }
        let response_bytes = fs::read(dir.join("response.json")).map_err(|e| {
            FrfError::new(format!(
                "cannot read {}: {e}",
                dir.join("response.json").display()
            ))
        })?;
        if crate::host::sha256_bytes(&response_bytes) != res.response_cid {
            return Err(FrfError::new(format!(
                "mutation result {id}: the preserved response does not hash to the recorded response_cid"
            )));
        }
        Ok(res)
    }

    /// Load + cross-verify a mutation proposal's invocation AND result
    /// evidence, and the response's binding to its request: the result must
    /// answer the invocation's exact request, the response must
    /// cryptographically name it, and the proposed mutant must rehash to the
    /// recorded content address.
    pub fn load_mutation_evidence(&self, id: &str) -> Result<crate::model::MutationEvidence> {
        let invocation = self.load_mutation_invocation(id)?;
        let result = self.load_mutation_result(id)?;
        if result.request_cid != invocation.request_cid {
            return Err(FrfError::new(format!(
                "mutation evidence {id}: the result answers a different request than the invocation"
            )));
        }
        let dir = self.challenge_mutation_dir(id)?;
        let response: crate::model::MutationResponse =
            self.parse_evidence(&dir.join("response.json"))?;
        if response.request_id != invocation.request_cid {
            return Err(FrfError::new(format!(
                "mutation evidence {id}: the response does not name the request it answers"
            )));
        }
        if let Some(b64) = &response.mutant_base64 {
            let bytes = crate::ext::unb64(b64, "mutation response mutant")?;
            if crate::host::sha256_bytes(&bytes) != result.mutant_sha256 {
                return Err(FrfError::new(format!(
                    "mutation evidence {id}: the proposed mutant does not rehash to the recorded content address"
                )));
            }
        }
        Ok(crate::model::MutationEvidence { invocation, result })
    }

    /// `captures/<run>/normalizer/<id>/<side>/` — the invocation evidence
    /// directory for one normalizer applied to one side (request.json,
    /// response.json, invocation.json, result.json). The id and side are
    /// validated again for defense in depth: they become path components.
    pub fn normalizer_dir(&self, run: &str, id: &str, side: &str) -> Result<PathBuf> {
        validate_id("normalizer", id)?;
        if !matches!(side, "reference" | "candidate") {
            return Err(FrfError::new(format!(
                "invalid side {side:?}: a normalizer applies to reference or candidate"
            )));
        }
        Ok(self.run_dir(run)?.join("normalizer").join(id).join(side))
    }

    /// `captures/<run>/capture-adapter/<axis>/<side>/` — the invocation
    /// evidence directory for one capture adapter applied to one side.
    pub fn adapter_dir(&self, run: &str, axis: &str, side: &str) -> Result<PathBuf> {
        crate::model::ObservableId::parse(axis)?;
        if !matches!(side, "reference" | "candidate") {
            return Err(FrfError::new(format!(
                "invalid side {side:?}: a capture adapter applies to reference or candidate"
            )));
        }
        Ok(self
            .run_dir(run)?
            .join("capture-adapter")
            .join(axis)
            .join(side))
    }

    /// Load + verify a normalizer INVOCATION record: its identity rederives
    /// from its own fields, and the preserved request document hashes to the
    /// recorded `request_cid`. A hand-edited or corrupt record is refused,
    /// never silently consumed.
    pub fn load_normalizer_invocation(
        &self,
        run: &str,
        id: &str,
        side: &str,
    ) -> Result<crate::model::NormalizerInvocation> {
        let dir = self.normalizer_dir(run, id, side)?;
        let path = dir.join("invocation.json");
        if !path.is_file() {
            return Err(FrfError::new(format!(
                "run {run}: no normalizer invocation evidence for normalizer {id} on the {side} side (missing {})",
                path.display()
            )));
        }
        let inv: crate::model::NormalizerInvocation = self.parse_evidence(&path)?;
        if inv.normalizer_id != id || inv.side != side {
            return Err(FrfError::new(format!(
                "run {run}: normalizer invocation under {id}/{side} names normalizer {} on side {} — the name is a claim",
                inv.normalizer_id, inv.side
            )));
        }
        let rederived = crate::semantics::normalizer_invocation_identity(
            &crate::semantics::NormalizerInvocationContent {
                normalizer_id: &inv.normalizer_id,
                side: &inv.side,
                request_cid: &inv.request_cid,
                normalizer_semantic_cid: &inv.normalizer_semantic_cid,
                normalizer_implementation_artifact: &inv.normalizer_implementation_artifact,
                execution_provenance: &inv.execution_provenance,
            },
        )?;
        if rederived != inv.invocation_id {
            return Err(FrfError::new(format!(
                "run {run}: normalizer invocation {id}/{side} is not content-addressed (its recorded fields hash to {}) — refusing to consume a hand-edited invocation",
                &rederived[..16]
            )));
        }
        let request_path = dir.join("request.json");
        let request_bytes = fs::read(&request_path).map_err(|e| {
            FrfError::new(format!(
                "cannot read the preserved normalizer request {}: {e}",
                request_path.display()
            ))
        })?;
        if crate::host::sha256_bytes(&request_bytes) != inv.request_cid {
            return Err(FrfError::new(format!(
                "run {run}: the preserved normalizer request for {id}/{side} does not hash to its recorded request_cid"
            )));
        }
        Ok(inv)
    }

    /// Load + verify a normalizer RESULT record: its identity rederives from
    /// its own fields, and the preserved response document hashes to the
    /// recorded `response_cid`.
    pub fn load_normalizer_result(
        &self,
        run: &str,
        id: &str,
        side: &str,
    ) -> Result<crate::model::NormalizerResult> {
        let dir = self.normalizer_dir(run, id, side)?;
        let path = dir.join("result.json");
        if !path.is_file() {
            return Err(FrfError::new(format!(
                "run {run}: no normalizer result evidence for normalizer {id} on the {side} side (missing {})",
                path.display()
            )));
        }
        let res: crate::model::NormalizerResult = self.parse_evidence(&path)?;
        let rederived = crate::semantics::normalizer_result_identity(
            &crate::semantics::NormalizerResultContent {
                request_cid: &res.request_cid,
                response_cid: &res.response_cid,
                stdout_sha256: &res.stdout_sha256,
                stderr_sha256: &res.stderr_sha256,
            },
        )?;
        if rederived != res.result_id {
            return Err(FrfError::new(format!(
                "run {run}: normalizer result {id}/{side} is not content-addressed (its recorded fields hash to {}) — refusing to consume a hand-edited result",
                &rederived[..16]
            )));
        }
        let response_path = dir.join("response.json");
        let response_bytes = fs::read(&response_path).map_err(|e| {
            FrfError::new(format!(
                "cannot read the preserved normalizer response {}: {e}",
                response_path.display()
            ))
        })?;
        if crate::host::sha256_bytes(&response_bytes) != res.response_cid {
            return Err(FrfError::new(format!(
                "run {run}: the preserved normalizer response for {id}/{side} does not hash to its recorded response_cid"
            )));
        }
        Ok(res)
    }

    /// Load + cross-verify a normalizer's invocation AND result evidence:
    /// the result must answer the invocation's exact request (same
    /// `request_cid`), and the response must cryptographically name that
    /// request (`request_id`).
    pub fn load_normalizer_evidence(
        &self,
        run: &str,
        id: &str,
        side: &str,
    ) -> Result<(
        crate::model::NormalizerInvocation,
        crate::model::NormalizerResult,
    )> {
        let invocation = self.load_normalizer_invocation(run, id, side)?;
        let result = self.load_normalizer_result(run, id, side)?;
        if result.request_cid != invocation.request_cid {
            return Err(FrfError::new(format!(
                "run {run}: normalizer result for {id}/{side} answers a different request than its invocation"
            )));
        }
        let dir = self.normalizer_dir(run, id, side)?;
        let response: crate::model::NormalizerResponse =
            self.parse_evidence(&dir.join("response.json"))?;
        if response.request_id != invocation.request_cid {
            return Err(FrfError::new(format!(
                "run {run}: normalizer response for {id}/{side} does not name the request it answers"
            )));
        }
        Ok((invocation, result))
    }

    /// Load + cross-verify a capture adapter's invocation AND result
    /// evidence for one side.
    pub fn load_adapter_evidence(
        &self,
        run: &str,
        axis: &str,
        side: &str,
    ) -> Result<(
        crate::model::CaptureAdapterInvocation,
        crate::model::CaptureAdapterResult,
    )> {
        let dir = self.adapter_dir(run, axis, side)?;
        let inv_path = dir.join("invocation.json");
        let res_path = dir.join("result.json");
        if !inv_path.is_file() || !res_path.is_file() {
            return Err(FrfError::new(format!(
                "run {run}: no capture-adapter evidence for axis {axis} on the {side} side (missing {} or {})",
                inv_path.display(),
                res_path.display()
            )));
        }
        let inv: crate::model::CaptureAdapterInvocation = self.parse_evidence(&inv_path)?;
        let res: crate::model::CaptureAdapterResult = self.parse_evidence(&res_path)?;
        if inv.axis != axis || inv.side != side {
            return Err(FrfError::new(format!(
                "run {run}: capture-adapter invocation under {axis}/{side} names axis {} on side {} — the name is a claim",
                inv.axis, inv.side
            )));
        }
        let rederived = crate::semantics::capture_adapter_invocation_identity(
            &crate::semantics::CaptureAdapterInvocationContent {
                axis: &inv.axis,
                side: &inv.side,
                request_cid: &inv.request_cid,
                adapter_semantic_cid: &inv.adapter_semantic_cid,
                adapter_implementation_artifact: &inv.adapter_implementation_artifact,
                execution_provenance: &inv.execution_provenance,
            },
        )?;
        if rederived != inv.invocation_id {
            return Err(FrfError::new(format!(
                "run {run}: capture-adapter invocation for {axis}/{side} is not content-addressed (its recorded fields hash to {}) — refusing to consume a hand-edited invocation",
                &rederived[..16]
            )));
        }
        let rederived_result = crate::semantics::capture_adapter_result_identity(
            &crate::semantics::CaptureAdapterResultContent {
                request_cid: &res.request_cid,
                response_cid: &res.response_cid,
                observation_sha256: &res.observation_sha256,
            },
        )?;
        if rederived_result != res.result_id {
            return Err(FrfError::new(format!(
                "run {run}: capture-adapter result for {axis}/{side} is not content-addressed (its recorded fields hash to {}) — refusing to consume a hand-edited result",
                &rederived_result[..16]
            )));
        }
        if res.request_cid != inv.request_cid {
            return Err(FrfError::new(format!(
                "run {run}: capture-adapter result for {axis}/{side} answers a different request than its invocation"
            )));
        }
        let response_path = dir.join("response.json");
        let response: crate::model::CaptureAdapterResponse = self.parse_evidence(&response_path)?;
        if response.request_id != inv.request_cid {
            return Err(FrfError::new(format!(
                "run {run}: capture-adapter response for {axis}/{side} does not name the request it answers"
            )));
        }
        let response_bytes = fs::read(&response_path)
            .map_err(|e| FrfError::new(format!("cannot read {}: {e}", response_path.display())))?;
        if crate::host::sha256_bytes(&response_bytes) != res.response_cid {
            return Err(FrfError::new(format!(
                "run {run}: the preserved capture-adapter response for {axis}/{side} does not hash to its recorded response_cid"
            )));
        }
        Ok((inv, res))
    }

    /// `reductions/<id>/minimizer/` — the invocation evidence directory of
    /// the external minimizer that proposed a reduction (request.json,
    /// response.json, invocation.json, result.json). The reduction RECORD
    /// itself lives at `reductions/<id>.json`.
    pub fn minimizer_dir(&self, reduction_id: &str) -> Result<PathBuf> {
        validate_id("reduction", reduction_id)?;
        Ok(self
            .root
            .join("reductions")
            .join(reduction_id)
            .join("minimizer"))
    }

    /// The DERIVED residual index: `residuals/<id>.json` — a byte-identical
    /// copy of the residual record LEAF (which lives inside its run's
    /// directory, `captures/<run>/residuals/<id>.json`). The record's `run`
    /// field IS the index: given an id, the copy names the run the leaf
    /// lives in. The index is DERIVED (the leaf is the evidence; the copy is
    /// rederivable and self-heals on read) and the whole-store verifier
    /// enforces copy == leaf byte-for-byte — the run directory is the
    /// transactional root published by ONE rename, so the observation
    /// closure (capture + residual leaves) can never appear half-written,
    /// while the top-level residual namespace remains a content-addressed
    /// lookup over every residual.
    pub fn residual_path(&self, id: &str) -> Result<PathBuf> {
        validate_id("residual", id)?;
        Ok(self.root.join("residuals").join(format!("{id}.json")))
    }

    /// The residual LEAF path: `captures/<run>/residuals/<id>.json` — the
    /// canonical evidence, published atomically with its run.
    pub fn residual_leaf_path(&self, run: &str, id: &str) -> Result<PathBuf> {
        validate_id("run", run)?;
        validate_id("residual", id)?;
        Ok(self
            .root
            .join("captures")
            .join(run)
            .join("residuals")
            .join(format!("{id}.json")))
    }

    /// The residual leaf DIRECTORY of a run: `captures/<run>/residuals/`.
    pub fn residual_leaf_dir(&self, run: &str) -> Result<PathBuf> {
        validate_id("run", run)?;
        Ok(self.root.join("captures").join(run).join("residuals"))
    }

    /// The derived κ token path: `residuals/<id>.token.json` — a pure
    /// function of the residual record + its current disposition, so it is
    /// derived (rewritten on disposition change), never evidence.
    pub fn token_path(&self, id: &str) -> Result<PathBuf> {
        validate_id("residual", id)?;
        Ok(self.root.join("residuals").join(format!("{id}.token.json")))
    }

    pub fn receipt_path(&self, id: &str) -> Result<PathBuf> {
        validate_id("receipt", id)?;
        // Receipts are canonical JSON (RFC 8785) — the OpenReceipt protocol
        // representation — so their identity is stable across implementations.
        Ok(self.root.join("receipts").join(format!("{id}.json")))
    }

    /// The content-addressed claim document path: `claims/<id>.json`. The
    /// id is `FRF/CLAIM/v1` over the canonical document minus the id — a
    /// claim is an immutable protocol object, never a per-receipt slot.
    pub fn claim_path(&self, id: &str) -> Result<PathBuf> {
        validate_id("claim", id)?;
        Ok(self.root.join("claims").join(format!("{id}.json")))
    }

    /// The non-normative by-receipt index: `claims/by-receipt/<receipt>/`
    /// lists the claim ids compiled under that receipt (one marker file per
    /// claim). The receipt is a root into the evidence graph; the claims are
    /// the projections compiled over it — a receipt compiled under different
    /// universes or policies yields several claims that coexist forever.
    pub fn claim_index_dir(&self, receipt_id: &str) -> Result<PathBuf> {
        validate_id("receipt", receipt_id)?;
        Ok(self.root.join("claims").join("by-receipt").join(receipt_id))
    }

    /// The marker path of one claim in the by-receipt index.
    pub fn claim_index_path(&self, receipt_id: &str, claim_id: &str) -> Result<PathBuf> {
        Ok(self.claim_index_dir(receipt_id)?.join(claim_id))
    }

    /// The claim ids compiled under one receipt (the by-receipt index,
    /// sorted). The index is non-normative — the claims themselves are the
    /// evidence — but it is the portable way to find every projection of a
    /// receipt.
    pub fn claim_ids_for_receipt(&self, receipt_id: &str) -> Result<Vec<String>> {
        let dir = self.claim_index_dir(receipt_id)?;
        if !dir.is_dir() {
            return Ok(Vec::new());
        }
        let mut ids: Vec<String> = std::fs::read_dir(&dir)
            .map_err(|e| FrfError::new(format!("cannot read the claim index: {e}")))?
            .flatten()
            .filter(|e| e.path().is_file())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        ids.sort();
        Ok(ids)
    }

    /// Load a claim document by its content address: canonical parse (the
    /// document must BE its own canonical serialization), the embedded id
    /// must match the requested id, and the id must rederive from the
    /// document (`FRF/CLAIM/v1` over the canonical bytes minus the id).
    pub fn load_claim(&self, id: &str) -> Result<crate::model::ClaimRecord> {
        let path = self.claim_path(id)?;
        if !path.exists() {
            return Err(FrfError::new(format!(
                "no claim {id} (missing {})",
                path.display()
            )));
        }
        let claim: crate::model::ClaimRecord = self.parse_evidence(&path)?;
        if claim.id != id {
            return Err(FrfError::new(format!(
                "claim {id}: the id inside the document is {} — the name is a claim",
                claim.id
            )));
        }
        let rederived = crate::semantics::claim_identity(&claim)?;
        if rederived != id {
            return Err(FrfError::new(format!(
                "claim {id} is not content-addressed: the canonical document minus the id hashes to {}; refusing to consume a hand-edited or forged claim",
                &rederived[..16]
            )));
        }
        Ok(claim)
    }

    /// Write a compiled claim: content-addressed and IMMUTABLE. The document
    /// is written once at `claims/<id>.json` (an existing object is
    /// re-verified as the identical document — never overwritten), and the
    /// non-normative by-receipt index gains its marker. A claim is NOT a
    /// pure function of the receipt alone (it depends on the committed
    /// universe and the admission policy), so re-compiling is a NEW claim,
    /// never an overwrite.
    pub fn write_claim(&self, claim: &crate::model::ClaimRecord) -> Result<()> {
        let expected = crate::semantics::claim_identity(claim)?;
        if expected != claim.id {
            return Err(FrfError::new(format!(
                "cannot write claim {}: its fields hash to {} — the id is a claim",
                claim.id,
                &expected[..16]
            )));
        }
        let path = self.claim_path(&claim.id)?;
        let json = crate::canon::canonical(claim)?;
        if path.exists() {
            // Content-addressed idempotency: re-verify the existing object IS
            // this document. "exists" is never "assume okay".
            let existing = std::fs::read_to_string(&path)
                .map_err(|e| FrfError::new(format!("cannot read {}: {e}", path.display())))?;
            if existing != json {
                return Err(FrfError::new(format!(
                    "claim {} already exists with different bytes at {}; refusing to overwrite evidence",
                    claim.id,
                    path.display()
                )));
            }
        } else {
            self.write_once(&path, &json)?;
        }
        let index = self.claim_index_path(&claim.receipt, &claim.id)?;
        if !index.exists() {
            std::fs::create_dir_all(index.parent().unwrap()).map_err(|e| {
                FrfError::new(format!("cannot create the claim index directory: {e}"))
            })?;
            std::fs::write(&index, &claim.receipt)
                .map_err(|e| FrfError::new(format!("cannot write the claim index: {e}")))?;
        }
        Ok(())
    }

    /// The EVIDENCE UNIVERSE of the store right now: every residual head
    /// (id + RECORD CONTENT ADDRESS + fingerprint + projected disposition +
    /// the event that supplied it) and every other member of the universe
    /// (receipt, run, authority, series, reduction) as a TYPED CONTENT
    /// REFERENCE (kind/id/cid) — sorted and content-addressed. A claim
    /// compiled now is admissible relative to THIS universe: no unresolved
    /// residual in it intersects the claim's scope, and the compiled claim
    /// carries the snapshot, so the negative search is portable and a later
    /// store mutation cannot silently change what the claim means. The CID
    /// commits the exact bytes the blocker scan depended on — residual
    /// records and authority records by their canonical content hash (their
    /// ids are labels), runs/receipts/series/reductions by their
    /// content-derived addresses.
    pub fn knowledge_snapshot(&self) -> Result<KnowledgeSnapshot> {
        let mut snapshot = KnowledgeSnapshot {
            schema_version: crate::model::SCHEMA_CLAIM.to_string(),
            cid: String::new(),
            residual_heads: Vec::new(),
            objects: Vec::new(),
        };

        // Residual heads: every residual record with its canonical record
        // content address, its fingerprint, and its projected head
        // disposition (the event chain is verified on load). The universe
        // walks the CAPTURES (the evidence — every residual leaf lives in
        // its run), never the top-level residuals/ namespace (which is a
        // DERIVED index: it self-heals on read, so the committed universe
        // must not depend on its completeness).
        let captures_dir = self.root.join("captures");
        if captures_dir.is_dir() {
            let mut names: Vec<String> = std::fs::read_dir(&captures_dir)
                .map_err(|e| FrfError::new(format!("cannot read captures directory: {e}")))?
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| !n.starts_with('.'))
                .collect();
            names.sort();
            for run in names {
                let capture = self.load_capture(&run)?.into_inner();
                for id in &capture.residuals {
                    // Producer path: the snapshot COMMITS the residual's
                    // content address + fingerprint (computed from the
                    // record's own fields); the blocker scan re-verifies
                    // each committed head and refuses on mismatch before
                    // the scope may drive the claim.
                    let record = self.load_residual(id)?.into_inner();
                    let events = self.disposition_events(id)?;
                    let disposition = events
                        .last()
                        .map(|e| e.disposition.clone())
                        .unwrap_or(Disposition::Open);
                    snapshot.residual_heads.push(SnapshotResidualHead {
                        record_cid: crate::semantics::record_content_identity(&record)?,
                        fingerprint: crate::semantics::residual_fingerprint(&record)?,
                        id: id.clone(),
                        disposition: disposition.as_str().to_string(),
                        disposition_event_id: events.last().map(|e| e.event_id.clone()),
                    });
                }
            }
            snapshot.residual_heads.sort_by(|a, b| a.id.cmp(&b.id));
            snapshot.residual_heads.dedup_by(|a, b| a.id == b.id);
        }

        // The other members of the universe, as typed content references.
        // Runs, receipts, series, and reductions are content-addressed by
        // construction (their verified id IS their content address); an
        // authority's id is a LABEL, so its cid is the canonical hash of its
        // record — the exact bytes the blocker scan's lineage computation
        // reads.
        let listing = |sub: &str| -> Result<Vec<String>> {
            let dir = self.root.join(sub);
            let mut out = Vec::new();
            if dir.is_dir() {
                for entry in std::fs::read_dir(&dir)
                    .map_err(|e| FrfError::new(format!("cannot read {sub}: {e}")))?
                {
                    let entry =
                        entry.map_err(|e| FrfError::new(format!("cannot read {sub}: {e}")))?;
                    let name = entry.file_name().to_string_lossy().into_owned();
                    // Dot-prefixed entries are staging/scratch trees (the
                    // court stages a run under captures/.staging-*/ before its
                    // atomic publish), never protocol objects.
                    if name.starts_with('.') {
                        continue;
                    }
                    if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                        out.push(name);
                    } else if name.ends_with(".json") {
                        out.push(name.trim_end_matches(".json").to_string());
                    }
                }
            }
            out.sort();
            Ok(out)
        };
        for receipt in listing("receipts")? {
            // The verified receipt id is `receipt-{run}-{digest}`; the digest
            // IS the content address (verified on read).
            let cid = receipt
                .strip_prefix("receipt-")
                .and_then(|rest| rest.rsplit_once('-'))
                .map(|(_, d)| d.to_string())
                .unwrap_or_default();
            snapshot.objects.push(SnapshotObject {
                kind: "receipt".to_string(),
                id: receipt,
                cid,
            });
        }
        for run in listing("captures")? {
            let verified = crate::verify::load_capture_verified(self, &run)?;
            let residuals: Vec<ResidualRecord> = verified
                .capture
                .residuals
                .iter()
                .map(|rid| {
                    // The run digest consumes the residual projections; each
                    // is re-verified before its projections may be hashed.
                    crate::verify::load_residual_verified(self, rid).map(|v| v.record().clone())
                })
                .collect::<Result<_>>()?;
            let cid = verified.digest(&residuals)?;
            snapshot.objects.push(SnapshotObject {
                kind: "run".to_string(),
                id: run,
                cid,
            });
        }
        for authority in listing("authorities")? {
            let record = self.load_authority(&authority)?;
            let cid = crate::semantics::record_content_identity(&record)?;
            snapshot.objects.push(SnapshotObject {
                kind: "authority".to_string(),
                id: authority,
                cid,
            });
        }
        for series in listing("series")? {
            let cid = series.clone();
            snapshot.objects.push(SnapshotObject {
                kind: "series".to_string(),
                id: series,
                cid,
            });
        }
        for reduction in listing("reductions")? {
            let cid = reduction.clone();
            snapshot.objects.push(SnapshotObject {
                kind: "reduction".to_string(),
                id: reduction,
                cid,
            });
        }
        snapshot.objects.sort_by(|a, b| {
            (a.kind.as_str(), a.id.as_str()).cmp(&(b.kind.as_str(), b.id.as_str()))
        });
        // The universe is a SET of typed content references: a member listed
        // twice (e.g. a reduction named by both its `.json` file and its
        // `minimizer/` evidence directory) is one member. The independent
        // verifiers enforce uniqueness — the compiled snapshot must too.
        snapshot
            .objects
            .dedup_by(|a, b| a.kind == b.kind && a.id == b.id);

        let cid = crate::semantics::knowledge_snapshot_identity(&snapshot)?;
        snapshot.cid = cid;
        Ok(snapshot)
    }

    /// `reductions/<id>.json` — the content-addressed reduction record.
    pub fn reduction_path(&self, id: &str) -> Result<PathBuf> {
        validate_id("reduction", id)?;
        Ok(self.root.join("reductions").join(format!("{id}.json")))
    }

    /// `challenges/<id>.json` — the content-addressed court-challenge record
    /// (the negative-control evidence: the court run against a mutant
    /// candidate).
    pub fn challenge_path(&self, id: &str) -> Result<PathBuf> {
        validate_id("challenge", id)?;
        Ok(self.root.join("challenges").join(format!("{id}.json")))
    }

    /// `witnesses/<id>.json` — the content-addressed witness statement
    /// (canonical JSON, like receipts: the protocol representation).
    pub fn witness_path(&self, id: &str) -> Result<PathBuf> {
        validate_id("witness statement", id)?;
        Ok(self.root.join("witnesses").join(format!("{id}.json")))
    }

    /// `witnesses/<id>/` — the preserved canonical request + response of the
    /// attestation (the statement's own evidence).
    pub fn witness_dir(&self, id: &str) -> Result<PathBuf> {
        validate_id("witness statement", id)?;
        Ok(self.root.join("witnesses").join(id))
    }

    /// `harness/<id>.json` — the content-addressed harness-event evidence
    /// record (the evidentiary overflow: a declared bound the harness
    /// ENFORCED during an observation attempt).
    pub fn harness_path(&self, id: &str) -> Result<PathBuf> {
        validate_id("harness event", id)?;
        Ok(self.root.join("harness").join(format!("{id}.json")))
    }

    /// Write a harness event: content-addressed (`FRF/HARNESS-EVENT/v1` over
    /// the event's own fields), canonical JSON, write-once — an existing
    /// record with the same id must be byte-identical (idempotent: the same
    /// bound can fire in a replay, and the same refusal is the same record).
    pub fn write_harness_event(&self, event: &HarnessEvent) -> Result<()> {
        let expected = crate::semantics::harness_event_identity(
            &event.event_kind,
            &event.side,
            &event.court,
            &event.execution_profile,
            &event.cap,
            &event.observed,
            &event.target,
            &event.detail,
            &event.runner,
        )?;
        if expected != event.id {
            return Err(FrfError::new(format!(
                "harness event id mismatch: the record claims {} but its fields hash to {expected}",
                event.id
            )));
        }
        let path = self.harness_path(&event.id)?;
        if path.exists() {
            self.load_harness_event(&event.id)?;
            return Ok(());
        }
        // A refusal can occur before the store root has been initialized for
        // this run (the refused run leaves no capture); the harness dir must
        // exist regardless — the event is court-scoped refusal evidence.
        let parent = path.parent().ok_or_else(|| {
            FrfError::new(format!(
                "harness event path {} has no parent",
                path.display()
            ))
        })?;
        fs::create_dir_all(parent)
            .map_err(|e| FrfError::new(format!("cannot create {}: {e}", parent.display())))?;
        let json = self.to_evidence(event)?;
        self.write_once(&path, &json)
    }

    /// Load a harness event by its content address — identity rederives, the
    /// document is canonical (strict JSON, duplicates refused, bytes ==
    /// JCS). A hand-edited or corrupt record is refused, never read.
    pub fn load_harness_event(&self, id: &str) -> Result<HarnessEvent> {
        let path = self.harness_path(id)?;
        if !path.exists() {
            return Err(FrfError::new(format!(
                "no harness event {id} (missing {})",
                path.display()
            )));
        }
        let event: HarnessEvent = self.parse_evidence(&path)?;
        let expected = crate::semantics::harness_event_identity(
            &event.event_kind,
            &event.side,
            &event.court,
            &event.execution_profile,
            &event.cap,
            &event.observed,
            &event.target,
            &event.detail,
            &event.runner,
        )?;
        if expected != event.id {
            return Err(FrfError::new(format!(
                "harness event {id}: the content address does not rederive from its own fields"
            )));
        }
        Ok(event)
    }

    /// `attempts/<id>.json` — the content-addressed refused execution-attempt
    /// evidence record (the refusal-root: a failed observation attempt is
    /// itself a first-class portable observation).
    pub fn attempt_path(&self, id: &str) -> Result<PathBuf> {
        validate_id("execution attempt", id)?;
        Ok(self.root.join("attempts").join(format!("{id}.json")))
    }

    /// The `attempts/` directory (for bundle collection / tree scans).
    pub fn attempts_dir(&self) -> PathBuf {
        self.root.join("attempts")
    }

    /// Write a refused execution-attempt record: content-addressed
    /// (`FRF/EXECUTION-ATTEMPT/v1` over the record's own fields), canonical
    /// JSON, write-once — an existing record with the same id must be
    /// byte-identical (idempotent: re-running the same refused observation
    /// reproduces the same refusal record).
    pub fn write_execution_attempt(&self, attempt: &ExecutionAttemptRecord) -> Result<()> {
        let expected = crate::semantics::execution_attempt_identity(attempt)?;
        if expected != attempt.id {
            return Err(FrfError::new(format!(
                "execution attempt id mismatch: the record claims {} but its fields hash to {expected}",
                attempt.id
            )));
        }
        let path = self.attempt_path(&attempt.id)?;
        if path.exists() {
            self.load_execution_attempt(&attempt.id)?;
            return Ok(());
        }
        let parent = path.parent().ok_or_else(|| {
            FrfError::new(format!(
                "execution attempt path {} has no parent",
                path.display()
            ))
        })?;
        fs::create_dir_all(parent)
            .map_err(|e| FrfError::new(format!("cannot create {}: {e}", parent.display())))?;
        let json = self.to_evidence(attempt)?;
        self.write_once(&path, &json)
    }

    /// Load an execution attempt by its content address — identity rederives,
    /// the document is canonical (strict JSON, duplicates refused, bytes ==
    /// JCS). A hand-edited or corrupt record is refused, never read. (The
    /// VERIFIED loader additionally rederives every cited harness event.)
    pub fn load_execution_attempt(&self, id: &str) -> Result<ExecutionAttemptRecord> {
        let path = self.attempt_path(id)?;
        if !path.exists() {
            return Err(FrfError::new(format!(
                "no execution attempt {id} (missing {})",
                path.display()
            )));
        }
        let attempt: ExecutionAttemptRecord = self.parse_evidence(&path)?;
        let expected = crate::semantics::execution_attempt_identity(&attempt)?;
        if expected != attempt.id {
            return Err(FrfError::new(format!(
                "execution attempt {id}: the content address does not rederive from its own fields"
            )));
        }
        Ok(attempt)
    }

    /// Write a witness statement: content-addressed (the id rederives from
    /// the record's own fields), canonical JSON, write-once. The preserved
    /// request/response documents are the caller's to write under
    /// [`Store::witness_dir`]; the loader cross-verifies them.
    pub fn write_witness_statement(&self, stmt: &WitnessStatement) -> Result<()> {
        let expected = crate::semantics::witness_statement_identity(
            &crate::semantics::WitnessStatementContent {
                subject: &stmt.subject,
                witness_semantic: &stmt.witness_semantic,
                witness_implementation: &stmt.witness_implementation,
                witness_identity: &stmt.witness_identity,
                authority: &stmt.authority,
                statement: &stmt.statement,
                attestation: &stmt.attestation,
                request_cid: &stmt.request_cid,
                response_cid: &stmt.response_cid,
            },
        )?;
        if expected != stmt.id {
            return Err(FrfError::new(format!(
                "witness statement id mismatch: record says {} but its fields hash to {expected}",
                stmt.id
            )));
        }
        let path = self.witness_path(&stmt.id)?;
        if path.exists() {
            // Idempotent write, content-addressed discipline: the object
            // already exists — load + verify it IS this object (canonical
            // document, identity rederives from its fields, the preserved
            // request/response bind it) before declaring success. "Exists"
            // is never "assume okay": a corrupt or hand-edited statement at
            // this address is refused.
            self.load_witness_statement(&stmt.id)?;
            return Ok(());
        }
        let json = crate::canon::canonical(stmt)?;
        self.write_once(&path, &json)
    }

    /// Load + verify a witness statement: its identity rederives from its own
    /// fields, the preserved request document hashes to the recorded
    /// `request_cid`, the preserved response document hashes to the recorded
    /// `response_cid`, the response cryptographically names its request, and
    /// the attestation names exactly the statement recorded.
    pub fn load_witness_statement(&self, id: &str) -> Result<WitnessStatement> {
        let path = self.witness_path(id)?;
        if !path.exists() {
            return Err(FrfError::new(format!(
                "no witness statement {id} (missing {})",
                path.display()
            )));
        }
        let stmt: WitnessStatement = self.parse_evidence(&path)?;
        if stmt.id != id {
            return Err(FrfError::new(format!(
                "witness statement {id}: the id inside the record is {} — the name is a claim",
                stmt.id
            )));
        }
        let expected = crate::semantics::witness_statement_identity(
            &crate::semantics::WitnessStatementContent {
                subject: &stmt.subject,
                witness_semantic: &stmt.witness_semantic,
                witness_implementation: &stmt.witness_implementation,
                witness_identity: &stmt.witness_identity,
                authority: &stmt.authority,
                statement: &stmt.statement,
                attestation: &stmt.attestation,
                request_cid: &stmt.request_cid,
                response_cid: &stmt.response_cid,
            },
        )?;
        if expected != id {
            return Err(FrfError::new(format!(
                "witness statement {id} is not content-addressed: its recorded fields hash to {expected}; refusing to consume a hand-edited statement"
            )));
        }
        let dir = self.witness_dir(id)?;
        let request_path = dir.join("request.json");
        let response_path = dir.join("response.json");
        if !request_path.is_file() || !response_path.is_file() {
            return Err(FrfError::new(format!(
                "witness statement {id}: the preserved request/response evidence is missing under {}",
                dir.display()
            )));
        }
        let request_bytes = fs::read(&request_path)
            .map_err(|e| FrfError::new(format!("cannot read {}: {e}", request_path.display())))?;
        if crate::host::sha256_bytes(&request_bytes) != stmt.request_cid {
            return Err(FrfError::new(format!(
                "witness statement {id}: the preserved request does not hash to its recorded request_cid"
            )));
        }
        // The preserved REQUEST's subject block must equal the statement's
        // subject block: the witness answered a request about THIS exact
        // subject (kind + id + content address). A statement whose preserved
        // request names a different subject is internally inconsistent and is
        // refused even before the subject is rebound to the evidence tree.
        let request: serde_json::Value = self.parse_evidence(&request_path)?;
        let request_subject = request.get("subject").ok_or_else(|| {
            FrfError::new(format!(
                "witness statement {id}: the preserved request carries no subject block"
            ))
        })?;
        let stmt_subject = serde_json::to_value(&stmt.subject)
            .map_err(|e| FrfError::new(format!("cannot serialize the subject: {e}")))?;
        if request_subject != &stmt_subject {
            return Err(FrfError::new(format!(
                "witness statement {id}: the preserved request's subject block does not equal the statement's — a statement can only answer the request it records"
            )));
        }
        let response_bytes = fs::read(&response_path)
            .map_err(|e| FrfError::new(format!("cannot read {}: {e}", response_path.display())))?;
        if crate::host::sha256_bytes(&response_bytes) != stmt.response_cid {
            return Err(FrfError::new(format!(
                "witness statement {id}: the preserved response does not hash to its recorded response_cid"
            )));
        }
        let response: WitnessResponse = self.parse_evidence(&response_path)?;
        if response.request_id != stmt.request_cid {
            return Err(FrfError::new(format!(
                "witness statement {id}: the preserved response does not name the request it answers"
            )));
        }
        match &response.attestation {
            Some(att) => {
                if att.statement != stmt.statement {
                    return Err(FrfError::new(format!(
                        "witness statement {id}: the attestation names a different statement than the record"
                    )));
                }
            }
            None => {
                return Err(FrfError::new(format!(
                    "witness statement {id}: the preserved response carries no attestation"
                )))
            }
        }
        Ok(stmt)
    }

    /// The evidence-record path for one independence record
    /// (`independence/<id>.json`). The id is the content address.
    pub fn independence_path(&self, id: &str) -> Result<PathBuf> {
        crate::store::validate_id("independence", id)?;
        Ok(self.root.join("independence").join(format!("{id}.json")))
    }

    /// Write a content-addressed independence record: if the object already
    /// exists, load + verify it IS this object (canonical document, identity
    /// rederives, the bound statement verifies) before declaring success —
    /// "exists" is never "assume okay".
    pub fn write_independence(&self, record: &IndependenceEvidence) -> Result<()> {
        let path = self.independence_path(&record.id)?;
        if path.exists() {
            let existing = self.load_independence(&record.id)?;
            if existing != *record {
                return Err(FrfError::new(format!(
                    "independence record {} already exists with different content; refusing to overwrite evidence",
                    record.id
                )));
            }
            return Ok(());
        }
        let json = crate::canon::canonical(record)?;
        self.write_once(&path, &json)
    }

    /// Load + verify an independence record: the id rederives from the
    /// record's own fields, and the bound witness statement verifies on read
    /// (identity + preserved documents) — an independence claim can only
    /// bind real evidence.
    pub fn load_independence(&self, id: &str) -> Result<IndependenceEvidence> {
        let path = self.independence_path(id)?;
        if !path.exists() {
            return Err(FrfError::new(format!(
                "no independence record {id} (missing {})",
                path.display()
            )));
        }
        let record: IndependenceEvidence = self.parse_evidence(&path)?;
        if record.id != id {
            return Err(FrfError::new(format!(
                "independence {id}: the id inside the record is {} — the name is a claim",
                record.id
            )));
        }
        let expected =
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
        if expected != id {
            return Err(FrfError::new(format!(
                "independence record {id} is not content-addressed: its recorded fields hash to {expected}; refusing to consume a hand-edited record"
            )));
        }
        // The bound statement must verify (identity + preserved documents),
        // and the recorded witness identity + subject must match it.
        let stmt = self.load_witness_statement(&record.witness_statement)?;
        if stmt.witness_identity != record.witness_identity {
            return Err(FrfError::new(format!(
                "independence record {id}: the recorded witness identity does not match the bound statement"
            )));
        }
        if stmt.subject != record.subject {
            return Err(FrfError::new(format!(
                "independence record {id}: the recorded subject does not match the bound statement"
            )));
        }
        Ok(record)
    }

    /// The independence record ids present in the store (sorted).
    pub fn independence_ids(&self) -> Result<Vec<String>> {
        let dir = self.root.join("independence");
        if !dir.is_dir() {
            return Ok(Vec::new());
        }
        let mut ids: Vec<String> = std::fs::read_dir(&dir)
            .map_err(|e| FrfError::new(format!("cannot read independence directory: {e}")))?
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

    /// Load a challenge record by its content address: the id must rederive
    /// from the record's own fields (the name is a claim until recomputed).
    pub fn load_challenge(&self, id: &str) -> Result<CourtChallenge> {
        let path = self.challenge_path(id)?;
        if !path.exists() {
            return Err(FrfError::new(format!(
                "no challenge {id} (missing {})",
                path.display()
            )));
        }
        let record: CourtChallenge = self.parse_evidence(&path)?;
        if record.id != id {
            return Err(FrfError::new(format!(
                "challenge {id}: the id inside the record is {} — the name is a claim",
                record.id
            )));
        }
        let expected = crate::semantics::challenge_identity(
            &record.court,
            &record.operator,
            &record.target_axis,
            &record.reference_sha256,
            &record.mutant_candidate_sha256,
            &record.run,
        )?;
        if expected != id {
            return Err(FrfError::new(format!(
                "challenge {id} is not content-addressed: its recorded fields hash to {expected}; refusing to consume a hand-edited challenge"
            )));
        }
        Ok(record)
    }

    /// Write a challenge record (content-addressed, write-once; re-running
    /// the identical challenge is a no-op).
    pub fn write_challenge(&self, record: &CourtChallenge) -> Result<()> {
        let id = crate::semantics::challenge_identity(
            &record.court,
            &record.operator,
            &record.target_axis,
            &record.reference_sha256,
            &record.mutant_candidate_sha256,
            &record.run,
        )?;
        if id != record.id {
            return Err(FrfError::new(format!(
                "challenge id mismatch: record says {} but its fields hash to {id}",
                record.id
            )));
        }
        let path = self.challenge_path(&id)?;
        if path.exists() {
            // Idempotent write: the object already exists — load + verify it
            // IS this object (canonical document, id rederives from its
            // fields) before declaring success; a corrupt or hand-edited
            // record at this address is refused.
            self.load_challenge(&id)?;
            return Ok(());
        }
        let json = self.to_evidence(record)?;
        self.write_once(&path, &json)
    }

    /// Load a reduction record by its content address.
    pub fn load_reduction(&self, id: &str) -> Result<ReductionRecord> {
        let path = self.reduction_path(id)?;
        if !path.exists() {
            return Err(FrfError::new(format!(
                "no reduction {id} (missing {})",
                path.display()
            )));
        }
        let record: ReductionRecord = self.parse_evidence(&path)?;
        if record.id != id {
            return Err(FrfError::new(format!(
                "reduction {id}: the id inside the record is {} — the name is a claim",
                record.id
            )));
        }
        let expected = crate::semantics::reduction_identity(
            &record.residual_id,
            &record.source_run,
            &record.axis,
            record.kind.clone(),
            &record.court_semantic_identity,
            &record.authority_artifact_sha256,
            &record.candidate_artifact_sha256,
            &record.environment_digest,
            &record.comparator_semantic_id,
            &record.comparator_semantic_hash,
            &record.comparator_implementation_hash,
            &record.argv_template,
            &record.original_fixture_sha256,
            &record.final_fixture_sha256,
            &record.attempts,
            &record.derivation,
            &record.transform,
            crate::store::minimizer_binding(&record).as_ref().map(|b| {
                (
                    b.0.as_str(),
                    b.1.as_str(),
                    b.2.as_str(),
                    b.3,
                    b.4.as_str(),
                    b.5.as_str(),
                )
            }),
        )?;
        if expected != id {
            return Err(FrfError::new(format!(
                "reduction {id} is not content-addressed: its recorded fields hash to {expected}; refusing to consume a hand-edited reduction"
            )));
        }
        Ok(record)
    }

    /// Write a reduction record (content-addressed, write-once).
    pub fn write_reduction(&self, record: &ReductionRecord) -> Result<()> {
        let id = crate::semantics::reduction_identity(
            &record.residual_id,
            &record.source_run,
            &record.axis,
            record.kind.clone(),
            &record.court_semantic_identity,
            &record.authority_artifact_sha256,
            &record.candidate_artifact_sha256,
            &record.environment_digest,
            &record.comparator_semantic_id,
            &record.comparator_semantic_hash,
            &record.comparator_implementation_hash,
            &record.argv_template,
            &record.original_fixture_sha256,
            &record.final_fixture_sha256,
            &record.attempts,
            &record.derivation,
            &record.transform,
            crate::store::minimizer_binding(record).as_ref().map(|b| {
                (
                    b.0.as_str(),
                    b.1.as_str(),
                    b.2.as_str(),
                    b.3,
                    b.4.as_str(),
                    b.5.as_str(),
                )
            }),
        )?;
        if id != record.id {
            return Err(FrfError::new(format!(
                "reduction id mismatch: record says {} but its fields hash to {id}",
                record.id
            )));
        }
        let path = self.reduction_path(&id)?;
        if path.exists() {
            // Idempotent write: the object already exists — load + verify it
            // IS this object (canonical document, id rederives from its
            // fields) before declaring success; a corrupt or hand-edited
            // record at this address is refused.
            self.load_reduction(&id)?;
            return Ok(());
        }
        let json = self.to_evidence(record)?;
        self.write_once(&path, &json)
    }

    /// `trajectories/<lineage>.<coordinate-system>.<series>.json` — the
    /// residual trajectory protocol object, keyed by the residual LINEAGE
    /// (stable across candidate revisions, authority versions, environments,
    /// time), the coordinate system it is ordered over, and the
    /// [`ExecutionSeries`] snapshot it is derived from. Each series snapshot
    /// has its own derived trajectories; the receipt derives its sign from
    /// the series its run belongs to.
    pub fn trajectory_path(
        &self,
        lineage: &str,
        coordinate_system: &str,
        series: &str,
    ) -> Result<PathBuf> {
        validate_id("trajectory", lineage)?;
        validate_id("coordinate system", coordinate_system)?;
        validate_id("series", series)?;
        Ok(self
            .root
            .join("trajectories")
            .join(format!("{lineage}.{coordinate_system}.{series}.json")))
    }

    /// Load a residual trajectory by lineage + coordinate system + series.
    pub fn load_trajectory(
        &self,
        lineage: &str,
        coordinate_system: &str,
        series: &str,
    ) -> Result<TrajectoryRecord> {
        let path = self.trajectory_path(lineage, coordinate_system, series)?;
        if !path.exists() {
            return Err(FrfError::new(format!(
                "no trajectory for lineage {} on {} in series {} (missing {})",
                &lineage[..16],
                coordinate_system,
                &series[..16],
                path.display()
            )));
        }
        self.parse_evidence(&path)
    }

    /// `series/<id>.json` — the content-addressed ExecutionSeries record.
    pub fn series_path(&self, id: &str) -> Result<PathBuf> {
        validate_id("series", id)?;
        Ok(self.root.join("series").join(format!("{id}.json")))
    }

    /// Load an ExecutionSeries by its content address.
    pub fn load_series(&self, id: &str) -> Result<ExecutionSeries> {
        let path = self.series_path(id)?;
        if !path.exists() {
            return Err(FrfError::new(format!(
                "no series {id} (missing {})",
                path.display()
            )));
        }
        let series: ExecutionSeries = self.parse_evidence(&path)?;
        if series.id != id {
            return Err(FrfError::new(format!(
                "series {id}: the id inside the record is {} — the name is a claim; refusing to consume",
                series.id
            )));
        }
        let expected = crate::semantics::series_identity(
            &series.experiment_id,
            series.parent_series_id.as_deref(),
            &series.court,
            &series.coordinate_system,
            &series.points,
        )?;
        if expected != id {
            return Err(FrfError::new(format!(
                "series {id} is not content-addressed: its recorded fields hash to {expected}; refusing to consume a hand-edited series"
            )));
        }
        Ok(series)
    }

    /// Write an ExecutionSeries (content-addressed, write-once).
    pub fn write_series(&self, series: &ExecutionSeries) -> Result<()> {
        let id = crate::semantics::series_identity(
            &series.experiment_id,
            series.parent_series_id.as_deref(),
            &series.court,
            &series.coordinate_system,
            &series.points,
        )?;
        if id != series.id {
            return Err(FrfError::new(format!(
                "series id mismatch: record says {} but its fields hash to {id}",
                series.id
            )));
        }
        let path = self.series_path(&id)?;
        if path.exists() {
            // Idempotent write: the object already exists — load + verify it
            // IS this object (canonical document, id rederives from its
            // fields) before declaring success; a corrupt or hand-edited
            // record at this address is refused.
            self.load_series(&id)?;
            return Ok(());
        }
        let json = self.to_evidence(series)?;
        self.write_once(&path, &json)
    }

    /// The experiments in the store: every distinct (court, coordinate
    /// system) key that has at least one series snapshot.
    pub fn experiment_ids(&self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        let dir = self.root.join("series");
        if !dir.is_dir() {
            return Ok(out);
        }
        for entry in fs::read_dir(&dir)
            .map_err(|e| FrfError::new(format!("cannot read series directory: {e}")))?
        {
            let entry = entry.map_err(|e| FrfError::new(format!("series directory: {e}")))?;
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.ends_with(".json") {
                continue;
            }
            let id = name.trim_end_matches(".json").to_string();
            let series = self.load_series(&id)?;
            if !out.contains(&series.experiment_id) {
                out.push(series.experiment_id.clone());
            }
        }
        out.sort();
        Ok(out)
    }

    /// The HEAD snapshots of one experiment: the series records no other
    /// snapshot points to as their parent (the newest nodes of the
    /// experiment's history). A single unique head is the append target; two
    /// heads mean the experiment BRANCHED, and an implicit append must be
    /// refused (the caller chooses which branch to extend).
    pub fn experiment_heads(&self, experiment_id: &str) -> Result<Vec<ExecutionSeries>> {
        let dir = self.root.join("series");
        if !dir.is_dir() {
            return Ok(vec![]);
        }
        let mut snapshots: Vec<ExecutionSeries> = Vec::new();
        let mut children: std::collections::HashSet<String> = Default::default();
        for entry in fs::read_dir(&dir)
            .map_err(|e| FrfError::new(format!("cannot read series directory: {e}")))?
        {
            let entry = entry.map_err(|e| FrfError::new(format!("series directory: {e}")))?;
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.ends_with(".json") {
                continue;
            }
            let id = name.trim_end_matches(".json").to_string();
            let series = self.load_series(&id)?;
            if series.experiment_id != experiment_id {
                continue;
            }
            if let Some(parent) = &series.parent_series_id {
                children.insert(parent.clone());
            }
            snapshots.push(series);
        }
        snapshots.retain(|s| !children.contains(&s.id));
        snapshots.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(snapshots)
    }

    /// The chain depth of a series snapshot: the number of ancestors it has
    /// (0 for the first snapshot of an experiment). A later snapshot of the
    /// same experiment has a strictly greater depth than its ancestors.
    pub fn series_depth(&self, id: &str) -> Result<u32> {
        let mut depth = 0u32;
        let mut current = self.load_series(id)?;
        let mut seen: std::collections::HashSet<String> = Default::default();
        while let Some(parent) = current.parent_series_id.clone() {
            if !seen.insert(parent.clone()) {
                return Err(FrfError::new(format!(
                    "series chain cycle detected at {parent}; the series history is corrupt"
                )));
            }
            current = self.load_series(&parent)?;
            depth += 1;
        }
        Ok(depth)
    }

    /// True when `descendant` is the same as `ancestor` or reachable from it
    /// through parent links (i.e. `ancestor` is an ancestor of `descendant`).
    pub fn series_is_descendant_of(&self, descendant: &str, ancestor: &str) -> Result<bool> {
        if descendant == ancestor {
            return Ok(true);
        }
        let mut current = self.load_series(descendant)?;
        let mut seen: std::collections::HashSet<String> = Default::default();
        while let Some(parent) = current.parent_series_id.clone() {
            if !seen.insert(parent.clone()) {
                return Err(FrfError::new(format!(
                    "series chain cycle detected at {parent}; the series history is corrupt"
                )));
            }
            if parent == ancestor {
                return Ok(true);
            }
            current = self.load_series(&parent)?;
        }
        Ok(false)
    }

    /// Every series record that references `run` (the runs an experiment
    /// references; the run itself never knows its experiments).
    pub fn series_containing_run(&self, run: &str) -> Result<Vec<ExecutionSeries>> {
        let mut out = Vec::new();
        let dir = self.root.join("series");
        if !dir.is_dir() {
            return Ok(out);
        }
        for entry in fs::read_dir(&dir)
            .map_err(|e| FrfError::new(format!("cannot read series directory: {e}")))?
        {
            let entry = entry.map_err(|e| FrfError::new(format!("series directory: {e}")))?;
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.ends_with(".json") {
                continue;
            }
            let id = name.trim_end_matches(".json").to_string();
            let series = self.load_series(&id)?;
            if series.points.iter().any(|p| p.run == run) {
                out.push(series);
            }
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }

    /// `objects/sha256/<H>` — the content-addressed execution snapshot for a
    /// hash. Deterministic; the path is the identity.
    pub fn object_path(&self, sha256: &str) -> Result<PathBuf> {
        validate_id("object", sha256)?;
        Ok(self.root.join("objects").join("sha256").join(sha256))
    }

    /// Read + verify a content-addressed object by its hash. A missing or
    /// corrupt object is refused — replay never executes unverified bytes.
    /// NOTE: this is the EXECUTION path (comparators, replay, hydration) and
    /// it always requires the bytes; graph verification uses
    /// [`Store::object_availability`], which honors the detached-object
    /// declaration.
    pub fn verified_object_bytes(&self, sha256: &str) -> Result<Vec<u8>> {
        let path = self.object_path(sha256)?;
        if !path.is_file() {
            return Err(FrfError::new(format!(
                "object {} is missing ({}); the evidence tree is incomplete — cannot replay",
                &sha256[..16],
                path.display()
            )));
        }
        let bytes = fs::read(&path)
            .map_err(|e| FrfError::new(format!("cannot read {}: {e}", path.display())))?;
        let actual = crate::host::sha256_bytes(&bytes);
        if actual != sha256 {
            return Err(FrfError::new(format!(
                "object {} is corrupt: its bytes hash to {} but its name is {}; refusing to execute — remove the object and re-run",
                path.display(),
                &actual[..16],
                &sha256[..16]
            )));
        }
        Ok(bytes)
    }

    /// `detached-objects.json` — the publication-level declaration of
    /// deliberately withheld content addresses (schema
    /// `frf-detached-objects-v1`).
    pub fn detached_objects_path(&self) -> PathBuf {
        self.root.join("detached-objects.json")
    }

    /// Load + semantically validate the detached-object declaration, if
    /// present. A malformed declaration is refused — the publication cannot
    /// silently hide a payload.
    pub fn load_detached_objects(&self) -> Result<Option<crate::model::DetachedObjects>> {
        let path = self.detached_objects_path();
        if !path.is_file() {
            return Ok(None);
        }
        let doc: crate::model::DetachedObjects = self.parse_evidence(&path)?;
        doc.validate_semantics()
            .map_err(|e| FrfError::new(format!("detached-objects.json: {e}")))?;
        Ok(Some(doc))
    }

    /// The declaration entry for a CID, if declared detached.
    pub fn detached_entry(&self, cid: &str) -> Result<Option<crate::model::DetachedObjectRef>> {
        Ok(self
            .load_detached_objects()?
            .and_then(|d| d.objects.into_iter().find(|o| o.cid == cid)))
    }

    /// The availability of a content-addressed object for GRAPH
    /// verification: present (bytes verified), declared-detached (bytes
    /// withheld by policy), or missing (neither — an incomplete or corrupt
    /// publication).
    pub fn object_availability(&self, sha256: &str) -> Result<ObjectAvailability> {
        let path = self.object_path(sha256)?;
        if path.is_file() {
            let actual = crate::host::sha256_file(&path)?;
            if actual != sha256 {
                return Err(FrfError::new(format!(
                    "object {} is corrupt: its bytes hash to {} but its name is {}; refusing to consume it",
                    path.display(),
                    &actual[..16],
                    &sha256[..16]
                )));
            }
            return Ok(ObjectAvailability::Present);
        }
        if self.detached_entry(sha256)?.is_some() {
            return Ok(ObjectAvailability::DeclaredDetached);
        }
        Ok(ObjectAvailability::Missing)
    }

    /// Materialize bytes as an immutable content-addressed object and return
    /// its path. Invariants:
    ///
    /// - An existing object is RE-HASHED on every use; a mismatch is
    ///   [`FrfError`] (`CORRUPT_OBJECT`) — corruption is never executed.
    /// - A missing object is written to a unique temp file, fsynced,
    ///   verified byte-for-byte, atomically renamed into place, then sealed
    ///   read-only (`0555` when executed, `0444` otherwise). It is never
    ///   observed partially written and never accepted unverified.
    /// - Re-materializing identical bytes is a no-op (same hash, same
    ///   content); nothing is ever overwritten with different content.
    pub fn materialize_object(&self, bytes: &[u8], executable: bool) -> Result<PathBuf> {
        let sha256 = crate::host::sha256_bytes(bytes);
        let path = self.object_path(&sha256)?;
        if path.is_file() {
            // Content-addressed: the name must BE the content. A corrupt or
            // hand-planted object is refused, never executed.
            let actual = crate::host::sha256_file(&path)?;
            if actual != sha256 {
                return Err(FrfError::new(format!(
                    "object {} is corrupt: its bytes hash to {} but its name is {}; refusing to execute — remove the object and re-run",
                    path.display(),
                    &actual[..16],
                    &sha256[..16]
                )));
            }
            // Re-seal on every use: a checkout (git does not preserve write
            // bits) or a concurrent chmod must not leave an object writable.
            crate::host::set_permissions(&path, if executable { 0o555 } else { 0o444 })?;
            return Ok(path);
        }
        let parent = path.parent().ok_or_else(|| {
            FrfError::new(format!("object path {} has no parent", path.display()))
        })?;
        fs::create_dir_all(parent)
            .map_err(|e| FrfError::new(format!("cannot create {}: {e}", parent.display())))?;

        // Write to a unique temp file in the same directory (same filesystem
        // → atomic rename), fsync, verify, rename, seal.
        let tmp = parent.join(format!(".tmp-{}-{}", std::process::id(), &sha256[..16]));
        {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
                .map_err(|e| FrfError::new(format!("cannot create {}: {e}", tmp.display())))?;
            f.write_all(bytes)
                .and_then(|_| f.sync_all())
                .map_err(|e| FrfError::new(format!("cannot write {}: {e}", tmp.display())))?;
        }
        let written = crate::host::sha256_file(&tmp)?;
        if written != sha256 {
            let _ = fs::remove_file(&tmp);
            return Err(FrfError::new(format!(
                "internal error: temp object {} hashed to {} but {} was expected; refusing to install",
                tmp.display(),
                &written[..16],
                &sha256[..16]
            )));
        }
        // Atomic rename: readers never observe a partial object. If a
        // concurrent writer installed identical bytes first, rename simply
        // replaces them with the identical content.
        fs::rename(&tmp, &path)
            .map_err(|e| FrfError::new(format!("cannot install object {}: {e}", path.display())))?;
        // Seal read-only: executed artifacts r-xr-xr-x, data r--r--r--.
        crate::host::set_permissions(&path, if executable { 0o555 } else { 0o444 })?;
        Ok(path)
    }

    // -- serialization helpers ----------------------------------------------

    /// Serialize a generated evidence record as canonical JSON (RFC 8785) —
    /// the ONE protocol representation for every identity-bearing evidence
    /// object. YAML remains only for HUMAN-AUTHORED court manifests and
    /// configuration; generated evidence is canonical JSON so that any
    /// implementation, in any language, parses the same bytes.
    pub fn to_evidence<T: serde::Serialize>(&self, value: &T) -> Result<String> {
        crate::canon::canonical(value)
    }

    /// Parse a generated evidence document: strict JSON (duplicate property
    /// names refused — RFC 8785 §2), the bytes must BE the canonical
    /// serialization of the parsed document (one semantic document, one byte
    /// sequence — the same rule as receipts and extension responses), and the
    /// typed projection must deserialize from that canonical document.
    pub fn parse_evidence<T: serde::de::DeserializeOwned>(&self, path: &Path) -> Result<T> {
        let bytes = fs::read(path)
            .map_err(|e| FrfError::new(format!("cannot read {}: {e}", path.display())))?;
        crate::canon::require_canonical_bytes(&bytes, &format!("{}", path.display()))?;
        serde_json::from_slice(&bytes)
            .map_err(|e| FrfError::new(format!("cannot parse {}: {e}", path.display())))
    }

    /// Parse a HUMAN-AUTHORED YAML document (a court manifest or user
    /// configuration). YAML is the source format for humans; it is never the
    /// representation of generated evidence.
    pub fn parse_yaml<T: serde::de::DeserializeOwned>(&self, path: &Path) -> Result<T> {
        let text = fs::read_to_string(path)
            .map_err(|e| FrfError::new(format!("cannot read {}: {e}", path.display())))?;
        serde_yaml::from_str(&text)
            .map_err(|e| FrfError::new(format!("cannot parse {}: {e}", path.display())))
    }

    // -- writes ---------------------------------------------------------------

    /// Write a file that must not already exist. Used for authorities, raw
    /// captures, and receipts: re-observation is refused, not overwritten.
    pub fn write_once(&self, path: &Path, contents: &str) -> Result<()> {
        self.write_once_bytes(path, contents.as_bytes())
    }

    /// Binary variant of [`Store::write_once`]. `AlreadyExists` is an error
    /// here — except for content-addressed objects, where the caller treats
    /// it as a no-op because the hash guarantees identical bytes.
    pub fn write_once_bytes(&self, path: &Path, bytes: &[u8]) -> Result<()> {
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(mut f) => f
                .write_all(bytes)
                .and_then(|_| f.flush())
                .map_err(|e| FrfError::new(format!("cannot write {}: {e}", path.display()))),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(FrfError::new(format!(
                "{} already exists; refusing to overwrite evidence",
                path.display()
            ))),
            Err(e) => Err(FrfError::new(format!(
                "cannot create {}: {e}",
                path.display()
            ))),
        }
    }

    /// Commit a CONTENT-ADDRESSED evidence document idempotently: write it if
    /// absent; if the file already holds the IDENTICAL bytes, the content is
    /// already committed and the write is a no-op; different bytes at the
    /// same content address are a refusal (a content address can only ever
    /// hold its own content). This is the court's residual/token commit path:
    /// ids are content addresses (`FRF/RESIDUAL/v1`), so two concurrent
    /// courts observing the same divergence cannot race a sequence counter —
    /// and a crashed run's leftover leaf file is either absent or
    /// byte-identical, never half-committed.
    pub fn commit_content_addressed(&self, path: &Path, contents: &str) -> Result<()> {
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(mut f) => f
                .write_all(contents.as_bytes())
                .and_then(|_| f.flush())
                .map_err(|e| FrfError::new(format!("cannot write {}: {e}", path.display()))),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = fs::read(path).map_err(|re| {
                    FrfError::new(format!(
                        "cannot re-read the existing {}: {re}",
                        path.display()
                    ))
                })?;
                if existing == contents.as_bytes() {
                    Ok(())
                } else {
                    Err(FrfError::new(format!(
                        "{} already exists with DIFFERENT bytes; refusing to overwrite a content address",
                        path.display()
                    )))
                }
            }
            Err(e) => Err(FrfError::new(format!(
                "cannot create {}: {e}",
                path.display()
            ))),
        }
    }

    /// Write a derived artifact. Since claims became content-addressed
    /// immutable objects (`frf-claim-v8`), the only remaining derived
    /// artifact here is the κ TOKEN: a pure function of immutable inputs
    /// (the residual record + the disposition projection of its immutable
    /// event chain), so overwriting with identical output is safe. Claims
    /// are written through [`Store::write_claim`] — write-once, never
    /// overwritten, because a claim depends on the committed universe and
    /// the admission policy, not on the receipt alone.
    pub fn write_derived(&self, path: &Path, contents: &str) -> Result<()> {
        fs::write(path, contents)
            .map_err(|e| FrfError::new(format!("cannot write {}: {e}", path.display())))
    }

    /// Write the derived κ token for a residual under its current disposition.
    pub fn write_token(&self, record: &ResidualRecord, disposition: &Disposition) -> Result<()> {
        let token = crate::kappa::kappa(record, disposition);
        let json = self.to_evidence(&token)?;
        self.write_derived(&self.token_path(&record.id)?, &json)
    }

    // -- disposition events (append-only) ------------------------------------

    /// `residuals/<id>.events/` — one immutable file per disposition event.
    pub fn events_dir(&self, id: &str) -> Result<PathBuf> {
        validate_id("residual", id)?;
        Ok(self.root.join("residuals").join(format!("{id}.events")))
    }

    /// All disposition events for a residual, in sequence order. Immutable;
    /// the current disposition is the projection of the last one. Events are
    /// hash-chained: every event's identity rederives from its own content
    /// and its `parent_event_id` links to the previous event — a broken link
    /// or a hand-edited event is refused here, never silently consumed.
    pub fn disposition_events(&self, id: &str) -> Result<Vec<DispositionEvent>> {
        let dir = self.events_dir(id)?;
        let mut events: Vec<(u32, DispositionEvent)> = Vec::new();
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let name = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                let Ok(seq) = name.parse::<u32>() else {
                    continue;
                };
                events.push((seq, self.parse_evidence(&path)?));
            }
        }
        events.sort_by_key(|(seq, _)| *seq);
        let events: Vec<DispositionEvent> = events.into_iter().map(|(_, e)| e).collect();
        // Verify the hash chain: each event must rederive its own identity
        // from its recorded content, and link to the previous event. The
        // first event has no parent.
        let mut prev: Option<&str> = None;
        for e in &events {
            let rederived = crate::semantics::disposition_event_identity(
                &crate::semantics::DispositionEventContent {
                    residual_id: &e.residual_id,
                    parent_event_id: e.parent_event_id.as_deref(),
                    disposition: &e.disposition,
                    evidence_refs: &e.evidence_refs,
                },
            )?;
            if rederived != e.event_id {
                return Err(FrfError::new(format!(
                    "disposition event {} of {id} is not content-addressed: its recorded fields hash to {} but its event_id claims {}; refusing to consume a hand-edited event",
                    &e.event_id[..16.min(e.event_id.len())],
                    &rederived[..16],
                    &e.event_id[..16.min(e.event_id.len())]
                )));
            }
            if e.parent_event_id.as_deref() != prev {
                return Err(FrfError::new(format!(
                    "disposition event chain of {id} is broken: event {} does not link to its parent",
                    &e.event_id[..16]
                )));
            }
            prev = Some(&e.event_id);
        }
        Ok(events)
    }

    /// The projected current disposition: the last event, or `Open` when the
    /// residual has no events yet. Only a verified chain may project state.
    pub fn current_disposition(&self, id: &str) -> Result<Disposition> {
        Ok(self
            .disposition_events(id)?
            .pop()
            .map(|e| e.disposition)
            .unwrap_or(Disposition::Open))
    }

    /// Append one immutable disposition event, content-addressing it into the
    /// residual's hash chain: the parent link is the previous event's
    /// `event_id` (or `None` for the first), and the new `event_id` is the
    /// SHA-256 of the event's own content. Returns the complete event (with
    /// its identity), which the caller may print or bind into receipts.
    ///
    /// The append is a COMPARE-AND-SWAP against the caller's `expected_parent`
    /// (the last event id it observed when reading the chain, or `None` for an
    /// empty chain): if another writer appended first, the chain's real last
    /// event differs and the append is REFUSED as a conflict (`is_append_conflict`)
    /// — the caller re-reads the chain and retries. The hash chain is the
    /// compare: a stale writer can never splice a fork into the history, and
    /// `write_once` on the dense slot file remains the second fence (identical
    /// bytes are a no-op; different bytes refuse).
    pub fn append_disposition_event(
        &self,
        partial: &DispositionEvent,
        expected_parent: Option<&str>,
    ) -> Result<DispositionEvent> {
        let events = self.disposition_events(&partial.residual_id)?;
        let parent_event_id = events.last().map(|e| e.event_id.clone());
        if parent_event_id.as_deref() != expected_parent {
            return Err(FrfError::new(format!(
                "disposition append conflict on residual {}: the chain's last event is {} but the caller expected {} — another writer appended first; re-read the chain and retry",
                partial.residual_id,
                parent_event_id
                    .as_deref()
                    .map(|id| &id[..16.min(id.len())])
                    .unwrap_or("<none>"),
                expected_parent
                    .map(|id| &id[..16.min(id.len())])
                    .unwrap_or("<none>"),
            )));
        }
        // The only evidence a v0.1.15 disposition could reference was the
        // resolution run that closed it; the v3 vocabulary adds the
        // observation run (nonreproduced) and the trajectory document
        // (stabilized) as first-class evidence edges.
        let evidence_refs = match &partial.disposition {
            Disposition::Fixed {
                resolution_run_id, ..
            } => vec![resolution_run_id.clone()],
            Disposition::Nonreproduced {
                observation_run_id, ..
            } => vec![observation_run_id.clone()],
            Disposition::Stabilized { trajectory_id, .. } => vec![trajectory_id.clone()],
            _ => vec![],
        };
        let event_id = crate::semantics::disposition_event_identity(
            &crate::semantics::DispositionEventContent {
                residual_id: &partial.residual_id,
                parent_event_id: parent_event_id.as_deref(),
                disposition: &partial.disposition,
                evidence_refs: &evidence_refs,
            },
        )?;
        let event = DispositionEvent {
            schema_version: partial.schema_version.clone(),
            event_id,
            residual_id: partial.residual_id.clone(),
            parent_event_id,
            disposition: partial.disposition.clone(),
            evidence_refs,
        };
        let seq = events.len() + 1;
        let dir = self.events_dir(&event.residual_id)?;
        fs::create_dir_all(&dir)
            .map_err(|e| FrfError::new(format!("cannot create {}: {e}", dir.display())))?;
        let path = dir.join(format!("{seq:04}.json"));
        let json = self.to_evidence(&event)?;
        self.write_once(&path, &json)?;
        Ok(event)
    }

    /// The multi-writer-safe append for CLI/operator use: a bounded
    /// compare-and-swap loop around [`Store::append_disposition_event`]. The
    /// caller builds the event once (its content never depends on the chain —
    /// the parent link is filled by the append), then each attempt re-reads
    /// the chain, passes the last event as the expected parent, and retries a
    /// CONFLICT (a concurrent writer appended first) up to the bound. The
    /// events are hash-chained, so the parent link IS the compare: a stale
    /// writer can never splice a fork into the history.
    pub fn append_disposition_event_cas(
        &self,
        residual_id: &str,
        partial: &DispositionEvent,
    ) -> Result<DispositionEvent> {
        for attempt in 0..DISPOSITION_APPEND_MAX_RETRIES {
            let events = self.disposition_events(residual_id)?;
            let expected = events.last().map(|e| e.event_id.clone());
            match self.append_disposition_event(partial, expected.as_deref()) {
                Ok(event) => return Ok(event),
                Err(e)
                    if e.is_append_conflict() && attempt + 1 < DISPOSITION_APPEND_MAX_RETRIES =>
                {
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        Err(FrfError::new(format!(
            "disposition append on residual {residual_id} kept conflicting after {DISPOSITION_APPEND_MAX_RETRIES} attempts — concurrent writers are appending to the same residual; re-run the dispose"
        )))
    }

    // -- reads ---------------------------------------------------------------

    pub fn load_authority(&self, id: &str) -> Result<AuthorityRecord> {
        let path = self.authority_path(id)?;
        if !path.exists() {
            return Err(FrfError::new(format!(
                "authority '{id}' is not admitted (missing {})",
                path.display()
            )));
        }
        self.parse_evidence(&path)
    }

    /// Raw-parse a residual record: canonical document, NO identity/derivation
    /// proof (the record's id is content-addressed, but the rederivation is
    /// the verified loader's job). The returned [`Unverified`] marker must be
    /// resolved through `verify::load_residual_verified` before the record may
    /// drive a semantic decision; [`Unverified::into_inner`] is reserved for
    /// producers.
    ///
    /// The LEAF (inside the run, `captures/<run>/residuals/<id>.json`) is the
    /// authoritative evidence; the top-level `residuals/<id>.json` is a
    /// DERIVED INDEX copy naming its run. A missing index copy self-heals
    /// (the index is derived from the evidence, never the other way around).
    pub fn load_residual(&self, id: &str) -> Result<Unverified<ResidualRecord>> {
        let run = self.residual_run(id)?;
        let leaf = self.residual_leaf_path(&run, id)?;
        if !leaf.is_file() {
            return Err(FrfError::new(format!(
                "residual '{id}' has no leaf at {} (the derived index names run {run} but the leaf is missing — the evidence tree is incomplete)",
                leaf.display()
            )));
        }
        let record: ResidualRecord = self.parse_evidence(&leaf)?;
        if record.id != id {
            return Err(FrfError::new(format!(
                "residual leaf {} carries id {} — the name is a claim; refusing to consume",
                leaf.display(),
                record.id
            )));
        }
        if record.run != run {
            return Err(FrfError::new(format!(
                "residual leaf {} names run {} but sits in run {run} — a residual leaf cannot move",
                leaf.display(),
                record.run
            )));
        }
        Ok(Unverified::new(record))
    }

    /// Resolve the run a residual's leaf lives in, through the DERIVED
    /// INDEX: the top-level `residuals/<id>.json` copy names the run. When
    /// the copy is missing the index self-heals by scanning the verified
    /// runs (the copy is derived from the leaf + the capture's residual
    /// list, deterministically).
    fn residual_run(&self, id: &str) -> Result<String> {
        let index = self.residual_path(id)?;
        if index.is_file() {
            let record: ResidualRecord = self.parse_evidence(&index)?;
            if record.id != id {
                return Err(FrfError::new(format!(
                    "the derived residual index {} carries id {} — a derived index entry must sit at the id it names",
                    index.display(),
                    record.id
                )));
            }
            return Ok(record.run.clone());
        }
        let captures_dir = self.root.join("captures");
        if captures_dir.is_dir() {
            for entry in fs::read_dir(&captures_dir)
                .map_err(|e| FrfError::new(format!("cannot read captures: {e}")))?
            {
                let entry = entry.map_err(|e| FrfError::new(format!("captures: {e}")))?;
                if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    continue;
                }
                let run = entry.file_name().to_string_lossy().into_owned();
                if run.starts_with('.') {
                    continue; // a staging tree, not a run
                }
                let leaf = self.residual_leaf_path(&run, id)?;
                if !leaf.is_file() {
                    continue;
                }
                // The capture must reference the residual (a stray leaf is
                // not an index candidate). The capture is evidence, so the
                // canonical loader parses it; a run whose capture refuses to
                // parse is not an index candidate for THIS lookup (its
                // corruption is a whole-store violation the verifier catches
                // separately).
                let cap_path = self.run_dir(&run)?.join("capture.json");
                let Ok(cap) = self.parse_evidence::<crate::model::CaptureManifest>(&cap_path)
                else {
                    continue;
                };
                if !cap.residuals.iter().any(|r| r == id) {
                    continue;
                }
                // Derive the index copy (idempotent; deterministic).
                if let Ok(bytes) = fs::read(&leaf) {
                    self.write_index_copy(id, &bytes)?;
                }
                return Ok(run);
            }
        }
        Err(FrfError::new(format!(
            "no such residual '{id}' (missing {})",
            index.display()
        )))
    }

    /// Write the DERIVED residual index copy for a record: a byte-identical
    /// copy of the leaf, sitting at `residuals/<id>.json`, whose `run` field
    /// names the leaf's run. Derived (rewriteable) — the leaf is the
    /// evidence; this is the content-addressed lookup.
    pub fn write_residual_index(&self, record: &ResidualRecord) -> Result<()> {
        let json = self.to_evidence(record)?;
        self.write_index_copy(&record.id, json.as_bytes())
    }

    /// Write one derived index copy, creating the namespace if needed (the
    /// index is derived; its directory is not part of the evidence tree's
    /// creation contract).
    fn write_index_copy(&self, id: &str, bytes: &[u8]) -> Result<()> {
        let index = self.residual_path(id)?;
        if let Some(parent) = index.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| FrfError::new(format!("cannot create {}: {e}", parent.display())))?;
        }
        self.write_derived(&index, &String::from_utf8_lossy(bytes))
    }

    /// The index-consistency check: the top-level copy must be byte-identical
    /// to the leaf (the index is DERIVED — a divergent copy is tampering, not
    /// evidence). A MISSING copy is not an error here (the read path
    /// self-heals the derived index); a present-but-divergent copy is a graph
    /// violation.
    pub fn verify_residual_index(&self, id: &str) -> Result<()> {
        let index = self.residual_path(id)?;
        if !index.is_file() {
            return Ok(());
        }
        let record: ResidualRecord = self.parse_evidence(&index)?;
        if record.id != id {
            return Err(FrfError::new(format!(
                "the derived residual index {} carries id {} — a derived index entry must sit at the id it names",
                index.display(),
                record.id
            )));
        }
        let leaf = self.residual_leaf_path(&record.run, id)?;
        if !leaf.is_file() {
            return Err(FrfError::new(format!(
                "the derived residual index {} names run {} but the leaf is missing — the evidence tree is incomplete",
                index.display(),
                &record.run[..16.min(record.run.len())]
            )));
        }
        let index_bytes = fs::read(&index)
            .map_err(|e| FrfError::new(format!("cannot read {}: {e}", index.display())))?;
        let leaf_bytes = fs::read(&leaf)
            .map_err(|e| FrfError::new(format!("cannot read {}: {e}", leaf.display())))?;
        if index_bytes != leaf_bytes {
            return Err(FrfError::new(format!(
                "the derived residual index {} diverges from its leaf {} — the index is derived from the evidence; a divergent copy is tampering",
                index.display(),
                leaf.display()
            )));
        }
        Ok(())
    }

    /// Raw-parse a capture document: canonical, NO identity/derivation proof
    /// (the run id, the recorded identities, the side files, and the residual
    /// bindings are all claims until recomputed). Resolve through
    /// `verify::load_capture_verified` before semantic consumption;
    /// [`Unverified::into_inner`] is reserved for producers.
    pub fn load_capture(&self, run: &str) -> Result<Unverified<CaptureManifest>> {
        let path = self.run_dir(run)?.join("capture.json");
        if !path.exists() {
            return Err(FrfError::new(format!(
                "no such run '{run}' (missing {})",
                path.display()
            )));
        }
        Ok(Unverified::new(self.parse_evidence(&path)?))
    }

    /// Raw-parse a receipt document: canonical, NO identity/derivation proof.
    /// Resolve through `verify::load_receipt_verified` before semantic
    /// consumption; [`Unverified::into_inner`] is reserved for producers.
    pub fn load_receipt(&self, id: &str) -> Result<Unverified<Receipt>> {
        let path = self.receipt_path(id)?;
        if !path.exists() {
            return Err(FrfError::new(format!(
                "no such receipt '{id}' (missing {})",
                path.display()
            )));
        }
        Ok(Unverified::new(self.parse_evidence(&path)?))
    }

    /// The resolution-comparability predicate behind a `fixed` disposition.
    ///
    /// A resolution of residual R must rerun the SAME evidentiary question
    /// under a compatible envelope. The predicate is the court's semantic
    /// identity — the canonical hash of everything defining the question
    /// (question, falsifier, authority artifact, fixture bytes + arguments,
    /// full envelope, comparator SEMANTIC identities), computed at court
    /// time — plus the environment digest. The candidate is deliberately NOT
    /// compared: it is the one entity a fix court may change, and both runs
    /// record their artifact hashes so the evolution is explicit.
    ///
    /// Implementation provenance (which frf executable, which comparator
    /// implementations) is deliberately NOT required to match here: two
    /// independent implementations that ask the same question are
    /// comparable. A stricter reproducibility policy may additionally
    /// require equal provenance; the captures already record it.
    ///
    /// The axis closure is verified per comparator: a BUILT-IN axis rederives
    /// the projection equality from the resolution run's captures; an
    /// EXTERNAL axis requires the resolution run's own recorded comparator
    /// RESULT for that axis to be `equivalent` (verification must not
    /// require execution — the resolution court already executed the
    /// comparator and recorded the evidence).
    ///
    /// Every failure names the specific dimension that drifted (via
    /// [`crate::semantics::semantic_diff`]) so the refusal is actionable.
    pub fn resolution_compatibility(
        &self,
        original_run: &str,
        resolution_run: &str,
        axis: &ObservableId,
    ) -> Result<()> {
        if resolution_run == original_run {
            return Err(FrfError::new(format!(
                "resolution run must be a new court run, not '{original_run}' — the run that observed the residual"
            )));
        }
        // 0.1.59: comparability is a SEMANTIC decision — both captures are
        // verified (identity + derivation) before a single field may decide
        // whether the resolution closes the question. A forged or corrupted
        // capture must not be able to grant a `fixed` disposition.
        let original = crate::verify::load_capture_verified(self, original_run)?.capture;
        let resolution = crate::verify::load_capture_verified(self, resolution_run)?.capture;

        // Same evidentiary question: identical semantic identity. Everything
        // that defines the question is in the hash; only the candidate may
        // differ (it is excluded by construction).
        if original.court_semantic_identity != resolution.court_semantic_identity {
            let what = crate::semantics::semantic_diff(&original, &resolution)
                .unwrap_or_else(|| "semantic court identity".to_string());
            return Err(FrfError::new(format!(
                "resolution run '{resolution_run}' is not comparable to '{original_run}': {what}"
            )));
        }
        // Same environment envelope: a resolution that silently crossed an
        // environment boundary is not a resolution of the same question.
        if original.environment.digest != resolution.environment.digest {
            return Err(FrfError::new(format!(
                "resolution run '{resolution_run}' is not comparable to '{original_run}': environment digest differs ({} != {})",
                &original.environment.digest[..8],
                &resolution.environment.digest[..8]
            )));
        }

        // The axis being resolved must be declared by the resolution run.
        let declared = resolution
            .court_spec
            .admissibility_envelope
            .observables
            .iter()
            .any(|o| o == axis.as_str());
        if !declared {
            return Err(FrfError::new(format!(
                "resolution run '{resolution_run}' does not declare the {} axis",
                axis.as_str()
            )));
        }

        // Was the axis served by an external comparator? Its recorded result
        // must say `equivalent` (the exact instrument that observed the
        // resolution run is part of that run's verified evidence — the
        // recorded result IS the evaluate() verdict of that run; verification
        // must not require execution).
        let external = resolution
            .provenance
            .comparator_implementations
            .iter()
            .find(|i| i.id == axis.as_str())
            .and_then(|i| i.artifact.as_ref());
        let closes = if let Some(_artifact) = external {
            let result = self.load_comparator_result(resolution_run, axis.as_str())?;
            if result.outcome != "equivalent" {
                return Err(FrfError::new(format!(
                    "resolution run '{resolution_run}' does not close the residual: its comparator for the {} axis recorded outcome {:?}, not equivalent",
                    axis.as_str(),
                    result.outcome
                )));
            }
            true
        } else {
            // A built-in axis is evaluated IN-PROCESS through the ONE
            // evaluation operation — the same implementation that observed
            // the resolution run, applied to its verified captures. The sides
            // are hydrated exactly what the plan declares (the domain
            // comparators parse the raw stdout bytes, which the serialized
            // SideCapture carries only as a hash); a requirement the run
            // cannot satisfy is a refusal, never a silent empty value.
            let plan = crate::comparators::EvaluationPlan::from_capture(&resolution, axis)?;
            let reference = self.side_capture_for_plan(resolution_run, &resolution, &plan, true)?;
            let candidate =
                self.side_capture_for_plan(resolution_run, &resolution, &plan, false)?;
            let context = crate::comparators::EvaluationContext {
                fixture_sha256: &resolution.fixture_sha256,
                arguments: &resolution.arguments,
                environment_digest: &resolution.environment.digest,
                produced: reference.produced.as_ref().zip(candidate.produced.as_ref()),
                cwd: std::path::Path::new("."),
                raw: None,
                compared: None,
                profile: crate::host::ExecProfile::parse(&resolution.execution_profile)?,
                env: &resolution.environment.environment,
            };
            let evaluation =
                crate::comparators::evaluate(self, &plan, &reference, &candidate, &context)?;
            matches!(
                evaluation.result,
                crate::comparators::EvaluationResult::Pass
            )
        };
        if !closes {
            return Err(FrfError::new(format!(
                "resolution run '{resolution_run}' does not close the residual: the {} axis still diverges in its captures (a fixed disposition must be backed by a run where the residual no longer reproduces)",
                axis.as_str()
            )));
        }
        Ok(())
    }

    /// Rebuild a side capture with its raw stdout bytes filled from the run's
    /// captured `{side}.stdout` file (the serialized capture carries only the
    /// hash; the domain comparators parse the bytes). The bytes are verified
    /// against the recorded hash — a drifted side file is refused.
    /// Hydrate a side capture with EXACTLY what the plan's evaluation
    /// declares (see [`crate::comparators::CaptureRequirement`] and
    /// [`crate::comparators::EvaluationPlan::capture_requirements`]): the
    /// serialized projections (exit, first lines, produced-tree manifests)
    /// are verified on capture load and need nothing more; the RAW STREAM
    /// BYTES live as capture files and are rehashed here against the recorded
    /// hashes — a drifted side file is refused, and a requirement the run
    /// cannot satisfy is a refusal, never a silent empty value.
    pub fn side_capture_for_plan(
        &self,
        run: &str,
        capture: &CaptureManifest,
        plan: &crate::comparators::EvaluationPlan,
        reference: bool,
    ) -> Result<SideCapture> {
        let mut side = if reference {
            capture.reference.clone()
        } else {
            capture.candidate.clone()
        };
        let dir = self.run_dir(run)?;
        let name = if reference { "reference" } else { "candidate" };
        for requirement in plan.capture_requirements() {
            let Some(stream) = requirement.stream_file() else {
                // Serialized projection (exit / first lines / produced tree):
                // verified on capture load; nothing to hydrate.
                continue;
            };
            let recorded = if stream == "stdout" {
                &side.stdout_sha256
            } else {
                &side.stderr_sha256
            };
            let bytes = fs::read(dir.join(format!("{name}.{stream}"))).map_err(|e| {
                FrfError::new(format!(
                    "cannot read {name}.{stream} of run {run} (the {} axis requires it): {e}",
                    plan.axis.as_str()
                ))
            })?;
            let actual = crate::host::sha256_bytes(&bytes);
            if &actual != recorded {
                return Err(FrfError::new(format!(
                    "{name}.{stream} of run {run} does not hash to the recorded value; refusing to evaluate a drifted capture"
                )));
            }
            if stream == "stdout" {
                side.stdout_bytes = bytes;
            } else {
                side.stderr_bytes = bytes;
            }
        }
        Ok(side)
    }

    // -- fixed vs non-reproduction: the candidate-identity gates -------------

    /// The FIXED candidate-change gate: a `fixed` disposition is a change in
    /// the thing being compared, so the resolution run MUST have executed a
    /// DIFFERENT candidate artifact than the run that observed the residual.
    /// A later pass on the same candidate is a non-reproduction, never a
    /// fix — the honest labels are `nonreproduced` / `stabilized`.
    pub fn require_fix_candidate_change(
        &self,
        original_run: &str,
        resolution_run: &str,
    ) -> Result<()> {
        let original = crate::verify::load_capture_verified(self, original_run)?.capture;
        let resolution = crate::verify::load_capture_verified(self, resolution_run)?.capture;
        if original.candidate_artifact.sha256 == resolution.candidate_artifact.sha256 {
            return Err(FrfError::new(format!(
                "resolution run '{resolution_run}' executed the SAME candidate artifact ({}) as '{original_run}' — a later pass on the same candidate is a non-reproduction, not a fix; record --disposition nonreproduced (or stabilized, with a verified trajectory) instead",
                &original.candidate_artifact.sha256[..16]
            )));
        }
        Ok(())
    }

    /// The NONREPRODUCED same-candidate gate: a `nonreproduced` disposition
    /// is an observation that the residual did not reproduce while the
    /// candidate stayed IDENTICAL. A candidate change is a fix, not a
    /// non-reproduction.
    pub fn require_same_candidate(&self, original_run: &str, observation_run: &str) -> Result<()> {
        let original = crate::verify::load_capture_verified(self, original_run)?.capture;
        let observation = crate::verify::load_capture_verified(self, observation_run)?.capture;
        if original.candidate_artifact.sha256 != observation.candidate_artifact.sha256 {
            return Err(FrfError::new(format!(
                "observation run '{observation_run}' executed a DIFFERENT candidate artifact ({} vs {}) than '{original_run}' — a candidate change is a fix, not a non-reproduction; record --disposition fixed (or stabilized) instead",
                &observation.candidate_artifact.sha256[..16],
                &original.candidate_artifact.sha256[..16]
            )));
        }
        Ok(())
    }

    /// The STABILIZED trajectory gate: RE-DERIVES the trajectory for this
    /// residual's lineage from its verified series and requires
    ///
    /// - the stored trajectory document at `trajectory_id` re-derives
    ///   byte-for-byte from the series (trajectories are derived projections
    ///   of immutable runs — re-derivation IS the verification);
    /// - its subject is this residual's LINEAGE and its axis is the
    ///   residual's axis;
    /// - the LAST `consecutive_passes` observations (in point order) are all
    ///   non-observations;
    /// - `consecutive_passes >= STABILIZATION_MIN_CONSECUTIVE_PASSES` (the
    ///   protocol floor: a single pass is `nonreproduced`, not `stabilized`);
    /// - every passing point ran the SAME candidate artifact as the
    ///   residual's original run (a changed candidate is a fix, not a
    ///   stabilization).
    pub fn require_stabilization_trajectory(
        &self,
        record: &ResidualRecord,
        trajectory_id: &str,
        consecutive_passes: &str,
    ) -> Result<()> {
        let passes: u32 = consecutive_passes.parse().map_err(|_| {
            FrfError::new(format!(
                "consecutive_passes must be a decimal u32 string, not {consecutive_passes:?}"
            ))
        })?;
        if passes < STABILIZATION_MIN_CONSECUTIVE_PASSES {
            return Err(FrfError::new(format!(
                "consecutive_passes {passes} is below the protocol floor of {STABILIZATION_MIN_CONSECUTIVE_PASSES} — a single pass is 'nonreproduced', not 'stabilized'"
            )));
        }
        // The trajectory id is the document key `{lineage}.{coordinate-system}.{series}`.
        let mut parts = trajectory_id.splitn(3, '.');
        let (lineage, coordinate_system, series) = (
            parts.next().unwrap_or(""),
            parts.next().unwrap_or(""),
            parts.next().unwrap_or(""),
        );
        if lineage.is_empty() || coordinate_system.is_empty() || series.is_empty() {
            return Err(FrfError::new(format!(
                "trajectory_id must be the trajectory document key {{lineage}}.{{coordinate-system}}.{{series}}, not {trajectory_id:?}"
            )));
        }
        let expected_lineage = crate::semantics::residual_lineage_of_record(self, record)?;
        if lineage != expected_lineage {
            return Err(FrfError::new(format!(
                "trajectory {trajectory_id} is not about this residual's lineage ({}) — a stabilized disposition must cite a trajectory of the SAME comparison surface",
                &expected_lineage[..16]
            )));
        }
        // The stored trajectory document must re-derive from its series
        // byte-for-byte: load the verified series (content address rederives),
        // re-derive this lineage's trajectory, and compare.
        let stored = self.load_trajectory(lineage, coordinate_system, series)?;
        if stored.axis != record.axis.as_str() {
            return Err(FrfError::new(format!(
                "trajectory {trajectory_id} is over axis {} but this residual is on {} — a stabilized disposition must cite a trajectory of the SAME axis",
                stored.axis,
                record.axis.as_str()
            )));
        }
        let series_rec = self.load_series(series)?;
        let rederived = crate::store::derive_lineage_trajectory(self, &series_rec, lineage)?;
        let stored_canon = crate::canon::canonical(&stored)?;
        let derived_canon = crate::canon::canonical(&rederived)?;
        if stored_canon != derived_canon {
            return Err(FrfError::new(format!(
                "trajectory {trajectory_id} does not re-derive from its series — a stabilized disposition must cite a VERIFIED trajectory"
            )));
        }
        // The tail: the LAST `passes` observations, in point order, are all
        // non-observations, and every passing point ran the SAME candidate.
        let n = stored.observations.len();
        if (n as u32) < passes {
            return Err(FrfError::new(format!(
                "trajectory {trajectory_id} has {n} observation(s), fewer than the declared consecutive_passes {passes}"
            )));
        }
        let original_capture = crate::verify::load_capture_verified(self, &record.run)?;
        let original_candidate = original_capture.capture.candidate_artifact.sha256;
        for obs in &stored.observations[n - passes as usize..] {
            if obs.observed {
                return Err(FrfError::new(format!(
                    "trajectory {trajectory_id}: point {} OBSERVED the residual — the tail of a stabilized disposition must be consecutive non-reproductions",
                    obs.point_index
                )));
            }
            let capture = crate::verify::load_capture_verified(self, &obs.run)?;
            if capture.capture.candidate_artifact.sha256 != original_candidate {
                return Err(FrfError::new(format!(
                    "trajectory {trajectory_id}: point {} ran a DIFFERENT candidate artifact than the residual's original run — a candidate change is a fix, not a stabilization; record --disposition fixed instead",
                    obs.point_index
                )));
            }
        }
        Ok(())
    }
}

/// Derive ONE lineage's trajectory from a verified series: the pure
/// derivation shared by the series writer and the stabilized-disposition
/// verifier. Every consumed observation is VERIFIED first (a series point's
/// run is a verified capture, each residual a verified observation of it)
/// before its fingerprint, lineage, or magnitude may drive the record.
pub(crate) fn derive_lineage_trajectory(
    store: &Store,
    series: &ExecutionSeries,
    lineage: &str,
) -> Result<TrajectoryRecord> {
    // per-point observation of the lineage: (residual id, fingerprint, magnitude)
    let mut per_point: Vec<Option<(String, String, Option<String>)>> =
        vec![None; series.points.len()];
    let mut axis: Option<String> = None;
    let mut relation: Option<String> = None;
    for (i, point) in series.points.iter().enumerate() {
        let capture = crate::verify::load_capture_verified(store, &point.run)?;
        for id in &capture.capture.residuals {
            let record = crate::verify::load_residual_verified(store, id)?;
            let record = record.record();
            if crate::semantics::residual_lineage_of_record(store, record)? != lineage {
                continue;
            }
            axis = Some(record.axis.as_str().to_string());
            // The transform's observation relation is the axis's comparator
            // relation (the same identity the court bound) — resolved from
            // the verified capture, never from a caller-supplied label.
            if let Some(sem) = capture
                .capture
                .comparator_semantics
                .iter()
                .find(|s| s.id == record.axis.as_str())
            {
                relation = Some(sem.relation_label());
            }
            let fp = crate::semantics::residual_fingerprint(record)?;
            let magnitude = crate::comparators::divergence_magnitude(
                record.axis.as_str(),
                &record.raw_reference,
                &record.raw_candidate,
            );
            per_point[i] = Some((id.clone(), fp, magnitude));
        }
    }
    let axis = axis.ok_or_else(|| {
        FrfError::new(format!(
            "series {} has no verified observation of lineage {}",
            &series.id[..16],
            &lineage[..16]
        ))
    })?;
    let relation = relation.unwrap_or_else(|| format!("eq({axis})"));
    let observed: Vec<bool> = per_point.iter().map(|o| o.is_some()).collect();
    let magnitudes: Vec<Option<String>> = per_point
        .iter()
        .map(|o| o.as_ref().and_then(|(_, _, m)| m.clone()))
        .collect();
    let kind = crate::comparators::magnitude_kind(&axis);
    let derivation =
        crate::trajectory::classify(&observed, &series.coordinate_system, &magnitudes, &kind)?;
    let transform = EvidenceTransform::trajectory(&series.id, &relation);
    let mut record = TrajectoryRecord {
        schema_version: SCHEMA_TRAJECTORY.to_string(),
        id: String::new(),
        subject: lineage.to_string(),
        axis: axis.clone(),
        coordinate_system: series.coordinate_system.clone(),
        series: series.id.clone(),
        observations: per_point
            .iter()
            .enumerate()
            .map(|(i, o)| TrajectoryObservation {
                point_index: series.points[i].point_index.clone(),
                coordinate: series.points[i].coordinate.clone(),
                coordinate_identity: series.points[i].coordinate_identity.clone(),
                run: series.points[i].run.clone(),
                observed: o.is_some(),
                residual: o.as_ref().map(|(r, _, _)| r.clone()),
                fingerprint: o.as_ref().map(|(_, f, _)| f.clone()),
                magnitude: o.as_ref().and_then(|(_, _, m)| m.clone()),
            })
            .collect(),
        derivation,
        transform,
    };
    record.id = crate::semantics::trajectory_identity(&record)?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> Store {
        let dir = std::env::temp_dir().join(format!(
            "frf-store-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        Store::new(dir)
    }

    #[test]
    fn write_once_refuses_overwrite() {
        let store = temp_store();
        store.ensure_tree().unwrap();
        let p = store.root.join("authorities").join("x.json");
        store.write_once(&p, "a").unwrap();
        let err = store.write_once(&p, "b").unwrap_err();
        assert!(err.0.contains("refusing to overwrite"));
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "a");
    }

    #[test]
    fn materialize_is_content_addressed_and_idempotent() {
        let store = temp_store();
        let bytes = b"#!/bin/sh\necho hi\n";
        let a = store.materialize_object(bytes, true).unwrap();
        let b = store.materialize_object(bytes, true).unwrap();
        assert_eq!(a, b);
        assert_eq!(std::fs::read(&a).unwrap(), bytes);
        let name = a.file_name().unwrap().to_string_lossy().to_string();
        assert_eq!(crate::host::sha256_bytes(bytes), name);
        // Sealed read-only: no write bits.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&a).unwrap().permissions().mode();
            assert_eq!(mode & 0o222, 0, "object must be sealed ({mode:o})");
        }
    }

    #[test]
    fn materialize_refuses_corrupt_objects() {
        // The name must BE the content: a tampered object is refused on
        // every use, never executed.
        let store = temp_store();
        let bytes = b"#!/bin/sh\necho hi\n";
        let path = store.materialize_object(bytes, true).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        std::fs::write(&path, b"#!/bin/sh\necho corrupted\n").unwrap();
        let err = store.materialize_object(bytes, true).unwrap_err();
        assert!(err.0.contains("corrupt"), "error: {}", err.0);
    }

    #[test]
    fn materialize_seals_data_read_only_and_executables_executable() {
        let store = temp_store();
        let data = store.materialize_object(b"fixture bytes", false).unwrap();
        let exe = store.materialize_object(b"#!/bin/sh\n", true).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dm = std::fs::metadata(&data).unwrap().permissions().mode();
            let em = std::fs::metadata(&exe).unwrap().permissions().mode();
            assert_eq!(dm & 0o222, 0, "data object must not be writable");
            assert_eq!(em & 0o111, 0o111, "executed object must be executable");
        }
    }

    #[test]
    fn disposition_events_are_append_only() {
        let store = temp_store();
        store.ensure_tree().unwrap();
        assert_eq!(
            store.current_disposition("cli-exit-0001").unwrap(),
            Disposition::Open
        );
        let e1 =
            DispositionEvent::closed("cli-exit-0001", ClosureKind::Intentional, "wording".into())
                .unwrap();
        store.append_disposition_event(&e1, None).unwrap();
        let e2 = DispositionEvent::closed("cli-exit-0001", ClosureKind::Harness, "runner".into())
            .unwrap();
        // The second append CASes against the first event's id.
        let chain = store.disposition_events("cli-exit-0001").unwrap();
        store
            .append_disposition_event(&e2, chain.last().map(|e| e.event_id.as_str()))
            .unwrap();
        // Projection is the last event; both events survive in order.
        assert_eq!(
            store.current_disposition("cli-exit-0001").unwrap().as_str(),
            "harness"
        );
        let events = store.disposition_events("cli-exit-0001").unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].disposition.as_str(), "intentional");
        assert_eq!(events[1].disposition.as_str(), "harness");
        // Re-disposing appends; it never rewrites event 0001.
        let first =
            std::fs::read_to_string(store.events_dir("cli-exit-0001").unwrap().join("0001.json"))
                .unwrap();
        let e3 =
            DispositionEvent::closed("cli-exit-0001", ClosureKind::Unknown, "reclassified".into())
                .unwrap();
        let chain = store.disposition_events("cli-exit-0001").unwrap();
        store
            .append_disposition_event(&e3, chain.last().map(|e| e.event_id.as_str()))
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(store.events_dir("cli-exit-0001").unwrap().join("0001.json"))
                .unwrap(),
            first
        );
        assert_eq!(
            store.current_disposition("cli-exit-0001").unwrap().as_str(),
            "unknown"
        );
        // Events are content-addressed and hash-chained: each event rederives
        // its own identity and links to its parent, and a hand-edited event
        // is refused on read.
        let events = store.disposition_events("cli-exit-0001").unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].parent_event_id, None);
        for (i, e) in events.iter().enumerate() {
            assert_eq!(e.event_id.len(), 64);
            assert!(e.evidence_refs.is_empty());
            if i > 0 {
                assert_eq!(
                    e.parent_event_id.as_deref(),
                    Some(events[i - 1].event_id.as_str())
                );
            }
        }
        // Tamper with the second event: the chain must refuse to load. The
        // tampered document is itself CANONICAL JSON (so the canonical-bytes
        // gate passes) but its content differs — the content-address check
        // must refuse it.
        let dir = store.events_dir("cli-exit-0001").unwrap();
        let p2 = dir.join("0002.json");
        let mut value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&p2).unwrap()).unwrap();
        value["reason"] = serde_json::Value::String("rewritten history".into());
        let canonical = crate::canon::canonical(&value).unwrap();
        std::fs::write(&p2, canonical).unwrap();
        let err = store.disposition_events("cli-exit-0001").unwrap_err();
        assert!(
            err.0.contains("not content-addressed"),
            "tampered event must be refused: {}",
            err.0
        );
    }

    #[test]
    fn disposition_append_is_a_compare_and_swap_against_the_parent() {
        // Two writers read the chain, then both append: the SECOND must be
        // refused as a CONFLICT (its expected parent is stale) — the hash
        // chain is the compare, and a stale writer can never splice a fork
        // into the history. Re-reading the chain and retrying with the new
        // parent succeeds.
        let store = temp_store();
        store.ensure_tree().unwrap();
        let e1 =
            DispositionEvent::closed("cli-exit-0001", ClosureKind::Intentional, "wording".into())
                .unwrap();
        // Both writers observed an EMPTY chain.
        let stale_parent: Option<&str> = None;
        // Writer A appends first.
        store.append_disposition_event(&e1, stale_parent).unwrap();
        // Writer B still holds the stale read: its append must CONFLICT.
        let e2 = DispositionEvent::closed("cli-exit-0001", ClosureKind::Harness, "runner".into())
            .unwrap();
        let err = store
            .append_disposition_event(&e2, stale_parent)
            .unwrap_err();
        assert!(
            err.is_append_conflict(),
            "a stale parent must be a conflict, not a silent overwrite: {}",
            err.0
        );
        // B re-reads the chain and retries with the real parent: succeeds,
        // and the chain is dense (0001, 0002).
        let chain = store.disposition_events("cli-exit-0001").unwrap();
        assert_eq!(chain.len(), 1);
        store
            .append_disposition_event(&e2, chain.last().map(|e| e.event_id.as_str()))
            .unwrap();
        assert_eq!(store.disposition_events("cli-exit-0001").unwrap().len(), 2);
        // The CAS loop surfaces the conflict type to its caller: a
        // same-residual append through the loop succeeds after the re-read.
        let e3 =
            DispositionEvent::closed("cli-exit-0001", ClosureKind::Unknown, "reclassified".into())
                .unwrap();
        let appended = store
            .append_disposition_event_cas("cli-exit-0001", &e3)
            .unwrap();
        assert_eq!(appended.disposition.as_str(), "unknown");
        assert_eq!(store.disposition_events("cli-exit-0001").unwrap().len(), 3);
    }
}
