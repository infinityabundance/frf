//! Root-relative evidence store with immutability guards.
//!
//! Layout (Section 19.3 of the paper):
//!
//! ```text
//! <root>/
//!   authorities/   admitted once, never rewritten
//!   courts/        hand-authored declarations (never created by the tool)
//!   captures/      raw observations, written once (create_new)
//!   objects/       content-addressed execution snapshots (sha256/<H>)
//!   residuals/     residual records + derived token files
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
//!   that are pure functions of immutable inputs (tokens, claims).
//! - The residual record is the single mutable evidence object; mutation goes
//!   through [`Store::write_residual`], which rewrites the record and its
//!   derived token together.

use crate::error::{FrfError, Result};
use crate::model::*;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

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
        Ok(self.root.join("authorities").join(format!("{id}.yaml")))
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
        let inv: crate::model::ComparatorInvocation = serde_json::from_slice(
            &fs::read(&path)
                .map_err(|e| FrfError::new(format!("cannot read {}: {e}", path.display())))?,
        )
        .map_err(|e| FrfError::new(format!("cannot parse {}: {e}", path.display())))?;
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
        let res: crate::model::ComparatorResult = serde_json::from_slice(
            &fs::read(&path)
                .map_err(|e| FrfError::new(format!("cannot read {}: {e}", path.display())))?,
        )
        .map_err(|e| FrfError::new(format!("cannot parse {}: {e}", path.display())))?;
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
            serde_json::from_slice(&fs::read(dir.join("response.json")).map_err(|e| {
                FrfError::new(format!(
                    "cannot read {}: {e}",
                    dir.join("response.json").display()
                ))
            })?)
            .map_err(|e| {
                FrfError::new(format!(
                    "cannot parse {}: {e}",
                    dir.join("response.json").display()
                ))
            })?;
        if response.request_id != invocation.request_cid {
            return Err(FrfError::new(format!(
                "run {run}: comparator response for axis {axis} does not name the request it answers"
            )));
        }
        for rid in &result.residual_observation_ids {
            let record = self.load_residual(rid)?;
            if record.run != run {
                return Err(FrfError::new(format!(
                    "run {run}: comparator result for axis {axis} references residual {rid} which belongs to run {}",
                    record.run
                )));
            }
        }
        Ok(crate::model::ComparatorEvidence { invocation, result })
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
        let inv: crate::model::NormalizerInvocation = serde_json::from_slice(
            &fs::read(&path)
                .map_err(|e| FrfError::new(format!("cannot read {}: {e}", path.display())))?,
        )
        .map_err(|e| FrfError::new(format!("cannot parse {}: {e}", path.display())))?;
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
        let res: crate::model::NormalizerResult = serde_json::from_slice(
            &fs::read(&path)
                .map_err(|e| FrfError::new(format!("cannot read {}: {e}", path.display())))?,
        )
        .map_err(|e| FrfError::new(format!("cannot parse {}: {e}", path.display())))?;
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
            serde_json::from_slice(&fs::read(dir.join("response.json")).map_err(|e| {
                FrfError::new(format!(
                    "cannot read {}: {e}",
                    dir.join("response.json").display()
                ))
            })?)
            .map_err(|e| {
                FrfError::new(format!(
                    "cannot parse {}: {e}",
                    dir.join("response.json").display()
                ))
            })?;
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
        let inv: crate::model::CaptureAdapterInvocation = serde_json::from_slice(
            &fs::read(&inv_path)
                .map_err(|e| FrfError::new(format!("cannot read {}: {e}", inv_path.display())))?,
        )
        .map_err(|e| FrfError::new(format!("cannot parse {}: {e}", inv_path.display())))?;
        let res: crate::model::CaptureAdapterResult = serde_json::from_slice(
            &fs::read(&res_path)
                .map_err(|e| FrfError::new(format!("cannot read {}: {e}", res_path.display())))?,
        )
        .map_err(|e| FrfError::new(format!("cannot parse {}: {e}", res_path.display())))?;
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
        let response: crate::model::CaptureAdapterResponse =
            serde_json::from_slice(&fs::read(&response_path).map_err(|e| {
                FrfError::new(format!("cannot read {}: {e}", response_path.display()))
            })?)
            .map_err(|e| FrfError::new(format!("cannot parse {}: {e}", response_path.display())))?;
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
    /// itself lives at `reductions/<id>.yaml`.
    pub fn minimizer_dir(&self, reduction_id: &str) -> Result<PathBuf> {
        validate_id("reduction", reduction_id)?;
        Ok(self
            .root
            .join("reductions")
            .join(reduction_id)
            .join("minimizer"))
    }

    pub fn residual_path(&self, id: &str) -> Result<PathBuf> {
        validate_id("residual", id)?;
        Ok(self.root.join("residuals").join(format!("{id}.yaml")))
    }

    pub fn token_path(&self, id: &str) -> Result<PathBuf> {
        validate_id("residual", id)?;
        Ok(self.root.join("residuals").join(format!("{id}.token.yaml")))
    }

    pub fn receipt_path(&self, id: &str) -> Result<PathBuf> {
        validate_id("receipt", id)?;
        // Receipts are canonical JSON (RFC 8785) — the OpenReceipt protocol
        // representation — so their identity is stable across implementations.
        Ok(self.root.join("receipts").join(format!("{id}.json")))
    }

    pub fn claim_path(&self, receipt_id: &str) -> Result<PathBuf> {
        validate_id("receipt", receipt_id)?;
        Ok(self.root.join("claims").join(format!("{receipt_id}.yaml")))
    }

    /// The EVIDENCE UNIVERSE of the store right now: every residual head
    /// (id + projected disposition + the event that supplied it), receipt,
    /// run, authority, series snapshot, and reduction record present — sorted
    /// and content-addressed. A claim compiled now is admissible relative to
    /// THIS universe: no unresolved residual in it intersects the claim's
    /// scope, and the compiled claim carries the snapshot, so the negative
    /// search is portable and a later store mutation cannot silently change
    /// what the claim means.
    pub fn knowledge_snapshot(&self) -> Result<KnowledgeSnapshot> {
        let mut snapshot = KnowledgeSnapshot {
            schema_version: crate::model::SCHEMA_CLAIM.to_string(),
            cid: String::new(),
            residual_heads: Vec::new(),
            receipts: Vec::new(),
            runs: Vec::new(),
            authorities: Vec::new(),
            series: Vec::new(),
            reductions: Vec::new(),
        };

        // Residual heads: every residual record with its projected head
        // disposition (the event chain is verified on load).
        let residuals_dir = self.root.join("residuals");
        if residuals_dir.is_dir() {
            let mut names: Vec<String> = std::fs::read_dir(&residuals_dir)
                .map_err(|e| FrfError::new(format!("cannot read residuals directory: {e}")))?
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.ends_with(".yaml") && !n.ends_with(".token.yaml"))
                .collect();
            names.sort();
            for name in names {
                let id = name.trim_end_matches(".yaml").to_string();
                let events = self.disposition_events(&id)?;
                let disposition = events
                    .last()
                    .map(|e| e.disposition.clone())
                    .unwrap_or(Disposition::Open);
                snapshot.residual_heads.push(ResidualHead {
                    id,
                    disposition: disposition.as_str().to_string(),
                    disposition_event_id: events.last().map(|e| e.event_id.clone()),
                });
            }
            snapshot.residual_heads.sort_by(|a, b| a.id.cmp(&b.id));
        }

        // Receipts, runs, authorities, series, reductions: deterministic
        // sorted listings. Runs are the capture directories; the rest are
        // record files.
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
                    if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                        out.push(name);
                    } else if name.ends_with(".json") || name.ends_with(".yaml") {
                        out.push(
                            name.trim_end_matches(".json")
                                .trim_end_matches(".yaml")
                                .to_string(),
                        );
                    }
                }
            }
            out.sort();
            Ok(out)
        };
        snapshot.receipts = listing("receipts")?;
        snapshot.runs = listing("captures")?;
        snapshot.authorities = listing("authorities")?;
        snapshot.series = listing("series")?;
        snapshot.reductions = listing("reductions")?;

        let cid = crate::semantics::knowledge_snapshot_identity(&snapshot)?;
        snapshot.cid = cid;
        Ok(snapshot)
    }

    /// `reductions/<id>.yaml` — the content-addressed reduction record.
    pub fn reduction_path(&self, id: &str) -> Result<PathBuf> {
        validate_id("reduction", id)?;
        Ok(self.root.join("reductions").join(format!("{id}.yaml")))
    }

    /// `challenges/<id>.yaml` — the content-addressed court-challenge record
    /// (the negative-control evidence: the court run against a mutant
    /// candidate).
    pub fn challenge_path(&self, id: &str) -> Result<PathBuf> {
        validate_id("challenge", id)?;
        Ok(self.root.join("challenges").join(format!("{id}.yaml")))
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
        let stmt: WitnessStatement = serde_json::from_slice(
            &fs::read(&path)
                .map_err(|e| FrfError::new(format!("cannot read {}: {e}", path.display())))?,
        )
        .map_err(|e| FrfError::new(format!("cannot parse {}: {e}", path.display())))?;
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
        let response_bytes = fs::read(&response_path)
            .map_err(|e| FrfError::new(format!("cannot read {}: {e}", response_path.display())))?;
        if crate::host::sha256_bytes(&response_bytes) != stmt.response_cid {
            return Err(FrfError::new(format!(
                "witness statement {id}: the preserved response does not hash to its recorded response_cid"
            )));
        }
        let response: WitnessResponse = serde_json::from_slice(&response_bytes)
            .map_err(|e| FrfError::new(format!("cannot parse {}: {e}", response_path.display())))?;
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
        let record: CourtChallenge = self.parse_yaml(&path)?;
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
            return Ok(());
        }
        let yaml = self.to_yaml(record)?;
        self.write_once(&path, &yaml)
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
        let record: ReductionRecord = self.parse_yaml(&path)?;
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
            return Ok(());
        }
        let yaml = self.to_yaml(record)?;
        self.write_once(&path, &yaml)
    }

    /// `trajectories/<lineage>.<coordinate-system>.<series>.yaml` — the
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
            .join(format!("{lineage}.{coordinate_system}.{series}.yaml")))
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
        self.parse_yaml(&path)
    }

    /// `series/<id>.yaml` — the content-addressed ExecutionSeries record.
    pub fn series_path(&self, id: &str) -> Result<PathBuf> {
        validate_id("series", id)?;
        Ok(self.root.join("series").join(format!("{id}.yaml")))
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
        let series: ExecutionSeries = self.parse_yaml(&path)?;
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
            return Ok(()); // identical series already recorded — no-op
        }
        let yaml = self.to_yaml(series)?;
        self.write_once(&path, &yaml)
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
            if !name.ends_with(".yaml") {
                continue;
            }
            let id = name.trim_end_matches(".yaml").to_string();
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
            if !name.ends_with(".yaml") {
                continue;
            }
            let id = name.trim_end_matches(".yaml").to_string();
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
            if !name.ends_with(".yaml") {
                continue;
            }
            let id = name.trim_end_matches(".yaml").to_string();
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

    pub fn to_yaml<T: serde::Serialize>(&self, value: &T) -> Result<String> {
        serde_yaml::to_string(value)
            .map_err(|e| FrfError::new(format!("cannot serialize record: {e}")))
    }

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

    /// Write a derived artifact (tokens, claims): a pure function of
    /// immutable inputs, so overwriting with identical output is safe.
    pub fn write_derived(&self, path: &Path, contents: &str) -> Result<()> {
        fs::write(path, contents)
            .map_err(|e| FrfError::new(format!("cannot write {}: {e}", path.display())))
    }

    /// Write the derived κ token for a residual under its current disposition.
    pub fn write_token(&self, record: &ResidualRecord, disposition: &Disposition) -> Result<()> {
        let token = crate::kappa::kappa(record, disposition);
        let yaml = self.to_yaml(&token)?;
        self.write_derived(&self.token_path(&record.id)?, &yaml)
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
                events.push((seq, self.parse_yaml(&path)?));
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
    pub fn append_disposition_event(&self, partial: &DispositionEvent) -> Result<DispositionEvent> {
        let events = self.disposition_events(&partial.residual_id)?;
        let parent_event_id = events.last().map(|e| e.event_id.clone());
        // The only evidence a v0.1.15 disposition can reference is the
        // resolution run that closed it.
        let evidence_refs = match &partial.disposition {
            Disposition::Fixed {
                resolution_run_id, ..
            } => vec![resolution_run_id.clone()],
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
        let path = dir.join(format!("{seq:04}.yaml"));
        let yaml = self.to_yaml(&event)?;
        self.write_once(&path, &yaml)?;
        Ok(event)
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
        self.parse_yaml(&path)
    }

    pub fn load_residual(&self, id: &str) -> Result<ResidualRecord> {
        let path = self.residual_path(id)?;
        if !path.exists() {
            return Err(FrfError::new(format!(
                "no such residual '{id}' (missing {})",
                path.display()
            )));
        }
        self.parse_yaml(&path)
    }

    pub fn load_capture(&self, run: &str) -> Result<CaptureManifest> {
        let path = self.run_dir(run)?.join("capture.yaml");
        if !path.exists() {
            return Err(FrfError::new(format!(
                "no such run '{run}' (missing {})",
                path.display()
            )));
        }
        self.parse_yaml(&path)
    }

    pub fn load_receipt(&self, id: &str) -> Result<Receipt> {
        let path = self.receipt_path(id)?;
        if !path.exists() {
            return Err(FrfError::new(format!(
                "no such receipt '{id}' (missing {})",
                path.display()
            )));
        }
        let text = fs::read_to_string(&path)
            .map_err(|e| FrfError::new(format!("cannot read {}: {e}", path.display())))?;
        serde_json::from_str(&text)
            .map_err(|e| FrfError::new(format!("cannot parse {}: {e}", path.display())))
    }

    /// Next zero-padded sequence number for a residual kind: max existing
    /// `{domain}-{kind}-{n}` plus one. Deterministic for a given store state;
    /// residuals are never deleted, so ids never collide.
    pub fn next_residual_seq(&self, kind: ResidualKind) -> Result<u32> {
        let prefix = format!("{}-{}-", kind.domain_prefix(), kind.as_str());
        let dir = self.root.join("residuals");
        let mut max = 0u32;
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if let Some(rest) = name.strip_prefix(&prefix) {
                    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                    if let Ok(n) = digits.parse::<u32>() {
                        max = max.max(n);
                    }
                }
            }
        }
        Ok(max + 1)
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
        let original = self.load_capture(original_run)?;
        let resolution = self.load_capture(resolution_run)?;

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
            // the resolution run, applied to its verified captures. The raw
            // stdout bytes are rebuilt from the run's captured files (the
            // domain comparators parse them; the serialized SideCapture
            // carries only the hash).
            let reference = self.side_capture_with_raw_stdout(resolution_run, &resolution, true)?;
            let candidate =
                self.side_capture_with_raw_stdout(resolution_run, &resolution, false)?;
            let plan = crate::comparators::EvaluationPlan::from_capture(&resolution, axis)?;
            let context = crate::comparators::EvaluationContext {
                fixture_sha256: &resolution.fixture_sha256,
                arguments: &resolution.arguments,
                environment_digest: &resolution.environment.digest,
                produced: reference.produced.as_ref().zip(candidate.produced.as_ref()),
                cwd: std::path::Path::new("."),
                raw: None,
                compared: None,
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
    fn side_capture_with_raw_stdout(
        &self,
        run: &str,
        capture: &CaptureManifest,
        reference: bool,
    ) -> Result<SideCapture> {
        let mut side = if reference {
            capture.reference.clone()
        } else {
            capture.candidate.clone()
        };
        let dir = self.run_dir(run)?;
        let name = if reference { "reference" } else { "candidate" };
        let bytes = fs::read(dir.join(format!("{name}.stdout")))
            .map_err(|e| FrfError::new(format!("cannot read {name}.stdout: {e}")))?;
        let actual = crate::host::sha256_bytes(&bytes);
        if actual != side.stdout_sha256 {
            return Err(FrfError::new(format!(
                "{name}.stdout of run {run} does not hash to the recorded value; refusing to evaluate a drifted capture"
            )));
        }
        side.stdout_bytes = bytes;
        Ok(side)
    }
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
        let p = store.root.join("authorities").join("x.yaml");
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
    fn residual_sequence_counts_by_kind() {
        let store = temp_store();
        store.ensure_tree().unwrap();
        assert_eq!(store.next_residual_seq(ResidualKind::exit()).unwrap(), 1);
        let rec = ResidualRecord {
            schema_version: SCHEMA_RESIDUAL.into(),
            id: "cli-exit-0001".into(),
            court: "c".into(),
            run: "r".into(),
            axis: ObservableId::exit(),
            kind: ResidualKind::exit(),
            surface: None,
            authority: "a".into(),
            scope: "s".into(),
            candidate_sha256: "c".repeat(64),
            raw_reference: "2".into(),
            raw_candidate: "1".into(),
            raw_reference_sha256: "0".repeat(64),
            raw_candidate_sha256: "1".repeat(64),
        };
        let yaml = store.to_yaml(&rec).unwrap();
        store
            .write_once(&store.residual_path("cli-exit-0001").unwrap(), &yaml)
            .unwrap();
        assert_eq!(store.next_residual_seq(ResidualKind::exit()).unwrap(), 2);
        assert_eq!(store.next_residual_seq(ResidualKind::text()).unwrap(), 1);
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
        store.append_disposition_event(&e1).unwrap();
        let e2 = DispositionEvent::closed("cli-exit-0001", ClosureKind::Harness, "runner".into())
            .unwrap();
        store.append_disposition_event(&e2).unwrap();
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
            std::fs::read_to_string(store.events_dir("cli-exit-0001").unwrap().join("0001.yaml"))
                .unwrap();
        let e3 =
            DispositionEvent::closed("cli-exit-0001", ClosureKind::Unknown, "reclassified".into())
                .unwrap();
        store.append_disposition_event(&e3).unwrap();
        assert_eq!(
            std::fs::read_to_string(store.events_dir("cli-exit-0001").unwrap().join("0001.yaml"))
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
        // Tamper with the second event: the chain must refuse to load.
        let dir = store.events_dir("cli-exit-0001").unwrap();
        let p2 = dir.join("0002.yaml");
        let mut yaml: serde_yaml::Value =
            serde_yaml::from_str(&std::fs::read_to_string(&p2).unwrap()).unwrap();
        yaml["reason"] = serde_yaml::Value::String("rewritten history".into());
        std::fs::write(&p2, serde_yaml::to_string(&yaml).unwrap()).unwrap();
        let err = store.disposition_events("cli-exit-0001").unwrap_err();
        assert!(
            err.0.contains("not content-addressed"),
            "tampered event must be refused: {}",
            err.0
        );
    }
}
