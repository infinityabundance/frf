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

    /// `reductions/<id>.yaml` — the content-addressed reduction record.
    pub fn reduction_path(&self, id: &str) -> Result<PathBuf> {
        validate_id("reduction", id)?;
        Ok(self.root.join("reductions").join(format!("{id}.yaml")))
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
            &record.axis,
            record.kind,
            &record.authority,
            &record.candidate_sha256,
            &record.original_fixture_sha256,
            &record.final_fixture_sha256,
            &record.attempts,
            &record.derivation,
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
            &record.axis,
            record.kind,
            &record.authority,
            &record.candidate_sha256,
            &record.original_fixture_sha256,
            &record.final_fixture_sha256,
            &record.attempts,
            &record.derivation,
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
    /// Every failure names the specific dimension that drifted (via
    /// [`crate::semantics::semantic_diff`]) so the refusal is actionable.
    pub fn resolution_compatibility(
        &self,
        original_run: &str,
        resolution_run: &str,
        axis: Axis,
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

        // The axis being resolved must be declared by the resolution run, and
        // must now agree.
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
        let closes = match axis {
            Axis::Exit => resolution.reference.exit == resolution.candidate.exit,
            Axis::Stderr => {
                resolution.reference.stderr_first_line == resolution.candidate.stderr_first_line
            }
            Axis::Stdout => {
                resolution.reference.stdout_first_line == resolution.candidate.stdout_first_line
            }
        };
        if !closes {
            return Err(FrfError::new(format!(
                "resolution run '{resolution_run}' does not close the residual: the {} axis still diverges in its captures (a fixed disposition must be backed by a run where the residual no longer reproduces)",
                axis.as_str()
            )));
        }
        Ok(())
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
        assert_eq!(store.next_residual_seq(ResidualKind::Exit).unwrap(), 1);
        let rec = ResidualRecord {
            schema_version: SCHEMA_RESIDUAL.into(),
            id: "cli-exit-0001".into(),
            court: "c".into(),
            run: "r".into(),
            axis: Axis::Exit,
            kind: ResidualKind::Exit,
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
        assert_eq!(store.next_residual_seq(ResidualKind::Exit).unwrap(), 2);
        assert_eq!(store.next_residual_seq(ResidualKind::Text).unwrap(), 1);
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
