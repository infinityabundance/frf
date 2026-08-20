//! Root-relative evidence store with immutability guards.
//!
//! Layout (Section 19.3 of the paper):
//!
//! ```text
//! <root>/
//!   authorities/   admitted once, never rewritten
//!   courts/        hand-authored declarations (never created by the tool)
//!   captures/      raw observations, written once (create_new)
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
        for dir in ["authorities", "captures", "residuals", "receipts", "claims"] {
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
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(mut f) => f
                .write_all(contents.as_bytes())
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
    /// the current disposition is the projection of the last one.
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
        Ok(events.into_iter().map(|(_, e)| e).collect())
    }

    /// The projected current disposition: the last event, or `Open` when the
    /// residual has no events yet.
    pub fn current_disposition(&self, id: &str) -> Result<Disposition> {
        Ok(self
            .disposition_events(id)?
            .pop()
            .map(|e| e.disposition)
            .unwrap_or(Disposition::Open))
    }

    /// Append one immutable disposition event (sequence = count + 1).
    pub fn append_disposition_event(&self, event: &DispositionEvent) -> Result<()> {
        let dir = self.events_dir(&event.residual_id)?;
        fs::create_dir_all(&dir)
            .map_err(|e| FrfError::new(format!("cannot create {}: {e}", dir.display())))?;
        let seq = self.disposition_events(&event.residual_id)?.len() + 1;
        let path = dir.join(format!("{seq:04}.yaml"));
        let yaml = self.to_yaml(event)?;
        self.write_once(&path, &yaml)
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
    /// under a compatible envelope, holding everything stable except the
    /// candidate (the thing a fix is allowed to change), and show the axis
    /// now agreeing. Every check fails with a specific message; `Ok(())`
    /// means the run is valid resolution evidence for this residual.
    ///
    /// The candidate is deliberately NOT compared: it is the one entity a fix
    /// court may change, and both runs record their candidate artifact hashes
    /// so the evolution is explicit rather than silently crossed.
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

        let check = |what: &str, a: &str, b: &str| -> Result<()> {
            if a == b {
                Ok(())
            } else {
                Err(FrfError::new(format!(
                    "resolution run '{resolution_run}' is not comparable to '{original_run}': {what} differs ({a:?} != {b:?})"
                )))
            }
        };

        check("court", &original.court, &resolution.court)?;
        check("authority", &original.authority, &resolution.authority)?;
        check("fixture id", &original.fixture, &resolution.fixture)?;
        check(
            "fixture bytes (sha256)",
            &original.fixture_sha256,
            &resolution.fixture_sha256,
        )?;
        let orig_args = format!("{:?}", original.arguments);
        let res_args = format!("{:?}", resolution.arguments);
        check("fixture arguments", &orig_args, &res_args)?;
        let orig_obs = original
            .court_spec
            .admissibility_envelope
            .observables
            .join(",");
        let res_obs = resolution
            .court_spec
            .admissibility_envelope
            .observables
            .join(",");
        check("observables", &orig_obs, &res_obs)?;
        let orig_norm = original
            .court_spec
            .admissibility_envelope
            .normalizers
            .join(",");
        let res_norm = resolution
            .court_spec
            .admissibility_envelope
            .normalizers
            .join(",");
        check("normalizers", &orig_norm, &res_norm)?;
        check(
            "environment digest",
            &original.environment_digest,
            &resolution.environment_digest,
        )?;

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
    }
}
