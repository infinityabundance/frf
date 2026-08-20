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
        Ok(self.root.join("receipts").join(format!("{id}.yaml")))
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

    /// Sanctioned mutation of a residual record: rewrites the record and its
    /// derived token atomically enough for a CLI (record first, then token;
    /// both are pure functions of the same state).
    pub fn write_residual(&self, record: &ResidualRecord) -> Result<()> {
        let yaml = self.to_yaml(record)?;
        self.write_derived(&self.residual_path(&record.id)?, &yaml)?;
        let token = crate::kappa::kappa(record);
        let token_yaml = self.to_yaml(&token)?;
        self.write_derived(&self.token_path(&record.id)?, &token_yaml)
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
        self.parse_yaml(&path)
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
            raw_reference: "2".into(),
            raw_candidate: "1".into(),
            raw_reference_sha256: "0".repeat(64),
            raw_candidate_sha256: "1".repeat(64),
            disposition: Disposition::Open,
        };
        store.write_residual(&rec).unwrap();
        assert_eq!(store.next_residual_seq(ResidualKind::Exit).unwrap(), 2);
        assert_eq!(store.next_residual_seq(ResidualKind::Text).unwrap(), 1);
    }
}
