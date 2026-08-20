//! `frf bundle export | verify`: the OpenReceipt as a portable graph root.
//!
//! A bundle is a receipt plus the complete object closure it references,
//! laid out as a self-contained evidence tree with a canonical-JSON manifest:
//!
//! ```text
//! bundle.frf/
//!   manifest.json        frf-bundle-v1: schema_version, receipt_id, run,
//!                        created_by, and the content-addressed inventory
//!   receipts/<id>.json   the OpenReceipt (canonical JSON)
//!   captures/<run>/      capture.yaml + raw side files of every run in the
//!                        closure (the receipt's run and every resolution run
//!                        its disposition events reference, transitively)
//!   objects/sha256/<H>   the content-addressed execution snapshots
//!   residuals/           residual records + <id>.events/ hash-chained
//!                        disposition events
//!   claims/<id>.yaml     the compiled claim, when present
//! ```
//!
//! The property that defines this milestone:
//!
//! > If you possess the bundle, you do not need the original source tree or
//! > the original FRF installation to verify the evidence graph. Execution
//! > (replay) may still require an appropriate environment; verification does
//! > not.
//!
//! `export` first verifies the receipt against the live tree (only verified
//! evidence may leave it), then copies the closure verbatim. `verify` walks
//! the manifest transitively (every inventory file must exist and hash to its
//! recorded digest; objects must be named by their digest), recomputes the
//! receipt's required closure from the bundle alone, requires the manifest to
//! cover it, and verifies the receipt against the bundled evidence through
//! the same verified loaders used everywhere.

use crate::error::{FrfError, Result};
use crate::host;
use crate::model::*;
use crate::store::Store;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

/// One file in a bundle: bundle-relative path, content digest, and role.
pub struct ClosureEntry {
    pub rel: String,
    pub sha256: String,
    pub kind: &'static str,
}

/// A receipt's complete evidence closure (relative paths + digests).
pub struct Closure {
    pub run: String,
    pub entries: Vec<ClosureEntry>,
}

fn read(path: &Path, what: &str) -> Result<Vec<u8>> {
    fs::read(path).map_err(|e| FrfError::new(format!("cannot read {what} {}: {e}", path.display())))
}

/// The complete closure of a receipt, computed against `store`: the receipt
/// itself, then for the receipt's run and — transitively — every resolution
/// run its disposition events reference: capture manifest + raw side files,
/// content-addressed snapshots, residual records, and disposition-event
/// chains. The compiled claim is included when present. Sorted by path;
/// entries are deduplicated (objects and residuals are shared across runs).
pub fn collect_closure(store: &Store, receipt_id: &str) -> Result<Closure> {
    let verified = crate::verify::load_receipt_verified(store, receipt_id)?;
    let body = verified.body();

    let mut entries: BTreeMap<String, ClosureEntry> = BTreeMap::new();
    let mut runs: Vec<String> = vec![body.run.clone()];
    let mut seen_runs: HashSet<String> = HashSet::new();
    let mut seen_residuals: HashSet<String> = HashSet::new();

    let receipt_path = store.receipt_path(receipt_id)?;
    let receipt_bytes = read(&receipt_path, "receipt")?;
    let rel = format!("receipts/{receipt_id}.json");
    entries.insert(
        rel.clone(),
        ClosureEntry {
            rel,
            sha256: host::sha256_bytes(&receipt_bytes),
            kind: "receipt",
        },
    );

    while let Some(run) = runs.pop() {
        if !seen_runs.insert(run.clone()) {
            continue;
        }
        let cv = crate::verify::load_capture_verified(store, &run)?;
        let cap = &cv.capture;
        let dir = store.run_dir(&run)?;

        // Capture manifest + raw side files (the derived projections rehash
        // against the raw bytes during verification).
        let mut names = vec!["capture.yaml".to_string()];
        for side in ["reference", "candidate"] {
            for f in [
                "stdout",
                "stderr",
                "exit.txt",
                "stderr_first_line.txt",
                "stdout_first_line.txt",
            ] {
                names.push(format!("{side}.{f}"));
            }
        }
        for name in names {
            let path = dir.join(&name);
            let bytes = read(&path, "capture file")?;
            let rel = format!("captures/{run}/{name}");
            let kind = if name == "capture.yaml" {
                "capture"
            } else {
                "side"
            };
            entries.insert(
                rel.clone(),
                ClosureEntry {
                    rel,
                    sha256: host::sha256_bytes(&bytes),
                    kind,
                },
            );
        }

        // Content-addressed execution snapshots.
        for h in [
            &cap.authority_artifact.sha256,
            &cap.candidate_artifact.sha256,
            &cap.fixture_sha256,
        ] {
            // verified_object_bytes refuses a missing or corrupt snapshot.
            store.verified_object_bytes(h)?;
            let rel = format!("objects/sha256/{h}");
            entries.insert(
                rel.clone(),
                ClosureEntry {
                    rel,
                    sha256: h.clone(),
                    kind: "object",
                },
            );
        }

        // Residual records + disposition-event chains; a `fixed` event adds
        // its resolution run to the closure (the graph traversal).
        for id in &cap.residuals {
            if !seen_residuals.insert(id.clone()) {
                continue;
            }
            let rec_path = store.residual_path(id)?;
            let bytes = read(&rec_path, "residual")?;
            let rel = format!("residuals/{id}.yaml");
            entries.insert(
                rel.clone(),
                ClosureEntry {
                    rel,
                    sha256: host::sha256_bytes(&bytes),
                    kind: "residual",
                },
            );
            // The verified event chain (identity rederives, parents link).
            let events = store.disposition_events(id)?;
            let ev_dir = store.events_dir(id)?;
            for (i, e) in events.iter().enumerate() {
                let path = ev_dir.join(format!("{:04}.yaml", i + 1));
                let bytes = read(&path, "disposition event")?;
                let rel = format!("residuals/{id}.events/{:04}.yaml", i + 1);
                entries.insert(
                    rel.clone(),
                    ClosureEntry {
                        rel,
                        sha256: host::sha256_bytes(&bytes),
                        kind: "event",
                    },
                );
                if let Disposition::Fixed {
                    resolution_run_id, ..
                } = &e.disposition
                {
                    runs.push(resolution_run_id.clone());
                }
            }
        }
    }

    // The compiled claim, when present.
    let claim_path = store.claim_path(receipt_id)?;
    if claim_path.is_file() {
        let bytes = read(&claim_path, "claim")?;
        let rel = format!("claims/{receipt_id}.yaml");
        entries.insert(
            rel.clone(),
            ClosureEntry {
                rel,
                sha256: host::sha256_bytes(&bytes),
                kind: "claim",
            },
        );
    }

    Ok(Closure {
        run: body.run.clone(),
        entries: entries.into_values().collect(),
    })
}

/// Export a receipt's portable closure. Only verified evidence may leave the
/// tree; the bundle directory is written fresh (never overwritten) and the
/// manifest — the content-addressed inventory — is written last.
pub fn export(store: &Store, receipt_id: &str, output: &Path) -> Result<PathBuf> {
    let closure = collect_closure(store, receipt_id)?;
    if output.exists() {
        return Err(FrfError::new(format!(
            "bundle {} already exists; refusing to overwrite (remove it to re-export)",
            output.display()
        )));
    }
    fs::create_dir_all(output)
        .map_err(|e| FrfError::new(format!("cannot create {}: {e}", output.display())))?;

    let mut inventory: Vec<Value> = Vec::new();
    for entry in &closure.entries {
        let src = store.root.join(&entry.rel);
        let bytes = read(&src, "closure file")?;
        // The bundle mirrors the tree layout; write each file fresh.
        let dst = output.join(&entry.rel);
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| FrfError::new(format!("cannot create {}: {e}", parent.display())))?;
        }
        fs::write(&dst, &bytes)
            .map_err(|e| FrfError::new(format!("cannot write {}: {e}", dst.display())))?;
        // Sealed read-only: the bundle is evidence, not a working tree. (A
        // future replay-from-bundle re-materializes through the store, which
        // re-seals what it executes.)
        host::set_permissions(&dst, 0o444)?;
        inventory.push(json!({
            "path": entry.rel,
            "sha256": entry.sha256,
            "kind": entry.kind,
        }));
    }

    let manifest = json!({
        "schema_version": SCHEMA_BUNDLE,
        "receipt_id": receipt_id,
        "run": closure.run,
        "created_by": {
            "frf_version": env!("CARGO_PKG_VERSION"),
            "frf_executable_hash": host::current_exe_hash()?,
        },
        "inventory": inventory,
    });
    let manifest_bytes = crate::canon::canonical(&manifest)?;
    fs::write(output.join("manifest.json"), manifest_bytes)
        .map_err(|e| FrfError::new(format!("cannot write manifest.json: {e}")))?;

    eprintln!(
        "bundle {}: {} file(s) in the closure of receipt {receipt_id}",
        output.display(),
        closure.entries.len()
    );
    Ok(output.to_path_buf())
}

/// Verify a bundle: (1) every inventory file exists and hashes to its
/// recorded digest (objects must be named by their digest), (2) the receipt
/// verifies against the bundled evidence alone, and (3) the manifest's
/// inventory covers the receipt's complete required closure. Only the bundle
/// is touched — the original source tree and the exporting FRF installation
/// are irrelevant.
pub fn verify(bundle_root: &Path) -> Result<()> {
    if !bundle_root.is_dir() {
        return Err(FrfError::new(format!(
            "{} is not a bundle directory (missing manifest.json?)",
            bundle_root.display()
        )));
    }
    let manifest_path = bundle_root.join("manifest.json");
    let text = fs::read_to_string(&manifest_path)
        .map_err(|e| FrfError::new(format!("cannot read {}: {e}", manifest_path.display())))?;
    let manifest: Value = serde_json::from_str(&text)
        .map_err(|e| FrfError::new(format!("manifest.json is not valid JSON: {e}")))?;
    if manifest["schema_version"].as_str() != Some(SCHEMA_BUNDLE) {
        return Err(FrfError::new(format!(
            "unsupported bundle schema version {:?} (expected {SCHEMA_BUNDLE})",
            manifest["schema_version"]
        )));
    }
    let receipt_id = manifest["receipt_id"]
        .as_str()
        .ok_or_else(|| FrfError::new("manifest.json carries no receipt_id"))?
        .to_string();

    // 1. Prove the manifest: every entry exists and hashes to its digest.
    let inventory_list = manifest["inventory"]
        .as_array()
        .ok_or_else(|| FrfError::new("manifest.json carries no inventory"))?;
    let mut inventory: HashMap<String, (&str, &str)> = HashMap::new(); // rel -> (sha256, kind)
    for item in inventory_list {
        let rel = item["path"]
            .as_str()
            .ok_or_else(|| FrfError::new("inventory entry carries no path"))?;
        let sha = item["sha256"]
            .as_str()
            .ok_or_else(|| FrfError::new(format!("inventory entry {rel} carries no sha256")))?;
        let kind = item["kind"]
            .as_str()
            .ok_or_else(|| FrfError::new(format!("inventory entry {rel} carries no kind")))?;
        let rel_path = Path::new(rel);
        if rel_path.is_absolute()
            || rel_path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(FrfError::new(format!(
                "inventory path {rel} escapes the bundle"
            )));
        }
        let full = bundle_root.join(rel);
        let bytes = match fs::read(&full) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(FrfError::new(format!(
                    "bundle is incomplete: {rel} is missing — the manifest records it but the bundle does not carry it"
                )));
            }
            Err(e) => {
                return Err(FrfError::new(format!("cannot read {rel}: {e}")));
            }
        };
        let actual = host::sha256_bytes(&bytes);
        if actual != sha {
            return Err(FrfError::new(format!(
                "bundle is corrupt: {rel} hashes to {} but the manifest records {sha}",
                &actual[..16]
            )));
        }
        if kind == "object" {
            let name = rel_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            if name != sha {
                return Err(FrfError::new(format!(
                    "bundle is corrupt: object file {rel} is not named by its digest"
                )));
            }
        }
        inventory.insert(rel.to_string(), (sha, kind));
    }

    // 2. The receipt verifies against the bundle alone, and the manifest
    //    covers its complete required closure.
    let store = Store::new(bundle_root.to_path_buf());
    let closure = collect_closure(&store, &receipt_id)?;
    for entry in &closure.entries {
        match inventory.get(&entry.rel) {
            Some((sha, _)) if *sha == entry.sha256 => {}
            _ => {
                return Err(FrfError::new(format!(
                    "bundle closure incomplete: {}{} — the manifest must cover every file the receipt's evidence references",
                    entry.rel,
                    if inventory.contains_key(&entry.rel) { " is present but mismatched" } else { " is missing" }
                )));
            }
        }
    }

    println!(
        "bundle {} verified: receipt {receipt_id}, run {}, {} file(s) in the closure",
        bundle_root.display(),
        closure.run,
        closure.entries.len()
    );
    Ok(())
}
