//! `frf bundle export | verify`: the OpenReceipt as a portable graph root.
//!
//! A bundle is a receipt plus the complete object closure it references,
//! laid out as a self-contained evidence tree with a canonical-JSON manifest:
//!
//! ```text
//! bundle.frf/
//!   manifest.json        frf-bundle-v2: schema_version, receipt_id, run,
//!                        created_by, and the content-addressed inventory
//!   receipts/<id>.json   the OpenReceipt (canonical JSON)
//!   captures/<run>/      capture.yaml + raw side files of every run in the
//!                        closure (the receipt's run and every resolution run
//!                        its disposition events reference, transitively),
//!                        plus comparator/<axis>/{request,response,invocation,
//!                        result}.json for every externally served axis
//!   objects/sha256/<H>   the content-addressed execution snapshots — the
//!                        executed artifacts AND the comparator
//!                        instrumentation, walked via the capture's typed
//!                        evidence references
//!   residuals/           residual records + <id>.events/ hash-chained
//!                        disposition events
//!   claims/<id>.json     the compiled claim(s) bound to the receipt
//!                        (content-addressed) + claims/by-receipt/ index
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
//!
//! Both container forms feed ONE entry point — [`open_verified_bundle`] —
//! which CONFINES the bytes first (a directory is copied by a walk that
//! refuses symlinks/hard links and enforces the same count/size caps as the
//! archive extractor; a single-file archive is extracted by those same
//! rules), then parses the manifest strictly (I-JSON, closed schema, valid
//! identifiers), and only then proves the exact inventory. The container
//! format never changes the trust model: a portable bundle is self-contained
//! evidence in both forms.

use crate::error::{FrfError, Result};
use crate::host;
use crate::model::*;
use crate::store::Store;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

/// The bundle manifest, parsed STRICTLY: the bytes must be I-JSON (duplicate
/// property names refused) and the schema is closed (`deny_unknown_fields`) —
/// a manifest with an unknown property is refused, never read around. Every
/// identifier is validated before any value may construct a path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleManifest {
    pub schema_version: String,
    /// `directory` | `single-tar` — the container the manifest declares.
    pub container: String,
    pub receipt_id: String,
    pub run: String,
    pub created_by: BundleCreatedBy,
    /// The exact inventory: every file the bundle carries, its digest, and
    /// its role. Verification hashes every entry against this list.
    pub inventory: Vec<BundleInventoryEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleCreatedBy {
    pub frf_version: String,
    pub frf_executable_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleInventoryEntry {
    pub path: String,
    pub sha256: String,
    pub kind: String,
}

/// The closed inventory-role vocabulary a bundle manifest may declare. The
/// closure walker emits exactly these roles; [`parse_bundle_manifest`]
/// refuses any other, and export asserts every emitted role is in this set
/// (so a new role is a protocol change, not a silent manifest extension).
pub const BUNDLE_KINDS: &[&str] = &[
    "receipt",
    "claim",
    "claim-index",
    "challenge",
    "mutation-evidence",
    "witness",
    "witness-evidence",
    "independence",
    "reduction",
    "minimizer-evidence",
    "authority",
    "series",
    "trajectory",
    "produced",
    "harness-event",
    "normalizer-evidence",
    "capture-adapter-evidence",
    "residual",
    "residual-index",
    "event",
    "execution-attempt",
    "capture",
    "side",
    "object",
    "comparator-request",
    "comparator-response",
    "comparator-invocation",
    "comparator-result",
];

/// Parse and VALIDATE a bundle manifest: strict JSON (I-JSON — duplicate
/// property names refused), the closed schema above (unknown properties
/// refused), the protocol schema version, a declared container, valid
/// receipt/run identifiers, contained inventory paths, and the closed
/// inventory-role vocabulary. Only a manifest that passes ALL of this may
/// construct a path.
pub fn parse_bundle_manifest(bytes: &[u8]) -> Result<BundleManifest> {
    let strict = crate::canon::parse_strict(bytes)
        .map_err(|e| FrfError::new(format!("manifest.json is not strict JSON: {e}")))?;
    let manifest: BundleManifest = serde_json::from_value(strict).map_err(|e| {
        FrfError::new(format!(
            "manifest.json carries an unknown property or an invalid value: {e}"
        ))
    })?;
    if manifest.schema_version != SCHEMA_BUNDLE {
        return Err(FrfError::new(format!(
            "unsupported bundle schema version {:?} (expected {SCHEMA_BUNDLE})",
            manifest.schema_version
        )));
    }
    if !matches!(manifest.container.as_str(), "directory" | "single-tar") {
        return Err(FrfError::new(format!(
            "manifest.json declares unknown container {:?} (the protocol admits directory | single-tar)",
            manifest.container
        )));
    }
    crate::store::validate_id("receipt", &manifest.receipt_id)
        .map_err(|_| FrfError::new("manifest.json carries an invalid receipt_id"))?;
    crate::store::validate_id("run", &manifest.run)
        .map_err(|_| FrfError::new("manifest.json carries an invalid run id"))?;
    let mut seen: HashSet<&str> = HashSet::new();
    for entry in &manifest.inventory {
        let rel = &entry.path;
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
        if !BUNDLE_KINDS.contains(&entry.kind.as_str()) {
            return Err(FrfError::new(format!(
                "inventory entry {rel} carries unknown kind {:?}",
                entry.kind
            )));
        }
        if entry.sha256.len() != 64 || !entry.sha256.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(FrfError::new(format!(
                "inventory entry {rel} carries an invalid digest {:?}",
                entry.sha256
            )));
        }
        if !seen.insert(rel) {
            return Err(FrfError::new(format!(
                "inventory entry {rel} repeats a path"
            )));
        }
    }
    Ok(manifest)
}

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

/// The container a bundle ships in. The evidence graph is identical either
/// way; only the transport differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Container {
    /// A tree of files with `manifest.json` at its root (the original form).
    Directory,
    /// One deterministic tar archive carrying the identical layout.
    SingleTar,
}

impl Container {
    pub fn as_str(self) -> &'static str {
        match self {
            Container::Directory => BUNDLE_CONTAINER_DIRECTORY,
            Container::SingleTar => BUNDLE_CONTAINER_SINGLE_TAR,
        }
    }
}

/// An RAII temporary directory: replay and single-file verification must not
/// touch the sealed bundle, so they work on a temp copy that is removed on
/// drop (panics included).
pub struct TempRoot {
    pub dir: PathBuf,
}

impl TempRoot {
    fn new(tag: &str) -> Result<TempRoot> {
        let dir = std::env::temp_dir().join(format!(
            "frf-bundle-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::create_dir_all(&dir)
            .map_err(|e| FrfError::new(format!("cannot create {}: {e}", dir.display())))?;
        Ok(TempRoot { dir })
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Copy a bundle DIRECTORY tree into `dst` (which must exist), enforcing the
/// SAME confinement as the archive extractor — the container format must not
/// change the trust model. `symlink_metadata` never follows: a symlink is
/// refused, and a regular file with multiple hard links is refused too (a
/// hard link could share an inode with a file outside the bundle, leaking
/// its bytes into the tree). Entry names from `read_dir` are single path
/// components, so an escape is structurally impossible here — the archive
/// form's absolute/`..` checks exist because tar entry names are arbitrary
/// strings. Count and total-size ceilings are the archive form's exact caps
/// (10 000 entries / 1 GiB): the closure of one receipt is dozens of files
/// and a few MiB. Only regular files and directories are materialized.
fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    let mut count = 0usize;
    let mut total: u64 = 0;
    copy_tree_walk(src, dst, &mut count, &mut total)
}

fn copy_tree_walk(src: &Path, dst: &Path, count: &mut usize, total: &mut u64) -> Result<()> {
    for entry in fs::read_dir(src)
        .map_err(|e| FrfError::new(format!("cannot read {}: {e}", src.display())))?
    {
        let entry =
            entry.map_err(|e| FrfError::new(format!("cannot read {}: {e}", src.display())))?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        // symlink_metadata: inspect the entry itself, NEVER what it points at.
        let meta = fs::symlink_metadata(&from)
            .map_err(|e| FrfError::new(format!("cannot inspect {}: {e}", from.display())))?;
        let ft = meta.file_type();
        if ft.is_symlink() {
            return Err(FrfError::new(format!(
                "bundle directory refuses symlink {} — a bundle is self-contained evidence; a link could resolve outside it",
                from.display()
            )));
        }
        if ft.is_dir() {
            fs::create_dir_all(&to)
                .map_err(|e| FrfError::new(format!("cannot create {}: {e}", to.display())))?;
            copy_tree_walk(&from, &to, count, total)?;
        } else if ft.is_file() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if meta.nlink() > 1 {
                    return Err(FrfError::new(format!(
                        "bundle directory refuses hard-linked file {} — a hard link could share an inode outside the bundle",
                        from.display()
                    )));
                }
            }
            *count += 1;
            if *count > 10_000 {
                return Err(FrfError::new(
                    "bundle directory exceeds the 10 000-entry ceiling; refusing",
                ));
            }
            *total = total.saturating_add(meta.len());
            if *total > 1 << 30 {
                return Err(FrfError::new(
                    "bundle directory exceeds the 1 GiB ceiling; refusing",
                ));
            }
            fs::copy(&from, &to)
                .map_err(|e| FrfError::new(format!("cannot copy {}: {e}", from.display())))?;
        } else {
            return Err(FrfError::new(format!(
                "bundle directory refuses {} of unsupported type {:?}",
                from.display(),
                ft
            )));
        }
    }
    Ok(())
}

/// Extract a single-file bundle's tar archive into `root`, refusing hostile
/// archives: absolute or parent-escaped paths, symlinks and hard links (a
/// link could smuggle a read outside the bundle), and unbounded bombs (a
/// 10 000-entry / 1 GiB ceiling — the closure of one receipt is dozens of
/// files and a few MiB). Only regular files and directories are materialized.
fn extract_tar_into(bytes: &[u8], root: &Path) -> Result<()> {
    let mut archive = tar::Archive::new(bytes);
    let entries = archive.entries().map_err(|e| {
        FrfError::new(format!(
            "{} is not a readable single-file bundle (tar read failed: {e})",
            root.display()
        ))
    })?;
    let mut total: u64 = 0;
    let mut count: usize = 0;
    for entry in entries {
        let mut entry = entry.map_err(|e| {
            FrfError::new(format!("single-file bundle is corrupt (tar entry: {e})"))
        })?;
        let path = entry
            .path()
            .map_err(|e| FrfError::new(format!("single-file bundle is corrupt (entry path: {e})")))?
            .into_owned();
        if path.is_absolute()
            || path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(FrfError::new(format!(
                "single-file bundle refuses entry with path {path:?} (must stay inside the bundle)"
            )));
        }
        let etype = entry.header().entry_type();
        if etype.is_symlink() || etype.is_hard_link() {
            return Err(FrfError::new(format!(
                "single-file bundle refuses link entry {path:?}"
            )));
        }
        if !etype.is_file() && !etype.is_dir() {
            return Err(FrfError::new(format!(
                "single-file bundle refuses entry {path:?} of unsupported type {etype:?}"
            )));
        }
        count += 1;
        if count > 10_000 {
            return Err(FrfError::new(
                "single-file bundle exceeds the 10 000-entry ceiling; refusing",
            ));
        }
        if etype.is_file() {
            total = total.saturating_add(entry.size());
            if total > 1 << 30 {
                return Err(FrfError::new(
                    "single-file bundle exceeds the 1 GiB extraction ceiling; refusing",
                ));
            }
        }
        entry
            .unpack_in(root)
            .map_err(|e| FrfError::new(format!("cannot extract {}: {e}", path.display())))?;
    }
    Ok(())
}

/// A bundle that has been CONFINED and PROVEN — the ONE entry point for
/// bundle verification and replay. Both container forms are materialized
/// into a private temp tree (a directory bundle is COPIED by a confined walk
/// that refuses symlinks/hard links and enforces the same count/size caps as
/// the archive extractor; a single-file bundle is extracted by those same
/// rules), so the container format never changes the trust model: after
/// [`open_verified_bundle`] returns, every path lies inside a tree with no
/// links and no escapes, the manifest is a strict closed-schema document
/// with valid identifiers, and the exact inventory hashes. Only then are
/// paths/content exposed to the semantic layer.
pub struct VerifiedBundle {
    /// The safe tree: `manifest.json` at its root, every inventory file
    /// below it — guaranteed link-free and escape-free by construction.
    root: PathBuf,
    container: Container,
    manifest: BundleManifest,
    _temp: TempRoot,
}

impl VerifiedBundle {
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn container(&self) -> Container {
        self.container
    }

    pub fn manifest(&self) -> &BundleManifest {
        &self.manifest
    }
}

/// Open and PROVE a bundle: structural confinement walk (refuse
/// symlinks/hard links/escapes; enforce the count/size caps) → strict
/// canonical manifest (I-JSON, closed schema, every identifier validated) →
/// exact inventory (every entry exists and hashes to its recorded digest;
/// objects are named by their digest). The manifest's values may construct a
/// path only after ALL of this has passed.
pub fn open_verified_bundle(path: &Path) -> Result<VerifiedBundle> {
    let temp = TempRoot::new("bundle")?;
    let staged = temp.dir.join("extract");
    fs::create_dir_all(&staged)
        .map_err(|e| FrfError::new(format!("cannot create {}: {e}", staged.display())))?;
    let container = if path.is_dir() {
        // The directory bundle is COPIED by a confined walk: the source is
        // never read in place after the walk (a swap could smuggle a link in
        // between inspection and read), and the copy is the archive
        // extraction's identical trust model.
        copy_tree(path, &staged)?;
        Container::Directory
    } else if path.is_file() {
        let bytes = read(path, "bundle")?;
        extract_tar_into(&bytes, &staged)?;
        if !staged.join("manifest.json").is_file() {
            return Err(FrfError::new(format!(
                "{} is an incomplete single-file bundle: manifest.json is missing (truncated archive?)",
                path.display()
            )));
        }
        Container::SingleTar
    } else {
        return Err(FrfError::new(format!(
            "{} is neither a bundle directory nor a single-file bundle",
            path.display()
        )));
    };

    // The manifest: strict JSON (duplicates refused) + the closed schema +
    // valid identifiers — before ANY of its values construct a path.
    let manifest_bytes = fs::read(staged.join("manifest.json"))
        .map_err(|e| FrfError::new(format!("cannot read manifest.json: {e}")))?;
    let manifest = parse_bundle_manifest(&manifest_bytes)?;
    if manifest.container != container.as_str() {
        return Err(FrfError::new(format!(
            "bundle container mismatch: the manifest declares {:?} but the bundle is a {}",
            manifest.container,
            container.as_str()
        )));
    }

    // THE EXACT INVENTORY: every entry exists in the safe tree and hashes to
    // its recorded digest; an object file must be named by its digest.
    for entry in &manifest.inventory {
        let rel = &entry.path;
        let full = staged.join(rel);
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
        if actual != entry.sha256 {
            return Err(FrfError::new(format!(
                "bundle is corrupt: {rel} hashes to {} but the manifest records {}",
                &actual[..16],
                &entry.sha256[..16]
            )));
        }
        if entry.kind == "object" {
            let name = Path::new(rel)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            if name != entry.sha256 {
                return Err(FrfError::new(format!(
                    "bundle is corrupt: object file {rel} is not named by its digest"
                )));
            }
        }
    }

    Ok(VerifiedBundle {
        root: staged,
        container,
        manifest,
        _temp: temp,
    })
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

    // The compiled claims bound to this receipt, when present — every claim
    // in the by-receipt index (a receipt compiled under a different universe
    // or policy is a DIFFERENT claim, and a bundle carries them all) — plus
    // the EVIDENCE UNIVERSE each claim's knowledge snapshot names (the
    // negative search is as portable as the premises: the verifier must be
    // able to rehash every residual head, its events, its run, and the
    // reduction records the claim's absence search ran over). The snapshot's
    // residual heads are pushed as runs into the traversal below (a head's
    // record + its run's capture + authority + objects + series all enter the
    // closure that way).
    for claim_id in store.claim_ids_for_receipt(receipt_id)? {
        let claim_path = store.claim_path(&claim_id)?;
        let bytes = read(&claim_path, "claim")?;
        let rel = format!("claims/{claim_id}.json");
        entries.insert(
            rel.clone(),
            ClosureEntry {
                rel,
                sha256: host::sha256_bytes(&bytes),
                kind: "claim",
            },
        );
        // The non-normative by-receipt index marker travels with the claim:
        // a verifier resolves the receipt's claims through the index.
        let index_rel = format!("claims/by-receipt/{receipt_id}/{claim_id}");
        entries.insert(
            index_rel.clone(),
            ClosureEntry {
                rel: index_rel,
                sha256: host::sha256_bytes(receipt_id.as_bytes()),
                kind: "claim-index",
            },
        );
        let parsed: ClaimRecord = store.load_claim(&claim_id)?; // canonical + identity rederives
                                                                // The claim is MULTI-PREMISE since v6: every premise receipt's run is
                                                                // part of the evidence the claim was compiled under, so each premise's
                                                                // capture + objects + residuals + authorities enter the closure (the
                                                                // walk below picks them up by run id).
        for prem_id in &parsed.requires {
            let prem = crate::verify::load_receipt_verified(store, prem_id)?;
            // The premise receipt document itself is part of the closure (a
            // multi-premise claim's other premises are not the root receipt).
            let prem_bytes = read(&store.receipt_path(prem_id)?, "premise receipt")?;
            let prem_rel = format!("receipts/{prem_id}.json");
            entries.insert(
                prem_rel.clone(),
                ClosureEntry {
                    rel: prem_rel,
                    sha256: host::sha256_bytes(&prem_bytes),
                    kind: "receipt",
                },
            );
            if !runs.contains(&prem.body().run) {
                runs.push(prem.body().run.clone());
            }
        }
        // The capability evidence a sensitivity-backed claim was compiled
        // under: every content-addressed challenge record it names, and the
        // mutant run each challenge observed (the run traversal below picks
        // up its capture, objects, and residuals). Each capability entry
        // binds the PREMISE RECEIPT it covers: the challenge must be of that
        // premise's court and wrap that premise's reference artifact.
        for cap in &parsed.capability {
            if !parsed.requires.contains(&cap.receipt) {
                return Err(FrfError::new(format!(
                    "claim capability for axis {} binds premise {} which the claim does not require",
                    cap.axis, cap.receipt
                )));
            }
            let prem = crate::verify::load_receipt_verified(store, &cap.receipt)?;
            for chid in &cap.challenge_ids {
                let ch = store.load_challenge(chid)?; // verified: content-addressed
                if ch.court != prem.body().court.id
                    || ch.reference_sha256 != prem.body().authority.identity_hash
                {
                    return Err(FrfError::new(format!(
                        "claim capability for axis {} cites challenge {} which does not belong to premise {}'s court/reference",
                        cap.axis, chid, cap.receipt
                    )));
                }
                let bytes = read(&store.challenge_path(chid)?, "challenge")?;
                let rel = format!("challenges/{chid}.json");
                entries.insert(
                    rel.clone(),
                    ClosureEntry {
                        rel,
                        sha256: host::sha256_bytes(&bytes),
                        kind: "challenge",
                    },
                );
                // An external mutation proposal's preserved evidence (the
                // instrument that proposed the mutant): request + response +
                // invocation + result under `challenges/<id>/mutation/`.
                if ch.mutation_invocation_id.is_some() || ch.mutation_result_id.is_some() {
                    let mdir = store.challenge_mutation_dir(chid)?;
                    for f in [
                        "request.json",
                        "response.json",
                        "invocation.json",
                        "result.json",
                    ] {
                        let path = mdir.join(f);
                        if !path.is_file() {
                            continue;
                        }
                        let bytes = read(&path, "mutation evidence")?;
                        let rel = format!("challenges/{chid}/mutation/{f}");
                        entries.insert(
                            rel.clone(),
                            ClosureEntry {
                                rel,
                                sha256: host::sha256_bytes(&bytes),
                                kind: "mutation-evidence",
                            },
                        );
                    }
                }
                if !runs.contains(&ch.run) {
                    runs.push(ch.run.clone());
                }
            }
        }
        // The witness evidence an independently-witnessed claim was compiled
        // under: each verified statement (identity rederives, request +
        // response hash to their cids), its preserved documents, and the
        // witness PROGRAM object the attestation's implementation bound (the
        // independence evidence's typed refs point at it).
        for wid in &parsed.witness_statements {
            let stmt = crate::verify::load_witness_statement_verified(store, wid)?; // verified + subject rebound
            let bytes = read(&store.witness_path(wid)?, "witness statement")?;
            let rel = format!("witnesses/{wid}.json");
            entries.insert(
                rel.clone(),
                ClosureEntry {
                    rel,
                    sha256: host::sha256_bytes(&bytes),
                    kind: "witness",
                },
            );
            let inner = stmt.statement();
            if let Some(artifact) = &inner.witness_implementation.artifact {
                store.verified_object_bytes(&artifact.sha256)?;
                let rel = format!("objects/sha256/{}", artifact.sha256);
                entries.insert(
                    rel.clone(),
                    ClosureEntry {
                        rel,
                        sha256: artifact.sha256.clone(),
                        kind: "object",
                    },
                );
            }
            for f in ["request.json", "response.json"] {
                let path = store.witness_dir(&inner.id)?.join(f);
                let bytes = read(&path, "witness evidence")?;
                let rel = format!("witnesses/{}/{f}", inner.id);
                entries.insert(
                    rel.clone(),
                    ClosureEntry {
                        rel,
                        sha256: host::sha256_bytes(&bytes),
                        kind: "witness-evidence",
                    },
                );
            }
        }
        // The declared INDEPENDENCE evidence (v7): every verified
        // IndependenceEvidence record the claim carries (bound to its
        // witness statements).
        for iid in &parsed.independence_evidence {
            let _rec = store.load_independence(iid)?; // verified: content-addressed
            let bytes = read(&store.independence_path(iid)?, "independence evidence")?;
            let rel = format!("independence/{iid}.json");
            entries.insert(
                rel.clone(),
                ClosureEntry {
                    rel,
                    sha256: host::sha256_bytes(&bytes),
                    kind: "independence",
                },
            );
        }
        for head in &parsed.knowledge_snapshot.residual_heads {
            // The committed head's run enters the walk; the head is VERIFIED
            // (identity + derivation) and its content address must match the
            // committed universe before its run may drive the closure.
            let verified = crate::verify::load_residual_verified(store, &head.id)?;
            if !runs.contains(&verified.record().run) {
                runs.push(verified.record().run.clone());
            }
        }
        // The typed universe objects: the claim's absence search depended on
        // the EXACT bytes of every committed member, so the bundle carries
        // them ALL — reduction records (with their external-minimizer
        // evidence), the committed authorities (even one no run's capture
        // cites, e.g. a witness's admitted authority), the committed series,
        // and the committed receipts + runs (whose captures/objects/
        // residuals/authorities enter via the run walk below).
        for obj in &parsed.knowledge_snapshot.objects {
            match obj.kind.as_str() {
                "reduction" => {
                    let rid = &obj.id;
                    let r_path = store.reduction_path(rid)?;
                    let bytes = read(&r_path, "reduction")?;
                    let rel = format!("reductions/{rid}.json");
                    entries.insert(
                        rel.clone(),
                        ClosureEntry {
                            rel,
                            sha256: host::sha256_bytes(&bytes),
                            kind: "reduction",
                        },
                    );
                    // The external minimizer's invocation evidence, when the
                    // reduction binds one: `reductions/<id>/minimizer/`.
                    let rec = store.load_reduction(rid)?;
                    if rec.minimizer_invocation_id.is_some() {
                        let mdir = store.minimizer_dir(rid)?;
                        for f in [
                            "request.json",
                            "response.json",
                            "invocation.json",
                            "result.json",
                        ] {
                            let path = mdir.join(f);
                            if !path.is_file() {
                                continue;
                            }
                            let bytes = read(&path, "minimizer evidence")?;
                            let rel = format!("reductions/{rid}/minimizer/{f}");
                            entries.insert(
                                rel.clone(),
                                ClosureEntry {
                                    rel,
                                    sha256: host::sha256_bytes(&bytes),
                                    kind: "minimizer-evidence",
                                },
                            );
                        }
                    }
                }
                "authority" => {
                    // The universe commits the authority's canonical RECORD
                    // (its label is not its bytes); the bundle carries it
                    // even when no run's capture cites it.
                    let bytes = read(&store.authority_path(&obj.id)?, "authority")?;
                    let rel = format!("authorities/{}.json", obj.id);
                    entries.insert(
                        rel.clone(),
                        ClosureEntry {
                            rel,
                            sha256: host::sha256_bytes(&bytes),
                            kind: "authority",
                        },
                    );
                }
                "receipt" => {
                    // A committed universe receipt document + its run enter
                    // the closure (the run walk picks up the capture,
                    // objects, residuals, and the receipt's own authority).
                    let bytes = read(&store.receipt_path(&obj.id)?, "receipt")?;
                    let rel = format!("receipts/{}.json", obj.id);
                    entries.insert(
                        rel.clone(),
                        ClosureEntry {
                            rel,
                            sha256: host::sha256_bytes(&bytes),
                            kind: "receipt",
                        },
                    );
                    let rec: crate::model::Receipt =
                        store.parse_evidence(&store.receipt_path(&obj.id)?)?;
                    if !runs.contains(&rec.run) {
                        runs.push(rec.run.clone());
                    }
                }
                "run" => {
                    // A committed universe run enters the walk.
                    if !runs.contains(&obj.id) {
                        runs.push(obj.id.clone());
                    }
                }
                "series" => {
                    // The series id IS its content address; the bundle
                    // carries the record.
                    let bytes = read(&store.series_path(&obj.id)?, "series")?;
                    let rel = format!("series/{}.json", obj.id);
                    entries.insert(
                        rel.clone(),
                        ClosureEntry {
                            rel,
                            sha256: host::sha256_bytes(&bytes),
                            kind: "series",
                        },
                    );
                }
                other => {
                    return Err(FrfError::new(format!(
                        "claim {claim_id}: the knowledge universe names an unknown object kind {other:?} — only receipt/run/authority/series/reduction are universe members"
                    )));
                }
            }
        }
    }

    while let Some(run) = runs.pop() {
        if !seen_runs.insert(run.clone()) {
            continue;
        }
        let cv = crate::verify::load_capture_verified(store, &run)?;
        let cap = &cv.capture;
        let dir = store.run_dir(&run)?;

        // Capture manifest + raw side files (the derived projections rehash
        // against the raw bytes during verification).
        let mut names = vec!["capture.json".to_string()];
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
            let kind = if name == "capture.json" {
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

        // The PRODUCED ARTIFACT trees (the filesystem-tree surface): every
        // file a side built is copied under the run; the closure carries them
        // so verification rehashes the trees without executing anything.
        let produced_root = dir.join("produced");
        if produced_root.is_dir() {
            for side in ["reference", "candidate"] {
                let side_root = produced_root.join(side);
                if !side_root.is_dir() {
                    continue;
                }
                let mut pending: Vec<std::path::PathBuf> = vec![side_root.clone()];
                while let Some(d) = pending.pop() {
                    for entry in std::fs::read_dir(&d).map_err(|e| {
                        FrfError::new(format!("cannot read produced tree {}: {e}", d.display()))
                    })? {
                        let entry = entry.map_err(|e| {
                            FrfError::new(format!("cannot read produced tree {}: {e}", d.display()))
                        })?;
                        let path = entry.path();
                        if entry
                            .file_type()
                            .map_err(|e| {
                                FrfError::new(format!(
                                    "cannot inspect produced artifact {}: {e}",
                                    path.display()
                                ))
                            })?
                            .is_dir()
                        {
                            pending.push(path);
                            continue;
                        }
                        let rel = format!(
                            "captures/{run}/{}",
                            path.strip_prefix(&dir)
                                .map_err(|_| {
                                    FrfError::new(format!(
                                        "produced artifact {} escapes the run dir",
                                        path.display()
                                    ))
                                })?
                                .to_string_lossy()
                        );
                        let bytes = read(&path, "produced artifact")?;
                        entries.insert(
                            rel.clone(),
                            ClosureEntry {
                                rel,
                                sha256: host::sha256_bytes(&bytes),
                                kind: "produced",
                            },
                        );
                    }
                }
            }
        }

        // The admitted authority record: the receipt cites the authority by
        // id, so the admission evidence is part of the closure (authorities
        // are never rewritten; the bundle carries the exact admission).
        let authority_path = store.authority_path(&cap.authority)?;
        let bytes = read(&authority_path, "authority")?;
        let rel = format!("authorities/{}.json", cap.authority);
        entries.insert(
            rel.clone(),
            ClosureEntry {
                rel,
                sha256: host::sha256_bytes(&bytes),
                kind: "authority",
            },
        );

        // The harness events recorded during this run's observation (v15):
        // the content-addressed bound-firing records the capture cites (today
        // the CPU limit's SIGXCPU, which completes as a valid observation).
        // Each is verified (canonical + self-authenticating) before it may
        // leave the tree — a refusal's enforcement evidence is as portable
        // as the observation it annotated.
        for h in &cap.harness_events {
            store.load_harness_event(h)?; // canonical + identity rederives
            let path = store.harness_path(h)?;
            let bytes = read(&path, "harness event")?;
            let rel = format!("harness/{h}.json");
            entries.insert(
                rel.clone(),
                ClosureEntry {
                    rel,
                    sha256: host::sha256_bytes(&bytes),
                    kind: "harness-event",
                },
            );
        }

        // Content-addressed execution snapshots + instrumentation: walk the
        // capture's typed EVIDENCE REFERENCES (the generic graph traversal),
        // so adding a comparator implementation — or later a witness,
        // normalizer, or minimization run — needs no closure-walker edit. A
        // capture from an earlier version may carry no refs; fall back to the
        // recorded artifact hashes so old evidence still exports.
        let refs: Vec<String> = if cap.evidence_refs.is_empty() {
            vec![
                cap.authority_artifact.sha256.clone(),
                cap.candidate_artifact.sha256.clone(),
                cap.fixture_sha256.clone(),
            ]
        } else {
            cap.evidence_refs
                .iter()
                .filter(|r| r.object_kind == "object")
                .map(|r| r.cid.clone())
                .collect()
        };
        for h in refs {
            // verified_object_bytes refuses a missing or corrupt snapshot.
            store.verified_object_bytes(&h)?;
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

        // Comparator invocation evidence (externally served axes): the
        // canonical request + response documents and the content-addressed
        // invocation + result records — part of the instrumentation that
        // produced the observation.
        let comparator_dir = dir.join("comparator");
        if comparator_dir.is_dir() {
            let mut axes: Vec<String> = std::fs::read_dir(&comparator_dir)
                .map_err(|e| {
                    FrfError::new(format!(
                        "cannot read comparator evidence directory {}: {e}",
                        comparator_dir.display()
                    ))
                })?
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            axes.sort();
            for axis in axes {
                for f in [
                    "request.json",
                    "response.json",
                    "invocation.json",
                    "result.json",
                ] {
                    let path = comparator_dir.join(&axis).join(f);
                    if !path.is_file() {
                        continue;
                    }
                    let bytes = read(&path, "comparator evidence")?;
                    let rel = format!("captures/{run}/comparator/{axis}/{f}");
                    entries.insert(
                        rel.clone(),
                        ClosureEntry {
                            rel,
                            sha256: host::sha256_bytes(&bytes),
                            kind: match f {
                                "request.json" => "comparator-request",
                                "response.json" => "comparator-response",
                                "invocation.json" => "comparator-invocation",
                                _ => "comparator-result",
                            },
                        },
                    );
                }
            }
        }

        // Normalizer invocation evidence (the comparison-surface instruments):
        // `captures/<run>/normalizer/<id>/<side>/` — the canonical request +
        // response and the content-addressed invocation + result records, so
        // the exact normalization that built the compared streams is in the
        // closure.
        let normalizer_dir = dir.join("normalizer");
        if normalizer_dir.is_dir() {
            let mut ids: Vec<String> = std::fs::read_dir(&normalizer_dir)
                .map_err(|e| {
                    FrfError::new(format!(
                        "cannot read normalizer evidence directory {}: {e}",
                        normalizer_dir.display()
                    ))
                })?
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            ids.sort();
            for id in ids {
                let mut sides: Vec<String> = std::fs::read_dir(normalizer_dir.join(&id))
                    .map_err(|e| {
                        FrfError::new(format!(
                            "cannot read normalizer evidence directory {}: {e}",
                            normalizer_dir.join(&id).display()
                        ))
                    })?
                    .flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect();
                sides.sort();
                for side in sides {
                    for f in [
                        "request.json",
                        "response.json",
                        "invocation.json",
                        "result.json",
                    ] {
                        let path = normalizer_dir.join(&id).join(&side).join(f);
                        if !path.is_file() {
                            continue;
                        }
                        let bytes = read(&path, "normalizer evidence")?;
                        let rel = format!("captures/{run}/normalizer/{id}/{side}/{f}");
                        entries.insert(
                            rel.clone(),
                            ClosureEntry {
                                rel,
                                sha256: host::sha256_bytes(&bytes),
                                kind: "normalizer-evidence",
                            },
                        );
                    }
                }
            }
        }
        // Capture-adapter invocation evidence (the adapted-observation
        // instruments): `captures/<run>/capture-adapter/<axis>/<side>/`.
        let adapter_dir = dir.join("capture-adapter");
        if adapter_dir.is_dir() {
            let mut axes: Vec<String> = std::fs::read_dir(&adapter_dir)
                .map_err(|e| {
                    FrfError::new(format!(
                        "cannot read capture-adapter evidence directory {}: {e}",
                        adapter_dir.display()
                    ))
                })?
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            axes.sort();
            for axis in axes {
                let mut sides: Vec<String> = std::fs::read_dir(adapter_dir.join(&axis))
                    .map_err(|e| {
                        FrfError::new(format!(
                            "cannot read capture-adapter evidence directory {}: {e}",
                            adapter_dir.join(&axis).display()
                        ))
                    })?
                    .flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect();
                sides.sort();
                for side in sides {
                    for f in [
                        "request.json",
                        "response.json",
                        "invocation.json",
                        "result.json",
                    ] {
                        let path = adapter_dir.join(&axis).join(&side).join(f);
                        if !path.is_file() {
                            continue;
                        }
                        let bytes = read(&path, "capture-adapter evidence")?;
                        let rel = format!("captures/{run}/capture-adapter/{axis}/{side}/{f}");
                        entries.insert(
                            rel.clone(),
                            ClosureEntry {
                                rel,
                                sha256: host::sha256_bytes(&bytes),
                                kind: "capture-adapter-evidence",
                            },
                        );
                    }
                }
            }
        }

        // Residual records + disposition-event chains; a `fixed` event adds
        // its resolution run to the closure (the graph traversal). The
        // residual LEAF lives inside its run (the transactional root — the
        // bundle carries it at its canonical path); the top-level
        // `residuals/<id>.json` copy is the DERIVED INDEX, carried too so
        // the unpacked store is immediately consistent (byte-identical).
        for id in &cap.residuals {
            if !seen_residuals.insert(id.clone()) {
                continue;
            }
            let leaf_path = store.residual_leaf_path(&cap.run, id)?;
            let bytes = read(&leaf_path, "residual")?;
            let rel = format!("captures/{}/residuals/{id}.json", cap.run);
            entries.insert(
                rel.clone(),
                ClosureEntry {
                    rel,
                    sha256: host::sha256_bytes(&bytes),
                    kind: "residual",
                },
            );
            // The derived index copy (byte-identical to the leaf).
            let idx_rel = format!("residuals/{id}.json");
            entries.insert(
                idx_rel.clone(),
                ClosureEntry {
                    rel: idx_rel,
                    sha256: host::sha256_bytes(&bytes),
                    kind: "residual-index",
                },
            );
            // The verified event chain (identity rederives, parents link).
            let events = store.disposition_events(id)?;
            let ev_dir = store.events_dir(id)?;
            for (i, e) in events.iter().enumerate() {
                let path = ev_dir.join(format!("{:04}.json", i + 1));
                let bytes = read(&path, "disposition event")?;
                let rel = format!("residuals/{id}.events/{:04}.json", i + 1);
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
                if let Disposition::Nonreproduced {
                    observation_run_id, ..
                } = &e.disposition
                {
                    runs.push(observation_run_id.clone());
                }
                // A stabilized event's evidence edge is the trajectory
                // DOCUMENT, which lives under `trajectories/` and is already
                // swept by the namespace walker; the series it derives from
                // travels with the receipt's sign evidence.
            }
            // Refused external-minimizer proposals: a content-addressed
            // minimizer refusal under `residuals/<id>.minimizer/<request_cid>/`
            // is itself evidence and travels with the residual.
            let minimizer_evidence_root = store
                .residual_path(id)?
                .parent()
                .expect("residual path has a parent")
                .join(format!("{id}.minimizer"));
            if minimizer_evidence_root.is_dir() {
                let mut cids: Vec<String> = std::fs::read_dir(&minimizer_evidence_root)
                    .map_err(|e| {
                        FrfError::new(format!(
                            "cannot read minimizer evidence directory {}: {e}",
                            minimizer_evidence_root.display()
                        ))
                    })?
                    .flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect();
                cids.sort();
                for cid in cids {
                    for f in [
                        "request.json",
                        "response.json",
                        "invocation.json",
                        "result.json",
                    ] {
                        let path = minimizer_evidence_root.join(&cid).join(f);
                        if !path.is_file() {
                            continue;
                        }
                        let bytes = read(&path, "minimizer evidence")?;
                        let rel = format!("residuals/{id}.minimizer/{cid}/{f}");
                        entries.insert(
                            rel.clone(),
                            ClosureEntry {
                                rel,
                                sha256: host::sha256_bytes(&bytes),
                                kind: "minimizer-evidence",
                            },
                        );
                    }
                }
            }
            // The series experiments this run belongs to, and the derived
            // trajectories the receipt's signs read from: a run never knows
            // its experiments, so the closure walks the series records that
            // reference it and carries each series snapshot + its trajectories
            // for the run's residual lineages.
            let series = store.series_containing_run(&run)?;
            let mut seen_series: std::collections::BTreeSet<String> = Default::default();
            for s in &series {
                if !seen_series.insert(s.id.clone()) {
                    continue;
                }
                let s_path = store.series_path(&s.id)?;
                let bytes = read(&s_path, "series")?;
                let rel = format!("series/{}.json", s.id);
                entries.insert(
                    rel.clone(),
                    ClosureEntry {
                        rel,
                        sha256: host::sha256_bytes(&bytes),
                        kind: "series",
                    },
                );
                // The series' OTHER points' runs travel too: the receipt
                // PINNED this series (its trajectory signs read from it), so
                // the bundle must be able to RE-DERIVE the trajectory from
                // the pinned series — every point's run, its capture, its
                // residuals, and their objects are part of the closure.
                for point in &s.points {
                    runs.push(point.run.clone());
                }
                // Trajectories for the lineages this run's residuals belong
                // to, within this series. The residual is VERIFIED before its
                // lineage may name the trajectory file.
                let verified = crate::verify::load_residual_verified(store, id)?;
                let lineage =
                    crate::semantics::residual_lineage_of_record(store, verified.record())?;
                let t_path = store.trajectory_path(&lineage, &s.coordinate_system, &s.id)?;
                if t_path.is_file() {
                    let bytes = read(&t_path, "trajectory")?;
                    let rel = format!(
                        "trajectories/{}.{}.{}.json",
                        lineage, s.coordinate_system, s.id
                    );
                    entries.insert(
                        rel.clone(),
                        ClosureEntry {
                            rel,
                            sha256: host::sha256_bytes(&bytes),
                            kind: "trajectory",
                        },
                    );
                }
            }
        }
    }

    // The REFUSED execution attempts recorded for this court (the refusal-
    // roots): a failed observation attempt is itself a first-class portable
    // observation, and a bundle of this court's evidence carries its refusal
    // history alongside the successful runs. Each attempt is VERIFIED (canonical
    // + identity rederives + every cited harness event verified) before it may
    // leave the tree, and its content-addressed harness events travel with it.
    let attempts_dir = store.attempts_dir();
    if attempts_dir.is_dir() {
        let mut names: Vec<String> = std::fs::read_dir(&attempts_dir)
            .map_err(|e| {
                FrfError::new(format!(
                    "cannot read execution-attempt directory {}: {e}",
                    attempts_dir.display()
                ))
            })?
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".json"))
            .collect();
        names.sort();
        for name in names {
            let id = name.trim_end_matches(".json").to_string();
            let verified = crate::verify::load_execution_attempt_verified(store, &id)?;
            let attempt = verified.record();
            if attempt.court != body.court.id {
                continue;
            }
            let bytes = read(&store.attempt_path(&id)?, "execution attempt")?;
            let rel = format!("attempts/{id}.json");
            entries.insert(
                rel.clone(),
                ClosureEntry {
                    rel,
                    sha256: host::sha256_bytes(&bytes),
                    kind: "execution-attempt",
                },
            );
            for eid in &attempt.harness_events {
                store.load_harness_event(eid)?; // canonical + identity rederives
                let path = store.harness_path(eid)?;
                let bytes = read(&path, "harness event")?;
                let rel = format!("harness/{eid}.json");
                entries.insert(
                    rel.clone(),
                    ClosureEntry {
                        rel,
                        sha256: host::sha256_bytes(&bytes),
                        kind: "harness-event",
                    },
                );
            }
        }
    }

    // The claim (if any) and its knowledge universe were added up front; the
    // closure is complete.
    Ok(Closure {
        run: body.run.clone(),
        entries: entries.into_values().collect(),
    })
}

/// A tar header with the bundle's deterministic metadata: sealed 0444,
/// epoch mtime, root ownership — two exports of the same receipt produce
/// byte-identical archives.
fn bundle_tar_header(bytes: &[u8]) -> tar::Header {
    let mut header = tar::Header::new_gnu();
    header.set_mode(0o444);
    header.set_mtime(0);
    header.set_uid(0);
    header.set_gid(0);
    header.set_size(bytes.len() as u64);
    header
}

/// Export a receipt's portable closure. Only verified evidence may leave the
/// tree; the bundle is written fresh (never overwritten) and the manifest —
/// the content-addressed inventory, declaring its own container form — is
/// written last, so a partially failed export is never mistaken for a bundle.
pub fn export(
    store: &Store,
    receipt_id: &str,
    output: &Path,
    container: Container,
) -> Result<PathBuf> {
    let closure = collect_closure(store, receipt_id)?;
    // The manifest's role vocabulary is CLOSED: every closure role must be
    // registered (a new role is a protocol change, never a silent manifest
    // extension — parse_bundle_manifest refuses roles outside this set).
    for entry in &closure.entries {
        if !BUNDLE_KINDS.contains(&entry.kind) {
            return Err(FrfError::new(format!(
                "closure role {:?} is not in the registered bundle vocabulary; refusing to export a manifest the verifiers would reject",
                entry.kind
            )));
        }
    }
    if output.exists() {
        return Err(FrfError::new(format!(
            "bundle {} already exists; refusing to overwrite (remove it to re-export)",
            output.display()
        )));
    }

    // Read every closure file up front so a missing/corrupt object fails the
    // export before a single byte of the bundle is written.
    let mut payloads: Vec<(&ClosureEntry, Vec<u8>)> = Vec::new();
    let mut inventory: Vec<Value> = Vec::new();
    for entry in &closure.entries {
        let bytes = read(&store.root.join(&entry.rel), "closure file")?;
        payloads.push((entry, bytes));
        inventory.push(json!({
            "path": entry.rel,
            "sha256": entry.sha256,
            "kind": entry.kind,
        }));
    }
    let manifest = json!({
        "schema_version": SCHEMA_BUNDLE,
        "container": container.as_str(),
        "receipt_id": receipt_id,
        "run": closure.run,
        "created_by": {
            "frf_version": env!("CARGO_PKG_VERSION"),
            "frf_executable_hash": host::current_exe_hash()?,
        },
        "inventory": inventory,
    });
    let manifest_bytes = crate::canon::canonical(&manifest)?;

    match container {
        Container::Directory => {
            fs::create_dir_all(output)
                .map_err(|e| FrfError::new(format!("cannot create {}: {e}", output.display())))?;
            for (entry, bytes) in &payloads {
                let dst = output.join(&entry.rel);
                if let Some(parent) = dst.parent() {
                    fs::create_dir_all(parent).map_err(|e| {
                        FrfError::new(format!("cannot create {}: {e}", parent.display()))
                    })?;
                }
                fs::write(&dst, bytes)
                    .map_err(|e| FrfError::new(format!("cannot write {}: {e}", dst.display())))?;
                // Sealed read-only: the bundle is evidence, not a working
                // tree. Replay re-materializes through the store, which
                // re-seals what it executes (in a temp copy, never here).
                host::set_permissions(&dst, 0o444)?;
            }
            fs::write(output.join("manifest.json"), &manifest_bytes)
                .map_err(|e| FrfError::new(format!("cannot write manifest.json: {e}")))?;
        }
        Container::SingleTar => {
            // One deterministic archive: closure entries in path order (the
            // closure is sorted), fixed metadata, manifest last.
            let mut builder = tar::Builder::new(Vec::new());
            for (entry, bytes) in &payloads {
                let mut header = bundle_tar_header(bytes);
                builder
                    .append_data(&mut header, &entry.rel, &bytes[..])
                    .map_err(|e| {
                        FrfError::new(format!("cannot seal {} into the bundle: {e}", entry.rel))
                    })?;
            }
            let mut header = bundle_tar_header(manifest_bytes.as_bytes());
            builder
                .append_data(&mut header, "manifest.json", manifest_bytes.as_bytes())
                .map_err(|e| FrfError::new(format!("cannot seal manifest.json: {e}")))?;
            let archive = builder
                .into_inner()
                .map_err(|e| FrfError::new(format!("cannot finish the bundle archive: {e}")))?;
            fs::write(output, archive)
                .map_err(|e| FrfError::new(format!("cannot write {}: {e}", output.display())))?;
        }
    }

    eprintln!(
        "bundle {}: {} file(s) in the closure of receipt {receipt_id} ({})",
        output.display(),
        closure.entries.len(),
        container.as_str()
    );
    Ok(output.to_path_buf())
}

/// Verify a bundle: (0) the structural confinement walk + strict manifest +
/// exact inventory ([`open_verified_bundle`]), then (1) the receipt verifies
/// against the bundled evidence alone, and (2) the manifest's inventory
/// covers the receipt's complete required closure. Only the bundle is
/// touched — the original source tree and the exporting FRF installation are
/// irrelevant; both container forms are proven from a private safe tree and
/// never mutated.
pub fn verify(bundle_root: &Path) -> Result<()> {
    let verified = open_verified_bundle(bundle_root)?;
    let closure = verify_bundle_contents(&verified)?;
    println!(
        "bundle {} verified: receipt {}, run {}, {} file(s) in the closure ({})",
        verified.root().display(),
        verified.manifest().receipt_id,
        closure.run,
        closure.entries.len(),
        verified.container().as_str()
    );
    Ok(())
}

/// The semantic layer over a PROVEN bundle: the receipt verifies against the
/// bundle alone (identity + derivation + event chains + resolution edges —
/// the same verified loaders used everywhere), and the manifest's inventory
/// covers the receipt's complete required closure, recomputed from the
/// bundle. `open_verified_bundle` has already confined the tree, validated
/// the manifest, and proven the exact inventory — nothing here may construct
/// a path outside the safe tree.
pub fn verify_bundle_contents(verified: &VerifiedBundle) -> Result<Closure> {
    let root = verified.root();
    let manifest = &verified.manifest();
    let mut inventory: HashMap<String, (&str, &str)> = HashMap::new(); // rel -> (sha256, kind)
    for entry in &manifest.inventory {
        inventory.insert(
            entry.path.clone(),
            (entry.sha256.as_str(), entry.kind.as_str()),
        );
    }
    let store = Store::new(root.to_path_buf());
    let closure = collect_closure(&store, &manifest.receipt_id)?;
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
    Ok(closure)
}

/// `frf bundle replay BUNDLE.frf [--policy exact|semantic]`: re-execute the
/// bundle's snapshots under a checked environment, from the bundle ALONE.
///
/// The bundle is first proven against itself (manifest, closure, receipt —
/// the same verified loaders as `verify`), then the receipt is replayed with
/// the exact/semantic reproduction policy from a temp store materialized
/// from the bundle. The bundle carries everything replay needs — snapshots,
/// argv, environment, profile, bounds, interpreter chains, residuals,
/// comparator evidence — so the original source tree and the exporting FRF
/// installation are irrelevant.
///
/// The temp store is laid out under the receipt's declared evidence root
/// (`replay.evidence_root`, the `--root` the observation ran under), and the
/// sides execute from the reconstructed invocation root: a recorded
/// root-relative argv path like `frf/objects/sha256/<H>` resolves to the
/// BUNDLE's own verified object, so the sides never silently read the
/// surrounding tree (or miss the fixture entirely). The sealed bundle —
/// directory or archive — is never mutated; re-materialization re-seals
/// what it executes inside the temp copy, and a read-only bundle stays
/// replayable.
pub fn replay_bundle(bundle_path: &Path, policy: &str) -> Result<()> {
    // The bundle must prove itself BEFORE anything is copied, staged, or
    // replayed from it: `open_verified_bundle` confines the bytes (the same
    // structural rules for both container forms), parses the manifest
    // strictly, validates every identifier, and proves the exact inventory —
    // only then does replay read anything out of the safe tree.
    let verified = open_verified_bundle(bundle_path)?;
    verify_bundle_contents(&verified)?;
    let receipt_id = verified.manifest().receipt_id.clone();
    let temp = TempRoot::new("replay")?;
    let staged = verified.root();

    // The evidence root decides the reconstructed layout: the store lives at
    // <temp>/<evidence_root>, and the sides run from <temp>, so recorded
    // argv paths (which embed the observation's --root) resolve to the
    // bundle's objects. The value is read from the PROVEN receipt inside the
    // safe tree, and it is contained: absolute or parent-escaped roots are
    // refused up front.
    let receipt_text = fs::read_to_string(staged.join(format!("receipts/{receipt_id}.json")))
        .map_err(|e| FrfError::new(format!("cannot read {receipt_id}: {e}")))?;
    let receipt: Value = serde_json::from_str(&receipt_text)
        .map_err(|e| FrfError::new(format!("{receipt_id} is not valid JSON: {e}")))?;
    let evidence_root = receipt["replay"]["evidence_root"].as_str().unwrap_or("");
    let root_rel = Path::new(evidence_root);
    if evidence_root.is_empty()
        || root_rel.is_absolute()
        || root_rel
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(FrfError::new(format!(
            "receipt {receipt_id}: the evidence root {evidence_root:?} is not a contained relative path; refusing to reconstruct the layout"
        )));
    }
    let store_root = temp.dir.join(evidence_root);
    fs::create_dir_all(&store_root)
        .map_err(|e| FrfError::new(format!("cannot create {}: {e}", store_root.display())))?;
    // The safe tree is proven link-free, so this copy is a pure layout move;
    // it still goes through the confined walk (one code path, one trust
    // model).
    copy_tree(staged, &store_root)?;

    eprintln!(
        "bundle replay: replaying {} from {} (the bundle alone)",
        receipt_id,
        bundle_path.display()
    );
    // The replay pipeline (replay::run) resolves the receipt id inside the
    // temp store, enforces its expected_run_identity, rederives the run
    // identity, applies the drift gate, and requires the observation to
    // reproduce byte-for-byte — with the sides executing from the
    // reconstructed invocation root (<temp>), so their argv paths resolve to
    // the bundle's own objects.
    let store = Store::new(store_root);
    crate::commands::replay::run(&store, &receipt_id, policy, &temp.dir)?;
    Ok(())
}
