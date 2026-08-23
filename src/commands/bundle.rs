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

/// Copy a bundle directory tree into `dst` (which must exist).
fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    for entry in fs::read_dir(src)
        .map_err(|e| FrfError::new(format!("cannot read {}: {e}", src.display())))?
    {
        let entry =
            entry.map_err(|e| FrfError::new(format!("cannot read {}: {e}", src.display())))?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if from.is_dir() {
            fs::create_dir_all(&to)
                .map_err(|e| FrfError::new(format!("cannot create {}: {e}", to.display())))?;
            copy_tree(&from, &to)?;
        } else {
            fs::copy(&from, &to)
                .map_err(|e| FrfError::new(format!("cannot copy {}: {e}", from.display())))?;
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

/// Open a bundle for reading. A directory is used in place; a single-file
/// archive is extracted to a temp root (the archive itself is never
/// mutated). Neither form writes anything.
enum OpenedBundle {
    Directory(PathBuf),
    Extracted { root: PathBuf, _temp: TempRoot },
}

impl OpenedBundle {
    fn root(&self) -> &Path {
        match self {
            OpenedBundle::Directory(p) => p,
            OpenedBundle::Extracted { root, .. } => root,
        }
    }

    fn container(&self) -> Container {
        match self {
            OpenedBundle::Directory(_) => Container::Directory,
            OpenedBundle::Extracted { .. } => Container::SingleTar,
        }
    }
}

fn open_bundle(path: &Path) -> Result<OpenedBundle> {
    if path.is_dir() {
        return Ok(OpenedBundle::Directory(path.to_path_buf()));
    }
    if path.is_file() {
        let bytes = read(path, "bundle")?;
        let temp = TempRoot::new("open")?;
        extract_tar_into(&bytes, &temp.dir)?;
        if !temp.dir.join("manifest.json").is_file() {
            return Err(FrfError::new(format!(
                "{} is an incomplete single-file bundle: manifest.json is missing (truncated archive?)",
                path.display()
            )));
        }
        return Ok(OpenedBundle::Extracted {
            root: temp.dir.clone(),
            _temp: temp,
        });
    }
    Err(FrfError::new(format!(
        "{} is neither a bundle directory nor a single-file bundle",
        path.display()
    )))
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
        // its resolution run to the closure (the graph traversal).
        for id in &cap.residuals {
            if !seen_residuals.insert(id.clone()) {
                continue;
            }
            let rec_path = store.residual_path(id)?;
            let bytes = read(&rec_path, "residual")?;
            let rel = format!("residuals/{id}.json");
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

/// Verify a bundle: (0) its manifest declares the container it actually is,
/// (1) every inventory file exists and hashes to its recorded digest
/// (objects must be named by their digest), (2) the receipt verifies against
/// the bundled evidence alone, and (3) the manifest's inventory covers the
/// receipt's complete required closure. Only the bundle is touched — the
/// original source tree and the exporting FRF installation are irrelevant;
/// a single-file archive is verified from a temp extraction and never
/// mutated.
pub fn verify(bundle_root: &Path) -> Result<()> {
    let opened = open_bundle(bundle_root)?;
    verify_root(opened.root(), opened.container())
}

/// Verify an opened bundle root (a directory) against its declared container.
fn verify_root(root: &Path, container: Container) -> Result<()> {
    let manifest_path = root.join("manifest.json");
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
    let declared = manifest["container"].as_str().unwrap_or("<missing>");
    if declared != container.as_str() {
        return Err(FrfError::new(format!(
            "bundle container mismatch: the manifest declares {declared:?} but the bundle is a {}",
            container.as_str()
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
        let full = root.join(rel);
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
    let store = Store::new(root.to_path_buf());
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
        "bundle {} verified: receipt {receipt_id}, run {}, {} file(s) in the closure ({})",
        root.display(),
        closure.run,
        closure.entries.len(),
        container.as_str()
    );
    Ok(())
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
    // Always replay from a mutable temp copy of the bundle.
    let temp = TempRoot::new("replay")?;
    let container = if bundle_path.is_dir() {
        // Stage into a flat extraction dir first so the receipt's evidence
        // root can decide the final layout.
        let staged = temp.dir.join("extract");
        fs::create_dir_all(&staged)
            .map_err(|e| FrfError::new(format!("cannot create {}: {e}", staged.display())))?;
        copy_tree(bundle_path, &staged)?;
        Container::Directory
    } else if bundle_path.is_file() {
        let bytes = read(bundle_path, "bundle")?;
        let staged = temp.dir.join("extract");
        fs::create_dir_all(&staged)
            .map_err(|e| FrfError::new(format!("cannot create {}: {e}", staged.display())))?;
        extract_tar_into(&bytes, &staged)?;
        if !staged.join("manifest.json").is_file() {
            return Err(FrfError::new(format!(
                "{} is an incomplete single-file bundle: manifest.json is missing (truncated archive?)",
                bundle_path.display()
            )));
        }
        Container::SingleTar
    } else {
        return Err(FrfError::new(format!(
            "{} is neither a bundle directory nor a single-file bundle",
            bundle_path.display()
        )));
    };

    // The evidence root decides the reconstructed layout: the store lives at
    // <temp>/<evidence_root>, and the sides run from <temp>, so recorded
    // argv paths (which embed the observation's --root) resolve to the
    // bundle's objects. The value is a claim until verified, but it is
    // contained: absolute or parent-escaped roots are refused up front.
    let staged = temp.dir.join("extract");
    let manifest_text = fs::read_to_string(staged.join("manifest.json"))
        .map_err(|e| FrfError::new(format!("cannot read manifest.json: {e}")))?;
    let manifest: Value = serde_json::from_str(&manifest_text)
        .map_err(|e| FrfError::new(format!("manifest.json is not valid JSON: {e}")))?;
    let receipt_id = manifest["receipt_id"]
        .as_str()
        .ok_or_else(|| FrfError::new("manifest.json carries no receipt_id"))?
        .to_string();
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
    copy_tree(&staged, &store_root)?;
    fs::remove_dir_all(&staged)
        .map_err(|e| FrfError::new(format!("cannot remove {}: {e}", staged.display())))?;

    // The bundle must prove itself before anything is replayed from it.
    verify_root(&store_root, container)?;

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
