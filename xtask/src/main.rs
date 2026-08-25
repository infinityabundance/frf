//! xtask — the independent FRF verifier.
//!
//! A deliberately small SECOND implementation of the FRF protocol, with NO
//! dependency on the `frf` reference engine and NO execution. It loads an
//! OpenReceipt bundle, verifies every content address, runs the structural
//! and semantic conformance rules, walks the evidence graph, rederives court
//! identities, residual fingerprints, kappa tokens, trajectory signs and
//! disposition-event chains, verifies the receipt, and derives the
//! admissible Claim IR — from the bundle alone, with no original source tree
//! and no `frf` installation.
//!
//! If the Rust reference engine and this verifier agree on the same bundle
//! and the same corpus, FRF is a protocol, not a Rust file format. The
//! conformance corpus (conformance/) is the shared oracle both
//! implementations must pass.
//!
//! Modes:
//!   cargo xtask verify bundle <dir>              verify a bundle (exit 0)
//!   cargo xtask verify corpus <conformance-dir>  run the structural + semantic corpus
//!
//! The RFC 8785 canonicalizer below is implemented from the RFC, not
//! imported from the reference engine.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

mod experiment;
mod experiment_external;
mod experiment_external_v2;
mod experiment_external_v3;
mod experiment_external_v4;
mod experiment_external_v5;
mod jcs;
mod rederive;
mod regen;
mod regen_readme;
mod rules;
mod schema;

use jcs::{encode, parse_strict};
use rederive::*;
use rules::*;

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

fn load_json(path: &Path) -> Value {
    let bytes = read(path);
    parse_strict(&bytes).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// Load a generated EVIDENCE document: strict JSON (duplicate properties
/// refused), and the bytes must BE the canonical serialization of the parsed
/// document — the same canonical-JSON rule as the receipt. The independent
/// verifier deliberately parses evidence with its own strict JSON reader, not
/// a YAML parser: FRF's representations are canonical JSON, so a second
/// implementation that parses the same bytes reaches the same verdict without
/// sharing any parsing library with the reference engine.
fn load_evidence(path: &Path) -> Value {
    let bytes = read(path);
    let parsed = parse_strict(&bytes).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let canonical =
        encode(&parsed).unwrap_or_else(|e| panic!("{}: cannot canonicalize: {e}", path.display()));
    if canonical.as_bytes() != bytes {
        panic!(
            "{}: the document is not its own canonical serialization (RFC 8785); refusing to verify a non-canonical evidence document",
            path.display()
        );
    }
    parsed
}

fn safe_rel(bundle: &Path, rel: &str) -> std::path::PathBuf {
    if rel.starts_with('/') || rel.split('/').any(|c| c == "..") {
        panic!("inventory path {rel:?} escapes the bundle");
    }
    bundle.join(rel)
}

fn as_str(v: &Value) -> &str {
    v.as_str().unwrap_or_default()
}

/// A temp directory that removes itself on drop (single-file bundles are
/// verified from an extraction; the archive is never mutated).
struct TempRoot(std::path::PathBuf);

impl TempRoot {
    fn new() -> TempRoot {
        let dir = std::env::temp_dir().join(format!(
            "frf-xtask-bundle-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir)
            .unwrap_or_else(|e| panic!("cannot create {}: {e}", dir.display()));
        TempRoot(dir)
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Extract a single-file bundle's tar archive into `root`, refusing hostile
/// archives the same way the reference engine does: escaped or absolute
/// paths, links, and unbounded extractions.
fn extract_tar(bytes: &[u8], root: &Path) {
    let mut archive = tar::Archive::new(bytes);
    let entries = archive
        .entries()
        .unwrap_or_else(|e| panic!("not a readable single-file bundle: {e}"));
    let mut total: u64 = 0;
    let mut count: usize = 0;
    for entry in entries {
        let mut entry = entry.unwrap_or_else(|e| panic!("single-file bundle is corrupt: {e}"));
        let path = entry
            .path()
            .unwrap_or_else(|e| panic!("single-file bundle is corrupt: {e}"))
            .into_owned();
        if path.is_absolute()
            || path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            panic!("single-file bundle refuses entry with path {path:?}");
        }
        let etype = entry.header().entry_type();
        if etype.is_symlink() || etype.is_hard_link() {
            panic!("single-file bundle refuses link entry {path:?}");
        }
        if !etype.is_file() && !etype.is_dir() {
            panic!("single-file bundle refuses entry {path:?} of unsupported type");
        }
        count += 1;
        if count > 10_000 {
            panic!("single-file bundle exceeds the 10 000-entry ceiling");
        }
        if etype.is_file() {
            total = total.saturating_add(entry.size());
            if total > 1 << 30 {
                panic!("single-file bundle exceeds the 1 GiB extraction ceiling");
            }
        }
        entry
            .unpack_in(root)
            .unwrap_or_else(|e| panic!("cannot extract {}: {e}", path.display()));
    }
}

/// Confine a DIRECTORY bundle before a single byte is read: the walk refuses
/// symlinks and hard links (a link could smuggle a read outside the bundle),
/// refuses any entry that is not a regular file or directory, and enforces
/// the same count/size ceilings as the archive extractor. This is the archive
/// form's trust model applied to the directory form — the container format
/// must not change what "self-contained evidence" means.
fn confine_dir(root: &Path) {
    let mut count = 0usize;
    let mut total: u64 = 0;
    confine_dir_walk(root, &mut count, &mut total);
}

fn confine_dir_walk(dir: &Path, count: &mut usize, total: &mut u64) {
    for entry in
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
    {
        let entry = entry.unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()));
        let from = entry.path();
        // symlink_metadata: inspect the entry itself, NEVER what it points at.
        let meta = std::fs::symlink_metadata(&from)
            .unwrap_or_else(|e| panic!("cannot inspect {}: {e}", from.display()));
        let ft = meta.file_type();
        if ft.is_symlink() {
            panic!(
                "bundle directory refuses symlink {} — a bundle is self-contained evidence; a link could resolve outside it",
                from.display()
            );
        }
        if ft.is_dir() {
            confine_dir_walk(&from, count, total);
            continue;
        }
        if !ft.is_file() {
            panic!(
                "bundle directory refuses {} of unsupported type",
                from.display()
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if meta.nlink() > 1 {
                panic!(
                    "bundle directory refuses hard-linked file {} — a hard link could share an inode outside the bundle",
                    from.display()
                );
            }
        }
        *count += 1;
        if *count > 10_000 {
            panic!("bundle directory exceeds the 10 000-entry ceiling");
        }
        *total = total.saturating_add(meta.len());
        if *total > 1 << 30 {
            panic!("bundle directory exceeds the 1 GiB ceiling");
        }
    }
}

// ---------------------------------------------------------------------------
// Bundle verification
// ---------------------------------------------------------------------------

/// The full evidence closure of a receipt: the receipt, its run, every
/// resolution run its disposition events reference (transitively), and for
/// each run the capture + side files, snapshots, authority record, residuals
/// + events, and trajectories. Mirrors the reference engine's collect_closure.
fn needed_closure(bundle: &Path, receipt_id: &str) -> std::collections::BTreeSet<String> {
    let mut needed = std::collections::BTreeSet::new();
    let mut runs: Vec<String> = Vec::new();
    let mut seen_runs = std::collections::BTreeSet::new();
    let mut seen_residuals = std::collections::BTreeSet::new();

    needed.insert(format!("receipts/{receipt_id}.json"));
    let rec = load_json(&safe_rel(bundle, &format!("receipts/{receipt_id}.json")));
    runs.push(as_str(&rec["run"]).to_string());

    while let Some(run) = runs.pop() {
        if !seen_runs.insert(run.clone()) {
            continue;
        }
        let cap = load_evidence(&safe_rel(bundle, &format!("captures/{run}/capture.json")));
        needed.insert(format!("captures/{run}/capture.json"));
        for side in ["reference", "candidate"] {
            for f in [
                "stdout",
                "stderr",
                "exit.txt",
                "stderr_first_line.txt",
                "stdout_first_line.txt",
            ] {
                needed.insert(format!("captures/{run}/{side}.{f}"));
            }
            // The PRODUCED ARTIFACT tree (the filesystem-tree surface): every
            // produced file a side built, walked under the run.
            let produced_root = bundle.join(format!("captures/{run}/produced/{side}"));
            if produced_root.is_dir() {
                let mut pending: Vec<std::path::PathBuf> = vec![produced_root];
                while let Some(d) = pending.pop() {
                    for entry in std::fs::read_dir(&d).unwrap().flatten() {
                        let p = entry.path();
                        if entry.file_type().unwrap().is_dir() {
                            pending.push(p);
                            continue;
                        }
                        let rel = p
                            .strip_prefix(bundle)
                            .unwrap()
                            .to_string_lossy()
                            .to_string();
                        needed.insert(rel);
                    }
                }
            }
        }
        needed.insert(format!("authorities/{}.json", as_str(&cap["authority"])));
        // Objects: walk the capture's typed evidence references (the generic
        // graph traversal — comparator implementations included); fall back to
        // the recorded artifact hashes for captures that carry no refs.
        let refs: Vec<String> = cap["evidence_refs"]
            .as_array()
            .map(|rs| {
                rs.iter()
                    .filter(|r| as_str(&r["object_kind"]) == "object")
                    .map(|r| as_str(&r["cid"]).to_string())
                    .collect()
            })
            .filter(|rs: &Vec<String>| !rs.is_empty())
            .unwrap_or_else(|| {
                vec![
                    as_str(&cap["authority_artifact"]["sha256"]).to_string(),
                    as_str(&cap["candidate_artifact"]["sha256"]).to_string(),
                    as_str(&cap["fixture_sha256"]).to_string(),
                ]
            });
        for h in refs {
            needed.insert(format!("objects/sha256/{h}"));
        }
        // Comparator invocation evidence (externally served axes).
        let comp_dir = bundle.join(format!("captures/{run}/comparator"));
        if comp_dir.is_dir() {
            let mut axes: Vec<String> = std::fs::read_dir(&comp_dir)
                .unwrap()
                .flatten()
                .map(|e| e.file_name().to_string_lossy().to_string())
                .collect();
            axes.sort();
            for axis in axes {
                for f in [
                    "request.json",
                    "response.json",
                    "invocation.json",
                    "result.json",
                ] {
                    let p = comp_dir.join(&axis).join(f);
                    if p.is_file() {
                        needed.insert(format!("captures/{run}/comparator/{axis}/{f}"));
                    }
                }
            }
        }
        // Normalizer invocation evidence (the comparison-surface instruments):
        // `captures/<run>/normalizer/<id>/<side>/` — four files per side.
        let norm_dir = bundle.join(format!("captures/{run}/normalizer"));
        if norm_dir.is_dir() {
            let mut ids: Vec<String> = std::fs::read_dir(&norm_dir)
                .unwrap()
                .flatten()
                .map(|e| e.file_name().to_string_lossy().to_string())
                .collect();
            ids.sort();
            for id in ids {
                let side_dir = norm_dir.join(&id);
                let mut sides: Vec<String> = std::fs::read_dir(&side_dir)
                    .unwrap()
                    .flatten()
                    .map(|e| e.file_name().to_string_lossy().to_string())
                    .collect();
                sides.sort();
                for side in sides {
                    for f in [
                        "request.json",
                        "response.json",
                        "invocation.json",
                        "result.json",
                    ] {
                        let p = norm_dir.join(&id).join(&side).join(f);
                        if p.is_file() {
                            needed.insert(format!("captures/{run}/normalizer/{id}/{side}/{f}"));
                        }
                    }
                }
            }
        }
        // Capture-adapter invocation evidence (the adapted-observation
        // instruments): `captures/<run>/capture-adapter/<axis>/<side>/`.
        let adapter_dir = bundle.join(format!("captures/{run}/capture-adapter"));
        if adapter_dir.is_dir() {
            let mut axes: Vec<String> = std::fs::read_dir(&adapter_dir)
                .unwrap()
                .flatten()
                .map(|e| e.file_name().to_string_lossy().to_string())
                .collect();
            axes.sort();
            for axis in axes {
                let side_dir = adapter_dir.join(&axis);
                let mut sides: Vec<String> = std::fs::read_dir(&side_dir)
                    .unwrap()
                    .flatten()
                    .map(|e| e.file_name().to_string_lossy().to_string())
                    .collect();
                sides.sort();
                for side in sides {
                    for f in [
                        "request.json",
                        "response.json",
                        "invocation.json",
                        "result.json",
                    ] {
                        let p = adapter_dir.join(&axis).join(&side).join(f);
                        if p.is_file() {
                            needed.insert(format!(
                                "captures/{run}/capture-adapter/{axis}/{side}/{f}"
                            ));
                        }
                    }
                }
            }
        }
        for id in cap["residuals"].as_array().cloned().unwrap_or_default() {
            let id = as_str(&id).to_string();
            if !seen_residuals.insert(id.clone()) {
                continue;
            }
            needed.insert(format!("residuals/{id}.json"));
            let ev_dir = bundle.join(format!("residuals/{id}.events"));
            if ev_dir.is_dir() {
                let mut names: Vec<String> = std::fs::read_dir(&ev_dir)
                    .unwrap()
                    .flatten()
                    .map(|e| e.file_name().to_string_lossy().to_string())
                    .filter(|n| n.ends_with(".json"))
                    .collect();
                names.sort();
                for n in names {
                    needed.insert(format!("residuals/{id}.events/{n}"));
                }
            }
            // The series experiments this run belongs to, and their derived
            // trajectories for this residual's lineage (a run never knows its
            // experiments; the closure walks the series records that
            // reference it).
            let record = load_evidence(&safe_rel(bundle, &format!("residuals/{id}.json")));
            let lineage = residual_lineage_of(bundle, &record, &cap);
            let series_dir = bundle.join("series");
            if series_dir.is_dir() {
                let mut names: Vec<String> = std::fs::read_dir(&series_dir)
                    .unwrap()
                    .flatten()
                    .map(|e| e.file_name().to_string_lossy().to_string())
                    .filter(|n| n.ends_with(".json"))
                    .collect();
                names.sort();
                for n in names {
                    let sid = n.trim_end_matches(".json").to_string();
                    let s = load_evidence(&safe_rel(bundle, &format!("series/{sid}.json")));
                    let contains = s["points"]
                        .as_array()
                        .map(|ps| ps.iter().any(|p| as_str(&p["run"]) == run.as_str()))
                        .unwrap_or(false);
                    if !contains {
                        continue;
                    }
                    needed.insert(format!("series/{sid}.json"));
                    let coord = as_str(&s["coordinate_system"]);
                    needed.insert(format!("trajectories/{lineage}.{coord}.{sid}.json"));
                }
            }
        }
    }
    // The compiled claims bound to the receipt, when present — resolved
    // through the claims/by-receipt index (a receipt compiled under a
    // different universe or policy is a DIFFERENT claim; the bundle carries
    // them all). Each claim's EVIDENCE UNIVERSE enters the closure: every
    // residual head's record + events + run (the negative search must be
    // reproducible from the bundle), plus the reduction records it
    // references.
    let claim_index = bundle.join("claims/by-receipt").join(receipt_id);
    if claim_index.is_dir() {
        let claim_ids: Vec<String> = sorted_names(&claim_index)
            .into_iter()
            .filter(|n| n.len() == 64)
            .collect();
        for claim_id in claim_ids {
            let claim_rel = format!("claims/{claim_id}.json");
            needed.insert(claim_rel.clone());
            needed.insert(format!("claims/by-receipt/{receipt_id}/{claim_id}"));
            let claim = load_evidence(&safe_rel(bundle, &claim_rel));
            // The claim is MULTI-PREMISE since v6: every premise receipt's run is
            // part of the evidence, so each premise's capture/objects/residuals
            // enter the traversal, and the premise receipt documents are part of
            // the closure.
            if let Some(requires) = claim["requires"].as_array() {
                for prem_id in requires {
                    let prem_id = as_str(prem_id).to_string();
                    needed.insert(format!("receipts/{prem_id}.json"));
                    let prem =
                        load_evidence(&safe_rel(bundle, &format!("receipts/{prem_id}.json")));
                    let prun = as_str(&prem["run"]).to_string();
                    if !seen_runs.contains(&prun) && !runs.contains(&prun) {
                        runs.push(prun);
                    }
                }
            }
            if let Some(heads) = claim["knowledge_snapshot"]["residual_heads"].as_array() {
                for h in heads {
                    let hid = as_str(&h["id"]);
                    needed.insert(format!("residuals/{hid}.json"));
                    let ev_dir = bundle.join(format!("residuals/{hid}.events"));
                    if ev_dir.is_dir() {
                        let mut names: Vec<String> = std::fs::read_dir(&ev_dir)
                            .unwrap()
                            .flatten()
                            .map(|e| e.file_name().to_string_lossy().to_string())
                            .filter(|n| n.ends_with(".json"))
                            .collect();
                        names.sort();
                        for n in names {
                            needed.insert(format!("residuals/{hid}.events/{n}"));
                        }
                    }
                    // The head's run enters the traversal: its capture, sides,
                    // objects, authority, residuals, and series all become
                    // required closure.
                    let record = load_evidence(&safe_rel(bundle, &format!("residuals/{hid}.json")));
                    let hrun = as_str(&record["run"]).to_string();
                    if !seen_runs.contains(&hrun) && !runs.contains(&hrun) {
                        runs.push(hrun);
                    }
                }
            }
            // The capability evidence a sensitivity-backed claim names: each
            // content-addressed challenge record and its mutant run (the run
            // traversal picks up its capture, objects, residuals).
            if let Some(capability) = claim["capability"].as_array() {
                for cap in capability {
                    if let Some(ids) = cap["challenge_ids"].as_array() {
                        for cid in ids {
                            let cid = as_str(cid).to_string();
                            needed.insert(format!("challenges/{cid}.json"));
                            let ch =
                                load_evidence(&safe_rel(bundle, &format!("challenges/{cid}.json")));
                            // An external mutation proposal's preserved evidence
                            // travels with the challenge.
                            if ch
                                .get("mutation_invocation_id")
                                .is_some_and(|v| v.is_string())
                            {
                                for f in [
                                    "request.json",
                                    "response.json",
                                    "invocation.json",
                                    "result.json",
                                ] {
                                    needed.insert(format!("challenges/{cid}/mutation/{f}"));
                                }
                            }
                            let chrun = as_str(&ch["run"]).to_string();
                            if !seen_runs.contains(&chrun) && !runs.contains(&chrun) {
                                runs.push(chrun);
                            }
                        }
                    }
                }
            }
            // The witness evidence an independently-witnessed claim names: each
            // verified statement + its preserved request/response + the witness
            // program object the attestation's implementation bound.
            if let Some(witnesses) = claim["witness_statements"].as_array() {
                for wid in witnesses {
                    let wid = as_str(wid).to_string();
                    needed.insert(format!("witnesses/{wid}.json"));
                    for f in ["request.json", "response.json"] {
                        needed.insert(format!("witnesses/{wid}/{f}"));
                    }
                    let stmt = load_evidence(&safe_rel(bundle, &format!("witnesses/{wid}.json")));
                    if let Some(artifact) = stmt["witness_implementation"]["artifact"].as_object() {
                        needed.insert(format!("objects/sha256/{}", as_str(&artifact["sha256"])));
                    }
                }
            }
            // The declared independence evidence a claim carries: each record
            // binds one of the claim's witness statements.
            if let Some(independence) = claim["independence_evidence"].as_array() {
                for iid in independence {
                    needed.insert(format!("independence/{}.json", as_str(iid)));
                }
            }
            // The v2 universe commits every other member as (kind, id, cid)
            // objects; reductions enter the closure through kind == "reduction".
            if let Some(objects) = claim["knowledge_snapshot"]["objects"].as_array() {
                for o in objects {
                    if as_str(&o["kind"]) != "reduction" {
                        continue;
                    }
                    let rid = as_str(&o["id"]);
                    needed.insert(format!("reductions/{rid}.json"));
                    // An external minimizer's invocation evidence lives under
                    // `reductions/<id>/minimizer/`; the record binds it.
                    let reduction =
                        load_evidence(&safe_rel(bundle, &format!("reductions/{rid}.json")));
                    if reduction["minimizer_semantic_id"].is_string() {
                        for f in [
                            "request.json",
                            "response.json",
                            "invocation.json",
                            "result.json",
                        ] {
                            let p = bundle.join(format!("reductions/{rid}/minimizer/{f}"));
                            if p.is_file() {
                                needed.insert(format!("reductions/{rid}/minimizer/{f}"));
                            }
                        }
                    }
                }
            }
        }
    }
    needed
}

fn axis_agrees(reference: &Value, candidate: &Value, axis: &str) -> bool {
    match axis {
        "exit" => as_str(&reference["exit"]) == as_str(&candidate["exit"]),
        "stderr" => {
            as_str(&reference["stderr_first_line"]) == as_str(&candidate["stderr_first_line"])
        }
        _ => as_str(&reference["stdout_first_line"]) == as_str(&candidate["stdout_first_line"]),
    }
}

/// The residual lineage of a bundle residual: kind/axis/surface from the
/// record, fixture/family from its run's capture, authority NAME from the
/// admitted authority record (the lineage spans authority versions).
fn residual_lineage_of(bundle: &Path, record: &Value, cap: &Value) -> String {
    let authority_id = as_str(&record["authority"]);
    let authority = load_evidence(&safe_rel(
        bundle,
        &format!("authorities/{authority_id}.json"),
    ));
    let env = &cap["court_spec"]["admissibility_envelope"];
    let surface = record.get("surface").and_then(|s| s.as_str());
    rederive::residual_lineage(
        as_str(&record["kind"]),
        as_str(&record["axis"]),
        surface,
        as_str(&env["fixture_family"]),
        as_str(&authority["name"]),
        as_str(&cap["fixture"]),
    )
}

/// Verify a bundle against itself. Panics (exit 1) on the first violation;
/// every check names what failed. `container` is how the bundle was opened
/// (directory or single-tar) and must match the manifest's declaration.
/// Re-derive a compiled claim's ADMISSION POLICY from the bundle alone — the
/// claim's `capability` / `witness_statements` / `replay_profile` are
/// evidence references, and each tier's requirements are checked against the
/// bundle's own objects (never trusted from the claim file). Since v6 a
/// claim is MULTI-PREMISE: every capability entry binds the premise receipt
/// its covered axes belong to, and each tier's obligations hold per premise
/// (a sensitivity-backed axis must be challenged by THAT premise's court;
/// every premise receipt must be attested; every premise must carry the
/// reference execution contract).
fn verify_claim_policy(bundle: &Path, claim: &Value, _body: &Value, receipt_id: &str) {
    let policy = as_str(&claim["policy"]);
    if ![
        "baseline",
        "sensitivity-backed",
        "independently-witnessed",
        "high-assurance",
    ]
    .contains(&policy)
    {
        panic!("claim {receipt_id}: unknown admission policy {policy:?}");
    }
    if matches!(policy, "baseline") {
        return;
    }

    // The premise receipts the claim names; the claim file is named after
    // the first premise.
    let requires: Vec<String> = claim["requires"]
        .as_array()
        .map(|a| a.iter().map(|v| as_str(v).to_string()).collect())
        .unwrap_or_default();
    if requires.is_empty() {
        panic!("claim {receipt_id}: names no premise receipts");
    }
    if as_str(&claim["receipt"]) != receipt_id {
        panic!("claim {receipt_id}: the claim file does not bind its first premise");
    }
    let premise = |prem_id: &str| -> Value {
        load_evidence(&safe_rel(bundle, &format!("receipts/{prem_id}.json")))
    };
    // Subject coherence: every premise binds the same authority and the same
    // candidate artifact (the reference compiler enforces this at compile
    // time; the verifier re-derives it from the bundle's own receipts).
    let first = premise(&requires[0]);
    for prem_id in &requires[1..] {
        let p = premise(prem_id);
        if as_str(&p["authority"]["name"]) != as_str(&first["authority"]["name"])
            || as_str(&p["authority"]["version"]) != as_str(&first["authority"]["version"])
            || as_str(&p["authority"]["identity_hash"])
                != as_str(&first["authority"]["identity_hash"])
        {
            panic!("claim {receipt_id}: the premises bind different authorities");
        }
        if as_str(&p["candidate"]["identity_hash"]) != as_str(&first["candidate"]["identity_hash"])
        {
            panic!("claim {receipt_id}: the premises bind different candidate artifacts");
        }
    }

    // The claimed axes: every one must be covered by a capability entry
    // BOUND TO THE PREMISE whose court observed it.
    let claimed: Vec<String> = claim["observable_scope"]
        .as_array()
        .map(|a| a.iter().map(|v| as_str(v).to_string()).collect())
        .unwrap_or_default();
    let capability = claim["capability"].as_array().cloned().unwrap_or_default();
    let mut covered: Vec<String> = Vec::new();
    for cap in &capability {
        let axis = as_str(&cap["axis"]).to_string();
        let prem_id = as_str(&cap["receipt"]).to_string();
        if !requires.contains(&prem_id) {
            panic!(
                "claim {receipt_id}: capability entry for axis {axis} binds premise {prem_id} which the claim does not require"
            );
        }
        let prem = premise(&prem_id);
        let challenge_ids = cap["challenge_ids"].as_array().cloned().unwrap_or_default();
        if challenge_ids.is_empty() {
            panic!("claim {receipt_id}: capability entry for axis {axis} names no challenge");
        }
        // The DEMONSTRATED mutation profile rederives from the named
        // challenges: the distinct operators of exactly the recorded ids.
        let mut rederived_profile: Vec<String> = Vec::new();
        for cid in challenge_ids {
            let cid = as_str(&cid).to_string();
            let ch = load_evidence(&safe_rel(bundle, &format!("challenges/{cid}.json")));
            rederived_profile.push(as_str(&ch["operator"]).to_string());
            if as_str(&ch["court"]) != as_str(&prem["court"]["id"]) {
                panic!(
                    "claim {receipt_id}: challenge {cid} is not a challenge of premise {prem_id}'s court"
                );
            }
            if as_str(&ch["target_axis"]) != axis {
                panic!(
                    "claim {receipt_id}: challenge {cid} targets {} not {axis}",
                    as_str(&ch["target_axis"])
                );
            }
            // The mutant wraps the same reference artifact the premise binds.
            if as_str(&ch["reference_sha256"]) != as_str(&prem["authority"]["identity_hash"]) {
                panic!("claim {receipt_id}: challenge {cid} does not wrap premise {prem_id}'s reference artifact");
            }
            // The mutant run answered the same question.
            let chrun = as_str(&ch["run"]);
            let mut_cap =
                load_evidence(&safe_rel(bundle, &format!("captures/{chrun}/capture.json")));
            if as_str(&mut_cap["court_semantic_identity"])
                != as_str(&prem["court"]["semantic_identity"])
            {
                panic!(
                    "claim {receipt_id}: challenge {cid} did not run premise {prem_id}'s question"
                );
            }
            // The verdicts RECOMPUTE from the mutant run's residuals.
            let mut on_target = false;
            let mut on_unaffected = false;
            if let Some(rids) = mut_cap["residuals"].as_array() {
                for rid in rids {
                    let rec = load_evidence(&safe_rel(
                        bundle,
                        &format!("residuals/{}.json", as_str(rid)),
                    ));
                    if as_str(&rec["axis"]) == axis {
                        on_target = true;
                    } else {
                        on_unaffected = true;
                    }
                }
            }
            if !on_target || on_unaffected {
                panic!(
                    "claim {receipt_id}: challenge {cid} does not demonstrate sensitivity on {axis} (recomputed: saw_defect={on_target}, specificity_clean={})",
                    !on_unaffected
                );
            }
        }
        // The recorded demonstrated profile must rederive exactly.
        rederived_profile.sort();
        rederived_profile.dedup();
        let recorded: Vec<String> = cap["mutation_profile"]
            .as_array()
            .map(|a| a.iter().map(|v| as_str(v).to_string()).collect())
            .unwrap_or_default();
        if recorded != rederived_profile {
            panic!(
                "claim {receipt_id}: capability entry for axis {axis} records mutation profile {:?} which does not rederive from its challenges ({:?})",
                recorded, rederived_profile
            );
        }
        covered.push(axis);
    }
    for axis in &claimed {
        if !covered.contains(axis) {
            panic!(
                "claim {receipt_id}: claimed axis {axis} has no capability coverage — the court never demonstrated it can see that surface"
            );
        }
    }
    // The REQUIRED sensitivity mutation profile: every AXIS:FAMILY pair the
    // claim was compiled under must name a claimed axis whose demonstrated
    // profile includes that family.
    if let Some(required) = claim["mutation_profile"].as_array() {
        for entry in required {
            let entry = as_str(entry);
            let Some((axis, family)) = entry.split_once(':') else {
                panic!("claim {receipt_id}: required mutation profile entry {entry:?} is not AXIS:FAMILY");
            };
            if !claimed.iter().any(|a| a == axis) {
                panic!("claim {receipt_id}: required mutation profile names axis {axis}, which the claim does not cover");
            }
            let demonstrated = capability.iter().any(|c| {
                as_str(&c["axis"]) == axis
                    && c["mutation_profile"]
                        .as_array()
                        .map(|a| a.iter().any(|f| as_str(f) == family))
                        .unwrap_or(false)
            });
            if !demonstrated {
                panic!("claim {receipt_id}: required mutation profile demands the {family} family on axis {axis}, which no capability entry demonstrates");
            }
        }
    }

    if matches!(policy, "independently-witnessed" | "high-assurance") {
        let witnesses = claim["witness_statements"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        if witnesses.is_empty() {
            panic!(
                "claim {receipt_id}: policy {policy} requires a witness attestation but names none"
            );
        }
        // The stable map from each carried witness statement to the premise
        // receipt it attests — the per-premise independence check needs it.
        let mut stmt_subject: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        // EVERY premise receipt must have at least one affirming attestation
        // of ITSELF (the compiler attests each premise before compiling).
        for prem_id in &requires {
            let mut affirmed_this = false;
            for wid in &witnesses {
                let wid = as_str(wid).to_string();
                let stmt = load_evidence(&safe_rel(bundle, &format!("witnesses/{wid}.json")));
                if as_str(&stmt["subject"]["kind"]) != "receipt" {
                    continue;
                }
                stmt_subject.insert(wid.clone(), as_str(&stmt["subject"]["id"]).to_string());
                if as_str(&stmt["subject"]["id"]) != *prem_id {
                    continue;
                }
                // The statement's identity rederives from its own fields
                // (the witness IDENTITY — the stable WHO — included), and
                // the identity itself rederives from the semantic +
                // implementation.
                if rederive::witness_statement_identity(&stmt) != wid {
                    panic!("claim {receipt_id}: witness {wid} is not content-addressed");
                }
                if rederive::witness_identity(
                    &stmt["witness_semantic"],
                    &stmt["witness_implementation"],
                ) != as_str(&stmt["witness_identity"])
                {
                    panic!("claim {receipt_id}: witness {wid} identity does not rederive");
                }
                // The preserved documents hash to their cids (the attestation
                // is bound to the exact request/response evidence).
                for f in ["request.json", "response.json"] {
                    let bytes = read(&safe_rel(bundle, &format!("witnesses/{wid}/{f}")));
                    let cid_field = if f == "request.json" {
                        "request_cid"
                    } else {
                        "response_cid"
                    };
                    if sha256_bytes(&bytes) != as_str(&stmt[cid_field]) {
                        panic!(
                            "claim {receipt_id}: witness {wid} preserved {f} does not hash to its cid"
                        );
                    }
                }
                // A SIGNED witness statement: the ed25519 signature must
                // verify over the subject document's exact canonical bytes
                // from the bundle, and the recorded implementation hash must
                // commit the signature's public key.
                if let Some(sig) = stmt.get("signature") {
                    verify_witness_signature(bundle, &wid, &stmt);
                    let _ = sig;
                }
                if as_str(&stmt["attestation"]["outcome"]) == "affirm" {
                    affirmed_this = true;
                }
            }
            if !affirmed_this {
                panic!("claim {receipt_id}: no named witness affirms premise receipt {prem_id}");
            }
        }
        // The declared INDEPENDENCE evidence the claim carries: every record
        // verifies (identity rederives, the relation is closed, the spec hash
        // rederives) and binds one of the claim's own witness statements —
        // the independence claim is as portable as the attestation, and a
        // record about a statement the claim does not carry is refused.
        if let Some(independence) = claim["independence_evidence"].as_array() {
            for iid in independence {
                let iid = as_str(iid).to_string();
                let rec = load_evidence(&safe_rel(bundle, &format!("independence/{iid}.json")));
                if rederive::independence_identity(&rec) != iid {
                    panic!(
                        "claim {receipt_id}: independence record {iid} is not content-addressed"
                    );
                }
                let relation = as_str(&rec["relation"]);
                if ![
                    "different-implementation",
                    "separate-party",
                    "unaffiliated-channel",
                    "adversarial-review",
                ]
                .contains(&relation)
                {
                    panic!("claim {receipt_id}: independence record {iid} names unknown relation {relation:?}");
                }
                if rederive::independence_spec_hash(relation, as_str(&rec["relation_version"]))
                    != as_str(&rec["specification_hash"])
                {
                    panic!(
                        "claim {receipt_id}: independence record {iid} spec hash does not rederive"
                    );
                }
                if !witnesses
                    .iter()
                    .any(|w| w == as_str(&rec["witness_statement"]))
                {
                    panic!("claim {receipt_id}: independence record {iid} binds a witness statement the claim does not carry");
                }
            }
            // The tier is NAMED independently-witnessed: EVERY premise must
            // be covered by at least one admissible independence relation
            // bound to an attestation of THAT premise — an affirming witness
            // with zero declared independence is witnessed, not
            // independently witnessed.
            let independence_ids: Vec<String> = claim["independence_evidence"]
                .as_array()
                .map(|a| a.iter().map(|v| as_str(v).to_string()).collect())
                .unwrap_or_default();
            for prem_id in &requires {
                let covered = independence_ids.iter().any(|iid| {
                    let rec = load_evidence(&safe_rel(bundle, &format!("independence/{iid}.json")));
                    stmt_subject.get(as_str(&rec["witness_statement"])) == Some(prem_id)
                });
                if !covered {
                    panic!("claim {receipt_id}: premise receipt {prem_id} has no admissible independence relation — an attestation alone is witnessed, not independently witnessed");
                }
            }
        }
    }

    if policy == "high-assurance" {
        // The reference capture contract — the EXACT capture bounds the
        // reference profile enforces (mirroring the reference engine's
        // `host::reference_capture_bounds`, v19 included the produced-tree
        // caps). High assurance requires the exact contract, never a
        // superset.
        let reference = serde_json::json!({
            "timeout_ms": "60000",
            "max_stream_bytes": "16777216",
            "produced_max_files": "4096",
            "produced_max_bytes": "268435456",
            "produced_max_file_bytes": "16777216",
            "rlimit_as_mb": "2048",
            "rlimit_cpu_s": "30",
            "rlimit_nofile": "1024",
            "rlimit_nproc": "4096",
        });
        // High assurance requires a CAPABILITY SET (the reference contract),
        // never a profile-name equality: every premise must have been
        // observed under a profile providing every required capability (v1
        // exactly; v2/v3/OCI provide supersets), under the exact capture
        // contract, with the claim recording the requirement.
        let required: Vec<String> = claim["required_capabilities"]
            .as_array()
            .map(|a| a.iter().map(|c| as_str(c).to_string()).collect())
            .unwrap_or_default();
        if required.is_empty() {
            panic!("claim {receipt_id}: high-assurance must record its required capability set");
        }
        for prem_id in &requires {
            let prem = premise(prem_id);
            let profile = as_str(&prem["execution_profile"]);
            let caps = profile_capabilities(profile);
            for c in &required {
                if !caps.iter().any(|cap| cap == c) {
                    panic!("claim {receipt_id}: high-assurance requires capability {c}, premise {prem_id} (profile {profile}) does not provide it");
                }
            }
            if prem["capture_bounds"] != reference {
                panic!("claim {receipt_id}: high-assurance requires the reference capture bounds (the exact capture contract) for premise {prem_id}");
            }
        }
        if as_str(&claim["replay_profile"]) != "frf-exec-linux-v1" {
            panic!("claim {receipt_id}: the claim's replay_profile does not record the reference profile");
        }
    }
}

/// The capability set of an execution profile (the orthogonal assurance
/// model, mirroring the reference engine's `model::profile_capabilities`):
/// the reference contract for every profile, plus each later profile's
/// mechanism.
pub fn profile_capabilities(profile: &str) -> Vec<&'static str> {
    match profile {
        "frf-exec-linux-v1" => vec![
            "exact_capture_contract",
            "sealed_executable_image",
            "native_runtime_closure_bound",
        ],
        "frf-exec-linux-v2" => vec![
            "exact_capture_contract",
            "sealed_executable_image",
            "native_runtime_closure_bound",
            "descendant_resource_envelope",
        ],
        "frf-exec-linux-v3" => vec![
            "exact_capture_contract",
            "sealed_executable_image",
            "native_runtime_closure_bound",
            "descendant_resource_envelope",
            "io_world_closed",
        ],
        "frf-exec-oci" => vec![
            "exact_capture_contract",
            "sealed_executable_image",
            "native_runtime_closure_bound",
            "descendant_resource_envelope",
            "io_world_closed",
            "rootfs_content_bound",
        ],
        _ => Vec::new(),
    }
}

/// The bundle manifest's CLOSED schema (frf-bundle-v3): the top-level key
/// set, `created_by`'s key set, and each inventory entry's key set are exact
/// — an unknown property is refused, never read around; the receipt/run
/// identifiers pass the id grammar; every inventory path is contained; the
/// role vocabulary is closed; every digest is 64 hex digits; and no
/// inventory path repeats. The reference engine enforces exactly this on the
/// same bytes, so a manifest one verifier accepts and another refuses is a
/// protocol bug.
fn verify_manifest_schema(m: &Value) {
    const TOP: &[&str] = &[
        "schema_version",
        "container",
        "receipt_id",
        "run",
        "created_by",
        "inventory",
    ];
    const CREATED: &[&str] = &["frf_version", "frf_executable_hash"];
    const ENTRY: &[&str] = &["path", "sha256", "kind"];
    const KINDS: &[&str] = &[
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
    let unknown = |o: &Value, allowed: &[&str], what: &str| -> Vec<String> {
        let mut out = Vec::new();
        if let Some(obj) = o.as_object() {
            for k in obj.keys() {
                if !allowed.contains(&k.as_str()) {
                    out.push(format!(
                        "manifest.json carries unknown property {k:?} on {what}"
                    ));
                }
            }
        }
        out
    };
    let mut problems = unknown(m, TOP, "manifest");
    if let Some(cb) = m.get("created_by") {
        problems.extend(unknown(cb, CREATED, "created_by"));
    }
    if let Some(inv) = m["inventory"].as_array() {
        let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for item in inv {
            problems.extend(unknown(item, ENTRY, "inventory entry"));
            let rel = as_str(&item["path"]);
            let sha = as_str(&item["sha256"]);
            let kind = as_str(&item["kind"]);
            if rel.is_empty() {
                problems.push("inventory entry carries no path".to_string());
            }
            let rel_path = Path::new(rel);
            if rel_path.is_absolute()
                || rel_path
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                problems.push(format!("inventory path {rel} escapes the bundle"));
            }
            if !seen.insert(rel) {
                problems.push(format!("inventory entry {rel} repeats a path"));
            }
            if !KINDS.contains(&kind) {
                problems.push(format!(
                    "inventory entry {rel} carries unknown kind {kind:?}"
                ));
            }
            if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
                problems.push(format!(
                    "inventory entry {rel} carries an invalid digest {sha:?}"
                ));
            }
        }
    } else {
        problems.push("manifest.json carries no inventory".to_string());
    }
    let valid_id = |id: &str| {
        !id.is_empty()
            && id != "."
            && id != ".."
            && id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    };
    if !valid_id(as_str(&m["receipt_id"])) {
        problems.push("manifest.json carries an invalid receipt_id".to_string());
    }
    if !valid_id(as_str(&m["run"])) {
        problems.push("manifest.json carries an invalid run id".to_string());
    }
    if !problems.is_empty() {
        panic!("invalid bundle manifest:\n  {}", problems.join("\n  "));
    }
}

/// Verify a SIGNED witness statement inside a bundle (spec/witness.md §7):
/// the ed25519 signature must verify over the subject document's EXACT
/// canonical bytes (read from the bundle: `receipts/<id>.json` or
/// `claims/<id>.json`), and the recorded implementation hash must commit the
/// signature's public key (FRF/ED25519-KEY/v1) — a signature cannot be
/// re-attributed to a different key or document without breaking the
/// statement's content address.
fn verify_witness_signature(bundle: &Path, wid: &str, stmt: &Value) {
    use base64::Engine as _;
    let sig = &stmt["signature"];
    if as_str(&sig["algorithm"]) != "ed25519" {
        panic!(
            "witness {wid}: signature algorithm {:?} is not admitted (the protocol admits ed25519)",
            as_str(&sig["algorithm"])
        );
    }
    let public_key = base64::engine::general_purpose::STANDARD
        .decode(as_str(&sig["public_key"]))
        .unwrap_or_else(|e| {
            panic!("witness {wid}: the recorded public key is not valid base64: {e}")
        });
    let signature_value = base64::engine::general_purpose::STANDARD
        .decode(as_str(&sig["value"]))
        .unwrap_or_else(|e| {
            panic!("witness {wid}: the recorded signature value is not valid base64: {e}")
        });
    let public_key: [u8; 32] = public_key
        .try_into()
        .unwrap_or_else(|_| panic!("witness {wid}: an ed25519 public key is exactly 32 bytes"));
    let signature_value: [u8; 64] = signature_value
        .try_into()
        .unwrap_or_else(|_| panic!("witness {wid}: an ed25519 signature is exactly 64 bytes"));
    // The subject document's exact canonical bytes from the bundle.
    let kind = as_str(&stmt["subject"]["kind"]);
    let subject_id = as_str(&stmt["subject"]["id"]);
    let rel = match kind {
        "receipt" => format!("receipts/{subject_id}.json"),
        "claim" => format!("claims/{subject_id}.json"),
        other => panic!("witness {wid}: subject kind {other:?} is not a signable document (the signing protocol admits receipt or claim)"),
    };
    let canonical = read(&safe_rel(bundle, &rel));
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key).unwrap_or_else(|e| {
        panic!("witness {wid}: the recorded public key is not a valid ed25519 key: {e}")
    });
    let signature = ed25519_dalek::Signature::from_bytes(&signature_value);
    verifying_key
        .verify_strict(&canonical, &signature)
        .unwrap_or_else(|e| panic!("witness {wid}: the ed25519 signature does NOT verify over the {kind} {subject_id}'s exact canonical bytes: {e}"));
    // The key-identity binding.
    let expected =
        rederive::ed25519_key_identity(as_str(&sig["algorithm"]), as_str(&sig["public_key"]));
    if as_str(&stmt["witness_implementation"]["implementation_hash"]) != expected {
        panic!("witness {wid}: the recorded implementation hash does not commit the signature's public key — the signature cannot be re-attributed to this statement");
    }
}

fn verify_bundle(bundle: &Path, container: &str) -> rules::ClaimIr {
    let manifest = load_json(&safe_rel(bundle, "manifest.json"));
    verify_manifest_schema(&manifest);
    if let Err(e) = schema::admit("bundle", as_str(&manifest["schema_version"])) {
        panic!("unsupported bundle schema version: {e}");
    }
    let declared = manifest["container"].as_str().unwrap_or("<missing>");
    if declared != container {
        panic!(
            "bundle container mismatch: the manifest declares {declared:?} but the bundle is a {container}"
        );
    }
    let receipt_id = as_str(&manifest["receipt_id"]).to_string();
    if receipt_id.is_empty() {
        panic!("manifest.json carries no receipt_id");
    }

    // 1. Prove the manifest: every inventory file exists and hashes to its
    //    recorded digest; objects are named by their digest.
    let mut inventory: BTreeMap<String, String> = BTreeMap::new();
    for item in manifest["inventory"]
        .as_array()
        .cloned()
        .unwrap_or_default()
    {
        let rel = as_str(&item["path"]).to_string();
        let sha = as_str(&item["sha256"]).to_string();
        let kind = as_str(&item["kind"]).to_string();
        let actual = sha256_bytes(&read(&safe_rel(bundle, &rel)));
        if actual != sha {
            panic!(
                "bundle is corrupt: {rel} hashes to {} but the manifest records {sha}",
                &actual[..16]
            );
        }
        if kind == "object" {
            let name = Path::new(&rel)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if name != sha {
                panic!("bundle is corrupt: object file {rel} is not named by its digest");
            }
        }
        inventory.insert(rel, sha);
    }

    // 2. The receipt: strict-JSON content-addressed (the DOCUMENT hashes —
    //    duplicate property names and unknown properties are refused, never
    //    silently dropped), structurally and semantically conformant.
    let rest = receipt_id.strip_prefix("receipt-").expect("receipt id");
    let (run, digest) = rest.rsplit_once('-').expect("receipt id digest");
    let body = load_json(&safe_rel(bundle, &format!("receipts/{receipt_id}.json")));
    if as_str(&body["run"]) != run {
        panic!("receipt {receipt_id}: the run field does not match its id");
    }
    let canonical = encode(&body).unwrap_or_else(|e| panic!("receipt {receipt_id}: {e}"));
    let actual = sha256_bytes(canonical.as_bytes());
    if actual != digest {
        panic!("receipt {receipt_id} is not content-addressed");
    }
    let struct_v = structural_violations(&body);
    if !struct_v.is_empty() {
        panic!(
            "receipt {receipt_id} fails structural conformance: {}",
            struct_v.join("; ")
        );
    }
    let sem_v = semantic_violations(&body);
    if !sem_v.is_empty() {
        panic!(
            "receipt {receipt_id} fails semantic conformance: {}",
            sem_v.join("; ")
        );
    }

    // 3. The capture: run identity rederives; raw side files rehash; objects
    //    are content-addressed.
    let cap = load_evidence(&safe_rel(bundle, &format!("captures/{run}/capture.json")));
    if as_str(&cap["run"]) != run {
        panic!("capture {run}: the run field inside capture.json does not match");
    }
    let residuals: Vec<Value> = cap["residuals"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|id| {
            load_evidence(&safe_rel(
                bundle,
                &format!("residuals/{}.json", as_str(&id)),
            ))
        })
        .collect();
    let expected_run = format!(
        "run-{}-{}",
        as_str(&cap["court"]),
        run_identity(&cap, &residuals)
    );
    if expected_run != run {
        panic!("capture {run}: the recorded fields do not hash to the run identity");
    }
    // The recorded observation/execution identities must rederive from the
    // recorded fields (the run identity commits each of them separately).
    if observation_identity(&cap, &residuals) != as_str(&cap["observation_identity"]) {
        panic!("capture {run}: the recorded observation_identity does not rederive");
    }
    if execution_identity(&cap) != as_str(&cap["execution_identity"]) {
        panic!("capture {run}: the recorded execution_identity does not rederive");
    }
    // v18: the DECLARED execution-context closure (when carried) is
    // self-authenticating — its cid rederives from its own artifacts.
    if let Some(closure) = cap.get("execution_context").filter(|n| !n.is_null()) {
        let expected = crate::rederive::execution_context_identity(closure);
        if expected != as_str(&closure["cid"]) {
            panic!("capture {run}: the execution-context closure cid does not rederive");
        }
    }
    for side in ["reference", "candidate"] {
        let s = &cap[side];
        let stdout = read(&safe_rel(bundle, &format!("captures/{run}/{side}.stdout")));
        let stderr = read(&safe_rel(bundle, &format!("captures/{run}/{side}.stderr")));
        if sha256_bytes(&stdout) != as_str(&s["stdout_sha256"]) {
            panic!("capture {run}: {side}.stdout does not hash to the recorded value");
        }
        if sha256_bytes(&stderr) != as_str(&s["stderr_sha256"]) {
            panic!("capture {run}: {side}.stderr does not hash to the recorded value");
        }
        let first_out = String::from_utf8_lossy(&stdout)
            .split('\n')
            .next()
            .unwrap_or("")
            .to_string();
        let first_err = String::from_utf8_lossy(&stderr)
            .split('\n')
            .next()
            .unwrap_or("")
            .to_string();
        if first_out != as_str(&s["stdout_first_line"])
            || first_err != as_str(&s["stderr_first_line"])
        {
            panic!("capture {run}: {side} first lines do not derive");
        }
        for (f, recorded, recorded_hash) in [
            (
                "exit.txt",
                as_str(&s["exit"]).to_string(),
                as_str(&s["exit_sha256"]).to_string(),
            ),
            (
                "stderr_first_line.txt",
                first_err.clone(),
                as_str(&s["stderr_first_line_sha256"]).to_string(),
            ),
            (
                "stdout_first_line.txt",
                first_out.clone(),
                as_str(&s["stdout_first_line_sha256"]).to_string(),
            ),
        ] {
            let text = read(&safe_rel(bundle, &format!("captures/{run}/{side}.{f}")));
            let text = String::from_utf8_lossy(&text).trim().to_string();
            if text != recorded {
                panic!("capture {run}: {side}.{f} does not derive to the recorded projection");
            }
            if sha256_bytes(recorded.as_bytes()) != recorded_hash {
                panic!("capture {run}: {side}.{f} hash does not rederive");
            }
        }
    }
    for h in [
        as_str(&cap["authority_artifact"]["sha256"]).to_string(),
        as_str(&cap["candidate_artifact"]["sha256"]).to_string(),
        as_str(&cap["fixture_sha256"]).to_string(),
    ] {
        if sha256_bytes(&read(&safe_rel(bundle, &format!("objects/sha256/{h}")))) != h {
            panic!("object {h} is corrupt (or missing)");
        }
    }

    // 3b. The extension instruments' objects (normalizer / capture-adapter /
    //     minimizer implementations) are content-addressed — the exact
    //     program bytes that built the comparison surface are in the closure.
    for impls in [
        &cap["provenance"]["normalizer_implementations"],
        &cap["provenance"]["adapter_implementations"],
        &cap["provenance"]["minimizer_implementations"],
    ] {
        for impl_ in impls.as_array().cloned().unwrap_or_default() {
            if let Some(artifact) = impl_.get("artifact") {
                let h = as_str(&artifact["sha256"]);
                if sha256_bytes(&read(&safe_rel(bundle, &format!("objects/sha256/{h}")))) != h {
                    panic!("object {h} is corrupt (or missing)");
                }
            }
        }
    }

    // 3c. The normalizer chain: the COMPARED streams recorded in the capture
    //     derive from the recorded normalizer evidence. Each preserved
    //     request carries the streams the normalizer received; its result
    //     records the hashes it returned; the next request must carry exactly
    //     those; the last result's hashes ARE the capture's compared hashes.
    //     No execution — the raw streams survive inside the first request
    //     document, and the chain is rehashed end to end.
    let b64dec = |s: &str| -> Vec<u8> {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .unwrap_or_else(|e| panic!("cannot decode base64: {e}"))
    };
    for side in ["reference", "candidate"] {
        let cap_side = &cap[side];
        let mut incoming: Option<(String, String)> = None;
        for semantic in cap["normalizer_semantics"]
            .as_array()
            .cloned()
            .unwrap_or_default()
        {
            let id = as_str(&semantic["id"]);
            let base = format!("captures/{run}/normalizer/{id}/{side}");
            let inv = load_json(&safe_rel(bundle, &format!("{base}/invocation.json")));
            if as_str(&inv["normalizer_semantic_cid"]) != as_str(&semantic["specification_hash"]) {
                panic!(
                    "capture {run}: normalizer {id} invocation does not bind the recorded semantic identity"
                );
            }
            let req = load_json(&safe_rel(bundle, &format!("{base}/request.json")));
            let carried = (
                sha256_bytes(&b64dec(as_str(&req["stdout_base64"]))),
                sha256_bytes(&b64dec(as_str(&req["stderr_base64"]))),
            );
            if let Some((prev_stdout, prev_stderr)) = &incoming {
                if carried.0 != *prev_stdout || carried.1 != *prev_stderr {
                    panic!(
                        "capture {run}: the normalizer chain is broken — normalizer {id} on the {side} side received streams that are not the previous result's output"
                    );
                }
            }
            let res = load_json(&safe_rel(bundle, &format!("{base}/result.json")));
            incoming = Some((
                as_str(&res["stdout_sha256"]).to_string(),
                as_str(&res["stderr_sha256"]).to_string(),
            ));
        }
        if let Some((stdout_sha256, stderr_sha256)) = &incoming {
            if stdout_sha256 != as_str(&cap_side["stdout_sha256"])
                || stderr_sha256 != as_str(&cap_side["stderr_sha256"])
            {
                panic!(
                    "capture {run}: the {side} side's recorded compared streams do not derive from the recorded normalizer chain"
                );
            }
        }
    }

    // 3d. The capture adapters: the capture's adapted observations ARE the
    //     adapters' recorded outputs (payloads decode to the recorded content
    //     hashes), each invocation binds the recorded semantic identity, and
    //     each adapter request carried the truly raw outcome — the side files
    //     when no normalizers applied, else the first normalizer's request.
    for impl_ in cap["provenance"]["adapter_implementations"]
        .as_array()
        .cloned()
        .unwrap_or_default()
    {
        let axis = as_str(&impl_["id"]);
        let semantic = cap["adapter_semantics"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .find(|s| as_str(&s["id"]) == axis)
            .unwrap_or_else(|| panic!("capture {run}: capture adapter {axis} has no semantic"));
        for side in ["reference", "candidate"] {
            let cap_side = &cap[side];
            let base = format!("captures/{run}/capture-adapter/{axis}/{side}");
            let inv = load_json(&safe_rel(bundle, &format!("{base}/invocation.json")));
            if as_str(&inv["adapter_semantic_cid"]) != as_str(&semantic["specification_hash"]) {
                panic!(
                    "capture {run}: capture adapter {axis} invocation does not bind the recorded semantic identity"
                );
            }
            let res = load_json(&safe_rel(bundle, &format!("{base}/result.json")));
            let recorded = cap_side.get("adapted").unwrap_or_else(|| {
                panic!(
                    "capture {run}: the {side} side carries no adapted observation for adapted axis {axis}"
                )
            });
            if as_str(&recorded["content_sha256"]) != as_str(&res["observation_sha256"]) {
                panic!(
                    "capture {run}: the {side} side's adapted observation for axis {axis} does not match the adapter's recorded result"
                );
            }
            if sha256_bytes(&b64dec(as_str(&recorded["payload_base64"])))
                != as_str(&recorded["content_sha256"])
            {
                panic!(
                    "capture {run}: the {side} side's adapted payload for axis {axis} does not decode to its recorded content hash"
                );
            }
            let req = load_json(&safe_rel(bundle, &format!("{base}/request.json")));
            let carried = (
                sha256_bytes(&b64dec(as_str(&req["outcome"]["stdout_base64"]))),
                sha256_bytes(&b64dec(as_str(&req["outcome"]["stderr_base64"]))),
            );
            let raw: (String, String) = if cap["normalizer_semantics"]
                .as_array()
                .map(|a| a.is_empty())
                .unwrap_or(true)
            {
                (
                    sha256_bytes(&read(&safe_rel(
                        bundle,
                        &format!("captures/{run}/{side}.stdout"),
                    ))),
                    sha256_bytes(&read(&safe_rel(
                        bundle,
                        &format!("captures/{run}/{side}.stderr"),
                    ))),
                )
            } else {
                let first = as_str(&cap["normalizer_semantics"][0]["id"]);
                let first_req = load_json(&safe_rel(
                    bundle,
                    &format!("captures/{run}/normalizer/{first}/{side}/request.json"),
                ));
                (
                    sha256_bytes(&b64dec(as_str(&first_req["stdout_base64"]))),
                    sha256_bytes(&b64dec(as_str(&first_req["stderr_base64"]))),
                )
            };
            if carried.0 != raw.0 || carried.1 != raw.1 {
                panic!(
                    "capture {run}: the capture adapter for axis {axis} on the {side} side did not receive the truly raw outcome"
                );
            }
        }
    }

    // 4. Residuals: records rederive their fingerprints; the receipt entries
    //    derive from the records; dispositions bind the exact event and the
    //    chain is hash-verified; signs derive from trajectories; tokens
    //    rederive.
    let mut residual_records: BTreeMap<String, Value> = BTreeMap::new();
    for rid in cap["residuals"].as_array().cloned().unwrap_or_default() {
        let rid = as_str(&rid).to_string();
        residual_records.insert(
            rid.clone(),
            load_evidence(&safe_rel(bundle, &format!("residuals/{rid}.json"))),
        );
    }
    for r in body["residuals"].as_array().cloned().unwrap_or_default() {
        let rid = as_str(&r["id"]).to_string();
        let record = residual_records
            .get(&rid)
            .unwrap_or_else(|| panic!("receipt residual {rid} is not in the run's capture"));
        if as_str(&record["run"]) != run {
            panic!("residual {rid} belongs to another run");
        }
        if as_str(&r["axis"]) != as_str(&record["axis"])
            || as_str(&r["kind"]) != as_str(&record["kind"])
        {
            panic!("residual {rid} does not derive from its record file");
        }
        if as_str(&r["raw_reference_hash"]) != as_str(&record["raw_reference_sha256"])
            || as_str(&r["raw_candidate_hash"]) != as_str(&record["raw_candidate_sha256"])
        {
            panic!("residual {rid} raw hashes do not rederive");
        }
        if as_str(&r["residual_fingerprint"]) != residual_fingerprint(record) {
            panic!("residual fingerprint of {rid} does not rederive");
        }

        let ev_dir = bundle.join(format!("residuals/{rid}.events"));
        let mut events: Vec<Value> = Vec::new();
        if ev_dir.is_dir() {
            let mut names: Vec<String> = std::fs::read_dir(&ev_dir)
                .unwrap()
                .flatten()
                .map(|e| e.file_name().to_string_lossy().to_string())
                .filter(|n| n.ends_with(".json"))
                .collect();
            names.sort();
            events = names
                .iter()
                .map(|n| load_evidence(&ev_dir.join(n)))
                .collect();
        }
        let mut prev: Option<String> = None;
        for e in &events {
            if as_str(&e["event_id"]) != disposition_event_identity(e) {
                panic!("disposition event of {rid} is not content-addressed");
            }
            let parent = e.get("parent_event_id").and_then(|p| p.as_str());
            if parent != prev.as_deref() {
                panic!("disposition event chain of {rid} is broken");
            }
            prev = Some(as_str(&e["event_id"]).to_string());
        }
        if as_str(&r["disposition"]) == "open" {
            if r.get("disposition_event_id")
                .and_then(|v| v.as_str())
                .is_some()
            {
                panic!("open residual {rid} claims a disposition_event_id");
            }
        } else {
            let eid = as_str(&r["disposition_event_id"]).to_string();
            let event = events.iter().find(|e| as_str(&e["event_id"]) == eid);
            let event = event
                .unwrap_or_else(|| panic!("residual {rid} binds event {eid} not in its chain"));
            if as_str(&event["disposition"]) != as_str(&r["disposition"])
                || event.get("reason").and_then(|v| v.as_str())
                    != r.get("reason").and_then(|v| v.as_str())
            {
                panic!("residual {rid} disposition/reason does not match the bound event");
            }
            if event.get("resolution_run_id").and_then(|v| v.as_str())
                != r.get("resolution_run_id").and_then(|v| v.as_str())
            {
                panic!("residual {rid} resolution edge does not match the bound event");
            }
        }

        // v12: the sign is TRAJECTORY EVIDENCE per coordinate system. Each
        // entry PINs the exact ExecutionSeries snapshot the drift/slew were
        // derived from; the verifier replays that series (later experiments
        // that reference the same run can never change what a receipt means).
        let sign = &r["sign"];
        let entries = sign["trajectory_evidence"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let mut seen_coordinates: Vec<String> = Vec::new();
        for entry in &entries {
            let coord = as_str(&entry["coordinate_system"]).to_string();
            if seen_coordinates.contains(&coord) {
                panic!("residual {rid} names coordinate system {coord} twice");
            }
            seen_coordinates.push(coord.clone());
            let sid = as_str(&entry["series"]);
            if sid.is_empty() {
                panic!("residual {rid} has trajectory evidence without a pinned series");
            }
            let series = load_evidence(&safe_rel(bundle, &format!("series/{sid}.json")));
            if as_str(&series["id"]) != sid {
                panic!("series {sid} is not content-addressed");
            }
            if rederive::series_identity(
                as_str(&series["experiment_id"]),
                series.get("parent_series_id").and_then(|v| v.as_str()),
                as_str(&series["court"]),
                as_str(&series["coordinate_system"]),
                &series["points"],
            ) != sid
            {
                panic!("series {sid}: the recorded fields do not hash to the id");
            }
            if as_str(&series["coordinate_system"]) != coord {
                panic!(
                    "residual {rid}: the pinned series {sid} is a {} experiment, not {coord}",
                    as_str(&series["coordinate_system"])
                );
            }
            if !series["points"]
                .as_array()
                .map(|ps| {
                    ps.iter()
                        .any(|p| as_str(&p["run"]) == as_str(&record["run"]))
                })
                .unwrap_or(false)
            {
                panic!("residual {rid}: the pinned series {sid} does not contain its run");
            }
            let lineage = residual_lineage_of(bundle, record, &cap);
            let t = load_evidence(&safe_rel(
                bundle,
                &format!("trajectories/{lineage}.{coord}.{sid}.json"),
            ));
            if as_str(&t["subject"]) != lineage {
                panic!("trajectory of {rid} is not keyed by its lineage");
            }
            // frf-trajectory-v6: the trajectory is CONTENT-ADDRESSED — the
            // id rederives (FRF/TRAJECTORY/v1 over the canonical document
            // minus the id, the transform declaration included) and the
            // transform declaration is the trajectory transform (only the
            // coordinate varies). A relabeled or hand-edited trajectory is
            // refused.
            let mut tdoc = t.clone();
            if let Some(obj) = tdoc.as_object_mut() {
                obj.remove("id");
            }
            let tcanon = encode(&tdoc)
                .unwrap_or_else(|e| panic!("trajectory of {rid}: cannot canonicalize: {e}"));
            let trederived = sha256_bytes(format!("FRF/TRAJECTORY/v1\n{tcanon}").as_bytes());
            if as_str(&t["id"]) != trederived {
                panic!(
                    "trajectory of {rid} is not content-addressed: the canonical document minus the id hashes to {trederived}; refusing a hand-edited or relabeled trajectory"
                );
            }
            let tform = &t["transform"];
            let varying: Vec<&str> = tform["varying_dimensions"]
                .as_array()
                .map(|a| a.iter().map(|v| v.as_str().unwrap_or("")).collect())
                .unwrap_or_default();
            if as_str(&tform["kind"]) != "trajectory"
                || as_str(&tform["source"]) != sid
                || varying != ["coordinate"]
                || as_str(&tform["success_predicate"]) != "movement-classified"
            {
                panic!(
                    "trajectory of {rid} does not declare the trajectory transform (coordinate varies; movement-classified)"
                );
            }
            // The classification REDERIVES from the observations (sorted by
            // point), it is not read from the file's derivation: the
            // presence pattern over the coordinate system, with the
            // divergence magnitudes RECOMPUTED from the observed residuals'
            // compared projections (never trusted from the trajectory file).
            let mut obs: Vec<(u64, bool, Option<String>)> = t["observations"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .map(|o| {
                            (
                                o["point_index"].as_u64().unwrap_or(0),
                                o["observed"].as_bool().unwrap_or(false),
                                o["residual"].as_str().and_then(|rid| {
                                    let rec = load_evidence(&safe_rel(
                                        bundle,
                                        &format!("residuals/{rid}.json"),
                                    ));
                                    rederive::divergence_magnitude(
                                        as_str(&rec["axis"]),
                                        as_str(&rec["raw_reference"]),
                                        as_str(&rec["raw_candidate"]),
                                    )
                                }),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();
            obs.sort_by_key(|(rep, _, _)| *rep);
            let flags: Vec<bool> = obs.iter().map(|(_, o, _)| *o).collect();
            let magnitudes: Vec<Option<String>> = obs.iter().map(|(_, _, m)| m.clone()).collect();
            let kind = rederive::magnitude_kind(as_str(&t["axis"]));
            let (drift, slew, localization, bands, trend) =
                rederive::classify(&flags, as_str(&t["coordinate_system"]), &magnitudes, &kind);
            if drift != as_str(&t["derivation"]["drift"])
                || slew != as_str(&t["derivation"]["slew"])
                || localization != as_str(&t["derivation"]["localization"])
                || bands != t["derivation"]["bands"].as_u64().unwrap_or(0) as u32
                || trend != as_str(&t["derivation"]["trend"])
                || kind != as_str(&t["derivation"]["magnitude_kind"])
            {
                panic!("residual {rid} trajectory derivation does not rederive");
            }
            if drift != as_str(&entry["drift"]) || slew != as_str(&entry["slew"]) {
                panic!("residual {rid} sign does not match its pinned trajectory");
            }
            // The trajectory observations must match the series points.
            if t["observations"].as_array().map(|a| a.len()).unwrap_or(0)
                != series["points"].as_array().map(|a| a.len()).unwrap_or(0)
            {
                panic!("residual {rid} trajectory does not mirror its series");
            }
        }

        let family = as_str(&cap["court_spec"]["admissibility_envelope"]["fixture_family"]);
        let token = body["endoduction"]["tokens"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .find(|t| as_str(&t["residual_id"]) == rid)
            .unwrap_or_else(|| panic!("no token bound for {rid}"));
        if as_str(&token["token"]) != expected_token(&r)
            || as_str(&token["next_court"]) != kappa_next(&r)
            || as_str(&token["blocks_claims"][0]) != expected_blocks(&r, family)
        {
            panic!("the endoduction token of {rid} does not rederive");
        }
    }

    // 5. Resolution edges: a fixed closure must be backed by a run that
    //    reran the same question under a compatible envelope and closed the
    //    axis.
    for r in body["residuals"].as_array().cloned().unwrap_or_default() {
        let Some(resolution_run_id) = r.get("resolution_run_id").and_then(|v| v.as_str()) else {
            continue;
        };
        if resolution_run_id == run {
            panic!(
                "residual {} claims to be fixed by the run that observed it",
                as_str(&r["id"])
            );
        }
        let res_cap = load_evidence(&safe_rel(
            bundle,
            &format!("captures/{resolution_run_id}/capture.json"),
        ));
        if as_str(&res_cap["court_semantic_identity"]) != as_str(&cap["court_semantic_identity"]) {
            panic!("resolution run {resolution_run_id} does not rerun the same question");
        }
        if as_str(&res_cap["environment"]["digest"]) != as_str(&cap["environment"]["digest"]) {
            panic!("resolution run {resolution_run_id} crossed an environment boundary");
        }
        if !axis_agrees(
            &res_cap["reference"],
            &res_cap["candidate"],
            as_str(&r["axis"]),
        ) {
            panic!(
                "resolution run {resolution_run_id} does not close the {} axis",
                as_str(&r["axis"])
            );
        }
    }

    // 6. The manifest covers the receipt's complete required closure.
    for rel in needed_closure(bundle, &receipt_id) {
        if !inventory.contains_key(&rel) {
            panic!("bundle closure incomplete: {rel} is missing");
        }
    }

    // 6.5 The REFUSED execution attempts the bundle carries (the refusal-
    //     roots: a failed observation attempt is a first-class portable
    //     observation). Every `attempts/<id>.json` record must rederive its
    //     identity (FRF/EXECUTION-ATTEMPT/v1 over the record's own fields),
    //     be a `refused` attempt, and cite harness events that exist in the
    //     bundle, rederive THEIR identities (FRF/HARNESS-EVENT/v1), and
    //     belong to the SAME court — an attempt citing missing, corrupt, or
    //     foreign enforcement evidence is not self-consistent.
    let attempts_dir = bundle.join("attempts");
    if attempts_dir.is_dir() {
        for name in sorted_names(&attempts_dir) {
            if !name.ends_with(".json") {
                continue;
            }
            let id = name.trim_end_matches(".json").to_string();
            let attempt = load_evidence(&safe_rel(bundle, &format!("attempts/{id}.json")));
            if rederive::execution_attempt_identity(&attempt) != id {
                panic!("execution attempt {id} is not content-addressed: the recorded fields do not hash to the id");
            }
            if as_str(&attempt["kind"]) != "refused" {
                panic!(
                    "execution attempt {id}: unexpected kind {:?} (this schema admits only 'refused'; a completed attempt IS a run)",
                    as_str(&attempt["kind"])
                );
            }
            let mut seen: Vec<String> = Vec::new();
            for ev in attempt["harness_events"]
                .as_array()
                .cloned()
                .unwrap_or_default()
            {
                let eid = as_str(&ev).to_string();
                if seen.contains(&eid) {
                    panic!("execution attempt {id} cites harness event {eid} twice");
                }
                seen.push(eid.clone());
                let event = load_evidence(&safe_rel(bundle, &format!("harness/{eid}.json")));
                if rederive::harness_event_identity(&event) != eid {
                    panic!("execution attempt {id}: cited harness event {eid} is not content-addressed");
                }
                if as_str(&event["court"]) != as_str(&attempt["court"]) {
                    panic!(
                        "execution attempt {id}: cited harness event {eid} belongs to court {}; the attempt is not self-consistent",
                        as_str(&event["court"])
                    );
                }
            }
        }
    }

    // 7. The compiled claims bound to the receipt, when the bundle carries
    //    them: resolved through the claims/by-receipt index. Each claim's id
    //    must rederive (FRF/CLAIM/v1 over the canonical document minus the
    //    id — a hand-written or forged claim file is refused), its EVIDENCE
    //    UNIVERSE (the knowledge snapshot the absence search ran over) must
    //    be self-consistent — the snapshot cid rederives from its own
    //    fields, every residual head exists in the bundle with the recorded
    //    disposition, and every referenced reduction exists with a rederived
    //    identity. The negative search is as portable as the premises.
    let claim_index = bundle.join("claims/by-receipt").join(&receipt_id);
    if claim_index.is_dir() {
        let claim_ids: Vec<String> = sorted_names(&claim_index)
            .into_iter()
            .filter(|n| n.len() == 64)
            .collect();
        for claim_id in claim_ids {
            let claim_rel = format!("claims/{claim_id}.json");
            let claim = load_evidence(&safe_rel(bundle, &claim_rel));
            // The claim id rederives: FRF/CLAIM/v1 over the canonical
            // document minus the id field.
            let mut doc = claim.clone();
            if let Some(obj) = doc.as_object_mut() {
                obj.remove("id");
            }
            let canonical = encode(&doc)
                .unwrap_or_else(|e| panic!("claim {claim_id}: cannot canonicalize: {e}"));
            let expected = sha256_bytes(format!("FRF/CLAIM/v1\n{canonical}").as_bytes());
            if expected != claim_id {
                panic!(
                    "claim {claim_id} is not content-addressed: the canonical document minus the id hashes to {expected}; refusing to consume a hand-edited or forged claim"
                );
            }
            if let Err(e) = schema::admit("claim", as_str(&claim["schema_version"])) {
                panic!("claim {claim_id}: unexpected schema version: {e}");
            }
            // The transform declaration is the CLAIM transform
            // (frf-claim-v13): nothing varies — parity over the premises,
            // committed by the content address — and its SOURCE is the
            // COMPLETE canonical dependency set (source_set = the ClaimInputs
            // content address), which must REDERIVE from the claim + its
            // premise receipts in the bundle. A relabeled or under-describing
            // claim is refused.
            let ct = &claim["transform"];
            if as_str(&ct["kind"]) != "claim"
                || ct.get("source").is_some()
                || as_str(&ct["source_set"]).is_empty()
                || !ct["varying_dimensions"]
                    .as_array()
                    .map(|a| a.is_empty())
                    .unwrap_or(false)
                || as_str(&ct["observation_relation"]) != "parity"
                || as_str(&ct["success_predicate"]) != "scope-admitted"
            {
                panic!(
                    "claim {claim_id}: its transform declaration is not the claim transform (nothing varies; parity; scope-admitted; source_set = the ClaimInputs content address)"
                );
            }
            // The source_set rederives: the observations are the runs the
            // premise receipts bound (from the bundle's receipt documents).
            let mut observations: Vec<String> = Vec::new();
            if let Some(requires) = claim["requires"].as_array() {
                for rid in requires {
                    let rec =
                        load_evidence(&safe_rel(bundle, &format!("receipts/{}.json", as_str(rid))));
                    observations.push(as_str(&rec["run"]).to_string());
                }
            }
            let expected_inputs = rederive::claim_inputs_identity(&claim, &observations);
            if as_str(&ct["source_set"]) != expected_inputs {
                panic!(
                    "claim {claim_id}: its transform's source_set {} is not the rederived ClaimInputs content address {} — the claim transform must name its COMPLETE canonical dependency set",
                    &as_str(&ct["source_set"])[..16],
                    &expected_inputs[..16]
                );
            }
            let snapshot = &claim["knowledge_snapshot"];
            let expected_cid = rederive::knowledge_snapshot_identity(snapshot);
            if as_str(&snapshot["cid"]) != expected_cid {
                panic!("claim {receipt_id}: the knowledge snapshot cid does not rederive");
            }
            let mut head_ids: Vec<String> = Vec::new();
            if let Some(heads) = snapshot["residual_heads"].as_array() {
                for h in heads {
                    let hid = as_str(&h["id"]).to_string();
                    head_ids.push(hid.clone());
                    let record = load_evidence(&safe_rel(bundle, &format!("residuals/{hid}.json")));
                    if as_str(&record["id"]) != hid {
                        panic!("claim {receipt_id}: snapshot residual head {hid} is missing from the bundle");
                    }
                    // The v2 universe commits the head's RECORD CONTENT ADDRESS
                    // and FINGERPRINT — the exact immutable observation the
                    // blocker scan read — not the label. Both rederive from the
                    // bundle's own record.
                    let record_cid = sha256_bytes(
                        encode(&record)
                            .unwrap_or_else(|e| {
                                panic!(
                                    "claim {receipt_id}: cannot canonicalize residual {hid}: {e}"
                                )
                            })
                            .as_bytes(),
                    );
                    if record_cid != as_str(&h["record_cid"]) {
                        panic!(
                        "claim {receipt_id}: snapshot head {hid} record_cid does not rederive from the bundle's record"
                    );
                    }
                    if rederive::residual_fingerprint(&record) != as_str(&h["fingerprint"]) {
                        panic!(
                            "claim {receipt_id}: snapshot head {hid} fingerprint does not rederive"
                        );
                    }
                    // The head disposition must be the bundle's projected
                    // disposition for that residual (the events are verified
                    // elsewhere in this walk).
                    if projected_disposition(bundle, &hid) != as_str(&h["disposition"]) {
                        panic!(
                        "claim {receipt_id}: snapshot head {hid} disposition does not match its events"
                    );
                    }
                }
            }
            head_ids.sort();
            let mut snapshot_ids = head_ids.clone();
            snapshot_ids.dedup();
            if snapshot_ids.len() != head_ids.len() {
                panic!("claim {receipt_id}: duplicate residual heads in the knowledge snapshot");
            }
            // The v2 universe commits every other member as (kind, id, cid)
            // objects; each committed cid must REDERIVE from the bundle's own
            // object — a universe that names evidence the bundle cannot
            // reproduce is not the universe the claim was compiled under.
            if let Some(objects) = snapshot["objects"].as_array() {
                let mut seen: Vec<String> = Vec::new();
                for o in objects {
                    let key = format!("{}:{}", as_str(&o["kind"]), as_str(&o["id"]));
                    if seen.contains(&key) {
                        panic!(
                            "claim {receipt_id}: duplicate object {:?} in the knowledge snapshot",
                            key
                        );
                    }
                    seen.push(key);
                }
                for o in objects {
                    let kind = as_str(&o["kind"]);
                    let oid = as_str(&o["id"]);
                    let committed = as_str(&o["cid"]);
                    match kind {
                        "receipt" => {
                            // The receipt id is receipt-<run>-<digest>; the
                            // committed cid must equal that digest AND the
                            // canonical body must hash to it.
                            let rec =
                                load_evidence(&safe_rel(bundle, &format!("receipts/{oid}.json")));
                            let rest = oid
                                .strip_prefix("receipt-")
                                .and_then(|r| r.rsplit_once('-'))
                                .map(|(_, d)| d)
                                .unwrap_or("");
                            let digest = sha256_bytes(
                                encode(&rec)
                                    .unwrap_or_else(|e| {
                                        panic!("claim {receipt_id}: cannot canonicalize receipt {oid}: {e}")
                                    })
                                    .as_bytes(),
                            );
                            if committed != rest || committed != digest {
                                panic!("claim {receipt_id}: committed universe receipt {oid} does not rederive (cid {committed})");
                            }
                        }
                        "run" => {
                            // The run identity rederives from its capture; the
                            // committed cid is its digest.
                            let cap = load_evidence(&safe_rel(
                                bundle,
                                &format!("captures/{oid}/capture.json"),
                            ));
                            let residuals: Vec<Value> = cap["residuals"]
                                .as_array()
                                .cloned()
                                .unwrap_or_default()
                                .into_iter()
                                .map(|id| {
                                    load_evidence(&safe_rel(
                                        bundle,
                                        &format!("residuals/{}.json", as_str(&id)),
                                    ))
                                })
                                .collect();
                            let expected = format!(
                                "run-{}-{}",
                                as_str(&cap["court"]),
                                run_identity(&cap, &residuals)
                            );
                            if expected != oid {
                                panic!("claim {receipt_id}: committed universe run {oid} is not content-addressed");
                            }
                            let digest = oid
                                .strip_prefix("run-")
                                .and_then(|r| r.rsplit_once('-'))
                                .map(|(_, d)| d)
                                .unwrap_or("");
                            if committed != digest {
                                panic!("claim {receipt_id}: committed universe run {oid} cid does not match its identity ({committed})");
                            }
                        }
                        "authority" => {
                            // An authority id is a LABEL; the committed cid is
                            // the canonical hash of its record — the exact
                            // bytes the blocker scan's lineage computation
                            // reads.
                            let rec = load_evidence(&safe_rel(
                                bundle,
                                &format!("authorities/{oid}.json"),
                            ));
                            let actual = sha256_bytes(
                                encode(&rec)
                                    .unwrap_or_else(|e| {
                                        panic!("claim {receipt_id}: cannot canonicalize authority {oid}: {e}")
                                    })
                                    .as_bytes(),
                            );
                            if actual != committed {
                                panic!("claim {receipt_id}: committed universe authority {oid} does not rederive (cid {committed})");
                            }
                        }
                        "series" => {
                            // The series id IS its content address; the
                            // committed cid must equal it.
                            let series =
                                load_evidence(&safe_rel(bundle, &format!("series/{oid}.json")));
                            let expected = rederive::series_identity(
                                as_str(&series["experiment_id"]),
                                series["parent_series_id"].as_str(),
                                as_str(&series["court"]),
                                as_str(&series["coordinate_system"]),
                                &series["points"],
                            );
                            if expected != oid || committed != oid {
                                panic!("claim {receipt_id}: committed universe series {oid} does not rederive (cid {committed})");
                            }
                        }
                        "reduction" => {
                            let rid = oid;
                            let reduction =
                                load_evidence(&safe_rel(bundle, &format!("reductions/{rid}.json")));
                            if as_str(&reduction["id"]) != rid {
                                panic!(
                                "claim {receipt_id}: snapshot reduction {rid} is missing from the bundle"
                            );
                            }
                            let expected = rederive::reduction_identity(
                                as_str(&reduction["residual_id"]),
                                as_str(&reduction["source_run"]),
                                as_str(&reduction["axis"]),
                                as_str(&reduction["kind"]),
                                as_str(&reduction["court_semantic_identity"]),
                                as_str(&reduction["authority_artifact_sha256"]),
                                as_str(&reduction["candidate_artifact_sha256"]),
                                as_str(&reduction["environment_digest"]),
                                as_str(&reduction["comparator_semantic_id"]),
                                as_str(&reduction["comparator_semantic_hash"]),
                                as_str(&reduction["comparator_implementation_hash"]),
                                &reduction["argv_template"],
                                as_str(&reduction["original_fixture_sha256"]),
                                as_str(&reduction["final_fixture_sha256"]),
                                &reduction["attempts"],
                                &reduction["derivation"],
                                &reduction["transform"],
                                &minimizer_doc(&reduction),
                            );
                            if expected != rid || committed != rid {
                                panic!("claim {receipt_id}: committed universe reduction {rid} does not rederive (cid {committed})");
                            }
                        }
                        other => {
                            panic!("claim {receipt_id}: the knowledge universe names an unknown object kind {other:?}");
                        }
                    }
                }
            }
            // 7b. The TRAJECTORY PREMISES (frf-claim-v13): every premise's
            //     trajectory document must exist in the bundle, its content
            //     address must rederive (FRF/TRAJECTORY/v1), the copied
            //     classification must match the re-derived document, its
            //     axis must be a claimed observable — AND the premise must be
            //     BOUND TO ITS SUBJECT: the premise names the anchored
            //     premise receipt (∈ claim.requires) whose run is a point of
            //     the series, the axis is a clean declared observable of that
            //     receipt, and the lineage rederives from the receipt's
            //     authority/fixture-family/fixture semantics — an unrelated
            //     same-axis trajectory is never a movement premise.
            if let Some(premises) = claim["trajectory_premises"].as_array() {
                let scope: Vec<&str> = claim["observable_scope"]
                    .as_array()
                    .map(|a| a.iter().map(|v| v.as_str().unwrap_or("")).collect())
                    .unwrap_or_default();
                let requires: Vec<&str> = claim["requires"]
                    .as_array()
                    .map(|a| a.iter().map(|v| v.as_str().unwrap_or("")).collect())
                    .unwrap_or_default();
                let claim_candidate = as_str(&claim["candidate"]["identity_hash"]);
                for p in premises {
                    let lineage = as_str(&p["lineage"]);
                    let coord = as_str(&p["coordinate_system"]);
                    let sid = as_str(&p["series"]);
                    let receipt_id = as_str(&p["receipt"]);
                    let anchor_run = as_str(&p["anchor_run"]);
                    let t = load_evidence(&safe_rel(
                        bundle,
                        &format!("trajectories/{lineage}.{coord}.{sid}.json"),
                    ));
                    if !scope.iter().any(|a| *a == as_str(&p["axis"])) {
                        panic!(
                            "claim {receipt_id}: trajectory premise {lineage}.{coord}.{sid} is about axis {}, which the claim does not cover",
                            as_str(&p["axis"])
                        );
                    }
                    if as_str(&t["id"]) != as_str(&p["trajectory"]) {
                        panic!(
                            "claim {receipt_id}: trajectory premise {lineage}.{coord}.{sid} does not name its re-derived trajectory document"
                        );
                    }
                    let mut tdoc = t.clone();
                    if let Some(obj) = tdoc.as_object_mut() {
                        obj.remove("id");
                    }
                    let tcanon = encode(&tdoc).unwrap_or_else(|e| {
                        panic!("claim {receipt_id}: cannot canonicalize trajectory: {e}")
                    });
                    let trederived =
                        sha256_bytes(format!("FRF/TRAJECTORY/v1\n{tcanon}").as_bytes());
                    if as_str(&t["id"]) != trederived {
                        panic!("claim {receipt_id}: trajectory premise {lineage}.{coord}.{sid} is not content-addressed");
                    }
                    if as_str(&t["derivation"]["drift"]) != as_str(&p["drift"])
                        || as_str(&t["derivation"]["slew"]) != as_str(&p["slew"])
                        || as_str(&t["derivation"]["localization"]) != as_str(&p["localization"])
                        || as_str(&t["derivation"]["bands"]) != as_str(&p["bands"])
                        || as_str(&t["axis"]) != as_str(&p["axis"])
                    {
                        panic!(
                            "claim {receipt_id}: trajectory premise {lineage}.{coord}.{sid} does not match its re-derived document"
                        );
                    }
                    // THE SUBJECT BINDING (frf-claim-v13).
                    if !requires.contains(&receipt_id) {
                        panic!(
                            "claim {receipt_id}: trajectory premise {lineage}.{coord}.{sid} anchors receipt {receipt_id}, which is not a premise of this claim"
                        );
                    }
                    let anchored =
                        load_evidence(&safe_rel(bundle, &format!("receipts/{receipt_id}.json")));
                    if as_str(&anchored["run"]) != anchor_run {
                        panic!(
                            "claim {receipt_id}: trajectory premise {lineage}.{coord}.{sid} anchor run {anchor_run} is not the anchored receipt's run ({})",
                            as_str(&anchored["run"])
                        );
                    }
                    let series = load_evidence(&safe_rel(bundle, &format!("series/{sid}.json")));
                    if as_str(&series["court"]) != as_str(&anchored["court"]["id"]) {
                        panic!(
                            "claim {receipt_id}: trajectory premise {lineage}.{coord}.{sid} series belongs to court {}, not the anchored receipt's court {}",
                            as_str(&series["court"]),
                            as_str(&anchored["court"]["id"])
                        );
                    }
                    let point_in_series = series["points"]
                        .as_array()
                        .map(|pts| pts.iter().any(|pt| as_str(&pt["run"]) == anchor_run))
                        .unwrap_or(false);
                    if !point_in_series {
                        panic!(
                            "claim {receipt_id}: trajectory premise {lineage}.{coord}.{sid} anchor run {anchor_run} is not a point of its series"
                        );
                    }
                    // The axis is a clean declared observable of the anchored
                    // receipt (declared passing; no residual on the axis).
                    let declared_clean = anchored["observables"]
                        .as_array()
                        .map(|obs| {
                            obs.iter().any(|o| {
                                as_str(&o["axis"]) == as_str(&p["axis"])
                                    && as_str(&o["verdict"]) == "pass"
                            })
                        })
                        .unwrap_or(false)
                        && !anchored["residuals"]
                            .as_array()
                            .map(|res| res.iter().any(|r| as_str(&r["axis"]) == as_str(&p["axis"])))
                            .unwrap_or(false);
                    if !declared_clean {
                        panic!(
                            "claim {receipt_id}: trajectory premise {lineage}.{coord}.{sid} is about axis {}, which is not a clean declared observable of its anchored receipt {receipt_id}",
                            as_str(&p["axis"])
                        );
                    }
                    // The lineage rederives from the anchored receipt's
                    // subject semantics: the movement's own first observed
                    // residual record names kind/surface; the anchored
                    // receipt names authority/fixture-family/fixture.
                    let observed = t["observations"]
                        .as_array()
                        .and_then(|obs| {
                            obs.iter().find(|o| {
                                o.get("observed")
                                    .and_then(|v| v.as_bool())
                                    .unwrap_or(false)
                            })
                        })
                        .unwrap_or_else(|| {
                            panic!("claim {receipt_id}: trajectory premise {lineage}.{coord}.{sid} has no observed point")
                        });
                    let obs_residual = as_str(&observed["residual"]);
                    if obs_residual.is_empty() {
                        panic!("claim {receipt_id}: trajectory premise {lineage}.{coord}.{sid} observed point names no residual");
                    }
                    let residual =
                        load_evidence(&safe_rel(bundle, &format!("residuals/{obs_residual}.json")));
                    if as_str(&residual["axis"]) != as_str(&p["axis"]) {
                        panic!("claim {receipt_id}: trajectory premise {lineage}.{coord}.{sid} own observed residual {obs_residual} is about axis {}, not the premise's axis", as_str(&residual["axis"]));
                    }
                    let fixture = anchored["fixtures"]
                        .as_array()
                        .and_then(|f| f.first())
                        .map(|f| as_str(&f["id"]))
                        .unwrap_or("");
                    if fixture.is_empty() {
                        panic!("claim {receipt_id}: trajectory premise {lineage}.{coord}.{sid} anchored receipt {receipt_id} carries no fixture");
                    }
                    let rederived = rederive::residual_lineage(
                        as_str(&residual["kind"]),
                        as_str(&p["axis"]),
                        residual.get("surface").and_then(|s| s.as_str()),
                        as_str(&anchored["court"]["admissibility_envelope"]["fixture_family"]),
                        as_str(&anchored["authority"]["name"]),
                        fixture,
                    );
                    if rederived != lineage {
                        panic!(
                            "claim {receipt_id}: trajectory premise {lineage}.{coord}.{sid} is NOT about the anchored receipt's subject: its lineage rederives to {} from the receipt's authority/fixture-family/fixture semantics",
                            &rederived[..16]
                        );
                    }
                    // On candidate_revision the candidate varies by design:
                    // the anchored point must be the point that corresponds
                    // to the candidate the parity claim is about.
                    if coord == "candidate_revision" {
                        let capture = load_evidence(&safe_rel(
                            bundle,
                            &format!("captures/{anchor_run}/capture.json"),
                        ));
                        if as_str(&capture["candidate_artifact"]["sha256"]) != claim_candidate {
                            panic!("claim {receipt_id}: trajectory premise {lineage}.{coord}.{sid} anchored point {anchor_run} executed candidate {}, not the claim's candidate {}", &as_str(&capture["candidate_artifact"]["sha256"])[..16], &claim_candidate[..16]);
                        }
                    }
                }
            }
            // 8. The claim's ADMISSION POLICY re-derives from the bundle alone:
            //    a sensitivity-backed claim must name challenge records that
            //    genuinely demonstrate sensitivity on every claimed axis, an
            //    independently-witnessed claim must name verified attestations of
            //    this receipt, and high-assurance must additionally be backed by
            //    the reference execution contract. The capability is evidence,
            //    never a boolean in the claim file.
            verify_claim_policy(bundle, &claim, &body, &receipt_id);
        }
    }

    let ir = claim_ir(&body, bundle);
    println!(
        "verified: bundle={} receipt={} run={} files={}",
        bundle.display(),
        receipt_id,
        run,
        inventory.len()
    );
    println!(
        "claim-ir: admissible={} harness={} observable_scope={} excluded_evidence={} blockers={}",
        ir.admissible,
        ir.harness_invalidated,
        serde_json::to_string(&ir.observable_scope).unwrap(),
        serde_json::to_string(&ir.excluded_evidence).unwrap(),
        serde_json::to_string(&ir.blockers).unwrap(),
    );
    ir
}

// ---------------------------------------------------------------------------
// Corpus mode
// ---------------------------------------------------------------------------

fn verify_corpus(dir: &Path) {
    let mut count = 0usize;
    for name in sorted_names(&dir.join("valid")) {
        let doc = load_json(&dir.join("valid").join(&name));
        let canonical = encode(&doc).unwrap_or_else(|e| panic!("valid/{name}: {e}"));
        let expected = String::from_utf8(read(&dir.join("canonical").join(&name)))
            .expect("canonical pin must be utf-8");
        if canonical != expected {
            panic!("valid/{name}: canonical bytes drifted");
        }
        let digest = sha256_bytes(canonical.as_bytes());
        let pinned = String::from_utf8(read(&dir.join("hashes").join(format!("{name}.sha256"))))
            .expect("hash pin must be utf-8");
        if digest != pinned.trim() {
            panic!("valid/{name}: digest drifted");
        }
        // The reduction-record family rederives its content address from its
        // own fields (the domain-aware minimality predicate enters the
        // identity exactly as it serializes) — the same function the bundle
        // verifier runs against committed universe members.
        if name.starts_with("reduction-") {
            let expected = rederive::reduction_identity(
                as_str(&doc["residual_id"]),
                as_str(&doc["source_run"]),
                as_str(&doc["axis"]),
                as_str(&doc["kind"]),
                as_str(&doc["court_semantic_identity"]),
                as_str(&doc["authority_artifact_sha256"]),
                as_str(&doc["candidate_artifact_sha256"]),
                as_str(&doc["environment_digest"]),
                as_str(&doc["comparator_semantic_id"]),
                as_str(&doc["comparator_semantic_hash"]),
                as_str(&doc["comparator_implementation_hash"]),
                &doc["argv_template"],
                as_str(&doc["original_fixture_sha256"]),
                as_str(&doc["final_fixture_sha256"]),
                &doc["attempts"],
                &doc["derivation"],
                &doc["transform"],
                &minimizer_doc(&doc),
            );
            if expected != as_str(&doc["id"]) {
                panic!("valid/{name}: the content address does not rederive from its own fields");
            }
        }
        count += 1;
    }
    for name in sorted_names(&dir.join("invalid")) {
        let source = read(&dir.join("invalid").join(&name));
        // Malformed JSON, duplicate property names (RFC 8785 §2 I-JSON), or
        // a document that does not deserialize as an OpenReceipt (unknown
        // properties refused) — all refusals.
        let refused = parse_strict(&source)
            .ok()
            .map(|v| structural_violations(&v).is_empty())
            .map(|v| !v)
            .unwrap_or(true);
        if !refused {
            panic!("invalid/{name}: must be refused");
        }
        count += 1;
    }
    for name in sorted_names(&dir.join("invalid-semantic")) {
        let doc = load_json(&dir.join("invalid-semantic").join(&name));
        if name.starts_with("detached-") {
            // The detached-objects declaration family (frf-detached-objects-v1):
            // structurally valid, semantically refused.
            if detached_semantic_violations(&doc).is_empty() {
                panic!("invalid-semantic/{name}: must fail detached-objects semantic conformance");
            }
            count += 1;
            continue;
        }
        if name.starts_with("reduction-") {
            // The reduction-record family (frf-reduction-v5): structurally
            // valid, semantically refused — the minimality predicate must be
            // exactly what the record's own attempts establish.
            if reduction_semantic_violations(&doc).is_empty() {
                panic!("invalid-semantic/{name}: must fail reduction semantic conformance");
            }
            count += 1;
            continue;
        }
        let struct_v = structural_violations(&doc);
        if !struct_v.is_empty() {
            panic!(
                "invalid-semantic/{name}: must be structurally valid: {}",
                struct_v.join("; ")
            );
        }
        let sem_v = semantic_violations(&doc);
        if sem_v.is_empty() {
            panic!("invalid-semantic/{name}: must fail semantic conformance");
        }
        count += 1;
    }
    // The kind protocol records (FRF/KIND/v1): each registered kind is
    // pinned byte-for-byte, and its derived identity rederives from the
    // record's own semantic fields.
    for name in sorted_names(&dir.join("kinds")) {
        let doc = load_json(&dir.join("kinds").join(&name));
        let canonical = encode(&doc).unwrap_or_else(|e| panic!("kinds/{name}: {e}"));
        let expected = String::from_utf8(read(&dir.join("canonical/kinds").join(&name)))
            .expect("kind canonical pin must be utf-8");
        if canonical != expected {
            panic!("kinds/{name}: canonical bytes drifted");
        }
        let digest = sha256_bytes(canonical.as_bytes());
        let stem = name.strip_suffix(".json").unwrap_or(&name);
        let pinned = String::from_utf8(read(
            &dir.join("hashes").join(format!("{stem}.kind.sha256")),
        ))
        .expect("kind hash pin must be utf-8");
        if digest != pinned.trim() {
            panic!("kinds/{name}: digest drifted");
        }
        // The identity field rederives from the record's own semantic fields.
        let rederived = kind_identity_parts(
            as_str(&doc["id"]),
            as_str(&doc["meaning"]),
            as_str(&doc["surface_grammar"]),
            as_str(&doc["comparator_family"]),
        );
        if rederived != as_str(&doc["identity"]) {
            panic!("kinds/{name}: the identity does not rederive from its own fields");
        }
        count += 1;
    }
    println!("corpus {}: {count} fixture(s) passed", dir.display());
}

fn sorted_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    names.sort();
    names
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "xtask — the independent FRF verifier + the empirical program\n\n\
             usage:\n\
               cargo xtask verify bundle <bundle.frf/>\n\
               cargo xtask verify corpus <conformance-dir>\n\
               cargo xtask regen corpus <conformance-dir>\n\
               cargo xtask regen-readme [--check]\n\
               cargo xtask experiment [OUT.json] [--no-check]\n\
               cargo xtask external-experiment [OUT.json] [--no-check]\n\
               cargo xtask external-experiment-v2 [OUT.json] [--no-check]\n\
               cargo xtask external-experiment-v3 [OUT.json] [--no-check]\n\
               cargo xtask external-experiment-v4 [OUT.json] [--no-check]
\
               cargo xtask external-experiment-v5 [OUT.json] [--no-check]\n"
        );
        std::process::exit(2);
    }
    let result = std::panic::catch_unwind(|| match args[1].as_str() {
        "verify" => {
            if args.len() < 4 {
                eprintln!("xtask: verify needs a target argument");
                std::process::exit(2);
            }
            match args[2].as_str() {
                "bundle" => {
                    let path = Path::new(&args[3]);
                    if path.is_file() {
                        // A single-file bundle: verify from a temp extraction;
                        // the archive itself is never mutated (the extractor
                        // enforces the confinement rules).
                        let bytes = read(path);
                        let temp = TempRoot::new();
                        extract_tar(&bytes, &temp.0);
                        let _ = verify_bundle(&temp.0, "single-tar");
                    } else {
                        // A DIRECTORY bundle gets the SAME confinement as the
                        // archive form before a single byte is read: the walk
                        // refuses symlinks/hard links/escapes and enforces the
                        // count/size caps, so a link can never smuggle a read
                        // outside the bundle.
                        confine_dir(path);
                        let _ = verify_bundle(path, "directory");
                    }
                }
                "corpus" => verify_corpus(Path::new(&args[3])),
                other => {
                    eprintln!("unknown verify target {other:?}");
                    std::process::exit(2);
                }
            }
        }
        "regen" => {
            if args.len() < 4 {
                eprintln!("xtask: regen needs a target argument");
                std::process::exit(2);
            }
            match args[2].as_str() {
                "corpus" => regen::regen_corpus(Path::new(&args[3])),
                other => {
                    eprintln!("unknown regen target {other:?}");
                    std::process::exit(2);
                }
            }
        }
        "regen-readme" => {
            let check = args.iter().any(|a| a == "--check");
            regen_readme::run(check);
        }
        "experiment" => {
            // The empirical program: seeded mutations over the cross-domain
            // corpus, measured against conventional suites (drives the
            // reference-engine binary as a subprocess; --no-check disables
            // the metric gates).
            let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
            let mut out = repo_root
                .join("golden")
                .join("work")
                .join("experiment.json");
            let mut check = true;
            for a in &args[2..] {
                match a.as_str() {
                    "--no-check" => check = false,
                    other => out = PathBuf::from(other),
                }
            }
            experiment::run(repo_root, &out, check);
        }
        "external-experiment" => {
            // The EXTERNAL empirical program: real historical defects across
            // domains (external-corpus/), measured with the reference engine
            // (--no-check disables the metric gates).
            let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
            let mut out = repo_root
                .join("golden")
                .join("work")
                .join("external-experiment.json");
            let mut check = true;
            for a in &args[2..] {
                match a.as_str() {
                    "--no-check" => check = false,
                    other => out = PathBuf::from(other),
                }
            }
            experiment_external::run(repo_root, &out, check);
        }
        "external-experiment-v2" => {
            // The EXTERNAL empirical program v2: the trajectory axes on real
            // historical defects — version ladders, environment matrices,
            // and authority transitions (--no-check disables the gates).
            let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
            let mut out = repo_root
                .join("golden")
                .join("work")
                .join("external-experiment-v2.json");
            let mut check = true;
            for a in &args[2..] {
                match a.as_str() {
                    "--no-check" => check = false,
                    other => out = PathBuf::from(other),
                }
            }
            experiment_external_v2::run(repo_root, &out, check);
        }
        "external-experiment-v3" => {
            // The EXTERNAL empirical program v3: the trajectory axes on the
            // ACTUAL upstream vulnerable and fixed releases (bash, OpenSSL,
            // Log4j) built from pinned sources by the hermetic recipes in
            // external-corpus/v3/ (--no-check disables the gates).
            let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
            let mut out = repo_root
                .join("golden")
                .join("work")
                .join("external-experiment-v3.json");
            let mut check = true;
            for a in &args[2..] {
                match a.as_str() {
                    "--no-check" => check = false,
                    other => out = PathBuf::from(other),
                }
            }
            experiment_external_v3::run(repo_root, &out, check);
        }
        "external-experiment-v4" => {
            // The EXTERNAL empirical program v4: the comparative measurement
            // study over the ACTUAL upstream corpus — the metric table of the
            // empirical-program review (defects, false positives, version and
            // environment boundaries, nondeterminism, challenge sensitivity,
            // minimization, claim inflation, replay, storage and runtime
            // overhead, localization, human investigation cost) measured
            // against golden, differential, and unit baselines executed BARE.
            // The log4shell case is skipped (and reported) when no JVM is
            // available (--no-check disables the gates).
            let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
            let mut out = repo_root
                .join("golden")
                .join("work")
                .join("external-experiment-v4.json");
            let mut check = true;
            for a in &args[2..] {
                match a.as_str() {
                    "--no-check" => check = false,
                    other => out = PathBuf::from(other),
                }
            }
            experiment_external_v4::run(repo_root, &out, check);
        }
        "external-experiment-v5" => {
            // The EXTERNAL empirical program v5: the PROPER benchmark
            // protocol for the single-host runtime overhead — warmups +
            // isolated samples (a fresh store per sample, so the reuse path
            // never short-circuits), wall + child CPU per sample,
            // p50/p90/p99/mean/stddev, the overhead ratio at the median and
            // the p90, and a machine description. Measurements only — the
            // gates are protocol-correctness gates (isolation, sample count,
            // quantile monotonicity, hermeticity at the run-identity level),
            // never timing thresholds (--no-check disables the gates).
            let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
            let mut out = repo_root
                .join("golden")
                .join("work")
                .join("external-experiment-v5.json");
            let mut check = true;
            for a in &args[2..] {
                match a.as_str() {
                    "--no-check" => check = false,
                    other => out = PathBuf::from(other),
                }
            }
            experiment_external_v5::run(repo_root, &out, check);
        }
        other => {
            eprintln!("unknown mode {other:?}");
            std::process::exit(2);
        }
    });
    match result {
        Ok(()) => std::process::exit(0),
        Err(panic) => {
            let msg = panic
                .downcast_ref::<String>()
                .map(|s| s.as_str())
                .or_else(|| panic.downcast_ref::<&str>().copied())
                .unwrap_or("operation failed");
            eprintln!("xtask: {msg}");
            std::process::exit(1);
        }
    }
}
