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
mod jcs;
mod rederive;
mod regen;
mod rules;

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
    // The compiled claim, when present — and the EVIDENCE UNIVERSE its
    // knowledge snapshot names: every residual head's record + events + run
    // (the negative search must be reproducible from the bundle), plus the
    // reduction records it references.
    let claim_rel = format!("claims/{receipt_id}.json");
    if bundle.join(&claim_rel).is_file() {
        needed.insert(claim_rel.clone());
        let claim = load_evidence(&safe_rel(bundle, &claim_rel));
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
        // verified statement + its preserved request/response.
        if let Some(witnesses) = claim["witness_statements"].as_array() {
            for wid in witnesses {
                let wid = as_str(wid).to_string();
                needed.insert(format!("witnesses/{wid}.json"));
                for f in ["request.json", "response.json"] {
                    needed.insert(format!("witnesses/{wid}/{f}"));
                }
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
                let reduction = load_evidence(&safe_rel(bundle, &format!("reductions/{rid}.json")));
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
/// bundle's own objects (never trusted from the claim file).
fn verify_claim_policy(bundle: &Path, claim: &Value, body: &Value, receipt_id: &str) {
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

    // The claimed axes: every one must be covered by a capability entry.
    let claimed: Vec<String> = claim["observable_scope"]
        .as_array()
        .map(|a| a.iter().map(|v| as_str(v).to_string()).collect())
        .unwrap_or_default();
    let capability = claim["capability"].as_array().cloned().unwrap_or_default();
    let mut covered: Vec<String> = Vec::new();
    for cap in &capability {
        let axis = as_str(&cap["axis"]).to_string();
        let challenge_ids = cap["challenge_ids"].as_array().cloned().unwrap_or_default();
        if challenge_ids.is_empty() {
            panic!("claim {receipt_id}: capability entry for axis {axis} names no challenge");
        }
        for cid in challenge_ids {
            let cid = as_str(&cid).to_string();
            let ch = load_evidence(&safe_rel(bundle, &format!("challenges/{cid}.json")));
            if as_str(&ch["court"]) != as_str(&body["court"]["id"]) {
                panic!(
                    "claim {receipt_id}: challenge {cid} is not a challenge of the receipt's court"
                );
            }
            if as_str(&ch["target_axis"]) != axis {
                panic!(
                    "claim {receipt_id}: challenge {cid} targets {} not {axis}",
                    as_str(&ch["target_axis"])
                );
            }
            // The mutant wraps the same reference artifact the receipt binds.
            if as_str(&ch["reference_sha256"]) != as_str(&body["authority"]["identity_hash"]) {
                panic!("claim {receipt_id}: challenge {cid} does not wrap the receipt's reference artifact");
            }
            // The mutant run answered the same question.
            let chrun = as_str(&ch["run"]);
            let mut_cap =
                load_evidence(&safe_rel(bundle, &format!("captures/{chrun}/capture.json")));
            if as_str(&mut_cap["court_semantic_identity"])
                != as_str(&body["court"]["semantic_identity"])
            {
                panic!("claim {receipt_id}: challenge {cid} did not run the same question");
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
        covered.push(axis);
    }
    for axis in &claimed {
        if !covered.contains(axis) {
            panic!(
                "claim {receipt_id}: claimed axis {axis} has no capability coverage — the court never demonstrated it can see that surface"
            );
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
        let mut affirmed = false;
        for wid in witnesses {
            let wid = as_str(&wid).to_string();
            let stmt = load_evidence(&safe_rel(bundle, &format!("witnesses/{wid}.json")));
            if as_str(&stmt["subject"]["kind"]) != "receipt"
                || as_str(&stmt["subject"]["id"]) != receipt_id
            {
                panic!("claim {receipt_id}: witness {wid} does not attest this receipt");
            }
            // The preserved documents hash to their cids (the attestation is
            // bound to the exact request/response evidence).
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
            if as_str(&stmt["attestation"]["outcome"]) == "affirm" {
                affirmed = true;
            }
        }
        if !affirmed {
            panic!("claim {receipt_id}: no named witness affirms the receipt");
        }
    }

    if policy == "high-assurance" {
        if as_str(&body["execution_profile"]) != "frf-exec-linux-v1" {
            panic!("claim {receipt_id}: high-assurance requires the reference execution profile");
        }
        let bounds = &body["capture_bounds"];
        let reference = serde_json::json!({
            "timeout_ms": "60000",
            "max_stream_bytes": "16777216",
            "rlimit_as_mb": "2048",
            "rlimit_cpu_s": "30",
            "rlimit_nofile": "1024",
        });
        if bounds != &reference {
            panic!("claim {receipt_id}: high-assurance requires the reference capture bounds (the exact-replay contract)");
        }
        if as_str(&claim["replay_profile"]) != "frf-exec-linux-v1" {
            panic!("claim {receipt_id}: the claim's replay_profile does not record the reference profile");
        }
    }
}

fn verify_bundle(bundle: &Path, container: &str) -> rules::ClaimIr {
    let manifest = load_json(&safe_rel(bundle, "manifest.json"));
    if as_str(&manifest["schema_version"]) != "frf-bundle-v3" {
        panic!(
            "unsupported bundle schema version {:?}",
            manifest["schema_version"]
        );
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
            // The classification REDERIVES from the observations (sorted by
            // point), it is not read from the file's derivation.
            let mut obs: Vec<(u64, bool)> = t["observations"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .map(|o| {
                            (
                                o["point_index"].as_u64().unwrap_or(0),
                                o["observed"].as_bool().unwrap_or(false),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();
            obs.sort_by_key(|(rep, _)| *rep);
            let flags: Vec<bool> = obs.iter().map(|(_, o)| *o).collect();
            let (drift, slew, localization, bands) = classify(&flags);
            if drift != as_str(&t["derivation"]["drift"])
                || slew != as_str(&t["derivation"]["slew"])
                || localization != as_str(&t["derivation"]["localization"])
                || bands != t["derivation"]["bands"].as_u64().unwrap_or(0) as u32
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

    // 7. The compiled claim, when the bundle carries one: its EVIDENCE
    //    UNIVERSE (the knowledge snapshot the absence search ran over) must
    //    be self-consistent — the snapshot cid rederives from its own
    //    fields, every residual head exists in the bundle with the recorded
    //    disposition, and every referenced reduction exists with a rederived
    //    identity. The negative search is as portable as the premises.
    let claim_rel = format!("claims/{receipt_id}.json");
    if inventory.contains_key(&claim_rel) {
        let claim = load_evidence(&safe_rel(bundle, &claim_rel));
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
                            panic!("claim {receipt_id}: cannot canonicalize residual {hid}: {e}")
                        })
                        .as_bytes(),
                );
                if record_cid != as_str(&h["record_cid"]) {
                    panic!(
                        "claim {receipt_id}: snapshot head {hid} record_cid does not rederive from the bundle's record"
                    );
                }
                if rederive::residual_fingerprint(&record) != as_str(&h["fingerprint"]) {
                    panic!("claim {receipt_id}: snapshot head {hid} fingerprint does not rederive");
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
        // objects; the reduction records enter through kind == "reduction".
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
                if as_str(&o["kind"]) != "reduction" {
                    continue;
                }
                let rid = as_str(&o["id"]);
                let reduction = load_evidence(&safe_rel(bundle, &format!("reductions/{rid}.json")));
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
                    &reduction["minimizer"],
                );
                if expected != rid {
                    panic!("claim {receipt_id}: reduction {rid} is not content-addressed");
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
               cargo xtask experiment [OUT.json] [--no-check]\n"
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
                        // the archive itself is never mutated.
                        let bytes = read(path);
                        let temp = TempRoot::new();
                        extract_tar(&bytes, &temp.0);
                        let _ = verify_bundle(&temp.0, "single-tar");
                    } else {
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
