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
use std::path::Path;

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

fn load_yaml(path: &Path) -> Value {
    let text =
        String::from_utf8(read(path)).unwrap_or_else(|_| panic!("{}: not utf-8", path.display()));
    serde_yaml::from_str(&text)
        .unwrap_or_else(|e| panic!("{}: cannot parse YAML: {e}", path.display()))
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
        let cap = load_yaml(&safe_rel(bundle, &format!("captures/{run}/capture.yaml")));
        needed.insert(format!("captures/{run}/capture.yaml"));
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
        }
        needed.insert(format!("authorities/{}.yaml", as_str(&cap["authority"])));
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
        for id in cap["residuals"].as_array().cloned().unwrap_or_default() {
            let id = as_str(&id).to_string();
            if !seen_residuals.insert(id.clone()) {
                continue;
            }
            needed.insert(format!("residuals/{id}.yaml"));
            let ev_dir = bundle.join(format!("residuals/{id}.events"));
            if ev_dir.is_dir() {
                let mut names: Vec<String> = std::fs::read_dir(&ev_dir)
                    .unwrap()
                    .flatten()
                    .map(|e| e.file_name().to_string_lossy().to_string())
                    .filter(|n| n.ends_with(".yaml"))
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
            let record = load_yaml(&safe_rel(bundle, &format!("residuals/{id}.yaml")));
            let lineage = residual_lineage_of(bundle, &record, &cap);
            let series_dir = bundle.join("series");
            if series_dir.is_dir() {
                let mut names: Vec<String> = std::fs::read_dir(&series_dir)
                    .unwrap()
                    .flatten()
                    .map(|e| e.file_name().to_string_lossy().to_string())
                    .filter(|n| n.ends_with(".yaml"))
                    .collect();
                names.sort();
                for n in names {
                    let sid = n.trim_end_matches(".yaml").to_string();
                    let s = load_yaml(&safe_rel(bundle, &format!("series/{sid}.yaml")));
                    let contains = s["points"]
                        .as_array()
                        .map(|ps| ps.iter().any(|p| as_str(&p["run"]) == run.as_str()))
                        .unwrap_or(false);
                    if !contains {
                        continue;
                    }
                    needed.insert(format!("series/{sid}.yaml"));
                    let coord = as_str(&s["coordinate_system"]);
                    needed.insert(format!("trajectories/{lineage}.{coord}.{sid}.yaml"));
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
    let authority = load_yaml(&safe_rel(
        bundle,
        &format!("authorities/{authority_id}.yaml"),
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
    let cap = load_yaml(&safe_rel(bundle, &format!("captures/{run}/capture.yaml")));
    if as_str(&cap["run"]) != run {
        panic!("capture {run}: the run field inside capture.yaml does not match");
    }
    let residuals: Vec<Value> = cap["residuals"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|id| {
            load_yaml(&safe_rel(
                bundle,
                &format!("residuals/{}.yaml", as_str(&id)),
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

    // 4. Residuals: records rederive their fingerprints; the receipt entries
    //    derive from the records; dispositions bind the exact event and the
    //    chain is hash-verified; signs derive from trajectories; tokens
    //    rederive.
    let mut residual_records: BTreeMap<String, Value> = BTreeMap::new();
    for rid in cap["residuals"].as_array().cloned().unwrap_or_default() {
        let rid = as_str(&rid).to_string();
        residual_records.insert(
            rid.clone(),
            load_yaml(&safe_rel(bundle, &format!("residuals/{rid}.yaml"))),
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
                .filter(|n| n.ends_with(".yaml"))
                .collect();
            names.sort();
            events = names.iter().map(|n| load_yaml(&ev_dir.join(n))).collect();
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

        let sign = &r["sign"];
        if as_str(&sign["norm"]) == "single-run" {
            if as_str(&sign["drift"]) != "not-observed"
                || as_str(&sign["slew"]) != "not-observed"
                || sign.get("series").and_then(|v| v.as_str()).is_some()
            {
                panic!("single-run residual {rid} must carry not-observed drift/slew and no series pin");
            }
        } else if as_str(&sign["norm"]) == "repeated-run" {
            // The sign PINs the exact ExecutionSeries snapshot it was derived
            // from; the verifier replays that series (later experiments that
            // reference the same run can never change what a receipt means).
            let sid = as_str(&sign["series"]);
            if sid.is_empty() {
                panic!("repeated-run residual {rid} without a pinned series");
            }
            let series = load_yaml(&safe_rel(bundle, &format!("series/{sid}.yaml")));
            if as_str(&series["id"]) != sid {
                panic!("series {sid} is not content-addressed");
            }
            if rederive::series_identity(
                as_str(&series["court"]),
                as_str(&series["coordinate_system"]),
                &series["points"],
            ) != sid
            {
                panic!("series {sid}: the recorded fields do not hash to the id");
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
            let coord = as_str(&series["coordinate_system"]);
            let lineage = residual_lineage_of(bundle, record, &cap);
            let t = load_yaml(&safe_rel(
                bundle,
                &format!("trajectories/{lineage}.{coord}.{sid}.yaml"),
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
            if drift != as_str(&sign["drift"]) || slew != as_str(&sign["slew"]) {
                panic!("residual {rid} sign does not match its pinned trajectory");
            }
            // The trajectory observations must match the series points.
            if t["observations"].as_array().map(|a| a.len()).unwrap_or(0)
                != series["points"].as_array().map(|a| a.len()).unwrap_or(0)
            {
                panic!("residual {rid} trajectory does not mirror its series");
            }
        } else {
            panic!("residual {rid} has invalid sign norm {:?}", sign["norm"]);
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
        let res_cap = load_yaml(&safe_rel(
            bundle,
            &format!("captures/{resolution_run_id}/capture.yaml"),
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
    if args.len() < 4 {
        eprintln!(
            "xtask — the independent FRF verifier\n\n\
             usage:\n  cargo xtask verify bundle <bundle.frf/>\n  cargo xtask verify corpus <conformance-dir>\n  cargo xtask regen corpus <conformance-dir>"
        );
        std::process::exit(2);
    }
    let result = std::panic::catch_unwind(|| match args[1].as_str() {
        "verify" => match args[2].as_str() {
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
        },
        "regen" => match args[2].as_str() {
            "corpus" => regen::regen_corpus(Path::new(&args[3])),
            other => {
                eprintln!("unknown regen target {other:?}");
                std::process::exit(2);
            }
        },
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
