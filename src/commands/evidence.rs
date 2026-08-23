//! `frf evidence status`: the three-state verification report of an
//! evidence tree.
//!
//! The engine distinguishes, mechanically:
//!
//!   - **graph_verified** — every canonical document parses, every identity
//!     rederives, and every referenced content address resolves: its bytes
//!     are present and verified, OR it is declared detached in
//!     `detached-objects.json` (frf-detached-objects-v1) with a
//!     reconstruction recipe;
//!   - **object_closure** — `complete` when every referenced CID's bytes are
//!     present, or `incomplete-by-policy` naming the declared-detached
//!     payloads;
//!   - **replayable** — the closure is complete (replay additionally checks
//!     execution provenance; a detached tree is never replayable until
//!     hydrated).
//!
//! A declared-detached publication is NEVER treated as corruption: the graph
//! verifies, the closure reports exactly what is withheld and how to rebuild
//! it, and replay refuses until the bytes are materialized locally and
//! verified against the declared CIDs.
use crate::error::{FrfError, Result};
use crate::model::{DetachedObjectRef, DetachedObjects};
use crate::store::Store;
use crate::verify;
use std::io::Write;
use std::path::{Path, PathBuf};

fn push_unique(detached: &mut Vec<DetachedObjectRef>, entry: DetachedObjectRef) {
    if !detached.contains(&entry) {
        detached.push(entry);
    }
}

pub fn status(store: &Store) -> Result<()> {
    // The detached declaration (if any) — a malformed declaration is refused
    // before anything is reported.
    let declaration = store.load_detached_objects()?;

    let mut detached: Vec<DetachedObjectRef> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut receipts_verified = 0usize;
    let mut captures_verified = 0usize;
    let mut surface_declared = 0usize;
    let mut surface_withheld = 0usize;

    // Walk every committed receipt: each must verify at the GRAPH level
    // (identity + derivation + every referenced CID resolving).
    let receipts_dir = store.root.join("receipts");
    if receipts_dir.is_dir() {
        let mut names: Vec<String> = std::fs::read_dir(&receipts_dir)
            .map_err(|e| FrfError::new(format!("cannot read {}: {e}", receipts_dir.display())))?
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.ends_with(".json"))
            .collect();
        names.sort();
        for name in names {
            let id = name.trim_end_matches(".json").to_string();
            match verify::load_receipt_verified(store, &id) {
                Ok(rv) => {
                    receipts_verified += 1;
                    for d in rv.detached() {
                        push_unique(&mut detached, d.clone());
                    }
                }
                Err(e) => errors.push(format!("receipt {id}: {e}")),
            }
        }
    }

    // Walk every committed capture (runs without a receipt — the series
    // members — must verify too).
    let captures_dir = store.root.join("captures");
    if captures_dir.is_dir() {
        let mut names: Vec<String> = std::fs::read_dir(&captures_dir)
            .map_err(|e| FrfError::new(format!("cannot read {}: {e}", captures_dir.display())))?
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        for run in names {
            match verify::load_capture_verified(store, &run) {
                Ok(cv) => {
                    captures_verified += 1;
                    for d in cv.detached {
                        push_unique(&mut detached, d);
                    }
                    if let Some(surface) = &cv.capture.publication_surface {
                        for p in surface {
                            surface_declared += 1;
                            if p.withholds_bytes() {
                                surface_withheld += 1;
                            }
                        }
                    }
                }
                Err(e) => errors.push(format!("capture {run}: {e}")),
            }
        }
    }

    let graph_verified = errors.is_empty();
    let closure_complete = detached.is_empty();
    let stream_closure_complete = surface_withheld == 0;

    println!("evidence status (root {})", store.root.display());
    if let Some(decl) = &declaration {
        println!(
            "  detached declaration: {} ({})",
            decl.schema_version, decl.policy
        );
    }
    println!("  verified: {receipts_verified} receipt(s), {captures_verified} capture(s)");
    if surface_declared > 0 {
        println!(
            "  capture surface: {surface_declared} stream(s) declared ({surface_withheld} withheld by policy)"
        );
    }
    // The publication manifest (written by `publish-detached`) is part of a
    // publication's contract: when present it must parse and its withheld
    // count must match the verified captures' surfaces.
    let manifest_path = store.root.join("publication-manifest.json");
    if manifest_path.is_file() {
        let manifest: crate::model::PublicationManifest =
            serde_json::from_str(&std::fs::read_to_string(&manifest_path).map_err(|e| {
                FrfError::new(format!(
                    "cannot read the publication manifest {}: {e}",
                    manifest_path.display()
                ))
            })?)
            .map_err(|e| {
                FrfError::new(format!(
                    "the publication manifest {} is not a valid publication manifest: {e}",
                    manifest_path.display()
                ))
            })?;
        if manifest.schema_version != crate::model::SCHEMA_PUBLICATION_MANIFEST {
            return Err(FrfError::new(format!(
                "the publication manifest has an unsupported schema {:?}",
                manifest.schema_version
            )));
        }
        let manifest_withheld = manifest.streams.iter().filter(|s| !s.published).count();
        if manifest_withheld != surface_withheld {
            return Err(FrfError::new(format!(
                "the publication manifest records {manifest_withheld} withheld stream(s) but the verified captures declare {surface_withheld} — the transform is inconsistent"
            )));
        }
        println!(
            "  publication manifest: {} stream disposition(s) recorded",
            manifest.streams.len()
        );
    }
    if graph_verified {
        println!("  graph_verified: yes");
    } else {
        println!("  graph_verified: NO");
        for e in &errors {
            println!("    {e}");
        }
    }
    if closure_complete && stream_closure_complete {
        println!("  object_closure: complete");
        println!("  stream_closure: complete");
        println!("  replayable: yes");
    } else {
        if closure_complete {
            println!("  object_closure: complete");
        } else {
            println!(
                "  object_closure: incomplete-by-policy ({} declared-detached payload(s))",
                detached.len()
            );
            for d in &detached {
                println!(
                    "    {}  role={}  publication={}  size={}",
                    &d.cid[..16],
                    d.role,
                    d.publication,
                    d.size
                );
                println!("      reconstruction: {}", d.reconstruction.recipe);
                if let Some(src) = &d.reconstruction.source_path {
                    println!("      source: {src}");
                }
                if let Some(p) = &d.path {
                    println!("      path: {p}");
                }
            }
        }
        if !stream_closure_complete {
            println!(
                "  stream_closure: incomplete-by-policy ({surface_withheld} withheld stream(s); identities + dispositions published, bytes local)"
            );
        }
        println!(
            "  replayable: no — hydrate the detached payloads and withheld streams first (verify each against its declared identity)"
        );
    }
    if !graph_verified {
        return Err(FrfError::new(format!(
            "evidence status: the graph does not verify ({} violation(s))",
            errors.len()
        )));
    }
    Ok(())
}

/// THE PUBLICATION TRANSFORM — `full local evidence -> publish-detached ->`
/// `publication tree`.
///
/// Copies a COMPLETE local evidence root to an output tree, withholding
/// every payload the policy declares detached, and writes the declaration
/// into the output. The transform is deterministic (identical input +
/// policy -> byte-identical output) and content-addressed in effect: the
/// output's documents are the input's documents, only the withheld bytes
/// are absent, and every withheld CID is declared with its reconstruction
/// recipe.
///
/// Refusals (fail-closed):
///   - the SOURCE tree must be complete — graph verified AND object closure
///     complete (you cannot publish a tree you cannot verify);
///   - every policy CID must actually exist in the source (an object or a
///     record at its declared path) — a policy that names nothing is a
///     hand-wave, not a declaration;
///   - the output must NOT already exist (the publication is written fresh,
///     never overwritten);
///   - after the transform the OUTPUT must verify at the graph level with
///     the closure incomplete-by-policy exactly as declared.
pub fn publish_detached(source: &Store, policy: &Path, output: &Path) -> Result<PathBuf> {
    // 1. The policy: a frf-detached-objects-v1 declaration naming the cids
    //    (and optional record paths) to withhold.
    let policy_bytes = std::fs::read(policy).map_err(|e| {
        FrfError::new(format!(
            "cannot read the publication policy {}: {e}",
            policy.display()
        ))
    })?;
    let policy_value = crate::canon::parse_strict(&policy_bytes)
        .map_err(|e| FrfError::new(format!("publication policy {}: {e}", policy.display())))?;
    let policy_doc: DetachedObjects = serde_json::from_value(policy_value)
        .map_err(|e| FrfError::new(format!("publication policy {}: {e}", policy.display())))?;
    policy_doc
        .validate_semantics()
        .map_err(|e| FrfError::new(format!("publication policy {}: {e}", policy.display())))?;

    // 2. The source must be COMPLETE before publication: graph verified AND
    //    every referenced object present.
    let status = status_impl(source)?;
    if !status.graph_verified {
        return Err(FrfError::new(
            "publish-detached: the source tree does not verify — nothing may be published",
        ));
    }
    if !status.closure_complete {
        return Err(FrfError::new(format!(
            "publish-detached: the source tree is already incomplete ({} declared-detached payload(s)); publish only from a COMPLETE local tree",
            status.detached.len()
        )));
    }

    // 3. Every policy CID must exist in the source (as an object, or as a
    //    record at its declared path).
    let source_root = source.root.clone();
    for entry in &policy_doc.objects {
        let object_path = source_root.join("objects").join("sha256").join(&entry.cid);
        let record_path = entry
            .path
            .as_ref()
            .map(|p| source_root.join(p))
            .unwrap_or_else(|| object_path.clone());
        if !object_path.is_file() && !record_path.is_file() {
            return Err(FrfError::new(format!(
                "publish-detached: policy cid {} exists nowhere in the source tree (no object, no record at {:?}) — the declaration must name real evidence",
                &entry.cid[..16],
                entry.path
            )));
        }
    }

    // 4. The output must be fresh.
    if output.exists() {
        return Err(FrfError::new(format!(
            "publish-detached: the output {} already exists; refusing to overwrite (remove it to re-publish)",
            output.display()
        )));
    }

    // 5. Copy the tree verbatim, withholding the declared payloads.
    copy_tree_withholding(&source_root, output, &policy_doc)?;

    // 5b. The capture-surface stream policies: every observed stream the
    //     source captures declared non-publishable (`hash-only`/`detached`)
    //     is withheld from the publication, its disposition record written
    //     where the bytes used to live, and every stream's disposition
    //     recorded in the publication manifest. The transform is explicit:
    //     a stream is either published as-is or withheld WITH its identity
    //     and policy recorded — nothing is silently altered.
    let publication_manifest = withhold_streams(source, output)?;
    let manifest_canonical = crate::canon::canonical(
        &serde_json::to_value(&publication_manifest)
            .map_err(|e| FrfError::new(format!("publication manifest: {e}")))?,
    )?;
    let manifest_path = output.join("publication-manifest.json");
    let mut mf = std::fs::File::create(&manifest_path)
        .map_err(|e| FrfError::new(format!("cannot create {}: {e}", manifest_path.display())))?;
    mf.write_all(manifest_canonical.as_bytes())
        .map_err(|e| FrfError::new(format!("cannot write {}: {e}", manifest_path.display())))?;
    mf.sync_all().ok();

    // 6. Write the declaration (canonical) into the publication.
    let canonical = crate::canon::canonical(
        &serde_json::to_value(&policy_doc)
            .map_err(|e| FrfError::new(format!("publication policy: {e}")))?,
    )?;
    let decl_path = output.join("detached-objects.json");
    let mut f = std::fs::File::create(&decl_path)
        .map_err(|e| FrfError::new(format!("cannot create {}: {e}", decl_path.display())))?;
    f.write_all(canonical.as_bytes())
        .map_err(|e| FrfError::new(format!("cannot write {}: {e}", decl_path.display())))?;
    f.sync_all().ok();

    // 7. The output must verify at the graph level with the closure
    //    incomplete-by-policy: every declared payload ABSENT from the
    //    output, every declared-detached reference within the policy, and at
    //    least one payload actually withheld.
    for entry in &policy_doc.objects {
        let obj = output.join("objects").join("sha256").join(&entry.cid);
        let rec = entry
            .path
            .as_ref()
            .map(|p| output.join(p))
            .unwrap_or_else(|| obj.clone());
        if obj.is_file() || rec.is_file() {
            return Err(FrfError::new(format!(
                "publish-detached: payload {} was NOT withheld — the transform produced a publication that still carries it",
                &entry.cid[..16]
            )));
        }
    }
    let out_store = Store::new(output.to_path_buf());
    let out_status = status_impl(&out_store)?;
    if !out_status.graph_verified {
        return Err(FrfError::new(
            "publish-detached: the produced publication does not verify at the graph level — the transform failed closed",
        ));
    }
    let stream_withheld_any = publication_manifest.streams.iter().any(|s| !s.published);
    if out_status.closure_complete && !stream_withheld_any {
        return Err(FrfError::new(
            "publish-detached: the produced publication withholds NOTHING — no declared payload existed in the source and no capture-surface stream is non-publishable",
        ));
    }
    for d in &out_status.detached {
        if !policy_doc.objects.iter().any(|o| o.cid == d.cid) {
            return Err(FrfError::new(format!(
                "publish-detached: the produced publication reports a declared-detached cid {} that the policy does not name — the transform is inconsistent",
                &d.cid[..16]
            )));
        }
    }

    Ok(output.to_path_buf())
}

struct EvidenceStatus {
    graph_verified: bool,
    closure_complete: bool,
    detached: Vec<DetachedObjectRef>,
}

fn status_impl(store: &Store) -> Result<EvidenceStatus> {
    let mut detached: Vec<DetachedObjectRef> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let receipts_dir = store.root.join("receipts");
    if receipts_dir.is_dir() {
        for entry in std::fs::read_dir(&receipts_dir)
            .map_err(|e| FrfError::new(format!("cannot read {}: {e}", receipts_dir.display())))?
        {
            let entry = entry.map_err(|e| FrfError::new(format!("read_dir: {e}")))?;
            if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.ends_with(".json") {
                continue;
            }
            let id = name.trim_end_matches(".json").to_string();
            match verify::load_receipt_verified(store, &id) {
                Ok(rv) => {
                    for d in rv.detached() {
                        push_unique(&mut detached, d.clone());
                    }
                }
                Err(e) => errors.push(format!("receipt {id}: {e}")),
            }
        }
    }
    let captures_dir = store.root.join("captures");
    if captures_dir.is_dir() {
        for entry in std::fs::read_dir(&captures_dir)
            .map_err(|e| FrfError::new(format!("cannot read {}: {e}", captures_dir.display())))?
        {
            let entry = entry.map_err(|e| FrfError::new(format!("read_dir: {e}")))?;
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let run = entry.file_name().to_string_lossy().to_string();
            match verify::load_capture_verified(store, &run) {
                Ok(cv) => {
                    for d in cv.detached {
                        push_unique(&mut detached, d);
                    }
                }
                Err(e) => errors.push(format!("capture {run}: {e}")),
            }
        }
    }
    Ok(EvidenceStatus {
        graph_verified: errors.is_empty(),
        closure_complete: detached.is_empty(),
        detached,
    })
}

/// Copy `src` to `dst`, skipping every withheld payload (objects/sha256/<cid>
/// and the declared record paths). Everything else is copied verbatim
/// (permissions preserved).
fn copy_tree_withholding(src: &Path, dst: &Path, policy: &DetachedObjects) -> Result<()> {
    copy_tree_withholding_from(src, dst, src, policy)
}

fn copy_tree_withholding_from(
    src: &Path,
    dst: &Path,
    root: &Path,
    policy: &DetachedObjects,
) -> Result<()> {
    let withhold_objects: std::collections::HashSet<&str> =
        policy.objects.iter().map(|o| o.cid.as_str()).collect();
    let withhold_paths: std::collections::HashSet<&str> = policy
        .objects
        .iter()
        .filter_map(|o| o.path.as_deref())
        .collect();
    std::fs::create_dir_all(dst)
        .map_err(|e| FrfError::new(format!("cannot create {}: {e}", dst.display())))?;
    for entry in std::fs::read_dir(src)
        .map_err(|e| FrfError::new(format!("cannot read {}: {e}", src.display())))?
    {
        let entry = entry.map_err(|e| FrfError::new(format!("read_dir: {e}")))?;
        let from = entry.path();
        // The FULL root-relative path: the recursion narrows `src`, but the
        // withholding rules are expressed against the evidence root
        // (objects/sha256/<cid>, and record paths under the root).
        let full_rel = from
            .strip_prefix(root)
            .map_err(|e| FrfError::new(e.to_string()))?;
        let rel = from
            .strip_prefix(src)
            .map_err(|e| FrfError::new(e.to_string()))?;
        let full_rel_str = full_rel.to_string_lossy();
        let to = dst.join(rel);
        let ft = entry
            .file_type()
            .map_err(|e| FrfError::new(format!("file_type: {e}")))?;
        if ft.is_dir() {
            copy_tree_withholding_from(&from, &to, root, policy)?;
        } else {
            // Withhold: an object whose cid is declared, or a record at a
            // declared path.
            if full_rel_str.starts_with("objects/sha256/") {
                if let Some(name) = full_rel.file_name().and_then(|n| n.to_str()) {
                    if withhold_objects.contains(name) {
                        continue;
                    }
                }
            }
            if withhold_paths.contains(full_rel_str.as_ref()) {
                continue;
            }
            std::fs::create_dir_all(to.parent().unwrap()).map_err(|e| {
                FrfError::new(format!(
                    "cannot create {}: {e}",
                    to.parent().unwrap().display()
                ))
            })?;
            std::fs::copy(&from, &to)
                .map_err(|e| FrfError::new(format!("cannot copy {}: {e}", from.display())))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&from)
                    .map_err(|e| FrfError::new(format!("metadata: {e}")))?
                    .permissions()
                    .mode();
                std::fs::set_permissions(&to, std::fs::Permissions::from_mode(mode))
                    .map_err(|e| FrfError::new(format!("permissions: {e}")))?;
            }
        }
    }
    Ok(())
}

/// The capture-surface pass of the publication transform: walk every source
/// capture, apply each declared stream policy to the OUTPUT copy, and return
/// the deterministic publication manifest.
///
/// - a stream declared `hash-only` or `detached` is withheld: its copied
///   bytes are REMOVED from the output and a disposition record
///   (`<side>.<stream>.pub.json`) naming the withheld bytes' SHA-256 and the
///   policy is written where the bytes used to live — the observation's
///   identity travels, its bytes do not;
/// - every other stream (and every undeclared stream — the default is
///   `inline`) is published as-is, recorded with `published: true`;
/// - every stream of every run is recorded in the publication manifest
///   (sorted, deterministic), so the publication can never silently alter
///   what an observation means.
fn withhold_streams(source: &Store, output: &Path) -> Result<crate::model::PublicationManifest> {
    use crate::model::{StreamDisposition, StreamPublicationRecord};
    let mut dispositions: Vec<StreamDisposition> = Vec::new();
    let captures_dir = source.root.join("captures");
    if !captures_dir.is_dir() {
        return Ok(crate::model::PublicationManifest {
            schema_version: crate::model::SCHEMA_PUBLICATION_MANIFEST.to_string(),
            streams: Vec::new(),
        });
    }
    let mut runs: Vec<String> = std::fs::read_dir(&captures_dir)
        .map_err(|e| FrfError::new(format!("cannot read {}: {e}", captures_dir.display())))?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    runs.sort();
    for run in runs {
        let capture = source.load_capture(&run)?.into_inner();
        let out_dir = output.join("captures").join(&run);
        for (side, s) in [
            ("reference", &capture.reference),
            ("candidate", &capture.candidate),
        ] {
            for (stream, sha) in [("stdout", &s.stdout_sha256), ("stderr", &s.stderr_sha256)] {
                let policy = capture
                    .publication_surface
                    .as_ref()
                    .and_then(|v| {
                        v.iter()
                            .find(|p| p.side == side && p.stream == stream)
                            .map(|p| p.policy.clone())
                    })
                    .unwrap_or_else(|| "inline".to_string());
                let withholds = policy == "hash-only" || policy == "detached";
                if withholds {
                    // Remove the copied bytes from the publication.
                    let stream_path = out_dir.join(format!("{side}.{stream}"));
                    if stream_path.is_file() {
                        std::fs::remove_file(&stream_path).map_err(|e| {
                            FrfError::new(format!("cannot withhold {}: {e}", stream_path.display()))
                        })?;
                    }
                    // Write the disposition record in their place.
                    let record = StreamPublicationRecord {
                        schema_version: crate::model::SCHEMA_STREAM_PUBLICATION.to_string(),
                        side: side.to_string(),
                        stream: stream.to_string(),
                        policy: policy.clone(),
                        sha256: sha.clone(),
                    };
                    let canonical = crate::canon::canonical(
                        &serde_json::to_value(&record)
                            .map_err(|e| FrfError::new(format!("stream disposition: {e}")))?,
                    )?;
                    let disp_path = out_dir.join(format!("{side}.{stream}.pub.json"));
                    std::fs::create_dir_all(disp_path.parent().unwrap()).map_err(|e| {
                        FrfError::new(format!(
                            "cannot create {}: {e}",
                            disp_path.parent().unwrap().display()
                        ))
                    })?;
                    let mut f = std::fs::File::create(&disp_path).map_err(|e| {
                        FrfError::new(format!("cannot create {}: {e}", disp_path.display()))
                    })?;
                    f.write_all(canonical.as_bytes()).map_err(|e| {
                        FrfError::new(format!("cannot write {}: {e}", disp_path.display()))
                    })?;
                    f.sync_all().ok();
                }
                dispositions.push(StreamDisposition {
                    run: run.clone(),
                    side: side.to_string(),
                    stream: stream.to_string(),
                    policy,
                    sha256: sha.clone(),
                    published: !withholds,
                });
            }
        }
    }
    dispositions.sort_by(|a, b| (&a.run, &a.side, &a.stream).cmp(&(&b.run, &b.side, &b.stream)));
    Ok(crate::model::PublicationManifest {
        schema_version: crate::model::SCHEMA_PUBLICATION_MANIFEST.to_string(),
        streams: dispositions,
    })
}
