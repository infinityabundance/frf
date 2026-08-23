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
use crate::model::DetachedObjectRef;
use crate::store::Store;
use crate::verify;

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
                }
                Err(e) => errors.push(format!("capture {run}: {e}")),
            }
        }
    }

    let graph_verified = errors.is_empty();
    let closure_complete = detached.is_empty();

    println!("evidence status (root {})", store.root.display());
    if let Some(decl) = &declaration {
        println!(
            "  detached declaration: {} ({})",
            decl.schema_version, decl.policy
        );
    }
    println!("  verified: {receipts_verified} receipt(s), {captures_verified} capture(s)");
    if graph_verified {
        println!("  graph_verified: yes");
    } else {
        println!("  graph_verified: NO");
        for e in &errors {
            println!("    {e}");
        }
    }
    if closure_complete {
        println!("  object_closure: complete");
        println!("  replayable: yes");
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
        println!("  replayable: no — hydrate the detached payloads first (verify each against its declared CID)");
    }
    if !graph_verified {
        return Err(FrfError::new(format!(
            "evidence status: the graph does not verify ({} violation(s))",
            errors.len()
        )));
    }
    Ok(())
}
