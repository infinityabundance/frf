//! The protocol registry (`protocol/registry.json`) is the machine-readable
//! inventory of the FRF evidence protocol — the AUTHORITY. For an evidence
//! protocol, spec drift is itself a protocol defect, so this test makes it a
//! build failure:
//!
//! 1. every schema version / identity domain used anywhere in the reference
//!    engine, the independent verifiers, the test suite, or the specification
//!    documents must occur in the registry (a version used in code but absent
//!    from the registry is an undocumented protocol surface);
//! 2. every admission policy and execution profile the engine declares must
//!    be registered;
//! 3. the README's registry tables (generated from the registry) must carry
//!    every registered id — a registry entry that vanished from the prose is
//!    a documentation regression.
//!
//! Run: `cargo test --test protocol_registry`.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const MANIFEST: &str = env!("CARGO_MANIFEST_DIR");

/// The registry is configuration, not evidence: it is read as strict JSON but
/// never required to be in canonical byte form (like a court manifest).
fn registry() -> serde_json::Value {
    let bytes = fs::read(Path::new(MANIFEST).join("protocol/registry.json")).unwrap();
    serde_json::from_slice(&bytes).expect("protocol/registry.json must parse")
}

/// Walk a directory tree, returning every file path and its text content.
fn walk(root: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let base = Path::new(MANIFEST).join(root);
    let mut stack = vec![base];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let bytes = fs::read(&path).unwrap();
            out.push((
                path.strip_prefix(MANIFEST)
                    .unwrap()
                    .to_string_lossy()
                    .to_string(),
                String::from_utf8_lossy(&bytes).into_owned(),
            ));
        }
    }
    out
}

/// Scan for `frf-…-v<N>`-shaped tokens (schemas and execution profiles share
/// the shape).
fn scan_schema_tokens(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut rest = text;
    while let Some(pos) = rest.find("frf-") {
        let after = &rest[pos + "frf-".len()..];
        let end = after
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
            .unwrap_or(after.len());
        let token = format!("frf-{}", &after[..end]);
        // The shape is `frf-<name>-v<N>` with a non-empty name and numeric N.
        if let Some((name, ver)) = token.rsplit_once("-v") {
            if !name.is_empty()
                && !ver.is_empty()
                && ver.chars().all(|c| c.is_ascii_digit())
                && name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            {
                out.insert(token);
            }
        }
        rest = &after[end..];
    }
    out
}

/// Scan for `FRF/<NAME>/v<N>` domain tags.
fn scan_domain_tokens(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut rest = text;
    while let Some(pos) = rest.find("FRF/") {
        let after = &rest[pos + "FRF/".len()..];
        let end = after
            .find(|c: char| !(c.is_ascii_uppercase() || c == '-' || c == '/'))
            .unwrap_or(after.len());
        let token = format!("FRF/{}", &after[..end]);
        if let Some((name, ver)) = token.rsplit_once('/') {
            if !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c == '-')
                // Allow a lowercase v in the version part (v1).
                && ver.starts_with('v')
                && ver[1..].chars().all(|c| c.is_ascii_digit())
            {
                out.insert(token);
            }
        }
        rest = &after[end..];
    }
    out
}

fn collect(registry: &serde_json::Value, key: &str, id_key: &str) -> BTreeSet<String> {
    registry[key]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|e| e[id_key].as_str().unwrap().to_string())
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn every_schema_and_domain_used_in_code_is_registered() {
    let reg = registry();
    let schemas = collect(&reg, "schemas", "id");
    let domains = collect(&reg, "identities", "domain");
    let policies = collect(&reg, "policies", "id");
    let profiles = collect(&reg, "execution_profiles", "id");

    // The engine's declared policy set and reference profile are registered.
    for p in [
        "baseline",
        "sensitivity-backed",
        "independently-witnessed",
        "high-assurance",
    ] {
        assert!(policies.contains(p), "policy {p} is not in the registry");
    }
    for p in ["frf-exec-linux-v1", "frf-exec-linux-v2"] {
        assert!(
            profiles.contains(p),
            "execution profile {p} is not in the registry"
        );
    }

    let mut missing: Vec<String> = Vec::new();
    for root in ["src", "xtask/src", "verifier-go", "tests", "spec"] {
        for (path, text) in walk(root) {
            if path.contains("/target/") {
                continue;
            }
            for token in scan_schema_tokens(&text) {
                if !schemas.contains(&token) && !profiles.contains(&token) {
                    missing.push(format!(
                        "{path}: schema/profile {token} is not in the registry"
                    ));
                }
            }
            for token in scan_domain_tokens(&text) {
                if !domains.contains(&token) {
                    missing.push(format!(
                        "{path}: identity domain {token} is not in the registry"
                    ));
                }
            }
        }
    }
    assert!(
        missing.is_empty(),
        "unregistered protocol identifiers (spec drift is a protocol defect):\n{}",
        missing.join("\n")
    );
}

#[test]
fn the_readme_registry_tables_carry_every_registered_id() {
    let reg = registry();
    let readme = fs::read_to_string(Path::new(MANIFEST).join("README.md")).unwrap();
    let mut ids: Vec<String> = Vec::new();
    ids.extend(collect(&reg, "objects", "id"));
    ids.extend(collect(&reg, "identities", "domain"));
    ids.extend(collect(&reg, "schemas", "id"));
    ids.extend(collect(&reg, "policies", "id"));
    ids.extend(collect(&reg, "execution_profiles", "id"));

    let mut missing: Vec<String> = Vec::new();
    for id in ids {
        // Every entry's id must occur in the README's registry tables.
        if !readme.contains(&id) {
            missing.push(id);
        }
    }
    assert!(
        missing.is_empty(),
        "the README registry tables are missing entries (regenerate from protocol/registry.json):\n{}",
        missing.join("\n")
    );
}
