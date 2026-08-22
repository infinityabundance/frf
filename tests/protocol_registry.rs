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

/// Scan for `FRF/<NAME>/v<N>` domain tags. The lexical scan accepts the
/// whole token shape (`FRF/` + uppercase/hyphen names + `/v` + digits) and
/// then VALIDATES the shape — a scanner that stops at the first lowercase
/// character would never recognize an ordinary domain tag like `FRF/RUN/v2`
/// (the `v` is lowercase), and a tag whose name part still contains a `/`
/// after `rsplit_once('/')` is likewise not a domain tag. Both failure
/// modes made the old scan vacuously pass; the unit tests below pin the
/// recognition.
fn scan_domain_tokens(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut rest = text;
    while let Some(pos) = rest.find("FRF/") {
        let after = &rest[pos + "FRF/".len()..];
        let end = after
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '/'))
            .unwrap_or(after.len());
        let token = format!("FRF/{}", &after[..end]);
        if is_domain_tag(&token) {
            out.insert(token);
        }
        rest = &after[end..];
    }
    out
}

/// The domain-tag shape: `FRF/<NAME>/v<N>` where NAME is one or more
/// uppercase letters/hyphens (no slashes) and N is one or more digits.
fn is_domain_tag(token: &str) -> bool {
    let Some((head, ver)) = token.rsplit_once("/v") else {
        return false;
    };
    if ver.is_empty() || !ver.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let Some(name) = head.strip_prefix("FRF/") else {
        return false;
    };
    !name.is_empty() && name.chars().all(|c| c.is_ascii_uppercase() || c == '-')
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
    let mut found_any = false;
    for root in ["src", "xtask/src", "verifier-go", "tests", "spec"] {
        for (path, text) in walk(root) {
            if path.contains("/target/") {
                continue;
            }
            for token in scan_schema_tokens(&text) {
                found_any = true;
                if !schemas.contains(&token) && !profiles.contains(&token) {
                    missing.push(format!(
                        "{path}: schema/profile {token} is not in the registry"
                    ));
                }
            }
            for token in scan_domain_tokens(&text) {
                found_any = true;
                if !domains.contains(&token) {
                    missing.push(format!(
                        "{path}: identity domain {token} is not in the registry"
                    ));
                }
            }
        }
    }
    // The scanners must actually RECOGNIZE tags, or this test is vacuous —
    // a scanner that recognizes nothing reports nothing missing. The code
    // below has an identity domain in it (FRF/KNOWLEDGE/v2 in the comment),
    // so a healthy scanner always finds at least the schema and domain sets.
    assert!(
        found_any,
        "the scanners recognized no protocol tags at all — this test would be vacuous"
    );
    assert!(
        missing.is_empty(),
        "unregistered protocol identifiers (spec drift is a protocol defect):\n{}",
        missing.join("\n")
    );
}

#[test]
fn the_readme_registry_tables_are_generated_projections() {
    // The README block between the PROTOCOL-REGISTRY markers must BE the
    // projection of the registry — not merely "contain" each id somewhere.
    // The xtask generator rewrites the block from protocol/registry.json;
    // this test runs its --check mode, which byte-compares the committed
    // block against the generated one and exits non-zero on any drift.
    let xtask = Path::new(MANIFEST).join("xtask/Cargo.toml");
    let out = std::process::Command::new(env!("CARGO"))
        .args(["run", "--quiet", "--manifest-path"])
        .arg(&xtask)
        .args(["--", "regen-readme", "--check"])
        .current_dir(MANIFEST)
        .output()
        .expect("cargo xtask regen-readme --check must run");
    assert!(
        out.status.success(),
        "README.md's protocol registry tables drifted from protocol/registry.json — run `cargo xtask regen-readme` and commit the result.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn the_domain_scanner_recognizes_ordinary_domain_tags() {
    // The regression that motivated the rewrite: the scanner stopped at the
    // first lowercase character (the `v` in `/v1`) and then failed the name
    // check because the name still contained a `/`. It could not recognize
    // an ordinary domain tag at all, so the registry test passed vacuously.
    let cases: &[(&str, &[&str])] = &[
        ("x FRF/RUN/v2 y", &["FRF/RUN/v2"]),
        (
            "FRF/CAPTURE-ADAPTER-RESULT/v1",
            &["FRF/CAPTURE-ADAPTER-RESULT/v1"],
        ),
        ("FRF/COURT/v2", &["FRF/COURT/v2"]),
        (
            "FRF/RUN/v2 and FRF/OBSERVATION/v1 and FRF/EXECUTION/v1 and FRF/REDUCTION/v3",
            &[
                "FRF/EXECUTION/v1",
                "FRF/OBSERVATION/v1",
                "FRF/REDUCTION/v3",
                "FRF/RUN/v2",
            ],
        ),
        // Invalid shapes must not be recognized.
        ("FRF/run/v1", &[]),
        ("FRF/RUN/v", &[]),
        ("FRF/RUN/v1x", &[]),
        ("FRF/RUN", &[]),
        ("FRF/RUN/1", &[]),
    ];
    for (input, expected) in cases {
        let got: Vec<String> = scan_domain_tokens(input).into_iter().collect();
        assert_eq!(
            got, *expected,
            "scan_domain_tokens({input:?}) — a scanner that misses a real tag or accepts a fake one breaks the registry guarantee"
        );
    }
    // The specific regression: an ordinary tag must be recognized.
    assert!(scan_domain_tokens("FRF/RUN/v2").contains("FRF/RUN/v2"));
    assert!(scan_domain_tokens("FRF/CAPTURE-ADAPTER-RESULT/v1")
        .contains("FRF/CAPTURE-ADAPTER-RESULT/v1"));
}

#[test]
fn the_schema_scanner_recognizes_ordinary_schema_ids() {
    let cases: &[(&str, &[&str])] = &[
        ("frf-receipt-v15", &["frf-receipt-v15"]),
        ("frf-mutation-request-v1", &["frf-mutation-request-v1"]),
        (
            "frf-receipt-v15 and frf-claim-v7",
            &["frf-claim-v7", "frf-receipt-v15"],
        ),
        // Invalid shapes must not be recognized.
        ("frf-receipt", &[]),
        ("frf-receipt-v", &[]),
        ("frf-receipt-v15x", &[]),
        ("frf-Receipt-v15", &[]),
    ];
    for (input, expected) in cases {
        let got: Vec<String> = scan_schema_tokens(input).into_iter().collect();
        assert_eq!(got, *expected, "scan_schema_tokens({input:?})");
    }
}

#[test]
fn the_registry_has_no_vacuous_domains() {
    // The registry's identity list must contain real domains (the scan above
    // depends on them), and every registered domain must be recognizable by
    // the scanner itself — otherwise a registry entry that is not a domain
    // tag would be unfindable by construction.
    let reg = registry();
    let domains = collect(&reg, "identities", "domain");
    for d in &domains {
        assert!(
            is_domain_tag(d),
            "registry domain {d} is not a valid FRF/<NAME>/v<N> tag"
        );
    }
}
