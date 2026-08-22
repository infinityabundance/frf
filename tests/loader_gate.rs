//! The canonical-loader gate — there is EXACTLY ONE way to deserialize a
//! generated protocol evidence document.
//!
//! Evidence identities hash the DOCUMENT, never a typed projection: an
//! unknown property must survive into the canonical bytes or the document is
//! refused — it can never be discarded before the digest is recomputed.
//! Direct `serde_json::from_slice` of an evidence struct anywhere else would
//! reopen that hole (a loader that parses before canonicalizing cannot see
//! what it is hashing), so this test scans the engine's source and refuses
//! every `serde_json::from_slice` call site EXCEPT the three canonical
//! loaders:
//!
//! - `Store::parse_evidence` (store.rs) — the canonical evidence loader
//!   (strict JSON, bytes == canonical, then the typed projection);
//! - `ext::parse_canonical_response` (ext.rs) — the canonical RESPONSE
//!   loader for every extension protocol (comparator, normalizer, capture
//!   adapter, minimizer, witness, mutation);
//! - `canon::parse_strict` (canon.rs) — the strict-JSON parser (RFC 8785 §2
//!   I-JSON, duplicate property names refused) that both of the above and
//!   the canonicalizer itself are built on.
//!
//! A new `serde_json::from_slice` of an evidence struct anywhere else is a
//! protocol violation and fails this test (CI runs `cargo test`). Parsing a
//! comparator's captured STREAM as a JSON *value* (the built-in
//! `structured.state` surface compares documents, it does not deserialize
//! evidence) and test-only parsing are outside the rule and outside this
//! scan.

use std::path::PathBuf;

fn walk_rs(dir: &PathBuf, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            walk_rs(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The enclosing `fn` name of a source line: scan backwards to the nearest
/// top-level function declaration. (Closures and inner items never precede a
/// `serde_json::from_slice` evidence load in this codebase.)
fn enclosing_fn(lines: &[&str], line_index: usize) -> Option<String> {
    for l in lines[..=line_index].iter().rev() {
        let trimmed = l.trim_start();
        let rest = trimmed
            .strip_prefix("pub ")
            .or_else(|| trimmed.strip_prefix("pub(crate) "))
            .unwrap_or(trimmed)
            .strip_prefix("fn ")
            .map(|s| s.to_string());
        if let Some(sig) = rest {
            // The function NAME is the first identifier in the signature.
            return sig
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .next()
                .filter(|n| !n.is_empty())
                .map(str::to_string);
        }
    }
    None
}

/// Scan one file for `serde_json::from_slice` call sites outside the
/// canonical loaders. Returns the violation messages.
fn violations_in(path: &PathBuf) -> Vec<String> {
    let allowed = ["parse_evidence", "parse_canonical_response", "parse_strict"];
    let text = std::fs::read_to_string(path).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue; // comments and doc comments are not call sites
        }
        if !line.contains("serde_json::from_slice") {
            continue;
        }
        let within = enclosing_fn(&lines, i).unwrap_or_default();
        if !allowed.contains(&within.as_str()) {
            out.push(format!(
                "{}:{}: serde_json::from_slice inside fn {within:?} — evidence must deserialize only through the canonical loaders (Store::parse_evidence / ext::parse_canonical_response / canon::parse_strict)",
                path.file_name().unwrap().to_string_lossy(),
                i + 1
            ));
        }
    }
    out
}

#[test]
fn every_evidence_deserialization_goes_through_the_canonical_loaders() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    walk_rs(&src, &mut files);
    files.sort();
    assert!(!files.is_empty(), "the source tree must exist");

    let mut violations: Vec<String> = Vec::new();
    let mut total = 0usize;
    for path in &files {
        let text = std::fs::read_to_string(path).unwrap();
        for line in text.lines() {
            if line.contains("serde_json::from_slice") {
                total += 1;
            }
        }
        violations.extend(violations_in(path));
    }
    assert!(
        total >= 3,
        "the canonical loaders must contain their from_slice calls (found {total})"
    );
    assert!(
        violations.is_empty(),
        "the canonical-loader gate failed:\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn the_gate_catches_a_planted_violation() {
    // A synthetic source tree: one canonical loader and one rogue loader.
    let tmp = std::env::temp_dir().join(format!("frf-loader-gate-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(tmp.join("src")).unwrap();
    std::fs::write(
        tmp.join("src/store.rs"),
        "pub fn parse_evidence() { serde_json::from_slice(&b) }\n",
    )
    .unwrap();
    std::fs::write(
        tmp.join("src/evil.rs"),
        "pub fn load_evidence_directly() { serde_json::from_slice(&b) }\n",
    )
    .unwrap();
    std::fs::write(
        tmp.join("src/ext.rs"),
        "pub fn parse_canonical_response() { serde_json::from_slice(&b) }\n",
    )
    .unwrap();

    let mut files = Vec::new();
    walk_rs(&tmp.join("src"), &mut files);
    let mut violations: Vec<String> = Vec::new();
    for path in &files {
        violations.extend(violations_in(path));
    }
    assert_eq!(
        violations.len(),
        1,
        "exactly the planted violation must be caught: {violations:?}"
    );
    assert!(violations[0].contains("load_evidence_directly"));
    let _ = std::fs::remove_dir_all(&tmp);
}
