//! `cargo xtask regen-readme [--check]` — regenerate the Protocol registry
//! tables in the README from `protocol/registry.json`.
//!
//! The registry is the AUTHORITY; the README block between the
//! `<!-- PROTOCOL-REGISTRY:BEGIN -->` and `<!-- PROTOCOL-REGISTRY:END -->`
//! markers is a generated projection. `--check` verifies the committed
//! README matches the projection byte-for-byte and exits non-zero on drift
//! (the CI test `tests/protocol_registry.rs` runs this), so a registry
//! change is never committed without its generated documentation.

use serde_json::Value;
use std::path::{Path, PathBuf};

const BEGIN: &str = "<!-- PROTOCOL-REGISTRY:BEGIN -->";
const END: &str = "<!-- PROTOCOL-REGISTRY:END -->";

fn field<'a>(o: &'a Value, key: &str) -> &'a str {
    o.get(key).and_then(Value::as_str).unwrap_or("")
}

fn cell(value: &str) -> String {
    if value.is_empty() {
        "—".to_string()
    } else {
        value.to_string()
    }
}

/// Render the whole delimited registry block from the registry document.
pub fn render_block(reg: &Value) -> String {
    let mut out = String::new();
    out.push_str(BEGIN);
    out.push('\n');

    // -- Protocol objects --------------------------------------------------
    out.push_str("### Protocol objects\n\n");
    out.push_str("| object | meaning | schema / identity | status |\n");
    out.push_str("|---|---|---|---|\n");
    for o in reg["objects"].as_array().unwrap_or(&vec![]) {
        let mut binding = String::new();
        let mut parts: Vec<&str> = Vec::new();
        let schema = field(o, "schema");
        let identity = field(o, "identity");
        if !schema.is_empty() {
            parts.push(schema);
        }
        if !identity.is_empty() {
            parts.push(identity);
        }
        if !parts.is_empty() {
            binding = parts.join(" · ");
        }
        out.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            field(o, "id"),
            field(o, "meaning"),
            cell(&binding),
            field(o, "status")
        ));
    }
    out.push('\n');

    // -- Identity domains --------------------------------------------------
    out.push_str("### Identity domains (domain-separated preimages)\n\n");
    out.push_str("| domain | meaning | status |\n");
    out.push_str("|---|---|---|\n");
    for i in reg["identities"].as_array().unwrap_or(&vec![]) {
        out.push_str(&format!(
            "| {} | {} | {} |\n",
            field(i, "domain"),
            field(i, "meaning"),
            field(i, "status")
        ));
    }
    out.push('\n');

    // -- Schemas -----------------------------------------------------------
    out.push_str("### Schemas (evidence documents)\n\n");
    out.push_str("| id | status | scope |\n");
    out.push_str("|---|---|---|\n");
    for s in reg["schemas"].as_array().unwrap_or(&vec![]) {
        out.push_str(&format!(
            "| {} | {} | {} |\n",
            field(s, "id"),
            field(s, "status"),
            field(s, "scope")
        ));
    }
    out.push('\n');

    // -- Relations ---------------------------------------------------------
    out.push_str("### Relations\n\n");
    out.push_str("| relation | id | meaning | status |\n");
    out.push_str("|---|---|---|---|\n");
    if let Some(relations) = reg["relations"].as_object() {
        for (group, entries) in relations {
            match entries {
                Value::Array(list) => {
                    for e in list {
                        out.push_str(&format!(
                            "| {} | {} | {} | {} |\n",
                            group,
                            field(e, "id"),
                            field(e, "meaning"),
                            field(e, "status")
                        ));
                    }
                }
                Value::Object(nested) => {
                    for (sub, list) in nested {
                        for e in list.as_array().unwrap_or(&vec![]) {
                            out.push_str(&format!(
                                "| {}.{} | {} | {} | {} |\n",
                                group,
                                sub,
                                field(e, "id"),
                                field(e, "meaning"),
                                field(e, "status")
                            ));
                        }
                    }
                }
                _ => {}
            }
        }
    }
    out.push('\n');

    // -- Admission policies ------------------------------------------------
    out.push_str("### Admission policies\n\n");
    out.push_str("| policy | requires (per premise) | status |\n");
    out.push_str("|---|---|---|\n");
    for p in reg["policies"].as_array().unwrap_or(&vec![]) {
        out.push_str(&format!(
            "| {} | {} | {} |\n",
            field(p, "id"),
            field(p, "meaning"),
            field(p, "status")
        ));
    }
    out.push('\n');

    // -- Execution profiles ------------------------------------------------
    out.push_str("### Execution profiles\n\n");
    out.push_str("| id | meaning | status |\n");
    out.push_str("|---|---|---|\n");
    for p in reg["execution_profiles"].as_array().unwrap_or(&vec![]) {
        out.push_str(&format!(
            "| {} | {} | {} |\n",
            field(p, "id"),
            field(p, "meaning"),
            field(p, "status")
        ));
    }

    out.push_str(END);
    out
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Replace the delimited block in `readme` with `block`. The block ends
/// exactly at the `END` marker; the separator after the marker is
/// NORMALIZED (every newline that followed the marker in the old text is
/// consumed, and exactly one blank line is re-emitted), so regeneration is
/// byte-idempotent instead of accumulating newlines.
fn replace_block(readme: &str, block: &str) -> Result<String, String> {
    let begin = readme
        .find(BEGIN)
        .ok_or_else(|| "README.md has no PROTOCOL-REGISTRY:BEGIN marker".to_string())?;
    let marker_end = readme
        .find(END)
        .ok_or_else(|| "README.md has no PROTOCOL-REGISTRY:END marker".to_string())?;
    let mut end = marker_end + END.len();
    while readme.as_bytes().get(end) == Some(&b'\n') {
        end += 1;
    }
    Ok(format!(
        "{}{}\n\n{}",
        &readme[..begin],
        block,
        &readme[end..]
    ))
}

/// Regenerate the README block in place; with `check`, verify instead of
/// writing (exit status is the verdict).
pub fn run(check: bool) {
    let root = repo_root();
    let reg_bytes = std::fs::read(root.join("protocol/registry.json"))
        .unwrap_or_else(|e| panic!("cannot read protocol/registry.json: {e}"));
    let reg: Value = serde_json::from_slice(&reg_bytes)
        .unwrap_or_else(|e| panic!("protocol/registry.json does not parse: {e}"));
    let block = render_block(&reg);

    let readme_path = root.join("README.md");
    let readme = std::fs::read_to_string(&readme_path)
        .unwrap_or_else(|e| panic!("cannot read README.md: {e}"));
    let updated =
        replace_block(&readme, &block).unwrap_or_else(|e| panic!("cannot update README.md: {e}"));

    if updated == readme {
        println!("regen-readme: README.md is in sync with protocol/registry.json");
        return;
    }
    if check {
        panic!(
            "README.md's protocol registry tables are out of sync with protocol/registry.json — run `cargo xtask regen-readme` and commit the result"
        );
    }
    std::fs::write(&readme_path, updated).unwrap_or_else(|e| panic!("cannot write README.md: {e}"));
    println!("regen-readme: regenerated README.md from protocol/registry.json");
}
