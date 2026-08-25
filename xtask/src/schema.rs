//! Schema-version admission for the independent xtask verifier
//! (spec/versioning.md §2): a protocol object's `schema_version` must be a
//! REGISTERED id of its object family with status `active` or `superseded`.
//! Everything else is refused, and the refusal names the version.
//!
//! The xtask is the repo's own tool, so it reads `protocol/registry.json`
//! directly at runtime (the registry is the AUTHORITY); the reference engine
//! embeds the same registry (src/schema.rs) and the Go verifier embeds a
//! byte-identical copy (verifier-go/registry.json) — the three admission
//! predicates are the same function over the same data, and the conformance
//! corpus is the shared executable agreement.

use std::collections::HashMap;
use std::sync::OnceLock;

/// The registry path, resolved relative to the xtask crate (xtask/).
const REGISTRY_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../protocol/registry.json");

fn registry_schemas() -> &'static HashMap<String, String> {
    static SCHEMAS: OnceLock<HashMap<String, String>> = OnceLock::new();
    SCHEMAS.get_or_init(|| {
        let raw = std::fs::read_to_string(REGISTRY_PATH)
            .expect("protocol/registry.json must exist next to the xtask crate");
        let value: serde_json::Value =
            serde_json::from_str(&raw).expect("protocol/registry.json must be valid JSON");
        let list = value
            .get("schemas")
            .and_then(|v| v.as_array())
            .expect("the registry must carry a schemas array");
        let mut map = HashMap::with_capacity(list.len());
        for entry in list {
            let id = entry
                .get("id")
                .and_then(|v| v.as_str())
                .expect("every registered schema has an id");
            let status = entry
                .get("status")
                .and_then(|v| v.as_str())
                .expect("every registered schema has a status");
            map.insert(id.to_string(), status.to_string());
        }
        map
    })
}

/// The object family part of a registered schema id (`frf-receipt-v20` →
/// `"receipt"`). The LAST `-v` is the version separator, so a family name
/// that itself contains `-v` (`frf-v3-build-manifest-v1`) still parses.
fn family_of(version: &str) -> Option<&str> {
    let rest = version.strip_prefix("frf-")?;
    let end = rest.rfind("-v")?;
    let family = &rest[..end];
    let number = &rest[end + 2..];
    if family.is_empty() || number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(family)
}

/// Admit a document's `schema_version` for the given object family, or
/// refuse it — the refusal always names the version.
pub fn admit(family: &str, version: &str) -> Result<(), String> {
    let Some(actual_family) = family_of(version) else {
        return Err(format!(
            "schema_version {version:?} is not a registered schema id of the {family} family \
             (expected the shape frf-{family}-v<N>)"
        ));
    };
    if actual_family != family {
        return Err(format!(
            "schema_version {version:?} is a {actual_family} schema, not a {family} schema — \
             the wrong object family"
        ));
    }
    match registry_schemas().get(version) {
        Some(status) if status == "active" || status == "superseded" => Ok(()),
        Some(status) => Err(format!(
            "schema_version {version:?} is registered as {status} — only active or superseded \
             schemas are admissible"
        )),
        None => Err(format!(
            "schema_version {version:?} is not a registered schema (protocol/registry.json) — \
             unregistered versions are refused"
        )),
    }
}
