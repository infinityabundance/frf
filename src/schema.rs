//! Schema-version admission (spec/versioning.md §2).
//!
//! A protocol object's `schema_version` must be a REGISTERED id of its
//! object family with status `active` or `superseded`. Everything else is
//! refused, and the refusal names the version:
//!
//! - a `reserved-invalid` id (`frf-bundle-v9`, `frf-comparator-response-v9`,
//!   `frf-execution-context-v9`) is deliberately refused — it exists so
//!   nothing can collide with it, and it can never become active;
//! - an unregistered id (a version the registry does not list, including a
//!   future version) is refused — undocumented protocol surface is not
//!   protocol;
//! - an id of the wrong object family (a claim schema on a receipt) is
//!   refused;
//! - a `future` or `test-only` id (statuses the registry reserves) is
//!   refused.
//!
//! A REGISTERED superseded id is admitted: a superseded schema's records
//! remain what they were — content-addressed evidence does not stop
//! verifying because a newer shape exists, whenever the parser keeps
//! accepting the shape (a genuinely old shape that no longer deserializes
//! is refused by the parser, naming the field).
//!
//! The registry (`protocol/registry.json`) is embedded into the crate so the
//! reference engine is self-contained and publishable; `tests/protocol_registry.rs`
//! and `tests/schema_admission.rs` pin the embedded copy against the file so
//! they cannot drift.

use std::collections::HashMap;
use std::sync::OnceLock;

/// The registered schema ids and their statuses, embedded at compile time.
fn registry_schemas() -> &'static HashMap<String, String> {
    static SCHEMAS: OnceLock<HashMap<String, String>> = OnceLock::new();
    SCHEMAS.get_or_init(|| {
        let raw = include_str!("../protocol/registry.json");
        let value: serde_json::Value = serde_json::from_str(raw)
            .expect("the embedded protocol/registry.json must be valid JSON");
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
/// `"receipt"`, `frf-execution-context-v1` → `"execution-context"`). The
/// LAST `-v` is the version separator, so a family name that itself contains
/// `-v` (`frf-v3-build-manifest-v1` → `"v3-build-manifest"`) still parses.
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
        Some(status) if *status == "active" || *status == "superseded" => Ok(()),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_parsing() {
        assert_eq!(family_of("frf-receipt-v20"), Some("receipt"));
        assert_eq!(
            family_of("frf-execution-context-v1"),
            Some("execution-context")
        );
        assert_eq!(
            family_of("frf-v3-build-manifest-v1"),
            Some("v3-build-manifest")
        );
        assert_eq!(family_of("frf-claim-v13"), Some("claim"));
        assert_eq!(family_of("frf-receipt"), None);
        assert_eq!(family_of("frf-receipt-v"), None);
        assert_eq!(family_of("frf-receipt-v1x"), None);
        assert_eq!(family_of("receipt-v20"), None);
    }

    #[test]
    fn every_current_schema_const_is_admitted() {
        // The engine's own current versions are registered and active: the
        // admission rule can never refuse the shape the engine writes.
        for (family, version) in [
            (
                "stream-publication",
                crate::model::SCHEMA_STREAM_PUBLICATION,
            ),
            (
                "publication-manifest",
                crate::model::SCHEMA_PUBLICATION_MANIFEST,
            ),
            ("execution-context", crate::model::SCHEMA_EXECUTION_CONTEXT),
            ("runtime-closure", crate::model::SCHEMA_RUNTIME_CLOSURE),
            ("receipt", crate::model::SCHEMA_RECEIPT),
            ("detached-objects", crate::model::SCHEMA_DETACHED_OBJECTS),
            ("reduction", crate::model::SCHEMA_REDUCTION),
            (
                "normalizer-response",
                crate::model::SCHEMA_NORMALIZER_RESPONSE,
            ),
            (
                "comparator-response",
                crate::model::SCHEMA_COMPARATOR_RESPONSE,
            ),
            (
                "capture-response",
                crate::model::SCHEMA_CAPTURE_ADAPTER_RESPONSE,
            ),
            ("witness-response", crate::model::SCHEMA_WITNESS_RESPONSE),
            ("bundle", crate::model::SCHEMA_BUNDLE),
            (
                "minimizer-response",
                crate::model::SCHEMA_MINIMIZER_RESPONSE,
            ),
            ("mutation-response", crate::model::SCHEMA_MUTATION_RESPONSE),
            ("minimizer-request", crate::model::SCHEMA_MINIMIZER_REQUEST),
            ("claim", crate::model::SCHEMA_CLAIM),
            ("capture", crate::model::SCHEMA_CAPTURE),
            ("trajectory", crate::model::SCHEMA_TRAJECTORY),
            ("series", crate::model::SCHEMA_SERIES),
        ] {
            admit(family, version)
                .unwrap_or_else(|e| panic!("{family} {version} must be admitted: {e}"));
        }
    }

    #[test]
    fn reserved_invalid_refusals_name_the_version() {
        for (family, version) in [
            ("bundle", "frf-bundle-v9"),
            ("comparator-response", "frf-comparator-response-v9"),
            ("execution-context", "frf-execution-context-v9"),
        ] {
            let err = admit(family, version).expect_err("reserved-invalid must refuse");
            assert!(
                err.contains("reserved-invalid") && err.contains(version),
                "the refusal must name the version and its status: {err}"
            );
        }
    }
}
