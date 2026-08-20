//! RFC 8785 canonical JSON — the normative serialization for receipts.
//!
//! A receipt's bytes must be reproducible by any implementation — Rust, Go,
//! Python, an air-gapped verification appliance — so its identity is a
//! digest over *canonical* bytes, not over one serializer's habits. This
//! module is the whole serialization surface: a struct is converted to a
//! `serde_json::Value` and encoded with the RFC 8785 rules:
//!
//! - object keys sorted lexicographically, recursively;
//! - no whitespace anywhere;
//! - strings escape only `"`, `\`, U+0000–U+001F, and U+007F (as `\u00xx`
//!   with lowercase hex); every other code point, non-ASCII included, is
//!   emitted raw as UTF-8.
//!
//! The v2 receipt schema uses strings and arrays only — no numbers,
//! booleans, or nulls are emitted — so the RFC's number-formatting clauses
//! never apply. `Option<T>` serializes as `null`, which is part of the
//! grammar.
//!
//! Auditable in one pass: `encode` below *is* the implementation.

use crate::error::{FrfError, Result};
use serde::Serialize;
use serde_json::Value;

/// Serialize `value` to canonical JSON (RFC 8785).
pub fn canonical<T: Serialize>(value: &T) -> Result<String> {
    let value = serde_json::to_value(value)
        .map_err(|e| FrfError::new(format!("cannot convert to canonical JSON: {e}")))?;
    Ok(encode(&value))
}

fn encode(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(b) => {
            if *b {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        Value::Number(n) => n.to_string(),
        Value::String(s) => format!("\"{}\"", escape(s)),
        Value::Array(items) => {
            let inner: Vec<String> = items.iter().map(encode).collect();
            format!("[{}]", inner.join(","))
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let inner: Vec<String> = keys
                .iter()
                .map(|k| format!("\"{}\":{}", escape(k), encode(&map[*k])))
                .collect();
            format!("{{{}}}", inner.join(","))
        }
    }
}

/// RFC 8785 string escaping: `"` and `\` backslash-escaped; U+0000–U+001F
/// and U+007F as `\u00xx` (lowercase hex); every other code point emitted
/// as-is (raw UTF-8, never `\uXXXX`).
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) <= 0x1F || c as u32 == 0x7F => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keys_are_sorted_recursively() {
        let v = json!({"b": 1, "a": {"d": 2, "c": 3}, "e": [{"g": 4, "f": 5}]});
        assert_eq!(
            encode(&v),
            r#"{"a":{"c":3,"d":2},"b":1,"e":[{"f":5,"g":4}]}"#
        );
    }

    #[test]
    fn strings_follow_rfc8785_escaping() {
        let v = json!({"s": "quote\" back\\ tab\t del\u{7f} \u{e9}"});
        assert_eq!(
            encode(&v),
            "{\"s\":\"quote\\\" back\\\\ tab\\u0009 del\\u007f é\"}"
        );
    }

    #[test]
    fn no_whitespace_and_deterministic() {
        let v = json!({"x": [1, 2], "y": null});
        let a = encode(&v);
        assert_eq!(a, encode(&v));
        assert!(!a.contains(' '));
        assert!(!a.contains('\n'));
    }

    #[test]
    fn canonical_round_trips_through_serde_json() {
        let v = json!({"b": [1, 2], "a": {"d": "x", "c": "y"}, "e": null});
        let s = encode(&v);
        let back: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(back, v);
    }
}
