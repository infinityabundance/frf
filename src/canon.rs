//! RFC 8785 canonical JSON (JCS) — the normative serialization for receipts.
//!
//! A receipt's bytes must be reproducible by any implementation — Rust, Go,
//! Python, an air-gapped verification appliance — so its identity is a
//! digest over *canonical* bytes, not over one serializer's habits. This
//! module is the whole serialization surface, and it implements the RFC
//! exactly, on the value domain the OpenReceipt schema actually emits:
//!
//! - **strings**, **arrays**, **booleans**, and **null** (`Option`); numbers
//!   are REJECTED with an error. RFC 8785 number serialization is
//!   ECMAScript's (ECMA-262 §7.1.12.1, Ryu); the OpenReceipt v2 schema emits
//!   no numbers, and a serializer that silently emits a possibly
//!   non-compliant number would be worse than one that refuses.
//! - **escaping** (§3.2.2.2): U+0000–U+001F are `\u00xx` with lowercase hex,
//!   except the predefined escapes U+0008 `\b`, U+0009 `\t`, U+000A `\n`,
//!   U+000C `\f`, U+000D `\r`. Everything outside that range — U+007F and
//!   U+0080 included — is emitted as-is (raw UTF-8), except `"` → `\"` and
//!   `\` → `\\`. Lone surrogates cannot occur: input strings are Rust
//!   `String`s, which are valid UTF-8 by construction.
//! - **property order** (§3.2.3): names are compared as arrays of UTF-16
//!   code units (unsigned, locale-independent), recursively, with array
//!   element order preserved. This is *not* UTF-8/byte or code-point order:
//!   a supplementary-plane name (surrogate pair, e.g. U+1F600 → units
//!   D83D DE00) sorts before U+FB33 even though its code point is larger.
//! - **whitespace** (§3.2.1): none.
//!
//! The RFC's own vectors (§3.2.2 string example, §3.2.3 sorting corpus,
//! §3.2.4 byte output) are pinned in the tests below.
//!
//! Auditable in one pass: `encode` and `escape` below *are* the
//! implementation.

use crate::error::{FrfError, Result};
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::Serialize;
use serde_json::Value;
use std::cmp::Ordering;
use std::fmt;

/// Serialize `value` to canonical JSON (RFC 8785).
pub fn canonical<T: Serialize>(value: &T) -> Result<String> {
    let value = serde_json::to_value(value)
        .map_err(|e| FrfError::new(format!("cannot convert to canonical JSON: {e}")))?;
    encode(&value)
}

pub fn encode(value: &Value) -> Result<String> {
    match value {
        Value::Null => Ok("null".to_string()),
        Value::Bool(b) => Ok(if *b { "true" } else { "false" }.to_string()),
        // RFC 8785 number serialization is ECMAScript's (§3.2.2.3), which is
        // out of scope for this protocol surface: the OpenReceipt schema
        // emits no numbers. Refusing beats emitting a possibly non-compliant
        // number (e.g. serde_json renders 0.0 as "0.0", ECMAScript as "0").
        Value::Number(n) => Err(FrfError::new(format!(
            "cannot canonicalize the JSON number {n}: RFC 8785 number serialization is out of scope for the OpenReceipt value domain (strings, arrays, booleans, and null only)"
        ))),
        Value::String(s) => Ok(format!("\"{}\"", escape(s))),
        Value::Array(items) => {
            let inner: Vec<String> = items.iter().map(encode).collect::<Result<_>>()?;
            Ok(format!("[{}]", inner.join(",")))
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| utf16_cmp(a, b));
            let inner: Vec<String> = keys
                .iter()
                .map(|k| Ok(format!("\"{}\":{}", escape(k), encode(&map[*k])?)))
                .collect::<Result<_>>()?;
            Ok(format!("{{{}}}", inner.join(",")))
        }
    }
}

/// RFC 8785 §3.2.3 property ordering: lexicographic comparison over UTF-16
/// code units (unsigned, locale-independent). `Vec<u16>`'s `Ord` is exactly
/// that: first differing unit decides; a shorter name precedes a longer one
/// that has it as a prefix.
fn utf16_cmp(a: &str, b: &str) -> Ordering {
    let av: Vec<u16> = a.encode_utf16().collect();
    let bv: Vec<u16> = b.encode_utf16().collect();
    av.cmp(&bv)
}

// ---------------------------------------------------------------------------
// Strict JSON parsing (RFC 8785 §2 — I-JSON)
// ---------------------------------------------------------------------------

/// A JSON document whose object property names are UNIQUE. RFC 8785
/// constrains JCS input to I-JSON and says explicitly that JSON objects MUST
/// NOT contain duplicate property names. `serde_json::Value` silently keeps
/// the last duplicate, which would let an unknown duplicate property vanish
/// before a content address is recomputed; this type refuses instead.
/// Property order is preserved (the raw document's order — JCS reorders).
#[derive(Debug, Clone, PartialEq)]
enum StrictJson {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<StrictJson>),
    Object(Vec<(String, StrictJson)>),
}

impl<'de> serde::Deserialize<'de> for StrictJson {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StrictVisitor;

        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictJson;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a JSON value with no duplicate object property names")
            }

            fn visit_unit<E>(self) -> std::result::Result<StrictJson, E> {
                Ok(StrictJson::Null)
            }
            fn visit_bool<E>(self, v: bool) -> std::result::Result<StrictJson, E> {
                Ok(StrictJson::Bool(v))
            }
            fn visit_i64<E>(self, v: i64) -> std::result::Result<StrictJson, E> {
                Ok(StrictJson::Number(v.into()))
            }
            fn visit_u64<E>(self, v: u64) -> std::result::Result<StrictJson, E> {
                Ok(StrictJson::Number(v.into()))
            }
            fn visit_f64<E>(self, v: f64) -> std::result::Result<StrictJson, E>
            where
                E: de::Error,
            {
                Ok(StrictJson::Number(
                    serde_json::Number::from_f64(v)
                        .ok_or_else(|| de::Error::custom("non-finite number"))?,
                ))
            }
            fn visit_str<E>(self, v: &str) -> std::result::Result<StrictJson, E> {
                Ok(StrictJson::String(v.to_string()))
            }
            fn visit_string<E>(self, v: String) -> std::result::Result<StrictJson, E> {
                Ok(StrictJson::String(v))
            }
            fn visit_seq<A>(self, mut seq: A) -> std::result::Result<StrictJson, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut out = Vec::new();
                while let Some(v) = seq.next_element::<StrictJson>()? {
                    out.push(v);
                }
                Ok(StrictJson::Array(out))
            }
            fn visit_map<A>(self, mut map: A) -> std::result::Result<StrictJson, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut out: Vec<(String, StrictJson)> = Vec::new();
                while let Some(key) = map.next_key::<String>()? {
                    if out.iter().any(|(k, _)| k == &key) {
                        return Err(de::Error::custom(format!(
                            "duplicate object property name {key:?} — RFC 8785 requires I-JSON (no duplicate names)"
                        )));
                    }
                    let value = map.next_value::<StrictJson>()?;
                    out.push((key, value));
                }
                Ok(StrictJson::Object(out))
            }
        }

        deserializer.deserialize_any(StrictVisitor)
    }
}

impl From<StrictJson> for Value {
    fn from(v: StrictJson) -> Value {
        match v {
            StrictJson::Null => Value::Null,
            StrictJson::Bool(b) => Value::Bool(b),
            StrictJson::Number(n) => Value::Number(n),
            StrictJson::String(s) => Value::String(s),
            StrictJson::Array(items) => Value::Array(items.into_iter().map(Value::from).collect()),
            StrictJson::Object(pairs) => {
                Value::Object(pairs.into_iter().map(|(k, v)| (k, v.into())).collect())
            }
        }
    }
}

/// Parse `bytes` as strict JSON (RFC 8785 §2 I-JSON). The parse REFUSES
/// duplicate object property names, which `serde_json::Value` would silently
/// collapse. Evidence identities MUST hash the document, never a projection:
/// an unknown property has to survive into the canonical bytes or the
/// receipt is refused — it can never be discarded before the digest is
/// recomputed.
pub fn parse_strict(bytes: &[u8]) -> Result<Value> {
    let doc: StrictJson = serde_json::from_slice(bytes)
        .map_err(|e| FrfError::new(format!("not strict JSON: {e}")))?;
    Ok(doc.into())
}

/// The canonical-bytes rule, shared by every canonical-JSON consumer: a
/// document must BE its own canonical serialization — strict-JSON parse the
/// bytes (duplicate properties refused), JCS-encode the parsed value, and
/// refuse anything that is not byte-identical. One semantic document has one
/// byte sequence, so two encodings cannot split one evidence identity. This
/// is the rule behind receipts, extension responses, and (v0.1.32+) every
/// generated evidence document.
pub fn require_canonical_bytes(bytes: &[u8], what: &str) -> Result<()> {
    let parsed = parse_strict(bytes)
        .map_err(|e| FrfError::refused(format!("{what} is not strict JSON: {e}")))?;
    let canonical = encode(&parsed)
        .map_err(|e| FrfError::refused(format!("{what} cannot be canonicalized: {e}")))?;
    if canonical.as_bytes() != bytes {
        return Err(FrfError::refused(format!(
            "{what} is not its own canonical serialization (RFC 8785); the protocol says canonical JSON, and a non-canonical document would split one semantic document into many evidence identities"
        )));
    }
    Ok(())
}

/// RFC 8785 §3.2.2.2 string escaping. Predefined escapes for U+0008/0009/
/// 000A/000C/000D; `\u00xx` (lowercase) for the remaining U+0000–U+001F;
/// `\"` and `\\`; every other code point raw — U+007F included.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{0009}' => out.push_str("\\t"),
            '\u{000A}' => out.push_str("\\n"),
            '\u{000C}' => out.push_str("\\f"),
            '\u{000D}' => out.push_str("\\r"),
            c if (c as u32) <= 0x1F => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// RFC 8785 §3.2.2.2: the five predefined escapes, the remaining
    /// controls as lower-hex `\u00xx`, and — per the RFC — U+007F and U+0080
    /// emitted RAW, never escaped.
    #[test]
    fn escaping_matches_rfc_8785_exactly() {
        // \b \t \n \f \r use the predefined escapes; \u0000, \u0001, \u001f
        // use lower-hex \u notation; U+007F and U+0080 stay raw.
        let v = json!({
            "s": "\u{0008}\u{0009}\u{000A}\u{000C}\u{000D}\u{0000}\u{0001}\u{001f}\u{007f}\u{0080}"
        });
        assert_eq!(
            encode(&v).unwrap(),
            "{\"s\":\"\\b\\t\\n\\f\\r\\u0000\\u0001\\u001f\u{007f}\u{0080}\"}"
        );
    }

    /// RFC 8785 §3.2.2 string example (string part only — the example's
    /// numbers are outside the OpenReceipt value domain). The canonical form
    /// escapes U+000F as lower-hex `\u000f`, the newline as `\n`, and leaves
    /// `'`, `B`, and `/` raw.
    #[test]
    fn rfc_section_3_2_2_string_example() {
        // Input decoded: "€$" U+000F LF "A'B\"\\\"/" — i.e. € $ 0x0F \n A '
        // B " \ \ " /.
        let v = json!({"string": "€$\u{000f}\u{000a}A'\u{0042}\u{0022}\u{005c}\\\"/"});
        assert_eq!(
            encode(&v).unwrap(),
            "{\"string\":\"€$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}"
        );
    }

    /// RFC 8785 §3.2.3 sorting corpus, verbatim. The expected order is
    /// Carriage Return, One, Control, ö, Euro, Emoji, Hebrew Dalet — the
    /// emoji (U+1F600, surrogate pair D83D DE00) sorts BEFORE U+FB33 even
    /// though its code point is larger: UTF-16 order, not code-point order.
    #[test]
    fn rfc_section_3_2_3_sorting_corpus() {
        let mut map = serde_json::Map::new();
        map.insert("\u{20ac}".into(), json!("Euro Sign"));
        map.insert("\r".into(), json!("Carriage Return"));
        map.insert("\u{fb33}".into(), json!("Hebrew Letter Dalet With Dagesh"));
        map.insert("1".into(), json!("One"));
        map.insert("\u{1f600}".into(), json!("Emoji: Grinning Face"));
        map.insert("\u{80}".into(), json!("Control"));
        map.insert(
            "\u{f6}".into(),
            json!("Latin Small Letter O With Diaeresis"),
        );
        let v = Value::Object(map);
        assert_eq!(
            encode(&v).unwrap(),
            "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u{80}\":\"Control\",\"ö\":\"Latin Small Letter O With Diaeresis\",\"€\":\"Euro Sign\",\"\u{1f600}\":\"Emoji: Grinning Face\",\"דּ\":\"Hebrew Letter Dalet With Dagesh\"}"
        );
    }

    /// UTF-16 vs UTF-8/code-point ordering, isolated: U+10000 (units D800
    /// DC00) sorts before U+E000 (unit E000) under UTF-16, while its code
    /// point is larger. A byte-order sorter would get this backwards.
    #[test]
    fn property_order_is_utf16_not_utf8() {
        let mut map = serde_json::Map::new();
        map.insert("\u{10000}".into(), json!("a"));
        map.insert("\u{e000}".into(), json!("b"));
        assert_eq!(
            encode(&Value::Object(map)).unwrap(),
            "{\"\u{10000}\":\"a\",\"\u{e000}\":\"b\"}"
        );
    }

    /// §3.2.3 plain-English example: "" < "a" < "aa" < "ab".
    #[test]
    fn prefix_ordering_is_ascending() {
        let mut map = serde_json::Map::new();
        for (i, k) in ["ab", "aa", "a", ""].iter().enumerate() {
            map.insert((*k).into(), json!(i.to_string()));
        }
        assert_eq!(
            encode(&Value::Object(map)).unwrap(),
            "{\"\":\"3\",\"a\":\"2\",\"aa\":\"1\",\"ab\":\"0\"}"
        );
    }

    #[test]
    fn keys_are_sorted_recursively_arrays_keep_order() {
        let v = json!({"b": "1", "a": {"d": "x", "c": "y"}, "e": [{"g": "4", "f": "5"}]});
        assert_eq!(
            encode(&v).unwrap(),
            r#"{"a":{"c":"y","d":"x"},"b":"1","e":[{"f":"5","g":"4"}]}"#
        );
    }

    #[test]
    fn numbers_are_rejected_outside_the_value_domain() {
        let err = encode(&json!({"n": 1})).unwrap_err();
        assert!(
            err.message().contains("out of scope"),
            "error: {}",
            err.message()
        );
        // But a string that LOOKS like a number is just a string.
        assert_eq!(encode(&json!({"n": "1"})).unwrap(), r#"{"n":"1"}"#);
    }

    #[test]
    fn no_whitespace_and_deterministic() {
        let v = json!({"x": ["a", "b"], "y": null, "z": true});
        let a = encode(&v).unwrap();
        assert_eq!(a, encode(&v).unwrap());
        assert!(!a.contains(' '));
        assert!(!a.contains('\n'));
    }

    #[test]
    fn canonical_round_trips_through_serde_json() {
        let v = json!({"b": ["a", "b"], "a": {"d": "x", "c": "y"}, "e": null});
        let s = encode(&v).unwrap();
        let back: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(back, v);
    }

    /// Cross-implementation pin: a receipt-shaped object exercising every
    /// escape class and both non-ASCII planes. The expected bytes were
    /// derived by hand from RFC 8785 §3.2.2.2/§3.2.3 (note "array" sorts
    /// before U+007F: 0x61 < 0x7F — hand-sorting gets this wrong), and the
    /// SHA-256 was computed with an independent tool (Python hashlib). Any
    /// deviation in escaping or UTF-16 ordering breaks this vector.
    #[test]
    fn cross_implementation_bytes_and_hash_are_pinned() {
        let mut map = serde_json::Map::new();
        map.insert("\u{0000}".into(), json!("nul"));
        map.insert(
            "\u{0008}\u{0009}\u{000a}\u{000c}\u{000d}".into(),
            json!("predefined"),
        );
        map.insert("\u{001f}".into(), json!("unit-sep"));
        map.insert("1".into(), json!("ascii-digit-first"));
        map.insert("array".into(), json!(["a", "b"]));
        map.insert("nested".into(), json!({"z": "1", "a": "2"}));
        map.insert("nil".into(), Value::Null);
        map.insert("\u{7f}".into(), json!("del-raw"));
        map.insert("\u{80}".into(), json!("c1-raw"));
        map.insert("ö".into(), json!("latin"));
        map.insert("€".into(), json!("euro"));
        map.insert("\u{1f600}".into(), json!("emoji"));
        map.insert("דּ".into(), json!("hebrew"));
        let v = Value::Object(map);

        let expected = "{\"\\u0000\":\"nul\",\"\\b\\t\\n\\f\\r\":\"predefined\",\"\\u001f\":\"unit-sep\",\"1\":\"ascii-digit-first\",\"array\":[\"a\",\"b\"],\"nested\":{\"a\":\"2\",\"z\":\"1\"},\"nil\":null,\"\u{7f}\":\"del-raw\",\"\u{80}\":\"c1-raw\",\"ö\":\"latin\",\"€\":\"euro\",\"\u{1f600}\":\"emoji\",\"דּ\":\"hebrew\"}";
        assert_eq!(encode(&v).unwrap(), expected);
        assert_eq!(
            crate::host::sha256_bytes(expected.as_bytes()),
            "41c6ee64e779f9d7e80d511ae33a0c2763f497ccf32063e9cce359576e68b65d"
        );
    }

    /// RFC 8785 §2: JCS input is I-JSON — duplicate object property names
    /// are refused, never silently collapsed (serde_json::Value would keep
    /// the last one).
    #[test]
    fn duplicate_property_names_are_refused() {
        let doc = b"{\"a\":1,\"a\":2}";
        let err = parse_strict(doc).unwrap_err();
        assert!(
            err.to_string().contains("duplicate object property name"),
            "error: {err}"
        );
        // Nested duplicates are caught too.
        let doc = b"{\"outer\":{\"b\":true,\"b\":false}}";
        assert!(parse_strict(doc).is_err());
        // In ARRAYS duplicate-named objects are two distinct objects — fine.
        let doc = b"[{\"k\":1},{\"k\":2}]";
        assert!(parse_strict(doc).is_ok());
    }

    /// Strict parse preserves the full document: an unknown property
    /// survives into the canonical bytes (it must — the content address
    /// covers the DOCUMENT, not a typed projection).
    #[test]
    fn strict_parse_keeps_unknown_properties_in_the_document() {
        let doc = b"{\"a\":\"x\",\"unrecognized\":\"tampered\"}";
        let value = parse_strict(doc).unwrap();
        let canonical = encode(&value).unwrap();
        assert_eq!(canonical, "{\"a\":\"x\",\"unrecognized\":\"tampered\"}");
    }
}
