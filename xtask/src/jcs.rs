//! RFC 8785 canonical JSON (JCS) + strict JSON parsing — implemented from the
//! RFC for this verifier, independent of the reference engine's canonicalizer
//! (which must produce byte-identical output; the corpus pins that).

use serde_json::Value;
use std::cmp::Ordering;
use std::fmt::Write as _;

/// RFC 8785 §3.2.2.2 string escaping: the five predefined escapes, the
/// remaining U+0000–U+001F as lower-hex `\u00xx`, `\"` and `\\`, and every
/// other code point RAW (U+007F and U+0080 included).
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
            c if (c as u32) <= 0x1F => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// RFC 8785 §3.2.3 property ordering: UTF-16 code-unit comparison (NOT
/// UTF-8/byte or code-point order).
fn utf16_cmp(a: &str, b: &str) -> Ordering {
    let av: Vec<u16> = a.encode_utf16().collect();
    let bv: Vec<u16> = b.encode_utf16().collect();
    av.cmp(&bv)
}

/// Canonical JSON per RFC 8785. The OpenReceipt value domain is strings,
/// arrays, booleans, and null — numbers are refused (RFC 8785 number
/// serialization is ECMAScript's, out of scope here; a serializer that might
/// emit a non-compliant number is worse than one that refuses).
pub fn encode(value: &Value) -> Result<String, String> {
    match value {
        Value::Null => Ok("null".to_string()),
        Value::Bool(b) => Ok(if *b { "true" } else { "false" }.to_string()),
        Value::Number(n) => Err(format!(
            "JSON number {n} is outside the OpenReceipt value domain (strings, arrays, booleans, null)"
        )),
        Value::String(s) => Ok(format!("\"{}\"", escape(s))),
        Value::Array(items) => {
            let inner: Vec<String> = items.iter().map(encode).collect::<Result<_, _>>()?;
            Ok(format!("[{}]", inner.join(",")))
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| utf16_cmp(a, b));
            let mut inner = String::new();
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    inner.push(',');
                }
                let _ = write!(inner, "\"{}\":{}", escape(k), encode(&map[*k])?);
            }
            Ok(format!("{{{inner}}}"))
        }
    }
}

/// A JSON document whose object property names are UNIQUE (RFC 8785 §2:
/// JCS input is I-JSON — objects MUST NOT contain duplicate names).
/// `serde_json::Value` silently keeps the last duplicate; this visitor
/// refuses instead, because evidence identities hash the DOCUMENT.
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
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{Error as _, MapAccess, SeqAccess, Visitor};

        struct V;

        impl<'de> Visitor<'de> for V {
            type Value = StrictJson;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a JSON value with no duplicate object property names")
            }

            fn visit_unit<E>(self) -> Result<StrictJson, E> {
                Ok(StrictJson::Null)
            }
            fn visit_bool<E>(self, v: bool) -> Result<StrictJson, E> {
                Ok(StrictJson::Bool(v))
            }
            fn visit_i64<E>(self, v: i64) -> Result<StrictJson, E> {
                Ok(StrictJson::Number(v.into()))
            }
            fn visit_u64<E>(self, v: u64) -> Result<StrictJson, E> {
                Ok(StrictJson::Number(v.into()))
            }
            fn visit_f64<E>(self, v: f64) -> Result<StrictJson, E>
            where
                E: serde::de::Error,
            {
                Ok(StrictJson::Number(
                    serde_json::Number::from_f64(v)
                        .ok_or_else(|| E::custom("non-finite number"))?,
                ))
            }
            fn visit_str<E>(self, v: &str) -> Result<StrictJson, E> {
                Ok(StrictJson::String(v.to_string()))
            }
            fn visit_string<E>(self, v: String) -> Result<StrictJson, E> {
                Ok(StrictJson::String(v))
            }
            fn visit_seq<A>(self, mut seq: A) -> Result<StrictJson, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut out = Vec::new();
                while let Some(v) = seq.next_element::<StrictJson>()? {
                    out.push(v);
                }
                Ok(StrictJson::Array(out))
            }
            fn visit_map<A>(self, mut map: A) -> Result<StrictJson, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut out: Vec<(String, StrictJson)> = Vec::new();
                while let Some(key) = map.next_key::<String>()? {
                    if out.iter().any(|(k, _)| k == &key) {
                        return Err(A::Error::custom(format!(
                            "duplicate object property name {key:?} — RFC 8785 requires I-JSON"
                        )));
                    }
                    let value = map.next_value::<StrictJson>()?;
                    out.push((key, value));
                }
                Ok(StrictJson::Object(out))
            }
        }

        deserializer.deserialize_any(V)
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

/// Parse strict JSON (RFC 8785 §2 I-JSON): duplicate property names are
/// refused, never silently collapsed.
pub fn parse_strict(bytes: &[u8]) -> Result<Value, String> {
    let doc: StrictJson =
        serde_json::from_slice(bytes).map_err(|e| format!("not strict JSON: {e}"))?;
    Ok(doc.into())
}
