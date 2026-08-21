package jcs

import "testing"

// The RFC 8785 escaping rules, pinned independently of the corpus: the five
// predefined short escapes, lower-hex \u00xx for the remaining controls, and
// U+007F/U+0080/non-ASCII emitted RAW (never escaped — \uXXXX escapes are
// literal characters, not code points, in JCS).
func TestEscapingMatchesRFC8785(t *testing.T) {
	v, err := ParseStrict([]byte(`{"s":"\u0008\u0009\u000A\u000C\u000D\u0000\u0001\u001f\u007f\u0080"}`))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Canonical(v)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"s\":\"\\b\\t\\n\\f\\r\\u0000\\u0001\\u001f\u007f\u0080\"}"
	if got != want {
		t.Fatalf("escaping mismatch:\n got %q\nwant %q", got, want)
	}
}

// Duplicate property names are refused (RFC 8785 §2 I-JSON): a duplicate
// would let an unknown property vanish before a content address is recomputed.
func TestDuplicatePropertyNamesAreRefused(t *testing.T) {
	if _, err := ParseStrict([]byte(`{"a":1,"a":2}`)); err == nil {
		t.Fatal("duplicate property names must be refused")
	}
}

// Keys sort by UTF-16 code units, not by code points or UTF-8 bytes: the
// emoji U+1F600 has the units 0xD83D 0xDE00, so it sorts BEFORE U+E000
// (unit 0xE000) even though its code point is larger. A code-point or
// byte-order sorter gets this backwards (Rust canon.rs pins the same
// property with U+10000 < U+E000).
func TestUtf16KeySorting(t *testing.T) {
	// "a" (0x0061) < "😀" (0xD83D 0xDE00) < "\uE000" (0xE000): UTF-16 code
	// unit ordering, unsigned and locale-independent.
	v, err := ParseStrict([]byte(`{"\uD83D\uDE00":"x","\uE000":"y","a":"z"}`))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Canonical(v)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"a\":\"z\",\"\U0001F600\":\"x\",\"\uE000\":\"y\"}"
	if got != want {
		t.Fatalf("utf-16 key sort mismatch:\n got %q\nwant %q", got, want)
	}
}

// Numbers are parsed (structural checks accept them) but refused at canonical
// encode: RFC 8785 number serialization is ECMAScript's and out of scope for
// the FRF value domain.
func TestNumbersAreRefusedAtCanonicalEncode(t *testing.T) {
	v, err := ParseStrict([]byte(`{"n":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Canonical(v); err == nil {
		t.Fatal("canonical encode must refuse numbers")
	}
}

// Surrogate pairs decode to the single code point; lone surrogates are
// refused.
func TestSurrogatePairs(t *testing.T) {
	v, err := ParseStrict([]byte(`{"s":"\uD83D\uDE00"}`))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := Canonical(v)
	if got != "{\"s\":\"\U0001F600\"}" {
		t.Fatalf("surrogate pair must decode to the code point, got %q", got)
	}
	if _, err := ParseStrict([]byte(`"\uD83D"`)); err == nil {
		t.Fatal("a lone high surrogate must be refused")
	}
}
