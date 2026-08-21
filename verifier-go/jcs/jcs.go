// Package jcs implements RFC 8785 (JCS — JSON Canonicalization Scheme) for
// the FRF protocol value domain, independently of the Rust reference engine:
//
//   - a STRICT I-JSON parser that refuses duplicate object property names
//     (RFC 8785 §2 says JSON objects MUST NOT contain duplicate names; a
//     duplicate would let an unknown property vanish before a content
//     address is recomputed);
//   - a canonical encoder that sorts object keys by UTF-16 code units
//     (§3.2.3), emits no whitespace (§3.2.1), applies the RFC's exact string
//     escaping (§3.2.2.2), and REFUSES numbers — the FRF value domain is
//     strings, arrays, booleans, and null only (§3.2.2.3 is ECMAScript's
//     number serialization, deliberately out of scope).
//
// The byte-for-byte reference is the conformance corpus in conformance/:
// the valid fixtures' canonical pins and SHA-256 hash pins were produced by
// the Rust engine, and this package must reproduce them exactly — that is
// the whole point of the conformance triangle.

package jcs

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Value is a parsed JCS value: nil (null), bool, string, []Value, or *Object.
type Value interface{}

// Object preserves the source document's property order (JCS reorders at
// encode time); duplicate keys are REFUSED by the parser.
type Object struct {
	Keys   []string
	Values []Value
}

func (o *Object) Get(key string) (Value, bool) {
	for i, k := range o.Keys {
		if k == key {
			return o.Values[i], true
		}
	}
	return nil, false
}

func (o *Object) Str(key string) string {
	if v, ok := o.Get(key); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// ParseStrict parses a JSON document, refusing duplicate property names and
// trailing garbage. Returns the value tree.
func ParseStrict(b []byte) (Value, error) {
	p := &parser{src: b}
	v, err := p.parseValue()
	if err != nil {
		return nil, err
	}
	p.skipWS()
	if p.pos != len(p.src) {
		return nil, fmt.Errorf("trailing data after JSON document at byte %d", p.pos)
	}
	return v, nil
}

type parser struct {
	src []byte
	pos int
}

func (p *parser) skipWS() {
	for p.pos < len(p.src) {
		switch p.src[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *parser) parseValue() (Value, error) {
	p.skipWS()
	if p.pos >= len(p.src) {
		return nil, fmt.Errorf("unexpected end of document")
	}
	switch c := p.src[p.pos]; {
	case c == '{':
		return p.parseObject()
	case c == '[':
		return p.parseArray()
	case c == '"':
		s, err := p.parseString()
		return s, err
	case c == 't':
		return p.parseLit("true", true)
	case c == 'f':
		return p.parseLit("false", false)
	case c == 'n':
		return p.parseLit("null", nil)
	case c == '-' || (c >= '0' && c <= '9'):
		return p.parseNumber()
	default:
		return nil, fmt.Errorf("unexpected character %q at byte %d", c, p.pos)
	}
}

func (p *parser) parseLit(lit string, v Value) (Value, error) {
	if p.pos+len(lit) > len(p.src) || string(p.src[p.pos:p.pos+len(lit)]) != lit {
		return nil, fmt.Errorf("invalid literal at byte %d", p.pos)
	}
	p.pos += len(lit)
	return v, nil
}

func (p *parser) parseNumber() (Value, error) {
	start := p.pos
	if p.src[p.pos] == '-' {
		p.pos++
	}
	for p.pos < len(p.src) && p.src[p.pos] >= '0' && p.src[p.pos] <= '9' {
		p.pos++
	}
	if p.pos < len(p.src) && p.src[p.pos] == '.' {
		p.pos++
		for p.pos < len(p.src) && p.src[p.pos] >= '0' && p.src[p.pos] <= '9' {
			p.pos++
		}
	}
	if p.pos < len(p.src) && (p.src[p.pos] == 'e' || p.src[p.pos] == 'E') {
		p.pos++
		if p.pos < len(p.src) && (p.src[p.pos] == '+' || p.src[p.pos] == '-') {
			p.pos++
		}
		for p.pos < len(p.src) && p.src[p.pos] >= '0' && p.src[p.pos] <= '9' {
			p.pos++
		}
	}
	// The number is parsed (structural checks accept it) but the FRF value
	// domain refuses numbers at CANONICAL-ENCODE time; the token is kept.
	return &numberToken{raw: string(p.src[start:p.pos])}, nil
}

type numberToken struct{ raw string }

func (p *parser) parseArray() (Value, error) {
	p.pos++ // [
	p.skipWS()
	var items []Value
	if p.pos < len(p.src) && p.src[p.pos] == ']' {
		p.pos++
		return items, nil
	}
	for {
		v, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		items = append(items, v)
		p.skipWS()
		if p.pos >= len(p.src) {
			return nil, fmt.Errorf("unterminated array")
		}
		switch p.src[p.pos] {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return items, nil
		default:
			return nil, fmt.Errorf("expected ',' or ']' at byte %d", p.pos)
		}
	}
}

func (p *parser) parseObject() (Value, error) {
	p.pos++ // {
	p.skipWS()
	obj := &Object{}
	if p.pos < len(p.src) && p.src[p.pos] == '}' {
		p.pos++
		return obj, nil
	}
	seen := make(map[string]bool)
	for {
		p.skipWS()
		if p.pos >= len(p.src) || p.src[p.pos] != '"' {
			return nil, fmt.Errorf("expected property name at byte %d", p.pos)
		}
		key, err := p.parseString()
		if err != nil {
			return nil, err
		}
		if seen[key] {
			return nil, fmt.Errorf("duplicate property name %q (RFC 8785 §2: JSON objects MUST NOT contain duplicate names)", key)
		}
		seen[key] = true
		p.skipWS()
		if p.pos >= len(p.src) || p.src[p.pos] != ':' {
			return nil, fmt.Errorf("expected ':' after property %q at byte %d", key, p.pos)
		}
		p.pos++
		v, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		obj.Keys = append(obj.Keys, key)
		obj.Values = append(obj.Values, v)
		p.skipWS()
		if p.pos >= len(p.src) {
			return nil, fmt.Errorf("unterminated object")
		}
		switch p.src[p.pos] {
		case ',':
			p.pos++
		case '}':
			p.pos++
			return obj, nil
		default:
			return nil, fmt.Errorf("expected ',' or '}' at byte %d", p.pos)
		}
	}
}

func (p *parser) parseString() (string, error) {
	// p.src[p.pos] == '"'
	p.pos++
	var sb strings.Builder
	for {
		if p.pos >= len(p.src) {
			return "", fmt.Errorf("unterminated string")
		}
		c := p.src[p.pos]
		switch {
		case c == '"':
			p.pos++
			return sb.String(), nil
		case c == '\\':
			p.pos++
			if p.pos >= len(p.src) {
				return "", fmt.Errorf("unterminated escape")
			}
			e := p.src[p.pos]
			p.pos++
			switch e {
			case '"':
				sb.WriteByte('"')
			case '\\':
				sb.WriteByte('\\')
			case '/':
				sb.WriteByte('/')
			case 'b':
				sb.WriteByte('\b')
			case 'f':
				sb.WriteByte('\f')
			case 'n':
				sb.WriteByte('\n')
			case 'r':
				sb.WriteByte('\r')
			case 't':
				sb.WriteByte('\t')
			case 'u':
				if p.pos+4 > len(p.src) {
					return "", fmt.Errorf("truncated \\u escape")
				}
				r1, err := hex4(p.src[p.pos : p.pos+4])
				if err != nil {
					return "", err
				}
				p.pos += 4
				// Surrogate pairs.
				if utf16.IsSurrogate(rune(r1)) {
					if r1 >= 0xD800 && r1 <= 0xDBFF { // high surrogate
						if p.pos+6 <= len(p.src) && p.src[p.pos] == '\\' && p.src[p.pos+1] == 'u' {
							r2, err := hex4(p.src[p.pos+2 : p.pos+6])
							if err != nil {
								return "", err
							}
							if r2 >= 0xDC00 && r2 <= 0xDFFF {
								p.pos += 6
								sb.WriteRune(utf16.DecodeRune(rune(r1), rune(r2)))
								continue
							}
						}
						return "", fmt.Errorf("lone high surrogate in \\u escape")
					}
					return "", fmt.Errorf("lone low surrogate in \\u escape")
				}
				sb.WriteRune(rune(r1))
			default:
				return "", fmt.Errorf("invalid escape \\%c", e)
			}
		case c < 0x20:
			return "", fmt.Errorf("raw control character 0x%02x in string (RFC 8785 requires escaped control characters)", c)
		default:
			r, size := utf8.DecodeRune(p.src[p.pos:])
			if r == utf8.RuneError && size == 1 {
				return "", fmt.Errorf("invalid UTF-8 at byte %d", p.pos)
			}
			sb.WriteRune(r)
			p.pos += size
		}
	}
}

func hex4(b []byte) (uint32, error) {
	var v uint32
	for i := 0; i < 4; i++ {
		c := b[i]
		var d uint32
		switch {
		case c >= '0' && c <= '9':
			d = uint32(c - '0')
		case c >= 'a' && c <= 'f':
			d = uint32(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = uint32(c-'A') + 10
		default:
			return 0, fmt.Errorf("invalid \\u hex digit %q", c)
		}
		v = v*16 + d
	}
	return v, nil
}

// Canonical serializes a parsed value per RFC 8785, refusing numbers (the
// FRF value domain). The output is the byte-for-byte identity document.
func Canonical(v Value) (string, error) {
	var sb strings.Builder
	if err := encode(&sb, v); err != nil {
		return "", err
	}
	return sb.String(), nil
}

func encode(sb *strings.Builder, v Value) error {
	switch t := v.(type) {
	case nil:
		sb.WriteString("null")
	case bool:
		if t {
			sb.WriteString("true")
		} else {
			sb.WriteString("false")
		}
	case string:
		sb.WriteString(escapeString(t))
	case *numberToken:
		return fmt.Errorf("cannot canonicalize the JSON number %s: RFC 8785 number serialization is out of scope for the FRF value domain (strings, arrays, booleans, and null only)", t.raw)
	case []Value:
		sb.WriteByte('[')
		for i, item := range t {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := encode(sb, item); err != nil {
				return err
			}
		}
		sb.WriteByte(']')
	case *Object:
		// RFC 8785 §3.2.3: keys sorted by UTF-16 code units.
		idx := make([]int, len(t.Keys))
		for i := range idx {
			idx[i] = i
		}
		sort.SliceStable(idx, func(a, b int) bool {
			return utf16Compare(t.Keys[idx[a]], t.Keys[idx[b]]) < 0
		})
		sb.WriteByte('{')
		for i, j := range idx {
			if i > 0 {
				sb.WriteByte(',')
			}
			sb.WriteString(escapeString(t.Keys[j]))
			sb.WriteByte(':')
			if err := encode(sb, t.Values[j]); err != nil {
				return err
			}
		}
		sb.WriteByte('}')
	default:
		return fmt.Errorf("cannot canonicalize unknown value type %T", v)
	}
	return nil
}

// utf16Compare compares two strings by their UTF-16 code units (unsigned,
// locale-independent): first differing unit decides; a shorter name precedes
// a longer one that has it as a prefix (RFC 8785 §3.2.3).
func utf16Compare(a, b string) int {
	au := utf16.Encode([]rune(a))
	bu := utf16.Encode([]rune(b))
	for i := 0; i < len(au) && i < len(bu); i++ {
		if au[i] < bu[i] {
			return -1
		}
		if au[i] > bu[i] {
			return 1
		}
	}
	switch {
	case len(au) < len(bu):
		return -1
	case len(au) > len(bu):
		return 1
	}
	return 0
}

// escapeString applies RFC 8785 §3.2.2.2: `"` and `\` escaped, the five
// predefined short escapes for U+0008/0009/000A/000C/000D, lower-hex \u00xx
// for the remaining U+0000–U+001F, and everything else — U+007F and U+0080
// included — emitted RAW as UTF-8.
func escapeString(s string) string {
	var sb strings.Builder
	sb.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		case '\b':
			sb.WriteString(`\b`)
		case '\t':
			sb.WriteString(`\t`)
		case '\n':
			sb.WriteString(`\n`)
		case '\f':
			sb.WriteString(`\f`)
		case '\r':
			sb.WriteString(`\r`)
		default:
			if r <= 0x1F {
				fmt.Fprintf(&sb, `\u%04x`, r)
			} else {
				sb.WriteRune(r)
			}
		}
	}
	sb.WriteByte('"')
	return sb.String()
}

// Sha256Hex returns the lowercase hex SHA-256 of b.
func Sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	const hexd = "0123456789abcdef"
	out := make([]byte, 64)
	for i, c := range sum {
		out[i*2] = hexd[c>>4]
		out[i*2+1] = hexd[c&0xF]
	}
	return string(out)
}
