package main

// Schema-version admission for the Go verifier (spec/versioning.md §2): a
// protocol object's schema_version must be a REGISTERED id of its object
// family with status active or superseded. Everything else is refused, and
// the refusal names the version.
//
// The registry is embedded (registry.json is a byte-identical copy of
// protocol/registry.json; registry_fresh_test.go pins the copy against the
// file). The Rust reference engine embeds the same registry (src/schema.rs)
// and the xtask verifier reads it directly — the three admission predicates
// are the same function over the same data, and the conformance corpus is
// the shared executable agreement.

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

//go:embed registry.json
var registryJSON []byte

var registryOnce sync.Once
var registrySchemas map[string]string

func registry() map[string]string {
	registryOnce.Do(func() {
		var doc struct {
			Schemas []struct {
				ID     string `json:"id"`
				Status string `json:"status"`
			} `json:"schemas"`
		}
		if err := json.Unmarshal(registryJSON, &doc); err != nil {
			panic(fmt.Sprintf("the embedded registry.json must be valid JSON: %v", err))
		}
		registrySchemas = make(map[string]string, len(doc.Schemas))
		for _, s := range doc.Schemas {
			registrySchemas[s.ID] = s.Status
		}
	})
	return registrySchemas
}

// familyOf is the object family part of a registered schema id
// (frf-receipt-v20 -> "receipt", frf-execution-context-v1 ->
// "execution-context"). The LAST -v is the version separator, so a family
// name that itself contains -v (frf-v3-build-manifest-v1) still parses.
func familyOf(version string) (string, bool) {
	rest, ok := strings.CutPrefix(version, "frf-")
	if !ok {
		return "", false
	}
	end := strings.LastIndex(rest, "-v")
	if end < 0 {
		return "", false
	}
	family := rest[:end]
	number := rest[end+2:]
	if family == "" || number == "" {
		return "", false
	}
	for _, b := range []byte(number) {
		if b < '0' || b > '9' {
			return "", false
		}
	}
	return family, true
}

// admitSchemaVersion admits a document's schema_version for the given object
// family, or refuses it — the refusal always names the version.
func admitSchemaVersion(family, version string) error {
	actual, ok := familyOf(version)
	if !ok {
		return fmt.Errorf("schema_version %q is not a registered schema id of the %s family (expected the shape frf-%s-v<N>)", version, family, family)
	}
	if actual != family {
		return fmt.Errorf("schema_version %q is a %s schema, not a %s schema — the wrong object family", version, actual, family)
	}
	switch status, registered := registry()[version]; {
	case registered && (status == "active" || status == "superseded"):
		return nil
	case registered:
		return fmt.Errorf("schema_version %q is registered as %s — only active or superseded schemas are admissible", version, status)
	default:
		return fmt.Errorf("schema_version %q is not a registered schema (protocol/registry.json) — unregistered versions are refused", version)
	}
}
