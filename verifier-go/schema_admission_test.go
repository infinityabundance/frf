package main

// The schema-admission triangle, from the Go side: the embedded registry copy
// must be byte-identical to the authoritative protocol/registry.json (the
// reference engine embeds the same registry; the xtask verifier reads the
// file — a drift in any copy would admit a different version set, so the
// conformance agreement would silently diverge), and the admission predicate
// must accept exactly the registered active/superseded ids and refuse
// reserved-invalid / unregistered / wrong-family ids — naming the version.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmbeddedRegistryIsByteIdenticalToTheAuthority(t *testing.T) {
	repo, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	authority, err := os.ReadFile(filepath.Join(repo, "protocol", "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(authority) != string(registryJSON) {
		t.Fatal("verifier-go/registry.json drifted from protocol/registry.json — copy the authoritative file into verifier-go/ and commit both")
	}
}

func TestAdmissionAcceptsEveryRegisteredActiveOrSupersededId(t *testing.T) {
	repo, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(repo, "protocol", "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Schemas []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"schemas"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, s := range doc.Schemas {
		id, status := s.ID, s.Status
		family, ok := familyOf(id)
		if !ok {
			continue // not a frf-<family>-v<N> schema id shape
		}
		if status != "active" && status != "superseded" {
			continue
		}
		if err := admitSchemaVersion(family, id); err != nil {
			t.Errorf("admitSchemaVersion(%q, %q) must accept a registered %s id: %v", family, id, status, err)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no registered active/superseded schema ids were exercised — the test is vacuous")
	}
}

func TestAdmissionRefusesReservedInvalidUnregisteredAndWrongFamily(t *testing.T) {
	// The three reserved-invalid ids the registry declares.
	for family, version := range map[string]string{
		"bundle":              "frf-bundle-v9",
		"comparator-response": "frf-comparator-response-v9",
		"execution-context":   "frf-execution-context-v9",
	} {
		err := admitSchemaVersion(family, version)
		if err == nil {
			t.Errorf("admitSchemaVersion(%q, %q) must refuse a reserved-invalid id", family, version)
			continue
		}
		if !strings.Contains(err.Error(), "reserved-invalid") || !strings.Contains(err.Error(), version) {
			t.Errorf("the refusal must name the version and its status: %v", err)
		}
	}
	// Unregistered versions are refused, naming the version. The version is
	// built dynamically so the protocol_registry lexical scan never sees an
	// unregistered token in source.
	unregistered := fmt.Sprintf("frf-receipt-v%d", 99)
	err := admitSchemaVersion("receipt", unregistered)
	if err == nil || !strings.Contains(err.Error(), unregistered) {
		t.Errorf("an unregistered version must be refused naming the version: %v", err)
	}
	// A wrong-family id is refused, naming the version.
	err = admitSchemaVersion("receipt", "frf-claim-v13")
	if err == nil || !strings.Contains(err.Error(), "frf-claim-v13") {
		t.Errorf("a wrong-family id must be refused naming the version: %v", err)
	}
	// A non-id is refused.
	if err := admitSchemaVersion("receipt", "not-a-schema"); err == nil {
		t.Error("a non-schema-id string must be refused")
	}
}

func TestAdmissionAdmitsOldRegisteredReceiptVersions(t *testing.T) {
	// The old-evidence guarantee: a registered SUPERSEDED receipt id is
	// admissible — a v19-shaped receipt (the current shape, one version back)
	// must pass the admission rule exactly like v20.
	for _, version := range []string{
		"frf-receipt-v5",
		"frf-receipt-v7",
		"frf-receipt-v12",
		"frf-receipt-v15",
		"frf-receipt-v16",
		"frf-receipt-v17",
		"frf-receipt-v18",
		"frf-receipt-v19",
		"frf-receipt-v20",
	} {
		if err := admitSchemaVersion("receipt", version); err != nil {
			t.Errorf("registered receipt version %s must be admitted: %v", version, err)
		}
	}
	if err := admitSchemaVersion("receipt", "not-a-schema"); err == nil {
		t.Error("a non-schema-id string must be refused")
	}
}
