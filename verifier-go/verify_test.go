package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The conformance triangle, from the Go side: the corpus pins must reproduce
// byte-for-byte, and the golden bundle must verify to the same admissible
// claim IR as the Rust engine and the Rust xtask verifier.
func TestCorpusConformance(t *testing.T) {
	repo, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	count := verifyCorpus(filepath.Join(repo, "conformance"))
	if count == 0 {
		t.Fatal("corpus runner reported no fixtures")
	}
}

// goldenBundle returns the path to the checked-in golden bundle, or "" when
// ./golden/demo.sh has not been run yet (the bundles are generated, not
// checked in).
func goldenBundle() string {
	repo, err := repoRoot()
	if err != nil {
		return ""
	}
	p := filepath.Join(repo, "golden", "work", "portable.frf")
	if _, err := os.Stat(p); err != nil {
		return ""
	}
	return p
}

func TestGoldenBundleDerivesTheSameClaimIR(t *testing.T) {
	p := goldenBundle()
	if p == "" {
		t.Skip("golden bundle not generated (run ./golden/demo.sh first)")
	}
	ir := verifyBundle(p)
	if !ir.Admissible {
		t.Fatalf("the golden bundle must derive an admissible claim: %+v", ir)
	}
	if len(ir.ObservableScope) != 1 || ir.ObservableScope[0] != "exit" {
		t.Fatalf("unexpected observable scope: %v", ir.ObservableScope)
	}
	if len(ir.Blockers) != 0 {
		t.Fatalf("unexpected blockers: %v", ir.Blockers)
	}
}

func TestSingleFileBundleVerifies(t *testing.T) {
	p := goldenBundle()
	if p == "" {
		t.Skip("golden bundle not generated (run ./golden/demo.sh first)")
	}
	repo, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	dir, cleanup := openBundle(filepath.Join(repo, "golden", "work", "portable-single.frf"))
	defer cleanup()
	ir := verifyBundle(dir)
	if !ir.Admissible {
		t.Fatalf("the single-file bundle must derive an admissible claim: %+v", ir)
	}
}
