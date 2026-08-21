// Command frf-verifier-go — the independent FRF verifier in Go.
//
// Usage:
//
//	frf-verifier-go verify bundle <bundle-dir>          verify an exported bundle
//	frf-verifier-go verify bundle <bundle.frf>          (single-file tar, extracted to a temp dir)
//	frf-verifier-go verify corpus <conformance-dir>     run the structural + semantic corpus
//	frf-verifier-go test                                run corpus + golden bundle self-tests
//
// It shares no code and no parsing library with the Rust reference engine or
// the Rust xtask verifier: it reads court manifests never, and every evidence
// document as strict canonical JSON with its own RFC 8785 encoder.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		usage()
	}
	switch args[0] {
	case "verify":
		if len(args) < 3 {
			usage()
		}
		switch args[1] {
		case "bundle":
			dir, cleanup := openBundle(args[2])
			defer cleanup()
			ir := verifyBundle(dir)
			fmt.Printf("claim-ir: admissible=%v harness=%v observable_scope=%v excluded_evidence=%v blockers=%v\n",
				ir.Admissible, ir.HarnessInvalid, ir.ObservableScope, ir.Excluded, ir.Blockers)
		case "corpus":
			count := verifyCorpus(args[2])
			fmt.Printf("corpus conformance: %d fixture(s) passed\n", count)
		default:
			usage()
		}
	case "test":
		repo, err := repoRoot()
		if err != nil {
			fail("%v", err)
		}
		count := verifyCorpus(filepath.Join(repo, "conformance"))
		fmt.Printf("corpus conformance: %d fixture(s) passed\n", count)
		ir := verifyBundle(filepath.Join(repo, "golden", "work", "portable.frf"))
		fmt.Printf("claim-ir: admissible=%v harness=%v observable_scope=%v excluded_evidence=%v blockers=%v\n",
			ir.Admissible, ir.HarnessInvalid, ir.ObservableScope, ir.Excluded, ir.Blockers)
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `frf-verifier-go — the independent FRF verifier

  verify bundle <dir|single.frf>   verify an exported OpenReceipt bundle
  verify corpus <conformance-dir>  run the structural + semantic corpus
  test                             run the corpus + the golden bundle`)
	os.Exit(2)
}

func isTar(p string) bool {
	return strings.HasSuffix(p, ".frf") && !isDir(p)
}

func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// repoRoot walks up from the working directory to find the repository root
// (the directory containing conformance/).
func repoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := wd
	for {
		if isDir(filepath.Join(dir, "conformance")) && isDir(filepath.Join(dir, "golden")) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("cannot find the repository root (no conformance/ above %s)", wd)
		}
		dir = parent
	}
}
