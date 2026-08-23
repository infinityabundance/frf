package main

import (
	"os"
	"path/filepath"
	"testing"

	"frf-verifier-go/jcs"
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

// The disposition event identity must rederive for the FIRST event (null
// parent) and for a chained event (a real parent id) — a typed nil *string
// parent must not leak into the canonical preimage.
func TestDispositionEventIdentityRederives(t *testing.T) {
	first := &jcs.Object{
		Keys:   []string{"disposition", "event_id", "evidence_refs", "parent_event_id", "reason", "residual_id", "schema_version"},
		Values: []jcs.Value{"intentional", "", []jcs.Value{}, nil, "wording", "cli-text-0001", "frf-disposition-v2"},
	}
	// The event id rederives from the canonical content over the NULL parent.
	refs := []jcs.Value{}
	id, err := dispositionEventIdentity("cli-text-0001", nil, dispositionDoc(first), refs)
	if err != nil {
		t.Fatalf("first event identity: %v", err)
	}
	if id == "" {
		t.Fatal("first event identity is empty")
	}
	// A chained event: the parent id participates as a plain string.
	second := &jcs.Object{
		Keys:   []string{"disposition", "event_id", "evidence_refs", "parent_event_id", "reason", "residual_id", "schema_version"},
		Values: []jcs.Value{"fixed", "", []jcs.Value{}, id, "patched", "cli-text-0001", "frf-disposition-v2"},
	}
	secondID, err := dispositionEventIdentity("cli-text-0001", id, dispositionDoc(second), refs)
	if err != nil {
		t.Fatalf("chained event identity: %v", err)
	}
	if secondID == id {
		t.Fatal("the chained event must not collide with its parent")
	}
	// The chained preimage differs from treating the parent as null.
	withNullParent, err := dispositionEventIdentity("cli-text-0001", nil, dispositionDoc(second), refs)
	if err != nil {
		t.Fatalf("null-parent chained identity: %v", err)
	}
	if withNullParent == secondID {
		t.Fatal("the parent id must participate in the chain identity")
	}
}

// The series identity must rederive for the FIRST snapshot (null parent) and
// a parent-linked append (a real parent id).
func TestSeriesIdentityRederives(t *testing.T) {
	point := &jcs.Object{
		Keys:   []string{"point_index", "coordinate", "coordinate_identity", "run"},
		Values: []jcs.Value{"1", "golden-machine", "cid-1", "run-x"},
	}
	id, err := seriesIdentity("exp-1", nil, "cli-malformed-input", "environment", []*jcs.Object{point})
	if err != nil {
		t.Fatalf("first series identity: %v", err)
	}
	if id == "" {
		t.Fatal("series identity is empty")
	}
	child, err := seriesIdentity("exp-1", id, "cli-malformed-input", "environment", []*jcs.Object{point})
	if err != nil {
		t.Fatalf("child series identity: %v", err)
	}
	if child == id {
		t.Fatal("the child snapshot must not collide with its parent")
	}
}

// The extended trajectory vocabulary rederives: boundary-localized,
// version-stratified, and gradual (a monotonic magnitude ramp).
func TestTrajectoryVocabularyRederives(t *testing.T) {
	none := func(n int) []*string { return make([]*string, n) }
	strPtr := func(s string) *string { return &s }

	// Persistent + stable with no measure.
	drift, slew, loc, bands, trend := trajectoryClassify([]bool{true, true, true}, "repeat_index", none(3), "none")
	if drift != "persistent" || slew != "stable" || loc != "none" || bands != "1" || trend != "unknown" {
		t.Fatalf("persistent: %s/%s/%s/%s/%s", drift, slew, loc, bands, trend)
	}
	// A cessation confined to the start: boundary-localized.
	drift, slew, loc, bands, _ = trajectoryClassify([]bool{true, false, false}, "candidate_revision", none(3), "none")
	if drift != "boundary-localized" || slew != "abrupt" || loc != "start" {
		t.Fatalf("boundary-localized: %s/%s/%s", drift, slew, loc)
	}
	// Two interior bands on a version ladder: version-stratified.
	drift, slew, loc, bands, _ = trajectoryClassify([]bool{false, true, false, true, false}, "authority_version", none(5), "none")
	if drift != "version-stratified" || slew != "recurrent" || loc != "interior" || bands != "2" {
		t.Fatalf("version-stratified: %s/%s/%s/%s", drift, slew, loc, bands)
	}
	// The same pattern on the environment axis is not stratified.
	drift, _, _, _, _ = trajectoryClassify([]bool{false, true, false, true, false}, "environment", none(5), "none")
	if drift != "transient" {
		t.Fatalf("environment pattern must be transient, got %s", drift)
	}
	// A monotonic magnitude ramp is gradual.
	mags := []*string{strPtr("1"), strPtr("2"), strPtr("3"), strPtr("4")}
	drift, slew, _, _, trend = trajectoryClassify([]bool{true, true, true, true}, "candidate_revision", mags, "line-edit-distance")
	if drift != "persistent" || slew != "gradual" || trend != "increasing" {
		t.Fatalf("gradual: %s/%s/%s", drift, slew, trend)
	}
	// Flat magnitude is not gradual.
	flat := []*string{strPtr("2"), strPtr("2"), strPtr("2")}
	_, slew, _, _, trend = trajectoryClassify([]bool{true, true, true}, "repeat_index", flat, "exit-code-distance")
	if slew != "stable" || trend != "flat" {
		t.Fatalf("flat: %s/%s", slew, trend)
	}
}

// The magnitude measures rederive deterministically.
func TestDivergenceMagnitudeRederives(t *testing.T) {
	e := divergenceMagnitude("exit", "2", "1")
	if e == nil || *e != "1" {
		t.Fatalf("exit magnitude: %v", e)
	}
	same := divergenceMagnitude("exit", "2", "2")
	if same == nil || *same != "0" {
		t.Fatalf("equal exit magnitude: %v", same)
	}
	l := divergenceMagnitude("stderr", "tool: line 4: unknown directive", "error: unknown directive")
	if l == nil || *l == "0" {
		t.Fatalf("line magnitude must be nonzero: %v", l)
	}
	n := divergenceMagnitude("filesystem.tree", "abc", "def")
	if n != nil {
		t.Fatalf("tree must declare no magnitude: %v", n)
	}
}
