package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"frf-verifier-go/jcs"
)

func fail(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "frf-verifier-go: "+format+"\n", args...)
	os.Exit(1)
}

func readFile(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		fail("cannot read %s: %v", path, err)
	}
	return b
}

func loadEvidence(path string) jcs.Value {
	b := readFile(path)
	v, err := jcs.ParseStrict(b)
	if err != nil {
		fail("%s: not strict JSON: %v", path, err)
	}
	canonical, err := jcs.Canonical(v)
	if err != nil {
		fail("%s: cannot canonicalize: %v", path, err)
	}
	if canonical != string(b) {
		fail("%s: the document is not its own canonical serialization (RFC 8785); refusing to verify a non-canonical evidence document", path)
	}
	return v
}

func loadEvidenceNoCanonical(path string) jcs.Value {
	b := readFile(path)
	v, err := jcs.ParseStrict(b)
	if err != nil {
		fail("%s: not strict JSON: %v", path, err)
	}
	return v
}

func safeJoin(root, rel string) string {
	p := filepath.Join(root, rel)
	if !strings.HasPrefix(p, root+string(os.PathSeparator)) && p != root {
		fail("path %s escapes the bundle root", rel)
	}
	return p
}

func sortedNames(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

// openBundle resolves a bundle path: a directory directly, or a single-file
// tar archive extracted to a fresh temp directory (returned with a cleanup).
func openBundle(path string) (string, func()) {
	if isDir(path) {
		return path, func() {}
	}
	dir, err := extractTar(path)
	if err != nil {
		fail("cannot extract single-file bundle: %v", err)
	}
	return dir, func() { os.RemoveAll(dir) }
}

// verifyBundle proves, from the bundle alone: the manifest's inventory
// rehashes, the receipt is content-addressed and semantically valid, the run
// identity rederives from the capture, every residual fingerprint + κ token
// rederives, the disposition chains verify, the claim's knowledge snapshot
// rederives, and the admissible claim IR matches the claim compiler's.
func verifyBundle(bundle string) ClaimIR {
	manifest := loadEvidenceNoCanonical(safeJoin(bundle, "manifest.json"))
	m := obj(manifest)
	if str(m, "schema_version") != "frf-bundle-v3" {
		fail("unsupported bundle schema version %v", str(m, "schema_version"))
	}
	receiptID := str(m, "receipt_id")
	run := str(m, "run")

	// 1. The manifest inventory: every file exists and hashes to its digest.
	inventory := make(map[string]string)
	for _, item := range arr(recVal(m, "inventory")) {
		io := obj(item)
		rel := str(io, "path")
		sha := str(io, "sha256")
		inventory[rel] = sha
		b := readFile(safeJoin(bundle, rel))
		if jcs.Sha256Hex(b) != sha {
			fail("bundle is corrupt: %s does not hash to the recorded digest", rel)
		}
	}

	// 2. The receipt: content-addressed from the raw canonical document.
	rec := loadEvidence(safeJoin(bundle, "receipts/"+receiptID+".json"))
	body := obj(rec)
	canonical, err := jcs.Canonical(rec)
	if err != nil {
		fail("receipt %s: cannot canonicalize: %v", receiptID, err)
	}
	digest := jcs.Sha256Hex([]byte(canonical))
	if !strings.HasSuffix(receiptID, "-"+digest) {
		fail("receipt %s is not content-addressed (the canonical document hashes to ...%s)", receiptID, digest[:16])
	}
	if str(body, "run") != run {
		fail("receipt %s: the run field does not match its id", receiptID)
	}
	for _, violation := range structuralViolations(rec) {
		fail("receipt %s fails structural conformance: %s", receiptID, violation)
	}
	for _, violation := range semanticViolations(rec) {
		fail("receipt %s fails semantic conformance: %s", receiptID, violation)
	}

	// 3. The capture: run identity rederives from the recorded fields.
	cap := loadEvidence(safeJoin(bundle, "captures/"+run+"/capture.json"))
	c := obj(cap)
	if str(c, "run") != run {
		fail("capture %s: the run field inside capture.json does not match", run)
	}
	if str(c, "court_semantic_identity") != str(objKeys(body, "court"), "semantic_identity") {
		// The receipt's court semantic identity must equal the capture's.
		fail("receipt %s: court semantic identity does not match the capture", receiptID)
	}
	var residuals []*jcs.Object
	for _, rid := range arr(recVal(c, "residuals")) {
		residuals = append(residuals, obj(loadEvidence(safeJoin(bundle, "residuals/"+rid.(string)+".json"))))
	}
	expectedRun, err := runIdentity(c, residuals)
	if err != nil {
		fail("capture %s: cannot rederive run identity: %v", run, err)
	}
	if "run-"+str(c, "court")+"-"+expectedRun != run {
		fail("capture %s: the run identity does not rederive (recorded %s, recomputed run-%s-%s)", run, run, str(c, "court"), expectedRun)
	}
	// Objects are content-addressed.
	objects := arr(recVal(c, "evidence_refs"))
	for _, r := range objects {
		ro := obj(r)
		if _, ok := ro.Get("cid"); ok {
			h := str(ro, "cid")
			if jcs.Sha256Hex(readFile(safeJoin(bundle, "objects/sha256/"+h))) != h {
				fail("object %s is corrupt (or missing)", h)
			}
		}
	}

	// 4. Residuals: fingerprints rederive; the receipt's residual records
	//    match the store's records; κ tokens rederive.
	receiptResiduals := arr(recVal(body, "residuals"))
	for i, rr := range receiptResiduals {
		rrObj := obj(rr)
		rid := str(rrObj, "id")
		var storeRecord *jcs.Object
		for _, s := range residuals {
			if str(s, "id") == rid {
				storeRecord = s
				break
			}
		}
		if storeRecord == nil {
			fail("receipt residual %s is missing from the bundle", rid)
		}
		fp, err := residualFingerprint(storeRecord)
		if err != nil || fp != str(rrObj, "residual_fingerprint") {
			fail("residual %s: the recorded fingerprint does not rederive", rid)
		}
		// The event chain verifies and projects the recorded disposition.
		var events []*jcs.Object
		for _, n := range sortedNames(safeJoin(bundle, "residuals/"+rid+".events")) {
			events = append(events, obj(loadEvidence(safeJoin(bundle, "residuals/"+rid+".events/"+n))))
		}
		verifyEventChain(events, rid)
		projected := projectedDisposition(events)
		if projected != str(rrObj, "disposition") {
			fail("residual %s: the receipt disposition %v does not match the event projection %v", rid, str(rrObj, "disposition"), projected)
		}
		if str(rrObj, "grammar_state") != grammarState(projected) {
			fail("residual %s: grammar_state does not match its disposition", rid)
		}
		// The κ token record matches the receipt's endoduction token.
		tok := obj(arr(recVal(objKeys(body, "endoduction"), "tokens"))[i])
		if str(tok, "residual_id") != rid {
			fail("token bound to %s but the residual is %s", str(tok, "residual_id"), rid)
		}
		expectedTok, _ := expectedToken(&jcs.Object{
			Keys:   []string{"kind", "axis", "disposition"},
			Values: []jcs.Value{str(rrObj, "kind"), str(rrObj, "axis"), str(rrObj, "disposition")},
		})
		if expectedTok != str(tok, "token") {
			fail("token of %s does not rederive", rid)
		}
		_ = i
	}

	// 5. The claim, when the bundle carries one: its knowledge snapshot
	//    rederives and its blockers derive from the bundle's universe.
	var ir ClaimIR
	claimRel := "claims/" + receiptID + ".json"
	if _, ok := inventory[claimRel]; ok {
		claim := loadEvidence(safeJoin(bundle, claimRel))
		snapshot := obj(recVal(obj(claim), "knowledge_snapshot"))
		expectedCID, err := knowledgeSnapshotIdentity(snapshot)
		if err != nil || expectedCID != str(snapshot, "cid") {
			fail("claim %s: the knowledge snapshot cid does not rederive", receiptID)
		}
		for _, h := range arr(recVal(snapshot, "residual_heads")) {
			ho := obj(h)
			record := obj(loadEvidence(safeJoin(bundle, "residuals/"+str(ho, "id")+".json")))
			rcid, err := recordContentIdentity(record)
			if err != nil || rcid != str(ho, "record_cid") {
				fail("claim %s: snapshot head %s record_cid does not rederive", receiptID, str(ho, "id"))
			}
			fp, err := residualFingerprint(record)
			if err != nil || fp != str(ho, "fingerprint") {
				fail("claim %s: snapshot head %s fingerprint does not rederive", receiptID, str(ho, "id"))
			}
		}
		ir = claimIR(body, bundle)
	} else {
		ir = claimIR(body, bundle)
	}
	return ir
}

// ClaimIR — the derived admissible claim set, computed from the bundle alone.
type ClaimIR struct {
	Admissible      bool
	HarnessInvalid  bool
	ObservableScope []string
	Excluded        []string
	Blockers        []string
}

// verifyEventChain proves the disposition events of one residual are
// content-addressed and hash-chained: each event rederives its own event_id
// from its recorded content and links to the previous event.
func verifyEventChain(events []*jcs.Object, rid string) {
	var prev *string
	for _, e := range events {
		var refs []jcs.Value
		for _, r := range arr(recVal(e, "evidence_refs")) {
			refs = append(refs, r)
		}
		id, err := dispositionEventIdentity(str(e, "residual_id"), prev, dispositionDoc(e), refs)
		if err != nil {
			fail("residual %s: cannot rederive disposition event identity: %v", rid, err)
		}
		if id != str(e, "event_id") {
			fail("residual %s: disposition event %s is not content-addressed; refusing to consume a hand-edited event", rid, str(e, "event_id"))
		}
		prev = stringPtr(id)
	}
}

func stringPtr(s string) *string { return &s }

// claimIR mirrors the claim compiler's scope algebra: a claim is admissible
// iff its scope K is non-empty, no premise run is harness-invalidated, and no
// open/unknown residual in the bundle intersects K (wherever it was
// recorded).
func claimIR(rec *jcs.Object, bundle string) ClaimIR {
	residuals := arr(recVal(rec, "residuals"))
	harness := false
	for _, r := range residuals {
		if str(obj(r), "disposition") == "harness" {
			harness = true
			break
		}
	}
	k := claimScope(rec)
	clean := asStrArray(recVal(k, "observables"))
	noCleanAxis := len(clean) == 0

	var blockers []string
	if !harness && !noCleanAxis {
		for _, rid := range sortedNames(safeJoin(bundle, "residuals")) {
			if !strings.HasSuffix(rid, ".json") || strings.HasSuffix(rid, ".token.json") {
				continue
			}
			id := strings.TrimSuffix(rid, ".json")
			var events []*jcs.Object
			for _, n := range sortedNames(safeJoin(bundle, "residuals/"+id+".events")) {
				events = append(events, obj(loadEvidence(safeJoin(bundle, "residuals/"+id+".events/"+n))))
			}
			disposition := projectedDisposition(events)
			if disposition != "open" && disposition != "unknown" {
				continue
			}
			record := obj(loadEvidence(safeJoin(bundle, "residuals/"+rid)))
			run := str(record, "run")
			cap := obj(loadEvidence(safeJoin(bundle, "captures/"+run+"/capture.json")))
			authorityID := str(record, "authority")
			authority := obj(loadEvidence(safeJoin(bundle, "authorities/"+authorityID+".json")))
			scope := residualScope(record, cap, authority)
			if scopesIntersect(scope, k) {
				blockers = append(blockers, id)
			}
		}
		sort.Strings(blockers)
	}
	var excluded []string
	for _, r := range residuals {
		excluded = append(excluded, str(obj(r), "id"))
	}
	return ClaimIR{
		Admissible:      !harness && !noCleanAxis && len(blockers) == 0,
		HarnessInvalid:  harness,
		ObservableScope: clean,
		Excluded:        excluded,
		Blockers:        blockers,
	}
}

func claimScope(rec *jcs.Object) *jcs.Object {
	envelope := objKeys(objKeys(rec, "court"), "admissibility_envelope")
	var clean []string
	for _, ob := range arr(recVal(rec, "observables")) {
		axis := str(obj(ob), "axis")
		hasResidual := false
		for _, r := range arr(recVal(rec, "residuals")) {
			if str(obj(r), "axis") == axis {
				hasResidual = true
				break
			}
		}
		if !hasResidual {
			clean = append(clean, axis)
		}
	}
	var fixtures []string
	for _, f := range arr(recVal(rec, "fixtures")) {
		fixtures = append(fixtures, str(obj(f), "id"))
	}
	var versions []string
	for _, v := range arrStr(recVal(envelope, "authority_versions")) {
		versions = append(versions, v)
	}
	authority := obj(recVal(rec, "authority"))
	return &jcs.Object{
		Keys: []string{"authority", "candidate", "fixtures", "fixture_family", "observables", "environments", "versions", "temporal"},
		Values: []jcs.Value{
			[]jcs.Value{authority.Str("name") + "-" + authority.Str("version")},
			[]jcs.Value{str(obj(recVal(rec, "candidate")), "identity_hash")},
			toValues(fixtures),
			str(envelope, "fixture_family"),
			toValues(clean),
			[]jcs.Value{str(obj(recVal(rec, "environment")), "digest")},
			toValues(versions),
			[]jcs.Value{str(rec, "run")},
		},
	}
}

func residualScope(record, cap, authority *jcs.Object) *jcs.Object {
	env := objKeys(objKeys(cap, "court_spec"), "admissibility_envelope")
	return &jcs.Object{
		Keys: []string{"authority", "candidate", "fixtures", "fixture_family", "observables", "environments", "versions", "temporal"},
		Values: []jcs.Value{
			[]jcs.Value{str(record, "authority")},
			[]jcs.Value{str(record, "candidate_sha256")},
			[]jcs.Value{str(cap, "fixture")},
			str(env, "fixture_family"),
			[]jcs.Value{str(record, "axis")},
			[]jcs.Value{str(obj(recVal(cap, "environment")), "digest")},
			[]jcs.Value{str(authority, "version")},
			[]jcs.Value{str(record, "run")},
		},
	}
}

func toValues(ss []string) []jcs.Value {
	out := make([]jcs.Value, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func scopesIntersect(a, b *jcs.Object) bool {
	overlap := func(x, y jcs.Value) bool {
		xa := asStrArray(x)
		ya := asStrArray(y)
		for _, v := range xa {
			for _, w := range ya {
				if v == w {
					return true
				}
			}
		}
		return false
	}
	return overlap(recVal(a, "authority"), recVal(b, "authority")) &&
		overlap(recVal(a, "candidate"), recVal(b, "candidate")) &&
		overlap(recVal(a, "fixtures"), recVal(b, "fixtures")) &&
		overlap(recVal(a, "observables"), recVal(b, "observables")) &&
		overlap(recVal(a, "environments"), recVal(b, "environments")) &&
		overlap(recVal(a, "versions"), recVal(b, "versions")) &&
		str(a, "fixture_family") == str(b, "fixture_family")
}

// verifyCorpus runs the conformance corpus: valid fixtures must canonicalize
// and hash to their pins; invalid must be refused structurally;
// invalid-semantic must be structurally valid but semantically refused.
func verifyCorpus(dir string) int {
	count := 0
	for _, name := range sortedNames(dir + "/valid") {
		path := dir + "/valid/" + name
		v := loadEvidenceNoCanonical(path)
		canonical, err := jcs.Canonical(v)
		if err != nil {
			fail("valid/%s: cannot canonicalize: %v", name, err)
		}
		expected := string(readFile(dir + "/canonical/" + name))
		if canonical != expected {
			fail("valid/%s: canonical bytes drifted", name)
		}
		digest := jcs.Sha256Hex([]byte(canonical))
		pinned := strings.TrimSpace(string(readFile(dir + "/hashes/" + name + ".sha256")))
		if digest != pinned {
			fail("valid/%s: digest drifted (got %s, pinned %s)", name, digest, pinned)
		}
		count++
	}
	for _, name := range sortedNames(dir + "/invalid") {
		source := readFile(dir + "/invalid/" + name)
		refused := true
		if v, err := jcs.ParseStrict(source); err == nil {
			refused = len(structuralViolations(v)) > 0
		}
		if !refused {
			fail("invalid/%s: must be refused", name)
		}
		count++
	}
	for _, name := range sortedNames(dir + "/invalid-semantic") {
		path := dir + "/invalid-semantic/" + name
		v := loadEvidenceNoCanonical(path)
		if sv := structuralViolations(v); len(sv) > 0 {
			fail("invalid-semantic/%s: must be structurally valid (found: %s)", name, sv[0])
		}
		if sv := semanticViolations(v); len(sv) == 0 {
			fail("invalid-semantic/%s: must be semantically refused", name)
		}
		count++
	}
	return count
}
