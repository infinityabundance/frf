package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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

	// 4b. The receipt's trajectory evidence REDERIVES from the pinned
	//     series: each entry's snapshot must exist, match the coordinate
	//     system, contain the run, and its trajectory record for the
	//     residual's lineage must yield the recorded drift/slew — with the
	//     full derivation (localization/bands/trend/magnitude_kind)
	//     recomputed from the trajectory's observations and the observed
	//     residuals' compared projections.
	verifyTrajectoryEvidence(bundle, body, run)

	// 5. The claims bound to the receipt, when the bundle carries them:
	//    resolved through the claims/by-receipt index. Each claim's id must
	//    rederive (FRF/CLAIM/v1 over the canonical document minus the id — a
	//    hand-written or forged claim file is refused), its knowledge
	//    snapshot rederives, and its blockers derive from the bundle's
	//    universe.
	var ir ClaimIR
	claimIndex := safeJoin(bundle, "claims/by-receipt/"+receiptID)
	claimIDs := sortedNames(claimIndex)
	if len(claimIDs) > 0 {
		for _, claimID := range claimIDs {
			if len(claimID) != 64 {
				fail("claim index %s: %s is not a claim id", receiptID, claimID)
			}
			claimRel := "claims/" + claimID + ".json"
			claim := loadEvidence(safeJoin(bundle, claimRel))
			// The claim id rederives: FRF/CLAIM/v1 over the canonical
			// document minus the id field.
			claimCID, err := claimIdentity(claim)
			if err != nil || claimCID != claimID {
				fail("claim %s is not content-addressed: the canonical document minus the id hashes to %s; refusing to consume a hand-edited or forged claim", claimID, claimCID)
			}
			if str(obj(claim), "schema_version") != "frf-claim-v9" {
				fail("claim %s: unexpected schema version %s", claimID, str(obj(claim), "schema_version"))
			}
			snapshot := obj(recVal(obj(claim), "knowledge_snapshot"))
			expectedCID, err := knowledgeSnapshotIdentity(snapshot)
			if err != nil || expectedCID != str(snapshot, "cid") {
				fail("claim %s: the knowledge snapshot cid does not rederive", claimID)
			}
			for _, h := range arr(recVal(snapshot, "residual_heads")) {
				ho := obj(h)
				record := obj(loadEvidence(safeJoin(bundle, "residuals/"+str(ho, "id")+".json")))
				rcid, err := recordContentIdentity(record)
				if err != nil || rcid != str(ho, "record_cid") {
					fail("claim %s: snapshot head %s record_cid does not rederive", claimID, str(ho, "id"))
				}
				fp, err := residualFingerprint(record)
				if err != nil || fp != str(ho, "fingerprint") {
					fail("claim %s: snapshot head %s fingerprint does not rederive", claimID, str(ho, "id"))
				}
			}
			// The universe's committed OBJECTS must rederive from the bundle's
			// own documents: every receipt/run/authority/series/reduction the
			// blocker scan depended on must be present with its committed
			// content address.
			seen := map[string]bool{}
			for _, ov := range arr(recVal(snapshot, "objects")) {
				o := obj(ov)
				kind := str(o, "kind")
				oid := str(o, "id")
				committed := str(o, "cid")
				key := kind + ":" + oid
				if seen[key] {
					fail("claim %s: duplicate object %s in the knowledge snapshot", claimID, key)
				}
				seen[key] = true
				switch kind {
				case "receipt":
					rec := obj(loadEvidence(safeJoin(bundle, "receipts/"+oid+".json")))
					digest := ""
					if parts := strings.Split(oid, "-"); len(parts) >= 2 {
						digest = parts[len(parts)-1]
					}
					if digest != committed {
						fail("claim %s: committed universe receipt %s cid does not match its identity", claimID, oid)
					}
					if rc, err := recordContentIdentity(rec); err != nil || rc != committed {
						fail("claim %s: committed universe receipt %s does not rederive", claimID, oid)
					}
				case "run":
					cap := obj(loadEvidence(safeJoin(bundle, "captures/"+oid+"/capture.json")))
					var residuals []*jcs.Object
					for _, ridV := range arr(recVal(cap, "residuals")) {
						residuals = append(residuals, obj(loadEvidence(safeJoin(bundle, "residuals/"+ridV.(string)+".json"))))
					}
					expected, err := runIdentity(cap, residuals)
					if err != nil || "run-"+str(cap, "court")+"-"+expected != oid {
						fail("claim %s: committed universe run %s is not content-addressed", claimID, oid)
					}
					digest := ""
					if parts := strings.Split(oid, "-"); len(parts) >= 2 {
						digest = parts[len(parts)-1]
					}
					if digest != committed {
						fail("claim %s: committed universe run %s cid does not match its identity", claimID, oid)
					}
				case "authority":
					rec := obj(loadEvidence(safeJoin(bundle, "authorities/"+oid+".json")))
					if rc, err := recordContentIdentity(rec); err != nil || rc != committed {
						fail("claim %s: committed universe authority %s does not rederive", claimID, oid)
					}
				case "series":
					ser := obj(loadEvidence(safeJoin(bundle, "series/"+oid+".json")))
					expected, err := seriesIdentity(str(ser, "experiment_id"), recVal(ser, "parent_series_id"), str(ser, "court"), str(ser, "coordinate_system"), arrP(recVal(ser, "points")))
					if err != nil || expected != oid || committed != oid {
						fail("claim %s: committed universe series %s does not rederive", claimID, oid)
					}
				case "reduction":
					rd := obj(loadEvidence(safeJoin(bundle, "reductions/"+oid+".json")))
					expected, err := reductionIdentity(rd)
					if err != nil || expected != oid || committed != oid {
						fail("claim %s: committed universe reduction %s does not rederive", claimID, oid)
					}
				default:
					fail("claim %s: the knowledge universe names an unknown object kind %s", claimID, kind)
				}
			}
			// The claim's admission policy re-derives from the bundle alone:
			// the capability/witness evidence is referenced by content, never
			// trusted from the claim file.
			verifyClaimPolicy(bundle, obj(claim), body, receiptID)
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

// verifyTrajectoryEvidence — the receipt's sign entries REDERIVE from the
// bundle alone: each entry's pinned series snapshot must exist, match the
// coordinate system, contain the run, and its trajectory record for the
// residual's lineage must yield the recorded drift/slew. The trajectory's
// derivation (drift/slew/localization/bands/trend/magnitude_kind) is
// recomputed from its observations and the observed residuals' compared
// projections — never trusted from the trajectory file.
func verifyTrajectoryEvidence(bundle string, body *jcs.Object, run string) {
	cap := obj(loadEvidence(safeJoin(bundle, "captures/"+run+"/capture.json")))
	fixture := str(cap, "fixture")
	for _, rv := range arr(recVal(body, "residuals")) {
		ro := obj(rv)
		rid := str(ro, "id")
		record := obj(loadEvidence(safeJoin(bundle, "residuals/"+rid+".json")))
		authority := obj(loadEvidence(safeJoin(bundle, "authorities/"+str(record, "authority")+".json")))
		var surface *string
		if s, ok := recVal(record, "surface").(string); ok {
			surface = &s
		}
		lineage, err := residualLineage(
			str(record, "kind"),
			str(record, "axis"),
			surface,
			str(record, "scope"),
			str(authority, "name"),
			fixture,
		)
		if err != nil {
			fail("residual %s: cannot rederive lineage: %v", rid, err)
		}
		sign := objKeys(ro, "sign")
		for _, ev := range arr(recVal(sign, "trajectory_evidence")) {
			eo := obj(ev)
			coord := str(eo, "coordinate_system")
			sid := str(eo, "series")
			series := obj(loadEvidence(safeJoin(bundle, "series/"+sid+".json")))
			if str(series, "coordinate_system") != coord {
				fail("residual %s: the pinned series %s is a %s experiment, not %s", rid, sid, str(series, "coordinate_system"), coord)
			}
			containsRun := false
			for _, p := range arr(recVal(series, "points")) {
				if str(obj(p), "run") == str(record, "run") {
					containsRun = true
					break
				}
			}
			if !containsRun {
				fail("residual %s: the pinned series %s does not contain its run", rid, sid)
			}
			t := obj(loadEvidence(safeJoin(bundle, "trajectories/"+lineage+"."+coord+"."+sid+".json")))
			if str(t, "subject") != lineage {
				fail("residual %s: the trajectory is not keyed by its lineage", rid)
			}
			// The classification recomputes from the observations (sorted by
			// point index) with the magnitudes recomputed from the residuals.
			type obsPoint struct {
				idx       int
				observed  bool
				magnitude *string
			}
			var points []obsPoint
			for _, ov := range arr(recVal(t, "observations")) {
				oo := obj(ov)
				observed, _ := recVal(oo, "observed").(bool)
				var mag *string
				if ridObs := str(oo, "residual"); ridObs != "" {
					obsRec := obj(loadEvidence(safeJoin(bundle, "residuals/"+ridObs+".json")))
					mag = divergenceMagnitude(
						str(obsRec, "axis"),
						str(obsRec, "raw_reference"),
						str(obsRec, "raw_candidate"),
					)
				}
				idx, _ := strconv.Atoi(str(oo, "point_index"))
				points = append(points, obsPoint{idx: idx, observed: observed, magnitude: mag})
			}
			sort.SliceStable(points, func(a, b int) bool { return points[a].idx < points[b].idx })
			observed := make([]bool, len(points))
			magnitudes := make([]*string, len(points))
			for i, p := range points {
				observed[i] = p.observed
				magnitudes[i] = p.magnitude
			}
			kind := magnitudeKind(str(t, "axis"))
			der := obj(recVal(t, "derivation"))
			drift, slew, localization, bands, trend := trajectoryClassify(observed, coord, magnitudes, kind)
			if drift != str(der, "drift") ||
				slew != str(der, "slew") ||
				localization != str(der, "localization") ||
				bands != str(der, "bands") ||
				trend != str(der, "trend") ||
				kind != str(der, "magnitude_kind") {
				fail("residual %s: trajectory derivation does not rederive", rid)
			}
			if drift != str(eo, "drift") || slew != str(eo, "slew") {
				fail("residual %s: sign does not match its pinned trajectory", rid)
			}
		}
	}
}

// verifyEventChain proves the disposition events of one residual are
// content-addressed and hash-chained: each event rederives its own event_id
// from its recorded content and links to the previous event.
func verifyEventChain(events []*jcs.Object, rid string) {
	var prev jcs.Value
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
		prev = id
	}
}

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

// verifyClaimPolicy re-derives a compiled claim's admission policy from the
// bundle alone: the claim's capability / witness_statements / replay_profile
// are evidence references, and each tier's requirements are checked against
// the bundle's own objects — never trusted from the claim file. Since v6 a
// claim is MULTI-PREMISE: every capability entry binds the premise receipt
// its covered axes belong to, and each tier's obligations hold per premise.
func verifyClaimPolicy(bundle string, claim, body *jcs.Object, receiptID string) {
	policy := str(claim, "policy")
	switch policy {
	case "baseline":
		return
	case "sensitivity-backed", "independently-witnessed", "high-assurance":
	default:
		fail("claim %s: unknown admission policy %s", receiptID, policy)
	}

	// The premise receipts the claim names; the claim file is named after
	// the first premise.
	requires := asStrArray(recVal(claim, "requires"))
	if len(requires) == 0 {
		fail("claim %s: names no premise receipts", receiptID)
	}
	if str(claim, "receipt") != receiptID {
		fail("claim %s: the claim file does not bind its first premise", receiptID)
	}
	premise := func(premID string) *jcs.Object {
		return obj(loadEvidence(safeJoin(bundle, "receipts/"+premID+".json")))
	}
	// Subject coherence: every premise binds the same authority and the same
	// candidate artifact (the reference compiler enforces this at compile
	// time; the verifier re-derives it from the bundle's own receipts).
	first := premise(requires[0])
	for _, premID := range requires[1:] {
		p := premise(premID)
		if str(obj(recVal(p, "authority")), "name") != str(obj(recVal(first, "authority")), "name") ||
			str(obj(recVal(p, "authority")), "version") != str(obj(recVal(first, "authority")), "version") ||
			str(obj(recVal(p, "authority")), "identity_hash") != str(obj(recVal(first, "authority")), "identity_hash") {
			fail("claim %s: the premises bind different authorities", receiptID)
		}
		if str(obj(recVal(p, "candidate")), "identity_hash") != str(obj(recVal(first, "candidate")), "identity_hash") {
			fail("claim %s: the premises bind different candidate artifacts", receiptID)
		}
	}

	claimed := asStrArray(recVal(claim, "observable_scope"))
	covered := make(map[string]bool)
	for _, capV := range arr(recVal(claim, "capability")) {
		cap := obj(capV)
		axis := str(cap, "axis")
		premID := str(cap, "receipt")
		premOK := false
		for _, r := range requires {
			if r == premID {
				premOK = true
				break
			}
		}
		if !premOK {
			fail("claim %s: capability entry for axis %s binds premise %s which the claim does not require", receiptID, axis, premID)
		}
		prem := premise(premID)
		ids := asStrArray(recVal(cap, "challenge_ids"))
		if len(ids) == 0 {
			fail("claim %s: capability entry for axis %s names no challenge", receiptID, axis)
		}
		// The DEMONSTRATED mutation profile rederives from the named
		// challenges: the distinct operators of exactly the recorded ids.
		rederived := []string{}
		for _, cid := range ids {
			ch := obj(loadEvidence(safeJoin(bundle, "challenges/"+cid+".json")))
			rederived = append(rederived, str(ch, "operator"))
			if str(ch, "court") != str(obj(recVal(prem, "court")), "id") {
				fail("claim %s: challenge %s is not a challenge of premise %s's court", receiptID, cid, premID)
			}
			if str(ch, "target_axis") != axis {
				fail("claim %s: challenge %s targets %s not %s", receiptID, cid, str(ch, "target_axis"), axis)
			}
			if str(ch, "reference_sha256") != str(obj(recVal(prem, "authority")), "identity_hash") {
				fail("claim %s: challenge %s does not wrap premise %s's reference artifact", receiptID, cid, premID)
			}
			chRun := str(ch, "run")
			mutCap := obj(loadEvidence(safeJoin(bundle, "captures/"+chRun+"/capture.json")))
			if str(mutCap, "court_semantic_identity") != str(obj(recVal(prem, "court")), "semantic_identity") {
				fail("claim %s: challenge %s did not run premise %s's question", receiptID, cid, premID)
			}
			onTarget, onUnaffected := false, false
			for _, ridV := range arr(recVal(mutCap, "residuals")) {
				rec := obj(loadEvidence(safeJoin(bundle, "residuals/"+ridV.(string)+".json")))
				if str(rec, "axis") == axis {
					onTarget = true
				} else {
					onUnaffected = true
				}
			}
			if !onTarget || onUnaffected {
				fail("claim %s: challenge %s does not demonstrate sensitivity on %s (recomputed: saw_defect=%v, specificity_clean=%v)", receiptID, cid, axis, onTarget, !onUnaffected)
			}
		}
		// The recorded demonstrated profile must rederive exactly.
		sort.Strings(rederived)
		dedup := []string{}
		for _, op := range rederived {
			if len(dedup) == 0 || dedup[len(dedup)-1] != op {
				dedup = append(dedup, op)
			}
		}
		recorded := asStrArray(recVal(cap, "mutation_profile"))
		if !slicesEqual(recorded, dedup) {
			fail("claim %s: capability entry for axis %s records mutation profile %v which does not rederive from its challenges (%v)", receiptID, axis, recorded, dedup)
		}
		covered[axis] = true
	}
	for _, axis := range claimed {
		if !covered[axis] {
			fail("claim %s: claimed axis %s has no capability coverage — the court never demonstrated it can see that surface", receiptID, axis)
		}
	}
	// The REQUIRED sensitivity mutation profile: every AXIS:FAMILY pair the
	// claim was compiled under must name a claimed axis whose demonstrated
	// profile includes that family.
	for _, entryV := range arr(recVal(claim, "mutation_profile")) {
		entry := entryV.(string)
		parts := strings.SplitN(entry, ":", 2)
		if len(parts) != 2 {
			fail("claim %s: required mutation profile entry %q is not AXIS:FAMILY", receiptID, entry)
		}
		axis, family := parts[0], parts[1]
		claimedAxis := false
		for _, a := range claimed {
			if a == axis {
				claimedAxis = true
				break
			}
		}
		if !claimedAxis {
			fail("claim %s: required mutation profile names axis %s, which the claim does not cover", receiptID, axis)
		}
		demonstrated := false
		for _, capV := range arr(recVal(claim, "capability")) {
			cap := obj(capV)
			if str(cap, "axis") != axis {
				continue
			}
			for _, f := range asStrArray(recVal(cap, "mutation_profile")) {
				if f == family {
					demonstrated = true
				}
			}
		}
		if !demonstrated {
			fail("claim %s: required mutation profile demands the %s family on axis %s, which no capability entry demonstrates", receiptID, family, axis)
		}
	}

	if policy == "independently-witnessed" || policy == "high-assurance" {
		witnesses := asStrArray(recVal(claim, "witness_statements"))
		if len(witnesses) == 0 {
			fail("claim %s: policy %s requires a witness attestation but names none", receiptID, policy)
		}
		// The stable map from each carried witness statement to the premise
		// receipt it attests — the per-premise independence check needs it.
		stmtSubject := make(map[string]string)
		// EVERY premise receipt must have at least one affirming attestation
		// of ITSELF (the compiler attests each premise before compiling).
		for _, premID := range requires {
			affirmedThis := false
			for _, wid := range witnesses {
				stmt := obj(loadEvidence(safeJoin(bundle, "witnesses/"+wid+".json")))
				subj := obj(recVal(stmt, "subject"))
				if str(subj, "kind") != "receipt" {
					continue
				}
				stmtSubject[wid] = str(subj, "id")
				if str(subj, "id") != premID {
					continue
				}
				// The statement's identity rederives from its own fields (the
				// witness IDENTITY — the stable WHO — included), and the
				// identity itself rederives from the semantic + implementation.
				id, err := witnessStatementIdentity(stmt)
				if err != nil || id != wid {
					fail("claim %s: witness %s is not content-addressed", receiptID, wid)
				}
				widID, err := witnessIdentity(obj(recVal(stmt, "witness_semantic")), obj(recVal(stmt, "witness_implementation")))
				if err != nil || widID != str(stmt, "witness_identity") {
					fail("claim %s: witness %s identity does not rederive", receiptID, wid)
				}
				for _, f := range []string{"request.json", "response.json"} {
					b := readFile(safeJoin(bundle, "witnesses/"+wid+"/"+f))
					cidField := "request_cid"
					if f == "response.json" {
						cidField = "response_cid"
					}
					if jcs.Sha256Hex(b) != str(stmt, cidField) {
						fail("claim %s: witness %s preserved %s does not hash to its cid", receiptID, wid, f)
					}
				}
				if str(obj(recVal(stmt, "attestation")), "outcome") == "affirm" {
					affirmedThis = true
				}
			}
			if !affirmedThis {
				fail("claim %s: no named witness affirms premise receipt %s", receiptID, premID)
			}
		}
		// The declared INDEPENDENCE evidence the claim carries: every record
		// verifies (identity rederives, the relation is closed, the spec hash
		// rederives) and binds one of the claim's own witness statements.
		for _, iidV := range arr(recVal(claim, "independence_evidence")) {
			iid := iidV.(string)
			rec := obj(loadEvidence(safeJoin(bundle, "independence/"+iid+".json")))
			recID, err := independenceIdentity(rec)
			if err != nil || recID != iid {
				fail("claim %s: independence record %s is not content-addressed", receiptID, iid)
			}
			relation := str(rec, "relation")
			switch relation {
			case "different-implementation", "separate-party", "unaffiliated-channel", "adversarial-review":
			default:
				fail("claim %s: independence record %s names unknown relation %s", receiptID, iid, relation)
			}
			spec, err := independenceSpecHash(relation, str(rec, "relation_version"))
			if err != nil || spec != str(rec, "specification_hash") {
				fail("claim %s: independence record %s spec hash does not rederive", receiptID, iid)
			}
			stmtID := str(rec, "witness_statement")
			inClaim := false
			for _, w := range witnesses {
				if w == stmtID {
					inClaim = true
					break
				}
			}
			if !inClaim {
				fail("claim %s: independence record %s binds a witness statement the claim does not carry", receiptID, iid)
			}
		}
		// The tier is NAMED independently-witnessed: EVERY premise must be
		// covered by at least one admissible independence relation bound to an
		// attestation of THAT premise — an affirming witness with zero
		// declared independence is witnessed, not independently witnessed.
		independence := asStrArray(recVal(claim, "independence_evidence"))
		for _, premID := range requires {
			covered := false
			for _, iid := range independence {
				rec := obj(loadEvidence(safeJoin(bundle, "independence/"+iid+".json")))
				if stmtSubject[str(rec, "witness_statement")] == premID {
					covered = true
					break
				}
			}
			if !covered {
				fail("claim %s: premise receipt %s has no admissible independence relation — an attestation alone is witnessed, not independently witnessed", receiptID, premID)
			}
		}
	}

	if policy == "high-assurance" {
		// EVERY premise was observed under the reference execution contract.
		for _, premID := range requires {
			prem := premise(premID)
			if str(prem, "execution_profile") != "frf-exec-linux-v1" {
				fail("claim %s: high-assurance requires the reference execution profile for premise %s", receiptID, premID)
			}
			bounds := obj(recVal(prem, "capture_bounds"))
			if str(bounds, "timeout_ms") != "60000" ||
				str(bounds, "max_stream_bytes") != "16777216" ||
				str(bounds, "rlimit_as_mb") != "2048" ||
				str(bounds, "rlimit_cpu_s") != "30" ||
				str(bounds, "rlimit_nofile") != "1024" ||
				str(bounds, "rlimit_nproc") != "4096" {
				fail("claim %s: high-assurance requires the reference capture bounds (the exact-replay contract) for premise %s", receiptID, premID)
			}
		}
		if str(claim, "replay_profile") != "frf-exec-linux-v1" {
			fail("claim %s: the claim's replay_profile does not record the reference profile", receiptID)
		}
	}
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
	// The kind protocol records (FRF/KIND/v1): each registered kind is pinned
	// byte-for-byte, and its derived identity rederives from the record's own
	// semantic fields (an independent re-implementation of the identity).
	for _, name := range sortedNames(dir + "/kinds") {
		path := dir + "/kinds/" + name
		v := loadEvidenceNoCanonical(path)
		canonical, err := jcs.Canonical(v)
		if err != nil {
			fail("kinds/%s: cannot canonicalize: %v", name, err)
		}
		expected := string(readFile(dir + "/canonical/kinds/" + name))
		if canonical != expected {
			fail("kinds/%s: canonical bytes drifted", name)
		}
		digest := jcs.Sha256Hex([]byte(canonical))
		stem := strings.TrimSuffix(name, ".json")
		pinned := strings.TrimSpace(string(readFile(dir + "/hashes/" + stem + ".kind.sha256")))
		if digest != pinned {
			fail("kinds/%s: digest drifted", name)
		}
		ko := obj(v)
		id, meaning := str(ko, "id"), str(ko, "meaning")
		grammar, family := str(ko, "surface_grammar"), str(ko, "comparator_family")
		if ident, err := kindIdentity(id, meaning, grammar, family); err != nil || ident != str(ko, "identity") {
			fail("kinds/%s: the identity does not rederive from its own fields", name)
		}
		count++
	}
	return count
}
