// Package main — the independent FRF verifier in Go.
//
// This package is the second half of the conformance triangle: the Rust
// reference engine produces evidence, the Rust xtask verifies it, and this Go
// verifier verifies it AGAIN from the bundle alone, with its own strict JSON
// parser and its own RFC 8785 encoder — no code, schema, or parsing library
// shared with either Rust implementation. It consumes only:
//
//	conformance/  — the pinned structural + semantic corpus
//	<dir>/        — an exported OpenReceipt bundle (or its single-file tar)
//	spec/         — the protocol documents (read by humans, not by code)
//
// If all three implementations agree on the same bytes, CIDs, identities,
// and admissible claim set for the same evidence, FRF is a protocol, not a
// Rust file format.

package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"frf-verifier-go/jcs"
)

// hashPreimage: SHA-256 of "KIND\n" + canonical(doc) — the domain-separated
// identity rule shared by every FRF identity.
func hashPreimage(kind string, doc jcs.Value) (string, error) {
	json, err := jcs.Canonical(doc)
	if err != nil {
		return "", err
	}
	return jcs.Sha256Hex(append([]byte(kind+"\n"), []byte(json)...)), nil
}

// runtimeClosureIdentity: FRF/RUNTIME-CLOSURE/v1 over the closure's fields
// minus the cid, with the components sorted by path — the closure is a
// deterministic function of the resolved SET.
func runtimeClosureIdentity(closure *jcs.Object) string {
	var comps []jcs.Value
	for _, c := range arr(recVal(closure, "components")) {
		comps = append(comps, c)
	}
	sort.Slice(comps, func(i, j int) bool {
		return str(obj(comps[i]), "path") < str(obj(comps[j]), "path")
	})
	var sorted []jcs.Value
	for _, c := range comps {
		sorted = append(sorted, &jcs.Object{
			Keys:   []string{"path", "sha256"},
			Values: []jcs.Value{str(obj(c), "path"), str(obj(c), "sha256")},
		})
	}
	doc := &jcs.Object{
		Keys: []string{"schema_version", "interp", "components"},
		Values: []jcs.Value{
			str(closure, "schema_version"),
			&jcs.Object{
				Keys:   []string{"path", "sha256"},
				Values: []jcs.Value{str(objKeys(closure, "interp"), "path"), str(objKeys(closure, "interp"), "sha256")},
			},
			sorted,
		},
	}
	return mustPreimage("FRF/RUNTIME-CLOSURE/v1", doc)
}

// executionContextIdentity: FRF/EXECUTION-CONTEXT/v1 over the closure's
// fields minus the cid, with the artifacts sorted by path — the closure is a
// deterministic function of the declared SET (two observations that snapshot
// the same declared paths to the same bytes share one identity).
func executionContextIdentity(closure *jcs.Object) (string, error) {
	var arts []jcs.Value
	for _, a := range arr(recVal(closure, "artifacts")) {
		arts = append(arts, a)
	}
	sort.Slice(arts, func(i, j int) bool {
		return str(obj(arts[i]), "path") < str(obj(arts[j]), "path")
	})
	var sorted []jcs.Value
	for _, a := range arts {
		sorted = append(sorted, &jcs.Object{
			Keys:   []string{"path", "role", "sha256"},
			Values: []jcs.Value{str(obj(a), "path"), str(obj(a), "role"), str(obj(a), "sha256")},
		})
	}
	doc := &jcs.Object{
		Keys:   []string{"schema_version", "artifacts"},
		Values: []jcs.Value{str(closure, "schema_version"), sorted},
	}
	return hashPreimage("FRF/EXECUTION-CONTEXT/v1", doc)
}

// mustPreimage: hashPreimage that cannot fail (the document is already
// constructed from strings/arrays).
func mustPreimage(kind string, doc jcs.Value) string {
	h, err := hashPreimage(kind, doc)
	if err != nil {
		panic("cannot canonicalize " + kind + ": " + err.Error())
	}
	return h
}

// recordContentIdentity: SHA-256 of the canonical serialization of a record's
// own fields — what the knowledge universe commits for a record whose id is a
// label.
func recordContentIdentity(record jcs.Value) (string, error) {
	json, err := jcs.Canonical(record)
	if err != nil {
		return "", err
	}
	return jcs.Sha256Hex([]byte(json)), nil
}

// claimIdentity — the content address of a compiled claim: FRF/CLAIM/v1
// over the canonical document minus the id field (the same formula as the
// reference engine, over the Go verifier's own strict parser + JCS
// encoder). The claim is an immutable protocol object — the same receipt
// under a different universe or policy is a different claim id.
func claimIdentity(claim jcs.Value) (string, error) {
	clone := *obj(claim)
	var kept []string
	var keptValues []jcs.Value
	for i, k := range clone.Keys {
		if k != "id" {
			kept = append(kept, k)
			keptValues = append(keptValues, clone.Values[i])
		}
	}
	doc := &jcs.Object{Keys: kept, Values: keptValues}
	json, err := jcs.Canonical(doc)
	if err != nil {
		return "", err
	}
	return jcs.Sha256Hex([]byte("FRF/CLAIM/v1\n" + json)), nil
}

// trajectoryIdentity — the content address of a trajectory record:
// FRF/TRAJECTORY/v1 over the canonical document minus the id field (the
// same formula as the reference engine). The trajectory is a DERIVED
// protocol object — the transform declaration included — so it can never
// be relabeled as a different kind of evidence without changing its
// identity.
func trajectoryIdentity(t jcs.Value) string {
	clone := *obj(t)
	var kept []string
	var keptValues []jcs.Value
	for i, k := range clone.Keys {
		if k != "id" {
			kept = append(kept, k)
			keptValues = append(keptValues, clone.Values[i])
		}
	}
	doc := &jcs.Object{Keys: kept, Values: keptValues}
	json, err := jcs.Canonical(doc)
	if err != nil {
		return ""
	}
	return jcs.Sha256Hex([]byte("FRF/TRAJECTORY/v1\n" + json))
}

// witnessIdentity: FRF/WITNESS-IDENTITY/v1 over {specification_hash,
// implementation_hash, interpreter} — the stable WHO behind an attestation.
func witnessIdentity(semantic, implementation *jcs.Object) (string, error) {
	artifact := obj(recVal(implementation, "artifact"))
	var interpreter jcs.Value
	if artifact != nil {
		if iv, ok := recVal(artifact, "interpreter").(*jcs.Object); ok {
			interpreter = iv
		}
	}
	doc := &jcs.Object{
		Keys:   []string{"specification_hash", "implementation_hash", "interpreter"},
		Values: []jcs.Value{str(semantic, "specification_hash"), str(implementation, "implementation_hash"), interpreter},
	}
	return hashPreimage("FRF/WITNESS-IDENTITY/v1", doc)
}

// witnessStatementIdentity: FRF/WITNESS-STATEMENT/v1 over the statement's own
// fields (v3: the witness identity and the declared authority enter the
// preimage).
func witnessStatementIdentity(stmt *jcs.Object) (string, error) {
	doc := &jcs.Object{
		Keys:   []string{"subject", "witness_semantic", "witness_implementation", "witness_identity", "authority", "statement", "attestation", "request_cid", "response_cid"},
		Values: []jcs.Value{recVal(stmt, "subject"), recVal(stmt, "witness_semantic"), recVal(stmt, "witness_implementation"), str(stmt, "witness_identity"), recVal(stmt, "authority"), str(stmt, "statement"), recVal(stmt, "attestation"), str(stmt, "request_cid"), str(stmt, "response_cid")},
	}
	return hashPreimage("FRF/WITNESS-STATEMENT/v1", doc)
}

// independenceSpecHash: FRF/INDEPENDENCE-SPEC/v1 over {relation,
// relation_version} — the semantic identity of a declared independence
// relation.
func independenceSpecHash(relation, relationVersion string) (string, error) {
	doc := &jcs.Object{
		Keys:   []string{"relation", "relation_version"},
		Values: []jcs.Value{relation, relationVersion},
	}
	return hashPreimage("FRF/INDEPENDENCE-SPEC/v1", doc)
}

// independenceIdentity: FRF/INDEPENDENCE/v1 over the record's own fields —
// the content address of a declared independence claim.
func independenceIdentity(record *jcs.Object) (string, error) {
	doc := &jcs.Object{
		Keys:   []string{"subject", "witness_statement", "witness_identity", "relation", "relation_version", "specification_hash", "basis", "detail", "evidence_refs"},
		Values: []jcs.Value{recVal(record, "subject"), str(record, "witness_statement"), str(record, "witness_identity"), str(record, "relation"), str(record, "relation_version"), str(record, "specification_hash"), str(record, "basis"), recVal(record, "detail"), recVal(record, "evidence_refs")},
	}
	return hashPreimage("FRF/INDEPENDENCE/v1", doc)
}

// fixtureIdentity: FRF/FIXTURE/v1 over the canonical document of the
// fixture's semantic id, content SHA-256, and declared arguments — claim
// scopes and residual surfaces carry this identity in their `fixtures`
// dimension, so two different files that share a fixture id are different
// exact inputs.
func fixtureIdentity(semanticID, contentSHA256 string, declaredArguments jcs.Value) string {
	doc := &jcs.Object{
		Keys:   []string{"semantic_id", "content_sha256", "declared_arguments"},
		Values: []jcs.Value{semanticID, contentSHA256, declaredArguments},
	}
	return mustPreimage("FRF/FIXTURE/v1", doc)
}

// envDigest: FRF/ENVIRONMENT/v2 over the canonical-JSON document of the host
// strata (os/arch/kernel/locale/timezone/umask) AND the declared execution
// environment map — a declared variable is content-addressed input. The one
// formula, shared with the reference engine and the Rust verifier.
func envDigest(os, arch, kernel, locale, timezone, umask string, environment jcs.Value) string {
	doc := &jcs.Object{
		Keys:   []string{"os", "architecture", "kernel_release", "locale", "timezone", "umask", "environment"},
		Values: []jcs.Value{os, arch, kernel, locale, timezone, umask, environment},
	}
	return mustPreimage("FRF/ENVIRONMENT/v2", doc)
}

// harnessEventIdentity: FRF/HARNESS-EVENT/v1 over the event's own fields
// (the id is never in the preimage). Mirrors the reference engine's
// semantics::harness_event_identity and the Rust verifier's rederive.
func harnessEventIdentity(event *jcs.Object) string {
	doc := &jcs.Object{
		Keys:   []string{"event_kind", "side", "court", "execution_profile", "cap", "observed", "target", "detail", "runner"},
		Values: []jcs.Value{str(event, "event_kind"), str(event, "side"), str(event, "court"), str(event, "execution_profile"), str(event, "cap"), str(event, "observed"), str(event, "target"), str(event, "detail"), str(event, "runner")},
	}
	return mustPreimage("FRF/HARNESS-EVENT/v1", doc)
}

// executionAttemptIdentity: FRF/EXECUTION-ATTEMPT/v1 over the record's own
// fields minus the id, with the cited harness events sorted (the identity is
// a deterministic function of the cited SET). Mirrors the reference engine's
// semantics::execution_attempt_identity and the Rust verifier's rederive.
func executionAttemptIdentity(attempt *jcs.Object) string {
	var events []string
	for _, e := range arr(recVal(attempt, "harness_events")) {
		events = append(events, e.(string))
	}
	sort.Strings(events)
	var sorted []jcs.Value
	for _, e := range events {
		sorted = append(sorted, e)
	}
	doc := &jcs.Object{
		Keys:   []string{"court", "court_semantic_identity", "authority_sha256", "candidate_sha256", "fixture_sha256", "arguments", "environment_digest", "execution_profile", "capture_bounds", "side", "harness_events", "refusal_reason"},
		Values: []jcs.Value{str(attempt, "court"), str(attempt, "court_semantic_identity"), str(attempt, "authority_sha256"), str(attempt, "candidate_sha256"), str(attempt, "fixture_sha256"), recVal(attempt, "arguments"), str(attempt, "environment_digest"), str(attempt, "execution_profile"), recVal(attempt, "capture_bounds"), str(attempt, "side"), sorted, recVal(attempt, "refusal_reason")},
	}
	return mustPreimage("FRF/EXECUTION-ATTEMPT/v1", doc)
}

// trajectoryClassify — the deterministic ordered-axis classification
// (mirrors the reference engine's trajectory::classify, frf-trajectory-v4):
// drift/slew/localization/bands/trend. The stratified axes (authority_version,
// candidate_revision) yield `version-stratified` for 2+ bands; a single
// contiguous band touching one bound is `boundary-localized`; a monotonic
// magnitude trend licenses `gradual`.
func trajectoryClassify(observed []bool, coordinateSystem string, magnitudes []*string, magnitudeKind string) (string, string, string, string, string) {
	n := len(observed)
	var t []int
	for i, o := range observed {
		if o {
			t = append(t, i)
		}
	}
	if len(t) == 0 {
		panic("no observations in the series")
	}
	first := t[0]
	last := t[len(t)-1]
	bands := 1
	for i := 1; i < len(t); i++ {
		if t[i] != t[i-1]+1 {
			bands++
		}
	}
	contiguous := last-first+1 == len(t)
	stratified := coordinateSystem == "authority_version" || coordinateSystem == "candidate_revision"
	var drift, slew, localization string
	switch {
	case len(t) == n:
		drift, slew, localization = "persistent", "stable", "none"
	case contiguous && first == 0:
		drift, slew, localization = "boundary-localized", "abrupt", "start"
	case contiguous && last == n-1:
		drift, slew, localization = "boundary-localized", "abrupt", "end"
	case contiguous:
		drift, slew, localization = "transient", "burst", "interior"
	case bands >= 2 && stratified:
		drift = "version-stratified"
		slew = "recurrent"
		switch {
		case first == 0 && last == n-1:
			localization = "both"
		case first == 0:
			localization = "start"
		case last == n-1:
			localization = "end"
		default:
			localization = "interior"
		}
	case first == 0 && last == n-1:
		drift, slew, localization = "recurrent", "recurrent", "both"
	default:
		drift, slew = "transient", "recurrent"
		switch {
		case first == 0:
			localization = "start"
		case last == n-1:
			localization = "end"
		default:
			localization = "interior"
		}
	}
	trend := trajectoryTrend(observed, magnitudes, magnitudeKind)
	if trend == "increasing" || trend == "decreasing" {
		slew = "gradual"
	}
	return drift, slew, localization, itoa(bands), trend
}

// trajectoryTrend — the magnitude trend over the observed points (mirrors
// the reference engine): `unknown` when no measure is declared or fewer than
// three observed magnitudes; else flat/increasing/decreasing/non-monotonic.
// Only OBSERVED points carry a magnitude.
func trajectoryTrend(observed []bool, magnitudes []*string, magnitudeKind string) string {
	if magnitudeKind == "none" {
		return "unknown"
	}
	var values []int64
	for i, m := range magnitudes {
		if m == nil || !observed[i] {
			continue
		}
		if v, err := strconv.ParseInt(*m, 10, 64); err == nil {
			values = append(values, v)
		}
	}
	if len(values) < 3 {
		return "unknown"
	}
	increasing, decreasing := false, false
	for i := 1; i < len(values); i++ {
		if values[i] > values[i-1] {
			increasing = true
		} else if values[i] < values[i-1] {
			decreasing = true
		}
	}
	switch {
	case !increasing && !decreasing:
		return "flat"
	case increasing && !decreasing:
		return "increasing"
	case !increasing && decreasing:
		return "decreasing"
	default:
		return "non-monotonic"
	}
}

// divergenceMagnitude — the deterministic divergence degree between a
// residual observation's compared projections on `axis` (mirrors the
// reference engine's comparators::divergence_magnitude, bound included): a
// decimal string, or nil when the axis declares no measure.
func divergenceMagnitude(axis, rawReference, rawCandidate string) *string {
	const magnitudeBound = 2048
	switch axis {
	case "exit":
		a, errA := strconv.ParseInt(strings.TrimSpace(rawReference), 10, 64)
		b, errB := strconv.ParseInt(strings.TrimSpace(rawCandidate), 10, 64)
		if errA != nil || errB != nil {
			return nil
		}
		d := a - b
		if d < 0 {
			d = -d
		}
		s := itoa(int(d))
		return &s
	case "stderr", "stdout", "structured.state":
		d := editDistance(truncate(rawReference, magnitudeBound), truncate(rawCandidate, magnitudeBound))
		s := itoa(d)
		return &s
	default:
		return nil
	}
}

func magnitudeKind(axis string) string {
	switch axis {
	case "exit":
		return "exit-code-distance"
	case "stderr", "stdout":
		return "line-edit-distance"
	case "structured.state":
		return "value-edit-distance"
	default:
		return "none"
	}
}

func truncate(s string, bound int) string {
	if len(s) <= bound {
		return s
	}
	return s[:bound]
}

// editDistance — the Levenshtein (byte edit) distance, the declared
// line/value distance measure of the text-family comparators.
func editDistance(a, b string) int {
	if a == b {
		return 0
	}
	prev := make([]int, len(b)+1)
	curr := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		curr[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 0
			if a[i-1] != b[j-1] {
				cost = 1
			}
			m := prev[j] + 1
			if curr[j-1]+1 < m {
				m = curr[j-1] + 1
			}
			if prev[j-1]+cost < m {
				m = prev[j-1] + cost
			}
			curr[j] = m
		}
		prev, curr = curr, prev
	}
	return prev[len(b)]
}

// itoa — the canonical value domain has no numbers; every integer in an
// evidence document is a decimal string.
func itoa(v int) string { return strconv.Itoa(v) }

// object helpers over the jcs.Value tree.
func str(v jcs.Value, key string) string {
	if o, ok := v.(*jcs.Object); ok {
		return o.Str(key)
	}
	return ""
}

func obj(v jcs.Value) *jcs.Object {
	o, _ := v.(*jcs.Object)
	return o
}

func arr(v jcs.Value) []jcs.Value {
	a, _ := v.([]jcs.Value)
	return a
}

// arrP — arr() as objects (for identities that take []*jcs.Object).
func arrP(v jcs.Value) []*jcs.Object {
	var out []*jcs.Object
	for _, item := range arr(v) {
		if o, ok := item.(*jcs.Object); ok {
			out = append(out, o)
		}
	}
	return out
}

func asStrArray(v jcs.Value) []string {
	var out []string
	for _, item := range arr(v) {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// slicesEqual: two ordered string slices are identical.
func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// comparatorSpecHash: FRF/COMPARATOR-SPEC/v2 over {id, relation, extractor,
// residual_classifier, relation_version}.
func comparatorSpecHash(id, relation, extractor, classifier, version string) (string, error) {
	return hashPreimage("FRF/COMPARATOR-SPEC/v2", &jcs.Object{
		Keys:   []string{"id", "relation", "extractor", "residual_classifier", "relation_version"},
		Values: []jcs.Value{id, relation, extractor, classifier, version},
	})
}

func normalizerSpecHash(id, relation, appliesTo, version string) (string, error) {
	return hashPreimage("FRF/NORMALIZER-SPEC/v2", &jcs.Object{
		Keys:   []string{"id", "relation", "applies_to", "relation_version"},
		Values: []jcs.Value{id, relation, appliesTo, version},
	})
}

func captureAdapterSpecHash(id, relation, version string) (string, error) {
	return hashPreimage("FRF/CAPTURE-ADAPTER-SPEC/v2", &jcs.Object{
		Keys:   []string{"id", "relation", "relation_version"},
		Values: []jcs.Value{id, relation, version},
	})
}

// courtSemanticIdentityFromReceipt: FRF/COURT/v2 — the full
// observation-defining semantics: question, falsifier, authority artifact,
// fixture, envelope, comparator semantics, normalizer semantics in
// application order, and capture-adapter semantics sorted by axis.
func courtSemanticIdentityFromReceipt(rec *jcs.Object) (string, error) {
	court := obj(recVal(rec, "court"))
	env := obj(recVal(court, "admissibility_envelope"))
	fixture := obj(arr(recVal(rec, "fixtures"))[0])

	var comparators []jcs.Value
	for _, c := range arr(recVal(rec, "comparator_semantics")) {
		co := obj(c)
		comparators = append(comparators, &jcs.Object{
			Keys:   []string{"id", "relation_id", "relation_version", "specification_hash"},
			Values: []jcs.Value{str(co, "id"), str(co, "relation_id"), str(co, "relation_version"), str(co, "specification_hash")},
		})
	}
	var normalizers []jcs.Value
	for _, n := range arr(recVal(rec, "normalizer_semantics")) {
		no := obj(n)
		normalizers = append(normalizers, &jcs.Object{
			Keys:   []string{"id", "relation_id", "applies_to", "relation_version", "specification_hash"},
			Values: []jcs.Value{str(no, "id"), str(no, "relation_id"), str(no, "applies_to"), str(no, "relation_version"), str(no, "specification_hash")},
		})
	}
	adapters := append([]jcs.Value(nil), arr(recVal(rec, "adapter_semantics"))...)
	sortObjectsByID(adapters)
	var captureAdapters []jcs.Value
	for _, a := range adapters {
		ao := obj(a)
		captureAdapters = append(captureAdapters, &jcs.Object{
			Keys:   []string{"id", "relation_id", "relation_version", "specification_hash"},
			Values: []jcs.Value{str(ao, "id"), str(ao, "relation_id"), str(ao, "relation_version"), str(ao, "specification_hash")},
		})
	}

	doc := &jcs.Object{
		Keys: []string{"question", "falsifier", "authority_artifact_identity", "fixture", "envelope", "comparators", "normalizers", "capture_adapters"},
		Values: []jcs.Value{
			str(court, "question"),
			str(court, "falsifier"),
			str(obj(recVal(rec, "authority")), "identity_hash"),
			&jcs.Object{
				Keys:   []string{"id", "sha256", "arguments"},
				Values: []jcs.Value{str(fixture, "id"), str(fixture, "hash"), recVal(fixture, "declared_arguments")},
			},
			&jcs.Object{
				Keys:   []string{"fixture_family", "platforms", "observables", "normalizers", "replay_scope"},
				Values: []jcs.Value{str(env, "fixture_family"), recVal(env, "platforms"), recVal(env, "observables"), recVal(env, "normalizers"), str(env, "replay_scope")},
			},
			comparators,
			normalizers,
			captureAdapters,
		},
	}
	return hashPreimage("FRF/COURT/v2", doc)
}

func recVal(o *jcs.Object, key string) jcs.Value {
	if v, ok := o.Get(key); ok {
		return v
	}
	return nil
}

func sortObjectsByID(vs []jcs.Value) {
	for i := 1; i < len(vs); i++ {
		for j := i; j > 0; j-- {
			if str(obj(vs[j-1]), "id") > str(obj(vs[j]), "id") {
				vs[j-1], vs[j] = vs[j], vs[j-1]
			} else {
				break
			}
		}
	}
}

// residualFingerprint: FRF/RESIDUAL-FINGERPRINT/v1 over the hashed
// projections of the immutable observation record.
func residualFingerprint(record *jcs.Object) (string, error) {
	doc := &jcs.Object{
		Keys:   []string{"kind", "axis", "surface", "reference_sha256", "candidate_sha256"},
		Values: []jcs.Value{str(record, "kind"), str(record, "axis"), recVal(record, "surface"), jcs.Sha256Hex([]byte(str(record, "raw_reference"))), jcs.Sha256Hex([]byte(str(record, "raw_candidate")))},
	}
	return hashPreimage("FRF/RESIDUAL-FINGERPRINT/v1", doc)
}

// residualLineage: FRF/RESIDUAL-LINEAGE/v1 — the stable comparison question
// (kind, axis, surface, fixture family, authority NAME, fixture), excluding
// the exact observed bytes so the lineage spans revisions and environments.
func residualLineage(kind, axis string, surface *string, fixtureFamily, authorityName, fixture string) (string, error) {
	var surfaceVal jcs.Value
	if surface == nil {
		surfaceVal = nil
	} else {
		surfaceVal = *surface
	}
	doc := &jcs.Object{
		Keys:   []string{"kind", "axis", "surface", "fixture_family", "authority_name", "fixture"},
		Values: []jcs.Value{kind, axis, surfaceVal, fixtureFamily, authorityName, fixture},
	}
	return hashPreimage("FRF/RESIDUAL-LINEAGE/v1", doc)
}

// kindIdentity: FRF/KIND/v1 — the residual-kind protocol record (id, meaning,
// surface_grammar, comparator_family). The identity rederives from the record's
// own fields in every implementation; the records are pinned in the
// conformance corpus (conformance/kinds/).
func kindIdentity(id, meaning, surfaceGrammar, comparatorFamily string) (string, error) {
	doc := &jcs.Object{
		Keys:   []string{"id", "meaning", "surface_grammar", "comparator_family"},
		Values: []jcs.Value{id, meaning, surfaceGrammar, comparatorFamily},
	}
	return hashPreimage("FRF/KIND/v1", doc)
}

// sideProjection: the observed surface of one side — exit class, stream
// hashes + first lines, produced artifact tree, adapted payload (never raw
// bytes) — shared by the observation and run identities.
func sideProjection(s *jcs.Object) *jcs.Object {
	var produced jcs.Value
	if p, ok := s.Get("produced"); ok && p != nil {
		pv := p.(*jcs.Object)
		var files []jcs.Value
		for _, f := range arr(recVal(pv, "files")) {
			fo := obj(f)
			files = append(files, &jcs.Object{
				Keys:   []string{"path", "sha256", "executable"},
				Values: []jcs.Value{str(fo, "path"), str(fo, "sha256"), recVal(fo, "executable")},
			})
		}
		produced = &jcs.Object{
			Keys:   []string{"schema_version", "manifest_sha256", "files"},
			Values: []jcs.Value{str(pv, "schema_version"), str(pv, "manifest_sha256"), files},
		}
	}
	var adapted jcs.Value
	if a, ok := s.Get("adapted"); ok && a != nil {
		av := a.(*jcs.Object)
		adapted = &jcs.Object{
			Keys:   []string{"format", "payload_base64", "content_sha256"},
			Values: []jcs.Value{str(av, "format"), str(av, "payload_base64"), str(av, "content_sha256")},
		}
	}
	return &jcs.Object{
		Keys:   []string{"exit", "stdout_sha256", "stderr_sha256", "stdout_first_line", "stderr_first_line", "produced", "adapted"},
		Values: []jcs.Value{str(s, "exit"), str(s, "stdout_sha256"), str(s, "stderr_sha256"), str(s, "stdout_first_line"), str(s, "stderr_first_line"), produced, adapted},
	}
}

// interpreterHash: the downstream interpreter's sha256 of one side's
// artifact, or nil (JSON null) when the artifact declares no interpreter.
func interpreterHash(s *jcs.Object) jcs.Value {
	if v, ok := s.Get("interpreter"); ok && v != nil {
		io := v.(*jcs.Object)
		down := obj(recVal(io, "downstream_interpreter"))
		if h, ok := down.Get("sha256"); ok {
			return h
		}
	}
	return nil
}

// residualProjection: the residual projection shared by the observation and
// run identities — the recorded disagreement (kind + raw projections).
func residualProjection(r *jcs.Object) *jcs.Object {
	return &jcs.Object{
		Keys:   []string{"kind", "raw_reference", "raw_candidate"},
		Values: []jcs.Value{str(r, "kind"), str(r, "raw_reference"), str(r, "raw_candidate")},
	}
}

// implementationProjection: the exact program that served one axis/route,
// bound by its implementation hash.
func implementationProjection(d *jcs.Object) *jcs.Object {
	return &jcs.Object{
		Keys:   []string{"id", "implementation_hash"},
		Values: []jcs.Value{str(d, "id"), str(d, "implementation_hash")},
	}
}

// observationIdentity: FRF/OBSERVATION/v1 over the capture's recorded fields
// — what was observed: the question, the inputs, the effective environment,
// and the answer. Two observations with the same question, inputs,
// environment, and outputs share this identity regardless of which harness
// observed them.
func observationIdentity(cap *jcs.Object, residuals []*jcs.Object) (string, error) {
	var res []jcs.Value
	for _, r := range residuals {
		res = append(res, residualProjection(r))
	}
	keys := []string{"court", "court_semantic_identity", "authority", "candidate_sha256", "fixture_sha256", "arguments", "environment_digest", "reference", "candidate", "residuals"}
	values := []jcs.Value{
		str(cap, "court"),
		str(cap, "court_semantic_identity"),
		str(cap, "authority"),
		str(obj(recVal(cap, "candidate_artifact")), "sha256"),
		str(cap, "fixture_sha256"),
		recVal(cap, "arguments"),
		str(obj(recVal(cap, "environment")), "digest"),
		sideProjection(obj(recVal(cap, "reference"))),
		sideProjection(obj(recVal(cap, "candidate"))),
		res,
	}
	// The capture surface is part of the observation contract; entered only
	// when the capture declares one (absent == the pre-surface shape).
	if v, ok := cap.Get("publication_surface"); ok && v != nil {
		if a, ok := v.([]jcs.Value); ok && len(a) > 0 {
			keys = append(keys, "publication_surface")
			values = append(values, v)
		}
	}
	doc := &jcs.Object{Keys: keys, Values: values}
	return hashPreimage("FRF/OBSERVATION/v1", doc)
}

// executionIdentity: FRF/EXECUTION/v1 over the capture's recorded fields —
// under exactly what machinery and contract the observation was made: the
// execution profile, the effective capture bounds (including FRF_EXEC_*
// overrides), the runner executable, the side interpreter chains, and every
// comparator/normalizer/adapter/minimizer implementation.
func executionIdentity(cap *jcs.Object) (string, error) {
	bounds := obj(recVal(cap, "capture_bounds"))
	prov := obj(recVal(cap, "provenance"))
	runner := obj(recVal(prov, "runner"))
	impls := func(key string) []jcs.Value {
		var out []jcs.Value
		for _, v := range arr(recVal(prov, key)) {
			out = append(out, implementationProjection(obj(v)))
		}
		return out
	}
	cb := &jcs.Object{
		Keys:   []string{"timeout_ms", "max_stream_bytes", "produced_max_files", "produced_max_bytes", "produced_max_file_bytes", "rlimit_as_mb", "rlimit_cpu_s", "rlimit_nofile", "rlimit_nproc", "cgroup_pids_max", "cgroup_memory_max", "cgroup_cpu_max"},
		Values: []jcs.Value{str(bounds, "timeout_ms"), str(bounds, "max_stream_bytes"), str(bounds, "produced_max_files"), str(bounds, "produced_max_bytes"), str(bounds, "produced_max_file_bytes"), str(bounds, "rlimit_as_mb"), str(bounds, "rlimit_cpu_s"), str(bounds, "rlimit_nofile"), str(bounds, "rlimit_nproc"), recVal(bounds, "cgroup_pids_max"), recVal(bounds, "cgroup_memory_max"), recVal(bounds, "cgroup_cpu_max")},
	}
	doc := &jcs.Object{
		Keys: []string{"execution_profile", "capture_bounds", "runner_hash", "authority_interpreter", "candidate_interpreter", "comparator_implementations", "normalizer_implementations", "adapter_implementations", "minimizer_implementations", "container_image"},
		Values: []jcs.Value{
			str(cap, "execution_profile"),
			cb,
			str(runner, "frf_executable_hash"),
			interpreterHash(obj(recVal(cap, "authority_artifact"))),
			interpreterHash(obj(recVal(cap, "candidate_artifact"))),
			impls("comparator_implementations"),
			impls("normalizer_implementations"),
			impls("adapter_implementations"),
			impls("minimizer_implementations"),
			// 0.1.62: the OCI image the observation ran inside (null when the
			// court did not declare frf-exec-oci) — the complete root
			// filesystem is execution machinery, bound by digest.
			recVal(cap, "container_image"),
		},
	}
	return hashPreimage("FRF/EXECUTION/v1", doc)
}

// runIdentity: FRF/RUN/v2 over the capture's recorded fields — the
// composition of the observation identity and the execution identity; the
// name is a claim until recomputed.
func runIdentity(cap *jcs.Object, residuals []*jcs.Object) (string, error) {
	obs, err := observationIdentity(cap, residuals)
	if err != nil {
		return "", err
	}
	exec, err := executionIdentity(cap)
	if err != nil {
		return "", err
	}
	doc := &jcs.Object{
		Keys:   []string{"observation_identity", "execution_identity"},
		Values: []jcs.Value{obs, exec},
	}
	return hashPreimage("FRF/RUN/v2", doc)
}

// dispositionEventIdentity: FRF/DISPOSITION-EVENT/v1 over the event content.
// The parent event id is a jcs.Value (nil encodes as null, a string as the
// string) — a typed nil *string would not match the canonicalizer's `nil`
// case.
func dispositionEventIdentity(residualID string, parentEventID jcs.Value, disposition *jcs.Object, evidenceRefs []jcs.Value) (string, error) {
	doc := &jcs.Object{
		Keys:   []string{"residual_id", "parent_event_id", "disposition", "evidence_refs"},
		Values: []jcs.Value{residualID, parentEventID, disposition, evidenceRefs},
	}
	return hashPreimage("FRF/DISPOSITION-EVENT/v1", doc)
}

func dispositionDoc(event *jcs.Object) *jcs.Object {
	kind := str(event, "disposition")
	switch kind {
	case "open":
		return &jcs.Object{Keys: []string{"kind"}, Values: []jcs.Value{"open"}}
	case "fixed":
		return &jcs.Object{
			Keys:   []string{"kind", "reason", "resolution_run_id", "closure_predicate"},
			Values: []jcs.Value{"fixed", str(event, "reason"), str(event, "resolution_run_id"), str(event, "closure_predicate")},
		}
	case "nonreproduced":
		return &jcs.Object{
			Keys:   []string{"kind", "reason", "observation_run_id"},
			Values: []jcs.Value{"nonreproduced", str(event, "reason"), str(event, "observation_run_id")},
		}
	case "stabilized":
		return &jcs.Object{
			Keys:   []string{"kind", "reason", "trajectory_id", "consecutive_passes", "stabilization_bound"},
			Values: []jcs.Value{"stabilized", str(event, "reason"), str(event, "trajectory_id"), str(event, "consecutive_passes"), str(event, "stabilization_bound")},
		}
	default:
		return &jcs.Object{
			Keys:   []string{"kind", "reason"},
			Values: []jcs.Value{kind, str(event, "reason")},
		}
	}
}

// seriesIdentity: FRF/SERIES/v3 over the snapshot's own fields. The parent
// series id is a jcs.Value (nil encodes as null, a string as the string) —
// a typed nil *string would not match the canonicalizer's `nil` case. v3:
// each point commits its coordinate identity (FRF/COORDINATE/v1), so the
// series is content-addressed over the exact coordinates, not the labels.
func seriesIdentity(experimentID string, parent jcs.Value, court, coordinateSystem string, points []*jcs.Object) (string, error) {
	var ps []jcs.Value
	for _, p := range points {
		ps = append(ps, &jcs.Object{
			Keys:   []string{"point_index", "coordinate", "coordinate_identity", "run"},
			Values: []jcs.Value{str(p, "point_index"), str(p, "coordinate"), str(p, "coordinate_identity"), str(p, "run")},
		})
	}
	doc := &jcs.Object{
		Keys:   []string{"experiment_id", "parent_series_id", "court", "coordinate_system", "points"},
		Values: []jcs.Value{experimentID, parent, court, coordinateSystem, ps},
	}
	return hashPreimage("FRF/SERIES/v3", doc)
}

// reductionIdentity: FRF/REDUCTION/v3 over the reduction record's own fields.
func reductionIdentity(r *jcs.Object) (string, error) {
	derivation := obj(recVal(r, "derivation"))
	minimality := obj(recVal(derivation, "minimality"))
	var attempts []jcs.Value
	for _, a := range arr(recVal(r, "attempts")) {
		ao := obj(a)
		attempts = append(attempts, &jcs.Object{
			Keys:   []string{"attempt", "role", "fixture_sha256", "outcome", "accepted"},
			Values: []jcs.Value{str(ao, "attempt"), str(ao, "role"), str(ao, "fixture_sha256"), str(ao, "outcome"), recVal(ao, "accepted")},
		})
	}
	var minimizer jcs.Value
	if _, ok := r.Get("minimizer_semantic_id"); ok {
		// The record carries the minimizer binding as minimizer_* fields (no
		// top-level `minimizer` key); the identity doc mirrors the reference
		// engine's store::minimizer_binding.
		minimizer = &jcs.Object{
			Keys:   []string{"semantic_id", "semantic_hash", "implementation_hash", "implementation_artifact", "invocation_id", "result_id"},
			Values: []jcs.Value{str(r, "minimizer_semantic_id"), str(r, "minimizer_semantic_hash"), str(r, "minimizer_implementation_hash"), recVal(r, "minimizer_implementation_artifact"), str(r, "minimizer_invocation_id"), str(r, "minimizer_result_id")},
		}
	}
	// The domain-aware predicate fields enter the identity ONLY when the
	// record carries them, exactly as they serialize (absent == the record
	// shape written before the generalization; an explicit coordinate is a
	// different preimage). v5 types the domain: the nested `reduction_domain`
	// (kind + semantic) and the two-point `boundary` (predecessor + value,
	// each with its observed preservation) replace the flat coordinates. The
	// minimizer's claim likewise enters only when present.
	minimalityKeys := []string{"kind", "proven"}
	minimalityValues := []jcs.Value{str(minimality, "kind"), recVal(minimality, "proven")}
	for _, key := range []string{"granularity", "reduction_domain", "boundary", "proposal_minimality_claimed"} {
		if v, ok := minimality.Get(key); ok && v != nil {
			minimalityKeys = append(minimalityKeys, key)
			minimalityValues = append(minimalityValues, v)
		}
	}
	doc := &jcs.Object{
		Keys: []string{"residual_id", "source_run", "axis", "kind", "court_semantic_identity", "authority_artifact_sha256", "candidate_artifact_sha256", "environment_digest", "comparator_semantic_id", "comparator_semantic_hash", "comparator_implementation_hash", "argv_template", "original_fixture_sha256", "final_fixture_sha256", "attempts", "derivation", "transform", "minimizer"},
		Values: []jcs.Value{
			str(r, "residual_id"), str(r, "source_run"), str(r, "axis"), str(r, "kind"),
			str(r, "court_semantic_identity"), str(r, "authority_artifact_sha256"), str(r, "candidate_artifact_sha256"),
			str(r, "environment_digest"), str(r, "comparator_semantic_id"), str(r, "comparator_semantic_hash"),
			str(r, "comparator_implementation_hash"), recVal(r, "argv_template"),
			str(r, "original_fixture_sha256"), str(r, "final_fixture_sha256"),
			attempts,
			&jcs.Object{
				Keys: []string{"strategy", "original_lines", "final_lines", "minimality"},
				Values: []jcs.Value{str(derivation, "strategy"), str(derivation, "original_lines"), str(derivation, "final_lines"),
					&jcs.Object{
						Keys:   minimalityKeys,
						Values: minimalityValues,
					}},
			},
			recVal(r, "transform"),
			minimizer,
		},
	}
	return hashPreimage("FRF/REDUCTION/v3", doc)
}

// challengeIdentity: FRF/CHALLENGE/v1 over the declared evidence.
func challengeIdentity(c *jcs.Object) (string, error) {
	doc := &jcs.Object{
		Keys:   []string{"schema_version", "court", "operator", "target_axis", "reference_sha256", "mutant_candidate_sha256", "run"},
		Values: []jcs.Value{str(c, "schema_version"), str(c, "court"), str(c, "operator"), str(c, "target_axis"), str(c, "reference_sha256"), str(c, "mutant_candidate_sha256"), str(c, "run")},
	}
	return hashPreimage("FRF/CHALLENGE/v1", doc)
}

// knowledgeSnapshotIdentity: FRF/KNOWLEDGE/v2 over the claim's committed
// evidence universe.
func knowledgeSnapshotIdentity(snapshot *jcs.Object) (string, error) {
	var heads []jcs.Value
	for _, h := range arr(recVal(snapshot, "residual_heads")) {
		ho := obj(h)
		heads = append(heads, &jcs.Object{
			Keys:   []string{"id", "record_cid", "fingerprint", "disposition", "disposition_event_id"},
			Values: []jcs.Value{str(ho, "id"), str(ho, "record_cid"), str(ho, "fingerprint"), str(ho, "disposition"), recVal(ho, "disposition_event_id")},
		})
	}
	var objects []jcs.Value
	for _, o := range arr(recVal(snapshot, "objects")) {
		oo := obj(o)
		objects = append(objects, &jcs.Object{
			Keys:   []string{"kind", "id", "cid"},
			Values: []jcs.Value{str(oo, "kind"), str(oo, "id"), str(oo, "cid")},
		})
	}
	doc := &jcs.Object{
		Keys:   []string{"residual_heads", "objects"},
		Values: []jcs.Value{heads, objects},
	}
	return hashPreimage("FRF/KNOWLEDGE/v2", doc)
}

// The κ routing table (spec/kappa.md): the surface/magnitude/next-court of a
// divergence, per axis.
func tokenShape(axis string) (surface, magnitude, nextCourt string) {
	switch axis {
	case "exit":
		return "exit-class", "class-change", "cli-exit-minimize"
	case "stderr":
		return "diagnostic-routing", "first-line-token-change", "cli-diagnostic-minimize"
	case "stdout":
		return "stdout-routing", "first-line-token-change", "cli-stdout-minimize"
	default:
		return axis + "-divergence", "observed", "none"
	}
}

func blocksClaims(axis, scope string) []string {
	switch axis {
	case "exit":
		return []string{scope + " exit parity"}
	case "stderr":
		return []string{"byte-identical diagnostics"}
	case "stdout":
		return []string{"byte-identical stdout"}
	default:
		return []string{scope + " " + axis + " parity"}
	}
}

func expectedToken(record *jcs.Object) (string, error) {
	surface, magnitude, _ := tokenShape(str(record, "axis"))
	return fmt.Sprintf("%s/%s/%s/%s", str(record, "kind"), surface, magnitude, str(record, "disposition")), nil
}

func grammarState(disposition string) string {
	switch disposition {
	case "open":
		return "violation"
	case "fixed", "nonreproduced", "stabilized":
		return "recovery"
	case "intentional":
		return "intentional_divergence"
	case "environmental", "oracle_version", "harness":
		return "boundary"
	default:
		return "unknown"
	}
}

// projectedDisposition: the last event's disposition string, or "open" when
// the residual has no events (the event JSON FLATTENS the disposition: the
// `disposition` key is a string at the event's top level, with sibling
// reason/resolution_run_id/closure_predicate keys when closed).
func projectedDisposition(events []*jcs.Object) string {
	if len(events) == 0 {
		return "open"
	}
	return str(events[len(events)-1], "disposition")
}
