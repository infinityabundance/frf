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

func envDigest(os, arch, kernel, locale, timezone, umask string) string {
	return jcs.Sha256Hex([]byte(fmt.Sprintf(
		"os=%s\narch=%s\nkernel=%s\nlocale=%s\ntimezone=%s\numask=%s",
		os, arch, kernel, locale, timezone, umask)))
}

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

func asStrArray(v jcs.Value) []string {
	var out []string
	for _, item := range arr(v) {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
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

// runIdentity: FRF/RUN/v1 over the capture's recorded fields — the name is a
// claim until recomputed.
func runIdentity(cap *jcs.Object, residuals []*jcs.Object) (string, error) {
	prov := obj(recVal(cap, "provenance"))
	runner := obj(recVal(prov, "runner"))
	side := func(s *jcs.Object) *jcs.Object {
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
	var res []jcs.Value
	for _, r := range residuals {
		res = append(res, &jcs.Object{
			Keys:   []string{"kind", "raw_reference", "raw_candidate"},
			Values: []jcs.Value{str(r, "kind"), str(r, "raw_reference"), str(r, "raw_candidate")},
		})
	}
	interp := func(s *jcs.Object) jcs.Value {
		if v, ok := s.Get("interpreter"); ok && v != nil {
			io := v.(*jcs.Object)
			down := obj(recVal(io, "downstream_interpreter"))
			if h, ok := down.Get("sha256"); ok {
				return h
			}
		}
		return nil
	}
	doc := &jcs.Object{
		Keys: []string{"court", "authority", "authority_interpreter", "candidate_sha256", "candidate_interpreter", "fixture_sha256", "arguments", "environment_digest", "runner_hash", "court_semantic_identity", "reference", "candidate", "residuals"},
		Values: []jcs.Value{
			str(cap, "court"),
			str(cap, "authority"),
			interp(obj(recVal(cap, "authority_artifact"))),
			str(obj(recVal(cap, "candidate_artifact")), "sha256"),
			interp(obj(recVal(cap, "candidate_artifact"))),
			str(cap, "fixture_sha256"),
			recVal(cap, "arguments"),
			str(obj(recVal(cap, "environment")), "digest"),
			str(runner, "frf_executable_hash"),
			str(cap, "court_semantic_identity"),
			side(obj(recVal(cap, "reference"))),
			side(obj(recVal(cap, "candidate"))),
			res,
		},
	}
	return hashPreimage("FRF/RUN/v1", doc)
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
	default:
		return &jcs.Object{
			Keys:   []string{"kind", "reason"},
			Values: []jcs.Value{kind, str(event, "reason")},
		}
	}
}

// seriesIdentity: FRF/SERIES/v2 over the snapshot's own fields. The parent
// series id is a jcs.Value (nil encodes as null, a string as the string) —
// a typed nil *string would not match the canonicalizer's `nil` case.
func seriesIdentity(experimentID string, parent jcs.Value, court, coordinateSystem string, points []*jcs.Object) (string, error) {
	var ps []jcs.Value
	for _, p := range points {
		ps = append(ps, &jcs.Object{
			Keys:   []string{"point_index", "coordinate", "run"},
			Values: []jcs.Value{str(p, "point_index"), str(p, "coordinate"), str(p, "run")},
		})
	}
	doc := &jcs.Object{
		Keys:   []string{"experiment_id", "parent_series_id", "court", "coordinate_system", "points"},
		Values: []jcs.Value{experimentID, parent, court, coordinateSystem, ps},
	}
	return hashPreimage("FRF/SERIES/v2", doc)
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
	if m, ok := r.Get("minimizer"); ok && m != nil {
		mo := m.(*jcs.Object)
		minimizer = &jcs.Object{
			Keys:   []string{"semantic_id", "semantic_hash", "implementation_hash", "implementation_artifact", "invocation_id", "result_id"},
			Values: []jcs.Value{str(mo, "semantic_id"), str(mo, "semantic_hash"), str(mo, "implementation_hash"), recVal(mo, "implementation_artifact"), str(mo, "invocation_id"), str(mo, "result_id")},
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
						Keys:   []string{"kind", "granularity", "proven"},
						Values: []jcs.Value{str(minimality, "kind"), str(minimality, "granularity"), recVal(minimality, "proven")},
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
	case "fixed":
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
