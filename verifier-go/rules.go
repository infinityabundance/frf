package main

import (
	"fmt"
	"strings"

	"frf-verifier-go/jcs"
)

// The structural + semantic conformance rules — the Go ports of the
// document-level rules in the Rust engine's semantic validator and the xtask
// verifier. Written by hand from the protocol documents; no generated
// schemas, no shared code. The corpus in conformance/ is the ground truth:
// valid fixtures must pass, invalid must be refused structurally,
// invalid-semantic must be structurally valid but semantically refused.

func isValidIdentifier(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	if !(s[0] >= 'a' && s[0] <= 'z') {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

func hex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func unknownKeys(v jcs.Value, allowed []string) []string {
	o, ok := v.(*jcs.Object)
	if !ok || o == nil {
		return nil
	}
	var out []string
	for _, k := range o.Keys {
		found := false
		for _, a := range allowed {
			if k == a {
				found = true
				break
			}
		}
		if !found {
			out = append(out, k)
		}
	}
	return out
}

func objKeys(o *jcs.Object, key string) *jcs.Object {
	v, ok := o.Get(key)
	if !ok || v == nil {
		return nil
	}
	return obj(v)
}

func arrStr(v jcs.Value) []string {
	var out []string
	for _, item := range arr(v) {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

var requiredReceiptKeys = []string{
	"schema_version", "run", "court", "provenance", "comparator_semantics",
	"normalizer_semantics", "adapter_semantics", "execution_profile", "capture_bounds",
	"authority", "candidate", "environment", "fixtures", "observables", "residuals",
	"endoduction", "claims", "replay",
}
var courtKeys = []string{"id", "question", "falsifier", "admissibility_envelope", "semantic_identity"}
var envelopeKeys = []string{"authority_versions", "fixture_family", "platforms", "observables", "normalizers", "replay_scope"}
var provenanceKeys = []string{"schema_version", "runner", "comparator_implementations", "normalizer_implementations", "adapter_implementations", "minimizer_implementations"}
var runnerKeys = []string{"schema_version", "frf_version", "frf_executable_hash"}
var comparatorImplKeys = []string{"id", "implementation_hash", "runner_hash", "artifact"}
var extensionImplKeys = []string{"id", "implementation_hash", "runner_hash", "artifact"}
var artifactKeys = []string{"path", "sha256", "interpreter"}
var normalizerSemanticKeys = []string{"id", "relation_id", "applies_to", "relation_version", "specification_hash"}
var adapterSemanticKeys = []string{"id", "relation_id", "relation_version", "specification_hash"}
var comparatorSemanticKeys = []string{"id", "relation_id", "extractor", "residual_classifier", "relation_version", "specification_hash"}
var authorityKeys = []string{"name", "kind", "version", "identity_hash", "provenance", "interpreter"}
var candidateKeys = []string{"name", "version_or_commit", "build_profile", "identity_hash", "interpreter"}
var interpreterKeys = []string{"kernel_interpreter", "shebang_argument_bytes", "resolver", "downstream_interpreter"}
var interpreterExecKeys = []string{"path", "sha256"}
var resolverKeys = []string{"kind", "path", "sha256", "path_digest"}
var environmentKeys = []string{"schema_version", "os", "architecture", "kernel_release", "locale", "timezone", "umask", "cwd", "digest"}
var fixtureKeys = []string{"id", "hash", "arguments", "declared_arguments"}
var observableKeys = []string{"axis", "raw_reference_hash", "raw_candidate_hash", "comparator", "normalization_rules", "verdict", "comparator_request", "comparator_result"}
var residualKeys = []string{"id", "axis", "kind", "sign", "grammar_state", "raw_reference_hash", "raw_candidate_hash", "invariant", "reproducer", "residual_fingerprint", "disposition", "disposition_event_id", "reason", "resolution_run_id", "closure_predicate"}
var signKeys = []string{"trajectory_evidence"}
var trajectoryEvidenceKeys = []string{"coordinate_system", "series", "drift", "slew"}
var tokenKeys = []string{"residual_id", "token", "next_court", "blocks_claims"}
var endoductionKeys = []string{"schema_version", "tokens"}
var claimKeys = []string{"positive", "non_claims", "blocked_by_open_residuals"}
var replayKeys = []string{"program", "evidence_root", "argv", "expected_run_identity"}
var captureBoundsKeys = []string{"timeout_ms", "max_stream_bytes", "rlimit_as_mb", "rlimit_cpu_s", "rlimit_nofile", "rlimit_nproc", "cgroup_pids_max", "cgroup_memory_max", "cgroup_cpu_max"}
var dispositeions = []string{"open", "fixed", "intentional", "environmental", "oracle_version", "harness", "unknown"}
var closurePredicate = "fix-court: same court, authority, fixture, arguments, observables, normalizers, environment; axis equality"

func push(v *[]string, s string) {
	*v = append(*v, s)
}

func structuralViolations(doc jcs.Value) []string {
	var v []string
	o, ok := doc.(*jcs.Object)
	if !ok {
		return []string{"receipt is not an object"}
	}
	if str(o, "schema_version") != "frf-receipt-v16" {
		push(&v, fmt.Sprintf("schema_version is %v, expected frf-receipt-v16", str(o, "schema_version")))
	}
	for _, k := range requiredReceiptKeys {
		if _, ok := o.Get(k); !ok {
			push(&v, fmt.Sprintf("missing required field %q", k))
		}
	}
	for _, k := range unknownKeys(o, requiredReceiptKeys) {
		push(&v, fmt.Sprintf("unknown property %q on the receipt (strict evidence)", k))
	}
	for _, pair := range [][2]string{{"court", "court"}, {"provenance", "provenance"}, {"authority", "authority"}, {"candidate", "candidate"}, {"environment", "environment"}, {"endoduction", "endoduction"}, {"claims", "claims"}, {"replay", "replay"}} {
		sub := objKeys(o, pair[0])
		var allowed []string
		switch pair[0] {
		case "court":
			allowed = courtKeys
		case "provenance":
			allowed = provenanceKeys
		case "authority":
			allowed = authorityKeys
		case "candidate":
			allowed = candidateKeys
		case "environment":
			allowed = environmentKeys
		case "endoduction":
			allowed = endoductionKeys
		case "claims":
			allowed = claimKeys
		case "replay":
			allowed = replayKeys
		}
		for _, k := range unknownKeys(sub, allowed) {
			push(&v, fmt.Sprintf("unknown property %q on receipt.%s (strict evidence)", k, pair[1]))
		}
	}
	env := objKeys(objKeys(o, "court"), "admissibility_envelope")
	for _, k := range unknownKeys(env, envelopeKeys) {
		push(&v, fmt.Sprintf("unknown property %q on the admissibility envelope", k))
	}
	for _, k := range unknownKeys(objKeys(o, "capture_bounds"), captureBoundsKeys) {
		push(&v, fmt.Sprintf("unknown property %q on capture_bounds", k))
	}
	prov := objKeys(o, "provenance")
	for _, k := range unknownKeys(objKeys(prov, "runner"), runnerKeys) {
		push(&v, fmt.Sprintf("unknown property %q on provenance.runner", k))
	}
	if impls, ok := prov.Get("comparator_implementations"); ok {
		for i, c := range arr(impls) {
			co := obj(c)
			for _, k := range unknownKeys(co, comparatorImplKeys) {
				push(&v, fmt.Sprintf("unknown property %q on comparator_implementations[%d]", k, i))
			}
			if art, ok := co.Get("artifact"); ok {
				for _, k := range unknownKeys(art, artifactKeys) {
					push(&v, fmt.Sprintf("unknown property %q on comparator_implementations[%d].artifact", k, i))
				}
			}
		}
	}
	if sems, ok := o.Get("comparator_semantics"); ok {
		for i, c := range arr(sems) {
			co := obj(c)
			for _, k := range unknownKeys(co, comparatorSemanticKeys) {
				push(&v, fmt.Sprintf("unknown property %q on comparator_semantics[%d]", k, i))
			}
			if !hex64(str(co, "specification_hash")) {
				push(&v, fmt.Sprintf("comparator_semantics[%d].specification_hash must be 64 hex", i))
			}
		}
	}
	if sems, ok := o.Get("normalizer_semantics"); ok {
		for i, c := range arr(sems) {
			co := obj(c)
			for _, k := range unknownKeys(co, normalizerSemanticKeys) {
				push(&v, fmt.Sprintf("unknown property %q on normalizer_semantics[%d]", k, i))
			}
			if !hex64(str(co, "specification_hash")) {
				push(&v, fmt.Sprintf("normalizer_semantics[%d].specification_hash must be 64 hex", i))
			}
			applies := str(co, "applies_to")
			if applies != "stdout" && applies != "stderr" && applies != "both" {
				push(&v, fmt.Sprintf("normalizer_semantics[%d].applies_to must be stdout, stderr, or both", i))
			}
		}
	}
	if sems, ok := o.Get("adapter_semantics"); ok {
		for i, c := range arr(sems) {
			co := obj(c)
			for _, k := range unknownKeys(co, adapterSemanticKeys) {
				push(&v, fmt.Sprintf("unknown property %q on adapter_semantics[%d]", k, i))
			}
			if !hex64(str(co, "specification_hash")) {
				push(&v, fmt.Sprintf("adapter_semantics[%d].specification_hash must be 64 hex", i))
			}
		}
	}
	if fixtures, ok := o.Get("fixtures"); ok {
		for i, f := range arr(fixtures) {
			for _, k := range unknownKeys(f, fixtureKeys) {
				push(&v, fmt.Sprintf("unknown property %q on fixtures[%d]", k, i))
			}
		}
	}
	if obs, ok := o.Get("observables"); ok {
		for i, ob := range arr(obs) {
			oo := obj(ob)
			for _, k := range unknownKeys(oo, observableKeys) {
				push(&v, fmt.Sprintf("unknown property %q on observables[%d]", k, i))
			}
			for _, what := range []string{"comparator_request", "comparator_result"} {
				if cid, ok := oo.Get(what); ok && cid != nil {
					if s, ok := cid.(string); !ok || !hex64(s) {
						push(&v, fmt.Sprintf("observables[%d].%s must be a 64-hex content address", i, what))
					}
				}
			}
		}
	}
	for _, who := range []string{"authority", "candidate"} {
		interp := objKeys(objKeys(o, who), "interpreter")
		if interp == nil {
			continue
		}
		for _, k := range unknownKeys(interp, interpreterKeys) {
			push(&v, fmt.Sprintf("unknown property %q on %s.interpreter", k, who))
		}
		if res := objKeys(interp, "resolver"); res != nil {
			for _, k := range unknownKeys(res, resolverKeys) {
				push(&v, fmt.Sprintf("unknown property %q on %s.interpreter.resolver", k, who))
			}
		}
		for _, part := range []string{"kernel_interpreter", "downstream_interpreter"} {
			for _, k := range unknownKeys(objKeys(interp, part), interpreterExecKeys) {
				push(&v, fmt.Sprintf("unknown property %q on %s.interpreter.%s", k, who, part))
			}
		}
	}
	if residuals, ok := o.Get("residuals"); ok {
		for i, r := range arr(residuals) {
			ro := obj(r)
			if ro == nil {
				push(&v, "residual entry is not an object")
				continue
			}
			for _, k := range unknownKeys(ro, residualKeys) {
				push(&v, fmt.Sprintf("unknown property %q on residuals[%d]", k, i))
			}
			sign := objKeys(ro, "sign")
			for _, k := range unknownKeys(sign, signKeys) {
				push(&v, fmt.Sprintf("unknown property %q on residuals[%d].sign", k, i))
			}
			if entries, ok := sign.Get("trajectory_evidence"); ok {
				for j, e := range arr(entries) {
					for _, k := range unknownKeys(e, trajectoryEvidenceKeys) {
						push(&v, fmt.Sprintf("unknown property %q on residuals[%d].sign.trajectory_evidence[%d]", k, i, j))
					}
				}
			}
			if !isValidIdentifier(str(ro, "kind")) {
				push(&v, fmt.Sprintf("residual %v has invalid kind %v", ro.Str("id"), str(ro, "kind")))
			}
			d := str(ro, "disposition")
			found := false
			for _, x := range dispositeions {
				if x == d {
					found = true
					break
				}
			}
			if !found {
				push(&v, fmt.Sprintf("residual %v has unknown disposition %v", ro.Str("id"), d))
			}
		}
	}
	if tokens, ok := objKeys(o, "endoduction").Get("tokens"); ok {
		for i, t := range arr(tokens) {
			for _, k := range unknownKeys(t, tokenKeys) {
				push(&v, fmt.Sprintf("unknown property %q on endoduction.tokens[%d]", k, i))
			}
		}
	}
	return v
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func semanticViolations(rec jcs.Value) []string {
	var v []string
	o := obj(rec)
	if str(o, "schema_version") != "frf-receipt-v16" {
		push(&v, fmt.Sprintf("schema_version is %v, expected frf-receipt-v16", str(o, "schema_version")))
	}
	fixtures := arr(recVal(o, "fixtures"))
	if len(fixtures) != 1 {
		push(&v, fmt.Sprintf("exactly one fixture is required (found %d)", len(fixtures)))
	}
	env := objKeys(objKeys(o, "court"), "admissibility_envelope")
	if str(env, "replay_scope") != "single-run" {
		push(&v, fmt.Sprintf("replay_scope %v is not executable in v0", str(env, "replay_scope")))
	}

	var declared []string
	for _, axis := range arrStr(recVal(env, "observables")) {
		if !isValidIdentifier(axis) {
			push(&v, fmt.Sprintf("invalid observable axis identifier %q", axis))
		}
		if containsString(declared, axis) {
			push(&v, fmt.Sprintf("duplicate declared observable axis %q", axis))
		} else {
			declared = append(declared, axis)
		}
	}
	var obsAxes []string
	for _, ob := range arr(recVal(o, "observables")) {
		oo := obj(ob)
		axis := str(oo, "axis")
		if !isValidIdentifier(axis) {
			push(&v, fmt.Sprintf("observable with invalid axis identifier %q", axis))
		}
		if !containsString(declared, axis) {
			push(&v, fmt.Sprintf("observable %s is not declared in the envelope", axis))
		}
		if containsString(obsAxes, axis) {
			push(&v, fmt.Sprintf("duplicate observable block for axis %s", axis))
		} else {
			obsAxes = append(obsAxes, axis)
		}
		req, hasReq := oo.Get("comparator_request")
		res, hasRes := oo.Get("comparator_result")
		switch {
		case !hasReq && !hasRes:
		case hasReq && hasRes && req != nil && res != nil:
			// both present — checked structurally for hex
		default:
			push(&v, fmt.Sprintf("observable %s binds only one of comparator_request/comparator_result", axis))
		}
	}

	var semantics []*jcs.Object
	for _, c := range arr(recVal(o, "comparator_semantics")) {
		co := obj(c)
		id := str(co, "id")
		if containsString(semanticIDs(semantics), id) {
			push(&v, fmt.Sprintf("duplicate comparator semantic id %s", id))
		}
		if !containsString(obsAxes, id) {
			push(&v, fmt.Sprintf("comparator semantic %s serves no observable", id))
		}
		expected, err := comparatorSpecHash(id, str(co, "relation_id"), str(co, "extractor"), str(co, "residual_classifier"), str(co, "relation_version"))
		if err == nil && expected != str(co, "specification_hash") {
			push(&v, fmt.Sprintf("comparator semantic %s: the specification_hash does not rederive from its own fields", id))
		}
		semantics = append(semantics, co)
	}
	for _, ob := range arr(recVal(o, "observables")) {
		axis := str(obj(ob), "axis")
		n := 0
		for _, c := range semantics {
			if str(c, "id") == axis {
				n++
			}
		}
		if n != 1 {
			push(&v, fmt.Sprintf("observable %s must have exactly one comparator semantic (found %d)", axis, n))
		}
	}

	// Normalizer semantics: ids match the envelope's application order.
	var envNorm []string
	for _, n := range arrStr(recVal(env, "normalizers")) {
		envNorm = append(envNorm, n)
	}
	var recNorm []string
	for _, n := range arr(recVal(o, "normalizer_semantics")) {
		no := obj(n)
		recNorm = append(recNorm, str(no, "id"))
	}
	if strings.Join(recNorm, "\x00") != strings.Join(envNorm, "\x00") {
		push(&v, "normalizer_semantics ids must match the envelope's application order exactly")
	}
	var normIDs []string
	for _, n := range arr(recVal(o, "normalizer_semantics")) {
		no := obj(n)
		id := str(no, "id")
		if containsString(normIDs, id) {
			push(&v, fmt.Sprintf("duplicate normalizer semantic id %s", id))
		} else {
			normIDs = append(normIDs, id)
		}
		expected, err := normalizerSpecHash(id, str(no, "relation_id"), str(no, "applies_to"), str(no, "relation_version"))
		if err == nil && expected != str(no, "specification_hash") {
			push(&v, fmt.Sprintf("normalizer semantic %s: the specification_hash does not rederive from its own fields", id))
		}
	}
	// Capture-adapter semantics: ids are declared observable axes, unique.
	var adapterIDs []string
	for _, a := range arr(recVal(o, "adapter_semantics")) {
		ao := obj(a)
		id := str(ao, "id")
		if containsString(adapterIDs, id) {
			push(&v, fmt.Sprintf("duplicate capture-adapter semantic id %s", id))
		} else {
			adapterIDs = append(adapterIDs, id)
		}
		if !containsString(declared, id) {
			push(&v, fmt.Sprintf("capture-adapter semantic %s serves no declared observable", id))
		}
		expected, err := captureAdapterSpecHash(id, str(ao, "relation_id"), str(ao, "relation_version"))
		if err == nil && expected != str(ao, "specification_hash") {
			push(&v, fmt.Sprintf("capture-adapter semantic %s: the specification_hash does not rederive from its own fields", id))
		}
	}

	impls := arr(recVal(objKeys(o, "provenance"), "comparator_implementations"))
	if len(impls) != len(semantics) {
		push(&v, "comparator_implementations must mirror comparator_semantics one-to-one")
	}
	for _, c := range semantics {
		found := false
		for _, i := range impls {
			if str(obj(i), "id") == str(c, "id") {
				found = true
				break
			}
		}
		if !found {
			push(&v, fmt.Sprintf("comparator semantic %s has no implementation provenance", str(c, "id")))
		}
	}

	family := str(env, "fixture_family")
	var residualIDs []string
	for _, r := range arr(recVal(o, "residuals")) {
		ro := obj(r)
		rid := str(ro, "id")
		if containsString(residualIDs, rid) {
			push(&v, fmt.Sprintf("duplicate residual id %s", rid))
		} else {
			residualIDs = append(residualIDs, rid)
		}
		axis := str(ro, "axis")
		if !containsString(declared, axis) {
			push(&v, fmt.Sprintf("residual %s axis %s is not a declared observable", rid, axis))
		}
		var classifier string
		for _, c := range semantics {
			if str(c, "id") == axis {
				classifier = str(c, "residual_classifier")
			}
		}
		if classifier != str(ro, "kind") {
			push(&v, fmt.Sprintf("residual %s kind %v is inconsistent with the %s axis's residual classifier %v", rid, str(ro, "kind"), axis, classifier))
		}
		d := str(ro, "disposition")
		switch d {
		case "open":
			if _, ok := ro.Get("reason"); ok {
				push(&v, fmt.Sprintf("open residual %s carries a reason", rid))
			}
			if _, ok := ro.Get("resolution_run_id"); ok {
				push(&v, fmt.Sprintf("open residual %s carries a resolution_run_id", rid))
			}
			if _, ok := ro.Get("closure_predicate"); ok {
				push(&v, fmt.Sprintf("open residual %s carries a closure_predicate", rid))
			}
			if eid, ok := ro.Get("disposition_event_id"); ok && eid != nil {
				if _, isStr := eid.(string); isStr {
					push(&v, fmt.Sprintf("open residual %s carries a disposition_event_id", rid))
				}
			}
		case "fixed":
			if _, ok := ro.Get("reason"); !ok {
				push(&v, fmt.Sprintf("fixed residual %s without a reason", rid))
			}
			if _, ok := ro.Get("resolution_run_id"); !ok {
				push(&v, fmt.Sprintf("fixed residual %s without a resolution_run_id", rid))
			}
			if str(ro, "closure_predicate") != closurePredicate {
				push(&v, fmt.Sprintf("fixed residual %s must carry the fix-court closure predicate", rid))
			}
			if eid, ok := ro.Get("disposition_event_id"); !ok || eid == nil {
				push(&v, fmt.Sprintf("fixed residual %s without a disposition_event_id", rid))
			}
		default:
			found := false
			for _, x := range dispositeions {
				if x == d {
					found = true
					break
				}
			}
			if !found {
				push(&v, fmt.Sprintf("residual %s has unknown disposition %v", rid, d))
			}
			if _, ok := ro.Get("reason"); !ok {
				push(&v, fmt.Sprintf("%s residual %s requires a reason", d, rid))
			}
			if _, ok := ro.Get("resolution_run_id"); ok {
				push(&v, fmt.Sprintf("%s residual %s carries a resolution_run_id", d, rid))
			}
			if _, ok := ro.Get("closure_predicate"); ok {
				push(&v, fmt.Sprintf("%s residual %s carries a closure_predicate", d, rid))
			}
			if eid, ok := ro.Get("disposition_event_id"); !ok || eid == nil {
				push(&v, fmt.Sprintf("%s residual %s without a disposition_event_id", d, rid))
			}
		}
		if str(ro, "grammar_state") != grammarState(d) {
			push(&v, fmt.Sprintf("grammar_state of %s is %v, expected %v", rid, str(ro, "grammar_state"), grammarState(d)))
		}
		sign := objKeys(ro, "sign")
		var seenCoords []string
		for _, e := range arr(recVal(sign, "trajectory_evidence")) {
			eo := obj(e)
			coord := str(eo, "coordinate_system")
			if coord != "repeat_index" && coord != "candidate_revision" && coord != "authority_version" && coord != "environment" && coord != "time" {
				push(&v, fmt.Sprintf("residual %s names unknown trajectory coordinate system %v", rid, coord))
			}
			if containsString(seenCoords, coord) {
				push(&v, fmt.Sprintf("residual %s names coordinate system %v twice in its trajectory evidence", rid, coord))
			}
			seenCoords = append(seenCoords, coord)
			if str(eo, "series") == "" {
				push(&v, fmt.Sprintf("residual %s has trajectory evidence without a pinned series", rid))
			}
			drift := str(eo, "drift")
			if drift != "persistent" && drift != "transient" && drift != "recurrent" && drift != "boundary-localized" && drift != "version-stratified" {
				push(&v, fmt.Sprintf("residual %s has invalid drift %v in its trajectory evidence", rid, drift))
			}
			slew := str(eo, "slew")
			if slew != "stable" && slew != "abrupt" && slew != "burst" && slew != "recurrent" && slew != "gradual" {
				push(&v, fmt.Sprintf("residual %s has invalid slew %v in its trajectory evidence", rid, slew))
			}
		}
		if str(ro, "reproducer") != str(o, "run") {
			push(&v, fmt.Sprintf("residual %s reproducer must be the receipt's run", rid))
		}
	}

	for _, ob := range arr(recVal(o, "observables")) {
		axis := str(obj(ob), "axis")
		has := false
		for _, r := range arr(recVal(o, "residuals")) {
			if str(obj(r), "axis") == axis {
				has = true
				break
			}
		}
		verdict := str(obj(ob), "verdict")
		if verdict == "pass" && has {
			push(&v, fmt.Sprintf("pass verdict on %s while a residual exists", axis))
		}
		if verdict == "residual" && !has {
			push(&v, fmt.Sprintf("residual verdict on %s without any residual", axis))
		}
	}

	envDoc := objKeys(o, "environment")
	if envDigest(str(envDoc, "os"), str(envDoc, "architecture"), str(envDoc, "kernel_release"), str(envDoc, "locale"), str(envDoc, "timezone"), str(envDoc, "umask")) != str(envDoc, "digest") {
		push(&v, "the environment digest does not rederive")
	}
	if !isValidIdentifier(str(o, "execution_profile")) {
		push(&v, fmt.Sprintf("invalid execution_profile identifier %v", str(o, "execution_profile")))
	}
	bounds := objKeys(o, "capture_bounds")
	for _, what := range []string{"timeout_ms", "max_stream_bytes", "rlimit_as_mb", "rlimit_cpu_s", "rlimit_nofile", "rlimit_nproc"} {
		s := str(bounds, what)
		if s == "" {
			push(&v, fmt.Sprintf("capture bound %s missing", what))
		}
	}
	// v16: the cgroup v2 aggregate envelope, when present, validates too; the
	// profile's contract is exactly what it declares.
	switch str(o, "execution_profile") {
	case "frf-exec-linux-v1":
		for _, what := range []string{"cgroup_pids_max", "cgroup_memory_max", "cgroup_cpu_max"} {
			if _, ok := bounds.Get(what); ok {
				push(&v, fmt.Sprintf("execution profile frf-exec-linux-v1 must not carry the v2 cgroup bound %s", what))
			}
		}
	case "frf-exec-linux-v2":
		for _, what := range []string{"cgroup_pids_max", "cgroup_memory_max", "cgroup_cpu_max"} {
			if s := str(bounds, what); s == "" {
				push(&v, fmt.Sprintf("execution profile frf-exec-linux-v2 requires the cgroup bound %s", what))
			}
		}
	default:
		push(&v, fmt.Sprintf("unregistered execution profile %v", str(o, "execution_profile")))
	}

	semantic, err := courtSemanticIdentityFromReceipt(o)
	if err != nil || semantic != str(objKeys(o, "court"), "semantic_identity") {
		push(&v, "the court semantic identity does not rederive from the document")
	}

	replay := objKeys(o, "replay")
	if str(replay, "program") != "frf" {
		push(&v, "replay.program must be \"frf\"")
	}
	if str(replay, "expected_run_identity") != str(o, "run") {
		push(&v, "replay.expected_run_identity must equal the receipt's run")
	}
	argv := arrStr(recVal(replay, "argv"))
	if len(argv) < 5 || argv[0] != "--root" || argv[2] != "court" || argv[3] != "run" {
		push(&v, "replay.argv must be a court-run invocation")
	}

	tokens := arr(recVal(objKeys(o, "endoduction"), "tokens"))
	residuals := arr(recVal(o, "residuals"))
	if len(tokens) != len(residuals) {
		push(&v, "endoduction tokens must mirror residuals one-to-one")
	}
	for i := range residuals {
		if i >= len(tokens) {
			break
		}
		r := obj(residuals[i])
		t := obj(tokens[i])
		if str(t, "residual_id") != str(r, "id") {
			push(&v, fmt.Sprintf("token bound to %s but the residual is %s", str(t, "residual_id"), str(r, "id")))
			continue
		}
		tok, err := expectedToken(r)
		if err != nil || tok != str(t, "token") {
			push(&v, fmt.Sprintf("token of %s does not rederive", str(r, "id")))
		}
		surface, magnitude, next := tokenShape(str(r, "axis"))
		_ = surface
		_ = magnitude
		if next != str(t, "next_court") {
			push(&v, fmt.Sprintf("next_court of %s does not rederive", str(r, "id")))
		}
		blocks := blocksClaims(str(r, "axis"), family)
		bc := arrStr(recVal(t, "blocks_claims"))
		if len(blocks) == 0 || len(bc) == 0 || bc[0] != blocks[0] {
			push(&v, fmt.Sprintf("blocks_claims of %s does not rederive", str(r, "id")))
		}
	}

	for _, who := range []string{"authority", "candidate"} {
		interp := objKeys(objKeys(o, who), "interpreter")
		if interp == nil {
			continue
		}
		resolver := objKeys(interp, "resolver")
		if resolver != nil {
			if str(resolver, "kind") != "env" {
				push(&v, fmt.Sprintf("%s interpreter resolver kind must be \"env\"", who))
			}
			if str(resolver, "path") != str(objKeys(interp, "kernel_interpreter"), "path") {
				push(&v, fmt.Sprintf("%s interpreter resolver path must be the kernel interpreter path", who))
			}
		} else {
			kernel := objKeys(interp, "kernel_interpreter")
			down := objKeys(interp, "downstream_interpreter")
			if kernel == nil || down == nil || str(kernel, "path") != str(down, "path") || str(kernel, "sha256") != str(down, "sha256") {
				push(&v, fmt.Sprintf("%s interpreter: without a resolver the kernel must BE the downstream interpreter", who))
			}
		}
	}

	if len(fixtures) >= 1 {
		f := obj(fixtures[0])
		resolved := arrStr(recVal(f, "arguments"))
		declared := arrStr(recVal(f, "declared_arguments"))
		for i := range resolved {
			if i >= len(declared) {
				break
			}
			sub := declared[i] == "{fixture}" || declared[i] == "{output}"
			if resolved[i] != declared[i] && !sub {
				push(&v, fmt.Sprintf("argv[%d] %v is neither the declared argument nor a {fixture}/{output} substitution", i, resolved[i]))
			}
		}
	}

	if pos := arr(recVal(objKeys(o, "claims"), "positive")); len(pos) > 0 {
		push(&v, "v0 receipts carry no positive claims; the claim compiler writes claims/")
	}
	return v
}

func semanticIDs(sems []*jcs.Object) []string {
	var out []string
	for _, s := range sems {
		out = append(out, str(s, "id"))
	}
	return out
}
