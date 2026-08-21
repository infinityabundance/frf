//! Structural + semantic conformance (the document-level rules) and the
//! admissible Claim IR — mirrors of the reference engine's
//! `validate_semantics` and claim compiler, computed from the document
//! alone.

use crate::as_str;
use crate::load_yaml;
use crate::rederive::*;
use serde_json::{json, Value};
use std::path::Path;

const DISPOSITIONS: &[&str] = &[
    "open",
    "fixed",
    "intentional",
    "environmental",
    "oracle_version",
    "harness",
    "unknown",
];
const CLOSURE_PREDICATE: &str =
    "fix-court: same court, authority, fixture, arguments, observables, normalizers, environment; axis equality";
const REQUIRED_RECEIPT_KEYS: &[&str] = &[
    "schema_version",
    "run",
    "court",
    "provenance",
    "comparator_semantics",
    "execution_profile",
    "capture_bounds",
    "authority",
    "candidate",
    "environment",
    "fixtures",
    "observables",
    "residuals",
    "endoduction",
    "claims",
    "replay",
];
const CAPTURE_BOUNDS_KEYS: &[&str] = &[
    "timeout_ms",
    "max_stream_bytes",
    "rlimit_as_mb",
    "rlimit_cpu_s",
    "rlimit_nofile",
];

/// Unknown-key rejection per object kind — the structural mirror of the
/// reference engine's `deny_unknown_fields`: an unknown property is refused,
/// never silently dropped before a content address is recomputed.
fn unknown_keys(obj: &Value, allowed: &[&str]) -> Vec<String> {
    obj.as_object()
        .map(|m| {
            m.keys()
                .filter(|k| !allowed.contains(&k.as_str()))
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

fn hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_valid_identifier(s: &str) -> bool {
    crate::rederive::is_valid_identifier(s)
}

pub fn structural_violations(doc: &Value) -> Vec<String> {
    let mut v = Vec::new();
    if !doc.is_object() {
        return vec!["receipt is not an object".to_string()];
    }
    if as_str(&doc["schema_version"]) != "frf-receipt-v12" {
        v.push(format!(
            "schema_version is {:?}, expected frf-receipt-v12",
            doc["schema_version"]
        ));
    }
    for k in REQUIRED_RECEIPT_KEYS {
        if doc.get(k).is_none() {
            v.push(format!("missing required field {k:?}"));
        }
    }
    for k in unknown_keys(doc, REQUIRED_RECEIPT_KEYS) {
        v.push(format!(
            "unknown property {k:?} on the receipt (strict evidence)"
        ));
    }
    if let Some(run) = doc["run"].as_i64() {
        v.push(format!("run must be a string (found number {run})"));
    }
    for (key, allowed, what) in [
        ("court", COURT_KEYS, "court"),
        ("provenance", PROVENANCE_KEYS, "provenance"),
        ("authority", AUTHORITY_KEYS, "authority"),
        ("candidate", CANDIDATE_KEYS, "candidate"),
        ("environment", ENVIRONMENT_KEYS, "environment"),
        ("endoduction", ENDODUCTION_KEYS, "endoduction"),
        ("claims", CLAIMS_KEYS, "claims"),
        ("replay", REPLAY_KEYS, "replay"),
    ] {
        for k in unknown_keys(&doc[key], allowed) {
            v.push(format!(
                "unknown property {k:?} on receipt.{what} (strict evidence)"
            ));
        }
    }
    for k in unknown_keys(&doc["court"]["admissibility_envelope"], ENVELOPE_KEYS) {
        v.push(format!(
            "unknown property {k:?} on the admissibility envelope"
        ));
    }
    for k in unknown_keys(&doc["capture_bounds"], CAPTURE_BOUNDS_KEYS) {
        v.push(format!("unknown property {k:?} on capture_bounds"));
    }
    for k in unknown_keys(&doc["provenance"]["runner"], RUNNER_KEYS) {
        v.push(format!("unknown property {k:?} on provenance.runner"));
    }
    if let Some(impls) = doc["provenance"]["comparator_implementations"].as_array() {
        for (i, c) in impls.iter().enumerate() {
            for k in unknown_keys(c, COMPARATOR_IMPL_KEYS) {
                v.push(format!(
                    "unknown property {k:?} on comparator_implementations[{i}]"
                ));
            }
            if let Some(artifact) = c.get("artifact") {
                for k in unknown_keys(artifact, ARTIFACT_KEYS) {
                    v.push(format!(
                        "unknown property {k:?} on comparator_implementations[{i}].artifact"
                    ));
                }
                if !hex64(as_str(&artifact["sha256"])) {
                    v.push(format!(
                        "comparator_implementations[{i}].artifact.sha256 must be 64 hex"
                    ));
                }
            }
        }
    }
    if let Some(sems) = doc["comparator_semantics"].as_array() {
        for (i, c) in sems.iter().enumerate() {
            for k in unknown_keys(c, COMPARATOR_SEMANTIC_KEYS) {
                v.push(format!(
                    "unknown property {k:?} on comparator_semantics[{i}]"
                ));
            }
            if !hex64(as_str(&c["specification_hash"])) {
                v.push(format!(
                    "comparator_semantics[{i}].specification_hash must be 64 hex"
                ));
            }
        }
    }
    if let Some(fixtures) = doc["fixtures"].as_array() {
        for (i, f) in fixtures.iter().enumerate() {
            for k in unknown_keys(f, FIXTURE_KEYS) {
                v.push(format!("unknown property {k:?} on fixtures[{i}]"));
            }
        }
    }
    if let Some(obs) = doc["observables"].as_array() {
        for (i, o) in obs.iter().enumerate() {
            for k in unknown_keys(o, OBSERVABLE_KEYS) {
                v.push(format!("unknown property {k:?} on observables[{i}]"));
            }
            for what in ["comparator_request", "comparator_result"] {
                if let Some(cid) = o.get(what) {
                    if !hex64(as_str(cid)) {
                        v.push(format!(
                            "observables[{i}].{what} must be a 64-hex content address"
                        ));
                    }
                }
            }
        }
    }
    for who in ["authority", "candidate"] {
        if let Some(interp) = doc[who]["interpreter"].as_object() {
            for k in unknown_keys(&doc[who]["interpreter"], INTERPRETER_KEYS) {
                v.push(format!("unknown property {k:?} on {who}.interpreter"));
            }
            if let Some(resolver) = interp.get("resolver") {
                for k in unknown_keys(resolver, RESOLVER_KEYS) {
                    v.push(format!(
                        "unknown property {k:?} on {who}.interpreter.resolver"
                    ));
                }
            }
            for part in ["kernel_interpreter", "downstream_interpreter"] {
                for k in unknown_keys(&doc[who]["interpreter"][part], INTERPRETER_EXEC_KEYS) {
                    v.push(format!(
                        "unknown property {k:?} on {who}.interpreter.{part}"
                    ));
                }
            }
        }
    }
    if let Some(residuals) = doc["residuals"].as_array() {
        for (i, r) in residuals.iter().enumerate() {
            if !r.is_object() {
                v.push("residual entry is not an object".to_string());
                continue;
            }
            for k in unknown_keys(r, RESIDUAL_KEYS) {
                v.push(format!("unknown property {k:?} on residuals[{i}]",));
            }
            for k in unknown_keys(&r["sign"], SIGN_KEYS) {
                v.push(format!("unknown property {k:?} on residuals[{i}].sign"));
            }
            if let Some(entries) = r["sign"]["trajectory_evidence"].as_array() {
                for (j, entry) in entries.iter().enumerate() {
                    for k in unknown_keys(entry, TRAJECTORY_EVIDENCE_KEYS) {
                        v.push(format!(
                            "unknown property {k:?} on residuals[{i}].sign.trajectory_evidence[{j}]"
                        ));
                    }
                }
            }
            if !is_valid_identifier(as_str(&r["kind"])) {
                v.push(format!(
                    "residual {:?} has invalid kind {:?}",
                    r["id"], r["kind"]
                ));
            }
            let d = as_str(&r["disposition"]);
            if !DISPOSITIONS.contains(&d) {
                v.push(format!(
                    "residual {:?} has unknown disposition {:?}",
                    r["id"], r["disposition"]
                ));
            }
        }
    }
    if let Some(tokens) = doc["endoduction"]["tokens"].as_array() {
        for (i, t) in tokens.iter().enumerate() {
            for k in unknown_keys(t, TOKEN_KEYS) {
                v.push(format!("unknown property {k:?} on endoduction.tokens[{i}]"));
            }
        }
    }
    v
}

const COURT_KEYS: &[&str] = &[
    "id",
    "question",
    "falsifier",
    "admissibility_envelope",
    "semantic_identity",
];
const ENVELOPE_KEYS: &[&str] = &[
    "authority_versions",
    "fixture_family",
    "platforms",
    "observables",
    "normalizers",
    "replay_scope",
];
const PROVENANCE_KEYS: &[&str] = &["schema_version", "runner", "comparator_implementations"];
const RUNNER_KEYS: &[&str] = &["schema_version", "frf_version", "frf_executable_hash"];
const COMPARATOR_IMPL_KEYS: &[&str] = &["id", "implementation_hash", "runner_hash", "artifact"];
const ARTIFACT_KEYS: &[&str] = &["path", "sha256", "interpreter"];
const COMPARATOR_SEMANTIC_KEYS: &[&str] = &[
    "id",
    "relation_id",
    "extractor",
    "residual_classifier",
    "relation_version",
    "specification_hash",
];
const AUTHORITY_KEYS: &[&str] = &[
    "name",
    "kind",
    "version",
    "identity_hash",
    "provenance",
    "interpreter",
];
const CANDIDATE_KEYS: &[&str] = &[
    "name",
    "version_or_commit",
    "build_profile",
    "identity_hash",
    "interpreter",
];
const INTERPRETER_KEYS: &[&str] = &[
    "kernel_interpreter",
    "shebang_argument_bytes",
    "resolver",
    "downstream_interpreter",
];
const INTERPRETER_EXEC_KEYS: &[&str] = &["path", "sha256"];
const RESOLVER_KEYS: &[&str] = &["kind", "path", "sha256", "path_digest"];
const ENVIRONMENT_KEYS: &[&str] = &[
    "schema_version",
    "os",
    "architecture",
    "kernel_release",
    "locale",
    "timezone",
    "umask",
    "cwd",
    "digest",
];
const FIXTURE_KEYS: &[&str] = &["id", "hash", "arguments", "declared_arguments"];
const OBSERVABLE_KEYS: &[&str] = &[
    "axis",
    "raw_reference_hash",
    "raw_candidate_hash",
    "comparator",
    "normalization_rules",
    "verdict",
    "comparator_request",
    "comparator_result",
];
const RESIDUAL_KEYS: &[&str] = &[
    "id",
    "axis",
    "kind",
    "sign",
    "grammar_state",
    "raw_reference_hash",
    "raw_candidate_hash",
    "invariant",
    "reproducer",
    "residual_fingerprint",
    "disposition",
    "disposition_event_id",
    "reason",
    "resolution_run_id",
    "closure_predicate",
];
const SIGN_KEYS: &[&str] = &["trajectory_evidence"];
const TRAJECTORY_EVIDENCE_KEYS: &[&str] = &["coordinate_system", "series", "drift", "slew"];
const ENDODUCTION_KEYS: &[&str] = &["schema_version", "tokens"];
const TOKEN_KEYS: &[&str] = &["residual_id", "token", "next_court", "blocks_claims"];
const CLAIMS_KEYS: &[&str] = &["positive", "non_claims", "blocked_by_open_residuals"];
const REPLAY_KEYS: &[&str] = &["program", "evidence_root", "argv", "expected_run_identity"];

pub fn semantic_violations(rec: &Value) -> Vec<String> {
    let mut v = Vec::new();
    if as_str(&rec["schema_version"]) != "frf-receipt-v12" {
        v.push(format!(
            "schema_version is {:?}, expected frf-receipt-v12",
            rec["schema_version"]
        ));
    }
    let fixtures = rec["fixtures"].as_array().cloned().unwrap_or_default();
    if fixtures.len() != 1 {
        v.push(format!(
            "exactly one fixture is required (found {})",
            fixtures.len()
        ));
    }
    let envelope = &rec["court"]["admissibility_envelope"];
    if as_str(&envelope["replay_scope"]) != "single-run" {
        v.push(format!(
            "replay_scope {:?} is not executable in v0",
            envelope["replay_scope"]
        ));
    }

    let mut declared: Vec<String> = Vec::new();
    for axis in envelope["observables"]
        .as_array()
        .cloned()
        .unwrap_or_default()
    {
        let axis = as_str(&axis).to_string();
        if !is_valid_identifier(&axis) {
            v.push(format!("invalid observable axis identifier {axis:?}"));
        }
        if declared.contains(&axis) {
            v.push(format!("duplicate declared observable axis {axis:?}"));
        } else {
            declared.push(axis);
        }
    }

    let mut obs_axes: Vec<String> = Vec::new();
    for obs in rec["observables"].as_array().cloned().unwrap_or_default() {
        let axis = as_str(&obs["axis"]).to_string();
        if !is_valid_identifier(&axis) {
            v.push(format!("observable with invalid axis identifier {axis:?}"));
        }
        if !declared.contains(&axis) {
            v.push(format!("observable {axis} is not declared in the envelope"));
        }
        if obs_axes.contains(&axis) {
            v.push(format!("duplicate observable block for axis {axis}"));
        } else {
            obs_axes.push(axis.clone());
        }
        // An observable's comparator binding is all-or-nothing.
        let req = obs.get("comparator_request").map(as_str);
        let res = obs.get("comparator_result").map(as_str);
        match (req, res) {
            (None, None) => {}
            (Some(r), Some(r2)) => {
                if !hex64(r) || !hex64(r2) {
                    v.push(format!(
                        "observable {axis} comparator_request/comparator_result must be 64-hex content addresses"
                    ));
                }
            }
            _ => v.push(format!(
                "observable {axis} binds only one of comparator_request/comparator_result — an external verdict binds both, an in-binary verdict binds neither"
            )),
        }
    }

    let semantics = rec["comparator_semantics"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut sem_ids: Vec<String> = Vec::new();
    for c in &semantics {
        let id = as_str(&c["id"]).to_string();
        if sem_ids.contains(&id) {
            v.push(format!("duplicate comparator semantic id {id}"));
        } else {
            sem_ids.push(id.clone());
        }
        if !obs_axes.contains(&id) {
            v.push(format!("comparator semantic {id} serves no observable"));
        }
        // The specification hash REDERIVES from the record's own fields.
        let expected = comparator_spec_hash(
            &id,
            as_str(&c["relation_id"]),
            as_str(&c["extractor"]),
            as_str(&c["residual_classifier"]),
        );
        if expected != as_str(&c["specification_hash"]) {
            v.push(format!(
                "comparator semantic {id}: the specification_hash does not rederive from its own fields"
            ));
        }
    }
    for obs in rec["observables"].as_array().cloned().unwrap_or_default() {
        let n = semantics
            .iter()
            .filter(|c| as_str(&c["id"]) == as_str(&obs["axis"]))
            .count();
        if n != 1 {
            v.push(format!(
                "observable {} must have exactly one comparator semantic (found {n})",
                as_str(&obs["axis"])
            ));
        }
    }

    let impls = rec["provenance"]["comparator_implementations"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if impls.len() != semantics.len() {
        v.push(
            "comparator_implementations must mirror comparator_semantics one-to-one".to_string(),
        );
    }
    for c in &semantics {
        if !impls.iter().any(|i| as_str(&i["id"]) == as_str(&c["id"])) {
            v.push(format!(
                "comparator semantic {} has no implementation provenance",
                as_str(&c["id"])
            ));
        }
    }

    let family = as_str(&envelope["fixture_family"]).to_string();
    let mut residual_ids: Vec<String> = Vec::new();
    for r in rec["residuals"].as_array().cloned().unwrap_or_default() {
        let rid = as_str(&r["id"]).to_string();
        if residual_ids.contains(&rid) {
            v.push(format!("duplicate residual id {rid}"));
        } else {
            residual_ids.push(rid.clone());
        }
        if !declared.contains(&as_str(&r["axis"]).to_string()) {
            v.push(format!(
                "residual {rid} axis {} is not a declared observable",
                as_str(&r["axis"])
            ));
        }
        // The residual kind is the axis's comparator's residual classifier.
        let classifier = semantics
            .iter()
            .find(|c| as_str(&c["id"]) == as_str(&r["axis"]))
            .map(|c| as_str(&c["residual_classifier"]).to_string());
        if classifier.as_deref() != Some(as_str(&r["kind"])) {
            v.push(format!(
                "residual {rid} kind {:?} is inconsistent with the {} axis's residual classifier {:?}",
                r["kind"],
                as_str(&r["axis"]),
                classifier.unwrap_or_else(|| "<none>".to_string())
            ));
        }
        let d = as_str(&r["disposition"]).to_string();
        match d.as_str() {
            "open" => {
                if r.get("reason").is_some() {
                    v.push(format!("open residual {rid} carries a reason"));
                }
                if r.get("resolution_run_id").is_some() {
                    v.push(format!("open residual {rid} carries a resolution_run_id"));
                }
                if r.get("closure_predicate").is_some() {
                    v.push(format!("open residual {rid} carries a closure_predicate"));
                }
                if r.get("disposition_event_id")
                    .and_then(|x| x.as_str())
                    .is_some()
                {
                    v.push(format!(
                        "open residual {rid} carries a disposition_event_id"
                    ));
                }
            }
            "fixed" => {
                if r.get("reason").is_none() {
                    v.push(format!("fixed residual {rid} without a reason"));
                }
                if r.get("resolution_run_id").is_none() {
                    v.push(format!("fixed residual {rid} without a resolution_run_id"));
                }
                if as_str(&r["closure_predicate"]) != CLOSURE_PREDICATE {
                    v.push(format!(
                        "fixed residual {rid} must carry the fix-court closure predicate"
                    ));
                }
                if r.get("disposition_event_id")
                    .and_then(|x| x.as_str())
                    .is_none()
                {
                    v.push(format!(
                        "fixed residual {rid} without a disposition_event_id"
                    ));
                }
            }
            other => {
                if !DISPOSITIONS.contains(&other) {
                    v.push(format!("residual {rid} has unknown disposition {other:?}"));
                }
                if r.get("reason").is_none() {
                    v.push(format!("{other} residual {rid} requires a reason"));
                }
                if r.get("resolution_run_id").is_some() {
                    v.push(format!(
                        "{other} residual {rid} carries a resolution_run_id"
                    ));
                }
                if r.get("closure_predicate").is_some() {
                    v.push(format!(
                        "{other} residual {rid} carries a closure_predicate"
                    ));
                }
                if r.get("disposition_event_id")
                    .and_then(|x| x.as_str())
                    .is_none()
                {
                    v.push(format!(
                        "{other} residual {rid} without a disposition_event_id"
                    ));
                }
            }
        }
        let grammar = match d.as_str() {
            "open" => "violation",
            "fixed" => "recovery",
            "intentional" => "intentional_divergence",
            "environmental" | "oracle_version" | "harness" => "boundary",
            _ => "unknown",
        };
        if as_str(&r["grammar_state"]) != grammar {
            v.push(format!(
                "grammar_state of {rid} is {:?}, expected {grammar:?}",
                r["grammar_state"]
            ));
        }
        let sign = &r["sign"];
        // v12: the sign is TRAJECTORY EVIDENCE per coordinate system — a
        // residual does not have one universal drift, it has a trajectory
        // with respect to a coordinate system. A single-run receipt honestly
        // carries NO entries; every entry names a closed vocabulary
        // coordinate system (at most once), a non-empty pinned series, and
        // well-formed drift/slew.
        let mut seen_coordinates: Vec<&str> = Vec::new();
        if let Some(entries) = sign["trajectory_evidence"].as_array() {
            for entry in entries {
                if ![
                    "repeat_index",
                    "candidate_revision",
                    "authority_version",
                    "environment",
                    "time",
                ]
                .contains(&as_str(&entry["coordinate_system"]))
                {
                    v.push(format!(
                        "residual {rid} names unknown trajectory coordinate system {:?}",
                        entry["coordinate_system"]
                    ));
                }
                if seen_coordinates.contains(&as_str(&entry["coordinate_system"])) {
                    v.push(format!(
                        "residual {rid} names coordinate system {:?} twice in its trajectory evidence",
                        entry["coordinate_system"]
                    ));
                }
                seen_coordinates.push(as_str(&entry["coordinate_system"]));
                if as_str(&entry["series"]).is_empty() {
                    v.push(format!(
                        "residual {rid} has trajectory evidence without a pinned series"
                    ));
                }
                if !["persistent", "transient", "recurrent"].contains(&as_str(&entry["drift"])) {
                    v.push(format!(
                        "residual {rid} has invalid drift {:?} in its trajectory evidence",
                        entry["drift"]
                    ));
                }
                if !["stable", "abrupt", "burst", "recurrent"].contains(&as_str(&entry["slew"])) {
                    v.push(format!(
                        "residual {rid} has invalid slew {:?} in its trajectory evidence",
                        entry["slew"]
                    ));
                }
            }
        }
        if as_str(&r["reproducer"]) != as_str(&rec["run"]) {
            v.push(format!(
                "residual {rid} reproducer must be the receipt's run"
            ));
        }
    }

    for obs in rec["observables"].as_array().cloned().unwrap_or_default() {
        let axis = as_str(&obs["axis"]).to_string();
        let has = rec["residuals"]
            .as_array()
            .map(|rs| rs.iter().any(|r| as_str(&r["axis"]) == axis))
            .unwrap_or(false);
        if as_str(&obs["verdict"]) == "pass" && has {
            v.push(format!("pass verdict on {axis} while a residual exists"));
        }
        if as_str(&obs["verdict"]) == "residual" && !has {
            v.push(format!("residual verdict on {axis} without any residual"));
        }
    }

    let env = &rec["environment"];
    if env_digest(
        as_str(&env["os"]),
        as_str(&env["architecture"]),
        as_str(&env["kernel_release"]),
        as_str(&env["locale"]),
        as_str(&env["timezone"]),
        as_str(&env["umask"]),
    ) != as_str(&env["digest"])
    {
        v.push("the environment digest does not rederive".to_string());
    }

    // The execution profile is a valid protocol identifier, and the capture
    // bounds are positive integers within the protocol's maxima.
    if !is_valid_identifier(as_str(&rec["execution_profile"])) {
        v.push(format!(
            "invalid execution_profile identifier {:?}",
            rec["execution_profile"]
        ));
    }
    let bounds = &rec["capture_bounds"];
    for (what, max) in [
        ("timeout_ms", 3_600_000u64),
        ("max_stream_bytes", 1u64 << 30),
        ("rlimit_as_mb", 65_536u64),
        ("rlimit_cpu_s", 86_400u64),
        ("rlimit_nofile", 1_048_576u64),
    ] {
        let v_str = as_str(&bounds[what]);
        match v_str.parse::<u64>() {
            Ok(n) if n > 0 && n <= max => {}
            _ => v.push(format!(
                "capture bound {what} must be a positive integer within the protocol maximum {max}, got {v_str:?}"
            )),
        }
    }

    match court_semantic_identity_from_receipt(rec) {
        id if id == as_str(&rec["court"]["semantic_identity"]) => {}
        _ => v.push("the court semantic identity does not rederive from the document".to_string()),
    }

    let replay = &rec["replay"];
    if as_str(&replay["program"]) != "frf" {
        v.push("replay.program must be \"frf\"".to_string());
    }
    if as_str(&replay["expected_run_identity"]) != as_str(&rec["run"]) {
        v.push("replay.expected_run_identity must equal the receipt's run".to_string());
    }
    let argv = replay["argv"].as_array().cloned().unwrap_or_default();
    if argv.len() < 5
        || as_str(&argv[0]) != "--root"
        || as_str(&argv[2]) != "court"
        || as_str(&argv[3]) != "run"
    {
        v.push("replay.argv must be a court-run invocation".to_string());
    }

    let tokens = rec["endoduction"]["tokens"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if tokens.len() != rec["residuals"].as_array().map(|a| a.len()).unwrap_or(0) {
        v.push("endoduction tokens must mirror residuals one-to-one".to_string());
    }
    for (r, t) in rec["residuals"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .zip(tokens.iter())
    {
        if as_str(&t["residual_id"]) != as_str(&r["id"]) {
            v.push(format!(
                "token bound to {} but the residual is {}",
                t["residual_id"], r["id"]
            ));
            continue;
        }
        if as_str(&t["token"]) != expected_token(r) {
            v.push(format!("token of {} does not rederive", r["id"]));
        }
        if as_str(&t["next_court"]) != kappa_next(r) {
            v.push(format!("next_court of {} does not rederive", r["id"]));
        }
        if as_str(&t["blocks_claims"][0]) != expected_blocks(r, &family) {
            v.push(format!("blocks_claims of {} does not rederive", r["id"]));
        }
    }

    for who in ["authority", "candidate"] {
        let interp = rec[who].get("interpreter").cloned();
        if let Some(interp) = interp {
            if let Some(resolver) = interp.get("resolver") {
                if as_str(&resolver["kind"]) != "env" {
                    v.push(format!("{who} interpreter resolver kind must be \"env\""));
                }
                if as_str(&resolver["path"]) != as_str(&interp["kernel_interpreter"]["path"]) {
                    v.push(format!(
                        "{who} interpreter resolver path must be the kernel interpreter path"
                    ));
                }
            } else if interp.get("kernel_interpreter") != interp.get("downstream_interpreter") {
                v.push(format!(
                    "{who} interpreter: without a resolver the kernel must BE the downstream interpreter"
                ));
            }
        }
    }

    if let Some(f) = fixtures.first() {
        let resolved = f["arguments"].as_array().cloned().unwrap_or_default();
        let declared = f["declared_arguments"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        for (i, (resolved_arg, declared_arg)) in resolved.iter().zip(declared.iter()).enumerate() {
            let is_substitution =
                as_str(declared_arg) == "{fixture}" || as_str(declared_arg) == "{output}";
            if as_str(resolved_arg) != as_str(declared_arg) && !is_substitution {
                v.push(format!(
                    "argv[{i}] {:?} is neither the declared argument nor a {{fixture}}/{{output}} substitution",
                    resolved_arg
                ));
            }
        }
    }

    if let Some(pos) = rec["claims"]["positive"].as_array() {
        if !pos.is_empty() {
            v.push(
                "v0 receipts carry no positive claims; the claim compiler writes claims/"
                    .to_string(),
            );
        }
    }

    v
}

// ---------------------------------------------------------------------------
// The admissible Claim IR — mirrors the claim compiler's scope algebra
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct ClaimIr {
    pub admissible: bool,
    pub harness_invalidated: bool,
    pub observable_scope: Vec<String>,
    pub excluded_evidence: Vec<String>,
    pub blockers: Vec<String>,
}

pub fn projected_disposition(bundle: &Path, rid: &str) -> String {
    let ev_dir = bundle.join(format!("residuals/{rid}.events"));
    let mut events: Vec<Value> = Vec::new();
    if ev_dir.is_dir() {
        let mut names: Vec<String> = std::fs::read_dir(&ev_dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.ends_with(".yaml"))
            .collect();
        names.sort();
        events = names.iter().map(|n| load_yaml(&ev_dir.join(n))).collect();
    }
    events
        .last()
        .map(|e| as_str(&e["disposition"]).to_string())
        .unwrap_or_else(|| "open".to_string())
}

/// The surface of a residual: where the divergence was observed, derived
/// from the immutable record + its run's capture + the admitted authority.
fn residual_scope(record: &Value, cap: &Value, authorities: &BTreeMapLike) -> Value {
    let env = &cap["court_spec"]["admissibility_envelope"];
    let authority_id = as_str(&record["authority"]);
    let authority = authorities.get(authority_id).unwrap_or_else(|| {
        panic!(
            "residual {} cites authority {authority_id} which is missing from the bundle",
            as_str(&record["id"])
        )
    });
    json!({
        "authority": [authority_id],
        "candidate": [as_str(&record["candidate_sha256"])],
        "fixtures": [as_str(&cap["fixture"])],
        "fixture_family": as_str(&env["fixture_family"]),
        "observables": [as_str(&record["axis"])],
        "environments": [as_str(&cap["environment"]["digest"])],
        "versions": [as_str(&authority["version"])],
        "temporal": [as_str(&record["run"])],
    })
}

type BTreeMapLike = std::collections::BTreeMap<String, Value>;

/// The scope K of a claim compiled from a receipt: the executed surface
/// restricted to the clean axes.
fn claim_scope(rec: &Value) -> Value {
    let envelope = &rec["court"]["admissibility_envelope"];
    let clean: Vec<String> = rec["observables"]
        .as_array()
        .map(|obs| {
            obs.iter()
                .filter(|o| {
                    !rec["residuals"]
                        .as_array()
                        .map(|rs| rs.iter().any(|r| as_str(&r["axis"]) == as_str(&o["axis"])))
                        .unwrap_or(false)
                })
                .map(|o| as_str(&o["axis"]).to_string())
                .collect()
        })
        .unwrap_or_default();
    json!({
        "authority": [format!("{}-{}", as_str(&rec["authority"]["name"]), as_str(&rec["authority"]["version"]))],
        "candidate": [as_str(&rec["candidate"]["identity_hash"])],
        "fixtures": rec["fixtures"].as_array().map(|fs| {
            fs.iter().map(|f| as_str(&f["id"]).to_string()).collect::<Vec<_>>()
        }).unwrap_or_default(),
        "fixture_family": as_str(&envelope["fixture_family"]),
        "observables": clean,
        "environments": [as_str(&rec["environment"]["digest"])],
        "versions": envelope["authority_versions"].as_array().map(|vs| {
            vs.iter().map(as_str).map(str::to_string).collect::<Vec<_>>()
        }).unwrap_or_default(),
        "temporal": [as_str(&rec["run"])],
    })
}

fn scopes_intersect(a: &Value, b: &Value) -> bool {
    let overlap = |x: &Value, y: &Value| {
        x.as_array()
            .map(|xa| {
                xa.iter().any(|v| {
                    y.as_array()
                        .map(|ya| ya.iter().any(|w| v == w))
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    };
    overlap(&a["authority"], &b["authority"])
        && overlap(&a["candidate"], &b["candidate"])
        && overlap(&a["fixtures"], &b["fixtures"])
        && overlap(&a["observables"], &b["observables"])
        && overlap(&a["environments"], &b["environments"])
        && overlap(&a["versions"], &b["versions"])
        && as_str(&a["fixture_family"]) == as_str(&b["fixture_family"])
}

/// Mirror of the claim compiler's dependency algebra over the bundle's
/// closure: a claim is admissible iff its scope K is non-empty, no premise
/// run is harness-invalidated, and no `open`/`unknown` residual in the
/// bundle intersects K (wherever it was recorded — the cross-run rule).
pub fn claim_ir(rec: &Value, bundle: &Path) -> ClaimIr {
    let residuals = rec["residuals"].as_array().cloned().unwrap_or_default();
    let harness = residuals
        .iter()
        .filter(|r| as_str(&r["disposition"]) == "harness")
        .count()
        > 0;
    let k = claim_scope(rec);
    let no_clean_axis = k["observables"]
        .as_array()
        .map(|a| a.is_empty())
        .unwrap_or(true);

    let mut blockers: Vec<String> = Vec::new();
    if !harness && !no_clean_axis {
        let res_dir = bundle.join("residuals");
        let cap_dir = bundle.join("captures");
        let auth_dir = bundle.join("authorities");
        let mut records: BTreeMapLike = BTreeMapLike::new();
        if res_dir.is_dir() {
            for entry in std::fs::read_dir(&res_dir).unwrap().flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.ends_with(".yaml") && !name.ends_with(".token.yaml") {
                    let rid = name.trim_end_matches(".yaml").to_string();
                    records.insert(rid.clone(), load_yaml(&res_dir.join(name)));
                }
            }
        }
        let mut captures: BTreeMapLike = BTreeMapLike::new();
        if cap_dir.is_dir() {
            for entry in std::fs::read_dir(&cap_dir).unwrap().flatten() {
                let run = entry.file_name().to_string_lossy().to_string();
                let cap_path = cap_dir.join(&run).join("capture.yaml");
                if cap_path.is_file() {
                    captures.insert(run, load_yaml(&cap_path));
                }
            }
        }
        let mut authorities: BTreeMapLike = BTreeMapLike::new();
        if auth_dir.is_dir() {
            for entry in std::fs::read_dir(&auth_dir).unwrap().flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.ends_with(".yaml") {
                    let id = name.trim_end_matches(".yaml").to_string();
                    authorities.insert(id, load_yaml(&auth_dir.join(name)));
                }
            }
        }
        for rid in records.keys() {
            if !matches!(
                projected_disposition(bundle, rid).as_str(),
                "open" | "unknown"
            ) {
                continue;
            }
            let record = &records[rid];
            let run = as_str(&record["run"]);
            let Some(cap) = captures.get(run) else {
                panic!("residual {rid}: its run's capture is missing from the bundle");
            };
            if scopes_intersect(&residual_scope(record, cap, &authorities), &k) {
                blockers.push(rid.clone());
            }
        }
        blockers.sort();
    }

    ClaimIr {
        admissible: !harness && !no_clean_axis && blockers.is_empty(),
        harness_invalidated: harness,
        observable_scope: k["observables"]
            .as_array()
            .map(|a| a.iter().map(as_str).map(str::to_string).collect())
            .unwrap_or_default(),
        excluded_evidence: residuals
            .iter()
            .map(|r| as_str(&r["id"]).to_string())
            .collect(),
        blockers,
    }
}
