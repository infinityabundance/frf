//! The documentation-consistency seal: the closed enumerations the protocol
//! and the specs declare are EXACTLY the enumerations the code implements.
//! A documented value the code does not implement — or an implemented value
//! the docs do not list — is protocol drift, caught here.
//!
//!   - the capture-surface policy vocabulary (spec/publication-surface.md);
//!   - the reduction minimality predicate kinds (spec/reduction.md);
//!   - the reduction attempt roles (spec/reduction.md);
//!   - the claim admission policies (the protocol registry `policies`);
//!   - the execution profiles (the protocol registry `execution_profiles`);
//!   - the reference capture-bounds defaults (spec/execution-profile.md);
//!   - the corpus publication mode (detached: spec/detached-objects.md).

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn registry() -> serde_json::Value {
    serde_json::from_str(
        &std::fs::read_to_string(repo_root().join("protocol/registry.json"))
            .expect("protocol/registry.json must exist"),
    )
    .expect("protocol/registry.json must be valid JSON")
}

/// The capture-surface policy vocabulary is closed and documented: the five
/// policies the code implements are exactly the five the spec lists.
#[test]
fn capture_surface_policies_match_the_spec_vocabulary() {
    let spec_policies: Vec<&str> = vec![
        "inline",
        "hash-only",
        "redacted-with-commitment",
        "detached",
        "synthetic-publication",
    ];
    assert_eq!(
        frf::model::CaptureSurfacePolicy::POLICIES.to_vec(),
        spec_policies,
        "an implemented surface policy the spec does not list (or vice versa) is drift"
    );
    // Every policy's withholding behavior is the documented one.
    assert!(!frf::model::CaptureSurfacePolicy {
        side: "candidate".into(),
        stream: "stdout".into(),
        policy: "inline".into(),
    }
    .withholds_bytes());
    for policy in ["hash-only", "detached"] {
        assert!(frf::model::CaptureSurfacePolicy {
            side: "candidate".into(),
            stream: "stdout".into(),
            policy: policy.into(),
        }
        .withholds_bytes());
    }
}

/// The reduction minimality predicates are exactly the two documented kinds.
#[test]
fn reduction_minimality_kinds_match_the_spec() {
    assert_eq!(
        frf::model::ReductionMinimality::KINDS.to_vec(),
        vec!["one-minimal", "boundary"],
        "spec/reduction.md documents exactly these two predicate kinds"
    );
    // The semantic validator's unknown-kind refusal names the same set (a
    // kind the validator accepts must be in the const, and vice versa).
    let zeros = "0".repeat(64);
    let record: frf::model::ReductionRecord = serde_json::from_str(&format!(
        r#"{{"schema_version":"frf-reduction-v4","id":"{z}","residual_id":"r","source_run":"s","axis":"exit","kind":"exit","court_semantic_identity":"{z}","authority_artifact_sha256":"{z}","candidate_artifact_sha256":"{z}","environment_digest":"{z}","comparator_semantic_id":"exit","comparator_semantic_hash":"{z}","comparator_implementation_hash":"{z}","argv_template":[],"original_fixture_sha256":"{z}","final_fixture_sha256":"{z}","attempts":[],"derivation":{{"strategy":"x","original_lines":"1","final_lines":"1","minimality":{{"kind":"bogus-kind","proven":false}}}},"transform":{{"kind":"reduction","source":"r","observation_relation":"eq(x)","success_predicate":"lineage-survives","invariant_dimensions":["candidate"],"varying_dimensions":["fixture"]}}}}"#,
        z = zeros
    ))
    .expect("the fixture must deserialize");
    let err = record
        .validate_semantics()
        .expect_err("an unknown minimality kind must be refused");
    assert!(
        err.contains("unknown minimality kind") && err.contains("one-minimal | boundary"),
        "the refusal names the documented vocabulary: {err}"
    );
}

/// The reduction attempt roles serialize exactly as the spec documents them.
#[test]
fn reduction_attempt_roles_match_the_spec() {
    use frf::model::ReductionAttemptRole as Role;
    assert_eq!(Role::Baseline.as_str(), "baseline");
    assert_eq!(Role::Candidate.as_str(), "candidate");
    assert_eq!(Role::BoundaryControl.as_str(), "boundary_control");
    assert_eq!(Role::FinalVerification.as_str(), "final_verification");
}

/// The claim admission policies the engine implements are exactly the
/// registry's `policies`.
#[test]
fn claim_policies_match_the_registry() {
    use frf::model::{
        CLAIM_POLICY_BASELINE, CLAIM_POLICY_HIGH_ASSURANCE, CLAIM_POLICY_INDEPENDENTLY_WITNESSED,
        CLAIM_POLICY_SENSITIVITY_BACKED,
    };
    let implemented = [
        CLAIM_POLICY_BASELINE,
        CLAIM_POLICY_SENSITIVITY_BACKED,
        CLAIM_POLICY_INDEPENDENTLY_WITNESSED,
        CLAIM_POLICY_HIGH_ASSURANCE,
    ];
    let registered: Vec<String> = registry()["policies"]
        .as_array()
        .expect("the registry must list policies")
        .iter()
        .filter(|p| p["status"] == "active")
        .map(|p| p["id"].as_str().expect("policy id").to_string())
        .collect();
    assert_eq!(
        implemented.to_vec(),
        registered.as_slice(),
        "the implemented admission policies must be exactly the registry's active policies"
    );
}

/// The execution profiles the engine implements are exactly the registry's
/// `execution_profiles`.
#[test]
fn execution_profiles_match_the_registry() {
    use frf::model::{
        EXECUTION_PROFILE_LINUX, EXECUTION_PROFILE_LINUX_V2, EXECUTION_PROFILE_LINUX_V3,
        EXECUTION_PROFILE_OCI,
    };
    let implemented = [
        EXECUTION_PROFILE_LINUX,
        EXECUTION_PROFILE_LINUX_V2,
        EXECUTION_PROFILE_LINUX_V3,
        EXECUTION_PROFILE_OCI,
    ];
    let registered: Vec<String> = registry()["execution_profiles"]
        .as_array()
        .expect("the registry must list execution profiles")
        .iter()
        .filter(|p| p["status"] == "active")
        .map(|p| p["id"].as_str().expect("profile id").to_string())
        .collect();
    assert_eq!(
        implemented.to_vec(),
        registered.as_slice(),
        "the implemented execution profiles must be exactly the registry's active profiles"
    );
}

/// The REFERENCE capture bounds are exactly the defaults spec/execution-
/// profile.md documents (the bounds a claim's high-assurance tier requires).
#[test]
fn reference_capture_bounds_match_the_spec_defaults() {
    let b = frf::host::reference_capture_bounds();
    assert_eq!(b.timeout_ms, "60000", "spec: timeout_ms default 60000");
    assert_eq!(
        b.max_stream_bytes, "16777216",
        "spec: max_stream_bytes default 16777216"
    );
    assert_eq!(
        b.produced_max_files, "4096",
        "spec: produced_max_files 4096"
    );
    assert_eq!(
        b.produced_max_bytes, "268435456",
        "spec: produced_max_bytes 268435456"
    );
    assert_eq!(
        b.produced_max_file_bytes, "16777216",
        "spec: produced_max_file_bytes 16777216"
    );
    assert_eq!(b.rlimit_as_mb, "2048", "spec: rlimit_as_mb 2048");
    assert_eq!(b.rlimit_cpu_s, "30", "spec: rlimit_cpu_s 30");
    assert_eq!(b.rlimit_nofile, "1024", "spec: rlimit_nofile 1024");
    assert_eq!(b.rlimit_nproc, "4096", "spec: rlimit_nproc 4096");
    // The reference profile records no cgroup envelope.
    assert_eq!(b.cgroup_pids_max, None);
}

/// The v3 corpus's publication mode is DETACHED (spec/detached-objects.md):
/// the published evidence tree carries the detached-objects declaration and
/// the publication manifest, and the probes are withheld — the publication
/// boundary the whole security review enforced.
#[test]
fn corpus_publication_mode_is_detached() {
    let ev = repo_root().join("external-corpus/v3/heartbleed/evidence");
    assert!(
        ev.join("detached-objects.json").is_file(),
        "a detached publication carries the declaration"
    );
    assert!(
        ev.join("publication-manifest.json").is_file(),
        "a detached publication carries the explicit stream-disposition manifest"
    );
    // No probe payload bytes anywhere in the published tree (the sibling
    // gate tests/prohibited_payloads.rs proves it for the WHOLE repo).
    let store = frf::store::Store::new(ev.clone());
    let declaration = store
        .load_detached_objects()
        .expect("the declaration must load")
        .expect("the declaration must exist");
    assert!(
        !declaration.objects.is_empty(),
        "payloads are declared detached"
    );
    for o in &declaration.objects {
        assert_eq!(o.publication, "external-security-sensitive");
        assert!(!o.reconstruction.recipe.is_empty());
        assert!(
            !ev.join("objects").join("sha256").join(&o.cid).is_file(),
            "a detached payload must NOT travel with the publication"
        );
    }
}

/// The execution-assurance capabilities are the orthogonal assurance model
/// (spec/execution-profile.md § assurance capabilities): the vocabulary is
/// closed, every registered profile has a capability row (and every row
/// names a registered profile), every capability is from the vocabulary,
/// and EVERY profile provides the high-assurance set — a policy reasons
/// over capabilities, never over a profile-name equality, so v2/v3/OCI
/// observations qualify for high assurance exactly like the reference one.
#[test]
fn execution_assurance_capabilities_are_coherent() {
    use frf::model::*;
    assert_eq!(
        EXECUTION_CAPABILITIES.to_vec(),
        vec![
            "exact_capture_contract",
            "sealed_executable_image",
            "descendant_resource_envelope",
            "io_world_closed",
            "rootfs_content_bound",
            "native_runtime_closure_bound",
        ],
        "the capability vocabulary is closed and documented"
    );
    let registered: Vec<String> = registry()["execution_profiles"]
        .as_array()
        .expect("the registry must list execution profiles")
        .iter()
        .filter(|p| p["status"] == "active")
        .map(|p| p["id"].as_str().expect("profile id").to_string())
        .collect();
    for p in &registered {
        assert!(
            PROFILE_CAPABILITIES.iter().any(|(pp, _)| pp == p),
            "registered profile {p} has no capability row"
        );
    }
    for (p, caps) in PROFILE_CAPABILITIES {
        assert!(
            registered.iter().any(|pp| pp == p),
            "capability row names an unregistered profile {p}"
        );
        for c in *caps {
            assert!(
                EXECUTION_CAPABILITIES.contains(c),
                "profile {p} carries an unknown capability {c}"
            );
        }
        for required in HIGH_ASSURANCE_CAPABILITIES {
            assert!(
                caps.contains(required),
                "profile {p} lacks the high-assurance capability {required}"
            );
        }
    }
    assert_eq!(
        profile_capabilities(EXECUTION_PROFILE_LINUX)
            .expect("the reference profile has capabilities")
            .to_vec(),
        HIGH_ASSURANCE_CAPABILITIES.to_vec(),
        "the reference profile's capability set IS the high-assurance set"
    );
}

/// The versioning policy (spec/versioning.md): every registry schema id has
/// exactly one coherent status (active or superseded, never both, never an
/// invented state), every ACTIVE schema id the code uses is registered
/// (protocol_registry covers the reverse), and a superseded id documents
/// history — it must never reappear as active.
#[test]
fn the_registry_supersession_rules_are_coherent() {
    let mut seen: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for schema in registry()["schemas"]
        .as_array()
        .expect("the registry must list schemas")
    {
        let id = schema["id"].as_str().expect("schema id").to_string();
        let status = schema["status"]
            .as_str()
            .expect("schema status")
            .to_string();
        assert!(
            status == "active" || status == "superseded" || status == "reserved-invalid",
            "schema {id} has an undefined status {status:?} — the status vocabulary is closed (active | superseded | reserved-invalid)"
        );
        match seen.get(&id) {
            None => {
                seen.insert(id.clone(), status);
            }
            Some(prev) => {
                assert_eq!(
                    prev, &status,
                    "schema {id} is registered with conflicting statuses {prev} and {status}"
                );
            }
        }
    }
    // The active set is non-empty and every family's current schema is
    // present (the code's schema consts are checked against this list by
    // tests/protocol_registry.rs).
    let active: Vec<String> = seen
        .iter()
        .filter(|(_, s)| s.as_str() == "active")
        .map(|(id, _)| id.clone())
        .collect();
    assert!(
        active.len() >= 20,
        "the active schema set must be substantial (found {})",
        active.len()
    );
    for required in [
        "frf-receipt-v20",
        "frf-disposition-v3",
        "frf-reduction-v4",
        "frf-detached-objects-v1",
        "frf-stream-publication-v1",
        "frf-publication-manifest-v1",
        "frf-v3-build-manifest-v1",
    ] {
        assert!(
            active.iter().any(|a| a == required),
            "the active schema set must include {required}"
        );
    }
}
