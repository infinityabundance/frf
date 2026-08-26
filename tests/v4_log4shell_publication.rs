//! The Log4Shell (CVE-2021-44228) V3 publication-integrity gate — the
//! CI-checkable meaning of a green badge for the THIRD semantic-domain
//! study. Hosted CI does NOT execute the empirical programs (they construct
//! and run CVE-2021-44228-vulnerable Log4j stacks); it proves the
//! PUBLICATION is intact:
//!
//!   ✓ source hashes declared                             (per-case manifest)
//!   ✓ reconstruction recipes present                     (this gate)
//!   ✓ expected artifact hashes declared                  (shared corpus
//!     manifest: probe.jar, the eight pinned jars, the four launchers)
//!   ✓ safe evidence documents canonical/valid            (evidence status:
//!     every committed receipt + capture verifies at the graph level)
//!   ✓ detached-object references resolve structurally    (this gate + status:
//!     the declaration parses, validates, and names EXACTLY the pinned
//!     probe/jars/launchers and the mutation request)
//!
//! `reproduce.sh` (external-corpus/v3/log4shell) is the only path that
//! builds and executes the vulnerable stacks; it is never part of ordinary
//! CI.

use frf::store::Store;
use std::collections::HashSet;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

#[test]
fn the_log4shell_v3_publication_integrity_gate_holds() {
    let root = repo_root();
    let case = root.join("external-corpus/v3/log4shell");

    // ✓ source hashes declared: the probe source is pinned in the per-case
    // manifest (it is a LOCAL SYNTHETIC MODEL of the defect observable —
    // the shared corpus manifest's source schema holds URL-bearing upstream
    // artifacts only, so the probe's pin lives with its provenance here).
    let case_manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(case.join("build/build-manifest.json"))
            .expect("the per-case build manifest must exist"),
    )
    .expect("the per-case build manifest must be valid JSON");
    assert_eq!(
        case_manifest["schema_version"], "frf-v3-build-manifest-v1",
        "the build manifest's schema is part of the protocol"
    );
    let sources = case_manifest["sources"]
        .as_array()
        .expect("the manifest must declare its sources");
    assert_eq!(sources.len(), 1, "one probe source");
    let src_sha = sources[0]["sha256"].as_str().unwrap_or_default();
    assert!(
        hex64(src_sha),
        "source {:?} must pin a 64-hex sha256",
        sources[0]["name"]
    );
    // The pinned source hash matches the tracked file.
    let actual_src = std::fs::read(case.join("src/Log4ShellProbe.java")).unwrap();
    let actual_sha = frf::host::sha256_bytes(&actual_src);
    assert_eq!(
        actual_sha, src_sha,
        "the tracked Log4ShellProbe.java must hash to the pinned source hash"
    );
    assert_eq!(
        sources[0]["provenance_kind"],
        "synthetic-model",
        "the source declares its provenance honestly (a local synthetic model of the defect observable, not an upstream repository)"
    );

    // ✓ expected artifact hashes declared: the shared corpus manifest pins
    // the probe, the eight log4j jars (the four release points of the
    // CVE-2021-44228 lifecycle x api/core), and the four launchers.
    let shared_manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("external-corpus/v3/build/build-manifest.json"))
            .expect("the shared corpus build manifest must exist"),
    )
    .expect("the shared corpus build manifest must be valid JSON");
    let artifacts = shared_manifest["artifacts"]
        .as_object()
        .expect("the shared manifest must declare its artifacts");
    let l4s_pins: HashSet<String> = artifacts
        .iter()
        .filter(|(rel, _)| rel.starts_with("log4shell/builds/"))
        .map(|(_, v)| v.as_str().expect("pinned sha256").to_string())
        .collect();
    assert_eq!(
        l4s_pins.len(),
        13,
        "the probe + eight jars + four launchers are pinned"
    );
    for pin in &l4s_pins {
        assert!(hex64(pin), "pinned artifact hashes are 64-hex sha256");
    }
    // The runtime payloads (probe + jars) are loaded through the JVM
    // classpath — the Java analogue of the native runtime closure — and are
    // never snapshotted by the court as evidence objects; only the four
    // launchers (the side programs) are evidence references.
    let launcher_pins: HashSet<String> = artifacts
        .iter()
        .filter(|(rel, _)| rel.starts_with("log4shell/builds/") && rel.ends_with(".sh"))
        .map(|(_, v)| v.as_str().expect("pinned sha256").to_string())
        .collect();
    assert_eq!(launcher_pins.len(), 4, "the four launchers are pinned");

    // ✓ the published evidence tree's detached declaration resolves
    // structurally: it parses as frf-detached-objects-v1, passes semantic
    // conformance, carries role/publication/reconstruction for every object,
    // and names EXACTLY the pinned probe/jars/launchers plus the mutation
    // request — no more, no less.
    let ev_root = case.join("evidence");
    assert!(ev_root.is_dir(), "the published evidence tree must exist");
    let store = Store::new(ev_root.clone());
    let declaration = store
        .load_detached_objects()
        .expect("the published tree's detached declaration must load")
        .expect("the published tree must carry a detached-objects declaration");
    declaration
        .validate_semantics()
        .expect("the detached declaration must pass semantic conformance");
    assert_eq!(
        declaration.policy, "detached",
        "the declaration names the publication policy"
    );
    let declared_payloads: HashSet<String> = declaration
        .objects
        .iter()
        .filter(|o| o.role != "mutation-request")
        .map(|o| o.cid.clone())
        .collect();
    assert_eq!(
        declared_payloads, launcher_pins,
        "the declared-detached payloads are exactly the pinned launchers (the side programs; the jars/probe are classpath runtime dependencies, not evidence references)"
    );
    assert_eq!(
        declaration
            .objects
            .iter()
            .filter(|o| o.role == "mutation-request")
            .count(),
        1,
        "the challenge operator's mutation request (embedded reference bytes) is withheld too"
    );
    for o in &declaration.objects {
        assert!(
            !o.role.is_empty() && !o.publication.is_empty(),
            "cid {}: role and publication must be non-empty",
            o.cid
        );
        assert!(
            !o.reconstruction.recipe.is_empty(),
            "cid {}: a reconstruction recipe must be present (the payload is rebuildable)",
            o.cid
        );
    }

    // ✓ safe evidence documents canonical/valid: `evidence status` walks
    // every committed receipt and capture and verifies identity +
    // derivation + CID resolution at the graph level.
    frf::commands::evidence::status(&store)
        .expect("the published graph verifies (graph_verified=yes)");

    // The publication boundary is intact: the tree the gate just verified
    // is the detached publication, and the payloads it withholds are
    // exactly the pinned build products.
}
