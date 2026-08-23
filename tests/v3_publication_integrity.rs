//! The V3 publication-integrity gate — the CI-checkable meaning of a green
//! badge for the historical-upstream corpus. Hosted CI deliberately does NOT
//! execute the empirical programs (they construct and run historically
//! vulnerable software); instead it proves the PUBLICATION is intact and the
//! prohibited payloads never entered the tracked tree:
//!
//!   ✓ prohibited historical build products absent        (prohibited_payloads)
//!   ✓ prohibited artifact hashes absent as Git blobs/
//!     CAS payloads anywhere in the tracked tree          (prohibited_payloads)
//!   ✓ source hashes declared                             (this gate)
//!   ✓ reconstruction recipes present                     (this gate)
//!   ✓ expected artifact hashes declared                  (this gate)
//!   ✓ safe evidence documents canonical/valid            (evidence status:
//!     every committed receipt + capture verifies at the graph level)
//!   ✓ detached-object references resolve structurally    (this gate + status:
//!     the declaration parses, validates, and names EXACTLY the pinned probes)
//!   ℹ empirical replay intentionally not executed in hosted CI
//!
//! `reproduce.sh` (external-corpus/v3/heartbleed) is the only path that
//! executes the historical probes; it is never part of ordinary CI.

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
fn the_v3_publication_integrity_gate_holds() {
    let root = repo_root();
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("external-corpus/v3/build/build-manifest.json"))
            .expect("build-manifest.json must exist"),
    )
    .expect("build-manifest.json must be valid JSON");
    assert_eq!(
        manifest["schema_version"], "frf-v3-build-manifest-v1",
        "the build manifest's schema is part of the protocol"
    );

    // ✓ source hashes declared: every historical upstream tarball is pinned
    // by SHA-256 with its retrieval URL, so the reconstruction is bound to
    // exact bytes, not to whatever a mirror serves today.
    let sources = manifest["sources"]
        .as_array()
        .expect("the manifest must declare its sources");
    assert!(sources.len() >= 13, "every v3 case's sources are declared");
    for s in sources {
        let sha = s["sha256"].as_str().unwrap_or_default();
        assert!(
            hex64(sha),
            "source {:?} must pin a 64-hex sha256, got {:?}",
            s["name"],
            sha
        );
        let url = s["url"].as_str().unwrap_or_default();
        assert!(
            url.starts_with("https://") || url.starts_with("http://"),
            "source {:?} must declare a retrieval URL",
            s["name"]
        );
    }

    // ✓ expected artifact hashes declared: every built probe/jar is pinned.
    let artifacts = manifest["artifacts"]
        .as_object()
        .expect("the manifest must declare its artifacts");
    assert!(artifacts.len() >= 16, "all v3 build products are pinned");
    for (rel, v) in artifacts {
        let sha = v.as_str().unwrap_or_default();
        assert!(
            hex64(sha),
            "artifact {rel} must pin a 64-hex sha256, got {sha:?}"
        );
    }

    // The heartbleed probes are EXACTLY the set the published evidence
    // declares detached — the publication boundary and the build manifest
    // must name the same seven payloads.
    let hb_pins: HashSet<String> = artifacts
        .iter()
        .filter(|(rel, _)| rel.starts_with("heartbleed/builds/"))
        .map(|(_, v)| v.as_str().expect("artifact hash").to_string())
        .collect();
    assert_eq!(
        hb_pins.len(),
        7,
        "the seven heartbleed probes are pinned by the manifest"
    );

    // ✓ the published evidence tree's detached declaration resolves
    // structurally: it parses as frf-detached-objects-v1, passes semantic
    // conformance, carries role/publication/reconstruction for every object,
    // and names EXACTLY the pinned probes — no more, no less.
    let ev_root = root.join("external-corpus/v3/heartbleed/evidence");
    assert!(ev_root.is_dir(), "the published evidence tree must exist");
    let store = Store::new(ev_root);
    let declaration = store
        .load_detached_objects()
        .expect("the published tree's detached declaration must load")
        .expect("the published tree must carry a detached-objects declaration");
    declaration
        .validate_semantics()
        .expect("the detached declaration must pass semantic conformance");
    assert!(
        !declaration.objects.is_empty(),
        "the declaration names payloads"
    );
    // The declared-detached payloads are exactly the pinned probes plus the
    // mutation request (which embeds reference bytes and is withheld by the
    // same publication policy).
    let declared_probes: HashSet<String> = declaration
        .objects
        .iter()
        .filter(|o| o.role != "mutation-request")
        .map(|o| o.cid.clone())
        .collect();
    assert_eq!(
        declared_probes, hb_pins,
        "the declared-detached probe payloads are exactly the pinned heartbleed probes"
    );
    assert_eq!(
        declaration
            .objects
            .iter()
            .filter(|o| o.role == "mutation-request")
            .count(),
        1,
        "the mutation request (embedded reference bytes) is withheld too"
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
    // derivation + CID resolution at the graph level. The three-state
    // verdict is printed by the command; here we assert the graph verifies
    // (graph_verified = yes). The object closure is DELIBERATELY
    // incomplete-by-policy (the seven payloads are detached) — that is the
    // publication model, not a defect.
    frf::commands::evidence::status(&store)
        .expect("the published graph verifies (graph_verified=yes)");

    // The publication boundary is intact: the tree the gate just verified is
    // the detached publication, and the payloads it withholds are exactly
    // the prohibited probes the sibling gate (tests/prohibited_payloads.rs)
    // proves are absent from the tracked tree in ANY form.

    // ℹ empirical replay intentionally not executed in hosted CI.
}
