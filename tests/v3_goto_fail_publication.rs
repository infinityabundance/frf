//! The Goto Fail (CVE-2014-1266) V3 publication-integrity gate — the
//! CI-checkable meaning of a green badge for the SECOND semantic-domain
//! study. Hosted CI does NOT execute the empirical programs; it proves the
//! PUBLICATION is intact:
//!
//!   ✓ source hashes declared                             (build-manifest)
//!   ✓ reconstruction recipes present                     (this gate)
//!   ✓ expected artifact hashes declared                  (this gate)
//!   ✓ safe evidence documents canonical/valid            (evidence status:
//!     every committed receipt + capture verifies at the graph level)
//!   ✓ detached-object references resolve structurally    (this gate + status:
//!     the declaration parses, validates, and names EXACTLY the pinned
//!     binaries and the mutation request)
//!
//! `reproduce.sh` (external-corpus/v3/goto-fail) is the only path that
//! builds and executes the verifier programs; it is never part of ordinary
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
fn the_goto_fail_v3_publication_integrity_gate_holds() {
    let root = repo_root();
    let case = root.join("external-corpus/v3/goto-fail");
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(case.join("build/build-manifest.json"))
            .expect("build-manifest.json must exist"),
    )
    .expect("build-manifest.json must be valid JSON");
    assert_eq!(
        manifest["schema_version"], "frf-v3-build-manifest-v1",
        "the build manifest's schema is part of the protocol"
    );

    // ✓ source hashes declared: the single C source is pinned, so the
    // reconstruction is bound to exact bytes.
    let sources = manifest["sources"]
        .as_array()
        .expect("the manifest must declare its sources");
    assert_eq!(sources.len(), 1, "one C source");
    let src_sha = sources[0]["sha256"].as_str().unwrap_or_default();
    assert!(
        hex64(src_sha),
        "source {:?} must pin a 64-hex sha256",
        sources[0]["name"]
    );
    // The pinned source hash matches the tracked file.
    let actual_src = std::fs::read(case.join("src/sslcheck.c")).unwrap();
    let actual_sha = frf::host::sha256_bytes(&actual_src);
    assert_eq!(
        actual_sha, src_sha,
        "the tracked sslcheck.c must hash to the pinned source hash"
    );

    // ✓ expected artifact hashes declared: both verifiers are pinned.
    let artifacts = manifest["artifacts"]
        .as_object()
        .expect("the manifest must declare its artifacts");
    assert_eq!(
        artifacts.len(),
        2,
        "the clean and buggy verifiers are pinned"
    );
    let pins: HashSet<String> = artifacts
        .values()
        .map(|v| v.as_str().expect("pinned sha256").to_string())
        .collect();
    for pin in &pins {
        assert!(hex64(pin), "pinned artifact hashes are 64-hex sha256");
    }

    // ✓ the reconstruction is GENUINELY byte-reproducible (source
    // reproducibility is NOT artifact reproducibility): the builder record
    // pins the toolchain — the base image by OCI digest, the exact
    // compiler/linker/libc versions, the target, and the flags — and the
    // source declares its provenance honestly (a synthetic model of the
    // defect observable, with no unrelated upstream repository URL claimed).
    let builder = &manifest["builder"];
    for key in [
        "base_image",
        "built_image_id",
        "containerfile",
        "compiler",
        "linker",
        "libc",
        "target",
    ] {
        assert!(
            !builder[key].as_str().unwrap_or_default().is_empty(),
            "the builder record must pin {key}"
        );
    }
    assert_eq!(
        builder["flags"].as_array().map(|f| f.len()).unwrap_or(0),
        2,
        "the builder record pins the exact compile flags for both verifiers"
    );
    assert_eq!(
        sources[0]["provenance_kind"],
        "synthetic-model",
        "the source declares its provenance honestly (a local synthetic model, not an upstream repository)"
    );

    // ✓ the published evidence tree's detached declaration resolves
    // structurally: it parses as frf-detached-objects-v1, passes semantic
    // conformance, carries role/publication/reconstruction for every object,
    // and names EXACTLY the pinned binaries plus the mutation request — no
    // more, no less.
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
    let declared_binaries: HashSet<String> = declaration
        .objects
        .iter()
        .filter(|o| o.role != "mutation-request")
        .map(|o| o.cid.clone())
        .collect();
    assert_eq!(
        declared_binaries, pins,
        "the declared-detached binaries are exactly the pinned verifiers"
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
