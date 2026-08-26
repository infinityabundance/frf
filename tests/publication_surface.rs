//! The capture-surface capability (spec/publication-surface.md) — the
//! general publication boundary: the court declares, per observed stream,
//! HOW its bytes may be published; the capture records the declaration as
//! part of the OBSERVATION (bound into the observation identity); the
//! publication transform honors it EXPLICITLY (withheld bytes + disposition
//! record + publication manifest); the verifier reports the stream closure
//! and refuses a tampered surface.
//!
//!   - `surface_is_bound_into_the_observation_and_the_transform_honors_it` —
//!     the full loop on a `hash-only` stream: capture records it, the local
//!     tree's stream closure is complete, the publication withholds the
//!     bytes with a disposition record + manifest, the published tree still
//!     verifies (surface-aware), and a tampered surface refuses.
//!   - `unknown_surface_policy_refuses_the_court` — a bogus policy is a
//!     refused manifest, never a silently mislabeled publication.

use frf::store::Store;
use std::fs;
use std::path::PathBuf;

mod common;
use common::*;

/// The court manifest for the surface tests: the canonical cli-malformed-
/// input court plus a declared capture surface. The policy and the side are
/// injected per case.
const SURFACE_MANIFEST: &str = r#"court:
  id: cli-surface-{COURT}
  question: >-
    For malformed input in fixture family malformed-input, does the candidate
    preserve the admitted reference's exit class and first diagnostic line?
  falsifier: >-
    The candidate's exit class or first diagnostic line diverges from the
    admitted reference on a fixture in family malformed-input.
  authority: ref-cli-1.8.2
  candidate:
    name: cand-cli
    version_or_commit: "0.1.0"
    build_profile: debug
    path: golden/candidate.sh
  fixture:
    id: malformed-path.conf
    path: frf/courts/cli-malformed-input/fixtures/malformed-path.conf
    arguments: ["--strict", "{fixture}"]
  admissibility_envelope:
    fixture_family: malformed-input
    platforms: ["x86_64-linux"]
    observables: [exit, stderr]
    normalizers: []
    replay_scope: single-run
capture_surface:
  {SURFACE}
"#;

fn run_surface_court(work: &Workdir, court: &str, surface_yaml: &str) -> String {
    let manifest = SURFACE_MANIFEST
        .replace("{COURT}", court)
        .replace("{SURFACE}", surface_yaml);
    let mpath = work.path(&format!("frf/courts/cli-surface-{court}/manifest.yaml"));
    fs::create_dir_all(mpath.parent().unwrap()).unwrap();
    fs::write(&mpath, manifest).unwrap();
    let out = frf(
        work,
        &[
            "--root",
            ROOT,
            "court",
            "run",
            &format!("frf/courts/cli-surface-{court}/manifest.yaml"),
        ],
    );
    assert_success(&out, &format!("surface court {court} run"));
    stdout(&out)
}

/// The minimal publication policy: no object detachments — the stream
/// surface alone must make the transform withhold something.
fn write_empty_policy(work: &Workdir) -> PathBuf {
    let path = work.path("policy.json");
    fs::write(
        &path,
        r#"{"schema_version":"frf-detached-objects-v1","policy":"surface-only","objects":[]}"#,
    )
    .unwrap();
    path
}

#[test]
fn surface_is_bound_into_the_observation_and_the_transform_honors_it() {
    let work = Workdir::new("publication-surface");
    work.copy_canonical_tree();
    admit_reference(&work);

    // The candidate's stdout is declared hash-only: only its SHA-256 is
    // publishable.
    let run = run_surface_court(
        &work,
        "hashonly",
        r#"- side: candidate
    stream: stdout
    policy: hash-only"#,
    );
    let local = Store::new(work.path(ROOT));

    // The capture RECORDS the surface, and the local tree's stream closure
    // is complete (the bytes are present and derive the recorded hashes).
    let verified = frf::verify::load_capture_verified(&local, &run).unwrap();
    let surface = verified
        .capture
        .publication_surface
        .as_ref()
        .expect("the capture must record the declared surface");
    assert_eq!(surface.len(), 1);
    assert_eq!(surface[0].side, "candidate");
    assert_eq!(surface[0].stream, "stdout");
    assert_eq!(surface[0].policy, "hash-only");
    let candidate_stdout_sha = &verified.capture.candidate.stdout_sha256;
    assert!(
        work.path(&format!("{ROOT}/captures/{run}/candidate.stdout"))
            .is_file(),
        "the LOCAL tree keeps the observation bytes"
    );

    // The publication transform: the declared stream is withheld, its
    // disposition record written where the bytes used to live, and every
    // stream's disposition recorded in the publication manifest.
    let policy = write_empty_policy(&work);
    let pub_dir = work.path("pub");
    frf::commands::evidence::publish_detached(&local, &policy, &pub_dir)
        .expect("the publication transform must succeed");
    assert!(
        !pub_dir
            .join("captures")
            .join(&run)
            .join("candidate.stdout")
            .is_file(),
        "a hash-only stream's bytes must NOT travel with the publication"
    );
    let disp: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(
            pub_dir
                .join("captures")
                .join(&run)
                .join("candidate.stdout.pub.json"),
        )
        .expect("the disposition record must be written"),
    )
    .unwrap();
    assert_eq!(disp["schema_version"], "frf-stream-publication-v1");
    assert_eq!(disp["side"], "candidate");
    assert_eq!(disp["stream"], "stdout");
    assert_eq!(disp["policy"], "hash-only");
    assert_eq!(disp["sha256"], candidate_stdout_sha.as_str());
    let manifest: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(pub_dir.join("publication-manifest.json"))
            .expect("the publication manifest must be written"),
    )
    .unwrap();
    assert_eq!(manifest["schema_version"], "frf-publication-manifest-v1");
    let candidate_stdout_disp = manifest["streams"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["run"] == run && s["side"] == "candidate" && s["stream"] == "stdout")
        .expect("the manifest records every stream's disposition");
    assert_eq!(candidate_stdout_disp["published"], false);

    // The PUBLISHED tree verifies surface-aware: the graph verifies, the
    // withheld stream is authenticated by its disposition record, and the
    // stream closure is incomplete-by-policy.
    let pub_store = Store::new(pub_dir.clone());
    frf::commands::evidence::status(&pub_store)
        .expect("the publication verifies at the graph level");
    let published_verified = frf::verify::load_capture_verified(&pub_store, &run)
        .expect("the published capture verifies with the withheld stream");
    assert!(published_verified.capture.candidate.stdout_bytes.is_empty());

    // A TAMPERED surface refuses: flipping hash-only -> inline would
    // relicense the withheld bytes for publication. The surface is part of
    // the observation identity, so the capture no longer rederives.
    let capture_path = pub_dir.join("captures").join(&run).join("capture.json");
    let mut capture_doc: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&capture_path).unwrap()).unwrap();
    capture_doc["publication_surface"][0]["policy"] = serde_json::json!("inline");
    fs::write(&capture_path, serde_json::to_string(&capture_doc).unwrap()).unwrap();
    let err = match frf::verify::load_capture_verified(&pub_store, &run) {
        Err(e) => e,
        Ok(_) => panic!("a tampered capture surface MUST refuse the capture"),
    };
    assert!(
        err.message().contains("observation_identity")
            || err.message().contains("does not rederive")
            || err.message().contains("self-authenticating"),
        "unexpected refusal: {}",
        err.message()
    );
}

#[test]
fn unknown_surface_policy_refuses_the_court() {
    let work = Workdir::new("publication-surface-bad-policy");
    work.copy_canonical_tree();
    admit_reference(&work);
    let manifest = SURFACE_MANIFEST.replace("{COURT}", "badpolicy").replace(
        "{SURFACE}",
        r#"- side: candidate
    stream: stdout
    policy: publish-everything"#,
    );
    let mpath = work.path("frf/courts/cli-surface-badpolicy/manifest.yaml");
    fs::create_dir_all(mpath.parent().unwrap()).unwrap();
    fs::write(&mpath, manifest).unwrap();
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "court",
            "run",
            "frf/courts/cli-surface-badpolicy/manifest.yaml",
        ],
    );
    assert!(
        !out.status.success(),
        "an unknown capture-surface policy MUST refuse the court"
    );
    let err = stderr(&out);
    assert!(
        err.contains("policy") && err.contains("not one of"),
        "the refusal must name the policy vocabulary: {err}"
    );
}
