//! The publication-integrity gate: the tracked repository must never carry
//! prohibited payloads, in ANY form, under ANY path.
//!
//! - every tracked file is hashed against the v3 build-manifest's artifact
//!   pins: a file whose SHA-256 equals a pinned historical build product
//!   (the vulnerable OpenSSL probes, the vulnerable bash, the log4j jars,
//!   probe.jar) is a forbidden payload wherever it appears — a `builds/`
//!   copy, a content-addressed evidence object, a base64 blob, anything;
//! - the `builds/` artifact directories must never be tracked;
//! - the published evidence's captured raw streams must be small text
//!   (the projection probe never writes raw memory dumps to an observed
//!   stream) — a tracked capture stream larger than 4 KiB is a raw
//!   process-memory dump that slipped through.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn tracked_files() -> Vec<String> {
    let out = Command::new("git")
        .args(["--no-optional-locks", "ls-files"])
        .current_dir(repo_root())
        .output()
        .expect("git ls-files must run (the repo is a git checkout)");
    assert!(out.status.success(), "git ls-files failed");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|s| s.to_string())
        .collect()
}

fn sha256_file(path: &Path) -> String {
    let bytes =
        std::fs::read(path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    frf::host::sha256_bytes(&bytes)
}

/// The pinned artifact hashes from the v3 build manifest (rel -> sha256).
fn pinned_artifact_hashes() -> Vec<String> {
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(repo_root().join("external-corpus/v3/build/build-manifest.json"))
            .expect("build-manifest.json must exist"),
    )
    .expect("build-manifest.json must be valid JSON");
    manifest["artifacts"]
        .as_object()
        .expect("artifacts must be an object")
        .iter()
        // The log4shell launcher scripts (run-fixed.sh / run-vuln.sh) are
        // small tracked TEXT wrappers, not build products — deliberately
        // not in the prohibited set.
        .filter(|(rel, _)| !rel.starts_with("log4shell/builds/run-"))
        .map(|(_, v)| {
            v.as_str()
                .expect("artifact hash must be a string")
                .to_string()
        })
        .collect()
}

#[test]
fn no_prohibited_payload_is_tracked_anywhere() {
    let root = repo_root();
    let pins: HashSet<String> = pinned_artifact_hashes().into_iter().collect();
    assert!(!pins.is_empty(), "the manifest must pin artifacts");

    // The artifact directories must not be tracked at all.
    for dir in [
        "external-corpus/v3/heartbleed/builds",
        "external-corpus/v3/shellshock/builds",
        "external-corpus/v3/log4shell/builds/lib",
    ] {
        let tracked: Vec<String> = tracked_files()
            .into_iter()
            .filter(|f| f.starts_with(&format!("{dir}/")))
            .collect();
        assert!(
            tracked.is_empty(),
            "prohibited payload directory {dir} is TRACKED: {}",
            tracked.join(", ")
        );
    }
    let tracked_probe_jar: Vec<String> = tracked_files()
        .into_iter()
        .filter(|f| f == "external-corpus/v3/log4shell/builds/probe.jar")
        .collect();
    assert!(
        tracked_probe_jar.is_empty(),
        "the prohibited probe.jar is TRACKED"
    );

    // Every tracked file: a hash match anywhere is a forbidden payload.
    let mut offenders: Vec<String> = Vec::new();
    for rel in tracked_files() {
        if rel.contains("/target/") {
            continue;
        }
        let path = root.join(&rel);
        if !path.is_file() {
            continue;
        }
        let digest = sha256_file(&path);
        if pins.contains(&digest) {
            offenders.push(format!(
                "{rel} hashes to a pinned build product ({})",
                &digest[..16]
            ));
        }
        // Raw-memory boundary: captured streams are small text projections.
        if rel.starts_with("external-corpus/v3/heartbleed/evidence/captures/")
            && (rel.ends_with(".stdout") || rel.ends_with(".stderr"))
        {
            let size = std::fs::metadata(&path).expect("metadata").len();
            assert!(
                size <= 4096,
                "{rel} is a {size}-byte captured stream — a raw memory dump must never be published"
            );
        }
    }
    assert!(
        offenders.is_empty(),
        "prohibited build-product payloads are tracked (the publication boundary is broken):\n{}",
        offenders.join("\n")
    );
}
