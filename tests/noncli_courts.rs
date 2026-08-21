//! First non-CLI courts — the domain-generality test.
//!
//! The golden path is a CLI court (exit + stderr of subprocesses). This
//! suite proves the abstractions are genuinely domain-general, not just
//! designed to become so, by running the FULL pipeline — capture, residual,
//! token, receipt, claim gate, replay — on four non-CLI surfaces:
//!
//! - **filesystem.tree**: the sides BUILD a tree (the `produce` clause);
//!   the built-in tree comparator diffs the produced files per path.
//! - **bytes.wire**: the sides emit raw bytes; the built-in bytes comparator
//!   compares the streams byte-exactly (by content identity).
//! - **structured.state**: the sides emit JSON state; the built-in json
//!   comparator diffs field by field (residuals surfaced by JSON pointer).
//! - **timing.latency**: the sides emit a duration; an EXTERNAL comparator
//!   (the extension protocol) applies the declared envelope relation and
//!   returns equivalent or divergent.

mod common;
use common::*;

use std::fs;

/// Write a file tree into the workdir from `(rel_path, contents)` pairs.
fn write_files(work: &Workdir, files: &[(&str, &str)]) {
    for (rel, contents) in files {
        let path = work.path(rel);
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).unwrap();
            }
        }
        fs::write(&path, contents).unwrap();
        if rel.ends_with(".sh") {
            set_exec(&path);
        }
    }
}

/// Read a YAML doc from the workdir.
fn load_yaml(work: &Workdir, rel: &str) -> serde_yaml::Value {
    serde_yaml::from_str(&fs::read_to_string(work.path(rel)).unwrap()).unwrap()
}

/// Admit an authority script and return its id.
fn admit(work: &Workdir, path: &str, name: &str, version: &str) {
    let out = frf(
        work,
        &[
            "--root",
            ROOT,
            "authority",
            "admit",
            path,
            "--name",
            name,
            "--version",
            version,
        ],
    );
    assert_success(&out, "authority admit");
}

// ---------------------------------------------------------------------------
// filesystem.tree — produced artifacts
// ---------------------------------------------------------------------------

const TREE_REF: &str = r#"#!/bin/sh
# treegen-ref: read a spec (path<TAB>content per line) and build the tree.
set -u
spec=""; out=""
while [ $# -gt 0 ]; do
  case "$1" in
    --spec) spec="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    *) shift ;;
  esac
done
[ -n "$spec" ] && [ -n "$out" ] || exit 2
rm -rf "$out"
while IFS=$'\t' read -r path content || [ -n "$path" ]; do
  [ -z "$path" ] && continue
  case "$path" in \#*) continue ;; esac
  mkdir -p "$out/$(dirname "$path")"
  printf '%s\n' "$content" > "$out/$path"
done < "$spec"
exit 0
"#;

const TREE_CAND: &str = r#"#!/bin/sh
# treegen-cand: identical, but writes DIFFERENT content for src/main.c and
# drops build/config — the seeded tree divergences.
set -u
spec=""; out=""
while [ $# -gt 0 ]; do
  case "$1" in
    --spec) spec="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    *) shift ;;
  esac
done
[ -n "$spec" ] && [ -n "$out" ] || exit 2
rm -rf "$out"
while IFS=$'\t' read -r path content || [ -n "$path" ]; do
  [ -z "$path" ] && continue
  case "$path" in \#*) continue ;; esac
  mkdir -p "$out/$(dirname "$path")"
  if [ "$path" = "src/main.c" ]; then
    printf '%s\n' "int main(void){return 0;}" > "$out/$path"
  elif [ "$path" = "build/config" ]; then
    continue
  else
    printf '%s\n' "$content" > "$out/$path"
  fi
done < "$spec"
exit 0
"#;

const TREE_MANIFEST: &str = "court:\n  id: fs-tree-build\n  question: >-\n    For the build spec in fixture family tree-build, does the candidate\n    produce the same filesystem tree as the reference?\n  falsifier: >-\n    The candidate's produced tree diverges from the reference's on some\n    path or file content.\n  authority: treegen-ref-1.0\n  candidate:\n    name: treegen-cand\n    version_or_commit: \"0.1.0\"\n    build_profile: debug\n    path: treegen-cand.sh\n  fixture:\n    id: tree-spec.conf\n    path: frf/courts/fs-tree-build/fixtures/tree-spec.conf\n    arguments: [\"--spec\", \"{fixture}\", \"--out\", \"{output}\"]\n  admissibility_envelope:\n    fixture_family: tree-build\n    platforms: [\"x86_64-linux\"]\n    observables: [filesystem.tree]\n    normalizers: []\n    replay_scope: single-run\n  produce:\n    path: tree-out/\n";

#[test]
fn filesystem_tree_court_observes_produced_artifacts() {
    let work = Workdir::new("noncli-tree");
    write_files(
        &work,
        &[
            ("treegen-ref.sh", TREE_REF),
            ("treegen-cand.sh", TREE_CAND),
            ("frf/courts/fs-tree-build/manifest.yaml", TREE_MANIFEST),
            (
                "frf/courts/fs-tree-build/fixtures/tree-spec.conf",
                "src/main.c\t#include <stdio.h>\nREADME.md\t# treegen\nbuild/config\tDEBUG=0\n",
            ),
        ],
    );
    admit(&work, "treegen-ref.sh", "treegen-ref", "1.0");

    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "court",
            "run",
            "frf/courts/fs-tree-build/manifest.yaml",
        ],
    );
    assert_success(&out, "tree court run");
    let run = stdout(&out);

    // The produced trees were captured immutably under the run.
    for side in ["reference", "candidate"] {
        let produced = work.path(&format!("frf/captures/{run}/produced/{side}"));
        assert!(produced.is_dir(), "produced tree for {side} missing");
        assert!(
            produced.join("README.md").is_file(),
            "produced README.md for {side} missing"
        );
    }
    assert!(work
        .path(&format!(
            "frf/captures/{run}/produced/reference/build/config"
        ))
        .is_file());
    assert!(!work
        .path(&format!(
            "frf/captures/{run}/produced/candidate/build/config"
        ))
        .exists());

    // The capture records the produced observation per side, and the run
    // identity binds it (the run binds what the sides BUILT).
    let capture = load_yaml(&work, &format!("frf/captures/{run}/capture.yaml"));
    let ref_prod = &capture["reference"]["produced"];
    let cand_prod = &capture["candidate"]["produced"];
    assert_eq!(ref_prod["schema_version"], "frf-produced-v1");
    assert_eq!(ref_prod["manifest_sha256"].as_str().unwrap().len(), 64);
    assert_ne!(
        ref_prod["manifest_sha256"], cand_prod["manifest_sha256"],
        "the produced trees differ, so their manifests must differ"
    );

    // The residuals: one per differing file, surfaced by path.
    let residuals: Vec<serde_yaml::Value> = fs::read_dir(work.path("frf/residuals"))
        .unwrap()
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "yaml"))
        .filter(|e| {
            !e.file_name().to_string_lossy().contains(".token")
                && !e.file_name().to_string_lossy().contains(".events")
        })
        .map(|e| {
            load_yaml(
                &work,
                &format!("frf/residuals/{}", e.file_name().to_string_lossy()),
            )
        })
        .collect();
    let tree_residuals: Vec<&serde_yaml::Value> = residuals
        .iter()
        .filter(|r| r["axis"] == "filesystem.tree")
        .collect();
    assert_eq!(tree_residuals.len(), 2, "two produced files diverge");
    let surfaces: Vec<String> = tree_residuals
        .iter()
        .map(|r| r["surface"].as_str().unwrap().to_string())
        .collect();
    assert!(
        surfaces.contains(&"path:src/main.c".to_string()),
        "content divergence surfaced: {surfaces:?}"
    );
    assert!(
        surfaces.contains(&"path:build/config".to_string()),
        "absent-file divergence surfaced: {surfaces:?}"
    );
    let config = tree_residuals
        .iter()
        .find(|r| r["surface"] == "path:build/config")
        .unwrap();
    assert_eq!(config["raw_candidate"], "<absent>");
    assert_eq!(config["raw_reference"].as_str().unwrap().len(), 64);

    // The receipt emits (the filesystem.tree axis is an ordinary observable),
    // and the open residual blocks the claim.
    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &run]);
    assert_success(&out, "tree receipt emit");
    let receipt = stdout(&out);
    let out = frf(&work, &["--root", ROOT, "claim", "compile", &receipt]);
    assert!(
        !out.status.success(),
        "open tree residual must block the claim"
    );

    // Replay reproduces the produced trees byte-for-byte.
    let out = frf(
        &work,
        &["--root", ROOT, "replay", &run, "--policy", "exact"],
    );
    assert_success(&out, "tree replay");
    let out_text = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        out_text.contains("2 residual(s) with matching fingerprints"),
        "the produced-tree residuals must reproduce: {out_text}"
    );

    // The produce path is transient: cleared after the run, never evidence.
    assert!(
        !work.path("tree-out").exists(),
        "the produce path is transient"
    );
}

#[test]
fn a_filesystem_tree_court_without_produce_is_refused() {
    let work = Workdir::new("noncli-tree-noproduce");
    write_files(
        &work,
        &[
            ("treegen-ref.sh", TREE_REF),
            ("treegen-cand.sh", TREE_CAND),
            ("frf/courts/fs-tree-build/manifest.yaml", TREE_MANIFEST),
            (
                "frf/courts/fs-tree-build/fixtures/tree-spec.conf",
                "src/main.c\t#include <stdio.h>\n",
            ),
        ],
    );
    admit(&work, "treegen-ref.sh", "treegen-ref", "1.0");
    // Drop the produce clause: the filesystem.tree axis would compare two
    // empty trees — refuse, never pretend.
    let manifest_path = work.path("frf/courts/fs-tree-build/manifest.yaml");
    let mut manifest: serde_yaml::Value =
        load_yaml(&work, "frf/courts/fs-tree-build/manifest.yaml");
    manifest["court"]
        .as_mapping_mut()
        .unwrap()
        .remove("produce");
    fs::write(&manifest_path, serde_yaml::to_string(&manifest).unwrap()).unwrap();

    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "court",
            "run",
            "frf/courts/fs-tree-build/manifest.yaml",
        ],
    );
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("must declare `produce`"),
        "{}",
        stderr(&out)
    );
}

// ---------------------------------------------------------------------------
// bytes.wire — the raw stream, byte-exact
// ---------------------------------------------------------------------------

const WIRE_MANIFEST: &str = "court:\n  id: wire-encode\n  question: >-\n    For the packet spec in fixture family wire-encode, does the candidate\n    emit the same wire bytes as the reference?\n  falsifier: >-\n    The candidate's emitted bytes diverge from the reference's.\n  authority: wire-ref-1.0\n  candidate:\n    name: wire-cand\n    version_or_commit: \"0.1.0\"\n    build_profile: debug\n    path: wire-cand.sh\n  fixture:\n    id: packet-spec.conf\n    path: frf/courts/wire-encode/fixtures/packet-spec.conf\n    arguments: [\"{fixture}\"]\n  admissibility_envelope:\n    fixture_family: wire-encode\n    platforms: [\"x86_64-linux\"]\n    observables: [bytes.wire]\n    normalizers: []\n    replay_scope: single-run\n";

#[test]
fn bytes_wire_court_compares_the_raw_stream_byte_exactly() {
    let work = Workdir::new("noncli-wire");
    write_files(
        &work,
        &[
            (
                "wire-ref.sh",
                "#!/bin/sh\nprintf '\\001\\002\\003\\004' >&1\n",
            ),
            (
                "wire-cand.sh",
                "#!/bin/sh\nprintf '\\001\\002\\377\\004' >&1\n",
            ),
            ("frf/courts/wire-encode/manifest.yaml", WIRE_MANIFEST),
            (
                "frf/courts/wire-encode/fixtures/packet-spec.conf",
                "packet: 4\n",
            ),
        ],
    );
    admit(&work, "wire-ref.sh", "wire-ref", "1.0");

    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "court",
            "run",
            "frf/courts/wire-encode/manifest.yaml",
        ],
    );
    assert_success(&out, "wire court run");
    let run = stdout(&out);

    // The raw stdout files are captured; the single divergence is on the
    // bytes.wire axis (the streams differ in one byte).
    let capture = load_yaml(&work, &format!("frf/captures/{run}/capture.yaml"));
    assert_ne!(
        capture["reference"]["stdout_sha256"], capture["candidate"]["stdout_sha256"],
        "one byte differs, so the stream hashes must differ"
    );
    let residual: serde_yaml::Value = load_yaml(
        &work,
        &format!(
            "frf/residuals/{}.yaml",
            capture["residuals"][0].as_str().unwrap()
        ),
    );
    assert_eq!(residual["axis"], "bytes.wire");
    assert_eq!(residual["kind"], "text");

    // Replay reproduces the stream divergence.
    let out = frf(
        &work,
        &["--root", ROOT, "replay", &run, "--policy", "exact"],
    );
    assert_success(&out, "wire replay");
}

// ---------------------------------------------------------------------------
// structured.state — JSON field diffs
// ---------------------------------------------------------------------------

const STATE_MANIFEST: &str = "court:\n  id: state-json\n  question: >-\n    For the state spec in fixture family state-json, does the candidate\n    preserve the reference's structured state?\n  falsifier: >-\n    The candidate's emitted JSON state diverges from the reference's on\n    some field.\n  authority: state-ref-1.0\n  candidate:\n    name: state-cand\n    version_or_commit: \"0.1.0\"\n    build_profile: debug\n    path: state-cand.sh\n  fixture:\n    id: state-spec.conf\n    path: frf/courts/state-json/fixtures/state-spec.conf\n    arguments: [\"{fixture}\"]\n  admissibility_envelope:\n    fixture_family: state-json\n    platforms: [\"x86_64-linux\"]\n    observables: [structured.state]\n    normalizers: []\n    replay_scope: single-run\n";

#[test]
fn structured_state_court_diffs_json_fields() {
    let work = Workdir::new("noncli-state");
    write_files(
        &work,
        &[
            (
                "state-ref.sh",
                "#!/bin/sh\necho '{\"config\":{\"timeout\":5,\"retries\":2},\"status\":\"ok\"}'\n",
            ),
            (
                "state-cand.sh",
                "#!/bin/sh\necho '{\"config\":{\"timeout\":9,\"retries\":2},\"status\":\"ok\"}'\n",
            ),
            ("frf/courts/state-json/manifest.yaml", STATE_MANIFEST),
            (
                "frf/courts/state-json/fixtures/state-spec.conf",
                "state: config\n",
            ),
        ],
    );
    admit(&work, "state-ref.sh", "state-ref", "1.0");

    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "court",
            "run",
            "frf/courts/state-json/manifest.yaml",
        ],
    );
    assert_success(&out, "state court run");
    let run = stdout(&out);

    // One residual, surfaced by the exact JSON pointer of the differing field.
    let capture = load_yaml(&work, &format!("frf/captures/{run}/capture.yaml"));
    let residual: serde_yaml::Value = load_yaml(
        &work,
        &format!(
            "frf/residuals/{}.yaml",
            capture["residuals"][0].as_str().unwrap()
        ),
    );
    assert_eq!(residual["axis"], "structured.state");
    assert_eq!(residual["surface"], "$.config.timeout");
    assert_eq!(residual["raw_reference"], "5");
    assert_eq!(residual["raw_candidate"], "9");

    let out = frf(
        &work,
        &["--root", ROOT, "replay", &run, "--policy", "exact"],
    );
    assert_success(&out, "state replay");
}

// ---------------------------------------------------------------------------
// timing.latency — an external envelope comparator (the extension protocol)
// ---------------------------------------------------------------------------

const TIMING_REF: &str = "#!/bin/sh\nsleep 0.01\necho 'duration_ms 10'\n";
const TIMING_CAND: &str = "#!/bin/sh\nsleep 0.01\necho 'duration_ms 30'\n";

const TIMING_COMPARATOR: &str = r#"#!/usr/bin/env python3
# timing envelope comparator: the declared relation is `within-2x` — the
# candidate's latency must be at most twice the reference's.
import base64, hashlib, json, re, sys
raw = sys.stdin.buffer.read()
req = json.loads(raw.decode("utf-8"))
request_id = hashlib.sha256(raw).hexdigest()
def dur(side):
    text = base64.b64decode(side["stdout_base64"]).decode("utf-8", "replace")
    m = re.search(r"duration_ms (\d+)", text)
    return int(m.group(1)) if m else None
ref = dur(req["reference"])
cand = dur(req["candidate"])
base = {"schema_version": "frf-comparator-response-v2", "request_id": request_id, "indeterminate": False, "failure": None}
if ref is None or cand is None:
    out = {"surface": "latency-parse", "raw_reference": str(ref), "raw_candidate": str(cand)}
    print(json.dumps({**base, "equivalent": False, "residuals": [out]}, separators=(",", ":")))
elif cand <= 2 * ref:
    print(json.dumps({**base, "equivalent": True, "residuals": []}, separators=(",", ":")))
else:
    out = {"surface": "latency-ratio", "raw_reference": str(ref), "raw_candidate": str(cand)}
    print(json.dumps({**base, "equivalent": False, "residuals": [out]}, separators=(",", ":")))
"#;

const TIMING_MANIFEST: &str = "court:\n  id: timing-bench\n  question: >-\n    For the bench spec in fixture family timing-bench, is the candidate's\n    latency within the declared envelope of the reference's?\n  falsifier: >-\n    The candidate's latency exceeds twice the reference's.\n  authority: timing-ref-1.0\n  candidate:\n    name: timing-cand\n    version_or_commit: \"0.1.0\"\n    build_profile: debug\n    path: timing-cand.sh\n  fixture:\n    id: bench-spec.conf\n    path: frf/courts/timing-bench/fixtures/bench-spec.conf\n    arguments: [\"{fixture}\"]\n  admissibility_envelope:\n    fixture_family: timing-bench\n    platforms: [\"x86_64-linux\"]\n    observables: [timing.latency]\n    normalizers: []\n    replay_scope: single-run\ncomparators:\n  - axis: timing.latency\n    relation: within-2x\n    extractor: latency-ms\n    residual_classifier: text\n    relation_version: \"v1\"\n    program: timing-compare.py\n";

#[test]
fn timing_court_uses_an_external_envelope_comparator() {
    let work = Workdir::new("noncli-timing");
    write_files(
        &work,
        &[
            ("timing-ref.sh", TIMING_REF),
            ("timing-cand.sh", TIMING_CAND),
            ("timing-compare.py", TIMING_COMPARATOR),
            ("frf/courts/timing-bench/manifest.yaml", TIMING_MANIFEST),
            (
                "frf/courts/timing-bench/fixtures/bench-spec.conf",
                "bench: latency\n",
            ),
        ],
    );
    admit(&work, "timing-ref.sh", "timing-ref", "1.0");

    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "court",
            "run",
            "frf/courts/timing-bench/manifest.yaml",
        ],
    );
    assert_success(&out, "timing court run");
    let run = stdout(&out);

    // The external comparator applied the envelope: 30 > 2*10 → divergent,
    // surfaced as the latency-ratio residual on the timing.latency axis.
    let capture = load_yaml(&work, &format!("frf/captures/{run}/capture.yaml"));
    assert_eq!(capture["residuals"].as_sequence().unwrap().len(), 1);
    let residual: serde_yaml::Value = load_yaml(
        &work,
        &format!(
            "frf/residuals/{}.yaml",
            capture["residuals"][0].as_str().unwrap()
        ),
    );
    assert_eq!(residual["axis"], "timing.latency");
    assert_eq!(residual["surface"], "latency-ratio");
    assert_eq!(residual["raw_reference"], "10");
    assert_eq!(residual["raw_candidate"], "30");

    // The comparator invocation evidence was preserved (the instrument is
    // part of the evidence).
    let comp_dir = work.path(&format!("frf/captures/{run}/comparator/timing.latency"));
    for f in [
        "request.json",
        "response.json",
        "invocation.json",
        "result.json",
    ] {
        assert!(comp_dir.join(f).is_file(), "{f} missing");
    }

    // Replay re-invokes the snapshotted comparator and reproduces the verdict.
    let out = frf(
        &work,
        &["--root", ROOT, "replay", &run, "--policy", "exact"],
    );
    assert_success(&out, "timing replay");
    let out_text = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        out_text.contains("1 residual(s) with matching fingerprints"),
        "the timing residual must reproduce: {out_text}"
    );

    // A within-envelope candidate is equivalent: no residual.
    let fast = "#!/bin/sh\nsleep 0.01\necho 'duration_ms 15'\n";
    let cand_path = work.path("timing-cand.sh");
    fs::write(&cand_path, fast).unwrap();
    set_exec(&cand_path);
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "court",
            "run",
            "frf/courts/timing-bench/manifest.yaml",
        ],
    );
    assert_success(&out, "within-envelope run");
    let run2 = stdout(&out);
    let capture2 = load_yaml(&work, &format!("frf/captures/{run2}/capture.yaml"));
    assert_eq!(
        capture2["residuals"].as_sequence().unwrap().len(),
        0,
        "15 <= 2*10: within the envelope, no residual"
    );
}
