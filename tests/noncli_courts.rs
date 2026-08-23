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
//! - **external mutation providers** (spec/mutation.md): the court challenge
//!   can seed domain defects through the extension protocol — a provider
//!   PROPOSES a mutant candidate, the court runs it and independently
//!   decides the verdicts.

mod common;
use common::*;

use frf::store::Store;
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

/// Read a JSON evidence document from the workdir (generated evidence is
/// canonical JSON; court manifests stay YAML and are read directly).
fn load_evidence(work: &Workdir, rel: &str) -> serde_json::Value {
    serde_json::from_str(&fs::read_to_string(work.path(rel)).unwrap()).unwrap()
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
while IFS='	' read -r path content || [ -n "$path" ]; do
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
while IFS='	' read -r path content || [ -n "$path" ]; do
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
    let capture = load_evidence(&work, &format!("frf/captures/{run}/capture.json"));
    let ref_prod = &capture["reference"]["produced"];
    let cand_prod = &capture["candidate"]["produced"];
    assert_eq!(ref_prod["schema_version"], "frf-produced-v1");
    assert_eq!(ref_prod["manifest_sha256"].as_str().unwrap().len(), 64);
    assert_ne!(
        ref_prod["manifest_sha256"], cand_prod["manifest_sha256"],
        "the produced trees differ, so their manifests must differ"
    );

    // The residuals: one per differing file, surfaced by path.
    let residuals: Vec<serde_json::Value> = fs::read_dir(work.path("frf/residuals"))
        .unwrap()
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
        .filter(|e| {
            !e.file_name().to_string_lossy().contains(".token")
                && !e.file_name().to_string_lossy().contains(".events")
        })
        .map(|e| {
            load_evidence(
                &work,
                &format!("frf/residuals/{}", e.file_name().to_string_lossy()),
            )
        })
        .collect();
    let tree_residuals: Vec<&serde_json::Value> = residuals
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
        serde_yaml::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
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

#[test]
fn a_mode_divergence_is_preserved_alongside_a_content_divergence() {
    // One file diverges in CONTENT and in EXECUTABLE STATE at once. That is
    // two observable facts, and FRF preserves BOTH residuals: a trajectory
    // must be able to watch a content divergence vanish while a mode
    // divergence persists (the older comparator suppressed the mode residual
    // whenever the bytes also differed — a residual was thrown away).
    let work = Workdir::new("noncli-tree-mode");
    write_files(
        &work,
        &[
            (
                "treegen-ref.sh",
                "#!/bin/sh\nset -u\nwhile [ $# -gt 0 ]; do case \"$1\" in --out) out=\"$2\"; shift 2;; *) shift;; esac; done\n[ -n \"$out\" ] || exit 2\nrm -rf \"$out\"\nmkdir -p \"$out/bin\"\nprintf '#!/bin/sh\\necho ref-tool\\n' > \"$out/bin/tool\"\nchmod +x \"$out/bin/tool\"\nexit 0\n",
            ),
            (
                "treegen-cand.sh",
                "#!/bin/sh\nset -u\nwhile [ $# -gt 0 ]; do case \"$1\" in --out) out=\"$2\"; shift 2;; *) shift;; esac; done\n[ -n \"$out\" ] || exit 2\nrm -rf \"$out\"\nmkdir -p \"$out/bin\"\nprintf '#!/bin/sh\\necho cand-tool\\n' > \"$out/bin/tool\"\nexit 0\n",
            ),
            ("frf/courts/fs-tree-build/manifest.yaml", TREE_MANIFEST),
            (
                "frf/courts/fs-tree-build/fixtures/tree-spec.conf",
                "bin/tool\tignored-by-these-scripts\n",
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
    assert_success(&out, "tree court run (mode + content divergence)");
    let run = stdout(&out);

    let residuals: Vec<serde_json::Value> = fs::read_dir(work.path("frf/residuals"))
        .unwrap()
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
        .filter(|e| {
            !e.file_name().to_string_lossy().contains(".token")
                && !e.file_name().to_string_lossy().contains(".events")
        })
        .map(|e| {
            load_evidence(
                &work,
                &format!("frf/residuals/{}", e.file_name().to_string_lossy()),
            )
        })
        .collect();
    let surfaces: Vec<(String, String, String)> = residuals
        .iter()
        .filter(|r| r["axis"] == "filesystem.tree")
        .map(|r| {
            (
                r["surface"].as_str().unwrap().to_string(),
                r["raw_reference"].as_str().unwrap().to_string(),
                r["raw_candidate"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert_eq!(
        surfaces.len(),
        2,
        "content + mode are two residuals, not one: {surfaces:?}"
    );
    let content = surfaces
        .iter()
        .find(|(s, _, _)| s == "path:bin/tool")
        .expect("content divergence surfaced");
    assert_ne!(content.1, content.2, "different contents are divergent");
    let mode = surfaces
        .iter()
        .find(|(s, _, _)| s == "path:bin/tool#executable")
        .expect("mode divergence surfaced");
    assert_eq!(mode.1, "true", "reference tool is executable");
    assert_eq!(mode.2, "false", "candidate tool is not executable");

    // Both residuals re-derive through the one comparison relation: the
    // verified read accepts them (and would refuse a residual the comparator
    // did not generate). The ids are content addresses.
    let store = Store::new(work.path(ROOT));
    for (_, id) in residual_ids(&work, &run) {
        let verified = frf::verify::load_residual_verified(&store, &id).unwrap();
        assert_eq!(verified.record().run, run);
        assert_eq!(verified.record().axis.as_str(), "filesystem.tree");
    }
}

/// The tree court manifest plus a declared EXTERNAL mutation provider
/// (spec/mutation.md). The provider proposes a mutant candidate; the court
/// runs the proposal and independently decides the verdicts.
fn tree_manifest_with_mutation(provider_id: &str, program: &str, relation: &str) -> String {
    format!(
        "court:\n  id: fs-tree-build\n  question: >-\n    For the build spec in fixture family tree-build, does the candidate\n    produce the same filesystem tree as the reference?\n  falsifier: >-\n    The candidate's produced tree diverges from the reference's on some\n    path or file content.\n  authority: treegen-ref-1.0\n  candidate:\n    name: treegen-cand\n    version_or_commit: \"0.1.0\"\n    build_profile: debug\n    path: treegen-cand.sh\n  fixture:\n    id: tree-spec.conf\n    path: frf/courts/fs-tree-build/fixtures/tree-spec.conf\n    arguments: [\"--spec\", \"{{fixture}}\", \"--out\", \"{{output}}\"]\n  admissibility_envelope:\n    fixture_family: tree-build\n    platforms: [\"x86_64-linux\"]\n    observables: [filesystem.tree]\n    normalizers: []\n    replay_scope: single-run\n  produce:\n    path: tree-out/\nmutations:\n    - id: {provider_id}\n      relation: {relation}\n      relation_version: \"1\"\n      target_axes: [filesystem.tree]\n      program: {program}\n"
    )
}

/// The external mutation provider: reads the canonical request, rebuilds the
/// reference artifact, and PROPOSES a mutant that replaces every produced
/// file's content with a fixed marker — a domain mutation the built-in
/// operators cannot express (it alters the produced TREE, not exit/stderr/
/// stdout).
const TREE_MUTATOR: &str = "#!/usr/bin/env python3\n\
import base64, hashlib, json, sys\n\
raw = sys.stdin.buffer.read()\n\
req = json.loads(raw.decode(\"utf-8\"))\n\
assert req[\"schema_version\"] == \"frf-mutation-request-v1\", req\n\
request_id = hashlib.sha256(raw).hexdigest()\n\
ref = base64.b64decode(req[\"reference_artifact\"][\"contents_base64\"]).decode(\"utf-8\")\n\
# Deterministic domain mutation: every produced file's content is replaced.\nmutant = ref.replace(\n\
    \"printf '%s\\\\n' \\\"$content\\\" > \\\"$out/$path\\\"\",\n\
    \"printf 'MUTATED-DEFECT\\\\n' > \\\"$out/$path\\\"\",\n\
)\n\
assert mutant != ref, \"the mutant must differ from the reference\"\n\
response = {\n\
    \"schema_version\": \"frf-mutation-response-v1\",\n\
    \"request_id\": request_id,\n\
    \"mutant_base64\": base64.b64encode(mutant.encode(\"utf-8\")).decode(\"ascii\"),\n\
    \"expected_affected_surfaces\": [\"filesystem.tree\"],\n\
    \"failure\": None,\n\
}\n\
json.dump(response, sys.stdout, sort_keys=True, separators=(\",\", \":\"))\n";

#[test]
fn an_external_mutation_provider_proposes_a_domain_mutant_and_the_court_decides() {
    let work = Workdir::new("noncli-tree-mutation");
    write_files(
        &work,
        &[
            ("treegen-ref.sh", TREE_REF),
            ("treegen-cand.sh", TREE_CAND),
            ("treegen-mutate.py", TREE_MUTATOR),
            (
                "frf/courts/fs-tree-build/manifest.yaml",
                &tree_manifest_with_mutation(
                    "treegen-content-swap",
                    "treegen-mutate.py",
                    "produced-content-swap",
                ),
            ),
            (
                "frf/courts/fs-tree-build/fixtures/tree-spec.conf",
                "src/main.c\t#include <stdio.h>\nREADME.md\t# treegen\nbuild/config\tDEBUG=0\n",
            ),
        ],
    );
    admit(&work, "treegen-ref.sh", "treegen-ref", "1.0");

    // The external operator: the provider proposes; the court runs the
    // proposal and must observe the seeded tree defect and only it.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "court",
            "challenge",
            "frf/courts/fs-tree-build/manifest.yaml",
            "--operators",
            "treegen-content-swap",
        ],
    );
    assert_success(&out, "external mutation challenge");
    assert!(
        stderr(&out).contains("court can see this defect class"),
        "stderr: {}",
        stderr(&out)
    );

    // The challenge record: operator = the provider id, verdicts rederive
    // from the run, and the mutation evidence is bound + cross-verified.
    let store = Store::new(work.path(ROOT));
    let mut found = 0;
    for entry in fs::read_dir(work.path("frf/challenges")).unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().to_string();
        if !name.ends_with(".json") {
            continue;
        }
        let id = name.trim_end_matches(".json").to_string();
        let ch = store.load_challenge(&id).unwrap();
        if ch.operator != "treegen-content-swap" {
            continue;
        }
        found += 1;
        assert_eq!(ch.target_axis, "filesystem.tree");
        assert!(ch.saw_defect && ch.specificity_clean);
        let inv_id = ch.mutation_invocation_id.expect("mutation invocation id");
        let res_id = ch.mutation_result_id.expect("mutation result id");
        // The preserved evidence is cross-verified on read: identities
        // rederive, the response names its request, the mutant rehashes to
        // the challenge's recorded mutant hash.
        let evidence = store.load_mutation_evidence(&id).unwrap();
        assert_eq!(evidence.invocation.invocation_id, inv_id);
        assert_eq!(evidence.result.result_id, res_id);
        assert_eq!(evidence.invocation.operator, "treegen-content-swap");
        assert_eq!(evidence.invocation.target_axis, "filesystem.tree");
        assert_eq!(evidence.result.mutant_sha256, ch.mutant_candidate_sha256);
        assert_eq!(
            evidence.result.expected_affected_surfaces,
            vec!["filesystem.tree".to_string()]
        );
        // The mutant object is content-addressed like any candidate.
        assert!(store
            .object_path(&ch.mutant_candidate_sha256)
            .unwrap()
            .is_file());
    }
    assert_eq!(found, 1, "exactly one external-mutation challenge");
}

#[test]
fn a_mutation_provider_that_does_not_move_the_target_axis_is_refused() {
    // The extension PROPOSES; the court DECIDES. A provider whose mutant
    // leaves the targeted surface unchanged is a blind challenge — the court
    // observes no divergence, saw_defect rederives false, and the command
    // refuses (the records remain as evidence).
    let work = Workdir::new("noncli-tree-mutation-blind");
    // A provider that mutates the generator's COMMENT: the script differs
    // from the reference (a real proposal) but the produced TREE is
    // byte-identical — the targeted surface does not move.
    let blind_mutator = TREE_MUTATOR.replace(
        "printf 'MUTATED-DEFECT\\\\n' > \\\"$out/$path\\\"",
        "printf 'MUTATED-COMMENT\\\\n' > /dev/null; printf '%s\\\\n' \\\"$content\\\" > \\\"$out/$path\\\"",
    );
    write_files(
        &work,
        &[
            ("treegen-ref.sh", TREE_REF),
            ("treegen-cand.sh", TREE_CAND),
            ("treegen-mutate.py", &blind_mutator),
            (
                "frf/courts/fs-tree-build/manifest.yaml",
                &tree_manifest_with_mutation(
                    "treegen-content-swap",
                    "treegen-mutate.py",
                    "produced-content-swap",
                ),
            ),
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
            "challenge",
            "frf/courts/fs-tree-build/manifest.yaml",
            "--operators",
            "treegen-content-swap",
        ],
    );
    assert!(!out.status.success(), "a blind challenge must be refused");
    assert!(
        stderr(&out).contains("observed NO divergence on the targeted axis"),
        "stderr: {}",
        stderr(&out)
    );
    // The refusal record remains as evidence: the mutation was proposed and
    // the court ran it — and could not see the (nonexistent) defect.
    let store = Store::new(work.path(ROOT));
    let mut found = 0;
    for entry in fs::read_dir(work.path("frf/challenges")).unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().to_string();
        if !name.ends_with(".json") {
            continue;
        }
        let id = name.trim_end_matches(".json").to_string();
        let ch = store.load_challenge(&id).unwrap();
        if ch.operator != "treegen-content-swap" {
            continue;
        }
        found += 1;
        assert!(!ch.saw_defect, "the mutant did not move the tree surface");
        let evidence = store.load_mutation_evidence(&id).unwrap();
        assert_eq!(evidence.result.outcome, "proposed");
    }
    assert_eq!(found, 1, "the refusal record remains as evidence");
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
    let capture = load_evidence(&work, &format!("frf/captures/{run}/capture.json"));
    assert_ne!(
        capture["reference"]["stdout_sha256"], capture["candidate"]["stdout_sha256"],
        "one byte differs, so the stream hashes must differ"
    );
    let residual: serde_json::Value = load_evidence(
        &work,
        &format!(
            "frf/residuals/{}.json",
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
    let capture = load_evidence(&work, &format!("frf/captures/{run}/capture.json"));
    let residual: serde_json::Value = load_evidence(
        &work,
        &format!(
            "frf/residuals/{}.json",
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
    sys.stdout.write(json.dumps({**base, "equivalent": False, "residuals": [out]}, sort_keys=True, separators=(",", ":")))
elif cand <= 2 * ref:
    sys.stdout.write(json.dumps({**base, "equivalent": True, "residuals": []}, sort_keys=True, separators=(",", ":")))
else:
    out = {"surface": "latency-ratio", "raw_reference": str(ref), "raw_candidate": str(cand)}
    sys.stdout.write(json.dumps({**base, "equivalent": False, "residuals": [out]}, sort_keys=True, separators=(",", ":")))
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
    let capture = load_evidence(&work, &format!("frf/captures/{run}/capture.json"));
    assert_eq!(capture["residuals"].as_array().unwrap().len(), 1);
    let residual: serde_json::Value = load_evidence(
        &work,
        &format!(
            "frf/residuals/{}.json",
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
    let capture2 = load_evidence(&work, &format!("frf/captures/{run2}/capture.json"));
    assert_eq!(
        capture2["residuals"].as_array().unwrap().len(),
        0,
        "15 <= 2*10: within the envelope, no residual"
    );
}
