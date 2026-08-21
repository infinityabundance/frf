//! The empirical program — Phase 9.
//!
//! Seeded mutations over a cross-domain corpus, measured against
//! conventional suites. Drives the REAL `frf` reference engine (as a
//! subprocess) over five courts — CLI, filesystem tree, byte/wire,
//! structured state, timing — each with a clean control and seeded mutants,
//! and measures:
//!
//! 1. **defect discovery** — every seeded mutation must produce a residual
//!    on its targeted axis (sensitivity); a clean candidate must produce
//!    zero residuals (specificity, i.e. false positives);
//! 2. **claim inflation** — with a defective candidate the claim compiler
//!    must be blocked; with a clean candidate the bounded claim must compile
//!    and its observable scope must cover exactly the declared axes;
//! 3. **minimization cost** — deterministic ddmin: attempts and fixture
//!    reduction per routed residual (and the honest refusal where a surface
//!    has no reducer);
//! 4. **replay stability** — every run replayed three times, byte-identical
//!    reproduction;
//! 5. **evidence overhead** — the bytes FRF generates per observation vs a
//!    conventional pass/fail baseline.
//!
//! The corpus is deterministic and self-contained (regenerated under
//! `golden/work/experiment/`); the report is canonical JSON. `--check`
//! (default) exits non-zero when the measurements violate the standards:
//! any undetected seeded defect, any false positive, any claim compiled on
//! a defective run, or any replay that did not reproduce.
//!
//! This is a MEASUREMENT harness, distinct from the independent verifier:
//! it executes the reference engine to measure it, rather than verifying
//! evidence without executing anything.

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// One case in a court: a candidate script, either clean (no seeded defect)
/// or a seeded mutant.
struct Case {
    id: &'static str,
    candidate: (&'static str, &'static str),
    /// True = a seeded defect the court must see; false = a clean control.
    seeded: bool,
    /// The axis the seeded defect targets (clean cases target none).
    target_axis: &'static str,
}

/// One court: reference, fixture, authority, envelope, and its cases.
struct Court {
    id: &'static str,
    authority: (&'static str, &'static str),
    reference: (&'static str, &'static str),
    fixture: (&'static str, &'static str),
    observables: &'static [&'static str],
    /// The manifest TEMPLATE: `{candidate}` is substituted per case, and
    /// `{fixture}` / `{output}` are the court's substitution slots.
    manifest: &'static str,
    /// The produce clause path (filesystem tree only), else None.
    produce: Option<&'static str>,
    cases: &'static [Case],
}

// ---------------------------------------------------------------------------
// The corpus
// ---------------------------------------------------------------------------

/// The cross-domain corpus. Everything is deterministic; the scripts mirror
/// the golden courts and the Phase-8 non-CLI courts.
fn corpus() -> Vec<Court> {
    const CLI_REF: &str = "#!/bin/sh\n\
         # ref-cli: parses a directive file; malformed directives exit 2.\n\
         set -u\n\
         file=\"\"\n\
         for arg in \"$@\"; do\n  case \"$arg\" in\n    --strict) ;;\n    *) file=\"$arg\" ;;\n  esac\n\
         done\n\
         [ -n \"$file\" ] || { echo \"tool: no input file\" >&2; exit 2; }\n\
         line=0\n\
         while IFS= read -r entry || [ -n \"$entry\" ]; do\n\
           line=$((line + 1))\n\
           case \"$entry\" in\n\
             '' | \\#*) continue ;;\n\
             server\\ * | listen\\ * | log\\ *) echo \"ok: $entry\" ;;\n\
             *) echo \"tool: $file:$line: unknown directive '$entry'\" >&2; exit 2 ;;\n\
           esac\n\
         done <\"$file\"\n\
         exit 0\n";
    const CLI_CLEAN: &str = "#!/bin/sh\n\
         # clean candidate: identical behavior to the reference.\n\
         set -u\n\
         file=\"\"\n\
         for arg in \"$@\"; do\n  case \"$arg\" in\n    --strict) ;;\n    *) file=\"$arg\" ;;\n  esac\n\
         done\n\
         [ -n \"$file\" ] || { echo \"tool: no input file\" >&2; exit 2; }\n\
         line=0\n\
         while IFS= read -r entry || [ -n \"$entry\" ]; do\n\
           line=$((line + 1))\n\
           case \"$entry\" in\n\
             '' | \\#*) continue ;;\n\
             server\\ * | listen\\ * | log\\ *) echo \"ok: $entry\" ;;\n\
             *) echo \"tool: $file:$line: unknown directive '$entry'\" >&2; exit 2 ;;\n\
           esac\n\
         done <\"$file\"\n\
         exit 0\n";
    const CLI_EXIT_MUTANT: &str = "#!/bin/sh\n\
         # mutant: same behavior, but the malformed-input exit class is 3\n\
         # instead of the reference's 2 — the seeded exit defect.\n\
         set -u\n\
         file=\"\"\n\
         for arg in \"$@\"; do\n  case \"$arg\" in\n    --strict) ;;\n    *) file=\"$arg\" ;;\n  esac\n\
         done\n\
         [ -n \"$file\" ] || { echo \"cand: no input file\" >&2; exit 3; }\n\
         line=0\n\
         while IFS= read -r entry || [ -n \"$entry\" ]; do\n\
           line=$((line + 1))\n\
           case \"$entry\" in\n\
             '' | \\#*) continue ;;\n\
             server\\ * | listen\\ * | log\\ *) echo \"ok: $entry\" ;;\n\
             *) echo \"tool: $file:$line: unknown directive '$entry'\" >&2; exit 3 ;;\n\
           esac\n\
         done <\"$file\"\n\
         exit 0\n";
    const CLI_STDERR_MUTANT: &str = "#!/bin/sh\n\
         # mutant: same behavior, but the diagnostic wording differs — the\n\
         # seeded first-stderr-line defect.\n\
         set -u\n\
         file=\"\"\n\
         for arg in \"$@\"; do\n  case \"$arg\" in\n    --strict) ;;\n    *) file=\"$arg\" ;;\n  esac\n\
         done\n\
         [ -n \"$file\" ] || { echo \"cand: no input file\" >&2; exit 2; }\n\
         line=0\n\
         while IFS= read -r entry || [ -n \"$entry\" ]; do\n\
           line=$((line + 1))\n\
           case \"$entry\" in\n\
             '' | \\#*) continue ;;\n\
             server\\ * | listen\\ * | log\\ *) echo \"ok: $entry\" ;;\n\
             *) echo \"error: unknown directive $entry at line $line\" >&2; exit 2 ;;\n\
           esac\n\
         done <\"$file\"\n\
         exit 0\n";

    const TREE_REF: &str = "#!/bin/sh\n\
         # treegen-ref: read a spec (path<TAB>content) and build the tree.\n\
         set -u\n\
         spec=\"\"; out=\"\"\n\
         while [ $# -gt 0 ]; do\n  case \"$1\" in\n    --spec) spec=\"$2\"; shift 2 ;;\n    --out) out=\"$2\"; shift 2 ;;\n    *) shift ;;\n  esac\n\
         done\n\
         [ -n \"$spec\" ] && [ -n \"$out\" ] || exit 2\n\
         rm -rf \"$out\"\n\
         while IFS=$'\\t' read -r path content || [ -n \"$path\" ]; do\n\
           [ -z \"$path\" ] && continue\n\
           case \"$path\" in \\#*) continue ;; esac\n\
           mkdir -p \"$out/$(dirname \"$path\")\"\n\
           printf '%s\\n' \"$content\" > \"$out/$path\"\n\
         done < \"$spec\"\n\
         exit 0\n";
    const TREE_CLEAN: &str = TREE_REF;
    const TREE_CONTENT_MUTANT: &str = "#!/bin/sh\n\
         # mutant: identical, but src/main.c has different content.\n\
         set -u\n\
         spec=\"\"; out=\"\"\n\
         while [ $# -gt 0 ]; do\n  case \"$1\" in\n    --spec) spec=\"$2\"; shift 2 ;;\n    --out) out=\"$2\"; shift 2 ;;\n    *) shift ;;\n  esac\n\
         done\n\
         [ -n \"$spec\" ] && [ -n \"$out\" ] || exit 2\n\
         rm -rf \"$out\"\n\
         while IFS=$'\\t' read -r path content || [ -n \"$path\" ]; do\n\
           [ -z \"$path\" ] && continue\n\
           case \"$path\" in \\#*) continue ;; esac\n\
           mkdir -p \"$out/$(dirname \"$path\")\"\n\
           if [ \"$path\" = \"src/main.c\" ]; then\n\
             printf '%s\\n' \"int main(void){return 0;}\" > \"$out/$path\"\n\
           else\n\
             printf '%s\\n' \"$content\" > \"$out/$path\"\n\
           fi\n\
         done < \"$spec\"\n\
         exit 0\n";
    const TREE_ABSENT_MUTANT: &str = "#!/bin/sh\n\
         # mutant: identical, but build/config is dropped entirely.\n\
         set -u\n\
         spec=\"\"; out=\"\"\n\
         while [ $# -gt 0 ]; do\n  case \"$1\" in\n    --spec) spec=\"$2\"; shift 2 ;;\n    --out) out=\"$2\"; shift 2 ;;\n    *) shift ;;\n  esac\n\
         done\n\
         [ -n \"$spec\" ] && [ -n \"$out\" ] || exit 2\n\
         rm -rf \"$out\"\n\
         while IFS=$'\\t' read -r path content || [ -n \"$path\" ]; do\n\
           [ -z \"$path\" ] && continue\n\
           case \"$path\" in \\#*) continue ;; esac\n\
           [ \"$path\" = \"build/config\" ] && continue\n\
           mkdir -p \"$out/$(dirname \"$path\")\"\n\
           printf '%s\\n' \"$content\" > \"$out/$path\"\n\
         done < \"$spec\"\n\
         exit 0\n";

    vec![
        Court {
            id: "cli-malformed-input",
            authority: ("ref-cli", "1.0"),
            reference: ("scripts/cli-ref.sh", CLI_REF),
            fixture: (
                "courts/cli-malformed-input/fixtures/malformed.conf",
                "server 10.0.0.1\nlisten 8080\nservre bogus\n",
            ),
            observables: &["exit", "stderr"],
            manifest: "court:\n  id: cli-malformed-input\n  question: >-\n    For malformed input in fixture family malformed-input, does the candidate\n    preserve the admitted reference's exit class and first diagnostic line?\n  falsifier: >-\n    The candidate's exit class or first diagnostic line diverges from the\n    admitted reference on a fixture in family malformed-input.\n  authority: ref-cli-1.0\n  candidate:\n    name: cand-cli\n    version_or_commit: \"0.1.0\"\n    build_profile: debug\n    path: {candidate}\n  fixture:\n    id: malformed.conf\n    path: courts/cli-malformed-input/fixtures/malformed.conf\n    arguments: [\"--strict\", \"{fixture}\"]\n  admissibility_envelope:\n    fixture_family: malformed-input\n    platforms: [\"x86_64-linux\"]\n    observables: [exit, stderr]\n    normalizers: []\n    replay_scope: single-run\n",
            produce: None,
            cases: &[
                Case { id: "clean", candidate: ("scripts/cli-clean.sh", CLI_CLEAN), seeded: false, target_axis: "" },
                Case { id: "mutant-exit-class", candidate: ("scripts/cli-exit.sh", CLI_EXIT_MUTANT), seeded: true, target_axis: "exit" },
                Case { id: "mutant-stderr-first-line", candidate: ("scripts/cli-stderr.sh", CLI_STDERR_MUTANT), seeded: true, target_axis: "stderr" },
            ],
        },
        Court {
            id: "fs-tree-build",
            authority: ("treegen-ref", "1.0"),
            reference: ("scripts/treegen-ref.sh", TREE_REF),
            fixture: (
                "courts/fs-tree-build/fixtures/tree-spec.conf",
                "src/main.c\t#include <stdio.h>\nREADME.md\t# treegen\nbuild/config\tDEBUG=0\n",
            ),
            observables: &["filesystem.tree"],
            manifest: "court:\n  id: fs-tree-build\n  question: >-\n    For the build spec in fixture family tree-build, does the candidate\n    produce the same filesystem tree as the reference?\n  falsifier: >-\n    The candidate's produced tree diverges from the reference's on some\n    path or file content.\n  authority: treegen-ref-1.0\n  candidate:\n    name: treegen-cand\n    version_or_commit: \"0.1.0\"\n    build_profile: debug\n    path: {candidate}\n  fixture:\n    id: tree-spec.conf\n    path: courts/fs-tree-build/fixtures/tree-spec.conf\n    arguments: [\"--spec\", \"{fixture}\", \"--out\", \"{output}\"]\n  admissibility_envelope:\n    fixture_family: tree-build\n    platforms: [\"x86_64-linux\"]\n    observables: [filesystem.tree]\n    normalizers: []\n    replay_scope: single-run\n  produce:\n    path: out/\n",
            produce: Some("out/"),
            cases: &[
                Case { id: "clean", candidate: ("scripts/treegen-clean.sh", TREE_CLEAN), seeded: false, target_axis: "" },
                Case { id: "mutant-content", candidate: ("scripts/treegen-content.sh", TREE_CONTENT_MUTANT), seeded: true, target_axis: "filesystem.tree" },
                Case { id: "mutant-absent", candidate: ("scripts/treegen-absent.sh", TREE_ABSENT_MUTANT), seeded: true, target_axis: "filesystem.tree" },
            ],
        },
        Court {
            id: "wire-encode",
            authority: ("wire-ref", "1.0"),
            reference: ("scripts/wire-ref.sh", "#!/bin/sh\nprintf '\\001\\002\\003\\004' >&1\n"),
            fixture: (
                "courts/wire-encode/fixtures/packet-spec.conf",
                "packet: 4\n",
            ),
            observables: &["bytes.wire"],
            manifest: "court:\n  id: wire-encode\n  question: >-\n    For the packet spec in fixture family wire-encode, does the candidate\n    emit the same wire bytes as the reference?\n  falsifier: >-\n    The candidate's emitted bytes diverge from the reference's.\n  authority: wire-ref-1.0\n  candidate:\n    name: wire-cand\n    version_or_commit: \"0.1.0\"\n    build_profile: debug\n    path: {candidate}\n  fixture:\n    id: packet-spec.conf\n    path: courts/wire-encode/fixtures/packet-spec.conf\n    arguments: [\"{fixture}\"]\n  admissibility_envelope:\n    fixture_family: wire-encode\n    platforms: [\"x86_64-linux\"]\n    observables: [bytes.wire]\n    normalizers: []\n    replay_scope: single-run\n",
            produce: None,
            cases: &[
                Case { id: "clean", candidate: ("scripts/wire-clean.sh", "#!/bin/sh\nprintf '\\001\\002\\003\\004' >&1\n"), seeded: false, target_axis: "" },
                Case { id: "mutant-byte", candidate: ("scripts/wire-byte.sh", "#!/bin/sh\nprintf '\\001\\002\\377\\004' >&1\n"), seeded: true, target_axis: "bytes.wire" },
            ],
        },
        Court {
            id: "state-json",
            authority: ("state-ref", "1.0"),
            reference: ("scripts/state-ref.sh", "#!/bin/sh\necho '{\"config\":{\"timeout\":5,\"retries\":2},\"status\":\"ok\"}'\n"),
            fixture: (
                "courts/state-json/fixtures/state-spec.conf",
                "state: config\n",
            ),
            observables: &["structured.state"],
            manifest: "court:\n  id: state-json\n  question: >-\n    For the state spec in fixture family state-json, does the candidate\n    preserve the reference's structured state?\n  falsifier: >-\n    The candidate's emitted JSON state diverges from the reference's on\n    some field.\n  authority: state-ref-1.0\n  candidate:\n    name: state-cand\n    version_or_commit: \"0.1.0\"\n    build_profile: debug\n    path: {candidate}\n  fixture:\n    id: state-spec.conf\n    path: courts/state-json/fixtures/state-spec.conf\n    arguments: [\"{fixture}\"]\n  admissibility_envelope:\n    fixture_family: state-json\n    platforms: [\"x86_64-linux\"]\n    observables: [structured.state]\n    normalizers: []\n    replay_scope: single-run\n",
            produce: None,
            cases: &[
                Case { id: "clean", candidate: ("scripts/state-clean.sh", "#!/bin/sh\necho '{\"config\":{\"timeout\":5,\"retries\":2},\"status\":\"ok\"}'\n"), seeded: false, target_axis: "" },
                Case { id: "mutant-field", candidate: ("scripts/state-field.sh", "#!/bin/sh\necho '{\"config\":{\"timeout\":9,\"retries\":2},\"status\":\"ok\"}'\n"), seeded: true, target_axis: "structured.state" },
            ],
        },
        Court {
            id: "timing-bench",
            authority: ("timing-ref", "1.0"),
            reference: ("scripts/timing-ref.sh", "#!/bin/sh\nsleep 0.01\necho 'duration_ms 10'\n"),
            fixture: (
                "courts/timing-bench/fixtures/bench-spec.conf",
                "bench: latency\n",
            ),
            observables: &["timing.latency"],
            manifest: "court:\n  id: timing-bench\n  question: >-\n    For the bench spec in fixture family timing-bench, is the candidate's\n    latency within the declared envelope of the reference's?\n  falsifier: >-\n    The candidate's latency exceeds twice the reference's.\n  authority: timing-ref-1.0\n  candidate:\n    name: timing-cand\n    version_or_commit: \"0.1.0\"\n    build_profile: debug\n    path: {candidate}\n  fixture:\n    id: bench-spec.conf\n    path: courts/timing-bench/fixtures/bench-spec.conf\n    arguments: [\"{fixture}\"]\n  admissibility_envelope:\n    fixture_family: timing-bench\n    platforms: [\"x86_64-linux\"]\n    observables: [timing.latency]\n    normalizers: []\n    replay_scope: single-run\ncomparators:\n  - axis: timing.latency\n    relation: within-2x\n    extractor: latency-ms\n    residual_classifier: text\n    relation_version: \"v1\"\n    program: scripts/timing-compare.py\n",
            produce: None,
            cases: &[
                Case { id: "clean", candidate: ("scripts/timing-clean.sh", "#!/bin/sh\nsleep 0.01\necho 'duration_ms 15'\n"), seeded: false, target_axis: "" },
                Case { id: "mutant-latency", candidate: ("scripts/timing-latency.sh", "#!/bin/sh\nsleep 0.01\necho 'duration_ms 30'\n"), seeded: true, target_axis: "timing.latency" },
            ],
        },
    ]
}

/// The timing court's external envelope comparator (the extension protocol).
/// (The Python is built with explicit `\n` escapes — the Rust `\n\` line
/// continuation strips leading whitespace, which would destroy the
/// function-body indentation.)
const TIMING_COMPARATOR: &str = "#!/usr/bin/env python3\n# timing envelope comparator: the declared relation is `within-2x` — the\n# candidate's latency must be at most twice the reference's.\nimport base64, hashlib, json, re, sys\nraw = sys.stdin.buffer.read()\nreq = json.loads(raw.decode(\"utf-8\"))\nrequest_id = hashlib.sha256(raw).hexdigest()\ndef dur(side):\n    text = base64.b64decode(side[\"stdout_base64\"]).decode(\"utf-8\", \"replace\")\n    m = re.search(r\"duration_ms (\\d+)\", text)\n    return int(m.group(1)) if m else None\nref = dur(req[\"reference\"])\ncand = dur(req[\"candidate\"])\nbase = {\"schema_version\": \"frf-comparator-response-v2\", \"request_id\": request_id, \"indeterminate\": False, \"failure\": None}\nif ref is None or cand is None:\n    out = {\"surface\": \"latency-parse\", \"raw_reference\": str(ref), \"raw_candidate\": str(cand)}\n    print(json.dumps({**base, \"equivalent\": False, \"residuals\": [out]}, separators=(\",\", \":\")))\nelif cand <= 2 * ref:\n    print(json.dumps({**base, \"equivalent\": True, \"residuals\": []}, separators=(\",\", \":\")))\nelse:\n    out = {\"surface\": \"latency-ratio\", \"raw_reference\": str(ref), \"raw_candidate\": str(cand)}\n    print(json.dumps({**base, \"equivalent\": False, \"residuals\": [out]}, separators=(\",\", \":\")))\n";

// ---------------------------------------------------------------------------
// Harness plumbing
// ---------------------------------------------------------------------------

fn dir_size(path: &Path) -> u64 {
    let mut total = 0u64;
    if path.is_file() {
        return path.metadata().map(|m| m.len()).unwrap_or(0);
    }
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            total += dir_size(&entry.path());
        }
    }
    total
}

/// Run the frf binary from the corpus cwd. Returns (exit_ok, stdout, stderr).
fn run_frf(frf: &Path, corpus: &Path, args: &[&str]) -> (bool, String, String) {
    let out = Command::new(frf)
        .args(args)
        .current_dir(corpus)
        .output()
        .unwrap_or_else(|e| panic!("cannot execute {frf:?}: {e}"));
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).trim().to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

fn load_yaml(path: &Path) -> Value {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_yaml::from_str(&text).unwrap_or_else(|e| panic!("cannot parse {}: {e}", path.display()))
}

fn as_str(v: &Value) -> &str {
    v.as_str().unwrap_or_default()
}

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

/// One measured observation.
struct Observed {
    court: String,
    case: String,
    seeded: bool,
    target_axis: String,
    run: String,
    residual_axes: Vec<String>,
    residual_surfaces: Vec<(String, String)>,
    claim_compiled: bool,
    claim_scope: Vec<String>,
    evidence_bytes: u64,
    replays_ok: u32,
}

pub fn run(repo_root: &Path, out_path: &Path, check: bool) {
    let frf = frf_bin(repo_root);
    let corpus_root = repo_root.join("golden").join("work").join("experiment");
    let _ = std::fs::remove_dir_all(&corpus_root);
    std::fs::create_dir_all(&corpus_root).unwrap();
    let ev = corpus_root.join("ev");

    let courts = corpus();

    // The timing comparator is shared by the timing court.
    write_file(
        &corpus_root,
        "scripts/timing-compare.py",
        TIMING_COMPARATOR,
        true,
    );

    let mut observed: Vec<Observed> = Vec::new();
    for court in &courts {
        write_file(&corpus_root, court.reference.0, court.reference.1, true);
        write_file(&corpus_root, court.fixture.0, court.fixture.1, false);
        admit(
            &frf,
            &corpus_root,
            court.reference.0,
            court.authority.0,
            court.authority.1,
        );

        for case in court.cases {
            write_file(&corpus_root, case.candidate.0, case.candidate.1, true);
            let manifest = court
                .manifest
                .replace("{candidate}", case.candidate.0)
                .replace("{fixture}", "PLACEHOLDER_FIXTURE") // see below
                .replace("{output}", court.produce.unwrap_or("out/"));
            // The fixture substitution slot must be the literal {fixture} in
            // the manifest; restore it.
            let manifest = manifest.replace("PLACEHOLDER_FIXTURE", "{fixture}");
            let manifest_rel = format!("courts/{}/cases/{}.yaml", court.id, case.id);
            write_file(&corpus_root, &manifest_rel, &manifest, false);

            let (ok, out, err) = run_frf(
                &frf,
                &corpus_root,
                &["--root", "ev", "court", "run", &manifest_rel],
            );
            if !ok {
                panic!(
                    "court run {}/{} failed:\nstdout: {out}\nstderr: {err}",
                    court.id, case.id
                );
            }
            let run = out.lines().last().unwrap_or_default().to_string();
            assert!(
                run.starts_with(&format!("run-{}", court.id)),
                "unexpected run id {run:?}"
            );

            // Parse the run: the capture's residual ids + axes/surfaces.
            let capture = load_yaml(&ev.join("captures").join(&run).join("capture.yaml"));
            let mut residual_axes = Vec::new();
            let mut residual_surfaces = Vec::new();
            for rid in capture["residuals"].as_array().cloned().unwrap_or_default() {
                let rid = as_str(&rid).to_string();
                let record = load_yaml(&ev.join("residuals").join(format!("{rid}.yaml")));
                residual_axes.push(as_str(&record["axis"]).to_string());
                residual_surfaces.push((
                    as_str(&record["axis"]).to_string(),
                    as_str(&record["surface"]).to_string(),
                ));
            }

            // Receipt + claim behavior.
            let (ok, receipt, _) = run_frf(
                &frf,
                &corpus_root,
                &["--root", "ev", "receipt", "emit", &run],
            );
            assert!(ok, "receipt emit failed for {}/{}", court.id, case.id);
            let receipt = receipt.trim().to_string();
            let (claim_ok, _, _) = run_frf(
                &frf,
                &corpus_root,
                &["--root", "ev", "claim", "compile", &receipt],
            );
            let mut claim_scope = Vec::new();
            if claim_ok {
                let claim = load_yaml(&ev.join("claims").join(format!("{receipt}.yaml")));
                for o in claim["scope"]["observables"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                {
                    claim_scope.push(as_str(&o).to_string());
                }
            }

            // Evidence bytes: the run's capture dir + its residuals + tokens.
            let mut evidence_bytes = dir_size(&ev.join("captures").join(&run));
            for rid in capture["residuals"].as_array().cloned().unwrap_or_default() {
                let rid = as_str(&rid).to_string();
                evidence_bytes += dir_size(&ev.join("residuals").join(format!("{rid}.yaml")));
                evidence_bytes += dir_size(&ev.join("residuals").join(format!("{rid}.token.yaml")));
            }

            // Replay stability: three exact replays.
            let mut replays_ok = 0u32;
            for _ in 0..3 {
                let (ok, out_text, _) = run_frf(
                    &frf,
                    &corpus_root,
                    &["--root", "ev", "replay", &run, "--policy", "exact"],
                );
                if ok && out_text.contains("reproduced") {
                    replays_ok += 1;
                }
            }

            observed.push(Observed {
                court: court.id.to_string(),
                case: case.id.to_string(),
                seeded: case.seeded,
                target_axis: case.target_axis.to_string(),
                run,
                residual_axes,
                residual_surfaces,
                claim_compiled: claim_ok,
                claim_scope,
                evidence_bytes,
                replays_ok,
            });
        }
    }

    // -- metrics -------------------------------------------------------------
    let seeded: Vec<&Observed> = observed.iter().filter(|o| o.seeded).collect();
    let clean: Vec<&Observed> = observed.iter().filter(|o| !o.seeded).collect();

    // Defect discovery: every seeded mutation produced a residual on its
    // targeted axis.
    let mut undetected: Vec<String> = Vec::new();
    for o in &seeded {
        if !o.residual_axes.iter().any(|a| a == &o.target_axis) {
            undetected.push(format!("{}/{}", o.court, o.case));
        }
    }
    let discovery = seeded.len().saturating_sub(undetected.len());

    // Specificity: clean controls produced zero residuals.
    let false_positives: Vec<&Observed> = clean
        .iter()
        .filter(|o| !o.residual_axes.is_empty())
        .copied()
        .collect();

    // Claims: on a DEFECTIVE run, a claim may compile ONLY scoped to the
    // clean axes — a claim covering the seeded-defect axis is claim
    // INFLATION (the compiler over-claimed). On a CLEAN run, the bounded
    // claim must compile and its observable scope must cover exactly the
    // court's declared axes.
    let claims_on_defective: Vec<&Observed> = seeded
        .iter()
        .filter(|o| o.claim_compiled)
        .copied()
        .collect();
    let mut inflated: Vec<String> = Vec::new();
    for o in &seeded {
        if o.claim_compiled && o.claim_scope.iter().any(|a| a == &o.target_axis) {
            inflated.push(format!("{}/{}", o.court, o.case));
        }
    }
    let claims_on_clean: Vec<&Observed> =
        clean.iter().filter(|o| o.claim_compiled).copied().collect();
    let mut scope_misses: Vec<String> = Vec::new();
    for o in &clean {
        let court_declared: Vec<&str> = courts
            .iter()
            .find(|c| c.id == o.court)
            .unwrap()
            .observables
            .to_vec();
        for a in court_declared {
            if !o.claim_scope.iter().any(|s| s == a) {
                scope_misses.push(format!("{}/{} lacks {}", o.court, o.case, a));
            }
        }
    }

    // Minimization cost: one residual per court where a reducer exists.
    let mut minimization: Vec<Value> = Vec::new();
    for court in &courts {
        // Pick the first seeded case's first residual on the target axis.
        let case = court
            .cases
            .iter()
            .find(|c| c.seeded)
            .expect("every court has a seeded case");
        let run = observed
            .iter()
            .find(|o| o.court == court.id && o.case == case.id)
            .unwrap();
        // The first seeded case's first residual on the target axis.
        let capture = load_yaml(&ev.join("captures").join(&run.run).join("capture.yaml"));
        let residual_id: Option<String> = {
            let mut on_axis: Vec<String> = Vec::new();
            for r in capture["residuals"].as_array().cloned().unwrap_or_default() {
                let rid = as_str(&r).to_string();
                let rec = load_yaml(&ev.join("residuals").join(format!("{rid}.yaml")));
                if as_str(&rec["axis"]) == run.target_axis {
                    on_axis.push(rid);
                }
            }
            on_axis.first().cloned()
        };
        let Some(residual_id) = residual_id else {
            continue;
        };
        let (ok, out, err) = run_frf(
            &frf,
            &corpus_root,
            &["--root", "ev", "court", "minimize", &residual_id],
        );
        if !ok {
            minimization.push(json!({
                "court": court.id,
                "axis": run.target_axis,
                "residual": residual_id,
                "refused": err.trim(),
            }));
            continue;
        }
        let reduction_id = out.lines().last().unwrap_or_default().to_string();
        let record = load_yaml(&ev.join("reductions").join(format!("{reduction_id}.yaml")));
        minimization.push(json!({
            "court": court.id,
            "axis": run.target_axis,
            "residual": residual_id,
            "reduction": reduction_id,
            "attempts": record["attempts"].as_array().map(|a| a.len()).unwrap_or(0),
            "original_lines": record["derivation"]["original_lines"],
            "final_lines": record["derivation"]["final_lines"],
            "minimality": {
                "kind": record["derivation"]["minimality"]["kind"],
                "granularity": record["derivation"]["minimality"]["granularity"],
                "proven": record["derivation"]["minimality"]["proven"],
            },
        }));
    }

    // Replay stability.
    let replay_attempts: u32 = observed.iter().map(|o| o.replays_ok).sum();
    let replay_total = observed.len() as u32 * 3;

    // Evidence overhead: FRF evidence bytes vs a conventional pass/fail
    // baseline (one short line per run, as a plain test runner would record).
    let frf_bytes: u64 = observed.iter().map(|o| o.evidence_bytes).sum();
    let baseline_bytes = observed.len() as u64 * 24; // ~24 bytes per pass/fail line
    let per_run: BTreeMap<String, u64> = observed
        .iter()
        .map(|o| (format!("{}/{}", o.court, o.case), o.evidence_bytes))
        .collect();
    let residuals_per_run: BTreeMap<String, Value> = observed
        .iter()
        .map(|o| {
            (
                format!("{}/{}", o.court, o.case),
                json!(o
                    .residual_surfaces
                    .iter()
                    .map(|(axis, surface)| json!({"axis": axis, "surface": surface}))
                    .collect::<Vec<_>>()),
            )
        })
        .collect();

    let report = json!({
        "schema_version": "frf-experiment-v1",
        "corpus": {
            "courts": courts.len(),
            "seeded_cases": seeded.len(),
            "clean_controls": clean.len(),
            "runs": observed.len(),
        },
        "defect_discovery": {
            "seeded": seeded.len(),
            "detected": discovery,
            "rate": if seeded.is_empty() { 0.0 } else { discovery as f64 / seeded.len() as f64 },
            "undetected": undetected,
        },
        "specificity": {
            "clean_runs": clean.len(),
            "false_positives": false_positives.len(),
            "rate": if clean.is_empty() { 0.0 } else { (clean.len() - false_positives.len()) as f64 / clean.len() as f64 },
            "false_positive_cases": false_positives.iter().map(|o| format!("{}/{}", o.court, o.case)).collect::<Vec<_>>(),
        },
        "claims": {
            "defective_runs": seeded.len(),
            "claims_compiled_scoped_to_clean_axes": claims_on_defective.len(),
            "inflated": inflated.len(),
            "inflation": if seeded.is_empty() { 0.0 } else { inflated.len() as f64 / seeded.len() as f64 },
            "inflated_cases": inflated,
            "clean_runs": clean.len(),
            "compiled_on_clean": claims_on_clean.len(),
            "scope_coverage_misses": scope_misses,
        },
        "minimization": minimization,
        "replay": {
            "attempts": replay_total,
            "reproduced": replay_attempts,
            "stability": if replay_total == 0 { 0.0 } else { replay_attempts as f64 / replay_total as f64 },
        },
        "evidence_overhead": {
            "frf_bytes": frf_bytes,
            "baseline_bytes": baseline_bytes,
            "ratio": if baseline_bytes == 0 { 0.0 } else { frf_bytes as f64 / baseline_bytes as f64 },
            "per_run_bytes": per_run,
        },
        "residuals_per_run": residuals_per_run,
    });

    std::fs::write(out_path, serde_json::to_string_pretty(&report).unwrap()).unwrap();

    // -- the printed summary -------------------------------------------------
    println!("FRF empirical program — seeded mutations over the cross-domain corpus");
    println!(
        "  corpus: {} court(s), {} seeded defect(s), {} clean control(s), {} run(s)",
        courts.len(),
        seeded.len(),
        clean.len(),
        observed.len()
    );
    println!(
        "  defect discovery: {}/{} detected (rate {:.0}%)",
        discovery,
        seeded.len(),
        discovery as f64 / seeded.len() as f64 * 100.0
    );
    println!(
        "  specificity: {} clean run(s), {} false positive(s)",
        clean.len(),
        false_positives.len()
    );
    println!("  claims: {} scoped clean-axis claim(s) compiled on defective run(s), {:.0}% claim inflation (a claim covering a seeded-defect axis), {} compiled on {} clean run(s)",
        claims_on_defective.len(),
        inflated.len() as f64 / seeded.len() as f64 * 100.0,
        claims_on_clean.len(), clean.len());
    for m in &minimization {
        if let Some(refused) = m.get("refused") {
            println!(
                "  minimization {}/{}: refused ({})",
                m["court"], m["axis"], refused
            );
        } else {
            println!(
                "  minimization {}/{}: {} attempt(s), {} -> {} lines (minimality {}/{}, proven {})",
                m["court"],
                m["axis"],
                m["attempts"],
                m["original_lines"],
                m["final_lines"],
                m["minimality"]["kind"],
                m["minimality"]["granularity"],
                m["minimality"]["proven"]
            );
        }
    }
    println!(
        "  replay stability: {}/{} reproduced ({:.0}%)",
        replay_attempts,
        replay_total,
        replay_attempts as f64 / replay_total as f64 * 100.0
    );
    println!(
        "  evidence overhead: {} FRF bytes vs {} baseline bytes (ratio {:.1}x)",
        frf_bytes,
        baseline_bytes,
        frf_bytes as f64 / baseline_bytes as f64
    );
    println!("report: {}", out_path.display());

    if check {
        let mut failures: Vec<String> = Vec::new();
        if !undetected.is_empty() {
            failures.push(format!(
                "undetected seeded defects: {}",
                undetected.join(", ")
            ));
        }
        if !false_positives.is_empty() {
            failures.push(format!(
                "false positives: {}",
                false_positives
                    .iter()
                    .map(|o| format!("{}/{}", o.court, o.case))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if !inflated.is_empty() {
            failures.push(format!(
                "claim inflation (a claim covered a seeded-defect axis): {}",
                inflated.join(", ")
            ));
        }
        if claims_on_clean.len() != clean.len() {
            failures.push(format!(
                "clean claims compiled: {}/{}",
                claims_on_clean.len(),
                clean.len()
            ));
        }
        if !scope_misses.is_empty() {
            failures.push(format!("claim scope misses: {}", scope_misses.join(", ")));
        }
        if replay_attempts != replay_total {
            failures.push(format!(
                "replay stability: {replay_attempts}/{replay_total}"
            ));
        }
        if !failures.is_empty() {
            panic!("experiment CHECK FAILED:\n  {}", failures.join("\n  "));
        }
    }
}

fn write_file(root: &Path, rel: &str, contents: &str, executable: bool) {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).unwrap();
        }
    }
    std::fs::write(&path, contents).unwrap();
    if executable {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
}

fn admit(frf: &Path, corpus: &Path, path: &str, name: &str, version: &str) {
    let (ok, out, err) = run_frf(
        frf,
        corpus,
        &[
            "--root",
            "ev",
            "authority",
            "admit",
            path,
            "--name",
            name,
            "--version",
            version,
        ],
    );
    assert!(ok, "authority admit failed: {out} {err}");
}

/// The frf reference-engine binary: `FRF_BIN` env, else
/// `<repo>/target/release/frf`.
fn frf_bin(repo_root: &Path) -> PathBuf {
    if let Ok(path) = std::env::var("FRF_BIN") {
        return PathBuf::from(path);
    }
    let bin = repo_root.join("target").join("release").join("frf");
    assert!(
        bin.is_file(),
        "{} is missing — build the reference engine first (cargo build --release)",
        bin.display()
    );
    bin
}
