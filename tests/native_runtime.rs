//! Phase 0.1.46 — the native runtime closure: for native (ELF) software,
//! `executable hash` is not `executable semantics`. The artifact's behavior
//! depends on its dynamic loader (`PT_INTERP`), its resolved dependency
//! closure (`DT_NEEDED`, transitively), and the loader search configuration
//! that resolved them. The engine binds that closure AT OBSERVATION TIME,
//! hashed component by component, and the receipt carries it (v17).
//!
//! 1. a court run with NATIVE authority + candidate records the closure in
//!    the capture and the receipt, and the receipt verifies;
//! 2. a tampered closure (wrong cid) refuses verification;
//! 3. the closure travels in the bundle and the independent verifiers accept
//!    it (the conformance triangle on a native receipt).

mod common;
use common::*;

use std::fs;
use std::path::Path;
use std::process::Command;

/// Compile a tiny native CLI (C) into `work/golden/<name>`; returns its
/// work-relative path. The program parses directive lines: `ok`/comment
/// lines pass, anything else prints a diagnostic to stderr and exits 2.
/// `exit` overrides the malformed-input exit class (the reference's class is
/// 2).
fn compile_native_tool(work: &Workdir, name: &str, exit: u32) -> String {
    let src = work.path(&format!("golden/{name}.c"));
    let out = work.path(&format!("golden/{name}"));
    let body = format!(
        r#"#include <stdio.h>
#include <string.h>
int main(int argc, char** argv) {{
    if (argc < 2) {{ fprintf(stderr, "native: no input\n"); return 2; }}
    FILE* f = fopen(argv[1], "r");
    if (!f) {{ fprintf(stderr, "native: cannot open %s\n", argv[1]); return 2; }}
    char line[512]; int bad = 0;
    while (fgets(line, sizeof line, f)) {{
        if (line[0] == '#' || strncmp(line, "ok", 2) == 0) continue;
        fprintf(stderr, "native: unknown directive in %s\n", argv[1]);
        bad = 1; break;
    }}
    fclose(f);
    return bad ? {exit} : 0;
}}
"#
    );
    fs::write(&src, body).unwrap();
    let status = Command::new("gcc")
        .arg("-o")
        .arg(&out)
        .arg(&src)
        .status()
        .expect("gcc must be available to compile the native fixture");
    assert!(status.success(), "gcc failed to compile {name}");
    format!("golden/{name}")
}

/// The native court manifest: authority + candidate are the compiled
/// binaries, the fixture is the malformed-input corpus file.
fn native_manifest(work: &Workdir, candidate: &str, fixture: &str) -> String {
    let manifest = format!(
        "court:\n  id: native-cli\n  question: >-\n    For malformed input in fixture family native, does the candidate preserve\n    the admitted reference's exit class and first diagnostic line?\n  falsifier: >-\n    The candidate's exit class or first diagnostic line diverges from the\n    admitted reference on a fixture in family native.\n  authority: ref-native-1.0\n  candidate:\n    name: cand-native\n    version_or_commit: \"0.1.0\"\n    build_profile: release\n    path: {candidate}\n  fixture:\n    id: malformed-path.conf\n    path: {fixture}\n    arguments: [\"{{fixture}}\"]\n  admissibility_envelope:\n    fixture_family: native\n    platforms: [\"x86_64-linux\"]\n    observables: [exit, stderr]\n    normalizers: []\n    replay_scope: single-run\n"
    );
    let path = work.path("frf/courts/native-cli/manifest.yaml");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, &manifest).unwrap();
    "frf/courts/native-cli/manifest.yaml".to_string()
}

/// The native fixture (the same malformed-input corpus fixture).
fn native_fixture(work: &Workdir) -> String {
    let src = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("frf/courts/cli-malformed-input/fixtures/malformed-path.conf");
    let dst = work.path("frf/courts/native-cli/fixtures/malformed-path.conf");
    fs::create_dir_all(dst.parent().unwrap()).unwrap();
    fs::copy(&src, &dst).unwrap();
    "frf/courts/native-cli/fixtures/malformed-path.conf".to_string()
}

/// A native court run binds the runtime closure: the capture's artifact
/// identities carry the dynamic loader + resolved dependency closure (no
/// interpreter — the artifacts are ELF, not scripts), and the receipt copies
/// it and verifies.
#[test]
fn a_native_court_run_binds_the_runtime_closure_in_capture_and_receipt() {
    let work = Workdir::new("native-closure");
    work.copy_canonical_tree();
    // The golden fixtures carry the malformed-input corpus file + the
    // reference; admit the NATIVE authority and run a native court.
    let ref_tool = compile_native_tool(&work, "ref-native", 2);
    let cand_tool = compile_native_tool(&work, "cand-native", 1);
    let fixture = native_fixture(&work);
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "authority",
            "admit",
            &ref_tool,
            "--name",
            "ref-native",
            "--version",
            "1.0",
        ],
    );
    assert_success(&out, "native authority admit");
    let manifest = native_manifest(&work, &cand_tool, &fixture);
    let out = frf(&work, &["--root", ROOT, "court", "run", &manifest]);
    assert_success(&out, "native court run");
    let run = stdout(&out);
    assert!(run.starts_with("run-native-cli-"), "run id: {run}");

    // The capture binds the closure: both artifacts are ELF (no interpreter)
    // and carry the runtime closure; its cid rederives and every component
    // hash is well-formed.
    let capture: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("frf/captures/{run}/capture.json"))).unwrap(),
    )
    .unwrap();
    for (who, artifact) in [
        ("authority", &capture["authority_artifact"]),
        ("candidate", &capture["candidate_artifact"]),
    ] {
        assert!(
            artifact["interpreter"].is_null(),
            "a native artifact must carry no interpreter chain ({who})"
        );
        let closure = &artifact["native_runtime"];
        assert_eq!(
            closure["schema_version"], "frf-runtime-closure-v1",
            "{who} closure schema"
        );
        assert_eq!(
            closure["cid"].as_str().unwrap().len(),
            64,
            "{who} closure cid"
        );
        assert!(
            !closure["interp"]["path"].as_str().unwrap().is_empty(),
            "{who} closure must name the dynamic loader"
        );
        assert!(
            !closure["components"].as_array().unwrap().is_empty(),
            "{who} closure must resolve at least the C runtime (libc)"
        );
        for c in closure["components"].as_array().unwrap() {
            assert_eq!(
                c["sha256"].as_str().unwrap().len(),
                64,
                "{who} closure component {} hash",
                c["path"]
            );
        }
    }

    // The receipt copies the contract verbatim and VERIFIES (the verified
    // loader rederives the closure cid and checks the interpreter/closure
    // exclusivity).
    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &run]);
    assert_success(&out, "receipt emit");
    let receipt = stdout(&out);
    assert!(receipt.starts_with("receipt-run-"), "receipt id: {receipt}");
    let body: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("frf/receipts/{receipt}.json"))).unwrap(),
    )
    .unwrap();
    assert_eq!(body["schema_version"], "frf-receipt-v19");
    assert_eq!(
        body["authority"]["native_runtime"],
        capture["authority_artifact"]["native_runtime"]
    );
    assert_eq!(
        body["candidate"]["native_runtime"],
        capture["candidate_artifact"]["native_runtime"]
    );
    // Replay consumes it through the verified loader: the closure rederives.
    let out = frf(
        &work,
        &["--root", ROOT, "replay", &receipt, "--policy", "exact"],
    );
    assert_success(&out, "exact replay of the native receipt");
    assert!(stdout(&out).contains("reproduced"));

    // A compiled claim (baseline) is admissible over the native evidence.
    let out = frf(&work, &["--root", ROOT, "claim", "compile", &receipt]);
    assert_success(&out, "claim over native evidence");
}

/// A tampered closure is refused: the cid is part of the closure's own
/// content address, and the verified loader rederives it before consuming
/// the receipt.
#[test]
fn a_tampered_runtime_closure_is_refused() {
    let work = Workdir::new("native-tamper");
    work.copy_canonical_tree();
    let ref_tool = compile_native_tool(&work, "ref-native", 2);
    let cand_tool = compile_native_tool(&work, "cand-native", 2);
    let fixture = native_fixture(&work);
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "authority",
            "admit",
            &ref_tool,
            "--name",
            "ref-native",
            "--version",
            "1.0",
        ],
    );
    assert_success(&out, "native authority admit");
    let manifest = native_manifest(&work, &cand_tool, &fixture);
    let out = frf(&work, &["--root", ROOT, "court", "run", &manifest]);
    assert_success(&out, "native court run");
    let run = stdout(&out);
    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &run]);
    let receipt = stdout(&out);

    // Tamper the closure's cid in the receipt document.
    let path = work.path(&format!("frf/receipts/{receipt}.json"));
    let mut body: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    body["authority"]["native_runtime"]["cid"] = serde_json::Value::String("f".repeat(64));
    fs::write(&path, serde_json::to_string(&body).unwrap()).unwrap();

    // Verification must refuse: the name is a claim until recomputed.
    let out = frf(
        &work,
        &["--root", ROOT, "replay", &receipt, "--policy", "exact"],
    );
    assert!(
        !out.status.success(),
        "a tampered closure must refuse verification"
    );
    let err = stderr(&out);
    assert!(
        err.contains("not content-addressed") || err.contains("refusing"),
        "the refusal must name the forged closure: {err}"
    );
}

/// Priority 6 — the sealed-image / native-closure `$ORIGIN` interaction,
/// proved by a court built to expose it. A binary whose `DT_RUNPATH` is
/// `$ORIGIN`-relative resolves its dependencies from the directory of the
/// executable THE LOADER SEES: `/proc/self/fd/<n>` under sealed execution
/// (the memfd path the side is exec'd from), NEVER the materialized snapshot
/// path. The recorded closure must resolve against that same sealed path —
/// so an `$ORIGIN` dependency the sealed mechanism cannot find is a REFUSAL:
/// the artifact cannot load under the profile's sealed execution, and
/// recording a closure resolved from the materialized location would
/// describe an execution that never happened.
#[test]
fn an_origin_relative_dependency_is_resolved_against_the_sealed_exec_path() {
    let work = Workdir::new("native-origin");
    work.copy_canonical_tree();
    // Compile a shared library and a binary whose DT_RUNPATH is `$ORIGIN`,
    // with the library NEXT TO the binary (golden/) — the classic
    // deployed-package layout that $ORIGIN exists for.
    let lib = work.path("golden/libfoo.so");
    let lib_src = work.path("golden/libfoo.c");
    fs::write(&lib_src, "int foo(void) { return 42; }\n").unwrap();
    let status = Command::new("gcc")
        .args(["-shared", "-fPIC", "-o"])
        .arg(&lib)
        .arg(&lib_src)
        .status()
        .expect("gcc must be available to compile the shared library");
    assert!(status.success(), "gcc failed to compile libfoo.so");
    let cand = work.path("golden/origin-cand");
    let cand_src = work.path("golden/origin-cand.c");
    fs::write(
        &cand_src,
        "#include <stdio.h>\nextern int foo(void);\nint main(void) { printf(\"foo=%d\\n\", foo()); return 0; }\n",
    )
    .unwrap();
    let status = Command::new("gcc")
        .arg("-o")
        .arg(&cand)
        .arg(&cand_src)
        .arg(format!("-L{}", work.path("golden").display()))
        .arg("-lfoo")
        .arg("-Wl,-rpath,$ORIGIN")
        .status()
        .expect("gcc must be available to compile the origin binary");
    assert!(status.success(), "gcc failed to compile the origin binary");
    // Prove the fixture is the hazard: the RUNPATH is $ORIGIN-relative.
    let readelf = Command::new("readelf")
        .args(["-d", work.path("golden/origin-cand").to_str().unwrap()])
        .output()
        .expect("readelf must be available");
    let dyn_text = String::from_utf8_lossy(&readelf.stdout);
    assert!(
        dyn_text.contains("RUNPATH") && dyn_text.contains("$ORIGIN"),
        "the fixture must carry a $ORIGIN-relative RUNPATH"
    );

    // Stage the library NEXT TO where the candidate object will be
    // materialized (objects/sha256/): the materialized-path resolution WOULD
    // find it there — the hazard is precisely that the sealed path does not.
    let objects_dir = work.path("frf/objects/sha256");
    fs::create_dir_all(&objects_dir).unwrap();
    fs::copy(&lib, objects_dir.join("libfoo.so")).unwrap();

    // Admit the (normal) reference + run the court. The CANDIDATE's closure
    // must resolve against the sealed exec path: libfoo.so is not under
    // /proc/self/fd, so the closure cannot be bound and the run is REFUSED —
    // never recorded with a closure the execution contradicts.
    let fixture = native_fixture(&work);
    let ref_tool = compile_native_tool(&work, "ref-native", 2);
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "authority",
            "admit",
            &ref_tool,
            "--name",
            "ref-native",
            "--version",
            "1.0",
        ],
    );
    assert_success(&out, "native authority admit");
    let manifest = native_manifest(&work, "golden/origin-cand", &fixture);
    let out = frf(&work, &["--root", ROOT, "court", "run", &manifest]);
    assert!(
        !out.status.success(),
        "an $ORIGIN-relative dependency the sealed exec path cannot find must refuse the court"
    );
    let err = stderr(&out);
    assert!(
        err.contains("cannot be bound")
            || err.contains("refused to resolve")
            || err.contains("could not resolve"),
        "the refusal must name the closure-binding failure: {err}"
    );
}
