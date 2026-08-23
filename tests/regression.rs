//! Regression suite — the invariant bank.
//!
//! Where the golden-path test proves the happy chain, this suite locks down
//! every rejection path and behavioral edge: admission validation, court
//! declaration validation, the disposition reason gate, re-disposition,
//! claim-blocking semantics for every closure kind, the id/path-safety
//! boundary, execution timeout kill, and the zero-residual positive control.

mod common;
use common::*;

use std::fs;

/// The declared execution environment is evidence: the sides are spawned
/// with EXACTLY the court's declared map (content-addressed into the
/// capture — a new execution engine reproduces the observation from the
/// evidence alone), and the ambient host environment is never inherited
/// (it would leak secrets and make the observation non-reproducible).
#[test]
fn declared_environment_is_evidence_and_ambient_is_not_inherited() {
    let work = Workdir::new("declared-env");
    work.copy_canonical_tree();
    admit_reference(&work);
    // The candidate prints a declared variable and probes for an ambient one
    // (a hook variable set on the frf process itself).
    work.write_candidate(
        "#!/bin/sh\nprintf 'declared=[%s]\\n' \"$TRIGGER\"\nprintf 'ambient=[%s]\\n' \"$FRF_EXEC_TIMEOUT_MS\"\n",
    );
    let manifest = "env-test.yaml";
    fs::write(
        work.path(manifest),
        r#"court:
  id: cli-malformed-input
  question: q
  falsifier: f
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
  environment:
    TRIGGER: "() { :;}; echo PWNED"
  admissibility_envelope:
    fixture_family: malformed-input
    platforms: ["x86_64-linux"]
    observables: [stdout, exit]
    normalizers: []
    replay_scope: single-run
"#,
    )
    .unwrap();
    // Run with an ambient hook override set: the side must NOT see it.
    let out = frf_env(
        &work,
        &["--root", ROOT, "court", "run", manifest],
        &[("FRF_EXEC_TIMEOUT_MS", "9999")],
    );
    assert_success(&out, "court run (declared env)");
    let run = stdout(&out);

    // The capture records the declared environment (content-addressed
    // input) — and nothing else.
    let cap: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("{ROOT}/captures/{run}/capture.json"))).unwrap(),
    )
    .unwrap();
    assert_eq!(
        cap["environment"]["environment"]["TRIGGER"],
        "() { :;}; echo PWNED"
    );
    assert_eq!(
        cap["environment"]["environment"]["FRF_EXEC_TIMEOUT_MS"],
        serde_json::Value::Null,
        "the ambient host environment must never be recorded"
    );

    // The side SAW the declared variable and did NOT see the ambient one.
    let cand =
        fs::read_to_string(work.path(&format!("{ROOT}/captures/{run}/candidate.stdout"))).unwrap();
    assert!(cand.contains("declared=[() { :;}; echo PWNED]"));
    assert!(
        cand.contains("ambient=[]"),
        "the ambient host environment must not be inherited by the side: {cand:?}"
    );

    // Replay reproduces the observation: the same declared environment is
    // re-spawned (exact replay also gates the environment digest and the
    // effective capture bounds — the ambient override the court ran under).
    let out = frf_env(
        &work,
        &["--root", ROOT, "replay", &run, "--policy", "exact"],
        &[("FRF_EXEC_TIMEOUT_MS", "9999")],
    );
    assert_success(&out, "replay with the declared env");
}

/// The claim scope's `fixtures` dimension is the EXACT fixture input
/// identity (FRF/FIXTURE/v1 — semantic id + content hash + declared
/// arguments), never the human label: an open residual about one fixture's
/// exact bytes must not block a claim about different exact bytes that
/// share the fixture id. The blocker fires only on the same exact input.
#[test]
fn claim_scope_binds_the_exact_fixture_bytes_not_the_label() {
    let work = Workdir::new("claim-exact-fixture");
    work.copy_canonical_tree();
    admit_reference(&work);
    // A candidate that always passes (exit 0, no output): any divergence is
    // the REFERENCE's behavior on the fixture, and a clean fixture yields a
    // fully passing run (a compilable claim).
    work.write_candidate("#!/bin/sh\nexit 0\n");
    let fixture_path = "frf/courts/cli-malformed-input/fixtures/malformed-path.conf";

    // Run 1: the DEFECT fixture bytes (a malformed directive) — the
    // reference diverges, an OPEN residual about these exact bytes.
    fs::write(work.path(fixture_path), "nonsense directive\n").unwrap();
    let run_a = run_court(&work);
    assert!(
        fs::read_dir(work.path("frf/residuals"))
            .unwrap()
            .flatten()
            .count()
            > 0,
        "run A must leave open residuals"
    );

    // Run 2: the SAME fixture id (same manifest, same path) with DIFFERENT
    // exact bytes (a clean file) — a fully passing run.
    fs::write(work.path(fixture_path), "log entry\n").unwrap();
    let run_b = run_court(&work);
    assert_ne!(
        run_a, run_b,
        "different fixture bytes are different observations"
    );
    let cap_b: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("{ROOT}/captures/{run_b}/capture.json"))).unwrap(),
    )
    .unwrap();
    assert_eq!(
        cap_b["residuals"].as_array().unwrap().len(),
        0,
        "run B passes"
    );

    // The claim from run B must COMPILE: the open residual from run A is
    // about different exact fixture bytes (the exact-input rule), even
    // though both runs share the fixture ID in the manifest.
    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &run_b]);
    assert_success(&out, "receipt emit (run B)");
    let receipt = stdout(&out);
    let out = frf(&work, &["--root", ROOT, "claim", "compile", &receipt]);
    assert_success(
        &out,
        "claim from run B compiles under the exact-fixture rule",
    );

    // The recorded fixture identities differ — the surfaces genuinely
    // differ.
    let cap_a: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("{ROOT}/captures/{run_a}/capture.json"))).unwrap(),
    )
    .unwrap();
    assert_ne!(cap_a["fixture_sha256"], cap_b["fixture_sha256"]);
}

/// The immutable observation record.
fn raw_residual(work: &Workdir, id: &str) -> serde_json::Value {
    serde_json::from_str(
        &fs::read_to_string(work.path(&format!("frf/residuals/{id}.json"))).unwrap(),
    )
    .unwrap()
}

/// The last appended disposition event (the projection).
fn last_event(work: &Workdir, id: &str) -> serde_json::Value {
    let dir = work.path(&format!("frf/residuals/{id}.events"));
    let mut seqs: Vec<u32> = fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .filter_map(|e| {
            e.path()
                .file_stem()
                .and_then(|s| s.to_str())
                .and_then(|s| s.parse().ok())
        })
        .collect();
    seqs.sort_unstable();
    let last = seqs.last().expect("at least one event");
    serde_json::from_str(
        &fs::read_to_string(work.path(&format!("frf/residuals/{id}.events/{last:04}.json")))
            .unwrap(),
    )
    .unwrap()
}

/// The projected disposition string of a residual (from its last event).
fn projected_disposition(work: &Workdir, id: &str) -> String {
    let events_dir = work.path(&format!("frf/residuals/{id}.events"));
    if !events_dir.is_dir() {
        return "open".to_string();
    }
    last_event(work, id)["disposition"]
        .as_str()
        .unwrap()
        .to_string()
}

// ---------------------------------------------------------------------------
// Admission validation
// ---------------------------------------------------------------------------

#[test]
fn admission_rejects_bad_kind_name_version_and_file() {
    let work = Workdir::new("admit-rejects");
    work.copy_canonical_tree();

    // Only executable_reference is admitted in v0.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "authority",
            "admit",
            "golden/reference.sh",
            "--name",
            "ref-cli",
            "--version",
            "1.8.2",
            "--kind",
            "specification",
        ],
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("only 'executable_reference' is supported"));

    // Names and versions must be safe path components (they become the id).
    for (flag, value) in [
        ("--name", "a b"),
        ("--version", "1.0/rc1"),
        ("--name", "../x"),
    ] {
        let mut args = vec!["--root", ROOT, "authority", "admit", "golden/reference.sh"];
        if flag == "--name" {
            args.extend_from_slice(&["--name", value, "--version", "1.8.2"]);
        } else {
            args.extend_from_slice(&["--name", "ref-cli", "--version", value]);
        }
        let out = frf(&work, &args);
        assert!(!out.status.success(), "{flag}={value} must be rejected");
        assert!(
            stderr(&out).contains("invalid authority"),
            "stderr: {}",
            stderr(&out)
        );
    }

    // Missing file.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "authority",
            "admit",
            "golden/nope.sh",
            "--name",
            "ref-cli",
            "--version",
            "1.8.2",
        ],
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("not a file"));

    // Non-executable file.
    let plain = work.path("golden/plain.txt");
    fs::write(&plain, "not a program\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&plain, fs::Permissions::from_mode(0o644)).unwrap();
    }
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "authority",
            "admit",
            "golden/plain.txt",
            "--name",
            "plain",
            "--version",
            "1.0",
        ],
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("not executable"));
}

// ---------------------------------------------------------------------------
// Court declaration validation
// ---------------------------------------------------------------------------

/// A manifest copy with one declared line replaced. `old_line` and `new_line`
/// are matched by trimmed content; the matched line's indentation is kept.
fn manifest_variant(work: &Workdir, old_line: &str, new_line: &str) -> String {
    let path = work.path("frf/courts/cli-malformed-input/manifest.yaml");
    let text = fs::read_to_string(&path).unwrap();
    let mut replaced = false;
    let out: String = text
        .lines()
        .map(|line| {
            if line.trim() == old_line {
                replaced = true;
                let indent: String = line.chars().take_while(|c| *c == ' ').collect();
                format!("{indent}{new_line}")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(replaced, "line {old_line:?} not found in manifest");
    let variant = work.path("frf/courts/variant.yaml");
    fs::write(&variant, out).unwrap();
    "frf/courts/variant.yaml".to_string()
}

#[test]
fn court_rejects_bad_declarations() {
    let work = Workdir::new("court-rejects");
    work.copy_canonical_tree();
    admit_reference(&work);

    // An observable axis that is a valid protocol identifier but served by
    // no comparator (not a built-in, no external declaration).
    let m = manifest_variant(&work, "observables: [exit, stderr]", "observables: [wire]");
    let out = frf(&work, &["--root", ROOT, "court", "run", &m]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("no comparator serves observable axis 'wire'"));

    // Unknown authority id.
    let m = manifest_variant(&work, "authority: ref-cli-1.8.2", "authority: nope-1.0");
    let out = frf(&work, &["--root", ROOT, "court", "run", &m]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("not admitted"));

    // Missing candidate.
    let m = manifest_variant(&work, "path: golden/candidate.sh", "path: golden/nope.sh");
    let out = frf(&work, &["--root", ROOT, "court", "run", &m]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("cannot read golden/nope.sh"));

    // Missing fixture.
    let m = manifest_variant(
        &work,
        "path: frf/courts/cli-malformed-input/fixtures/malformed-path.conf",
        "path: frf/courts/cli-malformed-input/fixtures/nope.conf",
    );
    let out = frf(&work, &["--root", ROOT, "court", "run", &m]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("cannot read frf/courts/cli-malformed-input/fixtures/nope.conf"));

    // Missing manifest file itself.
    let out = frf(
        &work,
        &["--root", ROOT, "court", "run", "frf/courts/nope.yaml"],
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("cannot read"));
}

#[test]
fn envelope_declarations_are_fail_closed() {
    // Declaration must never masquerade as enforcement: anything the
    // executor does not actually apply is refused up front.
    let work = Workdir::new("envelope");
    work.copy_canonical_tree();
    admit_reference(&work);

    // A normalizer the envelope applies but the manifest never declares ->
    // refused (the executor would run unverifiable code).
    let m = manifest_variant(&work, "normalizers: []", "normalizers: [strip-ansi]");
    let out = frf(&work, &["--root", ROOT, "court", "run", &m]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("the envelope applies normalizer \"strip-ansi\" but no normalizer with that id is declared"),
        "stderr: {}",
        stderr(&out)
    );

    // A declared normalizer the envelope never applies -> refused (the
    // declaration would be a lie). The variant adds a top-level declaration
    // while leaving the envelope's `normalizers` list empty.
    let path = work.path("frf/courts/cli-malformed-input/manifest.yaml");
    let text = fs::read_to_string(&path).unwrap();
    let variant = format!(
        "{text}\nnormalizers:\n  - id: strip-ansi\n    relation: strip-ansi-sequences\n    applies_to: stderr\n    relation_version: \"v1\"\n    program: golden/normalizers/strip-ansi.py\n"
    );
    let variant_path = work.path("frf/courts/variant.yaml");
    fs::write(&variant_path, variant).unwrap();
    let out = frf(
        &work,
        &["--root", ROOT, "court", "run", "frf/courts/variant.yaml"],
    );
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("is declared but the envelope does not apply it"),
        "stderr: {}",
        stderr(&out)
    );

    // A replay_scope beyond single-run is declared but not executed -> refused.
    let m = manifest_variant(
        &work,
        "replay_scope: single-run",
        "replay_scope: repeated(3)",
    );
    let out = frf(&work, &["--root", ROOT, "court", "run", &m]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("only 'single-run'"),
        "stderr: {}",
        stderr(&out)
    );

    // The current platform outside the declared envelope -> refused.
    let m = manifest_variant(
        &work,
        "platforms: [\"x86_64-linux\"]",
        "platforms: [\"aarch64-darwin\"]",
    );
    let out = frf(&work, &["--root", ROOT, "court", "run", &m]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("outside the declared envelope"),
        "stderr: {}",
        stderr(&out)
    );

    // An authority admitted for another platform is an out-of-envelope
    // oracle -> refused.
    let authority_path = work.path("frf/authorities/ref-cli-1.8.2.json");
    let text = fs::read_to_string(&authority_path).unwrap();
    let text = text.replace(
        "\"platform\":\"x86_64-linux\"",
        "\"platform\":\"aarch64-darwin\"",
    );
    fs::write(&authority_path, text).unwrap();
    let out = frf(&work, &["--root", ROOT, "court", "run", MANIFEST]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("out-of-envelope oracle"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn court_rejects_ids_that_could_escape_the_root() {
    let work = Workdir::new("court-ids");
    work.copy_canonical_tree();
    admit_reference(&work);

    // Court id becomes a run-dir component; a traversal must be refused.
    let m = manifest_variant(&work, "id: cli-malformed-input", "id: ../../evil");
    let out = frf(&work, &["--root", ROOT, "court", "run", &m]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("invalid court id '../../evil'"));

    // Authority id in the manifest is validated at load time.
    let m = manifest_variant(&work, "authority: ref-cli-1.8.2", "authority: ../../x");
    let out = frf(&work, &["--root", ROOT, "court", "run", &m]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("invalid authority id '../../x'"));

    // Nothing was created outside the root.
    assert!(!work.path("evil").exists());
    assert!(!work.path("x.yaml").exists());
}

#[test]
fn fixture_not_referenced_warns_but_runs() {
    let work = Workdir::new("fixture-warn");
    work.copy_canonical_tree();
    admit_reference(&work);

    // No {fixture} placeholder: the fixture is not exercised; a warning must
    // name that observability gap.
    let m = manifest_variant(
        &work,
        "arguments: [\"--strict\", \"{fixture}\"]",
        "arguments: []",
    );
    let out = frf(&work, &["--root", ROOT, "court", "run", &m]);
    assert_success(&out, "court run without fixture reference");
    let run = stdout(&out);
    assert!(stderr(&out).contains("does not exercise it"));
    // Without a file argument both sides hit their no-input path: same exit
    // class (2), different wording → exactly one text residual, no exit
    // residual (the ids are content addresses).
    let ids = residual_ids(&work, &run);
    assert_eq!(ids.len(), 1, "exactly one text residual: {ids:?}");
    assert_eq!(ids[0].0, "stderr", "the single residual is the text one");
    assert!(work
        .path(&format!("frf/residuals/{}.json", ids[0].1))
        .is_file());
}

// ---------------------------------------------------------------------------
// Dispositions
// ---------------------------------------------------------------------------

#[test]
fn closure_kinds_round_trip_and_claim_semantics() {
    let work = Workdir::new("dispose-kinds");
    work.copy_canonical_tree();
    admit_reference(&work);
    let run = run_court(&work);
    let exit_id = residual_id(&work, &run, "exit");
    let text_id = residual_id(&work, &run, "stderr");

    // Close the text residual first so the claim semantics below are decided
    // by the exit residual alone.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "residual",
            "dispose",
            &text_id,
            "--disposition",
            "intentional",
            "--reason",
            "clearer wording",
        ],
    );
    assert_success(&out, "dispose text");

    // Every non-fixed closure appends an event, in sequence, on the same
    // residual (re-disposition is allowed; `open` is not). `fixed` is
    // exercised separately: it needs a resolution run. Whatever the
    // disposition, the ORIGINAL run's receipt observed divergence on exit,
    // so it can never yield a parity claim.
    for (kind, expect_refusal) in [
        ("environmental", "no declared observable axis"),
        ("oracle_version", "no declared observable axis"),
        ("intentional", "no declared observable axis"),
        ("harness", "harness"),
        ("unknown", "unknown"),
    ] {
        let out = frf(
            &work,
            &[
                "--root",
                ROOT,
                "residual",
                "dispose",
                &exit_id,
                "--disposition",
                kind,
                "--reason",
                &format!("regression: {kind}"),
            ],
        );
        assert_success(&out, &format!("dispose {kind}"));
        // The observation record stays immutable; the event carries the
        // disposition.
        assert!(
            raw_residual(&work, &exit_id).get("disposition").is_none(),
            "observation must never carry a disposition"
        );
        let event = last_event(&work, &exit_id);
        assert_eq!(event["disposition"], kind);
        assert_eq!(event["reason"], format!("regression: {kind}"));
        assert!(
            event.get("resolution_run_id").is_none(),
            "{kind} must not carry a resolution_run_id"
        );
        // The token follows the projection.
        let tok: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(work.path(&format!("frf/residuals/{exit_id}.token.json"))).unwrap(),
        )
        .unwrap();
        assert_eq!(tok["token"], format!("exit/exit-class/class-change/{kind}"));

        // Claim semantics per closure kind on the ORIGINAL run's receipt.
        let out = frf(&work, &["--root", ROOT, "receipt", "emit", &run]);
        assert_success(&out, "receipt emit");
        let receipt = stdout(&out);
        let out = frf(&work, &["--root", ROOT, "claim", "compile", &receipt]);
        assert!(!out.status.success(), "{kind} must not license a claim");
        assert!(
            stderr(&out).contains(expect_refusal),
            "{kind}: expected '{expect_refusal}' in: {}",
            stderr(&out)
        );
    }

    // `fixed` without a resolution run is refused at dispose time.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "residual",
            "dispose",
            &exit_id,
            "--disposition",
            "fixed",
            "--reason",
            "candidate patched",
        ],
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("--resolution-run"));

    // `fixed` backed by a real resolution run appends the event with the
    // verified predicate — but the ORIGINAL receipt still cannot become a
    // parity receipt: it observed divergence. The positive claim belongs to
    // the resolution run's receipt.
    let resolution_run = run_resolution_court(&work);
    let res_text_id = residual_id(&work, &resolution_run, "stderr");
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "residual",
            "dispose",
            &exit_id,
            "--disposition",
            "fixed",
            "--resolution-run",
            &resolution_run,
            "--reason",
            "candidate patched",
        ],
    );
    assert_success(&out, "dispose exit fixed with closure evidence");
    let event = last_event(&work, &exit_id);
    assert_eq!(event["disposition"], "fixed");
    assert_eq!(event["resolution_run_id"], resolution_run);
    assert!(event["closure_predicate"]
        .as_str()
        .unwrap()
        .contains("fix-court"));

    // The resolution run re-observed the wording divergence; dispose it as
    // intentional so the resolution run's receipt can carry the claim.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "residual",
            "dispose",
            &res_text_id,
            "--disposition",
            "intentional",
            "--reason",
            "clearer diagnostic wording; documented divergence",
        ],
    );
    assert_success(&out, "dispose text 0002");

    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &run]);
    assert_success(&out, "receipt emit (original run)");
    let receipt_old = stdout(&out);
    let out = frf(&work, &["--root", ROOT, "claim", "compile", &receipt_old]);
    assert!(
        !out.status.success(),
        "the failing run's receipt must never become a parity receipt"
    );
    assert!(stderr(&out).contains("compile the claim from the resolution run"));

    // The claim comes from the resolution run's receipt, which observed the
    // exit axis passing.
    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &resolution_run]);
    assert_success(&out, "receipt emit (resolution run)");
    let receipt_res = stdout(&out);
    let out = frf(&work, &["--root", ROOT, "claim", "compile", &receipt_res]);
    assert_success(&out, "claim compile from the resolution run");
    let text = stdout(&out);
    assert!(text.contains("malformed-input exit class"));
}

#[test]
fn fixed_requires_resolution_run_that_closes_the_residual() {
    let work = Workdir::new("fixed-evidence");
    work.copy_canonical_tree();
    admit_reference(&work);
    let run = run_court(&work);
    let exit_id = residual_id(&work, &run, "exit");

    // The resolution run must exist.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "residual",
            "dispose",
            &exit_id,
            "--disposition",
            "fixed",
            "--resolution-run",
            "run-nope",
            "--reason",
            "patched",
        ],
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("no such run"));

    // It must be a new run, not the one that observed the residual.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "residual",
            "dispose",
            &exit_id,
            "--disposition",
            "fixed",
            "--resolution-run",
            &run,
            "--reason",
            "patched",
        ],
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("new court run"));

    // A resolution run whose captures still diverge on the axis must be
    // refused: re-run an UNFIXED candidate under fresh artifact bytes (a
    // byte-distinct script, so the run id is new — the candidate name is a
    // label and does not enter the run identity), then point `fixed` at it.
    work.write_candidate("#!/bin/sh\n# unfixed re-observation (byte-distinct artifact)\nexit 1\n");
    let out = frf(&work, &["--root", ROOT, "court", "run", MANIFEST]);
    assert_success(&out, "court run (unfixed candidate, fresh artifact)");
    let unfixed_run = stdout(&out);
    assert_ne!(
        unfixed_run, run,
        "fresh candidate bytes must yield a new run"
    );
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "residual",
            "dispose",
            &exit_id,
            "--disposition",
            "fixed",
            "--resolution-run",
            &unfixed_run,
            "--reason",
            "patched",
        ],
    );
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("does not close"),
        "stderr: {}",
        stderr(&out)
    );

    // The comparability predicate holds EVERYTHING but the candidate stable:
    // a run with a different fixture id must be refused before axis checks.
    let variant2 = work.path("frf/courts/variant2.yaml");
    let text = fs::read_to_string(work.path(MANIFEST)).unwrap();
    let text = text
        .replace("    name: cand-cli", "    name: cand-cli-fix2")
        .replace("id: malformed-path.conf", "id: malformed-path2.conf");
    fs::write(&variant2, text).unwrap();
    let out = frf(
        &work,
        &["--root", ROOT, "court", "run", "frf/courts/variant2.yaml"],
    );
    assert_success(&out, "court run (different fixture id)");
    let other_fixture_run = stdout(&out);
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "residual",
            "dispose",
            &exit_id,
            "--disposition",
            "fixed",
            "--resolution-run",
            &other_fixture_run,
            "--reason",
            "patched",
        ],
    );
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("fixture id differs"),
        "stderr: {}",
        stderr(&out)
    );

    // A run under a different admitted AUTHORITY ARTIFACT must be refused:
    // the semantic identity binds the authority bytes, not the id label.
    // (An authority id change with identical bytes asks the same question.)
    let variant_ref2 = work.path("golden/reference2.sh");
    fs::write(
        &variant_ref2,
        format!(
            "#!/bin/sh\n# distinct authority artifact\n{}",
            fs::read_to_string(work.path("golden/reference.sh")).unwrap()
        ),
    )
    .unwrap();
    set_exec(&variant_ref2);
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "authority",
            "admit",
            "golden/reference2.sh",
            "--name",
            "ref-cli2",
            "--version",
            "1.8.2",
        ],
    );
    assert_success(&out, "admit second authority (distinct bytes)");
    let variant3 = work.path("frf/courts/variant3.yaml");
    let text = fs::read_to_string(work.path(MANIFEST)).unwrap();
    let text = text
        .replace("    name: cand-cli", "    name: cand-cli-fix3")
        .replace("  authority: ref-cli-1.8.2", "  authority: ref-cli2-1.8.2");
    fs::write(&variant3, text).unwrap();
    let out = frf(
        &work,
        &["--root", ROOT, "court", "run", "frf/courts/variant3.yaml"],
    );
    assert_success(&out, "court run (different authority artifact)");
    let other_authority_run = stdout(&out);
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "residual",
            "dispose",
            &exit_id,
            "--disposition",
            "fixed",
            "--resolution-run",
            &other_authority_run,
            "--reason",
            "patched",
        ],
    );
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("authority artifact"),
        "stderr: {}",
        stderr(&out)
    );

    // And the residual is still open after all refusals.
    assert_eq!(projected_disposition(&work, &exit_id), "open");
}

#[test]
fn disposition_reason_gate() {
    let work = Workdir::new("reason-gate");
    work.copy_canonical_tree();
    admit_reference(&work);
    let run = run_court(&work);
    let exit_id = residual_id(&work, &run, "exit");

    // Missing --reason: clap refuses at parse time.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "residual",
            "dispose",
            &exit_id,
            "--disposition",
            "intentional",
        ],
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("reason"));

    // Empty or whitespace-only reason.
    for reason in ["", "   "] {
        let out = frf(
            &work,
            &[
                "--root",
                ROOT,
                "residual",
                "dispose",
                &exit_id,
                "--disposition",
                "intentional",
                "--reason",
                reason,
            ],
        );
        assert!(!out.status.success());
        assert!(stderr(&out).contains("non-empty one-line reason"));
    }

    // Multi-line reason.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "residual",
            "dispose",
            &exit_id,
            "--disposition",
            "intentional",
            "--reason",
            "line one\nline two",
        ],
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("single line"));

    // The residual is still open after all refusals (no events appended).
    assert_eq!(projected_disposition(&work, &exit_id), "open");
}

#[test]
fn dispositions_are_append_only_events() {
    let work = Workdir::new("append-only");
    work.copy_canonical_tree();
    admit_reference(&work);
    let run = run_court(&work);
    let text_id = residual_id(&work, &run, "stderr");

    // The observation record is byte-identical before and after disposal.
    let observation = work.path(&format!("frf/residuals/{text_id}.json"));
    let before = fs::read(&observation).unwrap();

    let dispose = |kind: &str, reason: &str| {
        let out = frf(
            &work,
            &[
                "--root",
                ROOT,
                "residual",
                "dispose",
                &text_id,
                "--disposition",
                kind,
                "--reason",
                reason,
            ],
        );
        assert_success(&out, &format!("dispose {kind}"));
    };
    dispose("intentional", "clearer wording");
    dispose("harness", "runner contamination suspected");
    dispose("unknown", "reclassified after review");

    // The observation never changed.
    assert_eq!(
        fs::read(&observation).unwrap(),
        before,
        "observation must be immutable"
    );

    // Three immutable events, in order, each carrying its own reason; the
    // projection is the last one.
    let events_dir = work.path(&format!("frf/residuals/{text_id}.events"));
    let names: Vec<String> = fs::read_dir(&events_dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.ends_with(".json"))
        .collect::<Vec<_>>();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(sorted, vec!["0001.json", "0002.json", "0003.json"]);
    let e1: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(events_dir.join("0001.json")).unwrap()).unwrap();
    assert_eq!(e1["disposition"], "intentional");
    assert_eq!(e1["reason"], "clearer wording");
    assert_eq!(projected_disposition(&work, &text_id), "unknown");

    // The trajectory survives: every event is still there after the last.
    let e2: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(events_dir.join("0002.json")).unwrap()).unwrap();
    assert_eq!(e2["disposition"], "harness");
}

#[test]
fn ids_cannot_escape_the_root_from_commands() {
    let work = Workdir::new("id-escape");
    work.copy_canonical_tree();
    admit_reference(&work);
    run_court(&work);

    for (verb_args, needle) in [
        (
            vec![
                "residual",
                "dispose",
                "../../evil",
                "--disposition",
                "fixed",
                "--reason",
                "x",
            ],
            "invalid residual id '../../evil'",
        ),
        (
            vec!["receipt", "emit", "../../evil"],
            "invalid run id '../../evil'",
        ),
        (
            vec!["claim", "compile", "../../evil"],
            "invalid receipt id '../../evil'",
        ),
    ] {
        let mut args = vec!["--root", ROOT];
        args.extend(verb_args);
        let out = frf(&work, &args);
        assert!(!out.status.success());
        assert!(stderr(&out).contains(needle), "stderr: {}", stderr(&out));
    }

    // `..` and `.` specifically.
    for id in ["..", "."] {
        let out = frf(
            &work,
            &[
                "--root",
                ROOT,
                "residual",
                "dispose",
                id,
                "--disposition",
                "fixed",
                "--reason",
                "x",
            ],
        );
        assert!(!out.status.success());
        assert!(stderr(&out).contains("invalid residual id"));
    }

    // Nothing escaped: no stray files in the workdir root or above the root.
    assert!(!work.path("evil.yaml").exists());
    assert!(!work.path("evil").exists());
    assert!(!work.dir.parent().unwrap().join("evil.yaml").exists());
}

// ---------------------------------------------------------------------------
// Behavioral edges
// ---------------------------------------------------------------------------

#[test]
fn clean_pair_yields_no_residuals_and_two_axis_claim() {
    // Positive control: a candidate identical in behavior to the reference
    // produces no residuals on either axis, and the claim covers both.
    let work = Workdir::new("clean");
    work.copy_canonical_tree();
    let ref_content = fs::read_to_string(work.path("golden/reference.sh")).unwrap();
    work.write_candidate(&ref_content);
    admit_reference(&work);
    let run = run_court(&work);

    let residuals = fs::read_dir(work.path("frf/residuals")).unwrap().count();
    assert_eq!(residuals, 0, "identical behavior must leave zero residuals");

    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &run]);
    assert_success(&out, "receipt emit");
    let receipt = stdout(&out);
    let out = frf(&work, &["--root", ROOT, "claim", "compile", &receipt]);
    assert_success(&out, "claim compile");
    let text = stdout(&out);
    assert!(
        text.contains("malformed-input exit class and malformed-input first diagnostic line"),
        "claim: {text}"
    );
}

#[test]
fn stdout_axis_is_a_declared_comparator() {
    // A third observable, exercised only when declared: the stdout axis
    // compares first stdout lines and produces a text-family residual that
    // routes to its own minimizer. Comparator identity lands in the receipt.
    let work = Workdir::new("stdout-axis");
    work.copy_canonical_tree();
    // Different first stdout line, different exit class, empty stderr.
    work.write_candidate("#!/bin/sh\necho \"cand banner\"\nexit 1\n");
    admit_reference(&work);

    let m = manifest_variant(
        &work,
        "observables: [exit, stderr]",
        "observables: [exit, stderr, stdout]",
    );
    let out = frf(&work, &["--root", ROOT, "court", "run", &m]);
    assert_success(&out, "court run with stdout axis");
    let run = stdout(&out);

    // exit, stderr, stdout -> three content-addressed residuals.
    let exit_id = residual_id(&work, &run, "exit");
    let stderr_id = residual_id(&work, &run, "stderr");
    let stdout_id = residual_id(&work, &run, "stdout");
    let exit_res = raw_residual(&work, &exit_id);
    assert_eq!(exit_res["raw_reference"], "2");
    assert_eq!(exit_res["raw_candidate"], "1");
    let err_res = raw_residual(&work, &stderr_id);
    assert_eq!(err_res["surface"], "first-diagnostic-line");
    assert_eq!(err_res["axis"], "stderr");
    let out_res = raw_residual(&work, &stdout_id);
    assert_eq!(out_res["surface"], "first-stdout-line");
    assert_eq!(out_res["axis"], "stdout");
    assert_eq!(
        out_res["raw_reference"].as_str().unwrap(),
        "ok: server 192.168.1.1",
        "reference stdout first line"
    );
    assert_eq!(out_res["raw_candidate"].as_str().unwrap(), "cand banner");

    // The token routes to the stdout minimizer.
    let tok: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("frf/residuals/{stdout_id}.token.json"))).unwrap(),
    )
    .unwrap();
    assert_eq!(
        tok["token"],
        "text/stdout-routing/first-line-token-change/open"
    );
    assert_eq!(tok["next_court"], "cli-stdout-minimize");
    assert_eq!(tok["blocks_claims"][0], "byte-identical stdout");

    // Comparator identity is evidence: the receipt's observable block names
    // the exact relation applied.
    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &run]);
    assert_success(&out, "receipt emit");
    let receipt = stdout(&out);
    let rec: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("{ROOT}/receipts/{receipt}.json"))).unwrap(),
    )
    .unwrap();
    let obs = rec["observables"].as_array().unwrap();
    let stdout_obs = obs
        .iter()
        .find(|o| o["axis"] == "stdout")
        .expect("stdout observable in receipt");
    assert_eq!(stdout_obs["comparator"], "eq(stdout-first-line)");
    assert_eq!(stdout_obs["verdict"], "residual");
    let tokens = rec["endoduction"]["tokens"].as_array().unwrap();
    let out_token = tokens
        .iter()
        .find(|t| t["residual_id"] == stdout_id)
        .expect("stdout token in receipt");
    assert_eq!(out_token["next_court"], "cli-stdout-minimize");
}

#[test]
fn clean_stdout_axis_is_claimable() {
    // Positive control for the new axis: a candidate identical to the
    // reference leaves stdout clean too, and the claim covers it.
    let work = Workdir::new("stdout-clean");
    work.copy_canonical_tree();
    let ref_content = fs::read_to_string(work.path("golden/reference.sh")).unwrap();
    work.write_candidate(&ref_content);
    admit_reference(&work);

    let m = manifest_variant(
        &work,
        "observables: [exit, stderr]",
        "observables: [exit, stdout]",
    );
    let out = frf(&work, &["--root", ROOT, "court", "run", &m]);
    assert_success(&out, "court run with stdout axis");
    let run = stdout(&out);

    let residuals = fs::read_dir(work.path("frf/residuals")).unwrap().count();
    assert_eq!(
        residuals, 0,
        "identical behavior leaves no residuals on any axis"
    );

    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &run]);
    assert_success(&out, "receipt emit");
    let receipt = stdout(&out);
    let out = frf(&work, &["--root", ROOT, "claim", "compile", &receipt]);
    assert_success(&out, "claim compile");
    let text = stdout(&out);
    assert!(
        text.contains("malformed-input exit class and malformed-input first stdout line"),
        "claim: {text}"
    );
}

#[test]
fn open_residual_blocks_only_its_own_axis() {
    // exit clean, stderr open: the claim compiles scoped to exit parity,
    // and the refusal names the open stderr residual as the non-claim
    // boundary. An open residual never throws away unrelated knowledge.
    let work = Workdir::new("axis-block");
    work.copy_canonical_tree();
    // Same exit class as the reference, empty stderr: only the text axis
    // diverges.
    work.write_candidate("#!/bin/sh\n# same exit class, no stderr\nexit 2\n");
    admit_reference(&work);
    let run = run_court(&work);

    // Exactly one residual: text, open (the ids are content addresses).
    let residuals: Vec<String> = fs::read_dir(work.path("frf/residuals"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.ends_with(".json") && !n.ends_with(".token.json"))
        .collect();
    assert_eq!(
        residuals.len(),
        1,
        "only the stderr axis diverges: {residuals:?}"
    );
    let text_id = residuals[0].trim_end_matches(".json").to_string();

    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &run]);
    assert_success(&out, "receipt emit");
    let receipt = stdout(&out);

    // The claim compiles (exit is clean), with the refusal printed.
    let out = frf(&work, &["--root", ROOT, "claim", "compile", &receipt]);
    assert_success(&out, "claim compile (exit scope only)");
    let text = stdout(&out);
    assert!(text.contains("malformed-input exit class"), "claim: {text}");
    assert!(!text.contains("first diagnostic line"));
    assert!(stderr(&out).contains(&format!(
        "cannot claim compatibility for fixture family malformed-input because residual {text_id} (text) is open"
    )));

    // The claim file carries the IR: scope = [exit], exclusions = [text].
    let claim_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(claim_path(&work, &receipt)).unwrap()).unwrap();
    assert_eq!(claim_json["observable_scope"][0], "exit");
    assert_eq!(claim_json["excluded_evidence"][0], text_id);
    // The full scope algebra: the claim's scope carries the executed
    // surface, and the open text residual does NOT block it (different
    // axis — intersection is empty), while it IS recorded as evidence the
    // claim excludes.
    assert_eq!(claim_json["scope"]["cells"][0]["observables"][0], "exit");
    assert_eq!(claim_json["requires"][0], receipt);
    assert_eq!(claim_json["blockers"].as_array().unwrap().len(), 0);
}

#[test]
fn open_residual_on_the_same_surface_blocks_a_later_claim() {
    // The cross-run half of the scope algebra: a claim compiled from a
    // passing run is refused when an OPEN residual about the SAME surface
    // (same candidate artifact, axis, fixture, environment) was recorded by
    // an earlier run — an unexplained divergence about the claimed surface
    // blocks wherever it was recorded. A claim about a DIFFERENT surface is
    // not blocked.
    let work = Workdir::new("surface-block");
    work.copy_canonical_tree();
    admit_reference(&work);

    // Run 1: a nondeterministic candidate — first execution diverges on
    // exit (open residual on candidate H), second execution matches the
    // reference's exit class. (stderr always diverges: the reference emits a
    // diagnostic, this candidate emits none — that residual is on a
    // different axis and must NOT block the exit claim.)
    work.write_candidate(
        "#!/bin/sh\n# flip: exit 1 on the first execution, 2 (the reference class) afterwards\nif [ ! -f frf/captures/.flip ]; then mkdir -p frf/captures && touch frf/captures/.flip; exit 1; fi\nexit 2\n",
    );
    let out = frf(&work, &["--root", ROOT, "court", "run", MANIFEST]);
    assert_success(&out, "court run 1 (diverges)");
    let run1 = stdout(&out);
    let mut residuals: Vec<String> = fs::read_dir(work.path("frf/residuals"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.ends_with(".json") && !n.ends_with(".token.json"))
        .collect();
    residuals.sort();
    assert_eq!(
        residuals.len(),
        2,
        "run 1 diverges on exit AND stderr: {residuals:?}"
    );
    let exit_id = residual_id(&work, &run1, "exit");

    // Run 2: same candidate, same fixture, same environment — now passes.
    let out = frf(&work, &["--root", ROOT, "court", "run", MANIFEST]);
    assert_success(&out, "court run 2 (passes)");
    let run2 = stdout(&out);
    assert_ne!(run1, run2, "the two runs are distinct observations");

    // The passing run's receipt would have a clean exit axis, but the OPEN
    // residual from run 1 lies on the SAME surface (same candidate hash,
    // same fixture, same environment, same axis) — the claim must be
    // refused, and the refusal must name the blocking residual.
    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &run2]);
    assert_success(&out, "receipt emit (passing run)");
    let receipt2 = stdout(&out);
    let out = frf(&work, &["--root", ROOT, "claim", "compile", &receipt2]);
    assert!(
        !out.status.success(),
        "an open residual on the claimed surface must block the claim"
    );
    assert!(
        stderr(&out).contains(&exit_id) && stderr(&out).contains("intersect this claim's scope"),
        "the refusal must name the blocking residual: {}",
        stderr(&out)
    );
    // No claim file is written while blocked.
    assert!(
        fs::read_dir(work.path("frf/claims"))
            .unwrap()
            .next()
            .is_none(),
        "blocked compile must not write a claim"
    );

    // Disposing the residual fixed with a REAL resolution run closes it —
    // then the same claim compiles (the disposition is evidence-backed, and
    // the closure edge re-verifies).
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "residual",
            "dispose",
            &exit_id,
            "--disposition",
            "fixed",
            "--resolution-run",
            &run2,
            "--reason",
            "nondeterministic first-execution divergence; re-observed passing",
        ],
    );
    assert_success(&out, "dispose fixed (evidence-backed)");
    let out = frf(&work, &["--root", ROOT, "claim", "compile", &receipt2]);
    assert_success(&out, "claim compiles after the closure is evidenced");
}

#[test]
fn claim_json_renderer_emits_the_ir_canonically() {
    // Prose is one renderer; --json emits the same Claim IR as canonical
    // JSON (RFC 8785), deterministically.
    let work = Workdir::new("claim-json");
    work.copy_canonical_tree();
    // Same exit class as the reference, no stderr: only the text axis
    // diverges, so exit parity is claimable (the open text residual blocks
    // only its own axis).
    work.write_candidate("#!/bin/sh\n# same exit class, no stderr\nexit 2\n");
    admit_reference(&work);
    let run = run_court(&work);
    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &run]);
    assert_success(&out, "receipt emit");
    let receipt = stdout(&out);

    let out = frf(
        &work,
        &["--root", ROOT, "claim", "compile", &receipt, "--json"],
    );
    assert_success(&out, "claim --json");
    let first = stdout(&out);
    let value: serde_json::Value = serde_json::from_str(&first).unwrap();
    assert_eq!(value["receipt"], receipt);
    assert_eq!(value["schema_version"], "frf-claim-v9");
    assert_eq!(value["policy"], "baseline");
    assert_eq!(value["scope"]["cells"][0]["observables"][0], "exit");
    // Determinism: a second emission is byte-identical (canonical form).
    let out = frf(
        &work,
        &["--root", ROOT, "claim", "compile", &receipt, "--json"],
    );
    assert_success(&out, "claim --json (again)");
    assert_eq!(first, stdout(&out));
}

#[test]
fn harness_invalidates_the_entire_run_evidence() {
    // harness is run-level: even a clean axis is not claimable while a
    // harness residual exists.
    let work = Workdir::new("harness-run");
    work.copy_canonical_tree();
    work.write_candidate("#!/bin/sh\n# same exit class, no stderr\nexit 2\n");
    admit_reference(&work);
    let run = run_court(&work);
    let text_id = residual_id(&work, &run, "stderr");
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "residual",
            "dispose",
            &text_id,
            "--disposition",
            "harness",
            "--reason",
            "runner contamination suspected",
        ],
    );
    assert_success(&out, "dispose harness");
    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &run]);
    assert_success(&out, "receipt emit");
    let receipt = stdout(&out);
    let out = frf(&work, &["--root", ROOT, "claim", "compile", &receipt]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("invalidate the evidence of this run"),
        "stderr: {}",
        stderr(&out)
    );
    let claims_dir = work.path(&format!("{ROOT}/claims"));
    assert!(
        fs::read_dir(&claims_dir).unwrap().next().is_none(),
        "harness must refuse any claim file"
    );
}

/// The FRF/RUN/v2 identity commits the EXECUTION CONTRACT, not merely the
/// outputs: the same court with the same observable results under a
/// different FRF_EXEC_* override is a DIFFERENT bounded observation — a
/// different run identity — while the observation identity (what was
/// observed) stays equal. An override cannot silently share a run id with
/// the reference contract.
#[test]
fn run_identity_commits_frf_exec_overrides_end_to_end() {
    let work = Workdir::new("run-identity-commits-contract");
    work.copy_canonical_tree();
    admit_reference(&work);

    let default = run_court(&work);
    let overridden = run_court_env(&work, &[("FRF_EXEC_TIMEOUT_MS", "30000")]);
    assert_ne!(
        default, overridden,
        "identical outputs under a different execution contract must not share a run id"
    );

    let read_capture = |run: &str| -> serde_json::Value {
        serde_json::from_str(
            &fs::read_to_string(work.path(&format!("{ROOT}/captures/{run}/capture.json"))).unwrap(),
        )
        .unwrap()
    };
    let a = read_capture(&default);
    let b = read_capture(&overridden);

    // Same question, inputs, environment, and observed answer: the same
    // observation identity.
    assert_eq!(a["observation_identity"], b["observation_identity"]);
    // Different effective bounds: a different execution identity.
    assert_ne!(a["execution_identity"], b["execution_identity"]);
    assert_eq!(a["capture_bounds"]["timeout_ms"], "60000");
    assert_eq!(b["capture_bounds"]["timeout_ms"], "30000");
    // The recorded identities are real: rehashing through the verified
    // loader (frf replay) must accept the default run and refuse nothing
    // (replay rederives the identity from the recorded fields).
    let out = frf(
        &work,
        &["--root", ROOT, "replay", &default, "--policy", "exact"],
    );
    assert_success(&out, "replay the default run (identity rederives)");
    let out = frf_env(
        &work,
        &["--root", ROOT, "replay", &overridden, "--policy", "exact"],
        &[("FRF_EXEC_TIMEOUT_MS", "30000")],
    );
    assert_success(
        &out,
        "replay the overridden run under its own contract (identity rederives)",
    );
}

/// A timed-out court writes NO capture and NO residual — but it now writes
/// REFUSAL EVIDENCE: the content-addressed harness event AND the
/// execution-attempt record (the refusal-root: a failed observation attempt
/// is itself a first-class portable observation). The refusal record binds
/// the declared court, the bound artifacts, the execution contract (the
/// profile and capture bounds as enforced, including the override that
/// fired), the side, the harness event, and the reason — and every cited
/// member rederives on read.
#[test]
fn execution_timeout_writes_refusal_evidence_only() {
    let work = Workdir::new("timeout");
    work.copy_canonical_tree();
    work.write_candidate("#!/bin/sh\nsleep 5\n");
    admit_reference(&work);

    let out = frf_env(
        &work,
        &["--root", ROOT, "court", "run", MANIFEST],
        &[("FRF_EXEC_TIMEOUT_MS", "200")],
    );
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("execution timeout"),
        "stderr: {}",
        stderr(&out)
    );

    // No capture, no residual — the observation was refused, never truncated.
    let captures = fs::read_dir(work.path("frf/captures")).unwrap().count();
    assert_eq!(captures, 0, "no run dir may exist after a timeout");
    let residuals = fs::read_dir(work.path("frf/residuals")).unwrap().count();
    assert_eq!(residuals, 0, "no residuals may exist after a timeout");

    // The refusal is now evidence: exactly one harness event (the timeout on
    // the reference side first) and exactly one execution-attempt record.
    let harness: Vec<String> = fs::read_dir(work.path("frf/harness"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(harness.len(), 1, "one enforced-bound record: {harness:?}");
    let attempts: Vec<String> = fs::read_dir(work.path("frf/attempts"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(attempts.len(), 1, "one refusal-root record: {attempts:?}");
    let attempt_id = attempts[0].trim_end_matches(".json").to_string();

    // The attempt is VERIFIED before consumption: canonical, self-
    // authenticating, and every cited harness event verified + same-court.
    let store = frf::store::Store::new(work.path("frf").to_path_buf());
    let verified = frf::verify::load_execution_attempt_verified(&store, &attempt_id)
        .expect("the refusal-root must verify");
    let attempt = verified.record();
    assert_eq!(attempt.kind, "refused");
    assert_eq!(attempt.side, "candidate");
    assert_eq!(attempt.court, "cli-malformed-input");
    assert_eq!(attempt.refusal_reason.kind, "timeout");
    // The execution contract as enforced: the override that fired is part of
    // the record, not an ambient fact.
    assert_eq!(attempt.capture_bounds.timeout_ms, "200");
    assert_eq!(attempt.harness_events.len(), 1);
    let event = store
        .load_harness_event(&attempt.harness_events[0])
        .expect("the cited harness event must load");
    assert_eq!(event.event_kind, "timeout");
    assert_eq!(event.court, attempt.court);
}

/// The refusal-root is CONTRACT-BOUND: a different enforced execution
/// contract produces a different attempt — the identity commits the contract
/// exactly like the run identity does. (A timeout's recorded `observed` value
/// is the real elapsed time, so two timeouts are two distinct enforcement
/// records; the deterministic idempotence case is the stream overflow below.)
#[test]
fn refusal_attempt_identity_commits_the_execution_contract() {
    let work = Workdir::new("attempt-contract");
    work.copy_canonical_tree();
    work.write_candidate("#!/bin/sh\nsleep 5\n");
    admit_reference(&work);

    let run_once = |timeout: &str| {
        let out = frf_env(
            &work,
            &["--root", ROOT, "court", "run", MANIFEST],
            &[("FRF_EXEC_TIMEOUT_MS", timeout)],
        );
        assert!(!out.status.success());
        let mut attempts: Vec<String> = fs::read_dir(work.path("frf/attempts"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        attempts.sort();
        attempts
            .iter()
            .map(|n| n.trim_end_matches(".json").to_string())
            .collect::<Vec<_>>()
    };

    let a = run_once("200");
    let ac = run_once("150"); // a different enforced contract
    assert_eq!(
        ac.len(),
        2,
        "a different enforced timeout must be a different attempt (got {ac:?})"
    );
    assert_ne!(ac[0], ac[1]);

    // Both records verify.
    let store = frf::store::Store::new(work.path("frf").to_path_buf());
    for id in [&a[0], &ac[0], &ac[1]] {
        let v = frf::verify::load_execution_attempt_verified(&store, id)
            .expect("every refusal-root must verify");
        assert_eq!(v.record().refusal_reason.kind, "timeout");
    }
}

/// A deterministic enforcement (stream overflow — the observed value is the
/// overflowed byte count) is IDEMPOTENT: re-running the same refused
/// observation reproduces the same attempt record, and a different enforced
/// cap is a different attempt.
#[test]
fn stream_overflow_refusal_is_idempotent_and_contract_bound() {
    let work = Workdir::new("attempt-overflow-idem");
    work.copy_canonical_tree();
    work.write_candidate("#!/bin/sh\nhead -c 100000 /dev/zero\n");
    admit_reference(&work);

    let run_once = |cap: &str| {
        let out = frf_env(
            &work,
            &["--root", ROOT, "court", "run", MANIFEST],
            &[("FRF_EXEC_MAX_BYTES", cap)],
        );
        assert!(!out.status.success());
        let mut attempts: Vec<String> = fs::read_dir(work.path("frf/attempts"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        attempts.sort();
        attempts
            .iter()
            .map(|n| n.trim_end_matches(".json").to_string())
            .collect::<Vec<_>>()
    };

    let ab = run_once("1024");
    let abc = run_once("2048");
    assert_eq!(
        ab.len(),
        1,
        "the same deterministic refused observation must reproduce the same attempt (got {ab:?})"
    );
    assert_eq!(
        abc.len(),
        2,
        "a different enforced cap must be a different attempt (got {abc:?})"
    );
    assert_ne!(
        abc[0], abc[1],
        "a different enforced cap must be a different attempt"
    );

    let store = frf::store::Store::new(work.path("frf").to_path_buf());
    for id in [&abc[0], &abc[1]] {
        let v = frf::verify::load_execution_attempt_verified(&store, id)
            .expect("every refusal-root must verify");
        assert_eq!(v.record().refusal_reason.kind, "stream-overflow");
        assert_eq!(v.record().side, "candidate");
    }
}

/// A hand-edited refusal-root is refused on read — the identity rederives
/// from the record's own fields, so a tampered record can never be consumed
/// as evidence.
#[test]
fn tampered_refusal_attempt_is_refused() {
    let work = Workdir::new("attempt-tamper");
    work.copy_canonical_tree();
    work.write_candidate("#!/bin/sh\nsleep 5\n");
    admit_reference(&work);

    let out = frf_env(
        &work,
        &["--root", ROOT, "court", "run", MANIFEST],
        &[("FRF_EXEC_TIMEOUT_MS", "200")],
    );
    assert!(!out.status.success());
    let attempts: Vec<String> = fs::read_dir(work.path("frf/attempts"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    let id = attempts[0].trim_end_matches(".json").to_string();
    let path = work.path(&format!("frf/attempts/{id}.json"));
    let store = frf::store::Store::new(work.path("frf").to_path_buf());
    let original = fs::read(&path).unwrap();

    // Tamper 1: flip a field the IDENTITY commits (side candidate ->
    // reference) without touching the id: the content address must no longer
    // rederive — the store loader refuses before the record may be consumed.
    let flipped = String::from_utf8(original.clone())
        .unwrap()
        .replace("\"side\":\"candidate\"", "\"side\":\"reference\"");
    fs::write(&path, flipped).unwrap();
    let err = match frf::verify::load_execution_attempt_verified(&store, &id) {
        Err(e) => e,
        Ok(_) => panic!("a tampered refusal-root (side) must be refused"),
    };
    assert!(
        err.0.contains("does not rederive"),
        "unexpected error: {}",
        err.0
    );

    // Tamper 2: flip the kind (refused -> completed) from the ORIGINAL
    // record. The identity does not commit `kind` (a completed attempt IS a
    // run — no such record exists), so the verified loader's kind check is
    // what refuses it.
    let flipped = String::from_utf8(original)
        .unwrap()
        .replace("\"kind\":\"refused\"", "\"kind\":\"completed\"");
    fs::write(&path, flipped).unwrap();
    let err = match frf::verify::load_execution_attempt_verified(&store, &id) {
        Err(e) => e,
        Ok(_) => panic!("a tampered refusal-root (kind) must be refused"),
    };
    assert!(
        err.0.contains("unexpected kind"),
        "unexpected error: {}",
        err.0
    );
}

/// The refusal-root is portable: a receipt-rooted bundle carries the refused
/// attempts recorded for the root receipt's court, and bundle verification
/// accepts the refusal history — then refuses a tampered attempt inside the
/// bundle.
#[test]
fn bundle_carries_and_verifies_the_court_refusal_history() {
    let work = Workdir::new("attempt-bundle");
    work.copy_canonical_tree();
    work.write_candidate("#!/bin/sh\nsleep 5\n");
    admit_reference(&work);

    // First a refusal (the sleeping candidate), then a success (the patched
    // candidate) — same court, same store.
    let out = frf_env(
        &work,
        &["--root", ROOT, "court", "run", MANIFEST],
        &[("FRF_EXEC_TIMEOUT_MS", "200")],
    );
    assert!(!out.status.success());
    work.write_candidate("#!/bin/sh\nexit 2\n"); // the reference's exit class
    let run = run_court(&work);
    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &run]);
    assert_success(&out, "receipt emit");
    let receipt = stdout(&out);

    let bundle = work.path("bundle");
    let out = frf(
        &work,
        &[
            "--root", ROOT, "bundle", "export", &receipt, "--output", "bundle",
        ],
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let out = frf(&work, &["--root", ROOT, "bundle", "verify", "bundle"]);
    assert!(
        out.status.success(),
        "the bundle must verify with its refusal history: {}",
        stderr(&out)
    );
    // The attempt + its harness event travel with the bundle.
    assert!(
        bundle.join("attempts").is_dir(),
        "the bundle must carry the refusal-root"
    );
    assert_eq!(
        fs::read_dir(bundle.join("attempts")).unwrap().count(),
        1,
        "exactly the one refusal"
    );
    assert!(
        fs::read_dir(bundle.join("harness")).unwrap().count() >= 1,
        "the attempt's harness event must travel with it"
    );

    // Tamper the attempt inside the bundle: verification must refuse. Flip
    // the kind (refused -> completed): the identity does not commit `kind`
    // (a completed attempt IS a run — no such record exists), so the
    // verifier's kind check is what refuses it.
    let attempt_file = fs::read_dir(bundle.join("attempts"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    let path = attempt_file.path();
    // The bundle seals files 0444; a tamperer would chmod first.
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    let mut bytes = fs::read(&path).unwrap();
    let flipped = String::from_utf8(bytes.clone())
        .unwrap()
        .replace("\"kind\":\"refused\"", "\"kind\":\"completed\"");
    bytes = flipped.into_bytes();
    fs::write(&path, &bytes).unwrap();
    let out = frf(&work, &["--root", ROOT, "bundle", "verify", "bundle"]);
    assert!(
        !out.status.success(),
        "a bundle with a tampered refusal-root must not verify"
    );
}

/// A stream overflow is also a refusal-root: the enforced stream cap fires
/// the harness event, the attempt record binds it, and the record is a
/// stream-overflow refusal with the enforced cap committed.
#[test]
fn stream_overflow_writes_a_verified_refusal_root() {
    let work = Workdir::new("overflow-attempt");
    work.copy_canonical_tree();
    work.write_candidate("#!/bin/sh\nhead -c 100000 /dev/zero\n");
    admit_reference(&work);

    let out = frf_env(
        &work,
        &["--root", ROOT, "court", "run", MANIFEST],
        &[("FRF_EXEC_MAX_BYTES", "1024")],
    );
    assert!(!out.status.success());
    let attempts: Vec<String> = fs::read_dir(work.path("frf/attempts"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(attempts.len(), 1);
    let id = attempts[0].trim_end_matches(".json").to_string();
    let store = frf::store::Store::new(work.path("frf").to_path_buf());
    let verified = frf::verify::load_execution_attempt_verified(&store, &id)
        .expect("the overflow refusal-root must verify");
    assert_eq!(verified.record().refusal_reason.kind, "stream-overflow");
    assert_eq!(verified.record().capture_bounds.max_stream_bytes, "1024");
    assert_eq!(verified.record().harness_events.len(), 1);
}

#[test]
fn timeout_terminates_descendants_that_hold_the_pipes() {
    // The candidate spawns a grandchild that keeps stdout/stderr open for
    // 5 s, then sleeps past the timeout. The harness must kill the whole
    // process group (not just the direct child) so the pipes reach EOF and
    // the run fails cleanly instead of waiting on the grandchild.
    let work = Workdir::new("timeout-desc");
    work.copy_canonical_tree();
    work.write_candidate("#!/bin/sh\nsleep 5 &\nsleep 30\n");
    admit_reference(&work);

    let start = std::time::Instant::now();
    let out = frf_env(
        &work,
        &["--root", ROOT, "court", "run", MANIFEST],
        &[("FRF_EXEC_TIMEOUT_MS", "200")],
    );
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("execution timeout"),
        "stderr: {}",
        stderr(&out)
    );
    assert!(
        start.elapsed() < std::time::Duration::from_secs(3),
        "must not wait for the grandchild to release the pipes (took {:?})",
        start.elapsed()
    );

    let captures = fs::read_dir(work.path("frf/captures")).unwrap().count();
    assert_eq!(captures, 0, "no run dir may exist after a timeout");
}

#[test]
fn replay_reproduces_the_captured_observation() {
    // Replay is a first-class evidence operation: it re-executes the exact
    // snapshotted artifacts + argv under a checked environment and requires
    // the observation to reproduce byte-for-byte.
    let work = Workdir::new("replay");
    work.copy_canonical_tree();
    admit_reference(&work);
    let run = run_court(&work);

    let out = frf(&work, &["--root", ROOT, "replay", &run]);
    assert_success(&out, "replay run");
    assert!(
        stdout(&out).contains("reproduced") && stdout(&out).contains("2 residual"),
        "stdout: {}",
        stdout(&out)
    );

    // A receipt id replays the same run.
    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &run]);
    assert_success(&out, "receipt emit");
    let receipt = stdout(&out);
    let out = frf(&work, &["--root", ROOT, "replay", &receipt]);
    assert_success(&out, "replay receipt");
    assert!(stdout(&out).contains("reproduced"));
}

#[test]
fn replay_refuses_corrupt_objects_and_unknown_ids() {
    let work = Workdir::new("replay-refuse");
    work.copy_canonical_tree();
    admit_reference(&work);
    let run = run_court(&work);

    // Corrupt the candidate snapshot: replay must refuse, never execute the
    // tampered bytes.
    let capture: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("{ROOT}/captures/{run}/capture.json"))).unwrap(),
    )
    .unwrap();
    let cand_sha = capture["candidate_artifact"]["sha256"].as_str().unwrap();
    let obj = work.path(&format!("{ROOT}/objects/sha256/{cand_sha}"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&obj, fs::Permissions::from_mode(0o644)).unwrap();
    }
    fs::write(&obj, b"#!/bin/sh\necho corrupted\n").unwrap();
    let out = frf(&work, &["--root", ROOT, "replay", &run]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("corrupt"), "stderr: {}", stderr(&out));

    // Unknown id.
    let out = frf(&work, &["--root", ROOT, "replay", "run-nope"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("no such run or receipt 'run-nope'"));
}

#[test]
fn receipt_emit_is_idempotent_per_state() {
    let work = Workdir::new("receipt-idem");
    work.copy_canonical_tree();
    admit_reference(&work);
    let run = run_court(&work);

    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &run]);
    assert_success(&out, "receipt emit");
    let first = stdout(&out);
    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &run]);
    assert_success(&out, "receipt emit again");
    let second = stdout(&out);
    assert_eq!(first, second, "same state must yield the same receipt id");
    assert!(stderr(&out).contains("already exists"));

    // Unknown run.
    let out = frf(&work, &["--root", ROOT, "receipt", "emit", "run-nope"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("no such run 'run-nope'"));
}

#[test]
fn claim_compile_rejects_unknown_receipt() {
    let work = Workdir::new("claim-unknown");
    work.copy_canonical_tree();
    let out = frf(&work, &["--root", ROOT, "claim", "compile", "receipt-nope"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("no such receipt 'receipt-nope'"));
}

#[test]
fn minimize_reduces_the_fixture_with_a_court_verified_reproducer() {
    // The routed minimizer (the exit residual's κ token routes to
    // cli-exit-minimize): deterministic ddmin over the fixture lines, holding
    // candidate/authority/comparator/environment fixed, every attempt
    // recorded, the final reproducer court-verified.
    let work = Workdir::new("minimize");
    work.copy_canonical_tree();
    admit_reference(&work);
    let run = run_court(&work);
    let exit_id = residual_id(&work, &run, "exit");

    let out = frf(&work, &["--root", ROOT, "court", "minimize", &exit_id]);
    assert_success(&out, "court minimize");
    let reduction_id = stdout(&out);
    assert_eq!(reduction_id.len(), 64, "content-addressed reduction id");

    let rec: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("frf/reductions/{reduction_id}.json"))).unwrap(),
    )
    .unwrap();
    assert_eq!(rec["schema_version"], "frf-reduction-v4");
    assert_eq!(rec["residual_id"], exit_id);
    assert_eq!(rec["axis"], "exit");
    assert_eq!(rec["derivation"]["strategy"], "ddmin-lines");
    assert_eq!(rec["derivation"]["minimality"]["kind"], "one-minimal");
    assert_eq!(rec["derivation"]["minimality"]["granularity"], "line");
    assert_eq!(rec["derivation"]["minimality"]["proven"], true);
    assert!(
        rec["derivation"]["final_lines"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap()
            < rec["derivation"]["original_lines"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap(),
        "the reproducer must be strictly smaller"
    );
    // The content address rederives from the record's own fields.
    let attempts = rec["attempts"].as_array().unwrap();
    assert!(!attempts.is_empty(), "every attempt is recorded");
    // Attempts carry their role/outcome/acceptance: the FIRST is the
    // baseline (never accepted), the LAST is the final court verification.
    assert_eq!(attempts[0]["role"], "baseline");
    assert_eq!(attempts[0]["accepted"], false);
    let last = attempts.last().unwrap();
    assert_eq!(last["fixture_sha256"], rec["final_fixture_sha256"]);
    assert_eq!(last["outcome"], "preserved");
    assert_eq!(last["accepted"], true);
    // The reproducer object exists (content-addressed, sealed).
    let final_sha = rec["final_fixture_sha256"].as_str().unwrap();
    let reproducer =
        fs::read_to_string(work.path(&format!("frf/objects/sha256/{final_sha}"))).unwrap();
    // The minimal reproducer is the malformed directive alone.
    assert!(reproducer.contains("servre"), "reproducer: {reproducer:?}");
    assert!(!reproducer.contains("server"), "reproducer: {reproducer:?}");

    // The record refuses tampering: a hand-edited field breaks the content
    // address (the store refuses on read).
    let mut tampered: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("frf/reductions/{reduction_id}.json"))).unwrap(),
    )
    .unwrap();
    tampered["axis"] = serde_json::Value::String("stdout".to_string());
    // Write the tampered record as CANONICAL JSON: the canonical-bytes gate
    // passes, and the content-address check must refuse the edited field.
    fs::write(
        work.path(&format!("frf/reductions/{reduction_id}.json")),
        frf::canon::canonical(&tampered).unwrap(),
    )
    .unwrap();
    let store = frf::store::Store::new(work.path(ROOT));
    assert!(
        store.load_reduction(&reduction_id).is_err(),
        "a tampered reduction must be refused on read"
    );
}

#[test]
fn minimize_refuses_a_non_text_fixture() {
    // The reducer is ddmin over text lines; a binary fixture is refused
    // honestly rather than mangled.
    let work = Workdir::new("minimize-binary");
    work.copy_canonical_tree();
    admit_reference(&work);
    // A binary fixture (invalid UTF-8): the reducer refuses it honestly
    // rather than mangling bytes.
    let fixture_path = work.path("frf/courts/cli-malformed-input/fixtures/malformed-path.conf");
    fs::write(&fixture_path, b"\xff\xfe\x00binary\n").unwrap();
    let out = frf(&work, &["--root", ROOT, "court", "run", MANIFEST]);
    assert_success(&out, "court run (binary fixture)");
    let run = stdout(&out);
    let exit_id = residual_id(&work, &run, "exit");
    let out = frf(&work, &["--root", ROOT, "court", "minimize", &exit_id]);
    assert!(!out.status.success(), "binary fixtures are refused");
    assert!(
        stderr(&out).contains("not UTF-8 text"),
        "refusal must name the reason: {}",
        stderr(&out)
    );
}

// ---------------------------------------------------------------------------
// Knowledge snapshot — a claim is admissible relative to a committed universe
// ---------------------------------------------------------------------------

#[test]
fn claims_bind_the_evidence_universe_they_were_admissible_under() {
    // The review's P0 for claims, executed: claim admissibility is relative
    // to an explicitly committed state of knowledge. The compiled claim
    // carries the universe (its residual heads + dispositions + content
    // address), so the negative search is portable — and a later store
    // mutation is a NEW universe, not a silent rewrite of the old claim.
    let work = Workdir::new("claim-universe");
    work.copy_canonical_tree();
    admit_reference(&work);
    let run = run_court(&work);
    let resolution_run = run_resolution_court(&work);
    let exit_id = residual_id(&work, &run, "exit");
    let text_id = residual_id(&work, &run, "stderr");
    let res_text_id = residual_id(&work, &resolution_run, "stderr");
    for (id, disposition, reason, resolution) in [
        (
            exit_id.clone(),
            "fixed",
            "candidate patched to preserve reference exit class",
            Some(resolution_run.as_str()),
        ),
        (
            text_id.clone(),
            "intentional",
            "clearer diagnostic wording",
            None,
        ),
        (
            res_text_id.clone(),
            "intentional",
            "re-observed wording divergence",
            None,
        ),
    ] {
        let mut args = vec![
            "--root".to_string(),
            ROOT.to_string(),
            "residual".to_string(),
            "dispose".to_string(),
            id.to_string(),
            "--disposition".to_string(),
            disposition.to_string(),
            "--reason".to_string(),
            reason.to_string(),
        ];
        if let Some(run) = resolution {
            args.push("--resolution-run".to_string());
            args.push(run.to_string());
        }
        let out = frf(&work, &args.iter().map(|s| s.as_str()).collect::<Vec<_>>());
        assert_success(&out, &format!("dispose {id}"));
    }
    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &resolution_run]);
    assert_success(&out, "receipt emit");
    let receipt = stdout(&out);
    let out = frf(&work, &["--root", ROOT, "claim", "compile", &receipt]);
    assert_success(&out, "claim compile (universe U1)");
    // The receipt now has one claim (universe U1); after the recompile below
    // it will have TWO — a different knowledge universe is a DIFFERENT claim
    // and they coexist forever. Resolve each by its snapshot cid.
    let claims = claim_json_all(&work, &receipt);
    let claim1 = claims[0].clone();
    let snapshot1 = claim1["knowledge_snapshot"].clone();
    let cid1 = snapshot1["cid"].as_str().unwrap().to_string();
    // The snapshot's cid rederives from its own fields.
    let snapshot1_typed: frf::model::KnowledgeSnapshot =
        serde_json::from_value(snapshot1.clone()).unwrap();
    assert_eq!(
        frf::semantics::knowledge_snapshot_identity(&snapshot1_typed).unwrap(),
        cid1
    );
    // The universe records the text residual as INTENTIONAL at compile time.
    let head_1 = snapshot1["residual_heads"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["id"] == text_id)
        .unwrap();
    assert_eq!(head_1["disposition"], "intentional");

    // Mutate the universe: RE-DISPOSE the text residual (intentional ->
    // environmental: a new event, a new head, a new universe).
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "residual",
            "dispose",
            &text_id,
            "--disposition",
            "environmental",
            "--reason",
            "reclassified later",
        ],
    );
    assert_success(&out, "re-dispose the text residual (universe mutation)");
    let out = frf(&work, &["--root", ROOT, "claim", "compile", &receipt]);
    assert_success(&out, "claim recompile (universe U2)");
    // TWO claims now coexist for the same receipt — U1's and U2's.
    let claims = claim_json_all(&work, &receipt);
    assert_eq!(claims.len(), 2, "U1's claim and U2's claim coexist forever");
    let claim2 = claims
        .iter()
        .find(|c| c["knowledge_snapshot"]["cid"] != cid1)
        .expect("the U2 claim")
        .clone();
    let snapshot2 = claim2["knowledge_snapshot"].clone();
    let cid2 = snapshot2["cid"].as_str().unwrap().to_string();
    assert_ne!(
        cid1, cid2,
        "a different knowledge universe is a different claim"
    );
    let head_1_new = snapshot2["residual_heads"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["id"] == text_id)
        .unwrap();
    assert_eq!(head_1_new["disposition"], "environmental");

    // The OLD universe is still self-consistent and still admissible: the
    // blocker scan over the OLD snapshot (the negative search, reproduced)
    // finds no blocker intersecting the claim's scope K — the mutation did
    // not retroactively change what the old claim meant.
    let store = frf::store::Store::new(work.path("frf"));
    let receipt_doc: frf::model::Receipt = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("frf/receipts/{receipt}.json"))).unwrap(),
    )
    .unwrap();
    let k = frf::scope::claim_scope(&receipt_doc);
    let k_region = frf::model::EvidenceRegion::cell(k);
    let blockers_old =
        frf::commands::claim::store_blockers(&store, &k_region, &snapshot1_typed).unwrap();
    assert!(
        blockers_old.is_empty(),
        "the claim's own universe carries no blocker for its scope"
    );
    let snapshot2_typed: frf::model::KnowledgeSnapshot = serde_json::from_value(snapshot2).unwrap();
    assert_eq!(
        frf::semantics::knowledge_snapshot_identity(&snapshot2_typed).unwrap(),
        cid2
    );
}
