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
    assert!(stderr(&out).contains("does not exercise it"));
    // Without a file argument both sides hit their no-input path: same exit
    // class (2), different wording → exactly one text residual.
    assert!(work.path("frf/residuals/cli-text-0001.json").is_file());
    assert!(!work.path("frf/residuals/cli-exit-0001.json").exists());
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

    // Close the text residual first so the claim semantics below are decided
    // by the exit residual alone.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "residual",
            "dispose",
            "cli-text-0001",
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
                "cli-exit-0001",
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
            raw_residual(&work, "cli-exit-0001")
                .get("disposition")
                .is_none(),
            "observation must never carry a disposition"
        );
        let event = last_event(&work, "cli-exit-0001");
        assert_eq!(event["disposition"], kind);
        assert_eq!(event["reason"], format!("regression: {kind}"));
        assert!(
            event.get("resolution_run_id").is_none(),
            "{kind} must not carry a resolution_run_id"
        );
        // The token follows the projection.
        let tok: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(work.path("frf/residuals/cli-exit-0001.token.json")).unwrap(),
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
            "cli-exit-0001",
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
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "residual",
            "dispose",
            "cli-exit-0001",
            "--disposition",
            "fixed",
            "--resolution-run",
            &resolution_run,
            "--reason",
            "candidate patched",
        ],
    );
    assert_success(&out, "dispose exit fixed with closure evidence");
    let event = last_event(&work, "cli-exit-0001");
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
            "cli-text-0002",
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

    // The resolution run must exist.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "residual",
            "dispose",
            "cli-exit-0001",
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
            "cli-exit-0001",
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
            "cli-exit-0001",
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
            "cli-exit-0001",
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
            "cli-exit-0001",
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
    assert_eq!(projected_disposition(&work, "cli-exit-0001"), "open");
}

#[test]
fn disposition_reason_gate() {
    let work = Workdir::new("reason-gate");
    work.copy_canonical_tree();
    admit_reference(&work);
    run_court(&work);

    // Missing --reason: clap refuses at parse time.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "residual",
            "dispose",
            "cli-exit-0001",
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
                "cli-exit-0001",
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
            "cli-exit-0001",
            "--disposition",
            "intentional",
            "--reason",
            "line one\nline two",
        ],
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("single line"));

    // The residual is still open after all refusals (no events appended).
    assert_eq!(projected_disposition(&work, "cli-exit-0001"), "open");
}

#[test]
fn dispositions_are_append_only_events() {
    let work = Workdir::new("append-only");
    work.copy_canonical_tree();
    admit_reference(&work);
    run_court(&work);

    // The observation record is byte-identical before and after disposal.
    let observation = work.path("frf/residuals/cli-text-0001.json");
    let before = fs::read(&observation).unwrap();

    let dispose = |kind: &str, reason: &str| {
        let out = frf(
            &work,
            &[
                "--root",
                ROOT,
                "residual",
                "dispose",
                "cli-text-0001",
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
    let events_dir = work.path("frf/residuals/cli-text-0001.events");
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
    assert_eq!(projected_disposition(&work, "cli-text-0001"), "unknown");

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

    // exit, stderr, stdout -> cli-exit-0001, cli-text-0001, cli-text-0002.
    let exit_res = raw_residual(&work, "cli-exit-0001");
    assert_eq!(exit_res["raw_reference"], "2");
    assert_eq!(exit_res["raw_candidate"], "1");
    let err_res = raw_residual(&work, "cli-text-0001");
    assert_eq!(err_res["surface"], "first-diagnostic-line");
    assert_eq!(err_res["axis"], "stderr");
    let out_res = raw_residual(&work, "cli-text-0002");
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
        &fs::read_to_string(work.path("frf/residuals/cli-text-0002.token.json")).unwrap(),
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
        .find(|t| t["residual_id"] == "cli-text-0002")
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

    // Exactly one residual: text, open.
    let residuals: Vec<String> = fs::read_dir(work.path("frf/residuals"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.ends_with(".json") && !n.ends_with(".token.json"))
        .collect();
    assert_eq!(
        residuals,
        vec!["cli-text-0001.json"],
        "only the stderr axis diverges"
    );

    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &run]);
    assert_success(&out, "receipt emit");
    let receipt = stdout(&out);

    // The claim compiles (exit is clean), with the refusal printed.
    let out = frf(&work, &["--root", ROOT, "claim", "compile", &receipt]);
    assert_success(&out, "claim compile (exit scope only)");
    let text = stdout(&out);
    assert!(text.contains("malformed-input exit class"), "claim: {text}");
    assert!(!text.contains("first diagnostic line"));
    assert!(stderr(&out).contains(
        "cannot claim compatibility for fixture family malformed-input because residual cli-text-0001 (text) is open"
    ));

    // The claim file carries the IR: scope = [exit], exclusions = [text].
    let claim_json: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("{ROOT}/claims/{receipt}.json"))).unwrap(),
    )
    .unwrap();
    assert_eq!(claim_json["observable_scope"][0], "exit");
    assert_eq!(claim_json["excluded_evidence"][0], "cli-text-0001");
    // The full scope algebra: the claim's scope carries the executed
    // surface, and the open text residual does NOT block it (different
    // axis — intersection is empty), while it IS recorded as evidence the
    // claim excludes.
    assert_eq!(claim_json["scope"]["observables"][0], "exit");
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
        residuals,
        vec!["cli-exit-0001.json", "cli-text-0001.json"],
        "run 1 diverges on exit AND stderr"
    );

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
        stderr(&out).contains("cli-exit-0001")
            && stderr(&out).contains("intersect this claim's scope"),
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
            "cli-exit-0001",
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
    assert_eq!(value["schema_version"], "frf-claim-v4");
    assert_eq!(value["scope"]["observables"][0], "exit");
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
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "residual",
            "dispose",
            "cli-text-0001",
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

#[test]
fn execution_timeout_kills_and_writes_nothing() {
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

    // A timed-out court writes no evidence at all.
    let captures = fs::read_dir(work.path("frf/captures")).unwrap().count();
    assert_eq!(captures, 0, "no run dir may exist after a timeout");
    let residuals = fs::read_dir(work.path("frf/residuals")).unwrap().count();
    assert_eq!(residuals, 0, "no residuals may exist after a timeout");
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
    let _run = run_court(&work);

    let out = frf(
        &work,
        &["--root", ROOT, "court", "minimize", "cli-exit-0001"],
    );
    assert_success(&out, "court minimize");
    let reduction_id = stdout(&out);
    assert_eq!(reduction_id.len(), 64, "content-addressed reduction id");

    let rec: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("frf/reductions/{reduction_id}.json"))).unwrap(),
    )
    .unwrap();
    assert_eq!(rec["schema_version"], "frf-reduction-v4");
    assert_eq!(rec["residual_id"], "cli-exit-0001");
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
    let out = frf(
        &work,
        &["--root", ROOT, "court", "minimize", "cli-exit-0001"],
    );
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
    run_court(&work);
    let resolution_run = run_resolution_court(&work);
    for (id, disposition, reason, resolution) in [
        (
            "cli-exit-0001",
            "fixed",
            "candidate patched to preserve reference exit class",
            Some(resolution_run.as_str()),
        ),
        (
            "cli-text-0001",
            "intentional",
            "clearer diagnostic wording",
            None,
        ),
        (
            "cli-text-0002",
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
    let claim1: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("frf/claims/{receipt}.json"))).unwrap(),
    )
    .unwrap();
    let snapshot1 = claim1["knowledge_snapshot"].clone();
    let cid1 = snapshot1["cid"].as_str().unwrap().to_string();
    // The snapshot's cid rederives from its own fields.
    let snapshot1_typed: frf::model::KnowledgeSnapshot =
        serde_json::from_value(snapshot1.clone()).unwrap();
    assert_eq!(
        frf::semantics::knowledge_snapshot_identity(&snapshot1_typed).unwrap(),
        cid1
    );
    // The universe records cli-text-0001 as INTENTIONAL at compile time.
    let head_1 = snapshot1["residual_heads"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["id"] == "cli-text-0001")
        .unwrap();
    assert_eq!(head_1["disposition"], "intentional");

    // Mutate the universe: RE-DISPOSE an unrelated residual (cli-text-0001
    // intentional -> environmental: a new event, a new head, a new universe).
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "residual",
            "dispose",
            "cli-text-0001",
            "--disposition",
            "environmental",
            "--reason",
            "reclassified later",
        ],
    );
    assert_success(&out, "re-dispose cli-text-0001 (universe mutation)");
    let out = frf(&work, &["--root", ROOT, "claim", "compile", &receipt]);
    assert_success(&out, "claim recompile (universe U2)");
    let claim2: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("frf/claims/{receipt}.json"))).unwrap(),
    )
    .unwrap();
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
        .find(|h| h["id"] == "cli-text-0001")
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
    let blockers_old = frf::commands::claim::store_blockers(&store, &k, &snapshot1_typed).unwrap();
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
