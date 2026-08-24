//! The TRAJECTORY SUBJECT BINDING (frf-claim-v13, P0): a trajectory premise
//! is evidence ABOUT the claim's subject — the anchored premise receipt —
//! never merely a valid graph on a matching axis. The premise carries
//! `receipt` (∈ claim.requires) and `anchor_run` (== receipt.run, a point of
//! the series); verification rederives the lineage from the anchored
//! receipt's authority / fixture-family / fixture semantics, requires the
//! axis to be a clean declared observable of that receipt, and (on
//! `candidate_revision`) proves the anchored point is the point of the
//! trajectory that corresponds to the candidate the parity claim is about.
//!
//! The falsification this suite pins: with two independently valid evidence
//! graphs on the SAME axis about DIFFERENT authorities, the unrelated
//! trajectory must never become a movement premise of the other authority's
//! claim — the subject binding is as unforgiving as the binding between a
//! residual and its run.
//!
//! Run: `cargo test --test trajectory_subject_binding`.

use std::fs;

mod common;
use common::*;

/// The candidate_revision trajectories present in the tree: (lineage, series,
/// file stem), sorted.
fn candidate_revision_trajectories(work: &Workdir) -> Vec<(String, String, String)> {
    let dir = work.path("frf/trajectories");
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.contains("candidate_revision") {
            continue;
        }
        let stem = name.trim_end_matches(".json").to_string();
        let mut parts = stem.split('.');
        let (lineage, series) = (
            parts.next().unwrap().to_string(),
            parts.nth(1).unwrap().to_string(),
        );
        out.push((lineage, series, stem));
    }
    out.sort();
    out
}

/// The candidate_revision trajectory whose axis is `axis` and whose series is
/// `series` (or, when `series` is None, the first such trajectory), with its
/// observations' runs.
fn trajectory_for_axis(
    work: &Workdir,
    axis: &str,
    series: Option<&str>,
) -> (String, String, String, Vec<(String, bool)>) {
    for (lineage, sid, stem) in candidate_revision_trajectories(work) {
        if let Some(want) = series {
            if sid != want {
                continue;
            }
        }
        let path = work.path(&format!("frf/trajectories/{stem}.json"));
        let doc: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
        if doc["axis"] != axis {
            continue;
        }
        let obs: Vec<(String, bool)> = doc["observations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| {
                (
                    o["run"].as_str().unwrap().to_string(),
                    o["observed"].as_bool().unwrap(),
                )
            })
            .collect();
        return (lineage, sid, stem, obs);
    }
    panic!("no {axis} candidate_revision trajectory in the tree");
}

/// The exit lineage's candidate_revision ladder: run the court over
/// (candidate, candidate-fixed), pick the exit-axis trajectory, and return
/// its document key (`lineage.candidate_revision.series`) plus the runs of
/// its two points (observed, clean).
fn exit_ladder(work: &Workdir, manifest: &str) -> (String, String, String) {
    let out = frf(
        work,
        &[
            "--root",
            ROOT,
            "court",
            "run",
            manifest,
            "--candidate-revisions",
            "golden/candidate.sh,golden/work/candidate-fixed.sh",
        ],
    );
    assert_success(&out, "candidate-revision ladder");
    let (lineage, series, stem, obs) = trajectory_for_axis(work, "exit", None);
    let _ = stem;
    assert_eq!(obs.len(), 2, "the ladder has two points");
    assert!(
        obs[0].1,
        "the original candidate observed the exit divergence"
    );
    assert!(!obs[1].1, "the fixed candidate ceased the exit divergence");
    (
        format!("{lineage}.candidate_revision.{series}"),
        obs[0].0.clone(),
        obs[1].0.clone(),
    )
}

#[test]
fn unrelated_same_axis_trajectory_cannot_become_claim_premise() {
    let work = Workdir::new("trajectory-subject-binding");
    work.copy_canonical_tree();
    admit_reference(&work);

    // Court A's OWN movement: the exit lineage over the candidate ladder —
    // observed at the original candidate, ceased at the fixed one.
    let (key_a, _buggy_run, clean_run) = exit_ladder(&work, MANIFEST);
    // The anchored premise: the CLEAN point's receipt (exit parity).
    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &clean_run]);
    assert_success(&out, "receipt emit (clean ladder point)");
    let receipt_a = stdout(&out);

    // POSITIVE CONTROL: the claim compiles WITH its own court's movement,
    // bound to its own clean premise.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "claim",
            "compile",
            &receipt_a,
            "--trajectory",
            &format!("{key_a}@{receipt_a}"),
        ],
    );
    assert_success(&out, "the claim compiles with its own court's movement");
    let pos = stdout(&out);
    assert!(
        pos.contains(
            "For reference ref-cli-1.8.2, the exit divergence is boundary-localized/abrupt"
        ) && pos.contains("it first appears at golden/candidate.sh")
            && pos.contains("no longer observed from golden/work/candidate-fixed.sh"),
        "the compiled claim renders the movement from its anchored premise's authority: {pos}"
    );
    // The compiled claim CARRIES the binding: the premise names the anchored
    // receipt and its run.
    let claim_dir = work.path("frf/claims/by-receipt").join(&receipt_a);
    let ids: Vec<String> = fs::read_dir(&claim_dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(ids.len(), 1, "one claim for the receipt");
    let claim: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("frf/claims/{}.json", ids[0]))).unwrap(),
    )
    .unwrap();
    let premise = &claim["trajectory_premises"][0];
    assert_eq!(premise["receipt"], receipt_a);
    assert_eq!(premise["anchor_run"], clean_run);
    assert_eq!(
        claim["proposition"].as_str().unwrap(),
        format!(
            "parity(cells=[{{observables=[exit]; fixtures=[{}]; family=malformed-input; authority=[ref-cli-1.8.2]; candidate=[{}]; environments=[{}]; versions=[1.8.2]}}]) + movement(cells=[{{lineage={},receipt={},anchor_run={},axis=exit,coordinate_system=candidate_revision,series={},trajectory={},drift=boundary-localized,slew=abrupt,localization=start,bands=1,onset=golden/candidate.sh,cessation=golden/work/candidate-fixed.sh}}])",
            claim["scope"]["cells"][0]["fixtures"][0].as_str().unwrap(),
            claim["scope"]["cells"][0]["candidate"][0].as_str().unwrap(),
            claim["scope"]["cells"][0]["environments"][0].as_str().unwrap(),
            premise["lineage"].as_str().unwrap(),
            receipt_a,
            clean_run,
            premise["series"].as_str().unwrap(),
            premise["trajectory"].as_str().unwrap(),
        )
    );

    // Court B: the SAME question shape on the SAME axis, but a DIFFERENT
    // authority — an independently admitted reference with different bytes
    // (hence a different identity) and identical behavior.
    let alt_ref = "golden/work/reference-alt.sh";
    let reference_body = fs::read_to_string(work.path("golden/reference.sh")).unwrap();
    fs::write(
        work.path(alt_ref),
        format!(
            "#!/bin/sh\n# ref-cli 1.8.2-alt — an INDEPENDENTLY admitted reference with\n# IDENTICAL behavior but DIFFERENT bytes: the same court question shape and\n# exit class under a DIFFERENT authority identity (the subject-binding\n# falsification control).\n{}",
            reference_body.trim_start_matches("#!/bin/sh\n")
        ),
    )
    .unwrap();
    set_exec(&work.path(alt_ref));
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "authority",
            "admit",
            alt_ref,
            "--name",
            "ref-cli-alt",
            "--version",
            "2.0.0",
        ],
    );
    assert_success(&out, "admit the alternative authority");

    // The alt court manifest: same fixture family, same observables, same
    // fixture — a different court id and a different authority.
    let manifest_alt = "frf/courts/cli-malformed-input-alt/manifest.yaml";
    let manifest_body = fs::read_to_string(work.path(MANIFEST)).unwrap();
    let manifest_alt_body = manifest_body
        .replace("id: cli-malformed-input", "id: cli-malformed-input-alt")
        .replace("authority: ref-cli-1.8.2", "authority: ref-cli-alt-2.0.0");
    fs::create_dir_all(work.path("frf/courts/cli-malformed-input-alt")).unwrap();
    fs::write(work.path(manifest_alt), manifest_alt_body).unwrap();

    // Court B's OWN movement on the same axis.
    let (key_b, _, _) = exit_ladder(&work, manifest_alt);
    assert_ne!(
        key_a.split('.').next().unwrap(),
        key_b.split('.').next().unwrap(),
        "the two authorities must produce distinct lineages"
    );

    // FALSIFICATION (P0): the unrelated same-axis trajectory B — perfectly
    // valid evidence about authority ref-cli-alt — must be REFUSED as a
    // movement premise of the ref-cli claim, even though its axis matches
    // and it is bound to a receipt the claim requires.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "claim",
            "compile",
            &receipt_a,
            "--trajectory",
            &format!("{key_b}@{receipt_a}"),
        ],
    );
    assert!(
        !out.status.success(),
        "the unrelated same-axis trajectory must be refused: {}",
        stdout(&out)
    );
    let err = stderr(&out);
    assert!(
        err.contains("not bound to its subject"),
        "the refusal must name the subject binding: {err}"
    );

    // A movement premise cannot anchor to a receipt the claim does not
    // require, even when the movement is the claim's own court's.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "claim",
            "compile",
            &receipt_a,
            "--trajectory",
            &format!("{key_a}@{}", "1".repeat(64)),
        ],
    );
    assert!(
        !out.status.success(),
        "a movement premise anchored to a non-premise receipt must be refused"
    );
    let err = stderr(&out);
    assert!(
        err.contains("not a premise of this claim"),
        "the refusal must name the missing premise: {err}"
    );
}

/// The trajectory-premise set is a SET with a CANONICAL order (P2): sorting
/// by the complete canonical key `(lineage, axis, coordinate_system, series,
/// trajectory, receipt, anchor_run)` means `--trajectory A --trajectory B`
/// and `--trajectory B --trajectory A` derive the SAME claim, and a
/// re-passed identical premise deduplicates — the movement clause is a pure
/// function of the sorted set.
#[test]
fn trajectory_premise_order_is_canonical_and_duplicates_collapse() {
    let work = Workdir::new("trajectory-canonical-order");
    work.copy_canonical_tree();
    admit_reference(&work);

    // A court with TWO clean-at-fix axes: the candidates diverge from the
    // reference on exit AND stdout at the original revision, and match on
    // both at the fixed revision — so the ladder observes TWO lineages
    // (exit, stdout), each a legitimate movement premise of the fixed-run
    // claim.
    fs::write(
        work.path("golden/candidate.sh"),
        "#!/bin/sh\nset -u\nfile=\"\"\nfor arg in \"$@\"; do\n  case \"$arg\" in\n    --strict) ;;\n    *) file=\"$arg\" ;;\n  esac\ndone\nif [ -z \"$file\" ]; then echo \"cand: no input file\" >&2; exit 2; fi\nline=0\nwhile IFS= read -r entry || [ -n \"$entry\" ]; do\n  line=$((line + 1))\n  case \"$entry\" in\n    '' | \\#*) continue ;;\n    server\\ * | listen\\ * | log\\ *) echo \"CAND-OK: $entry\" ;;\n    *)\n      word=${entry%% *}\n      echo \"error: unknown directive $word at line $line\" >&2\n      exit 1\n      ;;\n  esac\ndone <\"$file\"\nexit 0\n",
    )
    .unwrap();
    set_exec(&work.path("golden/candidate.sh"));
    fs::write(
        work.path("golden/work/candidate-fixed.sh"),
        "#!/bin/sh\nset -u\nfile=\"\"\nfor arg in \"$@\"; do\n  case \"$arg\" in\n    --strict) ;;\n    *) file=\"$arg\" ;;\n  esac\ndone\nif [ -z \"$file\" ]; then echo \"tool: no input file\" >&2; exit 2; fi\nline=0\nwhile IFS= read -r entry || [ -n \"$entry\" ]; do\n  line=$((line + 1))\n  case \"$entry\" in\n    '' | \\#*) continue ;;\n    server\\ * | listen\\ * | log\\ *) echo \"ok: $entry\" ;;\n    *)\n      word=${entry%% *}\n      echo \"tool: $file:$line: unknown directive '$word'\" >&2\n      exit 2\n      ;;\n  esac\ndone <\"$file\"\nexit 0\n",
    )
    .unwrap();
    set_exec(&work.path("golden/work/candidate-fixed.sh"));
    fs::create_dir_all(work.path("frf/courts/cli-two-axis")).unwrap();
    fs::write(
        work.path("frf/courts/cli-two-axis/manifest.yaml"),
        "court:\n  id: cli-two-axis\n  question: >-\n    For malformed input in fixture family malformed-input, does the candidate\n    preserve the admitted reference's exit class and stdout?\n  falsifier: >-\n    The candidate's exit class or stdout diverges from the admitted reference\n    on a fixture in family malformed-input.\n  authority: ref-cli-1.8.2\n  candidate:\n    name: cand-cli\n    version_or_commit: \"0.1.0\"\n    build_profile: debug\n    path: golden/candidate.sh\n  fixture:\n    id: malformed-path.conf\n    path: frf/courts/cli-malformed-input/fixtures/malformed-path.conf\n    arguments: [\"--strict\", \"{fixture}\"]\n  admissibility_envelope:\n    fixture_family: malformed-input\n    platforms: [\"x86_64-linux\"]\n    observables: [exit, stdout]\n    normalizers: []\n    replay_scope: single-run\n",
    )
    .unwrap();

    // The ladder: original (diverges on exit + stdout) then fixed (matches).
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "court",
            "run",
            "frf/courts/cli-two-axis/manifest.yaml",
            "--candidate-revisions",
            "golden/candidate.sh,golden/work/candidate-fixed.sh",
        ],
    );
    assert_success(&out, "two-axis ladder");
    let (_lineage, series, _stem, obs) = trajectory_for_axis(&work, "exit", None);
    let (_l2, s2, _st2, obs2) = trajectory_for_axis(&work, "stdout", None);
    assert_eq!(s2, series, "both lineages live in the same ladder series");
    let clean_run = obs[1].0.clone();
    let clean_run2 = obs2[1].0.clone();
    assert_eq!(
        clean_run, clean_run2,
        "both lineages cease at the same fixed point"
    );

    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &clean_run]);
    assert_success(&out, "receipt emit (fixed point)");
    let receipt = stdout(&out);

    // The two trajectory document keys, in BOTH CLI orders.
    let key_exit = {
        let (lineage, series, _stem, _o) = trajectory_for_axis(&work, "exit", None);
        format!("{lineage}.candidate_revision.{series}")
    };
    let key_stdout = {
        let (lineage, series, _stem, _o) = trajectory_for_axis(&work, "stdout", None);
        format!("{lineage}.candidate_revision.{series}")
    };
    let claim_id_of = |keys: &[&String]| {
        let mut args: Vec<String> = vec![
            "--root".into(),
            ROOT.into(),
            "claim".into(),
            "compile".into(),
            receipt.clone(),
        ];
        for k in keys {
            args.push("--trajectory".into());
            args.push(format!("{k}@{receipt}"));
        }
        let args: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let out = frf(&work, &args);
        assert_success(&out, "claim compile with trajectory premises");
        stdout(&out)
            .lines()
            .find(|l| l.starts_with("claim "))
            .expect("the compile prints the claim id")
            .trim_start_matches("claim ")
            .to_string()
    };

    // The SAME two premises in either CLI order derive the SAME claim.
    let id_ab = claim_id_of(&[&key_exit, &key_stdout]);
    let id_ba = claim_id_of(&[&key_stdout, &key_exit]);
    assert_eq!(id_ab, id_ba, "the premise ORDER must not change the claim");

    // A re-passed identical premise collapses: the same key twice is the
    // same claim as once (the premise set is a set).
    let id_dup = claim_id_of(&[&key_exit, &key_exit]);
    assert_eq!(
        id_dup,
        claim_id_of(&[&key_exit]),
        "identical premises deduplicate"
    );

    // The compiled claim's premises are in canonical sorted order.
    let claim: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("frf/claims/{id_ab}.json"))).unwrap(),
    )
    .unwrap();
    let premises = claim["trajectory_premises"].as_array().unwrap().clone();
    let mut sorted = premises.clone();
    sorted.sort_by_key(|p| {
        (
            p["lineage"].as_str().unwrap_or_default().to_string(),
            p["axis"].as_str().unwrap_or_default().to_string(),
            p["coordinate_system"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            p["series"].as_str().unwrap_or_default().to_string(),
            p["trajectory"].as_str().unwrap_or_default().to_string(),
            p["receipt"].as_str().unwrap_or_default().to_string(),
            p["anchor_run"].as_str().unwrap_or_default().to_string(),
        )
    });
    assert_eq!(
        premises, sorted,
        "the stored premises are canonically ordered"
    );
}
