//! OpenReceipt bundle tests: export a receipt's portable closure, verify it
//! against the bundle ALONE (no original source tree, no exporting
//! installation), and refuse tampered, incomplete, or unknown bundles.
//!
//! The bundle milestone's defining property:
//!
//! > If you possess the bundle, you do not need the original source tree or
//! > the original FRF installation to verify the evidence graph. Execution
//! > (replay) may still require an appropriate environment; verification
//! > does not.

mod common;
use common::*;

use std::fs;

fn copy_dir(src: &std::path::Path, dst: &std::path::Path) {
    fs::create_dir_all(dst).unwrap();
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if from.is_dir() {
            copy_dir(&from, &to);
        } else {
            fs::copy(&from, &to).unwrap();
        }
    }
}

/// Run the golden path to a claimable state and return (original run,
/// resolution run, final receipt id, original receipt id).
fn golden_to_claim(work: &Workdir) -> (String, String, String, String) {
    admit_reference(work);
    let run = run_court(work);
    let resolution_run = run_resolution_court(work);
    // Residual ids are content addresses: resolve them from the evidence.
    let exit_id = residual_id(work, &run, "exit");
    let text_id = residual_id(work, &run, "stderr");
    let res_text_id = residual_id(work, &resolution_run, "stderr");
    let out = frf(
        work,
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
            "candidate patched to preserve reference exit class",
        ],
    );
    assert_success(&out, "dispose exit fixed");
    for (id, reason) in [
        (
            text_id.clone(),
            "clearer diagnostic wording; documented divergence",
        ),
        (
            res_text_id.clone(),
            "clearer diagnostic wording; documented divergence (re-observed)",
        ),
    ] {
        let out = frf(
            work,
            &[
                "--root",
                ROOT,
                "residual",
                "dispose",
                &id,
                "--disposition",
                "intentional",
                "--reason",
                reason,
            ],
        );
        assert_success(&out, &format!("dispose {id} intentional"));
    }
    let out = frf(work, &["--root", ROOT, "receipt", "emit", &resolution_run]);
    assert_success(&out, "receipt emit (final)");
    let receipt_final = stdout(&out);
    let out = frf(work, &["--root", ROOT, "claim", "compile", &receipt_final]);
    assert_success(&out, "claim compile");
    // The original (failing) run's receipt, emitted after disposal: it binds
    // the fixed closure edge to the resolution run.
    let out = frf(work, &["--root", ROOT, "receipt", "emit", &run]);
    assert_success(&out, "receipt emit (original)");
    let receipt_original = stdout(&out);
    (run, resolution_run, receipt_final, receipt_original)
}

#[test]
fn bundle_round_trips_and_verifies_without_the_original_tree() {
    let work = Workdir::new("bundle-roundtrip");
    work.copy_canonical_tree();
    let (_run, resolution_run, receipt_final, _receipt_original) = golden_to_claim(&work);

    // Export the final receipt's bundle.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "bundle",
            "export",
            &receipt_final,
            "--output",
            "portable.frf",
        ],
    );
    assert_success(&out, "bundle export");

    // Verify from a DIFFERENT working directory with only a copy of the
    // bundle present: the bundle alone must authenticate the evidence graph.
    let foreign = Workdir::new("bundle-foreign");
    copy_dir(&work.path("portable.frf"), &foreign.path("portable.frf"));
    let out = frf(&foreign, &["bundle", "verify", "portable.frf"]);
    assert_success(&out, "bundle verify (foreign dir, no tree)");
    let out_text = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        out_text.contains("verified"),
        "verification output: {out_text}"
    );
    assert!(
        out_text.contains(&receipt_final),
        "names the receipt: {out_text}"
    );
    assert!(
        out_text.contains(&resolution_run),
        "names the run: {out_text}"
    );

    // The bundle is sealed evidence: exported files are read-only.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(foreign.path("portable.frf/receipts"))
            .unwrap()
            .permissions()
            .mode();
        // A directory: writable bits may be set for traversal; the FILE check
        // below is the evidence one.
        let _ = mode;
        let file_mode =
            fs::metadata(foreign.path(&format!("portable.frf/receipts/{receipt_final}.json")))
                .unwrap()
                .permissions()
                .mode();
        assert_eq!(
            file_mode & 0o222,
            0,
            "bundle files must be sealed (0{file_mode:o})"
        );
    }
}

#[test]
fn bundle_of_the_original_receipt_carries_the_resolution_run() {
    let work = Workdir::new("bundle-resolution");
    work.copy_canonical_tree();
    let (_run, resolution_run, _receipt_final, receipt_original) = golden_to_claim(&work);

    // The original failing receipt carries a `fixed` residual whose evidence
    // is the resolution run — the closure must include BOTH runs.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "bundle",
            "export",
            &receipt_original,
            "--output",
            "original.frf",
        ],
    );
    assert_success(&out, "bundle export (original)");

    let captures = fs::read_dir(work.path("original.frf/captures")).unwrap();
    let runs: Vec<String> = captures
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    assert_eq!(
        runs.len(),
        2,
        "closure must carry the original AND the resolution run: {runs:?}"
    );
    assert!(
        runs.iter()
            .any(|r| r.contains(resolution_run.trim_start_matches("run-cli-malformed-input-"))),
        "resolution run missing from the closure: {runs:?}"
    );

    let out = frf(&work, &["bundle", "verify", "original.frf"]);
    assert_success(&out, "bundle verify (original, with resolution edge)");
}

#[test]
fn bundle_verify_refuses_tampered_incomplete_and_unknown_bundles() {
    let work = Workdir::new("bundle-tamper");
    work.copy_canonical_tree();
    let (_run, resolution_run, receipt_final, _receipt_original) = golden_to_claim(&work);
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "bundle",
            "export",
            &receipt_final,
            "--output",
            "portable.frf",
        ],
    );
    assert_success(&out, "bundle export");

    // 1. Tampered side file: the manifest hash check refuses. (The final
    // receipt's bundle carries the RESOLUTION run — the run that observed the
    // passing candidate — not the original failing run.)
    let side = work.path(&format!(
        "portable.frf/captures/{resolution_run}/reference.stdout"
    ));
    // Sealing is not the security boundary — an attacker can chmod. The
    // manifest hash must catch the content change regardless.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&side, fs::Permissions::from_mode(0o644)).unwrap();
    }
    fs::write(&side, b"tampered").unwrap();
    let out = frf(&work, &["bundle", "verify", "portable.frf"]);
    assert!(!out.status.success(), "tampered bundle must be refused");
    assert!(
        stderr(&out).contains("corrupt"),
        "tamper refusal must name the corruption: {}",
        stderr(&out)
    );

    // 2. Missing object: the closure is incomplete.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "bundle",
            "export",
            &receipt_final,
            "--output",
            "second.frf",
        ],
    );
    assert_success(&out, "re-export");
    let objects = fs::read_dir(work.path("second.frf/objects/sha256")).unwrap();
    let first = objects
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_none())
        .unwrap();
    fs::remove_file(&first).unwrap();
    let out = frf(&work, &["bundle", "verify", "second.frf"]);
    assert!(!out.status.success(), "incomplete bundle must be refused");
    assert!(
        stderr(&out).contains("incomplete") || stderr(&out).contains("missing"),
        "incompleteness refusal: {}",
        stderr(&out)
    );

    // 3. Unknown manifest version: refused up front.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "bundle",
            "export",
            &receipt_final,
            "--output",
            "third.frf",
        ],
    );
    assert_success(&out, "re-export 2");
    let manifest_path = work.path("third.frf/manifest.json");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o644)).unwrap();
    }
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest["schema_version"] = serde_json::json!("frf-bundle-v9");
    fs::write(&manifest_path, serde_json::to_string(&manifest).unwrap()).unwrap();
    let out = frf(&work, &["bundle", "verify", "third.frf"]);
    assert!(
        !out.status.success(),
        "unknown manifest version must be refused"
    );
    assert!(
        stderr(&out).contains("unsupported bundle schema version"),
        "version refusal: {}",
        stderr(&out)
    );
}

#[test]
fn bundle_export_refuses_unverified_evidence() {
    let work = Workdir::new("bundle-unverified");
    work.copy_canonical_tree();
    admit_reference(&work);
    // No court run exists: the receipt id is fabricated, so there is nothing
    // to export.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "bundle",
            "export",
            "receipt-run-cli-malformed-input-0000",
            "--output",
            "nope.frf",
        ],
    );
    assert!(
        !out.status.success(),
        "exporting a fabricated receipt must fail"
    );
}

/// Export the final receipt as a single-file bundle and return the run it
/// observed.
fn export_single(work: &Workdir, receipt_final: &str, name: &str) {
    let out = frf(
        work,
        &[
            "--root",
            ROOT,
            "bundle",
            "export",
            receipt_final,
            "--output",
            name,
            "--single",
        ],
    );
    assert_success(&out, "single-file bundle export");
    // It is ONE file, not a directory, and a readable tar archive.
    assert!(work.path(name).is_file(), "single-file bundle is one file");
}

#[test]
fn single_file_bundle_exports_verifies_and_replays_anywhere() {
    let work = Workdir::new("bundle-single-roundtrip");
    work.copy_canonical_tree();
    let (_run, resolution_run, receipt_final, _receipt_original) = golden_to_claim(&work);
    export_single(&work, &receipt_final, "portable-single.frf");

    // From a foreign directory with ONLY the archive present — no evidence
    // tree, no exporting installation — the bundle must authenticate itself.
    // Verification never depends on where it runs. Replay from a foreign
    // directory is a SEMANTIC reproduction: the working directory is part of
    // the execution provenance (the sides ran under the observation cwd), so
    // exact policy demands the same cwd while semantic admits the difference
    // and reports it. Both run from the bundle alone.
    let foreign = Workdir::new("bundle-single-foreign");
    fs::copy(
        work.path("portable-single.frf"),
        foreign.path("portable-single.frf"),
    )
    .unwrap();
    let out = frf(&foreign, &["bundle", "verify", "portable-single.frf"]);
    assert_success(&out, "single-file bundle verify (foreign, no tree)");
    let out_text = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        out_text.contains("single-tar"),
        "names the container: {out_text}"
    );

    // Semantic replay from the foreign dir: the cwd drift is REPORTED, the
    // observation reproduces.
    let out = frf(
        &foreign,
        &[
            "bundle",
            "replay",
            "portable-single.frf",
            "--policy",
            "semantic",
        ],
    );
    assert_success(
        &out,
        "single-file bundle semantic replay (foreign, no tree)",
    );
    let out_text = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        out_text.contains("replay (semantic)") && out_text.contains("reproduced"),
        "the bundle alone must reproduce the observation: {out_text}"
    );
    assert!(
        out_text.contains("working directory changed"),
        "the foreign cwd drift must be reported: {out_text}"
    );
    assert!(
        out_text.contains(&resolution_run),
        "names the replayed run: {out_text}"
    );

    // Exact replay from the observation's own cwd (the original workdir):
    // same execution provenance, reproduced byte-for-byte — still from the
    // bundle alone, no tree required.
    let out = frf(
        &work,
        &[
            "bundle",
            "replay",
            "portable-single.frf",
            "--policy",
            "exact",
        ],
    );
    assert_success(&out, "single-file bundle exact replay (bundle alone)");
    let out_text = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        out_text.contains("replay (exact)") && out_text.contains("reproduced"),
        "exact replay from the bundle alone: {out_text}"
    );
}

#[test]
fn single_file_bundle_export_is_deterministic() {
    let work = Workdir::new("bundle-single-determinism");
    work.copy_canonical_tree();
    let (_run, _resolution_run, receipt_final, _receipt_original) = golden_to_claim(&work);
    export_single(&work, &receipt_final, "a.frf");
    export_single(&work, &receipt_final, "b.frf");
    let a = fs::read(work.path("a.frf")).unwrap();
    let b = fs::read(work.path("b.frf")).unwrap();
    assert_eq!(
        a, b,
        "two exports of the same receipt must be byte-identical (fixed metadata, sorted entries)"
    );
}

#[test]
fn single_file_bundle_replay_respects_the_reproduction_policy() {
    let work = Workdir::new("bundle-single-policy");
    work.copy_canonical_tree();
    let (_run, _resolution_run, receipt_final, _receipt_original) = golden_to_claim(&work);
    export_single(&work, &receipt_final, "portable-single.frf");

    // A declared provenance difference (a different capture cap in force)
    // refuses exact replay and is reported by semantic replay.
    let out = frf_env(
        &work,
        &[
            "bundle",
            "replay",
            "portable-single.frf",
            "--policy",
            "exact",
        ],
        &[("FRF_EXEC_MAX_BYTES", "2048")],
    );
    assert!(!out.status.success(), "exact replay must refuse on drift");
    assert!(
        stderr(&out).contains("replay (exact)")
            && stderr(&out).contains("capture bound max_stream_bytes changed"),
        "the refusal names the drifted dimension: {}",
        stderr(&out)
    );

    let out = frf_env(
        &work,
        &[
            "bundle",
            "replay",
            "portable-single.frf",
            "--policy",
            "semantic",
        ],
        &[("FRF_EXEC_MAX_BYTES", "2048")],
    );
    assert_success(&out, "semantic replay reproduces under admitted drift");
    let out_text = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        out_text.contains("replay (semantic): declared provenance difference"),
        "the drift is reported, never silent: {out_text}"
    );
    assert!(
        out_text.contains("reproduced"),
        "the observation reproduces anyway: {out_text}"
    );
}

#[test]
fn single_file_bundle_verify_refuses_tampering() {
    let work = Workdir::new("bundle-single-tamper");
    work.copy_canonical_tree();
    let (_run, resolution_run, receipt_final, _receipt_original) = golden_to_claim(&work);
    export_single(&work, &receipt_final, "portable-single.frf");

    // 1. A truncated archive is refused as unreadable.
    let full = fs::read(work.path("portable-single.frf")).unwrap();
    fs::write(work.path("truncated.frf"), &full[..1024]).unwrap();
    let out = frf(&work, &["bundle", "verify", "truncated.frf"]);
    assert!(!out.status.success(), "truncated archive must be refused");
    assert!(
        stderr(&out).contains("single-file bundle"),
        "truncation refusal: {}",
        stderr(&out)
    );

    // 2. A repacked archive with a tampered side file: the manifest hash
    //    check must catch the content change.
    let unpack = work.path("unpacked");
    fs::create_dir_all(&unpack).unwrap();
    {
        let file = fs::File::open(work.path("portable-single.frf")).unwrap();
        let mut archive = tar::Archive::new(file);
        archive.unpack(&unpack).unwrap();
    }
    let side = unpack.join(format!("captures/{resolution_run}/reference.stdout"));
    // Sealing is not the security boundary — an attacker can chmod. The
    // manifest hash must catch the content change regardless.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&side, fs::Permissions::from_mode(0o644)).unwrap();
    }
    fs::write(&side, b"tampered").unwrap();
    {
        let out = fs::File::create(work.path("tampered.frf")).unwrap();
        let mut builder = tar::Builder::new(out);
        fn walk(
            dir: &std::path::Path,
            prefix: &std::path::Path,
            builder: &mut tar::Builder<fs::File>,
        ) -> std::io::Result<()> {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let from = entry.path();
                let rel = prefix.join(entry.file_name());
                if from.is_dir() {
                    walk(&from, &rel, builder)?;
                } else {
                    let mut header = tar::Header::new_gnu();
                    let bytes = fs::read(&from)?;
                    header.set_size(bytes.len() as u64);
                    header.set_mode(0o444);
                    builder.append_data(&mut header, &rel, &bytes[..])?;
                }
            }
            Ok(())
        }
        walk(&unpack, std::path::Path::new(""), &mut builder).unwrap();
        builder.finish().unwrap();
    }
    let out = frf(&work, &["bundle", "verify", "tampered.frf"]);
    assert!(
        !out.status.success(),
        "tampered single-file bundle must be refused"
    );
    assert!(
        stderr(&out).contains("corrupt"),
        "the tamper refusal must name the corruption: {}",
        stderr(&out)
    );

    // 3. A directory whose manifest claims to be a single-tar is refused:
    //    the manifest declares its own container, and a mismatch is a lie.
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "bundle",
            "export",
            &receipt_final,
            "--output",
            "dir.frf",
        ],
    );
    assert_success(&out, "directory export");
    let manifest_path = work.path("dir.frf/manifest.json");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o644)).unwrap();
    }
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest["container"] = serde_json::json!("single-tar");
    fs::write(&manifest_path, serde_json::to_string(&manifest).unwrap()).unwrap();
    let out = frf(&work, &["bundle", "verify", "dir.frf"]);
    assert!(!out.status.success(), "container mismatch must be refused");
    assert!(
        stderr(&out).contains("container mismatch"),
        "mismatch refusal: {}",
        stderr(&out)
    );
}

#[test]
fn directory_bundle_replays_away_from_the_tree() {
    let work = Workdir::new("bundle-dir-replay");
    work.copy_canonical_tree();
    let (_run, _resolution_run, receipt_final, _receipt_original) = golden_to_claim(&work);
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "bundle",
            "export",
            &receipt_final,
            "--output",
            "portable.frf",
        ],
    );
    assert_success(&out, "directory export");

    // The directory bundle replays from a foreign dir too — verification
    // and semantic replay need no tree and no original cwd (the cwd drift is
    // admitted and reported), and the sealed bundle itself is never mutated
    // by the replay (materialization happens in a temp copy).
    let foreign = Workdir::new("bundle-dir-replay-foreign");
    copy_dir(&work.path("portable.frf"), &foreign.path("portable.frf"));
    let out = frf(
        &foreign,
        &["bundle", "replay", "portable.frf", "--policy", "semantic"],
    );
    assert_success(&out, "directory bundle semantic replay (foreign, no tree)");
    let out_text = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        out_text.contains("reproduced"),
        "the directory bundle alone must reproduce: {out_text}"
    );
    assert!(
        out_text.contains("working directory changed"),
        "the foreign cwd drift must be reported: {out_text}"
    );

    // Exact replay from the observation's own cwd.
    let out = frf(
        &work,
        &["bundle", "replay", "portable.frf", "--policy", "exact"],
    );
    assert_success(&out, "directory bundle exact replay (bundle alone)");
    let out_text = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        out_text.contains("replay (exact)") && out_text.contains("reproduced"),
        "exact replay from the directory bundle alone: {out_text}"
    );
}
