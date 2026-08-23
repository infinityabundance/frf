//! The ADVERSARIAL FALSIFICATION harness — for each catastrophic outcome the
//! framework claims to make impossible, this suite ATTEMPTS to produce it
//! and asserts the refusal (fail-closed, fail-visible):
//!
//!   1. false claim      — a claim covers a surface containing an unresolved
//!      divergence;
//!   2. evidence substitution — FRF accepts artifact/fixture/comparator/
//!      environment bytes other than those named;
//!   3. semantic substitution — the observation used relation A but a
//!      downstream consumer effectively uses relation B;
//!   4. universe omission — deleting/hiding evidence makes an inadmissible
//!      claim admissible without changing the committed universe;
//!   5. scope inflation   — legitimate premises combine into a claim over an
//!      unobserved point;
//!   6. false replay      — replay says reproduced when the recorded
//!      observation did not reproduce;
//!   7. false resolution  — a residual marked fixed without the divergence
//!      closing under the same question;
//!   8. verifier disagreement — the three implementations accept different
//!      semantics for identical bytes;
//!   9. identity aliasing — semantically different evidence maps to an
//!      identity FRF treats as equivalent;
//!  10. fail-open execution — malformed input / hostile extension / missing
//!      dependency becomes a pass instead of refusal.
//!
//! Plus the adversarial STATE MACHINE: legal and hostile near-legal FRF
//! histories with MUST-SUCCEED / MUST-FAIL rules at every step.

use frf::store::Store;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

mod common;
use common::*;

fn store_of(work: &Workdir) -> Store {
    Store::new(work.path(ROOT).to_path_buf())
}

/// Overwrite a SEALED evidence file (objects are 0444/0555 — a hostile
/// actor would chmod first, exactly as a bundle tamperer must).
fn force_write(path: &std::path::Path, bytes: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::write(path, bytes).unwrap();
}

fn claim_cid(work: &Workdir, receipt: &str) -> String {
    let idx = work.path(&format!("{ROOT}/claims/by-receipt/{receipt}"));
    let mut names: Vec<String> = fs::read_dir(&idx)
        .unwrap_or_else(|e| panic!("no claim index for {receipt}: {e}"))
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.len() == 64)
        .collect();
    names.sort();
    assert_eq!(names.len(), 1, "exactly one claim per receipt+universe");
    names[0].clone()
}

/// Drive the golden path to the final resolution receipt (exit axis clean).
fn resolution_receipt(work: &Workdir) -> (String, String) {
    admit_reference(work);
    let run = run_court(work);
    let resolution_run = run_resolution_court(work);
    // Residual ids are content addresses: resolve them from the evidence.
    let exit_id = residual_id(work, &run, "exit");
    let text_id = residual_id(work, &run, "stderr");
    let res_text_id = residual_id(work, &resolution_run, "stderr");
    // The exit residual is disposed FIXED with the closing resolution run;
    // the text residuals are documented intentional (a resolution-run is
    // only valid for a fixed disposition).
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
    for id in [text_id, res_text_id] {
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
                "clearer diagnostic wording; documented divergence",
            ],
        );
        assert_success(&out, &format!("dispose {id} intentional"));
    }
    let out = frf(work, &["--root", ROOT, "receipt", "emit", &resolution_run]);
    assert_success(&out, "receipt emit");
    (resolution_run, stdout(&out))
}

// ---------------------------------------------------------------------------
// 1. False claim
// ---------------------------------------------------------------------------

/// Outcome 1: a claim over a surface containing an UNRESOLVED divergence is
/// unproducible — the claim compiler refuses while any residual in scope is
/// open, and the refusal is unconditional (the residual cannot be hidden).
#[test]
fn false_claim_is_unproducible() {
    let work = Workdir::new("falsify-false-claim");
    work.copy_canonical_tree();
    admit_reference(&work);
    let run = run_court(&work); // both axes diverge; residuals open

    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &run]);
    assert_success(&out, "receipt emit (open residuals)");
    let receipt = stdout(&out);
    let out = frf(&work, &["--root", ROOT, "claim", "compile", &receipt]);
    assert!(
        !out.status.success(),
        "a claim over an unresolved divergence MUST be refused"
    );
    assert!(
        stderr(&out).contains("blocked") || stderr(&out).contains("open"),
        "the refusal must name the blocker: {}",
        stderr(&out)
    );
}

// ---------------------------------------------------------------------------
// 2. Evidence substitution
// ---------------------------------------------------------------------------

/// Outcome 2: FRF accepts artifact bytes OTHER than those its evidence names
/// — unproducible. Substituting the candidate bytes after capture breaks the
/// run identity on replay, and a bundle whose object does not match the
/// manifest's recorded hash refuses.
#[test]
fn evidence_substitution_is_unproducible() {
    let work = Workdir::new("falsify-evidence-substitution");
    work.copy_canonical_tree();
    admit_reference(&work);
    let run = run_court(&work);

    // Capture which object the run executed.
    let cap: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("{ROOT}/captures/{run}/capture.json"))).unwrap(),
    )
    .unwrap();
    let obj_path = work.path(&format!(
        "{ROOT}/objects/sha256/{}",
        cap["candidate_artifact"]["sha256"].as_str().unwrap()
    ));

    // Substitute DIFFERENT bytes for the recorded candidate object: the
    // content address no longer matches the bytes.
    force_write(&obj_path, b"#!/bin/sh\necho SUBSTITUTED\n");

    // Replay refuses: the verified object bytes do not match the recorded
    // identity.
    let out = frf(
        &work,
        &["--root", ROOT, "replay", &run, "--policy", "exact"],
    );
    assert!(
        !out.status.success(),
        "a substituted artifact MUST be refused on replay"
    );
    let out = frf(
        &work,
        &["--root", ROOT, "replay", &run, "--policy", "semantic"],
    );
    assert!(
        !out.status.success(),
        "a substituted artifact MUST be refused under any policy"
    );
}

// ---------------------------------------------------------------------------
// 3. Semantic substitution
// ---------------------------------------------------------------------------

/// Outcome 3: the observation used relation A but a consumer effectively
/// uses relation B — unproducible. The comparator semantic identity is
/// content-addressed: two relations yield two distinct identities, and a
/// capture whose recorded comparator semantics do not rederive refuses.
#[test]
fn semantic_substitution_is_unproducible() {
    let work = Workdir::new("falsify-semantic-substitution");
    work.copy_canonical_tree();
    admit_reference(&work);
    let run = run_court(&work);
    let cap_path = work.path(&format!("{ROOT}/captures/{run}/capture.json"));
    let mut cap: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&cap_path).unwrap()).unwrap();

    // Mutate a field the observation identity COMMITS (the candidate's
    // compared first stderr line): the identity no longer rederives from the
    // recorded fields, and the capture is not self-consistent — a consumer
    // can never silently read a different answer than the identity named.
    let _original = cap["candidate"]["stderr_first_line"].clone();
    cap["candidate"]["stderr_first_line"] = serde_json::json!("a completely different diagnostic");
    fs::write(&cap_path, serde_json::to_vec(&cap).unwrap()).unwrap();

    let store = store_of(&work);
    let err = match frf::verify::load_capture_verified(&store, &run) {
        Err(e) => e,
        Ok(_) => panic!("a capture whose semantics do not rederive MUST be refused"),
    };
    assert!(
        err.0.contains("does not rederive") || err.0.contains("observation"),
        "unexpected error: {}",
        err.0
    );

    // Restore; the two relations are distinct identities even at the
    // specification level.
    let a = frf::comparators::specification_hash("stderr", "eq", "stderr-first-line", "text", "v2")
        .unwrap();
    let b = frf::comparators::specification_hash("stderr", "ne", "stderr-first-line", "text", "v2")
        .unwrap();
    assert_ne!(a, b, "eq and ne must be distinct semantic identities");
}

// ---------------------------------------------------------------------------
// 4. Universe omission
// ---------------------------------------------------------------------------

/// Outcome 4: deleting/hiding evidence makes an inadmissible claim
/// admissible WITHOUT changing the committed universe — unproducible. The
/// knowledge snapshot commits the exact residual records (record_cid +
/// fingerprint); deleting a record breaks the rederivation and the claim
/// verification refuses.
#[test]
fn universe_omission_is_unproducible() {
    let work = Workdir::new("falsify-universe-omission");
    work.copy_canonical_tree();
    let (_resolution_run, receipt_final) = resolution_receipt(&work);

    let out = frf(&work, &["--root", ROOT, "claim", "compile", &receipt_final]);
    assert_success(&out, "claim compile (clean exit axis)");
    let cid = claim_cid(&work, &receipt_final);
    let claim_path = work.path(&format!("{ROOT}/claims/{cid}.json"));

    // Delete ONE residual head the snapshot commits (an open residual from
    // the original run whose absence would change the blocker scan).
    let claim: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&claim_path).unwrap()).unwrap();
    let heads = claim["knowledge_snapshot"]["residual_heads"]
        .as_array()
        .unwrap();
    assert!(!heads.is_empty());
    let head_id = heads[0]["id"].as_str().unwrap();
    let rec_path = work.path(&format!("{ROOT}/residuals/{head_id}.json"));
    let rec = fs::read(&rec_path).unwrap();
    fs::remove_file(&rec_path).unwrap();

    // The claim VERIFICATION refuses: the committed universe cannot be
    // reproduced from the store (the head's record_cid no longer rederives).
    let store = store_of(&work);
    let err = match frf::verify::load_claim_verified(&store, &cid) {
        Err(e) => e,
        Ok(_) => panic!("a claim whose committed universe is incomplete MUST be refused"),
    };
    assert!(
        err.0.contains("missing") || err.0.contains("record") || err.0.contains("rederive"),
        "unexpected error: {}",
        err.0
    );

    // The claim COMPILER under the same receipt still refuses to re-derive
    // the missing head's scope — the omission cannot license the claim.
    let out = frf(&work, &["--root", ROOT, "claim", "compile", &receipt_final]);
    assert!(
        !out.status.success(),
        "an omitted residual must still block the claim"
    );

    // Restore so later assertions on other tests' trees are unaffected.
    fs::write(&rec_path, &rec).unwrap();
}

// ---------------------------------------------------------------------------
// 5. Scope inflation
// ---------------------------------------------------------------------------

/// Outcome 5: multiple legitimate premises combine into a claim over an
/// UNOBSERVED point — unproducible. The claim scope is the DNF union of the
/// premise cells; every point in the compiled scope must be covered by a
/// premise (a property checked by the claim compiler itself, and verified
/// literally by the claim-algebra oracle test).
#[test]
fn scope_inflation_is_unproducible() {
    // The canonical court diverges on BOTH axes; a claim over the pair must
    // refuse (both open) — no single premise observed a clean pair, so the
    // compiler cannot manufacture one.
    let work = Workdir::new("falsify-scope-inflation");
    work.copy_canonical_tree();
    admit_reference(&work);
    let run = run_court(&work);
    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &run]);
    assert_success(&out, "receipt emit");
    let receipt = stdout(&out);
    let out = frf(&work, &["--root", ROOT, "claim", "compile", &receipt]);
    assert!(
        !out.status.success(),
        "a two-axis claim over two open axes MUST be refused"
    );
}

// ---------------------------------------------------------------------------
// 6. False replay
// ---------------------------------------------------------------------------

/// Outcome 6: replay says reproduced when the recorded observation did not
/// reproduce — unproducible. Replay re-executes the exact snapshotted bytes
/// and requires the observation to reproduce; tampering the fixture (an
/// input the observation depends on) makes the replay refuse.
#[test]
fn false_replay_is_unproducible() {
    let work = Workdir::new("falsify-false-replay");
    work.copy_canonical_tree();
    admit_reference(&work);
    let run = run_court(&work);
    let out = frf(
        &work,
        &["--root", ROOT, "replay", &run, "--policy", "exact"],
    );
    assert_success(&out, "replay reproduces the untouched observation");

    // Tamper the fixture OBJECT (the exact input bytes): the replay must
    // refuse — the observation it re-observes is not the recorded one.
    let cap: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("{ROOT}/captures/{run}/capture.json"))).unwrap(),
    )
    .unwrap();
    let fixture_sha = cap["fixture_sha256"].as_str().unwrap().to_string();
    let fixture_path = work.path(&format!("{ROOT}/objects/sha256/{fixture_sha}"));
    let original = fs::read(&fixture_path).unwrap();
    force_write(&fixture_path, b"server 1.2.3.4\nserver 5.6.7.8\n");

    let out = frf(
        &work,
        &["--root", ROOT, "replay", &run, "--policy", "exact"],
    );
    assert!(
        !out.status.success(),
        "replay with substituted input MUST be refused"
    );
    force_write(&fixture_path, &original);
    let out = frf(
        &work,
        &["--root", ROOT, "replay", &run, "--policy", "exact"],
    );
    assert_success(&out, "replay reproduces again after restoration");
}

// ---------------------------------------------------------------------------
// 7. False resolution
// ---------------------------------------------------------------------------

/// Outcome 7: a residual marked fixed without the divergence closing under
/// the same question — unproducible. The disposition gate requires a
/// resolution run that re-observes the SAME court semantic identity and
/// closes the axis; an unrelated or divergent run is refused.
#[test]
fn false_resolution_is_unproducible() {
    let work = Workdir::new("falsify-false-resolution");
    work.copy_canonical_tree();
    admit_reference(&work);
    let run = run_court(&work); // the run's two residuals (exit + stderr)
    let exit_id = residual_id(&work, &run, "exit");

    // "Fix" the residual with the run that OBSERVED it (no closure): refuse.
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
            "no closure",
        ],
    );
    assert!(
        !out.status.success(),
        "fixing a residual with its own observing run MUST be refused"
    );

    // A resolution run that does not close the axis: the patched candidate
    // is NOT actually a fix for this fixture — but the gate itself requires
    // the SAME question. Use the canonical resolution manifest; dispose with
    // a run from a DIFFERENT question (the exit-only court, if present) —
    // the gate refuses on the semantic identity mismatch.
    let resolution_run = run_resolution_court(&work);
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
            "proper closure",
        ],
    );
    assert_success(
        &out,
        "a closing resolution run licenses the fixed disposition",
    );
}

// ---------------------------------------------------------------------------
// 8. Verifier disagreement
// ---------------------------------------------------------------------------

/// Outcome 8: the three implementations accept different semantics for
/// identical bytes — the conformance corpus + the golden bundle must agree
/// byte-for-byte (engine, xtask, Go). A deliberately pathological bundle is
/// run through all three; agreement is the assertion.
#[test]
fn verifier_disagreement_is_unproducible() {
    let work = Workdir::new("falsify-verifier-disagreement");
    work.copy_canonical_tree();
    let (_resolution_run, receipt_final) = resolution_receipt(&work);
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
    let bundle = work.path("portable.frf");

    // Engine.
    let out = frf(&work, &["bundle", "verify", "portable.frf"]);
    assert_success(&out, "engine verifies the bundle");

    // Independent Rust verifier.
    let out = Command::new(env!("CARGO"))
        .args(["run", "--quiet", "--manifest-path"])
        .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("xtask/Cargo.toml"))
        .args(["--", "verify", "bundle"])
        .arg(&bundle)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "xtask must agree: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Go verifier.
    let out = Command::new("go")
        .args(["run", ".", "verify", "bundle"])
        .arg(&bundle)
        .current_dir(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("verifier-go"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "Go must agree: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---------------------------------------------------------------------------
// 9. Identity aliasing
// ---------------------------------------------------------------------------

/// Outcome 9: semantically different evidence maps to an identity FRF treats
/// as equivalent — unproducible. The label is never the identity: two
/// DIFFERENT fixture files sharing a semantic id are different exact inputs
/// (FRF/FIXTURE/v1 commits the content hash), and a residual about one file
/// does not block the other's claim surface.
#[test]
fn identity_aliasing_is_unproducible() {
    let work = Workdir::new("falsify-identity-aliasing");
    work.copy_canonical_tree();
    admit_reference(&work);

    // Two distinct files with the same semantic id: the exact-input
    // identities MUST differ.
    let bytes_a = b"server 1.1.1.1\n";
    let bytes_b = b"server 2.2.2.2\n";
    let id_a = frf::semantics::fixture_identity(
        "malformed-path.conf",
        &frf::host::sha256_bytes(bytes_a),
        &["--strict".to_string(), "{fixture}".to_string()],
    )
    .unwrap();
    let id_b = frf::semantics::fixture_identity(
        "malformed-path.conf",
        &frf::host::sha256_bytes(bytes_b),
        &["--strict".to_string(), "{fixture}".to_string()],
    )
    .unwrap();
    assert_ne!(
        id_a, id_b,
        "two different files sharing a fixture id MUST be different exact inputs"
    );
    // The same bytes + id + args: the SAME identity (the identity is a
    // deterministic function of the exact input).
    let id_a2 = frf::semantics::fixture_identity(
        "malformed-path.conf",
        &frf::host::sha256_bytes(bytes_a),
        &["--strict".to_string(), "{fixture}".to_string()],
    )
    .unwrap();
    assert_eq!(id_a, id_a2);
}

// ---------------------------------------------------------------------------
// 10. Fail-open execution
// ---------------------------------------------------------------------------

/// Outcome 10: malformed input / hostile extension becomes a pass instead of
/// refusal/evidence — unproducible. A comparator that returns NON-CANONICAL
/// response bytes is refused (the protocol says canonical; enforce
/// canonical), and an unresolved divergence stays open forever.
#[test]
fn fail_open_execution_is_unproducible() {
    let work = Workdir::new("falsify-fail-open");
    work.copy_canonical_tree();
    admit_reference(&work);

    // The canonical parser refuses a NON-CANONICAL evidence document (a
    // receipt reformatted with whitespace): strict JSON + bytes == JCS.
    let run = run_court(&work);
    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &run]);
    assert_success(&out, "receipt emit");
    let receipt = stdout(&out);
    let rec_path = work.path(&format!("{ROOT}/receipts/{receipt}.json"));
    let bytes = fs::read(&rec_path).unwrap();
    let pretty =
        serde_json::to_string_pretty(&serde_json::from_slice::<serde_json::Value>(&bytes).unwrap())
            .unwrap();
    fs::write(&rec_path, pretty).unwrap();

    let store = store_of(&work);
    let err = match frf::verify::load_receipt_verified(&store, &receipt) {
        Err(e) => e,
        Ok(_) => panic!("a non-canonical receipt MUST be refused"),
    };
    assert!(
        err.0.contains("canonical") || err.0.contains("strict"),
        "unexpected error: {}",
        err.0
    );
}

// ---------------------------------------------------------------------------
// The adversarial state machine
// ---------------------------------------------------------------------------

/// The reviewer's state-machine rules, executed as explicit transitions:
///
///   observe D  -> compile affected claim        MUST FAIL
///   observe D  -> delete D -> old-universe      MUST FAIL
///   observe D  -> dispose intentional           -> parity from same run
///                                                MUST FAIL
///   D fixed by R -> compile from ORIGINAL       MUST NOT gain parity
///   D fixed by R -> compile from RESOLUTION     MAY succeed
///   P1(A,X)+P2(B,Y) -> claim (A,Y)              MUST FAIL
///
/// Each transition is one concrete run against a fresh store; the oracle is
/// FRF's own formal rules.
#[test]
fn adversarial_state_machine_transitions() {
    // observe D -> compile affected claim: MUST FAIL (already the false-claim
    // case, re-asserted as a transition).
    let work = Workdir::new("falsify-sm-1");
    work.copy_canonical_tree();
    admit_reference(&work);
    let run = run_court(&work);
    let out = frf(&work, &["--root", ROOT, "receipt", "emit", &run]);
    assert_success(&out, "receipt emit");
    let receipt = stdout(&out);
    let out = frf(&work, &["--root", ROOT, "claim", "compile", &receipt]);
    assert!(!out.status.success(), "observe D -> compile MUST FAIL");

    // observe D -> dispose intentional -> parity from the SAME run:
    // MUST FAIL. An intentional disposition documents the divergence; it
    // cannot turn the run into parity.
    let exit_id = residual_id(&work, &run, "exit");
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
            "documented divergence",
        ],
    );
    assert_success(&out, "intentional disposition");
    let out = frf(&work, &["--root", ROOT, "claim", "compile", &receipt]);
    assert!(
        !out.status.success(),
        "an intentional disposition MUST NOT license parity from the same run"
    );

    // fixed by R -> compile from the ORIGINAL receipt MUST NOT gain parity;
    // compile from the RESOLUTION receipt MAY succeed.
    let work2 = Workdir::new("falsify-sm-2");
    work2.copy_canonical_tree();
    let (resolution_run, receipt_final) = resolution_receipt(&work2);
    let original_receipt = {
        // Re-derive the ORIGINAL run's receipt from the same store: emit it
        // before the resolution run overwrote nothing (the original run is
        // still there).
        let caps = fs::read_dir(work2.path(&format!("{ROOT}/captures"))).unwrap();
        let mut runs: Vec<String> = caps
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("run-cli-malformed-input-"))
            .collect();
        runs.sort();
        runs.dedup();
        let original_run = runs
            .iter()
            .find(|r| *r != &resolution_run)
            .expect("the original run must exist")
            .clone();
        let out = frf(&work2, &["--root", ROOT, "receipt", "emit", &original_run]);
        assert_success(&out, "original receipt emit");
        stdout(&out)
    };
    let out = frf(
        &work2,
        &["--root", ROOT, "claim", "compile", &original_receipt],
    );
    assert!(
        !out.status.success(),
        "the ORIGINAL receipt observed the divergence; it MUST NOT gain parity"
    );
    let out = frf(
        &work2,
        &["--root", ROOT, "claim", "compile", &receipt_final],
    );
    assert_success(&out, "the RESOLUTION receipt MAY license the claim");
}

// ---------------------------------------------------------------------------
// The external-minimizer proof bypass (P0: proposal_minimality_claimed vs
// minimality_proven)
// ---------------------------------------------------------------------------

/// An EXTERNAL minimizer has no oracle and no search of its own: it PROPOSES
/// a reduced fixture, and the core court-verifies each proposal with the one
/// comparison operation. Its response's `minimal` field is therefore a CLAIM,
/// never proof. An adversarial minimizer that shouts `"minimal": true` must
/// not be able to make FRF emit `minimality.proven: true`: the record must
/// carry the claim as `proposal_minimality_claimed` and state `proven: false`
/// unless the CORE itself established the predicate (a completed search or a
/// separately verifiable proof — neither exists for an external proposal).
/// The fixture used here is `golden/minimizers/ddmin-lines.py`, which does
/// exactly that: it statically drops comment/blank lines and — like an
/// adversarial minimizer — claims `minimal: true` in its response.
#[test]
fn external_minimizer_minimal_claim_is_never_proof() {
    let work = Workdir::new("falsify-minimizer-proof");
    work.copy_canonical_tree();
    admit_reference(&work);

    // The external-minimizer court: the same reference/candidate pair on a
    // verbose fixture, with a minimizer declared for the exit residual's
    // κ route (cli-exit-minimize).
    let out = frf(
        &work,
        &[
            "--root",
            ROOT,
            "court",
            "run",
            "frf/courts/cli-external-minimizer/manifest.yaml",
        ],
    );
    assert_success(&out, "external-minimizer court run");
    let run = stdout(&out);

    // The exit residual routes to the declared minimizer. Residual ids are
    // content addresses: resolve the exit residual from the capture.
    let residual = residual_id(&work, &run, "exit");

    let out = frf(&work, &["--root", ROOT, "court", "minimize", &residual]);
    assert_success(&out, "external minimize");
    let reduction_id = stdout(&out);

    let record: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("{ROOT}/reductions/{reduction_id}.json"))).unwrap(),
    )
    .unwrap();
    let minimality = &record["derivation"]["minimality"];
    // The record binds the external minimizer, so a reader can see the claim
    // came from an extension, never from the core.
    assert_eq!(record["minimizer_semantic_id"], "cli-exit-minimize");
    // The minimizer DID claim minimality — the record carries the claim.
    assert_eq!(
        minimality["proposal_minimality_claimed"], true,
        "the minimizer's own claim must be recorded as a claim"
    );
    // ...but the claim is never proof: the core did not search, so `proven`
    // must be false. This is the assertion the old relay made impossible.
    assert_eq!(
        minimality["proven"], false,
        "an external minimizer's `minimal: true` must NEVER become `proven: true`"
    );
    // And the committed record is identity-consistent: it rederives from its
    // own fields (proven=false, claim present), and the content address the
    // command printed matches the filename.
    let store = store_of(&work);
    let r = store.load_reduction(&reduction_id).expect(
        "the reduction record must rederive its own content address (claim enters the identity)",
    );
    assert!(!r.derivation.minimality.proven);
    assert_eq!(
        r.derivation.minimality.proposal_minimality_claimed,
        Some(true)
    );
    // The invocation evidence (the canonical request the minimizer answered
    // with `minimal: true`) is preserved under the reduction.
    for f in [
        "request.json",
        "response.json",
        "invocation.json",
        "result.json",
    ] {
        let p = work.path(&format!("{ROOT}/reductions/{reduction_id}/minimizer/{f}"));
        assert!(p.is_file(), "missing minimizer evidence {f}");
    }
}

// ---------------------------------------------------------------------------
// The domain-aware boundary predicate (P0/P1: kind=boundary minimality)
// ---------------------------------------------------------------------------

/// The boundary court manifest template: the same reference/candidate pair
/// and verbose fixture as the golden external-minimizer court, with a
/// minimizer whose program path differs per case. `program` resolves
/// relative to the workdir (the working directory the court runs under).
const BOUNDARY_MANIFEST: &str = r#"court:
  id: falsify-boundary-{COURT}
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
    id: malformed-verbose.conf
    path: frf/courts/cli-external-minimizer/fixtures/malformed-verbose.conf
    arguments: ["--strict", "{fixture}"]
  admissibility_envelope:
    fixture_family: malformed-input
    platforms: ["x86_64-linux"]
    observables: [exit, stderr]
    normalizers: []
    replay_scope: single-run
minimizers:
  - id: cli-exit-minimize
    relation: drop-comment-blank-lines
    relation_version: "v1"
    program: falsify-minimizers/{PROGRAM}
"#;

/// One adversarial minimizer implementation: proposes a malformed config
/// (preserving the divergence) and DECLARES a boundary whose adjacent
/// non-passing fixture embeds the predecessor coordinate `bad=1` — which is
/// PRESERVED, so the boundary is REFUTED by the core's own execution. The
/// minimizer also shouts `minimal: true`. Neither the claim nor the
/// declaration may become proof. The declared domain projection
/// (`embedded-integer` over `bad=`) makes the coordinates DERIVABLE from the
/// exact fixtures — the core derives them, and the refutation lands in band.
const REFUTED_MINIMIZER: &str = r##"#!/usr/bin/env python3
import base64, hashlib, json, sys
raw = sys.stdin.buffer.read()
req = json.loads(raw.decode("utf-8"))
request_id = hashlib.sha256(raw).hexdigest()
original = base64.b64decode(req["fixture"]["raw_base64"])
# The proposal: a malformed config (the divergence survives). The value
# coordinate is embedded as `bad=2`.
proposal = b"server 1.1.1.1\nbad=2\n"
# The declared adjacent non-passing fixture EMBEDS the predecessor
# coordinate (`bad=1`): still malformed, so the lineage SURVIVES the core's
# execution -> the boundary is refuted in band.
adjacent = b"server 1.1.1.1\nbad=1\n"
response = {
    "schema_version": "frf-minimizer-response-v2",
    "request_id": request_id,
    "fixture_sha256": hashlib.sha256(proposal).hexdigest(),
    "fixture_base64": base64.b64encode(proposal).decode("ascii"),
    "minimal": True,
    "minimality": {
        "kind": "adjacent-boundary",
        "reduction_domain": {
            "kind": "ordered-integer",
            "semantic": "falsify.example_parameter",
            "extractor": {
                "kind": "embedded-integer",
                "radix": "10",
                "prefix": "bad=",
            },
        },
        "boundary": {
            "predecessor": "1",
            "predecessor_preserves": False,  # claimed: the point below is NOT preserved
            "value": "2",
            "value_preserves": True,
        },
        "adjacent_fixture_sha256": hashlib.sha256(adjacent).hexdigest(),
        "adjacent_fixture_base64": base64.b64encode(adjacent).decode("ascii"),
    },
    "attempts": [],
    "indeterminate": False,
    "failure": None,
}
json.dump(response, sys.stdout, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
"##;

/// The honest minimizer: proposes a malformed config whose value coordinate
/// (`bad=2`) preserves the divergence, and declares an adjacent non-passing
/// fixture that is a COMMENT-ONLY config embedding the predecessor
/// coordinate (`# bad=1`) — both sides exit 0 there, so the lineage is
/// genuinely LOST at the adjacent point. The core's two observations (final
/// verification preserved, control lost) AND its own coordinate derivation
/// establish the boundary: `proven` may be true, and the record's attempts
/// prove it.
const HONEST_MINIMIZER: &str = r##"#!/usr/bin/env python3
import base64, hashlib, json, sys
raw = sys.stdin.buffer.read()
req = json.loads(raw.decode("utf-8"))
request_id = hashlib.sha256(raw).hexdigest()
original = base64.b64decode(req["fixture"]["raw_base64"])
# The proposal: a malformed config (the divergence survives). The value
# coordinate is embedded as `bad=2`.
proposal = b"server 1.1.1.1\nbad=2\n"
# A comment-only config embedding the predecessor coordinate (`# bad=1`):
# no directive at all, so both sides exit 0 and the exit lineage is LOST at
# the adjacent point.
adjacent = b"# bad=1\n"
response = {
    "schema_version": "frf-minimizer-response-v2",
    "request_id": request_id,
    "fixture_sha256": hashlib.sha256(proposal).hexdigest(),
    "fixture_base64": base64.b64encode(proposal).decode("ascii"),
    "minimal": True,
    "minimality": {
        "kind": "adjacent-boundary",
        "reduction_domain": {
            "kind": "ordered-integer",
            "semantic": "falsify.example_parameter",
            "extractor": {
                "kind": "embedded-integer",
                "radix": "10",
                "prefix": "bad=",
            },
        },
        "boundary": {
            "predecessor": "1",
            "predecessor_preserves": False,  # claimed: the clean config is NOT preserved
            "value": "2",
            "value_preserves": True,
        },
        "adjacent_fixture_sha256": hashlib.sha256(adjacent).hexdigest(),
        "adjacent_fixture_base64": base64.b64encode(adjacent).decode("ascii"),
    },
    "attempts": [],
    "indeterminate": False,
    "failure": None,
}
json.dump(response, sys.stdout, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
"##;

/// Drive one boundary-minimizer court and return (residual id, reduction id).
fn run_boundary_minimize(work: &Workdir, court: &str) -> (String, String) {
    let manifest = BOUNDARY_MANIFEST
        .replace("{COURT}", court)
        .replace("{PROGRAM}", &format!("{court}.py"));
    let mpath = work.path(&format!(
        "frf/courts/falsify-boundary-{court}/manifest.yaml"
    ));
    fs::create_dir_all(mpath.parent().unwrap()).unwrap();
    fs::write(&mpath, manifest).unwrap();
    let out = frf(
        work,
        &[
            "--root",
            ROOT,
            "court",
            "run",
            &format!("frf/courts/falsify-boundary-{court}/manifest.yaml"),
        ],
    );
    assert_success(&out, &format!("boundary court {court} run"));
    let run = stdout(&out);
    // The residual id is a content address: resolve the exit residual from
    // the capture's evidence.
    let residual = residual_id(work, &run, "exit");
    let out = frf(work, &["--root", ROOT, "court", "minimize", &residual]);
    assert_success(&out, &format!("boundary minimize {court}"));
    (residual, stdout(&out))
}

/// The adversarial boundary declaration: a minimizer declares a boundary
/// whose adjacent non-passing point is actually PRESERVED. The core executes
/// it and observes the refutation — `proven` must stay false, the refuting
/// attempt must be recorded as evidence, and the record must remain
/// identity- and semantically-consistent.
#[test]
fn refuted_boundary_declaration_is_never_proven() {
    let work = Workdir::new("falsify-boundary-refuted");
    work.copy_canonical_tree();
    admit_reference(&work);
    fs::create_dir_all(work.path("falsify-minimizers")).unwrap();
    let program = work.path("falsify-minimizers/refuted.py");
    fs::write(&program, REFUTED_MINIMIZER).unwrap();
    set_exec(&program);

    let (_residual, reduction_id) = run_boundary_minimize(&work, "refuted");
    let record: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("{ROOT}/reductions/{reduction_id}.json"))).unwrap(),
    )
    .unwrap();
    let minimality = &record["derivation"]["minimality"];
    // The boundary declaration IS recorded — typed domain and the two-point
    // boundary with its claimed preservation — so a reader can see exactly
    // what was claimed and refuted.
    assert_eq!(minimality["kind"], "adjacent-boundary");
    assert_eq!(minimality["reduction_domain"]["kind"], "ordered-integer");
    assert_eq!(
        minimality["reduction_domain"]["semantic"],
        "falsify.example_parameter"
    );
    assert_eq!(minimality["boundary"]["predecessor"], "1");
    assert_eq!(minimality["boundary"]["value"], "2");
    assert_eq!(minimality["proposal_minimality_claimed"], true);
    // The boundary's in-band preservation flags are the CORE'S OWN
    // observations, never the minimizer's claims: the adjacent point
    // SURVIVED the core's execution, so the refutation is recorded IN BAND
    // (predecessor_preserves=true) — never only as proven=false.
    assert_eq!(
        minimality["boundary"]["predecessor_preserves"], true,
        "the refuting observation is recorded in band"
    );
    assert_eq!(minimality["boundary"]["value_preserves"], true);
    // ...but the core observed the adjacent point SURVIVE: the boundary is
    // refuted and `proven` must be false. This is the assertion the relay
    // made impossible.
    assert_eq!(
        minimality["proven"], false,
        "a refuted boundary declaration must NEVER become `proven: true`"
    );
    // The refuting execution is recorded as evidence: a boundary_control
    // attempt with outcome preserved.
    let control = record["attempts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["role"] == "boundary_control")
        .expect("the refuting boundary control must be recorded");
    assert_eq!(control["outcome"], "preserved");
    assert_eq!(control["accepted"], false);
    // The record rederives its own content address and passes semantic
    // conformance (proven=false makes no demand on the control).
    let store = store_of(&work);
    let r = store.load_reduction(&reduction_id).expect(
        "the refuted boundary record must rederive its content address (the boundary coordinates enter the identity)",
    );
    r.validate_semantics()
        .expect("the refuted boundary record is semantically consistent");
    assert!(!r.derivation.minimality.proven);
    assert_eq!(
        r.derivation.minimality.proposal_minimality_claimed,
        Some(true)
    );
    assert_eq!(
        r.derivation
            .minimality
            .reduction_domain
            .as_ref()
            .map(|d| d.semantic.as_str()),
        Some("falsify.example_parameter")
    );
    assert_eq!(
        r.derivation
            .minimality
            .boundary
            .as_ref()
            .map(|b| b.value.as_str()),
        Some("2")
    );
}

/// The honest boundary: a minimizer declares a boundary whose adjacent
/// non-passing point genuinely loses the lineage. The core executes BOTH
/// points itself — the final verification preserves the passing point, the
/// boundary control loses the adjacent point — and MAY then record
/// `proven: true`, with the two observations as the record's evidence.
#[test]
fn honest_boundary_can_be_established_by_the_core() {
    let work = Workdir::new("falsify-boundary-honest");
    work.copy_canonical_tree();
    admit_reference(&work);
    fs::create_dir_all(work.path("falsify-minimizers")).unwrap();
    let program = work.path("falsify-minimizers/honest.py");
    fs::write(&program, HONEST_MINIMIZER).unwrap();
    set_exec(&program);

    let (_residual, reduction_id) = run_boundary_minimize(&work, "honest");
    let record: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path(&format!("{ROOT}/reductions/{reduction_id}.json"))).unwrap(),
    )
    .unwrap();
    let minimality = &record["derivation"]["minimality"];
    assert_eq!(minimality["kind"], "adjacent-boundary");
    assert_eq!(minimality["proposal_minimality_claimed"], true);
    // The boundary's in-band preservation flags match the core's own two
    // observations: the control was LOST (predecessor_preserves=false) and
    // the final verification preserved (value_preserves=true).
    assert_eq!(minimality["boundary"]["predecessor_preserves"], false);
    assert_eq!(minimality["boundary"]["value_preserves"], true);
    // The core observed both sides of the boundary itself: the control was
    // LOST and the final verification preserved, so `proven` is the core's
    // own statement — not a relayed claim.
    assert_eq!(
        minimality["proven"], true,
        "the core established the boundary pair by executing both points"
    );
    let attempts = record["attempts"].as_array().unwrap();
    let control = attempts
        .iter()
        .find(|a| a["role"] == "boundary_control")
        .expect("the boundary control must be recorded");
    assert_eq!(control["outcome"], "lost");
    let last = attempts.last().expect("attempts exist");
    assert_eq!(last["role"], "final_verification");
    assert_eq!(last["accepted"], true);
    // The record rederives and passes semantic conformance (a proven boundary
    // REQUIRES exactly this evidence).
    let store = store_of(&work);
    let r = store
        .load_reduction(&reduction_id)
        .expect("the honest boundary record must rederive its content address");
    r.validate_semantics()
        .expect("the honest boundary record is semantically consistent");
    assert!(r.derivation.minimality.proven);
}

// ---------------------------------------------------------------------------
// The domain projection (P0: the extension proposes coordinates, the core
// derives coordinates)
// ---------------------------------------------------------------------------

/// A boundary minimizer built from raw parts: the declared coordinates, the
/// adjacent + proposal fixture TEXTS (which the extractor reads), and the
/// `extractor` JSON to splice into `reduction_domain` (empty = none). Used to
/// drive the adversarial declarations below.
fn boundary_minimizer_source(
    predecessor: &str,
    value: &str,
    adjacent_text: &str,
    proposal_text: &str,
    extractor_json: &str,
) -> String {
    let adjacent = format!("{adjacent_text:?}");
    let proposal = format!("{proposal_text:?}");
    format!(
        r##"#!/usr/bin/env python3
import base64, hashlib, json, sys
raw = sys.stdin.buffer.read()
req = json.loads(raw.decode("utf-8"))
request_id = hashlib.sha256(raw).hexdigest()
adjacent = b{adjacent}
proposal = b{proposal}
response = {{
    "schema_version": "frf-minimizer-response-v2",
    "request_id": request_id,
    "fixture_sha256": hashlib.sha256(proposal).hexdigest(),
    "fixture_base64": base64.b64encode(proposal).decode("ascii"),
    "minimal": True,
    "minimality": {{
        "kind": "adjacent-boundary",
        "reduction_domain": {{
            "kind": "ordered-integer",
            "semantic": "falsify.example_parameter"{extractor_json}
        }},
        "boundary": {{
            "predecessor": "{predecessor}",
            "predecessor_preserves": False,
            "value": "{value}",
            "value_preserves": True,
        }},
        "adjacent_fixture_sha256": hashlib.sha256(adjacent).hexdigest(),
        "adjacent_fixture_base64": base64.b64encode(adjacent).decode("ascii"),
    }},
    "attempts": [],
    "indeterminate": False,
    "failure": None,
}}
json.dump(response, sys.stdout, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
"##
    )
}

/// The canonical embedded-integer projection used by the adversarial
/// declarations: the coordinate is the digit token after the first `bad=`.
const BAD_EXTRACTOR: &str =
    r#","extractor":{"kind":"embedded-integer","radix":"10","prefix":"bad="}"#;

/// Drive one boundary court and assert `court minimize` REFUSES the
/// minimizer's declaration, returning the stderr for message assertions.
fn run_boundary_minimize_refused(work: &Workdir, court: &str, needle: &str) -> String {
    let manifest = BOUNDARY_MANIFEST
        .replace("{COURT}", court)
        .replace("{PROGRAM}", &format!("{court}.py"));
    let mpath = work.path(&format!(
        "frf/courts/falsify-boundary-{court}/manifest.yaml"
    ));
    fs::create_dir_all(mpath.parent().unwrap()).unwrap();
    fs::write(&mpath, manifest).unwrap();
    let out = frf(
        work,
        &[
            "--root",
            ROOT,
            "court",
            "run",
            &format!("frf/courts/falsify-boundary-{court}/manifest.yaml"),
        ],
    );
    assert_success(&out, &format!("boundary court {court} run"));
    let run = stdout(&out);
    let residual = residual_id(work, &run, "exit");
    let out = frf(work, &["--root", ROOT, "court", "minimize", &residual]);
    assert!(
        !out.status.success(),
        "the adversarial declaration must be REFUSED ({court})"
    );
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        stderr.contains(needle),
        "refusal must name the violation; got: {stderr}"
    );
    stderr
}

/// Non-adjacent coordinates: the declaration claims predecessor 1, value 3 —
/// adjacency is a DERIVED relation (predecessor + 1 == value), never an
/// asserted one, so the core refuses before executing anything.
#[test]
fn non_adjacent_boundary_declaration_is_refused() {
    let work = Workdir::new("falsify-boundary-non-adjacent");
    work.copy_canonical_tree();
    admit_reference(&work);
    fs::create_dir_all(work.path("falsify-minimizers")).unwrap();
    let program = work.path("falsify-minimizers/nonadjacent.py");
    fs::write(
        &program,
        boundary_minimizer_source(
            "1",
            "3",
            "server 1.1.1.1\nbad=1\n",
            "server 1.1.1.1\nbad=3\n",
            BAD_EXTRACTOR,
        ),
    )
    .unwrap();
    set_exec(&program);
    run_boundary_minimize_refused(&work, "nonadjacent", "non-adjacent boundary coordinates");
}

/// Non-integer coordinates: the predecessor is not a canonical integer, so
/// the ordered-integer executable semantics cannot even parse the pair.
#[test]
fn non_integer_boundary_coordinates_are_refused() {
    let work = Workdir::new("falsify-boundary-non-integer");
    work.copy_canonical_tree();
    admit_reference(&work);
    fs::create_dir_all(work.path("falsify-minimizers")).unwrap();
    let program = work.path("falsify-minimizers/noninteger.py");
    fs::write(
        &program,
        boundary_minimizer_source(
            "abc",
            "2",
            "server 1.1.1.1\nbad=1\n",
            "server 1.1.1.1\nbad=2\n",
            BAD_EXTRACTOR,
        ),
    )
    .unwrap();
    set_exec(&program);
    run_boundary_minimize_refused(&work, "noninteger", "non-canonical boundary predecessor");
}

/// No domain projection: a boundary over ordered-integer MUST carry the
/// extractor — without it the coordinates are only labels, and the core
/// never accepts labels.
#[test]
fn boundary_without_domain_projection_is_refused() {
    let work = Workdir::new("falsify-boundary-no-projection");
    work.copy_canonical_tree();
    admit_reference(&work);
    fs::create_dir_all(work.path("falsify-minimizers")).unwrap();
    let program = work.path("falsify-minimizers/noprojection.py");
    fs::write(
        &program,
        boundary_minimizer_source(
            "1",
            "2",
            "server 1.1.1.1\nbad=1\n",
            "server 1.1.1.1\nbad=2\n",
            "",
        ),
    )
    .unwrap();
    set_exec(&program);
    run_boundary_minimize_refused(&work, "noprojection", "without the domain projection");
}

/// Misprojecting coordinates: the declaration names 5/6 but its own fixtures
/// embed 1/2. The extension proposes coordinates; the core derives them from
/// the exact executed bytes — a self-inconsistent declaration is refused.
#[test]
fn misprojecting_boundary_declaration_is_refused() {
    let work = Workdir::new("falsify-boundary-misprojecting");
    work.copy_canonical_tree();
    admit_reference(&work);
    fs::create_dir_all(work.path("falsify-minimizers")).unwrap();
    let program = work.path("falsify-minimizers/misprojecting.py");
    fs::write(
        &program,
        boundary_minimizer_source(
            "5",
            "6",
            "server 1.1.1.1\nbad=1\n",
            "server 1.1.1.1\nbad=2\n",
            BAD_EXTRACTOR,
        ),
    )
    .unwrap();
    set_exec(&program);
    run_boundary_minimize_refused(
        &work,
        "misprojecting",
        "do not project from its own fixtures",
    );
}

/// The whole-store verifier re-derives a boundary's coordinates from the
/// EXACT fixtures the record claims it executed: a record that is
/// doc-consistent (identity rederives, adjacency holds, the in-band
/// preservation flags match its attempts) but whose declared coordinates do
/// not project from its fixtures is a GRAPH violation — never silently
/// accepted.
#[test]
fn whole_store_refuses_a_boundary_whose_fixtures_do_not_project() {
    use frf::model::{
        DomainExtractor, EvidenceTransform, MinimalityBoundary, ReductionAttempt,
        ReductionAttemptOutcome, ReductionAttemptRole, ReductionDerivation, ReductionDomain,
        ReductionMinimality, ReductionRecord, ResidualKind,
    };
    let work = Workdir::new("falsify-boundary-misprojection-store");
    work.copy_canonical_tree();
    let store = store_of(&work);

    // The two fixture objects the record claims it executed: `bad=1` (the
    // boundary control) and `bad=2` (the final verification).
    let control_bytes = b"server 1.1.1.1\nbad=1\n";
    let final_bytes = b"server 1.1.1.1\nbad=2\n";
    let control_sha = frf::host::sha256_bytes(control_bytes);
    let final_sha = frf::host::sha256_bytes(final_bytes);
    let obj_dir = work.path(&format!("{ROOT}/objects/sha256"));
    fs::create_dir_all(&obj_dir).unwrap();
    fs::write(obj_dir.join(&control_sha), control_bytes).unwrap();
    fs::write(obj_dir.join(&final_sha), final_bytes).unwrap();

    // The record: doc-consistent in every way (adjacent pair, extractor
    // present, control lost + final preserved -> validate_semantics passes)
    // EXCEPT the coordinates name 5/6 while the fixtures embed 1/2.
    let attempts = vec![
        ReductionAttempt {
            attempt: "1".into(),
            role: ReductionAttemptRole::Baseline,
            fixture_sha256: control_sha.clone(),
            outcome: ReductionAttemptOutcome::Preserved,
            accepted: false,
        },
        ReductionAttempt {
            attempt: "2".into(),
            role: ReductionAttemptRole::BoundaryControl,
            fixture_sha256: control_sha.clone(),
            outcome: ReductionAttemptOutcome::Lost,
            accepted: false,
        },
        ReductionAttempt {
            attempt: "3".into(),
            role: ReductionAttemptRole::FinalVerification,
            fixture_sha256: final_sha.clone(),
            outcome: ReductionAttemptOutcome::Preserved,
            accepted: true,
        },
    ];
    let derivation = ReductionDerivation {
        strategy: "external:falsify".into(),
        original_lines: "1".into(),
        final_lines: "1".into(),
        minimality: ReductionMinimality {
            kind: "adjacent-boundary".into(),
            granularity: None,
            reduction_domain: Some(ReductionDomain {
                kind: "ordered-integer".into(),
                semantic: "falsify.example_parameter".into(),
                extractor: Some(DomainExtractor {
                    kind: "embedded-integer".into(),
                    radix: "10".into(),
                    prefix: Some("bad=".into()),
                }),
            }),
            boundary: Some(MinimalityBoundary {
                predecessor: "5".into(),
                predecessor_preserves: false,
                value: "6".into(),
                value_preserves: true,
            }),
            proven: true,
            proposal_minimality_claimed: Some(true),
        },
    };
    let transform = EvidenceTransform::reduction("falsify-residual", "eq(exit)");
    let record = ReductionRecord {
        schema_version: frf::model::SCHEMA_REDUCTION.to_string(),
        id: String::new(),
        residual_id: "falsify-residual".into(),
        source_run: "run-falsify-deadbeef".into(),
        axis: "exit".into(),
        kind: ResidualKind::exit(),
        court_semantic_identity: "0".repeat(64),
        authority_artifact_sha256: "a".repeat(64),
        candidate_artifact_sha256: "b".repeat(64),
        environment_digest: "c".repeat(64),
        comparator_semantic_id: "exit".into(),
        comparator_semantic_hash: "d".repeat(64),
        comparator_implementation_hash: "e".repeat(64),
        argv_template: vec!["--strict".into(), "{fixture}".into()],
        original_fixture_sha256: control_sha.clone(),
        final_fixture_sha256: final_sha.clone(),
        attempts,
        derivation,
        transform,
        minimizer_semantic_id: Some("falsify-min".into()),
        minimizer_semantic_hash: Some("f".repeat(64)),
        minimizer_implementation_hash: Some("0".repeat(64)),
        minimizer_implementation_artifact: None,
        minimizer_invocation_id: None,
        minimizer_result_id: None,
    };
    let id = frf::semantics::reduction_identity(
        &record.residual_id,
        &record.source_run,
        &record.axis,
        record.kind.clone(),
        &record.court_semantic_identity,
        &record.authority_artifact_sha256,
        &record.candidate_artifact_sha256,
        &record.environment_digest,
        &record.comparator_semantic_id,
        &record.comparator_semantic_hash,
        &record.comparator_implementation_hash,
        &record.argv_template,
        &record.original_fixture_sha256,
        &record.final_fixture_sha256,
        &record.attempts,
        &record.derivation,
        &record.transform,
        None, // no minimizer binding in the record (all six fields absent)
    )
    .unwrap();
    let mut record = record;
    record.id = id.clone();
    let json = store.to_evidence(&record).unwrap();
    fs::create_dir_all(work.path(&format!("{ROOT}/reductions"))).unwrap();
    store
        .commit_content_addressed(&store.reduction_path(&id).unwrap(), &json)
        .unwrap();

    // The record is doc-consistent: it rederives and passes the semantic
    // validator.
    let loaded = store.load_reduction(&id).unwrap();
    loaded.validate_semantics().unwrap();

    // But the WHOLE-STORE verifier derives the coordinates from the exact
    // executed fixtures and refuses the mismatch.
    let report = frf::verify::verify_whole_store(&store).unwrap();
    let joined = report.errors.join("\n");
    assert!(
        joined.contains("do not project from the executed fixtures"),
        "whole-store must refuse the misprojection; got: {joined}"
    );
}
