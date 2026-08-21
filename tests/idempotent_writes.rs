//! Idempotent content-addressed writes (the object-CAS discipline, applied
//! to every generated evidence object):
//!
//!   desired identity H:
//!     path absent  -> write atomically
//!     path exists  -> load + verify the existing object IS H
//!                      identical:  success (a no-op)
//!                      corrupt/different:  REFUSE
//!
//! "Exists => assume okay" is never acceptable: an object that lives at a
//! content address MUST hash to that address, or the address is a lie.
//!
//! Run: `cargo test --test idempotent_writes`.

use frf::store::Store;
use std::fs;
use std::path::PathBuf;

mod common;
use common::*;

/// Corrupt a canonical JSON evidence document in place (still canonical
/// bytes, so the refusal comes from the content-address check, not from the
/// canonical-bytes loader).
fn corrupt_canonical(work: &Workdir, rel: &str, mutate: impl FnOnce(&mut serde_json::Value)) {
    let path = work.path(rel);
    let value = frf::canon::parse_strict(&fs::read(&path).unwrap()).unwrap();
    let mut value = serde_json::to_value(value).unwrap();
    mutate(&mut value);
    let canonical = frf::canon::canonical(&value).unwrap();
    fs::write(&path, canonical.into_bytes()).unwrap();
}

#[test]
fn witness_attest_is_idempotent_and_refuses_corruption() {
    let work = Workdir::new("idem-witness");
    work.copy_canonical_tree();
    admit_reference(&work);
    let _run = run_court(&work);

    let program = work.path("golden/witnesses/attest.py");
    fs::create_dir_all(program.parent().unwrap()).unwrap();
    fs::write(
        &program,
        "#!/usr/bin/env python3\n\
import hashlib, json, sys\n\
raw = sys.stdin.buffer.read()\n\
request_id = hashlib.sha256(raw).hexdigest()\n\
req = json.loads(raw.decode(\"utf-8\"))\n\
response = {\n\
    \"schema_version\": \"frf-witness-response-v2\",\n\
    \"request_id\": request_id,\n\
    \"indeterminate\": False,\n\
    \"failure\": None,\n\
    \"attestation\": {\n\
        \"statement\": req[\"statement\"],\n\
        \"outcome\": \"affirm\",\n\
        \"detail\": \"idempotent witness\",\n\
    },\n\
}\n\
json.dump(response, sys.stdout, sort_keys=True, separators=(\",\", \":\"))\n",
    )
    .unwrap();
    set_exec(&program);

    let args: Vec<&str> = vec![
        "--root",
        ROOT,
        "witness",
        "attest",
        "residual",
        "cli-exit-0001",
        "--id",
        "manual-review",
        "--relation",
        "independent-confirmation",
        "--program",
        "golden/witnesses/attest.py",
        "--statement",
        "identical statement",
    ];
    let out = frf(&work, &args);
    assert_success(&out, "witness attest (first)");
    let id = stdout(&out);
    assert_eq!(id.len(), 64);

    // Identical attestation: the statement AND its preserved request +
    // response all exist and verify — a content-addressed no-op.
    let out = frf(&work, &args);
    assert_success(&out, "witness attest (identical re-run)");
    assert_eq!(stdout(&out), id, "identical evidence state, identical id");

    // A corrupt statement at the address is REFUSED, never reused.
    corrupt_canonical(&work, &format!("{ROOT}/witnesses/{id}.json"), |v| {
        v["statement"] = serde_json::Value::String("forged".to_string());
    });
    let out = frf(&work, &args);
    assert!(
        !out.status.success(),
        "a corrupt witness statement must refuse the re-attestation"
    );
}

#[test]
fn challenge_write_is_idempotent_and_refuses_corruption() {
    let work = Workdir::new("idem-challenge");
    work.copy_canonical_tree();
    admit_reference(&work);
    let _run = run_court(&work);

    let args: Vec<&str> = vec![
        "--root",
        ROOT,
        "court",
        "challenge",
        MANIFEST,
        "--operators",
        "exit-class",
    ];
    let out = frf(&work, &args);
    assert_success(&out, "challenge (first)");

    // The challenge WRITE is content-addressed: writing the identical
    // record again is a verified no-op; a corrupt record at the address is
    // refused. (The challenge COMMAND itself re-runs the mutant court, whose
    // immutable captures rightly refuse a duplicate observation — the write
    // primitive is exercised here directly.)
    let store = Store::new(work.path(ROOT));
    let challenge_files: Vec<PathBuf> = fs::read_dir(work.path(&format!("{ROOT}/challenges")))
        .unwrap()
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
        .map(|e| e.path())
        .collect();
    assert!(!challenge_files.is_empty());
    let id = challenge_files[0]
        .file_stem()
        .unwrap()
        .to_string_lossy()
        .to_string();
    let record = store.load_challenge(&id).unwrap();
    store.write_challenge(&record).unwrap(); // identical -> verified no-op

    let rel = challenge_files[0]
        .strip_prefix(&work.dir)
        .unwrap()
        .to_string_lossy()
        .to_string();
    corrupt_canonical(&work, &rel, |v| {
        v["operator"] = serde_json::Value::String("forged".to_string());
    });
    let err = store.write_challenge(&record).unwrap_err();
    assert!(
        err.to_string().contains("not content-addressed"),
        "unexpected refusal: {err}"
    );
}

#[test]
fn reduction_is_idempotent_and_refuses_corruption() {
    let work = Workdir::new("idem-reduction");
    work.copy_canonical_tree();
    admit_reference(&work);
    let _run = run_court(&work);

    // The golden exit residual routes to the built-in ddmin reducer.
    let args: Vec<&str> = vec!["--root", ROOT, "court", "minimize", "cli-exit-0001"];
    let out = frf(&work, &args);
    assert_success(&out, "minimize (first)");

    let out = frf(&work, &args);
    assert_success(&out, "minimize (identical re-run)");

    let reduction_files: Vec<PathBuf> = fs::read_dir(work.path(&format!("{ROOT}/reductions")))
        .unwrap()
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
        .map(|e| e.path())
        .collect();
    assert!(!reduction_files.is_empty());
    let corrupt = reduction_files[0].clone();
    let rel = corrupt
        .strip_prefix(&work.dir)
        .unwrap()
        .to_string_lossy()
        .to_string();
    corrupt_canonical(&work, &rel, |v| {
        v["axis"] = serde_json::Value::String("stderr".to_string());
    });
    let out = frf(&work, &args);
    assert!(
        !out.status.success(),
        "a corrupt reduction record must refuse the re-run"
    );
}

#[test]
fn receipt_emit_is_idempotent_and_refuses_corruption() {
    let work = Workdir::new("idem-receipt");
    work.copy_canonical_tree();
    admit_reference(&work);
    let run = run_court(&work);

    let args: Vec<&str> = vec!["--root", ROOT, "receipt", "emit", &run];
    let out = frf(&work, &args);
    assert_success(&out, "receipt emit (first)");
    let id = stdout(&out);

    let out = frf(&work, &args);
    assert_success(&out, "receipt emit (identical re-run)");
    assert_eq!(stdout(&out), id);

    // Corrupt the receipt document (canonically): re-emitting the same state
    // produces the same id, and the existing file must hash to it — refuse.
    corrupt_canonical(&work, &format!("{ROOT}/receipts/{id}.json"), |v| {
        v["run"] = serde_json::Value::String("run-forged".to_string());
    });
    let out = frf(&work, &args);
    assert!(
        !out.status.success(),
        "a corrupt receipt must refuse re-emit"
    );
    assert!(
        stderr(&out).contains("does not hash to its id"),
        "unexpected refusal: {}",
        stderr(&out)
    );
}

#[test]
fn series_append_is_idempotent_and_refuses_corruption() {
    let work = Workdir::new("idem-series");
    work.copy_canonical_tree();
    admit_reference(&work);

    // A repeat-axis series: three identical observations share one run.
    let args: Vec<&str> = vec!["--root", ROOT, "court", "run", MANIFEST, "--repeat", "3"];
    let out = frf(&work, &args);
    assert_success(&out, "repeat series (first)");
    let run = stdout(&out);

    let out = frf(&work, &args);
    assert_success(&out, "repeat series (identical re-run)");
    assert_eq!(stdout(&out), run, "identical evidence, identical run");

    // The series snapshot is content-addressed: corrupting it must make the
    // next append refuse (it would reuse a lying record).
    let series_files: Vec<PathBuf> = fs::read_dir(work.path(&format!("{ROOT}/series")))
        .unwrap()
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
        .map(|e| e.path())
        .collect();
    assert!(!series_files.is_empty());
    let corrupt = series_files[0].clone();
    let rel = corrupt
        .strip_prefix(&work.dir)
        .unwrap()
        .to_string_lossy()
        .to_string();
    corrupt_canonical(&work, &rel, |v| {
        v["coordinate_system"] = serde_json::Value::String("time".to_string());
    });
    let out = frf(&work, &args);
    assert!(
        !out.status.success(),
        "a corrupt series record must refuse the append"
    );
}
