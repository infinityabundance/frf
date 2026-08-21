//! Corpus regeneration for the OpenReceipt conformance suite.
//!
//! After a protocol change (a bumped `frf-receipt-vN` schema, new fields, a
//! changed specification document), the pinned corpus in `conformance/` must
//! be regenerated so every fixture is internally consistent: each
//! `invalid-semantic` fixture violates exactly the one rule its name claims,
//! the comparator specification hashes rederive from each document's own
//! fields, and the court semantic identity rederives from the document.
//!
//!     cargo xtask regen corpus <conformance-dir>
//!
//! Rewrites `valid/`, `canonical/`, `invalid/`, `invalid-semantic/`, and
//! `hashes/`. The transform is deliberately mechanical and audit-able: it
//! only adds the v10 protocol fields, recomputes derived hashes from each
//! document's own fields, and materializes the fixtures that exercise the
//! new observable-pluggability invariants.

use crate::jcs::encode;
use crate::load_json;
use crate::rederive::{comparator_spec_hash, court_semantic_identity_from_receipt};
use crate::{sha256_bytes, sorted_names};
use serde_json::{json, Value};
use std::fs;
use std::path::Path;

const RECEIPT_V11: &str = "frf-receipt-v11";

/// The corpus's fixed environment strata (deterministic values; the digest is
/// recomputed from them by [`bump`]).
const CORPUS_LOCALE: &str = "C";
const CORPUS_TIMEZONE: &str = "Etc/UTC";
const CORPUS_UMASK: &str = "0022";
const CORPUS_CWD: &str = "frf";

/// The corpus's fixed execution profile + capture bounds (the reference
/// profile's defaults).
const CORPUS_PROFILE: &str = "frf-exec-linux-v1";

/// The built-in specification table used to complete fixtures that predate
/// the residual classifier (axis → (extractor, residual_classifier)).
fn builtin_spec(id: &str) -> Option<(&'static str, &'static str)> {
    match id {
        "exit" => Some(("exit-code", "exit")),
        "stderr" => Some(("stderr-first-line", "text")),
        "stdout" => Some(("stdout-first-line", "text")),
        _ => None,
    }
}

/// Complete a comparator semantic entry to the v10 shape and recompute its
/// specification hash from its own fields (so the hash REDERIVES).
fn bump_semantic(c: &mut Value) {
    let id = c["id"].as_str().unwrap_or_default().to_string();
    if c.get("extractor").is_none() {
        if let Some((extractor, classifier)) = builtin_spec(&id) {
            c["extractor"] = json!(extractor);
            c["residual_classifier"] = json!(classifier);
        }
    }
    if c.get("residual_classifier").is_none() {
        c["residual_classifier"] = json!("text");
    }
    let spec = comparator_spec_hash(
        &id,
        c["relation_id"].as_str().unwrap_or_default(),
        c["extractor"].as_str().unwrap_or_default(),
        c["residual_classifier"].as_str().unwrap_or_default(),
    );
    c["specification_hash"] = json!(spec);
}

/// Bring a document to the current protocol version: schema version, the
/// comparator semantic fields, the execution profile + capture bounds, the
/// expanded environment strata — and, when the corresponding fix flag is
/// set, the recomputed derived hashes (the environment digest, and the court
/// semantic identity). A fixture whose NAME says a hash is the violation
/// keeps its wrong hash so the corpus isolates exactly one rule per
/// document.
fn bump(doc: &mut Value, fix_semantic_identity: bool, fix_env_digest: bool) {
    doc["schema_version"] = json!(RECEIPT_V11);
    if let Some(sems) = doc["comparator_semantics"].as_array_mut() {
        for c in sems.iter_mut() {
            bump_semantic(c);
        }
    }
    // The execution profile + applied capture bounds (v11).
    doc["execution_profile"] = json!(CORPUS_PROFILE);
    doc["capture_bounds"] = json!({
        "timeout_ms": "60000",
        "max_stream_bytes": "16777216",
        "rlimit_as_mb": "2048",
        "rlimit_cpu_s": "30",
        "rlimit_nofile": "1024",
    });
    // The expanded environment strata; recompute the digest from them unless
    // the fixture's violation IS the digest.
    let env = &mut doc["environment"];
    env["schema_version"] = json!("frf-environment-v2");
    env["locale"] = json!(CORPUS_LOCALE);
    env["timezone"] = json!(CORPUS_TIMEZONE);
    env["umask"] = json!(CORPUS_UMASK);
    env["cwd"] = json!(CORPUS_CWD);
    if fix_env_digest {
        env["digest"] = json!(crate::rederive::env_digest(
            env["os"].as_str().unwrap_or_default(),
            env["architecture"].as_str().unwrap_or_default(),
            env["kernel_release"].as_str().unwrap_or_default(),
            CORPUS_LOCALE,
            CORPUS_TIMEZONE,
            CORPUS_UMASK,
        ));
    }
    if fix_semantic_identity {
        doc["court"]["semantic_identity"] = json!(court_semantic_identity_from_receipt(doc));
    }
}

fn canonical(doc: &Value) -> String {
    encode(doc).unwrap_or_else(|e| panic!("cannot canonicalize fixture: {e}"))
}

fn write(dir: &Path, rel: &str, bytes: &str) {
    let path = dir.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&path, bytes).unwrap();
}

/// Materialize a new valid fixture: an OpenReceipt with a wholly external
/// observable axis (`wire`) — the observable-pluggability milestone. Built
/// from the regenerated golden fixture so everything else is consistent.
fn wire_fixture(golden: &Value) -> Value {
    let mut doc = golden.clone();
    let wire_spec = comparator_spec_hash("wire", "eq", "stderr-bytes", "wire");
    let request_cid =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
    let result_cid = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string();
    let run = as_str(&doc["run"]);
    doc["court"]["admissibility_envelope"]["observables"] = json!(["wire"]);
    doc["court"]["question"] =
        json!("For malformed input in fixture family malformed-input, does the candidate preserve the admitted reference's wire stream?");
    doc["court"]["falsifier"] =
        json!("The candidate's wire stream diverges from the admitted reference.");
    doc["comparator_semantics"] = json!([{
        "id": "wire",
        "relation_id": "eq",
        "extractor": "stderr-bytes",
        "residual_classifier": "wire",
        "relation_version": "v1",
        "specification_hash": wire_spec,
    }]);
    doc["observables"] = json!([{
        "axis": "wire",
        "raw_reference_hash": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "raw_candidate_hash": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        "comparator": "eq(stderr-bytes)",
        "normalization_rules": [],
        "verdict": "residual",
        "comparator_request": request_cid,
        "comparator_result": result_cid,
    }]);
    doc["residuals"] = json!([{
        "id": "cli-wire-0001",
        "axis": "wire",
        "kind": "wire",
        "sign": {"norm": "single-run", "drift": "not-observed", "slew": "not-observed"},
        "grammar_state": "violation",
        "raw_reference_hash": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "raw_candidate_hash": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        "disposition": "open",
        "disposition_event_id": null,
        "reproducer": run,
        "invariant": "",
        "residual_fingerprint": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    }]);
    doc["endoduction"]["tokens"] = json!([{
        "residual_id": "cli-wire-0001",
        "token": "wire/wire-divergence/observed/open",
        "next_court": "none",
        "blocks_claims": ["malformed-input wire parity"],
    }]);
    doc["claims"]["blocked_by_open_residuals"] = json!([
        "cannot claim compatibility for fixture family malformed-input because residual cli-wire-0001 (wire) is open"
    ]);
    doc["court"]["semantic_identity"] = json!(court_semantic_identity_from_receipt(&doc));
    doc
}

fn as_str(v: &Value) -> String {
    v.as_str().unwrap_or_default().to_string()
}

pub fn regen_corpus(dir: &Path) {
    // 1. Valid fixtures: bump, recompute the semantic identity, then pin the
    //    canonical bytes + hash.
    let mut valid_names: Vec<String> = sorted_names(&dir.join("valid"));
    for name in &valid_names {
        let mut doc = load_json(&dir.join("valid").join(name));
        bump(&mut doc, true, true);
        let canonical = canonical(&doc);
        write(dir, &format!("valid/{name}"), &canonical);
        write(dir, &format!("canonical/{name}"), &canonical);
        let digest = sha256_bytes(canonical.as_bytes());
        write(
            dir,
            &format!("hashes/{name}.sha256"),
            &format!("{digest}\n"),
        );
        eprintln!("regen valid/{name}");
    }

    // 2. The new observable-pluggability fixture: an externally served
    //    `wire` axis (kind `wire`), with its request/result binding.
    let golden = load_json(&dir.join("valid/01-golden-resolution.json"));
    let wire = wire_fixture(&golden);
    let wire_canonical = canonical(&wire);
    write(dir, "valid/05-wire-observable.json", &wire_canonical);
    write(dir, "canonical/05-wire-observable.json", &wire_canonical);
    let digest = sha256_bytes(wire_canonical.as_bytes());
    write(
        dir,
        "hashes/05-wire-observable.json.sha256",
        &format!("{digest}\n"),
    );
    eprintln!("regen valid/05-wire-observable.json (new)");
    valid_names.push("05-wire-observable.json".to_string());

    // 3. Invalid-semantic fixtures: bump; recompute the semantic identity
    //    EXCEPT for the fixture whose violation IS the identity. Each keeps
    //    its one intended violation.
    for name in sorted_names(&dir.join("invalid-semantic")) {
        let fix_identity = name != "10-bad-semantic-identity.json";
        let fix_env_digest = name != "09-bad-environment-digest.json";
        let mut doc = load_json(&dir.join("invalid-semantic").join(&name));
        bump(&mut doc, fix_identity, fix_env_digest);
        if name == "09-bad-environment-digest.json" {
            // The fixture's violation IS the digest: keep it wrong so the
            // corpus isolates exactly one rule per document.
            doc["environment"]["digest"] = json!("0".repeat(64));
        }
        write(dir, &format!("invalid-semantic/{name}"), &canonical(&doc));
        eprintln!("regen invalid-semantic/{name}");
    }

    // 4. New invalid-semantic fixtures exercising the v10 invariants.
    type Mutation = fn(&mut Value);
    let base = load_json(&dir.join("valid/01-golden-resolution.json"));
    let new_fixtures: Vec<(&str, Mutation)> = vec![
        ("16-bad-spec-hash.json", |d| {
            d["comparator_semantics"][0]["specification_hash"] = json!("0".repeat(64));
        }),
        ("17-kind-vs-classifier.json", |d| {
            // The stderr axis's classifier is `text`; claiming `exit`
            // kind (with the token adjusted so the KIND rule is the only
            // violation) is inconsistent evidence.
            d["residuals"][0]["kind"] = json!("exit");
            d["endoduction"]["tokens"][0]["token"] =
                json!("exit/diagnostic-routing/first-line-token-change/intentional");
        }),
        ("18-half-external-observable.json", |d| {
            // An observable that binds a comparator request but no result
            // — an external verdict binds both, an in-binary neither.
            d["observables"][0]["comparator_request"] = json!("0".repeat(64));
        }),
        ("19-invalid-axis-identifier.json", |d| {
            // Observable axes are protocol identifiers: `bad axis!` is
            // outside the grammar (and consequently undeclared).
            d["observables"][0]["axis"] = json!("bad axis!");
        }),
    ];
    for (name, mutate) in new_fixtures {
        let mut doc = base.clone();
        bump(&mut doc, true, true);
        mutate(&mut doc);
        write(dir, &format!("invalid-semantic/{name}"), &canonical(&doc));
        eprintln!("regen invalid-semantic/{name} (new)");
    }

    // 5. Invalid fixtures: bump so the INTENDED violation is the refusal
    //    reason (a fixture that fails only because it predates the v10
    //    fields would not test anything). `06-duplicate-property` cannot be
    //    parsed (that IS its violation) and is left verbatim.
    for name in sorted_names(&dir.join("invalid")) {
        // `06-duplicate-property` cannot be parsed (that IS its violation)
        // and `03-number-in-string-slot` cannot be canonicalized (numbers
        // are outside the value domain — its violation); both stay verbatim.
        if matches!(
            name.as_str(),
            "06-duplicate-property.json" | "03-number-in-string-slot.json"
        ) {
            continue;
        }
        let fix_schema_version = name != "01-bad-schema-version.json";
        let mut doc = load_json(&dir.join("invalid").join(&name));
        bump(&mut doc, false, false);
        if !fix_schema_version {
            // The fixture's violation is the schema version itself.
            doc["schema_version"] = json!("frf-receipt-v7");
        }
        write(dir, &format!("invalid/{name}"), &canonical(&doc));
        eprintln!("regen invalid/{name}");
    }

    let total = valid_names.len();
    eprintln!(
        "corpus regenerated under {}: {total} valid fixture(s) with canonical+hash pins",
        dir.display()
    );
}
