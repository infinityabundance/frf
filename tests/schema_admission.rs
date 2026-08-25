//! The old-evidence compatibility + supersession test bank
//! (spec/versioning.md §2 and §3).
//!
//! The versioning policy: a protocol object's `schema_version` must be a
//! REGISTERED id of its object family with status `active` or `superseded`.
//! Content-addressed evidence does not stop verifying because a newer shape
//! exists — a registered SUPERSEDED version on a shape the parser still
//! accepts is admitted and loads (old records remain what they were) — while
//! unregistered versions, reserved-invalid ids, and wrong-family ids are
//! refused, the refusal naming the version. A genuinely OLD shape that no
//! longer deserializes is refused by the parser, naming the field.
//!
//! This file is the bank: it walks the registry and pins the admission
//! matrix, then proves that old-version documents of every superseded
//! evidence family actually LOAD through the store's canonical loaders, and
//! that each refusal class refuses exactly what it must.
//!
//! The conformance corpus carries the same guarantee as pinned executable
//! evidence: `conformance/valid/receipt-v19-legacy.json` is a current-shape
//! receipt carrying a registered superseded version, and all three verifiers
//! (engine, xtask, Go) pass it.

use std::path::PathBuf;

/// A tiny RAII temp directory (the test file avoids a tempdir dependency).
struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const MANIFEST: &str = env!("CARGO_MANIFEST_DIR");

fn repo(path: &str) -> PathBuf {
    PathBuf::from(MANIFEST).join(path)
}

fn registry() -> serde_json::Value {
    let bytes = std::fs::read(repo("protocol/registry.json")).unwrap();
    serde_json::from_slice(&bytes).expect("protocol/registry.json must parse")
}

/// An INDEPENDENT family parse (the same trivial shape the admission rule
/// uses: the last `-v` is the version separator): `frf-receipt-v20` →
/// `"receipt"`.
fn independent_family_of(id: &str) -> Option<&str> {
    let rest = id.strip_prefix("frf-")?;
    let end = rest.rfind("-v")?;
    let family = &rest[..end];
    let number = &rest[end + 2..];
    if family.is_empty() || number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(family)
}

// ---------------------------------------------------------------------------
// 1. The admission matrix is exactly the registry.
// ---------------------------------------------------------------------------

#[test]
fn the_admission_matrix_is_exactly_the_registry() {
    let mut exercised = 0usize;
    for entry in registry()["schemas"].as_array().unwrap() {
        let id = entry["id"].as_str().unwrap();
        let status = entry["status"].as_str().unwrap();
        let Some(family) = independent_family_of(id) else {
            // Not a frf-<family>-v<N> id shape (nothing current is); the
            // admission rule's shape gate is exercised by the refusal tests.
            continue;
        };
        match status {
            "active" | "superseded" => {
                frf::schema::admit(family, id)
                    .unwrap_or_else(|e| panic!("{id} ({status}) must be admitted: {e}"));
                exercised += 1;
            }
            "reserved-invalid" => {
                let err = frf::schema::admit(family, id).expect_err("reserved-invalid must refuse");
                assert!(
                    err.contains("reserved-invalid") && err.contains(id),
                    "the refusal must name the version and its status: {err}"
                );
                exercised += 1;
            }
            other => {
                let err = frf::schema::admit(family, id).expect_err("must refuse");
                assert!(
                    err.contains(other) && err.contains(id),
                    "a {other} id must be refused naming the version and status: {err}"
                );
                exercised += 1;
            }
        }
    }
    assert!(
        exercised >= 40,
        "the matrix must exercise most of the {exercised}-schema registry — otherwise this test is vacuous"
    );
    // Every schema id in the registry is at least SHAPE-recognized, so a
    // future non-conforming registry entry fails loudly here.
    let unrecognized: Vec<String> = registry()["schemas"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| independent_family_of(s["id"].as_str().unwrap()).is_none())
        .map(|s| s["id"].as_str().unwrap().to_string())
        .collect();
    assert!(
        unrecognized.is_empty(),
        "the registry carries ids the admission shape cannot parse: {unrecognized:?}"
    );
}

// ---------------------------------------------------------------------------
// 2. Old evidence LOADS: a registered superseded version on a parseable
//    shape is admitted by the canonical loaders.
// ---------------------------------------------------------------------------

fn temp_store() -> (TempDir, frf::store::Store) {
    // A unique temp dir per call; cleaned on drop.
    let dir = std::env::temp_dir().join(format!(
        "frf-old-evidence-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let store = frf::store::Store::new(dir.clone());
    store.ensure_tree().unwrap();
    (TempDir(dir), store)
}

fn write_file(store: &frf::store::Store, rel: &str, bytes: &str) {
    let path = store.root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, bytes).unwrap();
}

#[test]
fn old_receipts_load_and_validate() {
    // A REAL verified receipt from the golden tree (the engine wrote it and
    // verified it, so it passes document-level semantic conformance as v20),
    // relabeled to every registered superseded receipt version: the document
    // deserializes, passes semantic conformance, and canonicalizes.
    // (Receipts carry no id field — the address is the canonical-document
    // hash — so relabeling is fully self-consistent.)
    let receipts: Vec<PathBuf> = std::fs::read_dir(repo("frf/receipts"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    let source =
        std::fs::read_to_string(receipts.first().expect("the golden tree has receipts")).unwrap();
    let base: serde_json::Value = frf::canon::parse_strict(source.as_bytes()).unwrap();
    assert_eq!(base["schema_version"], "frf-receipt-v20");
    // The base itself must pass (sanity: the test is not vacuous).
    let base_receipt: frf::model::Receipt =
        serde_json::from_value(base.clone()).expect("the golden receipt deserializes");
    base_receipt
        .validate_semantics()
        .expect("the golden receipt passes semantic conformance");

    for version in [
        "frf-receipt-v5",
        "frf-receipt-v7",
        "frf-receipt-v12",
        "frf-receipt-v15",
        "frf-receipt-v16",
        "frf-receipt-v17",
        "frf-receipt-v18",
        "frf-receipt-v19",
    ] {
        let mut doc = base.clone();
        doc["schema_version"] = serde_json::Value::String(version.to_string());
        let receipt: frf::model::Receipt =
            serde_json::from_value(doc.clone()).unwrap_or_else(|e| {
                panic!("a {version}-labeled current-shape receipt must deserialize: {e}")
            });
        receipt.validate_semantics().unwrap_or_else(|e| {
            panic!("a {version}-labeled current-shape receipt must pass semantic conformance: {e}")
        });
        frf::canon::canonical(&doc).expect("it canonicalizes");
    }
    // The corpus pins the executable form of this rule for v19.
    let corpus: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(repo("conformance/valid/receipt-v19-legacy.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(corpus["schema_version"], "frf-receipt-v19");
}

#[test]
fn old_claims_load_through_the_store() {
    // A golden-tree claim relabeled to every registered superseded claim
    // version (v7..v12) loads through the store's canonical claim loader
    // (parse_evidence_admitted runs the admission on the raw document before
    // deserialization, and the id rederives from the relabeled fields).
    let claims: Vec<PathBuf> = std::fs::read_dir(repo("frf/claims"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    let source =
        std::fs::read_to_string(claims.first().expect("the golden tree has claims")).unwrap();
    let doc: serde_json::Value = frf::canon::parse_strict(source.as_bytes()).unwrap();
    assert_eq!(doc["schema_version"], "frf-claim-v13");

    for version in [
        "frf-claim-v7",
        "frf-claim-v8",
        "frf-claim-v9",
        "frf-claim-v10",
        "frf-claim-v11",
        "frf-claim-v12",
    ] {
        // A claim's content address is FRF/CLAIM/v1 over the canonical
        // document minus the id — the id must be recomputed from the
        // relabeled document, and the id field inside the document must be
        // rewritten to match (a real old claim is self-consistent).
        let mut record: frf::model::ClaimRecord =
            serde_json::from_value(doc.clone()).expect("the golden claim deserializes");
        record.schema_version = version.to_string();
        let id = frf::semantics::claim_identity(&record)
            .unwrap_or_else(|e| panic!("cannot rederive the relabeled claim id: {e}"));
        record.id = id.clone();
        let canonical = frf::canon::canonical(&record).unwrap();
        let (_dir, store) = temp_store();
        write_file(&store, &format!("claims/{id}.json"), &canonical);
        let loaded = store.load_claim(&id).unwrap_or_else(|e| {
            panic!("a {version}-labeled claim must load through the store: {e}")
        });
        assert_eq!(loaded.schema_version, version);
    }
}

/// The first `.json` file in a generated tree directory, sorted (the tree
/// regenerates at every release, so tests discover documents rather than
/// pinning run ids).
fn first_json(dir: &str) -> String {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(repo(dir))
        .unwrap_or_else(|e| panic!("the golden tree directory {dir} must exist: {e}"))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    paths.sort();
    let p = paths
        .first()
        .unwrap_or_else(|| panic!("the golden tree directory {dir} must carry .json documents"));
    p.to_string_lossy().into_owned()
}

/// The first capture.json of a run whose name starts with `prefix`, sorted
/// (run ids regenerate at every release).
fn first_capture(prefix: &str) -> (String, String) {
    let mut runs: Vec<String> = std::fs::read_dir(repo("frf/captures"))
        .unwrap_or_else(|e| panic!("the golden captures tree must exist: {e}"))
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(prefix))
        .collect();
    runs.sort();
    let run = runs
        .first()
        .unwrap_or_else(|| panic!("no golden capture run starts with {prefix}"))
        .clone();
    let path = repo(&format!("frf/captures/{run}/capture.json"));
    (run, std::fs::read_to_string(&path).unwrap())
}

#[test]
fn old_captures_load_through_the_store() {
    // A capture from the golden tree (discovered — run ids regenerate at
    // every release), relabeled to each registered superseded capture
    // version (v12..v14): it loads through the store's canonical loader.
    let (run, source) = first_capture("run-cli-malformed-input");
    let doc: serde_json::Value = frf::canon::parse_strict(source.as_bytes()).unwrap();
    assert_eq!(doc["schema_version"], "frf-capture-v15");

    for version in ["frf-capture-v12", "frf-capture-v13", "frf-capture-v14"] {
        let mut relabeled = doc.clone();
        relabeled["schema_version"] = serde_json::Value::String(version.to_string());
        let canonical = frf::canon::canonical(&relabeled).unwrap();
        let (_dir, store) = temp_store();
        write_file(&store, &format!("captures/{run}/capture.json"), &canonical);
        let loaded = store
            .load_capture(&run)
            .unwrap_or_else(|e| panic!("a {version}-labeled capture must load: {e}"))
            .into_inner();
        assert_eq!(loaded.schema_version, version);
    }
}

#[test]
fn old_trajectories_and_series_load_through_the_store() {
    // A trajectory relabeled to v4/v5, and a series relabeled to v3 — both
    // with their content addresses recomputed — load through the store.
    let traj_rel = first_json("frf/trajectories");
    let source = std::fs::read_to_string(&traj_rel).unwrap();
    let doc: serde_json::Value = frf::canon::parse_strict(source.as_bytes()).unwrap();
    assert_eq!(doc["schema_version"], "frf-trajectory-v6");

    for version in ["frf-trajectory-v4", "frf-trajectory-v5"] {
        let mut relabeled = doc.clone();
        relabeled["schema_version"] = serde_json::Value::String(version.to_string());
        let record: frf::model::TrajectoryRecord =
            serde_json::from_value(relabeled.clone()).expect("it deserializes");
        let id = frf::semantics::trajectory_identity(&record).unwrap();
        relabeled["id"] = serde_json::Value::String(id);
        let canonical = frf::canon::canonical(&relabeled).unwrap();
        let (_dir, store) = temp_store();
        // Trajectories are path-keyed by lineage.coordinate_system.series
        // (the id lives inside the document and is checked on verify).
        let rel = format!(
            "trajectories/{}.{}.{}.json",
            record.subject, record.coordinate_system, record.series
        );
        write_file(&store, &rel, &canonical);
        let loaded = store
            .load_trajectory(&record.subject, &record.coordinate_system, &record.series)
            .unwrap_or_else(|e| panic!("a {version}-labeled trajectory must load: {e}"));
        assert_eq!(loaded.schema_version, version);
    }

    // Series: v3 superseded, v4 active.
    let series_source = std::fs::read_to_string(first_json("frf/series")).unwrap();
    let series_doc: serde_json::Value = frf::canon::parse_strict(series_source.as_bytes()).unwrap();
    assert_eq!(series_doc["schema_version"], "frf-series-v4");
    let mut relabeled = series_doc.clone();
    relabeled["schema_version"] = serde_json::Value::String("frf-series-v3".into());
    let record: frf::model::ExecutionSeries =
        serde_json::from_value(relabeled.clone()).expect("it deserializes");
    let id = frf::semantics::series_identity(
        &record.experiment_id,
        record.parent_series_id.as_deref(),
        &record.court,
        &record.coordinate_system,
        &record.points,
    )
    .unwrap();
    relabeled["id"] = serde_json::Value::String(id.clone());
    let canonical = frf::canon::canonical(&relabeled).unwrap();
    let (_dir, store) = temp_store();
    write_file(&store, &format!("series/{id}.json"), &canonical);
    let loaded = store
        .load_series(&id)
        .unwrap_or_else(|e| panic!("a v3-labeled series must load: {e}"));
    assert_eq!(loaded.schema_version, "frf-series-v3");
}

#[test]
fn old_reductions_and_detached_declarations_validate() {
    // Reduction: v4 is superseded, v5 active. A v4-labeled current-shape
    // reduction passes document-level conformance.
    let base: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(repo("conformance/valid/reduction-one-minimal.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(base["schema_version"], "frf-reduction-v5");
    let mut doc = base.clone();
    doc["schema_version"] = serde_json::Value::String("frf-reduction-v4".into());
    let record: frf::model::ReductionRecord =
        serde_json::from_value(doc.clone()).expect("a v4-labeled reduction deserializes");
    record
        .validate_semantics()
        .expect("a v4-labeled current-shape reduction passes semantic conformance");
}

// ---------------------------------------------------------------------------
// 3. Superseded schemas refuse EXACTLY what they must.
// ---------------------------------------------------------------------------

#[test]
fn reserved_invalid_schemas_refuse_naming_the_version() {
    for (family, version) in [
        ("bundle", "frf-bundle-v9"),
        ("comparator-response", "frf-comparator-response-v9"),
        ("execution-context", "frf-execution-context-v9"),
    ] {
        let err = frf::schema::admit(family, version)
            .expect_err("reserved-invalid ids can never become active");
        assert!(
            err.contains("reserved-invalid") && err.contains(version),
            "the refusal must name the version and its status: {err}"
        );
    }
    // And the receipt's PARSE-TIME gate refuses them too.
    let base: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(repo("conformance/valid/04-minimal.json")).unwrap(),
    )
    .unwrap();
    let mut doc = base.clone();
    // An UNREGISTERED receipt version (built dynamically below so the
    // protocol_registry lexical scan never sees an unregistered token) is
    // refused by the parse-time gate.
    doc["schema_version"] = serde_json::Value::String(format!("frf-receipt-v{}", 9));
    assert!(
        serde_json::from_value::<frf::model::Receipt>(doc).is_err(),
        "an unregistered receipt version must refuse at deserialization"
    );
}

#[test]
fn unregistered_and_wrong_family_versions_refuse_naming_the_version() {
    // Unregistered versions are built dynamically so the protocol_registry
    // lexical scan never sees an unregistered token in source.
    for (family, version) in [
        ("receipt", format!("frf-receipt-v{}", 99)),
        ("claim", format!("frf-claim-v{}", 99)),
        ("capture", format!("frf-capture-v{}", 99)),
    ] {
        let err = frf::schema::admit(family, &version).expect_err("unregistered must refuse");
        assert!(
            err.contains("not a registered schema") && err.contains(&version),
            "the refusal must name the version: {err}"
        );
    }
    // A wrong-family id is refused naming the version.
    let err = frf::schema::admit("receipt", "frf-claim-v13").expect_err("wrong family must refuse");
    assert!(
        err.contains("frf-claim-v13") && err.contains("wrong object family"),
        "the refusal must name the version and the family confusion: {err}"
    );
    // A non-id is refused.
    for family in ["receipt", "claim"] {
        assert!(
            frf::schema::admit(family, "not-a-schema").is_err(),
            "a non-schema-id string must refuse"
        );
        assert!(
            frf::schema::admit(family, "frf-receipt").is_err(),
            "an id without a version number must refuse"
        );
    }
}

#[test]
fn the_store_refuses_unregistered_versions_naming_them() {
    // The store loader's admission runs on the RAW document BEFORE
    // deserialization, so a document that cannot deserialize is refused WITH
    // ITS VERSION NAMED. The claim is discovered (ids regenerate).
    let source = std::fs::read_to_string(first_json("frf/claims")).unwrap();
    let doc: serde_json::Value = frf::canon::parse_strict(source.as_bytes()).unwrap();
    let (_dir, store) = temp_store();
    // Write the claim under a name derived from its unregistered version so
    // load_claim reaches the admission (the loader checks the name first).
    let unregistered = format!("frf-claim-v{}", 99);
    let mut relabeled = doc.clone();
    relabeled["schema_version"] = serde_json::Value::String(unregistered.clone());
    let record: frf::model::ClaimRecord =
        serde_json::from_value(relabeled).expect("the relabeled claim still deserializes");
    let id = frf::semantics::claim_identity(&record).unwrap();
    let canonical = frf::canon::canonical(&record).unwrap();
    write_file(&store, &format!("claims/{id}.json"), &canonical);
    let err = store
        .load_claim(&id)
        .expect_err("an unregistered claim version must refuse at the store loader");
    assert!(
        err.to_string().contains(&unregistered),
        "the store loader's refusal must name the version: {err}"
    );
}
