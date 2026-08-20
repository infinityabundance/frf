//! libFuzzer target: id validation is the only gate between arbitrary input
//! and filesystem paths. For every input: if the id passes validation, the
//! constructed paths must stay under the root; if it fails, validation must
//! say so consistently.
//!
//! Run: `cargo +nightly fuzz run store_ids`

#![no_main]

use frf::store::{is_valid_id, validate_id};
use libfuzzer_sys::fuzz_target;
use std::path::PathBuf;

fuzz_target!(|data: &[u8]| {
    let id = String::from_utf8_lossy(data);
    let root = PathBuf::from("/frf-root");
    if is_valid_id(&id) {
        for dir in ["residuals", "receipts", "claims", "authorities"] {
            let p = root.join(dir).join(format!("{id}.yaml"));
            assert!(p.starts_with(&root), "id {id:?} escaped via {dir}");
            assert_eq!(p.parent().unwrap().file_name().unwrap(), dir);
        }
        let run_dir = root.join("captures").join(&*id);
        assert!(run_dir.starts_with(&root), "id {id:?} escaped via captures");
    } else {
        assert!(validate_id("fuzz", &id).is_err());
    }
});
