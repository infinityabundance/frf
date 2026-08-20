//! libFuzzer target: every YAML deserializer, plus the residual/disposition
//! reason invariant. Corpus-guided equivalent of the deterministic
//! `tests/fuzz.rs` harness.
//!
//! Run: `cargo +nightly fuzz run yaml_types`

#![no_main]

use frf::model::*;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let _ = serde_yaml::from_str::<CourtManifest>(&s);
    let _ = serde_yaml::from_str::<AuthorityRecord>(&s);
    let _ = serde_yaml::from_str::<CaptureManifest>(&s);
    let _ = serde_yaml::from_str::<TokenRecord>(&s);
    let _ = serde_yaml::from_str::<Receipt>(&s);
    let _ = serde_yaml::from_str::<ClaimRecord>(&s);
    if let Ok(r) = serde_yaml::from_str::<ResidualRecord>(&s) {
        match &r.disposition {
            Disposition::Open => assert!(r.disposition.reason().is_none()),
            Disposition::Closed { reason, .. } => {
                assert!(!reason.trim().is_empty());
                assert!(!reason.contains('\n'));
            }
        }
    }
});
