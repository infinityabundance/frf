//! libFuzzer target: every YAML deserializer, plus the disposition reason
//! invariant. Corpus-guided equivalent of the deterministic `tests/fuzz.rs`
//! harness. Observations (`ResidualRecord`) have no disposition field at all;
//! dispositions are parsed standalone and must satisfy the reason invariant.
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
    let _ = serde_yaml::from_str::<ResidualRecord>(&s);
    let _ = serde_yaml::from_str::<TokenRecord>(&s);
    let _ = serde_yaml::from_str::<Receipt>(&s);
    let _ = serde_yaml::from_str::<ClaimRecord>(&s);
    if let Ok(d) = serde_yaml::from_str::<Disposition>(&s) {
        match &d {
            Disposition::Open => assert!(d.reason().is_none()),
            Disposition::Closed { reason, .. } => {
                assert!(!reason.trim().is_empty());
                assert!(!reason.contains('\n'));
            }
            Disposition::Fixed {
                reason,
                resolution_run_id,
                closure_predicate,
            } => {
                assert!(!reason.trim().is_empty() && !reason.contains('\n'));
                assert!(!resolution_run_id.trim().is_empty());
                assert!(!closure_predicate.trim().is_empty());
            }
        }
    }
});
