//! Deterministic in-repo fuzz harness — negative controls that run under
//! plain `cargo test` (no nightly, no libFuzzer).
//!
//! Covers the same surfaces as the libFuzzer targets in `fuzz/`:
//! - YAML deserializers never panic, and parsed residuals/dispositions always
//!   satisfy the reason invariant (open ⇒ no reason, closed ⇒ one-line reason);
//! - the CLI parser never panics on arbitrary argument vectors;
//! - ids that pass validation can never escape the store root.
//!
//! Seeded PRNG ⇒ reproducible failures. Scale with `FRF_FUZZ_ITERS` (default
//! 20 000); the libFuzzer targets scale to millions with corpus-guided
//! mutation. Run: `cargo test --test fuzz`.

use clap::Parser;
use frf_rs::cli::Cli;
use frf_rs::model::*;
use frf_rs::store::{is_valid_id, validate_id};
use std::path::PathBuf;

/// xorshift64* — deterministic on every platform.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed.max(1))
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn byte(&mut self) -> u8 {
        (self.next_u64() >> 32) as u8
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf {
            *b = self.byte();
        }
    }

    fn pick(&mut self, alphabet: &[u8]) -> u8 {
        alphabet[(self.next_u64() as usize) % alphabet.len()]
    }
}

/// Byte alphabet biased toward id-relevant and YAML-relevant characters, so
/// hostile strings (slashes, dots, escapes) appear often.
const ALPHABET: &[u8] =
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-/\\ \t\n:#'\"[]{}&*!|>%@`~,()";

fn iters() -> usize {
    std::env::var("FRF_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000)
}

fn random_bytes(rng: &mut Rng, max_len: usize) -> Vec<u8> {
    let len = (rng.next_u64() as usize) % max_len;
    let mut v = vec![0u8; len];
    rng.fill(&mut v);
    v
}

fn random_id_string(rng: &mut Rng, max_len: usize) -> String {
    let len = (rng.next_u64() as usize) % max_len;
    (0..len).map(|_| rng.pick(ALPHABET) as char).collect()
}

fn assert_disposition_invariant(r: &ResidualRecord, origin: &str) {
    match &r.disposition {
        Disposition::Open => assert!(
            r.disposition.reason().is_none(),
            "{origin}: open disposition carried a reason"
        ),
        Disposition::Closed { reason, .. } => {
            assert!(
                !reason.trim().is_empty(),
                "{origin}: closed disposition without a reason"
            );
            assert!(
                !reason.contains('\n'),
                "{origin}: closed disposition with a multi-line reason"
            );
        }
    }
}

#[test]
fn yaml_parsers_never_panic_and_preserve_invariants() {
    let mut rng = Rng::new(0xF00D_F00D);
    let n = iters();
    for i in 0..n {
        // Raw random bytes (possibly invalid UTF-8; deserializers must cope).
        let s = String::from_utf8_lossy(&random_bytes(&mut rng, 512)).into_owned();
        let _ = serde_yaml::from_str::<CourtManifest>(&s);
        let _ = serde_yaml::from_str::<AuthorityRecord>(&s);
        let _ = serde_yaml::from_str::<CaptureManifest>(&s);
        let _ = serde_yaml::from_str::<TokenRecord>(&s);
        let _ = serde_yaml::from_str::<Receipt>(&s);
        let _ = serde_yaml::from_str::<ClaimRecord>(&s);
        if let Ok(r) = serde_yaml::from_str::<ResidualRecord>(&s) {
            assert_disposition_invariant(&r, &format!("random bytes iteration {i}"));
        }
    }
}

#[test]
fn mutated_valid_yaml_never_panics() {
    // Valid documents, then byte-level mutation: flip, insert, truncate.
    let seeds: &[&str] = &[
        "disposition: open\n",
        "disposition: fixed\nreason: patched the candidate\n",
        "disposition: intentional\nreason: clearer wording\n",
        r#"schema_version: frf-residual-v1
id: cli-exit-0001
court: cli-malformed-input
run: run-cli-malformed-input-ab12cd34
axis: exit
kind: exit
authority: ref-cli-1.8.2
scope: malformed-input
raw_reference: '2'
raw_candidate: '1'
raw_reference_sha256: 0000000000000000000000000000000000000000000000000000000000000000
raw_candidate_sha256: 1111111111111111111111111111111111111111111111111111111111111111
disposition: open
"#,
        r#"court:
  id: cli-malformed-input
  question: does the candidate preserve the exit class?
  falsifier: it diverges
  authority: ref-cli-1.8.2
  candidate: {name: cand-cli, version_or_commit: 0.1.0, build_profile: debug, path: golden/candidate.sh}
  fixture: {id: f, path: f.conf, arguments: ["--strict", "{fixture}"]}
  admissibility_envelope: {fixture_family: malformed-input, platforms: [x86_64-linux], observables: [exit, stderr], normalizers: [], replay_scope: single-run}
"#,
    ];
    let mut rng = Rng::new(0xBAD_F00D);
    for i in 0..iters() {
        let seed = seeds[(rng.next_u64() as usize) % seeds.len()];
        let mut bytes = seed.as_bytes().to_vec();
        match rng.next_u64() % 3 {
            0 => {
                let idx = (rng.next_u64() as usize) % bytes.len().max(1);
                bytes[idx] = rng.byte();
            }
            1 => {
                let idx = (rng.next_u64() as usize) % (bytes.len() + 1);
                bytes.insert(idx, rng.byte());
            }
            _ => {
                let len = (rng.next_u64() as usize) % (bytes.len() + 1);
                bytes.truncate(len);
            }
        }
        let s = String::from_utf8_lossy(&bytes);
        let _ = serde_yaml::from_str::<CourtManifest>(&s);
        let _ = serde_yaml::from_str::<ResidualRecord>(&s);
        let _ = serde_yaml::from_str::<Disposition>(&s);
        if let Ok(r) = serde_yaml::from_str::<ResidualRecord>(&s) {
            assert_disposition_invariant(&r, &format!("mutation iteration {i}"));
        }
    }
}

#[test]
fn cli_parser_never_panics_on_arbitrary_args() {
    let mut rng = Rng::new(0x00C1_1C11);
    for _ in 0..iters() {
        let nargs = (rng.next_u64() % 12) as usize;
        let mut args: Vec<String> = vec!["frf".to_string()];
        for _ in 0..nargs {
            args.push(random_id_string(&mut rng, 40));
        }
        // try_parse_from reports errors without printing; a panic is the bug.
        let _ = Cli::try_parse_from(args);
    }
}

#[test]
fn ids_never_escape_the_store_root() {
    let mut rng = Rng::new(0x1D51D);
    let root = PathBuf::from("/frf-root");
    for _ in 0..iters() {
        let id = random_id_string(&mut rng, 48);
        if is_valid_id(&id) {
            for (dir, filename) in [
                ("residuals", format!("{id}.yaml")),
                ("receipts", format!("{id}.yaml")),
                ("claims", format!("{id}.yaml")),
                ("authorities", format!("{id}.yaml")),
            ] {
                let p = root.join(dir).join(&filename);
                assert!(p.starts_with(&root), "id {id:?} escaped via {dir}");
                assert_eq!(p.parent().unwrap().file_name().unwrap(), dir);
            }
            let run_dir = root.join("captures").join(&id);
            assert!(run_dir.starts_with(&root), "id {id:?} escaped via captures");
        } else {
            assert!(
                validate_id("fuzz", &id).is_err(),
                "validate_id accepted {id:?} that is_valid_id rejected"
            );
        }
    }
}

#[test]
fn hostile_ids_are_rejected_by_validation() {
    for id in [
        "",
        ".",
        "..",
        "../..",
        "a/b",
        "a\\b",
        "a b",
        "a:0",
        "run-../../x",
        "..%2f",
        "a\nb",
        "cli-exit-0001/../../x",
    ] {
        assert!(!is_valid_id(id), "{id:?} must be invalid");
        assert!(validate_id("hostile", id).is_err());
    }
    for id in [
        "cli-exit-0001",
        "cli-text-0001",
        "run-cli-malformed-input-f951ec56",
        "receipt-run-x-2ecce0ba",
        "ref-cli-1.8.2",
        "a.b_c-d0",
    ] {
        assert!(is_valid_id(id), "{id:?} must be valid");
        assert!(validate_id("benign", id).is_ok());
    }
}
