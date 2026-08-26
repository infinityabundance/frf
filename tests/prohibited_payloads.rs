//! The publication-integrity gate: the tracked repository must never carry
//! prohibited payloads.
//!
//! The invariant is stated EXACTLY, never overstated:
//!
//! - **exact-byte pins**: every tracked file is hashed against the v3
//!   build-manifest's artifact pins — a file whose SHA-256 EQUALS a pinned
//!   historical build product is a forbidden payload wherever it appears (a
//!   `builds/` copy, a content-addressed evidence object, a stray blob). The
//!   check is exact-byte by construction: a base64/gzip/embedded/chunked
//!   copy has a different digest and is OUT OF SCOPE for this hash check
//!   (that boundary is the detached-objects declaration's exact-closure
//!   equality and the semantic stream gate below).
//! - **the `builds/` artifact directories must never be tracked**;
//! - **semantic stream gate**: the published v3 evidence's captured raw
//!   streams must be EXACTLY admissible values of their probe's declared
//!   output vocabulary — the heartbleed probe prints a `hb-leak-projection`
//!   record (len, sha256, canary, fraction) or one of its clean verdicts to
//!   stdout and its leak verdict to stderr, and the goto-fail verifier
//!   prints its handshake verdicts — so a raw process-memory dump (which the
//!   probes never write to an observed stream) matches nothing and is
//!   refused by the vocabulary, not by a byte-count heuristic. A stream may
//!   be empty; a legitimate projection of any size is admitted.
//! - **cross-stream consistency**: on a heartbleed run's REFERENCE side (the
//!   real fixed probe, whose output contract is unconditional), stdout and
//!   stderr must agree — the projection's `len` must equal the leak verdict's
//!   echoed byte count (hb.c prints both from the same `total`), and a clean
//!   stdout verdict must pair with empty stderr. The candidate side is not
//!   cross-checked: the mutation challenge runs adversarial launcher scripts
//!   that legitimately deviate from the probe's stream contract (the
//!   vocabulary gate is the candidate side's boundary);
//! - **fail closed**: a captured stream from any probe WITHOUT a declared
//!   admission vocabulary is refused outright — adding a new probe means
//!   declaring its output vocabulary in this gate first.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn tracked_files() -> Vec<String> {
    let out = Command::new("git")
        .args(["--no-optional-locks", "ls-files"])
        .current_dir(repo_root())
        .output()
        .expect("git ls-files must run (the repo is a git checkout)");
    assert!(out.status.success(), "git ls-files failed");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|s| s.to_string())
        .collect()
}

fn sha256_file(path: &Path) -> String {
    let bytes =
        std::fs::read(path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    frf::host::sha256_bytes(&bytes)
}

fn read_or_panic(root: &Path, rel: &str) -> Vec<u8> {
    std::fs::read(root.join(rel)).unwrap_or_else(|e| panic!("cannot read {rel}: {e}"))
}

/// The pinned artifact hashes from the v3 build manifest (rel -> sha256).
fn pinned_artifact_hashes() -> Vec<String> {
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(repo_root().join("external-corpus/v3/build/build-manifest.json"))
            .expect("build-manifest.json must exist"),
    )
    .expect("build-manifest.json must be valid JSON");
    manifest["artifacts"]
        .as_object()
        .expect("artifacts must be an object")
        .iter()
        // The log4shell launcher scripts (run-fixed.sh / run-vuln.sh) are
        // small tracked TEXT wrappers, not build products — deliberately
        // not in the prohibited set.
        .filter(|(rel, _)| !rel.starts_with("log4shell/builds/run-"))
        .map(|(_, v)| {
            v.as_str()
                .expect("artifact hash must be a string")
                .to_string()
        })
        .collect()
}

#[test]
fn no_prohibited_payload_is_tracked_anywhere() {
    let root = repo_root();
    let pins: HashSet<String> = pinned_artifact_hashes().into_iter().collect();
    assert!(!pins.is_empty(), "the manifest must pin artifacts");

    // The artifact directories must not be tracked at all.
    for dir in [
        "external-corpus/v3/heartbleed/builds",
        "external-corpus/v3/shellshock/builds",
        "external-corpus/v3/log4shell/builds/lib",
    ] {
        let tracked: Vec<String> = tracked_files()
            .into_iter()
            .filter(|f| f.starts_with(&format!("{dir}/")))
            .collect();
        assert!(
            tracked.is_empty(),
            "prohibited payload directory {dir} is TRACKED: {}",
            tracked.join(", ")
        );
    }
    let tracked_probe_jar: Vec<String> = tracked_files()
        .into_iter()
        .filter(|f| f == "external-corpus/v3/log4shell/builds/probe.jar")
        .collect();
    assert!(
        tracked_probe_jar.is_empty(),
        "the prohibited probe.jar is TRACKED"
    );

    // Every tracked file: a hash match anywhere is a forbidden payload.
    let mut offenders: Vec<String> = Vec::new();
    for rel in tracked_files() {
        if rel.contains("/target/") {
            continue;
        }
        let path = root.join(&rel);
        if !path.is_file() {
            continue;
        }
        let digest = sha256_file(&path);
        if pins.contains(&digest) {
            offenders.push(format!(
                "{rel} hashes to a pinned build product ({})",
                &digest[..16]
            ));
        }
        // Semantic stream gate: every published v3 captured stream must be an
        // exactly admissible value of its probe's output vocabulary (a raw
        // memory dump matches nothing), and a heartbleed run's stdout/stderr
        // pair must be cross-consistent. This replaces the old 4 KiB
        // byte-count heuristic: a dump that happens to be small was admitted
        // by the size check, and a legitimate large projection was refused.
        if let Some((probe, stream)) = probe_and_stream(&rel) {
            let bytes = read_or_panic(&root, &rel);
            assert_stream_admissible(&rel, probe, stream, &bytes);
            // The probe contract governs the REFERENCE side (always the real
            // fixed probe), so only there is cross-stream consistency
            // guaranteed. The mutation-challenge runs on the candidate side
            // are adversarial mutants that legitimately deviate (e.g. a
            // launcher script that prints the projection and exits 0).
            if probe == "heartbleed" && stream == "stdout" && rel.ends_with("reference.stdout") {
                check_hb_reference_consistency(&root, &rel, &bytes);
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "prohibited build-product payloads are tracked (the publication boundary is broken):\n{}",
        offenders.join("\n")
    );
}

/// A tracked path is a published v3 captured raw stream iff it lives under
/// `external-corpus/v3/<probe>/evidence/captures/` and ends in `.stdout` or
/// `.stderr` (the `*_first_line.txt` records are derived metadata, not raw
/// streams, and are deliberately not routed here).
fn probe_and_stream(rel: &str) -> Option<(&str, &str)> {
    let rest = rel.strip_prefix("external-corpus/v3/")?;
    if !rest.contains("/evidence/captures/") {
        return None;
    }
    let probe = rest.split('/').next()?;
    if rel.ends_with(".stdout") {
        Some((probe, "stdout"))
    } else if rel.ends_with(".stderr") {
        Some((probe, "stderr"))
    } else {
        None
    }
}

fn assert_stream_admissible(rel: &str, probe: &str, stream: &str, bytes: &[u8]) {
    let admissible = match (probe, stream) {
        ("heartbleed", "stdout") => hb_stdout_admissible(bytes),
        ("heartbleed", "stderr") => hb_stderr_admissible(bytes),
        ("goto-fail", "stdout") => gf_stdout_admissible(bytes),
        ("goto-fail", "stderr") => gf_stderr_admissible(bytes),
        ("log4shell", "stdout") => l4s_stdout_admissible(bytes),
        ("log4shell", "stderr") => l4s_stderr_admissible(bytes),
        (probe, _) => {
            panic!(
                "captured stream {rel} belongs to probe {probe}, which has no declared \
                 output vocabulary — the gate refuses streams it cannot semantically \
                 admit; declare {probe}'s vocabulary in this gate first"
            );
        }
    };
    assert!(
        admissible,
        "captured stream {rel} is NOT an admissible value of the {probe} probe's {stream} \
         output vocabulary — a raw process-memory dump must never be published"
    );
}

/// Within a heartbleed run, the REFERENCE side's stdout and stderr must agree
/// (hb.c prints both from the same `total`, and the reference is always the
/// real fixed probe — its contract is unconditional):
///
/// - projection `len=N`  <->  stderr `HEARTBLEED: ... echoed N bytes ...`;
/// - a clean stdout verdict <->  stderr empty.
///
/// The candidate side is deliberately NOT cross-checked: the mutation
/// challenge runs adversarial mutants (launcher scripts) that legitimately
/// deviate from the probe's stream contract, and the vocabulary gate above is
/// the candidate side's boundary.
fn check_hb_reference_consistency(root: &Path, stdout_rel: &str, stdout_bytes: &[u8]) {
    let stderr_rel = format!(
        "{}.stderr",
        &stdout_rel[..stdout_rel.len() - ".stdout".len()]
    );
    let stderr_bytes = read_or_panic(root, &stderr_rel);
    assert!(
        hb_reference_streams_consistent(stdout_bytes, &stderr_bytes),
        "run {stdout_rel}: the reference side's stdout/stderr pair violates the fixed \
         probe's contract — a clean verdict must pair with empty stderr, and a \
         projection's len must equal the stderr leak verdict's echoed byte count"
    );
}

/// The pure reference-contract decision: do a heartbleed reference side's
/// stdout and stderr agree (hb.c prints both from the same `total`)?
fn hb_reference_streams_consistent(stdout_bytes: &[u8], stderr_bytes: &[u8]) -> bool {
    if stdout_bytes.is_empty() {
        // Probe-failure run: stdout empty, stderr `hb: indeterminate (...)`.
        // The vocabulary gate is that case's boundary.
        return true;
    }
    // The trailing newline is guaranteed by admissibility.
    let stdout_line = &stdout_bytes[..stdout_bytes.len() - 1];
    if let Some(projection) = parse_hb_projection(stdout_line) {
        let echoed = hb_leak_echoed_count(&stderr_bytes[..stderr_bytes.len().saturating_sub(1)]);
        Some(projection.len) == echoed
    } else {
        // A clean stdout verdict must pair with empty stderr.
        stderr_bytes.is_empty()
    }
}

// ---------------------------------------------------------------------------
// The declared output vocabularies (the only values the probes can print).
// ---------------------------------------------------------------------------

fn is_decimal_digits(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.iter().all(u8::is_ascii_digit)
}

fn is_lower_hex(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn split_once<'a>(haystack: &'a [u8], needle: &'a [u8]) -> Option<(&'a [u8], &'a [u8])> {
    let pos = haystack.windows(needle.len()).position(|w| w == needle)?;
    Some((&haystack[..pos], &haystack[pos + needle.len()..]))
}

#[derive(Debug)]
struct HbProjection {
    len: u64,
}

/// Strictly parse the heartbleed leak-projection record
/// `hb-leak-projection len=N sha256=<64-hex> canary=present|absent fraction=F`
/// (hb.c line 555: `"hb-leak-projection len=%zu sha256=%s canary=%s fraction=%.2f"`).
fn parse_hb_projection(line: &[u8]) -> Option<HbProjection> {
    let rest = line.strip_prefix(b"hb-leak-projection ")?;
    let mut tokens = rest.split(|b| *b == b' ');
    let len = tokens.next()?.strip_prefix(b"len=")?;
    let sha = tokens.next()?.strip_prefix(b"sha256=")?;
    let canary = tokens.next()?.strip_prefix(b"canary=")?;
    let fraction = tokens.next()?.strip_prefix(b"fraction=")?;
    if tokens.next().is_some() {
        return None;
    }
    if !is_decimal_digits(len) {
        return None;
    }
    if sha.len() != 64 || !is_lower_hex(sha) {
        return None;
    }
    if canary != b"present" && canary != b"absent" {
        return None;
    }
    // `%.2f`: an integer part, a dot, and exactly two fraction digits.
    let (int, frac) = split_once(fraction, b".")?;
    if !is_decimal_digits(int) || frac.len() != 2 || !is_decimal_digits(frac) {
        return None;
    }
    let len = std::str::from_utf8(len).ok()?.parse().ok()?;
    Some(HbProjection { len })
}

/// Heartbleed stdout: the leak-projection record, one of the three clean
/// verdicts, or empty (probe-failure runs print nothing to stdout).
fn hb_stdout_admissible(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }
    if !bytes.ends_with(b"\n") {
        return false;
    }
    let line = &bytes[..bytes.len() - 1];
    if matches!(
        line,
        b"hb: no leak (malformed heartbeat silently discarded)"
            | b"hb: no leak (alert response)"
            | b"hb: no leak (connection closed without a heartbeat response)"
    ) {
        return true;
    }
    parse_hb_projection(line).is_some()
}

/// The echoed byte count of a `HEARTBLEED: the linked libssl echoed N bytes
/// in the heartbeat response` verdict line (hb.c line 559).
fn hb_leak_echoed_count(line: &[u8]) -> Option<u64> {
    let rest = line.strip_prefix(b"HEARTBLEED: the linked libssl echoed ")?;
    let rest = rest.strip_suffix(b" bytes in the heartbeat response")?;
    if !is_decimal_digits(rest) {
        return None;
    }
    std::str::from_utf8(rest).ok()?.parse().ok()
}

/// Heartbleed stderr: the leak verdict, the probe-failure verdict
/// (`hb: indeterminate (what)` — hb.c line 221, the only values are its own
/// failure reasons), or empty (fixed libraries print nothing).
fn hb_stderr_admissible(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }
    if !bytes.ends_with(b"\n") {
        return false;
    }
    let line = &bytes[..bytes.len() - 1];
    if hb_leak_echoed_count(line).is_some() {
        return true;
    }
    if let Some(rest) = line.strip_prefix(b"hb: indeterminate (") {
        return rest.ends_with(b")") && rest.len() > 1;
    }
    false
}

/// Goto-fail stdout: `tls: handshake accepted` (both the clean and the buggy
/// verifier print it — sslcheck.c lines 115/119) or empty.
fn gf_stdout_admissible(bytes: &[u8]) -> bool {
    bytes.is_empty() || bytes == b"tls: handshake accepted\n"
}

/// Goto-fail stderr: the signature-mismatch verdict, the malformed-record
/// error lines, or empty.
fn gf_stderr_admissible(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }
    if !bytes.ends_with(b"\n") {
        return false;
    }
    let line = &bytes[..bytes.len() - 1];
    if matches!(
        line,
        b"tls: no record file"
            | b"tls: cannot open record"
            | b"tls: missing signature, length, or data"
            | b"tls: malformed signature"
    ) {
        return true;
    }
    if let Some(rest) = line.strip_prefix(b"tls: length mismatch (declared ") {
        // `%ld` of a non-negative long, `%zu` of a strlen — decimal only.
        let Some((declared, got)) = rest
            .strip_suffix(b")")
            .and_then(|r| split_once(r, b", got "))
        else {
            return false;
        };
        return is_decimal_digits(declared) && is_decimal_digits(got);
    }
    if let Some(rest) = line.strip_prefix(b"tls: signature mismatch (got ") {
        // `got` is the record's lowercase-hex signature; `expected` is
        // `%02x` — exactly two lowercase hex digits (sslcheck.c line 105).
        let Some((got, expected)) = rest
            .strip_suffix(b")")
            .and_then(|r| split_once(r, b", expected "))
        else {
            return false;
        };
        return is_lower_hex(got) && expected.len() == 2 && is_lower_hex(expected);
    }
    false
}

/// Log4Shell stdout: the deterministic lookup verdict (Log4ShellProbe.java
/// lines 137-146) — exactly `JNDI_LOOKUP_NOT_ATTEMPTED` (no lookup was
/// attempted) or `JNDI_LOOKUP_ATTEMPTED` followed by the captured
/// StatusLogger diagnostic: the `Error looking up JNDI resource [uri].`
/// line and, when the throwable carried one, its summary
/// `javax.naming.CommunicationException: endpoint`. Every line is
/// newline-terminated; the uri is the lookup expression's target (no
/// newlines or brackets), the endpoint the resolved host:port.
fn l4s_stdout_admissible(bytes: &[u8]) -> bool {
    if bytes == b"JNDI_LOOKUP_NOT_ATTEMPTED\n" {
        return true;
    }
    let Some(rest) = bytes.strip_prefix(b"JNDI_LOOKUP_ATTEMPTED\n") else {
        return false;
    };
    let Some(rest) = rest.strip_prefix(b"Error looking up JNDI resource [") else {
        return false;
    };
    let Some(close) = rest.iter().position(|&b| b == b']') else {
        return false;
    };
    let (uri, after) = rest.split_at(close);
    let after = &after[1..]; // skip the ']'
    if uri.is_empty() || uri.contains(&b'\n') || uri.contains(&b'[') {
        return false;
    }
    let Some(after) = after.strip_prefix(b".\n") else {
        return false;
    };
    if after.is_empty() {
        return true;
    }
    // The optional throwable summary: `javax.naming.CommunicationException:
    // <endpoint>` — the resolved host:port (no newlines).
    let Some(endpoint) = after.strip_prefix(b"javax.naming.CommunicationException: ") else {
        return false;
    };
    let Some(endpoint) = endpoint.strip_suffix(b"\n") else {
        return false;
    };
    !endpoint.is_empty()
        && !endpoint.contains(&b'\n')
        && endpoint
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b':' | b'-' | b'_' | b'/'))
}

/// Log4Shell stderr: the logged message line — the ConsoleAppender writes
/// `%m%n` to SYSTEM_ERR (Log4ShellProbe.java), so stderr is exactly one
/// newline-terminated line whose content is the fixture-declared message
/// suffix. The constraint is the single-line shape: a multi-line stream
/// (any raw dump, any additional diagnostic) is refused.
fn l4s_stderr_admissible(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.ends_with(b"\n") && !bytes[..bytes.len() - 1].contains(&b'\n')
}

// ---------------------------------------------------------------------------
// Hostile tests: raw process memory must be refused by the vocabulary.
// ---------------------------------------------------------------------------

#[test]
fn hb_reference_consistency_refuses_contract_violations() {
    let clean = b"hb: no leak (malformed heartbeat silently discarded)\n";
    let projection = b"hb-leak-projection len=16384 sha256=1b55f3a15f98ec5342ae9f0e291268bb606a65ab41689cf3b6bebe9185001811 canary=present fraction=0.99\n";
    let verdict = b"HEARTBLEED: the linked libssl echoed 16384 bytes in the heartbeat response\n";
    assert!(hb_reference_streams_consistent(clean, b""));
    assert!(hb_reference_streams_consistent(projection, verdict));
    // A clean verdict paired with a leak verdict on stderr is impossible for
    // the real fixed probe (exit 0 prints nothing to stderr).
    assert!(!hb_reference_streams_consistent(clean, verdict));
    // A projection whose len disagrees with the echoed count is impossible
    // (hb.c prints both from the same `total`).
    let other = b"HEARTBLEED: the linked libssl echoed 8192 bytes in the heartbeat response\n";
    assert!(!hb_reference_streams_consistent(projection, other));
    // A projection with empty stderr is impossible for the probe.
    assert!(!hb_reference_streams_consistent(projection, b""));
    // Probe-failure runs (empty stdout) are the vocabulary gate's business.
    assert!(hb_reference_streams_consistent(
        b"",
        b"hb: indeterminate (connect)\n"
    ));
}

#[test]
fn heartbleed_stdout_refuses_raw_memory_dump() {
    // The canonical case the old size heuristic targeted: a 16384-byte blob
    // of process memory. It matches no admissible value.
    let dump = vec![b'A'; 16384];
    assert!(!hb_stdout_admissible(&dump));
    // A dump that merely appends a plausible-looking projection tail is
    // still refused — the whole stream must be one admissible value.
    let mut chunked = vec![0x90u8; 16384];
    chunked.extend_from_slice(b"hb-leak-projection len=16384");
    assert!(!hb_stdout_admissible(&chunked));
}

#[test]
#[should_panic(expected = "NOT an admissible value")]
fn raw_memory_dump_stream_is_refused_by_the_gate() {
    let dump = vec![b'A'; 16384];
    assert_stream_admissible(
        "external-corpus/v3/heartbleed/evidence/captures/run-x/candidate.stdout",
        "heartbleed",
        "stdout",
        &dump,
    );
}

#[test]
fn heartbleed_stdout_admits_large_legitimate_projection() {
    // The gate is semantic, not a byte-count heuristic: a legitimate
    // projection for a much larger leak is admitted.
    let line = b"hb-leak-projection len=1048576 sha256=1b55f3a15f98ec5342ae9f0e291268bb606a65ab41689cf3b6bebe9185001811 canary=present fraction=0.99\n";
    assert!(hb_stdout_admissible(line));
    // `%.2f` never prints a third fraction digit or a single one.
    let bad_fraction = b"hb-leak-projection len=16384 sha256=1b55f3a15f98ec5342ae9f0e291268bb606a65ab41689cf3b6bebe9185001811 canary=present fraction=0.995\n";
    assert!(!hb_stdout_admissible(bad_fraction));
    let bad_fraction = b"hb-leak-projection len=16384 sha256=1b55f3a15f98ec5342ae9f0e291268bb606a65ab41689cf3b6bebe9185001811 canary=present fraction=0.9\n";
    assert!(!hb_stdout_admissible(bad_fraction));
}

#[test]
fn heartbleed_stdout_refuses_malformed_projection_records() {
    let good_sha = "1b55f3a15f98ec5342ae9f0e291268bb606a65ab41689cf3b6bebe9185001811";
    let record = |sha: &str, canary: &str, fraction: &str| {
        format!("hb-leak-projection len=16384 sha256={sha} canary={canary} fraction={fraction}\n")
            .into_bytes()
    };
    assert!(hb_stdout_admissible(&record(good_sha, "present", "0.99")));
    assert!(hb_stdout_admissible(&record(good_sha, "absent", "0.00")));
    // sha256 must be exactly 64 lowercase hex characters.
    assert!(!hb_stdout_admissible(&record(
        &good_sha.to_uppercase(),
        "present",
        "0.99"
    )));
    assert!(!hb_stdout_admissible(&record(
        &good_sha[..63],
        "present",
        "0.99"
    )));
    assert!(!hb_stdout_admissible(&record(
        "zz55f3a15f98ec5342ae9f0e291268bb606a65ab41689cf3b6bebe9185001811",
        "present",
        "0.99"
    )));
    // canary is a closed vocabulary.
    assert!(!hb_stdout_admissible(&record(good_sha, "maybe", "0.99")));
    assert!(!hb_stdout_admissible(&record(good_sha, "Present", "0.99")));
    // len must be decimal digits.
    assert!(!hb_stdout_admissible(&record("0x4000", "present", "0.99")));
    // Tokens must be the four declared fields, in order, nothing extra.
    let extra = format!(
        "hb-leak-projection len=16384 sha256={good_sha} canary=present fraction=0.99 mode=leak\n"
    )
    .into_bytes();
    assert!(!hb_stdout_admissible(&extra));
    let missing = format!("hb-leak-projection len=16384 sha256={good_sha}\n").into_bytes();
    assert!(!hb_stdout_admissible(&missing));
    // A record without its trailing newline is not what the probe prints.
    let mut no_newline = record(good_sha, "present", "0.99");
    no_newline.pop();
    assert!(!hb_stdout_admissible(&no_newline));
}

#[test]
fn heartbleed_stdout_refuses_unknown_verdict() {
    assert!(hb_stdout_admissible(b"hb: no leak (alert response)\n"));
    assert!(hb_stdout_admissible(
        b"hb: no leak (connection closed without a heartbeat response)\n"
    ));
    assert!(hb_stdout_admissible(
        b"hb: no leak (malformed heartbeat silently discarded)\n"
    ));
    // The clean verdicts are a closed set — no other phrasing is admissible.
    assert!(!hb_stdout_admissible(b"hb: no leak (something invented)\n"));
    assert!(!hb_stdout_admissible(b"hb: no leak\n"));
    // A dump that embeds the exact verdict string is still refused: the
    // whole stream must BE the verdict, not merely contain it.
    assert!(!hb_stdout_admissible(
        b"hb: no leak (malformed heartbeat silently discarded)\x00\x01\x02\n"
    ));
    // Empty stdout is admissible (probe-failure runs print nothing).
    assert!(hb_stdout_admissible(b""));
}

#[test]
fn heartbleed_stderr_vocabulary() {
    assert!(hb_stderr_admissible(b""));
    assert!(hb_stderr_admissible(
        b"HEARTBLEED: the linked libssl echoed 16384 bytes in the heartbeat response\n"
    ));
    assert!(hb_stderr_admissible(b"hb: indeterminate (connect)\n"));
    assert!(hb_stderr_admissible(
        b"hb: indeterminate (cannot load the embedded certificate)\n"
    ));
    // A memory dump on stderr is refused.
    assert!(!hb_stderr_admissible(&vec![0x90u8; 16384]));
    // The echoed count must be decimal digits.
    assert!(!hb_stderr_admissible(
        b"HEARTBLEED: the linked libssl echoed -16384 bytes in the heartbeat response\n"
    ));
    assert!(!hb_stderr_admissible(
        b"HEARTBLEED: the linked libssl echoed 0x4000 bytes in the heartbeat response\n"
    ));
    assert!(!hb_stderr_admissible(
        b"HEARTBLEED: the linked libssl echoed bytes in the heartbeat response\n"
    ));
    // The verdict is the exact phrase.
    assert!(!hb_stderr_admissible(
        b"HEARTBLEED: the linked libssl echoed 16384 bytes in the heartbeet response\n"
    ));
    assert!(!hb_stderr_admissible(b"HEARTBLEED\n"));
    // The probe-failure verdict needs a non-empty reason.
    assert!(!hb_stderr_admissible(b"hb: indeterminate ()\n"));
    assert!(!hb_stderr_admissible(b"hb: indeterminate\n"));
}

#[test]
fn heartbleed_projection_and_verdict_counts_agree() {
    let projection = parse_hb_projection(
        b"hb-leak-projection len=16384 sha256=1b55f3a15f98ec5342ae9f0e291268bb606a65ab41689cf3b6bebe9185001811 canary=present fraction=0.99",
    )
    .expect("the projection must parse");
    let echoed = hb_leak_echoed_count(
        b"HEARTBLEED: the linked libssl echoed 16384 bytes in the heartbeat response",
    )
    .expect("the verdict must parse");
    assert_eq!(projection.len, echoed);
}

#[test]
fn goto_fail_stdout_vocabulary() {
    assert!(gf_stdout_admissible(b""));
    assert!(gf_stdout_admissible(b"tls: handshake accepted\n"));
    // The probe always prints the trailing newline.
    assert!(!gf_stdout_admissible(b"tls: handshake accepted"));
    // A dump is refused.
    assert!(!gf_stdout_admissible(&vec![b'x'; 4096]));
    assert!(!gf_stdout_admissible(
        b"tls: handshake accepted\n\x00\x01\x02\n"
    ));
}

#[test]
fn goto_fail_stderr_vocabulary() {
    assert!(gf_stderr_admissible(b""));
    assert!(gf_stderr_admissible(
        b"tls: signature mismatch (got 71, expected 14)\n"
    ));
    assert!(gf_stderr_admissible(
        b"tls: signature mismatch (got deadbeef, expected 14)\n"
    ));
    assert!(gf_stderr_admissible(b"tls: no record file\n"));
    assert!(gf_stderr_admissible(b"tls: cannot open record\n"));
    assert!(gf_stderr_admissible(
        b"tls: missing signature, length, or data\n"
    ));
    assert!(gf_stderr_admissible(
        b"tls: length mismatch (declared 5, got 3)\n"
    ));
    assert!(gf_stderr_admissible(b"tls: malformed signature\n"));
    // A dump is refused.
    assert!(!gf_stderr_admissible(&vec![0u8; 8192]));
    // `got` must be lowercase hex and `expected` exactly two hex digits.
    assert!(!gf_stderr_admissible(
        b"tls: signature mismatch (got zz, expected 14)\n"
    ));
    assert!(!gf_stderr_admissible(
        b"tls: signature mismatch (got 71, expected 1)\n"
    ));
    assert!(!gf_stderr_admissible(
        b"tls: signature mismatch (got 71, expected 014)\n"
    ));
    assert!(!gf_stderr_admissible(
        b"tls: signature mismatch (got 71, expected 1F)\n"
    ));
    // Lengths must be decimal.
    assert!(!gf_stderr_admissible(
        b"tls: length mismatch (declared 5, got 0x3)\n"
    ));
    assert!(!gf_stderr_admissible(
        b"tls: length mismatch (declared -5, got 3)\n"
    ));
    // The error lines are a closed set.
    assert!(!gf_stderr_admissible(b"tls: something new\n"));
}

#[test]
fn log4shell_stdout_vocabulary() {
    // The two deterministic verdict shapes.
    assert!(l4s_stdout_admissible(b"JNDI_LOOKUP_NOT_ATTEMPTED\n"));
    assert!(l4s_stdout_admissible(
        b"JNDI_LOOKUP_ATTEMPTED\nError looking up JNDI resource [ldap://127.0.0.1:1/a].\njavax.naming.CommunicationException: 127.0.0.1:1\n"
    ));
    // The diagnostic line alone (a throwable-less diagnostic) is admissible.
    assert!(l4s_stdout_admissible(
        b"JNDI_LOOKUP_ATTEMPTED\nError looking up JNDI resource [ldap://127.0.0.1:1/a].\n"
    ));
    // A raw dump is refused: the verdict line is exact, not a prefix.
    assert!(!l4s_stdout_admissible(
        b"JNDI_LOOKUP_NOT_ATTEMPTED\n\x00\x01\x02\n"
    ));
    assert!(!l4s_stdout_admissible(&vec![b'J'; 16384]));
    assert!(!l4s_stdout_admissible(b"JNDI_LOOKUP_ATTEMPTED\n"));
    // The verdicts are a closed set.
    assert!(!l4s_stdout_admissible(b"JNDI_LOOKUP_INTERRUPTED\n"));
    assert!(!l4s_stdout_admissible(b"JNDI_LOOKUP_NOT_ATTEMPTED")); // no trailing newline
                                                                   // The diagnostic line is the probe's exact phrasing with a bracketed uri.
    assert!(!l4s_stdout_admissible(
        b"JNDI_LOOKUP_ATTEMPTED\nError looking up JNDI resource ldap://127.0.0.1:1/a.\n"
    ));
    assert!(!l4s_stdout_admissible(
        b"JNDI_LOOKUP_ATTEMPTED\nError looking up JNDI resource [ldap://127.0.0.1:1/a]\n"
    ));
    assert!(!l4s_stdout_admissible(
        b"JNDI_LOOKUP_ATTEMPTED\nError looking up JNDI resource [].\n"
    ));
    // A nested or multiline uri is refused.
    assert!(!l4s_stdout_admissible(
        b"JNDI_LOOKUP_ATTEMPTED\nError looking up JNDI resource [a[b]].\n"
    ));
    // The throwable summary is the exact class + a single-line endpoint.
    assert!(!l4s_stdout_admissible(
        b"JNDI_LOOKUP_ATTEMPTED\nError looking up JNDI resource [ldap://127.0.0.1:1/a].\njava.io.IOException: boom\n"
    ));
    assert!(!l4s_stdout_admissible(
        b"JNDI_LOOKUP_ATTEMPTED\nError looking up JNDI resource [ldap://127.0.0.1:1/a].\njavax.naming.CommunicationException: \n"
    ));
}

#[test]
fn log4shell_stderr_vocabulary() {
    // The logged message line (single line, newline-terminated).
    assert!(l4s_stderr_admissible(
        b"connectivity check ${jndi:ldap://127.0.0.1:1/a}\n"
    ));
    assert!(l4s_stderr_admissible(b"nnectivity check ok\n"));
    // A multi-line stream (any raw dump, any extra diagnostic) is refused.
    assert!(!l4s_stderr_admissible(&vec![0x90u8; 8192]));
    assert!(!l4s_stderr_admissible(
        b"connectivity check ${jndi:ldap://127.0.0.1:1/a}\n\x00\x01\n"
    ));
    assert!(!l4s_stderr_admissible(b""));
    assert!(!l4s_stderr_admissible(b"no trailing newline"));
}

#[test]
#[should_panic(expected = "no declared output vocabulary")]
fn unknown_probe_captures_are_refused_fail_closed() {
    assert_stream_admissible(
        "external-corpus/v3/shellshock/evidence/captures/run-x/candidate.stdout",
        "shellshock",
        "stdout",
        b"",
    );
}
