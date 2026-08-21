//! Canonical FRF object model (v0 subset).
//!
//! Invariants stated before code:
//! - Authority ids are `{name}-{version}`, safe path components, unique in a store.
//! - A residual observation record is immutable once written by the court: it
//!   never changes epistemic meaning after observation. Dispositions are
//!   append-only events under `residuals/<id>.events/`; the current
//!   disposition is the projection of the last event, and `open` is the
//!   projection of no events. Nothing is ever rewritten in place.
//! - A `fixed` closure requires a `resolution_run_id` and the `closure_predicate`
//!   that was verified against it — a court run, under an explicit comparability
//!   predicate, whose captures show the residual no longer reproduces. A
//!   disposition can never substitute for new evidence, and no representable
//!   state lets a human promote a claim by changing a label.
//! - A positive parity claim is compiled only from a receipt whose run actually
//!   observed the axis passing; a receipt that observed divergence can never be
//!   turned into a parity receipt, however its residuals are disposed.
//! - Raw captures and receipts are written once and never rewritten.
//!
//! Field names and shapes follow Section 10, Section 12, and Appendix A of
//! *The Forensic Residual Framework* (de Beer, 2026). v0 additions beyond the
//! paper's minimal snippets (traceability fields such as `authority`, `scope`,
//! per-axis hashes, the mandatory `reason`, and the candidate artifact hash)
//! are documented in the README.

use serde::{Deserialize, Serialize};
use std::fmt;

pub const SCHEMA_AUTHORITY: &str = "frf-authority-v1";
/// Capture schema. v6 removes the repetition context from the run entirely:
/// a run knows nothing about which experiment later references it (v5's
/// `repeat_index`/`repeat_count` moved to the ExecutionSeries protocol
/// object). A run's identity is the observation, nothing else. v7 declares
/// the run's outgoing EVIDENCE REFERENCES ([`EvidenceRef`]) — the typed
/// edges the bundle closure walks (authority/candidate/fixture objects and
/// every external comparator implementation), so the closure traversal is
/// generic instead of special-casing a fixed artifact list. v8 binds the
/// EXECUTION PROFILE: which reference execution contract observed the run
/// (`execution_profile` + the applied `capture_bounds`), so exact replay can
/// require the same bounds and the receipt never guesses what the harness
/// actually enforced. v9 binds the sides' PRODUCED ARTIFACTS (the
/// filesystem-tree surface): when the court declares `produce`, each side's
/// output directory is walked after execution and captured immutably —
/// every produced file is copied under the run, hashed, and recorded in the
/// side capture, so a court observes what its sides BUILD, not only what
/// they print.
pub const SCHEMA_CAPTURE: &str = "frf-capture-v10";
pub const SCHEMA_RESIDUAL: &str = "frf-residual-v1";
/// Disposition event schema. v2 makes events content-addressed: every event
/// carries its own `event_id` (SHA-256 of its content), its
/// `parent_event_id` (the hash chain link), and `evidence_refs` (the
/// resolution run for a `fixed` closure).
pub const SCHEMA_DISPOSITION: &str = "frf-disposition-v2";
/// The OpenReceipt schema. v6 carried the interpreter CHAIN; v7 added the
/// fixture's DECLARED arguments (the semantic identity's input); v8 binds
/// each residual to the exact disposition EVENT that supplied its
/// disposition (`disposition_event_id`) — a receipt points at an immutable
/// event in the hash-chained history, it does not merely copy state. v9
/// pins each residual's sign to the exact ExecutionSeries snapshot it was
/// derived from (per coordinate system — `sign.trajectory_evidence`), so
/// later experiments that reference the
/// same content-addressed run can never change what a receipt means. v10
/// makes the comparator layer OBSERVABLE-PLUGGABLE: observable ids and
/// residual kinds become open protocol identifiers (no closed enum), each
/// comparator semantic carries its extractor and residual classifier (its
/// specification hash REDERIVES from its own fields), external
/// implementations record their artifact identity, and an externally served
/// observable binds the exact comparator request/result records that
/// produced its verdict. v11 binds the EXECUTION PROFILE: which reference
/// execution contract observed the run and the exact capture bounds that
/// applied (timeout, stream caps, resource limits) — an observation is
/// made under a declared harness contract, and exact replay requires the
/// same one. v12 replaces the single drift/slew/series sign with
/// TRAJECTORY EVIDENCE: a residual does not have one universal drift — it
/// has a trajectory with respect to a coordinate system, and the receipt
/// entry carries one entry per coordinate system the run participates in
/// (`sign.trajectory_evidence`), each pinning the exact ExecutionSeries
/// snapshot the drift/slew were derived from. The body is serialized as
/// canonical JSON (RFC 8785) and its identity is the full SHA-256 of those
/// bytes.
pub const SCHEMA_RECEIPT: &str = "frf-receipt-v13";
/// Claim schema. v2 carries the full Claim IR: the structured scope K, the
/// blocking residuals, the premise receipts (`requires`), the comparison
/// relation, and the machine proposition — admission is the paper's rule
/// `Scope(K) ⊆ Scope(P₁ ∪ … ∪ Pₙ)`, implemented literally. v3 binds the
/// EVIDENCE UNIVERSE the claim's absence search ran over
/// ([`KnowledgeSnapshot`]): a claim is admissible relative to an explicitly
/// committed state of knowledge — no unresolved residual IN U intersects K —
/// and the compiled claim carries U's content address, so the negative
/// search (not merely the positive premises) is portable and reproducible
/// by any implementation.
pub const SCHEMA_CLAIM: &str = "frf-claim-v3";
/// Runner identity block recorded in every capture at court time.
pub const SCHEMA_RUNNER: &str = "frf-runner-v1";
/// Environment identity block recorded in every capture at court time. v2
/// expands the strata the digest covers: os, architecture, kernel release,
/// effective locale, timezone, and umask (the dimensions that actually move
/// side output), plus the recorded working directory.
pub const SCHEMA_ENVIRONMENT: &str = "frf-environment-v2";
/// Observation provenance block (runner + comparator + normalizer + adapter
/// implementations). v3 records the normalizer and capture-adapter
/// implementations that applied to the compared streams/observations.
pub const SCHEMA_PROVENANCE: &str = "frf-provenance-v3";

/// The reference execution profile: the normative contract the reference
/// engine executes under (`spec/execution-profile.md`). v1 (linux): direct
/// exec (no shell), each side in its own process group with group
/// termination on exit/timeout/overflow, concurrent pipe draining, bounded
/// spawn retries, a 60 s execution timeout, 16 MiB stdout/stderr capture
/// caps (overflow REFUSES the run — truncated output is never evidence),
/// and child resource limits (2 GiB address space, 30 CPU-seconds, 1024
/// open files). An observation is made under a declared harness contract;
/// exact replay requires the same profile and the same applied bounds.
pub const EXECUTION_PROFILE_LINUX: &str = "frf-exec-linux-v1";

/// The token grammar schema (Section 6 of the paper).
pub const TOKEN_SCHEMA_VERSION: &str = "frf-token-v1";

/// Court-challenge schema: the negative-control evidence object. A court
/// run that yields a pass proves nothing unless the court has demonstrated
/// it can SEE the defect classes it declares: the challenge seeds a mutant
/// candidate (a deterministic wrapper of the admitted reference artifact
/// that alters exactly one observable dimension) and records whether the
/// court observed a divergence on the targeted axis and only on it. The
/// identity covers the DECLARED evidence (court, operator, targeted axis,
/// the reference artifact, the mutant artifact, the mutant run); the
/// verdicts (`saw_defect`, `specificity_clean`, `observed_residuals`) are
/// DERIVED from the run and recomputed by verification, never trusted from
/// the file.
pub const SCHEMA_CHALLENGE: &str = "frf-challenge-v1";

/// The capture bounds that actually applied to a court's executions — the
/// execution profile's parameters as enforced (the profile's defaults, or
/// the test hooks' overrides). Recorded at observation time so a receipt
/// never guesses what the harness bounded. All values are STRINGS: the
/// OpenReceipt canonical value domain has no numbers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureBounds {
    /// Milliseconds until a side is killed (the profile's timeout).
    pub timeout_ms: String,
    /// Maximum bytes retained per output stream; a side that exceeds it is
    /// killed and the run REFUSED (truncated output is never evidence).
    pub max_stream_bytes: String,
    /// Address-space limit of each side, in MiB (RLIMIT_AS).
    pub rlimit_as_mb: String,
    /// CPU-time limit of each side, in seconds (RLIMIT_CPU).
    pub rlimit_cpu_s: String,
    /// Open-file limit of each side (RLIMIT_NOFILE).
    pub rlimit_nofile: String,
}

/// The protocol's maxima for the capture bounds — a receipt can never claim
/// the harness enforced an unbounded or absurd contract.
pub const CAPTURE_BOUND_MAX_TIMEOUT_MS: u64 = 3_600_000; // 1 hour
pub const CAPTURE_BOUND_MAX_STREAM_BYTES: u64 = 1 << 30; // 1 GiB
pub const CAPTURE_BOUND_MAX_RLIMIT_AS_MB: u64 = 65_536; // 64 GiB
pub const CAPTURE_BOUND_MAX_RLIMIT_CPU_S: u64 = 86_400; // 1 day
pub const CAPTURE_BOUND_MAX_RLIMIT_NOFILE: u64 = 1_048_576;

/// Validate capture bounds: positive integers within the protocol's maxima.
pub fn validate_capture_bounds(b: &CaptureBounds) -> crate::error::Result<()> {
    for (what, v, max) in [
        ("timeout_ms", &b.timeout_ms, CAPTURE_BOUND_MAX_TIMEOUT_MS),
        (
            "max_stream_bytes",
            &b.max_stream_bytes,
            CAPTURE_BOUND_MAX_STREAM_BYTES,
        ),
        (
            "rlimit_as_mb",
            &b.rlimit_as_mb,
            CAPTURE_BOUND_MAX_RLIMIT_AS_MB,
        ),
        (
            "rlimit_cpu_s",
            &b.rlimit_cpu_s,
            CAPTURE_BOUND_MAX_RLIMIT_CPU_S,
        ),
        (
            "rlimit_nofile",
            &b.rlimit_nofile,
            CAPTURE_BOUND_MAX_RLIMIT_NOFILE,
        ),
    ] {
        let n: u64 = v.parse().map_err(|_| {
            crate::error::FrfError::new(format!(
                "capture bound {what} must be a positive integer, got {v:?}"
            ))
        })?;
        if n == 0 {
            return Err(crate::error::FrfError::new(format!(
                "capture bound {what} must be positive, got 0"
            )));
        }
        if n > max {
            return Err(crate::error::FrfError::new(format!(
                "capture bound {what} = {n} exceeds the protocol maximum {max}"
            )));
        }
    }
    Ok(())
}

/// Bundle manifest schema (OpenReceipt bundle: the receipt + its portable
/// object closure — see `spec/openreceipt.md`). v2 closure: the admitted
/// authority record is part of the evidence graph the receipt cites, so it
/// is included as an `authority` inventory entry, and the capture's typed
/// EVIDENCE REFERENCES
/// drive the object closure (authority/candidate/fixture snapshots AND every
/// external comparator implementation) — adding an evidence kind needs no
/// closure-walker edit. v3 declares the bundle's own CONTAINER form
/// (`directory` or `single-tar`): the same manifest + closure layout is the
/// protocol, whether it lives as a tree of files or sealed as one
/// deterministic tar archive with the manifest inside.
pub const SCHEMA_BUNDLE: &str = "frf-bundle-v3";

/// The bundle container forms. A bundle is the same evidence graph either
/// way: a `directory` tree, or a `single-tar` archive carrying the identical
/// layout (manifest.json at its root). The manifest declares its own
/// container, and a verifier refuses a mismatch (a directory whose manifest
/// claims to be a tar, or vice versa).
pub const BUNDLE_CONTAINER_DIRECTORY: &str = "directory";
pub const BUNDLE_CONTAINER_SINGLE_TAR: &str = "single-tar";

/// Residual trajectory schema v2: the trajectory's SUBJECT is the residual
/// LINEAGE identity (stable across candidate revisions, authority versions,
/// environments, and time — `FRF/RESIDUAL-LINEAGE/v1`), not the exact
/// observation fingerprint; each observation records the exact fingerprint
/// it saw. Trajectories are DERIVED from an [`ExecutionSeries`] — a run
/// never knows which experiment references it.
pub const SCHEMA_TRAJECTORY: &str = "frf-trajectory-v2";

/// The ExecutionSeries protocol object: the experiment. One chain per
/// (court, coordinate system); points are appended by series courts
/// (`--repeat`, `--candidate-revisions`, `--authority-versions`,
/// `--environment-point`, `--time-point`). v2 makes series snapshots
/// content-addressed and parent-linked: every snapshot carries its own
/// content address (`FRF/SERIES/v2`), its stable `experiment_id`, and its
/// `parent_series_id` — an immutable append history, so an append can never
/// silently fork the experiment, and branching becomes visible (a second
/// head refuses an implicit append). A run never carries series membership
/// — the series references the runs, and multiple coordinates may reference
/// the same content-addressed run.
pub const SCHEMA_SERIES: &str = "frf-series-v2";

/// The comparator extension protocol (spec/comparator.md): a canonical
/// JSON request a court writes to an external comparator program's stdin,
/// and the canonical JSON response it must produce on stdout. v2 adds
/// `request_id` to the RESPONSE: the SHA-256 of the exact canonical request
/// bytes the comparator received, so a response cryptographically names the
/// request it answers (the court refuses a response that does not). v3
/// carries the sides' PRODUCED ARTIFACT TREES in the request context (the
/// filesystem-tree surface): when the court declares `produce`, the request
/// delivers each side's produced-file manifest (paths + content hashes), so
/// an external comparator can compare what the sides BUILT, not only what
/// they printed.
pub const SCHEMA_COMPARATOR_REQUEST: &str = "frf-comparator-request-v4";
pub const SCHEMA_COMPARATOR_RESPONSE: &str = "frf-comparator-response-v2";

/// The normalizer extension protocol (spec/normalizer.md): a canonical JSON
/// request a court writes to an external normalizer program's stdin (one
/// side's raw streams, base64) and the canonical JSON response it must
/// produce on stdout (the normalized streams). The response must
/// cryptographically name the request it answers (`request_id`), and a
/// normalizer declared to touch only one stream must leave the other
/// byte-identical (fail closed). The normalized streams are what the court
/// COMPARES; the raw streams survive as the request evidence, so an
/// observation is never rewritten.
pub const SCHEMA_NORMALIZER_REQUEST: &str = "frf-normalizer-request-v1";
pub const SCHEMA_NORMALIZER_RESPONSE: &str = "frf-normalizer-response-v1";
pub const SCHEMA_NORMALIZER_INVOCATION: &str = "frf-normalizer-invocation-v1";
pub const SCHEMA_NORMALIZER_RESULT: &str = "frf-normalizer-result-v1";

/// The minimizer extension protocol (spec/minimizer.md): a canonical JSON
/// request to an external minimizer (the residual + the original fixture,
/// base64) and the canonical JSON response (a proposed reduced fixture). The
/// core COURT-VERIFIES every proposal by re-running the court and requiring
/// the residual's lineage to survive; proposals that do not survive are
/// recorded but never accepted.
pub const SCHEMA_MINIMIZER_REQUEST: &str = "frf-minimizer-request-v1";
pub const SCHEMA_MINIMIZER_RESPONSE: &str = "frf-minimizer-response-v1";
pub const SCHEMA_MINIMIZER_INVOCATION: &str = "frf-minimizer-invocation-v1";
pub const SCHEMA_MINIMIZER_RESULT: &str = "frf-minimizer-result-v1";

/// The capture-adapter extension protocol (spec/capture-adapter.md): a
/// canonical JSON request to an external capture-adapter (one side's raw
/// outcome) and the canonical JSON response (the ADAPTED observation for the
/// axis the adapter serves — e.g. the DNS wire bytes a server emitted, a
/// database state dump, a terminal frame). The adapted observation is what
/// the axis's external comparator receives; the raw outcome survives as the
/// request evidence. An adapted axis MUST be served by an external
/// comparator.
pub const SCHEMA_CAPTURE_ADAPTER_REQUEST: &str = "frf-capture-request-v1";
pub const SCHEMA_CAPTURE_ADAPTER_RESPONSE: &str = "frf-capture-response-v1";
pub const SCHEMA_CAPTURE_ADAPTER_INVOCATION: &str = "frf-capture-invocation-v1";
pub const SCHEMA_CAPTURE_ADAPTER_RESULT: &str = "frf-capture-result-v1";

/// The witness extension protocol (spec/witness.md): a canonical JSON request
/// to an external witness program (a content-addressed subject + a statement
/// to attest) and the canonical JSON response (the attestation, or an
/// explicit refusal). The attestation is recorded in a content-addressed
/// [`WitnessStatement`] with the canonical request/response preserved as
/// evidence.
pub const SCHEMA_WITNESS_REQUEST: &str = "frf-witness-request-v1";
pub const SCHEMA_WITNESS_RESPONSE: &str = "frf-witness-response-v1";
pub const SCHEMA_WITNESS_STATEMENT: &str = "frf-witness-statement-v1";

/// Versions of the extension RELATION lines. Bump whenever a relation's
/// semantics change; implementation changes alone never do (the program
/// bytes are the implementation identity).
pub const NORMALIZER_VERSION: &str = "v1";
pub const MINIMIZER_VERSION: &str = "v1";
pub const CAPTURE_ADAPTER_VERSION: &str = "v1";
pub const WITNESS_VERSION: &str = "v1";

// ---------------------------------------------------------------------------
// The normalizer extension protocol (spec/normalizer.md)
// ---------------------------------------------------------------------------

/// The semantic identity of a normalizer relation: WHAT the mapping is, not
/// which implementation ran it. The record carries the full specification
/// next to its hash, so the specification hash REDERIVES from the record's
/// own fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizerSemantic {
    pub id: String,
    pub relation_id: String,
    /// `stdout` | `stderr` | `both`.
    pub applies_to: String,
    pub relation_version: String,
    /// SHA-256 of the canonical normalizer specification document
    /// (`FRF/NORMALIZER-SPEC/v1`).
    pub specification_hash: String,
}

/// Which implementation of a normalizer applied to a run's streams. Always an
/// EXTERNAL program in v0; its artifact identity is the exact snapshotted
/// bytes + interpreter it ran under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizerImplementation {
    pub id: String,
    pub implementation_hash: String,
    pub runner_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact: Option<ArtifactIdentity>,
}

/// The normalizer REQUEST (court → normalizer, stdin, canonical JSON): ONE
/// side's raw streams; the response returns the normalized streams.
#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizerRequest<'a> {
    pub schema_version: &'static str,
    pub normalizer: &'a NormalizerSemantic,
    /// `reference` | `candidate`.
    pub side: &'a str,
    pub stdout_base64: String,
    pub stderr_base64: String,
    pub context: NormalizerContext<'a>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizerContext<'a> {
    pub fixture_sha256: &'a str,
    pub arguments: &'a [String],
    pub environment_digest: &'a str,
}

/// The normalizer RESPONSE (normalizer → court, stdout, canonical JSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizerResponse {
    pub schema_version: String,
    /// SHA-256 of the exact canonical request bytes the normalizer received.
    pub request_id: String,
    pub stdout_base64: String,
    pub stderr_base64: String,
    pub indeterminate: bool,
    pub failure: Option<String>,
}

/// The normalizer INVOCATION evidence record: what was invoked, against
/// which request, by which implementation, under which runner — written at
/// court time under `captures/<run>/normalizer/<id>/<side>/invocation.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizerInvocation {
    pub schema_version: String,
    pub invocation_id: String,
    pub normalizer_id: String,
    pub side: String,
    pub request_cid: String,
    pub normalizer_semantic_cid: String,
    pub normalizer_implementation_artifact: ArtifactIdentity,
    pub execution_provenance: RunnerIdentity,
}

/// The normalizer RESULT evidence record: which request the response
/// answered, the response document's content address, and the normalized
/// streams' hashes. Content-addressed (`FRF/NORMALIZER-RESULT/v1`): the
/// `result_id` rederives from the record's own fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizerResult {
    pub schema_version: String,
    /// Content address: `FRF/NORMALIZER-RESULT/v1` over the record's fields.
    pub result_id: String,
    pub invocation_id: String,
    pub request_cid: String,
    pub response_cid: String,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub outcome: String,
}

// ---------------------------------------------------------------------------
// The minimizer extension protocol (spec/minimizer.md)
// ---------------------------------------------------------------------------

/// The semantic identity of a minimizer relation: WHAT the reduction
/// strategy is, not which implementation ran it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MinimizerSemantic {
    pub id: String,
    pub relation_id: String,
    pub relation_version: String,
    pub specification_hash: String,
}

/// Which implementation of a minimizer reduced a residual's fixture. Always
/// an EXTERNAL program in v0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MinimizerImplementation {
    pub id: String,
    pub implementation_hash: String,
    pub runner_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact: Option<ArtifactIdentity>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MinimizerRequest<'a> {
    pub schema_version: &'static str,
    pub minimizer: &'a MinimizerSemantic,
    pub residual: MinimizerResidual<'a>,
    pub fixture: MinimizerFixture<'a>,
    /// The proposal budget the core will accept (decimal string — the
    /// canonical value domain admits strings, not numbers).
    pub budget: String,
    pub context: MinimizerContext<'a>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MinimizerResidual<'a> {
    pub id: &'a str,
    pub axis: &'a str,
    pub kind: &'a str,
    pub authority: &'a str,
    pub candidate_sha256: &'a str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MinimizerFixture<'a> {
    pub sha256: &'a str,
    pub raw_base64: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MinimizerContext<'a> {
    pub court_semantic_identity: &'a str,
    pub environment_digest: &'a str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MinimizerResponse {
    pub schema_version: String,
    /// SHA-256 of the exact canonical request bytes the minimizer received.
    pub request_id: String,
    /// The proposed reduced fixture (base64) + its SHA-256. The core
    /// court-verifies it before acceptance.
    pub fixture_sha256: String,
    pub fixture_base64: String,
    /// Whether the minimizer claims it proved minimality within the budget.
    pub minimal: bool,
    /// The minimizer's own attempt log (the core records which survived
    /// court verification).
    pub attempts: Vec<MinimizerAttempt>,
    pub indeterminate: bool,
    pub failure: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MinimizerAttempt {
    pub attempt: u32,
    pub fixture_sha256: String,
    pub kept: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MinimizerInvocation {
    pub schema_version: String,
    pub invocation_id: String,
    pub minimizer_id: String,
    pub residual_id: String,
    pub request_cid: String,
    pub minimizer_semantic_cid: String,
    pub minimizer_implementation_artifact: ArtifactIdentity,
    pub execution_provenance: RunnerIdentity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MinimizerResult {
    pub schema_version: String,
    /// Content address: `FRF/MINIMIZER-RESULT/v1` over the record's fields.
    pub result_id: String,
    pub invocation_id: String,
    pub request_cid: String,
    pub response_cid: String,
    pub proposed_fixture_sha256: String,
    /// Whether the proposed fixture survived COURT VERIFICATION.
    pub court_verified: bool,
    pub outcome: String,
}

// ---------------------------------------------------------------------------
// The capture-adapter extension protocol (spec/capture-adapter.md)
// ---------------------------------------------------------------------------

/// The semantic identity of a capture adapter relation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureAdapterSemantic {
    /// The observable axis the adapter serves.
    pub id: String,
    pub relation_id: String,
    pub relation_version: String,
    pub specification_hash: String,
}

/// Which implementation of a capture adapter observed a run. Always an
/// EXTERNAL program in v0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureAdapterImplementation {
    pub id: String,
    pub implementation_hash: String,
    pub runner_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact: Option<ArtifactIdentity>,
}

/// An ADAPTED observation: the capture adapter's output for one side, what
/// the axis's external comparator receives. `content_sha256` is the byte
/// identity of the payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdaptedObservation {
    /// The payload's declared format (e.g. `dns-wire`, `sql-dump`, `utf-8`).
    pub format: String,
    pub payload_base64: String,
    pub content_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureAdapterRequest<'a> {
    pub schema_version: &'static str,
    pub adapter: &'a CaptureAdapterSemantic,
    /// `reference` | `candidate`.
    pub side: &'a str,
    pub outcome: CaptureAdapterOutcome<'a>,
    pub context: NormalizerContext<'a>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureAdapterOutcome<'a> {
    pub exit: &'a str,
    pub stdout_base64: String,
    pub stderr_base64: String,
    /// The side's produced-tree manifest, when the court declares `produce`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub produced: Option<&'a ProducedContext<'a>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureAdapterResponse {
    pub schema_version: String,
    /// SHA-256 of the exact canonical request bytes the adapter received.
    pub request_id: String,
    /// The adapted observation, or `None` when the adapter declines.
    pub observation: Option<AdaptedObservation>,
    pub indeterminate: bool,
    pub failure: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureAdapterInvocation {
    pub schema_version: String,
    pub invocation_id: String,
    pub axis: String,
    pub side: String,
    pub request_cid: String,
    pub adapter_semantic_cid: String,
    pub adapter_implementation_artifact: ArtifactIdentity,
    pub execution_provenance: RunnerIdentity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureAdapterResult {
    pub schema_version: String,
    /// Content address: `FRF/CAPTURE-ADAPTER-RESULT/v1` over the record's
    /// fields.
    pub result_id: String,
    pub invocation_id: String,
    pub request_cid: String,
    pub response_cid: String,
    pub observation_sha256: String,
    pub outcome: String,
}

// ---------------------------------------------------------------------------
// The witness extension protocol (spec/witness.md)
// ---------------------------------------------------------------------------

/// The semantic identity of a witness relation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessSemantic {
    pub id: String,
    pub relation_id: String,
    pub relation_version: String,
    pub specification_hash: String,
}

/// Which implementation of a witness attested. Always an EXTERNAL program in
/// v0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessImplementation {
    pub id: String,
    pub implementation_hash: String,
    pub runner_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact: Option<ArtifactIdentity>,
}

/// The subject a witness attests to: a content-addressed evidence object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessSubject {
    /// `run` | `receipt` | `residual`.
    pub kind: String,
    pub id: String,
    /// The subject's content address (the run identity digest, the receipt
    /// digest, or the residual fingerprint).
    pub cid: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessRequest<'a> {
    pub schema_version: &'static str,
    pub witness: &'a WitnessSemantic,
    pub subject: &'a WitnessSubject,
    pub statement: &'a str,
    pub context: WitnessContext<'a>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessContext<'a> {
    pub evidence_root: &'a str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessResponse {
    pub schema_version: String,
    pub request_id: String,
    pub attestation: Option<WitnessAttestation>,
    pub indeterminate: bool,
    pub failure: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessAttestation {
    /// The exact statement the witness attests (must equal the request's).
    pub statement: String,
    pub verified: bool,
    pub detail: String,
}

/// The content-addressed [`WitnessStatement`] record: an independent
/// attestation bound to a content-addressed subject, with the canonical
/// request/response preserved as evidence. Identity: SHA-256 of
/// `FRF/WITNESS-STATEMENT/v1` over the record's fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessStatement {
    pub schema_version: String,
    pub id: String,
    pub subject: WitnessSubject,
    pub witness_semantic: WitnessSemantic,
    pub witness_implementation: WitnessImplementation,
    pub statement: String,
    pub attestation: WitnessAttestation,
    pub request_cid: String,
    pub response_cid: String,
    pub created_by: RunnerIdentity,
}

/// The produced-artifact observation schema: one side's output tree as a
/// canonical manifest (relative path → content hash + executable flag). The
/// manifest's SHA-256 is the tree's observation identity; the raw files are
/// copied under the run directory and rehashed by verification.
pub const SCHEMA_PRODUCED: &str = "frf-produced-v1";

/// The comparator INVOCATION evidence record: what was invoked, against
/// which request, by which implementation, under which runner — written at
/// court time under `captures/<run>/comparator/<axis>/invocation.json` and
/// verified on every read. Content-addressed (`FRF/COMPARATOR-INVOCATION/v1`).
pub const SCHEMA_COMPARATOR_INVOCATION: &str = "frf-comparator-invocation-v1";

/// The comparator RESULT evidence record: which request the response
/// answered, the response document's content address, the interpreted
/// outcome, and the residual observations the invocation produced — written
/// at court time under `captures/<run>/comparator/<axis>/result.json`.
/// Content-addressed (`FRF/COMPARATOR-RESULT/v1`).
pub const SCHEMA_COMPARATOR_RESULT: &str = "frf-comparator-result-v1";

// ---------------------------------------------------------------------------
// Observable axes + residual kinds (protocol identifiers)
// ---------------------------------------------------------------------------

/// The protocol identifier grammar shared by observable ids and residual
/// kinds: lowercase ASCII letter first, then lowercase letters, digits, `.`,
/// `_`, `-`; 1..=64 characters. This is the *only* vocabulary the protocol
/// admits, because these values become claim scopes, token strings, and
/// directory names (comparator evidence lives under `captures/<run>/
/// comparator/<axis>/`).
pub(crate) fn validate_identifier(what: &str, s: &str) -> std::result::Result<(), String> {
    if s.is_empty() {
        return Err(format!("{what} must not be empty"));
    }
    if s.len() > 64 {
        return Err(format!("{what} '{s}' is too long: at most 64 characters"));
    }
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => {
            return Err(format!(
                "invalid {what} '{s}': must start with a lowercase letter"
            ))
        }
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
    {
        return Err(format!(
            "invalid {what} '{s}': letters, digits, '.', '_', '-' only (lowercase)"
        ));
    }
    Ok(())
}

/// An observable axis id — an opaque, validated protocol identifier, NOT a
/// closed Rust enum. The reference engine ships three in-binary comparators
/// (`exit`, `stderr`, `stdout` — see [`crate::comparators`]), but any valid
/// id (`dns.wire`, `filesystem.tree`, `tzif.bytes`, …) can be declared and
/// served by an external comparator through the extension protocol: the
/// evidence core runs observables without knowing what stdout, packets, or
/// filesystem trees are.
///
/// Built-ins keep strongly typed helpers ([`ObservableId::exit`] etc.); the
/// comparison itself lives in the comparator registry, keyed on the id.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObservableId(String);

impl ObservableId {
    /// The built-in `exit` observable.
    pub fn exit() -> Self {
        ObservableId("exit".to_string())
    }

    /// The built-in `stderr` observable.
    pub fn stderr() -> Self {
        ObservableId("stderr".to_string())
    }

    /// The built-in `stdout` observable.
    pub fn stdout() -> Self {
        ObservableId("stdout".to_string())
    }

    /// Validate + construct an observable id. Refuses ids outside the
    /// protocol grammar (see [`validate_identifier`]).
    pub fn parse(s: &str) -> crate::error::Result<Self> {
        validate_identifier("observable id", s).map_err(crate::error::FrfError::new)?;
        Ok(ObservableId(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Is this one of the three in-binary built-ins?
    pub fn is_builtin(&self) -> bool {
        matches!(self.0.as_str(), "exit" | "stderr" | "stdout")
    }
}

impl fmt::Display for ObservableId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for ObservableId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ObservableId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        validate_identifier("observable id", &s).map_err(serde::de::Error::custom)?;
        Ok(ObservableId(s))
    }
}

/// A residual kind — an extensible semantic identifier, not a closed enum.
/// The built-in classifiers are `exit` (the exit axis) and `text` (the
/// stderr/stdout axes); an external comparator's declaration names its own
/// classifier, and every residual on that axis carries the classifier's
/// kind. The kind is part of the residual fingerprint, the lineage, and the
/// residual id (`cli-{kind}-{seq}`), so a new kind is a new residual class,
/// never a silent reinterpretation of an old one.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ResidualKind(String);

impl ResidualKind {
    /// The `exit` residual kind (the exit axis's classifier).
    pub fn exit() -> Self {
        ResidualKind("exit".to_string())
    }

    /// The `text` residual kind (the stderr/stdout axes' classifier).
    pub fn text() -> Self {
        ResidualKind("text".to_string())
    }

    /// Validate + construct a residual kind from a comparator's declared
    /// residual classifier.
    pub fn parse(s: &str) -> crate::error::Result<Self> {
        validate_identifier("residual kind", s).map_err(crate::error::FrfError::new)?;
        Ok(ResidualKind(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Residual ids are `{domain}-{kind}-{seq}`; v0 courts are CLI courts, so
    /// the domain prefix is `cli` (matching Section 12's `cli-exit-*`).
    pub fn domain_prefix(&self) -> &'static str {
        "cli"
    }
}

impl fmt::Display for ResidualKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for ResidualKind {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ResidualKind {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        validate_identifier("residual kind", &s).map_err(serde::de::Error::custom)?;
        Ok(ResidualKind(s))
    }
}

// ---------------------------------------------------------------------------
// Disposition
// ---------------------------------------------------------------------------

/// Closure kinds a developer may record. `open` is the initial state and is
/// not settable; `unknown` and `harness` closures still block positive claims
/// (the claim compiler's refusal rule). `fixed` is deliberately absent here:
/// it is not a label, it is a [`Disposition::Fixed`] carrying its resolution
/// run, so it cannot be spelled as a bare kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ClosureKind {
    Intentional,
    Environmental,
    OracleVersion,
    Harness,
    Unknown,
}

impl ClosureKind {
    pub const ALL: [ClosureKind; 5] = [
        ClosureKind::Intentional,
        ClosureKind::Environmental,
        ClosureKind::OracleVersion,
        ClosureKind::Harness,
        ClosureKind::Unknown,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            ClosureKind::Intentional => "intentional",
            ClosureKind::Environmental => "environmental",
            ClosureKind::OracleVersion => "oracle_version",
            ClosureKind::Harness => "harness",
            ClosureKind::Unknown => "unknown",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        ClosureKind::ALL.iter().copied().find(|k| k.as_str() == s)
    }

    /// Does a residual closed this way still block a positive claim?
    /// (Claim compiler rule: `open`, `unknown`, and `harness` block.)
    pub const fn blocks_claim(self) -> bool {
        matches!(self, ClosureKind::Harness | ClosureKind::Unknown)
    }
}

/// The closure predicate a `fixed` disposition must have verified: the
/// resolution run reran the same question under the same envelope, holding
/// everything stable except the candidate, and the axis now agrees.
pub const CLOSURE_PREDICATE_FIX_COURT: &str = "fix-court: same court, authority, fixture, arguments, observables, normalizers, environment; axis equality";

/// Residual disposition with the invariants enforced by construction:
/// - `Open` carries no reason.
/// - every `Closed` carries a non-empty one-line reason;
/// - `Fixed` carries a reason, the `resolution_run_id` of the court run whose
///   captures show the residual no longer reproduces, and the
///   `closure_predicate` that was verified against that run.
///
/// There is no representable "fixed without evidence" state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposition {
    Open,
    Closed {
        kind: ClosureKind,
        reason: String,
    },
    Fixed {
        reason: String,
        resolution_run_id: String,
        closure_predicate: String,
    },
}

impl Disposition {
    pub fn as_str(&self) -> &'static str {
        match self {
            Disposition::Open => "open",
            Disposition::Closed { kind, .. } => kind.as_str(),
            Disposition::Fixed { .. } => "fixed",
        }
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            Disposition::Open => None,
            Disposition::Closed { reason, .. } => Some(reason),
            Disposition::Fixed { reason, .. } => Some(reason),
        }
    }

    /// The resolution run backing a `fixed` closure, if any.
    pub fn resolution_run_id(&self) -> Option<&str> {
        match self {
            Disposition::Fixed {
                resolution_run_id, ..
            } => Some(resolution_run_id),
            _ => None,
        }
    }

    pub fn is_blocking(&self) -> bool {
        match self {
            Disposition::Open => true,
            Disposition::Closed { kind, .. } => kind.blocks_claim(),
            Disposition::Fixed { .. } => false,
        }
    }
}

impl fmt::Display for Disposition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// `Disposition` serializes as `disposition: <status>` with a sibling
// `reason:` key exactly when closed, and a `resolution_run_id:` key exactly
// when fixed — the Appendix A / Section 12 shape:
//
//   disposition: open
//   disposition: intentional
//   reason: "clearer diagnostic wording"
//   disposition: fixed
//   reason: "candidate patched to match reference exit class"
//   resolution_run_id: run-cli-malformed-input-…
//
// The custom impl exists so the forbidden states are unrepresentable even in
// YAML: `open` cannot carry a reason, a non-fixed closure cannot carry a
// resolution_run_id, and `fixed` cannot omit one.
impl Serialize for Disposition {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(None)?;
        match self {
            Disposition::Open => {
                map.serialize_entry("disposition", "open")?;
            }
            Disposition::Closed { kind, reason } => {
                map.serialize_entry("disposition", kind.as_str())?;
                map.serialize_entry("reason", reason)?;
            }
            Disposition::Fixed {
                reason,
                resolution_run_id,
                closure_predicate,
            } => {
                map.serialize_entry("disposition", "fixed")?;
                map.serialize_entry("reason", reason)?;
                map.serialize_entry("resolution_run_id", resolution_run_id)?;
                map.serialize_entry("closure_predicate", closure_predicate)?;
            }
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for Disposition {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{Error as _, MapAccess, Visitor};
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Disposition;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a disposition map with optional reason")
            }
            fn visit_map<A>(self, mut map: A) -> Result<Disposition, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut status: Option<String> = None;
                let mut reason: Option<String> = None;
                let mut resolution_run_id: Option<String> = None;
                let mut closure_predicate: Option<String> = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "disposition" => status = Some(map.next_value()?),
                        "reason" => reason = Some(map.next_value()?),
                        "resolution_run_id" => resolution_run_id = Some(map.next_value()?),
                        "closure_predicate" => closure_predicate = Some(map.next_value()?),
                        // Unknown keys are ignored so the flattened map can be
                        // consumed in any field order.
                        _ => {
                            let _: serde_yaml::Value = map.next_value()?;
                        }
                    }
                }
                let status = status.ok_or_else(|| A::Error::missing_field("disposition"))?;
                match status.as_str() {
                    "open" => {
                        if reason.is_some()
                            || resolution_run_id.is_some()
                            || closure_predicate.is_some()
                        {
                            return Err(A::Error::custom(
                                "disposition 'open' cannot carry a reason, resolution_run_id, or closure_predicate",
                            ));
                        }
                        Ok(Disposition::Open)
                    }
                    "fixed" => {
                        let reason = reason.ok_or_else(|| {
                            A::Error::custom("disposition 'fixed' requires a one-line reason")
                        })?;
                        let resolution_run_id = resolution_run_id.ok_or_else(|| {
                            A::Error::custom(
                                "disposition 'fixed' requires a resolution_run_id (a disposition is not evidence)",
                            )
                        })?;
                        let closure_predicate = closure_predicate.ok_or_else(|| {
                            A::Error::custom("disposition 'fixed' requires a closure_predicate")
                        })?;
                        if reason.trim().is_empty() {
                            return Err(A::Error::custom("reason must not be empty"));
                        }
                        if resolution_run_id.trim().is_empty() {
                            return Err(A::Error::custom("resolution_run_id must not be empty"));
                        }
                        if closure_predicate.trim().is_empty() {
                            return Err(A::Error::custom("closure_predicate must not be empty"));
                        }
                        Ok(Disposition::Fixed {
                            reason,
                            resolution_run_id,
                            closure_predicate,
                        })
                    }
                    other => {
                        let kind = ClosureKind::parse(other).ok_or_else(|| {
                            A::Error::custom(format!("unknown disposition '{other}'"))
                        })?;
                        if resolution_run_id.is_some() || closure_predicate.is_some() {
                            return Err(A::Error::custom(format!(
                                "only 'fixed' may carry a resolution_run_id or closure_predicate, not '{other}'"
                            )));
                        }
                        let reason = reason.ok_or_else(|| {
                            A::Error::custom(format!(
                                "disposition '{other}' requires a one-line reason"
                            ))
                        })?;
                        if reason.trim().is_empty() {
                            return Err(A::Error::custom("reason must not be empty"));
                        }
                        Ok(Disposition::Closed { kind, reason })
                    }
                }
            }
        }
        deserializer.deserialize_map(V)
    }
}

// ---------------------------------------------------------------------------
// Authority
// ---------------------------------------------------------------------------

/// Authority admission record (Section 12 shape, plus `name` and `path`
/// required by the build brief). Written once by `frf authority admit`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorityRecord {
    pub schema_version: String,
    /// `{name}-{version}` — the id cited by courts and receipts.
    pub id: String,
    pub name: String,
    /// v0 admits `executable_reference` only (Appendix A spelling).
    pub kind: String,
    pub version: String,
    /// SHA-256 of the executable bytes at admission time.
    pub executable_sha256: String,
    /// Working-directory-relative path admitted.
    pub path: String,
    /// `{arch}-{os}` (Section 12: `x86_64-linux`).
    pub platform: String,
}

// ---------------------------------------------------------------------------
// Court manifest (hand-authored declaration)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CourtManifest {
    pub court: CourtSpec,
    /// Optional comparator declarations (the extension protocol): an
    /// observable axis served by an EXTERNAL program instead of the in-binary
    /// registry. The declaration's relation/extractor/version define the
    /// comparator's SEMANTIC identity (specification hash); the program's
    /// bytes define its IMPLEMENTATION identity. Absent = the in-binary
    /// registry serves every declared observable.
    #[serde(default)]
    pub comparators: Vec<ComparatorDeclaration>,
    /// Optional normalizer declarations (the extension protocol): programs
    /// applied to both sides' raw streams BEFORE comparison. The envelope's
    /// `normalizers` list names exactly which declared normalizers are
    /// APPLIED, in order.
    #[serde(default)]
    pub normalizers: Vec<NormalizerDeclaration>,
    /// Optional minimizer declarations (the extension protocol): external
    /// reducers serving κ routes.
    #[serde(default)]
    pub minimizers: Vec<MinimizerDeclaration>,
    /// Optional capture-adapter declarations (the extension protocol):
    /// external programs that capture the observation for an externally
    /// served axis.
    #[serde(default)]
    pub capture_adapters: Vec<CaptureAdapterDeclaration>,
}

/// One external comparator declaration in a court manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComparatorDeclaration {
    /// The observable axis this comparator serves (must be declared in the
    /// envelope's observables).
    pub axis: String,
    /// Relation family (Section 10, Δ_a) — part of the semantic identity.
    pub relation: String,
    /// What the comparator extracts and compares — part of the semantic
    /// identity. A compliant implementation MUST honor it: the residual raw
    /// values (and therefore the fingerprints) follow the extractor.
    pub extractor: String,
    /// The residual kind every divergence on this axis is classified as —
    /// part of the semantic identity (the classifier is in the specification
    /// document). `exit` for the exit axis, `text` for stderr/stdout; an
    /// axis-specific kind (`wire`, `tree`, …) for a domain comparator.
    pub residual_classifier: String,
    pub relation_version: String,
    /// Working-directory-relative path to the comparator program. The court
    /// hashes its bytes BEFORE executing (snapshotted, sealed, re-hashed on
    /// use) and records the hash as the comparator's implementation identity.
    pub program: String,
}

/// One external normalizer declaration in a court manifest (the extension
/// protocol, spec/normalizer.md). Normalizers apply to BOTH sides' raw
/// streams BEFORE the compared projections are extracted; the raw streams
/// survive as the request evidence, so an observation is never rewritten.
/// The declaration's relation/applies_to/version define the SEMANTIC
/// identity; the program's bytes define its IMPLEMENTATION identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizerDeclaration {
    /// The normalizer id (e.g. `stderr-trailing-ws`). The envelope's
    /// `normalizers` list names exactly the ids that are APPLIED, in order.
    pub id: String,
    /// The mapping family (e.g. `trim-trailing-whitespace`) — part of the
    /// semantic identity.
    pub relation: String,
    /// Which streams the normalizer is declared to touch: `stdout`, `stderr`,
    /// or `both`. The untouched stream must come back byte-identical or the
    /// court refuses.
    pub applies_to: String,
    pub relation_version: String,
    /// Working-directory-relative path to the normalizer program. Read +
    /// hashed BEFORE execution, executed through a content-addressed
    /// snapshot, re-hashed on every use.
    pub program: String,
}

/// One external minimizer declaration in a court manifest (the extension
/// protocol, spec/minimizer.md). The id is the κ route it serves
/// (`cli-exit-minimize`, `cli-diagnostic-minimize`, or a domain route);
/// `frf court minimize` consults the residual's capture for a declared
/// minimizer matching the residual's route and uses it (court-verifying
/// every proposal) instead of the built-in ddmin reducer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MinimizerDeclaration {
    /// The κ route id this minimizer serves.
    pub id: String,
    /// The reduction strategy family (e.g. `ddmin-lines`, `argv-elimination`)
    /// — part of the semantic identity.
    pub relation: String,
    pub relation_version: String,
    /// Working-directory-relative path to the minimizer program.
    pub program: String,
}

/// One external capture-adapter declaration in a court manifest (the
/// extension protocol, spec/capture-adapter.md). The adapter captures the
/// observation for one externally served axis — the side's raw outcome in,
/// the ADAPTED observation out — so the core can observe surfaces it has no
/// built-in capture for (dns.wire, sql.schema, terminal.frame, …).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureAdapterDeclaration {
    /// The observable axis this adapter serves (must be declared in the
    /// envelope AND served by an external comparator).
    pub axis: String,
    /// The capture relation family (e.g. `dns-wire-dump`) — part of the
    /// semantic identity.
    pub relation: String,
    pub relation_version: String,
    /// Working-directory-relative path to the adapter program.
    pub program: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CourtSpec {
    pub id: String,
    pub question: String,
    pub falsifier: String,
    /// Admitted authority id (Section 12: `ref-cli-1.8.2`).
    pub authority: String,
    pub candidate: CandidateSpec,
    pub fixture: FixtureSpec,
    pub admissibility_envelope: AdmissibilityEnvelope,
    /// The produced-artifact clause: the sides write their OUTPUT to this
    /// directory (working-directory-relative, transient — cleared between
    /// sides and captured immutably into the run), and the harness observes
    /// the produced tree (the filesystem-tree surface). Absent = the sides
    /// are observed through their streams only.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub produce: Option<ProduceSpec>,
}

/// The produced-artifact clause. v0: one output directory per side,
/// walked recursively after execution; every produced file is copied under
/// the run, hashed, and recorded in the side capture. Symlinks are refused
/// (a hostile or careless side cannot smuggle a link outside its output).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProduceSpec {
    /// The output root each side writes (working-directory-relative, or
    /// relative to the side's working directory under replay; the literal
    /// `{output}` in the fixture arguments substitutes to this path).
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateSpec {
    pub name: String,
    pub version_or_commit: String,
    pub build_profile: String,
    /// Working-directory-relative path to the candidate executable.
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureSpec {
    pub id: String,
    /// Working-directory-relative path to the fixture file.
    pub path: String,
    /// Arguments; the literal `{fixture}` is replaced with the fixture path.
    pub arguments: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissibilityEnvelope {
    pub fixture_family: String,
    pub platforms: Vec<String>,
    pub observables: Vec<String>,
    pub normalizers: Vec<String>,
    pub replay_scope: String,
}

// ---------------------------------------------------------------------------
// Raw capture
// ---------------------------------------------------------------------------

/// A typed outgoing reference from one evidence object to another — the edge
/// of the evidence graph. Every content-addressed object a run's evidence
/// depends on is declared here at capture time, and the bundle closure walks
/// these refs instead of special-casing a fixed artifact list: adding a
/// comparator implementation, a witness, a normalizer, or a minimization run
/// no longer requires editing the closure walker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRef {
    /// Why the reference exists (e.g. `authority-artifact`,
    /// `candidate-artifact`, `fixture-object`, `comparator-implementation`).
    pub role: String,
    /// What kind of object is referenced (`object` = a content-addressed
    /// executable/data snapshot under `objects/sha256/`).
    pub object_kind: String,
    /// The content address: the SHA-256 the object is named by.
    pub cid: String,
}

/// Self-contained record of one court run: the raw bytes of both sides plus
/// the snapshot of the court declaration, so a receipt can be re-derived
/// without the original manifest file.
///
/// v3 separates the two questions an observation answers: WHAT question was
/// asked ([`CaptureManifest::court_semantic_identity`], built from
/// comparator *semantic* identities and artifact hashes) and WHO asked it
/// ([`CaptureManifest::provenance`], the runner and comparator
/// *implementations*). Everything is bound at observation time — a receipt
/// emitted later copies it, never reconstructs it from whatever binary or
/// host happens to be present.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureManifest {
    pub schema_version: String,
    pub run: String,
    pub court: String,
    pub authority: String,
    pub manifest: String,
    pub fixture: String,
    pub fixture_sha256: String,
    pub arguments: Vec<String>,
    /// The environment the observation happened in, captured at court time.
    pub environment: EnvironmentIdentity,
    pub court_spec: CourtSpec,
    /// The comparator relations applied (semantic identity of the question).
    pub comparator_semantics: Vec<ComparatorSemantic>,
    /// The normalizer relations applied to the compared streams, in
    /// application order. Empty when the court declares no normalizers.
    #[serde(default)]
    pub normalizer_semantics: Vec<NormalizerSemantic>,
    /// The capture adapters applied, per adapted axis. Empty when the court
    /// declares no adapters.
    #[serde(default)]
    pub adapter_semantics: Vec<CaptureAdapterSemantic>,
    /// The minimizers declared by the court (the extension protocol): the κ
    /// routes an external reducer serves, bound at observation time so
    /// `frf court minimize` can resolve them without the original manifest.
    #[serde(default)]
    pub minimizer_semantics: Vec<MinimizerSemantic>,
    /// The runner + comparator implementations that observed the run.
    pub provenance: ObservationProvenance,
    /// The admitted reference artifact, snapshotted and executed.
    pub authority_artifact: ArtifactIdentity,
    /// The candidate artifact, snapshotted and executed.
    pub candidate_artifact: ArtifactIdentity,
    /// Content hash of everything defining the evidentiary question
    /// (see [`crate::semantics::court_semantic_identity`]) — the key a
    /// resolution run must reproduce, except the candidate.
    pub court_semantic_identity: String,
    /// The execution profile the run was observed under (the harness
    /// contract, see [`EXECUTION_PROFILE_LINUX`] and
    /// `spec/execution-profile.md`).
    pub execution_profile: String,
    /// The capture bounds that actually applied (the profile's defaults or
    /// the overrides in force).
    pub capture_bounds: CaptureBounds,
    pub reference: SideCapture,
    pub candidate: SideCapture,
    pub residuals: Vec<String>,
    /// The run's outgoing evidence references: the authority, candidate, and
    /// fixture objects plus every external comparator implementation object.
    /// The bundle closure walks these (the generic graph traversal); a
    /// capture from an earlier version with no refs remains loadable (the
    /// closure walker falls back to the recorded artifact hashes).
    #[serde(default)]
    pub evidence_refs: Vec<EvidenceRef>,
}

/// Who executed the court. `frf_executable_hash` is the SHA-256 of the frf
/// binary itself: the comparators, normalizers, and endoduction are code in
/// that executable, so this one hash binds all their implementations at
/// observation time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerIdentity {
    pub schema_version: String,
    pub frf_version: String,
    pub frf_executable_hash: String,
}

/// Version of the comparator RELATIONS in this executable. Bump this
/// whenever a comparator's semantics change (never reuse a name with new
/// meaning under the old version). Implementation changes alone do NOT bump
/// it: the runner executable hash catches those. v2 adds the residual
/// classifier to the specification document (a semantic change: the
/// specification hash covers it).
pub const COMPARATOR_VERSION: &str = "v2";

/// The semantic identity of a comparator relation: WHAT the relation is, not
/// which implementation ran it. Two independent implementations with the
/// same `specification_hash` ask the same question; their different
/// executable bytes do not change the question.
///
/// The record carries the FULL specification (id, relation, extractor,
/// residual classifier) next to its hash, so the specification hash
/// REDERIVES from the record's own fields — a receipt cannot claim a
/// specification its own comparator semantics do not hash to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComparatorSemantic {
    /// The observable axis id this comparator serves (exit/stderr/stdout,
    /// or any valid protocol identifier for an external comparator).
    pub id: String,
    /// The relation family (Section 10, Δ_a): `eq`.
    pub relation_id: String,
    /// What the comparator extracts and compares (part of the specification
    /// document, hence of the specification hash).
    pub extractor: String,
    /// The residual kind this comparator classifies divergences as (part of
    /// the specification document, hence of the specification hash).
    pub residual_classifier: String,
    /// Bumped whenever the RELATION's semantics change (never reuse a name
    /// with new meaning under the old version).
    pub relation_version: String,
    /// SHA-256 of the comparator's canonical specification document
    /// (id + relation + extractor + residual_classifier), see
    /// [`crate::comparators`].
    pub specification_hash: String,
}

impl ComparatorSemantic {
    /// The human-readable comparison relation label recorded in an
    /// observable block: `eq(stderr-first-line)`.
    pub fn relation_label(&self) -> String {
        format!("{}({})", self.relation_id, self.extractor)
    }
}

/// Which implementation of a comparator observed the run. For in-binary
/// comparators both hashes are the runner executable hash; an external
/// comparator plugin carries its own implementation hash.
///
/// v0.1.23: an external comparator also records its ARTIFACT identity (the
/// exact snapshotted bytes + interpreter it ran under), so replay can
/// re-invoke the exact instrument and the bundle closure can carry it — the
/// same `ArtifactIdentity` discipline used for candidates and authorities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComparatorImplementation {
    pub id: String,
    pub implementation_hash: String,
    pub runner_hash: String,
    /// Present iff the axis was served by an EXTERNAL comparator program:
    /// the content-addressed snapshot it executed under (root-relative path,
    /// sha256, interpreter chain). Absent for in-binary comparators, which
    /// are implemented by the frf executable itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact: Option<ArtifactIdentity>,
}

/// Observation provenance: the runner and the comparator implementations
/// that produced a capture. Bound at court time; a stricter reproducibility
/// policy may require equal provenance on top of equal semantic identity.
/// v3 adds the normalizer implementations applied to the compared streams,
/// the capture-adapter implementations that produced adapted observations,
/// and the minimizer implementations bound for `frf court minimize`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationProvenance {
    pub schema_version: String,
    pub runner: RunnerIdentity,
    pub comparator_implementations: Vec<ComparatorImplementation>,
    /// The normalizer implementations applied to the compared streams, in
    /// application order. Empty when the court declares no normalizers.
    #[serde(default)]
    pub normalizer_implementations: Vec<NormalizerImplementation>,
    /// The capture-adapter implementations that produced adapted
    /// observations, per adapted axis. Empty when the court declares no
    /// adapters.
    #[serde(default)]
    pub adapter_implementations: Vec<CaptureAdapterImplementation>,
    /// The minimizer implementations the court bound for `court minimize`
    /// (one per declared κ route), snapshotted at observation time so the
    /// exact reducer is re-invokable without the original manifest. Empty
    /// when the court declares no minimizers.
    #[serde(default)]
    pub minimizer_implementations: Vec<MinimizerImplementation>,
}

/// The environment an observation happened in, captured at court time. The
/// receipt copies it verbatim — it never asks its own host what environment
/// an old court ran under.
///
/// v2: the digest now covers the strata that actually move side output —
/// os, architecture, kernel release, the effective locale, the timezone, and
/// the umask — plus the recorded working directory the sides ran under
/// (`cwd` is recorded, not digested: it is an invocation property, and the
/// observation's own bytes already capture its effects; exact replay gates
/// on it separately).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentIdentity {
    pub schema_version: String,
    pub os: String,
    pub architecture: String,
    pub kernel_release: String,
    /// The effective locale the sides ran under: `LC_ALL` / `LC_CTYPE` /
    /// `LANG`, or `C`.
    pub locale: String,
    /// The timezone the sides ran under: `TZ`, or the resolved system zone
    /// (from /etc/localtime), or `unknown`.
    pub timezone: String,
    /// The umask at observation time, as octal digits (e.g. `0022`).
    pub umask: String,
    /// The working directory the sides ran under (recorded provenance; exact
    /// replay requires the same cwd).
    pub cwd: String,
    pub digest: String,
}

/// One step of an interpreter chain: an executable, resolved + hashed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterpreterExecutable {
    /// Resolved, canonicalized absolute path.
    pub path: String,
    pub sha256: String,
}

/// The env(1) resolver, present when the kernel interpreter is env.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterpreterResolver {
    pub kind: String,
    pub path: String,
    pub sha256: String,
    /// Digest of $PATH at observation time — the search space the resolver
    /// would use to find the downstream interpreter.
    pub path_digest: String,
}

/// The interpreter chain of a script artifact: WHAT the kernel directly
/// invoked (`kernel_interpreter`), the raw shebang argument bytes (verbatim
/// evidence, even where v0 does not execute them), the env resolver when
/// present, and the actual language interpreter (`downstream_interpreter`).
/// For a script, "the exact artifact" is bytes + this chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterpreterIdentity {
    /// What execve(2) actually ran first (e.g. `/usr/bin/env`, `/bin/sh`).
    pub kernel_interpreter: InterpreterExecutable,
    /// The raw shebang argument bytes after the interpreter token, verbatim
    /// (`-S python3 -O`, `FOO=bar python3`, …) — recorded as evidence even
    /// though v0 does not execute them itself.
    pub shebang_argument_bytes: String,
    /// Present iff the kernel interpreter is env(1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolver: Option<InterpreterResolver>,
    /// The actual language interpreter the script runs under.
    pub downstream_interpreter: InterpreterExecutable,
}

/// A content-addressed execution object: the exact bytes a run executed,
/// materialized under `objects/sha256/<H>` BEFORE execution, so hashing and
/// executing can never observe different bytes (no TOCTOU window). Objects
/// are verified on every use and sealed read-only after materialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactIdentity {
    /// The snapshot path this run actually executed (root-relative).
    pub path: String,
    pub sha256: String,
    /// Present when the artifact is a script with a resolvable shebang.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interpreter: Option<InterpreterIdentity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SideCapture {
    /// Exit code as a string, or `signal(<n>)` if terminated by a signal.
    pub exit: String,
    pub exit_sha256: String,
    /// First stderr line (the stderr axis compares exactly this).
    pub stderr_first_line: String,
    pub stderr_first_line_sha256: String,
    /// First stdout line (the stdout axis compares exactly this).
    pub stdout_first_line: String,
    pub stdout_first_line_sha256: String,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    /// The produced-artifact tree this side wrote (when the court declares
    /// `produce`): every produced file's path + content hash. The raw files
    /// are copied under the run directory and rehashed by verification.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub produced: Option<ProducedSide>,
    /// The ADAPTED observation (capture-adapter protocol): the adapter's
    /// output for this side, when an adapter serves the axis. The raw
    /// streams remain the request evidence; the adapted payload is what the
    /// comparator compares.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub adapted: Option<AdaptedObservation>,
    /// The raw stdout bytes, retained IN MEMORY ONLY (never serialized — the
    /// raw stream already lives as a capture file; the domain comparators
    /// that parse it need the bytes, not just the hash). Excluded from
    /// equality: the captured document defaults it to empty on load, and the
    /// content identity is the recorded `stdout_sha256`.
    #[serde(skip_serializing, default)]
    pub stdout_bytes: Vec<u8>,
}

impl PartialEq for SideCapture {
    /// The observed surface equality — every serialized field. The raw
    /// stdout BYTES are not part of it (they are not serialized, and the
    /// captured document loads with them empty); the recorded `stdout_sha256`
    /// is the byte identity and IS compared.
    fn eq(&self, other: &Self) -> bool {
        self.exit == other.exit
            && self.exit_sha256 == other.exit_sha256
            && self.stderr_first_line == other.stderr_first_line
            && self.stderr_first_line_sha256 == other.stderr_first_line_sha256
            && self.stdout_first_line == other.stdout_first_line
            && self.stdout_first_line_sha256 == other.stdout_first_line_sha256
            && self.stdout_sha256 == other.stdout_sha256
            && self.stderr_sha256 == other.stderr_sha256
            && self.produced == other.produced
            && self.adapted == other.adapted
    }
}

impl Eq for SideCapture {}

impl SideCapture {
    /// The raw stdout bytes (the domain comparators' input).
    pub fn stdout(&self) -> &[u8] {
        &self.stdout_bytes
    }
}

/// One produced file: relative path, content hash, executable flag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProducedFile {
    pub path: String,
    pub sha256: String,
    pub executable: bool,
}

/// One side's produced-artifact observation: the canonical manifest (sorted
/// files) and its content address. The manifest formula is shared with the
/// independent verifier, so the tree observation rederives cross-language.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProducedSide {
    pub schema_version: String,
    /// SHA-256 of the canonical manifest document (see
    /// [`crate::produced::manifest_bytes`]).
    pub manifest_sha256: String,
    /// Sorted by path.
    pub files: Vec<ProducedFile>,
}

// ---------------------------------------------------------------------------
// Residual observation + disposition events
// ---------------------------------------------------------------------------

/// A preserved disagreement (Section 12 record + traceability fields).
///
/// IMMUTABLE: written once by `court run` with no disposition — the
/// observation never changes epistemic meaning. Dispositions are append-only
/// [`DispositionEvent`]s under `residuals/<id>.events/`; the current
/// disposition is the projection of the last event (`open` = no events).
///
/// `deny_unknown_fields`: an observation file that carries a stray
/// `disposition:` (or any other) key fails to load instead of silently
/// ignoring it — the forbidden state is unrepresentable, not merely unread.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResidualRecord {
    pub schema_version: String,
    pub id: String,
    pub court: String,
    /// Run id this residual was observed in.
    pub run: String,
    pub axis: ObservableId,
    pub kind: ResidualKind,
    /// Present for text residuals (Section 12: `surface: first-diagnostic-line`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub surface: Option<String>,
    pub authority: String,
    /// Fixture family the residual is scoped to (the token's `scope`).
    pub scope: String,
    /// SHA-256 of the candidate artifact bytes that produced this observation
    /// — the residual is bound to the exact candidate, not to a label.
    pub candidate_sha256: String,
    pub raw_reference: String,
    pub raw_candidate: String,
    pub raw_reference_sha256: String,
    pub raw_candidate_sha256: String,
}

/// One immutable disposition event. Each `frf residual dispose` appends a new
/// event; nothing is ever rewritten, so the residual trajectory survives
/// re-disposition. Sequence numbers are the file names under
/// `residuals/<id>.events/` (a reference-engine storage convention); the
/// PROTOCOL identity of an event is its content address `event_id`.
///
/// The event chain is a hash chain: every event carries its
/// `parent_event_id` (the previous event for the same residual, or `None`
/// for the first), and `event_id` is the SHA-256 of the event's own content
/// (residual + parent + disposition + evidence refs) — so an event's
/// identity binds its history, and the graph cannot be rewritten without
/// breaking every subsequent link.
#[derive(Debug, Clone, Serialize)]
pub struct DispositionEvent {
    pub schema_version: String,
    /// Content address: SHA-256 of `FRF/DISPOSITION-EVENT/v1` over the
    /// event's own fields (residual_id, parent_event_id, disposition,
    /// evidence_refs). Filled by `Store::append_disposition_event`; an
    /// un-appended event is not an event.
    pub event_id: String,
    pub residual_id: String,
    /// The event_id of the previous event for this residual (the chain
    /// link), or `None` for the first event.
    pub parent_event_id: Option<String>,
    #[serde(flatten)]
    pub disposition: Disposition,
    /// Generic evidence references: for a `fixed` event, the resolution run
    /// that closed the residual; otherwise empty. This is the seed of the
    /// evidence graph's explicit edges (later: receipts, artifacts, witness
    /// statements).
    pub evidence_refs: Vec<String>,
}

/// Strict evidence deserialization for [`DispositionEvent`]: the event is
/// content-addressed (its `event_id` binds its fields), so an unknown
/// property must be refused, never silently dropped before the identity is
/// recomputed. `serde(flatten)` is incompatible with `deny_unknown_fields`,
/// so the reader is hand-written: every key is checked, duplicates are
/// refused, the disposition's cross-field rules are enforced literally
/// (`fixed` requires reason + resolution_run_id + closure_predicate; a
/// non-fixed closure carries reason only; `open` is unrepresentable), and
/// anything else is an error.
impl<'de> Deserialize<'de> for DispositionEvent {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;

        struct EventVisitor;

        impl<'de> serde::de::Visitor<'de> for EventVisitor {
            type Value = DispositionEvent;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a disposition event")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<DispositionEvent, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut schema_version: Option<String> = None;
                let mut event_id: Option<String> = None;
                let mut residual_id: Option<String> = None;
                let mut parent_event_id: Option<String> = None;
                let mut evidence_refs: Option<Vec<String>> = None;
                let mut disposition: Option<String> = None;
                let mut reason: Option<String> = None;
                let mut resolution_run_id: Option<String> = None;
                let mut closure_predicate: Option<String> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "schema_version" => schema_version = Some(map.next_value()?),
                        "event_id" => event_id = Some(map.next_value()?),
                        "residual_id" => residual_id = Some(map.next_value()?),
                        "parent_event_id" => parent_event_id = map.next_value()?,
                        "evidence_refs" => evidence_refs = Some(map.next_value()?),
                        "disposition" => disposition = Some(map.next_value()?),
                        "reason" => reason = Some(map.next_value()?),
                        "resolution_run_id" => resolution_run_id = Some(map.next_value()?),
                        "closure_predicate" => closure_predicate = Some(map.next_value()?),
                        other => {
                            return Err(A::Error::custom(format!(
                                "unknown field `{other}` on DispositionEvent — the event is content-addressed; unknown properties are refused, never dropped"
                            )));
                        }
                    }
                }

                let disposition = match disposition.as_deref() {
                    Some("fixed") => Disposition::Fixed {
                        reason: reason
                            .ok_or_else(|| A::Error::custom("fixed event without a reason"))?,
                        resolution_run_id: resolution_run_id.ok_or_else(|| {
                            A::Error::custom("fixed event without a resolution_run_id")
                        })?,
                        closure_predicate: closure_predicate.ok_or_else(|| {
                            A::Error::custom("fixed event without a closure_predicate")
                        })?,
                    },
                    Some(kind) => {
                        if resolution_run_id.is_some() || closure_predicate.is_some() {
                            return Err(A::Error::custom(format!(
                                "{kind} event carries resolution_run_id/closure_predicate — only fixed may"
                            )));
                        }
                        let kind = match kind {
                            "intentional" => ClosureKind::Intentional,
                            "environmental" => ClosureKind::Environmental,
                            "oracle_version" => ClosureKind::OracleVersion,
                            "harness" => ClosureKind::Harness,
                            "unknown" => ClosureKind::Unknown,
                            other => {
                                return Err(A::Error::custom(format!(
                                    "unknown disposition kind {other:?} (open is not settable)"
                                )));
                            }
                        };
                        Disposition::Closed {
                            kind,
                            reason: reason.ok_or_else(|| {
                                A::Error::custom(format!("{kind:?} event without a reason"))
                            })?,
                        }
                    }
                    None => {
                        return Err(A::Error::custom("disposition event without a disposition"));
                    }
                };

                Ok(DispositionEvent {
                    schema_version: schema_version.ok_or_else(|| {
                        A::Error::custom("disposition event without schema_version")
                    })?,
                    event_id: event_id
                        .ok_or_else(|| A::Error::custom("disposition event without event_id"))?,
                    residual_id: residual_id
                        .ok_or_else(|| A::Error::custom("disposition event without residual_id"))?,
                    parent_event_id,
                    disposition,
                    evidence_refs: evidence_refs.unwrap_or_default(),
                })
            }
        }

        deserializer.deserialize_map(EventVisitor)
    }
}

impl DispositionEvent {
    /// Build a non-fixed closure event. `event_id`/`parent_event_id`/
    /// `evidence_refs` are filled by `Store::append_disposition_event` once
    /// the chain is known.
    pub fn closed(
        residual_id: &str,
        kind: ClosureKind,
        reason: String,
    ) -> crate::error::Result<Self> {
        validate_reason(&reason)?;
        Ok(DispositionEvent {
            schema_version: SCHEMA_DISPOSITION.to_string(),
            event_id: String::new(),
            residual_id: residual_id.to_string(),
            parent_event_id: None,
            disposition: Disposition::Closed { kind, reason },
            evidence_refs: vec![],
        })
    }

    /// Build a `fixed` closure event. `fixed` cannot be spelled without its
    /// resolution run and the predicate that was verified against it — a
    /// disposition is not evidence.
    pub fn fixed(
        residual_id: &str,
        reason: String,
        resolution_run_id: String,
        closure_predicate: String,
    ) -> crate::error::Result<Self> {
        validate_reason(&reason)?;
        if resolution_run_id.trim().is_empty() {
            return Err(crate::error::FrfError::new(
                "a fixed disposition requires a resolution_run_id",
            ));
        }
        if closure_predicate.trim().is_empty() {
            return Err(crate::error::FrfError::new(
                "a fixed disposition requires a closure_predicate",
            ));
        }
        Ok(DispositionEvent {
            schema_version: SCHEMA_DISPOSITION.to_string(),
            event_id: String::new(),
            residual_id: residual_id.to_string(),
            parent_event_id: None,
            disposition: Disposition::Fixed {
                reason,
                resolution_run_id,
                closure_predicate,
            },
            evidence_refs: vec![],
        })
    }
}

pub(crate) fn validate_reason(reason: &str) -> crate::error::Result<()> {
    if reason.trim().is_empty() {
        return Err(crate::error::FrfError::new(
            "disposition requires a non-empty one-line reason",
        ));
    }
    if reason.contains('\n') {
        return Err(crate::error::FrfError::new(
            "reason must be a single line (no newlines)",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Endoduction token
// ---------------------------------------------------------------------------

/// The κ(r_raw) = (kind, surface, authority, magnitude, scope, disposition,
/// next_court) output (Section 6). Derived, never hand-authored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenRecord {
    pub schema_version: String,
    pub residual_id: String,
    /// `{kind}/{surface}/{magnitude}/{disposition}` (Section 12 token shape).
    pub token: String,
    pub kind: ResidualKind,
    pub surface: String,
    pub authority: String,
    pub magnitude: String,
    pub scope: String,
    pub disposition: String,
    pub next_court: String,
    pub blocks_claims: Vec<String>,
}

// ---------------------------------------------------------------------------
// Residual trajectories (v0.1.21: the generalized protocol)
// ---------------------------------------------------------------------------

/// The deterministic classification of a trajectory: how STABLE the
/// divergence is (drift), what pattern of change it shows (slew), where the
/// observed bands touch the axis bounds (localization), and how many
/// contiguous observed bands there are (bands). See
/// [`crate::trajectory::classify`] for the exact table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrajectoryDrift {
    /// Observed at every point of the axis.
    Persistent,
    /// Observed at some but not all points.
    Transient,
    /// Transient AND observed at both the first and the last point (it came
    /// back).
    Recurrent,
}

impl TrajectoryDrift {
    pub const ALL: [TrajectoryDrift; 3] = [
        TrajectoryDrift::Persistent,
        TrajectoryDrift::Transient,
        TrajectoryDrift::Recurrent,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            TrajectoryDrift::Persistent => "persistent",
            TrajectoryDrift::Transient => "transient",
            TrajectoryDrift::Recurrent => "recurrent",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        TrajectoryDrift::ALL
            .iter()
            .copied()
            .find(|d| d.as_str() == s)
    }
}

/// The slew classification of a trajectory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrajectorySlew {
    /// No change across the axis.
    Stable,
    /// One boundary: appeared or disappeared at the start or end of the series.
    Abrupt,
    /// A contiguous interior window (appeared, then disappeared).
    Burst,
    /// Non-contiguous observation pattern.
    Recurrent,
}

impl TrajectorySlew {
    pub const ALL: [TrajectorySlew; 4] = [
        TrajectorySlew::Stable,
        TrajectorySlew::Abrupt,
        TrajectorySlew::Burst,
        TrajectorySlew::Recurrent,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            TrajectorySlew::Stable => "stable",
            TrajectorySlew::Abrupt => "abrupt",
            TrajectorySlew::Burst => "burst",
            TrajectorySlew::Recurrent => "recurrent",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        TrajectorySlew::ALL
            .iter()
            .copied()
            .find(|s2| s2.as_str() == s)
    }
}

/// Where the observed bands touch the axis bounds (ordered axes). For the
/// paper's vocabulary: `start`/`end` are the boundary-localized patterns
/// (`abrupt`); `interior` is the burst; `both` with 2+ bands is the
/// version-stratified/recurrent pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrajectoryLocalization {
    /// The divergence is present at every point (persistent).
    #[serde(rename = "none")]
    None_,
    /// The observed band touches the start boundary only.
    Start,
    /// The observed band touches the end boundary only.
    End,
    /// Observed at both the first and the last point.
    Both,
    /// The observed band is interior (touches neither boundary).
    Interior,
}

impl TrajectoryLocalization {
    pub const ALL: [TrajectoryLocalization; 5] = [
        TrajectoryLocalization::None_,
        TrajectoryLocalization::Start,
        TrajectoryLocalization::End,
        TrajectoryLocalization::Both,
        TrajectoryLocalization::Interior,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            TrajectoryLocalization::None_ => "none",
            TrajectoryLocalization::Start => "start",
            TrajectoryLocalization::End => "end",
            TrajectoryLocalization::Both => "both",
            TrajectoryLocalization::Interior => "interior",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        TrajectoryLocalization::ALL
            .iter()
            .copied()
            .find(|l| l.as_str() == s)
    }
}

/// The derived classification of one trajectory. `localization` and `bands`
/// make the paper's extended vocabulary executable: `abrupt` ↔ start/end
/// (boundary-localized), `burst` ↔ interior, `recurrent` ↔ both with 2+
/// bands (version-stratified along a version axis).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrajectoryDerivation {
    pub drift: TrajectoryDrift,
    pub slew: TrajectorySlew,
    /// Where the observed bands touch the axis bounds.
    pub localization: TrajectoryLocalization,
    /// The number of contiguous observed bands (1 for persistent/abrupt/
    /// burst; 2+ for the recurrent/stratified patterns).
    pub bands: u32,
}

/// One point of a trajectory: the coordinate value, the run that point
/// produced (identical evidence shares the content-addressed run), whether
/// the subject lineage was observed in it, and — when observed — the
/// residual id and the EXACT observation fingerprint at that point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrajectoryObservation {
    pub point_index: u32,
    /// The coordinate value (repetition index, candidate artifact hash,
    /// authority version, environment label, time label).
    pub coordinate: String,
    pub run: String,
    pub observed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub residual: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

/// The trajectory protocol object: an ordered series of observations of one
/// residual LINEAGE over a declared coordinate system, with the
/// deterministic derivation. The subject is the lineage identity
/// (`FRF/RESIDUAL-LINEAGE/v1`), stable across candidate revisions,
/// authority versions, environments, and time — so a trajectory records the
/// MOVEMENT of a divergence, not merely the exact recurrence of one byte
/// pattern. Trajectories are DERIVED from the referenced
/// [`ExecutionSeries`] and may be re-derived (and extended) as the series
/// accumulates; the runs are the immutable evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrajectoryRecord {
    pub schema_version: String,
    /// The residual lineage identity — the stable subject.
    pub subject: String,
    pub axis: String,
    /// One of: `repeat_index`, `candidate_revision`, `authority_version`,
    /// `environment`, `time`.
    pub coordinate_system: String,
    /// The ExecutionSeries this trajectory is derived from
    /// (`series/{court}-{coordinate_system}.yaml`).
    pub series: String,
    pub observations: Vec<TrajectoryObservation>,
    pub derivation: TrajectoryDerivation,
}

/// The reduction protocol object: a minimization experiment on one residual
/// (`frf court minimize`). Every executable attempt is recorded; the final
/// reproducer is court-verified (the lineage survives) and carries the full
/// transform declaration: what the reduction permitted to move (the fixture)
/// and what it required to stay (candidate, authority, comparator,
/// environment — each bound by identity, not label).
pub const SCHEMA_REDUCTION: &str = "frf-reduction-v3";

/// The general evidence-transform description — one frame for all six
/// evidence operations (observation, resolution, replay, trajectory,
/// reduction, claim): every operation that produces new evidence from old
/// evidence declares what it permits to move and what it requires to stay.
/// The transforms differ only in which dimensions may vary; the comparison
/// relation and the success predicate are the same protocol objects the
/// rest of the evidence graph uses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceTransform {
    /// `observation` | `resolution` | `replay` | `trajectory` | `reduction`.
    pub kind: String,
    /// The source evidence this transform consumes (run id / residual id).
    pub source: String,
    /// Dimensions that MAY change under this transform (e.g. `fixture` for a
    /// reduction, `candidate` for a resolution).
    pub varying_dimensions: Vec<String>,
    /// Dimensions that MUST NOT change (each bound by identity in the
    /// producing record).
    pub invariant_dimensions: Vec<String>,
    /// The evaluation relation governing the comparison: the observable axis
    /// and its specification hash — the same identity the court bound.
    pub observation_relation: String,
    /// How success is decided: `lineage-survives` (reduction),
    /// `axis-closes` (resolution), `observation-reproduces` (replay),
    /// `divergence-observed` (observation).
    pub success_predicate: String,
}

impl EvidenceTransform {
    /// The transform a court OBSERVATION is: nothing may change.
    pub fn observation(run: &str, relation: &str) -> EvidenceTransform {
        EvidenceTransform {
            kind: "observation".to_string(),
            source: run.to_string(),
            varying_dimensions: vec![],
            invariant_dimensions: vec![],
            observation_relation: relation.to_string(),
            success_predicate: "divergence-observed".to_string(),
        }
    }

    /// The transform a RESOLUTION is: only the candidate artifact may change.
    pub fn resolution(run: &str, relation: &str) -> EvidenceTransform {
        EvidenceTransform {
            kind: "resolution".to_string(),
            source: run.to_string(),
            varying_dimensions: vec!["candidate".to_string()],
            invariant_dimensions: vec![
                "question".to_string(),
                "authority".to_string(),
                "fixture".to_string(),
                "environment".to_string(),
                "comparator".to_string(),
            ],
            observation_relation: relation.to_string(),
            success_predicate: "axis-closes".to_string(),
        }
    }

    /// The transform a REPLAY is: nothing may change; the observation must
    /// reproduce.
    pub fn replay(run: &str, relation: &str) -> EvidenceTransform {
        EvidenceTransform {
            kind: "replay".to_string(),
            source: run.to_string(),
            varying_dimensions: vec![],
            invariant_dimensions: vec![],
            observation_relation: relation.to_string(),
            success_predicate: "observation-reproduces".to_string(),
        }
    }

    /// The transform a REDUCTION is: only the fixture may change; the
    /// candidate, authority, comparator, and environment must stay.
    pub fn reduction(residual: &str, relation: &str) -> EvidenceTransform {
        EvidenceTransform {
            kind: "reduction".to_string(),
            source: residual.to_string(),
            varying_dimensions: vec!["fixture".to_string()],
            invariant_dimensions: vec![
                "candidate".to_string(),
                "authority".to_string(),
                "comparator".to_string(),
                "environment".to_string(),
            ],
            observation_relation: relation.to_string(),
            success_predicate: "lineage-survives".to_string(),
        }
    }
}

/// One series snapshot: the ordered points of ONE experiment at ONE moment
/// of its history. v2: content-addressed and parent-linked — `id` is the
/// SHA-256 of `FRF/SERIES/v2` over the snapshot's own fields, `experiment_id`
/// is the stable experiment key, and `parent_series_id` chains the snapshot
/// to its predecessor, so an append is a NEW immutable node and branching is
/// visible (a second head refuses an implicit append).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionSeries {
    pub schema_version: String,
    /// Content address: `FRF/SERIES/v2` over this snapshot's fields.
    pub id: String,
    /// The stable experiment key: `{court}-{coordinate_system}`.
    pub experiment_id: String,
    /// The id of the previous snapshot in this experiment's history, or
    /// `None` for the first.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_series_id: Option<String>,
    pub court: String,
    pub coordinate_system: String,
    /// The ordered points (appended in observation order; multiple
    /// coordinates may reference the same content-addressed run).
    pub points: Vec<SeriesPoint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeriesPoint {
    pub point_index: u32,
    /// The coordinate value at this point.
    pub coordinate: String,
    /// The content-addressed run this point produced (identical evidence
    /// shares the run).
    pub run: String,
}

// ---------------------------------------------------------------------------
// Reduction (minimization) protocol
// ---------------------------------------------------------------------------

/// The role of one recorded executable attempt in a minimization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReductionAttemptRole {
    /// The ORIGINAL fixture checked before the search started (a reduction
    /// cannot begin if the original does not reproduce).
    Baseline,
    /// A ddmin candidate tried during the search.
    Candidate,
    /// The final confirmation run of the accepted reproducer.
    FinalVerification,
}

impl ReductionAttemptRole {
    pub fn as_str(self) -> &'static str {
        match self {
            ReductionAttemptRole::Baseline => "baseline",
            ReductionAttemptRole::Candidate => "candidate",
            ReductionAttemptRole::FinalVerification => "final_verification",
        }
    }
}

/// The outcome of one recorded executable attempt in a minimization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReductionAttemptOutcome {
    /// The residual's lineage survived (the preservation predicate held).
    Preserved,
    /// The lineage was lost.
    Lost,
    /// The attempt could not be evaluated (execution refused — timeout,
    /// overflow, missing artifact). The minimization is aborted, never
    /// silently skipped.
    HarnessFailure,
}

impl ReductionAttemptOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            ReductionAttemptOutcome::Preserved => "preserved",
            ReductionAttemptOutcome::Lost => "lost",
            ReductionAttemptOutcome::HarnessFailure => "harness_failure",
        }
    }
}

/// One recorded executable attempt: the fixture tried, its role, its
/// outcome, and whether the reduction was ACCEPTED (preserved AND the
/// fixture is a strict subset of the current best — a baseline is never
/// accepted, and re-verifying an already-accepted fixture is not a new
/// reduction).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReductionAttempt {
    pub attempt: u32,
    pub role: ReductionAttemptRole,
    /// SHA-256 of the fixture tried (content-addressed under `objects/`).
    pub fixture_sha256: String,
    pub outcome: ReductionAttemptOutcome,
    pub accepted: bool,
}

/// The minimality claim of a minimization, stated precisely: classic ddmin
/// establishes 1-minimality at the declared granularity (no single line can
/// be removed while preserving the lineage) — not global cardinality
/// minimality.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReductionMinimality {
    /// `one-minimal` in this version.
    pub kind: String,
    /// The granularity of removal (`line`).
    pub granularity: String,
    /// Whether the search completed within the attempt budget (a cut short
    /// search cannot claim minimality).
    pub proven: bool,
}

/// The derivation of a minimization experiment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReductionDerivation {
    /// The reduction strategy (`ddmin-lines` in this version).
    pub strategy: String,
    pub original_lines: u32,
    pub final_lines: u32,
    pub minimality: ReductionMinimality,
}

/// A minimization experiment: the record of reducing one residual's fixture
/// until the divergence lineage stops surviving. Content-addressed
/// (`FRF/REDUCTION/v3`); the final reproducer is court-verified and carries
/// the full transform declaration — the fixed dimensions bound by identity
/// (authority artifact, candidate artifact, environment digest, comparator
/// semantic + implementation), so the record itself proves the reduction
/// held what it claims to have held. v3 binds the external minimizer that
/// performed the reduction when the residual's κ route was served by a
/// declared minimizer (the built-in ddmin reducer leaves the minimizer
/// binding empty).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReductionRecord {
    pub schema_version: String,
    /// Content address: `FRF/REDUCTION/v3` over the record's own fields.
    pub id: String,
    /// The residual being minimized.
    pub residual_id: String,
    /// The run that observed the residual (the source evidence).
    pub source_run: String,
    pub axis: String,
    pub kind: ResidualKind,
    /// The court semantic identity of the question the reduction held fixed.
    pub court_semantic_identity: String,
    /// The authority artifact the residual was observed against.
    pub authority_artifact_sha256: String,
    /// The exact candidate artifact the residual was observed against (the
    /// minimizer holds the candidate fixed).
    pub candidate_artifact_sha256: String,
    /// The environment the residual was observed under.
    pub environment_digest: String,
    /// The comparator SEMANTIC identity governing the preservation predicate
    /// (specification hash).
    pub comparator_semantic_id: String,
    pub comparator_semantic_hash: String,
    /// The comparator IMPLEMENTATION identity that observed the residual.
    pub comparator_implementation_hash: String,
    /// The resolved argv template the sides executed under (the fixture slot
    /// is the reduced object's path).
    pub argv_template: Vec<String>,
    pub original_fixture_sha256: String,
    /// The minimal reproducer: the smallest fixture (at line granularity)
    /// still producing the lineage, court-verified.
    pub final_fixture_sha256: String,
    /// Every executable attempt, in order.
    pub attempts: Vec<ReductionAttempt>,
    pub derivation: ReductionDerivation,
    /// The transform declaration: fixture varies; candidate, authority,
    /// comparator, and environment must stay.
    pub transform: EvidenceTransform,
    // -- the external minimizer binding (the extension protocol) -----------
    /// The minimizer SEMANTIC identity that served this residual's κ route,
    /// when an external minimizer performed the reduction. Absent = the
    /// built-in ddmin reducer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimizer_semantic_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimizer_semantic_hash: Option<String>,
    /// The minimizer IMPLEMENTATION identity (the exact snapshotted program
    /// bytes) that proposed the reduction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimizer_implementation_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimizer_implementation_artifact: Option<ArtifactIdentity>,
    /// The content-addressed invocation + result records of the external
    /// minimizer (written under `reductions/<id>/minimizer/`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimizer_invocation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimizer_result_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Court challenge — the negative-control evidence object (spec/challenge.md)
// ---------------------------------------------------------------------------

/// One court challenge: the court run against a MUTANT candidate — a
/// deterministic wrapper of the admitted reference artifact that alters
/// exactly one observable dimension — proving the court can SEE the defect
/// class it declares. Content-addressed (`FRF/CHALLENGE/v1`); the verdicts
/// are derived from the run and recomputed by verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CourtChallenge {
    pub schema_version: String,
    /// Content address: `FRF/CHALLENGE/v1` over the declared evidence
    /// (court, operator, targeted axis, reference artifact, mutant artifact,
    /// mutant run).
    pub id: String,
    /// The court id the challenge exercises.
    pub court: String,
    /// The mutation operator applied (e.g. `exit-class`).
    pub operator: String,
    /// The observable axis the mutation targeted (`exit`, `stderr`, …).
    pub target_axis: String,
    /// The admitted reference artifact the mutant wraps.
    pub reference_sha256: String,
    /// The mutant candidate artifact: SHA-256 of the deterministic wrapper
    /// generated from (operator, reference_sha256) — rederivable by any
    /// verifier, so a forged mutant hash is caught.
    pub mutant_candidate_sha256: String,
    /// The court run against the mutant (a normal, content-addressed run).
    pub run: String,
    // -- derived verdicts (recomputed by verification, not part of the id) --
    /// The residuals the mutant run observed (their ids).
    pub observed_residuals: Vec<String>,
    /// Declared observables other than the targeted axis.
    pub unaffected_axes: Vec<String>,
    /// The court observed a divergence on the targeted axis (sensitivity).
    pub saw_defect: bool,
    /// No divergence appeared on the unaffected axes (the mutant moved only
    /// the targeted dimension, and the court did not conflate it with
    /// others).
    pub specificity_clean: bool,
    pub created_by: RunnerIdentity,
}

// ---------------------------------------------------------------------------
// Comparator extension protocol (spec/comparator.md)
// ---------------------------------------------------------------------------

/// The canonical request a court writes to an external comparator's stdin
/// (serialized as canonical JSON). The comparator receives the raw side
/// observations (base64) plus the context it needs to interpret them.
#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComparatorRequest<'a> {
    pub schema_version: &'a str,
    /// The SEMANTIC identity of the comparator being invoked — what the
    /// comparator program must verify it implements.
    pub comparator: &'a ComparatorSemantic,
    pub axis: &'a str,
    pub reference: ComparatorObservation<'a>,
    pub candidate: ComparatorObservation<'a>,
    pub context: ComparatorContext<'a>,
}

/// One side's raw observation, as delivered to a comparator.
#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComparatorObservation<'a> {
    pub exit: &'a str,
    pub stdout_base64: String,
    pub stderr_base64: String,
    /// The ADAPTED observation for this side (capture-adapter protocol):
    /// present when a capture adapter serves this axis — the raw streams are
    /// still carried (they are the request evidence), and the comparator
    /// compares the adapted payloads. Absent = compare the streams.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adapted: Option<&'a AdaptedObservation>,
}

/// The execution context a comparator may need (the question's inputs).
#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComparatorContext<'a> {
    pub fixture_sha256: &'a str,
    pub arguments: &'a [String],
    pub environment_digest: &'a str,
    /// The sides' PRODUCED ARTIFACT TREES (when the court declares
    /// `produce`): the manifests the comparator compares. Absent for
    /// stream-only courts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub produced: Option<ProducedContext<'a>>,
}

/// The produced-artifact context delivered to a comparator: each side's
/// manifest (paths + content hashes), so the comparator compares what the
/// sides BUILT. v0 delivers the manifests only — raw-file access is a
/// future extension.
#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProducedContext<'a> {
    pub reference: ProducedSideContext<'a>,
    pub candidate: ProducedSideContext<'a>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProducedSideContext<'a> {
    pub manifest_sha256: &'a str,
    pub files: &'a [ProducedFile],
}

/// The canonical response a comparator must produce on stdout.
/// Interpretation is fail-closed: `equivalent` and `residuals` are mutually
/// exclusive, `indeterminate` and `failure` refuse the court, and a
/// `divergent` response must name its residuals (see
/// [`crate::comparators::interpret`]).
///
/// v2: `request_id` MUST be the SHA-256 of the exact canonical request bytes
/// the comparator received — a response cryptographically names the request
/// it answers, and the court refuses a response that does not.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComparatorResponse {
    pub schema_version: String,
    /// The SHA-256 of the exact canonical request bytes this response
    /// answers (echoed from the comparator's stdin).
    pub request_id: String,
    /// The axes' projections agree.
    pub equivalent: bool,
    /// The divergences, as raw projections the court preserves verbatim.
    #[serde(default)]
    pub residuals: Vec<ComparatorResidual>,
    /// The comparator cannot decide; the court refuses the run (inconclusive
    /// evidence must not be recorded as conclusive).
    #[serde(default)]
    pub indeterminate: bool,
    /// The comparator malfunctioned; the court refuses the run.
    #[serde(default)]
    pub failure: Option<String>,
}

/// One divergence a comparator reports. `kind` is derived by the court from
/// the axis's residual classifier (exit ↔ `exit`, stderr/stdout ↔ `text`, an
/// external axis ↔ its declared classifier); the SURFACE and the raw values
/// follow the declared extractor.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComparatorResidual {
    #[serde(default)]
    pub surface: Option<String>,
    pub raw_reference: String,
    pub raw_candidate: String,
}

// ---------------------------------------------------------------------------
// Comparator invocation evidence (the exact instrument that observed)
// ---------------------------------------------------------------------------

/// The INVOCATION evidence record: what was invoked, against which exact
/// request, by which implementation, under which runner. Written at court
/// time under `captures/<run>/comparator/<axis>/invocation.json` and verified
/// on every read (the identity REDERIVES from the record's own fields — a
/// name is a claim until recomputed).
///
/// The `request_cid` is the SHA-256 of the exact canonical request bytes the
/// comparator received (the document's own byte hash — the schema_version
/// field inside names the domain); the comparator echoes it as the
/// response's `request_id`, so the whole chain is cryptographically bound:
/// invocation → request bytes → response → interpreted result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComparatorInvocation {
    pub schema_version: String,
    /// Content address: `FRF/COMPARATOR-INVOCATION/v1` over the record's own
    /// fields. Filled by the court; a record whose id does not rederive is
    /// refused on read.
    pub invocation_id: String,
    pub axis: ObservableId,
    /// SHA-256 of the exact canonical request bytes the comparator received.
    pub request_cid: String,
    /// The comparator's SEMANTIC identity (its specification hash) — the
    /// question the program was asked.
    pub comparator_semantic_cid: String,
    /// The exact implementation artifact that ran (snapshot path, sha256,
    /// interpreter chain).
    pub comparator_implementation_artifact: ArtifactIdentity,
    /// Who orchestrated the invocation (the runner).
    pub execution_provenance: RunnerIdentity,
}

/// The RESULT evidence record: which request the response answered, the
/// response document's content address, the interpreted outcome, and the
/// residual observations the invocation produced. Written at court time under
/// `captures/<run>/comparator/<axis>/result.json`; the identity REDERIVES
/// from the record's own fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComparatorResult {
    pub schema_version: String,
    /// Content address: `FRF/COMPARATOR-RESULT/v1` over the record's own
    /// fields.
    pub result_id: String,
    /// The request this result answers (must equal the invocation's
    /// `request_cid`).
    pub request_cid: String,
    /// SHA-256 of the exact canonical response bytes (the document's own byte
    /// hash).
    pub response_cid: String,
    /// The interpreted outcome: `equivalent` or `divergent` (a refused
    /// comparator produces no result — the run never happened).
    pub outcome: String,
    /// The residual observation records this invocation produced (the
    /// immutable observation records; their fingerprints are their semantic
    /// identity and rederive from the residual records themselves).
    pub residual_observation_ids: Vec<String>,
}

/// The complete verified evidence of one externally served axis: the
/// invocation and the result it produced (cross-verified by
/// [`crate::store::Store::load_comparator_evidence`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComparatorEvidence {
    pub invocation: ComparatorInvocation,
    pub result: ComparatorResult,
}

// ---------------------------------------------------------------------------
// Receipt (Appendix A, trimmed: verdict_case_file, taste_gates, invariants
// are real but not needed to prove the kernel — see README Known Limitations)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    /// The protocol version, enforced at deserialization: a receipt with any
    /// other schema is refused, not silently interpreted.
    #[serde(deserialize_with = "expect_receipt_schema")]
    pub schema_version: String,
    /// The run this receipt binds (the reproduction target).
    pub run: String,
    pub court: ReceiptCourt,
    /// Who observed: copied from the capture, never reconstructed.
    pub provenance: ObservationProvenance,
    /// The comparator relations applied, copied from the capture.
    pub comparator_semantics: Vec<ComparatorSemantic>,
    /// The normalizer relations applied to the compared streams, copied from
    /// the capture.
    #[serde(default)]
    pub normalizer_semantics: Vec<NormalizerSemantic>,
    /// The execution profile the observation was made under, and the capture
    /// bounds that applied (copied from the capture — a receipt never
    /// guesses what the harness enforced).
    pub execution_profile: String,
    pub capture_bounds: CaptureBounds,
    pub authority: ReceiptAuthority,
    pub candidate: ReceiptCandidate,
    /// The environment the observation happened in, copied from the capture.
    pub environment: EnvironmentIdentity,
    pub fixtures: Vec<ReceiptFixture>,
    pub observables: Vec<ReceiptObservable>,
    pub residuals: Vec<ReceiptResidual>,
    pub endoduction: ReceiptEndoduction,
    pub claims: ReceiptClaims,
    pub replay: ReceiptReplay,
}

/// Deserialize the receipt schema version, refusing anything but the
/// current protocol version: an OpenReceipt from another version is not
/// interpreted, it is rejected with a clear error.
pub(crate) fn expect_receipt_schema<'de, D>(
    deserializer: D,
) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    if s == SCHEMA_RECEIPT {
        Ok(s)
    } else {
        Err(serde::de::Error::custom(format!(
            "unsupported receipt schema '{s}' (this implementation speaks {SCHEMA_RECEIPT})"
        )))
    }
}

/// The closed set of dispositions a receipt entry may carry; anything else
/// is refused at deserialization (protocol enforcement, not a lint).
pub(crate) fn expect_disposition_str<'de, D>(
    deserializer: D,
) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    if matches!(
        s.as_str(),
        "open"
            | "fixed"
            | "intentional"
            | "environmental"
            | "oracle_version"
            | "harness"
            | "unknown"
    ) {
        Ok(s)
    } else {
        Err(serde::de::Error::custom(format!(
            "unknown disposition '{s}'"
        )))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptCourt {
    pub id: String,
    pub question: String,
    pub falsifier: String,
    pub admissibility_envelope: ReceiptEnvelope,
    /// The court's semantic identity (copied from the capture) — the key
    /// that makes two runs answer the same evidentiary question.
    pub semantic_identity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptEnvelope {
    pub authority_versions: Vec<String>,
    pub fixture_family: String,
    pub platforms: Vec<String>,
    pub observables: Vec<String>,
    pub normalizers: Vec<String>,
    pub replay_scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptAuthority {
    pub name: String,
    pub kind: String,
    pub version: String,
    /// The authority's admitted executable hash (Appendix A `identity_hash`).
    pub identity_hash: String,
    pub provenance: String,
    /// The interpreter the authority's script executed under, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interpreter: Option<InterpreterIdentity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptCandidate {
    pub name: String,
    pub version_or_commit: String,
    pub build_profile: String,
    /// SHA-256 of the exact candidate artifact bytes this receipt's run
    /// executed — labels are distrustful; bytes are not.
    pub identity_hash: String,
    /// The interpreter the candidate's script executed under, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interpreter: Option<InterpreterIdentity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptFixture {
    pub id: String,
    pub hash: String,
    /// The resolved argv the side actually received (replay).
    pub arguments: Vec<String>,
    /// The DECLARED fixture arguments — the input to the court semantic
    /// identity (the question), as opposed to the resolved argv (the
    /// execution). A receipt must carry both or it cannot rederive its own
    /// semantic identity.
    pub declared_arguments: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptObservable {
    pub axis: String,
    pub raw_reference_hash: String,
    pub raw_candidate_hash: String,
    pub comparator: String,
    pub normalization_rules: Vec<String>,
    pub verdict: ObservableVerdict,
    /// For an externally served axis: the content address of the exact
    /// comparator request (and the result record that answered it) this
    /// verdict was produced from. The raw hashes above are the SHA-256s of
    /// the canonical `reference`/`candidate` subtrees of that request. Absent
    /// for in-binary comparators, whose raw hashes rederive from the
    /// captured projections.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comparator_request: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comparator_result: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservableVerdict {
    Pass,
    Residual,
}

/// One coordinate system's trajectory evidence for a residual: the pinned
/// ExecutionSeries snapshot the drift/slew were derived from. A residual
/// does not have one universal drift — it has a trajectory with respect to a
/// coordinate system — so a receipt entry carries one of these per
/// coordinate system the run participates in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrajectoryEvidence {
    /// One of: `repeat_index`, `candidate_revision`, `authority_version`,
    /// `environment`, `time`.
    pub coordinate_system: String,
    /// The exact ExecutionSeries snapshot (content address) the drift/slew
    /// were derived from — an immutable node in the experiment's history.
    pub series: String,
    pub drift: String,
    pub slew: String,
}

/// The sign a receipt entry MUST carry for a residual record: the
/// trajectory evidence per coordinate system. A single-run receipt (no
/// series membership at emit time) honestly carries NO entries — drift and
/// slew are not-observed; one run cannot observe movement. A run that
/// belongs to an [`ExecutionSeries`] carries one entry per coordinate
/// system, each PINNING the exact series snapshot the drift/slew were
/// derived from, so later experiments that reference the same
/// content-addressed run can never change what an emitted receipt means —
/// the receipt is a snapshot, and the verifier replays each pinned series.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResidualSign {
    #[serde(default)]
    pub trajectory_evidence: Vec<TrajectoryEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptResidual {
    pub id: String,
    /// v0 addition: the axis the residual was observed on (needed to scope
    /// claim sentences per declared observable).
    pub axis: String,
    pub kind: ResidualKind,
    pub sign: ResidualSign,
    pub grammar_state: String,
    pub raw_reference_hash: String,
    pub raw_candidate_hash: String,
    /// Protocol-enforced closed set.
    #[serde(deserialize_with = "expect_disposition_str")]
    pub disposition: String,
    /// The event_id of the immutable disposition event that supplied this
    /// disposition at emit time; `null` for `open` (the projection of no
    /// events). A receipt points at the exact event snapshot it bound — it
    /// does not merely copy state.
    pub disposition_event_id: Option<String>,
    /// Mandatory reason for closed dispositions; absent while `open`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The resolution run backing a `fixed` disposition — v0 addition, the
    /// evidence edge a disposition must never substitute for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolution_run_id: Option<String>,
    /// The comparability predicate verified against the resolution run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closure_predicate: Option<String>,
    pub reproducer: String,
    pub invariant: String,
    pub residual_fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptEndoduction {
    pub schema_version: String,
    pub tokens: Vec<ReceiptToken>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptToken {
    pub residual_id: String,
    pub token: String,
    pub next_court: String,
    pub blocks_claims: Vec<String>,
}

/// Claim state as known at emit time. `positive` stays empty in v0: receipts
/// are immutable, and the positive sentence is compiled into `claims/` by
/// `frf claim compile` (see README Known Limitations).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptClaims {
    pub positive: Vec<String>,
    pub non_claims: Vec<String>,
    pub blocked_by_open_residuals: Vec<String>,
}

/// Structured replay data (OpenReceipt v5): executing this reproduces the
/// observation. Original repository paths become provenance, not replay
/// dependencies — the snapshots under `objects/` are the artifacts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptReplay {
    /// The program to execute (`frf`).
    pub program: String,
    /// The evidence root the run was captured under (as passed to --root).
    pub evidence_root: String,
    /// The argv that re-executes the court declaration.
    pub argv: Vec<String>,
    /// The run identity a faithful replay must reproduce.
    pub expected_run_identity: String,
}

// ---------------------------------------------------------------------------
/// The scope of a claim (or of a residual's surface) — the region of the
/// evidence space a proposition is asserted about.
///
/// The admission rule (Section 10 of the paper) is set containment:
/// `Scope(K) ⊆ Scope(P₁ ∪ … ∪ Pₙ)` — a claim may not assert parity over any
/// dimension the premises did not actually observe. And a blocking residual
/// blocks exactly the claims whose scope intersects its surface: an open
/// residual observed on the same candidate, axis, fixture, environment, and
/// authority as a claim blocks it, whatever run happened to record it;
/// a residual on a different candidate, axis, fixture, or environment does
/// not.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimScope {
    /// Admitted authority ids the claim is scoped to (`ref-cli-1.8.2`).
    pub authority: Vec<String>,
    /// The EXACT candidate artifact hashes the claim is about (labels are
    /// distrustful; the admitted bytes are not).
    pub candidate: Vec<String>,
    /// Fixture ids actually executed — the claim never covers a fixture that
    /// did not run.
    pub fixtures: Vec<String>,
    /// The fixture family (Section 12: `malformed-input`).
    pub fixture_family: String,
    /// The observable axes the claim covers (parity is per-axis).
    pub observables: Vec<String>,
    /// Environment digests the observation happened under.
    pub environments: Vec<String>,
    /// The authority versions the court was admitted against (the envelope's
    /// `authority_versions`).
    pub versions: Vec<String>,
    /// The observation moments: run ids. Evidence about the same surface from
    /// a DIFFERENT run still blocks (temporal is not part of the blocking
    /// intersection); this dimension records WHERE the evidence lives.
    pub temporal: Vec<String>,
}

impl ClaimScope {
    /// One dimension's set overlap.
    fn overlaps(a: &[String], b: &[String]) -> bool {
        a.iter().any(|x| b.iter().any(|y| x == y))
    }

    /// Product intersection: two scopes overlap iff they share a point in
    /// EVERY dimension that defines the evidence space. `temporal` is
    /// deliberately excluded — an open divergence recorded by an earlier run
    /// about the same surface is still an unexplained divergence about that
    /// surface, and must still block. (A different run about a different
    /// surface — different candidate, axis, fixture, environment, or
    /// authority — does not: that is the paper's rule that a disposition or
    /// a later observation never rewrites an older one, generalized to
    /// scopes.)
    pub fn intersects(&self, other: &ClaimScope) -> bool {
        Self::overlaps(&self.authority, &other.authority)
            && Self::overlaps(&self.candidate, &other.candidate)
            && Self::overlaps(&self.fixtures, &other.fixtures)
            && Self::overlaps(&self.observables, &other.observables)
            && Self::overlaps(&self.environments, &other.environments)
            && Self::overlaps(&self.versions, &other.versions)
            && self.fixture_family == other.fixture_family
    }

    /// Dimension-wise containment: `self ⊇ other` — every point of `other`
    /// is a point of `self`. The admission rule `Scope(K) ⊆ Scope(P₁ ∪ … ∪
    /// Pₙ)` is `premises.contains(&k)` (with the premise union formed by
    /// merging sets dimension-wise).
    pub fn contains(&self, other: &ClaimScope) -> bool {
        let superset = |big: &[String], small: &[String]| small.iter().all(|s| big.contains(s));
        superset(&self.authority, &other.authority)
            && superset(&self.candidate, &other.candidate)
            && superset(&self.fixtures, &other.fixtures)
            && superset(&self.observables, &other.observables)
            && superset(&self.environments, &other.environments)
            && superset(&self.versions, &other.versions)
            && (other.fixture_family.is_empty() || self.fixture_family == other.fixture_family)
    }
}

/// A region of the evidence space as a union of scope CELLS (disjunctive
/// normal form). This is the honest representation of the premise union
/// `P₁ ∪ … ∪ Pₙ` in the admission rule: a union of Cartesian products is NOT
/// generally the Cartesian product of dimension-wise unions, so merging
/// dimension sets would INVENT unsupported evidence points. The region keeps
/// the cells separate, and containment `Scope(K) ⊆ region` is existential:
/// every point of K must lie in SOME cell.
///
/// The single-premise compiler of today produces a one-cell region; the
/// multi-premise compiler (future) appends one cell per premise receipt
/// without ever merging dimensions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRegion {
    /// The cells, each a product of dimension sets. The region is the union
    /// of these cells — a cell list, never a merged product.
    pub cells: Vec<ClaimScope>,
}

impl EvidenceRegion {
    /// The empty region (no premises).
    pub fn empty() -> EvidenceRegion {
        EvidenceRegion { cells: vec![] }
    }

    /// A region containing exactly one cell.
    pub fn cell(scope: ClaimScope) -> EvidenceRegion {
        EvidenceRegion { cells: vec![scope] }
    }

    /// Add one premise cell to the region (deduplicated). The union is the
    /// cell LIST — no dimension merging, so no invented points.
    pub fn push(&mut self, cell: ClaimScope) {
        if !self.cells.contains(&cell) {
            self.cells.push(cell);
        }
    }

    /// The admission rule, implemented without inflation: `other` (the claim
    /// scope K) is contained in the region iff EVERY point of K lies in SOME
    /// cell. Because a `ClaimScope` is itself a product of dimension sets,
    /// `cell.contains(k)` is the dimension-wise check; the region check is
    /// existential over cells.
    pub fn contains(&self, k: &ClaimScope) -> bool {
        self.cells.iter().any(|cell| cell.contains(k))
    }
}

/// The exact candidate artifact a compiled claim is attributed to.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimCandidate {
    pub name: String,
    pub version_or_commit: String,
    pub identity_hash: String,
}

/// A compiled claim (written ONLY by `frf claim compile`, from a verified
/// receipt). The IR is the full scope algebra:
///
/// - `scope` is K — the region of the evidence space the claim asserts
///   parity over (never beyond the premises' surface, checked literally);
/// - `blockers` are the residuals that REFUSE the claim: `open`/`unknown`
///   residuals whose surface intersects K (a human or LLM cannot promote
///   evidence by relabeling it — an unexplained divergence on the claimed
///   surface blocks, wherever it was recorded), and `harness` residuals on a
///   premise run (run-level invalidation);
/// - `excluded_evidence` are the observed divergences this claim does NOT
///   cover (residuals outside K's surface);
/// - `requires` are the premise receipts, and admission is
///   `Scope(K) ⊆ Scope(P₁ ∪ … ∪ Pₙ)`;
/// - `knowledge_snapshot` is the EVIDENCE UNIVERSE the absence search ran
///   over: no unresolved residual IN that universe intersects K. A claim is
///   admissible relative to an explicitly committed state of knowledge —
///   the compiled claim carries the universe, so the negative search (not
///   merely the positive premises) is portable and reproducible;
/// - prose (`positive`) is ONE renderer of the IR; `--json` emits the same
///   IR canonically.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimRecord {
    pub schema_version: String,
    pub receipt: String,
    /// Prose id of the admitted reference (`ref-cli-1.8.2`).
    pub authority: String,
    pub candidate: ClaimCandidate,
    pub court: String,
    pub fixture_family: String,
    /// Prose environment label (arch-os + digest prefix).
    pub environment: String,
    /// The comparison relation(s) the claim asserts (the clean axes'
    /// comparators, e.g. `eq(exit-code)`).
    pub relation: String,
    /// The machine-readable proposition: what parity is asserted, of whom,
    /// over which surface, on whose evidence.
    pub proposition: String,
    /// Claim IR — the structured scope K.
    pub scope: ClaimScope,
    /// Claim IR — the axes covered (projection of `scope.observables`).
    pub observable_scope: Vec<String>,
    /// Claim IR — the residuals that block this claim (see the doc header).
    pub blockers: Vec<String>,
    /// Claim IR — observed divergences outside K's surface (this receipt's
    /// residuals on axes the claim does not cover).
    pub excluded_evidence: Vec<String>,
    /// Claim IR — the premise receipts: admission is
    /// `Scope(K) ⊆ Scope(P₁ ∪ … ∪ Pₙ)` over these.
    pub requires: Vec<String>,
    /// The evidence universe the blocker search ran over (the negative
    /// search is as portable as the premises).
    pub knowledge_snapshot: KnowledgeSnapshot,
    pub positive: Vec<String>,
    pub non_claims: Vec<String>,
}

// ---------------------------------------------------------------------------
// Knowledge snapshot — the evidence universe of a claim's absence search
// ---------------------------------------------------------------------------

/// One residual head in the knowledge universe: the residual id and its
/// CURRENT disposition (as an event projection, with the exact event that
/// supplied it). This is what the blocker scan actually reads — a claim's
/// absence is relative to these heads, and a later disposition change is a
/// NEW universe, not a silent rewrite of the old one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResidualHead {
    pub id: String,
    pub disposition: String,
    /// The disposition event that supplied the disposition, or `None` for
    /// `open` (the projection of no events).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disposition_event_id: Option<String>,
}

/// The evidence universe a claim's absence search ran over: the committed
/// state of knowledge at compile time. A claim is admissible relative to U —
/// no unresolved residual IN U intersects K — and the compiled claim carries
/// U, so the negative search is reproducible by any implementation from the
/// claim alone, and a store mutation after compile time does not silently
/// change what the claim means.
///
/// Identity: SHA-256 of `FRF/KNOWLEDGE/v1` over the canonical document of
/// the snapshot's fields — the snapshot is content-addressed, and a claim
/// binding a different universe is a different claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeSnapshot {
    pub schema_version: String,
    /// Content address: `FRF/KNOWLEDGE/v1` over this snapshot's fields.
    pub cid: String,
    /// Every residual present in the universe, with its head disposition.
    pub residual_heads: Vec<ResidualHead>,
    /// The receipts present in the universe.
    pub receipts: Vec<String>,
    /// The runs (captures) present in the universe.
    pub runs: Vec<String>,
    /// The admitted authorities present in the universe.
    pub authorities: Vec<String>,
    /// The series snapshots present in the universe.
    pub series: Vec<String>,
    /// The reduction records present in the universe.
    pub reductions: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disposition_serde_round_trips() {
        // open: no reason key
        let open: Disposition = serde_yaml::from_str("disposition: open\n").unwrap();
        assert_eq!(open, Disposition::Open);
        let yaml = serde_yaml::to_string(&Disposition::Open).unwrap();
        assert_eq!(yaml.trim(), "disposition: open");

        // closed: reason required
        let closed: Disposition =
            serde_yaml::from_str("disposition: intentional\nreason: clearer wording\n").unwrap();
        assert_eq!(
            closed,
            Disposition::Closed {
                kind: ClosureKind::Intentional,
                reason: "clearer wording".into()
            }
        );
        let yaml = serde_yaml::to_string(&closed).unwrap();
        assert!(yaml.contains("disposition: intentional"));
        assert!(yaml.contains("reason: clearer wording"));

        // fixed: reason, resolution_run_id, AND closure_predicate are
        // required — a disposition is not evidence.
        let fixed: Disposition = serde_yaml::from_str(
            "disposition: fixed\nreason: patched\nresolution_run_id: run-x\nclosure_predicate: \"fix-court: same question\"\n",
        )
        .unwrap();
        assert_eq!(
            fixed,
            Disposition::Fixed {
                reason: "patched".into(),
                resolution_run_id: "run-x".into(),
                closure_predicate: "fix-court: same question".into()
            }
        );
        let yaml = serde_yaml::to_string(&fixed).unwrap();
        assert!(yaml.contains("disposition: fixed"));
        assert!(yaml.contains("resolution_run_id: run-x"));
        assert!(yaml.contains("closure_predicate"));
    }

    #[test]
    fn disposition_serde_rejects_forbidden_states() {
        // closed without reason
        assert!(serde_yaml::from_str::<Disposition>("disposition: intentional\n").is_err());
        // open with a reason
        assert!(serde_yaml::from_str::<Disposition>("disposition: open\nreason: x\n").is_err());
        // fixed without a resolution run — the hole this tool closes
        assert!(
            serde_yaml::from_str::<Disposition>("disposition: fixed\nreason: patched\n").is_err()
        );
        // fixed without a closure predicate
        assert!(serde_yaml::from_str::<Disposition>(
            "disposition: fixed\nreason: patched\nresolution_run_id: run-x\n"
        )
        .is_err());
        // non-fixed closure carrying a resolution run
        assert!(serde_yaml::from_str::<Disposition>(
            "disposition: intentional\nreason: x\nresolution_run_id: run-y\n"
        )
        .is_err());
        // unknown status
        assert!(serde_yaml::from_str::<Disposition>("disposition: closed\n").is_err());
    }

    #[test]
    fn residual_record_round_trips_through_yaml() {
        let record = ResidualRecord {
            schema_version: SCHEMA_RESIDUAL.into(),
            id: "cli-exit-0001".into(),
            court: "cli-malformed-input".into(),
            run: "run-x".into(),
            axis: ObservableId::exit(),
            kind: ResidualKind::exit(),
            surface: None,
            authority: "ref-cli-1.8.2".into(),
            scope: "malformed-input".into(),
            candidate_sha256: "c".repeat(64),
            raw_reference: "2".into(),
            raw_candidate: "1".into(),
            raw_reference_sha256: "a".repeat(64),
            raw_candidate_sha256: "b".repeat(64),
        };
        let yaml = serde_yaml::to_string(&record).unwrap();
        assert!(
            !yaml.contains("disposition"),
            "the immutable observation must not carry a disposition"
        );
        let back: ResidualRecord = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(back.raw_reference, "2");
        assert_eq!(back.candidate_sha256, "c".repeat(64));
    }

    #[test]
    fn disposition_events_carry_the_closures() {
        let closed = DispositionEvent::closed(
            "cli-exit-0001",
            ClosureKind::Intentional,
            "clearer wording".into(),
        )
        .unwrap();
        assert_eq!(closed.disposition.as_str(), "intentional");
        let yaml = serde_yaml::to_string(&closed).unwrap();
        assert!(yaml.contains("disposition: intentional"));
        let back: DispositionEvent = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(back.disposition, closed.disposition);

        let fixed = DispositionEvent::fixed(
            "cli-exit-0001",
            "patched".into(),
            "run-cli-malformed-input-x".into(),
            CLOSURE_PREDICATE_FIX_COURT.into(),
        )
        .unwrap();
        assert_eq!(fixed.disposition.as_str(), "fixed");
        assert_eq!(
            fixed.disposition.resolution_run_id(),
            Some("run-cli-malformed-input-x")
        );
        // Events can never be `open`.
        assert!(DispositionEvent::closed("r", ClosureKind::Intentional, "   ".into()).is_err());
        assert!(DispositionEvent::fixed("r", "x".into(), "   ".into(), "p".into()).is_err());
    }

    #[test]
    fn disposition_event_reader_is_strict() {
        let good = "schema_version: frf-disposition-v2\nevent_id: aaaa\nresidual_id: r\nparent_event_id: null\ndisposition: intentional\nreason: clearer wording\nevidence_refs: []\n";
        let parsed: DispositionEvent = serde_yaml::from_str(good).unwrap();
        assert_eq!(parsed.disposition.as_str(), "intentional");

        // An unknown property is refused, never dropped before the event
        // identity is recomputed (the event is content-addressed).
        let bad = format!("{good}unrecognized: tampered\n");
        let err = serde_yaml::from_str::<DispositionEvent>(&bad).unwrap_err();
        assert!(err.to_string().contains("unknown field"), "error: {err}");

        // Cross-field rules are enforced literally: a fixed event without a
        // resolution run is refused; an intentional event carrying one is.
        let bad = "schema_version: frf-disposition-v2\nevent_id: aaaa\nresidual_id: r\nparent_event_id: null\ndisposition: fixed\nreason: patched\nevidence_refs: []\n";
        assert!(serde_yaml::from_str::<DispositionEvent>(bad).is_err());
        let bad = "schema_version: frf-disposition-v2\nevent_id: aaaa\nresidual_id: r\nparent_event_id: null\ndisposition: intentional\nreason: x\nresolution_run_id: run-y\nevidence_refs: []\n";
        assert!(serde_yaml::from_str::<DispositionEvent>(bad).is_err());
    }
}
