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

/// A parsed-but-not-yet-verified evidence document (0.1.59).
///
/// Parsing evidence-shaped data does not make it evidence: identity and
/// derivation must be ESTABLISHED before semantic consumption. The raw store
/// loaders (`Store::load_residual`, `load_capture`, `load_receipt`, …) parse
/// the canonical document and return `Unverified<T>` — the marker makes raw
/// loads visible at every call site and keeps new consumers on the verified
/// path (`verify::load_*_verified`, which returns the private-field
/// `*Verified` types that only exist after the proofs ran).
///
/// The deliberate escapes:
///
/// - [`Unverified::into_inner`] — for PRODUCERS (the court constructs the
///   records it just wrote, the series accumulation reads its own parent
///   chain) and for the verified loaders themselves (parse, then prove).
///   Every semantic CONSUMER of an observation record should prefer the
///   verified loaders.
/// - [`Unverified::inner`] — a read-only peek without consuming (used where
///   a caller only reads metadata before deciding which verified loader to
///   invoke).
pub struct Unverified<T>(T);

impl<T> Unverified<T> {
    /// The store loaders' constructor; the field stays private so the marker
    /// cannot be fabricated outside the store's parse path.
    pub(crate) fn new(inner: T) -> Unverified<T> {
        Unverified(inner)
    }

    /// Explicitly accept the parsed document WITHOUT the identity/derivation
    /// proofs. Reserved for producers and verified loaders; see the type
    /// documentation.
    pub fn into_inner(self) -> T {
        self.0
    }

    /// Read-only access to the parsed document without consuming it.
    pub fn inner(&self) -> &T {
        &self.0
    }
}

pub const SCHEMA_AUTHORITY: &str = "frf-authority-v1";
/// Execution-context closure schema: the DECLARED runtime closure of an
/// execution — the child executables, runtime libraries, and data
/// dependencies the side's behavior depends on beyond its own bytes (the
/// interpreter chain and native startup-link closure bind the artifact
/// ITSELF; this closure binds what it SPAWNS and LOADS). Content-addressed
/// as FRF/EXECUTION-CONTEXT/v1; snapshotted at observation time.
pub const SCHEMA_EXECUTION_CONTEXT: &str = "frf-execution-context-v1";
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
/// they print. v10 records the normalizer relations applied to the compared
/// streams and the normalizer/capture-adapter/minimizer implementations
/// bound at observation time. v11: the recorded `court_semantic_identity`
/// is the FRF/COURT/v2 formula — the question now covers the normalizer
/// and capture-adapter SEMANTICS, not only the comparator relations. v12:
/// the run identity is the FRF/RUN/v2 composition of the OBSERVATION
/// identity (FRF/OBSERVATION/v1 — what was observed) and the EXECUTION
/// identity (FRF/EXECUTION/v1 — under exactly what machinery/contract it
/// was observed: the execution profile, the EFFECTIVE capture bounds
/// including FRF_EXEC_* overrides, the runner executable, the side
/// interpreter chains, and every comparator/normalizer/adapter/minimizer
/// implementation). The capture records both identities, and the run id
/// commits the contract — two executions that coincide on outputs but
/// differ on bounds or profile are different bounded observations. v13:
/// the capture also carries the court's DECLARED EXECUTION-CONTEXT CLOSURE
/// (when declared): the child executables, runtime libraries, and data
/// dependencies the side's behavior depends on beyond its own bytes,
/// snapshotted and content-addressed at observation time (FRF/EXECUTION-
/// CONTEXT/v1) — a declared dependency is bound to the exact bytes, never
/// assumed.
pub const SCHEMA_CAPTURE: &str = "frf-capture-v15";
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
/// later experiments that reference the same content-addressed run can
/// never change what a receipt means. v10 makes the comparator layer
/// OBSERVABLE-PLUGGABLE: observable ids and residual kinds become open
/// protocol identifiers (no closed enum), each comparator semantic carries
/// its extractor and residual classifier (its specification hash REDERIVES
/// from its own fields), external implementations record their artifact
/// identity, and an externally served observable binds the exact comparator
/// request/result records that produced its verdict. v11 binds the
/// EXECUTION PROFILE: which reference execution contract observed the run
/// and the exact capture bounds that applied (timeout, stream caps,
/// resource limits) — an observation is made under a declared harness
/// contract, and exact replay requires the same one. v12 replaces the
/// single drift/slew/series sign with TRAJECTORY EVIDENCE: a residual does
/// not have one universal drift — it has a trajectory with respect to a
/// coordinate system, and the receipt entry carries one entry per
/// coordinate system the run participates in (`sign.trajectory_evidence`),
/// each pinning the exact ExecutionSeries snapshot the drift/slew were
/// derived from. v13 records the normalizer relations applied to the
/// compared streams. v14: the receipt also carries the capture-ADAPTER
/// relations applied (the axis-keyed observation semantics — part of the
/// court semantic identity, so a receipt can rederive the question it
/// The OpenReceipt protocol version this implementation speaks.
/// v15: the execution profile adds the per-side process-count limit
/// (`rlimit_nproc`, RLIMIT_NPROC) — the capture bounds record the complete
/// resource contract the observation was made under. v18: the receipt also
/// carries the court's DECLARED EXECUTION-CONTEXT CLOSURE (when declared):
/// the child executables, runtime libraries, and data dependencies the
/// side's behavior depends on beyond its own bytes, snapshotted and
/// content-addressed at observation time — the transitive execution
/// context, declared (never assumed) and bound to the exact bytes. v19: the
/// capture bounds carry the PRODUCED-TREE CAPS (the filesystem-tree
/// surface's overflow bounds: produced_max_files / produced_max_bytes /
/// produced_max_file_bytes) — a produced tree that exceeds a cap is refused
/// like a stream overflow, never truncated, and the enforced caps are part
/// of the recorded harness contract.
pub const SCHEMA_RECEIPT: &str = "frf-receipt-v19";
/// Claim schema. v2 carries the full Claim IR: the structured scope K, the
/// blocking residuals, the premise receipts (`requires`), the comparison
/// relation, and the machine proposition — admission is the paper's rule
/// `Scope(K) ⊆ Scope(P₁ ∪ … ∪ Pₙ)`, implemented literally. v3 binds the
/// EVIDENCE UNIVERSE the claim's absence search ran over
/// ([`KnowledgeSnapshot`]): a claim is admissible relative to an explicitly
/// committed state of knowledge — no unresolved residual IN U intersects K —
/// and the compiled claim carries U's content address, so the negative
/// search (not merely the positive premises) is portable and reproducible
/// by any implementation. v4: the knowledge snapshot is a TYPED CONTENT
/// REFERENCE — every residual head commits its record content address and
/// fingerprint, and the universe is a list of typed objects (kind, id, cid),
/// so the negative search's dependency set is itself content-addressed.
/// v5: the claim is compiled under a declared ADMISSION POLICY (baseline /
/// sensitivity-backed / independently-witnessed / high-assurance), and the
/// claim carries the capability evidence that satisfied the tier — per-axis
/// challenge coverage (the court demonstrated it can SEE the claimed
/// surface's defect classes), the witness statements that attested the
/// receipt, and the replay contract the observation was made under.
/// v6: the claim is MULTI-PREMISE — `scope` is K as an [`EvidenceRegion`]
/// (one cell per premise's clean surface, the honest DNF union — a union of
/// Cartesian products is never the product of dimension-wise unions),
/// `requires` carries every premise receipt, and admission is the literal
/// containment `K ⊆ P₁ ∪ … ∪ Pₙ` over the region cells: every point of K
/// lies in SOME premise cell, and a blocking residual blocks exactly the
/// claims whose surface intersects ANY cell.
/// v7: the claim CARRIES the independence evidence bound to its witness
/// statements (`independence_evidence`) — the declared independence
/// relations (spec/witness.md §6) that attest the premises, so an
/// independently-witnessed claim documents WHICH independence claims were
/// made, never conflating them with FRF's own verification. Admission
/// REQUIRES at least one admissible independence relation per premise
/// receipt at `independently-witnessed` and above: an affirming witness
/// with zero declared independence is witnessed, not independently
/// witnessed.
/// v8: the claim is a content-addressed IMMUTABLE protocol object
/// (`FRF/CLAIM/v1` over the canonical document minus the id; stored at
/// `claims/<id>.json` with the `claims/by-receipt/<receipt>/<id>` index —
/// the same receipt under a different universe or policy is a different
/// claim, and they coexist forever), and the stored prose fields
/// (`positive`/`non_claims`) are GONE — prose is a renderer output derived
/// from the verified IR, never stored as authoritative Claim IR.
/// v9: the SENSITIVITY MUTATION PROFILE — a sensitivity-backed claim (and
/// every tier above it) names WHICH mutation families were demonstrated on
/// each claimed surface: the claim records the required profile it was
/// compiled under (`--mutation-profile AXIS:FAMILY,…`) and each capability
/// entry records the DEMONSTRATED operators of its covering challenges, so
/// `claimed observables(K) ⊆ demonstrated-sensitive observables(C)` is
/// policy-checkable per family — and still bounded (a demonstrated family is
/// never a universal-correctness claim).
pub const SCHEMA_CLAIM: &str = "frf-claim-v9";
/// Runner identity block recorded in every capture at court time.
pub const SCHEMA_RUNNER: &str = "frf-runner-v1";

/// Claim admission policies — the assurance grade a claim is compiled under.
/// Each tier is a SUPERSET of the previous: the evidence that satisfies it
/// is carried in the compiled claim, so admission re-derives in any
/// implementation from the claim alone.
///
/// - [`CLAIM_POLICY_BASELINE`]: observation evidence only (the receipt's
///   verified run, the absence scan over the committed universe).
/// - [`CLAIM_POLICY_SENSITIVITY_BACKED`]: every claimed observable axis must
///   have CHALLENGE coverage — the court demonstrated it can SEE that
///   surface's defect class (same court semantic identity, same reference
///   artifact, a mutation on exactly that axis observed and nothing else).
/// - [`CLAIM_POLICY_INDEPENDENTLY_WITNESSED`]: sensitivity coverage PLUS a
///   verified witness attestation of the receipt (`outcome: affirm`) PLUS at
///   least one admissible INDEPENDENCE relation per premise receipt (a
///   content-addressed `IndependenceEvidence` record bound to an attestation
///   of that premise). An attestation alone is WITNESSED, not independently
///   witnessed — the tier's name is its semantics.
/// - [`CLAIM_POLICY_HIGH_ASSURANCE`]: independently witnessed PLUS the
///   observation was made under the reference execution profile with the
///   REFERENCE capture bounds — protocol constants that no `FRF_EXEC_*`
///   override can redefine (the exact-replay contract).
pub const CLAIM_POLICY_BASELINE: &str = "baseline";
pub const CLAIM_POLICY_SENSITIVITY_BACKED: &str = "sensitivity-backed";
pub const CLAIM_POLICY_INDEPENDENTLY_WITNESSED: &str = "independently-witnessed";
pub const CLAIM_POLICY_HIGH_ASSURANCE: &str = "high-assurance";
pub const CLAIM_POLICIES: &[&str] = &[
    CLAIM_POLICY_BASELINE,
    CLAIM_POLICY_SENSITIVITY_BACKED,
    CLAIM_POLICY_INDEPENDENTLY_WITNESSED,
    CLAIM_POLICY_HIGH_ASSURANCE,
];
/// Environment identity block recorded in every capture at court time. v2
/// expands the strata the digest covers: os, architecture, kernel release,
/// effective locale, timezone, and umask (the dimensions that actually move
/// side output), plus the recorded working directory. v3 records the
/// DECLARED EXECUTION ENVIRONMENT: the exact environment every program the
/// court executed ran under (built from scratch — the host's ambient
/// environment is never inherited and never recorded), and the digest is the
/// FRF/ENVIRONMENT/v2 canonical-JSON formula over the host strata AND the
/// declared environment map.
pub const SCHEMA_ENVIRONMENT: &str = "frf-environment-v3";
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

/// The cgroup v2 execution profile (`spec/execution-profile.md` §
/// `frf-exec-linux-v2`): the per-side AGGREGATE resource envelope the
/// setrlimit layer cannot give. Each side's WHOLE descendant tree runs in
/// its own cgroup with `pids.max` / `memory.max` / `cpu.max` — bounded per
/// side, not per real user id (RLIMIT_NPROC) and not per process
/// (RLIMIT_AS/RLIMIT_CPU). setrlimit remains a second layer. Requires a
/// writable cgroup v2 subtree (systemd delegation, a container with a
/// writable `/sys/fs/cgroup`, or a delegated user session); without one the
/// profile REFUSES to run — a declared profile is enforced, never
/// approximated.
pub const EXECUTION_PROFILE_LINUX_V2: &str = "frf-exec-linux-v2";

/// The I/O-CLOSED execution profile (`frf-exec-linux-v3`, 0.1.65,
/// `spec/execution-profile.md`): on top of the reference setrlimit layer,
/// each side's world is CLOSED — the filesystem closure (Landlock: the side
/// may read/execute only the content-addressed objects directory, the
/// execution machinery (interpreter, native runtime closure, declared
/// execution-context artifacts), the declared randomness channel, and the
/// produced-output staging directory — its only writable surface) and the
/// ambient channel closure (seccomp: no network, no Unix sockets, no shared
/// memory, no ptrace, no cross-process memory). A side that violates a
/// closure fails visibly and the observation captures the denial — the
/// court OBSERVES the denied access. The side executes its VERIFIED SNAPSHOT
/// PATH (the sealed-memfd mechanism is incompatible with a Landlock closure:
/// the kernel cannot bind access rules to anonymous-inode memfds — proven
/// empirically, see `src/sandbox.rs`); the OCI profile remains the mechanism
/// that closes both the path race and the ambient-environment race. Requires
/// Landlock (kernel >= 5.13, in the boot-time LSM list); without it the
/// profile REFUSES to run — a declared profile is enforced, never
/// approximated. The reference profile remains `frf-exec-linux-v1`;
/// `high-assurance` claim admission requires it.
pub const EXECUTION_PROFILE_LINUX_V3: &str = "frf-exec-linux-v3";

/// The OCI execution profile (`frf-exec-oci`, `spec/execution-profile.md`):
/// each side runs INSIDE a container spawned from a content-addressed OCI
/// image (digest-pinned — the image is resolved by its manifest digest, and
/// a missing or different image REFUSES the run). The image is the COMPLETE
/// execution machinery: instead of declaring the runtime closure artifact by
/// artifact (frf-execution-context-v1), the whole root filesystem — the
/// interpreter, the shared libraries, the loader configuration, the
/// certificates — is bound by the image digest in the execution identity. A
/// container runtime (`podman` or `docker`) must be present; without one the
/// profile REFUSES to run — a declared profile is enforced, never
/// approximated. The reference profile remains `frf-exec-linux-v1`;
/// `high-assurance` claim admission requires it.
pub const EXECUTION_PROFILE_OCI: &str = "frf-exec-oci";

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

/// The mutation extension protocol (spec/mutation.md): an external mutation
/// PROVIDER proposes a mutant candidate for a court challenge. The provider
/// declares the axes it seeds defects on; the court independently decides
/// whether the mutant moved the target axis and nothing else — the extension
/// proposes, the court decides.
pub const SCHEMA_MUTATION_REQUEST: &str = "frf-mutation-request-v1";
pub const SCHEMA_MUTATION_RESPONSE: &str = "frf-mutation-response-v1";
pub const SCHEMA_MUTATION_INVOCATION: &str = "frf-mutation-invocation-v1";
pub const SCHEMA_MUTATION_RESULT: &str = "frf-mutation-result-v1";

pub const SCHEMA_RUNTIME_CLOSURE: &str = "frf-runtime-closure-v1";

/// The capture bounds that actually applied to a court's executions — the
/// execution profile's parameters as enforced (the profile's defaults, or
/// the test hooks' overrides). Recorded at observation time so a receipt
/// never guesses what the harness bounded. All values are STRINGS: the
/// OpenReceipt canonical value domain has no numbers.
///
/// v16: the `cgroup_*` fields — the per-side AGGREGATE envelope of the
/// `frf-exec-linux-v2` profile (pids.max / memory.max / cpu.max over the
/// whole descendant tree). They are ABSENT under the reference profile v1
/// (whose bounds are per-process setrlimit limits + the per-real-UID
/// RLIMIT_NPROC layer, not an aggregate envelope), so a v15-shaped document
/// is a valid v16 document.
///
/// v19: the PRODUCED-TREE caps — the filesystem-tree surface's overflow
/// bounds (per side): the maximum produced file count, the maximum total
/// produced bytes, and the maximum bytes of any one produced file. A side
/// whose produced tree exceeds a cap is refused exactly like a stream
/// overflow (never truncated), and the enforced caps are recorded here so
/// replay enforces the same bounds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureBounds {
    /// Milliseconds until a side is killed (the profile's timeout).
    pub timeout_ms: String,
    /// Maximum bytes retained per output stream; a side that exceeds it is
    /// killed and the run REFUSED (truncated output is never evidence).
    pub max_stream_bytes: String,
    /// v19: the maximum number of files a side's produced tree may contain.
    pub produced_max_files: String,
    /// v19: the maximum TOTAL bytes of a side's produced tree.
    pub produced_max_bytes: String,
    /// v19: the maximum bytes of any ONE produced file.
    pub produced_max_file_bytes: String,
    /// Address-space limit of each side, in MiB (RLIMIT_AS).
    pub rlimit_as_mb: String,
    /// CPU-time limit of each side, in seconds (RLIMIT_CPU).
    pub rlimit_cpu_s: String,
    /// Open-file limit of each side (RLIMIT_NOFILE).
    pub rlimit_nofile: String,
    /// Process-count limit of each side (RLIMIT_NPROC, v15): a side cannot
    /// fork a process bomb that exhausts the user's process table while the
    /// harness waits for its own timeout. Linux semantics: the limit is
    /// per REAL USER ID, not per side, and privileged execution is exempt —
    /// it is one layer of the contract, not a per-side aggregate envelope
    /// (the cgroup v2 profile is that).
    pub rlimit_nproc: String,
    /// v16, `frf-exec-linux-v2` only: the cgroup v2 `pids.max` of the side's
    /// whole process tree — the per-side aggregate process-count envelope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup_pids_max: Option<String>,
    /// v16, `frf-exec-linux-v2` only: the cgroup v2 `memory.max` (bytes) of
    /// the side's whole process tree — the per-side aggregate memory
    /// envelope a per-process RLIMIT_AS cannot give.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup_memory_max: Option<String>,
    /// v16, `frf-exec-linux-v2` only: the cgroup v2 `cpu.max` (`quota
    /// period`, microseconds) of the side's whole process tree — the
    /// per-side aggregate CPU envelope a per-process RLIMIT_CPU cannot give.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup_cpu_max: Option<String>,
}

/// The protocol's maxima for the capture bounds — a receipt can never claim
/// the harness enforced an unbounded or absurd contract.
pub const CAPTURE_BOUND_MAX_TIMEOUT_MS: u64 = 3_600_000; // 1 hour
pub const CAPTURE_BOUND_MAX_STREAM_BYTES: u64 = 1 << 30; // 1 GiB
pub const CAPTURE_BOUND_MAX_PRODUCED_FILES: u64 = 65_536;
pub const CAPTURE_BOUND_MAX_PRODUCED_BYTES: u64 = 1 << 36; // 64 GiB
pub const CAPTURE_BOUND_MAX_PRODUCED_FILE_BYTES: u64 = 1 << 30; // 1 GiB
pub const CAPTURE_BOUND_MAX_RLIMIT_AS_MB: u64 = 65_536; // 64 GiB
pub const CAPTURE_BOUND_MAX_RLIMIT_CPU_S: u64 = 86_400; // 1 day
pub const CAPTURE_BOUND_MAX_RLIMIT_NOFILE: u64 = 1_048_576;
pub const CAPTURE_BOUND_MAX_RLIMIT_NPROC: u64 = 65_536;
pub const CAPTURE_BOUND_MAX_CGROUP_PIDS: u64 = 65_536;
pub const CAPTURE_BOUND_MAX_CGROUP_MEMORY: u64 = 1 << 36; // 64 GiB
pub const CAPTURE_BOUND_MAX_CGROUP_CPU_QUOTA_US: u64 = 1_000_000; // 1 second
pub const CAPTURE_BOUND_MAX_CGROUP_CPU_PERIOD_US: u64 = 1_000_000;

/// Validate capture bounds: positive integers within the protocol's maxima.
/// The v16 `cgroup_*` fields, when present, must be positive integers (the
/// `cpu.max` value is the kernel's `quota period` pair) within the protocol's
/// maxima.
pub fn validate_capture_bounds(b: &CaptureBounds) -> crate::error::Result<()> {
    for (what, v, max) in [
        ("timeout_ms", &b.timeout_ms, CAPTURE_BOUND_MAX_TIMEOUT_MS),
        (
            "max_stream_bytes",
            &b.max_stream_bytes,
            CAPTURE_BOUND_MAX_STREAM_BYTES,
        ),
        (
            "produced_max_files",
            &b.produced_max_files,
            CAPTURE_BOUND_MAX_PRODUCED_FILES,
        ),
        (
            "produced_max_bytes",
            &b.produced_max_bytes,
            CAPTURE_BOUND_MAX_PRODUCED_BYTES,
        ),
        (
            "produced_max_file_bytes",
            &b.produced_max_file_bytes,
            CAPTURE_BOUND_MAX_PRODUCED_FILE_BYTES,
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
        (
            "rlimit_nproc",
            &b.rlimit_nproc,
            CAPTURE_BOUND_MAX_RLIMIT_NPROC,
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
    if let Some(v) = &b.cgroup_pids_max {
        let n: u64 = v.parse().map_err(|_| {
            crate::error::FrfError::new(format!(
                "capture bound cgroup_pids_max must be a positive integer, got {v:?}"
            ))
        })?;
        if n == 0 || n > CAPTURE_BOUND_MAX_CGROUP_PIDS {
            return Err(crate::error::FrfError::new(format!(
                "capture bound cgroup_pids_max = {n} outside (0, {CAPTURE_BOUND_MAX_CGROUP_PIDS}]"
            )));
        }
    }
    if let Some(v) = &b.cgroup_memory_max {
        let n: u64 = v.parse().map_err(|_| {
            crate::error::FrfError::new(format!(
                "capture bound cgroup_memory_max must be a positive integer, got {v:?}"
            ))
        })?;
        if n == 0 || n > CAPTURE_BOUND_MAX_CGROUP_MEMORY {
            return Err(crate::error::FrfError::new(format!(
                "capture bound cgroup_memory_max = {n} outside (0, {CAPTURE_BOUND_MAX_CGROUP_MEMORY}]"
            )));
        }
    }
    if let Some(v) = &b.cgroup_cpu_max {
        let parts: Vec<&str> = v.split_whitespace().collect();
        if parts.len() != 2 {
            return Err(crate::error::FrfError::new(format!(
                "capture bound cgroup_cpu_max must be the kernel's `quota period` pair, got {v:?}"
            )));
        }
        let quota: u64 = parts[0].parse().map_err(|_| {
            crate::error::FrfError::new(format!(
                "capture bound cgroup_cpu_max quota must be a positive integer, got {:?}",
                parts[0]
            ))
        })?;
        let period: u64 = parts[1].parse().map_err(|_| {
            crate::error::FrfError::new(format!(
                "capture bound cgroup_cpu_max period must be a positive integer, got {:?}",
                parts[1]
            ))
        })?;
        if quota == 0
            || period == 0
            || quota > CAPTURE_BOUND_MAX_CGROUP_CPU_QUOTA_US
            || period > CAPTURE_BOUND_MAX_CGROUP_CPU_PERIOD_US
        {
            return Err(crate::error::FrfError::new(format!(
                "capture bound cgroup_cpu_max = {v} outside (0, {CAPTURE_BOUND_MAX_CGROUP_CPU_QUOTA_US}] us quota / (0, {CAPTURE_BOUND_MAX_CGROUP_CPU_PERIOD_US}] us period"
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
/// v4: the extended vocabulary — drift gains `boundary-localized` (a single
/// contiguous band touching exactly one axis bound) and `version-stratified`
/// (2+ bands along an ordered version/revision axis); slew gains `gradual`
/// (a monotonic magnitude trend across the axis, driven by the new
/// per-observation `magnitude` measure and the derivation's `trend`).
/// v5: the observations carry the CONTENT IDENTITY of their coordinate
/// (`FRF/COORDINATE/v1`) — a trajectory says exactly what varied at each
/// point (the candidate artifact identity, the authority record address, the
/// effective environment digest), not merely what the point was labelled.
pub const SCHEMA_TRAJECTORY: &str = "frf-trajectory-v5";

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
/// the same content-addressed run. v4: each point carries the CONTENT
/// IDENTITY of its coordinate (`FRF/COORDINATE/v1`), so the series says what
/// EXACTLY varied at each point, not merely what it was labelled.
pub const SCHEMA_SERIES: &str = "frf-series-v4";

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
pub const SCHEMA_WITNESS_RESPONSE: &str = "frf-witness-response-v3";
pub const SCHEMA_WITNESS_STATEMENT: &str = "frf-witness-statement-v3";
/// The witness INDEPENDENCE relation: the declared independence claim about a
/// witness statement, with its evidence (spec/witness.md §6). One statement
/// may carry several independence records (different relations, declarants,
/// bases).
pub const SCHEMA_INDEPENDENCE: &str = "frf-independence-v1";

/// The closed set of independence RELATIONS a declarant may claim about a
/// witness statement. Every relation is a DECLARED claim with a mandatory
/// basis — FRF verifies the evidence structure, never the social truth of
/// independence, and a different executable hash is never by itself
/// evidence of independent observation.
pub const INDEPENDENCE_RELATIONS: &[&str] = &[
    "different-implementation",
    "separate-party",
    "unaffiliated-channel",
    "adversarial-review",
];

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
    /// (`FRF/NORMALIZER-SPEC/v2`).
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
    /// The domain-aware minimality the minimizer CLAIMS its proposal
    /// establishes (kind=`boundary`, with the declared domain/ordering/
    /// points and the ADJACENT NON-PASSING FIXTURE bytes the core can
    /// execute). The core court-verifies the boundary itself — the final
    /// verification preserved AND the adjacent control lost — before
    /// `proven` can be true; the declaration alone is a claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimality: Option<MinimizerMinimality>,
    /// The minimizer's own attempt log (the core records which survived
    /// court verification).
    pub attempts: Vec<MinimizerAttempt>,
    pub indeterminate: bool,
    pub failure: Option<String>,
}

/// The domain-aware minimality DECLARATION a minimizer may attach to its
/// proposal (frf-minimizer-response-v1): the proposal claims to sit at an
/// observation boundary of a numeric parameter. Every coordinate is a STRING
/// (the canonical JSON value domain is strings/arrays/booleans/null). The
/// core verifies the adjacent fixture hashes to its declared sha256, is not
/// the proposal itself, and then EXECUTES it: the boundary is proven only
/// when the adjacent point loses the lineage and the proposal preserves it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MinimizerMinimality {
    /// `boundary` in this version.
    pub kind: String,
    /// The domain the boundary is over (e.g.
    /// `heartbeat.claimed_payload_length`).
    pub domain: String,
    /// The declared ordering of the boundary domain (e.g.
    /// `integer-ascending`).
    pub ordering: String,
    /// The passing point (decimal string) — the parameter value at which
    /// the proposal preserves the lineage.
    pub passing_point: String,
    /// The adjacent non-passing point (decimal string) — one step below the
    /// passing point in the declared ordering.
    pub adjacent_nonpassing_point: String,
    /// The ADJACENT NON-PASSING FIXTURE (base64 + SHA-256): the exact bytes
    /// the core executes to observe the boundary's other side.
    pub adjacent_fixture_sha256: String,
    pub adjacent_fixture_base64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MinimizerAttempt {
    /// The attempt index, as a STRING: the canonical JSON value domain is
    /// strings/arrays/booleans/null, so an attempt counter cannot be a JSON
    /// number (RFC 8785 number serialization is out of scope for the
    /// protocol value domain). The core records its own executable attempts
    /// with real ordering in the reduction record.
    pub attempt: String,
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
    /// The authority the witness declares it acts for (v3, optional): a
    /// declared identity, recorded verbatim — FRF verifies the response is
    /// canonical and names its request; it never interprets who the
    /// authority is or whether the declaration is true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<WitnessAuthority>,
}

/// The declared authority a witness acts for (the witness's own
/// declaration, recorded verbatim). `kind` is a closed set the host
/// enforces: the protocol distinguishes WHO claims to have attested, and
/// that claim is the witness's, never FRF's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessAuthority {
    /// The authority's declared id (e.g. a name or handle).
    pub id: String,
    /// `person` | `organization` | `automated` | `other`.
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl WitnessAuthority {
    pub const KINDS: [&'static str; 4] = ["person", "organization", "automated", "other"];
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessAttestation {
    /// The exact statement the witness attests (must equal the request's).
    pub statement: String,
    /// The witness's own assertion: `affirm`, `deny`, or `indeterminate`.
    /// This is the witness's claim about the world — NOT FRF's verification.
    /// FRF's verification of the evidence object's integrity is the
    /// content-address + the loader's rehash; the two predicates are never
    /// conflated. Independence is a separate, DECLARED relation
    /// ([`IndependenceEvidence`]) — a different executable hash is never by
    /// itself evidence of independent observation.
    pub outcome: String,
    pub detail: String,
}

/// The WITNESS IDENTITY: the stable WHO behind an attestation, content-
/// addressed over the relation's specification and the program's exact
/// bytes + interpreter chain (`FRF/WITNESS-IDENTITY/v1`). Two attestations
/// with the same identity were made by the same instrument; a different
/// identity is a different instrument — and nothing more (identity
/// distinctness is never independence).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessIdentity {
    /// The relation's specification hash (what the attestation relation is).
    pub specification_hash: String,
    /// The program bytes (what implemented the attestation).
    pub implementation_hash: String,
    /// The interpreter chain, when the program is a script.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interpreter: Option<InterpreterIdentity>,
}

/// The content-addressed [`WitnessStatement`] record: an attestation bound
/// to a content-addressed subject, with the canonical request/response
/// preserved as evidence. Identity: SHA-256 of `FRF/WITNESS-STATEMENT/v1`
/// over the record's fields. v3 adds the witness IDENTITY (the stable WHO)
/// and the declared AUTHORITY.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessStatement {
    pub schema_version: String,
    pub id: String,
    pub subject: WitnessSubject,
    pub witness_semantic: WitnessSemantic,
    pub witness_implementation: WitnessImplementation,
    /// The content-addressed witness identity (v3): the stable WHO.
    pub witness_identity: String,
    /// The declared authority (v3), when the witness declared one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<WitnessAuthority>,
    pub statement: String,
    pub attestation: WitnessAttestation,
    pub request_cid: String,
    pub response_cid: String,
    pub created_by: RunnerIdentity,
}

/// The INDEPENDENCE EVIDENCE record (spec/witness.md §6): a DECLARED
/// independence claim about one witness statement, with the evidence that
/// supports it. The declarant (an operator) states the relation and its
/// basis; FRF verifies the evidence structure — the statement verifies, the
/// identity rederives, the relation is closed, the typed evidence refs
/// rederive — never the social truth of independence. Claims that require
/// an independent witness may carry these records, and the compiled claim
/// names them so the independence claim is as portable as the attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndependenceEvidence {
    pub schema_version: String,
    /// Content address: `FRF/INDEPENDENCE/v1` over the record's fields.
    pub id: String,
    /// What was attested (copied from the statement; verified to match).
    pub subject: WitnessSubject,
    /// The attested statement this independence claim binds.
    pub witness_statement: String,
    /// The witness identity of the statement (the stable WHO).
    pub witness_identity: String,
    /// One of [`INDEPENDENCE_RELATIONS`].
    pub relation: String,
    pub relation_version: String,
    /// `FRF/INDEPENDENCE-SPEC/v1` over `{relation, relation_version}`.
    pub specification_hash: String,
    /// The declarant's stated basis (prose, mandatory): WHY the relation is
    /// claimed — the evidence the independence claim rests on.
    pub basis: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Typed content references: the witness statement and the witness
    /// program artifact the claim rests on.
    pub evidence_refs: Vec<EvidenceRef>,
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

    /// The REGISTERED protocol record of this kind, if the kind is part of
    /// the protocol vocabulary ([`KIND_SCHEMAS`]). A residual whose kind has
    /// no record is evidence of a protocol this engine does not know — the
    /// semantic validator refuses it (fail closed).
    pub fn schema(&self) -> Option<&'static KindSchema> {
        KIND_SCHEMAS.iter().find(|s| s.id == self.0)
    }
}

/// The protocol record of one residual kind: what the kind MEANS, what its
/// surface grammar is, and which comparator family classifies residuals into
/// it. A residual kind is an identity-bearing protocol object like every
/// other evidentiary vocabulary member — the record's canonical identity is
/// [`crate::semantics::kind_identity`] (`FRF/KIND/v1`), so two
/// implementations that agree on the record agree on the kind. The records
/// are pinned in the conformance corpus (`conformance/kinds/`); the
/// reference engine's table is the registry the corpus pins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KindSchema {
    pub id: &'static str,
    pub meaning: &'static str,
    pub surface_grammar: &'static str,
    pub comparator_family: &'static str,
}

/// The registered residual-kind vocabulary. The built-in comparators
/// classify into `exit` and `text`; the externally served `wire` and
/// `latency` axes (conformance corpus, the timing court) classify into
/// `wire` and `latency`. A future protocol kind is a new record here, in
/// `protocol/registry.json`, and in the corpus — never a silent
/// reinterpretation of an existing id.
pub const KIND_SCHEMAS: &[KindSchema] = &[
    KindSchema {
        id: "exit",
        meaning: "the candidate's exit class diverged from the reference's",
        surface_grammar: "exit code",
        comparator_family: "eq",
    },
    KindSchema {
        id: "text",
        meaning: "the candidate's compared text projection diverged from the reference's",
        surface_grammar: "the comparator's first-line projection",
        comparator_family: "eq",
    },
    KindSchema {
        id: "wire",
        meaning: "the candidate's compared byte-stream projection diverged from the reference's",
        surface_grammar: "the compared byte stream",
        comparator_family: "eq",
    },
    KindSchema {
        id: "latency",
        meaning: "the candidate's latency projection fell outside the declared envelope",
        surface_grammar: "latency ratio or parse outcome",
        comparator_family: "within-2x",
    },
];

/// The schema version of a kind protocol record (`conformance/kinds/`).
pub const SCHEMA_KIND: &str = "frf-kind-v1";

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
    /// Optional mutation-provider declarations (the extension protocol,
    /// spec/mutation.md): external programs that PROPOSE mutant candidates
    /// for `frf court challenge`. Each provider declares the observable axes
    /// it seeds defects on; the court decides the verdicts from the run.
    #[serde(default)]
    pub mutations: Vec<MutationDeclaration>,
    /// Optional CAPTURE-SURFACE declarations (the publication boundary, a
    /// general capability — spec/publication-surface.md): for each observed
    /// stream, HOW its bytes may be published. Every policy is part of the
    /// observation contract and is recorded in the capture; the publication
    /// transform honors it. Absent = every stream is `inline`.
    #[serde(default)]
    pub capture_surface: Vec<CaptureSurfacePolicy>,
}

/// One capture-surface declaration: HOW an observed stream may be published.
/// The policy vocabulary is closed and documented (spec/publication-surface.md):
///
/// - `inline` — the bytes are publishable as-is (safe text);
/// - `hash-only` — only the SHA-256 is publishable; the bytes stay local
///   (the publication transform withholds them and writes the disposition);
/// - `redacted-with-commitment` — the published bytes are a redacted
///   representative carrying a commitment (the policy declares the
///   redaction contract);
/// - `detached` — the bytes are external, reconstructable from a recipe;
/// - `synthetic-publication` — the published bytes are a SAFE SYNTHETIC
///   representative (e.g. a projection line), never the raw observation.
///
/// The court records the declarations in the capture (part of the
/// observation contract, bound into the observation identity); the
/// publication transform honors them; the verifier reports the stream
/// closure. A stream with NO declaration is `inline`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureSurfacePolicy {
    /// `reference` | `candidate`.
    pub side: String,
    /// `stdout` | `stderr` (the observed stream files).
    pub stream: String,
    /// One of `inline` | `hash-only` | `redacted-with-commitment` |
    /// `detached` | `synthetic-publication`.
    pub policy: String,
}

impl CaptureSurfacePolicy {
    /// The closed publication-policy vocabulary.
    pub const POLICIES: &'static [&'static str] = &[
        "inline",
        "hash-only",
        "redacted-with-commitment",
        "detached",
        "synthetic-publication",
    ];

    /// A stream declared `hash-only` or `detached` is NOT publishable: the
    /// bytes are withheld by the publication transform and only the
    /// disposition (hash + policy) travels.
    pub fn withholds_bytes(&self) -> bool {
        self.policy == "hash-only" || self.policy == "detached"
    }

    /// Semantic validation of one declaration: known side, known stream,
    /// known policy.
    pub fn validate(&self) -> std::result::Result<(), String> {
        if !matches!(self.side.as_str(), "reference" | "candidate") {
            return Err(format!(
                "capture-surface side {:?} is not reference|candidate",
                self.side
            ));
        }
        if !matches!(self.stream.as_str(), "stdout" | "stderr") {
            return Err(format!(
                "capture-surface stream {:?} is not stdout|stderr",
                self.stream
            ));
        }
        if !Self::POLICIES.contains(&self.policy.as_str()) {
            return Err(format!(
                "capture-surface policy {:?} is not one of {}",
                self.policy,
                Self::POLICIES.join(" | ")
            ));
        }
        Ok(())
    }
}

/// The disposition record of a WITHHELD stream in a publication: written by
/// the publication transform where the raw stream bytes used to live
/// (`captures/<run>/<side>.<stream>.pub.json`), naming the withheld bytes'
/// identity (SHA-256) and the policy that withheld them. A verifier finding
/// a declared non-publishable stream ABSENT must find exactly this record;
/// missing or mismatched, the tree is refused (a withheld stream cannot
/// silently disappear). Canonical JSON evidence, content-addressed by
/// position (the sha256 names the withheld bytes).
pub const SCHEMA_STREAM_PUBLICATION: &str = "frf-stream-publication-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamPublicationRecord {
    pub schema_version: String,
    /// `reference` | `candidate`.
    pub side: String,
    /// `stdout` | `stderr`.
    pub stream: String,
    /// The capture-surface policy that withheld the bytes (`hash-only` or
    /// `detached`).
    pub policy: String,
    /// SHA-256 of the WITHHELD bytes (must equal the capture's recorded
    /// stream hash).
    pub sha256: String,
}

/// The publication manifest written by `publish-detached`: the EXPLICIT,
/// deterministic record of every observed stream's disposition — which
/// streams were published as-is, and which were withheld and why. The
/// transform is a pure function of (source tree, policy); the manifest
/// rederives from the same inputs, so a publication can never silently
/// alter what an observation means.
pub const SCHEMA_PUBLICATION_MANIFEST: &str = "frf-publication-manifest-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationManifest {
    pub schema_version: String,
    /// Every captured stream of every run, sorted by (run, side, stream).
    pub streams: Vec<StreamDisposition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamDisposition {
    /// The run (capture) the stream belongs to.
    pub run: String,
    /// `reference` | `candidate`.
    pub side: String,
    /// `stdout` | `stderr`.
    pub stream: String,
    /// The effective policy (`inline` when the capture declared none).
    pub policy: String,
    /// SHA-256 of the stream bytes (the observation's identity).
    pub sha256: String,
    /// Whether the bytes travel with the publication.
    pub published: bool,
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

/// One external mutation-provider declaration in a court manifest (the
/// extension protocol, spec/mutation.md). The provider PROPOSES a mutant
/// candidate for a court challenge — not arbitrary source rewriting: the
/// court runs the proposed artifact and independently decides whether the
/// targeted axis moved and nothing else did. The declaration's
/// relation/version define the SEMANTIC identity; the program's bytes define
/// its IMPLEMENTATION identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationDeclaration {
    /// The operator id `--operators` names for this provider (e.g.
    /// `dns-response-swap`).
    pub id: String,
    /// The mutation family (e.g. `field-swap`) — part of the semantic
    /// identity.
    pub relation: String,
    pub relation_version: String,
    /// The observable axes this provider seeds defects on; each must be
    /// declared in the envelope's observables.
    pub target_axes: Vec<String>,
    /// Working-directory-relative path to the provider program. Read + hashed
    /// BEFORE execution, executed through a content-addressed snapshot,
    /// re-hashed on every use.
    pub program: String,
}

/// The semantic identity of a mutation relation: WHAT the mutation is, not
/// which program proposes it. Two implementations with the same
/// `specification_hash` ask for the same kind of mutant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationSemantic {
    /// The provider/operator id.
    pub id: String,
    /// The mutation family (part of the specification document).
    pub relation_id: String,
    pub relation_version: String,
    /// SHA-256 of the canonical specification document
    /// (`FRF/MUTATION-SPEC/v1` over id + relation + relation_version).
    pub specification_hash: String,
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
    /// The DECLARED execution profile (spec/execution-profile.md): the
    /// harness contract the sides and every extension program run under.
    /// Absent = the reference profile `frf-exec-linux-v1`. The declared
    /// profile is ENFORCED (never approximated): `frf-exec-linux-v2`
    /// requires a writable cgroup v2 subtree and refuses without one.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub execution_profile: Option<String>,
    /// The DECLARED EXECUTION ENVIRONMENT: the exact environment every
    /// program this court executes (both sides and every extension program)
    /// runs under — built from scratch, the host's ambient environment is
    /// never inherited (it is not evidence; inheriting it would leak secrets
    /// and make observations non-reproducible). Absent = the empty
    /// environment. The map is content-addressed into the observation: the
    /// capture's environment identity records it, and a new execution engine
    /// can reproduce the observation from the evidence alone.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub environment: Option<std::collections::BTreeMap<String, String>>,
    /// The DECLARED environment COORDINATES for the `--environment-point
    /// LABEL` axis: label → the env vars that define that coordinate. The
    /// point's effective environment is the court's declared `environment`
    /// with the coordinate's vars applied (coordinate wins). A label that is
    /// not declared here is refused — a coordinate label is not evidence
    /// unless the environment it names is.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub environment_points:
        Option<std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>>,
    /// The DECLARED execution-context closure: the child executables, runtime
    /// libraries, and data dependencies the side's execution depends on
    /// beyond its own bytes. Absent = no declared runtime dependencies (the
    /// side's context is its bytes + interpreter chain + declared
    /// environment). When declared, every artifact is snapshotted and
    /// content-addressed at observation time — a declared dependency is
    /// bound to the exact bytes, never assumed.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub execution_context: Option<ExecutionContextDeclaration>,
    /// The OCI image for the `frf-exec-oci` profile (0.1.62): the reference
    /// the runtime must resolve to its digest (e.g.
    /// `docker.io/library/alpine@sha256:…`). The image IS the complete
    /// execution machinery — the whole root filesystem is bound by the
    /// digest. Only valid with `execution_profile: frf-exec-oci`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub execution_image: Option<String>,
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
    /// The capture-surface declarations (the publication boundary): HOW each
    /// observed stream may be published, bound at observation time. Absent =
    /// every stream is `inline` (the historical default). The declarations
    /// are part of the observation contract (they enter the observation
    /// identity when present), so a tampered surface refuses the capture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publication_surface: Option<Vec<CaptureSurfacePolicy>>,
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
    /// The observation identity (`FRF/OBSERVATION/v1`): what was observed —
    /// the semantic question, inputs, effective environment, and the
    /// observed answer. Rederived from the recorded fields by every
    /// verifier; the run identity commits it.
    pub observation_identity: String,
    /// The execution identity (`FRF/EXECUTION/v1`): under exactly what
    /// machinery and contract the observation was made — the execution
    /// profile, the effective capture bounds (including `FRF_EXEC_*`
    /// overrides), the runner executable, the side interpreter chains, and
    /// every comparator/normalizer/adapter/minimizer implementation.
    /// Rederived from the recorded fields by every verifier; the run
    /// identity commits it.
    pub execution_identity: String,
    pub reference: SideCapture,
    pub candidate: SideCapture,
    pub residuals: Vec<String>,
    /// The harness events recorded during THIS run's observation (v15): the
    /// content addresses of the `harness/<id>.json` records written when a
    /// declared bound fired during a side's run — today the resource-limit
    /// signal (SIGXCPU — the CPU bound's declared outcome), which completes
    /// as a valid observation. A bound that REFUSES the run (stream
    /// overflow, timeout, produced overflow) leaves no capture to bind to;
    /// those events are court-scoped refusal evidence, named only by the
    /// refusal message.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub harness_events: Vec<String>,
    /// The run's outgoing evidence references: the authority, candidate, and
    /// fixture objects plus every external comparator implementation object.
    /// The bundle closure walks these (the generic graph traversal); a
    /// capture from an earlier version with no refs remains loadable (the
    /// closure walker falls back to the recorded artifact hashes).
    #[serde(default)]
    pub evidence_refs: Vec<EvidenceRef>,
    /// The snapshotted execution-context closure (when the court declared
    /// one): the child executables / runtime libraries / data dependencies
    /// the side's execution was declared to depend on, content-addressed at
    /// observation time.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub execution_context: Option<ExecutionContextClosure>,
    /// The OCI image the observation ran inside, present exactly when the
    /// court declared `execution_profile: frf-exec-oci` (0.1.62): the
    /// complete root filesystem the side ran under, bound by digest in the
    /// execution identity — the containerized equivalent of the declared
    /// execution-context closure.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub container_image: Option<OciImage>,
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
///
/// v3: the DECLARED EXECUTION ENVIRONMENT. The court declares the exact
/// environment its programs run under (the ambient host environment is
/// never inherited — it is not evidence); the sides and every extension
/// program are spawned with that environment and nothing else. `environment`
/// records the effective declared map (sorted by key), `locale`/`timezone`
/// derive from it when declared, and the digest is the FRF/ENVIRONMENT/v2
/// canonical-JSON formula over the host strata AND the declared map — a
/// declared variable is content-addressed input, so a new execution engine
/// can reproduce the observation from the evidence alone (the Shellshock
/// trigger, PATH, TZ, LD_PRELOAD, … are all explicit or absent).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentIdentity {
    pub schema_version: String,
    pub os: String,
    pub architecture: String,
    pub kernel_release: String,
    /// The effective locale the sides ran under: the declared `LC_ALL` /
    /// `LC_CTYPE` / `LANG`, or `C` when none is declared.
    pub locale: String,
    /// The timezone the sides ran under: the declared `TZ`, or the resolved
    /// system zone (from /etc/localtime), or `unknown`.
    pub timezone: String,
    /// The umask at observation time, as octal digits (e.g. `0022`).
    pub umask: String,
    /// The working directory the sides ran under (recorded provenance; exact
    /// replay requires the same cwd).
    pub cwd: String,
    /// The DECLARED execution environment the sides ran under, sorted by
    /// key — the exact map the harness spawned them with. The ambient host
    /// environment is never recorded.
    pub environment: std::collections::BTreeMap<String, String>,
    /// SHA-256 of the FRF/ENVIRONMENT/v2 canonical-JSON preimage over the
    /// host strata (os, architecture, kernel release, effective locale,
    /// timezone, umask) AND the declared environment map.
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
///
/// v17: a NATIVE (ELF) artifact additionally binds its runtime closure — the
/// dynamic loader (`PT_INTERP`), the resolved `DT_NEEDED` closure, and the
/// hash of every loaded component. For native software, `executable hash` is
/// not `executable semantics`; the closure is what the artifact actually
/// loaded, resolved by the system loader under the observation environment.
/// A script artifact carries the interpreter chain instead (never both).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactIdentity {
    /// The snapshot path this run actually executed (root-relative).
    pub path: String,
    pub sha256: String,
    /// Present when the artifact is a script with a resolvable shebang.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interpreter: Option<InterpreterIdentity>,
    /// Present when the artifact is a native ELF executable: the dynamic
    /// loader + resolved dependency closure, content-addressed (v17).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_runtime: Option<NativeRuntimeClosure>,
}

/// One declared runtime dependency of a court's execution: a child
/// executable the side spawns, a runtime library it loads, or a data
/// dependency it reads. The DECLARATION names the path (working-directory-
/// relative or absolute) and the role; the observation snapshots the bytes
/// and records the exact hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionContextArtifactDeclaration {
    /// Working-directory-relative or absolute path of the artifact.
    pub path: String,
    /// The role: `child-executable`, `runtime-library`, or `data` (a
    /// declared artifact whose role is not in the protocol set is refused).
    pub role: String,
}

/// The OCI image an `frf-exec-oci` observation ran inside (0.1.62): the
/// content-addressed container image, resolved by its manifest digest, and
/// the runtime that spawned it. The image IS the execution machinery — the
/// complete root filesystem the side ran under is bound by the digest in the
/// execution identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OciImage {
    /// The image reference as declared (e.g. `docker.io/library/alpine@sha256:…`)
    /// — the digest component is what the runtime must resolve to.
    pub reference: String,
    /// The digest the image must resolve to (e.g. `sha256:…`); a runtime
    /// that resolves the reference to a DIFFERENT digest refuses the run.
    pub digest: String,
    /// The container runtime that executed the side (`podman` or `docker`)
    /// and its version, at observation time.
    pub runtime: String,
}

/// The court's DECLARED execution-context closure: the runtime dependencies
/// the side's behavior depends on beyond its own bytes. The declaration is
/// part of the court (the manifest), the snapshot is part of the observation
/// (the capture) — a declared dependency is bound to the exact bytes at
/// observation time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionContextDeclaration {
    /// The declared artifacts, in declaration order (recorded sorted).
    pub artifacts: Vec<ExecutionContextArtifactDeclaration>,
}

/// One snapshotted execution-context artifact: the declared path, its role,
/// and the SHA-256 of its exact bytes at observation time (the bytes live in
/// the content-addressed object store).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionContextArtifact {
    pub path: String,
    pub role: String,
    pub sha256: String,
}

/// The observation-time snapshot of the court's declared execution-context
/// closure: the content-addressed set of runtime dependencies the side's
/// execution was declared to depend on. The identity is
/// `FRF/EXECUTION-CONTEXT/v1` over the canonical document minus the cid
/// (artifacts sorted by path, so the closure is a deterministic function of
/// the declared set).
///
/// This is a DECLARED closure, never a measured file-access trace: it binds
/// the child executables / runtime libraries / data dependencies the court
/// author declares the side needs — for JVM evidence, `java` + its native
/// startup closure + the classpath artifacts; for Python, the interpreter +
/// the module tree; for a service, the binary + shared libs + config. A
/// high-assurance claim therefore means "the declared execution context is
/// bound", not "every file the side ever read was captured".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionContextClosure {
    pub schema_version: String,
    /// Content address: `FRF/EXECUTION-CONTEXT/v1` over the canonical
    /// document minus the cid.
    pub cid: String,
    /// Sorted by path.
    pub artifacts: Vec<ExecutionContextArtifact>,
}

/// The HARNESS-EVENT schema: an evidence record that the harness ENFORCED a
/// declared bound during an observation attempt — a stream overflow, a
/// timeout, a resource-limit signal, or a produced-tree overflow. The run is
/// still REFUSED (fail-closed, never truncated), but the refusal is now
/// itself provable: a content-addressed, immutable record under
/// `harness/<id>.json` that future claims and reports can cite. Written when
/// a bound fires during a court run attempt, with the side, the declared
/// cap, and the observed value.
pub const SCHEMA_HARNESS_EVENT: &str = "frf-harness-event-v1";

/// One harness-enforcement evidence record (FRF/HARNESS-EVENT/v1). The id is
/// the content address over the event's own fields; verification rederives
/// it before the record may be consumed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessEvent {
    pub schema_version: String,
    /// Content address: `FRF/HARNESS-EVENT/v1` over the document minus the
    /// id.
    pub id: String,
    /// `stream-overflow` | `timeout` | `rlimit` | `produced-overflow`.
    pub event_kind: String,
    /// The executed side: `reference` | `candidate` (the court sides; an
    /// extension program's violation refuses its own invocation).
    pub side: String,
    /// The bound that fired: `stdout` | `stderr` | `wall` | `cpu` |
    /// `produced-files` | `produced-bytes` | `produced-file-bytes`.
    pub target: String,
    /// The declared cap, as enforced (the profile's value or the override in
    /// force).
    pub cap: String,
    /// The observed value that exceeded the cap.
    pub observed: String,
    /// The court whose run attempt enforced the bound.
    pub court: String,
    /// The execution profile the attempt ran under.
    pub execution_profile: String,
    /// The runner executable hash that enforced the bound.
    pub runner: String,
    /// Free-form detail (e.g. the terminating signal).
    pub detail: String,
}

/// The EXECUTION-ATTEMPT schema: a REFUSED observation attempt made first-
/// class. When a court's observation attempt ends in a harness refusal
/// (stream overflow, timeout, produced-tree overflow, or a bound the harness
/// must enforce by refusing) there is no successful run to become the durable
/// graph root of that attempt — the refusal itself is the observation about
/// the attempt, and it is now provable evidence: a content-addressed,
/// immutable record under `attempts/<id>.json` binding the DECLARED court,
/// the BOUND artifacts, the fixture, argv, the environment digest, the
/// EXECUTION CONTRACT (profile + capture bounds as enforced), the side that
/// refused, the harness events recorded during the attempt, and the refusal
/// reason. The attempt's identity rederives from those fields on every read;
/// verification also rederives every referenced harness event (each is
/// itself content-addressed), so the refusal is as portable as the
/// observation that would have been captured.
///
/// This is the `refused` arm of the conceptual `ExecutionAttempt` sum:
/// `completed → Run | refused { harness events, declared court, bound
/// artifacts, execution contract, refusal reason }`. A refusal is a first-
/// class portable observation; the error message is no longer the only
/// surface through which a failed observation attempt is named.
///
/// The `kind` field is always `"refused"` in this version: a completed
/// attempt IS a run (content-addressed under the capture), so the completed
/// arm carries no separate record — the attempt record exists exactly where
/// the run cannot.
pub const SCHEMA_EXECUTION_ATTEMPT: &str = "frf-execution-attempt-v1";

/// The refusal reason of a refused execution attempt: the enforced-bound kind
/// and the human detail (the cap and the observed value live in the
/// content-addressed harness event the attempt cites — never duplicated).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionAttemptRefusal {
    /// `stream-overflow` | `timeout` | `rlimit` | `produced-overflow`.
    pub kind: String,
    /// Free-form detail (the refusing error).
    pub detail: String,
}

/// One refused execution-attempt evidence record (FRF/EXECUTION-ATTEMPT/v1).
/// The id is the content address over the record's own fields; verification
/// rederives it — and every cited harness event — before the record may be
/// consumed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionAttemptRecord {
    pub schema_version: String,
    /// Content address: `FRF/EXECUTION-ATTEMPT/v1` over the document minus
    /// the id.
    pub id: String,
    /// Always `"refused"` in this schema version (a completed attempt is a
    /// run).
    pub kind: String,
    /// The court id (a stable declared identifier; the semantic identity
    /// below is the identity-bearing member).
    pub court: String,
    /// The court's semantic identity — the question, falsifier, authority
    /// artifact, fixture, envelope, and comparator/normalizer/adapter
    /// semantics the attempt would have observed under.
    pub court_semantic_identity: String,
    /// The exact authority bytes the attempt bound (content address).
    pub authority_sha256: String,
    /// The exact candidate bytes the attempt bound (content address).
    pub candidate_sha256: String,
    /// The exact fixture bytes the attempt would have observed (content
    /// address).
    pub fixture_sha256: String,
    /// The argv the sides would have been executed with.
    pub arguments: Vec<String>,
    /// The environment digest the attempt ran under (FRF/ENVIRONMENT/v2).
    pub environment_digest: String,
    /// The execution profile the attempt ran under.
    pub execution_profile: String,
    /// The execution contract AS ENFORCED — the effective capture bounds
    /// (including any overrides in force).
    pub capture_bounds: CaptureBounds,
    /// The side whose execution refused: `reference` | `candidate`.
    pub side: String,
    /// The content-addressed harness events recorded during the attempt
    /// (each is itself verified on read; sorted for determinism).
    pub harness_events: Vec<String>,
    /// The refusal reason.
    pub refusal_reason: ExecutionAttemptRefusal,
}

/// One component of a native runtime closure: a loaded executable or dynamic
/// library, by the path the system loader resolved and the SHA-256 of its
/// bytes at observation time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRuntimeComponent {
    /// The resolved filesystem path (the loader's own resolution — its
    /// search configuration, cache, and the effective LD_LIBRARY_PATH apply).
    pub path: String,
    /// SHA-256 of the component's bytes at observation time.
    pub sha256: String,
}

/// The native runtime closure of an ELF executable — `executable hash` is not
/// `executable semantics`: the artifact's behavior depends on its dynamic
/// loader, its dependency closure, and the loader search configuration that
/// resolved them. This object binds all of it, resolved by the SYSTEM loader
/// under the observation environment and hashed at observation time. The
/// identity is `FRF/RUNTIME-CLOSURE/v1` over the canonical document minus
/// the cid (the components are sorted by name, so the closure is a
/// deterministic function of the resolved set).
///
/// High-assurance admission requires the closure for every native premise
/// artifact: without it, a native artifact could not name what it actually
/// loaded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRuntimeClosure {
    pub schema_version: String,
    /// Content address: `FRF/RUNTIME-CLOSURE/v1` over the canonical document
    /// minus the cid.
    pub cid: String,
    /// The dynamic loader (`PT_INTERP` of the executable).
    pub interp: NativeRuntimeComponent,
    /// The resolved dependency closure (the executable's `DT_NEEDED`, and
    /// transitively theirs), sorted by name.
    pub components: Vec<NativeRuntimeComponent>,
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
/// observed bands touch the axis bounds (localization), how many contiguous
/// observed bands there are (bands), and — when the axis admits a
/// deterministic magnitude measure — the trend of the divergence's degree
/// across the axis. See [`crate::trajectory::classify`] for the exact table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrajectoryDrift {
    /// Observed at every point of the axis.
    Persistent,
    /// Observed at some but not all points, with no more specific pattern.
    Transient,
    /// Transient AND observed at both the first and the last point (it came
    /// back).
    Recurrent,
    /// A single contiguous band touching exactly one axis bound (the
    /// paper's boundary-localized): a cessation (present only at the start)
    /// or an onset (present only at the end).
    #[serde(rename = "boundary-localized")]
    BoundaryLocalized,
    /// Two or more distinct observed bands along an ORDERED stratification
    /// axis (an authority-version or candidate-revision ladder): the
    /// divergence is stratified across versions — it recurs in non-adjacent
    /// version bands.
    #[serde(rename = "version-stratified")]
    VersionStratified,
}

impl TrajectoryDrift {
    pub const ALL: [TrajectoryDrift; 5] = [
        TrajectoryDrift::Persistent,
        TrajectoryDrift::Transient,
        TrajectoryDrift::Recurrent,
        TrajectoryDrift::BoundaryLocalized,
        TrajectoryDrift::VersionStratified,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            TrajectoryDrift::Persistent => "persistent",
            TrajectoryDrift::Transient => "transient",
            TrajectoryDrift::Recurrent => "recurrent",
            TrajectoryDrift::BoundaryLocalized => "boundary-localized",
            TrajectoryDrift::VersionStratified => "version-stratified",
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
    /// The divergence's degree (magnitude) moves monotonically across the
    /// axis — a ramp, not a step: the boundary is gradual.
    Gradual,
}

impl TrajectorySlew {
    pub const ALL: [TrajectorySlew; 5] = [
        TrajectorySlew::Stable,
        TrajectorySlew::Abrupt,
        TrajectorySlew::Burst,
        TrajectorySlew::Recurrent,
        TrajectorySlew::Gradual,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            TrajectorySlew::Stable => "stable",
            TrajectorySlew::Abrupt => "abrupt",
            TrajectorySlew::Burst => "burst",
            TrajectorySlew::Recurrent => "recurrent",
            TrajectorySlew::Gradual => "gradual",
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

/// The magnitude TREND of a divergence across an axis: how the degree of
/// divergence (the per-observation magnitude measure) moves in coordinate
/// order. `gradual` is claimed exactly when the trend is monotonic
/// (`increasing` or `decreasing`) — a ramp, not a step. An axis whose
/// comparator declares no magnitude measure, or a series with too few
/// observed points to establish a trend, honestly yields `unknown` and never
/// claims gradual.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrajectoryTrend {
    /// All observed magnitudes are equal across the axis.
    Flat,
    /// Non-decreasing, with at least one strict increase.
    Increasing,
    /// Non-increasing, with at least one strict decrease.
    Decreasing,
    /// Neither monotonic direction holds.
    NonMonotonic,
    /// No magnitude evidence (no declared measure, or too few observed
    /// points to establish a trend).
    Unknown,
}

impl TrajectoryTrend {
    pub const ALL: [TrajectoryTrend; 5] = [
        TrajectoryTrend::Flat,
        TrajectoryTrend::Increasing,
        TrajectoryTrend::Decreasing,
        TrajectoryTrend::NonMonotonic,
        TrajectoryTrend::Unknown,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            TrajectoryTrend::Flat => "flat",
            TrajectoryTrend::Increasing => "increasing",
            TrajectoryTrend::Decreasing => "decreasing",
            TrajectoryTrend::NonMonotonic => "non-monotonic",
            TrajectoryTrend::Unknown => "unknown",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        TrajectoryTrend::ALL
            .iter()
            .copied()
            .find(|t| t.as_str() == s)
    }
}

/// The derived classification of one trajectory. `localization` and `bands`
/// make the paper's extended vocabulary executable: `abrupt` ↔ start/end
/// (boundary-localized), `burst` ↔ interior, `recurrent` ↔ both with 2+
/// bands (version-stratified along a version axis). v4 adds the magnitude
/// evidence: `trend` (how the divergence's degree moves across the axis, or
/// `unknown` when no deterministic measure exists) and `magnitude_kind` (the
/// declared measure, or `none`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrajectoryDerivation {
    pub drift: TrajectoryDrift,
    pub slew: TrajectorySlew,
    /// Where the observed bands touch the axis bounds.
    pub localization: TrajectoryLocalization,
    /// The number of contiguous observed bands (1 for persistent/abrupt/
    /// burst; 2+ for the recurrent/stratified patterns), as a STRING: the
    /// canonical JSON value domain is strings/arrays/booleans/null, so no
    /// generated evidence document can carry a JSON number.
    pub bands: String,
    /// The trend of the divergence's magnitude across the axis (v4).
    pub trend: TrajectoryTrend,
    /// The declared deterministic magnitude measure: `none` when the axis's
    /// comparator declares no distance function (external axes, the
    /// filesystem-tree and byte-wire surfaces), otherwise the measure name.
    pub magnitude_kind: String,
}

/// One point of a trajectory: the coordinate value, the run that point
/// produced (identical evidence shares the content-addressed run), whether
/// the subject lineage was observed in it, and — when observed — the
/// residual id and the EXACT observation fingerprint at that point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrajectoryObservation {
    /// The point index, as a STRING (the canonical JSON value domain has no
    /// numbers).
    pub point_index: String,
    /// The coordinate value (repetition index, candidate artifact hash,
    /// authority version, environment label, time label).
    pub coordinate: String,
    /// The CONTENT IDENTITY of this point's coordinate (`FRF/COORDINATE/v1`,
    /// v5): what EXACTLY varied at this point — the candidate artifact
    /// identity, the authority record's content address, or the effective
    /// environment digest. A trajectory says what moved, not merely what the
    /// point was labelled.
    pub coordinate_identity: String,
    pub run: String,
    pub observed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub residual: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// The deterministic divergence degree at this point (v4): the declared
    /// magnitude measure applied to this observation's compared projections,
    /// as a STRING. Absent when the axis declares no measure or the measure
    /// is not computable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub magnitude: Option<String>,
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

/// THE DETACHED-OBJECT DECLARATION — `detached-objects.json` at the
/// evidence root (schema `frf-detached-objects-v1`).
///
/// A publication may deliberately withhold the BYTES of some content
/// addresses (security-sensitive executables, export-controlled or
/// confidential artifacts, huge payloads) while publishing the graph that
/// references them. This declaration makes that choice explicit and
/// mechanical: every declared CID is attested as intentionally unavailable,
/// with its role, publication status, size, and the reconstruction recipe
/// that reproduces the exact bytes. Verification then distinguishes:
///
///   - `graph_verified`  — every canonical document parses, every identity
///     rederives, and every referenced CID resolves (its bytes are present
///     OR it is declared detached here);
///   - `object_closure_complete` — every referenced CID's bytes are
///     present (replayable until the detached set is hydrated);
///   - `replayable` — the closure is complete AND the replay checks pass.
///
/// A declared-detached CID is never treated as corruption: the graph
/// verifies with an explicitly incomplete closure (`incomplete-by-policy`),
/// and replay refuses until the bytes are materialized locally and verified
/// against the declared CID.
pub const SCHEMA_DETACHED_OBJECTS: &str = "frf-detached-objects-v1";

/// The reconstruction recipe for one detached payload: the instruction that
/// reproduces the exact withheld bytes (a pinned hermetic build, a pinned
/// fetch, a re-run of the observation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetachedReconstruction {
    /// The human- AND machine-actionable recipe (e.g. the pinned build
    /// script + the SHA-256-pinned sources).
    pub recipe: String,
    /// The repository-relative source path the bytes derive from, when the
    /// recipe is a build of a tracked source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_path: Option<String>,
}

/// ONE declared-detached content address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetachedObjectRef {
    /// The withheld payload's content address (SHA-256 hex, 64 chars).
    pub cid: String,
    /// The role the payload played (`authority-artifact`, `candidate-artifact`,
    /// `fixture-object`, `comparator-implementation`, `minimizer-implementation`,
    /// `mutation-request`, …) — matching the evidence references.
    pub role: String,
    /// The publication status explaining WHY the bytes are withheld
    /// (`external-security-sensitive`, `confidential`, `export-controlled`, …).
    pub publication: String,
    /// The payload size in bytes as a DECIMAL STRING (the canonical-JSON
    /// value domain is strings/arrays/booleans/null only, so a number would
    /// refuse to canonicalize; a hydrator parses it to bound the fetch/build).
    pub size: String,
    /// The store-relative path the bytes WOULD occupy, when the payload is a
    /// record (e.g. `challenges/<id>/mutation/request.json`) rather than a
    /// content-addressed object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// How to reproduce the exact bytes locally.
    pub reconstruction: DetachedReconstruction,
}

/// The publication-level declaration document (`detached-objects.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetachedObjects {
    pub schema_version: String,
    /// The publication policy label (`detached`).
    pub policy: String,
    pub objects: Vec<DetachedObjectRef>,
}

impl DetachedObjects {
    /// Semantic conformance for the declaration: schema version, non-empty
    /// policy, and every CID a well-formed 64-hex content address, unique,
    /// with a non-empty role/publication/recipe.
    pub fn validate_semantics(&self) -> std::result::Result<(), String> {
        if self.schema_version != SCHEMA_DETACHED_OBJECTS {
            return Err(format!(
                "unsupported schema version {:?} (expected {SCHEMA_DETACHED_OBJECTS})",
                self.schema_version
            ));
        }
        if self.policy.trim().is_empty() {
            return Err("policy must be non-empty".to_string());
        }
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for o in &self.objects {
            if !crate::host::is_sha256_hex(&o.cid) {
                return Err(format!("detached cid {:?} is not a 64-hex SHA-256", o.cid));
            }
            if !seen.insert(o.cid.as_str()) {
                return Err(format!("duplicate detached cid {}", &o.cid[..16]));
            }
            if o.role.trim().is_empty()
                || o.publication.trim().is_empty()
                || o.reconstruction.recipe.trim().is_empty()
            {
                return Err(format!(
                    "detached cid {}: role, publication, and reconstruction.recipe must be non-empty",
                    &o.cid[..16]
                ));
            }
        }
        Ok(())
    }
}

/// The reduction protocol object: a minimization experiment on one residual
/// (`frf court minimize`). Every executable attempt is recorded; the final
/// reproducer is court-verified (the lineage survives) and carries the full
/// transform declaration: what the reduction permitted to move (the fixture)
/// and what it required to stay (candidate, authority, comparator,
/// environment — each bound by identity, not label).
pub const SCHEMA_REDUCTION: &str = "frf-reduction-v4";

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
    /// The point index, as a STRING (the canonical JSON value domain has no
    /// numbers).
    pub point_index: String,
    /// The coordinate value at this point (repetition index, candidate path,
    /// authority version, environment label, time label).
    pub coordinate: String,
    /// The CONTENT IDENTITY of this point's coordinate (`FRF/COORDINATE/v1`,
    /// v4): what EXACTLY varied — the candidate artifact identity, the
    /// authority record's content address, or the effective environment
    /// digest — computed from the point's verified run, never from the
    /// caller's label.
    pub coordinate_identity: String,
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
    /// The ADJACENT NON-PASSING point the CORE executed to establish a
    /// domain-aware boundary predicate (kind=boundary): the lineage must be
    /// LOST here (and preserved at the final verification) for the boundary
    /// to be proven. A preserved control is a recorded REFUTATION.
    BoundaryControl,
    /// The final confirmation run of the accepted reproducer.
    FinalVerification,
}

impl ReductionAttemptRole {
    pub fn as_str(self) -> &'static str {
        match self {
            ReductionAttemptRole::Baseline => "baseline",
            ReductionAttemptRole::Candidate => "candidate",
            ReductionAttemptRole::BoundaryControl => "boundary_control",
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
    /// The attempt counter, as a STRING (the canonical JSON value domain has
    /// no numbers; the ORDER is the array position).
    pub attempt: String,
    pub role: ReductionAttemptRole,
    /// SHA-256 of the fixture tried (content-addressed under `objects/`).
    pub fixture_sha256: String,
    pub outcome: ReductionAttemptOutcome,
    pub accepted: bool,
}

/// The minimality statement of a minimization, stated precisely and
/// domain-aware. Two predicate kinds exist:
///
/// - `one-minimal` — classic ddmin establishes that no single line can be
///   removed while preserving the lineage (not global cardinality
///   minimality), at the declared removal `granularity`.
/// - `boundary` — the proposal sits at an OBSERVATION BOUNDARY of a numeric
///   parameter: at `passing_point` the lineage survives, at the adjacent
///   `adjacent_nonpassing_point` it does not. The boundary coordinates are
///   the minimizer's domain interpretation; the core ESTABLISHES the pair
///   by executing BOTH points itself (the boundary-control attempt must be
///   lost and the final verification preserved) before `proven` can be true.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReductionMinimality {
    /// The minimality predicate KIND: `one-minimal` or `boundary`.
    pub kind: String,
    /// The granularity of removal (`line`) — present for `one-minimal` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub granularity: Option<String>,
    /// The domain the boundary is over (e.g.
    /// `heartbeat.claimed_payload_length`) — `boundary` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// The declared ordering of the boundary domain (e.g.
    /// `integer-ascending`) — `boundary` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ordering: Option<String>,
    /// The passing point, a decimal STRING (the canonical JSON value domain
    /// has no numbers) — the parameter value at which the lineage survives.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passing_point: Option<String>,
    /// The adjacent non-passing point (decimal string) — the parameter value
    /// at which the lineage does NOT survive, executed and observed by the
    /// core itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adjacent_nonpassing_point: Option<String>,
    /// Whether the CORE actually established the predicate: a completed
    /// one-minimal search at the declared granularity, or a core-executed
    /// boundary (both points observed), or a separately verifiable proof the
    /// core checked. NEVER a relayed claim: an external minimizer's
    /// `minimal: true` is its own claim and is recorded in
    /// `proposal_minimality_claimed`, not here.
    pub proven: bool,
    /// The EXTERNAL minimizer's own minimality claim (its response's
    /// `minimal` field), recorded as a claim — present (true or false) only
    /// for external-minimizer reductions, absent for the built-in reducer
    /// (which has no external claim to record). `Option` keeps records
    /// written before this field existed byte-compatible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal_minimality_claimed: Option<bool>,
}

/// The derivation of a minimization experiment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReductionDerivation {
    /// The reduction strategy (`ddmin-lines` in this version).
    pub strategy: String,
    /// Line counts as STRINGS (the canonical JSON value domain has no
    /// numbers).
    pub original_lines: String,
    pub final_lines: String,
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

impl ReductionRecord {
    /// Semantic conformance for the record: the minimality predicate is
    /// exactly what the record's own attempts establish, and `proven` is
    /// never a relayed claim.
    ///
    /// - `one-minimal`: the removal `granularity` is present and the
    ///   boundary coordinates are absent; `proven` can only be the built-in
    ///   reducer's COMPLETED search, so a proven one-minimal record carries
    ///   no relayed external claim.
    /// - `boundary`: the boundary coordinates are present and no removal
    ///   `granularity` is recorded; `proven` requires the record's own
    ///   attempts to carry the core's observations — a LOST
    ///   `boundary_control` attempt AND an accepted `final_verification`.
    pub fn validate_semantics(&self) -> std::result::Result<(), String> {
        if self.schema_version != SCHEMA_REDUCTION {
            return Err(format!(
                "unsupported schema version {:?} (expected {SCHEMA_REDUCTION})",
                self.schema_version
            ));
        }
        let m = &self.derivation.minimality;
        let boundary_coords = [
            ("domain", &m.domain),
            ("ordering", &m.ordering),
            ("passing_point", &m.passing_point),
            ("adjacent_nonpassing_point", &m.adjacent_nonpassing_point),
        ];
        match m.kind.as_str() {
            "one-minimal" => {
                if m.granularity.is_none() {
                    return Err("one-minimal minimality requires a granularity".into());
                }
                for (name, value) in boundary_coords {
                    if value.is_some() {
                        return Err(format!(
                            "one-minimal minimality carries a boundary coordinate {name:?}"
                        ));
                    }
                }
                if m.proven && m.proposal_minimality_claimed == Some(true) {
                    return Err(
                        "one-minimal proven=true must never be a relayed external-minimizer claim"
                            .into(),
                    );
                }
            }
            "boundary" => {
                if m.granularity.is_some() {
                    return Err("boundary minimality has no removal granularity".into());
                }
                for (name, value) in boundary_coords {
                    if value.is_none() {
                        return Err(format!("boundary minimality requires {name}"));
                    }
                }
                if m.proven {
                    let control = self
                        .attempts
                        .iter()
                        .find(|a| a.role == ReductionAttemptRole::BoundaryControl);
                    let Some(control) = control else {
                        return Err(
                            "boundary proven=true requires a boundary_control attempt the core executed"
                                .into(),
                        );
                    };
                    if control.outcome != ReductionAttemptOutcome::Lost {
                        return Err(
                            "boundary proven=true requires the boundary_control attempt to be LOST (a preserved control is a refutation)"
                                .into(),
                        );
                    }
                    let last = self
                        .attempts
                        .last()
                        .ok_or("a proven boundary requires attempts")?;
                    if last.role != ReductionAttemptRole::FinalVerification || !last.accepted {
                        return Err(
                            "boundary proven=true requires an accepted final_verification of the passing point"
                                .into(),
                        );
                    }
                }
            }
            other => return Err(format!("unknown minimality kind {other:?}")),
        }
        Ok(())
    }
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
    /// The external mutation provider's invocation + result evidence ids,
    /// when the mutant was PROPOSED by an extension program (spec/mutation.md)
    /// rather than generated by a built-in operator. The preserved
    /// request/response/invocation/result records live under
    /// `challenges/<id>/mutation/` and are cross-verified on read.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mutation_invocation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mutation_result_id: Option<String>,
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
// Mutation extension protocol (spec/mutation.md)
// ---------------------------------------------------------------------------

/// The canonical request a court writes to a mutation provider's stdin. The
/// provider receives the court's question, the axis to seed a defect on, and
/// the reference + fixture ARTIFACTS (base64 contents + hashes) it needs to
/// build a domain-appropriate mutant candidate. The response must
/// cryptographically name this request and propose ONE mutant artifact; the
/// court executes the proposal and independently decides the verdicts.
#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MutationRequest<'a> {
    pub schema_version: &'a str,
    /// The mutation SEMANTIC being asked for (what kind of mutant).
    pub mutation: &'a MutationSemantic,
    /// The court the mutant will be run against (its question + envelope).
    pub court: MutationCourt<'a>,
    /// The observable axis the mutation targets.
    pub target_axis: &'a str,
    /// The admitted reference artifact the mutant wraps (base64 contents).
    pub reference_artifact: MutationArtifact<'a>,
    /// The fixture the court runs the mutant against (base64 contents).
    pub fixture: MutationArtifact<'a>,
}

/// The court's question, as a mutation provider needs it.
#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MutationCourt<'a> {
    pub id: &'a str,
    pub question: &'a str,
    pub falsifier: &'a str,
    pub observables: &'a [String],
    pub fixture_family: &'a str,
}

/// One artifact a mutation provider receives (content address + bytes).
#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MutationArtifact<'a> {
    pub sha256: &'a str,
    /// The artifact bytes, base64 (the provider builds its mutant from
    /// these; the same bytes a verifier rehashes).
    pub contents_base64: &'a str,
}

/// The canonical response a mutation provider returns: ONE mutant proposal
/// (the exact artifact bytes the court will execute as the candidate) and
/// the surfaces the provider EXPECTS to move — the court decides
/// independently, from the run, whether the expectation held.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationResponse {
    pub schema_version: String,
    /// Must equal the SHA-256 of the exact request bytes the provider
    /// received (a response that does not name its request is refused).
    pub request_id: String,
    /// The mutant candidate artifact bytes, base64. Absent = the provider
    /// declined to propose (a refusal, like a witness that declines).
    #[serde(default)]
    pub mutant_base64: Option<String>,
    /// The axes the provider expects the mutation to move. Informational:
    /// the court recomputes the verdicts from the run.
    #[serde(default)]
    pub expected_affected_surfaces: Vec<String>,
    /// The provider malfunctioned/refused with a message.
    #[serde(default)]
    pub failure: Option<String>,
}

/// The INVOCATION evidence record of one external mutation: what was asked,
/// of which implementation, by which runner. Written under
/// `challenges/<id>/mutation/invocation.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationInvocation {
    pub schema_version: String,
    /// Content address: `FRF/MUTATION-INVOCATION/v1` over the record's own
    /// fields.
    pub invocation_id: String,
    /// The provider/operator id.
    pub operator: String,
    /// The observable axis the mutation targeted.
    pub target_axis: String,
    /// SHA-256 of the exact canonical request bytes the provider received.
    pub request_cid: String,
    /// The mutation's SEMANTIC identity (its specification hash).
    pub mutation_semantic_cid: String,
    /// The exact implementation artifact that ran.
    pub mutation_implementation_artifact: ArtifactIdentity,
    pub execution_provenance: RunnerIdentity,
}

/// The RESULT evidence record of one external mutation: which request the
/// response answered, the response document's content address, the proposed
/// mutant's content address, and the surfaces the provider expected to move.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationResult {
    pub schema_version: String,
    /// Content address: `FRF/MUTATION-RESULT/v1` over the record's own
    /// fields.
    pub result_id: String,
    /// The request this result answers (must equal the invocation's
    /// `request_cid`).
    pub request_cid: String,
    /// SHA-256 of the exact canonical response bytes.
    pub response_cid: String,
    /// The interpreted outcome: `proposed` (a mutant was proposed and the
    /// court ran it) or `refused` (the provider declined/failed — the
    /// challenge records the refusal as evidence).
    pub outcome: String,
    /// Content address of the proposed mutant artifact.
    pub mutant_sha256: String,
    /// The surfaces the provider expected to move (its declared expectation;
    /// the verdicts rederive from the run).
    pub expected_affected_surfaces: Vec<String>,
}

/// The complete verified evidence of one external mutation proposal: the
/// invocation and the result it produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationEvidence {
    pub invocation: MutationInvocation,
    pub result: MutationResult,
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
    /// The capture-adapter relations applied (axis-keyed observation
    /// semantics), copied from the capture — part of the court semantic
    /// identity, so a receipt can rederive the question it binds.
    #[serde(default)]
    pub adapter_semantics: Vec<CaptureAdapterSemantic>,
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
    /// The snapshotted execution-context closure (when the court declared
    /// one), copied from the capture — a receipt never reconstructs the
    /// runtime context from whatever happens to be installed.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub execution_context: Option<ExecutionContextClosure>,
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
    /// The authority's native runtime closure (v17): present exactly when
    /// the artifact is a native ELF executable (no interpreter).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_runtime: Option<NativeRuntimeClosure>,
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
    /// The candidate's native runtime closure (v17): present exactly when
    /// the artifact is a native ELF executable (no interpreter).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_runtime: Option<NativeRuntimeClosure>,
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
    /// The EXACT fixture input identities the claim is scoped to — the
    /// FRF/FIXTURE/v1 identity (semantic id + content SHA-256 + declared
    /// arguments), never the human label alone: two different files that
    /// share a fixture id are different inputs, and the named role stays a
    /// separate (`fixture_family`) dimension.
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

    /// Whether a surface (a residual's scope) intersects the region: it
    /// intersects ANY cell. The blocker rule generalizes to multi-premise
    /// claims exactly here — an unexplained divergence on any claimed cell's
    /// surface blocks the claim.
    pub fn intersects(&self, surface: &ClaimScope) -> bool {
        self.cells.iter().any(|cell| cell.intersects(surface))
    }
}

/// The exact candidate artifact a compiled claim is attributed to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimCandidate {
    pub name: String,
    pub version_or_commit: String,
    pub identity_hash: String,
}

/// Claim IR — the demonstrated sensitivity of the court on ONE claimed
/// observable axis: the content-addressed challenge records that proved it.
/// Admission requires every claimed axis to have at least one such record;
/// the claim carries the exact ids so the coverage re-derives from the
/// evidence, never from a boolean. v6: the entry binds the PREMISE RECEIPT
/// the coverage belongs to (a multi-premise claim's cells can come from
/// different courts, and each cell's axes must be covered by challenges of
/// ITS court). v9: the entry ALSO records the DEMONSTRATED MUTATION
/// PROFILE — the distinct operators of its covering challenges (sorted) —
/// so the claim names WHICH mutation families the court proved it can see
/// on that surface, and a verifier re-derives the profile from the named
/// challenge records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimCapability {
    /// The premise receipt the covered axes belong to.
    pub receipt: String,
    /// The claimed observable axis this capability covers.
    pub axis: String,
    /// The mutation operators the covering challenges demonstrated on
    /// `axis` (distinct, sorted; re-derived by verification from the
    /// challenge records — a hand-edited profile is a tampered claim).
    pub mutation_profile: Vec<String>,
    /// The challenge records that demonstrated sensitivity on `axis`
    /// (content-addressed; a verifier recomputes `saw_defect` and
    /// `specificity_clean` from each mutant run).
    pub challenge_ids: Vec<String>,
}

/// A compiled claim (written ONLY by `frf claim compile`, from verified
/// premise receipts). The IR is the full scope algebra:
///
/// - `scope` is K — the REGION of the evidence space the claim asserts
///   parity over, as DNF cells (one per premise's clean surface; never
///   beyond the premises' surface, checked literally — every point of K
///   lies in SOME premise cell);
/// - `blockers` are the residuals that REFUSE the claim: `open`/`unknown`
///   residuals whose surface intersects ANY K cell (a human or LLM cannot
///   promote evidence by relabeling it — an unexplained divergence on the
///   claimed surface blocks, wherever it was recorded), and `harness`
///   residuals on a premise run (run-level invalidation);
/// - `excluded_evidence` are the observed divergences this claim does NOT
///   cover (residuals outside K's surface);
/// - `requires` are the premise receipts, and admission is
///   `Scope(K) ⊆ Scope(P₁ ∪ … ∪ Pₙ)` — the union is the cell list, never a
///   merged product;
/// - `knowledge_snapshot` is the EVIDENCE UNIVERSE the absence search ran
///   over: no unresolved residual IN that universe intersects K. A claim is
///   admissible relative to an explicitly committed state of knowledge —
///   the compiled claim carries the universe, so the negative search (not
///   merely the positive premises) is portable and reproducible;
/// - prose is NOT stored as authoritative Claim IR: `positive`/`non_claims`
///   are renderer outputs, deterministically derived from the verified
///   premises by the renderers. The stored IR is the proposition + the
///   evidence graph, and the claim is content-addressed (`FRF/CLAIM/v1` over
///   the canonical document minus the id), so the identity cryptographically
///   binds the exact proposition — not a sentence someone happened to write.
///
/// v8: the claim is a content-addressed IMMUTABLE protocol object
/// (`claims/<id>.json` with the `claims/by-receipt/<receipt>/<id>` index —
/// the same receipt compiled under a different universe or policy is a
/// DIFFERENT claim, and they coexist forever). The stored prose fields are
/// gone; the renderers derive them from the verified IR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimRecord {
    /// Content address: `FRF/CLAIM/v1` over the canonical document minus
    /// the id field. Immutable: a different universe, policy, or scope is a
    /// different claim id.
    pub id: String,
    pub schema_version: String,
    /// The FIRST premise receipt (the claim's root into the evidence
    /// graph; the `claims/by-receipt/<receipt>/<id>` index points here).
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
    /// Claim IR — K, the structured scope as a REGION of DNF cells (one per
    /// premise's clean surface). Admission is the literal containment
    /// `K ⊆ P₁ ∪ … ∪ Pₙ` over these cells.
    pub scope: EvidenceRegion,
    /// Claim IR — the axes covered (flat union across the scope cells).
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
    /// Claim IR — the admission policy the claim was compiled under
    /// (see [`CLAIM_POLICY_BASELINE`] and friends).
    pub policy: String,
    /// Claim IR (v9) — the REQUIRED SENSITIVITY MUTATION PROFILE the claim
    /// was compiled under: `AXIS:FAMILY` pairs (e.g.
    /// `exit:exit-class`) that MUST be demonstrated on the claimed surface —
    /// for each entry, the named axis (which the claim must cover) must have
    /// the named mutation family among its demonstrated operators. Empty =
    /// any demonstrated sensitivity on each claimed axis suffices. The
    /// per-axis DEMONSTRATED profile is recorded in each `capability` entry.
    #[serde(default)]
    pub mutation_profile: Vec<String>,
    /// Claim IR — the capability evidence that satisfied the policy tier,
    /// per claimed observable axis: the content-addressed challenge records
    /// (same court semantic identity, same reference artifact, targeted axis,
    /// recomputed `saw_defect` and `specificity_clean`) that demonstrated
    /// the court can SEE the claimed surface. Empty under `baseline`.
    #[serde(default)]
    pub capability: Vec<ClaimCapability>,
    /// Claim IR — the verified witness statements that attested this receipt
    /// (`outcome: affirm`); required from `independently-witnessed` up.
    #[serde(default)]
    pub witness_statements: Vec<String>,
    /// Claim IR (v7) — the declared independence evidence bound to the
    /// claim's witness statements (spec/witness.md §6): the content-
    /// addressed [`IndependenceEvidence`] records the claim's attestations
    /// carry, so an independently-witnessed claim documents WHICH
    /// independence relations were declared (never conflated with FRF's own
    /// verification of the attestations). Required per premise from
    /// `independently-witnessed` up: an attestation alone is witnessed, not
    /// independently witnessed.
    #[serde(default)]
    pub independence_evidence: Vec<String>,
    /// Claim IR — the replay contract the claim's evidence was observed
    /// under (the receipt's execution profile; `high-assurance` requires the
    /// reference profile and the reference capture bounds).
    pub replay_profile: String,
}

// ---------------------------------------------------------------------------
// Knowledge snapshot — the evidence universe of a claim's absence search
// ---------------------------------------------------------------------------

/// One residual head in the knowledge universe: the residual id, its
/// RECORD CONTENT ADDRESS (the canonical hash of the immutable residual
/// record the blocker scan reads), its fingerprint (the derived identity the
/// blocker scan's scope depends on), its CURRENT disposition (an event
/// projection, with the exact event that supplied it). A claim's absence is
/// relative to these heads; a later disposition change is a NEW universe,
/// not a silent rewrite of the old one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotResidualHead {
    pub id: String,
    /// SHA-256 of the canonical serialization of the residual RECORD — the
    /// universe commits the exact immutable observation, not merely the
    /// label "cli-exit-0007 exists".
    pub record_cid: String,
    /// The residual FINGERPRINT (the derived identity of the disagreement).
    pub fingerprint: String,
    pub disposition: String,
    /// The disposition event that supplied the disposition, or `None` for
    /// `open` (the projection of no events).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disposition_event_id: Option<String>,
}

/// One typed content reference in the knowledge universe: the kind of
/// object, its id, and its content address. The universe commits every
/// object the blocker scan depends upon BY CONTENT — a run/receipt/series/
/// reduction is content-addressed by construction (its id IS its cid); an
/// authority's cid is the canonical hash of its record (an authority id is
/// a label).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotObject {
    /// `receipt` | `run` | `authority` | `series` | `reduction`.
    pub kind: String,
    pub id: String,
    pub cid: String,
}

/// The evidence universe a claim's absence search ran over: the committed
/// state of knowledge at compile time. A claim is admissible relative to U —
/// no unresolved residual IN U intersects K — and the compiled claim carries
/// U, so the negative search is reproducible by any implementation from the
/// claim alone, and a store mutation after compile time does not silently
/// change what the claim means.
///
/// v2: the universe is a TYPED CONTENT REFERENCE — every residual head
/// commits its record content address + fingerprint, and the objects list
/// commits every authority/run/receipt/series/reduction by content, so the
/// CID binds the exact bytes the blocker scan depended on, not the labels.
///
/// Identity: SHA-256 of `FRF/KNOWLEDGE/v2` over the canonical document of
/// the snapshot's fields — the snapshot is content-addressed, and a claim
/// binding a different universe is a different claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeSnapshot {
    pub schema_version: String,
    /// Content address: `FRF/KNOWLEDGE/v2` over this snapshot's fields.
    pub cid: String,
    /// Every residual present in the universe, with its head disposition,
    /// record content address, and fingerprint.
    pub residual_heads: Vec<SnapshotResidualHead>,
    /// Every other object the universe commits, by kind/id/cid.
    pub objects: Vec<SnapshotObject>,
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
