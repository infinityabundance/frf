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
pub const SCHEMA_CAPTURE: &str = "frf-capture-v4";
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
/// event in the hash-chained history, it does not merely copy state. The
/// body is serialized as canonical JSON (RFC 8785) and its identity is the
/// full SHA-256 of those bytes.
pub const SCHEMA_RECEIPT: &str = "frf-receipt-v8";
pub const SCHEMA_CLAIM: &str = "frf-claim-v1";
/// Runner identity block recorded in every capture at court time.
pub const SCHEMA_RUNNER: &str = "frf-runner-v1";
/// Environment identity block recorded in every capture at court time.
pub const SCHEMA_ENVIRONMENT: &str = "frf-environment-v1";
/// Observation provenance block (runner + comparator implementations).
pub const SCHEMA_PROVENANCE: &str = "frf-provenance-v1";

/// The token grammar schema (Section 6 of the paper).
pub const TOKEN_SCHEMA_VERSION: &str = "frf-token-v1";

// ---------------------------------------------------------------------------
// Observable axes
// ---------------------------------------------------------------------------

/// Observable axis. Adding an axis means writing a new comparator in the
/// court command, not restructuring the core. v0.1.6: `exit`, `stderr`, and
/// `stdout` (stdout compared on its first line only — see README).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Axis {
    Exit,
    Stderr,
    Stdout,
}

impl Axis {
    pub fn as_str(self) -> &'static str {
        match self {
            Axis::Exit => "exit",
            Axis::Stderr => "stderr",
            Axis::Stdout => "stdout",
        }
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "exit" => Ok(Axis::Exit),
            "stderr" => Ok(Axis::Stderr),
            "stdout" => Ok(Axis::Stdout),
            other => Err(format!(
                "unsupported observable axis '{other}': v0.1.6 supports 'exit', 'stderr', and 'stdout' only"
            )),
        }
    }

    /// The declared comparison relation for this axis (Section 10, Δ_a). The
    /// comparator identity is recorded in every receipt's observable block,
    /// so the evidence says exactly which relation was applied.
    pub fn comparator(self) -> &'static str {
        match self {
            Axis::Exit => "eq(exit-code)",
            Axis::Stderr => "eq(stderr-first-line)",
            Axis::Stdout => "eq(stdout-first-line)",
        }
    }
}

/// Residual kind. v0.1.6 court comparators produce exactly these two kinds
/// (Section 12: `exit` and `text`; `stdout` residuals are text-family, with
/// the axis recorded separately); the enum has no catch-all so an
/// unclassifiable residual is unrepresentable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResidualKind {
    Exit,
    Text,
}

impl ResidualKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ResidualKind::Exit => "exit",
            ResidualKind::Text => "text",
        }
    }

    pub fn from_axis(axis: Axis) -> Self {
        match axis {
            Axis::Exit => ResidualKind::Exit,
            Axis::Stderr | Axis::Stdout => ResidualKind::Text,
        }
    }

    /// Residual ids are `{domain}-{kind}-{seq}`; v0 courts are CLI courts, so
    /// the domain prefix is `cli` (matching Section 12's `cli-exit-*`).
    pub fn domain_prefix(self) -> &'static str {
        "cli"
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
pub struct CourtManifest {
    pub court: CourtSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CourtSpec {
    pub id: String,
    pub question: String,
    pub falsifier: String,
    /// Admitted authority id (Section 12: `ref-cli-1.8.2`).
    pub authority: String,
    pub candidate: CandidateSpec,
    pub fixture: FixtureSpec,
    pub admissibility_envelope: AdmissibilityEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateSpec {
    pub name: String,
    pub version_or_commit: String,
    pub build_profile: String,
    /// Working-directory-relative path to the candidate executable.
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureSpec {
    pub id: String,
    /// Working-directory-relative path to the fixture file.
    pub path: String,
    /// Arguments; the literal `{fixture}` is replaced with the fixture path.
    pub arguments: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub reference: SideCapture,
    pub candidate: SideCapture,
    pub residuals: Vec<String>,
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
/// it: the runner executable hash catches those.
pub const COMPARATOR_VERSION: &str = "v1";

/// The semantic identity of a comparator relation: WHAT the relation is, not
/// which implementation ran it. Two independent implementations with the
/// same `specification_hash` ask the same question; their different
/// executable bytes do not change the question.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComparatorSemantic {
    /// The observable axis id this comparator serves (exit/stderr/stdout).
    pub id: String,
    /// The relation family (Section 10, Δ_a): `eq`.
    pub relation_id: String,
    /// Bumped whenever the RELATION's semantics change (never reuse a name
    /// with new meaning under the old version).
    pub relation_version: String,
    /// SHA-256 of the comparator's canonical specification document
    /// (id + relation + extractor), see [`crate::comparators`].
    pub specification_hash: String,
}

/// Which implementation of a comparator observed the run. For in-binary
/// comparators both hashes are the runner executable hash; an external
/// comparator plugin would carry its own implementation hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComparatorImplementation {
    pub id: String,
    pub implementation_hash: String,
    pub runner_hash: String,
}

/// Observation provenance: the runner and the comparator implementations
/// that produced a capture. Bound at court time; a stricter reproducibility
/// policy may require equal provenance on top of equal semantic identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationProvenance {
    pub schema_version: String,
    pub runner: RunnerIdentity,
    pub comparator_implementations: Vec<ComparatorImplementation>,
}

/// The environment an observation happened in, captured at court time. The
/// receipt copies it verbatim — it never asks its own host what environment
/// an old court ran under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentIdentity {
    pub schema_version: String,
    pub os: String,
    pub architecture: String,
    pub kernel_release: String,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    pub axis: Axis,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
// Receipt (Appendix A, trimmed: verdict_case_file, taste_gates, invariants
// are real but not needed to prove the kernel — see README Known Limitations)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
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
pub struct ReceiptEnvelope {
    pub authority_versions: Vec<String>,
    pub fixture_family: String,
    pub platforms: Vec<String>,
    pub observables: Vec<String>,
    pub normalizers: Vec<String>,
    pub replay_scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
pub struct ReceiptObservable {
    pub axis: String,
    pub raw_reference_hash: String,
    pub raw_candidate_hash: String,
    pub comparator: String,
    pub normalization_rules: Vec<String>,
    pub verdict: ObservableVerdict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservableVerdict {
    Pass,
    Residual,
}

/// Appendix A `sign` block. v0 runs each court once, so drift and slew cannot
/// be observed; the honest values are literal, not enum-named guesses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResidualSign {
    pub norm: String,
    pub drift: String,
    pub slew: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
pub struct ReceiptEndoduction {
    pub schema_version: String,
    pub tokens: Vec<ReceiptToken>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
/// A compiled claim (`claims/` — written only by `frf claim compile`).
///
/// The claim carries its IR: the observable scope it covers and the
/// residuals it explicitly excludes. A residual blocks ONLY claims whose
/// observable scope intersects it — an open stdout residual never blocks a
/// claim about exit parity. Prose is one renderer of this structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimRecord {
    pub schema_version: String,
    pub receipt: String,
    pub authority: String,
    pub candidate: ClaimCandidate,
    pub court: String,
    pub fixture_family: String,
    pub environment: String,
    /// Claim IR — the axes this claim covers (never beyond the receipt's
    /// declared observables, and never an axis this run observed diverging).
    pub observable_scope: Vec<String>,
    /// Claim IR — residuals excluded from this claim's scope (observed
    /// divergences on other axes, whatever their disposition).
    pub excluded_residuals: Vec<String>,
    pub positive: Vec<String>,
    pub non_claims: Vec<String>,
}

/// The exact candidate artifact a compiled claim is attributed to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimCandidate {
    pub name: String,
    pub version_or_commit: String,
    pub identity_hash: String,
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
            axis: Axis::Exit,
            kind: ResidualKind::Exit,
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
}
