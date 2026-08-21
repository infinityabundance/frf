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
/// generic instead of special-casing a fixed artifact list.
pub const SCHEMA_CAPTURE: &str = "frf-capture-v7";
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
/// derived from (`sign.series`), so later experiments that reference the
/// same content-addressed run can never change what a receipt means. v10
/// makes the comparator layer OBSERVABLE-PLUGGABLE: observable ids and
/// residual kinds become open protocol identifiers (no closed enum), each
/// comparator semantic carries its extractor and residual classifier (its
/// specification hash REDERIVES from its own fields), external
/// implementations record their artifact identity, and an externally served
/// observable binds the exact comparator request/result records that
/// produced its verdict. The body is serialized as canonical JSON (RFC
/// 8785) and its identity is the full SHA-256 of those bytes.
pub const SCHEMA_RECEIPT: &str = "frf-receipt-v10";
/// Claim schema. v2 carries the full Claim IR: the structured scope K, the
/// blocking residuals, the premise receipts (`requires`), the comparison
/// relation, and the machine proposition — admission is the paper's rule
/// `Scope(K) ⊆ Scope(P₁ ∪ … ∪ Pₙ)`, implemented literally.
pub const SCHEMA_CLAIM: &str = "frf-claim-v2";
/// Runner identity block recorded in every capture at court time.
pub const SCHEMA_RUNNER: &str = "frf-runner-v1";
/// Environment identity block recorded in every capture at court time.
pub const SCHEMA_ENVIRONMENT: &str = "frf-environment-v1";
/// Observation provenance block (runner + comparator implementations).
pub const SCHEMA_PROVENANCE: &str = "frf-provenance-v1";

/// The token grammar schema (Section 6 of the paper).
pub const TOKEN_SCHEMA_VERSION: &str = "frf-token-v1";

/// Bundle manifest schema (OpenReceipt bundle: the receipt + its portable
/// object closure — see `spec/openreceipt.md`). v2 closure: the admitted
/// authority record is part of the evidence graph the receipt cites, so it
/// travels with the bundle.
pub const SCHEMA_BUNDLE: &str = "frf-bundle-v2";

/// Residual trajectory schema v2: the trajectory's SUBJECT is the residual
/// LINEAGE identity (stable across candidate revisions, authority versions,
/// environments, and time — `FRF/RESIDUAL-LINEAGE/v1`), not the exact
/// observation fingerprint; each observation records the exact fingerprint
/// it saw. Trajectories are DERIVED from an [`ExecutionSeries`] — a run
/// never knows which experiment references it.
pub const SCHEMA_TRAJECTORY: &str = "frf-trajectory-v2";

/// The ExecutionSeries protocol object: the experiment. One series per
/// (court, coordinate system); points are appended by series courts
/// (`--repeat`, `--candidate-revisions`, `--authority-versions`,
/// `--environment-point`, `--time-point`). A run never carries series
/// membership — the series references the runs.
pub const SCHEMA_SERIES: &str = "frf-series-v1";

/// The comparator extension protocol (spec/comparator.md): a canonical
/// JSON request a court writes to an external comparator program's stdin,
/// and the canonical JSON response it must produce on stdout. v2 adds
/// `request_id` to the RESPONSE: the SHA-256 of the exact canonical request
/// bytes the comparator received, so a response cryptographically names the
/// request it answers (the court refuses a response that does not).
pub const SCHEMA_COMPARATOR_REQUEST: &str = "frf-comparator-request-v2";
pub const SCHEMA_COMPARATOR_RESPONSE: &str = "frf-comparator-response-v2";

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
/// (`frf court minimize`). Every ddmin attempt is recorded; the final
/// reproducer is court-verified (the lineage survives) and carries
/// provenance back to the original residual.
pub const SCHEMA_REDUCTION: &str = "frf-reduction-v1";
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionSeries {
    pub schema_version: String,
    /// The experiment key: `{court}-{coordinate_system}` (the series file
    /// name).
    pub id: String,
    pub court: String,
    pub coordinate_system: String,
    /// The ordered points (appended in observation order).
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

/// One ddmin attempt: the reduced fixture tried, whether the residual
/// lineage survived it, and whether the reduction was kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReductionAttempt {
    pub attempt: u32,
    /// SHA-256 of the reduced fixture tried (content-addressed under
    /// `objects/`).
    pub fixture_sha256: String,
    /// Whether the residual's LINEAGE survived the reduction (the
    /// preservation predicate: the same kind/axis/surface divergence is
    /// still observed).
    pub preserved: bool,
    /// Whether the reduction was kept (preserved AND the fixture shrank).
    pub kept: bool,
}

/// The derivation of a minimization experiment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReductionDerivation {
    /// The reduction strategy (`ddmin-lines` in this version).
    pub strategy: String,
    pub original_lines: u32,
    pub final_lines: u32,
    /// Whether minimality was PROVEN (the deterministic ddmin search
    /// completed within the attempt budget).
    pub minimal: bool,
}

/// A minimization experiment: the record of reducing one residual's fixture
/// until the divergence lineage stops surviving. Content-addressed
/// (`FRF/REDUCTION/v1`); the final reproducer is court-verified and carries
/// provenance back to the original residual.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReductionRecord {
    pub schema_version: String,
    /// Content address: `FRF/REDUCTION/v1` over the record's own fields.
    pub id: String,
    /// The residual being minimized.
    pub residual_id: String,
    pub axis: String,
    pub kind: ResidualKind,
    pub authority: String,
    /// The exact candidate artifact the residual was observed against (the
    /// minimizer holds the candidate fixed).
    pub candidate_sha256: String,
    pub original_fixture_sha256: String,
    /// The minimal reproducer: the smallest fixture (at line granularity)
    /// still producing the lineage, court-verified.
    pub final_fixture_sha256: String,
    /// Every reduction attempt, in order.
    pub attempts: Vec<ReductionAttempt>,
    pub derivation: ReductionDerivation,
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
}

/// The execution context a comparator may need (the question's inputs).
#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComparatorContext<'a> {
    pub fixture_sha256: &'a str,
    pub arguments: &'a [String],
    pub environment_digest: &'a str,
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

/// The sign a receipt entry MUST carry for a residual record: single-run
/// courts honestly record `not-observed` drift/slew (one run cannot observe
/// drift or slew); a residual whose run belongs to an [`ExecutionSeries`]
/// derives its sign from the series' trajectory for the residual's LINEAGE.
///
/// The receipt PINs the derivation basis: `series` names the exact
/// [`ExecutionSeries`] snapshot the drift/slew were derived from, so later
/// experiments that reference the same content-addressed run can never
/// change what an emitted receipt means — the receipt is a snapshot, and the
/// verifier replays the pinned series.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResidualSign {
    pub norm: String,
    pub drift: String,
    pub slew: String,
    /// The ExecutionSeries the drift/slew were derived from, present when
    /// `norm == "repeated-run"`. `None` = single-run (no series membership
    /// at emit time; the absence of a later experiment is not something an
    /// immutable snapshot can be held responsible for).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub series: Option<String>,
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

    /// Union of two premise scopes (the P₁ ∪ … ∪ Pₙ of the admission rule),
    /// merged set-wise per dimension.
    pub fn union(&self, other: &ClaimScope) -> ClaimScope {
        let merge = |a: &[String], b: &[String]| {
            let mut v = a.to_vec();
            for x in b {
                if !v.contains(x) {
                    v.push(x.clone());
                }
            }
            v
        };
        ClaimScope {
            authority: merge(&self.authority, &other.authority),
            candidate: merge(&self.candidate, &other.candidate),
            fixtures: merge(&self.fixtures, &other.fixtures),
            fixture_family: if self.fixture_family.is_empty() {
                other.fixture_family.clone()
            } else {
                self.fixture_family.clone()
            },
            observables: merge(&self.observables, &other.observables),
            environments: merge(&self.environments, &other.environments),
            versions: merge(&self.versions, &other.versions),
            temporal: merge(&self.temporal, &other.temporal),
        }
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
    pub positive: Vec<String>,
    pub non_claims: Vec<String>,
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
