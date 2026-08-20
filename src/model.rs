//! Canonical FRF object model (v0 subset).
//!
//! Invariants stated before code:
//! - Authority ids are `{name}-{version}`, safe path components, unique in a store.
//! - A residual disposition is either `open` (no reason) or a closure kind with a
//!   required one-line reason. There is no third state: `open` cannot carry a
//!   reason, and a closure cannot lack one. This is enforced at the type level
//!   by [`Disposition`] and by the only mutator, [`ResidualRecord::dispose`].
//! - Raw captures and receipts are written once and never rewritten; the residual
//!   record is the only evidence object that mutates, and only through
//!   [`ResidualRecord::dispose`].
//!
//! Field names and shapes follow Section 10, Section 12, and Appendix A of
//! *The Forensic Residual Framework* (de Beer, 2026). v0 additions beyond the
//! paper's minimal snippets (traceability fields such as `authority`, `scope`,
//! per-axis hashes, and the mandatory `reason`) are documented in the README.

use serde::{Deserialize, Serialize};
use std::fmt;

pub const SCHEMA_AUTHORITY: &str = "frf-authority-v1";
pub const SCHEMA_CAPTURE: &str = "frf-capture-v1";
pub const SCHEMA_RESIDUAL: &str = "frf-residual-v1";
pub const SCHEMA_RECEIPT: &str = "frf-receipt-v1";
pub const SCHEMA_CLAIM: &str = "frf-claim-v1";

/// The token grammar schema (Section 6 of the paper).
pub const TOKEN_SCHEMA_VERSION: &str = "frf-token-v1";

// ---------------------------------------------------------------------------
// Observable axes
// ---------------------------------------------------------------------------

/// Observable axis. v0 supports exactly two; adding an axis means writing a
/// new comparator in the court command, not restructuring the core.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Axis {
    Exit,
    Stderr,
}

impl Axis {
    pub fn as_str(self) -> &'static str {
        match self {
            Axis::Exit => "exit",
            Axis::Stderr => "stderr",
        }
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "exit" => Ok(Axis::Exit),
            "stderr" => Ok(Axis::Stderr),
            other => Err(format!(
                "unsupported observable axis '{other}': v0 supports 'exit' and 'stderr' only"
            )),
        }
    }

    /// The declared comparison relation for this axis (Section 10, Δ_a).
    pub fn comparator(self) -> &'static str {
        match self {
            Axis::Exit => "eq(exit-code)",
            Axis::Stderr => "eq(stderr-first-line)",
        }
    }
}

/// Residual kind. v0 court comparators produce exactly these two kinds
/// (Section 12: `exit` and `text`); the enum has no catch-all so an
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
            Axis::Stderr => ResidualKind::Text,
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
/// (the claim compiler's refusal rule).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ClosureKind {
    Fixed,
    Intentional,
    Environmental,
    OracleVersion,
    Harness,
    Unknown,
}

impl ClosureKind {
    pub const ALL: [ClosureKind; 6] = [
        ClosureKind::Fixed,
        ClosureKind::Intentional,
        ClosureKind::Environmental,
        ClosureKind::OracleVersion,
        ClosureKind::Harness,
        ClosureKind::Unknown,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            ClosureKind::Fixed => "fixed",
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

/// Residual disposition with the reason invariant enforced by construction:
/// `Open` carries no reason, every `Closed` carries a non-empty one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposition {
    Open,
    Closed { kind: ClosureKind, reason: String },
}

impl Disposition {
    pub fn as_str(&self) -> &'static str {
        match self {
            Disposition::Open => "open",
            Disposition::Closed { kind, .. } => kind.as_str(),
        }
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            Disposition::Open => None,
            Disposition::Closed { reason, .. } => Some(reason),
        }
    }

    pub fn is_blocking(&self) -> bool {
        match self {
            Disposition::Open => true,
            Disposition::Closed { kind, .. } => kind.blocks_claim(),
        }
    }
}

impl fmt::Display for Disposition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// `Disposition` serializes as `disposition: <status>` with a sibling
// `reason:` key exactly when closed — the Appendix A / Section 12 shape:
//
//   disposition: fixed
//   reason: "candidate patched to match reference exit class"
//
// The custom impl exists so the `open` state cannot carry a reason and a
// closed state cannot omit one, even in YAML.
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
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "disposition" => status = Some(map.next_value()?),
                        "reason" => reason = Some(map.next_value()?),
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
                        if reason.is_some() {
                            return Err(A::Error::custom(
                                "disposition 'open' cannot carry a reason",
                            ));
                        }
                        Ok(Disposition::Open)
                    }
                    other => {
                        let kind = ClosureKind::parse(other).ok_or_else(|| {
                            A::Error::custom(format!("unknown disposition '{other}'"))
                        })?;
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
    pub environment_digest: String,
    pub court_spec: CourtSpec,
    pub reference: SideCapture,
    pub candidate: SideCapture,
    pub residuals: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SideCapture {
    /// Exit code as a string, or `signal` if terminated by a signal.
    pub exit: String,
    pub exit_sha256: String,
    /// First stderr line (the stderr axis compares exactly this).
    pub stderr_first_line: String,
    pub stderr_first_line_sha256: String,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
}

// ---------------------------------------------------------------------------
// Residual
// ---------------------------------------------------------------------------

/// A preserved disagreement (Section 12 record + traceability fields).
///
/// Mutable only through [`ResidualRecord::dispose`]: `court run` writes the
/// record with `Open` disposition, and no other command may touch it.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub raw_reference: String,
    pub raw_candidate: String,
    pub raw_reference_sha256: String,
    pub raw_candidate_sha256: String,
    #[serde(flatten)]
    pub disposition: Disposition,
}

impl ResidualRecord {
    /// The only sanctioned mutation: record a closure. Rejects a missing or
    /// multi-line reason and refuses to move a residual back to `open`.
    pub fn dispose(&mut self, kind: ClosureKind, reason: String) -> crate::error::Result<()> {
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
        self.disposition = Disposition::Closed { kind, reason };
        Ok(())
    }
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
    pub schema_version: String,
    pub court: ReceiptCourt,
    pub authority: ReceiptAuthority,
    pub candidate: ReceiptCandidate,
    pub environment: ReceiptEnvironment,
    pub fixtures: Vec<ReceiptFixture>,
    pub observables: Vec<ReceiptObservable>,
    pub residuals: Vec<ReceiptResidual>,
    pub endoduction: ReceiptEndoduction,
    pub claims: ReceiptClaims,
    pub replay: ReceiptReplay,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptCourt {
    pub id: String,
    pub question: String,
    pub falsifier: String,
    pub admissibility_envelope: ReceiptEnvelope,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptCandidate {
    pub name: String,
    pub version_or_commit: String,
    pub build_profile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptEnvironment {
    pub os: String,
    pub architecture: String,
    pub toolchain: String,
    pub environment_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptFixture {
    pub id: String,
    pub hash: String,
    pub arguments: Vec<String>,
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
    pub disposition: String,
    /// Mandatory reason for closed dispositions; absent while `open`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptReplay {
    pub command: String,
}

// ---------------------------------------------------------------------------
// Compiled claim (claims/ — written only by `frf claim compile`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimRecord {
    pub schema_version: String,
    pub receipt: String,
    pub authority: String,
    pub court: String,
    pub fixture_family: String,
    pub environment: String,
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
            serde_yaml::from_str("disposition: fixed\nreason: candidate patched\n").unwrap();
        assert_eq!(
            closed,
            Disposition::Closed {
                kind: ClosureKind::Fixed,
                reason: "candidate patched".into()
            }
        );
        let yaml = serde_yaml::to_string(&closed).unwrap();
        assert!(yaml.contains("disposition: fixed"));
        assert!(yaml.contains("reason: candidate patched"));
    }

    #[test]
    fn disposition_serde_rejects_forbidden_states() {
        // closed without reason
        assert!(serde_yaml::from_str::<Disposition>("disposition: fixed\n").is_err());
        // open with a reason
        assert!(serde_yaml::from_str::<Disposition>("disposition: open\nreason: x\n").is_err());
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
            raw_reference: "2".into(),
            raw_candidate: "1".into(),
            raw_reference_sha256: "a".repeat(64),
            raw_candidate_sha256: "b".repeat(64),
            disposition: Disposition::Open,
        };
        let yaml = serde_yaml::to_string(&record).unwrap();
        let back: ResidualRecord = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(back.disposition, Disposition::Open);
        assert_eq!(back.raw_reference, "2");
    }

    #[test]
    fn dispose_rejects_missing_or_multiline_reason() {
        let mut record = ResidualRecord {
            schema_version: SCHEMA_RESIDUAL.into(),
            id: "cli-exit-0001".into(),
            court: "c".into(),
            run: "r".into(),
            axis: Axis::Exit,
            kind: ResidualKind::Exit,
            surface: None,
            authority: "a".into(),
            scope: "s".into(),
            raw_reference: "2".into(),
            raw_candidate: "1".into(),
            raw_reference_sha256: "a".repeat(64),
            raw_candidate_sha256: "b".repeat(64),
            disposition: Disposition::Open,
        };
        assert!(record.dispose(ClosureKind::Fixed, "   ".into()).is_err());
        assert!(record
            .dispose(ClosureKind::Fixed, "line one\nline two".into())
            .is_err());
        record
            .dispose(ClosureKind::Fixed, "one line".into())
            .unwrap();
        assert_eq!(record.disposition.as_str(), "fixed");
    }
}
