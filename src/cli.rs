//! CLI surface. The correct way to use the tool is shorter than the wrong
//! way: every verb is one level deep (`frf authority admit`, not
//! `frf admit --type authority`), and invalid dispositions are rejected by
//! the argument parser rather than silently defaulted.

use crate::model::ClosureKind;
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "frf",
    version,
    about = "Forensic Residual Framework kernel: authority -> court -> capture -> residual -> endoduction -> disposition -> receipt -> claim (v0)"
)]
pub struct Cli {
    /// Evidence root directory (`$FRF_ROOT` overrides; default `.frf`).
    #[arg(long, env = "FRF_ROOT", default_value = ".frf", value_name = "DIR")]
    pub root: PathBuf,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Admit an executable reference as an authority
    Authority {
        #[command(subcommand)]
        sub: AuthorityCmd,
    },
    /// Run a court: execute authority and candidate against a fixture, capture raw output, preserve residuals
    Court {
        #[command(subcommand)]
        sub: CourtCmd,
    },
    /// Record a residual's disposition (a one-line reason is mandatory; `open` is not settable)
    Residual {
        #[command(subcommand)]
        sub: ResidualCmd,
    },
    /// Bind court, authority, candidate, fixture, captures, residuals, and dispositions into a receipt
    Receipt {
        #[command(subcommand)]
        sub: ReceiptCmd,
    },
    /// Compile a claim from a receipt (refuses while any residual is open, unknown, or harness)
    Claim {
        #[command(subcommand)]
        sub: ClaimCmd,
    },
    /// Replay a captured run (or receipt): re-execute the exact snapshotted
    /// artifacts under a checked environment and require the observation to
    /// reproduce. `--policy exact` (default) additionally requires the same
    /// execution profile + capture bounds, environment, and interpreter
    /// provenance; `--policy semantic` admits provenance differences and
    /// reports them.
    Replay {
        /// Run id or receipt id (printed by `frf court run` / `frf receipt emit`)
        id: String,
        /// Reproduction policy: `exact` (same execution provenance, default)
        /// or `semantic` (same bounded observation, provenance drift reported)
        #[arg(long, value_name = "exact|semantic", default_value = "exact")]
        policy: String,
    },
    /// Export or verify a portable OpenReceipt bundle: the receipt + its complete object closure
    Bundle {
        #[command(subcommand)]
        sub: BundleCmd,
    },
    /// Attest a content-addressed evidence subject with an external witness
    /// program (the witness extension protocol, spec/witness.md): the
    /// statement is recorded as a content-addressed WitnessStatement with the
    /// canonical request/response preserved as evidence
    Witness {
        #[command(subcommand)]
        sub: WitnessCmd,
    },
    /// Report the verification status of an evidence tree: the GRAPH verdict
    /// (every canonical document, identity, and reference), the OBJECT
    /// CLOSURE (complete, or incomplete-by-policy with the declared-detached
    /// payloads), and REPLAYABILITY
    Evidence {
        #[command(subcommand)]
        sub: EvidenceCmd,
    },
}

#[derive(Subcommand)]
pub enum AuthorityCmd {
    /// Admit an executable reference as an authority
    Admit {
        /// Path to the executable (working-directory-relative)
        path: PathBuf,
        /// Authority name; the id becomes {name}-{version}
        #[arg(long)]
        name: String,
        /// Authority version; the id becomes {name}-{version}
        #[arg(long)]
        version: String,
        /// Authority kind; v0 admits executable_reference only
        #[arg(long, default_value = "executable_reference")]
        kind: String,
    },
}

#[derive(Subcommand)]
pub enum CourtCmd {
    /// Run the court declared in the manifest
    Run {
        /// Path to the court manifest (working-directory-relative)
        manifest: PathBuf,
        /// Execute the court this many times (fresh processes each time) and
        /// write the repeat_index ExecutionSeries + one residual trajectory
        /// per observed lineage; identical repetitions reuse the
        /// content-addressed run
        #[arg(long, value_name = "N")]
        repeat: Option<u32>,
        /// The candidate_revision axis: one run per candidate path
        /// (comma-separated), each point a new revision of the candidate
        #[arg(long, value_name = "P1,P2,...")]
        candidate_revisions: Option<String>,
        /// The authority_version axis: one run per admitted authority version
        /// (comma-separated, under the manifest's authority name)
        #[arg(long, value_name = "V1,V2,...")]
        authority_versions: Option<String>,
        /// The environment axis: this run is one point of the environment
        /// experiment at the given coordinate label (the series accumulates)
        #[arg(long, value_name = "LABEL")]
        environment_point: Option<String>,
        /// The time axis: this run is one point of the time experiment at
        /// the given coordinate label (the series accumulates)
        #[arg(long, value_name = "LABEL")]
        time_point: Option<String>,
        /// Explicitly choose the branch to extend when appending to an
        /// environment/time experiment that has branched (its head is
        /// ambiguous); the parent series snapshot id
        #[arg(long, value_name = "SERIES_ID")]
        series_parent: Option<String>,
    },
    /// Minimize a residual: the routed minimizer (its κ token's next_court)
    /// reduces the fixture with deterministic ddmin while holding the
    /// candidate, authority, comparator, and environment fixed, records every
    /// attempt, and court-verifies the final reproducer
    Minimize {
        /// Residual id (e.g. cli-exit-0001)
        residual: String,
    },
    /// Challenge the court: the negative controls. For every applicable
    /// mutation operator the court runs against a MUTANT candidate — a
    /// deterministic wrapper of the admitted reference that alters exactly
    /// one observable dimension — and must observe a divergence on the
    /// targeted axis and only on it. A court that is blind to a declared
    /// defect class, or conflates it with other axes, is refused
    Challenge {
        /// Court declaration (the same manifest `court run` takes)
        manifest: PathBuf,
        /// Mutation operators to apply (default: every built-in operator for
        /// the court's declared observables, plus each declared external
        /// mutation provider for its target axes): exit-class,
        /// stderr-first-line, stdout-first-line, or a declared mutation
        /// provider id
        #[arg(long, value_name = "exit-class,stderr-first-line,provider-id")]
        operators: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum ResidualCmd {
    /// Set a residual's disposition (requires --reason; `fixed` also requires
    /// --resolution-run — a disposition is not evidence)
    Dispose {
        /// Residual id (e.g. cli-exit-0001)
        id: String,
        #[arg(long, value_enum)]
        disposition: ClosureArg,
        /// One-line reason; mandatory, never silently defaulted
        #[arg(long)]
        reason: String,
        /// Required for `--disposition fixed`: a court run whose captures
        /// show the residual no longer reproduces
        #[arg(long, value_name = "RUN_ID")]
        resolution_run: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum ReceiptCmd {
    /// Emit the receipt binding a court run
    Emit {
        /// Run id (printed by `frf court run`)
        run: String,
    },
}

#[derive(Subcommand)]
pub enum ClaimCmd {
    /// Compile a claim from one or more premise receipts (multi-premise
    /// since v6: K is the region of each premise's clean surface, and
    /// admission is the literal containment K ⊆ P₁ ∪ … ∪ Pₙ over the region
    /// cells); refuses open/unknown/harness residuals whose surface
    /// intersects any claim cell
    Compile {
        /// Premise receipt ids (printed by `frf receipt emit`); all must
        /// bind the same authority and the same candidate artifact
        #[arg(value_name = "RECEIPT", num_args = 1.., required = true)]
        receipt: Vec<String>,
        /// Emit the Claim IR as canonical JSON instead of prose (prose is
        /// one renderer of the IR)
        #[arg(long)]
        json: bool,
        /// The admission policy (assurance grade): baseline (observation
        /// evidence only), sensitivity-backed (every claimed axis must have
        /// challenge coverage — the court demonstrated it can see the
        /// surface's defect class), independently-witnessed (sensitivity
        /// plus a verified witness attestation of the receipt AND at least
        /// one admissible independence relation per premise — an affirming
        /// witness alone is witnessed, not independently witnessed),
        /// high-assurance (independently witnessed, observed under the
        /// reference execution profile + the reference capture bounds, which
        /// no FRF_EXEC_* override can redefine). The compiled
        /// claim carries the capability evidence that satisfied the tier
        #[arg(long, default_value = "baseline")]
        policy: String,
        /// The REQUIRED sensitivity mutation profile: a comma-separated
        /// list of AXIS:FAMILY pairs (e.g. `exit:exit-class,stderr:stderr-first-line`)
        /// that MUST be demonstrated on the claimed surface — for each pair,
        /// the named axis (which the claim must cover) must have the named
        /// mutation family among its demonstrated operators. Absent = any
        /// demonstrated sensitivity on each claimed axis suffices. The claim
        /// records the required profile and each axis's DEMONSTRATED
        /// profile; a demonstrated family is sensitivity evidence for that
        /// family, never a universal-correctness claim
        #[arg(long, value_name = "AXIS:FAMILY,…", default_value = "")]
        mutation_profile: String,
    },
    /// Render a COMPILED claim into a presentation format (prose, json,
    /// sarif, ci, badge). The target is a CLAIM id (content address) or a
    /// receipt (resolved through the by-receipt index); the claim is
    /// RE-VERIFIED against the evidence tree before a single field is
    /// rendered — identity rederives (FRF/CLAIM/v1), the premises verify,
    /// scope + universe re-derive, and the policy evidence re-verifies — so
    /// a hand-written canonical file at `claims/<id>.json` is refused, never
    /// rendered. Prose is DERIVED from the verified premises, never stored
    /// as authoritative Claim IR.
    Render {
        /// A claim id (content address), or a receipt id (the by-receipt
        /// index must resolve it; a receipt compiled more than once names
        /// several claims and must be rendered by claim id)
        receipt: String,
        /// The presentation format
        #[arg(long, value_name = "prose|json|sarif|ci|badge")]
        format: String,
    },
}

#[derive(Subcommand)]
pub enum WitnessCmd {
    /// Attest a subject (a run, receipt, or residual id) with a declared
    /// witness program; prints the content-addressed statement id
    Attest {
        /// The subject kind: `run`, `receipt`, or `residual`
        #[arg(value_name = "run|receipt|residual")]
        kind: String,
        /// The subject id (printed by `frf court run` / `frf receipt emit`, or
        /// a residual id)
        subject_id: String,
        /// The witness semantic id (the attestation relation's name)
        #[arg(long, value_name = "ID")]
        id: String,
        /// The attestation relation family (part of the semantic identity)
        #[arg(long, value_name = "RELATION")]
        relation: String,
        /// The relation version (part of the semantic identity)
        #[arg(long, value_name = "VERSION", default_value = "v1")]
        relation_version: String,
        /// Working-directory-relative path to the witness program (read +
        /// hashed + sealed BEFORE it runs)
        #[arg(long, value_name = "PATH")]
        program: String,
        /// The exact statement the witness attests
        #[arg(long, value_name = "TEXT")]
        statement: String,
    },
    /// Declare the independence relation of a witness statement
    /// (spec/witness.md §6): an operator records an independence CLAIM about
    /// a verified attestation — which relation is claimed (`different-
    /// implementation`, `separate-party`, `unaffiliated-channel`,
    /// `adversarial-review`) and the basis it rests on. The claim is
    /// recorded as a content-addressed IndependenceEvidence record; FRF
    /// verifies the evidence structure, never the social truth of
    /// independence — a different executable hash is never by itself
    /// evidence of independent observation, the DECLARATION is the evidence
    Independence {
        /// Witness statement id (printed by `frf witness attest`)
        statement_id: String,
        /// The declared independence relation (a closed set)
        #[arg(
            long,
            value_name = "different-implementation|separate-party|unaffiliated-channel|adversarial-review"
        )]
        relation: String,
        /// The relation version (part of the semantic identity)
        #[arg(long, value_name = "VERSION", default_value = "v1")]
        relation_version: String,
        /// WHY the relation is claimed — the evidence the claim rests on
        /// (mandatory)
        #[arg(long, value_name = "TEXT")]
        basis: String,
        /// Optional detail
        #[arg(long, value_name = "TEXT")]
        detail: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum EvidenceCmd {
    /// Report the verification status of the evidence tree: the GRAPH
    /// verdict, the OBJECT CLOSURE (complete, or incomplete-by-policy with
    /// the declared-detached payloads), and REPLAYABILITY
    Status {},
    /// The publication transform: copy a COMPLETE local evidence tree to an
    /// output, withholding every payload the policy declares detached, and
    /// write the declaration into the output. The output is written fresh
    /// (never overwritten) and is verified at the graph level before the
    /// command returns
    PublishDetached {
        /// The publication policy: a frf-detached-objects-v1 declaration
        /// naming the cids (and optional record paths) to withhold
        #[arg(long, value_name = "PATH")]
        policy: PathBuf,
        /// The output tree (must not already exist)
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
pub enum BundleCmd {
    /// Export a receipt's portable closure: manifest + receipt + captures +
    /// objects + residuals + disposition events (and the compiled claim when
    /// present). Only verified evidence may be exported.
    Export {
        /// Receipt id (printed by `frf receipt emit`)
        receipt: String,
        /// Output path: a bundle directory, or the single-file archive with
        /// --single (default: bundles/<receipt-id>.frf)
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
        /// Seal the bundle as ONE deterministic tar archive (the manifest
        /// inside declares the single-tar container)
        #[arg(long)]
        single: bool,
    },
    /// Verify a bundle: prove every inventory file, recompute the receipt's
    /// required closure, and verify the receipt against the bundled evidence
    /// alone — no original source tree or FRF installation needed
    Verify {
        /// Path to the bundle: a directory, or a single-file archive
        path: PathBuf,
    },
    /// Replay a bundle: re-execute its snapshotted authority + candidate
    /// with the captured argv under a checked environment, from the bundle
    /// ALONE (no original source tree, no exporting installation). The
    /// bundle is verified against itself first; exact replay also requires
    /// the same execution provenance, semantic admits and reports drift
    Replay {
        /// Path to the bundle: a directory, or a single-file archive
        path: PathBuf,
        /// Reproduction policy: `exact` (same execution provenance, default)
        /// or `semantic` (same bounded observation, provenance drift reported)
        #[arg(long, value_name = "exact|semantic", default_value = "exact")]
        policy: String,
    },
}

/// The six settable dispositions, in the paper's spelling. `open` is
/// deliberately absent: it is the initial state, not a choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ClosureArg {
    #[value(name = "fixed")]
    Fixed,
    #[value(name = "intentional")]
    Intentional,
    #[value(name = "environmental")]
    Environmental,
    #[value(name = "oracle_version")]
    OracleVersion,
    #[value(name = "harness")]
    Harness,
    #[value(name = "unknown")]
    Unknown,
}

impl ClosureArg {
    /// The [`ClosureKind`] for non-fixed dispositions. `fixed` is not a bare
    /// kind: it is handled as [`Disposition::Fixed`] with a resolution run.
    pub fn closure_kind(self) -> Option<ClosureKind> {
        match self {
            ClosureArg::Fixed => None,
            ClosureArg::Intentional => Some(ClosureKind::Intentional),
            ClosureArg::Environmental => Some(ClosureKind::Environmental),
            ClosureArg::OracleVersion => Some(ClosureKind::OracleVersion),
            ClosureArg::Harness => Some(ClosureKind::Harness),
            ClosureArg::Unknown => Some(ClosureKind::Unknown),
        }
    }
}
