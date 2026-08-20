//! `frf court run`: execute authority and candidate against the fixture,
//! capture raw observations immutably, and preserve every declared-axis
//! disagreement as an `open` residual plus its endoduction token.
//!
//! Invariants enforced here:
//! - The admitted authority's file is re-hashed before execution; a drifted
//!   oracle refuses to run (silent oracle drift is prevented, not warned).
//! - Raw captures are written with `create_new` under a content-addressed run
//!   id: identical evidence cannot be re-captured, and nothing is overwritten.
//! - Residuals are written with disposition `open` and no interpretation:
//!   no explanation, no repair, no "who is right".
//! - `{fixture}` substitution is literal; arguments never pass through a shell.

use crate::error::{FrfError, Result};
use crate::host;
use crate::model::*;
use crate::store::Store;
use std::io::Write;
use std::path::Path;

pub fn run(store: &Store, manifest_path: &Path) -> Result<String> {
    let manifest: CourtManifest = store.parse_yaml(manifest_path)?;
    let spec = &manifest.court;

    // -- validate the declaration ------------------------------------------

    // The court id becomes a directory-name component (run-{court}-{hash});
    // it must not be able to escape the captures root.
    crate::store::validate_id("court", &spec.id)?;

    let observables: Vec<Axis> = spec
        .admissibility_envelope
        .observables
        .iter()
        .map(|o| Axis::parse(o).map_err(FrfError::new))
        .collect::<Result<_>>()?;

    let authority = store.load_authority(&spec.authority)?;

    // Drift check: the authority file must still hash to its admitted value.
    let authority_path = Path::new(&authority.path);
    if !authority_path.is_file() {
        return Err(FrfError::new(format!(
            "authority file {} is missing; the court cannot run (re-admit as a new version)",
            authority_path.display()
        )));
    }
    let current = host::sha256_file(authority_path)?;
    if current != authority.executable_sha256 {
        return Err(FrfError::new(format!(
            "authority file {} changed since admission ({} != {}); refusing to run against a drifted oracle — admit the new file as a new version",
            authority_path.display(),
            &current[..16],
            &authority.executable_sha256[..16]
        )));
    }

    let candidate_path = Path::new(&spec.candidate.path);
    if !candidate_path.is_file() {
        return Err(FrfError::new(format!(
            "candidate {} not found",
            candidate_path.display()
        )));
    }

    let fixture_path = Path::new(&spec.fixture.path);
    if !fixture_path.is_file() {
        return Err(FrfError::new(format!(
            "fixture {} not found",
            fixture_path.display()
        )));
    }
    let fixture_sha256 = host::sha256_file(fixture_path)?;

    let arguments: Vec<String> = spec
        .fixture
        .arguments
        .iter()
        .map(|a| {
            if a == "{fixture}" {
                spec.fixture.path.clone()
            } else {
                a.clone()
            }
        })
        .collect();
    if !arguments.contains(&spec.fixture.path) {
        eprintln!(
            "frf: warning: fixture {} is not referenced by the declared arguments; this execution does not exercise it",
            spec.fixture.path
        );
    }

    // -- observe both sides ---------------------------------------------------

    let reference_out = host::run_process(authority_path, &arguments)?;
    let candidate_out = host::run_process(candidate_path, &arguments)?;
    let environment_digest = host::environment_digest();
    // Bind the exact candidate artifact: labels are distrustful; the executed
    // bytes are the identity.
    let candidate_sha256 = host::sha256_file(candidate_path)?;

    let reference = SideCapture::from_outcome(&reference_out);
    let candidate = SideCapture::from_outcome(&candidate_out);

    // -- diff the declared axes (Section 12 comparators) -----------------------

    let mut residuals: Vec<ResidualRecord> = Vec::new();
    for axis in &observables {
        let (raw_ref, raw_cand, surface) = match axis {
            Axis::Exit => (reference.exit.clone(), candidate.exit.clone(), None),
            Axis::Stderr => (
                reference.stderr_first_line.clone(),
                candidate.stderr_first_line.clone(),
                Some("first-diagnostic-line".to_string()),
            ),
        };
        if raw_ref != raw_cand {
            let kind = ResidualKind::from_axis(*axis);
            let seq = store.next_residual_seq(kind)?;
            residuals.push(ResidualRecord {
                schema_version: SCHEMA_RESIDUAL.to_string(),
                id: format!("{}-{}-{:04}", kind.domain_prefix(), kind.as_str(), seq),
                court: spec.id.clone(),
                run: String::new(), // filled once the run id is known
                axis: *axis,
                kind,
                surface,
                authority: authority.id.clone(),
                scope: spec.admissibility_envelope.fixture_family.clone(),
                candidate_sha256: candidate_sha256.clone(),
                raw_reference: raw_ref,
                raw_candidate: raw_cand,
                raw_reference_sha256: String::new(),
                raw_candidate_sha256: String::new(),
            });
        }
    }

    // -- content-address the run ----------------------------------------------

    let mut evidence = format!(
        "court={}\nauthority={}\ncandidate={}|{}\nfixture={}\nargs={:?}\nenv={}\nreference={}\ncandidate={}",
        spec.id,
        authority.id,
        spec.candidate.name,
        candidate_sha256,
        fixture_sha256,
        arguments,
        environment_digest,
        reference.serialize(),
        candidate.serialize(),
    );
    for r in &residuals {
        evidence.push_str(&format!(
            "\nresidual={}|{}|{}",
            r.kind.as_str(),
            r.raw_reference,
            r.raw_candidate
        ));
    }
    let run = format!(
        "run-{}-{}",
        spec.id,
        &host::sha256_bytes(evidence.as_bytes())[..8]
    );
    let run_dir = store.run_dir(&run)?;
    if run_dir.exists() {
        return Err(FrfError::new(format!(
            "run '{run}' already exists (identical evidence was already captured); raw captures are immutable — refusing to re-capture"
        )));
    }

    // -- write raw captures (immutable) ----------------------------------------

    std::fs::create_dir(&run_dir)
        .map_err(|e| FrfError::new(format!("cannot create {}: {e}", run_dir.display())))?;
    write_side_files(&run_dir, "reference", &reference_out, &reference)?;
    write_side_files(&run_dir, "candidate", &candidate_out, &candidate)?;

    // Fill in run id + axis hashes, then persist the immutable observation
    // records and their (open) endoduction tokens.
    for r in &mut residuals {
        r.run = run.clone();
        r.raw_reference_sha256 = host::sha256_bytes(r.raw_reference.as_bytes());
        r.raw_candidate_sha256 = host::sha256_bytes(r.raw_candidate.as_bytes());
        let yaml = store.to_yaml(r)?;
        store.write_once(&store.residual_path(&r.id)?, &yaml)?;
        store.write_token(r, &Disposition::Open)?;
        let token = crate::kappa::kappa(r, &Disposition::Open);
        eprintln!(
            "residual {} ({}) open: reference={} candidate={} -> token {} -> {}",
            r.id,
            r.kind.as_str(),
            r.raw_reference,
            r.raw_candidate,
            token.token,
            token.next_court
        );
    }

    // -- capture manifest --------------------------------------------------------

    let capture = CaptureManifest {
        schema_version: SCHEMA_CAPTURE.to_string(),
        run: run.clone(),
        court: spec.id.clone(),
        authority: authority.id.clone(),
        manifest: manifest_path.to_string_lossy().into_owned(),
        fixture: spec.fixture.id.clone(),
        fixture_sha256,
        arguments,
        environment_digest,
        court_spec: spec.clone(),
        candidate_sha256,
        reference,
        candidate,
        residuals: residuals.iter().map(|r| r.id.clone()).collect(),
    };
    let yaml = store.to_yaml(&capture)?;
    store.write_once(&run_dir.join("capture.yaml"), &yaml)?;

    eprintln!(
        "court {} run: captures, residuals, and tokens written under {}",
        spec.id,
        run_dir.display()
    );
    Ok(run)
}

impl SideCapture {
    fn from_outcome(outcome: &host::ProcessOutcome) -> SideCapture {
        let stderr_first_line = String::from_utf8_lossy(&outcome.stderr)
            .split('\n')
            .next()
            .unwrap_or("")
            .to_string();
        SideCapture {
            exit: outcome.exit.clone(),
            exit_sha256: host::sha256_bytes(outcome.exit.as_bytes()),
            stderr_first_line: stderr_first_line.clone(),
            stderr_first_line_sha256: host::sha256_bytes(stderr_first_line.as_bytes()),
            stdout_sha256: host::sha256_bytes(&outcome.stdout),
            stderr_sha256: host::sha256_bytes(&outcome.stderr),
        }
    }

    fn serialize(&self) -> String {
        format!(
            "exit={}|stdout={}|stderr={}|first={}",
            self.exit, self.stdout_sha256, self.stderr_sha256, self.stderr_first_line
        )
    }
}

/// Raw bytes of stdout/stderr and the compared projections (exit code, first
/// stderr line) as plain text. All files are created with `create_new`.
fn write_side_files(
    run_dir: &Path,
    side: &str,
    outcome: &host::ProcessOutcome,
    capture: &SideCapture,
) -> Result<()> {
    for (name, bytes) in [("stdout", &outcome.stdout), ("stderr", &outcome.stderr)] {
        write_once(run_dir.join(format!("{side}.{name}")), bytes)?;
    }
    for (name, text) in [
        ("exit", &capture.exit),
        ("stderr_first_line", &capture.stderr_first_line),
    ] {
        write_once(
            run_dir.join(format!("{side}.{name}.txt")),
            format!("{text}\n").as_bytes(),
        )?;
    }
    Ok(())
}

fn write_once(path: std::path::PathBuf, bytes: &[u8]) -> Result<()> {
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(mut f) => f
            .write_all(bytes)
            .and_then(|_| f.flush())
            .map_err(|e| FrfError::new(format!("cannot write {}: {e}", path.display()))),
        Err(e) => Err(FrfError::new(format!(
            "cannot create {}: {e}",
            path.display()
        ))),
    }
}
