//! Shared scaffolding for integration tests: workdir setup, binary
//! invocation, and the canonical golden-path tree.
#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

pub const BIN: &str = env!("CARGO_BIN_EXE_frf");
pub const ROOT: &str = "frf";
pub const MANIFEST: &str = "frf/courts/cli-malformed-input/manifest.yaml";

/// Canonical fixture files mirrored from the repo into a scratch workdir, so
/// the manifest's working-directory-relative paths resolve exactly.
pub const CANONICAL_FILES: &[&str] = &[
    "golden/reference.sh",
    "golden/candidate.sh",
    "golden/work/candidate-fixed.sh",
    "golden/comparators/stderr-first-line.py",
    "frf/courts/cli-malformed-input/manifest.yaml",
    "frf/courts/cli-malformed-input/manifest-candidate-fixed.yaml",
    "frf/courts/cli-malformed-input/fixtures/malformed-path.conf",
];

/// The resolution court declaration: the same court question against the
/// patched candidate. Running it provides the closure evidence a `fixed`
/// disposition must point at.
pub const RESOLUTION_MANIFEST: &str =
    "frf/courts/cli-malformed-input/manifest-candidate-fixed.yaml";

pub struct Workdir {
    pub dir: PathBuf,
}

impl Workdir {
    pub fn new(tag: &str) -> Workdir {
        let dir = std::env::temp_dir().join(format!(
            "frf-test-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        Workdir { dir }
    }

    pub fn path(&self, rel: &str) -> PathBuf {
        self.dir.join(rel)
    }

    /// Mirror the canonical golden-path files into this workdir.
    pub fn copy_canonical_tree(&self) {
        let src_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        for rel in CANONICAL_FILES {
            let dst = self.path(rel);
            fs::create_dir_all(dst.parent().unwrap()).unwrap();
            fs::copy(src_root.join(rel), &dst).unwrap();
        }
        set_exec(&self.path("golden/reference.sh"));
        set_exec(&self.path("golden/candidate.sh"));
    }

    /// Overwrite the candidate with an arbitrary script (still executable).
    pub fn write_candidate(&self, contents: &str) {
        let path = self.path("golden/candidate.sh");
        fs::write(&path, contents).unwrap();
        set_exec(&path);
    }
}

impl Drop for Workdir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[cfg(unix)]
pub fn set_exec(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

pub fn frf(work: &Workdir, args: &[&str]) -> Output {
    frf_env(work, args, &[])
}

pub fn frf_env(work: &Workdir, args: &[&str], envs: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.args(args).current_dir(&work.dir);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output().unwrap()
}

pub fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

pub fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).to_string()
}

pub fn assert_success(out: &Output, what: &str) {
    assert!(
        out.status.success(),
        "{what} failed:\nstatus: {}\nstdout: {}\nstderr: {}",
        out.status,
        stdout(out),
        stderr(out)
    );
}

/// The compiled claim document path for a receipt: a claim is content-
/// addressed (`claims/<id>.json`) with a by-receipt index, and a test
/// workdir compiles each receipt exactly once — resolve the single claim
/// through the index. Panics when the index is empty or ambiguous.
pub fn claim_path(work: &Workdir, receipt_id: &str) -> PathBuf {
    let index = work.path(&format!("{ROOT}/claims/by-receipt/{receipt_id}"));
    let mut names: Vec<String> = fs::read_dir(&index)
        .unwrap_or_else(|e| panic!("no claim index for {receipt_id}: {e}"))
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.len() == 64)
        .collect();
    names.sort();
    assert_eq!(
        names.len(),
        1,
        "expected exactly one compiled claim for {receipt_id}, found: {names:?}"
    );
    work.path(&format!("{ROOT}/claims/{}.json", names[0]))
}

/// The compiled claim document CONTENT for a receipt (see [`claim_path`]).
pub fn claim_json(work: &Workdir, receipt_id: &str) -> serde_json::Value {
    serde_json::from_str(&fs::read_to_string(claim_path(work, receipt_id)).unwrap()).unwrap()
}

/// EVERY compiled claim bound to a receipt, in index order (a receipt
/// compiled under different universes or policies is several claims that
/// coexist forever).
pub fn claim_json_all(work: &Workdir, receipt_id: &str) -> Vec<serde_json::Value> {
    let index = work.path(&format!("{ROOT}/claims/by-receipt/{receipt_id}"));
    let mut names: Vec<String> = fs::read_dir(&index)
        .unwrap_or_else(|e| panic!("no claim index for {receipt_id}: {e}"))
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.len() == 64)
        .collect();
    names.sort();
    names
        .iter()
        .map(|id| {
            serde_json::from_str(
                &fs::read_to_string(work.path(&format!("{ROOT}/claims/{id}.json"))).unwrap(),
            )
            .unwrap()
        })
        .collect()
}

/// The canonical golden-path setup: fresh workdir, admitted authority.
pub fn admit_reference(work: &Workdir) {
    let out = frf(
        work,
        &[
            "--root",
            ROOT,
            "authority",
            "admit",
            "golden/reference.sh",
            "--name",
            "ref-cli",
            "--version",
            "1.8.2",
        ],
    );
    assert_success(&out, "authority admit");
}

/// Run the canonical court and return the run id.
pub fn run_court(work: &Workdir) -> String {
    run_court_manifest(work, MANIFEST)
}

/// Run the resolution court (patched candidate) and return the run id.
pub fn run_resolution_court(work: &Workdir) -> String {
    run_court_manifest(work, RESOLUTION_MANIFEST)
}

fn run_court_manifest(work: &Workdir, manifest: &str) -> String {
    let out = frf(work, &["--root", ROOT, "court", "run", manifest]);
    assert_success(&out, "court run");
    let run = stdout(&out);
    assert!(run.starts_with("run-cli-malformed-input-"), "run id: {run}");
    run
}
