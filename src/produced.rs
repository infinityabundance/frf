//! Produced-artifact observations — the filesystem-tree surface.
//!
//! A court that declares `produce` observes what its sides BUILD, not only
//! what they print: each side writes its output directory (the declared
//! produce path, transient — cleared between sides), and the harness walks
//! it after execution, staging the file bytes, and captures the tree
//! immutably: every produced file is copied under the run directory, hashed,
//! and recorded in the side capture as a canonical manifest (relative path →
//! content hash + executable flag).
//!
//! The manifest formula is THE protocol: the same canonical JSON document is
//! produced by the reference engine, the independent verifier, and any
//! conforming implementation, so the tree observation rederives
//! cross-language from the captured files alone.
//!
//! v0 safety: the walk refuses symlinks (a hostile or careless side cannot
//! smuggle a link outside its output), refuses anything that is not a
//! regular file or directory, and refuses paths that would escape the
//! produced root. Files are content-addressed; directories are not recorded
//! (an empty directory is an artifact of the side's creation order, not of
//! its content — a tree with the same files is the same tree).

use crate::error::{FrfError, Result};
use crate::host::{self, HarnessViolation, RunError};
use crate::model::{ProducedFile, ProducedSide};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

/// The produced-tree overflow bounds (v19): the filesystem-tree surface's
/// caps, enforced during the walk — a produced tree that exceeds a cap is
/// refused exactly like a stream overflow (never truncated, never partially
/// recorded), and the enforced caps are recorded in the capture bounds so
/// replay enforces the same contract.
#[derive(Debug, Clone, Copy)]
pub struct ProducedLimits {
    pub max_files: u64,
    pub max_bytes: u64,
    pub max_file_bytes: u64,
}

/// An RAII staging root for produced-file bytes: the walk copies each file's
/// bytes here, and the run-dir copies happen from the staging after the run
/// identity is known (the transient produce path is cleared between sides).
/// Removed on drop, panics included.
pub struct ProducedStaging {
    pub dir: PathBuf,
}

impl ProducedStaging {
    pub fn new(tag: &str) -> Result<ProducedStaging> {
        let dir = std::env::temp_dir().join(format!(
            "frf-produced-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::create_dir_all(&dir)
            .map_err(|e| FrfError::new(format!("cannot create {}: {e}", dir.display())))?;
        Ok(ProducedStaging { dir })
    }
}

impl Drop for ProducedStaging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Walk a produced tree, copying each file's bytes into `staging` (relative
/// paths preserved) and returning the files (sorted by path), content
/// hashed. Refuses symlinks, non-regular files, and escaped paths — and
/// ENFORCES the produced-tree caps (file count, total bytes, per-file
/// bytes): a cap exceeded is a harness violation (`produced-overflow`) the
/// caller records as a content-addressed harness event before refusing the
/// run.
pub fn capture_produced_tree(
    root: &Path,
    staging: &Path,
    limits: ProducedLimits,
) -> std::result::Result<Vec<ProducedFile>, RunError> {
    let mut files: Vec<ProducedFile> = Vec::new();
    if !root.exists() {
        // A side that produces nothing writes nothing: an absent output is
        // an empty observation, not an error.
        return Ok(files);
    }
    let mut total_bytes: u64 = 0;
    let mut pending: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let entries = fs::read_dir(&dir).map_err(|e| {
            RunError::new(format!(
                "cannot read the produced tree {}: {e}",
                dir.display()
            ))
        })?;
        for entry in entries {
            let entry = entry.map_err(|e| {
                RunError::new(format!(
                    "cannot read the produced tree {}: {e}",
                    dir.display()
                ))
            })?;
            let path = entry.path();
            // Containment is structural (the walk only descends from the
            // root via read_dir, and symlinks are refused below) and
            // re-checked when the relative path is built. The root itself
            // may be absolute.
            let file_type = entry.file_type().map_err(|e| {
                RunError::new(format!(
                    "cannot inspect produced artifact {}: {e}",
                    path.display()
                ))
            })?;
            if file_type.is_symlink() {
                return Err(RunError::new(format!(
                    "produced artifact {} is a symlink; this version refuses symlinks in produced trees",
                    path.display()
                )));
            }
            if file_type.is_dir() {
                pending.push(path);
                continue;
            }
            if !file_type.is_file() {
                return Err(RunError::new(format!(
                    "produced artifact {} is not a regular file; refusing to capture",
                    path.display()
                )));
            }
            // The produced-file cap: read only cap+1 bytes — an oversized
            // file is detected, never buffered (the observed size is the
            // file's actual size, from metadata).
            let meta = fs::metadata(&path).map_err(|e| {
                RunError::new(format!(
                    "cannot stat produced artifact {}: {e}",
                    path.display()
                ))
            })?;
            let observed = meta.len();
            if observed > limits.max_file_bytes {
                return Err(RunError {
                    message: format!(
                        "produced artifact {} is {} bytes, over the {} byte per-file cap; refusing to record a truncated tree",
                        path.display(),
                        observed,
                        limits.max_file_bytes
                    ),
                    violation: Some(Box::new(HarnessViolation {
                        event_kind: "produced-overflow",
                        target: "produced-file-bytes".to_string(),
                        cap: limits.max_file_bytes.to_string(),
                        observed: observed.to_string(),
                        detail: path.display().to_string(),
                    })),
                });
            }
            if files.len() as u64 >= limits.max_files {
                return Err(RunError {
                    message: format!(
                        "the produced tree exceeds the {} file cap; refusing to record a partial tree",
                        limits.max_files
                    ),
                    violation: Some(Box::new(HarnessViolation {
                        event_kind: "produced-overflow",
                        target: "produced-files".to_string(),
                        cap: limits.max_files.to_string(),
                        observed: (files.len() as u64 + 1).to_string(),
                        detail: path.display().to_string(),
                    })),
                });
            }
            if total_bytes + observed > limits.max_bytes {
                return Err(RunError {
                    message: format!(
                        "the produced tree exceeds the {} byte total cap; refusing to record a partial tree",
                        limits.max_bytes
                    ),
                    violation: Some(Box::new(HarnessViolation {
                        event_kind: "produced-overflow",
                        target: "produced-bytes".to_string(),
                        cap: limits.max_bytes.to_string(),
                        observed: (total_bytes + observed).to_string(),
                        detail: path.display().to_string(),
                    })),
                });
            }
            // Read the file bytes (bounded by the cap already checked).
            let mut f = fs::File::open(&path).map_err(|e| {
                RunError::new(format!(
                    "cannot read produced artifact {}: {e}",
                    path.display()
                ))
            })?;
            let mut bytes = Vec::with_capacity(observed as usize);
            f.read_to_end(&mut bytes).map_err(|e| {
                RunError::new(format!(
                    "cannot read produced artifact {}: {e}",
                    path.display()
                ))
            })?;
            let rel = path
                .strip_prefix(root)
                .map_err(|_| {
                    RunError::new(format!(
                        "produced artifact {} is outside the produced root",
                        path.display()
                    ))
                })?
                .to_string_lossy()
                .into_owned();
            #[cfg(unix)]
            let executable = {
                use std::os::unix::fs::PermissionsExt;
                fs::metadata(&path)
                    .map(|m| m.permissions().mode() & 0o111 != 0)
                    .unwrap_or(false)
            };
            #[cfg(not(unix))]
            let executable = false;
            // Stage the bytes: the transient produce path is cleared between
            // sides, so the run-dir copies come from the staging.
            let staged = staging.join(&rel);
            if let Some(parent) = staged.parent() {
                fs::create_dir_all(parent).map_err(|e| {
                    RunError::new(format!("cannot create {}: {e}", parent.display()))
                })?;
            }
            fs::write(&staged, &bytes).map_err(|e| {
                RunError::new(format!(
                    "cannot stage produced artifact {}: {e}",
                    staged.display()
                ))
            })?;
            total_bytes += observed;
            files.push(ProducedFile {
                path: rel,
                sha256: host::sha256_bytes(&bytes),
                executable,
            });
        }
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(files)
}

/// The canonical manifest document: `{schema_version, files: [...]}` sorted
/// by path, serialized as canonical JSON (RFC 8785). ONE formula, shared by
/// the reference engine and the independent verifier.
pub fn manifest_bytes(files: &[ProducedFile]) -> Result<Vec<u8>> {
    let doc = serde_json::json!({
        "schema_version": crate::model::SCHEMA_PRODUCED,
        "files": files.iter().map(|f| serde_json::json!({
            "path": f.path,
            "sha256": f.sha256,
            "executable": f.executable,
        })).collect::<Vec<_>>(),
    });
    let json = crate::canon::canonical(&doc)?;
    Ok(json.into_bytes())
}

/// Build the produced-side observation from walked files.
pub fn produced_side(files: Vec<ProducedFile>) -> Result<ProducedSide> {
    let manifest = manifest_bytes(&files)?;
    let manifest_sha256 = crate::host::sha256_bytes(&manifest);
    Ok(ProducedSide {
        schema_version: crate::model::SCHEMA_PRODUCED.to_string(),
        manifest_sha256,
        files,
    })
}

/// Copy a produced tree from the staging into `<run_dir>/produced/<side>/`,
/// preserving relative paths and the executable flag. The run-dir copies are
/// the immutable evidence: verification rehashes them and rebuilds the
/// manifest.
pub fn write_produced_dir(
    run_dir: &Path,
    side: &str,
    staging: &Path,
    files: &[ProducedFile],
) -> Result<()> {
    for f in files {
        let dst = run_dir.join("produced").join(side).join(&f.path);
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| FrfError::new(format!("cannot create {}: {e}", parent.display())))?;
        }
        let staged = staging.join(&f.path);
        fs::copy(&staged, &dst).map_err(|e| {
            FrfError::new(format!(
                "cannot copy produced artifact {}: {e}",
                staged.display()
            ))
        })?;
        if f.executable {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&dst, fs::Permissions::from_mode(0o755)).map_err(|e| {
                    FrfError::new(format!(
                        "cannot seal produced artifact {}: {e}",
                        dst.display()
                    ))
                })?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_tree(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "frf-produced-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Generous limits: the existing walk tests exercise the structural
    /// rules, not the caps.
    fn unlimited_limits() -> ProducedLimits {
        ProducedLimits {
            max_files: 1_000_000,
            max_bytes: 1 << 30,
            max_file_bytes: 1 << 30,
        }
    }

    #[test]
    fn walks_files_sorted_and_hashed() {
        let root = temp_tree("walk");
        fs::create_dir_all(root.join("a/b")).unwrap();
        fs::write(root.join("z.txt"), "zzz").unwrap();
        fs::write(root.join("a/b/x.txt"), "hello").unwrap();
        fs::write(root.join("a/top"), "top").unwrap();
        let staging = temp_tree("walk-staging");
        let files = capture_produced_tree(&root, &staging, unlimited_limits()).unwrap();
        let paths: Vec<&str> = files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, ["a/b/x.txt", "a/top", "z.txt"], "sorted by path");
        assert_eq!(files[0].sha256.len(), 64);
        assert!(!files[0].executable);
        // The bytes were staged for the run-dir copy.
        assert!(staging.join("a/b/x.txt").is_file());
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&staging);
    }

    #[test]
    fn absent_tree_is_an_empty_observation() {
        let root = temp_tree("absent");
        let staging = temp_tree("absent-staging");
        let files =
            capture_produced_tree(&root.join("nope"), &staging, unlimited_limits()).unwrap();
        assert!(files.is_empty());
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&staging);
    }

    #[test]
    fn executable_flag_is_recorded() {
        let root = temp_tree("exec");
        fs::write(root.join("tool.sh"), "#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.join("tool.sh"), fs::Permissions::from_mode(0o755)).unwrap();
        }
        let staging = temp_tree("exec-staging");
        let files = capture_produced_tree(&root, &staging, unlimited_limits()).unwrap();
        assert_eq!(files.len(), 1);
        #[cfg(unix)]
        assert!(files[0].executable);
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&staging);
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_refused() {
        let root = temp_tree("symlink");
        fs::write(root.join("real.txt"), "data").unwrap();
        std::os::unix::fs::symlink("real.txt", root.join("link.txt")).unwrap();
        let staging = temp_tree("symlink-staging");
        let err = capture_produced_tree(&root, &staging, unlimited_limits()).unwrap_err();
        assert!(err.message.contains("symlink"), "{}", err.message);
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&staging);
    }

    #[test]
    fn produced_file_count_cap_refuses_with_a_violation() {
        let root = temp_tree("cap-files");
        for i in 0..3 {
            fs::write(root.join(format!("f{i}")), "x").unwrap();
        }
        let staging = temp_tree("cap-files-staging");
        let err = capture_produced_tree(
            &root,
            &staging,
            ProducedLimits {
                max_files: 2,
                max_bytes: 1 << 30,
                max_file_bytes: 1 << 30,
            },
        )
        .unwrap_err();
        assert!(err.message.contains("file cap"), "{}", err.message);
        let v = err.violation.expect("a cap fire carries a violation");
        assert_eq!(v.event_kind, "produced-overflow");
        assert_eq!(v.target, "produced-files");
        assert_eq!(v.cap, "2");
        assert_eq!(v.observed, "3");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&staging);
    }

    #[test]
    fn produced_total_bytes_cap_refuses_with_a_violation() {
        let root = temp_tree("cap-bytes");
        fs::write(root.join("a"), "aaaa").unwrap();
        fs::write(root.join("b"), "bbbb").unwrap();
        let staging = temp_tree("cap-bytes-staging");
        let err = capture_produced_tree(
            &root,
            &staging,
            ProducedLimits {
                max_files: 100,
                max_bytes: 6,
                max_file_bytes: 1 << 30,
            },
        )
        .unwrap_err();
        assert!(err.message.contains("total cap"), "{}", err.message);
        let v = err.violation.expect("a cap fire carries a violation");
        assert_eq!(v.event_kind, "produced-overflow");
        assert_eq!(v.target, "produced-bytes");
        assert_eq!(v.cap, "6");
        assert_eq!(v.observed, "8");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&staging);
    }

    #[test]
    fn produced_file_bytes_cap_refuses_with_a_violation() {
        let root = temp_tree("cap-file-bytes");
        fs::write(root.join("big"), "0123456789").unwrap();
        let staging = temp_tree("cap-file-bytes-staging");
        let err = capture_produced_tree(
            &root,
            &staging,
            ProducedLimits {
                max_files: 100,
                max_bytes: 1 << 30,
                max_file_bytes: 5,
            },
        )
        .unwrap_err();
        assert!(err.message.contains("per-file cap"), "{}", err.message);
        let v = err.violation.expect("a cap fire carries a violation");
        assert_eq!(v.event_kind, "produced-overflow");
        assert_eq!(v.target, "produced-file-bytes");
        assert_eq!(v.cap, "5");
        assert_eq!(v.observed, "10");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&staging);
    }

    #[test]
    fn manifest_is_canonical_and_deterministic() {
        let files = vec![
            ProducedFile {
                path: "b.txt".into(),
                sha256: "b".repeat(64),
                executable: false,
            },
            ProducedFile {
                path: "a.txt".into(),
                sha256: "a".repeat(64),
                executable: true,
            },
        ];
        let m1 = manifest_bytes(&files).unwrap();
        let m2 = manifest_bytes(&files).unwrap();
        assert_eq!(m1, m2, "the manifest must be deterministic");
        let side = produced_side(files).unwrap();
        assert_eq!(side.manifest_sha256, crate::host::sha256_bytes(&m1));
        assert_eq!(side.schema_version, crate::model::SCHEMA_PRODUCED);
    }
}
