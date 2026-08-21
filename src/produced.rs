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
use crate::model::{ProducedFile, ProducedSide};
use std::fs;
use std::path::{Path, PathBuf};

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
/// hashed. Refuses symlinks, non-regular files, and escaped paths.
pub fn capture_produced_tree(root: &Path, staging: &Path) -> Result<Vec<ProducedFile>> {
    let mut files: Vec<ProducedFile> = Vec::new();
    if !root.exists() {
        // A side that produces nothing writes nothing: an absent output is
        // an empty observation, not an error.
        return Ok(files);
    }
    let mut pending: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let entries = fs::read_dir(&dir).map_err(|e| {
            FrfError::new(format!(
                "cannot read the produced tree {}: {e}",
                dir.display()
            ))
        })?;
        for entry in entries {
            let entry = entry.map_err(|e| {
                FrfError::new(format!(
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
                FrfError::new(format!(
                    "cannot inspect produced artifact {}: {e}",
                    path.display()
                ))
            })?;
            if file_type.is_symlink() {
                return Err(FrfError::new(format!(
                    "produced artifact {} is a symlink; this version refuses symlinks in produced trees",
                    path.display()
                )));
            }
            if file_type.is_dir() {
                pending.push(path);
                continue;
            }
            if !file_type.is_file() {
                return Err(FrfError::new(format!(
                    "produced artifact {} is not a regular file; refusing to capture",
                    path.display()
                )));
            }
            let bytes = fs::read(&path).map_err(|e| {
                FrfError::new(format!(
                    "cannot read produced artifact {}: {e}",
                    path.display()
                ))
            })?;
            let rel = path
                .strip_prefix(root)
                .map_err(|_| {
                    FrfError::new(format!(
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
                    FrfError::new(format!("cannot create {}: {e}", parent.display()))
                })?;
            }
            fs::write(&staged, &bytes).map_err(|e| {
                FrfError::new(format!(
                    "cannot stage produced artifact {}: {e}",
                    staged.display()
                ))
            })?;
            files.push(ProducedFile {
                path: rel,
                sha256: crate::host::sha256_bytes(&bytes),
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

    #[test]
    fn walks_files_sorted_and_hashed() {
        let root = temp_tree("walk");
        fs::create_dir_all(root.join("a/b")).unwrap();
        fs::write(root.join("z.txt"), "zzz").unwrap();
        fs::write(root.join("a/b/x.txt"), "hello").unwrap();
        fs::write(root.join("a/top"), "top").unwrap();
        let staging = temp_tree("walk-staging");
        let files = capture_produced_tree(&root, &staging).unwrap();
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
        let files = capture_produced_tree(&root.join("nope"), &staging).unwrap();
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
        let files = capture_produced_tree(&root, &staging).unwrap();
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
        let err = capture_produced_tree(&root, &staging).unwrap_err();
        assert!(err.0.contains("symlink"), "{}", err.0);
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
