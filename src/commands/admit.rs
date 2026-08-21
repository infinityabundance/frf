//! `frf authority admit`: admit an executable reference as an authority.
//!
//! Admission is once: an existing authority id is never overwritten, so a
//! drifted oracle cannot silently replace the admitted one. The recorded
//! SHA-256 is the drift check every later court run performs.

use crate::error::{FrfError, Result};
use crate::host;
use crate::model::*;
use crate::store::Store;
use std::path::Path;

/// `[A-Za-z0-9._-]` — safe as a filename component and as part of a claim
/// sentence. Everything else is rejected at admission.
fn valid_component(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

pub fn run(store: &Store, path: &Path, name: &str, version: &str, kind: &str) -> Result<String> {
    if kind != "executable_reference" {
        return Err(FrfError::new(format!(
            "kind '{kind}' is not admitted in v0; only 'executable_reference' is supported"
        )));
    }
    if !valid_component(name) {
        return Err(FrfError::new(format!(
            "invalid authority name '{name}': use letters, digits, '.', '_', '-' only"
        )));
    }
    if !valid_component(version) {
        return Err(FrfError::new(format!(
            "invalid authority version '{version}': use letters, digits, '.', '_', '-' only"
        )));
    }
    if !path.is_file() {
        return Err(FrfError::new(format!(
            "cannot admit {}: not a file",
            path.display()
        )));
    }
    if !is_executable(path) {
        return Err(FrfError::new(format!(
            "cannot admit {}: not executable (set the executable bit)",
            path.display()
        )));
    }

    let sha256 = host::sha256_file(path)?;
    let id = format!("{name}-{version}");
    let target = store.authority_path(&id)?;
    if target.exists() {
        return Err(FrfError::new(format!(
            "authority '{id}' is already admitted at {}; refusing to overwrite (admission is once — admit a new version instead)",
            target.display()
        )));
    }

    let record = AuthorityRecord {
        schema_version: SCHEMA_AUTHORITY.to_string(),
        id: id.clone(),
        name: name.to_string(),
        kind: kind.to_string(),
        version: version.to_string(),
        executable_sha256: sha256,
        path: path.to_string_lossy().into_owned(),
        platform: format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS),
    };

    let json = store.to_evidence(&record)?;
    store.write_once(&target, &json)?;
    eprintln!(
        "admitted authority {id} (sha256 {} platform {})",
        &record.executable_sha256[..16],
        record.platform
    );
    Ok(id)
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(_path: &Path) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn component_validation() {
        assert!(valid_component("ref-cli"));
        assert!(valid_component("1.8.2"));
        assert!(valid_component("a_b.c-d"));
        assert!(!valid_component(""));
        assert!(!valid_component(".."));
        assert!(!valid_component("a/b"));
        assert!(!valid_component("a b"));
        assert!(!valid_component("ref@cli"));
    }
}
