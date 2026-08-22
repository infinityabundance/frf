//! The native runtime closure of an ELF executable — `executable hash` is not
//! `executable semantics` (spec/execution-profile.md § native runtime
//! closure).
//!
//! For native software, the artifact's behavior depends on:
//!
//! - the dynamic loader the kernel invoked (`PT_INTERP`);
//! - the resolved dependency closure (`DT_NEEDED`, transitively), with the
//!   bytes of every loaded component;
//! - the loader search configuration that resolved them (the loader's cache,
//!   its default directories, and the effective `LD_LIBRARY_PATH` of the
//!   observation).
//!
//! This module binds that closure AT OBSERVATION TIME: the executable's ELF
//! program headers are parsed (self-contained, no external parser) to find
//! the loader, the SYSTEM loader is invoked read-only (`ld.so --list`) to
//! resolve the closure under the observation environment — the same
//! resolution the side's own exec would perform — and every resolved
//! component (loader + libraries) is hashed. The result is a
//! content-addressed [`NativeRuntimeClosure`] carried by the artifact's
//! identity; high-assurance admission requires it for every native premise
//! artifact.
//!
//! The resolved paths and hashes are evidence recorded at observation time
//! (like interpreter hashes, they are machine-specific and not re-derivable
//! cross-machine); the closure's CID rederives from its own fields in any
//! implementation.

use crate::error::{FrfError, Result};
use crate::host;
use crate::model::{NativeRuntimeClosure, NativeRuntimeComponent, SCHEMA_RUNTIME_CLOSURE};
use std::path::Path;

/// The ELF magic, checked before any parsing.
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// Does the artifact begin with the ELF magic (a native executable, not a
/// script)?
pub fn is_elf(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[..4] == ELF_MAGIC
}

/// Parse `PT_INTERP` from an ELF64 executable's program headers: the path of
/// the dynamic loader the kernel will invoke. Self-contained parsing (no
/// external parser); a malformed ELF is a refusal (an artifact that is not
/// what it claims is not evidence).
fn interp_path(bytes: &[u8]) -> Result<String> {
    if bytes.len() < 64 || bytes[..4] != ELF_MAGIC {
        return Err(FrfError::new("not an ELF executable"));
    }
    let class = bytes[4];
    if class != 2 {
        return Err(FrfError::new(format!(
            "unsupported ELF class {class}: only ELF64 is bound"
        )));
    }
    // ELF64 header fields (little-endian; the reference platform is
    // x86-64/aarch64, both LE).
    let e_phoff = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
    let e_phentsize = u16::from_le_bytes(bytes[54..56].try_into().unwrap());
    let e_phnum = u16::from_le_bytes(bytes[56..58].try_into().unwrap());
    if e_phentsize < 56 {
        return Err(FrfError::new(format!(
            "malformed ELF: program header size {e_phentsize} < 56"
        )));
    }
    for i in 0..e_phnum {
        let off = e_phoff as usize + i as usize * e_phentsize as usize;
        if off + 56 > bytes.len() {
            return Err(FrfError::new(
                "malformed ELF: program headers overrun the file",
            ));
        }
        let p_type = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        if p_type == 3 {
            // PT_INTERP: p_offset, p_filesz
            let p_offset = u64::from_le_bytes(bytes[off + 8..off + 16].try_into().unwrap());
            let p_filesz = u64::from_le_bytes(bytes[off + 32..off + 40].try_into().unwrap());
            let start = p_offset as usize;
            let end = start + p_filesz as usize;
            if end > bytes.len() {
                return Err(FrfError::new("malformed ELF: PT_INTERP overruns the file"));
            }
            let path = std::str::from_utf8(&bytes[start..end])
                .map_err(|_| FrfError::new("malformed ELF: PT_INTERP is not UTF-8"))?
                .trim_end_matches('\0');
            if path.is_empty() {
                return Err(FrfError::new("malformed ELF: empty PT_INTERP"));
            }
            return Ok(path.to_string());
        }
    }
    Err(FrfError::new(
        "the ELF executable declares no PT_INTERP (a statically linked binary has no dynamic loader to bind)",
    ))
}

/// Invoke the system loader read-only (`ld.so --list <executable>`) and parse
/// the resolved dependency closure. The loader performs the SAME resolution
/// the side's own exec would — its cache, default directories, and the
/// effective `LD_LIBRARY_PATH` of the observation all apply. This executes
/// only the loader (never the artifact's code): `--list` parses and resolves
/// without running the binary.
fn resolve_dependencies(loader: &str, executable: &Path) -> Result<Vec<String>> {
    let image = host::ExecImage::from_path(Path::new(loader));
    let args = vec![
        "--list".to_string(),
        executable.to_string_lossy().into_owned(),
    ];
    let out = host::run_process(
        &image,
        &args,
        host::ExecProfile::LinuxV1,
        &host::minimal_execution_environment(),
    )?;
    if out.exit != "0" {
        return Err(FrfError::new(format!(
            "the dynamic loader {loader} refused to resolve {} (exit {}): the native runtime closure cannot be bound",
            executable.display(),
            out.exit
        )));
    }
    let mut resolved: Vec<String> = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        // glibc's format: `libfoo.so.6 => /path/to/libfoo.so.6 (0x...)`
        // A line with no `=>` is the executable itself (or a not-found
        // report) — a `not found` line means the closure is UNRESOLVED.
        if line.contains("not found") {
            return Err(FrfError::new(format!(
                "the dynamic loader could not resolve a dependency of {}: {line} — the native runtime closure cannot be bound",
                executable.display()
            )));
        }
        if let Some((_, rest)) = line.split_once("=>") {
            let path = rest.split('(').next().unwrap_or("").trim();
            if !path.is_empty() {
                resolved.push(path.to_string());
            }
        }
    }
    resolved.sort();
    resolved.dedup();
    Ok(resolved)
}

/// Compute the native runtime closure of an ELF executable at
/// `<path>`, whose bytes are `bytes`: the loader (`PT_INTERP`), the resolved
/// dependency closure, and the hash of every loaded component. Returns
/// `Ok(None)` for a non-ELF artifact (a script — the caller binds the
/// interpreter chain instead). The closure is content-addressed:
/// `FRF/RUNTIME-CLOSURE/v1` over the canonical document minus the cid.
pub fn runtime_closure(path: &Path, bytes: &[u8]) -> Result<Option<NativeRuntimeClosure>> {
    if !is_elf(bytes) {
        return Ok(None);
    }
    let loader = interp_path(bytes)?;
    let mut components: Vec<NativeRuntimeComponent> = Vec::new();
    for dep in resolve_dependencies(&loader, path)? {
        let dep_bytes = std::fs::read(&dep).map_err(|e| {
            FrfError::new(format!(
                "cannot read the resolved dependency {dep}: {e} — the native runtime closure cannot be bound"
            ))
        })?;
        components.push(NativeRuntimeComponent {
            path: dep.clone(),
            sha256: host::sha256_bytes(&dep_bytes),
        });
    }
    // The loader itself is a component too (the kernel invoked it).
    let loader_bytes = std::fs::read(&loader).map_err(|e| {
        FrfError::new(format!(
            "cannot read the dynamic loader {loader}: {e} — the native runtime closure cannot be bound"
        ))
    })?;
    let interp = NativeRuntimeComponent {
        path: loader.clone(),
        sha256: host::sha256_bytes(&loader_bytes),
    };
    components.sort_by(|a, b| a.path.cmp(&b.path));
    let mut closure = NativeRuntimeClosure {
        schema_version: SCHEMA_RUNTIME_CLOSURE.to_string(),
        cid: String::new(),
        interp,
        components,
    };
    closure.cid = crate::semantics::runtime_closure_identity(&closure)?;
    Ok(Some(closure))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The closure identity rederives from the fields and is stable.
    #[test]
    fn closure_identity_rederives_and_is_deterministic() {
        let mk = || NativeRuntimeClosure {
            schema_version: SCHEMA_RUNTIME_CLOSURE.to_string(),
            cid: String::new(),
            interp: NativeRuntimeComponent {
                path: "/lib64/ld-linux-x86-64.so.2".into(),
                sha256: "a".repeat(64),
            },
            components: vec![
                NativeRuntimeComponent {
                    path: "/lib/x86_64-linux-gnu/libc.so.6".into(),
                    sha256: "b".repeat(64),
                },
                NativeRuntimeComponent {
                    path: "/lib/x86_64-linux-gnu/libm.so.6".into(),
                    sha256: "c".repeat(64),
                },
            ],
        };
        let a = crate::semantics::runtime_closure_identity(&mk()).unwrap();
        let b = crate::semantics::runtime_closure_identity(&mk()).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        let mut c = mk();
        c.components.swap(0, 1);
        // Sorted by the identity computation, so order does not matter.
        assert_eq!(crate::semantics::runtime_closure_identity(&c).unwrap(), a);
    }

    /// A script is not an ELF: no closure (the interpreter chain binds it).
    #[test]
    fn a_script_has_no_runtime_closure() {
        let bytes = b"#!/bin/sh\necho hi\n";
        assert!(!is_elf(bytes));
        assert!(runtime_closure(Path::new("/nonexistent"), bytes)
            .unwrap()
            .is_none());
    }
}
