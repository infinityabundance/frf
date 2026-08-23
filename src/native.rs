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
///
/// FAIL-CLOSED ARITHMETIC: every offset/range conversion is `usize::try_from`
/// + `checked_mul`/`checked_add`, because every numeric field here is read
/// from the artifact's own bytes. A wrapped header-table offset would read a
/// `p_type` from a different, attacker-chosen position and record a
/// wrong-but-plausible loader path as part of the runtime closure; a wrapped
/// `PT_INTERP` range would make `start > end` and panic at the slice. Neither
/// may happen: a malformed ELF is a refusal, never a misread and never a
/// panic.
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
    // EI_DATA: the declared byte order. Every field below is decoded
    // little-endian (the reference platform is x86-64/aarch64, both LE), so a
    // file that declares a different byte order is REFUSED here, never
    // misread — and ELFDATANONE (0) is refused too: an artifact that does not
    // declare its byte order is not what it claims.
    let ei_data = bytes[5];
    if ei_data != 1 {
        return Err(FrfError::new(format!(
            "malformed ELF: unsupported EI_DATA {ei_data} — only ELFDATA2LSB (1) is bound (the reference platform is little-endian)"
        )));
    }
    let e_phoff = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
    let e_phentsize = u16::from_le_bytes(bytes[54..56].try_into().unwrap());
    let e_phnum = u16::from_le_bytes(bytes[56..58].try_into().unwrap());
    if e_phentsize < 56 {
        return Err(FrfError::new(format!(
            "malformed ELF: program header size {e_phentsize} < 56"
        )));
    }
    let e_phoff_usize = usize::try_from(e_phoff)
        .map_err(|_| FrfError::new("malformed ELF: e_phoff does not fit this platform"))?;
    let e_phentsize_usize = usize::from(e_phentsize);
    for i in 0..e_phnum {
        let off = (i as usize)
            .checked_mul(e_phentsize_usize)
            .and_then(|p| e_phoff_usize.checked_add(p))
            .ok_or_else(|| FrfError::new("malformed ELF: program header offset overflows"))?;
        if off.checked_add(56).is_none_or(|end| end > bytes.len()) {
            return Err(FrfError::new(
                "malformed ELF: program headers overrun the file",
            ));
        }
        let p_type = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        if p_type == 3 {
            // PT_INTERP: p_offset, p_filesz
            let p_offset = u64::from_le_bytes(bytes[off + 8..off + 16].try_into().unwrap());
            let p_filesz = u64::from_le_bytes(bytes[off + 32..off + 40].try_into().unwrap());
            let start = usize::try_from(p_offset).map_err(|_| {
                FrfError::new("malformed ELF: PT_INTERP p_offset does not fit this platform")
            })?;
            let end = start
                .checked_add(usize::try_from(p_filesz).map_err(|_| {
                    FrfError::new("malformed ELF: PT_INTERP p_filesz does not fit this platform")
                })?)
                .ok_or_else(|| FrfError::new("malformed ELF: PT_INTERP range overflows"))?;
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
        None,
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

/// Compute the native runtime closure of an ELF executable whose bytes are
/// `bytes`, resolved exactly as the side's own exec resolves it: the
/// `exec_path` is the path the loader sees as the executable (for a sealed
/// image that is `/proc/self/fd/<n>` — the memfd fd the loader child
/// inherits — so `$ORIGIN`-relative resolution sees the SAME origin the real
/// execution sees, never the materialized snapshot path). Returns `Ok(None)`
/// for a non-ELF artifact (a script — the caller binds the interpreter chain
/// instead). The closure is content-addressed: `FRF/RUNTIME-CLOSURE/v1` over
/// the canonical document minus the cid.
pub fn runtime_closure(exec_path: &Path, bytes: &[u8]) -> Result<Option<NativeRuntimeClosure>> {
    if !is_elf(bytes) {
        return Ok(None);
    }
    let loader = interp_path(bytes)?;
    let mut components: Vec<NativeRuntimeComponent> = Vec::new();
    for dep in resolve_dependencies(&loader, exec_path)? {
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

    // -- the PT_INTERP parser: fail-closed on adversarial bytes ---------------
    //
    // Every malformation below must be a REFUSAL — never a panic and never a
    // read from a wrapped offset. The header/range arithmetic is checked
    // (`usize::try_from` + `checked_mul`/`checked_add`), so an
    // attacker-chosen `e_phoff`, `p_offset`, or `p_filesz` cannot wrap into a
    // different, plausible-looking loader path.

    /// A minimal ELF64 with one program-header slot, for the control and the
    /// adversarial cases. `ph` places one 56-byte program header at offset 64
    /// (a PT_INTERP entry also gets its interp bytes appended after the
    /// table, at offset 120).
    fn elf64(
        ei_data: u8,
        e_phoff: u64,
        e_phentsize: u16,
        e_phnum: u16,
        ph: Option<(u32, u64, u64, &[u8])>,
    ) -> Vec<u8> {
        let mut bytes = vec![0u8; 64];
        bytes[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        bytes[4] = 2; // ELFCLASS64
        bytes[5] = ei_data;
        bytes[6] = 1; // EV_CURRENT
        bytes[32..40].copy_from_slice(&e_phoff.to_le_bytes());
        bytes[54..56].copy_from_slice(&e_phentsize.to_le_bytes());
        bytes[56..58].copy_from_slice(&e_phnum.to_le_bytes());
        if let Some((p_type, p_offset, p_filesz, interp)) = ph {
            let table = 64usize;
            bytes.resize(table + 56, 0);
            let mut ph = [0u8; 56];
            ph[0..4].copy_from_slice(&p_type.to_le_bytes());
            ph[8..16].copy_from_slice(&p_offset.to_le_bytes());
            ph[32..40].copy_from_slice(&p_filesz.to_le_bytes());
            bytes[table..table + 56].copy_from_slice(&ph);
            if p_type == 3 {
                let data = table + 56;
                bytes.resize(data + interp.len() + 1, 0);
                bytes[data..data + interp.len()].copy_from_slice(interp);
                bytes[data + interp.len()] = 0;
            }
        }
        bytes
    }

    #[test]
    fn a_well_formed_elf64_yields_the_interp_path() {
        let interp = b"/lib64/ld-linux-x86-64.so.2";
        let bytes = elf64(1, 64, 56, 1, Some((3, 120, interp.len() as u64, interp)));
        assert_eq!(interp_path(&bytes).unwrap(), "/lib64/ld-linux-x86-64.so.2");
    }

    #[test]
    fn e_phoff_at_u64_max_is_refused_not_wrapped() {
        // A PT_INTERP entry at e_phoff=u64::MAX: the table offset must refuse
        // (on 64-bit the `off + 56` bound check overflows and refuses; on
        // 32-bit the u64->usize conversion refuses). The old code wrapped and
        // could slice with start > end — a panic — or, after the wrap landed
        // back in bounds, read a p_type from the wrong place.
        let bytes = elf64(1, u64::MAX, 56, 1, Some((3, 0, 1, b"/lib/ld.so")));
        let err = interp_path(&bytes).unwrap_err();
        assert!(err.0.contains("malformed ELF"), "{err}");
    }

    #[test]
    fn header_table_offset_overflow_is_refused() {
        // e_phoff just below usize::MAX with a MULTI-entry table: the
        // `i * e_phentsize + e_phoff` chain must refuse on overflow instead of
        // wrapping to an in-bounds but wrong offset (the silent-misread
        // failure mode).
        let bytes = elf64(1, u64::MAX - 100, 56, 2, Some((3, 0, 1, b"/lib/ld.so")));
        let err = interp_path(&bytes).unwrap_err();
        assert!(err.0.contains("malformed ELF"), "{err}");
    }

    #[test]
    fn p_offset_plus_p_filesz_overflow_is_refused() {
        // p_offset near u64::MAX with a nonzero p_filesz: the PT_INTERP range
        // must refuse on overflow (the old `start + p_filesz` wrapped end
        // below start and panicked at the slice).
        let bytes = elf64(1, 64, 56, 1, Some((3, u64::MAX, 1, b"/lib/ld.so")));
        let err = interp_path(&bytes).unwrap_err();
        assert!(err.0.contains("malformed ELF"), "{err}");
    }

    #[test]
    fn truncated_program_header_table_is_refused() {
        // e_phnum=2 but the file holds only one header slot: the second
        // entry overruns the file and must be refused, never read past EOF.
        let bytes = elf64(1, 64, 56, 2, Some((1, 0, 0, b""))); // PT_LOAD, not interp
        let err = interp_path(&bytes).unwrap_err();
        assert!(err.0.contains("malformed ELF"), "{err}");
    }

    #[test]
    fn big_endian_elf64_is_refused_not_misread() {
        // EI_DATA=2 (ELFDATA2MSB): the fields are decoded little-endian, so a
        // big-endian file must be REFUSED — the old parser silently misread
        // every field of it (a wrong-but-plausible loader path).
        let interp = b"/lib64/ld-linux-x86-64.so.2";
        let bytes = elf64(2, 64, 56, 1, Some((3, 120, interp.len() as u64, interp)));
        let err = interp_path(&bytes).unwrap_err();
        assert!(
            err.0.contains("EI_DATA") && err.0.contains("ELFDATA2LSB"),
            "the refusal must name the byte-order contract: {err}"
        );
    }

    #[test]
    fn undeclared_byte_order_is_refused() {
        // EI_DATA=0 (ELFDATANONE): an artifact that does not declare its byte
        // order is not what it claims.
        let bytes = elf64(0, 64, 56, 1, Some((3, 120, 3, b"/lib/ld.so")));
        let err = interp_path(&bytes).unwrap_err();
        assert!(
            err.0.contains("EI_DATA"),
            "the refusal must name EI_DATA: {err}"
        );
    }

    #[test]
    fn interp_range_beyond_the_file_is_refused() {
        // p_offset/p_filesz name a range past EOF: refused, never sliced.
        let bytes = elf64(1, 64, 56, 1, Some((3, 120, 1_000_000, b"/lib/ld.so")));
        let err = interp_path(&bytes).unwrap_err();
        assert!(
            err.0.contains("PT_INTERP overruns"),
            "the refusal must name the overrun: {err}"
        );
    }

    #[test]
    fn a_bare_elf64_header_without_phdrs_is_refused() {
        // No program-header table at all (e_phnum=1 but e_phoff past EOF):
        // the table overruns and must be refused.
        let bytes = elf64(1, 1_000_000, 56, 1, None);
        let err = interp_path(&bytes).unwrap_err();
        assert!(err.0.contains("malformed ELF"), "{err}");
    }
}
