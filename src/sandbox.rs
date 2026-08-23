//! The I/O-CLOSED execution sandbox (`frf-exec-linux-v3`): the side may
//! touch ONLY its declared world.
//!
//! Two kernel mechanisms, both installed in the child before exec:
//!
//! - **Landlock** (Linux ≥ 5.13, unprivileged with `no_new_privs`): the
//!   filesystem closure. The side may read/execute only the content-
//!   addressed objects directory, the execution machinery (interpreter,
//!   native runtime closure, declared execution-context artifacts), and the
//!   declared randomness channel; the ONLY writable surface is the produced-
//!   output staging directory. Everything else on the host — `/etc/passwd`,
//!   `/proc`, the court manifests, other users' files — is EACCES.
//!
//! - **seccomp** (BPF): the ambient channel closure. `socket`, `connect`,
//!   `bind`, `listen`, `accept`, `accept4` (all address families, including
//!   AF_UNIX), SysV shared memory (`shmget`/`shmctl`/`shmat`/`shmdt`),
//!   `ptrace`, and `process_vm_readv`/`process_vm_writev` return EPERM —
//!   no network, no Unix sockets, no shared memory, no cross-process
//!   inspection.
//!
//! A side that violates a closure does not crash the harness: its access is
//! denied (EACCES/EPERM) and the observation captures the failure — the
//! court OBSERVES the denied access like any other output divergence.
//!
//! ## The execution-mechanism tradeoff (empirically established)
//!
//! The reference profile executes the side from a SEALED MEMFD
//! (`/proc/self/fd/<n>`) to close the same-UID verify→execute race. Under a
//! Landlock filesystem closure that is impossible: the kernel refuses to
//! bind an access rule to an anonymous-inode memfd
//! (`landlock_add_rule` → EBADF/EBADFD — the dentry is negative), and both
//! path-based exec (`/proc/self/fd/<n>`) and `execveat(AT_EMPTY_PATH)` of
//! the inherited memfd are denied with EACCES even when the memfd predates
//! the restriction. So `frf-exec-linux-v3` executes the VERIFIED SNAPSHOT
//! PATH (content-addressed under `objects/sha256/`, sealed read-only, and
//! itself inside the Landlock closure) and documents the residual same-UID
//! window exactly as the normal operating model does ("permissions plus
//! rehashing"); the OCI profile remains the mechanism that closes both the
//! path race and the ambient-environment race. This is a protocol fact, not
//! an implementation detail: any implementation of an I/O-closed profile on
//! Linux must make the same choice unless the kernel grows anon-inode
//! Landlock rules.
//!
//! ## Refusal semantics
//!
//! A profile is ENFORCED, never approximated: if Landlock is unavailable
//! (kernel < 5.13, disabled at boot, or the syscall is absent) or the
//! ruleset cannot be installed, the run REFUSES with a clear message —
//! never a silent fallback to an unclosed profile.

use crate::error::FrfError;
use std::path::{Path, PathBuf};

/// The Landlock filesystem access rights (uapi/linux/landlock.h — the exact
/// ABI values; the access is checked per-bit at path resolution).
pub const FS_EXECUTE: u64 = 1 << 0;
pub const FS_WRITE_FILE: u64 = 1 << 1;
pub const FS_READ_FILE: u64 = 1 << 2;
pub const FS_READ_DIR: u64 = 1 << 3;
pub const FS_REMOVE_DIR: u64 = 1 << 4;
pub const FS_REMOVE_FILE: u64 = 1 << 5;
pub const FS_MAKE_CHAR: u64 = 1 << 6;
pub const FS_MAKE_DIR: u64 = 1 << 7;
pub const FS_MAKE_REG: u64 = 1 << 8;
pub const FS_MAKE_SOCK: u64 = 1 << 9;
pub const FS_MAKE_FIFO: u64 = 1 << 10;
pub const FS_MAKE_BLOCK: u64 = 1 << 11;
pub const FS_MAKE_SYM: u64 = 1 << 12;
pub const FS_REFER: u64 = 1 << 13;
pub const FS_TRUNCATE: u64 = 1 << 14;
pub const FS_IOCTL_DEV: u64 = 1 << 15;
/// Every filesystem access right this profile handles: unhandled rights are
/// not restricted, so the ruleset handles the FULL mask and every rule
/// grants exactly what the side may do.
pub const FS_HANDLED: u64 = (1 << 16) - 1;

/// The complete writable-surface grant (the produced staging directory):
/// read + write + create + remove + refer within the side's own tree.
pub const FS_WRITE_GRANT: u64 = FS_READ_FILE
    | FS_WRITE_FILE
    | FS_READ_DIR
    | FS_MAKE_REG
    | FS_MAKE_DIR
    | FS_MAKE_SYM
    | FS_MAKE_FIFO
    | FS_MAKE_SOCK
    | FS_REMOVE_FILE
    | FS_REMOVE_DIR
    | FS_TRUNCATE;

/// The read grant (fixture objects, randomness): read-only.
pub const FS_READ_GRANT: u64 = FS_READ_FILE | FS_READ_DIR;
/// The read+execute grant (execution machinery): read + exec + traverse.
pub const FS_EXEC_GRANT: u64 = FS_READ_FILE | FS_READ_DIR | FS_EXECUTE;

/// The declared I/O closure for one observed side. The sandbox is installed
/// in the child before exec; the paths must exist (Landlock rules bind
/// real paths — the produced directory is created by the caller first).
#[derive(Debug, Clone)]
pub struct IoClosedSandbox {
    /// Directories/files the side may READ (the content-addressed objects
    /// directory, context data artifacts).
    pub read: Vec<PathBuf>,
    /// Files/directories the side may READ + EXECUTE (the interpreter, the
    /// native runtime closure, child executables).
    pub read_exec: Vec<PathBuf>,
    /// The side's ONLY writable surface (the produced-output staging dir),
    /// when the court declares one. None = NO writable surface at all — a
    /// side that tries to write anywhere is EACCES (the strictest closure).
    pub write_dir: Option<PathBuf>,
}

impl IoClosedSandbox {
    /// The standard runtime channels every side needs: the randomness
    /// channel (declared) and the null device.
    fn runtime_channels(&self) -> Vec<(PathBuf, u64)> {
        vec![
            (PathBuf::from("/dev/urandom"), FS_READ_GRANT),
            (PathBuf::from("/dev/null"), FS_READ_FILE | FS_WRITE_FILE),
        ]
    }

    /// Every rule this sandbox installs: the read paths, the exec paths, the
    /// writable surface, and the runtime channels. Each path is canonicalized
    /// (the kernel rejects symlink fds — a rule must name the RESOLVED
    /// path), de-duplicated, and its ancestors are granted traversal.
    fn rules(&self) -> Vec<(PathBuf, u64)> {
        let mut out: Vec<(PathBuf, u64)> = Vec::new();
        for p in &self.read {
            out.push((p.clone(), FS_READ_GRANT));
        }
        for p in &self.read_exec {
            out.push((p.clone(), FS_EXEC_GRANT));
        }
        if let Some(w) = &self.write_dir {
            out.push((w.clone(), FS_WRITE_GRANT));
        }
        out.extend(self.runtime_channels());
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out.dedup_by(|a, b| a.0 == b.0);
        out
    }
}

/// Whether the I/O-closed profile can be enforced on this host: Landlock
/// present and enabled (ABI ≥ 1). Returns the ABI version or None.
pub fn landlock_abi() -> Option<i64> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: syscall with a NULL attr and the VERSION flag; the kernel
        // ignores attr/size for the version probe.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<u8>(),
                0usize,
                1, // LANDLOCK_CREATE_RULESET_VERSION
            )
        };
        if rc > 0 {
            Some(rc)
        } else {
            None
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// The full check performed by the caller before a v3 side spawns: Landlock
/// must be present AND no_new_privs must be settable. A profile is enforced,
/// never approximated — a missing mechanism refuses the run.
pub fn enforceability_error() -> Option<FrfError> {
    match landlock_abi() {
        Some(abi) if abi >= 1 => None,
        _ => Some(FrfError::new(format!(
            "{} was requested but the Landlock filesystem closure is not available on this host (kernel >= 5.13 with CONFIG_SECURITY_LANDLOCK and landlock in the boot-time LSM list are required): the side's filesystem world cannot be closed; use the reference profile {} or the OCI profile",
            crate::model::EXECUTION_PROFILE_LINUX_V3,
            crate::model::EXECUTION_PROFILE_LINUX
        ))),
    }
}

/// The execution-machinery paths of one side: the interpreter chain (with
/// the interpreter's own native closure — a script's machinery is its
/// interpreter PLUS bash->libc...), and the artifact's native runtime
/// closure (the dynamic loader + resolved DT_NEEDED closure). Every path
/// here is granted READ+EXECUTE by the closure. Shared by the court (from
/// observation-time identities) and replay (from the capture's recorded
/// identities) so the I/O-closed contract reproduces exactly.
pub fn machinery_paths(
    interpreter: Option<&crate::model::InterpreterIdentity>,
    native: Option<&crate::model::NativeRuntimeClosure>,
    profile: crate::host::ExecProfile,
) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    if let Some(i) = interpreter {
        for exe in [&i.kernel_interpreter, &i.downstream_interpreter] {
            out.push(PathBuf::from(&exe.path));
            if let Ok(bytes) = crate::host::read_file(Path::new(&exe.path)) {
                if let Ok(Some(closure)) =
                    crate::native::runtime_closure(Path::new(&exe.path), &bytes, profile)
                {
                    out.push(PathBuf::from(&closure.interp.path));
                    for c in &closure.components {
                        out.push(PathBuf::from(&c.path));
                    }
                }
            }
        }
    }
    if let Some(n) = native {
        out.push(PathBuf::from(&n.interp.path));
        for c in &n.components {
            out.push(PathBuf::from(&c.path));
        }
    }
    out
}

/// The declared execution-context artifact paths of one side, resolved
/// against the current working directory (relative declared paths), granted
/// READ+EXECUTE (the data artifacts' object copies live in the objects
/// directory the closure already allows).
pub fn context_artifact_paths(
    context: Option<&crate::model::ExecutionContextClosure>,
) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let Some(cx) = context else {
        return out;
    };
    for a in &cx.artifacts {
        let p = Path::new(&a.path);
        let resolved = if p.is_absolute() {
            p.to_path_buf()
        } else {
            std::env::current_dir()
                .map(|c| c.join(p))
                .unwrap_or_else(|_| p.to_path_buf())
        };
        match a.role.as_str() {
            "data" => {}
            _ => {
                // Only paths that still resolve enter the closure: a bundle
                // replay may not have the original tree, and the artifact's
                // OBJECT COPY (content-addressed, in the objects directory)
                // remains reachable either way.
                if resolved.exists() {
                    out.push(resolved);
                }
            }
        }
    }
    out
}

/// Install the I/O-closed sandbox in the CURRENT process (must run in the
/// forked child before exec; the process must be single-threaded — true in
/// `pre_exec`). On success the process is irreversibly closed.
///
/// Returns an `io::Error` so `pre_exec` can refuse the exec (fail-closed: a
/// side that could not be closed never runs).
pub fn install(sandbox: &IoClosedSandbox) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        install_linux(sandbox)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = sandbox;
        Err(std::io::Error::other(
            "the I/O-closed profile is Linux-only",
        ))
    }
}

/// The seccomp filter program: deny the ambient channel syscalls, allow
/// everything else. Classic BPF, built per-architecture (the syscall
/// numbers differ).
#[cfg(target_os = "linux")]
const DENIED_SYSCALLS: &[i64] = &[
    // Network + Unix sockets (all address families).
    arch::SYS_SOCKET,
    arch::SYS_CONNECT,
    arch::SYS_BIND,
    arch::SYS_LISTEN,
    arch::SYS_ACCEPT,
    arch::SYS_ACCEPT4,
    // SysV shared memory.
    arch::SYS_SHMGET,
    arch::SYS_SHMCTL,
    arch::SYS_SHMAT,
    arch::SYS_SHMDT,
    // Cross-process inspection.
    arch::SYS_PTRACE,
    arch::SYS_PROCESS_VM_READV,
    arch::SYS_PROCESS_VM_WRITEV,
];

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod arch {
    pub const AUDIT_ARCH: u32 = 0xC000_003E; // AUDIT_ARCH_X86_64
    pub const SYS_SOCKET: i64 = 41;
    pub const SYS_CONNECT: i64 = 42;
    pub const SYS_BIND: i64 = 49;
    pub const SYS_LISTEN: i64 = 50;
    pub const SYS_ACCEPT: i64 = 43;
    pub const SYS_ACCEPT4: i64 = 288;
    pub const SYS_SHMGET: i64 = 29;
    pub const SYS_SHMCTL: i64 = 30;
    pub const SYS_SHMAT: i64 = 31;
    pub const SYS_SHMDT: i64 = 67;
    pub const SYS_PTRACE: i64 = 101;
    pub const SYS_PROCESS_VM_READV: i64 = 310;
    pub const SYS_PROCESS_VM_WRITEV: i64 = 311;
}
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod arch {
    pub const AUDIT_ARCH: u32 = 0xC000_00B7; // AUDIT_ARCH_AARCH64
    pub const SYS_SOCKET: i64 = 198;
    pub const SYS_CONNECT: i64 = 203;
    pub const SYS_BIND: i64 = 200;
    pub const SYS_LISTEN: i64 = 201;
    pub const SYS_ACCEPT: i64 = 202;
    pub const SYS_ACCEPT4: i64 = 242;
    pub const SYS_SHMGET: i64 = 194;
    pub const SYS_SHMCTL: i64 = 195;
    pub const SYS_SHMAT: i64 = 196;
    pub const SYS_SHMDT: i64 = 197;
    pub const SYS_PTRACE: i64 = 117;
    pub const SYS_PROCESS_VM_READV: i64 = 270;
    pub const SYS_PROCESS_VM_WRITEV: i64 = 271;
}
#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
mod arch {
    pub const AUDIT_ARCH: u32 = 0;
    pub const SYS_SOCKET: i64 = -1;
    pub const SYS_CONNECT: i64 = -1;
    pub const SYS_BIND: i64 = -1;
    pub const SYS_LISTEN: i64 = -1;
    pub const SYS_ACCEPT: i64 = -1;
    pub const SYS_ACCEPT4: i64 = -1;
    pub const SYS_SHMGET: i64 = -1;
    pub const SYS_SHMCTL: i64 = -1;
    pub const SYS_SHMAT: i64 = -1;
    pub const SYS_SHMDT: i64 = -1;
    pub const SYS_PTRACE: i64 = -1;
    pub const SYS_PROCESS_VM_READV: i64 = -1;
    pub const SYS_PROCESS_VM_WRITEV: i64 = -1;
}

#[cfg(target_os = "linux")]
fn install_linux(sandbox: &IoClosedSandbox) -> std::io::Result<()> {
    use self::arch::*;
    use std::os::unix::ffi::OsStrExt;

    // 1. no_new_privs: required by both Landlock and seccomp for
    //    unprivileged enforcement.
    // SAFETY: prctl is async-signal-safe; the child is single-threaded.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }

    // 2. Landlock ruleset — the full FS mask is handled; every rule grants
    //    exactly what the side may do.
    // SAFETY: the attr is a valid pointer for the call; the syscall is
    //    async-signal-safe.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0usize,
            1, // LANDLOCK_CREATE_RULESET_VERSION
        )
    };
    if abi <= 0 {
        return Err(std::io::Error::last_os_error());
    }
    #[repr(C)]
    struct RulesetAttr {
        handled_access_fs: u64,
        handled_access_net: u64,
    }
    #[repr(C)]
    struct PathBeneathAttr {
        allowed_access: u64,
        parent_fd: i32,
    }
    let mut attr = RulesetAttr {
        handled_access_fs: FS_HANDLED,
        handled_access_net: 0,
    };
    // SAFETY: attr is valid; size 16 is accepted by every ABI >= 1 kernel.
    let ruleset_fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &mut attr as *mut RulesetAttr as *const _,
            16usize,
            0,
        )
    };
    if ruleset_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // 3. The rules — every path canonicalized (the kernel rejects symlink
    //    fds) and opened O_PATH; the ancestors are granted traversal so the
    //    resolved path is reachable from the root.
    // SAFETY: open/O_PATH + landlock_add_rule are async-signal-safe; each
    //    path buffer is valid for the duration of the call.
    let add_rule = |path: &Path, access: u64| -> std::io::Result<()> {
        let canon = std::fs::canonicalize(path).map_err(|e| {
            std::io::Error::other(format!(
                "cannot resolve {} for the I/O-closed sandbox: {e}",
                path.display()
            ))
        })?;
        // The kernel refuses directory-only rights (READ_DIR) on FILE rules:
        // a rule for a file may carry only the ACCESS_FILE subset. The
        // read/exec grants are masks; drop the dir-only bits for files.
        let is_dir = canon.is_dir();
        let access = if is_dir {
            access
        } else {
            access
                & !(FS_READ_DIR
                    | FS_MAKE_REG
                    | FS_MAKE_DIR
                    | FS_MAKE_SYM
                    | FS_MAKE_FIFO
                    | FS_MAKE_SOCK
                    | FS_MAKE_CHAR
                    | FS_MAKE_BLOCK
                    | FS_REMOVE_DIR
                    | FS_REMOVE_FILE
                    | FS_REFER)
        };
        // The rule needs the LEAF plus traversal of every ancestor.
        let mut components: Vec<&Path> = canon.ancestors().collect();
        components.reverse();
        for ancestor in components {
            let c = std::ffi::CString::new(ancestor.as_os_str().as_bytes())
                .map_err(|_| std::io::Error::other("path contains a NUL"))?;
            let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let ancestor_access = if ancestor == canon {
                access
            } else {
                // Traversal of the ancestors: read-dir + execute (the walk
                // must reach the leaf).
                FS_READ_DIR | FS_EXECUTE
            };
            let mut pba = PathBeneathAttr {
                allowed_access: ancestor_access,
                parent_fd: fd,
            };
            // SAFETY: ruleset_fd and pba are valid; the syscall copies the
            // struct immediately.
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_landlock_add_rule,
                    ruleset_fd,
                    1, // LANDLOCK_RULE_PATH_BENEATH
                    &mut pba as *mut PathBeneathAttr as *const _,
                    0,
                )
            };
            let errno = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            if rc != 0 {
                return Err(errno);
            }
        }
        Ok(())
    };
    for (path, access) in sandbox.rules() {
        add_rule(&path, access)?;
    }

    // 4. Restrict the current thread.
    // SAFETY: ruleset_fd is valid; the syscall is async-signal-safe.
    let rc = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset_fd, 0) };
    let errno = std::io::Error::last_os_error();
    unsafe { libc::close(ruleset_fd as i32) };
    if rc != 0 {
        return Err(errno);
    }

    // 5. seccomp: the ambient channel closure (BPF).
    // SAFETY: constructing the filter array and loading it via the seccomp
    //    syscall is async-signal-safe.
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SockFilter {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }
    #[repr(C)]
    struct SockFprog {
        len: u16,
        filter: *const SockFilter,
    }
    const BPF_LD: u16 = 0x00;
    const BPF_W: u16 = 0x00;
    const BPF_ABS: u16 = 0x20;
    const BPF_JMP: u16 = 0x05;
    const BPF_JEQ: u16 = 0x10;
    const BPF_K: u16 = 0x00;
    const BPF_RET: u16 = 0x06;
    const SECCOMP_RET_KILL: u32 = 0x8000_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7FFF_0000;
    // The program: load the architecture (kill on a foreign one), load the
    // syscall number, deny each ambient-channel syscall with EPERM (the side
    // fails visibly; the observation captures the denied access — match falls
    // through to the RET ERRNO, mismatch skips it: a filter that denied
    // everything would break the harness itself), and allow everything else.
    let mut prog: Vec<SockFilter> = vec![
        // Load the architecture.
        SockFilter {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: 4, // offsetof(seccomp_data, arch)
        },
        SockFilter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 1,
            jf: 0,
            k: AUDIT_ARCH,
        },
        // Wrong architecture: kill (never run under an unverified mapping).
        SockFilter {
            code: BPF_RET,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_KILL,
        },
        // Load the syscall number.
        SockFilter {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: 0, // offsetof(seccomp_data, nr)
        },
    ];
    for nr in DENIED_SYSCALLS {
        prog.push(SockFilter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 0,
            jf: 1,
            k: *nr as u32,
        });
        prog.push(SockFilter {
            code: BPF_RET,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ERRNO | 1, // EPERM
        });
    }
    prog.push(SockFilter {
        code: BPF_RET,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    });
    let fprog = SockFprog {
        len: prog.len() as u16,
        filter: prog.as_ptr(),
    };
    // SAFETY: fprog references the alive program array for the duration of
    // the syscall.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            1, // SECCOMP_SET_MODE_FILTER
            0, // no SECCOMP_FILTER_FLAG_*
            &fprog as *const SockFprog as *const _,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The full writable grant is a subset of the handled mask (a rule may
    /// never grant a right the ruleset does not handle — the kernel refuses
    /// that with EINVAL).
    #[test]
    fn grants_are_subsets_of_the_handled_mask() {
        for g in [FS_READ_GRANT, FS_EXEC_GRANT, FS_WRITE_GRANT] {
            assert_eq!(
                g | FS_HANDLED,
                FS_HANDLED,
                "grant {g:#x} must be handled by the ruleset"
            );
        }
        assert_eq!(
            FS_WRITE_GRANT & FS_EXECUTE,
            0,
            "write grant must not grant exec"
        );
    }

    /// The sandbox refuses cleanly when Landlock is unavailable (the profile
    /// is enforced, never approximated). On hosts WITH Landlock the probe
    /// returns an ABI; the enforceability gate must be silent.
    #[test]
    fn enforceability_matches_the_host() {
        if landlock_abi().is_some() {
            assert!(enforceability_error().is_none());
        } else {
            assert!(enforceability_error().is_some());
        }
    }
}
