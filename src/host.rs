//! Quarantined host-mutation surface.
//!
//! Everything that touches the outside world on behalf of a court lives here
//! and nowhere else in the crate: subprocess execution, file hashing, and the
//! environment digest. The rest of the codebase works on in-memory values and
//! YAML files, so a future review of "what can this tool actually run or
//! observe on my machine" is a review of this one file.
//!
//! Invariants:
//! - Executables are spawned directly (no shell), so manifest arguments cannot
//!   inject shell syntax.
//! - A court run is bounded by [`EXEC_TIMEOUT`]; a hung side is killed rather
//!   than allowed to stall the pipeline.
//! - Exit status is recorded as the raw code, or the literal `signal(<n>)`
//!   when the process was terminated by a signal (no fabricated code).
//! - Process topology (unix): each side runs in its own process group, and
//!   when the direct process exits or times out the whole group is
//!   terminated. A descendant that inherited the capture pipes can therefore
//!   never hold them open past the direct process's lifetime, and the pipe
//!   drains always reach EOF. The capture of a side is the complete output of
//!   its process group, collected before termination. Escaped descendants
//!   (a side that calls `setsid` into a new session) are outside this policy.
//! - Spawn retries are bounded: `ETXTBSY` (exec'ing a file another process is
//!   still writing) is retried within [`SPAWN_RETRY_BUDGET`], then fails — a
//!   persistently busy executable never hangs the court.

use crate::error::{FrfError, Result};
use crate::model::{
    CaptureBounds, EnvironmentIdentity, InterpreterExecutable, InterpreterIdentity,
    InterpreterResolver,
};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Upper bound for one side of a court execution (the execution profile's
/// timeout).
pub const EXEC_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum bytes retained per output stream (the execution profile's capture
/// cap). A side that exceeds it is killed and the run REFUSED — truncated
/// output is never evidence. The profile records the cap that applied.
pub const EXEC_MAX_STREAM_BYTES: usize = 16 * 1024 * 1024;

/// Maximum number of files a side's PRODUCED TREE may contain (the
/// filesystem-tree surface's overflow bound, v19). A side whose produced
/// tree exceeds a cap is refused exactly like a stream overflow — never
/// truncated, never partially recorded.
pub const EXEC_PRODUCED_MAX_FILES: u64 = 4096;
/// Maximum TOTAL bytes of a side's produced tree (v19).
pub const EXEC_PRODUCED_MAX_BYTES: u64 = 256 * 1024 * 1024;
/// Maximum bytes of any ONE produced file (v19); a file larger than this is
/// read only up to cap+1 bytes (the overflow is detected, never buffered).
pub const EXEC_PRODUCED_MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Child address-space limit in MiB (RLIMIT_AS).
pub const EXEC_RLIMIT_AS_MB: u64 = 2048;
/// Child CPU-time limit in seconds (RLIMIT_CPU) — a CPU-bound hostile side
/// hits this before the wall-clock timeout.
pub const EXEC_RLIMIT_CPU_S: u64 = 30;
/// Child open-file limit (RLIMIT_NOFILE).
pub const EXEC_RLIMIT_NOFILE: u64 = 1024;
/// Child process-count limit (RLIMIT_NPROC): a hostile side cannot fork a
/// process bomb that exhausts the user's process table while the harness
/// waits for its own timeout.
///
/// Linux semantics (the repository does not redefine them): RLIMIT_NPROC
/// bounds the number of processes/threads associated with the side's REAL
/// USER ID — not the descendants of this one side — and privileged/root
/// execution is exempt. It is therefore one LAYER against fork bombs, not a
/// per-side aggregate envelope; the per-side aggregate resource contract
/// (pids.max / memory.max / cpu.max over the whole descendant tree) is what
/// the cgroup v2 execution profile (`frf-exec-linux-v2`) is for.
pub const EXEC_RLIMIT_NPROC: u64 = 4096;

// ---------------------------------------------------------------------------
// Execution profiles
// ---------------------------------------------------------------------------

/// The declared harness contract an execution runs under (see
/// `spec/execution-profile.md`). The engine implements three Linux profiles:
/// the reference `frf-exec-linux-v1` (per-process setrlimit layer),
/// `frf-exec-linux-v2` (the cgroup v2 per-side AGGREGATE envelope on top of
/// the same setrlimit layer), and `frf-exec-linux-v3` (the I/O-CLOSED
/// profile: a Landlock filesystem closure + a seccomp ambient-channel
/// closure on top of the same setrlimit layer), plus the OCI container
/// profile. A profile is a protocol identifier; exact replay requires the
/// same profile, and a requested profile is ENFORCED, never approximated
/// (v2 without a writable cgroup v2 subtree refuses, v3 without Landlock
/// refuses).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecProfile {
    /// `frf-exec-linux-v1` — the reference profile.
    LinuxV1,
    /// `frf-exec-linux-v2` — cgroup v2 aggregate envelope + setrlimit.
    LinuxV2,
    /// `frf-exec-linux-v3` — I/O-closed: Landlock filesystem closure +
    /// seccomp ambient-channel closure + setrlimit.
    LinuxV3,
    /// `frf-exec-oci` — each side runs inside a container from a
    /// digest-pinned OCI image (the complete root filesystem is the
    /// execution machinery).
    Oci,
}

impl ExecProfile {
    /// Parse a protocol identifier. Unknown profiles are refused: a court
    /// declaring a profile this engine does not implement cannot be run
    /// (fail-closed, and the registry pins the namespace).
    pub fn parse(s: &str) -> crate::error::Result<Self> {
        match s {
            crate::model::EXECUTION_PROFILE_LINUX => Ok(ExecProfile::LinuxV1),
            crate::model::EXECUTION_PROFILE_LINUX_V2 => Ok(ExecProfile::LinuxV2),
            crate::model::EXECUTION_PROFILE_LINUX_V3 => Ok(ExecProfile::LinuxV3),
            crate::model::EXECUTION_PROFILE_OCI => Ok(ExecProfile::Oci),
            other => Err(crate::error::FrfError::new(format!(
                "unsupported execution profile {other:?}: this engine implements {} (the reference profile), {} (the cgroup v2 aggregate envelope), {} (the I/O-closed profile), and {} (the OCI container profile)",
                crate::model::EXECUTION_PROFILE_LINUX,
                crate::model::EXECUTION_PROFILE_LINUX_V2,
                crate::model::EXECUTION_PROFILE_LINUX_V3,
                crate::model::EXECUTION_PROFILE_OCI
            ))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ExecProfile::LinuxV1 => crate::model::EXECUTION_PROFILE_LINUX,
            ExecProfile::LinuxV2 => crate::model::EXECUTION_PROFILE_LINUX_V2,
            ExecProfile::LinuxV3 => crate::model::EXECUTION_PROFILE_LINUX_V3,
            ExecProfile::Oci => crate::model::EXECUTION_PROFILE_OCI,
        }
    }
}

/// `frf-exec-linux-v2` — the cgroup v2 per-side aggregate envelope
/// (pids.max / memory.max / cpu.max of the side's whole process tree).
pub const CGROUP2_PIDS_MAX: u64 = 1024;
/// 2 GiB — the per-side aggregate memory envelope (RLIMIT_AS is per
/// process; a hostile tree distributes over descendants).
pub const CGROUP2_MEMORY_MAX: u64 = 2 * 1024 * 1024 * 1024;
/// `quota period` in microseconds: one CPU core per side tree (a declared
/// contract; a court that needs more declares its own bounds).
pub const CGROUP2_CPU_MAX: &str = "100000 100000";

/// Unique per-side group-name suffix within this process.
static CGROUP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Total budget for `ETXTBSY` spawn retries. Exec'ing a file another process
/// just finished writing (or is still writing) transiently fails with
/// `ExecutableFileBusy` — parallel CI and generated-script workflows hit
/// this. The retry has a deadline of its own, so a persistently busy
/// executable fails instead of looping forever (the execution timeout only
/// starts after the spawn succeeds).
pub const SPAWN_RETRY_BUDGET: Duration = Duration::from_secs(1);

// ---------------------------------------------------------------------------
// Sealed executable images — closing the verify→execute race
// ---------------------------------------------------------------------------
//
// The reference engine executes ONLY images bound to verified bytes:
//
//   read artifact bytes → verify CID → memfd_create → copy → seal → exec
//
// never a pathname whose contents were verified earlier and then re-opened.
// On Linux (the reference profile) the bytes live in a memfd sealed with
// F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL and are executed via
// `/proc/self/fd/<n>`: after sealing, no process — not even the same OS
// user — can alter the image, and the kernel resolves the fd inside the
// child at exec time, so the executed bytes are exactly the sealed bytes.
// Script shebangs re-open `/proc/self/fd/<n>` in the same (post-exec)
// process, where the inherited fd still resolves to the sealed memfd.
//
// argv[0] is preserved as the materialized snapshot path, so a sealed
// execution observes the same argv[0] as the path-based execution it
// replaces (many programs inspect argv[0]). Data files (fixtures) stay
// path-based: the recorded argv is part of the run identity, and the
// content-addressed object CAS plus 0444/0555 permissions are the data
// discipline; sealing is for the executed IMAGE.

/// An executable image bound to the exact verified bytes.
///
/// - Linux: a sealed memfd (see the module docs).
/// - Other platforms: a private temp file with mode 0555 (best effort; the
///   reference profile is Linux).
///
/// The image is NOT `Clone` — the sealed fd / temp file is owned exactly
/// once, for the image's lifetime.
#[derive(Debug)]
pub struct ExecImage {
    /// The path passed to exec(2): `/proc/self/fd/<n>` when sealed, the
    /// temp file on fallback platforms.
    exec_path: PathBuf,
    /// argv[0]: the materialized snapshot path the execution observes.
    argv0: PathBuf,
    /// The sealed memfd (Linux), kept alive for the image's lifetime.
    #[cfg(target_os = "linux")]
    fd: Option<std::os::fd::OwnedFd>,
    /// The private temp file to remove on drop (fallback platforms).
    #[cfg(not(target_os = "linux"))]
    cleanup: Option<PathBuf>,
}

impl ExecImage {
    /// Seal `bytes` — which MUST already be verified by the caller
    /// (typically [`crate::store::Store::verified_object_bytes`]) — into an
    /// executable image. `expected_sha256` is re-checked against the bytes
    /// being sealed (defense in depth: the sealed bytes are the verified
    /// bytes, self-evidently). `argv0` is the materialized snapshot path the
    /// process will observe as its program name.
    pub fn seal(bytes: &[u8], expected_sha256: &str, argv0: &Path) -> Result<ExecImage> {
        let actual = sha256_bytes(bytes);
        if actual != expected_sha256 {
            return Err(FrfError::new(format!(
                "refusing to seal an executable image: the bytes hash to {} but the verified content address is {} — sealing unverified bytes would re-open the verify→execute race",
                &actual[..16],
                &expected_sha256[..16]
            )));
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            let fd = seal_memfd(bytes)?;
            let exec_path = PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()));
            Ok(ExecImage {
                exec_path,
                argv0: argv0.to_path_buf(),
                fd: Some(fd),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let cleanup = materialize_temp(bytes)?;
            Ok(ExecImage {
                exec_path: cleanup.clone(),
                argv0: argv0.to_path_buf(),
                cleanup: Some(cleanup),
            })
        }
    }

    /// A path-based image (argv[0] = the path): used by tests and any
    /// execution that is not a content-addressed object. The reference
    /// engine's evidence execution paths use [`ExecImage::seal`].
    pub fn from_path(path: &Path) -> ExecImage {
        #[cfg(target_os = "linux")]
        {
            ExecImage {
                exec_path: path.to_path_buf(),
                argv0: path.to_path_buf(),
                fd: None,
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            ExecImage {
                exec_path: path.to_path_buf(),
                argv0: path.to_path_buf(),
                cleanup: None,
            }
        }
    }

    /// The path passed to exec(2).
    pub fn path(&self) -> &Path {
        &self.exec_path
    }

    /// The program name the process observes (argv[0]).
    pub fn argv0(&self) -> &Path {
        &self.argv0
    }

    /// The seals currently in force on the image (Linux): the hostile
    /// regression test proves `F_SEAL_WRITE | F_SEAL_SEAL` are applied
    /// before the image may be executed. `None` on fallback platforms or
    /// path-based images.
    #[cfg(target_os = "linux")]
    pub fn seals(&self) -> Option<i32> {
        use std::os::fd::AsRawFd;
        let fd = self.fd.as_ref()?;
        // SAFETY: fcntl(2) F_GET_SEALS on a valid open memfd.
        let s = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) };
        (s >= 0).then_some(s)
    }
}

#[cfg(target_os = "linux")]
impl Drop for ExecImage {
    fn drop(&mut self) {
        // The OwnedFd closes the memfd when the image is dropped; nothing
        // else to clean up.
    }
}

#[cfg(not(target_os = "linux"))]
impl Drop for ExecImage {
    fn drop(&mut self) {
        if let Some(p) = &self.cleanup {
            let _ = std::fs::remove_file(p);
        }
    }
}

// ---------------------------------------------------------------------------
// cgroup v2 — the per-side AGGREGATE envelope (`frf-exec-linux-v2`)
// ---------------------------------------------------------------------------
//
// RLIMIT_NPROC bounds the processes of the side's real USER ID and
// RLIMIT_AS/RLIMIT_CPU bound ONE process each: a hostile tree distributes
// memory or CPU over descendants and the per-UID process cap is shared with
// every other process of the same user. The cgroup v2 profile bounds the
// side's WHOLE descendant tree — pids.max / memory.max / cpu.max are
// aggregate, per side, per tree.
//
// The side moves ITSELF into its group in pre_exec (before exec): the move
// is race-free (descendants inherit the cgroup at fork) and needs no
// post-fork parent-side pid manipulation. setrlimit remains a second layer.
//
// Delegation: cgroupfs is only writable where the manager (systemd user
// session with `Delegate=`, a container with a writable /sys/fs/cgroup, a
// delegated subtree) made it writable. The harness locates a writable
// cgroup v2 root and REFUSES the profile when none exists — a declared
// profile is enforced, never approximated. `FRF_CGROUP2_ROOT` is the test
// hook: it points the harness at a writable directory tree standing in for
// cgroupfs (delegation is a machine property, not a test one).

/// The `FRF_CGROUP2_ROOT` test hook: a writable directory tree standing in
/// for cgroupfs (the regression suite cannot rely on real delegation). The
/// literal value `none` forces the "no writable root" path deterministically
/// on ANY host (including one with real delegation), so the refusal path is
/// always testable.
fn cgroup2_hook() -> Option<Option<PathBuf>> {
    let v = std::env::var("FRF_CGROUP2_ROOT")
        .ok()
        .filter(|p| !p.is_empty())?;
    if v == "none" {
        return Some(None);
    }
    Some(Some(PathBuf::from(v)))
}

/// Is `dir` writable by this process (access(2) W_OK)?
fn dir_writable(dir: &Path) -> bool {
    // SAFETY: access(2) is async-signal-safe and takes a valid C string
    // (the path is converted lossily, matching the rest of the crate).
    let c = std::ffi::CString::new(dir.to_string_lossy().as_bytes()).unwrap_or_default();
    unsafe { libc::access(c.as_ptr(), libc::W_OK) == 0 }
}

/// Locate a writable cgroup v2 root: the `FRF_CGROUP2_ROOT` test hook
/// first, then `/sys/fs/cgroup` when it is v2 and writable, then the
/// deepest writable ancestor of the current process's own cgroup (a
/// delegated subtree). `Ok(None)` when no writable v2 root exists.
pub fn cgroup2_root() -> Result<Option<PathBuf>> {
    if let Some(hook) = cgroup2_hook() {
        if let Some(p) = &hook {
            if !p.join("cgroup.controllers").is_file() {
                return Err(FrfError::new(format!(
                    "FRF_CGROUP2_ROOT {} is not a cgroup v2 root (no cgroup.controllers)",
                    p.display()
                )));
            }
        }
        return Ok(hook);
    }
    #[cfg(target_os = "linux")]
    {
        let sys = PathBuf::from("/sys/fs/cgroup");
        if sys.join("cgroup.controllers").is_file() && dir_writable(&sys) {
            return Ok(Some(sys));
        }
        // A delegated subtree: walk the current process's own cgroup path
        // from the deepest ancestor upward and return the first writable
        // v2 directory (the delegation point).
        if let Ok(contents) = std::fs::read_to_string("/proc/self/cgroup") {
            for line in contents.lines() {
                // `0::/user.slice/user-1000.slice/...`
                let path = line.split_once("::").map(|(_, p)| p).unwrap_or("");
                let mut cur = sys.join(path.trim_start_matches('/'));
                loop {
                    if cur.join("cgroup.controllers").is_file() && dir_writable(&cur) {
                        return Ok(Some(cur));
                    }
                    if !cur.pop() {
                        break;
                    }
                }
            }
        }
    }
    Ok(None)
}

/// A per-side cgroup v2 group: the side's whole descendant tree runs in it,
/// bounded by the profile's aggregate envelope. When the side's direct
/// process is gone, the group is KILLED (not merely bounded) and emptied
/// before any evidence is emitted — a descendant that escaped the process
/// group via setsid() is still in the side's cgroup, and "no descendant of
/// the observed side remains alive after the observation is finalized" is
/// the v2 property. `cgroup.procs` is opened WITHOUT close-on-exec so the
/// child can move itself in during pre_exec.
pub struct CgroupV2 {
    dir: PathBuf,
    procs_fd: Option<std::os::fd::RawFd>,
    /// The side's DIRECT child pid, recorded once spawned. It is reaped by
    /// the harness before finalize, so the fallback empty-check must not
    /// count it (on a real kernel the pid leaves `cgroup.procs` at exit; on
    /// the regression suite's fake root it lingers, and a recycled pid at
    /// that number is NOT the side).
    direct_pid: Option<libc::pid_t>,
}

/// The bounded budget for draining a killed cgroup: after `cgroup.kill` (or
/// the enumerate-and-SIGKILL fallback), the group must report empty within
/// this window — a member in D state (uninterruptible I/O) can hold it
/// longer, and under v2 a group that cannot be emptied is a run REFUSAL,
/// never ignored cleanup.
const CGROUP_EMPTY_BUDGET: Duration = Duration::from_secs(2);

/// Poll interval for the cgroup-empty wait.
const CGROUP_EMPTY_POLL: Duration = Duration::from_millis(20);

impl CgroupV2 {
    /// Create `frf/<name>` under the writable root, apply the envelope, and
    /// open `cgroup.procs` for the side's pre_exec self-move. Fail-closed:
    /// any step (unwritable root, a controller not enabled, a limit file
    /// that refuses the write) aborts — a partial envelope is never used.
    pub fn create(root: &Path, name: &str) -> Result<CgroupV2> {
        let dir = root.join("frf").join(name);
        std::fs::create_dir_all(&dir).map_err(|e| {
            FrfError::new(format!(
                "cannot create the cgroup v2 group {}: {e} — the delegated root may be read-only or not delegated",
                dir.display()
            ))
        })?;
        for (what, value) in [
            ("pids.max", CGROUP2_PIDS_MAX.to_string()),
            ("memory.max", CGROUP2_MEMORY_MAX.to_string()),
            ("cpu.max", CGROUP2_CPU_MAX.to_string()),
        ] {
            let path = dir.join(what);
            std::fs::write(&path, format!("{value}\n")).map_err(|e| {
                FrfError::new(format!(
                    "cannot apply the cgroup v2 envelope: writing {what} under {} failed: {e} — the controller may not be enabled in the delegated root's subtree_control",
                    dir.display()
                ))
            })?;
        }
        // Open cgroup.procs WITHOUT O_CLOEXEC: the fd is inherited by the
        // child, which writes its own pid in pre_exec. The write is the
        // race-free move: descendants inherit the cgroup at fork. O_CREAT
        // makes the regression suite's fake cgroupfs (a plain temp dir)
        // provide the file the kernel provides on the real filesystem; on
        // real cgroupfs O_CREAT on an existing pseudo-file is a no-op.
        let c = std::ffi::CString::new(dir.join("cgroup.procs").to_string_lossy().as_bytes())
            .map_err(|_| FrfError::new("cgroup.procs path contains a NUL byte"))?;
        // SAFETY: open(2) with O_WRONLY|O_CREAT on a valid path.
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_WRONLY | libc::O_CREAT, 0o644) };
        if fd < 0 {
            return Err(FrfError::new(format!(
                "cannot open {}: {}",
                dir.join("cgroup.procs").display(),
                std::io::Error::last_os_error()
            )));
        }
        Ok(CgroupV2 {
            dir,
            procs_fd: Some(fd),
            direct_pid: None,
        })
    }

    /// Record the side's direct child pid (called once the child exists).
    pub fn mark_direct(&mut self, pid: u32) {
        self.direct_pid = Some(pid as libc::pid_t);
    }

    /// The inherited `cgroup.procs` fd the side writes its own pid to.
    pub fn procs_fd(&self) -> std::os::fd::RawFd {
        self.procs_fd.unwrap_or(-1)
    }

    /// The members of the group from `cgroup.procs` that are not the
    /// known-reaped direct child (the kernel removes a pid when its process
    /// exits; the harness probes existence because the regression suite's
    /// fake root never rewrites the file).
    fn live_members(&self) -> Vec<libc::pid_t> {
        let mut out = Vec::new();
        let Ok(contents) = std::fs::read_to_string(self.dir.join("cgroup.procs")) else {
            return out;
        };
        for line in contents.lines() {
            if let Ok(pid) = line.trim().parse::<libc::pid_t>() {
                if pid > 0 && Some(pid) != self.direct_pid && pid_exists(pid) {
                    out.push(pid);
                }
            }
        }
        out
    }

    /// The group is empty when the kernel says so (`cgroup.events`
    /// `populated 0`) or — where the events file is absent (an older kernel,
    /// or the regression suite's fake root) — when `cgroup.procs` holds no
    /// present member. A ZOMBIE counts as present: the kernel's populated
    /// accounting counts a task until it is reaped, and a killed descendant
    /// is only released once the harness (their subreaper) reaps it.
    fn is_empty(&self) -> bool {
        let events = self.dir.join("cgroup.events");
        if let Ok(contents) = std::fs::read_to_string(&events) {
            for line in contents.lines() {
                if let Some(v) = line.strip_prefix("populated ") {
                    return v.trim() == "0";
                }
            }
        }
        self.live_members().is_empty()
    }

    /// KILL the group, wait for it to EMPTY (bounded), and remove it — the
    /// v2 finalization. The side's direct process is already reaped; a
    /// descendant that survived the process-group kill (e.g. it called
    /// setsid()) is still HERE, inside the side's cgroup. `cgroup.kill`
    /// (kernel >= 5.14) is the atomic path; without it, enumerate
    /// `cgroup.procs` and SIGKILL every member until the group is empty. The
    /// harness is a child subreaper, so the side's orphaned descendants
    /// reparent HERE and are reaped in the wait loop — a container whose pid
    /// 1 never reaps cannot leave a zombie holding the group populated
    /// forever. A group that cannot be emptied within the budget REFUSES the
    /// run — under v2, failure to empty the group is a run refusal, never
    /// ignored cleanup.
    pub fn finalize(&self) -> Result<()> {
        ensure_subreaper();
        // 1. cgroup.kill: the kernel terminates every member atomically.
        let kill_path = self.dir.join("cgroup.kill");
        if kill_path.is_file() {
            let _ = std::fs::write(&kill_path, "1");
        }
        // 2. Wait for the group to empty (bounded), SIGKILLing any member
        //    the enumerate path still finds present and reaping the side's
        //    orphaned descendants (a no-op after cgroup.kill — the kernel
        //    already removed them; the reaping releases the zombies).
        let deadline = Instant::now() + CGROUP_EMPTY_BUDGET;
        loop {
            if self.is_empty() {
                break;
            }
            let members = self.live_members();
            if Instant::now() >= deadline {
                // One final SIGKILL sweep + reap drain, then REFUSE: a
                // member that survives the budget means the observation is
                // not finalized — the v2 property "no descendant of the
                // observed side remains alive after the observation is
                // finalized" is violated, and the run must not become
                // evidence.
                for pid in &members {
                    kill_member(*pid);
                }
                for pid in members {
                    reap_member(pid);
                }
                return Err(FrfError::new(format!(
                    "{} could not be emptied within the {} budget: a member survived SIGKILL (uninterruptible D-state?) — under {} the side's whole descendant tree must be dead before the observation is finalized",
                    self.dir.display(),
                    CGROUP_EMPTY_BUDGET.as_millis(),
                    ExecProfile::LinuxV2.as_str()
                )));
            }
            for pid in &members {
                kill_member(*pid);
            }
            for pid in members {
                reap_member(pid);
            }
            std::thread::sleep(CGROUP_EMPTY_POLL);
        }
        // 3. The group is empty: remove it (and the empty `frf/` parent).
        let _ = std::fs::remove_dir_all(&self.dir);
        if let Some(parent) = self.dir.parent() {
            let _ = std::fs::remove_dir(parent);
        }
        Ok(())
    }
}

/// The harness is a child subreaper (PR_SET_CHILD_SUBREAPER): when a side's
/// descendant loses its parent (the side itself), it reparents HERE, not to
/// init — so the v2 finalization reaps it, and a container whose pid 1 never
/// reaps cannot leave a zombie holding the side's cgroup populated forever.
/// Set once, process-wide; the per-member reap in [`CgroupV2::finalize`]
/// reaps exactly the side's reparented descendants (never `waitpid(-1)`: a
/// process-wide wait would race with any other child a concurrent caller
/// owns).
fn ensure_subreaper() {
    static SET: std::sync::Once = std::sync::Once::new();
    SET.call_once(|| {
        // SAFETY: prctl(2) with PR_SET_CHILD_SUBREAPER and value 1 is
        // infallible from Rust's perspective; errno is deliberately ignored
        // (an unsupported kernel leaves normal init-reaping semantics).
        unsafe {
            libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1);
        }
    });
}

/// SIGKILL one cgroup member (positive pid — exactly that process; a member
/// may exit between enumeration and signal, so errno is ignored).
fn kill_member(pid: libc::pid_t) {
    // SAFETY: kill(2) with a positive pid signals exactly that process.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
}

/// Reap one cgroup member IF it is the harness's child (a killed descendant
/// that reparented to the subreaper): `waitpid(pid, WNOHANG)` returns the
/// pid when reaped, 0 when it is still running, and -1/ECHILD when it is not
/// our child at all (leave it to its owner — never steal another child).
fn reap_member(pid: libc::pid_t) {
    // SAFETY: waitpid(2) with a specific pid and WNOHANG reaps exactly that
    // child when it is ready; errno is deliberately ignored.
    unsafe {
        libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG);
    }
}

/// Is a pid currently in the process table (`kill(pid, 0)`)? A ZOMBIE
/// answers YES — it is still a task, still counted by the kernel's cgroup
/// populated accounting — which is exactly the case the cgroup-empty wait
/// must treat as non-empty until the harness (their subreaper) reaps it.
fn pid_exists(pid: libc::pid_t) -> bool {
    // SAFETY: kill(2) with a positive pid and signal 0 performs only an
    // existence check; errno is deliberately ignored.
    unsafe { libc::kill(pid, 0) == 0 }
}

impl Drop for CgroupV2 {
    fn drop(&mut self) {
        if let Some(fd) = self.procs_fd.take() {
            // SAFETY: `fd` is an open fd owned by this guard.
            unsafe { libc::close(fd) };
        }
        let _ = std::fs::remove_dir_all(&self.dir);
        // Best-effort: remove the empty `frf/` parent too.
        if let Some(parent) = self.dir.parent() {
            let _ = std::fs::remove_dir(parent);
        }
    }
}

/// Write `pid` as ASCII decimal + newline into `buf`; returns the length.
/// Async-signal-safe (no allocation), for the pre_exec self-move.
fn write_pid(pid: libc::pid_t, buf: &mut [u8]) -> usize {
    let mut tmp = [0u8; 16];
    let mut n = 0usize;
    let mut v = pid.unsigned_abs();
    if v == 0 {
        tmp[n] = b'0';
        n += 1;
    }
    while v > 0 {
        tmp[n] = b'0' + (v % 10) as u8;
        n += 1;
        v /= 10;
    }
    let mut i = 0usize;
    while i < n {
        buf[i] = tmp[n - 1 - i];
        i += 1;
    }
    buf[i] = b'\n';
    i + 1
}

/// Create a memfd, copy `bytes` into it, and seal it
/// (F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL). After the final
/// F_ADD_SEALS no process can modify the image; the seals are read back to
/// prove it before the image is ever executed.
#[cfg(target_os = "linux")]
fn seal_memfd(bytes: &[u8]) -> Result<std::os::fd::OwnedFd> {
    use std::os::fd::{FromRawFd, OwnedFd, RawFd};

    // The name shows up in /proc/<pid>/fdinfo; "frf-object" is descriptive.
    let name = c"frf-object";
    // SAFETY: memfd_create(2) is async-signal-safe; MFD_ALLOW_SEALING is
    // required for F_ADD_SEALS. The returned fd is owned by us.
    let raw: RawFd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_ALLOW_SEALING) };
    if raw < 0 {
        return Err(FrfError::new(format!(
            "memfd_create failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: `raw` is a fresh fd owned by us.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    let mut written = 0usize;
    while written < bytes.len() {
        // SAFETY: `raw` is a valid open fd; the buffer is `bytes` itself.
        let n =
            unsafe { libc::write(raw, bytes[written..].as_ptr().cast(), bytes.len() - written) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(FrfError::new(format!(
                "cannot write the sealed executable image: {e}"
            )));
        }
        written += n as usize;
    }

    // Seal: after this, the image is immutable — even to us. The kernel
    // guarantees the order does not matter; F_SEAL_SEAL in the same call
    // makes the sealing permanent.
    // SAFETY: fcntl(2) on a valid fd with valid seal constants.
    let rc = unsafe {
        libc::fcntl(
            raw,
            libc::F_ADD_SEALS,
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL,
        )
    };
    if rc < 0 {
        return Err(FrfError::new(format!(
            "cannot seal the executable image: {}",
            std::io::Error::last_os_error()
        )));
    }
    // Prove the seals before the image may be executed: read them back.
    // SAFETY: fcntl(2) F_GET_SEALS on a valid fd.
    let seals = unsafe { libc::fcntl(raw, libc::F_GET_SEALS) };
    let required = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    if seals < 0 || (seals & required) != required {
        return Err(FrfError::new(format!(
            "the sealed executable image does not report the required seals (F_GET_SEALS = {seals}); refusing to execute an unsealed image"
        )));
    }
    Ok(fd)
}

/// Fallback (non-Linux): materialize the bytes to a private temp file with
/// mode 0555. The reference profile is Linux; this is a best-effort port.
#[cfg(not(target_os = "linux"))]
fn materialize_temp(bytes: &[u8]) -> Result<PathBuf> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    let dir = std::env::temp_dir();
    let mut path = dir.join(format!(
        "frf-image-{}-{}",
        std::process::id(),
        crate::host::sha256_bytes(bytes)
    ));
    // Avoid collision: append a monotonic counter suffix.
    for i in 0u32.. {
        let p = path.with_extension(format!("{i}.img"));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o555)
            .open(&p)
        {
            Ok(mut f) => {
                f.write_all(bytes)
                    .map_err(|e| FrfError::new(format!("cannot write {}: {e}", p.display())))?;
                path = p;
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(FrfError::new(format!(
                    "cannot create the fallback executable image: {e}"
                )))
            }
        }
    }
    Ok(path)
}

/// Effective execution timeout: the default, unless the `FRF_EXEC_TIMEOUT_MS`
/// test hook overrides it. Kept out of the public CLI surface on purpose;
/// its only legitimate use is making the kill path cheap to exercise.
pub fn exec_timeout() -> Duration {
    std::env::var("FRF_EXEC_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_millis)
        .unwrap_or(EXEC_TIMEOUT)
}

/// Effective per-stream capture cap: the profile default, unless the
/// `FRF_EXEC_MAX_BYTES` test hook overrides it (a hostile side must not be
/// able to exhaust the harness's memory before the timeout).
pub fn max_stream_bytes() -> usize {
    std::env::var("FRF_EXEC_MAX_BYTES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(EXEC_MAX_STREAM_BYTES)
}

/// Effective produced-tree file-count cap, `FRF_EXEC_PRODUCED_MAX_FILES`
/// override (v19).
pub fn produced_max_files() -> u64 {
    std::env::var("FRF_EXEC_PRODUCED_MAX_FILES")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(EXEC_PRODUCED_MAX_FILES)
}

/// Effective produced-tree total-bytes cap, `FRF_EXEC_PRODUCED_MAX_BYTES`
/// override (v19).
pub fn produced_max_bytes() -> u64 {
    std::env::var("FRF_EXEC_PRODUCED_MAX_BYTES")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(EXEC_PRODUCED_MAX_BYTES)
}

/// Effective per-produced-file bytes cap, `FRF_EXEC_PRODUCED_MAX_FILE_BYTES`
/// override (v19).
pub fn produced_max_file_bytes() -> u64 {
    std::env::var("FRF_EXEC_PRODUCED_MAX_FILE_BYTES")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(EXEC_PRODUCED_MAX_FILE_BYTES)
}

/// The SELF CPU of this process (getrusage(RUSAGE_SELF) user+sys, ms) — the
/// harness process's OWN CPU, excluding any children it spawned. 0.1.63: the
/// benchmark protocol reads this from the frf process itself
/// (FRF_PRINT_SELF_CPU=1) so harness-attributable CPU is separated from the
/// sides' CPU (which is accounted independently), never conflated.
pub fn self_cpu_ms() -> f64 {
    #[cfg(unix)]
    {
        let mut ru = std::mem::MaybeUninit::<libc::rusage>::uninit();
        // SAFETY: getrusage writes the struct on success; the pointer is
        // valid for the lifetime of the call.
        let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, ru.as_mut_ptr()) };
        if rc != 0 {
            return 0.0;
        }
        // SAFETY: rc == 0 means the struct was initialized.
        let ru = unsafe { ru.assume_init() };
        (ru.ru_utime.tv_sec as f64
            + ru.ru_utime.tv_usec as f64 / 1e6
            + ru.ru_stime.tv_sec as f64
            + ru.ru_stime.tv_usec as f64 / 1e6)
            * 1e3
    }
    #[cfg(not(unix))]
    {
        0.0
    }
}

/// The effective address-space limit (MiB), `FRF_EXEC_RLIMIT_AS_MB` override.
pub fn rlimit_as_mb() -> u64 {
    std::env::var("FRF_EXEC_RLIMIT_AS_MB")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(EXEC_RLIMIT_AS_MB)
}

/// Effective CPU-time limit (seconds), `FRF_EXEC_RLIMIT_CPU_S` override.
pub fn rlimit_cpu_s() -> u64 {
    std::env::var("FRF_EXEC_RLIMIT_CPU_S")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(EXEC_RLIMIT_CPU_S)
}

/// Effective open-file limit, `FRF_EXEC_RLIMIT_NOFILE` override.
pub fn rlimit_nofile() -> u64 {
    std::env::var("FRF_EXEC_RLIMIT_NOFILE")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(EXEC_RLIMIT_NOFILE)
}

/// Effective process-count limit, `FRF_EXEC_RLIMIT_NPROC` override.
pub fn rlimit_nproc() -> u64 {
    std::env::var("FRF_EXEC_RLIMIT_NPROC")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(EXEC_RLIMIT_NPROC)
}

/// The REFERENCE capture bounds: the immutable protocol constants of the
/// `frf-exec-linux-v1` profile. These NEVER honor the `FRF_EXEC_*` test
/// hooks — an override must not be able to redefine what the reference
/// execution contract IS. `high-assurance` claim admission compares a
/// premise's recorded bounds against this value, so a run made under any
/// overridden contract is refused no matter what environment the compiler
/// runs in. The reference profile is v1; a v2 run records its cgroup
/// envelope and is (by the profile check) not reference-contract evidence.
pub fn reference_capture_bounds() -> CaptureBounds {
    CaptureBounds {
        timeout_ms: EXEC_TIMEOUT.as_millis().to_string(),
        max_stream_bytes: EXEC_MAX_STREAM_BYTES.to_string(),
        produced_max_files: EXEC_PRODUCED_MAX_FILES.to_string(),
        produced_max_bytes: EXEC_PRODUCED_MAX_BYTES.to_string(),
        produced_max_file_bytes: EXEC_PRODUCED_MAX_FILE_BYTES.to_string(),
        rlimit_as_mb: EXEC_RLIMIT_AS_MB.to_string(),
        rlimit_cpu_s: EXEC_RLIMIT_CPU_S.to_string(),
        rlimit_nofile: EXEC_RLIMIT_NOFILE.to_string(),
        rlimit_nproc: EXEC_RLIMIT_NPROC.to_string(),
        cgroup_pids_max: None,
        cgroup_memory_max: None,
        cgroup_cpu_max: None,
    }
}

/// The EFFECTIVE capture bounds — the profile defaults or the `FRF_EXEC_*`
/// test-hook overrides (strings, because the OpenReceipt canonical value
/// domain has no numbers). Bound at OBSERVATION time and copied into the
/// capture/receipt, so an observation is always read against the harness
/// contract it was actually made under. The reference contract is
/// [`reference_capture_bounds`]; the two differ exactly when a test hook
/// overrides a bound, and only the observation side may consult the
/// effective value. The `frf-exec-linux-v2` profile additionally records
/// its cgroup v2 aggregate envelope (`cgroup_*`); the reference profile
/// records none.
pub fn capture_bounds(profile: ExecProfile) -> CaptureBounds {
    let mut bounds = CaptureBounds {
        timeout_ms: exec_timeout().as_millis().to_string(),
        max_stream_bytes: max_stream_bytes().to_string(),
        produced_max_files: produced_max_files().to_string(),
        produced_max_bytes: produced_max_bytes().to_string(),
        produced_max_file_bytes: produced_max_file_bytes().to_string(),
        rlimit_as_mb: rlimit_as_mb().to_string(),
        rlimit_cpu_s: rlimit_cpu_s().to_string(),
        rlimit_nofile: rlimit_nofile().to_string(),
        rlimit_nproc: rlimit_nproc().to_string(),
        cgroup_pids_max: None,
        cgroup_memory_max: None,
        cgroup_cpu_max: None,
    };
    if profile == ExecProfile::LinuxV2 {
        bounds.cgroup_pids_max = Some(CGROUP2_PIDS_MAX.to_string());
        bounds.cgroup_memory_max = Some(CGROUP2_MEMORY_MAX.to_string());
        bounds.cgroup_cpu_max = Some(CGROUP2_CPU_MAX.to_string());
    }
    bounds
}

/// SHA-256 hex digest of a byte slice.
pub fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(&hasher.finalize())
}

/// Is a string a well-formed 64-hex SHA-256 content address?
pub fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Read a file's bytes with a user-facing error.
pub fn read_file(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| FrfError::new(format!("cannot read {}: {e}", path.display())))
}

/// SHA-256 of the currently running frf executable — the runner identity
/// bound into every capture at observation time.
pub fn current_exe_hash() -> Result<String> {
    let exe = std::env::current_exe()
        .map_err(|e| FrfError::new(format!("cannot locate the frf executable: {e}")))?;
    sha256_file(&exe)
}

/// SHA-256 hex digest of a file's bytes.
pub fn sha256_file(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path)
        .map_err(|e| FrfError::new(format!("cannot read {} for hashing: {e}", path.display())))?;
    Ok(sha256_bytes(&bytes))
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// A harness-enforcement violation: a declared bound fired during an
/// observation attempt. Carried out of [`run_impl`] (and the produced-tree
/// walk) so the caller can write the content-addressed [`HarnessEvent`]
/// evidence record (`harness/<id>.json`) — the refusal is itself provable
/// evidence. The run is still REFUSED for stream/timeout/produced overflow
/// (fail-closed, never truncated); a resource-limit signal (SIGXCPU — the
/// CPU bound's declared outcome) completes as a valid observation whose
/// event is recorded alongside.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessViolation {
    /// `stream-overflow` | `timeout` | `rlimit` | `produced-overflow`.
    pub event_kind: &'static str,
    /// The bound that fired: `stdout` | `stderr` | `wall` | `cpu` |
    /// `produced-files` | `produced-bytes` | `produced-file-bytes`.
    pub target: String,
    /// The declared cap, as enforced.
    pub cap: String,
    /// The observed value that exceeded the cap.
    pub observed: String,
    /// Free-form detail.
    pub detail: String,
}

/// A harness execution error: the refusal message plus, when a DECLARED
/// BOUND fired, the structured violation that becomes a [`HarnessEvent`]
/// evidence record. The violation is boxed: the error value is carried on
/// hot paths (thread-scoped drain results) and its size must stay small.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunError {
    pub message: String,
    pub violation: Option<Box<HarnessViolation>>,
}

impl RunError {
    pub fn new(message: impl Into<String>) -> RunError {
        RunError {
            message: message.into(),
            violation: None,
        }
    }
}

impl From<RunError> for FrfError {
    fn from(e: RunError) -> FrfError {
        FrfError::new(e.message)
    }
}

impl From<FrfError> for RunError {
    fn from(e: FrfError) -> RunError {
        RunError::new(e.into_message())
    }
}

/// A completed process observation. `violation` is present when a declared
/// bound fired but the observation is still COMPLETE (a resource-limit
/// signal is a valid side outcome — the run continues, and the caller
/// records the harness event).
#[derive(Debug, Clone)]
pub struct ProcessOutcome {
    pub stdout: CapturedStream,
    pub stderr: CapturedStream,
    pub exit: String,
    /// Present when a resource-limit bound fired (the CPU limit's SIGXCPU).
    pub violation: Option<Box<HarnessViolation>>,
}

/// The in-memory threshold for a captured stream: a stream at or below this
/// size is kept INLINE (the common case — verdict lines, first lines); a
/// larger stream SPILLS to a temp file as it is read. Memory is therefore
/// bounded to the threshold + one read chunk regardless of the stream's
/// size, so very large outputs (a raised capture cap) do not buffer the
/// whole stream in RAM.
const STREAM_INLINE_LIMIT: usize = 64 * 1024;

/// A captured output stream's exact bytes: inline (small streams) or a temp
/// file (large streams, removed when the last reference drops).
#[derive(Debug)]
enum StreamSource {
    Inline(Vec<u8>),
    File(Arc<TempFile>),
}

/// A temporary stream file, removed on drop (reference-counted: the file
/// lives until the last [`CapturedStream`] clone is gone).
#[derive(Debug)]
struct TempFile(PathBuf);

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// A captured output stream: the EXACT bytes (inline or spilled to a temp
/// file), with the length, the first line, and the SHA-256 computed
/// INCREMENTALLY during the capture. The evidence invariants are unchanged:
/// the run is refused on overflow (truncated output is never evidence), and
/// the recorded first line and digest are exactly the stream's own.
#[derive(Debug, Clone)]
pub struct CapturedStream {
    source: Arc<StreamSource>,
    /// The exact stream length in bytes.
    pub length: u64,
    /// The first line (the text up to the first newline, exactly as the
    /// capture records it).
    pub first_line: String,
    /// SHA-256 of the exact stream bytes.
    pub sha256: String,
}

impl CapturedStream {
    /// Build a captured stream from bytes already in memory (the extension
    /// paths: normalizer output, a constructed outcome).
    pub fn from_bytes(bytes: Vec<u8>) -> CapturedStream {
        let length = bytes.len() as u64;
        let first_line = first_line_of(&bytes);
        let sha256 = sha256_bytes(&bytes);
        CapturedStream {
            source: Arc::new(StreamSource::Inline(bytes)),
            length,
            first_line,
            sha256,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// The exact bytes as a materialized buffer (the consumers that need the
    /// whole stream: comparators, normalizers, base64 requests).
    pub fn bytes(&self) -> Vec<u8> {
        match &*self.source {
            StreamSource::Inline(b) => b.clone(),
            StreamSource::File(f) => std::fs::read(&f.0)
                .unwrap_or_else(|e| panic!("cannot read the spilled capture stream: {e}")),
        }
    }

    /// Write the exact bytes to `w`, streaming from the source (no whole-
    /// stream materialization).
    pub fn write_to(&self, w: &mut impl std::io::Write) -> std::io::Result<()> {
        match &*self.source {
            StreamSource::Inline(b) => w.write_all(b),
            StreamSource::File(f) => {
                let mut r = std::fs::File::open(&f.0)?;
                std::io::copy(&mut r, w)?;
                Ok(())
            }
        }
    }
}

/// The first line of a byte stream: the text up to the first newline
/// (inclusive of nothing else), lossily decoded — the capture record's
/// projection.
pub(crate) fn first_line_of(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|b| *b == b'\n')
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// Drain a capture pipe into a [`CapturedStream`]: bytes are kept inline up
/// to [`STREAM_INLINE_LIMIT`] and spilled to a temp file beyond it, with the
/// length, first line, and SHA-256 computed incrementally. On exceeding the
/// per-stream cap the whole process group is terminated, the overflow flag
/// set, and the FIRST overflowing stream + observed size recorded: the
/// caller refuses the run (truncated output is never evidence) and writes
/// the harness event, and killing the group frees the peer pipes so every
/// other drain reaches EOF and the scope can join.
#[allow(clippy::too_many_arguments)]
fn drain_capped(
    pipe: &mut impl Read,
    max: usize,
    group: u32,
    overflow: &AtomicBool,
    overflow_detail: &Mutex<Option<(String, usize)>>,
    stream: &'static str,
) -> CapturedStream {
    use sha2::Digest as _;
    let mut inline: Vec<u8> = Vec::new();
    let mut file: Option<std::fs::File> = None;
    let mut file_path: Option<PathBuf> = None;
    let mut hasher = sha2::Sha256::new();
    let mut first_line: Vec<u8> = Vec::new();
    let mut first_line_done = false;
    let mut length: u64 = 0;
    let mut chunk = [0u8; 8192];
    loop {
        match pipe.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                let bytes = &chunk[..n];
                let new_length = length + n as u64;
                if new_length as usize > max {
                    overflow.store(true, Ordering::SeqCst);
                    let mut guard = overflow_detail.lock().expect("overflow detail lock");
                    if guard.is_none() {
                        *guard = Some((stream.to_string(), new_length as usize));
                    }
                    drop(guard);
                    #[cfg(unix)]
                    terminate_process_group(group);
                    break;
                }
                length = new_length;
                hasher.update(bytes);
                if !first_line_done {
                    for (i, b) in bytes.iter().enumerate() {
                        if *b == b'\n' {
                            first_line.extend_from_slice(&bytes[..i]);
                            first_line_done = true;
                            break;
                        }
                    }
                    if !first_line_done {
                        first_line.extend_from_slice(bytes);
                    }
                }
                // Spill once the inline threshold is exceeded: the bytes
                // buffered so far move to the temp file, and everything after
                // streams straight to disk.
                if file.is_none() && length as usize > STREAM_INLINE_LIMIT {
                    let path = std::env::temp_dir().join(format!(
                        "frf-stream-{}-{}-{stream}.tmp",
                        std::process::id(),
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_nanos()
                    ));
                    let mut f = std::fs::File::create(&path)
                        .unwrap_or_else(|e| panic!("cannot create the capture spill file: {e}"));
                    f.write_all(&inline)
                        .unwrap_or_else(|e| panic!("cannot spill the capture stream: {e}"));
                    file = Some(f);
                    file_path = Some(path);
                    inline.clear();
                }
                if let Some(f) = file.as_mut() {
                    f.write_all(bytes)
                        .unwrap_or_else(|e| panic!("cannot write the capture spill file: {e}"));
                } else {
                    inline.extend_from_slice(bytes);
                }
            }
            Err(_) => break, // the group-kill path closes the pipe
        }
    }
    let digest: [u8; 32] = hasher.finalize().into();
    let sha256 = hex(&digest);
    let source = match file_path {
        Some(path) => StreamSource::File(Arc::new(TempFile(path))),
        None => StreamSource::Inline(inline),
    };
    CapturedStream {
        source: Arc::new(source),
        length,
        first_line: String::from_utf8_lossy(&first_line).into_owned(),
        sha256,
    }
}

/// Execute `image` with `args`, capturing stdout/stderr without a shell,
/// under the declared [`ExecProfile`].
///
/// `ETXTBSY` (`ExecutableFileBusy`) is retried within [`SPAWN_RETRY_BUDGET`]
/// before failing; everything else fails immediately.
///
/// Under `frf-exec-oci`, `container` is the declared OCI image the side runs
/// INSIDE (the complete root filesystem is the execution machinery); it must
/// be `Some` for the OCI profile and is ignored otherwise.
pub fn run_process(
    image: &ExecImage,
    args: &[String],
    profile: ExecProfile,
    env: &std::collections::BTreeMap<String, String>,
    container: Option<&crate::model::OciImage>,
) -> std::result::Result<ProcessOutcome, RunError> {
    run_impl(image, args, None, None, profile, env, container, None)
}

/// [`run_process`] with a declared working directory.
pub fn run_process_in(
    image: &ExecImage,
    args: &[String],
    cwd: &Path,
    profile: ExecProfile,
    env: &std::collections::BTreeMap<String, String>,
    container: Option<&crate::model::OciImage>,
) -> std::result::Result<ProcessOutcome, RunError> {
    run_impl(image, args, None, Some(cwd), profile, env, container, None)
}

/// [`run_process`] with a declared stdin (the extension protocols' request).
pub fn run_process_with_stdin(
    image: &ExecImage,
    args: &[String],
    stdin: &[u8],
    profile: ExecProfile,
    env: &std::collections::BTreeMap<String, String>,
    container: Option<&crate::model::OciImage>,
) -> std::result::Result<ProcessOutcome, RunError> {
    run_impl(
        image,
        args,
        Some(stdin),
        None,
        profile,
        env,
        container,
        None,
    )
}

/// [`run_process_with_stdin`] with a declared working directory (bundle
/// replay invokes the snapshotted comparator from the reconstructed root).
pub fn run_process_with_stdin_in(
    image: &ExecImage,
    args: &[String],
    stdin: &[u8],
    cwd: &Path,
    profile: ExecProfile,
    env: &std::collections::BTreeMap<String, String>,
    container: Option<&crate::model::OciImage>,
) -> std::result::Result<ProcessOutcome, RunError> {
    run_impl(
        image,
        args,
        Some(stdin),
        Some(cwd),
        profile,
        env,
        container,
        None,
    )
}

/// [`run_process`] under the I/O-CLOSED profile: the side runs inside the
/// declared Landlock filesystem closure + seccomp ambient-channel closure
/// (`frf-exec-linux-v3`). The sandbox MUST be present exactly when the
/// profile is v3 — a v3 side without its closure REFUSES (a declared
/// profile is enforced, never approximated). The side runs with the
/// inherited working directory unless `cwd` is given.
pub fn run_process_closed(
    image: &ExecImage,
    args: &[String],
    cwd: Option<&Path>,
    profile: ExecProfile,
    env: &std::collections::BTreeMap<String, String>,
    sandbox: &crate::sandbox::IoClosedSandbox,
) -> std::result::Result<ProcessOutcome, RunError> {
    run_impl(image, args, None, cwd, profile, env, None, Some(sandbox))
}

/// The profile EXTENSION programs run under (0.1.62): extensions are
/// harness-side instrumentation — the FRF-provided machinery — so under
/// `frf-exec-oci` they execute on the HOST under the reference capture
/// discipline (the container binding applies to the OBSERVED sides; an
/// extension is not the observed software). Their invocation evidence
/// records the host profile honestly.
pub fn extension_profile(side_profile: ExecProfile) -> ExecProfile {
    match side_profile {
        // Under the OCI and I/O-closed profiles the sandbox applies to the
        // OBSERVED sides only; extension programs are harness-side
        // instrumentation and run on the host under the reference profile.
        ExecProfile::Oci | ExecProfile::LinuxV3 => ExecProfile::LinuxV1,
        other => other,
    }
}

/// Locate the container runtime (`podman`, then `docker`) and its version —
/// `frf-exec-oci` is ENFORCED, never approximated: without a runtime the
/// profile refuses to run.
pub(crate) fn container_runtime() -> Result<(String, String)> {
    for bin in ["podman", "docker"] {
        if let Ok(out) = Command::new(bin).arg("--version").output() {
            if out.status.success() {
                let version = String::from_utf8_lossy(&out.stdout).trim().to_string();
                return Ok((bin.to_string(), version));
            }
        }
    }
    Err(FrfError::new(format!(
        "{} was requested but no container runtime is available: neither `podman` nor `docker` is on PATH — the profile is enforced, never approximated; install a runtime and load the declared image, or use the reference profile {}",
        crate::model::EXECUTION_PROFILE_OCI,
        crate::model::EXECUTION_PROFILE_LINUX
    )))
}

/// Verify the runtime resolves the declared image reference to the exact
/// image: `image inspect <reference>` must succeed. Because the reference
/// carries the digest (e.g. `alpine@sha256:…`), a runtime that has any
/// OTHER image under that name cannot satisfy it — the image is
/// content-addressed, and a missing image REFUSES the run (never a silent
/// substitution).
pub(crate) fn verify_container_image(bin: &str, reference: &str) -> Result<()> {
    let out = Command::new(bin)
        .args(["image", "inspect", reference])
        .output()
        .map_err(|e| FrfError::new(format!("cannot run `{bin} image inspect {reference}`: {e}")))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(FrfError::new(format!(
            "the declared OCI image {reference} is not present in the {bin} store: the image is part of the declared execution machinery and may not be silently substituted; load the exact image (pull by digest or import) and re-run"
        )))
    }
}

/// The `frf-exec-oci` execution path: the side runs INSIDE a container from
/// the declared digest-pinned image. The image is the COMPLETE execution
/// machinery — the whole root filesystem (interpreter, shared libraries,
/// loader configuration, certificates) is bound by the digest in the
/// execution identity. The container runs with no network, the declared
/// environment, and the working directory bind-mounted at its own absolute
/// path, so the side's recorded root-relative argv (the materialized object
/// path, the fixture) resolve inside the container exactly as they do on the
/// host. The container is removed on exit; the capture discipline (drain,
/// timeout, overflow refusal) is the same as the reference profile.
fn run_oci(
    image: &ExecImage,
    args: &[String],
    stdin: Option<&[u8]>,
    cwd: Option<&Path>,
    env: &std::collections::BTreeMap<String, String>,
    container: Option<&crate::model::OciImage>,
) -> std::result::Result<ProcessOutcome, RunError> {
    let oci = container.ok_or_else(|| {
        RunError::new(format!(
            "{} requires the declared OCI image; the court must declare `execution_image`",
            crate::model::EXECUTION_PROFILE_OCI
        ))
    })?;
    let (runtime_bin, _runtime_version) =
        container_runtime().map_err(|e| RunError::new(e.into_message()))?;
    verify_container_image(&runtime_bin, &oci.reference)
        .map_err(|e| RunError::new(e.into_message()))?;

    // The working directory the container sees: the bind mount target equals
    // the host path, so recorded relative argv paths resolve identically.
    let workdir = cwd
        .map(Path::to_path_buf)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")));
    let program = image.argv0();

    let mut command = Command::new(&runtime_bin);
    command
        .arg("run")
        .arg("--rm")
        .arg("--network=none")
        .arg("-v")
        .arg(format!("{}:{}", workdir.display(), workdir.display()))
        .arg("-w")
        .arg(&workdir);
    for (k, v) in env {
        command.arg("--env").arg(format!("{k}={v}"));
    }
    command.arg(&oci.reference);
    // The container command is the MATERIALIZED snapshot path (argv[0] — the
    // path the observation sees), NOT the sealed memfd path: `/proc/self/fd/N`
    // is a host descriptor, invisible inside the container. The materialized
    // path resolves inside the container through the working-directory bind
    // mount, and its bytes are the verified snapshot (the store re-seals it
    // on every use).
    command.arg(image.argv0());
    command.args(args);
    command
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Every side runs in its own process group (unix) so the harness can
    // terminate the runtime and its tree when the side exits, times out, or
    // overflows its capture cap.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }

    let mut child = command.spawn().map_err(|e| {
        RunError::new(format!(
            "failed to execute {} in the OCI image {}: {e}",
            program.display(),
            oci.reference
        ))
    })?;
    let group = child.id();
    let start = Instant::now();
    let overflow = Arc::new(AtomicBool::new(false));
    let overflow_detail: Arc<Mutex<Option<(String, usize)>>> = Arc::new(Mutex::new(None));

    let timeout = exec_timeout();
    let max_bytes = max_stream_bytes();
    let mut stdin_pipe = child.stdin.take();
    let mut stdout_pipe = child.stdout.take().expect("stdout is piped");
    let mut stderr_pipe = child.stderr.take().expect("stderr is piped");
    let (status, stdout, stderr) = std::thread::scope(|s| {
        if let (Some(mut pipe), Some(bytes)) = (stdin_pipe.take(), stdin.map(|b| b.to_vec())) {
            s.spawn(move || {
                let _ = pipe.write_all(&bytes);
            });
        }
        let drain_out = s.spawn(|| {
            drain_capped(
                &mut stdout_pipe,
                max_bytes,
                group,
                &overflow,
                &overflow_detail,
                "stdout",
            )
        });
        let drain_err = s.spawn(|| {
            drain_capped(
                &mut stderr_pipe,
                max_bytes,
                group,
                &overflow,
                &overflow_detail,
                "stderr",
            )
        });
        let result = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) => {
                    if start.elapsed() > timeout {
                        let _ = child.kill();
                        let _ = child.wait();
                        break Err(RunError {
                            message: format!(
                                "{} exceeded the execution timeout ({} ms) inside the OCI image {}",
                                program.display(),
                                timeout.as_millis(),
                                oci.reference
                            ),
                            violation: Some(Box::new(HarnessViolation {
                                event_kind: "timeout",
                                target: "wall".to_string(),
                                cap: timeout.as_millis().to_string(),
                                observed: start.elapsed().as_millis().to_string(),
                                detail: oci.reference.clone(),
                            })),
                        });
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => {
                    break Err(RunError::new(format!(
                        "failed to wait on {}: {e}",
                        program.display()
                    )))
                }
            }
        };
        // The runtime is gone; terminate whatever remains in its group so the
        // capture streams reach EOF and the drains can join.
        #[cfg(unix)]
        terminate_process_group(group);
        (
            result,
            drain_out.join().expect("the stdout drain must join"),
            drain_err.join().expect("the stderr drain must join"),
        )
    });
    let status = status?;

    if overflow.load(Ordering::SeqCst) {
        let (target, observed) = overflow_detail
            .lock()
            .expect("overflow detail lock")
            .clone()
            .unwrap_or(("stdout".to_string(), max_bytes));
        return Err(RunError {
            message: format!(
                "{} exceeded the execution profile's {} byte per-stream capture cap inside the OCI image {}; refusing to record truncated output as evidence",
                program.display(),
                max_bytes,
                oci.reference
            ),
            violation: Some(Box::new(HarnessViolation {
                event_kind: "stream-overflow",
                target,
                cap: max_bytes.to_string(),
                observed: observed.to_string(),
                detail: String::new(),
            })),
        });
    }

    let exit = exit_string(&status);
    Ok(ProcessOutcome {
        stdout,
        stderr,
        exit,
        violation: None,
    })
}

#[allow(clippy::too_many_arguments)]
fn run_impl(
    image: &ExecImage,
    args: &[String],
    stdin: Option<&[u8]>,
    cwd: Option<&Path>,
    profile: ExecProfile,
    env: &std::collections::BTreeMap<String, String>,
    container: Option<&crate::model::OciImage>,
    sandbox: Option<&crate::sandbox::IoClosedSandbox>,
) -> std::result::Result<ProcessOutcome, RunError> {
    // The program name the process observes (argv[0]) is the materialized
    // snapshot path — a sealed execution must not silently change argv[0]
    // to `/proc/self/fd/<n>`: many programs inspect argv[0], and the
    // observation must match the path-based contract.
    let program = image.argv0();
    // `frf-exec-oci`: the side runs INSIDE a container spawned from the
    // declared OCI image (digest-pinned — the runtime must resolve the exact
    // image; a missing or different image REFUSES the run). The image is the
    // complete execution machinery: the whole root filesystem is bound by
    // the digest. The side's materialized path + the declared argv are made
    // visible inside the container by bind-mounting the working directory at
    // its own absolute path; the capture records the image identity.
    if profile == ExecProfile::Oci {
        return run_oci(image, args, stdin, cwd, env, container);
    }
    // `frf-exec-linux-v3`: the I/O-CLOSED profile. The closure is ENFORCED,
    // never approximated: Landlock must be available, the caller must supply
    // the sandbox (a v3 side without its closure refuses), and the writable
    // surface must exist before the spawn (Landlock rules bind real paths).
    #[cfg(target_os = "linux")]
    if profile == ExecProfile::LinuxV3 {
        if let Some(err) = crate::sandbox::enforceability_error() {
            return Err(err.into());
        }
        let sb = sandbox.ok_or_else(|| {
            RunError::new(format!(
                "{} was requested without an I/O-closed sandbox — the side cannot be closed; refusing to run it unclosed",
                ExecProfile::LinuxV3.as_str()
            ))
        })?;
        if let Some(w) = &sb.write_dir {
            std::fs::create_dir_all(w).map_err(|e| {
                RunError::new(format!(
                    "cannot create the I/O-closed write surface {}: {e}",
                    w.display()
                ))
            })?;
        }
    }
    #[cfg(not(target_os = "linux"))]
    if profile == ExecProfile::LinuxV3 {
        return Err(RunError::new(format!(
            "{} is a Linux profile; this host cannot enforce the Landlock filesystem closure — use the reference profile {}",
            ExecProfile::LinuxV3.as_str(),
            ExecProfile::LinuxV1.as_str()
        )));
    }
    let mut command = if profile == ExecProfile::LinuxV3 {
        // The I/O-CLOSED profile executes the VERIFIED SNAPSHOT PATH, not the
        // sealed memfd: the kernel cannot bind a Landlock access rule to an
        // anonymous-inode memfd (and both path-based and AT_EMPTY_PATH exec of
        // one are denied under a closure) — the sandbox module documents the
        // empirical proof. The snapshot lives inside the objects directory the
        // closure allows, sealed read-only, and is itself content-addressed;
        // the residual same-UID verify->execute window is documented in
        // spec/execution-profile.md (the OCI profile closes both races).
        Command::new(image.argv0())
    } else {
        Command::new(image.path())
    };
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.arg0(program.as_os_str());
    }
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    // The DECLARED execution environment: the child is spawned with EXACTLY
    // the declared map — the host's ambient environment is never inherited.
    // The ambient environment is not evidence (it would leak secrets and
    // make the observation non-reproducible); the declared environment is
    // content-addressed into the capture, so replay re-spawns the exact
    // same environment and a new execution engine can reproduce the
    // observation from the evidence alone.
    command.env_clear();
    command.envs(env);
    command
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // `frf-exec-linux-v2`: the side's WHOLE descendant tree runs in its own
    // cgroup (pids.max / memory.max / cpu.max — the per-side aggregate
    // envelope). The group is created BEFORE the spawn; the child moves
    // ITSELF in during pre_exec (writing its own pid to the inherited
    // cgroup.procs fd — race-free: descendants inherit the cgroup at fork).
    // The guard lives until the child is reaped (run_impl is synchronous),
    // then the group is removed. No writable cgroup v2 subtree = the profile
    // REFUSES to run (a declared profile is enforced, never approximated).
    #[cfg(target_os = "linux")]
    let mut cgroup: Option<CgroupV2> = if profile == ExecProfile::LinuxV2 {
        let root = cgroup2_root()?.ok_or_else(|| {
            FrfError::new(format!(
                "{} was requested but no writable cgroup v2 subtree is delegated to this user: the side's aggregate envelope cannot be enforced; run under a delegating manager (a systemd user session with Delegate=, a container with a writable /sys/fs/cgroup) or use the reference profile {}",
                ExecProfile::LinuxV2.as_str(),
                ExecProfile::LinuxV1.as_str()
            ))
        })?;
        Some(CgroupV2::create(
            &root,
            &format!(
                "{}-{}",
                std::process::id(),
                CGROUP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ),
        )?)
    } else {
        None
    };
    #[cfg(not(target_os = "linux"))]
    let mut cgroup: Option<CgroupV2> = None;
    #[cfg(not(target_os = "linux"))]
    if profile == ExecProfile::LinuxV2 {
        return Err(FrfError::new(format!(
            "{} is a Linux profile; this host cannot enforce the cgroup v2 envelope — use the reference profile {}",
            ExecProfile::LinuxV2.as_str(),
            ExecProfile::LinuxV1.as_str()
        )));
    }

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        // The execution profile's resource bounds, applied inside the child
        // before exec: a hostile side is bounded in memory, CPU time, file
        // descriptors, and process count (a side cannot fork a process bomb
        // that exhausts the user's process table while the harness waits for
        // its own timeout). A side that hits a limit dies by the profile's
        // deterministic signal outcome (declared in
        // spec/execution-profile.md); the capture records the signal.
        let as_bytes = rlimit_as_mb().saturating_mul(1024 * 1024);
        let cpu_s = rlimit_cpu_s();
        let nofile = rlimit_nofile();
        let nproc = rlimit_nproc();
        let cgroup_procs_fd = cgroup.as_ref().map(CgroupV2::procs_fd);
        // The I/O-closed profile's sandbox, owned by the child closure: the
        // Landlock filesystem closure + seccomp ambient-channel closure are
        // installed FIRST (before the cgroup move — the sandbox cannot block
        // the inherited cgroup.procs fd write, and installing it first means
        // the side NEVER runs a single instruction unclosed).
        let closed = (profile == ExecProfile::LinuxV3)
            .then(|| sandbox.cloned())
            .flatten();
        // SAFETY: `pre_exec` runs after fork(2), before execve(2), in the
        // single-threaded child; setrlimit(2), write(2), prctl(2), and the
        // Landlock/seccomp syscalls are async-signal-safe.
        unsafe {
            command.pre_exec(move || {
                if let Some(sb) = &closed {
                    crate::sandbox::install(sb)?;
                }
                if let Some(fd) = cgroup_procs_fd {
                    // Move the side into its cgroup BEFORE exec: descendants
                    // inherit the cgroup at fork, so the aggregate envelope
                    // bounds the whole tree, not just the direct process. A
                    // failed move refuses the exec (fail-closed: a side
                    // outside its envelope is not the declared contract).
                    let mut buf = [0u8; 24];
                    let n = write_pid(libc::getpid(), &mut buf);
                    if libc::write(fd, buf.as_ptr().cast(), n) != n as isize {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                set_rlimit(libc::RLIMIT_AS, as_bytes)
                    .and_then(|_| set_rlimit_cpu(cpu_s))
                    .and_then(|_| set_rlimit(libc::RLIMIT_NOFILE, nofile))
                    .and_then(|_| set_rlimit(libc::RLIMIT_NPROC, nproc))
            });
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Every side runs in its own process group (unix) so the harness can
        // terminate the entire tree — direct process plus any descendants
        // that inherited the capture pipes — when the side exits, times out,
        // or overflows its capture cap.
        command.process_group(0);
    }

    let spawn_deadline = Instant::now() + SPAWN_RETRY_BUDGET;
    let mut child = loop {
        match command.spawn() {
            Ok(child) => break child,
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                if Instant::now() >= spawn_deadline {
                    return Err(RunError::new(format!(
                        "{} stayed busy (ETXTBSY) through the full {} ms retry budget: another process is still writing it; refusing to hang the court",
                        program.display(),
                        SPAWN_RETRY_BUDGET.as_millis()
                    )));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                return Err(RunError::new(format!(
                    "failed to execute {}: {e} (does it exist and have its executable bit set?)",
                    program.display()
                )))
            }
        }
    };
    // The side's direct child is in the cgroup: record it so the
    // finalization can tell the reaped direct process from its descendants
    // (the empty-check must never count the pid the harness itself reaped).
    if let Some(cg) = &mut cgroup {
        cg.mark_direct(child.id());
    }

    // Drain both pipes *concurrently* with the wait loop, then join before
    // returning. Reading after the child exits is a deadlock: a child that
    // fills a 64 KiB pipe blocks on write while the parent blocks on
    // try_wait, and the run fails with a false timeout. The same rule holds
    // for stdin: it is written from its own thread and then closed (EOF), so
    // a child that fills the output pipes while still consuming input cannot
    // deadlock the harness.
    let mut stdout_pipe = child.stdout.take().expect("stdout is piped");
    let mut stderr_pipe = child.stderr.take().expect("stderr is piped");
    let mut stdin_pipe = child.stdin.take();
    let stdin_bytes = stdin.map(|b| b.to_vec());
    let timeout = exec_timeout();
    let max_bytes = max_stream_bytes();
    // The process group id is the direct child's pid, captured BEFORE the
    // wait loop: after the child is reaped its pid can be reused, and the
    // group kill must target the ORIGINAL group, never whatever process got
    // the recycled pid.
    let group = child.id();
    let start = Instant::now();
    let overflow = Arc::new(AtomicBool::new(false));
    // The FIRST stream that overflowed + the observed size (the drains race;
    // one record is enough — the refusal names the bound that fired).
    let overflow_detail: Arc<Mutex<Option<(String, usize)>>> = Arc::new(Mutex::new(None));

    let (status, stdout, stderr) = std::thread::scope(|s| {
        if let (Some(mut pipe), Some(bytes)) = (stdin_pipe.take(), stdin_bytes) {
            // `pipe` is dropped when the thread ends, closing stdin: the
            // comparator sees EOF after its request.
            s.spawn(move || {
                let _ = pipe.write_all(&bytes);
            });
        }
        let drain_out = s.spawn(|| {
            drain_capped(
                &mut stdout_pipe,
                max_bytes,
                group,
                &overflow,
                &overflow_detail,
                "stdout",
            )
        });
        let drain_err = s.spawn(|| {
            drain_capped(
                &mut stderr_pipe,
                max_bytes,
                group,
                &overflow,
                &overflow_detail,
                "stderr",
            )
        });
        let mut result = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) => {
                    if start.elapsed() > timeout {
                        // Kill, reap, and let the drain threads finish once
                        // the pipes close.
                        let _ = child.kill();
                        let _ = child.wait();
                        break Err(RunError {
                            message: format!(
                                "{} exceeded the execution timeout ({} ms)",
                                program.display(),
                                timeout.as_millis()
                            ),
                            violation: Some(Box::new(HarnessViolation {
                                event_kind: "timeout",
                                target: "wall".to_string(),
                                cap: timeout.as_millis().to_string(),
                                observed: start.elapsed().as_millis().to_string(),
                                detail: String::new(),
                            })),
                        });
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => {
                    break Err(RunError::new(format!(
                        "failed to wait on {}: {e}",
                        program.display()
                    )))
                }
            }
        };
        // The direct process is gone (exited, or killed and reaped by the
        // timeout path). Terminate whatever else remains in its group so the
        // capture streams reach EOF and the drains can join: a descendant
        // holding the pipes must never block the harness. The group id was
        // captured before the wait loop (the reaped pid must not be reused
        // by a different process that would then be signaled).
        #[cfg(unix)]
        terminate_process_group(group);
        // Under v2, the process-group kill is not the end: a descendant that
        // called setsid() escaped the group but is STILL in the side's
        // cgroup. KILL the cgroup, wait for it to empty, and remove it — a
        // group that cannot be emptied refuses the run (no descendant of the
        // observed side remains alive after the observation is finalized).
        // This runs INSIDE the scope, before the drains join: a surviving
        // descendant holding the capture pipes must die here, not deadlock
        // the harness. The finalize error wins only when the run was
        // otherwise successful (the timeout/overflow refusal is already an
        // honest outcome).
        if let Some(cg) = &cgroup {
            match cg.finalize() {
                Ok(()) => {}
                Err(e) => {
                    if result.is_ok() {
                        result = Err(RunError::new(e.into_message()));
                    }
                }
            }
        }
        // `scope` joins the stdin writer + both drains here, so the captured
        // streams are complete before the caller sees them.
        (
            result,
            drain_out.join().expect("the stdout drain must join"),
            drain_err.join().expect("the stderr drain must join"),
        )
    });
    let status = status?;

    // Evidentiary overflow: a stream exceeded the profile's capture cap and
    // the side was killed. The captured bytes are TRUNCATED — recording them
    // would fabricate an observation — so the run is refused, naming the
    // bound that was enforced AND carrying the violation so the caller
    // records the content-addressed harness event.
    if overflow.load(Ordering::SeqCst) {
        let (target, observed) = overflow_detail
            .lock()
            .expect("overflow detail lock")
            .clone()
            .unwrap_or(("stdout".to_string(), max_bytes));
        return Err(RunError {
            message: format!(
                "{} exceeded the execution profile's {} byte per-stream capture cap; refusing to record truncated output as evidence",
                program.display(),
                max_bytes
            ),
            violation: Some(Box::new(HarnessViolation {
                event_kind: "stream-overflow",
                target,
                cap: max_bytes.to_string(),
                observed: observed.to_string(),
                detail: String::new(),
            })),
        });
    }

    let exit = exit_string(&status);
    // A resource-limit signal is a COMPLETE observation (the side died by
    // the bound's declared signal — the CPU limit's SIGXCPU), not a refusal:
    // the run continues and the caller records the harness event alongside.
    let violation = (exit == format!("signal({})", libc::SIGXCPU)).then(|| {
        Box::new(HarnessViolation {
            event_kind: "rlimit",
            target: "cpu".to_string(),
            cap: rlimit_cpu_s().to_string(),
            observed: exit.clone(),
            detail: "RLIMIT_CPU's deterministic signal outcome (spec/execution-profile.md)"
                .to_string(),
        })
    });
    Ok(ProcessOutcome {
        stdout,
        stderr,
        exit,
        violation,
    })
}

/// Apply one child resource limit (inside the pre-exec hook). Lowering a
/// limit never needs privilege; an inability to apply the profile's bound is
/// a harness error that aborts the exec. Linux only: the reference profile
/// is `frf-exec-linux-v1`.
#[cfg(target_os = "linux")]
fn set_rlimit(resource: libc::__rlimit_resource_t, value: u64) -> std::io::Result<()> {
    // SAFETY: setrlimit(2) is async-signal-safe; `resource` is a valid
    // resource constant.
    let rlim = libc::rlimit {
        rlim_cur: value,
        rlim_max: value,
    };
    // SAFETY: the pointer refers to a valid rlimit struct for the duration
    // of the call.
    let rc = unsafe { libc::setrlimit(resource, &rlim) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// The RLIMIT_CPU escalation window: the hard limit is set ABOVE the
/// declared soft cap so the profile's deterministic outcome — SIGXCPU,
/// whose default disposition terminates the side — is the signal the kernel
/// actually delivers first. A side that catches or blocks SIGXCPU is still
/// SIGKILLed once it burns the escalation window (the hard bound): the
/// declared cap is enforced as a hard bound either way.
#[cfg(target_os = "linux")]
const EXEC_RLIMIT_CPU_ESCALATION_S: u64 = 10;

/// Apply the CPU-time limit with the declared cap as the SOFT limit (the
/// deterministic SIGXCPU outcome) and cap + the bounded escalation window as
/// the HARD limit. Setting the hard limit lower than the inherited value is
/// always permitted (no privilege needed).
#[cfg(target_os = "linux")]
fn set_rlimit_cpu(soft_s: u64) -> std::io::Result<()> {
    let hard_s = soft_s.saturating_add(EXEC_RLIMIT_CPU_ESCALATION_S);
    // SAFETY: setrlimit(2) is async-signal-safe.
    let rlim = libc::rlimit {
        rlim_cur: soft_s,
        rlim_max: hard_s,
    };
    // SAFETY: the pointer refers to a valid rlimit struct for the duration
    // of the call.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CPU, &rlim) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Terminate every process in `pid`'s process group. The side was spawned
/// with `process_group(0)`, so its process-group id is its own pid; a
/// negative `kill(2)` targets the group. Errors (e.g. `ESRCH`, the group
/// already gone) are expected and ignored — the policy is best-effort on
/// top of the deterministic direct-process kill.
#[cfg(unix)]
fn terminate_process_group(pid: u32) {
    // SAFETY: `kill(2)` with a negative pid signals the process group whose
    // id equals `pid`; the child was placed in its own group at spawn, so
    // this reaches exactly the side's descendants. The call itself is
    // infallible from Rust's perspective; errno is deliberately ignored.
    unsafe {
        libc::kill(-(pid as i32), libc::SIGKILL);
    }
}

/// Exit code as a string, or `signal(<n>)` when the process was terminated
/// by a signal — the raw number is recorded, not a vague "signal".
fn exit_string(status: &std::process::ExitStatus) -> String {
    if let Some(code) = status.code() {
        return code.to_string();
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        status
            .signal()
            .map(|s| format!("signal({s})"))
            .unwrap_or_else(|| "signal".into())
    }
    #[cfg(not(unix))]
    {
        "signal".into()
    }
}

/// Set a file's permission bits (unix). Content-addressed objects are sealed
/// read-only after materialization — executed artifacts `0555`, data `0444`
/// — so nothing under `objects/` is owner-writable.
pub fn set_permissions(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)
            .map_err(|e| FrfError::new(format!("cannot stat {}: {e}", path.display())))?
            .permissions();
        perms.set_mode(mode);
        std::fs::set_permissions(path, perms)
            .map_err(|e| FrfError::new(format!("cannot chmod {}: {e}", path.display())))?;
    }
    Ok(())
}

/// The environment digest: the one formula, shared by capture (at
/// observation time) and OpenReceipt semantic verification (rederived from
/// the receipt's own environment fields). `FRF/ENVIRONMENT/v2` over the
/// canonical-JSON document of the host strata that actually move side output
/// (os, architecture, kernel release, the effective locale, the timezone,
/// the umask) AND the DECLARED execution environment map — a declared
/// variable is content-addressed input, so two observations under different
/// declared environments are different observations.
pub fn environment_digest(
    os: &str,
    architecture: &str,
    kernel_release: &str,
    locale: &str,
    timezone: &str,
    umask: &str,
    environment: &std::collections::BTreeMap<String, String>,
) -> String {
    let doc = serde_json::json!({
        "os": os,
        "architecture": architecture,
        "kernel_release": kernel_release,
        "locale": locale,
        "timezone": timezone,
        "umask": umask,
        "environment": environment,
    });
    let canonical = crate::canon::canonical(&doc)
        .expect("the environment identity document is protocol-canonicalizable");
    sha256_bytes(format!("FRF/ENVIRONMENT/v2\n{canonical}").as_bytes())
}

/// The effective locale the sides run under: the DECLARED `LC_ALL`, else
/// `LC_CTYPE`, else `LANG`, else `C` (the POSIX default that applies when
/// none is declared). The side's environment is the court's declared
/// environment — the ambient host locale is irrelevant to the observation.
pub fn effective_locale(environment: &std::collections::BTreeMap<String, String>) -> String {
    environment
        .get("LC_ALL")
        .filter(|v| !v.is_empty())
        .or_else(|| environment.get("LC_CTYPE").filter(|v| !v.is_empty()))
        .or_else(|| environment.get("LANG").filter(|v| !v.is_empty()))
        .cloned()
        .unwrap_or_else(|| "C".to_string())
}

/// The timezone the sides run under: the DECLARED `TZ`, else the resolved
/// system zone (when /etc/localtime is a symlink into zoneinfo, its tail —
/// e.g. `Europe/London`), else a digest of the zone file's bytes, else
/// `unknown`.
pub fn timezone(environment: &std::collections::BTreeMap<String, String>) -> String {
    if let Some(tz) = environment.get("TZ") {
        if !tz.is_empty() {
            return tz.clone();
        }
    }
    if let Ok(canonical) = std::fs::canonicalize("/etc/localtime") {
        let path = canonical.to_string_lossy();
        if let Some(idx) = path.rfind("zoneinfo/") {
            return path[idx + "zoneinfo/".len()..].to_string();
        }
        if let Ok(bytes) = std::fs::read(&canonical) {
            return format!("tz:{}", &sha256_bytes(&bytes)[..16]);
        }
    }
    "unknown".to_string()
}

/// The process umask at observation time, as octal digits (`0022`).
/// Momentarily set-and-restored — the court is single-threaded at this
/// point, before any side is spawned.
pub fn umask() -> String {
    #[cfg(unix)]
    {
        // SAFETY: umask(2) returns the previous mask and takes the new one;
        // restoring the returned value leaves the process mask unchanged.
        let mask = unsafe { libc::umask(0) };
        unsafe {
            libc::umask(mask);
        }
        format!("{mask:04o}")
    }
    #[cfg(not(unix))]
    {
        "0000".to_string()
    }
}

/// The minimal execution environment: the deterministic baseline used where
/// no court declaration exists (standalone extension invocations such as
/// witness attestation). The ambient host environment is never inherited —
/// it is not evidence — so a standalone program sees exactly this fixed
/// map: a PATH that resolves the standard system utilities (the env(1)
/// resolver needs it for `#!/usr/bin/env` shebangs), and nothing else.
pub fn minimal_execution_environment() -> std::collections::BTreeMap<String, String> {
    let mut env = std::collections::BTreeMap::new();
    env.insert("PATH".to_string(), "/usr/bin:/bin".to_string());
    env
}

/// The environment an observation happens in, captured at court time: os,
/// architecture, kernel release, locale, timezone, umask, the DECLARED
/// execution environment the sides ran under (the exact map the harness
/// spawned them with — the ambient host environment is never inherited and
/// never recorded), the working directory, and the digest over the
/// output-moving strata AND the declared environment. The receipt copies
/// this identity verbatim — it never asks its own host what environment an
/// old court ran under.
pub fn environment_identity(
    environment: &std::collections::BTreeMap<String, String>,
) -> EnvironmentIdentity {
    let os = std::env::consts::OS.to_string();
    let architecture = std::env::consts::ARCH.to_string();
    let kernel_release = kernel_release();
    let locale = effective_locale(environment);
    let timezone = timezone(environment);
    let umask = umask();
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "unknown".to_string());
    let digest = environment_digest(
        &os,
        &architecture,
        &kernel_release,
        &locale,
        &timezone,
        &umask,
        environment,
    );
    EnvironmentIdentity {
        schema_version: crate::model::SCHEMA_ENVIRONMENT.to_string(),
        os,
        architecture,
        kernel_release,
        locale,
        timezone,
        umask,
        cwd,
        environment: environment.clone(),
        digest,
    }
}

/// Bind the interpreter CHAIN a script artifact executes under: what the
/// kernel directly invoked (the first shebang token), the raw shebang
/// argument bytes (verbatim evidence), the env resolver when the kernel
/// interpreter is env(1), and the downstream language interpreter. For a
/// script, "the exact artifact" is bytes + this chain; binaries (no shebang)
/// yield `None`.
///
/// An interpreter that cannot be resolved or hashed is an error: the
/// exact-artifact claim is the point, and an unbound interpreter would leave
/// it unverifiable.
pub fn interpreter_identity(artifact: &[u8]) -> Result<Option<InterpreterIdentity>> {
    let Some(first_line) = artifact.split(|b| *b == b'\n').next() else {
        return Ok(None);
    };
    if first_line.len() < 2 || first_line[0] != b'#' || first_line[1] != b'!' {
        return Ok(None);
    }
    let line = String::from_utf8_lossy(first_line);
    let mut tokens = line[2..].split_whitespace();
    let Some(kernel_token) = tokens.next() else {
        return Ok(None);
    };
    let kernel = resolve_interpreter(kernel_token)?;
    // Raw argument bytes after the interpreter token, verbatim.
    let arg_start = 2 + kernel_token.len();
    let shebang_argument_bytes = line[arg_start..].trim().to_string();

    // Is the kernel interpreter env(1)? Then the downstream interpreter is
    // the first token that is neither an option nor a VAR=value assignment.
    let is_env = kernel_token == "env" || kernel_token.ends_with("/env");
    if is_env {
        let downstream_token = tokens
            .find(|t| !t.starts_with('-') && (!t.contains('=') || t.starts_with('=')))
            .ok_or_else(|| FrfError::new("env shebang without a downstream interpreter"))?;
        let path_digest = {
            let path = std::env::var_os("PATH").unwrap_or_default();
            sha256_bytes(path.to_string_lossy().as_bytes())
        };
        Ok(Some(InterpreterIdentity {
            kernel_interpreter: kernel.clone(),
            shebang_argument_bytes,
            resolver: Some(InterpreterResolver {
                kind: "env".to_string(),
                path: kernel.path.clone(),
                sha256: kernel.sha256.clone(),
                path_digest,
            }),
            downstream_interpreter: resolve_interpreter(downstream_token)?,
        }))
    } else {
        Ok(Some(InterpreterIdentity {
            kernel_interpreter: kernel.clone(),
            shebang_argument_bytes,
            resolver: None,
            downstream_interpreter: kernel,
        }))
    }
}

/// Resolve one shebang token to an executable: absolute path as-is, bare
/// name via PATH lookup; then canonicalize and hash.
fn resolve_interpreter(token: &str) -> Result<InterpreterExecutable> {
    let resolved = if token.contains('/') {
        PathBuf::from(token)
    } else {
        let path_var = std::env::var_os("PATH").unwrap_or_default();
        std::env::split_paths(&path_var)
            .map(|dir| dir.join(token))
            .find(|candidate| candidate.is_file())
            .ok_or_else(|| {
                FrfError::new(format!(
                    "interpreter '{token}' from the shebang was not found on PATH"
                ))
            })?
    };
    let canonical = resolved.canonicalize().map_err(|e| {
        FrfError::new(format!(
            "cannot resolve interpreter {}: {e}",
            resolved.display()
        ))
    })?;
    let sha256 = sha256_file(&canonical)?;
    Ok(InterpreterExecutable {
        path: canonical.to_string_lossy().into_owned(),
        sha256,
    })
}

/// Kernel release via `uname -r`; `unknown` if unavailable.
pub fn kernel_release() -> String {
    Command::new("uname")
        .arg("-r")
        .output()
        .ok()
        .and_then(|out| {
            out.status
                .success()
                .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Unique per-invocation temp script path: pid + monotonic nanos, so
    /// parallel test threads and recycled pids can never collide and panicked
    /// runs never poison a later one.
    fn temp_script(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("frf-{tag}-{}-{nanos}.sh", std::process::id()))
    }

    /// The DECLARED execution environment for tests: a minimal map with a
    /// PATH (scripts that invoke external utilities — cat, etc. — need it;
    /// the ambient host environment is never inherited by a spawned child).
    fn test_env() -> std::collections::BTreeMap<String, String> {
        let mut e = std::collections::BTreeMap::new();
        e.insert("PATH".to_string(), "/usr/bin:/bin".to_string());
        e
    }

    /// Runs `body` with the given environment overrides set, restoring (or
    /// removing) the prior values afterwards. Test threads share the process
    /// environment, so hook-dependent tests must isolate themselves with this
    /// instead of calling `std::env::set_var` directly. The global hook lock
    /// serializes every test that reads or writes the execution hooks: an
    /// override from one thread would otherwise leak into a concurrently
    /// running test that reads the same variable mid-flight.
    static HOOK_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_env<T>(overrides: &[(&str, &str)], body: impl FnOnce() -> T) -> T {
        // Recover from a poisoned lock: a test that panicked inside an
        // earlier body already restored the environment before resuming its
        // unwind (the restore loop runs before the resume), so the
        // environment is consistent and the suite can continue.
        let _guard = match HOOK_LOCK.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let mut prior: Vec<(&str, Option<std::ffi::OsString>)> = Vec::new();
        for (k, v) in overrides {
            prior.push((k, std::env::var_os(k)));
            std::env::set_var(k, v);
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body));
        for (k, v) in prior {
            match v {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
        match result {
            Ok(value) => value,
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }

    /// Runs `body` under the hook lock without overriding anything: the test
    /// observes the profile defaults and must not race another thread's
    /// temporary override.
    fn with_default_hooks<T>(body: impl FnOnce() -> T) -> T {
        with_env(&[], body)
    }

    #[test]
    fn sha256_is_hex_and_stable() {
        let a = sha256_bytes(b"the quick brown fox");
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(a, sha256_bytes(b"the quick brown fox"));
    }

    #[test]
    fn runs_a_script_and_captures_exit_code() {
        let script = temp_script("host");
        std::fs::write(&script, "#!/bin/sh\necho out\necho err >&2\nexit 7\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let out = run_process(
            &ExecImage::from_path(&script),
            &[],
            ExecProfile::LinuxV1,
            &test_env(),
            None,
        )
        .unwrap();
        assert_eq!(out.exit, "7");
        assert_eq!(out.stdout.bytes(), b"out\n");
        assert_eq!(out.stderr.bytes(), b"err\n");
        let _ = std::fs::remove_file(&script);
    }

    /// The verify→execute race is closed: a SEALED image executes the exact
    /// verified bytes even when the materialized path it would otherwise be
    /// re-opened from is replaced by the same OS user between verification
    /// and execution. The executed image is the sealed memfd, never the
    /// pathname.
    #[test]
    fn sealed_image_runs_the_exact_verified_bytes() {
        let materialized = temp_script("sealed-argv0");
        let bytes_a = b"#!/bin/sh\necho sealed-A\n".to_vec();
        std::fs::write(&materialized, &bytes_a).unwrap();
        let hash_a = sha256_bytes(&bytes_a);
        let image = ExecImage::seal(&bytes_a, &hash_a, &materialized).unwrap();

        let out = run_process(&image, &[], ExecProfile::LinuxV1, &test_env(), None).unwrap();
        assert_eq!(out.exit, "0");
        assert_eq!(
            out.stdout.bytes(),
            b"sealed-A\n",
            "the sealed bytes must run"
        );
        assert_eq!(
            image.argv0(),
            materialized.as_path(),
            "argv[0] is the materialized snapshot path, never /proc/self/fd/<n>"
        );

        // The same OS user replaces the materialized path AFTER verification
        // and BEFORE execution. A path-based exec would run the tampered
        // bytes; the sealed image still runs the verified bytes.
        std::fs::write(&materialized, b"#!/bin/sh\necho TAMPERED\n").unwrap();
        let out2 = run_process(&image, &[], ExecProfile::LinuxV1, &test_env(), None).unwrap();
        assert_eq!(
            out2.stdout.bytes(),
            b"sealed-A\n",
            "the executed image must be the sealed verified bytes, not the mutated pathname"
        );
        let _ = std::fs::remove_file(&materialized);
    }

    /// Defense in depth: the bytes being sealed must BE the verified bytes.
    /// Sealing unverified bytes would re-open the race under a new name.
    #[test]
    fn sealing_refuses_unverified_bytes() {
        let materialized = temp_script("sealed-refuse");
        let bytes = b"#!/bin/sh\necho x\n".to_vec();
        std::fs::write(&materialized, &bytes).unwrap();
        let wrong = "0".repeat(64);
        let err = ExecImage::seal(&bytes, &wrong, &materialized)
            .unwrap_err()
            .into_message();
        assert!(err.contains("refusing to seal"), "error: {err}");
        let _ = std::fs::remove_file(&materialized);
    }

    /// The memfd is sealed before it may be executed: F_GET_SEALS reports
    /// the write/grow/shrink seals and the permanent F_SEAL_SEAL.
    #[cfg(target_os = "linux")]
    #[test]
    fn sealed_image_reports_the_required_seals() {
        let materialized = temp_script("sealed-seals");
        let bytes = b"#!/bin/sh\necho s\n".to_vec();
        std::fs::write(&materialized, &bytes).unwrap();
        let hash = sha256_bytes(&bytes);
        let image = ExecImage::seal(&bytes, &hash, &materialized).unwrap();
        let seals = image.seals().expect("sealed image must report its seals");
        let required =
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        assert_eq!(
            seals & required,
            required,
            "the image must be permanently sealed (reported seals {seals})"
        );
        let _ = std::fs::remove_file(&materialized);
    }

    /// The declared profile property for scripts: the kernel executes a
    /// shebang script via its image path, so a script observes the sealed
    /// image path as $0 (the args are preserved exactly). Native binaries
    /// keep argv[0] via arg0. This pins the property as declared, not
    /// accidental.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_sealed_script_observes_its_image_path_as_zero() {
        let materialized = temp_script("sealed-zero");
        let bytes = br#"#!/bin/sh
echo "zero=$0 one=$1"
"#
        .to_vec();
        std::fs::write(&materialized, &bytes).unwrap();
        let hash = sha256_bytes(&bytes);
        let image = ExecImage::seal(&bytes, &hash, &materialized).unwrap();
        let out = run_process(
            &image,
            &["argX".to_string()],
            ExecProfile::LinuxV1,
            &test_env(),
            None,
        )
        .unwrap();
        let stdout_bytes = out.stdout.bytes();
        let stdout = String::from_utf8_lossy(&stdout_bytes);
        let stdout = stdout.trim();
        assert!(
            stdout.starts_with("zero=/proc/self/fd/"),
            "a sealed script observes its image path as $0, got {stdout:?}"
        );
        assert!(
            stdout.ends_with("one=argX"),
            "the args are preserved, got {stdout:?}"
        );
        let _ = std::fs::remove_file(&materialized);
    }

    // -- cgroup v2 (frf-exec-linux-v2) ---------------------------------------

    /// A fake cgroup v2 root for the regression suite: a writable temp dir
    /// with the v2 root marker and pre-created controller files (the real
    /// cgroupfs would provide them).
    fn fake_cgroup_root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "frf-cgroup-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("cgroup.controllers"),
            "cpuset cpu io memory pids\n",
        )
        .unwrap();
        dir
    }

    /// The v2 profile REFUSES when no writable cgroup v2 subtree exists: a
    /// declared profile is enforced, never approximated. The `none` hook
    /// forces the path deterministically on any host.
    #[test]
    fn the_v2_profile_refuses_without_a_writable_cgroup_root() {
        let script = temp_script("v2-refuse");
        std::fs::write(&script, "#!/bin/sh\necho hi\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        with_env(&[("FRF_CGROUP2_ROOT", "none")], || {
            let err = run_process(
                &ExecImage::from_path(&script),
                &[],
                ExecProfile::LinuxV2,
                &test_env(),
                None,
            )
            .unwrap_err()
            .message;
            assert!(
                err.contains("no writable cgroup v2 subtree"),
                "error: {err}"
            );
        });
        let _ = std::fs::remove_file(&script);
    }

    /// The hook root must actually be a cgroup v2 root.
    #[test]
    fn the_v2_profile_rejects_a_non_cgroup_hook_root() {
        let script = temp_script("v2-badroot");
        std::fs::write(&script, "#!/bin/sh\necho hi\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let not_a_root = std::env::temp_dir().join("frf-not-a-cgroup-root");
        std::fs::create_dir_all(&not_a_root).unwrap();
        with_env(
            &[("FRF_CGROUP2_ROOT", not_a_root.to_str().unwrap())],
            || {
                let err = run_process(
                    &ExecImage::from_path(&script),
                    &[],
                    ExecProfile::LinuxV2,
                    &test_env(),
                    None,
                )
                .unwrap_err()
                .message;
                assert!(err.contains("not a cgroup v2 root"), "error: {err}");
            },
        );
        let _ = std::fs::remove_file(&script);
        let _ = std::fs::remove_dir_all(&not_a_root);
    }

    /// The v2 profile applies the AGGREGATE envelope: the side's whole tree
    /// runs in its own group with pids.max / memory.max / cpu.max written
    /// and the side's own pid moved in (the pre_exec self-move), and the
    /// group is removed once the side is reaped.
    #[test]
    fn the_v2_profile_applies_the_aggregate_envelope() {
        let root = fake_cgroup_root("envelope");
        let script = temp_script("v2-envelope");
        // The side reports its own pid and what the harness wrote into its
        // group (the fake root path is inherited through the environment).
        let body = "#!/bin/sh\n\
             echo my_pid=$$\n\
             echo procs=$(cat \"$FRF_CGROUP2_ROOT\"/frf/*/cgroup.procs)\n\
             echo pids_max=$(cat \"$FRF_CGROUP2_ROOT\"/frf/*/pids.max)\n\
             echo memory_max=$(cat \"$FRF_CGROUP2_ROOT\"/frf/*/memory.max)\n\
             echo cpu_max=$(cat \"$FRF_CGROUP2_ROOT\"/frf/*/cpu.max)\n";
        std::fs::write(&script, body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        with_env(&[("FRF_CGROUP2_ROOT", root.to_str().unwrap())], || {
            // The child also needs the hook root IN ITS OWN declared
            // environment: the ambient host environment is never inherited,
            // and the fake root path travels as a declared variable.
            let mut env = test_env();
            env.insert(
                "FRF_CGROUP2_ROOT".to_string(),
                root.to_str().unwrap().to_string(),
            );
            let out = run_process(
                &ExecImage::from_path(&script),
                &[],
                ExecProfile::LinuxV2,
                &env,
                None,
            )
            .unwrap();
            assert_eq!(out.exit, "0");
            let stdout_bytes = out.stdout.bytes();
            let text = String::from_utf8_lossy(&stdout_bytes);
            let mut my_pid = "";
            let mut procs = "";
            let mut pids_max = "";
            let mut memory_max = "";
            let mut cpu_max = "";
            for line in text.lines() {
                if let Some(v) = line.strip_prefix("my_pid=") {
                    my_pid = v;
                } else if let Some(v) = line.strip_prefix("procs=") {
                    procs = v;
                } else if let Some(v) = line.strip_prefix("pids_max=") {
                    pids_max = v;
                } else if let Some(v) = line.strip_prefix("memory_max=") {
                    memory_max = v;
                } else if let Some(v) = line.strip_prefix("cpu_max=") {
                    cpu_max = v;
                }
            }
            assert_eq!(
                procs.trim(),
                my_pid,
                "the side must have moved ITSELF into its cgroup before exec (procs={procs:?} my_pid={my_pid:?}); full output: {text:?}"
            );
            assert_eq!(
                pids_max.trim(),
                CGROUP2_PIDS_MAX.to_string(),
                "the aggregate pids.max must be applied"
            );
            assert_eq!(
                memory_max.trim(),
                CGROUP2_MEMORY_MAX.to_string(),
                "the aggregate memory.max must be applied"
            );
            assert_eq!(
                cpu_max.trim(),
                CGROUP2_CPU_MAX,
                "the aggregate cpu.max must be applied"
            );
        });
        // The group is removed once the side is reaped: nothing lingers.
        let leftover = std::fs::read_dir(root.join("frf"))
            .map(|it| it.flatten().count())
            .unwrap_or(0);
        assert_eq!(
            leftover, 0,
            "the per-side cgroup must be removed after the run"
        );
        assert_eq!(
            leftover, 0,
            "the per-side cgroup must be removed after the run"
        );
        let _ = std::fs::remove_file(&script);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Priority 5 — finalize KILLS the group, it does not merely remove the
    /// directory. A member that survived the process-group kill (it called
    /// setsid()) is still in the side's cgroup; finalize must SIGKILL it,
    /// reap the reparented orphan, wait for the group to empty, and only
    /// then remove the group.
    #[test]
    fn finalize_kills_a_member_that_survived_the_process_group() {
        ensure_subreaper();
        let root = fake_cgroup_root("finalize-kill");
        let cg = CgroupV2::create(&root, "frf-test").unwrap();
        // A live process NOT in our process group (the setsid() escapee
        // analogue): a long sleep. Its wrapper parent exits immediately, so
        // the sleep reparents to the harness (the child subreaper) — the way
        // a side's orphaned descendants reparent to the real harness. Nobody
        // else holds a handle on it, so finalize's per-member reap is the
        // only collector. The pid is written to a file — the background
        // sleep inherits the wrapper's stdout, so the harness must not wait
        // on a pipe the sleep holds.
        let pidfile = temp_script("orphan-pid");
        let script = format!("sleep 30 & echo $! > {0}", pidfile.display());
        std::process::Command::new("sh")
            .arg("-c")
            .arg(&script)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        let pid: libc::pid_t = {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            let mut pid = None;
            while std::time::Instant::now() < deadline {
                if let Ok(text) = std::fs::read_to_string(&pidfile) {
                    if let Ok(p) = text.trim().parse() {
                        pid = Some(p);
                        break;
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            pid.expect("the wrapper must print the sleep's pid")
        };
        std::fs::write(cg.dir.join("cgroup.procs"), format!("{pid}\n")).unwrap();

        cg.finalize().expect("finalize must empty the group");

        // The member was SIGKILLed and reaped by the finalization (a
        // kill(pid, 0) probe now answers no — the zombie was collected).
        assert!(
            !pid_exists(pid),
            "the cgroup member must be SIGKILLed and reaped by finalize"
        );
        // The group was removed only after it emptied.
        assert!(!cg.dir.exists(), "the emptied cgroup must be removed");
        let _ = std::fs::remove_file(&pidfile);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Priority 5 — a group that cannot be emptied is a run REFUSAL, never
    /// ignored cleanup. A ZOMBIE owned by a live, non-reaping parent cannot
    /// be SIGKILLed (it is already dead) and is not the harness's child, so
    /// the per-member reap cannot collect it: the group cannot empty, and
    /// finalize must refuse.
    #[test]
    fn finalize_refuses_a_group_it_cannot_empty() {
        ensure_subreaper();
        let root = fake_cgroup_root("finalize-refuse");
        let cg = CgroupV2::create(&root, "frf-test").unwrap();
        // `sh -c 'sleep 0.05 & echo $! > FILE; exec sleep 30'`: the shell
        // execs into a long sleep (30s, same pid), so the 50ms background
        // sleep's zombie is owned by the exec'd sleep — alive and never
        // waitpid()ing. It is not the harness's child (its parent never
        // died), so finalize can neither kill it nor reap it. The pid is
        // written to a file — the exec'd sleep holds the stdout pipe open
        // for 30s, so the harness must not wait on it.
        let pidfile = temp_script("zombie-pid");
        let script = format!(
            "sleep 0.05 & echo $! > {0}; exec sleep 30",
            pidfile.display()
        );
        let mut child = std::process::Command::new("sh")
            .arg("-c")
            .arg(&script)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let owner = child.id() as libc::pid_t;
        let zombie: libc::pid_t = {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            let mut pid = None;
            while std::time::Instant::now() < deadline {
                if let Ok(text) = std::fs::read_to_string(&pidfile) {
                    if let Ok(p) = text.trim().parse() {
                        pid = Some(p);
                        break;
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            pid.expect("the wrapper must print the zombie's pid")
        };
        // Wait for the 50ms sleep to exit (become a zombie).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut is_zombie = false;
        while std::time::Instant::now() < deadline {
            if let Ok(stat) = std::fs::read_to_string(format!("/proc/{zombie}/stat")) {
                if stat.split_whitespace().nth(2) == Some("Z") {
                    is_zombie = true;
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(is_zombie, "the short sleep must become a zombie");
        std::fs::write(cg.dir.join("cgroup.procs"), format!("{zombie}\n")).unwrap();

        let err = cg
            .finalize()
            .expect_err("an unemptyable group must refuse")
            .into_message();
        assert!(
            err.contains("could not be emptied"),
            "the refusal must name the empty failure: {err}"
        );

        // Cleanup: kill the exec'd sleep (the zombie's owner); the zombie
        // then reparents to the harness (this process is the subreaper) and
        // both are reaped there.
        // SAFETY: kill(2) with a positive pid signals exactly that process.
        unsafe {
            libc::kill(owner, libc::SIGKILL);
        }
        let _ = child.wait();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline && pid_exists(zombie) {
            reap_member(zombie);
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let _ = std::fs::remove_file(&pidfile);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_program_is_a_clear_error() {
        let err = run_process(
            &ExecImage::from_path(Path::new("/nonexistent/frf-nope")),
            &[],
            ExecProfile::LinuxV1,
            &test_env(),
            None,
        )
        .unwrap_err();
        assert!(err.message.contains("failed to execute"));
    }

    #[test]
    fn drains_large_output_without_deadlock() {
        // ~820 KiB of stdout: far beyond the 64 KiB pipe buffer. The old
        // read-after-exit runner would block on try_wait forever and false-
        // timeout; the concurrent drain must return the full stream.
        let script = temp_script("drain");
        std::fs::write(
            &script,
            "#!/bin/sh\nawk 'BEGIN{for(i=0;i<20000;i++) print \"0123456789abcdefghijklmnopqrstuvwxyz0123456789\"}'\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        with_default_hooks(|| {
            let out = run_process(
                &ExecImage::from_path(&script),
                &[],
                ExecProfile::LinuxV1,
                &test_env(),
                None,
            )
            .unwrap();
            assert_eq!(
                out.exit,
                "0",
                "expected exit 0; stderr={:?}",
                String::from_utf8_lossy(&out.stderr.bytes())
            );
            let line = "0123456789abcdefghijklmnopqrstuvwxyz0123456789";
            assert_eq!(
                out.stdout.length as usize,
                (line.len() + 1) * 20_000,
                "full stream must be drained; stderr={:?}",
                String::from_utf8_lossy(&out.stderr.bytes())
            );
            assert!(out.stderr.is_empty());
        });
        let _ = std::fs::remove_file(&script);
    }

    #[test]
    fn a_large_stream_spills_and_stays_exact() {
        // The streaming capture path: a stream beyond the in-memory threshold
        // spills to a temp file as it is read, and the outcome still carries
        // the EXACT bytes, the incremental SHA-256, the first line, and the
        // length — the evidence projections derive from the exact stream.
        // ~820 KiB is far beyond STREAM_INLINE_LIMIT, so the drain MUST have
        // taken the spill path.
        let script = temp_script("spill");
        std::fs::write(
            &script,
            "#!/bin/sh\nawk 'BEGIN{for(i=0;i<20000;i++) print \"0123456789abcdefghijklmnopqrstuvwxyz0123456789\"}'\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        with_default_hooks(|| {
            let out = run_process(
                &ExecImage::from_path(&script),
                &[],
                ExecProfile::LinuxV1,
                &test_env(),
                None,
            )
            .unwrap();
            assert_eq!(out.exit, "0");
            let line = "0123456789abcdefghijklmnopqrstuvwxyz0123456789";
            let expected: Vec<u8> = (0..20_000)
                .flat_map(|_| {
                    let mut l = line.as_bytes().to_vec();
                    l.push(b'\n');
                    l
                })
                .collect();
            assert!(
                expected.len() > STREAM_INLINE_LIMIT,
                "the fixture must spill"
            );
            // The exact bytes round-trip (inline or spilled, same contract).
            assert_eq!(out.stdout.bytes(), expected);
            // The incremental digest equals the whole-stream digest.
            assert_eq!(out.stdout.sha256, sha256_bytes(&expected));
            // The first line is the exact projection.
            assert_eq!(out.stdout.first_line, line);
            assert_eq!(out.stdout.length, expected.len() as u64);
        });
        let _ = std::fs::remove_file(&script);
    }

    #[cfg(unix)]
    #[test]
    fn records_the_signal_number() {
        let script = temp_script("signal");
        std::fs::write(&script, "#!/bin/sh\nkill -TERM $$\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let out = run_process(
            &ExecImage::from_path(&script),
            &[],
            ExecProfile::LinuxV1,
            &test_env(),
            None,
        )
        .unwrap();
        assert_eq!(out.exit, "signal(15)");
        let _ = std::fs::remove_file(&script);
    }

    #[cfg(unix)]
    #[test]
    fn persistently_busy_executable_fails_within_the_retry_budget() {
        // A file held open for writing cannot be exec'd: the kernel answers
        // ETXTBSY. The spawn retry must give up within its own budget
        // instead of looping forever (the old behavior hung the court when
        // the writer never finished).
        let script = temp_script("busy");
        std::fs::write(&script, "#!/bin/sh\necho hi\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let held = std::fs::OpenOptions::new()
            .write(true)
            .open(&script)
            .unwrap();
        let start = Instant::now();
        let err = run_process(
            &ExecImage::from_path(&script),
            &[],
            ExecProfile::LinuxV1,
            &test_env(),
            None,
        )
        .unwrap_err();
        drop(held);
        assert!(err.message.contains("ETXTBSY"), "error: {}", err.message);
        assert!(
            start.elapsed() < SPAWN_RETRY_BUDGET * 3,
            "retry must be bounded (took {:?})",
            start.elapsed()
        );
        let _ = std::fs::remove_file(&script);
    }

    #[cfg(unix)]
    #[test]
    fn descendants_cannot_hold_the_capture_pipes_open() {
        // The direct child exits immediately, leaving a grandchild holding
        // stdout/stderr open for 3 s. Without the process-group termination
        // policy the harness would block on EOF until the grandchild exits;
        // with it, the group is killed the moment the direct process is
        // reaped and the drains close at once.
        let script = temp_script("descendant");
        std::fs::write(&script, "#!/bin/sh\nsleep 3 &\necho child-done\nexit 0\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        // The timer starts AFTER the hook lock: in the parallel suite another
        // test may hold the env-override lock, and the elapsed must measure
        // the RUN, not the lock wait.
        let _ = with_default_hooks(|| {
            let start = Instant::now();
            let out = run_process(
                &ExecImage::from_path(&script),
                &[],
                ExecProfile::LinuxV1,
                &test_env(),
                None,
            )
            .unwrap();
            assert_eq!(out.exit, "0");
            assert_eq!(
                String::from_utf8_lossy(&out.stdout.bytes()).trim(),
                "child-done"
            );
            assert!(
                start.elapsed() < Duration::from_millis(1500),
                "harness must not wait for a descendant to release the pipes (took {:?})",
                start.elapsed()
            );
            out
        });
        let _ = std::fs::remove_file(&script);
    }

    #[test]
    fn capture_overflow_refuses_instead_of_truncating() {
        // The execution profile bounds each stream; a side that exceeds the
        // cap is killed and the run REFUSED — the truncated bytes must never
        // become evidence. The tiny cap makes the path cheap to exercise.
        with_env(&[("FRF_EXEC_MAX_BYTES", "1024")], || {
            let script = temp_script("overflow");
            std::fs::write(
                &script,
                "#!/bin/sh\nawk 'BEGIN{for(i=0;i<1000;i++) print \"0123456789abcdefghijklmnopqrstuvwxyz\"}'\n",
            )
            .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            let start = Instant::now();
            let err = run_process(
                &ExecImage::from_path(&script),
                &[],
                ExecProfile::LinuxV1,
                &test_env(),
                None,
            )
            .unwrap_err();
            assert!(
                err.message.contains("capture cap")
                    && err.message.contains("refusing to record truncated output"),
                "the overflow must refuse the run, naming the cap: {}",
                err.message
            );
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "the overflow path must terminate the side promptly (took {:?})",
                start.elapsed()
            );
            let _ = std::fs::remove_file(&script);
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_cpu_limit_terminates_a_cpu_bound_side() {
        // The profile's RLIMIT_CPU is applied in the child: a CPU-bound side
        // hits it and dies by the profile's deterministic signal outcome
        // (SIGXCPU, or SIGKILL once the hard limit is reached — the exact
        // signal is kernel-dependent; the property is that the resource bound
        // terminates the side before the wall-clock timeout). The 1-second
        // override keeps the test fast.
        with_env(
            &[
                ("FRF_EXEC_RLIMIT_CPU_S", "1"),
                ("FRF_EXEC_TIMEOUT_MS", "20000"),
            ],
            || {
                let script = temp_script("cpu-limit");
                std::fs::write(&script, "#!/bin/sh\nwhile :; do :; done\n").unwrap();
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
                let start = Instant::now();
                let out = run_process(
                    &ExecImage::from_path(&script),
                    &[],
                    ExecProfile::LinuxV1,
                    &test_env(),
                    None,
                )
                .unwrap();
                assert!(
                    out.exit.starts_with("signal("),
                    "the CPU limit must terminate the side by signal, got {:?}",
                    out.exit
                );
                // v19: the soft/hard split makes the profile's DETERMINISTIC
                // outcome — SIGXCPU (signal 24 on Linux), whose default
                // disposition terminates — the signal actually delivered, and
                // the harness records the bound-firing violation alongside
                // the complete observation.
                assert_eq!(
                    out.exit,
                    format!("signal({})", libc::SIGXCPU),
                    "the CPU bound's deterministic outcome is SIGXCPU, got {:?}",
                    out.exit
                );
                let v = out
                    .violation
                    .as_ref()
                    .expect("a resource-limit signal carries the violation");
                assert_eq!(v.event_kind, "rlimit");
                assert_eq!(v.target, "cpu");
                assert_eq!(v.cap, "1", "the declared cap as enforced");
                assert!(
                    start.elapsed() < Duration::from_secs(15),
                    "the CPU limit must bite before the wall-clock timeout (took {:?})",
                    start.elapsed()
                );
                let _ = std::fs::remove_file(&script);
            },
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_process_limit_is_applied_in_the_child() {
        // The profile's RLIMIT_NPROC is applied before exec: the side sees
        // its own declared process-count cap (a hostile side cannot fork a
        // process bomb that exhausts the user's process table while the
        // harness waits for its own timeout). The limit is read from
        // `/proc/self/limits` — deterministic, instant, and SHELL-AGNOSTIC
        // (`ulimit -u` is a bash/zsh extension; dash — /bin/sh on Debian and
        // Ubuntu — does not implement it, so a script that depends on it
        // fails on exactly the machines CI runs on).
        with_env(&[("FRF_EXEC_RLIMIT_NPROC", "42")], || {
            let script = temp_script("nproc-cap");
            // Read the limit with shell BUILTINS only (`read` + `echo`, no
            // external commands): RLIMIT_NPROC caps new processes for the
            // calling process's real UID, so once the cap is set the side may
            // be unable to fork even a single `cat` on a busy machine. A
            // `while read` loop needs no fork at all.
            std::fs::write(
                &script,
                "#!/bin/sh\nwhile read -r line; do echo \"$line\"; done < /proc/self/limits\n",
            )
            .unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
            let out = run_process(
                &ExecImage::from_path(&script),
                &[],
                ExecProfile::LinuxV1,
                &test_env(),
                None,
            )
            .unwrap();
            let stdout_bytes = out.stdout.bytes();
            let text = String::from_utf8_lossy(&stdout_bytes);
            let line = text
                .lines()
                .find(|l| l.contains("Max processes"))
                .unwrap_or_else(|| panic!("no Max processes line in /proc/self/limits: {text}"));
            assert!(
                line.split_whitespace().any(|tok| tok == "42"),
                "the child must run under its declared process-count cap; got {line:?}"
            );
            let _ = std::fs::remove_file(&script);
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_fork_bomb_cannot_outlive_the_wall_clock_bound() {
        // A side that forks without bound hits the process-count limit: its
        // forks fail (the shell may retry), it cannot create an unbounded
        // number of processes, and the harness's wall-clock deadline + group
        // kill terminate it — a fork bomb never hangs the court past the
        // profile's bound. The short timeout keeps the test fast.
        with_env(
            &[
                ("FRF_EXEC_RLIMIT_NPROC", "32"),
                ("FRF_EXEC_TIMEOUT_MS", "3000"),
            ],
            || {
                let script = temp_script("fork-bomb");
                std::fs::write(
                    &script,
                    "#!/bin/sh\ni=0\nwhile [ $i -lt 2000 ]; do sh -c 'sleep 1' & i=$((i+1)); done\nwait\n",
                )
                .unwrap();
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
                let start = Instant::now();
                // The side is bounded (its forks fail) and the harness returns
                // at the wall-clock deadline at the latest.
                let _ = run_process(
                    &ExecImage::from_path(&script),
                    &[],
                    ExecProfile::LinuxV1,
                    &test_env(),
                    None,
                );
                assert!(
                    start.elapsed() < Duration::from_secs(8),
                    "a fork bomb must not outlive the profile's wall-clock bound (took {:?})",
                    start.elapsed()
                );
                let _ = std::fs::remove_file(&script);
            },
        );
    }

    #[test]
    fn capture_bounds_reflect_the_applied_contract() {
        // The bounds are STRINGS (the OpenReceipt value domain has no
        // numbers) and reflect the profile defaults or the hooks' overrides.
        with_env(
            &[
                ("FRF_EXEC_TIMEOUT_MS", "1234"),
                ("FRF_EXEC_MAX_BYTES", "2048"),
                ("FRF_EXEC_RLIMIT_CPU_S", "7"),
            ],
            || {
                let bounds = capture_bounds(ExecProfile::LinuxV1);
                assert_eq!(bounds.timeout_ms, "1234");
                assert_eq!(bounds.max_stream_bytes, "2048");
                assert_eq!(bounds.rlimit_cpu_s, "7");
                assert_eq!(bounds.rlimit_as_mb, EXEC_RLIMIT_AS_MB.to_string());
                assert_eq!(bounds.rlimit_nofile, EXEC_RLIMIT_NOFILE.to_string());
                // The reference profile records no cgroup envelope.
                assert_eq!(bounds.cgroup_pids_max, None);
                // The v2 profile records its aggregate envelope.
                let v2 = capture_bounds(ExecProfile::LinuxV2);
                assert_eq!(
                    v2.cgroup_pids_max.as_deref(),
                    Some(CGROUP2_PIDS_MAX.to_string().as_str())
                );
                assert_eq!(
                    v2.cgroup_memory_max.as_deref(),
                    Some(CGROUP2_MEMORY_MAX.to_string().as_str())
                );
                assert_eq!(v2.cgroup_cpu_max.as_deref(), Some(CGROUP2_CPU_MAX));
                // The profile's contract validates within the protocol maxima.
                crate::model::validate_capture_bounds(&bounds).unwrap();
                crate::model::validate_capture_bounds(&v2).unwrap();
            },
        );
    }

    #[test]
    fn environment_identity_records_the_declared_strata() {
        // The digest covers locale/timezone/umask on top of os/arch/kernel
        // AND the DECLARED execution environment; the cwd is recorded (not
        // digested — an invocation property); the ambient host environment
        // is never inherited and never recorded.
        let empty = std::collections::BTreeMap::new();
        let env = environment_identity(&empty);
        assert_eq!(env.schema_version, crate::model::SCHEMA_ENVIRONMENT);
        assert_eq!(env.locale, effective_locale(&empty));
        assert_eq!(env.timezone, timezone(&empty));
        assert_eq!(env.umask, umask());
        assert!(env.environment.is_empty());
        assert!(!env.cwd.is_empty());
        let expected = environment_digest(
            &env.os,
            &env.architecture,
            &env.kernel_release,
            &env.locale,
            &env.timezone,
            &env.umask,
            &empty,
        );
        assert_eq!(env.digest, expected);

        // A declared variable moves the digest, and the declared
        // locale/timezone are what the SIDE sees (never the ambient host's).
        let mut declared = std::collections::BTreeMap::new();
        declared.insert("LANG".to_string(), "C.UTF-8".to_string());
        declared.insert("TZ".to_string(), "Asia/Tokyo".to_string());
        declared.insert("x".to_string(), "() { :;}; echo PWNED".to_string());
        let env2 = environment_identity(&declared);
        assert_eq!(env2.locale, "C.UTF-8");
        assert_eq!(env2.timezone, "Asia/Tokyo");
        assert_eq!(env2.environment, declared);
        assert_ne!(env2.digest, env.digest);
        // The same declared map is deterministic.
        assert_eq!(env2.digest, environment_identity(&declared).digest);
    }

    #[cfg(unix)]
    #[test]
    fn plain_shebang_binds_kernel_as_the_interpreter() {
        // `#!/bin/sh` — the kernel directly invokes /bin/sh; no resolver,
        // kernel == downstream.
        let script = temp_script("chain-plain");
        std::fs::write(&script, "#!/bin/sh\necho hi\n").unwrap();
        let chain = interpreter_identity(&std::fs::read(&script).unwrap())
            .unwrap()
            .expect("script interpreter");
        assert_eq!(chain.kernel_interpreter, chain.downstream_interpreter);
        assert!(chain.resolver.is_none());
        assert_eq!(chain.shebang_argument_bytes, "");
        assert_eq!(chain.kernel_interpreter.sha256.len(), 64);
        assert!(Path::new(&chain.kernel_interpreter.path).is_file());
        let _ = std::fs::remove_file(&script);
    }

    #[cfg(unix)]
    #[test]
    fn env_shebang_binds_the_full_chain() {
        // `#!/usr/bin/env -S sh -e` — the kernel invokes env(1); the
        // downstream is the first non-option token; the raw argument bytes
        // are preserved verbatim as evidence.
        let script = temp_script("chain-env");
        std::fs::write(&script, "#!/usr/bin/env -S sh -e\necho hi\n").unwrap();
        let chain = interpreter_identity(&std::fs::read(&script).unwrap())
            .unwrap()
            .expect("script interpreter");
        assert!(
            chain.kernel_interpreter.path.contains("/env"),
            "kernel: {}",
            chain.kernel_interpreter.path
        );
        let resolver = chain.resolver.as_ref().expect("env resolver");
        assert_eq!(resolver.kind, "env");
        assert_eq!(resolver.path, chain.kernel_interpreter.path);
        assert_eq!(resolver.path_digest.len(), 64);
        assert_eq!(chain.shebang_argument_bytes, "-S sh -e");
        assert_eq!(chain.downstream_interpreter.sha256.len(), 64);
        assert!(Path::new(&chain.downstream_interpreter.path).is_file());
        let _ = std::fs::remove_file(&script);
    }

    #[cfg(unix)]
    #[test]
    fn env_shebang_skips_assignments_when_resolving() {
        // `#!/usr/bin/env FOO=bar sh` — FOO=bar is an env assignment, not
        // the command; the downstream is sh.
        let script = temp_script("chain-assign");
        std::fs::write(&script, "#!/usr/bin/env FOO=bar sh\necho hi\n").unwrap();
        let chain = interpreter_identity(&std::fs::read(&script).unwrap())
            .unwrap()
            .expect("script interpreter");
        assert_eq!(chain.shebang_argument_bytes, "FOO=bar sh");
        // FOO=bar is skipped: the downstream is sh, not env and not the
        // assignment.
        assert_ne!(
            chain.downstream_interpreter.sha256, chain.kernel_interpreter.sha256,
            "downstream must differ from env"
        );
        assert!(Path::new(&chain.downstream_interpreter.path).is_file());
        let _ = std::fs::remove_file(&script);
    }

    #[cfg(unix)]
    #[test]
    fn binaries_have_no_interpreter_chain() {
        let script = temp_script("chain-bin");
        std::fs::write(&script, "\x7fELF-not-really\n").unwrap();
        assert!(interpreter_identity(&std::fs::read(&script).unwrap())
            .unwrap()
            .is_none());
        let _ = std::fs::remove_file(&script);
    }
}
