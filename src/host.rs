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
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Upper bound for one side of a court execution (the execution profile's
/// timeout).
pub const EXEC_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum bytes retained per output stream (the execution profile's capture
/// cap). A side that exceeds it is killed and the run REFUSED — truncated
/// output is never evidence. The profile records the cap that applied.
pub const EXEC_MAX_STREAM_BYTES: usize = 16 * 1024 * 1024;

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

/// Total budget for `ETXTBSY` spawn retries. Exec'ing a file another process
/// just finished writing (or is still writing) transiently fails with
/// `ExecutableFileBusy` — parallel CI and generated-script workflows hit
/// this. The retry has a deadline of its own, so a persistently busy
/// executable fails instead of looping forever (the execution timeout only
/// starts after the spawn succeeds).
pub const SPAWN_RETRY_BUDGET: Duration = Duration::from_secs(1);

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

/// Effective address-space limit (MiB), `FRF_EXEC_RLIMIT_AS_MB` override.
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
/// runs in.
pub fn reference_capture_bounds() -> CaptureBounds {
    CaptureBounds {
        timeout_ms: EXEC_TIMEOUT.as_millis().to_string(),
        max_stream_bytes: EXEC_MAX_STREAM_BYTES.to_string(),
        rlimit_as_mb: EXEC_RLIMIT_AS_MB.to_string(),
        rlimit_cpu_s: EXEC_RLIMIT_CPU_S.to_string(),
        rlimit_nofile: EXEC_RLIMIT_NOFILE.to_string(),
        rlimit_nproc: EXEC_RLIMIT_NPROC.to_string(),
    }
}

/// The EFFECTIVE capture bounds — the profile defaults or the `FRF_EXEC_*`
/// test-hook overrides (strings, because the OpenReceipt canonical value
/// domain has no numbers). Bound at OBSERVATION time and copied into the
/// capture/receipt, so an observation is always read against the harness
/// contract it was actually made under. The reference contract is
/// [`reference_capture_bounds`]; the two differ exactly when a test hook
/// overrides a bound, and only the observation side may consult the
/// effective value.
pub fn capture_bounds() -> CaptureBounds {
    CaptureBounds {
        timeout_ms: exec_timeout().as_millis().to_string(),
        max_stream_bytes: max_stream_bytes().to_string(),
        rlimit_as_mb: rlimit_as_mb().to_string(),
        rlimit_cpu_s: rlimit_cpu_s().to_string(),
        rlimit_nofile: rlimit_nofile().to_string(),
        rlimit_nproc: rlimit_nproc().to_string(),
    }
}

/// SHA-256 hex digest of a byte slice.
pub fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(&hasher.finalize())
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

/// Raw process observation: full stdout/stderr bytes plus the exit code.
#[derive(Debug, Clone)]
pub struct ProcessOutcome {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit: String,
}

/// Execute `program` with `args`, capturing stdout/stderr without a shell.
///
/// `ETXTBSY` (`ExecutableFileBusy`) is retried within [`SPAWN_RETRY_BUDGET`]
/// before failing; everything else fails immediately.
pub fn run_process(program: &Path, args: &[String]) -> Result<ProcessOutcome> {
    run_impl(program, args, None, None)
}

/// [`run_process`] with a declared working directory: the side runs from
/// `cwd`, so recorded root-relative argv paths resolve against the layout
/// the replay reconstructed (bundle replay executes sides from the temp
/// invocation root, never from the user's cwd).
pub fn run_process_in(program: &Path, args: &[String], cwd: &Path) -> Result<ProcessOutcome> {
    run_impl(program, args, None, Some(cwd))
}

/// Execute `program` with `args` and the given bytes on stdin (used by the
/// comparator extension protocol: the canonical request is written to the
/// comparator's stdin, which sees EOF once the write completes). Same
/// hostile-runner guarantees as [`run_process`]: own process group, pipes
/// drained concurrently (stdin written concurrently too), bounded timeout,
/// descendant termination.
pub fn run_process_with_stdin(
    program: &Path,
    args: &[String],
    stdin: &[u8],
) -> Result<ProcessOutcome> {
    run_impl(program, args, Some(stdin), None)
}

/// [`run_process_with_stdin`] with a declared working directory (bundle
/// replay invokes the snapshotted comparator from the reconstructed root).
pub fn run_process_with_stdin_in(
    program: &Path,
    args: &[String],
    stdin: &[u8],
    cwd: &Path,
) -> Result<ProcessOutcome> {
    run_impl(program, args, Some(stdin), Some(cwd))
}

fn run_impl(
    program: &Path,
    args: &[String],
    stdin: Option<&[u8]>,
    cwd: Option<&Path>,
) -> Result<ProcessOutcome> {
    // Every side runs in its own process group (unix) so the harness can
    // terminate the entire tree — direct process plus any descendants that
    // inherited the capture pipes — when the side exits, times out, or
    // overflows its capture cap.
    let mut command = Command::new(program);
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    command
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
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
        // SAFETY: `pre_exec` runs after fork(2), before execve(2), in the
        // single-threaded child; setrlimit(2) is async-signal-safe.
        unsafe {
            command.pre_exec(move || {
                set_rlimit(libc::RLIMIT_AS, as_bytes)
                    .and_then(|_| set_rlimit(libc::RLIMIT_CPU, cpu_s))
                    .and_then(|_| set_rlimit(libc::RLIMIT_NOFILE, nofile))
                    .and_then(|_| set_rlimit(libc::RLIMIT_NPROC, nproc))
            });
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }

    let spawn_deadline = Instant::now() + SPAWN_RETRY_BUDGET;
    let mut child = loop {
        match command.spawn() {
            Ok(child) => break child,
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                if Instant::now() >= spawn_deadline {
                    return Err(FrfError::new(format!(
                        "{} stayed busy (ETXTBSY) through the full {} ms retry budget: another process is still writing it; refusing to hang the court",
                        program.display(),
                        SPAWN_RETRY_BUDGET.as_millis()
                    )));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                return Err(FrfError::new(format!(
                    "failed to execute {}: {e} (does it exist and have its executable bit set?)",
                    program.display()
                )))
            }
        }
    };

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
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let timeout = exec_timeout();
    let max_bytes = max_stream_bytes();
    // The process group id is the direct child's pid, captured BEFORE the
    // wait loop: after the child is reaped its pid can be reused, and the
    // group kill must target the ORIGINAL group, never whatever process got
    // the recycled pid.
    let group = child.id();
    let start = Instant::now();
    let overflow = Arc::new(AtomicBool::new(false));

    let status = std::thread::scope(|s| {
        if let (Some(mut pipe), Some(bytes)) = (stdin_pipe.take(), stdin_bytes) {
            // `pipe` is dropped when the thread ends, closing stdin: the
            // comparator sees EOF after its request.
            s.spawn(move || {
                let _ = pipe.write_all(&bytes);
            });
        }
        let _drain_out =
            s.spawn(|| drain_capped(&mut stdout_pipe, &mut stdout, max_bytes, group, &overflow));
        let _drain_err =
            s.spawn(|| drain_capped(&mut stderr_pipe, &mut stderr, max_bytes, group, &overflow));
        let result = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) => {
                    if start.elapsed() > timeout {
                        // Kill, reap, and let the drain threads finish once
                        // the pipes close.
                        let _ = child.kill();
                        let _ = child.wait();
                        break Err(FrfError::new(format!(
                            "{} exceeded the execution timeout ({} ms)",
                            program.display(),
                            timeout.as_millis()
                        )));
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => {
                    break Err(FrfError::new(format!(
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
        result
        // `scope` joins all threads here (stdin writer + both drains), so the
        // buffers are complete before the caller sees them.
    })?;

    // Evidentiary overflow: a stream exceeded the profile's capture cap and
    // the side was killed. The captured bytes are TRUNCATED — recording them
    // would fabricate an observation — so the run is refused, naming the
    // bound that was enforced.
    if overflow.load(Ordering::SeqCst) {
        return Err(FrfError::new(format!(
            "{} exceeded the execution profile's {} byte per-stream capture cap; refusing to record truncated output as evidence",
            program.display(),
            max_bytes
        )));
    }

    let exit = exit_string(&status);
    Ok(ProcessOutcome {
        stdout,
        stderr,
        exit,
    })
}

/// Drain a capture pipe up to `max` bytes. On exceeding the cap the whole
/// process group is terminated and the overflow flag set: the caller refuses
/// the run (truncated output is never evidence), and killing the group frees
/// the peer pipes so every other drain reaches EOF and the scope can join.
fn drain_capped(
    pipe: &mut impl Read,
    out: &mut Vec<u8>,
    max: usize,
    group: u32,
    overflow: &AtomicBool,
) {
    let mut chunk = [0u8; 8192];
    loop {
        match pipe.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if out.len() + n > max {
                    overflow.store(true, Ordering::SeqCst);
                    #[cfg(unix)]
                    terminate_process_group(group);
                    break;
                }
                out.extend_from_slice(&chunk[..n]);
            }
            Err(_) => break, // the group-kill path closes the pipe
        }
    }
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
/// the receipt's own environment fields). Covers the strata that actually
/// move side output: os, architecture, kernel release, the effective locale,
/// the timezone, and the umask.
pub fn environment_digest(
    os: &str,
    architecture: &str,
    kernel_release: &str,
    locale: &str,
    timezone: &str,
    umask: &str,
) -> String {
    sha256_bytes(
        format!(
            "os={os}\narch={architecture}\nkernel={kernel_release}\nlocale={locale}\ntimezone={timezone}\numask={umask}"
        )
        .as_bytes(),
    )
}

/// The effective locale the sides run under: `LC_ALL`, else `LC_CTYPE`, else
/// `LANG`, else `C` (the POSIX default that applies when none is set).
pub fn effective_locale() -> String {
    std::env::var("LC_ALL")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| std::env::var("LC_CTYPE").ok().filter(|v| !v.is_empty()))
        .or_else(|| std::env::var("LANG").ok().filter(|v| !v.is_empty()))
        .unwrap_or_else(|| "C".to_string())
}

/// The timezone the sides run under: `TZ` when set, else the resolved system
/// zone (when /etc/localtime is a symlink into zoneinfo, its tail — e.g.
/// `Europe/London`), else a digest of the zone file's bytes, else `unknown`.
pub fn timezone() -> String {
    if let Ok(tz) = std::env::var("TZ") {
        if !tz.is_empty() {
            return tz;
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

/// The environment an observation happens in, captured at court time: os,
/// architecture, kernel release, locale, timezone, umask, the working
/// directory the sides ran under, and the digest over the output-moving
/// strata. The receipt copies this identity verbatim — it never asks its own
/// host what environment an old court ran under.
pub fn environment_identity() -> EnvironmentIdentity {
    let os = std::env::consts::OS.to_string();
    let architecture = std::env::consts::ARCH.to_string();
    let kernel_release = kernel_release();
    let locale = effective_locale();
    let timezone = timezone();
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

    /// Runs `body` with the given environment overrides set, restoring (or
    /// removing) the prior values afterwards. Test threads share the process
    /// environment, so hook-dependent tests must isolate themselves with this
    /// instead of calling `std::env::set_var` directly. The global hook lock
    /// serializes every test that reads or writes the execution hooks: an
    /// override from one thread would otherwise leak into a concurrently
    /// running test that reads the same variable mid-flight.
    static HOOK_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_env<T>(overrides: &[(&str, &str)], body: impl FnOnce() -> T) -> T {
        let _guard = HOOK_LOCK.lock().unwrap();
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
        let out = run_process(&script, &[]).unwrap();
        assert_eq!(out.exit, "7");
        assert_eq!(out.stdout, b"out\n");
        assert_eq!(out.stderr, b"err\n");
        let _ = std::fs::remove_file(&script);
    }

    #[test]
    fn missing_program_is_a_clear_error() {
        let err = run_process(Path::new("/nonexistent/frf-nope"), &[]).unwrap_err();
        assert!(err.0.contains("failed to execute"));
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
            let out = run_process(&script, &[]).unwrap();
            assert_eq!(out.exit, "0");
            let line = "0123456789abcdefghijklmnopqrstuvwxyz0123456789";
            assert_eq!(
                out.stdout.len(),
                (line.len() + 1) * 20_000,
                "full stream must be drained"
            );
            assert!(out.stderr.is_empty());
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
        let out = run_process(&script, &[]).unwrap();
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
        let err = run_process(&script, &[]).unwrap_err();
        drop(held);
        assert!(err.0.contains("ETXTBSY"), "error: {}", err.0);
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
            let out = run_process(&script, &[]).unwrap();
            assert_eq!(out.exit, "0");
            assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "child-done");
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
            let err = run_process(&script, &[]).unwrap_err();
            assert!(
                err.0.contains("capture cap")
                    && err.0.contains("refusing to record truncated output"),
                "the overflow must refuse the run, naming the cap: {}",
                err.0
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
                let out = run_process(&script, &[]).unwrap();
                assert!(
                    out.exit.starts_with("signal("),
                    "the CPU limit must terminate the side by signal, got {:?}",
                    out.exit
                );
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
        // harness waits for its own timeout). `ulimit -u` reads the child's
        // own limit — deterministic and instant.
        with_env(&[("FRF_EXEC_RLIMIT_NPROC", "42")], || {
            let script = temp_script("nproc-cap");
            std::fs::write(&script, "#!/bin/sh\nulimit -u\n").unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
            let out = run_process(&script, &[]).unwrap();
            assert_eq!(
                String::from_utf8_lossy(&out.stdout).trim(),
                "42",
                "the child must run under its declared process-count cap"
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
                let _ = run_process(&script, &[]);
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
                let bounds = capture_bounds();
                assert_eq!(bounds.timeout_ms, "1234");
                assert_eq!(bounds.max_stream_bytes, "2048");
                assert_eq!(bounds.rlimit_cpu_s, "7");
                assert_eq!(bounds.rlimit_as_mb, EXEC_RLIMIT_AS_MB.to_string());
                assert_eq!(bounds.rlimit_nofile, EXEC_RLIMIT_NOFILE.to_string());
                // The profile's contract validates within the protocol maxima.
                crate::model::validate_capture_bounds(&bounds).unwrap();
            },
        );
    }

    #[test]
    fn environment_identity_records_the_expanded_strata() {
        // The digest covers locale/timezone/umask on top of os/arch/kernel,
        // and the cwd is recorded (not digested — an invocation property).
        let env = environment_identity();
        assert_eq!(env.schema_version, crate::model::SCHEMA_ENVIRONMENT);
        assert_eq!(env.locale, effective_locale());
        assert_eq!(env.timezone, timezone());
        assert_eq!(env.umask, umask());
        assert!(!env.cwd.is_empty());
        let expected = environment_digest(
            &env.os,
            &env.architecture,
            &env.kernel_release,
            &env.locale,
            &env.timezone,
            &env.umask,
        );
        assert_eq!(env.digest, expected);
        // A different locale moves the digest. The "other" locale is chosen
        // to be guaranteed different from the effective one (CI runners set
        // C.UTF-8): the point is that changing the locale changes the
        // digest, not that any particular locale is "other".
        let other = if env.locale == "C.UTF-8" {
            "C"
        } else {
            "C.UTF-8"
        };
        assert_ne!(
            expected,
            environment_digest(
                &env.os,
                &env.architecture,
                &env.kernel_release,
                other,
                &env.timezone,
                &env.umask
            )
        );
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
