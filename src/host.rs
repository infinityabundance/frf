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
    EnvironmentIdentity, InterpreterExecutable, InterpreterIdentity, InterpreterResolver,
};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Upper bound for one side of a court execution.
pub const EXEC_TIMEOUT: Duration = Duration::from_secs(60);

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
    run_impl(program, args, None)
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
    run_impl(program, args, Some(stdin))
}

fn run_impl(program: &Path, args: &[String], stdin: Option<&[u8]>) -> Result<ProcessOutcome> {
    // Every side runs in its own process group (unix) so the harness can
    // terminate the entire tree — direct process plus any descendants that
    // inherited the capture pipes — when the side exits or times out.
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
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
    let start = Instant::now();

    let status = std::thread::scope(|s| {
        if let (Some(mut pipe), Some(bytes)) = (stdin_pipe.take(), stdin_bytes) {
            // `pipe` is dropped when the thread ends, closing stdin: the
            // comparator sees EOF after its request.
            s.spawn(move || {
                let _ = pipe.write_all(&bytes);
            });
        }
        let _drain_out = s.spawn(|| {
            let _ = stdout_pipe.read_to_end(&mut stdout);
        });
        let _drain_err = s.spawn(|| {
            let _ = stderr_pipe.read_to_end(&mut stderr);
        });
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
        // holding the pipes must never block the harness.
        #[cfg(unix)]
        terminate_process_group(child.id());
        result
        // `scope` joins all threads here (stdin writer + both drains), so the
        // buffers are complete before the caller sees them.
    })?;

    let exit = exit_string(&status);
    Ok(ProcessOutcome {
        stdout,
        stderr,
        exit,
    })
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
/// the receipt's own os/architecture/kernel_release fields).
pub fn environment_digest(os: &str, architecture: &str, kernel_release: &str) -> String {
    sha256_bytes(format!("os={os}\narch={architecture}\nkernel={kernel_release}").as_bytes())
}

/// The environment an observation happens in, captured at court time: os,
/// architecture, kernel release, and the digest over them. The receipt
/// copies this identity verbatim — it never asks its own host what
/// environment an old court ran under. (Expanding the strata — libc,
/// locale, timezone, dynamic dependencies, container/Nix digests — is
/// environment admission, a later milestone; the struct is already the
/// shape for it.)
pub fn environment_identity() -> EnvironmentIdentity {
    let os = std::env::consts::OS.to_string();
    let architecture = std::env::consts::ARCH.to_string();
    let kernel_release = kernel_release();
    let digest = environment_digest(&os, &architecture, &kernel_release);
    EnvironmentIdentity {
        schema_version: crate::model::SCHEMA_ENVIRONMENT.to_string(),
        os,
        architecture,
        kernel_release,
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
        let out = run_process(&script, &[]).unwrap();
        assert_eq!(out.exit, "0");
        let line = "0123456789abcdefghijklmnopqrstuvwxyz0123456789";
        assert_eq!(
            out.stdout.len(),
            (line.len() + 1) * 20_000,
            "full stream must be drained"
        );
        assert!(out.stderr.is_empty());
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
        let start = Instant::now();
        let out = run_process(&script, &[]).unwrap();
        assert_eq!(out.exit, "0");
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "child-done");
        assert!(
            start.elapsed() < Duration::from_millis(1500),
            "harness must not wait for a descendant to release the pipes (took {:?})",
            start.elapsed()
        );
        let _ = std::fs::remove_file(&script);
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
