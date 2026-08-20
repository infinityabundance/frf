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
//! - Exit status is recorded as the raw code, or the literal `signal` when the
//!   process was terminated by a signal (no fabricated code).

use crate::error::{FrfError, Result};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Upper bound for one side of a court execution.
pub const EXEC_TIMEOUT: Duration = Duration::from_secs(60);

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
/// `ETXTBSY` (`ExecutableFileBusy`) is retried briefly: it is the transient
/// writeback race of exec'ing a file another process just finished writing
/// (or is still writing), which happens in parallel CI and generated-script
/// workflows. Everything else fails immediately.
pub fn run_process(program: &Path, args: &[String]) -> Result<ProcessOutcome> {
    let mut child = loop {
        match Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => break child,
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                std::thread::sleep(Duration::from_millis(10));
                continue;
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
    // try_wait, and the run fails with a false timeout.
    let mut stdout_pipe = child.stdout.take().expect("stdout is piped");
    let mut stderr_pipe = child.stderr.take().expect("stderr is piped");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let timeout = exec_timeout();
    let start = Instant::now();

    let status = std::thread::scope(|s| {
        let _drain_out = s.spawn(|| {
            let _ = stdout_pipe.read_to_end(&mut stdout);
        });
        let _drain_err = s.spawn(|| {
            let _ = stderr_pipe.read_to_end(&mut stderr);
        });
        loop {
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
        }
        // `scope` joins both drain threads here, so the buffers are complete
        // before the caller sees them.
    })?;

    let exit = exit_string(&status);
    Ok(ProcessOutcome {
        stdout,
        stderr,
        exit,
    })
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

/// Environment digest: a content hash of the host strata a court run depends
/// on (os, architecture, kernel release). Two runs with the same digest are
/// replay-comparable; a changed digest means a changed environment.
pub fn environment_digest() -> String {
    let src = format!(
        "os={}\narch={}\nkernel={}",
        std::env::consts::OS,
        std::env::consts::ARCH,
        kernel_release()
    );
    sha256_bytes(src.as_bytes())
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
}
