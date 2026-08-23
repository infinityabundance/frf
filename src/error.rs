//! User-facing error type. Every command failure becomes a one-line
//! `frf: <message>` on stderr and a non-zero exit code; there is no other
//! error channel, so scripts can rely on exit codes and stderr text alone.

use std::fmt;

#[derive(Debug, Clone)]
pub struct FrfError(pub String);

impl FrfError {
    pub fn new(msg: impl Into<String>) -> Self {
        FrfError(msg.into())
    }

    /// Is this a disposition-append CONFLICT (a concurrent writer appended to
    /// the same residual's hash chain between our read and our write)? The
    /// CAS loop uses this to re-read the chain and retry instead of surfacing
    /// an opaque refusal.
    pub fn is_append_conflict(&self) -> bool {
        self.0.starts_with("disposition append conflict")
    }
}

impl fmt::Display for FrfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for FrfError {}

pub type Result<T> = std::result::Result<T, FrfError>;
