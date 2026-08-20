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
}

impl fmt::Display for FrfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for FrfError {}

pub type Result<T> = std::result::Result<T, FrfError>;
