//! The error type of the reference engine: a MESSAGE (the human contract —
//! every command failure becomes a one-line `frf: <message>` on stderr and
//! a non-zero exit code) plus a KIND (the machine-readable category a
//! library consumer can match on without parsing the message).

use std::fmt;

/// The structured category of an [`FrfError`]. The message is the human
/// contract; the kind is the machine-readable one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrfErrorKind {
    /// Evidence was REFUSED: a document did not verify, a semantic
    /// conformance check failed, an admission rule refused, a run was
    /// refused. The dominant kind — FRF's core is a refusal engine, and a
    /// consumer that wants "did the evidence hold up?" matches this.
    Refused,
    /// A requested object / file / run does not exist.
    Missing,
    /// A write-once object already exists (idempotent writers decide on
    /// this kind instead of parsing prose).
    AlreadyExists,
    /// Invalid user or caller input (a bad id, a malformed key, a bad
    /// argument).
    InvalidInput,
    /// An I/O failure (read / write / create).
    Io,
    /// An execution / harness failure (spawn, timeout, resource bound).
    Execution,
    /// Uncategorized. `FrfError::new` defaults here, so every existing call
    /// site keeps compiling; the strategic boundaries use the typed
    /// constructors and are pinned by tests/error_kinds.rs.
    Other,
}

/// The error type of the reference engine.
#[derive(Debug, Clone)]
pub struct FrfError {
    pub kind: FrfErrorKind,
    message: String,
}

impl FrfError {
    /// An uncategorized error (the message is the contract). Kept for the
    /// general case; the typed constructors below are preferred at the
    /// library-facing boundaries.
    pub fn new(msg: impl Into<String>) -> Self {
        FrfError {
            kind: FrfErrorKind::Other,
            message: msg.into(),
        }
    }

    /// Evidence refused: it did not verify, a semantic conformance check
    /// failed, an admission rule refused, a run was refused.
    pub fn refused(msg: impl Into<String>) -> Self {
        FrfError {
            kind: FrfErrorKind::Refused,
            message: msg.into(),
        }
    }

    /// A requested object / file / run does not exist.
    pub fn missing(msg: impl Into<String>) -> Self {
        FrfError {
            kind: FrfErrorKind::Missing,
            message: msg.into(),
        }
    }

    /// A write-once object already exists.
    pub fn already_exists(msg: impl Into<String>) -> Self {
        FrfError {
            kind: FrfErrorKind::AlreadyExists,
            message: msg.into(),
        }
    }

    /// Invalid user or caller input.
    pub fn invalid_input(msg: impl Into<String>) -> Self {
        FrfError {
            kind: FrfErrorKind::InvalidInput,
            message: msg.into(),
        }
    }

    /// An I/O failure.
    pub fn io(msg: impl Into<String>) -> Self {
        FrfError {
            kind: FrfErrorKind::Io,
            message: msg.into(),
        }
    }

    /// An execution / harness failure.
    pub fn execution(msg: impl Into<String>) -> Self {
        FrfError {
            kind: FrfErrorKind::Execution,
            message: msg.into(),
        }
    }

    /// The machine-readable kind.
    pub fn kind(&self) -> FrfErrorKind {
        self.kind
    }

    /// The human-readable message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Consume the error, returning its message.
    pub fn into_message(self) -> String {
        self.message
    }

    /// Is this a disposition-append CONFLICT (a concurrent writer appended to
    /// the same residual's hash chain between our read and our write)? The
    /// CAS loop uses this to re-read the chain and retry instead of surfacing
    /// an opaque refusal.
    pub fn is_append_conflict(&self) -> bool {
        self.message.starts_with("disposition append conflict")
    }

    pub fn is_refused(&self) -> bool {
        self.kind == FrfErrorKind::Refused
    }

    pub fn is_missing(&self) -> bool {
        self.kind == FrfErrorKind::Missing
    }

    pub fn is_already_exists(&self) -> bool {
        self.kind == FrfErrorKind::AlreadyExists
    }

    pub fn is_invalid_input(&self) -> bool {
        self.kind == FrfErrorKind::InvalidInput
    }
}

impl fmt::Display for FrfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for FrfError {}

pub type Result<T> = std::result::Result<T, FrfError>;
