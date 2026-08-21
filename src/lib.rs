//! frf — the Forensic Residual Framework kernel, executed.
//!
//! Library root. The binary (`frf`) is a thin argument-parsing shell over
//! [`commands::dispatch`]; everything testable lives here so the regression,
//! verification, and fuzz suites can call the pure functions (κ, sentence
//! assembly, hashing, path safety) directly instead of only through process
//! boundaries.

pub mod canon;
pub mod cli;
pub mod commands;
pub mod comparators;
pub mod error;
pub mod ext;
pub mod host;
pub mod kappa;
pub mod model;
pub mod mutation;
pub mod normalizers;
pub mod produced;
pub mod scope;
pub mod semantics;
pub mod sentences;
pub mod store;
pub mod trajectory;
pub mod verify;
