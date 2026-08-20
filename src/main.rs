//! `frf` binary: parse arguments, dispatch, map errors to exit codes.
//! All logic lives in the library so tests can exercise it in-process.

use clap::Parser;
use frf::cli::Cli;
use frf::store::Store;
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let store = Store::new(cli.root.clone());
    if let Err(e) = store.ensure_tree() {
        eprintln!("frf: {e}");
        return ExitCode::FAILURE;
    }
    match frf::commands::dispatch(&store, cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("frf: {e}");
            ExitCode::FAILURE
        }
    }
}
