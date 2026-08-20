//! libFuzzer target: the CLI parser must never panic on arbitrary argument
//! vectors (NUL-separated chunks become args, the standard cargo-fuzz
//! convention for argv-style input).
//!
//! Run: `cargo +nightly fuzz run cli_args`

#![no_main]

use clap::CommandFactory;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut args: Vec<std::ffi::OsString> = vec!["frf".into()];
    for chunk in data.split(|b| *b == 0) {
        args.push(String::from_utf8_lossy(chunk).into_owned().into());
    }
    let _ = frf::cli::Cli::command().try_get_matches_from(args);
});
