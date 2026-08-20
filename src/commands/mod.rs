//! Command dispatch: each verb is one function; stdout carries the single
//! machine-readable id a command produces, stderr carries narration.

pub mod admit;
pub mod bundle;
pub mod claim;
pub mod court;
pub mod dispose;
pub mod receipt;
pub mod replay;

use crate::cli::*;
use crate::error::Result;
use crate::store::Store;

pub fn dispatch(store: &Store, command: Command) -> Result<()> {
    match command {
        Command::Authority { sub } => match sub {
            AuthorityCmd::Admit {
                path,
                name,
                version,
                kind,
            } => {
                let id = admit::run(store, &path, &name, &version, &kind)?;
                println!("{id}");
                Ok(())
            }
        },
        Command::Court { sub } => match sub {
            CourtCmd::Run { manifest } => {
                let run = court::run(store, &manifest)?;
                println!("{run}");
                Ok(())
            }
        },
        Command::Residual { sub } => match sub {
            ResidualCmd::Dispose {
                id,
                disposition,
                reason,
                resolution_run,
            } => dispose::run(store, &id, disposition, &reason, resolution_run),
        },
        Command::Receipt { sub } => match sub {
            ReceiptCmd::Emit { run } => {
                let id = receipt::run(store, &run)?;
                println!("{id}");
                Ok(())
            }
        },
        Command::Claim { sub } => match sub {
            ClaimCmd::Compile { receipt } => claim::run(store, &receipt),
        },
        Command::Replay { id } => {
            replay::run(store, &id)?;
            Ok(())
        }
        Command::Bundle { sub } => match sub {
            BundleCmd::Export { receipt, output } => {
                let output = output.unwrap_or_else(|| {
                    std::path::PathBuf::from("bundles").join(format!("{receipt}.frf"))
                });
                let path = bundle::export(store, &receipt, &output)?;
                println!("{}", path.display());
                Ok(())
            }
            BundleCmd::Verify { path } => bundle::verify(&path),
        },
    }
}
