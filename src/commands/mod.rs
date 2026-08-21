//! Command dispatch: each verb is one function; stdout carries the single
//! machine-readable id a command produces, stderr carries narration.

pub mod admit;
pub mod bundle;
pub mod claim;
pub mod court;
pub mod dispose;
pub mod receipt;
pub mod replay;
pub mod witness;

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
            CourtCmd::Run {
                manifest,
                repeat,
                candidate_revisions,
                authority_versions,
                environment_point,
                time_point,
                series_parent,
            } => {
                let opts = court::SeriesOptions {
                    repeat,
                    candidate_revisions: candidate_revisions
                        .map(|s| {
                            s.split(',')
                                .map(|p| p.trim().to_string())
                                .filter(|p| !p.is_empty())
                                .collect()
                        })
                        .filter(|v: &Vec<String>| !v.is_empty()),
                    authority_versions: authority_versions
                        .map(|s| {
                            s.split(',')
                                .map(|v| v.trim().to_string())
                                .filter(|v| !v.is_empty())
                                .collect()
                        })
                        .filter(|v: &Vec<String>| !v.is_empty()),
                    environment_point,
                    time_point,
                    series_parent,
                };
                let run = court::run(store, &manifest, &opts)?;
                println!("{run}");
                Ok(())
            }
            CourtCmd::Minimize { residual } => {
                let id = court::minimize(store, &residual)?;
                println!("{id}");
                Ok(())
            }
            CourtCmd::Challenge {
                manifest,
                operators,
            } => {
                let ids = court::challenge(store, &manifest, operators.as_deref())?;
                for id in &ids {
                    println!("{id}");
                }
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
            ClaimCmd::Compile {
                receipt,
                json,
                policy,
            } => claim::run(store, &receipt, json, &policy),
            ClaimCmd::Render { receipt, format } => {
                // The renderers are PURE functions of the compiled Claim IR:
                // the claim file (canonical JSON) is loaded and verified
                // (schema + binding) and rendered without any re-derivation.
                let path = store.claim_path(&receipt).map_err(|e| {
                    crate::error::FrfError::new(format!("invalid claim render target: {e}"))
                })?;
                if !path.is_file() {
                    return Err(crate::error::FrfError::new(format!(
                        "no compiled claim for receipt '{receipt}': run `frf claim compile {receipt}` first — the renderers present the compiled IR"
                    )));
                }
                let claim: crate::model::ClaimRecord = store.parse_evidence(&path)?;
                let out = crate::render::render(&claim, &format, env!("CARGO_PKG_VERSION"))?;
                println!("{out}");
                Ok(())
            }
        },
        Command::Replay { id, policy } => {
            // Tree replay: the sides execute from the invocation cwd, so the
            // recorded argv paths resolve against the tree (whose objects are
            // verified before execution).
            let cwd = std::env::current_dir().map_err(|e| {
                crate::error::FrfError::new(format!("cannot resolve the current directory: {e}"))
            })?;
            replay::run(store, &id, &policy, &cwd)?;
            Ok(())
        }
        Command::Bundle { sub } => match sub {
            BundleCmd::Export {
                receipt,
                output,
                single,
            } => {
                let container = if single {
                    crate::commands::bundle::Container::SingleTar
                } else {
                    crate::commands::bundle::Container::Directory
                };
                let output = output.unwrap_or_else(|| {
                    std::path::PathBuf::from("bundles").join(format!("{receipt}.frf"))
                });
                let path = crate::commands::bundle::export(store, &receipt, &output, container)?;
                println!("{}", path.display());
                Ok(())
            }
            BundleCmd::Verify { path } => crate::commands::bundle::verify(&path),
            BundleCmd::Replay { path, policy } => {
                crate::commands::bundle::replay_bundle(&path, &policy)
            }
        },
        Command::Witness { sub } => match sub {
            WitnessCmd::Attest {
                kind,
                subject_id,
                id,
                relation,
                relation_version,
                program,
                statement,
            } => {
                let id = witness::attest(
                    store,
                    &kind,
                    &subject_id,
                    &id,
                    &relation,
                    &relation_version,
                    &program,
                    &statement,
                )?;
                println!("{id}");
                Ok(())
            }
            WitnessCmd::Independence {
                statement_id,
                relation,
                relation_version,
                basis,
                detail,
            } => {
                let id = witness::declare_independence(
                    store,
                    &statement_id,
                    &relation,
                    &relation_version,
                    &basis,
                    detail.as_deref(),
                )?;
                println!("{id}");
                Ok(())
            }
        },
    }
}
