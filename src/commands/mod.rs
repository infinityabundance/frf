//! Command dispatch: each verb is one function; stdout carries the single
//! machine-readable id a command produces, stderr carries narration.

pub mod admit;
pub mod bundle;
pub mod claim;
pub mod court;
pub mod dispose;
pub mod evidence;
pub mod receipt;
pub mod replay;
pub mod witness;

use crate::cli::*;
use crate::error::Result;
use crate::host;
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
                // 0.1.63: the benchmark protocol needs the HARNESS PROCESS's
                // own CPU (RUSAGE_SELF — user+sys of the frf executable
                // itself, excluding the sides it spawned) separated from the
                // sides' CPU. Printed only when explicitly requested
                // (FRF_PRINT_SELF_CPU=1, set by the v5 benchmark); a hostile
                // or benchmark-free invocation is unaffected.
                if std::env::var("FRF_PRINT_SELF_CPU")
                    .map(|v| v == "1")
                    .unwrap_or(false)
                {
                    println!("frf-self-cpu-ms: {:.3}", host::self_cpu_ms());
                }
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
                observation_run,
                trajectory,
                consecutive_passes,
            } => dispose::run(
                store,
                &id,
                disposition,
                &reason,
                resolution_run,
                observation_run,
                trajectory,
                consecutive_passes,
            ),
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
                mutation_profile,
                trajectory,
            } => claim::run(
                store,
                &receipt,
                json,
                &policy,
                &mutation_profile,
                &trajectory,
            ),
            ClaimCmd::Render { receipt, format } => {
                // The renderers present a VERIFIED claim only: the target is
                // resolved (a claim content address, or a receipt via the
                // by-receipt index) and the claim is re-verified against the
                // evidence tree (identity, premises, scope, universe, policy
                // evidence) before a single field is rendered — a hand-
                // written canonical file is refused, never rendered.
                let id = crate::commands::claim::resolve_claim(store, &receipt)?;
                let verified = crate::verify::load_claim_verified(store, &id)?;
                let view = crate::render::RenderView::from_verified(&verified)?;
                let out = crate::render::render(&view, &format, env!("CARGO_PKG_VERSION"))?;
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
        Command::Evidence { sub } => match sub {
            EvidenceCmd::Status {} => evidence::status(store),
            EvidenceCmd::PublishDetached { policy, output } => {
                let out = evidence::publish_detached(store, &policy, &output)?;
                println!("{}", out.display());
                Ok(())
            }
        },
    }
}
