use anyhow::Result;
use clap::Parser;
use std::{collections::HashSet, path::PathBuf};

fn main() -> Result<()> {
    let options = Args::parse();

    let sbf_trace_dir = options.sbf_trace_dir;
    let src_paths: HashSet<_> = options.src_path.into_iter().collect();
    let sbf_paths = options.sbf_path;

    solana_coverage::run(sbf_trace_dir, src_paths, sbf_paths, options.debug)?;

    Ok(())
}

/// CLI options
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Enable debug information when parsing
    #[arg(short, long)]
    debug: bool,

    /// Source path to the Solana program (can be specified multiple times), please use full path
    #[arg(long, action = clap::ArgAction::Append, required = true)]
    src_path: Vec<PathBuf>,

    /// SBF path to where the Solana program's .so and .debug are located (typically target/deploy or target/deploy/debug) (can be specified multiple times), please use full path
    #[arg(long, action = clap::ArgAction::Append, required = true)]
    sbf_path: Vec<PathBuf>,

    /// Path to the register tracing dumps, please use full path
    #[arg(long, required = true)]
    sbf_trace_dir: PathBuf,
}
